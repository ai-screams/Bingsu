//! Other sessions' leftovers (m6-C4a7): every shell session that ran a
//! command round leaves its lock `command-<digest>.lock` in the runtime root
//! and, on the Linux atomic path, its cgroup parent `bingsu-cmd-<digest>`
//! under the shell's cgroup. The collection GC reclaims a few each run
//! (C4a7 ruling D), only through this runtime root's locks:
//!
//! - A lock older than [`STALE_SECS`], not this session's, is taken without
//!   blocking (a round in progress holds its own, so it stays) and checked
//!   again on its descriptor and name.
//! - Then the parent of the same digest in this process's own cgroup (Linux,
//!   after the membership check): an empty one is removed, then the lock.
//!   One with a unit left keeps both. With no parent there, only the lock
//!   goes. Holding the lock is owning the parent: the digest covers the
//!   session and this runtime root, and a round of that session takes the
//!   same lock. A parent of another runtime root is never touched.
//!
//! A run reads at most [`BLOCKS_MAX`] blocks of the runtime root, starts at a
//! place that a fresh seed picks each run, looks at no more than
//! [`EXAMINE_MAX`] names and takes no more than [`RECLAIM_MAX`] locks, so
//! repeated runs reach every name those blocks hold without a saved cursor.
//! A live idle session that loses its lock and empty parent makes both
//! again on its next round.

use super::{snapshot_store, sys};
use std::{
    ffi::{OsStr, OsString},
    fs::File,
    io,
    os::fd::AsFd,
};

/// A lock unchanged this long is stale (ruling: 24 h by ctime). The lock is
/// never written, so its ctime is when it was made.
pub(crate) const STALE_SECS: i64 = 24 * 60 * 60;
/// Locks taken (reclaim tried) in one GC run. A lock a round holds is not
/// taken and does not count.
pub(crate) const RECLAIM_MAX: usize = 4;
/// Names looked at in one GC run.
pub(crate) const EXAMINE_MAX: usize = 32;
/// Directory blocks (8 KiB each) read in one GC run.
pub(crate) const BLOCKS_MAX: usize = 4;

const LOCK_PREFIX: &str = "command-";
const LOCK_SUFFIX: &str = ".lock";

/// `command-<cgroup parent digest>.lock`.
pub(crate) fn lock_name(session: &[u8], runtime: (u64, u64)) -> String {
    let digest = bingsu_core::command::cgroup::parent_digest(session, runtime);
    format!("{LOCK_PREFIX}{digest}{LOCK_SUFFIX}")
}

/// The digest of a session lock's name: 32 lowercase hex digits between
/// the fixed prefix and suffix, or `None` for any other name.
fn digest_of(name: &OsStr) -> Option<&str> {
    let digest = name
        .to_str()?
        .strip_prefix(LOCK_PREFIX)?
        .strip_suffix(LOCK_SUFFIX)?;
    let hex = |c: u8| c.is_ascii_digit() || (b'a'..=b'f').contains(&c);
    (digest.len() == 32 && digest.bytes().all(hex)).then_some(digest)
}

/// This process's own cgroup, as the GC sees it.
#[cfg_attr(
    not(target_os = "linux"),
    allow(dead_code, reason = "macOS has no cgroups: only Absent")
)]
pub(crate) enum OwnCgroup {
    /// The cgroup v2 folder that holds this process.
    Folder(File),
    /// No cgroup v2 here (macOS, or no cgroup v2 mount): no parent exists.
    Absent,
    /// Not found for another reason (an I/O error, a `cgroup.procs` too large,
    /// a namespace that names another folder): a parent may exist.
    Unknown,
}

/// What one lock came to (tests read it).
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Outcome {
    /// The lock removed, with its empty parent when there was one.
    Reclaimed(String),
    /// Taken but kept: changed since its stat, or its parent holds a unit.
    /// Counts against [`RECLAIM_MAX`].
    Kept(String),
    /// A round holds it: not taken, not counted.
    Busy(String),
}

/// Reclaims stale session locks of `runtime` and their empty parents.
/// `now` is the wall clock in seconds and `seed` picks where the run
/// starts; `session` is this helper's own session, whose lock is never
/// reclaimed here (its round released it just before the GC); `own_cgroup`
/// opens this process's cgroup folder, at most once and only after a lock
/// was taken. Every call goes through the collection GC's meter; a refused
/// charge ends the step. Returns what it did.
pub(crate) fn reclaim_stale(
    runtime: &File,
    me: u32,
    now: i64,
    seed: u64,
    session: Option<&[u8]>,
    own_cgroup: &mut dyn FnMut() -> OwnCgroup,
) -> Vec<Outcome> {
    let mut done = Vec::new();
    let names = listed(runtime);
    if names.is_empty() {
        return done;
    }
    let mut own: Option<Option<String>> = None;
    let mut mine = |digest: &str| {
        own.get_or_insert_with(|| {
            let at = sys::file_stamp(runtime).ok()?;
            let name = lock_name(session?, (at.dev, at.ino));
            digest_of(OsStr::new(&name)).map(str::to_owned)
        })
        .as_deref()
            == Some(digest)
    };
    let mut cgroup: Option<OwnCgroup> = None;
    // 이것을 실패시키는 것: 시작 위치를 실행마다 돌리지 않는 것(앞쪽 이름이 상한을 매번 채워 뒤쪽이 영영 안 보임).
    let start = usize::try_from(seed % names.len() as u64).unwrap_or(0);
    let mut taken = 0;
    // 이것을 실패시키는 것: 살펴보는 이름 수 상한을 지우는 것, 잡은 잠금 대신 결과마다(Busy 포함) 세는 것.
    for name in names
        .iter()
        .cycle()
        .skip(start)
        .take(names.len().min(EXAMINE_MAX))
    {
        if taken >= RECLAIM_MAX {
            break;
        }
        let digest = digest_of(name).expect("listed").to_owned();
        let step = reclaim_one(
            runtime,
            me,
            now,
            name,
            &digest,
            &mut mine,
            &mut cgroup,
            own_cgroup,
        );
        if matches!(step, Some(Outcome::Reclaimed(_) | Outcome::Kept(_))) {
            taken += 1;
        }
        done.extend(step);
    }
    done
}

/// A seed for [`reclaim_stale`]'s start: the clock's nanoseconds mixed with
/// the process id, so runs a fixed number of seconds apart do not repeat it.
pub(crate) fn start_seed() -> u64 {
    #[cfg(test)]
    if let Some(seed) = SEED.with(std::cell::Cell::get) {
        return seed;
    }
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::from(d.subsec_nanos()) ^ d.as_secs());
    (nanos ^ u64::from(std::process::id()).rotate_left(32)).wrapping_mul(0x9e37_79b9_7f4a_7c15)
        >> 16
}

/// The session lock names of `dir`, from at most [`BLOCKS_MAX`] blocks,
/// sorted (a block's order is the file system's).
fn listed(dir: &File) -> Vec<OsString> {
    let mut names = Vec::new();
    let mut at = 0;
    // 이것을 실패시키는 것: 첫 블록만 읽는 것, 블록 상한을 지우는 것.
    for _ in 0..BLOCKS_MAX {
        let Ok((next, block)) = sys::directory_batch(dir.as_fd(), at) else {
            break;
        };
        names.extend(block.into_iter().filter(|n| digest_of(n).is_some()));
        if next == at {
            break;
        }
        at = next;
    }
    names.sort();
    names
}

/// One lock: `None` when it is not a candidate (fresh, missing, this
/// session's own, or not a lock file).
#[allow(clippy::too_many_arguments, reason = "one candidate's inputs")]
fn reclaim_one(
    runtime: &File,
    me: u32,
    now: i64,
    name: &OsStr,
    digest: &str,
    mine: &mut dyn FnMut(&str) -> bool,
    cgroup: &mut Option<OwnCgroup>,
    own_cgroup: &mut dyn FnMut() -> OwnCgroup,
) -> Option<Outcome> {
    let kept = || Some(Outcome::Kept(digest.to_owned()));
    // The name's own stat first: a fresh lock (every live session's) costs
    // the GC this one call.
    let seen = sys::at_stamp(runtime.as_fd(), name).ok()?;
    // 이것을 실패시키는 것: 나이 확인을 지우는 것(만든 지 얼마 안 된 잠금도 회수됨).
    if now.saturating_sub(seen.ctime.0) < STALE_SECS {
        return None;
    }
    // 이것을 실패시키는 것: 자기 세션의 잠금을 건너뛰지 않는 것(24시간 넘은 세션이 자기 잠금과 부모를 지움).
    if mine(digest) {
        return None;
    }
    #[cfg(test)]
    BEFORE_OPEN.with(|hook| {
        if let Some(mut hook) = hook.borrow_mut().take() {
            hook();
        }
    });
    let file = sys::open_data_at_nofollow(runtime.as_fd(), name).ok()?;
    snapshot_store::check_data(&file, 0, me).ok()?;
    #[cfg(test)]
    AFTER_OPEN.with(|hook| {
        if let Some(mut hook) = hook.borrow_mut().take() {
            hook();
        }
    });
    // A round holds its lock: the non-blocking lock fails and it stays.
    // 이것을 실패시키는 것: 잠금 없이 지우는 것(회차 중인 세션의 잠금과 부모가 지워짐).
    let Ok(lock) = sys::try_lock(file) else {
        return Some(Outcome::Busy(digest.to_owned()));
    };
    let lock = lock.into_inherited_file();
    // The locked file is exactly the one stat'ed above, so its age still
    // holds: a file put under the name before the open (Linux may give it
    // the freed inode number) or one changed since (chmod moves its ctime)
    // is kept. The whole stamp, ctime with nanoseconds included.
    // 이것을 실패시키는 것: 잠근 fd의 stamp를 처음 stat과 비교하지 않는 것
    // (a_name_replaced_before_the_open_is_kept, a_lock_changed_after_its_stat_is_kept).
    // A name replaced between the open and the lock needs no check of its
    // own: unlinking or renaming over a name moves the old file's ctime, so
    // the stamp differs then too (a_name_replaced_after_the_open_is_kept).
    if sys::file_stamp(&lock).ok()? != seen {
        return kept();
    }
    if !remove_parent(digest, cgroup, own_cgroup) {
        return kept();
    }
    // A refused charge here leaves a stale lock with no parent: the next run
    // takes it again (an_unfinished_reclaim_is_finished_by_the_next_run).
    sys::unlink_at(runtime.as_fd(), name).ok()?;
    drop(lock);
    Some(Outcome::Reclaimed(digest.to_owned()))
}

/// Removes the empty cgroup parent of `digest` in this process's own
/// cgroup; `true` when none is there now (removed, never there, or no
/// cgroup v2 here). A parent with a unit cgroup left stays, and so does a
/// lock whose cgroup could not be found: its parent may still be there and
/// would never be found again.
fn remove_parent(
    digest: &str,
    cgroup: &mut Option<OwnCgroup>,
    own_cgroup: &mut dyn FnMut() -> OwnCgroup,
) -> bool {
    let own = match cgroup.get_or_insert_with(own_cgroup) {
        OwnCgroup::Folder(own) => own,
        OwnCgroup::Absent => return true,
        // 이것을 실패시키는 것: 찾지 못한 cgroup을 없음으로 보는 것(gc_lookup_failure_keeps_the_lock).
        OwnCgroup::Unknown => return false,
    };
    let parent = format!("bingsu-cmd-{digest}");
    // 이것을 실패시키는 것: 비지 않은 부모(남은 단위 cgroup)를 두고 잠금을 지우는 것, 부모가 없을 때 잠금을 남기는 것.
    match sys::remove_dir_at(own.as_fd(), OsStr::new(&parent)) {
        Ok(()) => true,
        Err(e) => e.kind() == io::ErrorKind::NotFound,
    }
}

/// This process's own cgroup folder (Linux), for [`reclaim_stale`].
pub(crate) fn own_cgroup() -> OwnCgroup {
    #[cfg(target_os = "linux")]
    return super::command_cgroup::fs::open_own();
    #[cfg(not(target_os = "linux"))]
    OwnCgroup::Absent
}

/// The wall clock in seconds, for [`reclaim_stale`].
pub(crate) fn now_secs() -> i64 {
    #[cfg(test)]
    if let Some(now) = NOW.with(std::cell::Cell::get) {
        return now;
    }
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

#[cfg(test)]
thread_local! {
    /// Tests stand in a later wall clock (a lock's ctime cannot be set back).
    pub(crate) static NOW: std::cell::Cell<Option<i64>> = const { std::cell::Cell::new(None) };
    /// Tests pick the start (`start_seed`).
    pub(crate) static SEED: std::cell::Cell<Option<u64>> = const { std::cell::Cell::new(None) };
    static BEFORE_OPEN: std::cell::RefCell<Option<Box<dyn FnMut()>>> = const { std::cell::RefCell::new(None) };
    static AFTER_OPEN: std::cell::RefCell<Option<Box<dyn FnMut()>>> = const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::MetadataExt;
    use std::path::{Path, PathBuf};

    struct Scratch(PathBuf);
    impl Scratch {
        fn new(tag: &str) -> Self {
            let p =
                std::env::temp_dir().join(format!("bingsu-sessions-{tag}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&p);
            std::fs::create_dir_all(p.join("runtime")).unwrap();
            std::fs::create_dir_all(p.join("cgroup")).unwrap();
            for d in [&p, &p.join("runtime"), &p.join("cgroup")] {
                std::fs::set_permissions(d, std::os::unix::fs::PermissionsExt::from_mode(0o700))
                    .unwrap();
            }
            Self(std::fs::canonicalize(p).unwrap())
        }
        fn runtime(&self) -> PathBuf {
            self.0.join("runtime")
        }
        fn cgroup(&self) -> PathBuf {
            self.0.join("cgroup")
        }
    }
    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn digest(i: u8) -> String {
        format!("{:032x}", u128::from(i) + 0xabc0)
    }

    /// A lock file as `close_only_lock` makes it, and its ctime.
    fn lock(at: &Path, d: &str) -> i64 {
        let p = at.join(format!("command-{d}.lock"));
        std::fs::write(&p, b"").unwrap();
        std::fs::set_permissions(&p, std::os::unix::fs::PermissionsExt::from_mode(0o600)).unwrap();
        std::fs::metadata(&p).unwrap().ctime()
    }

    fn run(s: &Scratch, now: i64) -> Vec<Outcome> {
        run_as(s, now, None)
    }

    fn run_as(s: &Scratch, now: i64, session: Option<&[u8]>) -> Vec<Outcome> {
        let runtime = File::open(s.runtime()).unwrap();
        let cgroup = s.cgroup();
        reclaim_stale(
            &runtime,
            sys::current_uid(),
            now,
            start_seed(),
            session,
            &mut || File::open(&cgroup).map_or(OwnCgroup::Unknown, OwnCgroup::Folder),
        )
    }

    fn hold(s: &Scratch, d: &str) -> sys::FileLock {
        sys::try_lock(File::open(s.runtime().join(format!("command-{d}.lock"))).unwrap()).unwrap()
    }

    fn exists(at: &Path, d: &str) -> bool {
        at.join(format!("command-{d}.lock")).exists()
    }

    // m6-C4a7: 24 h(ctime) 넘은 잠금만 후보이고 경계는 그 값에서 시작한다. 다른 이름은 건드리지 않는다. 이것을
    // 실패시키는 것: 나이 확인을 지우는 것, 경계를 하나 밀거나 당기는 것, 이름 문법(접두·접미·32 hex)을 넓히는 것.
    #[test]
    fn only_stale_session_locks_are_candidates() {
        let s = Scratch::new("age");
        let ctime = lock(&s.runtime(), &digest(1));
        for other in [
            "command-XYZ.lock",
            "command-abc.lock",
            "other.lock",
            "command-00000000000000000000000000000abc.lockx",
            "command-gggggggggggggggggggggggggggggggg.lock",
            "command-ABCDEF00000000000000000000000000.lock",
        ] {
            // As a lock file would be (0600, empty): only the name rules it out.
            std::fs::write(s.runtime().join(other), b"").unwrap();
            std::fs::set_permissions(
                s.runtime().join(other),
                std::os::unix::fs::PermissionsExt::from_mode(0o600),
            )
            .unwrap();
        }
        assert_eq!(run(&s, ctime + STALE_SECS - 1), []);
        assert!(exists(&s.runtime(), &digest(1)));
        assert_eq!(run(&s, ctime + STALE_SECS), [Outcome::Reclaimed(digest(1))]);
        assert!(!exists(&s.runtime(), &digest(1)));
        for other in [
            "command-XYZ.lock",
            "command-abc.lock",
            "other.lock",
            "command-00000000000000000000000000000abc.lockx",
            "command-gggggggggggggggggggggggggggggggg.lock",
            "command-ABCDEF00000000000000000000000000.lock",
        ] {
            assert!(s.runtime().join(other).exists(), "{other}");
        }
    }

    // 회차가 쥔 잠금은 남는다. 이것을 실패시키는 것: 비차단 잠금 실패를 무시하고 지우는 것.
    #[test]
    fn a_held_lock_is_kept() {
        let s = Scratch::new("held");
        let ctime = lock(&s.runtime(), &digest(2));
        let held = sys::try_lock(
            File::open(s.runtime().join(format!("command-{}.lock", digest(2)))).unwrap(),
        )
        .unwrap();
        assert_eq!(run(&s, ctime + STALE_SECS), [Outcome::Busy(digest(2))]);
        assert!(exists(&s.runtime(), &digest(2)));
        drop(held);
    }

    // 회차가 쥔 잠금은 상한을 쓰지 않는다: 쥔 잠금 다섯 뒤의 오래된 잠금도 회수된다. 이것을 실패시키는 것:
    // Busy도 상한에 세는 것.
    #[test]
    fn held_locks_do_not_use_the_limit() {
        let s = Scratch::new("held-cap");
        let mut ctime = 0;
        for i in 0..6 {
            ctime = ctime.max(lock(&s.runtime(), &digest(i)));
        }
        let _held: Vec<_> = (0..5).map(|i| hold(&s, &digest(i))).collect();
        // A start of 0: the free lock is the last name seen.
        SEED.with(|c| c.set(Some(0)));
        let done = run(&s, ctime + STALE_SECS);
        SEED.with(|c| c.set(None));
        assert_eq!(
            done.last(),
            Some(&Outcome::Reclaimed(digest(5))),
            "{done:?}"
        );
        assert!(!exists(&s.runtime(), &digest(5)));
    }

    // 한 번에 EXAMINE_MAX개 이름까지만 본다(모두 쥔 잠금이라 회수 상한은 차지 않음). 이것을 실패시키는 것: 살펴보는
    // 이름 수 상한을 지우는 것.
    #[test]
    fn at_most_examine_max_names_a_run() {
        let s = Scratch::new("examine");
        let mut ctime = 0;
        for i in 0..=EXAMINE_MAX as u8 {
            ctime = ctime.max(lock(&s.runtime(), &digest(i)));
        }
        let _held: Vec<_> = (0..=EXAMINE_MAX as u8)
            .map(|i| hold(&s, &digest(i)))
            .collect();
        let done = run(&s, ctime + STALE_SECS);
        assert_eq!(done.len(), EXAMINE_MAX, "{done:?}");
        assert!(
            done.iter().all(|o| matches!(o, Outcome::Busy(_))),
            "{done:?}"
        );
    }

    // 시작 위치가 seed로 돌아, 쥔 잠금 33개 뒤(정렬 순)의 오래된 잠금 셋도 실행을 거듭하면 모두 회수된다. 이것을
    // 실패시키는 것: 시작 위치를 seed로 돌리지 않는 것(앞의 32개만 매번 봄).
    #[test]
    fn repeated_runs_reach_every_lock() {
        let s = Scratch::new("rotate");
        let mut ctime = 0;
        for i in 0..36 {
            ctime = ctime.max(lock(&s.runtime(), &digest(i)));
        }
        let _held: Vec<_> = (0..33).map(|i| hold(&s, &digest(i))).collect();
        for k in 0..36 {
            SEED.with(|c| c.set(Some(k)));
            run(&s, ctime + STALE_SECS);
        }
        SEED.with(|c| c.set(None));
        for i in 33..36 {
            assert!(!exists(&s.runtime(), &digest(i)), "{i}");
        }
    }

    // 목록은 최대 BLOCKS_MAX블록을 읽는다: 둘째 블록의 잠금은 회수되고, 다섯째 블록의 잠금은 보지 않는다. 이것을
    // 실패시키는 것: 첫 블록만 읽는 것, 블록 상한을 지우는 것.
    #[test]
    fn the_listing_reads_at_most_four_blocks() {
        let s = Scratch::new("blocks");
        let ctime = lock(&s.runtime(), &digest(1)).max(lock(&s.runtime(), &digest(4)));
        // Blocks 0-4: the second holds digest 1, the fifth digest 4, the
        // rest nothing, so the four-lock limit is never what stops the run.
        let blocks: Vec<Vec<OsString>> = (0..5)
            .map(|k| match k {
                1 => vec![format!("command-{}.lock", digest(1)).into()],
                4 => vec![format!("command-{}.lock", digest(4)).into()],
                _ => Vec::new(),
            })
            .collect();
        let _reader = sys::FixtureDirectoryReader::install(Box::new(move |_, at| {
            let k = usize::try_from(at).unwrap();
            Ok(match blocks.get(k) {
                Some(names) => (at + 1, names.clone()),
                None => (at, Vec::new()),
            })
        }));
        let done = run(&s, ctime + STALE_SECS);
        assert_eq!(done, [Outcome::Reclaimed(digest(1))]);
        assert!(exists(&s.runtime(), &digest(4)));
    }

    // 자기 세션의 잠금은 오래돼도 남는다(회차가 GC 전에 놓음). 양성 대조: 같은 잠금을 세션 없이 돌리면 회수된다.
    // 이것을 실패시키는 것: 자기 세션 건너뛰기를 지우는 것, 잠금 이름을 다른 runtime 정체로 셈하는 것.
    #[test]
    fn this_sessions_own_lock_is_kept() {
        use std::os::unix::fs::MetadataExt;
        let s = Scratch::new("own");
        let root = std::fs::metadata(s.runtime()).unwrap();
        let session = b"0123456789abcdef0123456789abcdef";
        let name = lock_name(session, (root.dev(), root.ino()));
        let own = digest_of(OsStr::new(&name)).unwrap().to_owned();
        let ctime = lock(&s.runtime(), &own);
        assert_eq!(run_as(&s, ctime + STALE_SECS, Some(session)), []);
        assert!(exists(&s.runtime(), &own));
        assert_eq!(
            run_as(
                &s,
                ctime + STALE_SECS,
                Some(b"fedcba9876543210fedcba9876543210")
            ),
            [Outcome::Reclaimed(own.clone())]
        );
    }

    // stat 뒤 open 전에 이름이 새 파일로 바뀌면 지우지 않는다(Linux는 지운 inode 번호를 새 파일에 다시 줄 수
    // 있고, now를 10초 늦춰 나이로도 가리지 못하게 한다). 이것을 실패시키는 것: 잠근 fd의 stamp를 처음 stat과
    // 비교하지 않는 것.
    #[test]
    fn a_name_replaced_before_the_open_is_kept() {
        let s = Scratch::new("swap-early");
        let ctime = lock(&s.runtime(), &digest(6));
        let path = s.runtime().join(format!("command-{}.lock", digest(6)));
        let swap = path.clone();
        BEFORE_OPEN.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move || {
                // Past the kernel's coarse timestamp tick: a lock this old is
                // a day older than its replacement, never in the same tick.
                std::thread::sleep(std::time::Duration::from_millis(50));
                std::fs::remove_file(&swap).unwrap();
                std::fs::write(&swap, b"").unwrap();
                std::fs::set_permissions(
                    &swap,
                    std::os::unix::fs::PermissionsExt::from_mode(0o600),
                )
                .unwrap();
            }))
        });
        assert_eq!(run(&s, ctime + STALE_SECS + 10), [Outcome::Kept(digest(6))]);
        assert!(path.exists());
    }

    // stat 뒤 ctime이 바뀌면(chmod) 남긴다. 이것을 실패시키는 것: 잠근 fd의 stamp를 처음 stat과 비교하지 않는 것.
    #[test]
    fn a_lock_changed_after_its_stat_is_kept() {
        let s = Scratch::new("chmod");
        let ctime = lock(&s.runtime(), &digest(7));
        let path = s.runtime().join(format!("command-{}.lock", digest(7)));
        let touched = path.clone();
        AFTER_OPEN.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move || {
                // Past the kernel's coarse timestamp tick, so the chmod gives
                // the file another ctime.
                std::thread::sleep(std::time::Duration::from_millis(50));
                std::fs::set_permissions(
                    &touched,
                    std::os::unix::fs::PermissionsExt::from_mode(0o600),
                )
                .unwrap();
            }))
        });
        assert_eq!(run(&s, ctime + STALE_SECS), [Outcome::Kept(digest(7))]);
        assert!(path.exists());
    }

    // 한 번에 RECLAIM_MAX개까지만. 이것을 실패시키는 것: 상한을 지우는 것.
    #[test]
    fn at_most_four_a_run() {
        let s = Scratch::new("cap");
        let mut ctime = 0;
        for i in 0..6 {
            ctime = ctime.max(lock(&s.runtime(), &digest(i)));
        }
        let done = run(&s, ctime + STALE_SECS);
        assert_eq!(done.len(), RECLAIM_MAX);
        assert_eq!(
            (0..6).filter(|i| exists(&s.runtime(), &digest(*i))).count(),
            2
        );
    }

    // 연 뒤 이름이 다른 파일로 바뀌면 그 이름은 지우지 않는다(옛 파일의 unlink가 ctime을 바꿔 stamp가 다름). 이것을
    // 실패시키는 것: 잠근 fd의 stamp를 처음 stat과 비교하지 않는 것(바뀐 파일을 지움).
    #[test]
    fn a_name_replaced_after_the_open_is_kept() {
        let s = Scratch::new("swap");
        let ctime = lock(&s.runtime(), &digest(3));
        let path = s.runtime().join(format!("command-{}.lock", digest(3)));
        let swap = path.clone();
        AFTER_OPEN.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move || {
                // Past the kernel's coarse timestamp tick, so the unlink moves
                // the old file's ctime, as it always does for a day-old lock.
                std::thread::sleep(std::time::Duration::from_millis(50));
                std::fs::remove_file(&swap).unwrap();
                std::fs::write(&swap, b"").unwrap();
            }))
        });
        assert_eq!(run(&s, ctime + STALE_SECS), [Outcome::Kept(digest(3))]);
        assert!(path.exists());
    }

    // Linux: GC의 자기 cgroup 찾기는 호출마다 GC meter에 센다. `/proc/self/cgroup`(열기와 닫기 2, EOF까지 읽기 2),
    // 자기 폴더(열기와 닫기 2, fstatfs 1), cgroup.procs(열기와 닫기 2, 4 KiB씩 EOF까지 pread). 이것을 실패시키는 것:
    // 그 가운데 한 호출의 charge를 지우는 것.
    #[cfg(target_os = "linux")]
    #[test]
    fn own_cgroup_lookup_is_metered() {
        let text = std::fs::read("/proc/self/cgroup").unwrap();
        let Some(path) = bingsu_core::command::cgroup::own_path(&text) else {
            return;
        };
        let folder =
            Path::new("/sys/fs/cgroup").join(String::from_utf8_lossy(path).trim_start_matches('/'));
        let Ok(procs) = std::fs::read(folder.join("cgroup.procs")) else {
            return;
        };
        let meter = sys::CollectionMeter::fixture_operations(4_096);
        let found = own_cgroup();
        let used = meter.used();
        drop(meter);
        assert!(
            matches!(found, OwnCgroup::Folder(_)),
            "this process's cgroup v2 folder"
        );
        let preads = procs.len().div_ceil(4096) as u32 + 1;
        assert_eq!(used, 2 + 2 + 2 + 1 + 2 + preads);
    }

    fn parent(s: &Scratch, d: &str, busy: bool) -> PathBuf {
        let p = s.cgroup().join(format!("bingsu-cmd-{d}"));
        std::fs::create_dir(&p).unwrap();
        if busy {
            std::fs::create_dir(p.join("u0000000000000001")).unwrap();
        }
        p
    }

    // 판정 D: 부모는 이 뿌리의 오래된 잠금을 잡은 뒤에만 본다. 빈 부모는 잠금과 함께 가고, 단위가 남은 부모는
    // 잠금과 함께 남고, 부모가 없으면 잠금만 간다. 잠금 없는 부모(다른 runtime 뿌리의 것)와 새 잠금의 부모는
    // 건드리지 않는다. 이것을 실패시키는 것: 부모를 지우지 않는 것, 비지 않은 부모를 두고 잠금을 지우는 것, 부모가
    // 없을 때 잠금을 남기는 것.
    #[test]
    fn a_parent_goes_only_through_its_stale_lock() {
        let s = Scratch::new("parents");
        let mut ctime = 0;
        for i in 1..=3 {
            ctime = ctime.max(lock(&s.runtime(), &digest(i)));
        }
        let empty = parent(&s, &digest(1), false);
        let busy = parent(&s, &digest(2), true);
        let foreign = parent(&s, &digest(4), false);
        let mut done = run(&s, ctime + STALE_SECS);
        done.sort_by_key(|o| format!("{o:?}"));
        assert_eq!(
            done,
            [
                Outcome::Kept(digest(2)),
                Outcome::Reclaimed(digest(1)),
                Outcome::Reclaimed(digest(3))
            ]
        );
        assert!(!empty.exists() && !exists(&s.runtime(), &digest(1)));
        assert!(busy.exists() && exists(&s.runtime(), &digest(2)));
        assert!(!exists(&s.runtime(), &digest(3)));
        assert!(foreign.exists());
    }

    // 자기 cgroup을 찾지 못했으면(I/O 오류, 큰 cgroup.procs, 다른 폴더를 가리키는 namespace) 부모가 남아 있을 수
    // 있으므로 잠금을 남긴다. cgroup v2가 아예 없으면 잠금만 지운다. 이것을 실패시키는 것: 찾기 실패를 cgroup 없음으로
    // 보는 것, cgroup 없음을 실패로 보는 것.
    #[test]
    fn gc_lookup_failure_keeps_the_lock() {
        let s = Scratch::new("lookup");
        let ctime = lock(&s.runtime(), &digest(1));
        let runtime = File::open(s.runtime()).unwrap();
        let go = |own: fn() -> OwnCgroup| {
            reclaim_stale(
                &runtime,
                sys::current_uid(),
                ctime + STALE_SECS,
                0,
                None,
                &mut || own(),
            )
        };
        assert_eq!(go(|| OwnCgroup::Unknown), [Outcome::Kept(digest(1))]);
        assert!(exists(&s.runtime(), &digest(1)));
        assert_eq!(go(|| OwnCgroup::Absent), [Outcome::Reclaimed(digest(1))]);
        assert!(!exists(&s.runtime(), &digest(1)));
    }

    // Linux: cgroup v2 mount이 없을 때(폴더 없음, 다른 파일 시스템)만 없음이고, cgroup v2인데 이 프로세스의 폴더를
    // 못 찾으면 모름이다. 이것을 실패시키는 것: mount 확인 없이 찾기 실패를 없음으로 보는 것, 없는 mount를 모름으로
    // 보는 것, 다른 파일 시스템을 cgroup v2로 보는 것.
    #[cfg(target_os = "linux")]
    #[test]
    fn gc_lookup_failure_is_not_absence() {
        use super::super::command_cgroup::fs::own_or_why;
        let s = Scratch::new("absence");
        let plain = s.cgroup().into_os_string().into_encoded_bytes();
        assert!(matches!(own_or_why(&plain, b"0::/\n"), OwnCgroup::Absent));
        assert!(matches!(
            own_or_why(b"/bingsu-no-such-mount", b"0::/\n"),
            OwnCgroup::Absent
        ));
        // The CI runners and containers mount cgroup v2 there.
        assert!(matches!(
            own_or_why(b"/sys/fs/cgroup", b"0::/bingsu-no-such-cgroup\n"),
            OwnCgroup::Unknown
        ));
    }

    /// Probe for the fsbudget stale-lock terms (run under strace by hand,
    /// m6-C4a7): one stale lock reclaimed in this process's real cgroup.
    /// `BINGSU_PROBE_CASE`: `empty` (an empty parent), `busy` (a parent with a
    /// unit), `none` (no parent), `held` (the lock held), `other` (the lookup
    /// names a cgroup that does not hold this process).
    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "probe under strace, root in a privileged container"]
    fn stale_reclaim_probe() {
        #[expect(clippy::disallowed_methods, reason = "test-only probe input")]
        let case = std::env::var("BINGSU_PROBE_CASE").unwrap();
        let s = Scratch::new(&format!("probe-{case}"));
        let ctime = lock(&s.runtime(), &digest(1));
        let text = std::fs::read("/proc/self/cgroup").unwrap();
        let own = PathBuf::from(format!(
            "/sys/fs/cgroup{}",
            String::from_utf8_lossy(bingsu_core::command::cgroup::own_path(&text).unwrap())
                .trim_end_matches('/')
        ));
        let parent = own.join(format!("bingsu-cmd-{}", digest(1)));
        let other = own.join("bingsu-probe-other");
        if matches!(case.as_str(), "empty" | "busy" | "held") {
            std::fs::create_dir(&parent).unwrap();
        }
        if case == "busy" {
            std::fs::create_dir(parent.join("u0000000000000001")).unwrap();
        }
        if case == "other" {
            std::fs::create_dir(&other).unwrap();
        }
        let _held = (case == "held").then(|| hold(&s, &digest(1)));
        let fake = format!(
            "0::/{}\n",
            other.strip_prefix("/sys/fs/cgroup").unwrap().display()
        );
        let runtime = File::open(s.runtime()).unwrap();
        eprintln!("MARK-BEGIN");
        let done = reclaim_stale(
            &runtime,
            sys::current_uid(),
            ctime + STALE_SECS,
            0,
            Some(b"0123456789abcdef0123456789abcdef"),
            &mut || {
                if case == "other" {
                    super::super::command_cgroup::fs::own_or_why(b"/sys/fs/cgroup", fake.as_bytes())
                } else {
                    own_cgroup()
                }
            },
        );
        eprintln!("MARK-END {done:?}");
        let _ = std::fs::remove_dir(parent.join("u0000000000000001"));
        let _ = std::fs::remove_dir(&parent);
        let _ = std::fs::remove_dir(&other);
    }

    // rmdir과 unlink 사이에 예산이 바닥나면 오래된 잠금이 부모 없이 남고, 다음 실행이 그것을 마저 지운다. 이것을
    // 실패시키는 것: 부모가 없을 때 잠금을 남기는 것(다음 실행이 끝내지 못함).
    #[test]
    fn an_unfinished_reclaim_is_finished_by_the_next_run() {
        let s = Scratch::new("unfinished");
        let ctime = lock(&s.runtime(), &digest(1));
        let p = parent(&s, &digest(1), false);
        // The calls of the whole reclaim, then one fewer: the unlink, the
        // last charge, is refused.
        let used = {
            let probe = Scratch::new("unfinished-probe");
            let c = lock(&probe.runtime(), &digest(1));
            parent(&probe, &digest(1), false);
            let meter = sys::CollectionMeter::fixture_operations(4_096);
            assert_eq!(run(&probe, c + STALE_SECS), [Outcome::Reclaimed(digest(1))]);
            meter.used()
        };
        {
            let _meter = sys::CollectionMeter::fixture_operations(sys::CHECKPOINT_OPS + used - 1);
            assert_eq!(run(&s, ctime + STALE_SECS), []);
        }
        assert!(!p.exists() && exists(&s.runtime(), &digest(1)));
        assert_eq!(run(&s, ctime + STALE_SECS), [Outcome::Reclaimed(digest(1))]);
        assert!(!exists(&s.runtime(), &digest(1)));
    }

    // 단위가 남은 부모의 잠금 다섯(Kept, 상한에 셈)이 앞에 있어도, 실행마다 다른 seed로 시작하면 정렬 순 맨 뒤의
    // 오래된 잠금에 닿는다. 이것을 실패시키는 것: 시작 위치를 seed로 돌리지 않는 것.
    #[test]
    fn kept_locks_do_not_hide_the_rest_over_runs() {
        let s = Scratch::new("kept-rotate");
        let mut ctime = 0;
        for i in 0..6 {
            ctime = ctime.max(lock(&s.runtime(), &digest(i)));
        }
        for i in 0..5 {
            parent(&s, &digest(i), true);
        }
        for seed in [7u64, 1 << 40, 12_345_678_901, 3, 0x9e37_79b9] {
            SEED.with(|c| c.set(Some(seed)));
            run(&s, ctime + STALE_SECS);
        }
        SEED.with(|c| c.set(None));
        assert!(!exists(&s.runtime(), &digest(5)));
    }

    // start_seed는 같은 초 안에서도 되풀이되지 않는다(나노초와 pid를 섞음). 이것을 실패시키는 것: seed를 초로만
    // 정하는 것.
    #[test]
    fn start_seeds_differ_within_a_second() {
        let a = start_seed();
        std::thread::sleep(std::time::Duration::from_millis(5));
        let b = start_seed();
        assert_ne!(a, b);
    }
}
