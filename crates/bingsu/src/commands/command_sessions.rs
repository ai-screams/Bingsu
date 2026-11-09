//! Other sessions' leftovers (m6-C4a7): every shell session that ran a
//! command round leaves its lock `command-<digest>.lock` in the runtime root
//! and, on the Linux atomic path, its cgroup parent `bingsu-cmd-<digest>`
//! under the shell's cgroup. The collection GC reclaims a few each run, in
//! two sweeps that do not depend on each other (C4a7 ruling C):
//!
//! - Locks, whatever cgroup made them: a lock older than [`STALE_SECS`]
//!   that no round holds goes. A lock is only an empty file for mutual
//!   exclusion: a round re-checks the name after its `flock`, so removing
//!   one never breaks the exclusion. This sweep never touches a parent.
//! - Parents, found in this process's own cgroup listing (Linux, after the
//!   membership check), not through locks: for each `bingsu-cmd-<digest>`,
//!   the lock of the same digest is taken without blocking (made when
//!   missing, so a round and this sweep still exclude each other). A lock
//!   that was there must be stale; with none, the parent itself must have
//!   been made more than a day ago (another runtime root's session would not
//!   be excluded by a lock made here). An empty parent is removed with its lock;
//!   a parent still holding a unit keeps both, except a lock this sweep just
//!   made. Another cgroup's parents are found the same way by a GC that runs
//!   there; a cgroup where bingsu never runs again goes away with its scope.
//!
//! Each sweep reads at most [`BLOCKS_MAX`] blocks of its folder, starts at a
//! place that moves with the clock, looks at no more than [`EXAMINE_MAX`]
//! names and takes no more than [`RECLAIM_MAX`] locks, so repeated runs reach
//! every name the blocks hold without a saved cursor.

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
/// Locks taken (reclaim tried) by one sweep in one GC run. A lock a round
/// holds is not taken and does not count.
pub(crate) const RECLAIM_MAX: usize = 4;
/// Names one sweep looks at in one GC run.
pub(crate) const EXAMINE_MAX: usize = 32;
/// Directory blocks (8 KiB each) one sweep reads in one GC run.
pub(crate) const BLOCKS_MAX: usize = 4;

const LOCK_PREFIX: &str = "command-";
const LOCK_SUFFIX: &str = ".lock";
const PARENT_PREFIX: &str = "bingsu-cmd-";

/// `command-<cgroup parent digest>.lock`.
pub(crate) fn lock_name(session: &[u8], runtime: (u64, u64)) -> String {
    let digest = bingsu_core::command::cgroup::parent_digest(session, runtime);
    format!("{LOCK_PREFIX}{digest}{LOCK_SUFFIX}")
}

/// 32 lowercase hex digits.
fn is_digest(d: &str) -> bool {
    let hex = |c: u8| c.is_ascii_digit() || (b'a'..=b'f').contains(&c);
    d.len() == 32 && d.bytes().all(hex)
}

/// The digest of a session lock's name, or `None` for any other name.
fn digest_of(name: &OsStr) -> Option<&str> {
    let digest = name
        .to_str()?
        .strip_prefix(LOCK_PREFIX)?
        .strip_suffix(LOCK_SUFFIX)?;
    is_digest(digest).then_some(digest)
}

/// The digest of a cgroup parent's name, or `None` for any other name.
fn parent_digest_of(name: &OsStr) -> Option<&str> {
    let digest = name.to_str()?.strip_prefix(PARENT_PREFIX)?;
    is_digest(digest).then_some(digest)
}

/// What one name came to (tests read it).
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Outcome {
    /// A stale lock removed.
    Reclaimed(String),
    /// A lock taken but kept (changed since its stat): counts against
    /// [`RECLAIM_MAX`].
    Kept(String),
    /// A lock a round holds: not taken, not counted.
    Busy(String),
    /// An empty parent removed with its lock.
    ParentReclaimed(String),
    /// A parent taken but kept (a unit left, or its lock changed).
    ParentKept(String),
    /// A parent whose lock a round holds.
    ParentBusy(String),
}

/// Both sweeps. `now` is the wall clock in seconds; `session` is this
/// helper's own session, whose lock and parent are never reclaimed here (its
/// round released the lock just before the GC); `own_cgroup` opens this
/// process's cgroup folder. Every call goes through the collection GC's
/// meter; a refused charge ends the step. Returns what it did.
pub(crate) fn reclaim_stale(
    runtime: &File,
    me: u32,
    now: i64,
    session: Option<&[u8]>,
    own_cgroup: &mut dyn FnMut() -> Option<File>,
) -> Vec<Outcome> {
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
    let mut done = Vec::new();
    sweep(
        runtime,
        now,
        digest_of,
        false,
        &mut done,
        &mut |name, digest| reclaim_lock(runtime, me, now, name, digest, &mut mine),
    );
    if let Some(cgroup) = own_cgroup() {
        sweep(
            &cgroup,
            now,
            parent_digest_of,
            true,
            &mut done,
            &mut |name, digest| reclaim_parent(runtime, &cgroup, me, now, name, digest, &mut mine),
        );
    }
    done
}

/// What one candidate came to; `None`: not a candidate.
enum Step {
    Reclaimed,
    Kept,
    Busy,
}

/// One sweep over `dir` (`parents`: the cgroup sweep's outcomes): the
/// names `keep` accepts from at most
/// [`BLOCKS_MAX`] blocks, in order from a start that moves with `now`, at
/// most [`EXAMINE_MAX`] of them and until [`RECLAIM_MAX`] were taken.
fn sweep(
    dir: &File,
    now: i64,
    keep: fn(&OsStr) -> Option<&str>,
    parents: bool,
    done: &mut Vec<Outcome>,
    one: &mut dyn FnMut(&OsStr, &str) -> Option<Step>,
) {
    let names = listed(dir, keep);
    if names.is_empty() {
        return;
    }
    // 이것을 실패시키는 것: 시작 위치를 now로 돌리지 않는 것(앞쪽 이름이 상한을 매번 채워 뒤쪽이 영영 안 보임).
    let start = usize::try_from(now.rem_euclid(names.len() as i64)).unwrap_or(0);
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
        let digest = keep(name).expect("listed").to_owned();
        let step = one(name, &digest);
        if matches!(step, Some(Step::Reclaimed | Step::Kept)) {
            taken += 1;
        }
        done.extend(step.map(|s| match (s, parents) {
            (Step::Reclaimed, false) => Outcome::Reclaimed(digest),
            (Step::Kept, false) => Outcome::Kept(digest),
            (Step::Busy, false) => Outcome::Busy(digest),
            (Step::Reclaimed, true) => Outcome::ParentReclaimed(digest),
            (Step::Kept, true) => Outcome::ParentKept(digest),
            (Step::Busy, true) => Outcome::ParentBusy(digest),
        }));
    }
}

/// The names of `dir` that `keep` accepts, from at most [`BLOCKS_MAX`]
/// blocks, sorted (a block's order is the file system's).
fn listed(dir: &File, keep: fn(&OsStr) -> Option<&str>) -> Vec<OsString> {
    let mut names = Vec::new();
    let mut at = 0;
    // 이것을 실패시키는 것: 첫 블록만 읽는 것, 블록 상한을 지우는 것.
    for _ in 0..BLOCKS_MAX {
        let Ok((next, block)) = sys::directory_batch(dir.as_fd(), at) else {
            break;
        };
        names.extend(block.into_iter().filter(|n| keep(n).is_some()));
        if next == at {
            break;
        }
        at = next;
    }
    names.sort();
    names
}

/// A stale lock that no round holds, not this session's: removed.
fn reclaim_lock(
    runtime: &File,
    me: u32,
    now: i64,
    name: &OsStr,
    digest: &str,
    mine: &mut dyn FnMut(&str) -> bool,
) -> Option<Step> {
    // The name's own stat first: a fresh lock (every live session's) costs
    // the GC this one call.
    let seen = sys::at_stamp(runtime.as_fd(), name).ok()?;
    // 이것을 실패시키는 것: 나이 확인을 지우는 것(만든 지 얼마 안 된 잠금도 회수됨).
    if now.saturating_sub(seen.ctime.0) < STALE_SECS {
        return None;
    }
    // 이것을 실패시키는 것: 자기 세션의 잠금을 건너뛰지 않는 것(24시간 넘은 세션이 자기 잠금을 지움).
    if mine(digest) {
        return None;
    }
    let lock = match take(runtime, me, name, Some(&seen))? {
        Taken::Held(lock) => lock,
        Taken::Busy => return Some(Step::Busy),
        Taken::Changed => return Some(Step::Kept),
    };
    let removed = sys::unlink_at(runtime.as_fd(), name).is_ok();
    drop(lock);
    Some(if removed { Step::Reclaimed } else { Step::Kept })
}

/// A parent in this process's own cgroup, not this session's: its lock is
/// taken (made when missing); a lock that was there must be stale. Removed
/// with its lock when empty; kept otherwise, with its lock unless this
/// sweep made it.
fn reclaim_parent(
    runtime: &File,
    cgroup: &File,
    me: u32,
    now: i64,
    parent: &OsStr,
    digest: &str,
    mine: &mut dyn FnMut(&str) -> bool,
) -> Option<Step> {
    // 이것을 실패시키는 것: 자기 세션의 부모를 건너뛰지 않는 것.
    if mine(digest) {
        return None;
    }
    let name = format!("{LOCK_PREFIX}{digest}{LOCK_SUFFIX}");
    let name = OsStr::new(&name);
    let seen = match sys::at_stamp(runtime.as_fd(), name) {
        Ok(seen) => Some(seen),
        Err(e) if e.kind() == io::ErrorKind::NotFound => None,
        Err(_) => return None,
    };
    // 이것을 실패시키는 것: 원래 있던 잠금의 나이를 보지 않는 것(살아 있는 쉬는 세션의 빈 부모가 지워짐).
    if seen
        .as_ref()
        .is_some_and(|s| now.saturating_sub(s.ctime.0) < STALE_SECS)
    {
        return None;
    }
    if seen.is_none() {
        // No lock here: the parent may be another runtime root's session's
        // (the digest covers the root too), whose round a lock made here
        // would not exclude. Only a parent made more than a day ago is
        // taken: cgroupfs never changes a folder's times after it is made
        // (observed 2026-11-09: mkdir and rmdir of a child, a write to its
        // cgroup.procs), so its ctime is when it was made.
        // 이것을 실패시키는 것: 잠금이 없을 때 부모의 나이를 보지 않는 것(다른 runtime 뿌리의 세션 부모가 회차 사이에
        // 지워짐).
        let made_at = sys::at_stamp(cgroup.as_fd(), parent).ok()?;
        if now.saturating_sub(made_at.ctime.0) < STALE_SECS {
            return None;
        }
        // Made here, exclusively: a round that made it first wins and this
        // parent waits for a later run.
        drop(sys::create_file_at(runtime.as_fd(), name, 0o600).ok()?);
    }
    let made = seen.is_none();
    let lock = match take(runtime, me, name, seen.as_ref())? {
        Taken::Held(lock) => lock,
        Taken::Busy => return Some(Step::Busy),
        Taken::Changed => return Some(Step::Kept),
    };
    // 이것을 실패시키는 것: 비지 않은 부모(남은 단위 cgroup)를 두고 잠금을 지우는 것, 방금 만든 잠금을 남기는 것.
    let step = match sys::remove_dir_at(cgroup.as_fd(), parent) {
        Ok(()) => Step::Reclaimed,
        Err(e) if e.kind() == io::ErrorKind::NotFound => Step::Reclaimed,
        Err(_) => Step::Kept,
    };
    if matches!(step, Step::Reclaimed) || made {
        let _ = sys::unlink_at(runtime.as_fd(), name);
    }
    drop(lock);
    Some(step)
}

enum Taken {
    Held(File),
    Busy,
    Changed,
}

/// Opens and locks `name` without blocking. With `seen`, the locked file
/// must be exactly the one stat'ed then, so its age still holds: a file put
/// under the name before the open (Linux may give it the freed inode
/// number) or one changed since (chmod moves its ctime) is `Changed`. The
/// whole stamp, ctime with nanoseconds included. `None`: not a lock file.
fn take(runtime: &File, me: u32, name: &OsStr, seen: Option<&sys::Stamp>) -> Option<Taken> {
    #[cfg(test)]
    BEFORE_OPEN.with(|hook| {
        if let Some(mut hook) = hook.borrow_mut().take() {
            hook();
        }
    });
    let file = sys::open_data_at_nofollow(runtime.as_fd(), name).ok()?;
    snapshot_store::check_data(&file, 0, me).ok()?;
    let name_str = name.to_str()?;
    #[cfg(test)]
    AFTER_OPEN.with(|hook| {
        if let Some(mut hook) = hook.borrow_mut().take() {
            hook();
        }
    });
    // A round holds its lock: the non-blocking lock fails and it stays.
    // 이것을 실패시키는 것: 잠금 없이 지우는 것(회차 중인 세션의 잠금과 부모가 지워짐).
    let Ok(lock) = sys::try_lock(file) else {
        return Some(Taken::Busy);
    };
    let lock = lock.into_inherited_file();
    // 이것을 실패시키는 것: 잠근 fd의 stamp를 처음 stat과 비교하지 않는 것
    // (a_name_replaced_before_the_open_is_kept, a_lock_changed_after_its_stat_is_kept).
    if let Some(seen) = seen
        && sys::file_stamp(&lock).ok()? != *seen
    {
        return Some(Taken::Changed);
    }
    // The name may have been replaced between the open and the lock (with
    // `seen`, the stamp above already differs: unlinking a name moves the
    // old file's ctime; a lock made here has no `seen`).
    // 이것을 실패시키는 것: 잠근 뒤 이름 재확인을 지우는 것(a_made_lock_replaced_after_the_open_is_kept).
    if snapshot_store::same_name(&lock, runtime.as_fd(), name_str).is_err() {
        return Some(Taken::Changed);
    }
    Some(Taken::Held(lock))
}

/// This process's own cgroup folder (Linux), for [`reclaim_stale`].
pub(crate) fn own_cgroup() -> Option<File> {
    #[cfg(target_os = "linux")]
    return super::command_cgroup::fs::open_own();
    #[cfg(not(target_os = "linux"))]
    None
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
        reclaim_stale(&runtime, sys::current_uid(), now, session, &mut || {
            File::open(&cgroup).ok()
        })
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
        // A start of 0 (now a multiple of 6): the free lock is the last name seen.
        let now = (ctime + STALE_SECS).div_euclid(6) * 6 + 6;
        let done = run(&s, now);
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

    // 시작 위치가 now로 돌아, 쥔 잠금 33개 뒤(정렬 순)의 오래된 잠금 셋도 실행을 거듭하면 모두 회수된다. 이것을
    // 실패시키는 것: 시작 위치를 now로 돌리지 않는 것(앞의 32개만 매번 봄).
    #[test]
    fn repeated_runs_reach_every_lock() {
        let s = Scratch::new("rotate");
        let mut ctime = 0;
        for i in 0..36 {
            ctime = ctime.max(lock(&s.runtime(), &digest(i)));
        }
        let _held: Vec<_> = (0..33).map(|i| hold(&s, &digest(i))).collect();
        for k in 0..36 {
            run(&s, ctime + STALE_SECS + k);
        }
        for i in 33..36 {
            assert!(!exists(&s.runtime(), &digest(i)), "{i}");
        }
    }

    // 목록은 최대 BLOCKS_MAX블록을 읽는다: 둘째 블록의 잠금은 회수되고, 다섯째 블록의 잠금은 보지 않는다. 이것을
    // 실패시키는 것: 첫 블록만 읽는 것, 블록 상한을 지우는 것.
    #[test]
    fn the_listing_reads_at_most_four_blocks() {
        let s = Scratch::new("blocks");
        let mut ctime = 0;
        for i in 0..5 {
            ctime = ctime.max(lock(&s.runtime(), &digest(i)));
        }
        let names: Vec<OsString> = (0..5)
            .map(|i| format!("command-{}.lock", digest(i)).into())
            .collect();
        let _reader = sys::FixtureDirectoryReader::install(Box::new(move |_, at| {
            let k = usize::try_from(at).unwrap();
            Ok(match names.get(k) {
                Some(n) => (at + 1, vec![n.clone()]),
                None => (at, Vec::new()),
            })
        }));
        let done = run(&s, ctime + STALE_SECS);
        assert!(done.contains(&Outcome::Reclaimed(digest(1))), "{done:?}");
        assert!(exists(&s.runtime(), &digest(4)), "{done:?}");
        assert!(!done.iter().any(|o| *o == Outcome::Reclaimed(digest(4))));
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

    // 연 뒤 이름이 다른 파일로 바뀌면 그 이름은 지우지 않는다. 이것을 실패시키는 것: 잠근 뒤 이름 재확인을 지우는
    // 것(바뀐 파일을 지움).
    #[test]
    fn a_name_replaced_after_the_open_is_kept() {
        let s = Scratch::new("swap");
        let ctime = lock(&s.runtime(), &digest(3));
        let path = s.runtime().join(format!("command-{}.lock", digest(3)));
        let swap = path.clone();
        AFTER_OPEN.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move || {
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
        assert!(found.is_some(), "this process's cgroup v2 folder");
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

    // 부모 회수(C 판정): 자기 cgroup 목록에서 찾는다. 잠금이 없는 빈 부모는 지우고 잠금을 남기지 않는다. 단위가 남은
    // 부모는 남고, 방금 만든 잠금은 지운다. 새 잠금(살아 있는 쉬는 세션)의 부모는 건드리지 않는다. 오래된 잠금과
    // 빈 부모는 둘 다 간다. 잠금이 없고 하루 안에 만든 부모(다른 runtime 뿌리의 세션)는 남는다. 이것을 실패시키는 것:
    // 부모를 지우지 않는 것, 비지 않은 부모를 지운 것으로 보는 것, 방금 만든 잠금을 남기는 것, 원래 있던 잠금의 나이를
    // 보지 않는 것, 잠금이 없을 때 부모의 나이를 보지 않는 것.
    #[test]
    fn parents_are_found_in_the_cgroup_listing() {
        let s = Scratch::new("parents");
        lock(&s.runtime(), &digest(3));
        lock(&s.runtime(), &digest(4));
        let empty = parent(&s, &digest(1), false);
        let busy = parent(&s, &digest(2), true);
        let alive = parent(&s, &digest(3), false);
        let old = parent(&s, &digest(4), false);
        std::thread::sleep(std::time::Duration::from_millis(1100));
        // digest 3's lock made again, as a new round would: one second
        // younger than the boundary while everything else is past it.
        let young = lock_again(&s.runtime(), &digest(3));
        let fresh = parent(&s, &digest(7), false);
        let done = run(&s, young + STALE_SECS - 1);
        assert!(
            done.contains(&Outcome::ParentReclaimed(digest(1))),
            "{done:?}"
        );
        assert!(!empty.exists() && !exists(&s.runtime(), &digest(1)));
        assert!(done.contains(&Outcome::ParentKept(digest(2))), "{done:?}");
        assert!(busy.exists() && !exists(&s.runtime(), &digest(2)));
        assert!(
            alive.exists() && exists(&s.runtime(), &digest(3)),
            "{done:?}"
        );
        assert!(
            done.contains(&Outcome::ParentReclaimed(digest(4))),
            "{done:?}"
        );
        assert!(!old.exists() && !exists(&s.runtime(), &digest(4)));
        // A parent made within the day with no lock here: another root's.
        assert!(
            fresh.exists() && !exists(&s.runtime(), &digest(7)),
            "{done:?}"
        );
    }

    /// The lock of `d` made again (a later ctime), as a new round would.
    fn lock_again(at: &Path, d: &str) -> i64 {
        std::fs::remove_file(at.join(format!("command-{d}.lock"))).unwrap();
        lock(at, d)
    }

    // 원래 있던 오래된 잠금과 단위가 남은 부모는 둘 다 남는다(잠금 회수가 먼저 닿지 않은 경우: 부모 회수만 부름).
    // 이것을 실패시키는 것: 부모를 지우지 못했을 때도 원래 있던 잠금을 지우는 것.
    #[test]
    fn a_kept_parent_keeps_the_lock_it_found() {
        let s = Scratch::new("parent-kept");
        let ctime = lock(&s.runtime(), &digest(5));
        let busy = parent(&s, &digest(5), true);
        let runtime = File::open(s.runtime()).unwrap();
        let cgroup = File::open(s.cgroup()).unwrap();
        let name = format!("bingsu-cmd-{}", digest(5));
        let step = reclaim_parent(
            &runtime,
            &cgroup,
            sys::current_uid(),
            ctime + STALE_SECS,
            OsStr::new(&name),
            &digest(5),
            &mut |_| false,
        );
        assert!(matches!(step, Some(Step::Kept)));
        assert!(busy.exists() && exists(&s.runtime(), &digest(5)));
    }

    // 부모 회수가 방금 만든 잠금(처음 stat이 없음)을 연 뒤 이름이 다른 파일로 바뀌면 그 파일도 부모도 지우지 않는다.
    // 이것을 실패시키는 것: 잠근 뒤 이름 재확인을 지우는 것(바뀐 파일을 지움; 잠금 회수에서는 stamp 비교도 잡음).
    #[test]
    fn a_made_lock_replaced_after_the_open_is_kept() {
        let s = Scratch::new("made-swap");
        let empty = parent(&s, &digest(8), false);
        let path = s.runtime().join(format!("command-{}.lock", digest(8)));
        let swap = path.clone();
        AFTER_OPEN.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move || {
                std::fs::remove_file(&swap).unwrap();
                std::fs::write(&swap, b"").unwrap();
            }))
        });
        let done = run(&s, now_secs() + STALE_SECS + 1);
        assert!(done.contains(&Outcome::ParentKept(digest(8))), "{done:?}");
        assert!(path.exists() && empty.exists());
    }

    // 회차가 쥔 잠금의 부모는 남는다. 자기 세션의 부모도 남는다. 이것을 실패시키는 것: 부모 회수에서 비차단 잠금
    // 실패를 무시하는 것, 자기 세션의 부모를 건너뛰지 않는 것.
    #[test]
    fn held_and_own_parents_stay() {
        use std::os::unix::fs::MetadataExt;
        let s = Scratch::new("parent-held");
        let root = std::fs::metadata(s.runtime()).unwrap();
        let session = b"0123456789abcdef0123456789abcdef";
        let own_name = lock_name(session, (root.dev(), root.ino()));
        let own = digest_of(OsStr::new(&own_name)).unwrap().to_owned();
        let ctime = lock(&s.runtime(), &digest(6));
        let held = parent(&s, &digest(6), false);
        let mine = parent(&s, &own, false);
        let _hold = hold(&s, &digest(6));
        let done = run_as(&s, ctime + STALE_SECS, Some(session));
        assert!(done.contains(&Outcome::ParentBusy(digest(6))), "{done:?}");
        assert!(held.exists() && mine.exists(), "{done:?}");
    }

    // 단위가 남은 부모 다섯이 상한(4)을 채워도 실행을 거듭하면 정렬 순 맨 뒤의 빈 부모가 회수된다. 이것을 실패시키는
    // 것: cgroup 목록의 시작 위치를 돌리지 않는 것.
    #[test]
    fn repeated_runs_reach_every_parent() {
        let s = Scratch::new("parent-rotate");
        for i in 0..5 {
            parent(&s, &digest(i), true);
        }
        let last = parent(&s, &digest(9), false);
        let now = now_secs() + STALE_SECS + 1;
        for k in 0..6 {
            run(&s, now + k);
        }
        assert!(!last.exists());
    }
}
