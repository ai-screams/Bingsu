//! Other sessions' leftovers in the runtime root (m6-C4a7): every shell
//! session that ran a command round leaves its lock `command-<digest>.lock`
//! and, on the Linux atomic path, its cgroup parent `bingsu-cmd-<digest>`
//! under the shell's cgroup. Nothing removed them. The collection GC now
//! reclaims a few each run: a lock older than [`STALE_SECS`] that no round
//! holds, with the parent of the same digest when that is empty.
//!
//! The lock and the parent share one digest (core `cgroup::parent_digest`
//! over the session and the runtime root), so holding a lock is owning the
//! parent: a round in progress holds its lock (the supervisor keeps a
//! duplicate until it is reaped), a reclaimer's non-blocking lock then
//! fails and it moves on. A live idle session that loses its lock and empty
//! parent makes both again on its next round.

use super::{snapshot_store, sys};
use std::{
    ffi::{OsStr, OsString},
    fs::File,
    os::fd::AsFd,
};

/// A lock unchanged this long is a candidate (ruling: 24 h by ctime). The
/// lock is never written, so its ctime is when it was made.
pub(crate) const STALE_SECS: i64 = 24 * 60 * 60;
/// Locks taken (reclaim tried) in one GC run, so the run's budget stays
/// bounded. A lock a round holds is not taken and does not count.
pub(crate) const RECLAIM_MAX: usize = 4;
/// Session lock names stat'ed in one GC run.
pub(crate) const EXAMINE_MAX: usize = 32;

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

/// What one candidate came to (tests read it).
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Outcome {
    Reclaimed(String),
    /// Locked here, but its parent could not be removed: counts against
    /// [`RECLAIM_MAX`].
    Kept(String),
    /// A round holds it: not taken, not counted.
    Busy(String),
}

/// Reclaims up to [`RECLAIM_MAX`] stale session locks in `runtime` (and on
/// Linux their empty cgroup parents under this process's own cgroup),
/// looking at no more than [`EXAMINE_MAX`] names. `now` is the wall clock in
/// seconds; `session` is this helper's own session, whose lock is never
/// reclaimed here (its round released it just before the GC); `own_cgroup`
/// opens this process's cgroup folder, at most once and only when a
/// candidate is reached. Every call goes through the collection GC's meter;
/// a refused charge ends the step. Returns what it did.
pub(crate) fn reclaim_stale(
    runtime: &File,
    me: u32,
    now: i64,
    session: Option<&[u8]>,
    own_cgroup: &mut dyn FnMut() -> Option<File>,
) -> Vec<Outcome> {
    let mut done = Vec::new();
    let Ok((_, names)) = sys::directory_batch(runtime.as_fd(), 0) else {
        return done;
    };
    let mut cgroup: Option<Option<File>> = None;
    let mut own: Option<Option<String>> = None;
    let mut names: Vec<OsString> = names
        .into_iter()
        .filter(|n| digest_of(n).is_some())
        .collect();
    names.sort();
    let mut taken = 0;
    // 이것을 실패시키는 것: 살펴보는 이름 수 상한을 지우는 것, 잡은 잠금 대신 결과마다(Busy 포함) 세는 것.
    for name in names.into_iter().take(EXAMINE_MAX) {
        if taken >= RECLAIM_MAX {
            break;
        }
        let digest = digest_of(&name).expect("filtered").to_owned();
        let mut mine = || {
            own.get_or_insert_with(|| {
                let at = sys::file_stamp(runtime).ok()?;
                let name = lock_name(session?, (at.dev, at.ino));
                digest_of(OsStr::new(&name)).map(str::to_owned)
            })
            .as_deref()
                == Some(digest.as_str())
        };
        let step = reclaim_one(
            runtime,
            me,
            now,
            &name,
            &digest,
            &mut mine,
            &mut cgroup,
            own_cgroup,
        );
        match step {
            Some(Step::Reclaimed) => done.push(Outcome::Reclaimed(digest)),
            Some(Step::Kept) => done.push(Outcome::Kept(digest)),
            Some(Step::Busy) => done.push(Outcome::Busy(digest)),
            None => {}
        }
        if matches!(step, Some(Step::Reclaimed | Step::Kept)) {
            taken += 1;
        }
    }
    done
}

enum Step {
    Reclaimed,
    Kept,
    Busy,
}

/// `None`: not a candidate (fresh, missing, this session's own or not a
/// lock file).
#[allow(clippy::too_many_arguments, reason = "one candidate's inputs")]
fn reclaim_one(
    runtime: &File,
    me: u32,
    now: i64,
    name: &OsStr,
    digest: &str,
    mine: &mut dyn FnMut() -> bool,
    cgroup: &mut Option<Option<File>>,
    own_cgroup: &mut dyn FnMut() -> Option<File>,
) -> Option<Step> {
    // The name's own stat first: a fresh lock (every live session's) costs
    // the GC this one call.
    let seen = sys::at_stamp(runtime.as_fd(), name).ok()?;
    // 이것을 실패시키는 것: 나이 확인을 지우는 것(만든 지 얼마 안 된 잠금도 회수됨).
    if now.saturating_sub(seen.ctime.0) < STALE_SECS {
        return None;
    }
    // 이것을 실패시키는 것: 자기 세션의 잠금을 건너뛰지 않는 것(24시간 넘은 세션이 자기 잠금과 부모를 지움).
    if mine() {
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
        return Some(Step::Busy);
    };
    let lock = lock.into_inherited_file();
    // The locked file is exactly the one stat'ed above, so its age still
    // holds: a file put under the name before the open (Linux may give it
    // the freed inode number) or one changed since (chmod moves its ctime)
    // is not reclaimed. The whole stamp, ctime with nanoseconds included.
    // 이것을 실패시키는 것: 잠근 fd의 stamp를 처음 stat과 비교하지 않는 것
    // (a_name_replaced_before_the_open_is_kept, a_lock_changed_after_its_stat_is_kept).
    if sys::file_stamp(&lock).ok()? != seen {
        return Some(Step::Kept);
    }
    // The name may have been replaced between the open and the lock.
    // 이것을 실패시키는 것: 잠근 뒤 이름 재확인을 지우는 것(바뀐 파일의 잠금으로 다른 이름을 지움).
    if snapshot_store::same_name(&lock, runtime.as_fd(), name_str).is_err() {
        return Some(Step::Kept);
    }
    if !remove_parent(digest, cgroup, own_cgroup) {
        return Some(Step::Kept);
    }
    let removed = sys::unlink_at(runtime.as_fd(), name).is_ok();
    drop(lock);
    Some(if removed { Step::Reclaimed } else { Step::Kept })
}

/// Removes the empty cgroup parent of `digest` under this process's own
/// cgroup; `true` when it is gone (removed now or never there). A parent
/// with a unit cgroup left (a supervisor that was killed) stays, and so
/// does its lock, for that session's own reclaim.
#[cfg(target_os = "linux")]
fn remove_parent(
    digest: &str,
    cgroup: &mut Option<Option<File>>,
    own_cgroup: &mut dyn FnMut() -> Option<File>,
) -> bool {
    let Some(own) = cgroup.get_or_insert_with(|| own_cgroup()) else {
        // No cgroup v2 folder of ours: nothing of this session's is there.
        return true;
    };
    let parent = format!("bingsu-cmd-{digest}");
    // 이것을 실패시키는 것: 비지 않은 부모(남은 단위 cgroup)를 두고 잠금만 지우는 것.
    match sys::remove_dir_at(own.as_fd(), OsStr::new(&parent)) {
        Ok(()) => true,
        Err(e) => e.kind() == std::io::ErrorKind::NotFound,
    }
}

/// macOS has no cgroups: only the lock goes.
#[cfg(not(target_os = "linux"))]
fn remove_parent(
    _digest: &str,
    _cgroup: &mut Option<Option<File>>,
    _own_cgroup: &mut dyn FnMut() -> Option<File>,
) -> bool {
    true
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
        let done = run(&s, ctime + STALE_SECS);
        assert_eq!(
            done.last(),
            Some(&Outcome::Reclaimed(digest(5))),
            "{done:?}"
        );
        assert!(!exists(&s.runtime(), &digest(5)));
    }

    // 한 번에 EXAMINE_MAX개 이름까지만 본다. 이것을 실패시키는 것: 살펴보는 이름 수 상한을 지우는 것.
    #[test]
    fn at_most_examine_max_names_a_run() {
        let s = Scratch::new("examine");
        let mut ctime = 0;
        for i in 0..=EXAMINE_MAX as u8 {
            ctime = ctime.max(lock(&s.runtime(), &digest(i)));
        }
        let _held: Vec<_> = (0..EXAMINE_MAX as u8)
            .map(|i| hold(&s, &digest(i)))
            .collect();
        let done = run(&s, ctime + STALE_SECS);
        assert_eq!(done.len(), EXAMINE_MAX, "{done:?}");
        assert!(exists(&s.runtime(), &digest(EXAMINE_MAX as u8)));
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
        use std::os::unix::fs::MetadataExt;
        let s = Scratch::new("chmod");
        let ctime = lock(&s.runtime(), &digest(7));
        let path = s.runtime().join(format!("command-{}.lock", digest(7)));
        let touched = path.clone();
        AFTER_OPEN.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move || {
                // A later second, so the new ctime is younger than the boundary.
                while std::fs::metadata(&touched).unwrap().ctime() == ctime {
                    std::thread::sleep(std::time::Duration::from_millis(50));
                    std::fs::set_permissions(
                        &touched,
                        std::os::unix::fs::PermissionsExt::from_mode(0o600),
                    )
                    .unwrap();
                }
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

    // Linux: 빈 부모는 잠금과 함께 지워지고, 단위가 남은 부모와 그 잠금은 남는다. 이것을 실패시키는 것: 부모를
    // 지우지 않는 것, 비지 않은 부모를 두고 잠금만 지우는 것.
    #[cfg(target_os = "linux")]
    #[test]
    fn the_parent_goes_with_its_lock_only_when_empty() {
        let s = Scratch::new("parent");
        let empty = digest(4);
        let busy = digest(5);
        let ctime = lock(&s.runtime(), &empty).max(lock(&s.runtime(), &busy));
        std::fs::create_dir(s.cgroup().join(format!("bingsu-cmd-{empty}"))).unwrap();
        std::fs::create_dir_all(
            s.cgroup()
                .join(format!("bingsu-cmd-{busy}/u0000000000000001")),
        )
        .unwrap();
        let mut done = run(&s, ctime + STALE_SECS);
        done.sort_by_key(|o| format!("{o:?}"));
        assert_eq!(
            done,
            [
                Outcome::Kept(busy.clone()),
                Outcome::Reclaimed(empty.clone())
            ]
        );
        assert!(!s.cgroup().join(format!("bingsu-cmd-{empty}")).exists());
        assert!(!exists(&s.runtime(), &empty));
        assert!(s.cgroup().join(format!("bingsu-cmd-{busy}")).exists());
        assert!(exists(&s.runtime(), &busy));
    }
}
