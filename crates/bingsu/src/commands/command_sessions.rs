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
/// Candidates tried in one GC run, so the run's budget stays bounded.
pub(crate) const RECLAIM_MAX: usize = 4;

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
    Kept(String),
}

/// Reclaims up to [`RECLAIM_MAX`] stale session locks in `runtime` (and on
/// Linux their empty cgroup parents under this process's own cgroup).
/// `now` is the wall clock in seconds; `own_cgroup` opens that folder, at
/// most once and only when a candidate is reached. Every call goes through
/// the collection GC's meter; a refused charge ends the step. Returns what
/// it did.
pub(crate) fn reclaim_stale(
    runtime: &File,
    me: u32,
    now: i64,
    own_cgroup: &mut dyn FnMut() -> Option<File>,
) -> Vec<Outcome> {
    let mut done = Vec::new();
    let Ok((_, names)) = sys::directory_batch(runtime.as_fd(), 0) else {
        return done;
    };
    let mut cgroup: Option<Option<File>> = None;
    let mut names: Vec<OsString> = names
        .into_iter()
        .filter(|n| digest_of(n).is_some())
        .collect();
    names.sort();
    for name in names {
        if done.len() >= RECLAIM_MAX {
            break;
        }
        let digest = digest_of(&name).expect("filtered").to_owned();
        match reclaim_one(runtime, me, now, &name, &digest, &mut cgroup, own_cgroup) {
            Some(true) => done.push(Outcome::Reclaimed(digest)),
            Some(false) => done.push(Outcome::Kept(digest)),
            None => {}
        }
    }
    done
}

/// `None`: not a candidate (fresh, missing or not a lock file). `Some`:
/// reclaimed or kept (held by a round, or its parent not removable).
fn reclaim_one(
    runtime: &File,
    me: u32,
    now: i64,
    name: &OsStr,
    digest: &str,
    cgroup: &mut Option<Option<File>>,
    own_cgroup: &mut dyn FnMut() -> Option<File>,
) -> Option<bool> {
    // The name's own stat first: a fresh lock (every live session's) costs
    // the GC this one call.
    let seen = sys::at_stamp(runtime.as_fd(), name).ok()?;
    // 이것을 실패시키는 것: 나이 확인을 지우는 것(만든 지 얼마 안 된 잠금도 회수됨).
    if now.saturating_sub(seen.ctime.0) < STALE_SECS {
        return None;
    }
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
        return Some(false);
    };
    let lock = lock.into_inherited_file();
    // The name may have been replaced between the open and the lock.
    // 이것을 실패시키는 것: 잠근 뒤 이름 재확인을 지우는 것(바뀐 파일의 잠금으로 다른 이름을 지움).
    if snapshot_store::same_name(&lock, runtime.as_fd(), name_str).is_err() {
        return Some(false);
    }
    if !remove_parent(digest, cgroup, own_cgroup) {
        return Some(false);
    }
    let removed = sys::unlink_at(runtime.as_fd(), name).is_ok();
    drop(lock);
    Some(removed)
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
        let runtime = File::open(s.runtime()).unwrap();
        let cgroup = s.cgroup();
        reclaim_stale(&runtime, sys::current_uid(), now, &mut || {
            File::open(&cgroup).ok()
        })
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
        assert_eq!(run(&s, ctime + STALE_SECS), [Outcome::Kept(digest(2))]);
        assert!(exists(&s.runtime(), &digest(2)));
        drop(held);
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
