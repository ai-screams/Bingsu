//! The session's lock name and tag (`session_tag`, which names the macOS script
//! copies), the runtime root's identity, the neutral folder, the cgroup reclaim
//! and the macOS `nofollow_any` probe: what a round needs from the runtime root
//! before it spawns.
use super::*;

/// The first 16 bytes of sha256(session), hex: names the session's script
/// copies (macOS), never the raw session value.
#[cfg(target_os = "macos")]
pub(super) fn session_tag(session: &[u8]) -> String {
    bingsu_core::command::cgroup::session_digest(session)
}

/// The session lock's name, by the session's cgroup parent digest over the
/// runtime root's `(dev, ino)` (command_sessions, m6-C4a7).
pub(super) fn lock_name(session: &[u8], root: (u64, u64)) -> String {
    super::super::command_sessions::lock_name(session, root)
}

/// The runtime root's `(dev, ino)`: read once a round, before the session
/// lock, for the lock's name and the cgroup parent's.
pub(super) fn root_id(i: &Inputs<'_>) -> Option<(u64, u64)> {
    sys::fd_facts(i.runtime.as_fd())
        .ok()
        .map(|f| (f.dev, f.ino))
}

/// The neutral folder (spec: an empty private folder): made 0500 when
/// missing, so read and search work and nothing can be written in it, by
/// a unit either. One that is there must be empty, the user's and exactly
/// 0500; otherwise `neutral` units do not run this round. It is never
/// repaired or emptied.
pub(super) fn neutral(runtime: &File, me: u32) -> Result<bool, StoreError> {
    let name = OsStr::new(NEUTRAL);
    let made = sys::mkdir_at(runtime.as_fd(), name, 0o500)?;
    let dir = sys::open_dir_at_nofollow(runtime.as_fd(), name)?;
    // Only a folder this call made is set (a umask can take bits from it).
    if made {
        use std::os::unix::fs::PermissionsExt;
        dir.set_permissions(std::fs::Permissions::from_mode(0o500))?;
    }
    let facts = sys::fd_facts(dir.as_fd())?;
    Ok(facts.uid == me
        && facts.mode & 0o7777 == 0o500
        && sys::directory_names(dir.as_fd())?.is_empty())
}

/// Under the session lock no supervisor of the session is alive: whatever
/// its cgroup parent holds is left over. The
/// parent, for the round's supervisor, and the reclaim's log lines.
#[cfg(target_os = "linux")]
pub(super) fn session_reclaim(
    i: &Inputs<'_>,
    session: &[u8],
    root: (u64, u64),
) -> (
    Option<super::super::command_cgroup::fs::Dir>,
    Vec<&'static str>,
) {
    let mut cgroup =
        super::super::command_cgroup::fs::open_session(&super::super::command_cgroup::fs::Who {
            session,
            runtime: root,
            me: i.me,
            pid: std::process::id(),
        });
    let mut notes = Vec::new();
    if let Some(parent) = &mut cgroup {
        let r = super::super::command_cgroup::reclaim(
            &mut super::super::command_cgroup::fs::Fs,
            parent,
        );
        notes.extend(r.messages());
    }
    (cgroup, notes)
}

/// The behavior probe for `AT_SYMLINK_NOFOLLOW_ANY` on `path`: the result
/// of `fstatat` (0 or its errno).
#[cfg(target_os = "macos")]
pub(super) fn probe_nofollow_any(path: &std::ffi::CStr) -> i32 {
    // SAFETY: an all-zero stat is a valid out-parameter value.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: fixed NUL-terminated path, writable `st`.
    let rc = unsafe {
        libc::fstatat(
            libc::AT_FDCWD,
            path.as_ptr(),
            &mut st,
            sys::AT_SYMLINK_NOFOLLOW_ANY,
        )
    };
    if rc == 0 {
        0
    } else {
        std::io::Error::last_os_error().raw_os_error().unwrap_or(-1)
    }
}

/// Whether the probes say the flag works both ways: "/" (no symlink) is
/// found, and `/var/empty` (through the `/var -> private/var` link) is
/// refused with ELOOP. EINVAL is a macOS without the flag; a flag that is
/// accepted but not enforced passes "/" and fails the link.
#[cfg(target_os = "macos")]
pub(super) fn nofollow_any(root: i32, link: i32) -> bool {
    root == 0 && link == libc::ELOOP
}
