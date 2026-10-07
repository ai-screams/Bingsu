//! fd 1/2 juggling and the write-only child spawn for the writer-order
//! measurement (spec section 4 side-effect rules: release the shell's pipe
//! first, new session, the child holds no fd other than 0-2).
//!
//! fds 0-2 are never closed here, only replaced with dup2 (std treats them
//! as open for the whole process). Callers must be single-threaded, as for
//! `spawn::spawn`: another thread writing to fd 1 or 2 would see them move.
use super::spawn::SpawnSpec;
use std::io;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};

#[cfg(target_os = "macos")]
unsafe extern "C" {
    // <spawn.h>; not in the libc crate 0.2.190 (checked 2026-10-07).
    fn posix_spawn_file_actions_addinherit_np(
        fa: *mut libc::posix_spawn_file_actions_t,
        fd: libc::c_int,
    ) -> libc::c_int;
}

/// Copies of fds 1 and 2, owned and close-on-exec, so they never leak into
/// a child and are closed when dropped.
pub struct Saved(OwnedFd, OwnedFd);

impl Saved {
    /// The two descriptor numbers (for the fd-inventory probe).
    pub fn raw(&self) -> [RawFd; 2] {
        [self.0.as_raw_fd(), self.1.as_raw_fd()]
    }

    /// The saved copy of fd 2: where a message can still go while fd 2
    /// points at /dev/null.
    pub fn stderr(&self) -> BorrowedFd<'_> {
        self.1.as_fd()
    }
}

fn owned(n: libc::c_int) -> io::Result<OwnedFd> {
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `n` is a descriptor the caller just made and nobody else owns.
    Ok(unsafe { OwnedFd::from_raw_fd(n) })
}

fn dup_cloexec(fd: RawFd) -> io::Result<OwnedFd> {
    // SAFETY: F_DUPFD_CLOEXEC on a plain integer returns a new fd >= 3 with
    // FD_CLOEXEC set, or -1 and errno.
    owned(unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 3) })
}

pub fn save_stdout_stderr() -> io::Result<Saved> {
    Ok(Saved(dup_cloexec(1)?, dup_cloexec(2)?))
}

fn dup2(from: RawFd, to: RawFd) -> io::Result<()> {
    // SAFETY: dup2 on plain integers; `to` is 1 or 2, which is replaced in
    // one step and never left closed. Failure is reported through errno.
    if unsafe { libc::dup2(from, to) } < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Points fd 1 at `out` and fd 2 at `err`, checking each dup2. If the second
/// fails after the first succeeded, fd 1 is put back to `undo_1`; if that
/// undo fails as well, its error is returned and fd 1 stays at `out` (the
/// caller sees the failure either way). `dup2` is a parameter so the
/// rollback can be tested without breaking real descriptors.
fn point_1_and_2(
    out: RawFd,
    err: RawFd,
    undo_1: Option<RawFd>,
    mut dup2: impl FnMut(RawFd, RawFd) -> io::Result<()>,
) -> io::Result<()> {
    dup2(out, 1)?;
    if let Err(e) = dup2(err, 2) {
        if let Some(u) = undo_1 {
            dup2(u, 1)?;
        }
        return Err(e);
    }
    Ok(())
}

pub fn restore_stdout_stderr(s: &Saved) -> io::Result<()> {
    point_1_and_2(s.0.as_raw_fd(), s.1.as_raw_fd(), None, dup2)
}

/// Spec section 4: release the shell's pipe before spawning. Every step is
/// checked and any failure is returned; the caller must not spawn then. fds
/// 1/2 are what they were unless the undo of fd 1 failed too (see
/// `point_1_and_2`).
pub fn redirect_stdout_stderr_to_null(saved: &Saved) -> io::Result<()> {
    redirect_with(open_dev_null, saved.0.as_raw_fd(), dup2)
}

fn open_dev_null() -> io::Result<OwnedFd> {
    // SAFETY: the path is NUL-terminated; no O_CREAT, so no mode argument.
    owned(unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_WRONLY | libc::O_CLOEXEC) })
}

fn redirect_with(
    open: impl FnOnce() -> io::Result<OwnedFd>,
    saved_1: RawFd,
    dup2: impl FnMut(RawFd, RawFd) -> io::Result<()>,
) -> io::Result<()> {
    let null = open()?;
    point_1_and_2(null.as_raw_fd(), null.as_raw_fd(), Some(saved_1), dup2)
}

/// The write-only child takes a new session and none of the pipes `spawn`
/// can set up: anything else is a caller error, refused before spawning.
fn check_writer_spec(spec: &SpawnSpec<'_>) -> io::Result<()> {
    if spec.new_session && !spec.capture_stdout {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "a writer child needs new_session and no captured stdout",
        ))
    }
}

// Linux without glibc's posix_spawn closefrom (musl, the static user-run
// probes): this path is never used there; the caller records an `na` row.
#[cfg(all(target_os = "linux", not(target_env = "gnu")))]
pub fn spawn_writer_child(spec: &SpawnSpec<'_>) -> io::Result<libc::pid_t> {
    check_writer_spec(spec)?;
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "posix_spawn closefrom needs glibc >= 2.34",
    ))
}

/// The write-only child (spec section 4): inherits whatever fds 0-2 are
/// now, starts a new session and holds no other fd (Linux closefrom 3,
/// macOS CLOEXEC_DEFAULT with 0-2 inherited explicitly), through the same
/// posix_spawn path as `spawn::spawn`.
#[cfg(any(target_os = "macos", all(target_os = "linux", target_env = "gnu")))]
pub fn spawn_writer_child(spec: &SpawnSpec<'_>) -> io::Result<libc::pid_t> {
    check_writer_spec(spec)?;
    super::spawn::spawn_with_objects(spec, |_fa| {
        #[cfg(target_os = "macos")]
        for fd in 0..3 {
            // SAFETY: `_fa` was initialized; keeps fd open across CLOEXEC_DEFAULT.
            super::spawn::check(unsafe { posix_spawn_file_actions_addinherit_np(_fa, fd) })?;
        }
        Ok(())
    })
}

/// Every open fd >= 3 (read from the kernel's own list, so no scan limit
/// can hide a high fd) and this process's session id. Any error while
/// listing or checking is returned, never skipped.
pub fn open_fds_and_sid() -> io::Result<(Vec<RawFd>, libc::pid_t)> {
    #[cfg(target_os = "linux")]
    let dir = "/proc/self/fd";
    #[cfg(not(target_os = "linux"))]
    let dir = "/dev/fd";
    let names = std::fs::read_dir(dir)?.map(|e| e.map(|e| e.file_name()));
    let open = still_open(names, |fd| {
        // SAFETY: F_GETFD only queries the descriptor table.
        let rc = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        getfd_result(rc, io::Error::last_os_error())
    })?;
    // SAFETY: getsid(0) asks about the calling process, which always
    // exists and is in a session, so it cannot fail.
    let sid = unsafe { libc::getsid(0) };
    Ok((open, sid))
}

/// F_GETFD outcome: open, closed (only a confirmed EBADF), or an error.
fn getfd_result(rc: libc::c_int, err: io::Error) -> io::Result<bool> {
    if rc >= 0 {
        Ok(true)
    } else if err.raw_os_error() == Some(libc::EBADF) {
        Ok(false)
    } else {
        Err(err)
    }
}

/// Parses the fd directory entries (every name must be a decimal fd) and
/// keeps those still open once the listing itself is closed.
fn still_open(
    names: impl Iterator<Item = io::Result<std::ffi::OsString>>,
    is_open: impl Fn(RawFd) -> io::Result<bool>,
) -> io::Result<Vec<RawFd>> {
    let mut listed = Vec::new();
    for name in names {
        let name = name?;
        let fd = name
            .to_str()
            .filter(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()))
            .and_then(|s| s.parse::<RawFd>().ok())
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("unexpected fd entry {name:?}"),
                )
            })?;
        if fd >= 3 {
            listed.push(fd);
        }
    }
    // The iterator (and the directory fd it held) is gone now.
    let mut open = Vec::new();
    for fd in listed {
        if is_open(fd)? {
            open.push(fd);
        }
    }
    open.sort_unstable();
    Ok(open)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    fn fake(
        fail_at: usize,
        log: &RefCell<Vec<(RawFd, RawFd)>>,
    ) -> impl FnMut(RawFd, RawFd) -> io::Result<()> + '_ {
        let mut n = 0;
        move |from, to| {
            n += 1;
            if n == fail_at {
                return Err(io::Error::from_raw_os_error(libc::EBADF));
            }
            log.borrow_mut().push((from, to));
            Ok(())
        }
    }

    fn names(items: Vec<io::Result<&str>>) -> impl Iterator<Item = io::Result<std::ffi::OsString>> {
        items.into_iter().map(|r| r.map(std::ffi::OsString::from))
    }

    // 이것을 실패시키는 것: 목록 읽기 오류를 삼키는 것(filter_map), 숫자가 아닌 이름을 건너뛰는 것,
    // EBADF가 아닌 fcntl 오류를 "닫힘"으로 보는 것, 0–2를 목록에 넣는 것.
    #[test]
    fn fd_inventory_propagates_every_error() {
        let all_open = |_| Ok(true);
        assert!(
            still_open(
                names(vec![Ok("3"), Err(io::Error::other("readdir failed"))]),
                all_open
            )
            .is_err()
        );
        for bad in ["x", "", "-1", "3a", "+3"] {
            let e = still_open(names(vec![Ok(bad)]), all_open).unwrap_err();
            assert_eq!(e.kind(), io::ErrorKind::InvalidData, "{bad:?}");
        }
        {
            use std::os::unix::ffi::OsStringExt;
            let raw = std::iter::once(Ok(std::ffi::OsString::from_vec(vec![0xff])));
            assert!(still_open(raw, all_open).is_err());
        }
        let eio = |fd| {
            if fd == 5 {
                Err(io::Error::from_raw_os_error(libc::EIO))
            } else {
                Ok(true)
            }
        };
        assert!(still_open(names(vec![Ok("4"), Ok("5")]), eio).is_err());
        let ebadf_4 = |fd| Ok(fd != 4);
        let got = still_open(
            names(vec![Ok("0"), Ok("2"), Ok("7"), Ok("4"), Ok("3")]),
            ebadf_4,
        );
        assert_eq!(got.unwrap(), [3, 7]);
    }

    // 이것을 실패시키는 것: EBADF 말고도 fcntl 실패를 모두 "닫힘"으로 보는 것.
    #[test]
    fn only_ebadf_means_closed() {
        assert!(getfd_result(1, io::Error::from_raw_os_error(0)).unwrap());
        assert!(!getfd_result(-1, io::Error::from_raw_os_error(libc::EBADF)).unwrap());
        assert!(getfd_result(-1, io::Error::from_raw_os_error(libc::EINVAL)).is_err());
    }

    // 이것을 실패시키는 것: 새 세션이 아니거나 stdout 파이프를 달라는 spec으로 쓰기 자식을 띄우는 것.
    #[test]
    fn writer_spec_needs_new_session_and_no_pipe() {
        let p = c"/usr/bin/true";
        let argv = [p];
        let spec = |new_session, capture_stdout| SpawnSpec {
            program: p,
            argv: &argv,
            env: None,
            new_session,
            capture_stdout,
        };
        assert!(check_writer_spec(&spec(true, false)).is_ok());
        for (n, c) in [(false, false), (true, true)] {
            let e = check_writer_spec(&spec(n, c)).unwrap_err();
            assert_eq!(e.kind(), io::ErrorKind::InvalidInput, "{n} {c}");
        }
    }

    // 이것을 실패시키는 것: 두 번째 dup2 실패를 무시하거나, fd 1을 /dev/null에 둔 채 돌아가는 것.
    #[test]
    fn second_dup2_failure_rolls_back_fd1() {
        let log = RefCell::new(Vec::new());
        assert!(point_1_and_2(10, 10, Some(20), fake(2, &log)).is_err());
        assert_eq!(*log.borrow(), [(10, 1), (20, 1)]);
    }

    // 이것을 실패시키는 것: /dev/null을 열지 못했는데 dup2로 넘어가는 것.
    #[test]
    fn open_failure_touches_no_fd() {
        let log = RefCell::new(Vec::new());
        let r = redirect_with(
            || Err(io::Error::from_raw_os_error(libc::EMFILE)),
            20,
            fake(0, &log),
        );
        assert!(r.is_err());
        assert!(log.borrow().is_empty());
    }

    // 이것을 실패시키는 것: 첫 dup2 실패 뒤에도 fd 2를 바꾸는 것.
    #[test]
    fn first_dup2_failure_changes_nothing() {
        let log = RefCell::new(Vec::new());
        assert!(point_1_and_2(10, 10, Some(20), fake(1, &log)).is_err());
        assert!(log.borrow().is_empty());
    }
}
