//! posix_spawn with /dev/null stdin/stderr, optional stdout pipe, new
//! session, and every other fd closed in the child (spec section 4:
//! children never hold the shell's fds).
use std::ffi::CStr;
#[cfg(any(target_os = "macos", all(target_os = "linux", target_env = "gnu")))]
use std::ffi::c_char;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

#[cfg(all(target_os = "linux", target_env = "gnu"))]
const SETSID: libc::c_short = libc::POSIX_SPAWN_SETSID; // glibc <spawn.h> 0x80
#[cfg(target_os = "macos")]
const SETSID: libc::c_short = 0x0400; // <sys/spawn.h> POSIX_SPAWN_SETSID
#[cfg(target_os = "macos")]
const CLOEXEC_DEFAULT: libc::c_short = 0x4000; // <sys/spawn.h> POSIX_SPAWN_CLOEXEC_DEFAULT
#[cfg(target_os = "macos")]
const _: () = assert!(CLOEXEC_DEFAULT as libc::c_int == libc::POSIX_SPAWN_CLOEXEC_DEFAULT);

pub struct SpawnSpec<'a> {
    pub program: &'a CStr,
    pub argv: &'a [&'a CStr],
    pub env: Option<&'a [&'a CStr]>,
    pub new_session: bool,
    pub capture_stdout: bool,
}

pub struct Spawned {
    pub pid: libc::pid_t,
    pub stdout: Option<OwnedFd>,
}

#[cfg(any(target_os = "macos", all(target_os = "linux", target_env = "gnu")))]
fn check(rc: libc::c_int) -> io::Result<()> {
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(rc))
    }
}

#[cfg(any(target_os = "macos", all(target_os = "linux", target_env = "gnu")))]
unsafe extern "C" {
    static environ: *const *const c_char;
}

/// pipe with FD_CLOEXEC on both ends. Atomic on Linux (pipe2); on macOS the
/// fcntl follows immediately, which is enough in this single-threaded tool.
pub fn pipe_cloexec() -> io::Result<(OwnedFd, OwnedFd)> {
    let mut p = [-1 as libc::c_int; 2];
    #[cfg(target_os = "linux")]
    {
        // SAFETY: `p` is a two-element array for pipe2(2).
        if unsafe { libc::pipe2(p.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        // SAFETY: `p` is a two-element array for pipe(2).
        if unsafe { libc::pipe(p.as_mut_ptr()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        set_cloexec_pair(p)?;
    }
    // SAFETY: p[0] is open and owned by nobody else.
    let r = unsafe { OwnedFd::from_raw_fd(p[0]) };
    // SAFETY: p[1] is open and owned by nobody else.
    let w = unsafe { OwnedFd::from_raw_fd(p[1]) };
    Ok((r, w))
}

/// Sets FD_CLOEXEC on both ends; if either fails, closes both and returns
/// the error (no half-configured pipe escapes).
#[cfg(not(target_os = "linux"))]
fn set_cloexec_pair(p: [libc::c_int; 2]) -> io::Result<()> {
    for fd in p {
        // SAFETY: fcntl on a plain integer fd; failure is reported, not UB.
        if unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) } != 0 {
            let err = io::Error::last_os_error();
            for c in p {
                // SAFETY: closing fds this function owns; EBADF is harmless.
                unsafe { libc::close(c) };
            }
            return Err(err);
        }
    }
    Ok(())
}

/// A duplicate without FD_CLOEXEC (used by the fd-inventory test to prove
/// the child-side close works).
pub fn dup_inheritable(fd: &OwnedFd) -> io::Result<OwnedFd> {
    // SAFETY: dup takes an fd and returns a new one without FD_CLOEXEC.
    let n = unsafe { libc::dup(fd.as_raw_fd()) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `n` is a new descriptor owned by nobody else.
    Ok(unsafe { OwnedFd::from_raw_fd(n) })
}

/// dup2(fd, 1) for the writer-child probe.
pub fn dup_onto_stdout(fd: &OwnedFd) -> io::Result<()> {
    // SAFETY: dup2 takes two integers; fd 1 is replaced atomically.
    if unsafe { libc::dup2(fd.as_raw_fd(), 1) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

// Linux without glibc's posix_spawn closefrom (musl, the static user-run
// probes): this path is never used there; the caller records an `na` row.
#[cfg(all(target_os = "linux", not(target_env = "gnu")))]
pub fn spawn(_spec: &SpawnSpec<'_>) -> io::Result<Spawned> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "posix_spawn closefrom needs glibc >= 2.34",
    ))
}

#[cfg(any(target_os = "macos", all(target_os = "linux", target_env = "gnu")))]
pub fn spawn(spec: &SpawnSpec<'_>) -> io::Result<Spawned> {
    let pipe = if spec.capture_stdout {
        Some(pipe_cloexec()?)
    } else {
        None
    };
    // SAFETY: zeroed storage is what posix_spawn_file_actions_init initializes.
    let mut fa: libc::posix_spawn_file_actions_t = unsafe { std::mem::zeroed() };
    // SAFETY: zeroed storage is what posix_spawnattr_init initializes.
    let mut attr: libc::posix_spawnattr_t = unsafe { std::mem::zeroed() };
    // SAFETY: `fa` is valid storage for a file-actions object.
    check(unsafe { libc::posix_spawn_file_actions_init(&mut fa) })?;
    // SAFETY: `attr` is valid storage for an attributes object.
    if let Err(e) = check(unsafe { libc::posix_spawnattr_init(&mut attr) }) {
        // SAFETY: `fa` was initialized above and is not used again.
        unsafe { libc::posix_spawn_file_actions_destroy(&mut fa) };
        return Err(e);
    }
    // Every exit after both inits passes through the two destroys below.
    let rc = spawn_with(spec, &mut fa, &mut attr, pipe.as_ref().map(|(_, w)| w));
    // SAFETY: both objects were initialized above and are not used again.
    unsafe { libc::posix_spawn_file_actions_destroy(&mut fa) };
    // SAFETY: as above.
    unsafe { libc::posix_spawnattr_destroy(&mut attr) };
    let pid = rc?;
    // The parent's write end drops here; the child holds its own copy on fd 1.
    Ok(Spawned {
        pid,
        stdout: pipe.map(|(r, _w)| r),
    })
}

/// Fills the initialized `fa` and `attr` and spawns; the caller destroys them.
#[cfg(any(target_os = "macos", all(target_os = "linux", target_env = "gnu")))]
fn spawn_with(
    spec: &SpawnSpec<'_>,
    fa: &mut libc::posix_spawn_file_actions_t,
    attr: &mut libc::posix_spawnattr_t,
    stdout: Option<&OwnedFd>,
) -> io::Result<libc::pid_t> {
    let null = c"/dev/null";
    // SAFETY: `fa` was initialized; the path is NUL-terminated and outlives the call.
    check(unsafe {
        libc::posix_spawn_file_actions_addopen(fa, 0, null.as_ptr(), libc::O_RDONLY, 0)
    })?;
    match stdout {
        // SAFETY: `fa` was initialized; the write end stays open until after posix_spawn.
        Some(w) => check(unsafe { libc::posix_spawn_file_actions_adddup2(fa, w.as_raw_fd(), 1) })?,
        // SAFETY: as above.
        None => check(unsafe {
            libc::posix_spawn_file_actions_addopen(fa, 1, null.as_ptr(), libc::O_WRONLY, 0)
        })?,
    }
    // SAFETY: as above.
    check(unsafe {
        libc::posix_spawn_file_actions_addopen(fa, 2, null.as_ptr(), libc::O_WRONLY, 0)
    })?;
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    {
        // SAFETY: `fa` was initialized; closes every fd >= 3 in the child (glibc 2.34+).
        check(unsafe { libc::posix_spawn_file_actions_addclosefrom_np(fa, 3) })?;
    }
    let mut flags: libc::c_short = 0;
    if spec.new_session {
        flags |= SETSID;
    }
    #[cfg(target_os = "macos")]
    {
        flags |= CLOEXEC_DEFAULT;
    }
    // SAFETY: `attr` was initialized.
    check(unsafe { libc::posix_spawnattr_setflags(attr, flags) })?;
    let mut argv: Vec<*mut c_char> = spec.argv.iter().map(|a| a.as_ptr().cast_mut()).collect();
    argv.push(std::ptr::null_mut());
    let envv: Option<Vec<*mut c_char>> = spec.env.map(|e| {
        let mut v: Vec<*mut c_char> = e.iter().map(|a| a.as_ptr().cast_mut()).collect();
        v.push(std::ptr::null_mut());
        v
    });
    let envp: *const *mut c_char = match &envv {
        Some(v) => v.as_ptr(),
        // SAFETY: reading the process environment pointer; we do not mutate it.
        None => unsafe { environ }.cast(),
    };
    let mut pid: libc::pid_t = 0;
    // SAFETY: all pointers are valid, NUL-terminated and outlive the call.
    check(unsafe {
        libc::posix_spawn(
            &mut pid,
            spec.program.as_ptr(),
            fa,
            attr,
            argv.as_ptr(),
            envp,
        )
    })?;
    Ok(pid)
}

/// Blocks until one byte arrives (the child's "ready" byte).
pub fn read_byte(fd: &OwnedFd) -> io::Result<u8> {
    let mut b = [0u8; 1];
    loop {
        // SAFETY: `b` is one writable byte.
        let n = unsafe { libc::read(fd.as_raw_fd(), b.as_mut_ptr().cast(), 1) };
        match n {
            1 => return Ok(b[0]),
            0 => return Err(io::Error::from(io::ErrorKind::UnexpectedEof)),
            _ if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted => continue,
            _ => return Err(io::Error::last_os_error()),
        }
    }
}

pub fn reap(pid: libc::pid_t) -> io::Result<libc::c_int> {
    let mut status = 0;
    // SAFETY: `status` is a valid out-parameter; pid is our child.
    if unsafe { libc::waitpid(pid, &mut status, 0) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(status)
}

#[cfg(test)]
mod tests {
    use super::*;

    // 이것을 실패시키는 것: Linux에서 pipe2의 O_CLOEXEC를 빼거나, macOS에서 set_cloexec_pair 호출을 빼는 것.
    // (자식 쪽 closefrom·CLOEXEC_DEFAULT가 이 누락을 가리므로 spawn_fds 시험으로는 잡히지 않는다.)
    #[test]
    fn pipe_ends_are_cloexec() {
        let (r, w) = pipe_cloexec().unwrap();
        for fd in [r.as_raw_fd(), w.as_raw_fd()] {
            // SAFETY: querying the flags of a descriptor we own.
            let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
            assert_eq!(
                flags & libc::FD_CLOEXEC,
                libc::FD_CLOEXEC,
                "fd {fd} lacks FD_CLOEXEC"
            );
        }
    }

    // 이것을 실패시키는 것: fcntl 실패를 무시하거나, 실패 때 다른 한 끝을 열어 두는 것.
    #[cfg(not(target_os = "linux"))]
    #[test]
    fn cloexec_failure_closes_both_and_errors() {
        let mut p = [-1 as libc::c_int; 2];
        // SAFETY: `p` is a two-element array for pipe(2).
        assert_eq!(unsafe { libc::pipe(p.as_mut_ptr()) }, 0);
        // SAFETY: p[1] is ours; close it so the pair has one bad fd.
        unsafe { libc::close(p[1]) };
        assert!(set_cloexec_pair([p[0], 1_000_000]).is_err());
        // SAFETY: querying a descriptor number; -1 means it is closed.
        let flags = unsafe { libc::fcntl(p[0], libc::F_GETFD) };
        assert_eq!(flags, -1, "read end left open");
    }
}
