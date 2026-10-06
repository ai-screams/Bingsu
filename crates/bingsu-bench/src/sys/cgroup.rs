//! clone3(CLONE_INTO_CGROUP | CLONE_PIDFD): the child starts inside the
//! cgroup, so no fork can escape before a move (spec section 4 deadline
//! order 4). Measured in M1 for M6 command processes.
use std::ffi::{CStr, c_char};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

const CLONE_INTO_CGROUP: u64 = 0x2_0000_0000; // <linux/sched.h>

/// `struct clone_args` from <linux/sched.h> (CLONE_ARGS_SIZE_VER2, 88 bytes).
#[repr(C)]
#[derive(Default)]
struct CloneArgs {
    flags: u64,
    pidfd: u64,
    child_tid: u64,
    parent_tid: u64,
    exit_signal: u64,
    stack: u64,
    stack_size: u64,
    tls: u64,
    set_tid: u64,
    set_tid_size: u64,
    cgroup: u64,
}

const _: () = assert!(std::mem::size_of::<CloneArgs>() == 88);

/// `argv` must not be empty and `stdout_w`/`devnull` must be 3 or above
/// (dup2 onto 0..=2 would otherwise overwrite one with the other); either
/// is `InvalidInput` before any process exists. The NULL-terminated arrays
/// execve needs are built here, before the clone.
///
/// The child is a copy of this process (no CLONE_VM) and makes only
/// async-signal-safe calls before execve. It puts `devnull` on fds 0 and 2 and `stdout_w` on 1,
/// starts a new session, closes every fd >= 3 with close_range (Linux 5.9),
/// and exits 126 if any of those steps fails, 127 if execve fails.
pub fn spawn_in_cgroup(
    cgroup: &OwnedFd,
    program: &CStr,
    argv: &[&CStr],
    envp: &[&CStr],
    stdout_w: RawFd,
    devnull: RawFd,
) -> io::Result<(libc::pid_t, OwnedFd)> {
    if argv.is_empty() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "empty argv"));
    }
    if stdout_w < 3 || devnull < 3 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "stdout_w and devnull must not be stdio fds",
        ));
    }
    let nul_ended = |v: &[&CStr]| -> Vec<*const c_char> {
        v.iter()
            .map(|s| s.as_ptr())
            .chain([std::ptr::null()])
            .collect()
    };
    let (argv, envp) = (nul_ended(argv), nul_ended(envp));
    let mut pidfd: libc::c_int = -1;
    let args = CloneArgs {
        flags: CLONE_INTO_CGROUP | libc::CLONE_PIDFD as u64,
        pidfd: std::ptr::addr_of_mut!(pidfd) as u64,
        exit_signal: libc::SIGCHLD as u64,
        cgroup: cgroup.as_raw_fd() as u64,
        ..CloneArgs::default()
    };
    // SAFETY: `args` is a valid clone_args of the size passed; without
    // CLONE_VM the child gets its own copy of this stack. See the doc
    // comment for the child-side rules.
    let pid = unsafe {
        libc::syscall(
            libc::SYS_clone3,
            std::ptr::addr_of!(args),
            std::mem::size_of::<CloneArgs>(),
        )
    };
    if pid < 0 {
        return Err(io::Error::last_os_error());
    }
    if pid == 0 {
        child(program, &argv, &envp, stdout_w, devnull);
    }
    // SAFETY: on success the kernel stored a new pidfd (O_CLOEXEC) that
    // nobody else owns.
    Ok((pid as libc::pid_t, unsafe { OwnedFd::from_raw_fd(pidfd) }))
}

/// The child side of `spawn_in_cgroup`; never returns.
fn child(
    program: &CStr,
    argv: &[*const c_char],
    envp: &[*const c_char],
    stdout_w: RawFd,
    devnull: RawFd,
) -> ! {
    for (from, to) in [(devnull, 0), (stdout_w, 1), (devnull, 2)] {
        // SAFETY: dup2 is async-signal-safe and takes plain fd numbers.
        if unsafe { libc::dup2(from, to) } < 0 {
            // SAFETY: _exit is async-signal-safe.
            unsafe { libc::_exit(126) };
        }
    }
    // A new child is never a process group leader, so setsid cannot fail.
    // SAFETY: setsid is async-signal-safe.
    unsafe { libc::setsid() };
    let (first, last, flags): (libc::c_uint, libc::c_uint, libc::c_uint) = (3, !0, 0);
    // SAFETY: close_range takes three unsigned ints; it closes 3..=~0.
    if unsafe { libc::syscall(libc::SYS_close_range, first, last, flags) } != 0 {
        // SAFETY: as above.
        unsafe { libc::_exit(126) };
    }
    // SAFETY: argv/envp are NULL-terminated arrays (built in
    // spawn_in_cgroup) of pointers into `&CStr`s that outlive the call.
    unsafe { libc::execve(program.as_ptr(), argv.as_ptr(), envp.as_ptr()) };
    // SAFETY: as above.
    unsafe { libc::_exit(127) }
}
