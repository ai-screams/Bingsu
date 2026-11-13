//! One relay spawn for the command supervisor (spec section 4 "user command
//! execution model", row input and output). The relay's permit and exec frame
//! are written into an empty channel (a pipe; on macOS a socket pair) before
//! the spawn, so a relay that never reads cannot hold the supervisor. The relay always gets descriptors 0, 1
//! and 2 from the spawn actions, whatever the supervisor holds there: 0 is
//! `/dev/null`, 1 the stdout pipe, 2 the status pipe, 3 its input; nothing
//! else crosses (the supervisor's own descriptors are close-on-exec, and
//! macOS spawns with `POSIX_SPAWN_CLOEXEC_DEFAULT`). The environment is empty
//! and the spawn happens in "/"; the relay enters the unit's folder.
use super::collector_process::{OwnedChild, now_ns, pipe};
use std::{
    ffi::{CStr, CString},
    fs::File,
    io,
    os::fd::{AsRawFd, FromRawFd},
};

/// A running relay and the supervisor's ends of its pipes.
pub(crate) struct Spawned {
    pub child: OwnedChild,
    /// Non-blocking read end of the relay's (then the target's) stdout.
    pub stdout: File,
    /// Non-blocking read end of the relay's status pipe: a byte is the
    /// relay's refusal code, end of file without one means the target was
    /// executed (the write end is close-on-exec in the relay).
    pub status: File,
}

fn check(rc: i32) -> io::Result<()> {
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(rc))
    }
}

/// The channel for a relay's input, `(read, write)`, both close-on-exec. On
/// Linux a pipe. On macOS a Unix stream socket pair whose write end's send
/// buffer is set to `INPUT_BUFFER`: a pipe there can be as small as 512 bytes
/// when the kernel is short of pipe memory, and the input is written whole
/// before the relay starts, so it must fit. A refused buffer size is left as
/// the kernel's, so an input that does not fit is refused, never waited for.
fn input_ends() -> io::Result<(File, File)> {
    #[cfg(not(target_os = "macos"))]
    return pipe();
    #[cfg(target_os = "macos")]
    {
        let mut fds = [-1; 2];
        // SAFETY: two writable ints for the new descriptors.
        let rc = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr()) };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: both descriptors are newly owned and transferred once.
        let read = unsafe { File::from_raw_fd(fds[0]) };
        // SAFETY: the second newly owned descriptor.
        let write = unsafe { File::from_raw_fd(fds[1]) };
        for file in [&read, &write] {
            // SAFETY: live private fd; no unrelated open-file description is changed.
            if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
                return Err(io::Error::last_os_error());
            }
        }
        // SAFETY: the write end made above; reads `INPUT_BUFFER` for its size.
        let _ = unsafe {
            libc::setsockopt(
                write.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_SNDBUF,
                (&INPUT_BUFFER as *const libc::c_int).cast(),
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        Ok((read, write))
    }
}

/// The send buffer of the input socket on macOS: twice the largest input, for
/// the kernel's per-message overhead.
#[cfg(target_os = "macos")]
const INPUT_BUFFER: libc::c_int = 2 * bingsu_core::handoff::RELAY_INPUT_MAX as libc::c_int;

/// Spawns `exe` with `args` (argv[0] included) in "/", `input` on
/// descriptor 3. `input` must fit one write into the empty input channel
/// (`input_ends`); a shorter write is an error and nothing is spawned. The relay enters the unit's
/// folder itself: a chdir here would run in the spawn and hold the
/// supervisor on a stopped mount.
///
/// With `cgroup` (Linux, the atomic path) the relay starts inside that
/// cgroup through `clone3(CLONE_INTO_CGROUP)`, so what it forks starts
/// inside it too; only a descendant that cooperates stays there (one may
/// move itself to another cgroup it can write). On any error nothing was
/// spawned.
pub(crate) fn spawn(
    exe: &CStr,
    args: &[Vec<u8>],
    input: &[u8],
    expires_ns: u64,
    go: &dyn Fn() -> bool,
    cgroup: Option<std::os::fd::BorrowedFd<'_>>,
) -> io::Result<Spawned> {
    #[cfg(test)]
    PREPARE.with(|hook| {
        if let Some(hook) = hook.borrow_mut().as_mut() {
            hook();
        }
    });
    let (input_read, input_write) = input_ends()?;
    super::collector_process::nonblocking(&input_write)?;
    // SAFETY: `input` is readable for its length; the pipe is empty.
    let n = unsafe { libc::write(input_write.as_raw_fd(), input.as_ptr().cast(), input.len()) };
    if usize::try_from(n).ok() != Some(input.len()) {
        return Err(io::Error::other(
            "relay input did not fit the input channel",
        ));
    }
    drop(input_write);
    let (stdout, stdout_write) = pipe()?;
    let (status, status_write) = pipe()?;
    super::collector_process::nonblocking(&stdout)?;
    super::collector_process::nonblocking(&status)?;
    // The supervisor's own descriptors are close-on-exec, so nothing but
    // these crosses.
    #[cfg(target_os = "linux")]
    if let Some(cgroup) = cgroup {
        let child = clone_into(
            exe,
            args,
            &[(&stdout_write, 1), (&status_write, 2), (&input_read, 3)],
            Some(cgroup),
            expires_ns,
            go,
        )?;
        return Ok(Spawned {
            child,
            stdout,
            status,
        });
    }
    #[cfg(not(target_os = "linux"))]
    let _ = cgroup;
    // The best-effort path: the relay leads its own process group, so its
    // reap's `killpg` reaches what the target forks without a new session.
    let (child, _) = spawn_with(
        exe,
        args,
        &[(0, libc::O_RDONLY)],
        &[(&stdout_write, 1), (&status_write, 2), (&input_read, 3)],
        c"/",
        false,
        true,
        expires_ns,
        go,
    )?;
    Ok(Spawned {
        child,
        stdout,
        status,
    })
}

/// The supervisor itself, from the helper (`args`: the binary and
/// `__command-v1`): 0 to 2 `/dev/null`, then the grant pipe's read end, the
/// result pipe's write end and the lock copy at 3, 4 and 5, and on the
/// atomic path the session's cgroup parent at 6, in folder "/".
/// Every other helper descriptor is closed.
pub(crate) fn spawn_supervisor(
    exe: &CStr,
    args: &[Vec<u8>],
    grant: &File,
    results: &File,
    lock: &File,
    cgroup: Option<&File>,
    expires_ns: u64,
) -> io::Result<OwnedChild> {
    let mut dups = vec![(grant, 3), (results, 4), (lock, 5)];
    dups.extend(cgroup.map(|c| (c, 6)));
    spawn_with(
        exe,
        args,
        &[
            (0, libc::O_RDONLY),
            (1, libc::O_WRONLY),
            (2, libc::O_WRONLY),
        ],
        &dups,
        c"/",
        true,
        false,
        expires_ns,
        &|| true,
    )
    .map(|(child, _)| child)
}

#[cfg(all(test, target_os = "linux"))]
thread_local! {
    /// Per clone3 call, in order: an errno to fail with instead (tests only).
    pub(crate) static CLONE3_ERRORS: std::cell::RefCell<std::collections::VecDeque<Option<i32>>> =
        const { std::cell::RefCell::new(std::collections::VecDeque::new()) };
}

#[cfg(test)]
thread_local! {
    /// Runs at the start of a relay spawn's preparation (tests only).
    pub(crate) static PREPARE: std::cell::RefCell<Option<Box<dyn FnMut()>>> =
        const { std::cell::RefCell::new(None) };
}

/// One `posix_spawn` with an empty environment and default signals: `nulls`
/// open `/dev/null` at a number, `dups` move a source to a number (sources
/// are first moved above every target), the child starts in `cwd`. With
/// `close_rest` (Linux) every other open descriptor is closed in the child;
/// macOS always spawns with `POSIX_SPAWN_CLOEXEC_DEFAULT`. With `own_group`
/// (a best-effort relay) the child leads a new process group, which its
/// reap ends with `killpg` (OwnedChild::reap; there is no cgroup).
#[allow(clippy::too_many_arguments, reason = "one spawn's fixed inputs")]
fn spawn_with(
    exe: &CStr,
    args: &[Vec<u8>],
    nulls: &[(i32, i32)],
    dups: &[(&File, i32)],
    cwd: &CStr,
    close_rest: bool,
    own_group: bool,
    expires_ns: u64,
    go: &dyn Fn() -> bool,
) -> io::Result<(OwnedChild, Option<u64>)> {
    let words = args
        .iter()
        .map(|w| CString::new(w.as_slice()))
        .collect::<Result<Vec<_>, _>>()?;
    let mut argv: Vec<_> = words.iter().map(|w| w.as_ptr().cast_mut()).collect();
    argv.push(std::ptr::null_mut());
    let mut copies = Vec::new();
    for (file, _) in dups {
        // SAFETY: duplicates a live source above every target number.
        let fd = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 10) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: a fresh duplicate nothing else owns.
        copies.push(unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) });
    }
    // SAFETY: C objects initialized by the corresponding APIs below.
    let mut actions = unsafe { std::mem::zeroed() };
    // SAFETY: writable action storage.
    check(unsafe { libc::posix_spawn_file_actions_init(&mut actions) })?;
    // SAFETY: writable attribute storage.
    let mut attr = unsafe { std::mem::zeroed() };
    // SAFETY: writable attribute storage.
    if let Err(e) = check(unsafe { libc::posix_spawnattr_init(&mut attr) }) {
        // SAFETY: initialized actions, no longer used.
        unsafe { libc::posix_spawn_file_actions_destroy(&mut actions) };
        return Err(e);
    }
    let result = (|| {
        // SAFETY: writable mask storage.
        let mut mask: libc::sigset_t = unsafe { std::mem::zeroed() };
        // SAFETY: writable mask.
        if unsafe { libc::sigemptyset(&mut mask) } != 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: initialized empty mask resets inherited blocked signals.
        check(unsafe { libc::posix_spawnattr_setsigmask(&mut attr, &mask) })?;
        // SAFETY: writable mask.
        if unsafe { libc::sigfillset(&mut mask) } != 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: every signal to its default in the child.
        check(unsafe { libc::posix_spawnattr_setsigdefault(&mut attr, &mask) })?;
        let flags = libc::POSIX_SPAWN_SETSIGMASK | libc::POSIX_SPAWN_SETSIGDEF;
        #[cfg(target_os = "macos")]
        let flags = flags | libc::POSIX_SPAWN_CLOEXEC_DEFAULT;
        let flags = if own_group {
            // SAFETY: initialized attributes; group 0 is the child's own pid.
            check(unsafe { libc::posix_spawnattr_setpgroup(&mut attr, 0) })?;
            flags | libc::POSIX_SPAWN_SETPGROUP
        } else {
            flags
        };
        // SAFETY: supported child-only flags.
        check(unsafe { libc::posix_spawnattr_setflags(&mut attr, flags as libc::c_short) })?;
        for &(fd, mode) in nulls {
            // SAFETY: fixed path and initialized actions.
            check(unsafe {
                libc::posix_spawn_file_actions_addopen(
                    &mut actions,
                    fd,
                    c"/dev/null".as_ptr(),
                    mode,
                    0,
                )
            })?;
        }
        for (source, (_, target)) in copies.iter().zip(dups) {
            // SAFETY: sources sit above every target, so no dup2 overwrites one.
            check(unsafe {
                libc::posix_spawn_file_actions_adddup2(&mut actions, source.as_raw_fd(), *target)
            })?;
        }
        #[cfg(target_os = "linux")]
        if close_rest {
            let keep = nulls
                .len()
                .max(dups.iter().map(|d| d.1 as usize + 1).max().unwrap_or(0));
            for entry in std::fs::read_dir("/proc/self/fd")? {
                let fd: i32 = entry?
                    .file_name()
                    .to_str()
                    .ok_or_else(|| io::Error::other("fd census"))?
                    .parse()
                    .map_err(io::Error::other)?;
                if fd >= keep as i32 {
                    // SAFETY: kernel-observed descriptor and initialized actions.
                    check(unsafe { libc::posix_spawn_file_actions_addclose(&mut actions, fd) })?;
                }
            }
        }
        #[cfg(not(target_os = "linux"))]
        let _ = close_rest;
        // SAFETY: NUL-terminated folder, applied in the child before exec.
        check(unsafe { libc::posix_spawn_file_actions_addchdir_np(&mut actions, cwd.as_ptr()) })?;
        // The caller's last word, after every preparation step: false (the
        // helper is gone) spawns nothing.
        if !go() {
            return Err(io::Error::from(io::ErrorKind::Interrupted));
        }
        let mut pid = 0;
        let spawn_enter = now_ns().ok();
        // SAFETY: initialized objects and live NUL-terminated arrays; empty environment.
        check(unsafe {
            libc::posix_spawn(
                &mut pid,
                exe.as_ptr(),
                &actions,
                &attr,
                argv.as_ptr(),
                [std::ptr::null_mut()].as_ptr(),
            )
        })?;
        let child = OwnedChild::attach(pid, expires_ns)?;
        let child = if own_group {
            child.leads_group()
        } else {
            child
        };
        Ok((child, spawn_enter))
    })();
    // SAFETY: initialized actions, no longer used.
    unsafe { libc::posix_spawn_file_actions_destroy(&mut actions) };
    // SAFETY: initialized attributes, no longer used.
    unsafe { libc::posix_spawnattr_destroy(&mut attr) };
    result
}

/// The relay's status code when the spawned process could not even exec
/// the relay (`clone3` path; posix_spawn reports that itself). The relay's
/// own codes are 120 to 123.
#[cfg(target_os = "linux")]
pub(crate) const SPAWN_FAILED: u8 = 124;

/// `struct clone_args` up to `cgroup` (CLONE_ARGS_SIZE_VER2, Linux 5.7).
#[cfg(target_os = "linux")]
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
#[cfg(target_os = "linux")]
const CLONE_INTO_CGROUP: u64 = 0x2_0000_0000;

/// `clone3(CLONE_PIDFD [| CLONE_INTO_CGROUP])` with fork semantics, then in
/// the child only `dup2`, `chdir("/")` and `execve` with an empty
/// environment: everything they use is made before the call, and nothing
/// in the child allocates or locks. Signals need no reset here: the relay
/// resets every disposition and the mask itself (`relay.rs` reset_signals).
/// `/dev/null` is descriptor 0. An exec failure writes [`SPAWN_FAILED`] to
/// the status pipe (target 2), so it never reads as an executed target.
#[cfg(target_os = "linux")]
fn clone_into(
    exe: &CStr,
    args: &[Vec<u8>],
    dups: &[(&File, i32)],
    cgroup: Option<std::os::fd::BorrowedFd<'_>>,
    expires_ns: u64,
    go: &dyn Fn() -> bool,
) -> io::Result<OwnedChild> {
    use std::os::fd::{AsRawFd as _, OwnedFd};
    let words = args
        .iter()
        .map(|w| CString::new(w.as_slice()))
        .collect::<Result<Vec<_>, _>>()?;
    let mut argv: Vec<*const libc::c_char> = words.iter().map(|w| w.as_ptr()).collect();
    argv.push(std::ptr::null());
    let envp: [*const libc::c_char; 1] = [std::ptr::null()];
    // SAFETY: fixed path; the descriptor is owned below.
    let null = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
    if null < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: a fresh descriptor nothing else owns.
    let null = unsafe { OwnedFd::from_raw_fd(null) };
    // Sources above every target, so no dup2 overwrites one.
    let mut moves = Vec::new();
    for (fd, target) in
        std::iter::once((null.as_raw_fd(), 0)).chain(dups.iter().map(|(f, t)| (f.as_raw_fd(), *t)))
    {
        // SAFETY: duplicates a live source above every target number.
        let copy = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 10) };
        if copy < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: a fresh duplicate nothing else owns.
        moves.push((unsafe { OwnedFd::from_raw_fd(copy) }, target));
    }
    let raw: Vec<(i32, i32)> = moves.iter().map(|(f, t)| (f.as_raw_fd(), *t)).collect();
    let status = raw.iter().find(|m| m.1 == 2).map_or(-1, |m| m.0);
    let mut pidfd: i32 = -1;
    let mut a = CloneArgs {
        flags: libc::CLONE_PIDFD as u64,
        pidfd: std::ptr::addr_of_mut!(pidfd) as u64,
        exit_signal: libc::SIGCHLD as u64,
        ..CloneArgs::default()
    };
    if let Some(cg) = cgroup {
        a.flags |= CLONE_INTO_CGROUP;
        a.cgroup = cg.as_raw_fd() as u64;
    }
    if !go() {
        return Err(io::Error::from(io::ErrorKind::Interrupted));
    }
    #[cfg(test)]
    if let Some(errno) = CLONE3_ERRORS.with(|q| q.borrow_mut().pop_front()).flatten() {
        return Err(io::Error::from_raw_os_error(errno));
    }
    // SAFETY: a valid clone_args of its size; without CLONE_VM the child is
    // a copy and runs only async-signal-safe calls on prepared data.
    let pid = unsafe {
        libc::syscall(
            libc::SYS_clone3,
            std::ptr::addr_of_mut!(a),
            std::mem::size_of::<CloneArgs>(),
        )
    };
    if pid == 0 {
        // SAFETY: the child of clone3; prepared arrays and descriptors.
        unsafe { exec_child(&raw, status, exe, &argv, &envp) }
    }
    if pid < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: clone3 stored a new pidfd that nothing else owns.
    let pidfd = unsafe { OwnedFd::from_raw_fd(pidfd) };
    Ok(OwnedChild::adopt(pid as libc::pid_t, pidfd, expires_ns))
}

/// # Safety
/// Only in the child of [`clone_into`]: no allocation, no lock.
#[cfg(target_os = "linux")]
unsafe fn exec_child(
    moves: &[(i32, i32)],
    status: i32,
    exe: &CStr,
    argv: &[*const libc::c_char],
    envp: &[*const libc::c_char],
) -> ! {
    // No test for a dup2 failure: both numbers are open and the target is
    // below the descriptor limit, so it cannot be made to fail; it reports a
    // spawn failure (fail closed), the same class as the C1 fcntl branch.
    for &(from, to) in moves {
        // SAFETY: both numbers are open in this child.
        if unsafe { libc::dup2(from, to) } < 0 {
            // SAFETY: still the child of clone_into.
            unsafe { spawn_failed(status) }
        }
    }
    // A copy of the whole caller: any descriptor open there without
    // close-on-exec (another thread's, at this instant) would cross. Every
    // number above 3 goes, as the supervisor's own spawn does (close_rest);
    // from here the status pipe is fd 2. close_range is in every kernel the
    // atomic path runs on (5.9; the path needs 5.14). No test for its
    // failure: it cannot fail on that range; it reports a spawn failure.
    // SAFETY: closes only this child's descriptors.
    if unsafe { libc::syscall(libc::SYS_close_range, 4u32, u32::MAX, 0u32) } != 0 {
        // SAFETY: still the child of clone_into.
        unsafe { spawn_failed(2) }
    }
    // SAFETY: NUL-terminated fixed path.
    if unsafe { libc::chdir(c"/".as_ptr()) } == 0 {
        // SAFETY: NUL-terminated path and NULL-terminated arrays made before clone3.
        unsafe { libc::execve(exe.as_ptr(), argv.as_ptr(), envp.as_ptr()) };
    }
    // SAFETY: still the child of clone_into.
    unsafe { spawn_failed(2) }
}

/// # Safety
/// Only in the child of [`clone_into`].
#[cfg(target_os = "linux")]
unsafe fn spawn_failed(status: i32) -> ! {
    let code = [SPAWN_FAILED];
    // SAFETY: one byte from a live buffer to the status pipe's source copy.
    unsafe { libc::write(status, code.as_ptr().cast(), 1) };
    // SAFETY: ends the child without running the parent's exit handlers.
    unsafe { libc::_exit(127) }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    fn fds(pid: libc::pid_t) -> Vec<i32> {
        let mut v: Vec<i32> = std::fs::read_dir(format!("/proc/{pid}/fd"))
            .unwrap()
            .map(|e| e.unwrap().file_name().to_str().unwrap().parse().unwrap())
            .collect();
        v.sort_unstable();
        v
    }

    // GATE-CMD-FDS(감독 칸): 감독은 정확히 {0,1,2,3,4,5}이고 envp가 비어 있다. 도우미가 close-on-exec 없이
    // 쥔 fd도 넘어가지 않는다. 이것을 실패시키는 것: spawn_with의 close_rest 훑기를 지우는 것.
    #[test]
    fn test_supervisor_gets_exactly_six_fds() {
        let _inherited_fds = super::super::sys::test_inherited_fd_lock();
        let mut raw = [0; 2];
        // SAFETY: writable storage; deliberately without O_CLOEXEC.
        assert_eq!(unsafe { libc::pipe(raw.as_mut_ptr()) }, 0);
        // Above every target number, so no dup2 hides them.
        let raw = raw.map(|fd| {
            // SAFETY: `fd` is open; F_DUPFD leaves the copy inheritable.
            let high = unsafe { libc::fcntl(fd, libc::F_DUPFD, 50) };
            // SAFETY: the low number is closed once.
            unsafe { libc::close(fd) };
            high
        });
        let (a, b) = pipe().unwrap();
        let (c, _d) = pipe().unwrap();
        let sleep = c"/bin/sleep";
        let args = [b"sleep".to_vec(), b"5".to_vec()];
        let mut child = spawn_supervisor(sleep, &args, &a, &b, &c, None, u64::MAX).unwrap();
        // The spawn is synchronous; give exec a moment to settle the table.
        std::thread::sleep(std::time::Duration::from_millis(50));
        let seen = fds(child.pid);
        let environ = std::fs::read(format!("/proc/{}/environ", child.pid)).unwrap();
        let _ = child.signal(libc::SIGKILL);
        while !child.reap().unwrap() {}
        for fd in raw {
            // SAFETY: closes the test's own pipe ends once.
            unsafe { libc::close(fd) };
        }
        assert_eq!(seen, [0, 1, 2, 3, 4, 5]);
        assert!(environ.is_empty());
    }

    // GATE-CMD-FDS(원자 경로, C3 판정 R2): 세션 cgroup 부모가 있으면 정확히 {0..6}. 이것을 실패시키는 것:
    // spawn_supervisor의 `dups.extend(cgroup…)`를 지우는 것({0..5}가 됨).
    #[test]
    fn test_supervisor_gets_seven_fds_on_the_atomic_path() {
        let _inherited_fds = super::super::sys::test_inherited_fd_lock();
        let (a, b) = pipe().unwrap();
        let (c, _d) = pipe().unwrap();
        let (parent, _e) = pipe().unwrap();
        let args = [b"sleep".to_vec(), b"5".to_vec()];
        let mut child =
            spawn_supervisor(c"/bin/sleep", &args, &a, &b, &c, Some(&parent), u64::MAX).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(50));
        let seen = fds(child.pid);
        let _ = child.signal(libc::SIGKILL);
        while !child.reap().unwrap() {}
        assert_eq!(seen, [0, 1, 2, 3, 4, 5, 6]);
    }

    fn sleeper(
        go: &dyn Fn() -> bool,
        cgroup: Option<std::os::fd::BorrowedFd<'_>>,
    ) -> io::Result<Spawned> {
        let args = [b"sleep".to_vec(), b"5".to_vec()];
        spawn(c"/bin/sleep", &args, b"input", u64::MAX, go, cgroup)
    }

    /// The clone3 path without a cgroup; `None` where clone3 is refused
    /// (a default container's seccomp profile answers ENOSYS), except in the
    /// privileged cell, where CI asserts these tests pass.
    fn clone3_sleeper() -> Option<Spawned> {
        let args = [b"sleep".to_vec(), b"5".to_vec()];
        let (input_read, input_write) = pipe().unwrap();
        drop(input_write);
        let (stdout, stdout_write) = pipe().unwrap();
        let (status, status_write) = pipe().unwrap();
        match clone_into(
            c"/bin/sleep",
            &args,
            &[(&stdout_write, 1), (&status_write, 2), (&input_read, 3)],
            None,
            u64::MAX,
            &|| true,
        ) {
            Ok(child) => Some(Spawned {
                child,
                stdout,
                status,
            }),
            // In the privileged cell clone3 must work: a refusal there fails.
            Err(e)
                if matches!(e.raw_os_error(), Some(libc::ENOSYS | libc::EPERM))
                    && !super::super::command_cgroup::cell::privileged() =>
            {
                eprintln!("clone3 unavailable here: {e}");
                None
            }
            Err(e) => panic!("{e}"),
        }
    }

    fn end(mut s: Spawned) {
        let _ = s.child.signal(libc::SIGKILL);
        while !s.child.reap().unwrap() {}
    }

    // clone3 경로의 중계도 정확히 {0,1,2,3}, 빈 envp, 작업 폴더 "/". 호출 쪽에 close-on-exec 없는 fd가 열려
    // 있어도(멀티스레드 시험 하네스, 다른 스레드의 fd) 넘어가지 않는다. 이것을 실패시키는 것: exec_child가 마지막
    // 이동(fd 3)을 건너뛰는 것({0,1,2}가 됨), exec_child의 close_range를 지우는 것(아래 상속 fd가 넘어감),
    // exec_child의 chdir을 지우는 것(시험 프로세스 폴더에서 시작).
    #[test]
    fn test_clone3_relay_gets_exactly_four_fds() {
        let _inherited_fds = super::super::sys::test_inherited_fd_lock();
        // An inheritable descriptor in the caller, as another thread may hold one.
        let (keep, _w) = pipe().unwrap();
        // SAFETY: `keep` is open; F_DUPFD leaves the copy inheritable.
        let open = unsafe { libc::fcntl(keep.as_raw_fd(), libc::F_DUPFD, 60) };
        assert!(open >= 60);
        // Owned at once: a panic below still closes it before the lock goes.
        // SAFETY: a fresh duplicate nothing else owns.
        let open = unsafe { std::os::fd::OwnedFd::from_raw_fd(open) };
        let spawned = clone3_sleeper();
        drop(open);
        let Some(s) = spawned else { return };
        std::thread::sleep(std::time::Duration::from_millis(50));
        let seen = fds(s.child.pid);
        let environ = std::fs::read(format!("/proc/{}/environ", s.child.pid)).unwrap();
        let cwd = std::fs::read_link(format!("/proc/{}/cwd", s.child.pid)).unwrap();
        end(s);
        assert_eq!(seen, [0, 1, 2, 3]);
        assert!(environ.is_empty());
        assert_eq!(cwd, std::path::Path::new("/"));
    }

    // exec 실패는 상태 파이프의 SPAWN_FAILED 1바이트(대상 실행으로 읽히지 않음). 이것을 실패시키는 것:
    // spawn_failed의 write를 지우는 것(바이트 없는 EOF).
    #[test]
    fn test_clone3_exec_failure_is_reported() {
        let _inherited_fds = super::super::sys::test_inherited_fd_lock();
        let (input_read, _w) = pipe().unwrap();
        let (_stdout, stdout_write) = pipe().unwrap();
        let (status, status_write) = pipe().unwrap();
        let args = [b"missing".to_vec()];
        let child = match clone_into(
            c"/nonexistent/bingsu-missing",
            &args,
            &[(&stdout_write, 1), (&status_write, 2), (&input_read, 3)],
            None,
            u64::MAX,
            &|| true,
        ) {
            Ok(c) => c,
            Err(e)
                if matches!(e.raw_os_error(), Some(libc::ENOSYS | libc::EPERM))
                    && !super::super::command_cgroup::cell::privileged() =>
            {
                return;
            }
            Err(e) => panic!("{e}"),
        };
        drop(status_write);
        let mut child = child;
        while !child.reap().unwrap() {}
        let mut code = Vec::new();
        use std::io::Read;
        (&status).read_to_end(&mut code).unwrap();
        assert_eq!(code, [SPAWN_FAILED]);
        assert_eq!(child.exit_code(), Some(127));
    }

    // go()가 거짓이면 clone3을 부르지 않는다. 이것을 실패시키는 것: clone_into의 go() 검사를 지우는 것
    // (Interrupted 대신 자식이 생김).
    #[test]
    fn test_clone3_waits_for_go() {
        let _inherited_fds = super::super::sys::test_inherited_fd_lock();
        let (input_read, _w) = pipe().unwrap();
        let (_o, stdout_write) = pipe().unwrap();
        let (_s, status_write) = pipe().unwrap();
        let args = [b"sleep".to_vec(), b"5".to_vec()];
        let r = clone_into(
            c"/bin/sleep",
            &args,
            &[(&stdout_write, 1), (&status_write, 2), (&input_read, 3)],
            None,
            u64::MAX,
            &|| false,
        );
        match r {
            Err(e) => assert_eq!(e.kind(), io::ErrorKind::Interrupted),
            Ok(mut c) => {
                let _ = c.signal(libc::SIGKILL);
                while !c.reap().unwrap() {}
                panic!("spawned without go");
            }
        }
    }

    // 원자 경로: 중계는 처음부터 그 cgroup 안에서 시작한다. 이것을 실패시키는 것: clone_into에서
    // CLONE_INTO_CGROUP을 빼는 것(시험 프로세스의 cgroup에서 시작).
    #[test]
    #[ignore = "runs in the cgroup cells (BINGSU_CGROUP_CELL)"]
    fn test_clone3_starts_inside_the_cgroup() {
        if !super::super::command_cgroup::cell::privileged() {
            return;
        }
        let _inherited_fds = super::super::sys::test_inherited_fd_lock();
        let (p, _dir) = super::super::command_cgroup::cell::parent("clone3");
        let unit = p.join("u0000000000000001");
        std::fs::create_dir(&unit).unwrap();
        let cg = std::fs::File::open(&unit).unwrap();
        use std::os::fd::AsFd;
        let s = sleeper(&|| true, Some(cg.as_fd())).unwrap();
        let line = std::fs::read_to_string(format!("/proc/{}/cgroup", s.child.pid)).unwrap();
        end(s);
        let rel = unit
            .strip_prefix("/sys/fs/cgroup")
            .unwrap()
            .to_string_lossy()
            .into_owned();
        assert_eq!(line.trim_end(), format!("0::/{rel}"));
        std::fs::remove_dir(&unit).unwrap();
        std::fs::remove_dir(&p).unwrap();
    }
}

/// C2 timings with the real binaries (Linux): `BINGSU_BIN` names a built
/// `bingsu`. Run with `--ignored --nocapture`; it prints, never asserts.
#[cfg(all(test, target_os = "linux"))]
mod timing {
    use super::*;
    use bingsu_core::command::wire::{self, Grant, Message, Policy, Unit, policy_digest};
    use bingsu_core::handoff::{Cwd, Permit};

    fn now() -> u64 {
        crate::prompt_io::observe_clock().unwrap().now
    }

    fn grant(units: usize) -> Grant {
        let c = crate::prompt_io::observe_clock().unwrap();
        let policy = Policy::Argv {
            argv: vec![b"true".to_vec()],
        };
        let tmp = std::env::temp_dir().into_os_string().into_encoded_bytes();
        Grant {
            permit: Permit {
                kind: c.kind,
                deadline: c.now + 10_000_000_000,
                boot: c.boot,
                resume: c.resume,
                domain: c.domain,
            },
            helper_deadline: c.now + 2_000_000_000,
            cwd: tmp.clone(),
            neutral: tmp,
            units: (0..units)
                .map(|i| Unit {
                    id: format!("custom/t{i}"),
                    digest: policy_digest(&policy, Cwd::Neutral, 200_000_000, &[]),
                    policy: policy.clone(),
                    cwd: Cwd::Neutral,
                    environment: b"PATH=/usr/bin\0".to_vec(),
                    timeout: 200_000_000,
                    env_allow: Vec::new(),
                    executable: std::fs::canonicalize("/bin/true")
                        .unwrap()
                        .into_os_string()
                        .into_encoded_bytes(),
                    pin: None,
                    interpreter: None,
                })
                .collect(),
            probes: Vec::new(),
        }
    }

    /// Spawns the real supervisor; with `early` the grant is in the pipe
    /// before the spawn. Returns (spawned at, grant written at, results).
    fn round(exe: &CStr, units: usize, early: bool) -> (u64, u64, Vec<wire::Outcome>) {
        round_in(exe, units, early, None)
    }

    fn round_in(
        exe: &CStr,
        units: usize,
        early: bool,
        cgroup: Option<&File>,
    ) -> (u64, u64, Vec<wire::Outcome>) {
        let (grant_read, grant_write) = pipe().unwrap();
        let (results_read, results_write) = pipe().unwrap();
        let (lock, _keep) = pipe().unwrap();
        let frame = wire::encode(&Message::Grant(grant(units))).unwrap();
        let write = |at: &mut u64| {
            *at = now();
            assert!(matches!(
                crate::commands::sys::write_fd(grant_write.as_raw_fd(), &frame),
                crate::commands::sys::WriteOutcome::Done
            ));
        };
        let mut granted = 0;
        if early {
            write(&mut granted);
        }
        let args = [exe.to_bytes().to_vec(), b"__command-v1".to_vec()];
        let spawned = now();
        let mut child = spawn_supervisor(
            exe,
            &args,
            &grant_read,
            &results_write,
            &lock,
            cgroup,
            u64::MAX,
        )
        .unwrap();
        drop((grant_read, results_write));
        if !early {
            std::thread::sleep(std::time::Duration::from_millis(50));
            write(&mut granted);
        }
        let mut bytes = Vec::new();
        let mut buf = vec![0u8; 65_536];
        let mut out = Vec::new();
        while out.len() < units {
            // SAFETY: writable buffer; blocking read end.
            let n =
                unsafe { libc::read(results_read.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len()) };
            let n = usize::try_from(n).unwrap();
            if n == 0 {
                break;
            }
            bytes.extend_from_slice(&buf[..n]);
            while bytes.len() >= wire::HEADER {
                let total = wire::frame_len(&bytes).unwrap();
                if bytes.len() < total {
                    break;
                }
                if let Message::Result(o) = wire::decode(&bytes[..total]).unwrap() {
                    out.push(o);
                }
                bytes.drain(..total);
            }
        }
        drop(grant_write);
        while !child.reap().unwrap() {}
        (spawned, granted, out)
    }

    fn show(name: &str, mut v: Vec<u64>) {
        v.sort_unstable();
        let p = |q: f64| v[((v.len() as f64 * q) as usize).min(v.len() - 1)] as f64 / 1e6;
        println!(
            "{name}: n={} p50={:.3} ms p95={:.3} ms max={:.3} ms",
            v.len(),
            p(0.5),
            p(0.95),
            p(1.0)
        );
    }

    #[test]
    #[ignore = "timing: needs BINGSU_BIN"]
    fn c2_timings() {
        let _inherited_fds = super::super::sys::test_inherited_fd_lock();
        #[expect(clippy::disallowed_methods, reason = "test-only timing input")]
        let exe = CString::new(std::env::var("BINGSU_BIN").unwrap()).unwrap();
        let rounds: usize = 30;
        let (mut ready, mut first, mut approve) = (Vec::new(), Vec::new(), Vec::new());
        for _ in 0..rounds {
            // Grant already waiting: spawn -> first approval is start-up and grant read.
            let (spawned, _, out) = round(&exe, 1, true);
            ready.push(out[0].approved_at - spawned);
            // Supervisor idle on its pipe: grant -> first approval, and approval -> end.
            let (_, granted, out) = round(&exe, 8, false);
            first.push(out.iter().map(|o| o.approved_at).min().unwrap() - granted);
            for o in &out {
                assert!(matches!(o.reason, wire::Reason::Exited(0)), "{o:?}");
                approve.push(o.ended_at - o.approved_at);
            }
        }
        show(
            "supervisor_ready_ns (spawn -> first approval, grant waiting)",
            ready,
        );
        show("go_to_first_approval_ns (grant -> first approval)", first);
        show(
            "approve_to_end_ns (approval -> /bin/true reaped, 8 units)",
            approve,
        );
    }

    /// C3 `cgroup_ns`: the same 8-unit round on the atomic path (unit cgroup,
    /// clone3, cgroup.kill) and on the best-effort path, and one reclaim of
    /// the 8 unit folders a round leaves. Privileged cell, `BINGSU_BIN`.
    #[test]
    #[ignore = "timing: needs BINGSU_BIN and the privileged cell"]
    fn c3_cgroup_timings() {
        use super::super::command_cgroup::{cell, fs, reclaim};
        let _inherited_fds = super::super::sys::test_inherited_fd_lock();
        #[expect(clippy::disallowed_methods, reason = "test-only timing input")]
        let exe = CString::new(std::env::var("BINGSU_BIN").unwrap()).unwrap();
        let (path, _dir) = cell::parent("timing");
        let parent = File::open(&path).unwrap();
        let (mut atomic, mut plain, mut reclaims) = (Vec::new(), Vec::new(), Vec::new());
        for _ in 0..30 {
            let (_, _, out) = round_in(&exe, 8, true, Some(&parent));
            assert_eq!(cell::units(&path).len(), 8, "{out:?}");
            for o in &out {
                assert!(matches!(o.reason, wire::Reason::Exited(0)), "{o:?}");
                atomic.push(o.ended_at - o.approved_at);
            }
            let mut dir = fs::Dir::new(File::open(&path).unwrap());
            let r = reclaim(&mut fs::Fs, &mut dir);
            assert_eq!(r.removed, 8, "{r:?}");
            reclaims.push(r.elapsed_ns);
            let (_, _, out) = round(&exe, 8, true);
            plain.extend(out.iter().map(|o| o.ended_at - o.approved_at));
        }
        let _ = std::fs::remove_dir(&path);
        show(
            "approve_to_end_ns atomic (unit cgroup, clone3, cgroup.kill)",
            atomic,
        );
        show(
            "approve_to_end_ns best effort (posix_spawn, process group)",
            plain,
        );
        show("reclaim_ns (8 empty unit cgroups)", reclaims);
    }
}

#[cfg(test)]
mod input_channel {
    use super::*;

    fn mode(file: &File) -> libc::mode_t {
        // SAFETY: a zeroed stat is a valid out-parameter.
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: `file` is open and `st` is writable.
        assert_eq!(unsafe { libc::fstat(file.as_raw_fd(), &mut st) }, 0);
        st.st_mode & libc::S_IFMT
    }

    // 이것을 실패시키는 것: macOS에서 입력 통로를 pipe로 두는 것(파이프가 512 B로 줄면 작은 입력도 못 씀), Linux에서
    // 소켓으로 바꾸는 것(seccomp 표와 Linux의 동작이 바뀜), 양쪽 끝의 close-on-exec를 빼는 것(다른 relay가 쓰기 끝을
    // 물려받아 EOF가 오지 않음).
    #[test]
    fn the_input_channel_is_a_socket_on_macos_and_a_pipe_elsewhere() {
        let (read, write) = input_ends().unwrap();
        let want = if cfg!(target_os = "macos") {
            libc::S_IFSOCK
        } else {
            libc::S_IFIFO
        };
        assert_eq!((mode(&read), mode(&write)), (want, want));
        for f in [&read, &write] {
            // SAFETY: a flag query on an open descriptor.
            let flags = unsafe { libc::fcntl(f.as_raw_fd(), libc::F_GETFD) };
            assert!(flags >= 0 && flags & libc::FD_CLOEXEC != 0);
        }
    }

    // 이것을 실패시키는 것: macOS에서 SO_SNDBUF를 올리지 않는 것(이 시험이 도는 어떤 환경에서도 보내는 쪽 버퍼가
    // 작으면 가장 큰 입력이 한 번에 안 들어감), 버퍼를 가장 큰 입력보다 작게 두는 것.
    #[cfg(target_os = "macos")]
    #[test]
    fn the_input_socket_sends_the_largest_input_in_one_buffer() {
        let (_read, write) = input_ends().unwrap();
        let mut size: libc::c_int = 0;
        let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        // SAFETY: `size` and `len` are writable and `len` is its size.
        let rc = unsafe {
            libc::getsockopt(
                write.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_SNDBUF,
                (&mut size as *mut libc::c_int).cast(),
                &mut len,
            )
        };
        assert_eq!(rc, 0);
        assert!(
            usize::try_from(size).unwrap() >= bingsu_core::handoff::RELAY_INPUT_MAX,
            "{size}"
        );
    }

    // 이것을 실패시키는 것: 가장 큰 입력(RELAY_INPUT_MAX)이 비어 있는 입력 통로에 한 번에 안 들어가는 것. 파이프가
    // 512 B로 줄어든 macOS에서는 pipe를 쓰면 실패한다.
    #[test]
    fn the_largest_input_fits_one_write_into_the_empty_channel() {
        let (_read, write) = input_ends().unwrap();
        super::super::collector_process::nonblocking(&write).unwrap();
        let input = vec![b'x'; bingsu_core::handoff::RELAY_INPUT_MAX];
        // SAFETY: `input` is readable for its length.
        let n = unsafe { libc::write(write.as_raw_fd(), input.as_ptr().cast(), input.len()) };
        assert_eq!(usize::try_from(n).ok(), Some(input.len()), "{n}");
    }

    // A relay stand-in reads the input to the end; the supervisor wrote it all and closed.
    // 이것을 실패시키는 것: 큰 입력이 중계(`wc -c <&3`)에 온전히 도착하지 않는 것, 쓰기 끝을 닫지 않아 EOF가 오지 않는 것
    // (10 s 상한에서 실패).
    #[test]
    fn a_relay_reads_a_largest_input_to_end_of_file() {
        use std::io::Read as _;
        use std::time::{Duration, Instant};
        let input = vec![b'x'; bingsu_core::handoff::RELAY_INPUT_MAX];
        let args: Vec<Vec<u8>> = ["sh", "-c", "wc -c <&3"]
            .iter()
            .map(|a| a.as_bytes().to_vec())
            .collect();
        let mut s = spawn(c"/bin/sh", &args, &input, u64::MAX, &|| true, None).unwrap();
        let end = Instant::now() + Duration::from_secs(10);
        while !s.child.reap().unwrap() {
            assert!(Instant::now() < end, "the relay never saw end of input");
            std::thread::sleep(Duration::from_millis(5));
        }
        let mut out = String::new();
        s.stdout.read_to_string(&mut out).unwrap();
        assert_eq!(out.trim(), input.len().to_string());
    }
}
