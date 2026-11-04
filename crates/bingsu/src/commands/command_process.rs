//! One relay spawn for the command supervisor (spec section 4 "user command
//! execution model", row input and output). The relay's permit and exec frame
//! are written into an empty pipe before the spawn, so a relay that never
//! reads cannot hold the supervisor. The relay always gets descriptors 0, 1
//! and 2 from the spawn actions, whatever the supervisor holds there: 0 is
//! `/dev/null`, 1 the stdout pipe, 2 the status pipe, 3 its input; nothing
//! else crosses (the supervisor's own descriptors are close-on-exec, and
//! macOS spawns with `POSIX_SPAWN_CLOEXEC_DEFAULT`). The environment is empty
//! and the working folder is set by the spawn.
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

/// Spawns `exe` with `args` (argv[0] included) in folder `cwd`, `input` on
/// descriptor 3. `input` must fit one write into an empty pipe; a shorter
/// write is an error and nothing is spawned.
pub(crate) fn spawn(
    exe: &CStr,
    args: &[Vec<u8>],
    input: &[u8],
    cwd: &CStr,
    expires_ns: u64,
) -> io::Result<Spawned> {
    let (input_read, input_write) = pipe()?;
    super::collector_process::nonblocking(&input_write)?;
    // SAFETY: `input` is readable for its length; the pipe is empty.
    let n = unsafe { libc::write(input_write.as_raw_fd(), input.as_ptr().cast(), input.len()) };
    if usize::try_from(n).ok() != Some(input.len()) {
        return Err(io::Error::other("relay input did not fit the pipe"));
    }
    drop(input_write);
    let (stdout, stdout_write) = pipe()?;
    let (status, status_write) = pipe()?;
    super::collector_process::nonblocking(&stdout)?;
    super::collector_process::nonblocking(&status)?;
    // The supervisor's own descriptors are close-on-exec, so nothing but
    // these crosses.
    let (child, _) = spawn_with(
        exe,
        args,
        &[(0, libc::O_RDONLY)],
        &[(&stdout_write, 1), (&status_write, 2), (&input_read, 3)],
        cwd,
        false,
        expires_ns,
    )?;
    Ok(Spawned {
        child,
        stdout,
        status,
    })
}

/// The supervisor itself, from the helper (`args`: the binary and
/// `__command-v1`): 0 to 2 `/dev/null`, then the grant pipe's read end, the
/// result pipe's write end and the lock copy at 3, 4 and 5, in folder "/".
/// Every other helper descriptor is closed.
pub(crate) fn spawn_supervisor(
    exe: &CStr,
    args: &[Vec<u8>],
    grant: &File,
    results: &File,
    lock: &File,
    expires_ns: u64,
) -> io::Result<OwnedChild> {
    spawn_with(
        exe,
        args,
        &[
            (0, libc::O_RDONLY),
            (1, libc::O_WRONLY),
            (2, libc::O_WRONLY),
        ],
        &[(grant, 3), (results, 4), (lock, 5)],
        c"/",
        true,
        expires_ns,
    )
    .map(|(child, _)| child)
}

/// One `posix_spawn` with an empty environment and default signals: `nulls`
/// open `/dev/null` at a number, `dups` move a source to a number (sources
/// are first moved above every target), the child starts in `cwd`. With
/// `close_rest` (Linux) every other open descriptor is closed in the child;
/// macOS always spawns with `POSIX_SPAWN_CLOEXEC_DEFAULT`.
fn spawn_with(
    exe: &CStr,
    args: &[Vec<u8>],
    nulls: &[(i32, i32)],
    dups: &[(&File, i32)],
    cwd: &CStr,
    close_rest: bool,
    expires_ns: u64,
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
        Ok((OwnedChild::attach(pid, expires_ns)?, spawn_enter))
    })();
    // SAFETY: initialized actions, no longer used.
    unsafe { libc::posix_spawn_file_actions_destroy(&mut actions) };
    // SAFETY: initialized attributes, no longer used.
    unsafe { libc::posix_spawnattr_destroy(&mut attr) };
    result
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
        let mut child = spawn_supervisor(sleep, &args, &a, &b, &c, u64::MAX).unwrap();
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
}
