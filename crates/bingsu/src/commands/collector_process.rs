//! One direct child, one reaper, and independently owned signal handles.
use std::{
    ffi::{CString, OsStr},
    fs::File,
    io,
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd},
        unix::ffi::OsStrExt,
    },
    sync::{Arc, Mutex},
};

#[derive(Default)]
struct State {
    killed: bool,
    reaped: bool,
}

pub(crate) struct SignalChild {
    #[cfg(target_os = "linux")]
    pidfd: OwnedFd,
    #[cfg(target_os = "macos")]
    pid: libc::pid_t,
    state: Arc<Mutex<State>>,
}

pub(crate) struct OwnedChild {
    signal: SignalChild,
    expires_ns: u64,
}

impl SignalChild {
    pub fn signal(&self, signal: i32) -> io::Result<()> {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if state.reaped || state.killed {
            return Ok(());
        }
        // Record the request before the syscall; ESRCH is a normal exit race.
        state.killed = true;
        #[cfg(target_os = "linux")]
        // SAFETY: retained pidfd identifies this child even after PID reuse.
        let rc = unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                self.pidfd.as_raw_fd(),
                signal,
                std::ptr::null::<libc::siginfo_t>(),
                0,
            )
        };
        #[cfg(target_os = "macos")]
        // SAFETY: the same mutex excludes the only reaper until signal returns.
        let rc = unsafe { libc::kill(self.pid, signal) };
        if rc != 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::ESRCH) {
                return Err(error);
            }
        }
        Ok(())
    }

    pub fn reaped(&self) -> bool {
        self.state.lock().unwrap_or_else(|e| e.into_inner()).reaped
    }

    pub fn kill_requested(&self) -> bool {
        self.state.lock().unwrap_or_else(|e| e.into_inner()).killed
    }

    #[cfg(target_os = "macos")]
    pub fn footprint(&self) -> io::Result<Option<u64>> {
        let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if state.reaped {
            return Ok(None);
        }
        // SAFETY: integer-only output, proc_pid_rusage receives its exact layout.
        let mut usage: libc::rusage_info_v2 = unsafe { std::mem::zeroed() };
        // SAFETY: unreaped direct child; the state lock excludes PID reuse.
        let rc = unsafe {
            libc::proc_pid_rusage(
                self.pid,
                libc::RUSAGE_INFO_V2,
                (&mut usage as *mut libc::rusage_info_v2).cast(),
            )
        };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Some(usage.ri_phys_footprint))
    }
}

impl OwnedChild {
    fn attach(pid: libc::pid_t, expires_ns: u64) -> io::Result<Self> {
        #[cfg(target_os = "linux")]
        {
            // SAFETY: SIGCHLD is DFL and nobody has waited for this direct child.
            let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
            if fd < 0 {
                let error = io::Error::last_os_error();
                cleanup_unattached(pid, expires_ns);
                return Err(error);
            }
            // SAFETY: newly returned descriptor, transferred exactly once.
            let pidfd = unsafe { OwnedFd::from_raw_fd(fd as i32) };
            Ok(Self {
                signal: SignalChild {
                    pidfd,
                    state: Arc::default(),
                },
                expires_ns,
            })
        }
        #[cfg(target_os = "macos")]
        {
            Ok(Self {
                signal: SignalChild {
                    pid,
                    state: Arc::default(),
                },
                expires_ns,
            })
        }
    }

    pub fn signal(&self, signal: i32) -> io::Result<()> {
        self.signal.signal(signal)
    }

    pub fn signal_copy(&self) -> io::Result<SignalChild> {
        Ok(SignalChild {
            #[cfg(target_os = "linux")]
            pidfd: self.signal.pidfd.try_clone()?,
            #[cfg(target_os = "macos")]
            pid: self.signal.pid,
            state: self.signal.state.clone(),
        })
    }

    pub fn kill_requested(&self) -> bool {
        self.signal.kill_requested()
    }

    pub fn reap(&mut self) -> io::Result<bool> {
        let mut state = self.signal.state.lock().unwrap_or_else(|e| e.into_inner());
        if state.reaped {
            return Ok(true);
        }
        #[cfg(target_os = "linux")]
        {
            // SAFETY: zeroed writable siginfo_t; wait is strictly nonblocking.
            let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
            // SAFETY: owned pidfd of our child; this is its only reaper.
            let rc = unsafe {
                libc::waitid(
                    libc::P_PIDFD,
                    self.signal.pidfd.as_raw_fd() as libc::id_t,
                    &mut info,
                    libc::WEXITED | libc::WNOHANG,
                )
            };
            if rc != 0 {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: waitid initialized the child event fields.
            state.reaped = unsafe { info.si_pid() } != 0;
        }
        #[cfg(target_os = "macos")]
        {
            // SAFETY: sole reaper; signal and sampling are excluded by state.
            let rc = unsafe { libc::waitpid(self.signal.pid, std::ptr::null_mut(), libc::WNOHANG) };
            if rc < 0 {
                return Err(io::Error::last_os_error());
            }
            state.reaped = rc == self.signal.pid;
        }
        Ok(state.reaped)
    }
}

impl Drop for OwnedChild {
    fn drop(&mut self) {
        let _ = self.signal(libc::SIGKILL);
        loop {
            match self.reap() {
                Ok(true) => break,
                Ok(false) => {}
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(_) => break,
            }
            if now_ns().map_or(true, |now| now >= self.expires_ns) {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
    }
}

#[cfg(target_os = "linux")]
fn cleanup_unattached(pid: libc::pid_t, expires_ns: u64) {
    // The only numeric-PID cleanup is before the helper filter, before any
    // wait, for a direct child for which pidfd acquisition failed.
    // SAFETY: no waiter or automatic reaping can have released this PID.
    unsafe { libc::kill(pid, libc::SIGKILL) };
    loop {
        // SAFETY: sole waiter, nonblocking; a D-state child may remain unreaped.
        let rc = unsafe { libc::waitpid(pid, std::ptr::null_mut(), libc::WNOHANG) };
        if rc == pid
            || (rc < 0 && io::Error::last_os_error().kind() != io::ErrorKind::Interrupted)
            || now_ns().map_or(true, |now| now >= expires_ns)
        {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
}

pub(crate) fn now_ns() -> io::Result<u64> {
    crate::prompt_io::monotonic_ns().map_err(|_| io::Error::other("collection clock"))
}

pub(crate) fn pipe() -> io::Result<(File, File)> {
    let mut fds = [-1; 2];
    // SAFETY: writable storage for two new descriptors.
    if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: both descriptors are newly owned and transferred once.
    let read = unsafe { File::from_raw_fd(fds[0]) };
    // SAFETY: the second newly owned pipe descriptor.
    let write = unsafe { File::from_raw_fd(fds[1]) };
    for file in [&read, &write] {
        // SAFETY: live private fd; no unrelated open-file description is changed.
        if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok((read, write))
}

pub(crate) fn nonblocking(file: &File) -> io::Result<()> {
    // SAFETY: descriptor query on a private pipe endpoint.
    let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) };
    // SAFETY: only the helper's private endpoint shares this description.
    if flags < 0
        // SAFETY: only the helper's private endpoint is changed.
        || unsafe { libc::fcntl(file.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

pub(crate) fn spawn(
    path: &OsStr,
    request: &File,
    response: &File,
    lock: &File,
    expires_ns: u64,
) -> io::Result<OwnedChild> {
    spawn_args(
        path,
        &[OsStr::new("__collect-v1")],
        request,
        response,
        lock,
        expires_ns,
    )
}

fn check(rc: i32) -> io::Result<()> {
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(rc))
    }
}

pub(crate) fn spawn_args(
    path: &OsStr,
    args: &[&OsStr],
    request: &File,
    response: &File,
    lock: &File,
    expires_ns: u64,
) -> io::Result<OwnedChild> {
    let path = CString::new(path.as_bytes())?;
    let words = std::iter::once(Ok(path.clone()))
        .chain(args.iter().map(|v| CString::new(v.as_bytes())))
        .collect::<Result<Vec<_>, _>>()?;
    let mut argv: Vec<_> = words.iter().map(|v| v.as_ptr().cast_mut()).collect();
    argv.push(std::ptr::null_mut());
    let mut copies = Vec::new();
    for file in [request, response, lock] {
        // SAFETY: duplicate live sources above every reserved child slot.
        let fd = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 6) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: unique newly allocated duplicate.
        copies.push(unsafe { OwnedFd::from_raw_fd(fd) });
    }
    // SAFETY: C objects initialized by the corresponding APIs below.
    let mut actions = unsafe { std::mem::zeroed() };
    // SAFETY: writable action storage.
    check(unsafe { libc::posix_spawn_file_actions_init(&mut actions) })?;
    // SAFETY: initialized by posix_spawnattr_init.
    let mut attr = unsafe { std::mem::zeroed() };
    // SAFETY: writable attribute storage.
    if let Err(e) = check(unsafe { libc::posix_spawnattr_init(&mut attr) }) {
        // SAFETY: initialized actions, no longer used.
        unsafe { libc::posix_spawn_file_actions_destroy(&mut actions) };
        return Err(e);
    }
    let result = (|| {
        // Only the helper changes SIGCHLD. The front's policy is untouched.
        // SAFETY: initialized signal action and writable signal mask.
        let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
        action.sa_sigaction = libc::SIG_DFL;
        // SAFETY: writable signal mask.
        if unsafe { libc::sigemptyset(&mut action.sa_mask) } != 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: helper-local SIGCHLD policy; flags omit SA_NOCLDWAIT.
        if unsafe { libc::sigaction(libc::SIGCHLD, &action, std::ptr::null_mut()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: initialized empty mask resets inherited blocked signals.
        check(unsafe { libc::posix_spawnattr_setsigmask(&mut attr, &action.sa_mask) })?;
        // SAFETY: writable mask for default child dispositions.
        if unsafe { libc::sigfillset(&mut action.sa_mask) } != 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: initialized child-only mask and attributes.
        check(unsafe { libc::posix_spawnattr_setsigdefault(&mut attr, &action.sa_mask) })?;
        let flags = libc::POSIX_SPAWN_SETSIGMASK | libc::POSIX_SPAWN_SETSIGDEF;
        #[cfg(target_os = "macos")]
        let flags = flags | libc::POSIX_SPAWN_CLOEXEC_DEFAULT;
        // SAFETY: supported child-only flags.
        check(unsafe { libc::posix_spawnattr_setflags(&mut attr, flags as libc::c_short) })?;
        for fd in [0, 2] {
            // SAFETY: fixed path and initialized actions.
            check(unsafe {
                libc::posix_spawn_file_actions_addopen(
                    &mut actions,
                    fd,
                    c"/dev/null".as_ptr(),
                    libc::O_RDWR,
                    0,
                )
            })?;
        }
        for (source, target) in copies.iter().zip([3, 1, 5]) {
            // SAFETY: sources are disjoint from all destinations.
            check(unsafe {
                libc::posix_spawn_file_actions_adddup2(&mut actions, source.as_raw_fd(), target)
            })?;
        }
        // SAFETY: absolute child cwd, before exec; parent cwd is unchanged.
        check(unsafe { libc::posix_spawn_file_actions_addchdir_np(&mut actions, c"/".as_ptr()) })?;
        // fd4 has no role. The worker also closes every unwanted descriptor
        // before protection; CLOEXEC_DEFAULT closes them at spawn on macOS.
        #[cfg(target_os = "linux")]
        for entry in std::fs::read_dir("/proc/self/fd")? {
            let fd: i32 = entry?
                .file_name()
                .to_str()
                .ok_or_else(|| io::Error::other("fd census"))?
                .parse()
                .map_err(io::Error::other)?;
            if fd == 4 || fd >= 6 {
                // SAFETY: kernel-observed descriptor and initialized actions.
                check(unsafe { libc::posix_spawn_file_actions_addclose(&mut actions, fd) })?;
            }
        }
        let mut pid = 0;
        // SAFETY: initialized objects and live NUL-terminated arrays; empty environment.
        check(unsafe {
            libc::posix_spawn(
                &mut pid,
                path.as_ptr(),
                &actions,
                &attr,
                argv.as_ptr(),
                [std::ptr::null_mut()].as_ptr(),
            )
        })?;
        OwnedChild::attach(pid, expires_ns)
    })();
    // SAFETY: initialized actions, no longer used.
    unsafe { libc::posix_spawn_file_actions_destroy(&mut actions) };
    // SAFETY: initialized attributes, no longer used.
    unsafe { libc::posix_spawnattr_destroy(&mut attr) };
    result
}
