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
    exit_code: Option<i32>,
}

pub(crate) struct SignalChild {
    #[cfg(target_os = "linux")]
    // Every signal owner retains the same descriptor number across TSYNC.
    pidfd: Arc<OwnedFd>,
    #[cfg(target_os = "macos")]
    pid: libc::pid_t,
    state: Arc<Mutex<State>>,
}

pub(crate) struct OwnedChild {
    pub spawn_enter: Option<u64>,
    pub spawn_return: Option<u64>,
    signal: SignalChild,
    expires_ns: u64,
}

impl SignalChild {
    pub fn pidfd(&self) -> Option<std::os::fd::RawFd> {
        #[cfg(target_os = "linux")]
        {
            Some(self.pidfd.as_raw_fd())
        }
        #[cfg(not(target_os = "linux"))]
        {
            None
        }
    }

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
    #[cfg(test)]
    #[allow(
        dead_code,
        reason = "Linux native integration fixes the pidfd before TSYNC"
    )]
    pub fn pidfd(&self) -> Option<std::os::fd::RawFd> {
        self.signal.pidfd()
    }

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
                    pidfd: Arc::new(pidfd),
                    state: Arc::default(),
                },
                expires_ns,
                spawn_enter: None,
                spawn_return: None,
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
                spawn_enter: None,
                spawn_return: None,
            })
        }
    }

    pub fn signal(&self, signal: i32) -> io::Result<()> {
        self.signal.signal(signal)
    }

    pub fn signal_copy(&self) -> io::Result<SignalChild> {
        Ok(SignalChild {
            #[cfg(target_os = "linux")]
            pidfd: self.signal.pidfd.clone(),
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
            if state.reaped && info.si_code == libc::CLD_EXITED {
                // SAFETY: waitid returned an initialized CLD_EXITED event.
                state.exit_code = Some(unsafe { info.si_status() });
            }
        }
        #[cfg(target_os = "macos")]
        {
            let mut status = 0;
            // SAFETY: sole reaper, writable status; state excludes signals and sampling.
            let rc = unsafe { libc::waitpid(self.signal.pid, &mut status, libc::WNOHANG) };
            if rc < 0 {
                let error = io::Error::last_os_error();
                if error.raw_os_error() == Some(libc::ECHILD) {
                    state.reaped = true;
                } else {
                    return Err(error);
                }
            } else {
                state.reaped = rc == self.signal.pid;
                if state.reaped && libc::WIFEXITED(status) {
                    state.exit_code = Some(libc::WEXITSTATUS(status));
                }
            }
        }
        Ok(state.reaped)
    }

    pub fn exit_code(&self) -> Option<i32> {
        self.signal
            .state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .exit_code
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
    // Helper-side supervision clock; test builds count it as a deadline read.
    crate::prompt_io::monotonic_ns(
        #[cfg(test)]
        crate::prompt_io::ClockUse::Deadline,
    )
    .map_err(|_| io::Error::other("collection clock"))
}

pub(crate) fn pipe() -> io::Result<(File, File)> {
    let mut fds = [-1; 2];
    #[cfg(target_os = "linux")]
    // SAFETY: writable storage; CLOEXEC is set atomically at creation.
    let rc = unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) };
    #[cfg(not(target_os = "linux"))]
    // SAFETY: writable storage for two new descriptors.
    let rc = unsafe { libc::pipe(fds.as_mut_ptr()) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: both descriptors are newly owned and transferred once.
    let read = unsafe { File::from_raw_fd(fds[0]) };
    // SAFETY: the second newly owned pipe descriptor.
    let write = unsafe { File::from_raw_fd(fds[1]) };
    #[cfg(not(target_os = "linux"))]
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
    probe: Option<&super::collector::CollectorProbeFd>,
) -> io::Result<OwnedChild> {
    spawn_args_with_probe(
        path,
        &[OsStr::new("__collect-v1")],
        request,
        response,
        lock,
        expires_ns,
        probe,
    )
}

fn check(rc: i32) -> io::Result<()> {
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(rc))
    }
}

#[cfg(test)]
pub(crate) fn spawn_args(
    path: &OsStr,
    args: &[&OsStr],
    request: &File,
    response: &File,
    lock: &File,
    expires_ns: u64,
) -> io::Result<OwnedChild> {
    spawn_args_with_probe(path, args, request, response, lock, expires_ns, None)
}

#[allow(
    clippy::too_many_arguments,
    reason = "explicit, separately typed startup-only descriptor"
)]
fn spawn_args_with_probe(
    path: &OsStr,
    args: &[&OsStr],
    request: &File,
    response: &File,
    lock: &File,
    expires_ns: u64,
    probe: Option<&super::collector::CollectorProbeFd>,
) -> io::Result<OwnedChild> {
    let path = CString::new(path.as_bytes())?;
    let words = std::iter::once(Ok(path.clone()))
        .chain(args.iter().map(|v| CString::new(v.as_bytes())))
        .collect::<Result<Vec<_>, _>>()?;
    let mut argv: Vec<_> = words.iter().map(|v| v.as_ptr().cast_mut()).collect();
    argv.push(std::ptr::null_mut());
    let mut copies = Vec::new();
    let sources = [request, response, lock];
    #[cfg(target_os = "macos")]
    let sources = sources.into_iter().chain(probe.map(|p| p.spawn_source()));
    #[cfg(not(target_os = "macos"))]
    let _ = probe;
    for file in sources {
        // SAFETY: duplicate live sources above every reserved child slot.
        let fd = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 7) };
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
        for (source, target) in copies.iter().zip([3, 1, 5, 6]) {
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
        let spawn_enter = now_ns().ok();
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
        let spawn_return = now_ns().ok();
        let mut child = OwnedChild::attach(pid, expires_ns)?;
        child.spawn_enter = spawn_enter;
        child.spawn_return = spawn_return;
        Ok(child)
    })();
    // SAFETY: initialized actions, no longer used.
    unsafe { libc::posix_spawn_file_actions_destroy(&mut actions) };
    // SAFETY: initialized attributes, no longer used.
    unsafe { libc::posix_spawnattr_destroy(&mut attr) };
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    // 이것을 실패시키는 것: pipe2의 O_CLOEXEC(또는 macOS fcntl 설정) 제거.
    #[test]
    fn pipe_endpoints_are_cloexec() {
        let (read, write) = pipe().unwrap();
        for file in [read, write] {
            // SAFETY: live test-owned descriptor, read-only flag query.
            let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFD) };
            assert!(flags >= 0 && flags & libc::FD_CLOEXEC != 0);
        }
    }

    // 이것을 실패시키는 것: Linux 생성의 addclose(fd 4와 fd 6 이상)를 지우는 것. 도우미가 CLOEXEC 없이
    // 쥔 fd가 자식에 남는다.
    #[cfg(target_os = "linux")]
    #[test]
    fn spawn_closes_inherited_fds_outside_the_fixed_slots() {
        let _guard = crate::commands::sys::test_inherited_fd_lock();
        let out = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "commands::collector_process::tests::inherited_fds_parent",
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "isolated parent: leaves descriptors without CLOEXEC at 4, 6 and 1025"]
    fn inherited_fds_parent() {
        use std::io::Read;
        // SAFETY: writable limit storage.
        let mut limit: libc::rlimit = unsafe { std::mem::zeroed() };
        // SAFETY: valid resource and output pointer.
        let got = unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) };
        assert_eq!(got, 0);
        limit.rlim_cur = limit.rlim_max.min(4096);
        // SAFETY: isolated test process; soft limit within the hard limit.
        assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limit) }, 0);
        let null = File::open("/dev/null").unwrap();
        for slot in [4, 6, 1025] {
            // SAFETY: read-only query; the slot must be free in this isolated process.
            let flags = unsafe { libc::fcntl(slot, libc::F_GETFD) };
            assert!(flags < 0, "fd {slot} in use");
            // SAFETY: the free slot gets a duplicate without CLOEXEC and no Rust owner.
            assert_eq!(unsafe { libc::dup2(null.as_raw_fd(), slot) }, slot);
        }
        let path = std::env::temp_dir().join(format!("b2-collector-fds-{}", std::process::id()));
        let lock = File::create(&path).unwrap();
        std::fs::remove_file(&path).unwrap();
        let (request, _write) = pipe().unwrap();
        let (mut response, write) = pipe().unwrap();
        let mut child = spawn_args(
            std::env::current_exe().unwrap().as_os_str(),
            &[
                OsStr::new("--exact"),
                OsStr::new("commands::collector_process::tests::inherited_fds_child"),
                OsStr::new("--ignored"),
                OsStr::new("--nocapture"),
                OsStr::new("--test-threads=1"),
            ],
            &request,
            &write,
            &lock,
            now_ns().unwrap() + 5_000_000_000,
        )
        .unwrap();
        drop(write);
        let mut bytes = String::new();
        response.read_to_string(&mut bytes).unwrap();
        while !child.reap().unwrap() {
            std::thread::yield_now();
        }
        assert!(bytes.contains("collector census passed"), "{bytes}");
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "isolated child of spawn_closes_inherited_fds_outside_the_fixed_slots"]
    fn inherited_fds_child() {
        for fd in 0..2048 {
            // SAFETY: read-only descriptor query, invalid slots are expected.
            let open = unsafe { libc::fcntl(fd, libc::F_GETFD) } >= 0;
            assert_eq!(open, [0, 1, 2, 3, 5].contains(&fd), "fd {fd}");
        }
        println!("collector census passed");
    }

    // 이것을 실패시키는 것: signal_copy가 별도 fd 번호를 복제하는 것.
    #[cfg(target_os = "linux")]
    #[test]
    fn signal_copies_retain_one_descriptor_number() {
        // SAFETY: read-only own identity query.
        let pid = unsafe { libc::getpid() };
        // SAFETY: acquisition of our own pidfd.
        let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
        assert!(fd >= 0);
        let child = OwnedChild {
            spawn_enter: None,
            spawn_return: None,
            signal: SignalChild {
                // SAFETY: newly owned descriptor, transferred exactly once.
                pidfd: Arc::new(unsafe { OwnedFd::from_raw_fd(fd as i32) }),
                // Mark reaped so this descriptor-sharing test never signals.
                state: Arc::new(Mutex::new(State {
                    killed: false,
                    reaped: true,
                    exit_code: None,
                })),
            },
            expires_ns: 0,
        };
        let first = child.signal_copy().unwrap();
        let second = child.signal_copy().unwrap();
        assert_eq!(first.pidfd(), child.pidfd());
        assert_eq!(second.pidfd(), child.pidfd());
        drop(child);
        drop(first);
        // SAFETY: the last Arc must retain the original descriptor.
        assert!(unsafe { libc::fcntl(second.pidfd().unwrap(), libc::F_GETFD) } >= 0);
    }

    // 이것을 실패시키는 것: ECHILD 뒤 reaped=true 전이를 제거하는 것.
    #[cfg(target_os = "macos")]
    #[test]
    fn echild_marks_reaped_before_any_later_signal() {
        // Our own PID cannot be our child, so waitpid must return ECHILD.
        // Mark killed for panic-safe teardown even under the deliberate mutation.
        let mut child = OwnedChild {
            spawn_enter: None,
            spawn_return: None,
            signal: SignalChild {
                // SAFETY: read-only own identity.
                pid: unsafe { libc::getpid() },
                state: Arc::new(Mutex::new(State {
                    killed: true,
                    reaped: false,
                    exit_code: None,
                })),
            },
            expires_ns: 0,
        };
        let copy = child.signal_copy().unwrap();
        assert!(child.reap().unwrap());
        assert!(copy.reaped());
        child.signal.state.lock().unwrap().killed = false;
        // Signal 0 is harmless even if the reaped guard is mutated away.
        copy.signal(0).unwrap();
        assert!(!child.kill_requested());
        assert!(child.reap().unwrap());
    }
}

#[cfg(all(test, target_os = "macos"))]
mod probe_tests {
    use super::*;
    use std::{io::Read, os::unix::fs::PermissionsExt};
    struct Cleanup(std::path::PathBuf);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    // 이것을 실패시키는 것: helper의 probe source를 fd6에 dup2하지 않거나 임시 복사 fd를 상속하는 것.
    #[test]
    fn probe_spawn_targets_only_fd_six() {
        let _guard = crate::commands::sys::test_inherited_fd_lock();
        let path = std::env::temp_dir().join(format!("b2-spawn-probe-{}", std::process::id()));
        std::fs::create_dir(&path).unwrap();
        let _cleanup = Cleanup(path.clone());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        let probe = super::super::collector::CollectorProbeFd::prepare(&File::open(&path).unwrap())
            .unwrap();
        let lock = File::create(path.join("lock")).unwrap();
        for (name, fixture) in [
            ("probe_spawn_child", Some(&probe)),
            ("probe_absent_child", None),
        ] {
            let (request, _write) = pipe().unwrap();
            let (mut response, write) = pipe().unwrap();
            let test = format!("commands::collector_process::probe_tests::{name}");
            let mut child = spawn_args_with_probe(
                std::env::current_exe().unwrap().as_os_str(),
                &[
                    OsStr::new("--exact"),
                    OsStr::new(&test),
                    OsStr::new("--ignored"),
                    OsStr::new("--nocapture"),
                    OsStr::new("--test-threads=1"),
                ],
                &request,
                &write,
                &lock,
                now_ns().unwrap() + 1_000_000_000,
                fixture,
            )
            .unwrap();
            drop(write);
            let mut bytes = String::new();
            response.read_to_string(&mut bytes).unwrap();
            while !child.reap().unwrap() {
                std::thread::yield_now();
            }
            assert!(bytes.contains("probe handoff passed"), "{bytes}");
        }
    }
    #[allow(
        clippy::disallowed_methods,
        reason = "isolated test child verifies the empty spawn environment"
    )]
    fn child_census(probe: bool) {
        assert!(std::env::vars_os().next().is_none());
        assert_eq!(std::env::current_dir().unwrap(), std::path::Path::new("/"));
        for fd in 0..64 {
            // SAFETY: read-only descriptor query, invalid slots are expected.
            let open = unsafe { libc::fcntl(fd, libc::F_GETFD) } >= 0;
            assert_eq!(
                open,
                [0, 1, 2, 3, 5].contains(&fd) || (probe && fd == 6),
                "fd {fd}"
            );
        }
        if probe {
            // SAFETY: inherited fixture dir, fixed no-follow read-only name.
            let fd =
                unsafe { libc::openat(6, c"value".as_ptr(), libc::O_RDONLY | libc::O_NOFOLLOW) };
            assert!(fd >= 0);
            // SAFETY: newly owned descriptor.
            let mut file = unsafe { File::from_raw_fd(fd) };
            let mut bytes = Vec::new();
            file.read_to_end(&mut bytes).unwrap();
            assert_eq!(bytes, b"inside");
        }
        println!("probe handoff passed");
    }
    // 이것을 실패시키는 것: probe source·fd6 dup2 누락 (상위 시험이 실행하고 실패를 확인).
    #[test]
    #[ignore = "isolated child of probe_spawn_targets_only_fd_six"]
    fn probe_spawn_child() {
        child_census(true);
    }
    // 이것을 실패시키는 것: probe 부재에도 fd6이나 spawn 임시 fd를 남기는 것.
    #[test]
    #[ignore = "isolated child of probe_spawn_targets_only_fd_six"]
    fn probe_absent_child() {
        child_census(false);
    }
}
