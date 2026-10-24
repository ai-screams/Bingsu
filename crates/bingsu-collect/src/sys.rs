//! Descriptor-only entry checks and the B2 protection seam. No spawn APIs.
use std::{
    fs::File,
    io::{self, Read, Write},
    os::fd::FromRawFd,
};

/// Best-effort orphan fallback for an idle or cooperative worker. The helper's
/// absolute supervision deadline remains authoritative, even with no frames.
pub(crate) fn orphan_guard() -> io::Result<()> {
    // SAFETY: writable signal action, initialized before registration.
    let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
    action.sa_sigaction = libc::SIG_DFL;
    // SAFETY: writable empty signal set.
    if unsafe { libc::sigemptyset(&mut action.sa_mask) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: worker-local SIGALRM default disposition.
    if unsafe { libc::sigaction(libc::SIGALRM, &action, std::ptr::null_mut()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let mut mask = action.sa_mask;
    // SAFETY: initialized set and valid signal number.
    if unsafe { libc::sigaddset(&mut mask, libc::SIGALRM) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: only the worker's timer signal is unblocked.
    if unsafe { libc::sigprocmask(libc::SIG_UNBLOCK, &mask, std::ptr::null_mut()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: process-local one-second fallback, armed before startup I/O.
    unsafe { libc::alarm(1) };
    #[cfg(target_os = "linux")]
    {
        // SAFETY: read-only parent identity, before installing the death signal.
        let parent = unsafe { libc::getppid() };
        // SAFETY: worker-local fallback; does not grant any capability.
        if unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) } != 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: detect a death/reparenting race during installation.
        if parent == 1 || unsafe { libc::getppid() } != parent {
            return Err(io::Error::other("worker parent exited"));
        }
    }
    Ok(())
}

/// Unique ownership of the private result/request pipes and the inherited lock.
/// Dropping the lock only closes it: never LOCK_UN on a shared description.
pub struct WorkerFds {
    result: File,
    request: File,
    _lock: File,
    #[cfg(target_os = "macos")]
    probe: Option<CollectorProbeFd>,
}

/// Owns only the optional startup fd 6. It cannot be converted to a content Root.
#[cfg(target_os = "macos")]
pub(crate) struct CollectorProbeFd(File);

impl WorkerFds {
    #[cfg(target_os = "macos")]
    pub(crate) fn take_probe(&mut self) -> Option<CollectorProbeFd> {
        self.probe.take()
    }
    pub(crate) fn read_exact(&mut self, bytes: &mut [u8]) -> io::Result<()> {
        self.request.read_exact(bytes)
    }
    pub(crate) fn write_all(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.result.write_all(bytes)
    }
    pub(crate) fn write_all_until(
        &mut self,
        bytes: &[u8],
        deadline: std::time::Instant,
        stage_deadline: &std::cell::Cell<std::time::Instant>,
    ) -> io::Result<()> {
        write_checked(&mut self.result, bytes, || {
            if std::time::Instant::now() >= deadline.min(stage_deadline.get()) {
                Err(io::ErrorKind::TimedOut.into())
            } else {
                Ok(())
            }
        })
    }
}

// Check again between short writes/EINTR, including after encoding a frame.
// A write blocked in the kernel remains bounded by external supervision.
fn write_checked(
    writer: &mut impl Write,
    mut bytes: &[u8],
    check: impl Fn() -> io::Result<()>,
) -> io::Result<()> {
    while !bytes.is_empty() {
        check()?;
        match writer.write(bytes) {
            Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
            Ok(n) => bytes = &bytes[n..],
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

#[cfg(target_os = "macos")]
impl CollectorProbeFd {
    pub(crate) fn fixture(&self) -> std::os::fd::BorrowedFd<'_> {
        use std::os::fd::AsFd;
        self.0.as_fd()
    }
}
fn stat(fd: i32) -> io::Result<libc::stat> {
    // SAFETY: integer-only output structure.
    let mut value = unsafe { std::mem::zeroed() };
    // SAFETY: fstat validates fd; output is valid writable storage.
    if unsafe { libc::fstat(fd, &mut value) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(value)
}
fn access(fd: i32, expected: i32) -> io::Result<()> {
    // SAFETY: read-only descriptor query.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 || flags & libc::O_ACCMODE != expected {
        return Err(io::Error::other("descriptor access"));
    }
    Ok(())
}
fn null_device(fd: i32) -> io::Result<()> {
    let value = stat(fd)?;
    if value.st_mode & libc::S_IFMT != libc::S_IFCHR {
        return Err(io::Error::other("null device type"));
    }
    #[cfg(target_os = "linux")]
    if value.st_rdev != libc::makedev(1, 3) {
        return Err(io::Error::other("null device identity"));
    }
    #[cfg(target_os = "macos")]
    {
        let mut path = [0u8; libc::PATH_MAX as usize];
        // SAFETY: writable PATH_MAX buffer for this descriptor-only query.
        if unsafe { libc::fcntl(fd, libc::F_GETPATH, path.as_mut_ptr()) } != 0
            || path[..10] != *b"/dev/null\0"
        {
            return Err(io::Error::other("null device identity"));
        }
    }
    Ok(())
}

/// Close unwanted descriptors before NOFILE falls. No /proc path observation.
fn close_extras() -> io::Result<()> {
    #[cfg(target_os = "linux")]
    linux_floor()?;
    // SAFETY: fd4 is forbidden and not owned by a Rust object in this entry.
    unsafe { libc::close(4) };
    #[cfg(target_os = "linux")]
    {
        // SAFETY: this single-threaded entry owns all inherited descriptors.
        if unsafe { libc::syscall(libc::SYS_close_range, 6u32, u32::MAX, 0u32) } != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    #[cfg(target_os = "macos")]
    {
        // A fixed census also detects inherited descriptors above a lowered
        // hard limit. Too many inherited descriptors fail closed.
        // SAFETY: integer-only array of proc_fdinfo records.
        let mut records: [libc::proc_fdinfo; 256] = unsafe { std::mem::zeroed() };
        // SAFETY: no arguments.
        let pid = unsafe { libc::getpid() };
        // SAFETY: PROC_PIDLISTFDS writes at most the supplied array length.
        let n = unsafe {
            libc::proc_pidinfo(
                pid,
                libc::PROC_PIDLISTFDS,
                0,
                records.as_mut_ptr().cast(),
                std::mem::size_of_val(&records) as i32,
            )
        };
        let n = usize::try_from(n).map_err(|_| io::Error::last_os_error())?;
        if n == 0
            || n >= std::mem::size_of_val(&records)
            || n % std::mem::size_of::<libc::proc_fdinfo>() != 0
        {
            return Err(io::Error::other("descriptor census"));
        }
        for record in &records[..n / std::mem::size_of::<libc::proc_fdinfo>()] {
            let probe_directory = record.proc_fd == 6
                && stat(6).is_ok_and(|s| s.st_mode & libc::S_IFMT == libc::S_IFDIR);
            if record.proc_fd >= 6 && !probe_directory {
                // SAFETY: inherited descriptor from the single-threaded census.
                if unsafe { libc::close(record.proc_fd) } != 0 {
                    return Err(io::Error::last_os_error());
                }
            }
        }
    }
    Ok(())
}

/// Entry-only API: call once before constructing any descriptor owners.
pub fn validate_worker_fds() -> io::Result<WorkerFds> {
    static TAKEN: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    if TAKEN.swap(true, std::sync::atomic::Ordering::Relaxed) {
        return Err(io::Error::other("worker descriptors already claimed"));
    }
    close_extras()?;
    null_device(0)?;
    null_device(2)?;
    access(1, libc::O_WRONLY)?;
    access(3, libc::O_RDONLY)?;
    for fd in [1, 3] {
        if stat(fd)?.st_mode & libc::S_IFMT != libc::S_IFIFO {
            return Err(io::Error::other("private pipe required"));
        }
    }
    // Linux must not inherit a writable regular file, even the close-only lock.
    #[cfg(target_os = "linux")]
    access(5, libc::O_RDONLY)?;
    let lock = stat(5)?;
    // SAFETY: read-only effective uid query.
    let me = unsafe { libc::geteuid() };
    if lock.st_mode & libc::S_IFMT != libc::S_IFREG
        || lock.st_mode & 0o7777 != 0o600
        || lock.st_uid != me
        || lock.st_size != 0
        || lock.st_nlink != 1
    {
        return Err(io::Error::other("lock descriptor"));
    }
    // Lock validity includes ACLs; inheritance does not authorize filesystem I/O.
    #[cfg(target_os = "linux")]
    {
        // SAFETY: fixed attribute name, size-only descriptor query.
        let n = unsafe {
            libc::fgetxattr(
                5,
                c"system.posix_acl_access".as_ptr(),
                std::ptr::null_mut(),
                0,
            )
        };
        if n >= 0 || io::Error::last_os_error().raw_os_error() != Some(libc::ENODATA) {
            return Err(io::Error::other("lock ACL"));
        }
    }
    #[cfg(target_os = "macos")]
    {
        // SAFETY: descriptor-only ACL query returns an owned ACL.
        let acl = unsafe { acl_get_fd_np(5, 0x100) };
        if acl.is_null() {
            if io::Error::last_os_error().raw_os_error() != Some(libc::ENOENT) {
                return Err(io::Error::last_os_error());
            }
        } else {
            let mut entry = std::ptr::null_mut();
            // SAFETY: live ACL and writable entry output.
            let rc = unsafe { acl_get_entry(acl, 0, &mut entry) };
            let errno = io::Error::last_os_error().raw_os_error();
            // SAFETY: frees the ACL exactly once.
            unsafe { acl_free(acl) };
            if rc != -1 || errno != Some(libc::EINVAL) {
                return Err(io::Error::other("lock ACL"));
            }
        }
    }
    // SAFETY: all three descriptors were checked; entry transfers them once.
    let result = unsafe { File::from_raw_fd(1) };
    // SAFETY: checked descriptor, no other Rust owner.
    let request = unsafe { File::from_raw_fd(3) };
    // SAFETY: checked descriptor; close-only ownership, never flock unlock.
    let lock = unsafe { File::from_raw_fd(5) };
    #[cfg(target_os = "macos")]
    let probe = match stat(6) {
        // Only ownership is taken here. Fixture IO and validation follow protection.
        // SAFETY: entry owns this checked inherited descriptor exactly once.
        Ok(_) => Some(CollectorProbeFd(unsafe { File::from_raw_fd(6) })),
        Err(e) if e.raw_os_error() == Some(libc::EBADF) => None,
        Err(e) => return Err(e),
    };
    Ok(WorkerFds {
        result,
        request,
        _lock: lock,
        #[cfg(target_os = "macos")]
        probe,
    })
}

pub(crate) fn hygiene() -> io::Result<()> {
    if std::env::vars_os().next().is_some() || std::env::current_dir()?.as_os_str() != "/" {
        return Err(io::Error::other("worker environment or cwd"));
    }
    // SAFETY: changes only the dedicated worker's process-local creation mask.
    unsafe { libc::umask(0o077) };
    Ok(())
}

pub(crate) fn no_new_privs() -> io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        // SAFETY: integer-only irreversible privilege restriction.
        if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
static WRITE_POLICY: std::sync::OnceLock<crate::filter::Openat2Policy> = std::sync::OnceLock::new();

/// Landlock precedes the initial filter; any protection error prevents Ready.
pub(crate) fn initial_filter() -> io::Result<u32> {
    #[cfg(target_os = "linux")]
    {
        let state = crate::landlock::install_read_only()?;
        let mode = if state.covers_openat2_writes() {
            crate::filter::Openat2Policy::WriteSetCovered
        } else {
            crate::filter::Openat2Policy::Deny
        };
        crate::filter::install_bootstrap(mode)?;
        WRITE_POLICY
            .set(mode)
            .map_err(|_| io::Error::other("filter already installed"))?;
        Ok(match state {
            crate::landlock::LandlockState::Installed { abi, .. } => abi,
            crate::landlock::LandlockState::Absent => 0,
        })
    }
    #[cfg(target_os = "macos")]
    {
        Ok(0)
    } // Audited binary + external sampling, not a kernel execution ban.
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        Err(io::ErrorKind::Unsupported.into())
    }
}
pub(crate) fn final_filter() -> io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        crate::filter::seal_limits(
            *WRITE_POLICY
                .get()
                .ok_or_else(|| io::Error::other("missing write policy"))?,
        )
    }
    #[cfg(target_os = "macos")]
    {
        Ok(())
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        Err(io::ErrorKind::Unsupported.into())
    }
}

#[cfg(target_os = "macos")]
unsafe extern "C" {
    fn acl_get_fd_np(fd: i32, kind: i32) -> *mut libc::c_void;
    fn acl_get_entry(acl: *mut libc::c_void, id: i32, entry: *mut *mut libc::c_void) -> i32;
    fn acl_free(acl: *mut libc::c_void) -> i32;
}

// The floor is a deployment policy, never a substitute for probing features.
#[cfg(any(test, target_os = "linux"))]
fn supported_release(release: &[u8]) -> bool {
    let mut parts = release.split(|b| *b == b'.');
    let number = |part: Option<&[u8]>| {
        part.and_then(|p| std::str::from_utf8(p).ok())
            .and_then(|p| p.parse::<u32>().ok())
    };
    matches!((number(parts.next()), number(parts.next())), (Some(major), Some(minor))
        if (major, minor) >= (5, 9))
}

#[cfg(target_os = "linux")]
fn linux_floor() -> io::Result<()> {
    // SAFETY: plain output record; uname initializes every string field.
    let mut name: libc::utsname = unsafe { std::mem::zeroed() };
    // SAFETY: writable uname record.
    if unsafe { libc::uname(&mut name) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: uname release is a NUL-terminated fixed array on success.
    let release = unsafe { std::ffi::CStr::from_ptr(name.release.as_ptr()) };
    if !supported_release(release.to_bytes()) {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Linux 5.9 required",
        ));
    }
    // The helper also requires pidfd supervision; verify actual availability
    // before seccomp. close_range is checked by close_extras; STATX_MNT_ID is
    // checked by the protected fixed-root probe before Ready.
    // SAFETY: read-only process identity.
    let pid = unsafe { libc::getpid() };
    // SAFETY: read-only handle to our own process, flags zero.
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0u32) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fresh descriptor, closed once without releasing any lock.
    unsafe { libc::close(fd as i32) };
    Ok(())
}

#[cfg(all(test, target_os = "linux"))]
#[allow(dead_code, reason = "integration test injection only")]
pub fn required_features_for_test() -> io::Result<()> {
    close_extras()
}

#[cfg(test)]
mod floor_tests {
    use super::*;
    // 이것을 실패시키는 것: 커널 하한을 5.8로 낮추거나 잘못된 버전을 허용하는 것.
    #[test]
    fn linux_collection_floor_requires_capabilities() {
        for old in [b"5.8.18".as_slice(), b"4.19.0", b"5", b"unknown", b"5.x.0"] {
            assert!(!supported_release(old));
        }
        for supported in [b"5.9.0".as_slice(), b"6.1.0-vendor", b"7.0.0"] {
            assert!(supported_release(supported));
        }
    }
}

#[cfg(test)]
mod write_deadline_tests {
    use super::*;
    use std::cell::Cell;
    // 이것을 실패시키는 것: 첫 write 또는 short write/EINTR 재시도 전 마감 검사 제거.
    #[test]
    fn response_checks_deadline_before_each_write_attempt() {
        struct Writer {
            attempts: usize,
            interrupt: bool,
            bytes: Vec<u8>,
        }
        impl Write for Writer {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                self.attempts += 1;
                if self.interrupt {
                    return Err(io::ErrorKind::Interrupted.into());
                }
                self.bytes.push(bytes[0]);
                Ok(1)
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        for interrupt in [false, true] {
            for allowed in [0, 1, 3] {
                let checks = Cell::new(0);
                let mut writer = Writer {
                    attempts: 0,
                    interrupt,
                    bytes: Vec::new(),
                };
                let error = write_checked(&mut writer, b"frame", || {
                    let old = checks.replace(checks.get() + 1);
                    if old == allowed {
                        Err(io::ErrorKind::TimedOut.into())
                    } else {
                        Ok(())
                    }
                })
                .unwrap_err();
                assert_eq!(error.kind(), io::ErrorKind::TimedOut);
                assert_eq!(writer.attempts, allowed);
                assert_eq!(
                    writer.bytes,
                    if interrupt {
                        &b""[..]
                    } else {
                        &b"frame"[..allowed]
                    }
                );
            }
        }
        let mut bytes = Vec::new();
        write_checked(&mut bytes, b"frame", || Ok(())).unwrap();
        assert_eq!(bytes, b"frame");
    }
}
