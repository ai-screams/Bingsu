//! Descriptor-only entry checks and the B2 protection seam. No spawn APIs.
use std::{
    fs::File,
    io::{self, Read, Write},
    os::fd::FromRawFd,
};

/// Unique ownership of the private result/request pipes and the inherited lock.
/// Dropping the lock only closes it: never LOCK_UN on a shared description.
pub struct WorkerFds {
    result: File,
    request: File,
    _lock: File,
}
impl WorkerFds {
    pub(crate) fn read_exact(&mut self, bytes: &mut [u8]) -> io::Result<()> {
        self.request.read_exact(bytes)
    }
    pub(crate) fn write_all(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.result.write_all(bytes)
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
            if record.proc_fd >= 6 {
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
    Ok(WorkerFds {
        result,
        request,
        _lock: lock,
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

/// Landlock precedes the initial filter; any protection error prevents Ready.
pub(crate) fn initial_filter() -> io::Result<u32> {
    #[cfg(target_os = "linux")]
    {
        let state = crate::landlock::install_read_only()?;
        crate::filter::install_bootstrap()?;
        Ok(match state {
            crate::landlock::LandlockState::Installed { abi } => abi,
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
        crate::filter::seal_limits()
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
