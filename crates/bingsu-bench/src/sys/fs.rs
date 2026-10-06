//! Thin syscall wrappers so the synthetic program makes exactly the calls
//! it claims (std may add calls of its own).
use std::ffi::CStr;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

fn cvt(r: libc::c_long) -> io::Result<usize> {
    if r < 0 {
        Err(io::Error::last_os_error())
    } else {
        // A non-negative c_long always fits in usize on the 64-bit Linux
        // targets this runs on; anything else is a broken invariant.
        Ok(usize::try_from(r).expect("non-negative syscall result fits in usize"))
    }
}

pub fn openat(dir: RawFd, path: &CStr, flags: libc::c_int) -> io::Result<OwnedFd> {
    // SAFETY: `path` is NUL-terminated; mode is used only with O_CREAT.
    let fd = unsafe {
        libc::openat(
            dir,
            path.as_ptr(),
            flags | libc::O_CLOEXEC,
            0o600 as libc::c_uint,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` was just returned by openat and is owned by nobody else.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

pub fn fstat(fd: &OwnedFd) -> io::Result<libc::stat> {
    // SAFETY: an all-zero stat is a valid out-parameter.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: `st` is a valid, writable stat buffer.
    let r = unsafe { libc::fstat(fd.as_raw_fd(), &mut st) };
    cvt(r.into()).map(|_| st)
}

pub fn read(fd: &OwnedFd, buf: &mut [u8]) -> io::Result<usize> {
    // SAFETY: `buf` is writable for `buf.len()` bytes.
    cvt(unsafe { libc::read(fd.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len()) } as libc::c_long)
}

pub fn write(fd: &OwnedFd, buf: &[u8]) -> io::Result<usize> {
    // SAFETY: `buf` is readable for `buf.len()` bytes.
    cvt(unsafe { libc::write(fd.as_raw_fd(), buf.as_ptr().cast(), buf.len()) } as libc::c_long)
}

pub fn getdents64(fd: &OwnedFd, buf: &mut [u8]) -> io::Result<usize> {
    // SAFETY: `buf` is writable for `buf.len()` bytes; getdents64 writes at most that.
    cvt(unsafe {
        libc::syscall(
            libc::SYS_getdents64,
            fd.as_raw_fd(),
            buf.as_mut_ptr(),
            buf.len(),
        )
    })
}

pub fn readlinkat(dir: RawFd, path: &CStr, buf: &mut [u8]) -> io::Result<usize> {
    // SAFETY: `path` is NUL-terminated and `buf` writable for its length.
    cvt(
        unsafe { libc::readlinkat(dir, path.as_ptr(), buf.as_mut_ptr().cast(), buf.len()) }
            as libc::c_long,
    )
}

pub fn fstatfs(fd: &OwnedFd) -> io::Result<()> {
    // SAFETY: an all-zero statfs is a valid out-parameter.
    let mut s: libc::statfs = unsafe { std::mem::zeroed() };
    // SAFETY: `s` is a valid, writable statfs buffer.
    cvt(unsafe { libc::fstatfs(fd.as_raw_fd(), &mut s) }.into()).map(|_| ())
}

/// POSIX ACL probe; ENODATA (no ACL) is the normal answer.
pub fn acl_probe(fd: &OwnedFd) {
    // SAFETY: the name is NUL-terminated; size 0 asks only for the length.
    let _ = unsafe {
        libc::fgetxattr(
            fd.as_raw_fd(),
            c"system.posix_acl_access".as_ptr(),
            std::ptr::null_mut(),
            0,
        )
    };
}

pub fn flock_ex_nb(fd: &OwnedFd) -> io::Result<()> {
    // SAFETY: flock takes an fd and flags only.
    cvt(unsafe { libc::flock(fd.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) }.into()).map(|_| ())
}

pub fn renameat(dir: RawFd, from: &CStr, to: &CStr) -> io::Result<()> {
    // SAFETY: both names are NUL-terminated.
    cvt(unsafe { libc::renameat(dir, from.as_ptr(), dir, to.as_ptr()) }.into()).map(|_| ())
}

/// Opens or closes the counting window of the budget scaffold. A failure is
/// returned (and the scaffold also rejects a failed prctl in the trace).
pub fn marker(name: &CStr) -> io::Result<()> {
    // SAFETY: PR_SET_NAME reads a NUL-terminated string of at most 16 bytes.
    cvt(unsafe { libc::prctl(libc::PR_SET_NAME, name.as_ptr()) }.into()).map(|_| ())
}

/// Duplicates `fd` onto `target` without FD_CLOEXEC, so spawned roles
/// inherit the runtime-root fd (the reserved-fd hand-over of spec section 4
/// "fd inheritance").
///
/// # Safety
///
/// `target` must not be owned by anything in this process (no `OwnedFd`,
/// `File` or library holds it): dup2 closes whatever is open there, which
/// would break that owner's I/O safety.
pub unsafe fn dup_to_reserved(fd: &OwnedFd, target: RawFd) -> io::Result<()> {
    // SAFETY: dup2 takes two integers; the caller guarantees nothing owns `target`.
    cvt(unsafe { libc::dup2(fd.as_raw_fd(), target) }.into()).map(|_| ())
}

/// The inherited runtime-root fd as an owned fd.
///
/// # Safety
///
/// `fd` must be open and owned by nobody else in this process, and this
/// must be called at most once per fd.
pub unsafe fn inherited(fd: RawFd) -> OwnedFd {
    // SAFETY: the caller guarantees `fd` is open and has no other owner.
    unsafe { OwnedFd::from_raw_fd(fd) }
}
