//! Per-call filesystem costs (spec section 9 M1 row (7), "lock and
//! generation check" and the `statfs` of `init`). Every failed system call
//! is returned: a failure timed as a success would be a wrong number.
use std::ffi::CString;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

fn cpath(p: &Path) -> io::Result<CString> {
    CString::new(p.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains NUL"))
}

fn ok(r: libc::c_int) -> io::Result<()> {
    if r == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// open(2) with O_NOFOLLOW | O_CLOEXEC added to `flags`.
fn open_nofollow(p: &Path, flags: libc::c_int) -> io::Result<OwnedFd> {
    let c = cpath(p)?;
    // SAFETY: the path is NUL-terminated; no O_CREAT, so no mode argument.
    let raw = unsafe { libc::open(c.as_ptr(), flags | libc::O_NOFOLLOW | libc::O_CLOEXEC) };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `raw` is a new descriptor owned by nobody else; dropping closes it once.
    Ok(unsafe { OwnedFd::from_raw_fd(raw) })
}

fn fstat_uid(fd: &OwnedFd) -> io::Result<libc::uid_t> {
    // SAFETY: an all-zero stat is a valid out-parameter; it is read only after fstat succeeded.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: `fd` is open; `st` is writable.
    ok(unsafe { libc::fstat(fd.as_raw_fd(), &mut st) })?;
    Ok(st.st_uid)
}

pub fn stat_path(p: &Path) -> io::Result<()> {
    let c = cpath(p)?;
    // SAFETY: an all-zero stat is a valid out-parameter.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: the path is NUL-terminated; `st` is writable.
    ok(unsafe { libc::stat(c.as_ptr(), &mut st) })
}

pub fn lstat_path(p: &Path) -> io::Result<()> {
    let c = cpath(p)?;
    // SAFETY: an all-zero stat is a valid out-parameter.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: the path is NUL-terminated; `st` is writable.
    ok(unsafe { libc::lstat(c.as_ptr(), &mut st) })
}

pub fn statfs_path(p: &Path) -> io::Result<()> {
    let c = cpath(p)?;
    // SAFETY: an all-zero statfs is a valid out-parameter.
    let mut s: libc::statfs = unsafe { std::mem::zeroed() };
    // SAFETY: the path is NUL-terminated; `s` is writable.
    ok(unsafe { libc::statfs(c.as_ptr(), &mut s) })
}

/// ACL lookup by path, not following a final symlink, the way the product
/// asks (`bingsu::sys::acl_facts`): Linux POSIX access ACL xattr, macOS
/// extended ACL. `Ok(false)` is "no ACL" (Linux ENODATA or ENOTSUP, macOS
/// a NULL result with ENOENT, which a missing file also gives); any other
/// failure is an error.
pub fn acl_probe_path(p: &Path) -> io::Result<bool> {
    let c = cpath(p)?;
    #[cfg(target_os = "linux")]
    {
        // SAFETY: names are NUL-terminated; size 0 asks only for the length.
        let n = unsafe {
            libc::lgetxattr(
                c.as_ptr(),
                c"system.posix_acl_access".as_ptr(),
                std::ptr::null_mut(),
                0,
            )
        };
        if n >= 0 {
            return Ok(n > 0);
        }
        let e = io::Error::last_os_error();
        match e.raw_os_error() {
            Some(libc::ENODATA | libc::ENOTSUP) => Ok(false),
            _ => Err(e),
        }
    }
    #[cfg(target_os = "macos")]
    {
        unsafe extern "C" {
            fn acl_get_link_np(path: *const libc::c_char, ty: libc::c_int) -> *mut libc::c_void;
            fn acl_free(obj: *mut libc::c_void) -> libc::c_int;
        }
        // <sys/acl.h>, checked against the SDK on 2026-10-07.
        const ACL_TYPE_EXTENDED: libc::c_int = 0x0000_0100;
        // SAFETY: the path is NUL-terminated; NULL means no ACL or an error.
        let acl = unsafe { acl_get_link_np(c.as_ptr(), ACL_TYPE_EXTENDED) };
        if acl.is_null() {
            let e = io::Error::last_os_error();
            return if e.raw_os_error() == Some(libc::ENOENT) {
                Ok(false)
            } else {
                Err(e)
            };
        }
        // SAFETY: `acl` was returned by acl_get_link_np and is freed once.
        // acl_free fails only for a pointer the ACL library did not return.
        unsafe { acl_free(acl) };
        Ok(true)
    }
}

/// openat + fstat + ceil(size / buf.len()) reads (no end check) + close.
/// Returns the number of read calls made. An fstat or read failure is
/// returned, and a file that ends before `size` bytes is `UnexpectedEof`
/// (a short fixture would otherwise be timed as a valid read).
pub fn open_fstat_read_close(
    dir: &Path,
    name: &str,
    size: usize,
    buf: &mut [u8],
) -> io::Result<usize> {
    let fd = open_nofollow(&dir.join(name), libc::O_RDONLY)?;
    let read = |b: &mut [u8]| {
        // SAFETY: `b` is writable for `b.len()` bytes.
        let n = unsafe { libc::read(fd.as_raw_fd(), b.as_mut_ptr().cast(), b.len()) };
        if n < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(n as usize)
        }
    };
    read_counted(size, buf, || fstat_uid(&fd).map(drop), read)
}

/// The read loop of `open_fstat_read_close`, with fstat and read passed in
/// so faults can be tested.
fn read_counted(
    size: usize,
    buf: &mut [u8],
    fstat: impl FnOnce() -> io::Result<()>,
    mut read: impl FnMut(&mut [u8]) -> io::Result<usize>,
) -> io::Result<usize> {
    if buf.is_empty() && size > 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "empty read buffer",
        ));
    }
    fstat()?;
    let (mut reads, mut left) = (0, size);
    while left > 0 {
        let want = buf.len().min(left);
        let n = read(&mut buf[..want])?;
        reads += 1;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                format!("{left} of {size} bytes missing"),
            ));
        }
        left -= n;
    }
    Ok(reads)
}

/// O_NOFOLLOW open + fstat owner check + non-blocking flock + 8-byte
/// generation read (bytes 8..16 of the header) + unlock (spec section 4
/// helper "concurrency" row). `Ok(true)` only when the lock file is ours,
/// the lock is free and the generation matches; every failed system call is
/// an error, and the lock is released even when reading the generation fails.
pub fn lock_and_read_generation(lock: &Path, header: &Path, expect_gen: u64) -> io::Result<bool> {
    let fd = open_nofollow(lock, libc::O_RDWR)?;
    let try_lock = || {
        // SAFETY: flock takes an fd and flags only.
        if unsafe { libc::flock(fd.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
            return Ok(true);
        }
        let e = io::Error::last_os_error();
        if e.raw_os_error() == Some(libc::EWOULDBLOCK) {
            Ok(false)
        } else {
            Err(e)
        }
    };
    let read_gen = || {
        let h = open_nofollow(header, libc::O_RDONLY)?;
        let mut g = [0u8; 8];
        // SAFETY: `g` is 8 writable bytes.
        let n = unsafe { libc::pread(h.as_raw_fd(), g.as_mut_ptr().cast(), 8, 8) };
        match n {
            8 => Ok(u64::from_le_bytes(g)),
            n if n < 0 => Err(io::Error::last_os_error()),
            _ => Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "header shorter than 16 bytes",
            )),
        }
    };
    // SAFETY: flock takes an fd and flags only.
    let unlock = || ok(unsafe { libc::flock(fd.as_raw_fd(), libc::LOCK_UN) });
    // SAFETY: getuid has no preconditions and cannot fail.
    let me = unsafe { libc::getuid() };
    check_lock_and_generation(
        expect_gen,
        me,
        || fstat_uid(&fd),
        try_lock,
        read_gen,
        unlock,
    )
}

/// The decision of `lock_and_read_generation` with each system call passed
/// in, so failures can be injected. The lock is released even when reading
/// the generation fails.
fn check_lock_and_generation(
    expect_gen: u64,
    me: libc::uid_t,
    owner: impl FnOnce() -> io::Result<libc::uid_t>,
    try_lock: impl FnOnce() -> io::Result<bool>,
    read_gen: impl FnOnce() -> io::Result<u64>,
    unlock: impl FnOnce() -> io::Result<()>,
) -> io::Result<bool> {
    if owner()? != me || !try_lock()? {
        return Ok(false);
    }
    let generation = read_gen();
    unlock()?;
    Ok(generation? == expect_gen)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn eio() -> io::Error {
        io::Error::from_raw_os_error(libc::EIO)
    }

    // 이것을 실패시키는 것: fstat 실패를 무시하거나, read 실패를 0바이트로 보거나, 크기보다 짧은 파일을 성공으로 세는 것,
    // 빈 버퍼로 끝없이 0바이트를 읽는 것.
    #[test]
    fn read_faults_are_errors() {
        let mut buf = [0u8; 32];
        let e = read_counted(
            64,
            &mut buf,
            || Err(eio()),
            |_| panic!("read after a failed fstat"),
        )
        .unwrap_err();
        assert_eq!(e.raw_os_error(), Some(libc::EIO));
        let e = read_counted(64, &mut buf, || Ok(()), |_| Err(eio())).unwrap_err();
        assert_eq!(e.raw_os_error(), Some(libc::EIO));
        let mut chunks = [10usize, 0].into_iter();
        let e = read_counted(64, &mut buf, || Ok(()), |_| Ok(chunks.next().unwrap())).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::UnexpectedEof);
        assert_eq!(
            read_counted(64, &mut buf, || Ok(()), |b| Ok(b.len())).unwrap(),
            2
        );
        let e = read_counted(64, &mut [], || Ok(()), |b| Ok(b.len())).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::InvalidInput);
    }

    // 이것을 실패시키는 것: fstat 실패를 넘어가 0으로 채운 stat을 읽는 것, flock·세대 읽기 실패를 "아님"으로 보는 것,
    // 세대 읽기가 실패했을 때 잠금을 풀지 않는 것, 남의 파일·잠긴 파일·다른 세대를 true로 보는 것.
    #[test]
    fn lock_check_faults_are_errors() {
        let ok_gen = || Ok(7);
        let never = || -> io::Result<bool> { panic!("locked after a failed fstat") };
        let e = check_lock_and_generation(7, 501, || Err(eio()), never, ok_gen, || Ok(()));
        assert_eq!(e.unwrap_err().raw_os_error(), Some(libc::EIO));
        assert!(
            check_lock_and_generation(7, 501, || Ok(501), || Err(eio()), ok_gen, || Ok(()))
                .is_err()
        );
        let unlocked = std::cell::Cell::new(false);
        let r = check_lock_and_generation(
            7,
            501,
            || Ok(501),
            || Ok(true),
            || Err(eio()),
            || {
                unlocked.set(true);
                Ok(())
            },
        );
        assert!(r.is_err() && unlocked.get());
        assert!(
            !check_lock_and_generation(
                7,
                501,
                || Ok(0),
                || panic!("locked a file that is not ours"),
                ok_gen,
                || Ok(())
            )
            .unwrap()
        );
        assert!(
            !check_lock_and_generation(7, 501, || Ok(501), || Ok(false), ok_gen, || Ok(()))
                .unwrap()
        );
        assert!(
            !check_lock_and_generation(8, 501, || Ok(501), || Ok(true), ok_gen, || Ok(())).unwrap()
        );
        assert!(
            check_lock_and_generation(7, 501, || Ok(501), || Ok(true), ok_gen, || Ok(())).unwrap()
        );
    }

    // 이것을 실패시키는 것: NUL이 든 경로를 잘라 다른 경로로 부르거나 패닉하는 것.
    #[test]
    fn nul_path_is_invalid_input() {
        assert_eq!(
            cpath(Path::new("a\0b")).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
    }
}
