//! Linux primitive counts (close is ownership cleanup, outside the budget):
//! - probe: one openat("/") and one openat2(".") per attempt;
//! - acquisition: root open/fstat/fstatfs/statx; each ordinary component adds
//!   lstat/openat/fstat/fstatfs/statx, without a cross-mount comparison;
//! - fast content: openat2/fstat/fstatfs/statx, then bounded 16KiB reads + EOF;
//! - stepwise content: each opened component adds openat/fstat/fstatfs/statx;
//!   one entry lstat checks dev/ino against the opened fd. No ancestor rechecks;
//!   full stepwise reads require the installed Landlock read layer.
//! - symlink: readlinkat plus same-name lstat before/after, no path reopening;
//! - listing: getdents64 per 8KiB buffer plus EOF, except when the raw cap ends it.
use super::*;
use crate::meter::DIRENT_CHUNK;

/// The probe uses only the fixed filesystem root, never a repository path.
pub(super) fn probe(meter: &mut Meter) -> Result<Resolver, ReadError> {
    let previous = meter.phase;
    meter.phase = Phase::Probe;
    let result = (|| {
        let root = openat(
            libc::AT_FDCWD,
            c"/",
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
            meter,
        )?;
        match open_raw(root.as_raw_fd(), c".", true, meter) {
            Ok(_) => Ok(Resolver::Openat2),
            Err(ReadError::Io(libc::ENOSYS | libc::EPERM)) => Ok(Resolver::Stepwise),
            Err(ReadError::Io(error)) => Err(ReadError::errno(error)),
            Err(error) => Err(error),
        }
    })();
    meter.phase = previous;
    result
}

pub(super) fn open(
    root: &Root,
    path: &[u8],
    is_dir: bool,
    meter: &mut Meter,
) -> Result<Fd, ReadError> {
    meter.event("before_openat2");
    let path = cstring(path, meter)?;
    open_raw(root.fd.as_raw_fd(), &path, is_dir, meter).map_err(|error| match error {
        ReadError::Io(error) => ReadError::errno(error),
        other => other,
    })
}

fn open_raw(
    root: RawFd,
    path: &std::ffi::CStr,
    is_dir: bool,
    meter: &mut Meter,
) -> Result<Fd, ReadError> {
    // SAFETY: the UAPI requires zero initialization, including future fields.
    let mut how: libc::open_how = unsafe { std::mem::zeroed() };
    how.flags = (libc::O_RDONLY
        | libc::O_NONBLOCK
        | libc::O_CLOEXEC
        | if is_dir { libc::O_DIRECTORY } else { 0 }) as u64;
    how.resolve = libc::RESOLVE_BENEATH | libc::RESOLVE_NO_MAGICLINKS | libc::RESOLVE_NO_XDEV;
    let lease = meter.lease()?;
    let mut interrupted = 0;
    let mut changed = 0;
    loop {
        meter.charge(Op::Open)?;
        #[cfg(test)]
        let injected = meter.openat2_errors.pop_front();
        #[cfg(not(test))]
        let injected: Option<i32> = None;
        let result = if injected.is_some() {
            -1
        } else {
            // SAFETY: valid dirfd, terminated path and a zeroed 24-byte open_how.
            unsafe {
                libc::syscall(
                    libc::SYS_openat2,
                    root,
                    path.as_ptr(),
                    &how,
                    std::mem::size_of_val(&how),
                )
            }
        };
        if result >= 0 {
            return Ok(Fd {
                // SAFETY: successful syscall returns a fresh, uniquely owned fd.
                fd: unsafe { OwnedFd::from_raw_fd(result as RawFd) },
                _lease: lease,
            });
        }
        #[cfg(test)]
        let error = injected.unwrap_or_else(errno);
        #[cfg(not(test))]
        let error = errno();
        match error {
            libc::EINTR if interrupted < 8 => interrupted += 1,
            libc::EAGAIN if changed < 2 => changed += 1,
            libc::EINTR => return Err(ReadError::Changed),
            libc::EAGAIN => return Err(ReadError::Changed),
            _ => return Err(ReadError::Io(error)),
        }
        meter.charge(Op::Retry)?;
    }
}

pub(super) fn mount(fd: RawFd, meter: &mut Meter) -> Result<[u64; 2], ReadError> {
    // SAFETY: fstatfs is a plain C output record.
    let mut fs: libc::statfs = unsafe { std::mem::zeroed() };
    retry(meter, Op::Filesystem, || {
        // SAFETY: live descriptor and writable output record.
        unsafe { libc::fstatfs(fd, &mut fs) as isize }
    })?;
    if fs.f_type as u64 == 0x9fa0 {
        return Err(ReadError::Escape);
    }
    // SAFETY: statx is a plain C output record, including its reserved bytes.
    let mut out: libc::statx = unsafe { std::mem::zeroed() };
    #[cfg(test)]
    if let Some(error) = meter.mount_fault {
        meter.charge(Op::Mount)?;
        return mount_result(if error == 0 { Ok((0, 1)) } else { Err(error) });
    }
    let result = retry(meter, Op::Mount, || {
        // SAFETY: live fd, AT_EMPTY_PATH, empty string, full writable UAPI record.
        unsafe {
            libc::syscall(
                libc::SYS_statx,
                fd,
                c"".as_ptr(),
                libc::AT_EMPTY_PATH | libc::AT_SYMLINK_NOFOLLOW,
                libc::STATX_MNT_ID,
                &mut out,
            ) as isize
        }
    });
    match result {
        Ok(_) => mount_result(Ok((out.stx_mask, out.stx_mnt_id))),
        Err(ReadError::Io(libc::ENOSYS) | ReadError::Denied) => Err(ReadError::Denied),
        Err(error) => Err(error),
    }
}

fn mount_result(result: Result<(u32, u64), i32>) -> Result<[u64; 2], ReadError> {
    match result {
        Ok((mask, id)) if mask & libc::STATX_MNT_ID != 0 => Ok([id, 0]),
        _ => Err(ReadError::Denied),
    }
}

pub(super) fn entries(
    dir: &Directory,
    raw_limit: u32,
    meter: &mut Meter,
) -> Result<Listing, ReadError> {
    let mut names = Vec::new();
    let mut raw = 0;
    let mut buffer = [0u8; DIRENT_CHUNK];
    loop {
        if raw >= raw_limit {
            return Ok(Listing {
                names,
                complete: false,
            });
        }
        let size = retry(meter, Op::List, || {
            // SAFETY: owned directory fd and writable, bounded byte buffer.
            unsafe {
                libc::syscall(
                    libc::SYS_getdents64,
                    dir.root.fd.as_raw_fd(),
                    buffer.as_mut_ptr(),
                    buffer.len(),
                ) as isize
            }
        })? as usize;
        if size == 0 {
            return Ok(Listing {
                names,
                complete: true,
            });
        }
        let mut offset = 0;
        while offset < size {
            if raw >= raw_limit {
                return Ok(Listing {
                    names,
                    complete: false,
                });
            }
            // linux_dirent64: ino(8), off(8), reclen(2), type(1), name.
            let record = &buffer[offset..size];
            if record.len() < 20 {
                return Err(ReadError::Io(libc::EIO));
            }
            let length = u16::from_ne_bytes([record[16], record[17]]) as usize;
            if length < 20 || length > record.len() {
                return Err(ReadError::Io(libc::EIO));
            }
            meter.raw_entry()?;
            raw += 1;
            let name = &record[19..length];
            let end = name
                .iter()
                .position(|&byte| byte == 0)
                .ok_or(ReadError::Io(libc::EIO))?;
            let name = &name[..end];
            if name != b"." && name != b".." {
                if name.is_empty() || name.contains(&b'/') {
                    return Err(ReadError::Io(libc::EIO));
                }
                meter.allocation(name.len() + std::mem::size_of::<Vec<u8>>())?;
                names.try_reserve_exact(1).map_err(|_| ReadError::Limit)?;
                names.push(name.to_vec());
            }
            offset += length;
        }
    }
}

#[cfg(test)]
pub fn probe_for_test(meter: &mut Meter) -> Result<Resolver, ReadError> {
    probe(meter)
}
