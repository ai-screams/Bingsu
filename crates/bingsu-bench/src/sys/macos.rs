//! macOS memory probes: proc_pid_rusage(RUSAGE_INFO_V4) for the memory
//! watchdog (spec section 4, X-25), proc_pidinfo task info and RLIMIT_AS
//! for X-29. Struct layouts come from libc (<libproc.h>, <sys/resource.h>).
//! Callers query only this process or its own children.
use std::io;
use std::path::Path;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RusageSample {
    pub phys_footprint: u64,
    pub resident_size: u64,
}

pub fn rusage_v4(pid: libc::pid_t) -> io::Result<RusageSample> {
    // SAFETY: an all-zero rusage_info_v4 is a valid out-parameter.
    let mut ri: libc::rusage_info_v4 = unsafe { std::mem::zeroed() };
    // SAFETY: `ri` is a writable rusage_info_v4 and the flavor matches it.
    let rc = unsafe {
        libc::proc_pid_rusage(pid, libc::RUSAGE_INFO_V4, std::ptr::addr_of_mut!(ri).cast())
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(RusageSample {
        phys_footprint: ri.ri_phys_footprint,
        resident_size: ri.ri_resident_size,
    })
}

/// Virtual size of a process (proc_pidinfo PROC_PIDTASKINFO), for X-29.
pub fn virtual_size(pid: libc::pid_t) -> io::Result<u64> {
    // SAFETY: an all-zero proc_taskinfo is a valid out-parameter.
    let mut ti: libc::proc_taskinfo = unsafe { std::mem::zeroed() };
    let size = std::mem::size_of::<libc::proc_taskinfo>() as libc::c_int;
    // SAFETY: `ti` is writable for `size` bytes and the flavor matches it.
    let n = unsafe {
        libc::proc_pidinfo(
            pid,
            libc::PROC_PIDTASKINFO,
            0,
            std::ptr::addr_of_mut!(ti).cast(),
            size,
        )
    };
    if n != size {
        // 0 with errno (ESRCH for a gone pid), or a short copy.
        return Err(if n <= 0 {
            io::Error::last_os_error()
        } else {
            io::Error::other(format!("proc_pidinfo returned {n} of {size} bytes"))
        });
    }
    Ok(ti.pti_virtual_size)
}

/// (user ns, system ns) of this process.
pub fn self_rusage() -> io::Result<(u64, u64)> {
    // SAFETY: an all-zero rusage is a valid out-parameter.
    let mut r: libc::rusage = unsafe { std::mem::zeroed() };
    // SAFETY: `r` is writable.
    if unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut r) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let ns = |t: libc::timeval| (t.tv_sec as u64) * 1_000_000_000 + (t.tv_usec as u64) * 1000;
    Ok((ns(r.ru_utime), ns(r.ru_stime)))
}

/// mmap a file read-only and read one byte per 4 KiB (gix pack stand-in);
/// returns the sum of those bytes. The mapping is never unmapped: it stays
/// until the process exits, as the watchdog phases need.
pub fn touch_mapped_file(path: &Path) -> io::Result<u64> {
    use std::os::fd::AsRawFd;
    let f = std::fs::File::open(path)?;
    let len = usize::try_from(f.metadata()?.len()).map_err(io::Error::other)?;
    // SAFETY: a new private read-only mapping of `len` bytes of an open
    // regular file; no existing memory is affected. An empty file fails
    // here with EINVAL. If another process truncates the file while it is
    // mapped, touching a page past the new end raises SIGBUS and ends this
    // process: the pack fixture is a private file nobody else writes.
    let p = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            len,
            libc::PROT_READ,
            libc::MAP_PRIVATE,
            f.as_raw_fd(),
            0,
        )
    };
    if p == libc::MAP_FAILED {
        return Err(io::Error::last_os_error());
    }
    let mut sum = 0u64;
    for off in (0..len).step_by(4096) {
        // SAFETY: `off < len`, so the pointer stays inside the mapping.
        let q = unsafe { p.cast::<u8>().add(off) };
        // SAFETY: `q` points into a readable mapping that is never
        // unmapped; volatile so the page is really touched.
        sum += u64::from(unsafe { std::ptr::read_volatile(q) });
    }
    Ok(sum)
}

/// (soft, hard) RLIMIT_AS of this process.
pub fn get_rlimit_as() -> io::Result<(u64, u64)> {
    let mut r = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `r` is writable.
    if unsafe { libc::getrlimit(libc::RLIMIT_AS, &mut r) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok((r.rlim_cur, r.rlim_max))
}

/// setrlimit(RLIMIT_AS) as the call reports it: (rc, errno), errno 0 on
/// success. X-29 records both instead of turning a refusal into an error.
pub fn set_rlimit_as(cur: u64, max: u64) -> (i32, i32) {
    let r = libc::rlimit {
        rlim_cur: cur,
        rlim_max: max,
    };
    // SAFETY: `r` is a valid rlimit value.
    let rc = unsafe { libc::setrlimit(libc::RLIMIT_AS, &r) };
    let errno = if rc == 0 {
        0
    } else {
        io::Error::last_os_error().raw_os_error().unwrap_or(0)
    };
    (rc, errno)
}

#[cfg(test)]
mod tests {
    use super::*;

    // 이것을 실패시키는 것: flavor·구조체가 어긋나 rc가 0이 아니거나, 두 필드를 0으로 두는 것.
    #[test]
    fn own_rusage_is_nonzero() {
        let s = rusage_v4(std::process::id() as libc::pid_t).unwrap();
        assert!(s.phys_footprint > 0 && s.resident_size > 0, "{s:?}");
    }

    // 이것을 실패시키는 것: 짧게 채운 proc_pidinfo 결과를 받아들이거나 다른 필드를 읽는 것.
    #[test]
    fn own_virtual_size_is_large() {
        let v = virtual_size(std::process::id() as libc::pid_t).unwrap();
        assert!(v > 1 << 30, "{v}");
    }

    // 이것을 실패시키는 것: rc·반환 길이를 확인하지 않아 끝난 프로세스의 조회를 0 값으로 내는 것.
    #[test]
    fn reaped_child_is_an_error() {
        let _serial = crate::sys::fd_tests_lock();
        let mut c = std::process::Command::new("/usr/bin/true").spawn().unwrap();
        let pid = c.id() as libc::pid_t;
        c.wait().unwrap();
        let esrch = Some(libc::ESRCH);
        assert_eq!(rusage_v4(pid).unwrap_err().raw_os_error(), esrch);
        assert_eq!(virtual_size(pid).unwrap_err().raw_os_error(), esrch);
    }

    // 이것을 실패시키는 것: 페이지마다가 아니라 첫 바이트만 읽거나, 빈 파일을 Ok(0)으로 넘기는 것.
    #[test]
    fn touch_reads_one_byte_per_page() {
        let _serial = crate::sys::fd_tests_lock();
        let dir = std::env::temp_dir().join(format!("bingsu-touch-{}", std::process::id()));
        let _ = std::fs::create_dir(&dir);
        let f = dir.join("f");
        let mut data = vec![0u8; 3 * 4096 + 1];
        for (i, page) in [0usize, 4096, 8192, 12288].into_iter().enumerate() {
            data[page] = (i + 1) as u8;
        }
        data[1] = 100; // not on a page start: must not be counted
        std::fs::write(&f, &data).unwrap();
        let sum = touch_mapped_file(&f);
        std::fs::write(&f, b"").unwrap();
        let empty = touch_mapped_file(&f);
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(sum.unwrap(), 1 + 2 + 3 + 4);
        assert_eq!(empty.unwrap_err().kind(), io::ErrorKind::InvalidInput);
    }

    // 이것을 실패시키는 것: 거부된 setrlimit(soft > hard, EINVAL)을 (0, 0)으로 보고하는 것.
    #[test]
    fn rlimit_reports_errno() {
        let (cur, max) = get_rlimit_as().unwrap();
        assert!(cur <= max, "{cur} {max}");
        assert_eq!(set_rlimit_as(2, 1), (-1, libc::EINVAL));
        assert_eq!(get_rlimit_as().unwrap(), (cur, max));
    }
}
