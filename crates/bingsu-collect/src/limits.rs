//! Worker-owned, monotone limits. Only the filtered startup stage reads statm.
use std::io;

pub const MEMORY_ALLOWANCE: u64 = 33_554_432;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InstalledLimits {
    pub baseline_bytes: u64,
    pub memory_limit_bytes: u64,
}

#[cfg(all(target_os = "linux", target_env = "gnu"))]
type Resource = libc::__rlimit_resource_t;
#[cfg(not(all(target_os = "linux", target_env = "gnu")))]
type Resource = libc::c_int;

fn get(resource: Resource) -> io::Result<libc::rlimit> {
    // SAFETY: integer-only storage and a valid resource identifier.
    let mut value: libc::rlimit = unsafe { std::mem::zeroed() };
    // SAFETY: writable rlimit storage.
    if unsafe { libc::getrlimit(resource, &mut value) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(value)
}
fn lower(resource: Resource, ceiling: libc::rlim_t) -> io::Result<libc::rlimit> {
    lower_with(
        ceiling,
        || get(resource),
        |value| {
            // SAFETY: initialized values no larger than either inherited limit.
            if unsafe { libc::setrlimit(resource, value) } != 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        },
    )
}
fn lower_with(
    ceiling: libc::rlim_t,
    mut observe: impl FnMut() -> io::Result<libc::rlimit>,
    mut apply: impl FnMut(&libc::rlimit) -> io::Result<()>,
) -> io::Result<libc::rlimit> {
    let inherited = observe()?;
    let value = libc::rlimit {
        rlim_cur: inherited.rlim_cur.min(ceiling),
        rlim_max: inherited.rlim_max.min(ceiling),
    };
    apply(&value)?;
    let actual = observe()?;
    if actual.rlim_cur != value.rlim_cur || actual.rlim_max != value.rlim_max {
        return Err(io::Error::other("limit readback"));
    }
    Ok(actual)
}

pub fn install_base() -> io::Result<()> {
    reset_limit_signals()?;
    for (resource, ceiling) in [
        (libc::RLIMIT_CPU, 1),
        (libc::RLIMIT_NOFILE, 64),
        (libc::RLIMIT_FSIZE, 0),
        (libc::RLIMIT_CORE, 0),
    ] {
        lower(resource, ceiling)?;
    }
    Ok(())
}

/// An exec preserves ignored dispositions and blocked signals. The worker
/// owns these limit/watchdog signals, regardless of the spawning shell.
fn reset_limit_signals() -> io::Result<()> {
    // SAFETY: plain C signal storage, initialized before use below.
    let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
    action.sa_sigaction = libc::SIG_DFL;
    // SAFETY: writable signal set in the action.
    if unsafe { libc::sigemptyset(&mut action.sa_mask) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let mut signals = action.sa_mask;
    for signal in [libc::SIGXCPU, libc::SIGXFSZ, libc::SIGALRM] {
        // SAFETY: supported signal, initialized action, no previous-action output.
        if unsafe { libc::sigaction(signal, &action, std::ptr::null_mut()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: initialized set and supported signal.
        if unsafe { libc::sigaddset(&mut signals, signal) } != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    // SAFETY: single-threaded worker startup; unblock only its owned signals.
    if unsafe { libc::sigprocmask(libc::SIG_UNBLOCK, &signals, std::ptr::null_mut()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Exactly seven decimal statm columns and a terminal newline. One bounded
/// read; no fallback path, unbounded parser, or saturating address arithmetic.
#[cfg(target_os = "linux")]
fn statm_bytes(bytes: &[u8], page: u64) -> io::Result<u64> {
    let bad = || io::Error::other("statm");
    if bytes.last() != Some(&b'\n') || page == 0 {
        return Err(bad());
    }
    let mut columns = bytes[..bytes.len() - 1].split(|b| *b == b' ');
    let mut baseline = None;
    for i in 0..7 {
        let word = columns.next().ok_or_else(bad)?;
        if word.is_empty() || !word.iter().all(u8::is_ascii_digit) {
            return Err(bad());
        }
        let value = word
            .iter()
            .try_fold(0u64, |n, b| {
                n.checked_mul(10)?.checked_add(u64::from(b - b'0'))
            })
            .ok_or_else(bad)?;
        if i == 0 {
            baseline = Some(value.checked_mul(page).ok_or_else(bad)?);
        }
    }
    if columns.next().is_some() {
        return Err(bad());
    }
    baseline.filter(|value| *value > 0).ok_or_else(bad)
}

#[cfg(target_os = "linux")]
#[allow(
    clippy::useless_conversion,
    reason = "rlim_t may be narrower than u64 on 32-bit Linux"
)]
pub fn lower_as_under_filter() -> io::Result<InstalledLimits> {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    // SAFETY: read-only query. A caller must also install the B2 initial filter;
    // NNP alone is deliberately not considered sufficient by worker startup.
    if unsafe { libc::prctl(libc::PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) } != 1 {
        return Err(io::Error::other("no_new_privs missing"));
    }
    // SAFETY: fixed path, read-only flags; this function is called under filter.
    let raw = unsafe {
        libc::open(
            c"/proc/self/statm".as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC,
        )
    };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: newly opened descriptor, uniquely transferred.
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    let mut buffer = [0u8; 256];
    // SAFETY: writable fixed buffer and live descriptor. No retries/unbounded reads.
    let n = unsafe { libc::read(fd.as_raw_fd(), buffer.as_mut_ptr().cast(), buffer.len()) };
    let n = usize::try_from(n).map_err(|_| io::Error::last_os_error())?;
    if n == buffer.len() {
        return Err(io::Error::other("statm length"));
    }
    // SAFETY: read-only page-size query, no path lookup.
    let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    let baseline = statm_bytes(&buffer[..n], u64::try_from(page).map_err(io::Error::other)?)?;
    let ceiling = baseline
        .checked_add(MEMORY_ALLOWANCE)
        .ok_or_else(|| io::Error::other("AS overflow"))?;
    let installed = lower(
        libc::RLIMIT_AS,
        ceiling.try_into().map_err(io::Error::other)?,
    )?;
    Ok(InstalledLimits {
        baseline_bytes: baseline,
        memory_limit_bytes: installed.rlim_cur,
    })
}

/// Sampled footprint, not an RLIMIT_AS guarantee. C1 owns the external 2ms
/// watchdog; resident size is available separately for diagnostics.
#[cfg(target_os = "macos")]
pub fn memory_sample() -> io::Result<(u64, u64)> {
    // SAFETY: integer-only storage matching RUSAGE_INFO_V2.
    let mut usage: libc::rusage_info_v2 = unsafe { std::mem::zeroed() };
    // SAFETY: no arguments.
    let pid = unsafe { libc::getpid() };
    // SAFETY: live process and correctly sized output structure.
    if unsafe {
        libc::proc_pid_rusage(
            pid,
            libc::RUSAGE_INFO_V2,
            (&mut usage as *mut libc::rusage_info_v2).cast(),
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok((usage.ri_phys_footprint, usage.ri_resident_size))
}
#[cfg(target_os = "macos")]
pub fn lower_as_under_filter() -> io::Result<InstalledLimits> {
    let (baseline_bytes, _) = memory_sample()?;
    let memory_limit_bytes = baseline_bytes
        .checked_add(MEMORY_ALLOWANCE)
        .ok_or_else(|| io::Error::other("footprint overflow"))?;
    Ok(InstalledLimits {
        baseline_bytes,
        memory_limit_bytes,
    })
}
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub fn lower_as_under_filter() -> io::Result<InstalledLimits> {
    Err(io::ErrorKind::Unsupported.into())
}

#[cfg(target_os = "linux")]
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct CapData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}
#[cfg(target_os = "linux")]
#[repr(C)]
struct CapHeader {
    version: u32,
    pid: i32,
}

/// Bounding bits left on an unprivileged host are diagnostic evidence only.
/// B2 must deny capset/setuid/setgid/exec after this stage.
#[cfg(target_os = "linux")]
static BOUNDING_REMAINDER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
#[cfg(target_os = "linux")]
#[cfg(test)]
pub fn bounding_remainder() -> u64 {
    BOUNDING_REMAINDER.load(std::sync::atomic::Ordering::Relaxed)
}
#[cfg(target_os = "linux")]
pub fn drop_capabilities() -> io::Result<()> {
    let mut header = CapHeader {
        version: 0x2008_0522,
        pid: 0,
    };
    let mut data = [CapData::default(); 2];
    // SAFETY: v3 capability header and two writable u32 triples.
    if unsafe { libc::syscall(libc::SYS_capget, &mut header, data.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let can_drop = data[0].effective & (1 << 8) != 0; // CAP_SETPCAP
    let mut remainder = 0u64;
    let mut count = 0;
    for cap in 0..64 {
        // SAFETY: integer-only capability query; EINVAL terminates supported bits.
        let present = unsafe { libc::prctl(libc::PR_CAPBSET_READ, cap, 0, 0, 0) };
        if present < 0 {
            if io::Error::last_os_error().raw_os_error() == Some(libc::EINVAL) && cap > 0 {
                break;
            }
            return Err(io::Error::last_os_error());
        }
        count += 1;
        if present == 1 && can_drop {
            // SAFETY: dropping a supported bounding bit while CAP_SETPCAP is held.
            if unsafe { libc::prctl(libc::PR_CAPBSET_DROP, cap, 0, 0, 0) } != 0 {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: read back the supported bounding bit.
            if unsafe { libc::prctl(libc::PR_CAPBSET_READ, cap, 0, 0, 0) } != 0 {
                return Err(io::Error::other("bounding readback"));
            }
        } else if present == 1 {
            remainder |= 1u64 << cap;
        }
    }
    // SAFETY: CLEAR_ALL has no pointer arguments. EINVAL means an older kernel
    // with no ambient capabilities, not a failed drop on a supporting kernel.
    if unsafe {
        libc::prctl(
            libc::PR_CAP_AMBIENT,
            libc::PR_CAP_AMBIENT_CLEAR_ALL,
            0,
            0,
            0,
        )
    } != 0
        && io::Error::last_os_error().raw_os_error() != Some(libc::EINVAL)
    {
        return Err(io::Error::last_os_error());
    }
    let zero = [CapData::default(); 2];
    // SAFETY: initialized v3 header and two zero capability triples.
    if unsafe { libc::syscall(libc::SYS_capset, &header, zero.as_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: read back the same process's capability sets.
    if unsafe { libc::syscall(libc::SYS_capget, &mut header, data.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    if data
        .iter()
        .any(|c| c.effective | c.permitted | c.inheritable != 0)
    {
        return Err(io::Error::other("capability readback"));
    }
    for cap in 0..count {
        // SAFETY: query only supported capability numbers.
        let value =
            unsafe { libc::prctl(libc::PR_CAP_AMBIENT, libc::PR_CAP_AMBIENT_IS_SET, cap, 0, 0) };
        if value != 0
            && !(value < 0 && io::Error::last_os_error().raw_os_error() == Some(libc::EINVAL))
        {
            return Err(io::Error::other("ambient readback"));
        }
    }
    BOUNDING_REMAINDER.store(remainder, std::sync::atomic::Ordering::Relaxed);
    Ok(())
}
#[cfg(not(target_os = "linux"))]
pub fn drop_capabilities() -> io::Result<()> {
    Ok(())
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    // 이것을 실패시키는 것: statm의 일부·음수·추가 열·overflow를 기준값으로 받는 것.
    #[test]
    fn startup_statm_is_bounded_and_checked() {
        assert_eq!(statm_bytes(b"10 2 3 4 5 6 0\n", 4096).unwrap(), 40_960);
        for invalid in [
            b"".as_slice(),
            b"10",
            b"10 2 3 4 5 6 0",
            b"10 2 3 4 5 6 0 8\n",
            b"-1 2 3 4 5 6 0\n",
            b"18446744073709551616 2 3 4 5 6 0\n",
            b"18446744073709551615 2 3 4 5 6 0\n",
            b"0 2 3 4 5 6 0\n",
        ] {
            assert!(statm_bytes(invalid, 4096).is_err());
        }
        assert!(statm_bytes(b"10 2 3 4 5 6 0\n", 0).is_err());
    }

    // 이것을 실패시키는 것: root의 capability 또는 bounding set을 남겨 hard limit을 복원하는 것.
    // Run as a separate --exact --ignored --test-threads=1 root process in CI.
    // Final-filter denial of unchanged/soft-only writes remains a B2 acceptance.
    #[test]
    #[ignore = "requires root with CAP_SYS_RESOURCE and CAP_SETPCAP; mandatory Linux CI row"]
    fn root_cannot_restore_limits_or_capabilities() {
        assert_eq!(
            // SAFETY: read-only uid query.
            unsafe { libc::geteuid() },
            0,
            "BLOCKED: root fixture required"
        );
        let mut header = CapHeader {
            version: 0x2008_0522,
            pid: 0,
        };
        let mut data = [CapData::default(); 2];
        assert_eq!(
            // SAFETY: v3 capability output storage.
            unsafe { libc::syscall(libc::SYS_capget, &mut header, data.as_mut_ptr()) },
            0
        );
        assert_eq!(
            data[0].effective & ((1 << 24) | (1 << 8)),
            (1 << 24) | (1 << 8),
            "BLOCKED: required root capabilities absent"
        );
        install_base().unwrap();
        drop_capabilities().unwrap();
        assert_eq!(bounding_remainder(), 0);
        let higher = libc::rlimit {
            rlim_cur: 65,
            rlim_max: 65,
        };
        // SAFETY: attempts only to change this isolated child's limit.
        assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &higher) }, -1);
        assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::EPERM));
        data = [CapData::default(); 2];
        data[0].effective = 1 << 24;
        data[0].permitted = 1 << 24;
        assert_eq!(
            // SAFETY: attempts only to reacquire this child's dropped capability.
            unsafe { libc::syscall(libc::SYS_capset, &header, data.as_ptr()) },
            -1
        );
        assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::EPERM));
    }
}

#[cfg(test)]
mod readback_tests {
    use super::*;
    // 이것을 실패시키는 것: limit 적용·관찰 오류 또는 readback 불일치를 삼키는 것.
    #[test]
    fn protection_failure_in_limit_readback_is_closed() {
        for failure in 0..=4 {
            let calls = std::cell::Cell::new(0);
            let result = lower_with(
                64,
                || {
                    calls.set(calls.get() + 1);
                    if (failure == 1 && calls.get() == 1) || (failure == 3 && calls.get() == 2) {
                        return Err(io::Error::other("injected observation"));
                    }
                    Ok(libc::rlimit {
                        rlim_cur: if failure == 4 && calls.get() == 2 {
                            17
                        } else {
                            16
                        },
                        rlim_max: 32,
                    })
                },
                |value| {
                    assert_eq!((value.rlim_cur, value.rlim_max), (16, 32));
                    if failure == 2 {
                        Err(io::Error::other("injected set"))
                    } else {
                        Ok(())
                    }
                },
            );
            assert_eq!(result.is_ok(), failure == 0, "failure {failure}");
        }
    }
}
