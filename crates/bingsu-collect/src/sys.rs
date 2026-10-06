//! The only module in this crate allowed to use `unsafe`.
use std::io;

fn write1(b: &[u8]) {
    // SAFETY: `b` is readable for its length.
    let _ = unsafe { libc::write(1, b.as_ptr().cast(), b.len()) };
}

/// RLIMIT_CPU 1 s, RLIMIT_NOFILE 64, RLIMIT_FSIZE 0 (spec section 4).
pub fn set_limits() -> io::Result<()> {
    for (res, v) in [
        (libc::RLIMIT_CPU, 1),
        (libc::RLIMIT_NOFILE, 64),
        (libc::RLIMIT_FSIZE, 0),
    ] {
        let lim = libc::rlimit {
            rlim_cur: v,
            rlim_max: v,
        };
        // SAFETY: `lim` is a valid rlimit value for setrlimit.
        if unsafe { libc::setrlimit(res, &lim) } != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

/// no_new_privs, then deny exec/fork with EPERM and clone3 with ENOSYS. The
/// full write-deny filter is M3b; this measures the install cost of the
/// mechanism (rule count is reported with the results).
#[cfg(target_os = "linux")]
pub fn sandbox() -> io::Result<()> {
    use seccompiler::{BpfProgram, SeccompAction, SeccompFilter, SeccompRule, TargetArch};
    use std::collections::BTreeMap;
    fn filter(calls: &[libc::c_long], errno: libc::c_int) -> io::Result<BpfProgram> {
        let arch: TargetArch = std::env::consts::ARCH
            .try_into()
            .map_err(io::Error::other)?;
        // c_long is i64 on the 64-bit targets and i32 on 32-bit Linux.
        #[allow(clippy::useless_conversion)]
        let rules: BTreeMap<i64, Vec<SeccompRule>> =
            calls.iter().map(|&n| (i64::from(n), Vec::new())).collect();
        SeccompFilter::new(
            rules,
            SeccompAction::Allow,
            SeccompAction::Errno(errno as u32),
            arch,
        )
        .map_err(io::Error::other)?
        .try_into()
        .map_err(io::Error::other)
    }
    // SAFETY: PR_SET_NO_NEW_PRIVS takes integer arguments only.
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        return Err(io::Error::last_os_error());
    }
    #[allow(unused_mut)]
    let mut deny = vec![libc::SYS_execve, libc::SYS_execveat];
    #[cfg(target_arch = "x86_64")]
    deny.extend([libc::SYS_fork, libc::SYS_vfork]);
    seccompiler::apply_filter(&filter(&deny, libc::EPERM)?).map_err(io::Error::other)?;
    seccompiler::apply_filter(&filter(&[libc::SYS_clone3], libc::ENOSYS)?)
        .map_err(io::Error::other)?;
    Ok(())
}

/// macOS has no supported execution ban (spec section 4, OS limit).
#[cfg(not(target_os = "linux"))]
pub fn sandbox() -> io::Result<()> {
    Err(io::Error::from(io::ErrorKind::Unsupported))
}

/// Tries to exec /bin/true; prints "P" if the filter refused with EPERM.
pub fn probe_exec() {
    let argv = [c"/bin/true".as_ptr(), std::ptr::null()];
    // SAFETY: path and argv are NUL-terminated; on success this never returns.
    unsafe { libc::execv(c"/bin/true".as_ptr(), argv.as_ptr()) };
    if io::Error::last_os_error().raw_os_error() == Some(libc::EPERM) {
        write1(b"P");
    }
}

/// Calls clone3 with a NULL argument block of size 0, which the kernel
/// rejects with EINVAL before creating anything; prints "C" if the call
/// failed with ENOSYS instead (the filter, or a host that blocks clone3).
/// Not part of the cost rows: it checks that the clone3 filter is in place.
#[cfg(target_os = "linux")]
pub fn probe_clone3() {
    // SAFETY: clone3 with a NULL pointer and size 0 is refused (EINVAL) or
    // filtered (ENOSYS); it never creates a task.
    let rc = unsafe { libc::syscall(libc::SYS_clone3, std::ptr::null::<u8>(), 0usize) };
    if rc == -1 && io::Error::last_os_error().raw_os_error() == Some(libc::ENOSYS) {
        write1(b"C");
    }
}

#[cfg(not(target_os = "linux"))]
pub fn probe_clone3() {}

/// Linux: VmSize of this process right after the limits, for the
/// RLIMIT_AS = start + allowance rule (spec section 4).
pub fn report_vm() {
    #[cfg(target_os = "linux")]
    {
        let s = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
        let kib = s
            .lines()
            .find_map(|l| l.strip_prefix("VmSize:"))
            .map(|v| v.trim().trim_end_matches(" kB").to_string());
        write1(format!("VM {}\n", kib.unwrap_or_else(|| "unknown".into())).as_bytes());
    }
    #[cfg(not(target_os = "linux"))]
    write1(b"VM unsupported\n");
}

pub fn ready() {
    write1(b"R");
}
