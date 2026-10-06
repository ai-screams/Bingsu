//! The only module in this crate allowed to use `unsafe`.
use std::io;

/// Hands all of `b` to `w`, retrying short writes and EINTR.
fn write_all(mut b: &[u8], mut w: impl FnMut(&[u8]) -> io::Result<usize>) -> io::Result<()> {
    while !b.is_empty() {
        match w(b) {
            Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
            Ok(n) => b = &b[n..],
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// Writes all of `b` to fd 1.
fn write1(b: &[u8]) -> io::Result<()> {
    write_all(b, |b| {
        // SAFETY: `b` is readable for its length.
        let n = unsafe { libc::write(1, b.as_ptr().cast(), b.len()) };
        usize::try_from(n).map_err(|_| io::Error::last_os_error())
    })
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

/// `AUDIT_ARCH_X86_64` from <linux/audit.h>: EM_X86_64 (62) | 64BIT | LE.
#[cfg(target_os = "linux")]
const AUDIT_ARCH_X86_64: u32 = 0xC000_003E;
/// `__X32_SYSCALL_BIT` from <asm/unistd.h>: x32 ABI calls carry this bit.
#[cfg(target_os = "linux")]
const X32_SYSCALL_BIT: u32 = 0x4000_0000;

/// x86_64 only: kills the process on any x32 ABI call (nr with
/// `__X32_SYSCALL_BIT`). seccompiler checks the arch but not this bit, so an
/// x32 `execve` would miss its deny rule. KILL_PROCESS, not an errno: the
/// same action seccompiler takes for a wrong arch, since no code here makes
/// x32 calls on purpose. offsetof(seccomp_data, nr) = 0, arch = 4.
#[cfg(target_os = "linux")]
#[cfg_attr(not(target_arch = "x86_64"), allow(dead_code))]
fn x32_deny_program() -> seccompiler::BpfProgram {
    use seccompiler::sock_filter;
    let op = |code: u32, jt: u8, jf: u8, k: u32| sock_filter {
        code: code as u16,
        jt,
        jf,
        k,
    };
    vec![
        op(libc::BPF_LD | libc::BPF_W | libc::BPF_ABS, 0, 0, 4),
        op(
            libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K,
            0,
            3,
            AUDIT_ARCH_X86_64,
        ),
        op(libc::BPF_LD | libc::BPF_W | libc::BPF_ABS, 0, 0, 0),
        op(
            libc::BPF_JMP | libc::BPF_JSET | libc::BPF_K,
            1,
            0,
            X32_SYSCALL_BIT,
        ),
        op(libc::BPF_RET | libc::BPF_K, 0, 0, libc::SECCOMP_RET_ALLOW),
        op(
            libc::BPF_RET | libc::BPF_K,
            0,
            0,
            libc::SECCOMP_RET_KILL_PROCESS,
        ),
    ]
}

/// no_new_privs, then three filters: (x86_64) kill x32 calls; deny the exec
/// family and, on x86_64, the legacy `fork`/`vfork` system calls with EPERM;
/// clone3 with ENOSYS so glibc falls back to `clone`. The `clone`-based libc
/// `fork()` is not blocked: the clone flag check and the write-deny rules
/// are M3b, so the install cost measured here is a lower bound for the
/// spec's filter. seccompiler's apply_filter sets no_new_privs again for
/// each filter (one prctl per filter, part of the measured cost).
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
    #[cfg(target_arch = "x86_64")]
    seccompiler::apply_filter(&x32_deny_program()).map_err(io::Error::other)?;
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
pub fn probe_exec() -> io::Result<()> {
    let argv = [c"/bin/true".as_ptr(), std::ptr::null()];
    // SAFETY: path and argv are NUL-terminated; on success this never returns.
    unsafe { libc::execv(c"/bin/true".as_ptr(), argv.as_ptr()) };
    if io::Error::last_os_error().raw_os_error() == Some(libc::EPERM) {
        write1(b"P")?;
    }
    Ok(())
}

/// Calls clone3 with a NULL argument block of size 0, which the kernel
/// rejects with EINVAL before creating anything; prints "C" if the call
/// failed with ENOSYS instead (the filter, or a host that blocks clone3).
/// Not part of the cost rows: it checks that the clone3 filter is in place.
#[cfg(target_os = "linux")]
pub fn probe_clone3() -> io::Result<()> {
    // SAFETY: clone3 with a NULL pointer and size 0 is refused (EINVAL) or
    // filtered (ENOSYS); it never creates a task.
    let rc = unsafe { libc::syscall(libc::SYS_clone3, std::ptr::null::<u8>(), 0usize) };
    if rc == -1 && io::Error::last_os_error().raw_os_error() == Some(libc::ENOSYS) {
        write1(b"C")?;
    }
    Ok(())
}

/// Not reached: stub_main refuses `--probe-clone3` off Linux.
#[cfg(not(target_os = "linux"))]
pub fn probe_clone3() -> io::Result<()> {
    Ok(())
}

/// x86_64 Linux: raw `fork` and `vfork` system calls; prints "F" if both
/// failed with EPERM. Without the rules they succeed: the child leaves at
/// once with `_exit` (after a raw vfork it shares this stack, so a missing
/// rule may also crash the parent; either way the probe does not print F).
/// stub_main allows it in sandbox mode only. Not part of the cost rows.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub fn probe_fork() -> io::Result<()> {
    let mut denied = 0;
    for nr in [libc::SYS_fork, libc::SYS_vfork] {
        // SAFETY: fork/vfork take no arguments; a child (rc 0) only calls _exit.
        let rc = unsafe { libc::syscall(nr) };
        if rc == 0 {
            // SAFETY: _exit is async-signal-safe and does not return.
            unsafe { libc::_exit(0) };
        }
        if rc > 0 {
            let mut st = 0;
            // SAFETY: `rc` is our child's pid; `st` is a valid out-parameter.
            unsafe { libc::waitpid(rc as libc::pid_t, &mut st, 0) };
        } else if io::Error::last_os_error().raw_os_error() == Some(libc::EPERM) {
            denied += 1;
        }
    }
    if denied == 2 {
        write1(b"F")?;
    }
    Ok(())
}

/// Not reached: stub_main refuses `--probe-fork` off x86_64 Linux.
#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
pub fn probe_fork() -> io::Result<()> {
    Ok(())
}

/// x86_64 Linux: an x32 ABI `getpid` (nr | `__X32_SYSCALL_BIT`). With the
/// sandbox's x32 filter installed the process dies with SIGSYS; without it
/// the call returns (ENOSYS on a kernel without x32) and nothing is printed.
/// Not part of the cost rows: it shows the x32 filter is installed.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub fn probe_x32() -> io::Result<()> {
    let nr = libc::c_long::from(X32_SYSCALL_BIT) | libc::SYS_getpid;
    // SAFETY: getpid takes no arguments; the x32 bit only changes the ABI.
    unsafe { libc::syscall(nr) };
    Ok(())
}

/// Not reached: stub_main refuses `--probe-x32` off x86_64 Linux.
#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
pub fn probe_x32() -> io::Result<()> {
    Ok(())
}

/// Linux: VmSize of this process right after the limits, for the
/// RLIMIT_AS = start + allowance rule (spec section 4).
pub fn report_vm() -> io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        let s = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
        let kib = s
            .lines()
            .find_map(|l| l.strip_prefix("VmSize:"))
            .map(|v| v.trim().trim_end_matches(" kB").to_string());
        write1(format!("VM {}\n", kib.unwrap_or_else(|| "unknown".into())).as_bytes())
    }
    #[cfg(not(target_os = "linux"))]
    write1(b"VM unsupported\n")
}

pub fn ready() -> io::Result<()> {
    write1(b"R")
}

#[cfg(test)]
mod tests {
    use super::*;

    // 이것을 실패시키는 것: short write에서 남은 바이트를 버리는 것, EINTR을 오류로 돌려주는 것,
    // 0바이트 쓰기에서 멈추지 않는 것(무한 루프), 다른 오류를 삼키는 것.
    #[test]
    fn write_all_finishes_or_reports() {
        let mut got = Vec::new();
        let mut eintr = true;
        let r = write_all(b"VM 1\nR", |b| {
            if std::mem::take(&mut eintr) {
                return Err(io::ErrorKind::Interrupted.into());
            }
            got.push(b[0]);
            Ok(1)
        });
        assert_eq!((r.is_ok(), got.as_slice()), (true, &b"VM 1\nR"[..]));
        let zero = write_all(b"R", |_| Ok(0));
        assert_eq!(zero.unwrap_err().kind(), io::ErrorKind::WriteZero);
        let bad = write_all(b"R", |_| Err(io::ErrorKind::BrokenPipe.into()));
        assert_eq!(bad.unwrap_err().kind(), io::ErrorKind::BrokenPipe);
    }

    #[cfg(target_os = "linux")]
    /// A classic-BPF evaluator for the opcodes x32_deny_program uses, over
    /// a seccomp_data with only `nr` (offset 0) and `arch` (offset 4).
    fn eval(prog: &[seccompiler::sock_filter], nr: u32, arch: u32) -> u32 {
        let (ld, jeq, jset, ret) = (
            libc::BPF_LD | libc::BPF_W | libc::BPF_ABS,
            libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K,
            libc::BPF_JMP | libc::BPF_JSET | libc::BPF_K,
            libc::BPF_RET | libc::BPF_K,
        );
        let (mut pc, mut acc) = (0usize, 0u32);
        loop {
            let i = &prog[pc];
            let code = u32::from(i.code);
            pc += 1;
            if code == ld {
                acc = match i.k {
                    0 => nr,
                    4 => arch,
                    k => panic!("load from offset {k}"),
                };
            } else if code == jeq || code == jset {
                let hit = if code == jeq {
                    acc == i.k
                } else {
                    acc & i.k != 0
                };
                pc += usize::from(if hit { i.jt } else { i.jf });
            } else if code == ret {
                return i.k;
            } else {
                panic!("opcode {code:#x}");
            }
        }
    }

    #[cfg(target_os = "linux")]
    // 이것을 실패시키는 것: x32 비트 검사(JSET)를 빼거나, arch 검사를 빼거나, 점프 거리를 틀리는 것.
    #[test]
    fn x32_calls_are_killed() {
        let p = x32_deny_program();
        let (allow, kill) = (libc::SECCOMP_RET_ALLOW, libc::SECCOMP_RET_KILL_PROCESS);
        let execve_x86_64 = 59;
        assert_eq!(eval(&p, execve_x86_64, AUDIT_ARCH_X86_64), allow);
        assert_eq!(
            eval(&p, execve_x86_64 | X32_SYSCALL_BIT, AUDIT_ARCH_X86_64),
            kill
        );
        assert_eq!(eval(&p, 520 | X32_SYSCALL_BIT, AUDIT_ARCH_X86_64), kill); // x32 execve
        assert_eq!(eval(&p, execve_x86_64, 0x4000_0003), kill); // i386
    }
}
