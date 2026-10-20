//! Helper filter: installed after the fixed collection spawn and synchronized
//! with the already-running watchdog. This is not the prompt syscall policy.
#[cfg(target_os = "linux")]
fn program(pid: u32) -> Vec<libc::sock_filter> {
    let stmt = |code, k| libc::sock_filter {
        code,
        jt: 0,
        jf: 0,
        k,
    };
    let jump = |k, jt, jf| libc::sock_filter {
        code: 0x15,
        jt,
        jf,
        k,
    };
    #[cfg(target_arch = "x86_64")]
    let arch = 0xc000003e;
    #[cfg(target_arch = "aarch64")]
    let arch = 0xc00000b7;
    let mut code = vec![
        stmt(0x20, 4),
        jump(arch, 1, 0),
        stmt(0x06, libc::SECCOMP_RET_KILL_PROCESS),
        stmt(0x20, 0),
    ];
    #[cfg(target_arch = "x86_64")]
    {
        // Reject x32 and negative syscall numbers before native comparisons.
        code.push(libc::sock_filter {
            code: 0x35,
            jt: 0,
            jf: 1,
            k: 0x40000000,
        });
        code.push(stmt(0x06, libc::SECCOMP_RET_KILL_PROCESS));
    }
    let denied = [
        libc::SYS_execve,
        libc::SYS_execveat,
        libc::SYS_clone,
        libc::SYS_clone3,
        // All collector handles are acquired before TSYNC. Reopening numeric
        // PIDs here would bypass the supervised child's ownership boundary.
        libc::SYS_pidfd_open,
        #[cfg(target_arch = "x86_64")]
        libc::SYS_fork,
        #[cfg(target_arch = "x86_64")]
        libc::SYS_vfork,
    ];
    for nr in denied {
        code.push(jump(nr as u32, 0, 1));
        code.push(stmt(0x06, libc::SECCOMP_RET_ERRNO | libc::EPERM as u32));
    }
    code.push(jump(libc::SYS_kill as u32, 1, 0));
    code.push(stmt(0x06, libc::SECCOMP_RET_ALLOW));
    // The watchdog must still kill its own helper. Every other numeric-PID
    // signal is refused; collector signals use retained pidfds instead.
    for (offset, expected) in [(16, pid), (20, 0), (24, libc::SIGKILL as u32), (28, 0)] {
        code.push(stmt(0x20, offset));
        code.push(jump(expected, 1, 0));
        code.push(stmt(0x06, libc::SECCOMP_RET_ERRNO | libc::EPERM as u32));
    }
    code.push(stmt(0x06, libc::SECCOMP_RET_ALLOW));
    code
}
#[cfg(target_os = "linux")]
pub fn install() -> std::io::Result<()> {
    // SAFETY: own PID is captured once before TSYNC.
    let pid = unsafe { libc::getpid() } as u32;
    let mut code = program(pid);
    let prog = libc::sock_fprog {
        len: code.len() as u16,
        filter: code.as_mut_ptr(),
    };
    // SAFETY: scalar prctl arguments; this only removes privileges.
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: live sock_fprog and instruction array. TSYNC must return exactly
    // zero; a positive unsynchronized thread id is also a failure.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            libc::SECCOMP_SET_MODE_FILTER,
            libc::SECCOMP_FILTER_FLAG_TSYNC,
            &prog,
        )
    };
    tsync_result(rc)
}
#[cfg(any(target_os = "linux", test))]
fn tsync_result(rc: libc::c_long) -> std::io::Result<()> {
    if rc != 0 {
        return Err(std::io::Error::other("helper TSYNC filter unavailable"));
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn install() -> std::io::Result<()> {
    Ok(())
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    fn evaluate(nr: i64, args: [u64; 2]) -> u32 {
        let mut input = [0u8; 64];
        input[..4].copy_from_slice(&(nr as u32).to_ne_bytes());
        #[cfg(target_arch = "x86_64")]
        let arch = 0xc000003eu32;
        #[cfg(target_arch = "aarch64")]
        let arch = 0xc00000b7u32;
        input[4..8].copy_from_slice(&arch.to_ne_bytes());
        for (i, value) in args.into_iter().enumerate() {
            input[16 + i * 8..24 + i * 8].copy_from_slice(&value.to_ne_bytes());
        }
        let code = program(1234);
        let mut pc = 0;
        let mut a = 0;
        loop {
            let op = code[pc];
            pc += 1;
            match op.code {
                0x20 => {
                    a = u32::from_ne_bytes(
                        input[op.k as usize..op.k as usize + 4].try_into().unwrap(),
                    )
                }
                0x15 => pc += if a == op.k { op.jt } else { op.jf } as usize,
                0x35 => pc += if a >= op.k { op.jt } else { op.jf } as usize,
                0x06 => return op.k,
                _ => panic!("unexpected BPF operation"),
            }
        }
    }
    // 이것을 실패시키는 것: 자기 pid/SIGKILL의 64비트 조건 또는 늦은 pidfd_open 거부 제거.
    #[test]
    fn helper_filter_refuses_pid_kill_and_late_pidfd_open() {
        let denied = libc::SECCOMP_RET_ERRNO | libc::EPERM as u32;
        for pid in [0, 1, 1233, u64::MAX, (-1234i64) as u64, (1 << 32) | 1234] {
            assert_eq!(
                evaluate(libc::SYS_kill, [pid, libc::SIGKILL as u64]),
                denied
            );
        }
        for signal in [0, libc::SIGTERM as u64, (1 << 32) | libc::SIGKILL as u64] {
            assert_eq!(evaluate(libc::SYS_kill, [1234, signal]), denied);
        }
        assert_eq!(evaluate(libc::SYS_pidfd_open, [1234, 0]), denied);
        assert_eq!(
            evaluate(libc::SYS_kill, [1234, libc::SIGKILL as u64]),
            libc::SECCOMP_RET_ALLOW
        );
        for nr in [libc::SYS_pidfd_send_signal, libc::SYS_waitid] {
            assert_eq!(
                evaluate(nr, [3, libc::SIGKILL as u64]),
                libc::SECCOMP_RET_ALLOW
            );
        }
    }
    fn rejected_exec() {
        // SAFETY: fixed nonexistent path, NUL-terminated empty argv/env.
        let rc = unsafe {
            libc::execve(
                c"/bingsu-must-not-exec".as_ptr(),
                [std::ptr::null()].as_ptr(),
                [std::ptr::null()].as_ptr(),
            )
        };
        assert_eq!(rc, -1);
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::EPERM)
        );
        // Refusal probes have harmless effects even when the tested rule is
        // deliberately removed. Negative group targets are covered by BPF.
        // SAFETY: read-only own identity.
        let pid = unsafe { libc::getpid() };
        // SAFETY: no signal is delivered; only permission/existence is queried.
        let rc = unsafe { libc::kill(pid, 0) };
        assert_eq!(rc, -1);
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::EPERM)
        );
        // SAFETY: pid 0 cannot identify a process for pidfd_open.
        let rc = unsafe { libc::syscall(libc::SYS_pidfd_open, 0, 0) };
        assert_eq!(rc, -1);
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::EPERM)
        );
    }
    // 이것을 실패시키는 것: helper 필터의 exec 금지 또는 watchdog에 대한 TSYNC 적용을 제거하는 것.
    #[test]
    #[ignore = "installs irreversible filter in isolated child"]
    fn filtered_child() {
        let (send, recv) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            recv.recv().unwrap();
            rejected_exec();
        });
        let (send_supervisor, recv_supervisor) = std::sync::mpsc::channel();
        let supervisor = std::thread::spawn(move || {
            recv_supervisor.recv().unwrap();
            rejected_exec();
        });
        install().unwrap();
        rejected_exec();
        send.send(()).unwrap();
        send_supervisor.send(()).unwrap();
        worker.join().unwrap();
        supervisor.join().unwrap();
        // SAFETY: intentionally invalid clone3 request; EPERM must precede EINVAL.
        let rc = unsafe { libc::syscall(libc::SYS_clone3, std::ptr::null::<u8>(), 0) };
        assert_eq!(rc, -1);
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::EPERM)
        );
    }
    // 이것을 실패시키는 것: 필터 설치 실패를 무시하거나 실제 syscall 거부를 없애는 것.
    #[test]
    fn helper_filter_is_tsynced_and_cannot_spawn() {
        let out = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "commands::helper_filter::tests::filtered_child",
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .output()
            .unwrap();
        assert!(
            out.status.success()
                && String::from_utf8_lossy(&out.stdout)
                    .contains("test result: ok. 1 passed; 0 failed;"),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

#[cfg(test)]
mod result_tests {
    use super::*;
    // 이것을 실패시키는 것: 양수 TSYNC 실패 TID를 성공으로 처리하는 것.
    #[test]
    fn only_zero_tsync_result_allows_publication() {
        assert!(tsync_result(0).is_ok());
        for rc in [-1, 1, 1234] {
            assert!(tsync_result(rc).is_err());
        }
    }
}
