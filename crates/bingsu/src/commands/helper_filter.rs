//! Helper filter: installed after the fixed collection spawn and synchronized
//! with the already-running watchdog. This is not the prompt syscall policy.
#[cfg(target_os = "linux")]
fn program(pid: u32, child_pidfd: Option<std::os::fd::RawFd>) -> Vec<libc::sock_filter> {
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
        libc::SYS_tkill,
        #[cfg(target_arch = "x86_64")]
        libc::SYS_fork,
        #[cfg(target_arch = "x86_64")]
        libc::SYS_vfork,
    ];
    for nr in denied {
        code.push(jump(nr as u32, 0, 1));
        code.push(stmt(0x06, libc::SECCOMP_RET_ERRNO | libc::EPERM as u32));
    }
    if child_pidfd.is_none() {
        code.push(jump(libc::SYS_pidfd_send_signal as u32, 0, 1));
        code.push(stmt(0x06, libc::SECCOMP_RET_ERRNO | libc::EPERM as u32));
    }
    // Numeric process/group targets are fixed to this helper. Thread-directed
    // forms retain the tgid check so libc raise/abort can target any own thread.
    // All signal owners share one retained child pidfd; no /proc fd is admitted.
    let mut bound = vec![
        (
            libc::SYS_kill,
            vec![(0, u64::from(pid)), (1, libc::SIGKILL as u64)],
        ),
        (libc::SYS_tgkill, vec![(0, u64::from(pid))]),
        (libc::SYS_rt_sigqueueinfo, vec![(0, u64::from(pid))]),
        (libc::SYS_rt_tgsigqueueinfo, vec![(0, u64::from(pid))]),
    ];
    if let Some(fd) = child_pidfd {
        bound.push((libc::SYS_pidfd_send_signal, vec![(0, fd as u64)]));
    }
    for (nr, args) in bound {
        code.push(jump(nr as u32, 0, (args.len() * 6 + 1) as u8));
        for (arg, expected) in args {
            // seccomp_data stores full 64-bit arguments, even for pid_t/fd.
            for (offset, word) in [
                (16 + arg * 8, expected as u32),
                (20 + arg * 8, (expected >> 32) as u32),
            ] {
                code.push(stmt(0x20, offset));
                code.push(jump(word, 1, 0));
                code.push(stmt(0x06, libc::SECCOMP_RET_ERRNO | libc::EPERM as u32));
            }
        }
        code.push(stmt(0x06, libc::SECCOMP_RET_ALLOW));
    }
    code.push(stmt(0x06, libc::SECCOMP_RET_ALLOW));
    code
}
#[cfg(target_os = "linux")]
pub fn install(child_pidfd: Option<std::os::fd::RawFd>) -> std::io::Result<()> {
    // SAFETY: own PID is captured once before TSYNC.
    let pid = unsafe { libc::getpid() } as u32;
    let mut code = program(pid, child_pidfd);
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
pub fn install(_child_pidfd: Option<std::os::fd::RawFd>) -> std::io::Result<()> {
    Ok(())
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    fn evaluate(nr: i64, args: [u64; 2]) -> u32 {
        evaluate_with_pidfd(nr, args, Some(3))
    }
    fn evaluate_with_pidfd(
        nr: i64,
        args: [u64; 2],
        child_pidfd: Option<std::os::fd::RawFd>,
    ) -> u32 {
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
        evaluate_program(program(1234, child_pidfd), input)
    }
    fn evaluate_program(code: Vec<libc::sock_filter>, input: [u8; 64]) -> u32 {
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
    fn kill_requires_exact_self_pid_and_sigkill_and_pidfd_open_is_denied() {
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
        assert_eq!(evaluate(libc::SYS_waitid, [3, 0]), libc::SECCOMP_RET_ALLOW);
    }
    fn assert_self_target_only(nr: i64) {
        let denied = libc::SECCOMP_RET_ERRNO | libc::EPERM as u32;
        for target in [0, 1, 1233, u64::MAX, (-1234i64) as u64, (1 << 32) | 1234] {
            assert_eq!(evaluate(nr, [target, 0]), denied, "target={target}");
        }
        assert_eq!(evaluate(nr, [1234, 0]), libc::SECCOMP_RET_ALLOW);
    }
    // 이것을 실패시키는 것: tkill 거부를 제거하는 것(자기 tid도 예외 없음).
    #[test]
    fn tkill_is_always_denied() {
        for tid in [0, 1, 1234, u64::MAX] {
            assert_eq!(
                evaluate(libc::SYS_tkill, [tid, 0]),
                libc::SECCOMP_RET_ERRNO | libc::EPERM as u32
            );
        }
    }
    // 이것을 실패시키는 것: tgkill의 tgid 조건 또는 상위 32비트 비교 제거.
    #[test]
    fn tgkill_requires_exact_self_tgid() {
        assert_self_target_only(libc::SYS_tgkill);
    }
    // 이것을 실패시키는 것: rt_sigqueueinfo의 pid 조건 또는 상위 32비트 비교 제거.
    #[test]
    fn rt_sigqueueinfo_requires_exact_self_pid() {
        assert_self_target_only(libc::SYS_rt_sigqueueinfo);
    }
    // 이것을 실패시키는 것: rt_tgsigqueueinfo의 tgid 조건 또는 상위 32비트 비교 제거.
    #[test]
    fn rt_tgsigqueueinfo_requires_exact_self_tgid() {
        assert_self_target_only(libc::SYS_rt_tgsigqueueinfo);
    }
    // 이것을 실패시키는 것: pidfd 번호 조건·상위 비트·자식 부재 시 거부 제거.
    #[test]
    fn pidfd_send_signal_requires_exact_retained_child_fd() {
        let denied = libc::SECCOMP_RET_ERRNO | libc::EPERM as u32;
        for fd in [0, 1, 2, 4, u64::MAX, (1 << 32) | 3] {
            assert_eq!(evaluate(libc::SYS_pidfd_send_signal, [fd, 0]), denied);
        }
        assert_eq!(
            evaluate(libc::SYS_pidfd_send_signal, [3, libc::SIGKILL as u64]),
            libc::SECCOMP_RET_ALLOW
        );
        assert_eq!(
            evaluate_with_pidfd(libc::SYS_pidfd_send_signal, [3, 0], None),
            denied
        );
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
        install(None).unwrap();
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

    // 이것을 실패시키는 것: 실제 signal 행·/proc fd 거부 또는 자기 raise 허용 제거.
    #[test]
    fn live_signal_rows_and_self_raise() {
        let out = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "commands::helper_filter::tests::signal_rows_child",
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .output()
            .unwrap();
        print!("{}", String::from_utf8_lossy(&out.stdout));
        assert!(out.status.success(), "{out:?}");
        assert!(String::from_utf8_lossy(&out.stdout).contains("1 passed; 0 failed;"));
    }

    #[test]
    #[ignore = "installs irreversible TSYNC filter; real Linux signal probe"]
    fn signal_rows_child() {
        use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
        // Spawn before TSYNC. Even with a broken rule the only targets are
        // test-owned children; the unaddressable victim also exits on its own.
        let mut victim = std::process::Command::new("/bin/sleep")
            .arg("0.3")
            .spawn()
            .unwrap();
        let mut child = std::process::Command::new("/bin/sleep")
            .arg("2")
            .spawn()
            .unwrap();
        // SAFETY: direct test child, acquired before the filter.
        let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, child.id(), 0) };
        assert!(fd >= 0);
        // SAFETY: newly owned descriptor, transferred once.
        let pidfd = unsafe { OwnedFd::from_raw_fd(fd as i32) };
        install(Some(pidfd.as_raw_fd())).unwrap();
        let refused = |name: &str, rc: libc::c_long| {
            let errno = std::io::Error::last_os_error().raw_os_error();
            println!("{name}: rc={rc} errno={errno:?}");
            assert_eq!((rc, errno), (-1, Some(libc::EPERM)), "{name}");
        };
        let pid = victim.id();
        // SAFETY: every numeric target is our own disposable child.
        refused("kill(other)", unsafe {
            libc::syscall(libc::SYS_kill, pid, libc::SIGKILL)
        });
        // SAFETY: direct test child; acquisition must now be refused.
        refused("pidfd_open(other)", unsafe {
            libc::syscall(libc::SYS_pidfd_open, pid, 0)
        });
        // SAFETY: target tgid/tid belong to our direct test child.
        refused("tgkill(other)", unsafe {
            libc::syscall(libc::SYS_tgkill, pid, pid, libc::SIGKILL)
        });
        // SAFETY: direct test child.
        refused("tkill(other)", unsafe {
            libc::syscall(libc::SYS_tkill, pid, libc::SIGKILL)
        });
        // SAFETY: initialized writable signal metadata.
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        info.si_code = libc::SI_QUEUE;
        info.si_signo = libc::SIGKILL;
        // SAFETY: live initialized siginfo and our test child's PID.
        refused("rt_sigqueueinfo(other)", unsafe {
            libc::syscall(libc::SYS_rt_sigqueueinfo, pid, libc::SIGKILL, &info)
        });
        // SAFETY: live siginfo and our test child's tgid/tid.
        refused("rt_tgsigqueueinfo(other)", unsafe {
            libc::syscall(libc::SYS_rt_tgsigqueueinfo, pid, pid, libc::SIGKILL, &info)
        });
        let proc_fd = std::fs::File::open(format!("/proc/{pid}")).unwrap();
        // SAFETY: live /proc fd, null metadata; must not bypass the bound pidfd.
        refused("open(/proc/N)+pidfd_send_signal", unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                proc_fd.as_raw_fd(),
                libc::SIGKILL,
                std::ptr::null::<libc::siginfo_t>(),
                0,
            )
        });
        // SAFETY: SIGCONT has its normal, nonterminating disposition.
        assert_eq!(unsafe { libc::raise(libc::SIGCONT) }, 0);
        println!("raise(self,SIGCONT): rc=0");
        assert_eq!(
            // SAFETY: the retained pidfd identifies only the intended test child.
            unsafe {
                libc::syscall(
                    libc::SYS_pidfd_send_signal,
                    pidfd.as_raw_fd(),
                    libc::SIGKILL,
                    std::ptr::null::<libc::siginfo_t>(),
                    0,
                )
            },
            0
        );
        use std::os::unix::process::ExitStatusExt;
        assert_eq!(child.wait().unwrap().signal(), Some(libc::SIGKILL));
        assert!(
            victim.wait().unwrap().success(),
            "unrelated child was signalled"
        );
        println!("pidfd_send_signal(retained child): SIGKILL; unrelated child: exit 0");
    }

    // 이것을 실패시키는 것: 자기 tgkill까지 거부하여 libc abort 경로를 막는 것.
    #[test]
    fn self_abort_still_delivers_sigabrt() {
        use std::os::unix::process::ExitStatusExt;
        let out = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "commands::helper_filter::tests::abort_child",
                "--ignored",
                "--test-threads=1",
            ])
            .output()
            .unwrap();
        assert_eq!(out.status.signal(), Some(libc::SIGABRT), "{out:?}");
    }

    #[test]
    #[ignore = "intentionally aborts under the helper filter"]
    fn abort_child() {
        let limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: isolated test process; suppress its core dump.
        assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_CORE, &limit) }, 0);
        install(None).unwrap();
        // SAFETY: intentionally terminates only this isolated test process.
        unsafe { libc::abort() };
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
