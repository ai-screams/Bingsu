//! Helper filter: installed after the fixed collection spawn and synchronized
//! with the already-running watchdog. This is not the prompt syscall policy.
#[cfg(target_os = "linux")]
pub fn install() -> std::io::Result<()> {
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
        #[cfg(target_arch = "x86_64")]
        libc::SYS_fork,
        #[cfg(target_arch = "x86_64")]
        libc::SYS_vfork,
    ];
    for nr in denied {
        code.push(jump(nr as u32, 0, 1));
        code.push(stmt(0x06, libc::SECCOMP_RET_ERRNO | libc::EPERM as u32));
    }
    code.push(stmt(0x06, libc::SECCOMP_RET_ALLOW));
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
        install().unwrap();
        rejected_exec();
        send.send(()).unwrap();
        worker.join().unwrap();
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
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
}
