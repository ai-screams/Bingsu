//! `spawn_in_cgroup` refuses before any child exists: argv/envp without the
//! closing NULL, and an fd that is not a cgroup.
//!
//! Neither test makes a child, so `waitpid(-1, WNOHANG)` failing with ECHILD
//! proves no process was started; that is why they share this binary only
//! with each other.
#![cfg(target_os = "linux")]
use bingsu_bench::sys::cgroup::spawn_in_cgroup;
use std::io;
use std::os::fd::{AsRawFd, OwnedFd};

fn no_child_was_made() {
    // SAFETY: waitpid with a null status pointer only reports.
    let rc = unsafe { libc::waitpid(-1, std::ptr::null_mut(), libc::WNOHANG) };
    assert_eq!(
        (rc, io::Error::last_os_error().raw_os_error()),
        (-1, Some(libc::ECHILD)),
        "a child exists"
    );
}

fn dir_fd(p: &str) -> OwnedFd {
    std::fs::File::open(p).unwrap().into()
}

// 이것을 실패시키는 것: argv·envp 끝의 NULL 검사를 빼는 것(그러면 clone3 오류가 InvalidInput이 아니다).
#[test]
fn unterminated_argv_or_envp_is_refused() {
    let cg = dir_fd("/");
    let sh = c"/bin/sh";
    let ok = [sh.as_ptr(), std::ptr::null()];
    let open = [sh.as_ptr()];
    let devnull = std::fs::File::open("/dev/null").unwrap();
    for (argv, envp) in [
        (&open[..], &ok[..]),
        (&ok[..], &open[..]),
        (&[][..], &ok[..]),
    ] {
        let e = spawn_in_cgroup(
            &cg,
            sh,
            argv,
            envp,
            devnull.as_raw_fd(),
            devnull.as_raw_fd(),
        )
        .unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::InvalidInput, "{e}");
    }
    no_child_was_made();
}

// 이것을 실패시키는 것: flags에서 CLONE_INTO_CGROUP을 빼는 것(cgroup이 아닌 fd로도 자식이 생긴다).
#[test]
fn non_cgroup_fd_is_refused() {
    let not_cgroup = dir_fd("/");
    let sh = c"/bin/sh";
    let argv = [
        sh.as_ptr(),
        c"-c".as_ptr(),
        c"exit 0".as_ptr(),
        std::ptr::null(),
    ];
    let envp = [std::ptr::null()];
    let devnull = std::fs::File::open("/dev/null").unwrap();
    let r = spawn_in_cgroup(
        &not_cgroup,
        sh,
        &argv,
        &envp,
        devnull.as_raw_fd(),
        devnull.as_raw_fd(),
    );
    assert!(r.is_err(), "spawned into a directory that is not a cgroup");
    no_child_was_made();
}
