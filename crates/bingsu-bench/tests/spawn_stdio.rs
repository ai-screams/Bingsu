//! `spawn` puts /dev/null on the stdio the caller does not capture.
//!
//! The only test in this binary: it swaps this process's fds 0 and 2 for
//! the length of one spawn, which tests running in parallel would see.
#![cfg(any(target_os = "linux", target_os = "macos"))]
use bingsu_bench::sys::spawn::{SpawnSpec, pipe_cloexec, reap, spawn};
use std::os::fd::AsRawFd;

// 이것을 실패시키는 것: capture_stdout이 거짓일 때 자식의 fd 1을 /dev/null로 열지 않는 것, 그리고
// fd 0·2를 /dev/null로 열지 않는 것. 부모의 0·2가 이미 /dev/null이면 그 누락이 가려지므로
// 시험 동안 부모의 0·2를 파이프 두 끝으로 바꿔 둔다.
#[test]
fn uncaptured_stdio_is_dev_null() {
    let (r, w) = pipe_cloexec().unwrap();
    let saved = [0, 2].map(|fd| {
        // SAFETY: dup takes an fd number; the copy restores it below.
        let s = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 10) };
        assert!(s >= 0, "dup of fd {fd}");
        s
    });
    for (from, to) in [(r.as_raw_fd(), 0), (w.as_raw_fd(), 2)] {
        // SAFETY: dup2 takes two fd numbers; fds 0 and 2 are restored below.
        assert!(unsafe { libc::dup2(from, to) } >= 0);
    }
    let (sh, c) = (c"/bin/sh", c"-c");
    let child = spawn(&SpawnSpec {
        program: sh,
        argv: &[
            sh,
            c,
            c"for fd in 0 1 2; do [ /dev/fd/$fd -ef /dev/null ] || exit 7; done",
        ],
        env: None,
        new_session: false,
        capture_stdout: false,
    });
    for (s, to) in saved.into_iter().zip([0, 2]) {
        // SAFETY: puts the saved descriptors back on 0 and 2, then closes the copies.
        assert!(unsafe { libc::dup2(s, to) } >= 0);
        // SAFETY: `s` is the copy made above and is not used again.
        unsafe { libc::close(s) };
    }
    let child = child.unwrap();
    assert!(child.stdout.is_none());
    let status = reap(child.pid).unwrap();
    assert!(
        libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
        "status {status:#x}"
    );
}
