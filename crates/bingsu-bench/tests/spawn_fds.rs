//! The child of `spawn` holds only fds 0-2 (spec section 4: children never
//! hold the shell's or our pipes), and the ready byte arrives.
//!
//! The only test in this binary: tests running in parallel would open fds of
//! their own and push the leaked fd's number past the probed range.
#![cfg(any(target_os = "linux", target_os = "macos"))]
use bingsu_bench::sys::spawn::{SpawnSpec, dup_inheritable, read_byte, reap, spawn};
use std::os::fd::AsRawFd;

// 이것을 실패시키는 것: 자식에서 3 이상의 fd를 닫지 않는 것(Linux closefrom, macOS CLOEXEC_DEFAULT를 뺌).
// 파이프의 close-on-exec 누락은 자식 쪽 닫기가 가리므로 sys::spawn의 pipe_ends_are_cloexec가 본다.
#[test]
fn child_sees_only_stdio() {
    let devnull: std::os::fd::OwnedFd = std::fs::File::open("/dev/null").unwrap().into();
    let leak = dup_inheritable(&devnull).unwrap(); // an fd without FD_CLOEXEC in the parent
    // The probe below looks at 3-9 only; a leak above that would pass unseen.
    // 이것을 실패시키는 것: 상한을 2로 바꾸는 것(이 전제 단언이 살아 있음을 확인).
    assert!(
        leak.as_raw_fd() <= 9,
        "leak fd {} is outside the probed 3-9",
        leak.as_raw_fd()
    );
    let (sh, c) = (c"/bin/sh", c"-c");
    // Only 3-9: sh itself saves fds at 10 and above while it runs `>&N`.
    let script =
        c"for fd in 3 4 5 6 7 8 9; do (: >&$fd) 2>/dev/null && printf 'L%s' $fd; done; printf R";
    let child = spawn(&SpawnSpec {
        program: sh,
        argv: &[sh, c, script],
        env: None,
        new_session: true,
        capture_stdout: true,
    })
    .unwrap();
    let out = child.stdout.as_ref().unwrap();
    let mut got = Vec::new();
    while let Ok(b) = read_byte(out) {
        got.push(b);
        if b == b'R' {
            break;
        }
    }
    let status = reap(child.pid).unwrap();
    drop(leak);
    assert!(
        libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
        "status {status:#x}"
    );
    assert_eq!(
        got,
        b"R",
        "child inherited fds: {:?}",
        String::from_utf8_lossy(&got)
    );
}
