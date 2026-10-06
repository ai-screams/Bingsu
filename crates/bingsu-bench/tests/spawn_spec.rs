//! The other `spawn` options: new session and explicit environment.
#![cfg(any(target_os = "linux", target_os = "macos"))]
use bingsu_bench::sys::spawn::{SpawnSpec, read_byte, reap, spawn};

// 이것을 실패시키는 것: new_session일 때 SETSID 플래그를 세우지 않는 것(자식이 부모의 세션에 남음).
#[test]
fn new_session_makes_child_a_session_leader() {
    let (sh, c) = (c"/bin/sh", c"-c");
    let child = spawn(&SpawnSpec {
        program: sh,
        argv: &[sh, c, c"printf R; exec sleep 30"],
        env: None,
        new_session: true,
        capture_stdout: true,
    })
    .unwrap();
    assert_eq!(read_byte(child.stdout.as_ref().unwrap()).unwrap(), b'R');
    // SAFETY: getsid takes a pid; the child is alive (it is in `sleep`).
    let sid = unsafe { libc::getsid(child.pid) };
    // SAFETY: kill takes a pid and a signal; the child is ours and not yet reaped.
    unsafe { libc::kill(child.pid, libc::SIGKILL) };
    let status = reap(child.pid).unwrap();
    assert_eq!(sid, child.pid, "child is not a session leader");
    assert!(
        libc::WIFSIGNALED(status) && libc::WTERMSIG(status) == libc::SIGKILL,
        "status {status:#x}"
    );
}

// 이것을 실패시키는 것: env가 주어졌을 때 그 목록 대신 부모의 environ을 넘기는 것.
#[test]
fn explicit_env_replaces_the_parent_environment() {
    let (sh, c) = (c"/bin/sh", c"-c");
    let env = [c"BINGSU_SPAWN_T=e"];
    let child = spawn(&SpawnSpec {
        program: sh,
        argv: &[
            sh,
            c,
            c"printf '%s%s' \"$BINGSU_SPAWN_T\" \"${HOME:+H}\"; printf R",
        ],
        env: Some(&env),
        new_session: false,
        capture_stdout: true,
    })
    .unwrap();
    let out = child.stdout.as_ref().unwrap();
    let mut got = Vec::new();
    while let Ok(b) = read_byte(out) {
        got.push(b);
    }
    let status = reap(child.pid).unwrap();
    assert_eq!(got, b"eR", "{:?}", String::from_utf8_lossy(&got));
    assert!(
        libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
        "status {status:#x}"
    );
}
