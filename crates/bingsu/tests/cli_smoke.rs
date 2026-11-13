//! Smoke test for the `bingsu` binary entry point.
use std::process::Command;

// 이것을 실패시키는 것: main이 인자 없을 때 0으로 끝나거나 stdout에 쓰는 것.
#[test]
fn no_args_prints_usage_to_stderr_and_exits_2() {
    let out = Command::new(env!("CARGO_BIN_EXE_bingsu")).output().unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(out.stdout.is_empty());
    let err = String::from_utf8(out.stderr).unwrap();
    assert!(
        err.starts_with("usage: bingsu <config|doctor|explain|help|init|list|prompt|reload|setup>"),
        "{err}"
    );
}

// 이것을 실패시키는 것: commands::run의 `__exec-v2` 분기를 지우는 것(사용법 오류 2로 끝남).
// fd 3은 /dev/null이라 중계는 빈 입력을 받고 대상을 실행하지 않은 채 RELAY_INPUT(120)으로 끝나며,
// 상태 파이프(fd 2)에 그 코드 1바이트를 쓴다.
#[cfg(target_os = "linux")]
#[test]
fn exec_entry_reaches_the_relay() {
    use std::os::fd::AsRawFd;
    use std::os::unix::process::CommandExt;
    let null = std::fs::File::open("/dev/null").unwrap();
    let fd = null.as_raw_fd();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_bingsu"));
    cmd.args([
        "__exec-v2",
        "--permit-fd=3",
        "1",
        "/bin/true",
        "neutral",
        "--",
        "true",
    ])
    .env_clear();
    let setup = move || {
        // SAFETY: dup2 is async-signal-safe and `fd` is open in the child.
        if unsafe { libc::dup2(fd, 3) } == 3 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error())
        }
    };
    // SAFETY: `setup` only calls dup2.
    unsafe { cmd.pre_exec(setup) };
    let out = cmd.output().unwrap();
    assert_eq!(out.status.code(), Some(120), "{out:?}");
    // fd 2 is the relay's status pipe: the refusal code, one byte.
    assert!(out.stdout.is_empty());
    assert_eq!(out.stderr, [120]);
}
