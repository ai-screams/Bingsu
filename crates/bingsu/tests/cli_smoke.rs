//! Smoke test for the `bingsu` binary entry point.
use std::process::Command;

// 이것을 실패시키는 것: main이 인자 없을 때 0으로 끝나거나 stdout에 쓰는 것.
#[test]
fn no_args_prints_usage_to_stderr_and_exits_2() {
    let out = Command::new(env!("CARGO_BIN_EXE_bingsu")).output().unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(out.stdout.is_empty());
    let err = String::from_utf8(out.stderr).unwrap();
    assert!(err.starts_with("usage: bingsu <init|prompt>"), "{err}");
}
