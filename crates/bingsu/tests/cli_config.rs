//! `bingsu config schema` prints the JSON Schema core makes from the key
//! table (spec section 2 "JSON Schema").
#![cfg(unix)]
use bingsu_core::config::schema::{Which, schema};
use std::process::Command;

fn run(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_bingsu"))
        .args(args)
        .env_clear()
        .output()
        .expect("run bingsu")
}

// 이것을 실패시키는 것: 명령이 core 스키마와 다른 바이트를 내거나, `--theme`을 설정 스키마로 답하는 것,
// 모르는 인자를 받는 것.
#[test]
fn prints_the_core_schemas() {
    let c = run(&["config", "schema"]);
    assert_eq!(
        (c.status.code(), c.stdout, c.stderr.is_empty()),
        (Some(0), schema(Which::Config).into_bytes(), true)
    );
    let t = run(&["config", "schema", "--theme"]);
    assert_eq!(
        (t.status.code(), t.stdout),
        (Some(0), schema(Which::Theme).into_bytes())
    );
    for args in [
        vec!["config"],
        vec!["config", "--theme"],
        vec!["config", "schema", "--yaml"],
        vec!["config", "schema", "--theme", "extra"],
    ] {
        let bad = run(&args);
        assert_eq!((bad.status.code(), bad.stdout.is_empty()), (Some(2), true));
        assert_eq!(bad.stderr, b"usage: bingsu config schema [--theme]\n");
    }
    use std::os::unix::ffi::OsStringExt;
    let bad = Command::new(env!("CARGO_BIN_EXE_bingsu"))
        .args(["config", "schema"])
        .arg(std::ffi::OsString::from_vec(vec![0xff]))
        .env_clear()
        .output()
        .unwrap();
    assert_eq!((bad.status.code(), bad.stdout.is_empty()), (Some(2), true));
}
// 이것을 실패시키는 것: 스키마 출력이 실패했는데 성공 종료 코드를 반환하는 것.
#[test]
fn schema_write_failure_exits_1() {
    use std::os::fd::OwnedFd;
    use std::os::unix::net::UnixStream;
    use std::process::Stdio;
    let (reader, writer) = UnixStream::pair().unwrap();
    drop(reader);
    let output = Command::new(env!("CARGO_BIN_EXE_bingsu"))
        .args(["config", "schema"])
        .env_clear()
        .stdout(Stdio::from(OwnedFd::from(writer)))
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stderr.is_empty());
}
