//! The same-binary collector stub, `bingsu __collect-stub` (feature
//! `bench-stubs`), behaves like the dedicated `bingsu-collect`. The expected
//! bytes and exit codes are the ones crates/bingsu-collect/tests/stub.rs
//! pins for the dedicated binary (this crate's tests cannot name that
//! binary: cargo exposes only a package's own executables to its tests).
#![cfg(all(unix, feature = "bench-stubs"))]
use std::process::{Command, Stdio};

fn stub(args: &[&str], stdout: Stdio) -> (Vec<u8>, Option<i32>) {
    let out = Command::new(env!("CARGO_BIN_EXE_bingsu"))
        .arg("__collect-stub")
        .args(args)
        .stdout(stdout)
        .output()
        .unwrap();
    (out.stdout, out.status.code())
}

// 이것을 실패시키는 것: dispatch가 "__collect-stub" 자체를 stub_main에 넘기는 것(인자 전달), 또는 stub_main의
// 종료 코드를 ExitCode로 옮기지 않는 것(종료 코드 변환).
#[test]
fn same_binary_stub_matches_the_dedicated_one() {
    let piped = Stdio::piped;
    assert_eq!(stub(&[], piped()), (b"R".to_vec(), Some(0)));
    assert_eq!(stub(&["--mode", "exit"], piped()), (Vec::new(), Some(0)));
    assert_eq!(stub(&["--mode", "nope"], piped()), (Vec::new(), Some(2)));
    assert_eq!(
        stub(&["--mode", "limits", "--report-limits"], piped()),
        (b"L cpu=1/1 nofile=64/64 fsize=0/0\nR".to_vec(), Some(0))
    );
    // A read-only stdout: the ready byte cannot be written, exit 5.
    let read_only = std::fs::File::open("/dev/null").unwrap();
    assert_eq!(stub(&["--mode", "bare"], read_only.into()).1, Some(5));
}
