//! `m1-fd-report` takes no argument or `--cgroup` (Linux only); anything
//! else is a usage error, never a report.
#![cfg(any(target_os = "linux", target_os = "macos"))]
use std::process::Command;

// 이것을 실패시키는 것: 모르는 인자를 무시하고 보고를 내는 것, macOS에서 --cgroup을 받는 것(읽을 cgroup이 없음).
#[test]
fn unknown_arguments_are_refused() {
    let exe = env!("CARGO_BIN_EXE_m1-fd-report");
    let run = |args: &[&str]| Command::new(exe).args(args).output().unwrap();
    let plain = run(&[]);
    assert!(
        plain.status.success() && plain.stdout.starts_with(b"FDS "),
        "{plain:?}"
    );
    let mut bad: Vec<&[&str]> = vec![&["--bogus"], &["--cgroup", "--cgroup"]];
    if cfg!(target_os = "macos") {
        bad.push(&["--cgroup"]);
    }
    for args in bad {
        let r = run(args);
        assert_eq!(r.status.code(), Some(2), "{args:?}: {r:?}");
        assert!(r.stdout.is_empty(), "{args:?}: {r:?}");
    }
}
