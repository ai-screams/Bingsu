//! The matrix prints every row of the Task B3 table, measured or `na`.
#![cfg(any(target_os = "linux", target_os = "macos"))]
use std::os::unix::fs::PermissionsExt;
use std::process::Command;

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

/// The stub scripts, written once before any test spawns: a script still
/// open for writing in this process while another test thread forks would
/// fail to exec with ETXTBSY on Linux.
fn script(name: &str) -> PathBuf {
    static DIR: OnceLock<PathBuf> = OnceLock::new();
    DIR.get_or_init(|| {
        let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join("matrix-rows");
        std::fs::create_dir_all(&dir).unwrap();
        for (name, body) in [
            ("stub.sh", "#!/bin/sh\nprintf R\n"),
            ("ready-then-fail.sh", "#!/bin/sh\nprintf R\nexit 3\n"),
            // Fails only inside the matrix's own cgroups (Linux cgroup rows).
            (
                "fail-in-matrix-cgroup.sh",
                "#!/bin/sh\nprintf R\ngrep -q bingsu-m1 /proc/self/cgroup && exit 3\nexit 0\n",
            ),
        ] {
            let p = dir.join(name);
            std::fs::write(&p, body).unwrap();
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        dir
    })
    .join(name)
}

// 이것을 실패시키는 것: 행을 빼거나, 측정하지 못한 행을 조용히 건너뛰는 것.
// stub 스크립트는 인자를 무시하고 `R`만 내므로 Linux의 sandbox-ready 행도 여기서는 모양만 본다.
#[test]
fn prints_every_row() {
    let stub = script("stub.sh");
    let out = Command::new(env!("CARGO_BIN_EXE_m1-spawn-matrix"))
        .args(["--rounds", "3", "--warmup", "1", "--dedicated"])
        .arg(&stub)
        .arg("--same")
        .arg(&stub)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = String::from_utf8(out.stdout).unwrap();
    let mut want = vec![
        "bare/dedicated",
        "bare/same",
        "env-limits/dedicated",
        "env-limits/same",
        "min-child-spawn-call",
    ];
    if cfg!(target_os = "linux") {
        want.extend([
            "sandbox-ready/dedicated",
            "sandbox-ready/same",
            "cgroup-clone3/dedicated",
            "cgroup-clone3/same",
            "cgroup-mkdir-clone3/dedicated",
            "cgroup-mkdir-clone3/same",
        ]);
    }
    for row in want {
        let line = text
            .lines()
            .find(|l| l.contains(&format!(r#""row":"{row}""#)))
            .unwrap_or_else(|| panic!("missing row {row}"));
        assert!(
            line.contains(r#""n":3"#) || line.contains(r#""na":"#),
            "{row}: neither measured nor na: {line}"
        );
        // 이것을 실패시키는 것: stub 필터 비용이 스펙 필터의 하한이라는 표시를 빼는 것.
        if row.starts_with("sandbox-ready/") {
            assert!(line.contains(r#""sandbox_filter":"lower-bound""#), "{line}");
        }
        // 이것을 실패시키는 것: posix_spawn 행에서 생성 방식 표시를 빼는 것.
        if !row.starts_with("cgroup-") {
            assert!(line.contains(r#""spawn_method":"posix_spawn""#), "{line}");
        }
    }
}

// 이것을 실패시키는 것: 자식 종료 상태를 보지 않는 것(준비 바이트 뒤 실패한 stub을 측정값으로 받음).
#[test]
fn failing_child_fails_the_run() {
    let bad = script("ready-then-fail.sh");
    let out = Command::new(env!("CARGO_BIN_EXE_m1-spawn-matrix"))
        .args(["--rounds", "1", "--warmup", "0", "--dedicated"])
        .arg(&bad)
        .arg("--same")
        .arg(&bad)
        .output()
        .unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "accepted a failing child");
    assert!(err.contains("child exit status"), "{err}");
}

// 이것을 실패시키는 것: 모르는 인자·반복 인자·값 없는 인자·0회 rounds를 기본값으로 넘기는 것.
#[test]
fn bad_arguments_exit_2() {
    let ok = script("stub.sh");
    let ok = ok.to_str().unwrap();
    for args in [
        vec!["--dedicated", ok, "--same", ok, "--round", "3"],
        vec!["--dedicated", ok, "--same", ok, "--same", ok],
        vec!["--dedicated", ok, "--same"],
        vec!["--dedicated", ok, "--same", ok, "--rounds", "0"],
        vec!["--dedicated", ok],
    ] {
        let out = Command::new(env!("CARGO_BIN_EXE_m1-spawn-matrix"))
            .args(&args)
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(2), "{args:?}");
        assert!(out.stdout.is_empty(), "{args:?} printed rows");
    }
}

#[cfg(target_os = "linux")]
fn cgroup_rows(text: &str) -> Vec<&str> {
    text.lines()
        .filter(|l| l.contains(r#""row":"cgroup-"#))
        .collect()
}

// A writable folder that is not a cgroup: mkdir and open work, clone3 does not.
// 이것을 실패시키는 것: clone3 실패에서 패닉하는 것, na에서 실패한 회차 번호를 빼는 것, 실패한 회차의 고유 폴더나 고정 폴더를 지우지 않는 것.
#[cfg(target_os = "linux")]
#[test]
fn cgroup_failures_are_na_and_cleaned_up() {
    let dir =
        Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("not-a-cgroup-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let stub = script("stub.sh");
    let out = Command::new(env!("CARGO_BIN_EXE_m1-spawn-matrix"))
        .args(["--rounds", "2", "--warmup", "0", "--dedicated"])
        .arg(&stub)
        .arg("--same")
        .arg(&stub)
        .arg("--cgroup-dir")
        .arg(&dir)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = String::from_utf8(out.stdout).unwrap();
    let rows = cgroup_rows(&text);
    assert_eq!(rows.len(), 4, "{text}");
    for l in rows {
        assert!(l.contains(r#""na":"clone3: "#), "{l}");
        assert!(l.ends_with(r#" (round 1)"}"#), "{l}");
    }
    let left: Vec<_> = std::fs::read_dir(&dir).unwrap().collect();
    assert!(left.is_empty(), "left behind: {left:?}");
    std::fs::remove_dir(&dir).unwrap();
}

// Needs BINGSU_TEST_CGROUP_DIR (see tests/cgroup_spawn.rs); skipped with a NOTE
// otherwise, unless BINGSU_REQUIRE_CGROUP_TESTS=1 makes that a failure.
// 이것을 실패시키는 것: cgroup 행에서 자식 종료 상태를 보지 않는 것.
#[cfg(target_os = "linux")]
#[test]
fn cgroup_child_exit_status_is_checked() {
    let Some(area) = std::env::var_os("BINGSU_TEST_CGROUP_DIR") else {
        assert!(
            std::env::var_os("BINGSU_REQUIRE_CGROUP_TESTS").is_none_or(|v| v != "1"),
            "BINGSU_REQUIRE_CGROUP_TESTS=1 but BINGSU_TEST_CGROUP_DIR is not set"
        );
        eprintln!(
            "NOTE: cgroup_child_exit_status_is_checked needs BINGSU_TEST_CGROUP_DIR; skipped"
        );
        return;
    };
    let stub = script("fail-in-matrix-cgroup.sh");
    let out = Command::new(env!("CARGO_BIN_EXE_m1-spawn-matrix"))
        .args(["--rounds", "2", "--warmup", "0", "--dedicated"])
        .arg(&stub)
        .arg("--same")
        .arg(&stub)
        .arg("--cgroup-dir")
        .arg(&area)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = String::from_utf8(out.stdout).unwrap();
    let rows = cgroup_rows(&text);
    assert_eq!(rows.len(), 4, "{text}");
    for l in rows {
        assert!(
            l.contains(r#""na":"child exit status 0x300 (round 1)""#),
            "{l}"
        );
    }
}

// Same area rule as above. 이것을 실패시키는 것: cgroup 행에서 clone3(CLONE_VM 없음) 표시나
// stub 필터 하한 표시를 빼는 것.
#[cfg(target_os = "linux")]
#[test]
fn cgroup_rows_are_measured_and_marked() {
    let Some(area) = std::env::var_os("BINGSU_TEST_CGROUP_DIR") else {
        assert!(
            std::env::var_os("BINGSU_REQUIRE_CGROUP_TESTS").is_none_or(|v| v != "1"),
            "BINGSU_REQUIRE_CGROUP_TESTS=1 but BINGSU_TEST_CGROUP_DIR is not set"
        );
        eprintln!(
            "NOTE: cgroup_rows_are_measured_and_marked needs BINGSU_TEST_CGROUP_DIR; skipped"
        );
        return;
    };
    let stub = script("stub.sh");
    let out = Command::new(env!("CARGO_BIN_EXE_m1-spawn-matrix"))
        .args(["--rounds", "2", "--warmup", "1", "--dedicated"])
        .arg(&stub)
        .arg("--same")
        .arg(&stub)
        .arg("--cgroup-dir")
        .arg(&area)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = String::from_utf8(out.stdout).unwrap();
    let rows = cgroup_rows(&text);
    assert_eq!(rows.len(), 4, "{text}");
    for l in rows {
        for want in [
            r#""n":2"#,
            r#""spawn_method":"clone3-no-vm""#,
            r#""sandbox_filter":"lower-bound""#,
        ] {
            assert!(l.contains(want), "{want} missing: {l}");
        }
    }
}
