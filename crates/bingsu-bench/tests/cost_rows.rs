//! The file-cost and writer-order runners print every row: measured rows
//! carry `"n"`, a row that cannot be measured carries `na` with the reason,
//! and the file fixture is gone afterwards.
#![cfg(any(target_os = "linux", target_os = "macos"))]
use std::path::{Path, PathBuf};
use std::process::Command;

mod common;

const FILE_ROWS: [&str; 10] = [
    "header64+marker128",
    "sweep/64",
    "sweep/256",
    "sweep/1024",
    "sweep/4096",
    "meta/stat",
    "meta/lstat",
    "meta/statfs",
    "meta/acl",
    "lock+generation",
];

/// A fresh folder under the temp dir, removed on drop.
struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> TempDir {
        let p = std::env::temp_dir().join(format!("bingsu-rows-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        TempDir(p)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn run(bin: &str, args: &[&str]) -> (bool, Vec<String>, String) {
    let out = Command::new(bin).args(args).output().unwrap();
    let lines = String::from_utf8(out.stdout)
        .unwrap()
        .lines()
        .map(str::to_string)
        .collect();
    (
        out.status.success(),
        lines,
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn file_costs(dir: &Path) -> (bool, Vec<String>, String) {
    run(
        env!("CARGO_BIN_EXE_m1-file-costs"),
        &[
            "--dir",
            dir.to_str().unwrap(),
            "--rounds",
            "3",
            "--warmup",
            "1",
        ],
    )
}

fn row_of<'a>(lines: &'a [String], name: &str) -> &'a str {
    let key = format!(r#""row":"{name}""#);
    lines
        .iter()
        .find(|l| l.contains(&key))
        .unwrap_or_else(|| panic!("no row {name}: {lines:?}"))
}

// 이것을 실패시키는 것: 행을 빠뜨리거나 순서를 바꾸는 것, warmup을 표본에 넣는 것(n이 3이 아님),
// buf·reads 기록을 빼는 것, fixture 폴더를 남기는 것.
#[test]
fn file_costs_prints_every_row_and_cleans_up() {
    let dir = TempDir::new("file");
    let (ok, lines, err) = file_costs(&dir.0);
    assert!(ok, "{err}");
    let names: Vec<&str> = lines
        .iter()
        .map(|l| {
            l.split(r#""row":""#)
                .nth(1)
                .unwrap()
                .split('"')
                .next()
                .unwrap()
        })
        .collect();
    assert_eq!(names, FILE_ROWS, "{lines:?}");
    for l in &lines {
        assert!(
            l.starts_with(r#"{"matrix":"file""#) && l.contains(r#""n":3,"#),
            "{l}"
        );
    }
    assert!(row_of(&lines, "sweep/1024").ends_with(r#""buf":4096,"reads":1}"#));
    assert!(row_of(&lines, "header64+marker128").ends_with(r#""buf":4096}"#));
    let left: Vec<_> = std::fs::read_dir(&dir.0).unwrap().collect();
    assert!(left.is_empty(), "fixture left behind: {left:?}");
}

// 이것을 실패시키는 것: ACL이 있는 fixture를 "ACL 없음" 경로로 재는 것(na가 아님), 한 행의 실패로 다른 행을 버리는 것.
#[test]
fn inherited_acl_makes_the_acl_row_na() {
    let dir = TempDir::new("acl");
    #[cfg(target_os = "macos")]
    assert!(
        Command::new("/bin/chmod")
            .args(["+a", "everyone allow read,file_inherit,directory_inherit"])
            .arg(&dir.0)
            .status()
            .unwrap()
            .success()
    );
    #[cfg(target_os = "linux")]
    common::set_posix_acl(&dir.0, c"system.posix_acl_default");
    let (ok, lines, err) = file_costs(&dir.0);
    assert!(ok, "{err}");
    let acl = row_of(&lines, "meta/acl");
    assert!(
        acl.contains(r#""na":"the fixture has an ACL (round 1)""#),
        "{acl}"
    );
    assert!(row_of(&lines, "meta/stat").contains(r#""n":3,"#));
}

// 이것을 실패시키는 것: 런타임 폴더가 없는데 행을 찍거나 0으로 끝나는 것.
#[test]
fn file_costs_without_the_folder_fails() {
    let dir = TempDir::new("gone");
    let (ok, lines, _) = file_costs(&dir.0.join("missing"));
    assert!(!ok && lines.is_empty(), "{lines:?}");
}

// 이것을 실패시키는 것: 두 순서 중 하나를 빠뜨리는 것, warmup을 표본에 넣는 것.
#[test]
fn writer_prints_both_orders() {
    let (ok, lines, err) = run(
        env!("CARGO_BIN_EXE_m1-writer-child"),
        &["--rounds", "3", "--warmup", "1"],
    );
    assert!(ok, "{err}");
    assert_eq!(lines.len(), 2, "{lines:?}");
    for (l, row) in lines.iter().zip(["release-first", "spawn-first"]) {
        assert!(
            l.starts_with(&format!(r#"{{"matrix":"writer","row":"{row}""#))
                && l.contains(r#""n":3,"#),
            "{l}"
        );
    }
}

// 이것을 실패시키는 것: 자식의 종료 상태를 버리는 것(실패한 자식을 잰 값으로 찍음).
#[test]
fn writer_child_failure_is_na() {
    let (ok, lines, err) = run(
        env!("CARGO_BIN_EXE_m1-writer-child"),
        &["--rounds", "3", "--child", "/usr/bin/false"],
    );
    assert!(ok, "{err}");
    assert_eq!(lines.len(), 2, "{lines:?}");
    for l in &lines {
        assert!(
            l.contains(r#""na":"child exit status 0x100 (probe)""#),
            "{l}"
        );
    }
}
