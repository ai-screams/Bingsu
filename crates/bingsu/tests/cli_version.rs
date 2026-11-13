//! `bingsu --version` from a copy of the built binary in a folder of its own.
#![cfg(unix)]
use std::path::{Path, PathBuf};
use std::process::Command;

struct Folder(PathBuf);
impl Drop for Folder {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn install(tag: &str) -> (Folder, PathBuf) {
    let folder =
        std::env::temp_dir().join(format!("bingsu-cli-version-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&folder);
    std::fs::create_dir(&folder).unwrap();
    let folder = std::fs::canonicalize(folder).unwrap();
    let exe = folder.join("bingsu");
    std::fs::copy(env!("CARGO_BIN_EXE_bingsu"), &exe).unwrap();
    (Folder(folder), exe)
}

fn version(exe: &Path) -> Vec<String> {
    let out = Command::new(exe)
        .arg("--version")
        .env_clear()
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0), "{out:?}");
    assert!(out.stderr.is_empty(), "{out:?}");
    String::from_utf8(out.stdout)
        .unwrap()
        .lines()
        .map(str::to_owned)
        .collect()
}

/// The 32 bytes after the one build marker in `bytes`, as hex.
fn embedded_identity(bytes: &[u8]) -> String {
    let marker = b"BNGSIBLING-ID02\0";
    let at: Vec<_> = bytes
        .windows(16)
        .enumerate()
        .filter(|(_, w)| w == marker)
        .map(|(i, _)| i)
        .collect();
    assert_eq!(at.len(), 1);
    bytes[at[0] + 16..at[0] + 48]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

// 이것을 실패시키는 것: 첫 줄의 형식(버전, 전체 정체, target, rustc 판)을 바꾸거나 정체를 파일에 든 값과 다르게
// 내는 것, 형제 줄을 빼거나 순서를 바꾸는 것, 형제를 실행하는 것(복사한 bingsu는 실행되면 사용법 오류로 끝남).
#[test]
fn version_names_this_build_and_reads_the_siblings() {
    let (folder, exe) = install("lines");
    let identity = embedded_identity(&std::fs::read(&exe).unwrap());
    let lines = version(&exe);
    assert_eq!(lines.len(), 3, "{lines:?}");
    let rest = lines[0]
        .strip_prefix(&format!("bingsu {} (", env!("CARGO_PKG_VERSION")))
        .unwrap_or_else(|| panic!("{lines:?}"));
    let words: Vec<_> = rest.strip_suffix(')').unwrap().split(", ").collect();
    assert_eq!(words.len(), 3, "{lines:?}");
    assert_eq!(words[0], identity);
    assert!(!words[1].is_empty() && !words[1].contains(' '), "{lines:?}");
    let compiler: Vec<_> = words[2].split(' ').collect();
    assert_eq!(compiler.len(), 3, "{lines:?}");
    assert_eq!(compiler[0], "rustc");
    assert!(compiler[2].len() <= 9, "{lines:?}");
    assert_eq!(
        &lines[1..],
        ["bingsu-prompt: missing", "bingsu-collect: missing"]
    );

    // A copy of bingsu under a sibling's name carries bingsu's role; a link is not followed.
    std::fs::copy(&exe, folder.0.join("bingsu-prompt")).unwrap();
    std::os::unix::fs::symlink(&exe, folder.0.join("bingsu-collect")).unwrap();
    assert_eq!(
        &version(&exe)[1..],
        [
            "bingsu-prompt: not a bingsu-prompt build",
            "bingsu-collect: symlink, not read"
        ]
    );
}

// 이것을 실패시키는 것: --version 뒤의 낱말을 무시하는 것.
#[test]
fn version_takes_no_more_words() {
    let out = Command::new(env!("CARGO_BIN_EXE_bingsu"))
        .args(["--version", "extra"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(out.stdout.is_empty());
    assert_eq!(
        String::from_utf8(out.stderr).unwrap(),
        "usage: bingsu --version\n"
    );
}
