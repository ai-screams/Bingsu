//! Shared sibling identity. No git queries, timestamps, absolute paths in the
//! manifest, linker options or build dependencies. Cargo watches the inventory
//! directories too, so adding a source changes the identity. The compiler's
//! release and commit-hash join it: the same sources built by another rustc
//! are another build.
extern crate alloc;
#[allow(dead_code)]
#[path = "../bingsu-core/src/collection/cwd_hash.rs"]
mod digest;

use std::{env, fs, path::Path, process::Command};

fn inventory(root: &Path, path: &Path, out: &mut Vec<u8>) {
    assert!(!path.is_symlink(), "source manifest refuses symlinks");
    // The path goes out as one cargo directive line: a control character (a
    // newline above all) in a file or folder name would start another one.
    // 이것을 실패시키는 것: 아래 두 거부 중 하나를 빼는 것.
    let shown = path
        .to_str()
        .expect("source manifest refuses non-UTF-8 names");
    assert!(
        !shown.chars().any(char::is_control),
        "source manifest refuses control characters in names"
    );
    println!("cargo:rerun-if-changed={shown}");
    if path.is_dir() {
        let mut entries: Vec<_> = fs::read_dir(path)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .collect();
        entries.sort();
        for entry in entries {
            inventory(root, &entry, out);
        }
    } else {
        let name = path.strip_prefix(root).unwrap().to_str().unwrap();
        append(out, name.as_bytes(), &fs::read(path).unwrap());
    }
}
fn append(out: &mut Vec<u8>, key: &[u8], value: &[u8]) {
    out.extend((key.len() as u64).to_le_bytes());
    out.extend(key);
    out.extend((value.len() as u64).to_le_bytes());
    out.extend(value);
}
fn main() {
    let package = env::var_os("CARGO_MANIFEST_DIR").unwrap();
    let root = Path::new(&package).parent().unwrap().parent().unwrap();
    let mut manifest = b"bingsu-siblings-v1\0".to_vec();
    // The lock pins registry sources/checksums; the reviewed allowlist also pins
    // licenses, unified features and edges. Policy-only edits invalidate both
    // siblings even when the linked machine code would otherwise be unchanged.
    // 이것을 실패시키는 것: 아래 정책 파일 하나를 identity 입력에서 제외하는 것.
    for name in [
        "Cargo.toml",
        "Cargo.lock",
        "crates/bingsu-collect/dependencies.allowlist.tsv",
        "crates/bingsu-collect/collector-syscalls.tsv",
    ] {
        inventory(root, &root.join(name), &mut manifest);
    }
    // Every workspace crate the three binaries link: normal and build edges,
    // optional ones included, dev edges left out. Reading the graph here would
    // need a TOML or JSON parser in this build script, so the list is written
    // out and scripts/test_collector_audits.py compares it with cargo metadata.
    // A build script that appears later is picked up on the next clean build;
    // watching a missing file would rerun this script on every build.
    // 이것을 실패시키는 것: crate 하나나 crate의 build.rs를 identity 입력에서 빼는 것.
    for package in [
        "bingsu",
        "bingsu-prompt",
        "bingsu-core",
        "bingsu-collect",
        "bingsu-bench",
        "bingsu-identity",
        "bingsu-match",
    ] {
        let package = root.join("crates").join(package);
        inventory(root, &package.join("Cargo.toml"), &mut manifest);
        inventory(root, &package.join("src"), &mut manifest);
        let script = package.join("build.rs");
        if script.exists() {
            inventory(root, &script, &mut manifest);
        }
    }
    // Release and commit-hash only: host, binary and LLVM lines stay out, so a
    // cross build of the same sources by the same compiler from another host
    // gives the same identity. Cargo passes the real compiler in RUSTC, also
    // under RUSTC_WRAPPER.
    // 이것을 실패시키는 것: release·commit-hash 줄을 빼는 것, 실패한 rustc를 넘기는 것.
    println!("cargo:rerun-if-env-changed=RUSTC");
    let rustc = Command::new(env::var_os("RUSTC").expect("RUSTC"))
        .arg("-vV")
        .output()
        .expect("rustc -vV");
    assert!(rustc.status.success(), "rustc -vV failed");
    let rustc = String::from_utf8(rustc.stdout).unwrap();
    let [release, commit] = ["release: ", "commit-hash: "].map(|key| {
        let value = rustc
            .lines()
            .find_map(|line| line.strip_prefix(key))
            .unwrap_or_else(|| panic!("rustc -vV has no {key:?} line"));
        append(&mut manifest, key.as_bytes(), value.as_bytes());
        value
    });
    let mut settings: Vec<_> = env::vars()
        .filter(|(key, _)| {
            key.starts_with("CARGO_FEATURE_")
                || key.starts_with("CARGO_CFG_")
                || key.starts_with("CARGO_PROFILE_")
        })
        .collect();
    for key in [
        "TARGET",
        "PROFILE",
        "OPT_LEVEL",
        "DEBUG",
        "CARGO_ENCODED_RUSTFLAGS",
    ] {
        println!("cargo:rerun-if-env-changed={key}");
        settings.push((key.into(), env::var(key).unwrap_or_default()));
    }
    settings.sort();
    for (key, value) in settings {
        append(&mut manifest, key.as_bytes(), value.as_bytes());
    }
    let id = digest::sha256(&manifest);
    let mut tag = b"BNGSIBLING-ID02\0".to_vec();
    tag.extend(id);
    // `bingsu --version` prints the target and the compiler on one line that
    // release checks split at spaces, commas and parentheses: letters, digits
    // and `. _ + -` only (every real target triple, release and hash fits).
    // 이것을 실패시키는 것: 아래 검사를 빼거나 보이는 ASCII 전부로 넓히는 것.
    let target = env::var("TARGET").expect("TARGET");
    for (name, value) in [
        ("TARGET", target.as_str()),
        ("rustc release", release),
        ("rustc commit-hash", commit),
    ] {
        assert!(
            !value.is_empty()
                && value
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._+-".contains(&b)),
            "{name} has a character outside [A-Za-z0-9._+-]: {value:?}"
        );
    }
    let output = Path::new(&env::var_os("OUT_DIR").unwrap()).join("build_id.rs");
    fs::write(output, format!("#[used]\npub static BUILD_MANIFEST_TAG: [u8; 48] = {tag:?};\npub const BUILD_ID: bingsu_core::collection::wire::BuildId = bingsu_core::collection::wire::BuildId({id:?});\npub const TARGET: &str = {target:?};\npub const RUSTC_RELEASE: &str = {release:?};\npub const RUSTC_COMMIT_HASH: &str = {commit:?};\n")).unwrap();
}
