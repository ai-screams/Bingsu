//! Shared sibling identity. No git queries, timestamps, absolute paths in the
//! manifest, linker options or build dependencies. Cargo watches the inventory
//! directories too, so adding a source changes the identity.
extern crate alloc;
#[allow(dead_code)]
#[path = "../bingsu-core/src/collection/cwd_hash.rs"]
mod digest;

use std::{env, fs, path::Path};

fn inventory(root: &Path, path: &Path, out: &mut Vec<u8>) {
    println!("cargo:rerun-if-changed={}", path.display());
    assert!(!path.is_symlink(), "source manifest refuses symlinks");
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
    for package in [
        "bingsu",
        "bingsu-core",
        "bingsu-collect",
        "bingsu-bench",
        "bingsu-identity",
    ] {
        let package = root.join("crates").join(package);
        inventory(root, &package.join("Cargo.toml"), &mut manifest);
        inventory(root, &package.join("src"), &mut manifest);
    }
    inventory(
        root,
        &root.join("crates/bingsu-identity/build.rs"),
        &mut manifest,
    );
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
    let output = Path::new(&env::var_os("OUT_DIR").unwrap()).join("build_id.rs");
    fs::write(output, format!("#[used]\npub static BUILD_MANIFEST_TAG: [u8; 48] = {tag:?};\npub const BUILD_ID: bingsu_core::collection::wire::BuildId = bingsu_core::collection::wire::BuildId({id:?});\n")).unwrap();
}
