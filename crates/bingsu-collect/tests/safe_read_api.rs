//! Compile the production modules (without cfg(test)) to check capability boundaries.
#![cfg(unix)]
use std::{fs, path::PathBuf, process::Command};

// 이것을 실패시키는 것: Discovery 필드를 공개하거나 ancestor/단계 A 폴더에 Root 권한을 주거나 Landlock 증거를 외부에서 만들게 하는 것.
#[test]
fn capabilities_cannot_be_forged_or_read_as_roots() {
    let source = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
    let deps = std::env::current_exe()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf();
    let libc = fs::read_dir(&deps)
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| {
            p.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("liblibc-")
                && p.extension().is_some_and(|e| e == "rlib")
        })
        .expect("cargo-built libc rlib");
    let temp = std::env::temp_dir().join(format!("bingsu-api-{}", std::process::id()));
    fs::create_dir_all(&temp).unwrap();
    let prefix = format!(
        "#![allow(dead_code)]\n#[path = {meter:?}] mod meter;\n#[path = {safe:?}] mod safe_read;\n#[path = {landlock:?}] mod landlock;\nuse safe_read::*;\nuse meter::Meter;\n",
        meter = source.join("meter.rs"),
        safe = source.join("safe_read/mod.rs"),
        landlock = source.join("landlock.rs")
    );
    let compile = |name: &str, body: &str| {
        let file = temp.join(format!("{name}.rs"));
        fs::write(&file, format!("{prefix}{body}")).unwrap();
        Command::new("rustc")
            .args(["--edition=2024", "--crate-type=lib", "--emit=metadata"])
            .arg(&file)
            .arg("--out-dir")
            .arg(&temp)
            .arg("--extern")
            .arg(format!("libc={}", libc.display()))
            .arg("-L")
            .arg(format!("dependency={}", deps.display()))
            .output()
            .unwrap()
    };
    let positive = compile(
        "positive",
        "fn ok(d: Discovery, a: &AncestorDir, m: &mut Meter) { let _ = a.entries(256, m); let _: Result<Root, _> = d.select_cwd(); }",
    );
    assert!(
        positive.status.success(),
        "{}",
        String::from_utf8_lossy(&positive.stderr)
    );
    let cases = [
        (
            "private_cwd",
            "fn bad(d: Discovery) { let _: Root = d.cwd; }",
            "E0616",
        ),
        (
            "private_ancestors",
            "fn bad(d: Discovery) { let _ = d.ancestors; }",
            "E0616",
        ),
        (
            "private_logical",
            "fn bad(d: Discovery) { let _ = d.logical; }",
            "E0616",
        ),
        (
            "private_query",
            "fn bad(d: Discovery) { let _ = d.query; }",
            "E0616",
        ),
        (
            "ancestor_read",
            "fn bad(d: &Discovery, a: &Access, m: &mut Meter) { let _ = read(&d.ancestors()[0], b\"etc/passwd\", ReadCap { bytes: 64, single_link: false }, a, m); }",
            "E0308",
        ),
        (
            "ancestor_read_with",
            "fn bad(d: &Discovery, a: &Access, m: &mut Meter) { let _ = read_with(&d.ancestors()[0], b\"etc/passwd\", ReadCap { bytes: 64, single_link: false }, a, m); }",
            "E0308",
        ),
        (
            "ancestor_directory",
            "fn bad(d: &Discovery, a: &Access, m: &mut Meter) { let _ = directory_with(&d.ancestors()[0], b\"etc\", a, m); }",
            "E0308",
        ),
        (
            "ancestor_stage_a",
            "fn bad(d: &Discovery, a: &Access, m: &mut Meter) { let _ = read_stage_a(&d.ancestors()[0], StageAFile::Head, a, m); }",
            "E0308",
        ),
        (
            "stage_dir_root",
            "fn bad(d: &StageADir, a: &Access, m: &mut Meter) { let _ = directory_with(d, b\"etc\", a, m); }",
            "E0308",
        ),
    ];
    for (name, body, error) in cases {
        let output = compile(name, body);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            !output.status.success() && stderr.contains(error),
            "{name}: {stderr}"
        );
    }
    #[cfg(target_os = "linux")]
    for (name, body, error) in [
        (
            "private_proof",
            "fn bad() { let _ = landlock::ReadLayerInstalled { _thread: std::marker::PhantomData }; }",
            "E0451",
        ),
        (
            "missing_proof",
            "fn bad(a: &mut Access) { a.landlock_reads_installed(); }",
            "E0061",
        ),
        (
            "proof_send",
            "fn send<T: Send>() {} fn bad() { send::<landlock::ReadLayerInstalled>(); }",
            "E0277",
        ),
    ] {
        let output = compile(name, body);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            !output.status.success() && stderr.contains(error),
            "{name}: {stderr}"
        );
    }
    fs::remove_dir_all(temp).unwrap();
}
