//! `bingsu --version`: this build on one line, then whether each sibling
//! beside the running file is the same build. The siblings are read, never
//! run: the same markers `init` checks before it pins them
//! (`collector::read_build`). Owner, mode and file system checks stay with
//! `init`, so "same build" does not say `init` will pin the file.
use std::ffi::OsString;
use std::process::ExitCode;

pub fn run(args: &[OsString]) -> ExitCode {
    if !args.is_empty() {
        eprintln!("usage: bingsu --version");
        return ExitCode::from(2);
    }
    #[allow(unused_mut)]
    let mut text = format!("{}\n", this_build());
    #[cfg(unix)]
    {
        let folder = std::env::current_exe().and_then(std::fs::canonicalize);
        for sibling in [
            super::collector::Sibling::PROMPT,
            super::collector::Sibling::COLLECTOR,
        ] {
            let state = match &folder {
                Ok(exe) => match exe.parent() {
                    Some(folder) => describe(folder, sibling),
                    None => unreadable("no folder above this executable"),
                },
                Err(e) => unreadable(format!("this executable's folder: {e}")),
            };
            text.push_str(&format!("{}: {state}\n", sibling.name()));
        }
    }
    print!("{text}");
    ExitCode::SUCCESS
}

/// `bingsu <version> (<identity>, <target>, rustc <release> <commit>)`: the
/// full 64-character identity, and the first nine characters of the
/// compiler's commit-hash, as `rustc -V` shows them.
pub fn this_build() -> String {
    let commit = bingsu_identity::RUSTC_COMMIT_HASH;
    format!(
        "bingsu {} ({}, {}, rustc {} {})",
        env!("CARGO_PKG_VERSION"),
        hex(&bingsu_identity::build_id().0),
        bingsu_identity::TARGET,
        bingsu_identity::RUSTC_RELEASE,
        commit.get(..9).unwrap_or(commit),
    )
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// One sibling's state, from its markers alone. The name is opened inside
/// `folder` without following a symlink, as `init` opens it.
#[cfg(unix)]
fn describe(folder: &std::path::Path, sibling: super::collector::Sibling) -> String {
    use super::collector::{Build, read_build};
    use std::os::fd::AsFd;
    let folder = match std::fs::File::open(folder) {
        Ok(folder) => folder,
        Err(e) => return unreadable(format!("this executable's folder: {e}")),
    };
    let name = std::ffi::OsStr::new(sibling.name());
    let file = match super::sys::open_data_at_nofollow(folder.as_fd(), name) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return "missing".to_owned(),
        Err(e) if e.raw_os_error() == Some(libc::ELOOP) => return "symlink, not read".to_owned(),
        Err(e) => return unreadable(e),
    };
    match file.metadata() {
        Ok(md) if md.is_file() => {}
        Ok(_) => return unreadable("not a regular file"),
        Err(e) => return unreadable(e),
    }
    match read_build(&file, sibling.role()) {
        Ok(Build::Same) => "same build".to_owned(),
        Ok(Build::Other(id)) => format!("differs (build {})", hex(&id)),
        Ok(Build::NotSibling) => format!("not a {} build", sibling.name()),
        Err(super::snapshot_store::StoreError::Unsafe) => {
            unreadable("larger than 64 MiB or changed while read")
        }
        Err(e) => unreadable(e),
    }
}

/// The reason comes from the operating system, not from the sibling's bytes;
/// it is cleaned anyway so no control or escape character reaches the terminal.
#[cfg(unix)]
fn unreadable(reason: impl std::fmt::Display) -> String {
    format!(
        "unreadable ({})",
        bingsu_core::sanitize::sanitize(reason.to_string().as_bytes())
    )
}

#[cfg(all(test, unix))]
mod tests {
    use super::super::collector::Sibling;
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::path::{Path, PathBuf};

    struct Folder(PathBuf);
    impl Folder {
        fn new(tag: &str) -> Self {
            let path =
                std::env::temp_dir().join(format!("bingsu-version-{tag}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&path);
            std::fs::create_dir(&path).unwrap();
            Self(std::fs::canonicalize(path).unwrap())
        }
    }
    impl Drop for Folder {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// The two markers a sibling of `id` and `role` carries.
    fn markers(id: [u8; 32], role: u8) -> Vec<u8> {
        let mut manifest = bingsu_identity::manifest_tag().to_vec();
        manifest[16..].copy_from_slice(&id);
        let mut tag = bingsu_identity::role_tag(role).to_vec();
        tag[17..].copy_from_slice(&id);
        [
            b"code before".as_slice(),
            &manifest,
            b"between",
            &tag,
            b"after",
        ]
        .concat()
    }

    fn state(folder: &Path, sibling: Sibling, bytes: Option<&[u8]>) -> String {
        let path = folder.join(sibling.name());
        let _ = std::fs::remove_file(&path);
        if let Some(bytes) = bytes {
            std::fs::write(&path, bytes).unwrap();
        }
        describe(folder, sibling)
    }

    // 이것을 실패시키는 것: 표식이 같은 빌드인데 다르다고 하거나 그 반대, 다른 빌드의 정체를 보이지 않거나 잘라
    // 보이는 것, 다른 역할(복사한 bingsu)·표식 없음·표식 둘을 같은 빌드로 치는 것, 없는 파일을 오류로 치는 것.
    #[test]
    fn sibling_states_come_from_their_markers() {
        let f = Folder::new("markers");
        let me = bingsu_identity::build_id().0;
        let mut other = me;
        other[31] ^= 1;
        let prompt = bingsu_identity::PROMPT_ROLE;
        let collector = bingsu_identity::COLLECTOR_ROLE;
        assert_eq!(
            state(&f.0, Sibling::PROMPT, Some(&markers(me, prompt))),
            "same build"
        );
        assert_eq!(
            state(&f.0, Sibling::COLLECTOR, Some(&markers(me, collector))),
            "same build"
        );
        assert_eq!(
            state(&f.0, Sibling::PROMPT, Some(&markers(other, prompt))),
            format!("differs (build {})", hex(&other))
        );
        for bad in [
            markers(me, collector),
            markers(me, bingsu_identity::BINGSU_ROLE),
            b"no markers at all".to_vec(),
            [markers(me, prompt), markers(me, prompt)].concat(),
            // a second build marker with one role marker
            [
                bingsu_identity::manifest_tag().as_slice(),
                &markers(me, prompt),
            ]
            .concat(),
        ] {
            assert_eq!(
                state(&f.0, Sibling::PROMPT, Some(&bad)),
                "not a bingsu-prompt build"
            );
        }
        assert_eq!(state(&f.0, Sibling::PROMPT, None), "missing");
    }

    // 이것을 실패시키는 것: symlink를 따라가 그 대상을 읽는 것, 폴더·읽을 수 없는 파일·64 MiB를 넘는 파일을 같은
    // 빌드나 없음으로 치거나 그 이유를 지우는 것.
    #[test]
    fn links_folders_and_unreadable_files_are_not_read() {
        let f = Folder::new("links");
        let me = bingsu_identity::build_id().0;
        let target = f.0.join("elsewhere");
        std::fs::write(&target, markers(me, bingsu_identity::PROMPT_ROLE)).unwrap();
        let link = f.0.join("bingsu-prompt");
        symlink(&target, &link).unwrap();
        assert_eq!(describe(&f.0, Sibling::PROMPT), "symlink, not read");
        std::fs::remove_file(&link).unwrap();
        std::fs::create_dir(&link).unwrap();
        assert_eq!(
            describe(&f.0, Sibling::PROMPT),
            "unreadable (not a regular file)"
        );
        std::fs::remove_dir(&link).unwrap();
        std::fs::write(&link, markers(me, bingsu_identity::PROMPT_ROLE)).unwrap();
        std::fs::set_permissions(&link, std::fs::Permissions::from_mode(0o000)).unwrap();
        // root reads a mode 000 file anyway; the refusal is the kernel's, not ours.
        if super::super::sys::current_uid() != 0 {
            assert!(describe(&f.0, Sibling::PROMPT).starts_with("unreadable ("));
        }
        std::fs::remove_file(&link).unwrap();
        // Over the 64 MiB the scan refuses (sparse: nothing is written).
        let big = std::fs::File::create(&link).unwrap();
        big.set_len(64 * 1024 * 1024 + 1).unwrap();
        assert_eq!(
            describe(&f.0, Sibling::PROMPT),
            "unreadable (larger than 64 MiB or changed while read)"
        );
    }

    // 이것을 실패시키는 것: 정체를 앞부분만 보이는 것, target·rustc 판을 빼는 것, 버전을 package 버전이 아닌
    // 값으로 쓰는 것.
    #[test]
    fn this_build_line_names_version_identity_target_and_compiler() {
        let line = this_build();
        let identity = hex(&bingsu_identity::build_id().0);
        assert_eq!(identity.len(), 64);
        let commit = &bingsu_identity::RUSTC_COMMIT_HASH[..9];
        assert_eq!(
            line,
            format!(
                "bingsu {} ({identity}, {}, rustc {} {commit})",
                env!("CARGO_PKG_VERSION"),
                bingsu_identity::TARGET,
                bingsu_identity::RUSTC_RELEASE
            )
        );
        assert!(!bingsu_identity::TARGET.is_empty() && !bingsu_identity::RUSTC_RELEASE.is_empty());
    }

    // 형제 파일의 바이트는 hex로만 나간다. 이것을 실패시키는 것: 다른 빌드의 정체를 hex 대신 바이트로 보이는 것,
    // 표식 자리의 ESC·제어 바이트를 줄에 싣는 것, 오류 문구를 sanitize 없이 싣는 것.
    #[test]
    fn sibling_bytes_reach_the_line_only_as_hex() {
        let f = Folder::new("escapes");
        let mut id = [0x1b; 32];
        id[1..8].copy_from_slice(b"[2J\x07\n\r\x9b");
        let line = state(
            &f.0,
            Sibling::PROMPT,
            Some(&markers(id, bingsu_identity::PROMPT_ROLE)),
        );
        let shown = line
            .strip_prefix("differs (build ")
            .and_then(|s| s.strip_suffix(')'));
        let shown = shown.unwrap_or_else(|| panic!("{line:?}"));
        assert_eq!(shown.len(), 64);
        assert!(
            shown
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()),
            "{line:?}"
        );
        let cleaned = unreadable("os said \x1b[2J\x07\u{9b}done");
        assert!(!cleaned.chars().any(char::is_control), "{cleaned:?}");
        assert!(
            cleaned.starts_with("unreadable (os said ") && cleaned.ends_with("done)"),
            "{cleaned:?}"
        );
    }

    // init이 형제를 고정할 때(`verify_as`)와 --version은 여섯 경우마다 같은 판정을 낸다: 같은 빌드만 둘 다
    // 받는다. 이것을 실패시키는 것: 다른 빌드·다른 역할을 같은 빌드로 치는 것(read_build의 Other를 Same으로),
    // symlink를 따라가는 것, 없음·폴더를 받는 것, 두 쪽이 서로 다른 판정 함수를 쓰는 것.
    #[test]
    fn init_and_version_agree_on_every_case() {
        use super::super::collector::PinnedCollector;
        use bingsu_core::fs_trust::RefuseGroupWrite;
        // A folder whose whole chain init accepts (the crate folder, as collector.rs's tests use).
        let base = std::env::current_dir()
            .unwrap()
            .join(format!("bingsu-version-agree-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir(&base).unwrap();
        let f = Folder(std::fs::canonicalize(base).unwrap());
        let me = bingsu_identity::build_id().0;
        let mut other = me;
        other[0] ^= 1;
        let prompt = bingsu_identity::PROMPT_ROLE;
        let path = f.0.join("bingsu-prompt");
        let place = |case: &str| {
            let _ = std::fs::remove_file(&path);
            let _ = std::fs::remove_dir(&path);
            let file = |bytes: Vec<u8>| {
                std::fs::write(&path, bytes).unwrap();
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
            };
            match case {
                "same" => file(markers(me, prompt)),
                "differs" => file(markers(other, prompt)),
                "missing" => {}
                "symlink" => {
                    let target = f.0.join("target-file");
                    std::fs::write(&target, markers(me, prompt)).unwrap();
                    std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o700))
                        .unwrap();
                    symlink(&target, &path).unwrap();
                }
                "not a build" => file(markers(me, bingsu_identity::COLLECTOR_ROLE)),
                "unreadable" => std::fs::create_dir(&path).unwrap(),
                _ => unreachable!(),
            }
        };
        for (case, shown, pinned) in [
            ("same", "same build", true),
            ("differs", "differs (build ", false),
            ("missing", "missing", false),
            ("symlink", "symlink, not read", false),
            ("not a build", "not a bingsu-prompt build", false),
            ("unreadable", "unreadable (", false),
        ] {
            place(case);
            let line = describe(&f.0, Sibling::PROMPT);
            let init = PinnedCollector::verify_as(
                Sibling::PROMPT,
                path.as_os_str(),
                super::super::sys::current_uid(),
                &mut RefuseGroupWrite,
            )
            .is_ok();
            assert_eq!(init, pinned, "{case}: init");
            assert!(line.starts_with(shown), "{case}: {line:?}");
            assert_eq!(line == "same build", init, "{case}: the two disagree");
        }
    }
}
