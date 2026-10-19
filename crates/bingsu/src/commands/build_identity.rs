//! Executable file facts used only to distinguish cached compilations.
//! Never trust evidence: every reuse still revalidates descriptor evidence.
use super::{source_path::Resolved, sys};
use bingsu_core::fs_trust::RefuseGroupWrite;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

pub type BuildIdentity = [u8; 40];

/// Read the executable path passed by init's hook (or the user's command).
/// Resolve links explicitly using the source descriptor walk, then fstat the
/// verified final target. An unavailable or changing chain disables cache reuse.
/// No executable contents or source inventory are read.
pub fn read(exe: &Path) -> Option<BuildIdentity> {
    read_with(exe, || {})
}

fn read_with(exe: &Path, before_identity: impl FnOnce()) -> Option<BuildIdentity> {
    let resolved = Resolved::open(exe, sys::current_uid(), &mut RefuseGroupWrite).ok()?;
    before_identity();
    let m = resolved.file.metadata().ok()?;
    // Only name/descriptor stability is needed for a cache discriminator.
    // The config-specific trust verdict (e.g. user-only ownership of the last
    // file) does not apply to a root-owned package installation. This grants
    // no trust: refresh still independently revalidates all config evidence.
    resolved.revalidate_bindings().ok()?;
    let mut identity = [0; 40];
    for (slot, fact) in identity.chunks_exact_mut(8).zip([
        m.dev().to_le_bytes(),
        m.ino().to_le_bytes(),
        m.size().to_le_bytes(),
        m.mtime().to_le_bytes(),
        m.mtime_nsec().to_le_bytes(),
    ]) {
        slot.copy_from_slice(&fact);
    }
    Some(identity)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::{self, File};
    use std::os::unix::fs::symlink;
    use std::path::PathBuf;
    use std::time::{Duration, UNIX_EPOCH};

    struct Fx(PathBuf);
    impl Fx {
        fn new(tag: &str) -> Self {
            let path =
                std::env::temp_dir().join(format!("bingsu-build-{tag}-{}", std::process::id()));
            let _ = fs::remove_dir_all(&path);
            fs::create_dir(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for Fx {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    // 이것을 실패시키는 것: 고정 경로 대신 다른 파일을 읽거나 다섯 메타데이터 사실 중 하나를 빠뜨리는 것.
    #[test]
    fn pinned_file_facts_include_nanosecond_mtime() {
        let f = Fx::new("facts");
        let exe = f.0.join("exe");
        fs::write(&exe, b"executable fixture").unwrap();
        let file = File::open(&exe).unwrap();
        file.set_modified(UNIX_EPOCH + Duration::new(1_234_567_890, 123_456_789))
            .unwrap();
        let m = file.metadata().unwrap();
        assert_eq!((m.mtime(), m.mtime_nsec()), (1_234_567_890, 123_456_789));
        let identity = read(&exe).unwrap();
        assert_eq!(&identity[0..8], &m.dev().to_le_bytes());
        assert_eq!(&identity[8..16], &m.ino().to_le_bytes());
        assert_eq!(&identity[16..24], &m.size().to_le_bytes());
        assert_eq!(&identity[24..32], &m.mtime().to_le_bytes());
        assert_eq!(&identity[32..40], &m.mtime_nsec().to_le_bytes());
        assert_eq!(read(&exe), Some(identity));
    }

    // 이것을 실패시키는 것: 없는 경로에 기본 식별값을 주거나 미해결 링크·비정규 파일·상대 경로를 받는 것.
    #[test]
    fn unavailable_pin_has_no_identity() {
        let f = Fx::new("unavailable");
        let exe = f.0.join("exe");
        assert_eq!(read(&exe), None);
        fs::write(&exe, b"fixture").unwrap();
        assert!(read(&exe).is_some());
        let link = f.0.join("link");
        symlink("missing", &link).unwrap();
        assert_eq!(read(&link), None);
        let cycle = f.0.join("cycle");
        symlink("cycle", &cycle).unwrap();
        assert_eq!(read(&cycle), None);
        assert_eq!(read(&f.0), None);
        let fifo = f.0.join("fifo");
        crate::commands::sys::make_test_fifo(&fifo).unwrap();
        assert_eq!(read(&fifo), None);
        // Cargo runs this test in the package folder, where Cargo.toml exists.
        assert!(Path::new("Cargo.toml").is_file());
        assert_eq!(read(Path::new("Cargo.toml")), None);
    }

    // 이것을 실패시키는 것: 중간 링크의 예전 대상을 고정해 설치 교체를 놓치는 것.
    #[test]
    fn intermediate_link_replacement_invalidates_identity() {
        let f = Fx::new("intermediate");
        for version in ["v1", "v2"] {
            fs::create_dir_all(f.0.join(version).join("bin")).unwrap();
            let binary = f.0.join(version).join("bin/exe");
            fs::write(&binary, b"same bytes").unwrap();
            File::open(binary)
                .unwrap()
                .set_modified(UNIX_EPOCH + Duration::new(1_234_567_890, 123_456_789))
                .unwrap();
        }
        symlink("v1", f.0.join("current")).unwrap();
        let exe = f.0.join("current/bin/exe");
        let first = read(&exe).unwrap();
        assert_eq!(read(&exe), Some(first));
        symlink("v2", f.0.join("replacement")).unwrap();
        fs::rename(f.0.join("replacement"), f.0.join("current")).unwrap();
        assert_ne!(read(&exe), Some(first));
    }

    // 이것을 실패시키는 것: 최종 대상 대신 바뀌지 않은 alias 링크의 메타데이터를 식별값으로 쓰는 것.
    #[test]
    fn final_binary_replacement_invalidates_identity() {
        let f = Fx::new("binary");
        let binary = f.0.join("binary");
        fs::write(&binary, b"same bytes").unwrap();
        symlink("binary", f.0.join("link")).unwrap();
        let exe = f.0.join("exe");
        symlink("link", &exe).unwrap();
        let first = read(&exe).unwrap();
        // Hold the old inode and preserve size/mtime so only target identity
        // distinguishes the replacement; both alias links stay unchanged.
        let old = File::open(&binary).unwrap();
        let replacement = f.0.join("replacement");
        fs::write(&replacement, b"same bytes").unwrap();
        File::open(&replacement)
            .unwrap()
            .set_modified(old.metadata().unwrap().modified().unwrap())
            .unwrap();
        fs::rename(replacement, &binary).unwrap();
        assert_ne!(read(&exe), Some(first));
    }

    // 이것을 실패시키는 것: fd를 얻은 뒤 부모/이름·링크 사슬의 재검증을 빼거나 경로를 다시 여는 것.
    #[test]
    fn replaced_chain_during_read_has_no_identity() {
        for kind in ["intermediate", "final-link", "binary", "ancestor"] {
            let f = Fx::new(&format!("race-{kind}"));
            for version in ["v1", "v2"] {
                fs::create_dir(f.0.join(version)).unwrap();
                fs::write(f.0.join(version).join("binary"), b"same bytes").unwrap();
                symlink("binary", f.0.join(version).join("exe")).unwrap();
            }
            symlink("v1", f.0.join("current")).unwrap();
            let exe = f.0.join("current/exe");
            assert!(read(&exe).is_some());
            assert_eq!(
                read_with(&exe, || match kind {
                    "intermediate" => {
                        symlink("v2", f.0.join("replacement")).unwrap();
                        fs::rename(f.0.join("replacement"), f.0.join("current")).unwrap();
                    }
                    "final-link" => {
                        symlink("../v2/binary", f.0.join("replacement")).unwrap();
                        fs::rename(f.0.join("replacement"), f.0.join("v1/exe")).unwrap();
                    }
                    "binary" => {
                        fs::rename(f.0.join("v2/binary"), f.0.join("v1/binary")).unwrap();
                    }
                    "ancestor" => {
                        fs::rename(f.0.join("v1"), f.0.join("old-v1")).unwrap();
                        fs::rename(f.0.join("v2"), f.0.join("v1")).unwrap();
                    }
                    _ => unreachable!(),
                }),
                None,
                "{kind}"
            );
        }
    }
}
