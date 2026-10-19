//! Executable file facts used only to distinguish cached compilations.
//! Never trust evidence: every reuse still revalidates descriptor evidence.
use std::fs::OpenOptions;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;

pub type BuildIdentity = [u8; 40];

/// Read the executable path passed by init's hook (or the user's command).
/// One fstat, no executable contents or source inventory. An unavailable pin,
/// including a relative invocation or a final symlink, disables cache reuse.
pub fn read(exe: &Path) -> Option<BuildIdentity> {
    if !exe.is_absolute() {
        return None;
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK | libc::O_NOCTTY)
        .open(exe)
        .ok()?;
    let m = file.metadata().ok()?;
    if !m.is_file() {
        return None;
    }
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

    // 이것을 실패시키는 것: 없는 경로에 기본 식별값을 주거나 링크·비정규 파일·상대 경로를 받는 것.
    #[test]
    fn unavailable_pin_has_no_identity() {
        let f = Fx::new("unavailable");
        let exe = f.0.join("exe");
        assert_eq!(read(&exe), None);
        fs::write(&exe, b"fixture").unwrap();
        assert!(read(&exe).is_some());
        let link = f.0.join("link");
        symlink(&exe, &link).unwrap();
        assert_eq!(read(&link), None);
        assert_eq!(read(&f.0), None);
        let fifo = f.0.join("fifo");
        crate::commands::sys::make_test_fifo(&fifo).unwrap();
        assert_eq!(read(&fifo), None);
        // Cargo runs this test in the package folder, where Cargo.toml exists.
        assert!(Path::new("Cargo.toml").is_file());
        assert_eq!(read(Path::new("Cargo.toml")), None);
    }
}
