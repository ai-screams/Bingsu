//! Bounded fixed-name logs. Failure never changes publication. Off does no I/O.
use super::{
    runtime_root,
    snapshot_store::{StoreError, data_verdict},
    sys,
};
use bingsu_core::{envelope::LogLevel, fs_trust::GroupOracle};
use std::{
    ffi::OsStr,
    fs::File,
    io,
    os::fd::{AsFd, AsRawFd},
    os::unix::fs::MetadataExt,
    path::Path,
};
const FILE_MAX: usize = 1024 * 1024;
const EVENT_MAX: usize = 4096;
const NAMES: [&str; 3] = ["refresh.log", "refresh.1.log", "refresh.2.log"];

pub(super) fn checked(file: &File, cap: usize, me: u32) -> Result<usize, StoreError> {
    let md = file.metadata()?;
    data_verdict(
        sys::fd_facts(file.as_fd())?,
        md.is_file(),
        md.nlink(),
        md.len(),
        cap,
        sys::fd_is_local(file.as_raw_fd()),
        me,
    )
}
pub fn event(
    level: LogLevel,
    root: Option<&Path>,
    me: u32,
    groups: &mut dyn GroupOracle,
    severity: LogLevel,
    message: &str,
) {
    if level == LogLevel::Off || severity == LogLevel::Off || rank(severity) > rank(level) {
        return;
    }
    let _ = append(root, me, groups, message);
}
fn rank(l: LogLevel) -> u8 {
    match l {
        LogLevel::Off => 0,
        LogLevel::Error => 1,
        LogLevel::Info => 2,
        LogLevel::DebugLog => 3,
    }
}
fn append(
    root: Option<&Path>,
    me: u32,
    groups: &mut dyn GroupOracle,
    message: &str,
) -> Result<(), StoreError> {
    let root = root.ok_or(StoreError::Unsafe)?;
    // The same held-descriptor creator as R1 init; a pinned spelling is
    // never re-canonicalized, including when several parents are missing.
    let chain =
        runtime_root::ensure_root(root, me, groups, bingsu_core::fs_trust::Last::PrivateFolder)?;
    let dir = chain.last();
    let lock = sys::open_lock_at(dir.as_fd(), OsStr::new("log.lock"))?;
    checked(&lock, 0, me)?;
    // Held until return; dropping it unlocks explicitly (FileLock).
    let _held = sys::try_lock(lock).map_err(super::snapshot_store::lock_error)?;
    let mut sizes = [0; 3];
    let mut exists = [false; 3];
    for (i, name) in NAMES.iter().enumerate() {
        match sys::open_data_at_nofollow(dir.as_fd(), OsStr::new(name)) {
            Ok(f) => {
                sizes[i] = checked(&f, FILE_MAX, me)?;
                exists[i] = true;
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
    }
    // Fixed event text only in production; still make one bounded line.
    let mut bytes: Vec<u8> = message
        .bytes()
        .filter(|b| *b >= 0x20 && *b != 0x7f)
        .take(EVENT_MAX - 1)
        .collect();
    bytes.push(b'\n');
    chain.revalidate()?;
    if sizes[0] + bytes.len() > FILE_MAX {
        if exists[1] {
            sys::rename_at(dir.as_fd(), OsStr::new(NAMES[1]), OsStr::new(NAMES[2]))?;
        }
        if exists[0] {
            sys::rename_at(dir.as_fd(), OsStr::new(NAMES[0]), OsStr::new(NAMES[1]))?;
        }
        exists[0] = false;
    }
    if !exists[0] {
        drop(sys::create_file_at(
            dir.as_fd(),
            OsStr::new(NAMES[0]),
            0o600,
        )?);
    }
    let file = super::sys::open_append_at(dir.as_fd(), OsStr::new(NAMES[0]))?;
    let size = checked(&file, FILE_MAX, me)?;
    if size + bytes.len() > FILE_MAX {
        return Err(StoreError::Unsafe);
    }
    #[cfg(test)]
    super::n3_test::observe_lock_scope();
    if !matches!(
        sys::write_fd(file.as_raw_fd(), &bytes),
        sys::WriteOutcome::Done
    ) {
        return Err(StoreError::Unsafe);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bingsu_core::fs_trust::RefuseGroupWrite;
    use std::{
        fs,
        os::unix::fs::{PermissionsExt, symlink},
    };
    // 이것을 실패시키는 것: 쓰기 전에 guard를 버리거나 close에만 잠금 해제를 맡기는 것.
    #[test]
    fn log_guard_covers_write_and_unlocks_with_inherited_descriptors() {
        let base = std::env::temp_dir().join(format!("bingsu-n3-log-lock-{}", std::process::id()));
        fs::create_dir(&base).unwrap();
        fs::set_permissions(&base, fs::Permissions::from_mode(0o700)).unwrap();
        let base = fs::canonicalize(base).unwrap();
        let root = base.join("log");
        let inherited = std::rc::Rc::new(std::cell::RefCell::new(None));
        let child = inherited.clone();
        let lock_path = root.join("log.lock");
        super::super::n3_test::on_lock_scope(move || {
            *child.borrow_mut() = Some(sys::PausedFork::new());
            assert!(matches!(
                sys::try_lock(File::open(lock_path).unwrap()),
                Err(e) if e.raw_os_error() == Some(libc::EWOULDBLOCK)
            ));
        });
        append(
            Some(&root),
            sys::current_uid(),
            &mut RefuseGroupWrite,
            "one",
        )
        .unwrap();
        assert!(inherited.borrow().is_some());
        append(
            Some(&root),
            sys::current_uid(),
            &mut RefuseGroupWrite,
            "two",
        )
        .unwrap();
        assert_eq!(fs::read(root.join(NAMES[0])).unwrap(), b"one\ntwo\n");
        drop(inherited);
        fs::remove_dir_all(base).unwrap();
    }
    // 이것을 실패시키는 것: 로그의 여러 없는 부모를 R1 생성기로 만들지 않는 것.
    #[test]
    fn fresh_log_root_creates_its_missing_state_chain() {
        let base = std::env::temp_dir().join(format!("bingsu-n3-fresh-log-{}", std::process::id()));
        fs::create_dir(&base).unwrap();
        fs::set_permissions(&base, fs::Permissions::from_mode(0o700)).unwrap();
        let base = fs::canonicalize(base).unwrap();
        let root = base.join("st/bingsu/log");
        append(
            Some(&root),
            sys::current_uid(),
            &mut RefuseGroupWrite,
            "refresh published",
        )
        .unwrap();
        assert_eq!(
            fs::read(root.join(NAMES[0])).unwrap(),
            b"refresh published\n"
        );
        for name in ["st", "st/bingsu", "st/bingsu/log"] {
            assert_eq!(
                fs::metadata(base.join(name)).unwrap().mode() & 0o7777,
                0o700
            );
        }
        fs::remove_dir_all(base).unwrap();
    }
    // 이것을 실패시키는 것: off·수준 필터를 무시하거나 경로/파일 신뢰·크기·회전 검사를 빼는 것.
    #[test]
    fn bounded_logs_refuse_path_attacks_and_off_does_no_io() {
        let base = std::env::temp_dir().join(format!("bingsu-n3-log-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        fs::create_dir(&base).unwrap();
        fs::set_permissions(&base, fs::Permissions::from_mode(0o700)).unwrap();
        let base = fs::canonicalize(base).unwrap();
        let root = base.join("log");
        let me = sys::current_uid();
        event(
            LogLevel::Off,
            Some(&root),
            me,
            &mut RefuseGroupWrite,
            LogLevel::Error,
            "off",
        );
        assert!(!root.exists());
        event(
            LogLevel::Error,
            Some(&root),
            me,
            &mut RefuseGroupWrite,
            LogLevel::Info,
            "info",
        );
        assert!(!root.exists());
        event(
            LogLevel::Info,
            Some(&root),
            me,
            &mut RefuseGroupWrite,
            LogLevel::Info,
            "hello\nworld",
        );
        assert_eq!(fs::read(root.join(NAMES[0])).unwrap(), b"helloworld\n");
        assert_eq!(fs::metadata(&root).unwrap().mode() & 0o777, 0o700);
        assert_eq!(
            fs::metadata(root.join(NAMES[0])).unwrap().mode() & 0o777,
            0o600
        );
        append(
            Some(&root),
            me,
            &mut RefuseGroupWrite,
            &"x".repeat(EVENT_MAX + 1),
        )
        .unwrap();
        assert_eq!(
            fs::metadata(root.join(NAMES[0])).unwrap().len(),
            11 + EVENT_MAX as u64
        );
        for _ in 0..800 {
            append(
                Some(&root),
                me,
                &mut RefuseGroupWrite,
                &"x".repeat(EVENT_MAX + 1),
            )
            .unwrap();
        }
        for name in NAMES {
            assert!(fs::metadata(root.join(name)).unwrap().len() <= FILE_MAX as u64);
        }
        assert_eq!(fs::read_dir(&root).unwrap().count(), 4); // 3 logs + stable lock
        let path = root.join(NAMES[0]);
        let before = fs::read(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
        assert!(append(Some(&root), me, &mut RefuseGroupWrite, "bad").is_err());
        assert_eq!(fs::read(&path).unwrap(), before);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let alias = base.join("alias");
        fs::hard_link(&path, &alias).unwrap();
        assert!(append(Some(&root), me, &mut RefuseGroupWrite, "bad").is_err());
        fs::remove_file(alias).unwrap();
        fs::rename(&path, base.join("saved")).unwrap();
        symlink(base.join("saved"), &path).unwrap();
        assert!(append(Some(&root), me, &mut RefuseGroupWrite, "bad").is_err());
        fs::remove_file(&path).unwrap();
        fs::rename(base.join("saved"), &path).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(append(Some(&root), me, &mut RefuseGroupWrite, "bad").is_err());
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        fs::rename(&root, base.join("real")).unwrap();
        symlink(base.join("real"), &root).unwrap();
        assert!(append(Some(&root), me, &mut RefuseGroupWrite, "bad").is_err());
        fs::remove_dir_all(base).unwrap();
    }
}
