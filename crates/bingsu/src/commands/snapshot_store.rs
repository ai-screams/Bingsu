//! Checked context directory and bounded file reads. Publication/locking is N2.
use super::{runtime_root, sys};
use bingsu_core::fs_trust::{AclFacts, GroupOracle, Last, RefuseGroupWrite, walk_verdict};
use bingsu_core::snapshot::{self, COMPILED_MAX, HEADER, META_MAX, PREFIX};
use std::ffi::OsStr;
use std::fs::File;
use std::io::{self, Read};
use std::os::fd::{AsFd, AsRawFd};
use std::os::unix::fs::MetadataExt;

#[derive(Debug)]
pub enum StoreError {
    Root(runtime_root::RootError),
    Io(io::Error),
    Codec(bingsu_core::snapshot_codec::Error),
    Unsafe,
}
impl From<io::Error> for StoreError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}
impl From<bingsu_core::snapshot_codec::Error> for StoreError {
    fn from(e: bingsu_core::snapshot_codec::Error) -> Self {
        Self::Codec(e)
    }
}
impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Root(e) => write!(f, "runtime root: {e:?}"),
            Self::Io(e) => e.fmt(f),
            Self::Codec(e) => write!(f, "snapshot: {e:?}"),
            Self::Unsafe => f.write_str("unsafe snapshot entry"),
        }
    }
}

#[derive(Clone, Copy)]
pub enum DataFile {
    Snapshot,
    LastGood,
    Marker,
    Sequence,
    Lock,
}
impl DataFile {
    fn name(self) -> &'static str {
        match self {
            Self::Snapshot => "snapshot",
            Self::LastGood => "last-good",
            Self::Marker => "marker",
            Self::Sequence => "sequence",
            Self::Lock => "snapshot.lock",
        }
    }
    fn cap(self) -> usize {
        match self {
            Self::Snapshot | Self::LastGood => HEADER + PREFIX + COMPILED_MAX + META_MAX,
            Self::Marker => snapshot::MARKER,
            Self::Sequence => 96,
            Self::Lock => 0,
        }
    }
}
/// Constructed only after R1's pinned root walk and each 0700 child check.
/// A CRC never selects a directory. No PATH_MAX-sized joined path is built.
pub struct CheckedContextFd {
    dir: File,
    me: u32,
}
impl CheckedContextFd {
    pub fn open(
        pin: &runtime_root::Pinned,
        config: &[u8],
        state: &[u8],
        me: u32,
        groups: &mut dyn GroupOracle,
        create: bool,
    ) -> Result<Self, StoreError> {
        let components = snapshot::context_components(config, state)?;
        let mut dir = runtime_root::open_runtime_root(pin, me, groups).map_err(StoreError::Root)?;
        for name in components {
            if create {
                sys::mkdir_at(dir.as_fd(), OsStr::new(&name), 0o700)?;
            }
            let next = sys::open_dir_at_nofollow(dir.as_fd(), OsStr::new(&name))?;
            let facts = sys::fd_facts(next.as_fd())?;
            walk_verdict(
                &[facts],
                me,
                Last::PrivateFolder,
                sys::fd_is_local(next.as_raw_fd()),
                &mut RefuseGroupWrite,
            )
            .map_err(|_| StoreError::Unsafe)?;
            dir = next;
        }
        Ok(Self { dir, me })
    }
    pub fn open_data(&self, name: DataFile) -> Result<File, StoreError> {
        // NONBLOCK means FIFO/device entries cannot stall an open. No read occurs
        // until type, links, mode, ACL and ownership have passed on this very fd.
        let f = sys::open_data_at_nofollow(self.dir.as_fd(), OsStr::new(name.name()))?;
        self.check_file(&f, name.cap())?;
        Ok(f)
    }
    fn check_file(&self, f: &File, cap: usize) -> Result<usize, StoreError> {
        let facts = sys::fd_facts(f.as_fd())?;
        let md = f.metadata()?;
        data_verdict(
            facts,
            md.is_file(),
            md.nlink(),
            md.len(),
            cap,
            sys::fd_is_local(f.as_raw_fd()),
            self.me,
        )
    }
    pub fn read(&self, name: DataFile) -> Result<Vec<u8>, StoreError> {
        let mut f = self.open_data(name)?;
        let len = self.check_file(&f, name.cap())?;
        let bytes = read_exact_len(&mut f, len)?;
        if self.check_file(&f, name.cap())? != len {
            return Err(StoreError::Unsafe);
        }
        Ok(bytes)
    }
}
fn data_verdict(
    facts: bingsu_core::fs_trust::Facts,
    regular: bool,
    links: u64,
    len: u64,
    cap: usize,
    local: Option<bool>,
    me: u32,
) -> Result<usize, StoreError> {
    if !regular
        || links != 1
        || facts.uid != me
        || facts.mode & 0o7777 != 0o600
        || facts.ownership != Some(true)
        || !matches!(
            facts.acl,
            AclFacts::None | AclFacts::DenyOnly | AclFacts::PosixExtended
        )
        || local != Some(true)
    {
        return Err(StoreError::Unsafe);
    }
    let n = usize::try_from(len).map_err(|_| StoreError::Unsafe)?;
    if n > cap {
        return Err(StoreError::Unsafe);
    }
    Ok(n)
}
fn read_exact_len(f: &mut impl Read, len: usize) -> Result<Vec<u8>, StoreError> {
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(len)
        .map_err(|_| io::Error::other("snapshot allocation"))?;
    bytes.resize(len, 0);
    f.read_exact(&mut bytes)?;
    let mut extra = [0];
    if f.read(&mut extra)? != 0 {
        return Err(StoreError::Unsafe);
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};
    fn fixture(tag: &str) -> (std::path::PathBuf, runtime_root::Pinned) {
        let p = std::env::temp_dir().join(format!("bingsu-n1-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir(&p).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o700)).unwrap();
        let p = std::fs::canonicalize(p).unwrap();
        let m = std::fs::metadata(&p).unwrap();
        let pin = runtime_root::Pinned {
            path: p.clone(),
            dev: m.dev(),
            ino: m.ino(),
        };
        (p, pin)
    }
    fn path(root: &std::path::Path, config: &[u8], state: &[u8]) -> std::path::PathBuf {
        snapshot::context_components(config, state)
            .unwrap()
            .iter()
            .fold(root.to_path_buf(), |p, n| p.join(n))
    }
    // 이것을 실패시키는 것: state root를 주소에서 빼거나 read-only 경로가 폴더를 만드는 것, 0700/nofollow 검사를 빼는 것.
    #[test]
    fn context_walk_is_private_and_separate() {
        let (base, pin) = fixture("walk");
        let me = sys::current_uid();
        let open = |state, create| {
            CheckedContextFd::open(&pin, b"/cfg", state, me, &mut RefuseGroupWrite, create)
        };
        assert!(open(b"/state", false).is_err());
        let first = open(b"/state", true).unwrap();
        let same = open(b"/state", false).unwrap();
        let other = open(b"/other", true).unwrap();
        assert_eq!(
            first.dir.metadata().unwrap().ino(),
            same.dir.metadata().unwrap().ino()
        );
        assert_ne!(
            first.dir.metadata().unwrap().ino(),
            other.dir.metadata().unwrap().ino()
        );
        let store = path(&base, b"/cfg", b"/state");
        std::fs::set_permissions(&store, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(open(b"/state", true).is_err());
        std::fs::set_permissions(&store, std::fs::Permissions::from_mode(0o700)).unwrap();
        let old = store.with_file_name("old");
        std::fs::rename(&store, &old).unwrap();
        symlink(&old, &store).unwrap();
        assert!(open(b"/state", true).is_err());
        std::fs::remove_dir_all(base).unwrap();
    }
    // 이것을 실패시키는 것: 데이터의 0600·단일 링크·일반 파일·크기 검사를 빼거나 symlink를 따라가는 것.
    #[test]
    fn data_files_are_checked_before_read() {
        let (base, pin) = fixture("files");
        let c = CheckedContextFd::open(
            &pin,
            b"/cfg",
            b"/state",
            sys::current_uid(),
            &mut RefuseGroupWrite,
            true,
        )
        .unwrap();
        let file = path(&base, b"/cfg", b"/state").join("marker");
        std::fs::write(&file, b"data").unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(c.read(DataFile::Marker).unwrap(), b"data");
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o640)).unwrap();
        assert!(c.read(DataFile::Marker).is_err());
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
        let link = file.with_file_name("alias");
        std::fs::hard_link(&file, &link).unwrap();
        assert!(c.read(DataFile::Marker).is_err());
        std::fs::remove_file(&link).unwrap();
        std::fs::write(&file, [0; snapshot::MARKER + 1]).unwrap();
        assert!(c.read(DataFile::Marker).is_err());
        std::fs::remove_file(&file).unwrap();
        symlink("/dev/null", &file).unwrap();
        assert!(c.read(DataFile::Marker).is_err());
        std::fs::remove_file(&file).unwrap();
        std::fs::create_dir(&file).unwrap();
        assert!(c.read(DataFile::Marker).is_err());
        // The descriptor itself, not a fresh path, supplies uid/ownership/ACL.
        let mut wrong = c;
        wrong.me = wrong.me.wrapping_add(1);
        std::fs::remove_dir(&file).unwrap();
        std::fs::write(&file, b"data").unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(wrong.read(DataFile::Marker).is_err());
        assert_eq!(DataFile::Snapshot.name(), "snapshot");
        assert_eq!(DataFile::LastGood.name(), "last-good");
        assert_eq!(DataFile::Sequence.cap(), 96);
        assert_eq!(DataFile::Lock.name(), "snapshot.lock");
        std::fs::remove_dir_all(base).unwrap();
    }
    // 이것을 실패시키는 것: ACL/ownership/locality 관찰 실패·짧거나 늘어난 파일을 받아들이는 것.
    #[test]
    fn failed_observations_and_changed_length_refuse() {
        let facts = bingsu_core::fs_trust::Facts {
            dev: 1,
            ino: 2,
            uid: 3,
            gid: 4,
            mode: 0o100600,
            acl: AclFacts::None,
            ownership: Some(true),
        };
        assert_eq!(
            data_verdict(facts, true, 1, 10, 10, Some(true), 3).unwrap(),
            10
        );
        assert!(data_verdict(facts, false, 1, 10, 10, Some(true), 3).is_err());
        for ownership in [Some(false), None] {
            assert!(
                data_verdict(
                    bingsu_core::fs_trust::Facts { ownership, ..facts },
                    true,
                    1,
                    10,
                    10,
                    Some(true),
                    3
                )
                .is_err()
            );
        }
        for acl in [AclFacts::AllowsWrite, AclFacts::Unknown] {
            assert!(
                data_verdict(
                    bingsu_core::fs_trust::Facts { acl, ..facts },
                    true,
                    1,
                    10,
                    10,
                    Some(true),
                    3
                )
                .is_err()
            );
        }
        for local in [None, Some(false)] {
            assert!(data_verdict(facts, true, 1, 10, 10, local, 3).is_err());
        }
        assert!(read_exact_len(&mut b"short".as_slice(), 6).is_err());
        assert!(read_exact_len(&mut b"long".as_slice(), 3).is_err());
        assert_eq!(
            read_exact_len(&mut b"exact".as_slice(), 5).unwrap(),
            b"exact"
        );
    }
    // 이것을 실패시키는 것: FIFO를 blocking으로 열거나 일반 파일 검사 전에 읽는 것.
    #[test]
    fn fifo_open_is_nonblocking() {
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "commands::snapshot_store::tests::fifo_child",
                "--ignored",
                "--nocapture",
            ])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let until = std::time::Instant::now() + std::time::Duration::from_secs(3);
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                assert!(status.success());
                break;
            }
            if std::time::Instant::now() >= until {
                child.kill().unwrap();
                child.wait().unwrap();
                panic!("FIFO open blocked before metadata rejection");
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }
    // 이것을 실패시키는 것: FIFO를 0600 일반 파일처럼 허용하는 것. 위 부모 시험이 항상 실행한다.
    #[test]
    #[ignore = "child of fifo_open_is_nonblocking, bounded by the parent timeout"]
    fn fifo_child() {
        let (base, pin) = fixture("fifo");
        let c = CheckedContextFd::open(
            &pin,
            b"/cfg",
            b"/state",
            sys::current_uid(),
            &mut RefuseGroupWrite,
            true,
        )
        .unwrap();
        let fifo = path(&base, b"/cfg", b"/state").join("marker");
        sys::make_test_fifo(&fifo).unwrap();
        assert!(c.read(DataFile::Marker).is_err());
        std::fs::remove_dir_all(base).unwrap();
    }
}
