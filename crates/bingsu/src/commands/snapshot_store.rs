//! Checked context directories, bounded reads, locking and atomic publication.
use super::{runtime_root, sys};
use bingsu_core::fs_trust::{AclFacts, GroupOracle, Last, RefuseGroupWrite, walk_verdict};
use bingsu_core::snapshot::{self, COMPILED_MAX, HEADER, META_MAX, PREFIX};
use std::ffi::OsStr;
use std::fs::File;
use std::io::{self, Read};
use std::os::fd::{AsFd, AsRawFd};
use std::os::unix::fs::{FileExt, MetadataExt};

#[derive(Debug)]
pub enum StoreError {
    Busy,
    Root(runtime_root::RootError),
    Io(io::Error),
    Codec(bingsu_core::snapshot_codec::Error),
    Unsafe,
}
pub fn lock_error(e: io::Error) -> StoreError {
    if e.kind() == io::ErrorKind::WouldBlock {
        StoreError::Busy
    } else {
        StoreError::Io(e)
    }
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
            Self::Busy => f.write_str("snapshot lock is busy"),
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
    pub(super) dir: File,
    pub(super) runtime: File,
    pub(super) config: Vec<u8>,
    pub(super) state: Vec<u8>,
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
        let dir = runtime_root::open_runtime_root(pin, me, groups).map_err(StoreError::Root)?;
        Self::under_runtime(&dir, config, state, me, create)
    }

    /// The caller retains a previously checked runtime root descriptor.
    pub fn under_runtime(
        runtime: &File,
        config: &[u8],
        state: &[u8],
        me: u32,
        create: bool,
    ) -> Result<Self, StoreError> {
        let components = snapshot::context_components(config, state)?;
        let mut dir = runtime.try_clone()?;
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
        Ok(Self {
            dir,
            runtime: runtime.try_clone()?,
            config: config.to_vec(),
            state: state.to_vec(),
            me,
        })
    }
    pub fn open_data(&self, name: DataFile) -> Result<File, StoreError> {
        // NONBLOCK means FIFO/device entries cannot stall an open. No read occurs
        // until type, links, mode, ACL and ownership have passed on this very fd.
        let f = sys::open_data_at_nofollow(self.dir.as_fd(), OsStr::new(name.name()))?;
        self.check_file(&f, name.cap())?;
        Ok(f)
    }
    fn check_file(&self, f: &File, cap: usize) -> Result<usize, StoreError> {
        check_data(f, cap, self.me)
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
pub(super) fn check_data(f: &File, cap: usize, me: u32) -> Result<usize, StoreError> {
    let facts = sys::fd_facts(f.as_fd())?;
    sys::collection_ops(1)?;
    let md = f.metadata()?;
    data_verdict(
        facts,
        md.is_file(),
        md.nlink(),
        md.len(),
        cap,
        sys::fd_is_local(f.as_raw_fd()),
        me,
    )
}
pub(super) fn check_directory(dir: &File, me: u32) -> Result<(), StoreError> {
    walk_verdict(
        &[sys::fd_facts(dir.as_fd())?],
        me,
        Last::PrivateFolder,
        sys::fd_is_local(dir.as_raw_fd()),
        &mut RefuseGroupWrite,
    )
    .map_err(|_| StoreError::Unsafe)
}
pub(super) fn data_verdict(
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
/// Reads exactly the checked `len` bytes, with no end-check read: store files
/// are replaced only by rename, so a published file never changes in place
/// (spec 8 read-count rule). Callers compare the size again afterwards
/// (`check_file` or the file stamp), which refuses a file that grew; a shorter
/// file fails here.
pub(super) fn read_exact_len(f: &mut impl Read, len: usize) -> Result<Vec<u8>, StoreError> {
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(len)
        .map_err(|_| io::Error::other("snapshot allocation"))?;
    bytes.resize(len, 0);
    if sys::collection_meter_active() {
        let mut at = 0;
        while at < len {
            sys::collection_ops(1)?;
            let end = (at + 16_384).min(len);
            let n = f.read(&mut bytes[at..end])?;
            if n == 0 {
                return Err(StoreError::Unsafe);
            }
            at += n;
        }
    } else {
        f.read_exact(&mut bytes)?;
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
        assert_eq!(read_exact_len(&mut b"long".as_slice(), 3).unwrap(), b"lon");
        assert_eq!(
            read_exact_len(&mut b"exact".as_slice(), 5).unwrap(),
            b"exact"
        );
    }
    struct CountingReader<'a> {
        data: &'a [u8],
        calls: usize,
    }
    impl Read for CountingReader<'_> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.calls += 1;
            self.data.read(buf)
        }
    }

    // 이것을 실패시키는 것: 이름 바꾸기로만 교체되는 파일을 읽은 뒤 끝 확인 read를 하나 더 하는 것
    // (스펙 8: 읽기 수는 ⌈바이트 / 버퍼⌉, 끝 확인 없음).
    #[test]
    fn published_store_reads_have_no_end_check() {
        let mut reader = CountingReader {
            data: b"published bytes and more",
            calls: 0,
        };
        assert_eq!(read_exact_len(&mut reader, 15).unwrap(), b"published bytes");
        assert_eq!(reader.calls, 1);
        let mut short = CountingReader {
            data: b"short",
            calls: 0,
        };
        assert!(read_exact_len(&mut short, 6).is_err());
    }

    thread_local! {
        static READ_TICKS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
        static APPEND_AT: std::cell::RefCell<Option<(usize, std::path::PathBuf)>> = const { std::cell::RefCell::new(None) };
    }

    fn append_during_read_clock() -> u64 {
        use std::io::Write;
        let tick = READ_TICKS.with(|ticks| {
            ticks.set(ticks.get() + 1);
            ticks.get()
        });
        APPEND_AT.with(|slot| {
            let mut slot = slot.borrow_mut();
            if slot.as_ref().is_some_and(|(at, _)| *at == tick) {
                let (_, path) = slot.take().unwrap();
                let mut file = std::fs::OpenOptions::new().append(true).open(path).unwrap();
                assert_eq!(file.write(b"extra").unwrap(), 5);
            }
        });
        0
    }

    fn refuse_growth_during_read(locked: bool) {
        let (base, pin) = fixture(if locked { "locked-growth" } else { "growth" });
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
        let store = locked.then(|| c.try_lock().unwrap());
        let read = || match &store {
            Some(store) => store.read(DataFile::Marker).map(Option::unwrap),
            None => c.read(DataFile::Marker),
        };
        assert_eq!(read().unwrap(), b"data");

        READ_TICKS.with(|ticks| ticks.set(0));
        let meter =
            sys::CollectionMeter::fixture_clock(4_096, 20_000_000, append_during_read_clock);
        // Measure the prefix on this platform: ACL/ownership checks can charge
        // different numbers of operations. The next tick is the first read,
        // after the length (and, for LockedStore, the initial stamp) was saved.
        let f = c.open_data(DataFile::Marker).unwrap();
        if locked {
            sys::file_stamp(&f).unwrap();
        }
        assert_eq!(c.check_file(&f, DataFile::Marker.cap()).unwrap(), 4);
        let prefix_ticks = READ_TICKS.with(|ticks| ticks.get());
        APPEND_AT.with(|slot| *slot.borrow_mut() = Some((2 * prefix_ticks + 1, file.clone())));
        let result = read();
        drop(meter);
        assert!(
            APPEND_AT.with(|slot| slot.borrow().is_none()),
            "append hook did not run"
        );
        // Growth stays below the cap, preserves the inode and leaves the
        // original prefix readable; only the post-read comparison rejects it.
        assert_eq!(std::fs::read(&file).unwrap(), b"dataextra");
        assert!(matches!(result, Err(StoreError::Unsafe)), "{result:?}");
        drop(store);
        std::fs::remove_dir_all(base).unwrap();
    }

    // 이것을 실패시키는 것: CheckedContextFd::read의 post-read check_file 크기 비교 삭제.
    #[test]
    fn checked_context_read_rejects_growth_after_length_check() {
        refuse_growth_during_read(false);
    }

    // 이것을 실패시키는 것: LockedStore::read의 before/after file_stamp 비교 삭제.
    #[test]
    fn locked_store_read_rejects_growth_between_stamps() {
        refuse_growth_during_read(true);
    }

    fn refuse_same_inode_rewrite(slot: Slot, original: &[u8], changed: &[u8]) {
        let (base, pin) = fixture(slot.name());
        let c = CheckedContextFd::open(
            &pin,
            b"/cfg",
            b"/state",
            sys::current_uid(),
            &mut RefuseGroupWrite,
            true,
        )
        .unwrap();
        let store = c.try_lock().unwrap();
        let staged_path = path(&base, b"/cfg", b"/state").join(slot.name());
        let target = path(&base, b"/cfg", b"/state").join(slot.target().name());
        // A matching small slot must install even though stage() left its fd at EOF.
        store.stage(slot, original).unwrap();
        store.install(slot).unwrap();
        store.stage(slot, original).unwrap();
        let before = std::fs::metadata(&staged_path).unwrap();
        assert_ne!(original, changed);
        assert_eq!(original.len(), changed.len());
        validate_bytes(slot, changed).unwrap();
        std::fs::write(&staged_path, changed).unwrap();
        let after = std::fs::metadata(&staged_path).unwrap();
        assert_eq!((before.dev(), before.ino()), (after.dev(), after.ino()));
        assert_eq!(before.len(), after.len());
        // Emulate a coarse mtime/ctime tick deterministically on every filesystem:
        // make the saved stamp equal the current one, without changing saved bytes.
        {
            let mut stages = store.stages.borrow_mut();
            let staged = stages[slot as usize].as_mut().unwrap();
            staged.stamp = sys::file_stamp(&staged.file).unwrap();
            assert_eq!(
                staged.stamp,
                sys::at_stamp(c.dir.as_fd(), OsStr::new(slot.name())).unwrap()
            );
        }
        assert!(matches!(store.install(slot), Err(StoreError::Unsafe)));
        assert_eq!(std::fs::read(target).unwrap(), original);
        drop(store);
        std::fs::remove_dir_all(base).unwrap();
    }
    // 이것을 실패시키는 것: stamp가 같은 Sequence의 보유 fd 바이트 대조를 빼는 것.
    #[test]
    fn sequence_same_inode_same_length_rewrite_refuses_even_with_matching_stamp() {
        let seq = snapshot::Sequence {
            boot: [1; 16],
            epoch: [2; 16],
            generation: 1,
            verified: 1,
        };
        refuse_same_inode_rewrite(
            Slot::Sequence,
            &seq.encode(),
            &snapshot::Sequence {
                generation: 2,
                ..seq
            }
            .encode(),
        );
    }
    // 이것을 실패시키는 것: stamp가 같은 Marker의 보유 fd 바이트 대조를 빼는 것.
    #[test]
    fn marker_same_inode_same_length_rewrite_refuses_even_with_matching_stamp() {
        let marker = snapshot::Marker {
            id: snapshot::Identity {
                boot: [1; 16],
                epoch: [2; 16],
                context: [3; 4],
                generation: 1,
                source: [4; 4],
            },
            seq: 1,
            verified_at: 10,
            kind: 1,
            domain: [5; 16],
            resume: 0,
            invalid: false,
        };
        refuse_same_inode_rewrite(
            Slot::Marker,
            &marker.encode(),
            &snapshot::Marker { seq: 2, ..marker }.encode(),
        );
    }
    // 이것을 실패시키는 것: FIFO를 blocking으로 열거나 일반 파일 검사 전에 읽는 것.
    #[test]
    fn fifo_open_is_nonblocking() {
        let _inherited_fds = crate::commands::sys::test_inherited_fd_lock();
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

/// The four reusable slots are the entire crash-recovery namespace.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Slot {
    Sequence,
    Snapshot,
    LastGood,
    Marker,
}
impl Slot {
    pub const ALL: [Self; 4] = [Self::Sequence, Self::Snapshot, Self::LastGood, Self::Marker];
    fn name(self) -> &'static str {
        match self {
            Self::Sequence => ".sequence.stage",
            Self::Snapshot => ".snapshot.stage",
            Self::LastGood => ".last-good.stage",
            Self::Marker => ".marker.stage",
        }
    }
    fn target(self) -> DataFile {
        match self {
            Self::Sequence => DataFile::Sequence,
            Self::Snapshot => DataFile::Snapshot,
            Self::LastGood => DataFile::LastGood,
            Self::Marker => DataFile::Marker,
        }
    }
}
pub struct LockedStore<'a> {
    root: &'a CheckedContextFd,
    lock: sys::FileLock,
    stages: std::cell::RefCell<[Option<Staged>; 4]>,
    snapshot_before: std::cell::RefCell<Option<Option<sys::Stamp>>>,
}
pub(super) struct Staged {
    file: File,
    stamp: sys::Stamp,
    // Only Sequence (96 B) and Marker (208 B) are retained for the final pread.
    small_bytes: Option<Vec<u8>>,
}
impl CheckedContextFd {
    pub fn try_lock(&self) -> Result<LockedStore<'_>, StoreError> {
        let lock = sys::open_lock_at(self.dir.as_fd(), OsStr::new(DataFile::Lock.name()))?;
        self.check_file(&lock, 0)?;
        let lock = sys::try_lock(lock).map_err(lock_error)?;
        let store = LockedStore {
            root: self,
            lock,
            stages: std::cell::RefCell::new(std::array::from_fn(|_| None)),
            snapshot_before: std::cell::RefCell::new(None),
        };
        store.verify_lock()?;
        store.recover()?;
        Ok(store)
    }
    /// Reopen the context with a fresh group oracle, keeping this dirfd as the
    /// sole base for mutations. Replacement never redirects a publication.
    pub fn same_directory(&self, other: &Self) -> Result<(), StoreError> {
        if sys::fd_facts(self.dir.as_fd())? != sys::fd_facts(other.dir.as_fd())? {
            return Err(StoreError::Unsafe);
        }
        Ok(())
    }
}
impl LockedStore<'_> {
    pub fn verify_lock(&self) -> Result<(), StoreError> {
        self.root.check_file(&self.lock, 0)?;
        same_name(&self.lock, self.root.dir.as_fd(), DataFile::Lock.name())
    }
    fn recover(&self) -> Result<(), StoreError> {
        self.verify_lock()?;
        for slot in Slot::ALL {
            self.remove_slot(slot)?;
        }
        Ok(())
    }
    fn remove_slot(&self, slot: Slot) -> Result<(), StoreError> {
        let f = match sys::open_data_at_nofollow(self.root.dir.as_fd(), OsStr::new(slot.name())) {
            Ok(f) => f,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(e.into()),
        };
        // Interrupted contents need not decode, but safety is never waived.
        self.root.check_file(&f, 32 * 1024 * 1024)?;
        same_name(&f, self.root.dir.as_fd(), slot.name())?;
        sys::unlink_at(self.root.dir.as_fd(), OsStr::new(slot.name()))?;
        Ok(())
    }
    pub fn read(&self, name: DataFile) -> Result<Option<Vec<u8>>, StoreError> {
        let mut f = match self.root.open_data(name) {
            Ok(f) => f,
            Err(StoreError::Io(e)) if e.kind() == io::ErrorKind::NotFound => {
                if matches!(name, DataFile::Snapshot) {
                    *self.snapshot_before.borrow_mut() = Some(None);
                }
                return Ok(None);
            }
            Err(e) => return Err(e),
        };
        let stamp = sys::file_stamp(&f)?;
        let len = self.root.check_file(&f, name.cap())?;
        let bytes = read_exact_len(&mut f, len)?;
        if sys::file_stamp(&f)? != stamp {
            return Err(StoreError::Unsafe);
        }
        same_name(&f, self.root.dir.as_fd(), name.name())?;
        if matches!(name, DataFile::Snapshot) {
            *self.snapshot_before.borrow_mut() = Some(Some(stamp));
        }
        Ok(Some(bytes))
    }
    pub fn verify_snapshot(&self) -> Result<(), StoreError> {
        match &*self.snapshot_before.borrow() {
            Some(Some(before))
                if sys::at_stamp(self.root.dir.as_fd(), OsStr::new("snapshot"))? == *before =>
            {
                Ok(())
            }
            Some(None)
                if sys::at_stamp(self.root.dir.as_fd(), OsStr::new("snapshot"))
                    .is_err_and(|e| e.kind() == io::ErrorKind::NotFound) =>
            {
                Ok(())
            }
            _ => Err(StoreError::Unsafe),
        }
    }
    pub fn stage(&self, slot: Slot, bytes: &[u8]) -> Result<(), StoreError> {
        let mut staged = stage_verified(
            &self.root.dir,
            self.root.me,
            slot.name(),
            bytes,
            slot.target().cap(),
            &mut |bytes| validate_bytes(slot, bytes),
            &mut |_| {},
        )?;
        staged.small_bytes = matches!(slot, Slot::Sequence | Slot::Marker).then(|| bytes.to_vec());
        self.stages.borrow_mut()[slot as usize] = Some(staged);
        Ok(())
    }
    /// After Loader's final revalidation, check descriptor/name safety and
    /// compare the small slots through the held fd. Large slots use stamps only;
    /// their expensive copies and codec checks completed in stage().
    pub fn install(&self, slot: Slot) -> Result<(), StoreError> {
        self.verify_lock()?;
        let stages = self.stages.borrow();
        let staged = stages[slot as usize].as_ref().ok_or(StoreError::Unsafe)?;
        let f = &staged.file;
        staged.verify(
            &self.root.dir,
            self.root.me,
            slot.name(),
            slot.target().cap(),
        )?;
        if let Some(expected) = &staged.small_bytes {
            let mut actual = [0; snapshot::MARKER];
            let actual = &mut actual[..expected.len()];
            f.read_exact_at(actual, 0)?;
            if actual != expected.as_slice() {
                return Err(StoreError::Unsafe);
            }
        }
        staged.rename(&self.root.dir, slot.name(), slot.target().name())?;
        Ok(())
    }
}
impl Drop for LockedStore<'_> {
    fn drop(&mut self) {
        // A normal error cleans only validated reserved entries, still locked.
        // SIGKILL leaves them for the next owner. Never unlink the lock itself.
        let _ = self.recover();
    }
}
pub(super) fn same_name(
    f: &File,
    dir: std::os::fd::BorrowedFd<'_>,
    name: &str,
) -> Result<(), StoreError> {
    if sys::file_stamp(f)? != sys::at_stamp(dir, OsStr::new(name))? {
        return Err(StoreError::Unsafe);
    }
    Ok(())
}
/// The shared publication engine: exclusive creation, same-fd readback,
/// codec validation and descriptor/name identity. No runtime fsync.
pub(super) fn stage_verified(
    dir: &File,
    me: u32,
    name: &str,
    bytes: &[u8],
    cap: usize,
    validate: &mut dyn FnMut(&[u8]) -> Result<(), StoreError>,
    checkpoint: &mut dyn FnMut(&str),
) -> Result<Staged, StoreError> {
    if bytes.len() > cap {
        return Err(StoreError::Unsafe);
    }
    validate(bytes)?;
    checkpoint("before_create");
    let mut f = sys::create_file_at(dir.as_fd(), OsStr::new(name), 0o600)?;
    checkpoint("before_write");
    if sys::write_fd(f.as_raw_fd(), bytes) != sys::WriteOutcome::Done {
        return Err(io::Error::other("staging write failed").into());
    }
    checkpoint("after_write");
    let len = check_data(&f, cap, me)?;
    if len != bytes.len() {
        return Err(StoreError::Unsafe);
    }
    use std::io::Seek;
    sys::collection_ops(1)?;
    f.rewind()?;
    let actual = read_exact_len(&mut f, len)?;
    // The staging file is not published yet: its readback still proves that
    // our own write ended where it should.
    let mut extra = [0];
    sys::collection_ops(1)?;
    if actual != bytes || f.read(&mut extra)? != 0 {
        return Err(StoreError::Unsafe);
    }
    validate(&actual)?;
    same_name(&f, dir.as_fd(), name)?;
    let stamp = sys::file_stamp(&f)?;
    checkpoint("after_check");
    Ok(Staged {
        file: f,
        stamp,
        small_bytes: None,
    })
}
impl Staged {
    pub(super) fn verify(
        &self,
        dir: &File,
        me: u32,
        name: &str,
        cap: usize,
    ) -> Result<(), StoreError> {
        check_data(&self.file, cap, me)?;
        if sys::file_stamp(&self.file)? != self.stamp {
            return Err(StoreError::Unsafe);
        }
        same_name(&self.file, dir.as_fd(), name)
    }
    pub(super) fn install(
        &self,
        dir: &File,
        me: u32,
        name: &str,
        target: &str,
        cap: usize,
    ) -> Result<(), StoreError> {
        self.verify(dir, me, name, cap)?;
        self.rename(dir, name, target)
    }
    fn rename(&self, dir: &File, name: &str, target: &str) -> Result<(), StoreError> {
        sys::rename_at(dir.as_fd(), OsStr::new(name), OsStr::new(target))?;
        Ok(())
    }
}
fn validate_bytes(slot: Slot, bytes: &[u8]) -> Result<(), StoreError> {
    match slot {
        Slot::Snapshot | Slot::LastGood => {
            snapshot::Snapshot::decode(bytes)?;
        }
        Slot::Sequence => {
            snapshot::Sequence::decode(bytes)?;
        }
        Slot::Marker => {
            snapshot::Marker::decode(bytes)?;
        }
    }
    Ok(())
}

#[cfg(test)]
#[allow(dead_code, reason = "native collection_store integration target")]
pub(crate) fn context_dir_for_test(context: &CheckedContextFd) -> File {
    context.dir.try_clone().unwrap()
}
