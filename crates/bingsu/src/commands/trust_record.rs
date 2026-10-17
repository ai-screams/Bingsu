//! The `config use` trust record (spec section 4 "config edit loop": the
//! canonical path and identity of the config the user chose, kept under the
//! state root `init` pinned). The record makes a file outside the config
//! root a source of execution keys, so it is read like the runtime state
//! files (spec section 3 state file row): the state root passes rule 2, the
//! record is a regular file owned by the user, mode 0600, one link, at most
//! `RECORD_MAX` bytes, opened without following a symlink, in a known
//! format version. A record that fails any of these is not used.
//!
//! Format (version 1, bytes): `bingsu-config-use 1\n<st_dev> <st_ino>\n`
//! then the canonical path to the end (no newline added; a path may hold
//! one). Writing (`write`, called by `config use`, Task N5) goes through a
//! temporary file in the same folder, `fsync`, rename, folder `fsync`: the
//! record lives outside the runtime root, so it keeps the durable steps.
use crate::commands::runtime_root::{Chain, RootError, open_chain};
use crate::commands::sys;
use bingsu_core::fs_trust::{AclFacts, Facts, GroupOracle, Last, walk_verdict};
use std::ffi::{OsStr, OsString};
use std::io::Read;
use std::os::fd::AsFd;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

pub const RECORD_NAME: &str = "config-use";
const MAGIC: &[u8] = b"bingsu-config-use 1\n";
/// A canonical path is at most PATH_MAX (4096) bytes; the rest is the
/// header.
pub const RECORD_MAX: u64 = 4096 + 64;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    pub dev: u64,
    pub ino: u64,
    pub path: PathBuf,
}

#[derive(Debug, PartialEq, Eq)]
pub enum RecordError {
    /// No record: `config use` was never run (not an error to report).
    Absent,
    /// The state root failed the walk or rule 2.
    StateRoot(RootError),
    /// A symlink, FIFO or folder in the record's place, or a failed read.
    NotAFile,
    Owner,
    Mode(u32),
    Links(u64),
    TooBig(u64),
    /// Another format version, or bytes that are not this format.
    Format,
    Acl,
    Ownership,
    Changed,
}

fn parse(bytes: &[u8]) -> Option<Record> {
    let rest = bytes.strip_prefix(MAGIC)?;
    let nl = rest.iter().position(|&b| b == b'\n')?;
    let (ids, path) = (&rest[..nl], &rest[nl + 1..]);
    let ids = std::str::from_utf8(ids).ok()?;
    let (dev, ino) = ids.split_once(' ')?;
    let num = |s: &str| {
        let ok = !s.is_empty()
            && s.bytes().all(|b| b.is_ascii_digit())
            && (s == "0" || !s.starts_with('0'));
        ok.then(|| s.parse::<u64>().ok()).flatten()
    };
    let path = PathBuf::from(OsString::from_vec(path.to_vec()));
    path.is_absolute().then_some(())?;
    Some(Record {
        dev: num(dev)?,
        ino: num(ino)?,
        path,
    })
}

fn encode(r: &Record) -> Vec<u8> {
    let mut out = MAGIC.to_vec();
    out.extend_from_slice(format!("{} {}\n", r.dev, r.ino).as_bytes());
    out.extend_from_slice(r.path.as_os_str().as_bytes());
    out
}

/// Opens the state root through the walk and checks rule 2 (owned by the
/// user, nobody else can write it or any folder above it).
fn open_state_root(
    state_root: &Path,
    me: u32,
    groups: &mut dyn GroupOracle,
) -> Result<Chain, RecordError> {
    let chain = open_chain(state_root).map_err(RecordError::StateRoot)?;
    state_verdict(&chain, me, groups)?;
    Ok(chain)
}

fn state_verdict(chain: &Chain, me: u32, groups: &mut dyn GroupOracle) -> Result<(), RecordError> {
    walk_verdict(&chain.facts, me, Last::Mine, Some(true), groups)
        .map_err(|r| RecordError::StateRoot(RootError::Refused(r)))
}

/// N2 keeps the approval bytes and their exact source descriptor, including
/// the state-root chain. A bare decoded Record is never publication evidence.
pub struct RecordEvidence {
    pub record: Record,
    chain: Chain,
    file: std::fs::File,
    stamp: sys::Stamp,
    facts: Facts,
}

fn check_record(file: &std::fs::File, me: u32) -> Result<Facts, RecordError> {
    let md = file.metadata().map_err(|_| RecordError::NotAFile)?;
    if !md.file_type().is_file() {
        return Err(RecordError::NotAFile);
    }
    if md.uid() != me {
        return Err(RecordError::Owner);
    }
    if md.mode() & 0o7777 != 0o600 {
        return Err(RecordError::Mode(md.mode() & 0o7777));
    }
    if md.nlink() != 1 {
        return Err(RecordError::Links(md.nlink()));
    }
    if md.len() > RECORD_MAX {
        return Err(RecordError::TooBig(md.len()));
    }
    let facts = sys::fd_facts(file.as_fd()).map_err(|_| RecordError::NotAFile)?;
    record_permissions(facts)
}

fn record_permissions(facts: Facts) -> Result<Facts, RecordError> {
    if facts.ownership != Some(true) {
        return Err(RecordError::Ownership);
    }
    if !matches!(
        facts.acl,
        AclFacts::None | AclFacts::DenyOnly | AclFacts::PosixExtended
    ) {
        return Err(RecordError::Acl);
    }
    Ok(facts)
}

impl RecordEvidence {
    pub fn export(&self, e: &mut super::evidence::Encoder) {
        e.path(&self.record.path);
        e.num(self.record.dev);
        e.num(self.record.ino);
        e.chain(&self.chain);
        e.stamp(&self.stamp);
        e.facts(self.facts);
    }

    pub fn fd_count(&self) -> usize {
        self.chain.fds.len() + 1
    }

    pub fn revalidate(&self, me: u32, groups: &mut dyn GroupOracle) -> Result<(), RecordError> {
        self.chain.revalidate().map_err(|_| RecordError::Changed)?;
        state_verdict(&self.chain, me, groups)?;
        if check_record(&self.file, me)? != self.facts
            || sys::file_stamp(&self.file).map_err(|_| RecordError::Changed)? != self.stamp
            || sys::at_stamp(self.chain.last().as_fd(), OsStr::new(RECORD_NAME))
                .map_err(|_| RecordError::Changed)?
                != self.stamp
        {
            return Err(RecordError::Changed);
        }
        Ok(())
    }
}

pub fn read_session(
    state_root: &Path,
    me: u32,
    groups: &mut dyn GroupOracle,
) -> Result<RecordEvidence, RecordError> {
    let chain = open_state_root(state_root, me, groups)?;
    let mut file = match sys::open_file_at_nofollow(chain.last().as_fd(), OsStr::new(RECORD_NAME)) {
        Ok(f) => f,
        Err(e) if e.raw_os_error() == Some(libc::ENOENT) => return Err(RecordError::Absent),
        Err(_) => return Err(RecordError::NotAFile),
    };
    let facts = check_record(&file, me)?;
    let stamp = sys::file_stamp(&file).map_err(|_| RecordError::NotAFile)?;
    let mut bytes = Vec::new();
    file.by_ref()
        .take(RECORD_MAX + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| RecordError::NotAFile)?;
    if bytes.len() as u64 > RECORD_MAX {
        return Err(RecordError::TooBig(bytes.len() as u64));
    }
    let record = parse(&bytes).ok_or(RecordError::Format)?;
    let evidence = RecordEvidence {
        record,
        chain,
        file,
        stamp,
        facts,
    };
    evidence.revalidate(me, groups)?;
    Ok(evidence)
}

/// Convenience for diagnostics only. N2 must use read_session/with_record.
pub fn read(
    state_root: &Path,
    me: u32,
    groups: &mut dyn GroupOracle,
) -> Result<Record, RecordError> {
    Ok(read_session(state_root, me, groups)?.record)
}

/// Called on the finished temporary fd before its name is published.
fn validate_completed_record(f: &std::fs::File, me: u32) -> std::io::Result<()> {
    check_record(f, me).map_err(|e| std::io::Error::other(format!("record: {e:?}")))?;
    Ok(())
}

/// The shared state lock. Callers holding both locks always acquire the
/// context snapshot lock first. The lock is persistent and never renamed.
pub struct SelectionLock {
    chain: Chain,
    lock: std::fs::File,
    state: PathBuf,
    me: u32,
}
impl SelectionLock {
    pub fn evidence_export(&self) -> std::io::Result<Vec<u8>> {
        let mut e = super::evidence::Encoder::new();
        e.chain(&self.chain);
        e.finish()
    }

    pub fn try_lock(state: &Path, me: u32, groups: &mut dyn GroupOracle) -> std::io::Result<Self> {
        let chain = open_state_root(state, me, groups)
            .map_err(|e| std::io::Error::other(format!("state: {e:?}")))?;
        let lock = sys::open_lock_at(chain.last().as_fd(), OsStr::new("selection.lock"))?;
        check_record(&lock, me).map_err(|e| std::io::Error::other(format!("lock: {e:?}")))?;
        if lock.metadata()?.len() != 0 {
            return Err(std::io::Error::other("nonempty selection lock"));
        }
        sys::try_lock(&lock)?;
        let out = Self {
            chain,
            lock,
            state: state.to_path_buf(),
            me,
        };
        out.verify(groups)?;
        Ok(out)
    }
    pub fn verify(&self, groups: &mut dyn GroupOracle) -> std::io::Result<()> {
        self.chain.revalidate()?;
        state_verdict(&self.chain, self.me, groups)
            .map_err(|e| std::io::Error::other(format!("state: {e:?}")))?;
        check_record(&self.lock, self.me)
            .map_err(|e| std::io::Error::other(format!("lock: {e:?}")))?;
        if sys::file_stamp(&self.lock)?
            != sys::at_stamp(self.chain.last().as_fd(), OsStr::new("selection.lock"))?
            || self.lock.metadata()?.len() != 0
        {
            return Err(std::io::Error::other("selection lock changed"));
        }
        Ok(())
    }
    /// Retain a missing record as a checked absence as well as an existing fd.
    pub fn read(
        &self,
        groups: &mut dyn GroupOracle,
    ) -> Result<Option<RecordEvidence>, RecordError> {
        match read_session(&self.state, self.me, groups) {
            Ok(e) => Ok(Some(e)),
            Err(RecordError::Absent) => Ok(None),
            Err(e) => Err(e),
        }
    }
    pub fn unchanged(
        &self,
        expected: Option<&RecordEvidence>,
        groups: &mut dyn GroupOracle,
    ) -> std::io::Result<()> {
        self.verify(groups)?;
        if let Some(e) = expected {
            e.revalidate(self.me, groups)
                .map_err(|e| std::io::Error::other(format!("selection: {e:?}")))
        } else {
            match sys::at_stamp(self.chain.last().as_fd(), OsStr::new(RECORD_NAME)) {
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
                _ => Err(std::io::Error::other("selection appeared")),
            }
        }
    }
    /// N5 can compare an earlier selection before replacing it. Automatic
    /// renewal additionally requires the very same canonical selection.
    pub fn replace(
        &self,
        expected: Option<&RecordEvidence>,
        r: &Record,
        groups: &mut dyn GroupOracle,
    ) -> std::io::Result<()> {
        self.unchanged(expected, groups)?;
        self.write_record(r, groups)
    }
    pub fn renew(
        &self,
        expected: &RecordEvidence,
        r: &Record,
        groups: &mut dyn GroupOracle,
    ) -> std::io::Result<()> {
        if expected.record.path != r.path {
            return Err(std::io::Error::other("renewal changed selection"));
        }
        self.replace(Some(expected), r, groups)
    }
    fn write_record(&self, r: &Record, groups: &mut dyn GroupOracle) -> std::io::Result<()> {
        let bytes = encode(r);
        if bytes.len() as u64 > RECORD_MAX || parse(&bytes).as_ref() != Some(r) {
            return Err(std::io::Error::other("invalid approval record"));
        }
        let dir = self.chain.last();
        let sync_dir = sys::open_dir_at_nofollow(dir.as_fd(), OsStr::new("."))?;
        let tmp = OsStr::new(".config-use.stage");
        // One reserved durable-record slot, protected by selection.lock.
        match sys::open_file_at_nofollow(dir.as_fd(), tmp) {
            Ok(f) => {
                validate_completed_record(&f, self.me)?;
                if sys::file_stamp(&f)? != sys::at_stamp(dir.as_fd(), tmp)? {
                    return Err(std::io::Error::other("record staging changed"));
                }
                sys::unlink_at(dir.as_fd(), tmp)?;
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        let f = sys::create_file_at(dir.as_fd(), tmp, 0o600)?;
        let done = (|| {
            use std::os::fd::AsRawFd;
            if sys::write_fd(f.as_raw_fd(), &bytes) != sys::WriteOutcome::Done {
                return Err(std::io::Error::other("write failed"));
            }
            validate_completed_record(&f, self.me)?;
            self.verify(groups)?;
            if sys::file_stamp(&f)? != sys::at_stamp(dir.as_fd(), tmp)? {
                return Err(std::io::Error::other("record staging changed"));
            }
            f.sync_all()?;
            sys::rename_at(dir.as_fd(), tmp, OsStr::new(RECORD_NAME))?;
            sync_dir.sync_all()
        })();
        if done.is_err() && sys::file_stamp(&f).ok() == sys::at_stamp(dir.as_fd(), tmp).ok() {
            let _ = sys::unlink_at(dir.as_fd(), tmp);
        }
        done
    }
}

/// Explicit selection writes share exactly the same lock as automatic renew.
pub fn write(
    state_root: &Path,
    me: u32,
    groups: &mut dyn GroupOracle,
    r: &Record,
) -> std::io::Result<()> {
    let lock = SelectionLock::try_lock(state_root, me, groups)?;
    let expected = lock
        .read(groups)
        .map_err(|e| std::io::Error::other(format!("record: {e:?}")))?;
    lock.replace(expected.as_ref(), r, groups)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bingsu_core::fs_trust::RefuseGroupWrite;
    use std::os::unix::fs::PermissionsExt;

    fn scratch(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("bingsu-tr-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let d = std::fs::canonicalize(&d).unwrap();
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o700)).unwrap();
        d
    }

    fn rec() -> Record {
        Record {
            dev: 1,
            ino: 2,
            path: PathBuf::from("/a/b\nc.toml"),
        }
    }

    // 왕복과 형식 검사. 이것을 실패시키는 것: 형식 버전을 보지 않는 것, 앞자리 0·빈 숫자를 받는 것, 상대 경로를 받는 것,
    // 경로의 줄바꿈에서 자르는 것.
    #[test]
    fn the_record_round_trips_and_refuses_other_formats() {
        assert_eq!(parse(&encode(&rec())), Some(rec()));
        for bad in [
            b"bingsu-config-use 2\n1 2\n/x".as_slice(),
            b"bingsu-config-use 1\n01 2\n/x",
            b"bingsu-config-use 1\n 2\n/x",
            b"bingsu-config-use 1\n1 2\nrel",
            b"bingsu-config-use 1\n1 2",
            b"",
        ] {
            assert_eq!(parse(bad), None, "{}", String::from_utf8_lossy(bad));
        }
    }

    // 스펙 4절 표식 경로 시험과 같은 목록: symlink, 권한 0644, 링크 수 2, 큰 파일, 옛 형식, 남이 쓸 수 있는 상태 뿌리.
    // 이것을 실패시키는 것: O_NOFOLLOW·일반 파일·0600·링크 수·크기·형식·상태 뿌리 규칙 중 하나라도 빼는 것.
    #[test]
    fn the_record_is_read_like_a_state_file() {
        let me = sys::current_uid();
        let state = scratch("read");
        // 이것을 실패시키는 것: 상태 뿌리에도 런타임의 0700 제약을 요구하는 것.
        std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o755)).unwrap();
        let at = state.join(RECORD_NAME);
        assert_eq!(
            read(&state, me, &mut RefuseGroupWrite),
            Err(RecordError::Absent)
        );
        write(&state, me, &mut RefuseGroupWrite, &rec()).unwrap();
        assert_eq!(read(&state, me, &mut RefuseGroupWrite), Ok(rec()));
        // 이것을 실패시키는 것: 기록 파일의 소유자가 읽는 사용자와 달라도 허용하는 것.
        assert_eq!(
            check_record(&std::fs::File::open(&at).unwrap(), me.wrapping_add(1)),
            Err(RecordError::Owner)
        );
        std::fs::set_permissions(&at, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(
            read(&state, me, &mut RefuseGroupWrite),
            Err(RecordError::Mode(0o644))
        );
        std::fs::set_permissions(&at, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::hard_link(&at, state.join("second")).unwrap();
        assert_eq!(
            read(&state, me, &mut RefuseGroupWrite),
            Err(RecordError::Links(2))
        );
        std::fs::remove_file(state.join("second")).unwrap();
        std::fs::write(state.join("big"), vec![b'x'; RECORD_MAX as usize + 1]).unwrap();
        std::fs::set_permissions(state.join("big"), std::fs::Permissions::from_mode(0o600))
            .unwrap();
        std::fs::rename(state.join("big"), &at).unwrap();
        assert_eq!(
            read(&state, me, &mut RefuseGroupWrite),
            Err(RecordError::TooBig(RECORD_MAX + 1))
        );
        std::fs::write(&at, b"bingsu-config-use 0\n1 2\n/x").unwrap();
        assert_eq!(
            read(&state, me, &mut RefuseGroupWrite),
            Err(RecordError::Format)
        );
        std::fs::remove_file(&at).unwrap();
        std::fs::create_dir(&at).unwrap();
        assert_eq!(
            read(&state, me, &mut RefuseGroupWrite),
            Err(RecordError::NotAFile)
        );
        std::fs::remove_dir(&at).unwrap();
        let elsewhere = state.join("real");
        std::fs::write(&elsewhere, encode(&rec())).unwrap();
        std::fs::set_permissions(&elsewhere, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::os::unix::fs::symlink(&elsewhere, &at).unwrap();
        assert_eq!(
            read(&state, me, &mut RefuseGroupWrite),
            Err(RecordError::NotAFile)
        );
        std::fs::remove_file(&at).unwrap();
        write(&state, me, &mut RefuseGroupWrite, &rec()).unwrap();
        std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o757)).unwrap();
        assert!(matches!(
            read(&state, me, &mut RefuseGroupWrite),
            Err(RecordError::StateRoot(_))
        ));
        std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::remove_dir_all(&state).unwrap();
    }
    #[cfg(target_os = "macos")]
    // 이것을 실패시키는 것: 읽는 기록 또는 쓰기 완료 fd의 ACL 검사를 빼는 것.
    #[test]
    fn record_acl_is_checked_on_read_and_completed_write_fd() {
        let state = scratch("acl-fd");
        let me = sys::current_uid();
        write(&state, me, &mut RefuseGroupWrite, &rec()).unwrap();
        let at = state.join(RECORD_NAME);
        let status = std::process::Command::new("chmod")
            .args(["+a", "everyone allow write,append"])
            .arg(&at)
            .status()
            .unwrap();
        assert!(status.success());
        assert_eq!(
            read(&state, me, &mut RefuseGroupWrite),
            Err(RecordError::Acl)
        );
        // The write-side validation is the same function applied to the
        // completed temporary fd; mode 0600 alone must never be enough.
        let fd = std::fs::OpenOptions::new().write(true).open(&at).unwrap();
        assert!(validate_completed_record(&fd, me).is_err());
        assert!(
            std::process::Command::new("chmod")
                .arg("-N")
                .arg(&at)
                .status()
                .unwrap()
                .success()
        );
        assert_eq!(read(&state, me, &mut RefuseGroupWrite), Ok(rec()));
        std::fs::remove_dir_all(state).unwrap();
    }
    // 이것을 실패시키는 것: 소유권 집행 미확인·비활성 기록을 허용하는 것.
    #[test]
    fn record_permissions_require_enforced_ownership() {
        let mut facts = Facts {
            dev: 1,
            ino: 2,
            uid: 501,
            gid: 501,
            mode: 0o100600,
            acl: AclFacts::None,
            ownership: Some(true),
        };
        assert!(record_permissions(facts).is_ok());
        for ownership in [None, Some(false)] {
            facts.ownership = ownership;
            assert_eq!(record_permissions(facts), Err(RecordError::Ownership));
        }
    }

    // 이것을 실패시키는 것: 쓸 수 없는 형식·크기의 기록으로 기존 승인을 덮어쓰는 것.
    #[test]
    fn invalid_writes_leave_the_previous_record_intact() {
        let state = scratch("invalid-write");
        let me = sys::current_uid();
        write(&state, me, &mut RefuseGroupWrite, &rec()).unwrap();
        for path in [
            PathBuf::from("relative"),
            PathBuf::from(format!("/{}", "x".repeat(RECORD_MAX as usize))),
        ] {
            let invalid = Record { path, ..rec() };
            assert!(write(&state, me, &mut RefuseGroupWrite, &invalid).is_err());
            assert_eq!(read(&state, me, &mut RefuseGroupWrite), Ok(rec()));
        }
        let big = state.join("big-completed");
        std::fs::write(&big, vec![b'x'; RECORD_MAX as usize + 1]).unwrap();
        std::fs::set_permissions(&big, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(validate_completed_record(&std::fs::File::open(big).unwrap(), me).is_err());
        std::fs::remove_dir_all(state).unwrap();
    }
}
