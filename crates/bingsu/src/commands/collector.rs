//! Verified dedicated executable and on-demand supervised collection.
use super::{snapshot_store::StoreError, sys};
#[cfg(test)]
use bingsu_core::fs_trust::RefuseGroupWrite;
use std::{
    ffi::OsStr,
    fs::File,
    os::fd::{AsFd, AsRawFd},
    os::unix::fs::MetadataExt,
};

/// Held evidence for the canonical dedicated executable. This does not select
/// a worker from PATH, nor authorize any configured command. C1 consumes it
/// immediately before spawning the dedicated worker.
pub struct PinnedCollector {
    path: std::path::PathBuf,
    chain: super::runtime_root::Chain,
    executable: File,
    stamp: sys::Stamp,
    facts: bingsu_core::fs_trust::Facts,
}
impl PinnedCollector {
    pub fn verify(
        exe: &OsStr,
        me: u32,
        groups: &mut dyn bingsu_core::fs_trust::GroupOracle,
    ) -> Result<Self, StoreError> {
        use bingsu_core::fs_trust::{Verdict, entry_verdict};
        let path = std::path::Path::new(exe);
        if path.file_name() != Some(OsStr::new("bingsu-collect")) {
            return Err(StoreError::Unsafe);
        }
        let parent = path.parent().ok_or(StoreError::Unsafe)?;
        let chain = super::runtime_root::open_chain(parent).map_err(StoreError::Root)?;
        for facts in &chain.facts {
            if entry_verdict(facts, me, false, groups) != Verdict::Safe {
                return Err(StoreError::Unsafe);
            }
        }
        let executable =
            sys::open_data_at_nofollow(chain.last().as_fd(), OsStr::new("bingsu-collect"))?;
        let facts = sys::fd_facts(executable.as_fd())?;
        if entry_verdict(&facts, me, false, groups) != Verdict::Safe {
            return Err(StoreError::Unsafe);
        }
        let md = executable.metadata()?;
        if !md.is_file()
            || !executable_mode(md.mode())
            || sys::fd_is_local(executable.as_raw_fd()) != Some(true)
        {
            return Err(StoreError::Unsafe);
        }
        verify_build(&executable)?;
        let pin = Self {
            path: path.to_path_buf(),
            chain,
            stamp: sys::file_stamp(&executable)?,
            executable,
            facts,
        };
        pin.executable()?;
        Ok(pin)
    }
    /// Recheck retained descriptors and parent/name bindings without a new
    /// executable lookup. Replaced parents or targets invalidate this handle.
    pub fn executable(&self) -> Result<&OsStr, StoreError> {
        self.chain.revalidate()?;
        if sys::file_stamp(&self.executable)? != self.stamp
            || sys::fd_facts(self.executable.as_fd())? != self.facts
            || sys::at_stamp(self.chain.last().as_fd(), OsStr::new("bingsu-collect"))? != self.stamp
        {
            return Err(StoreError::Unsafe);
        }
        Ok(self.path.as_os_str())
    }
}
fn executable_mode(mode: u32) -> bool {
    mode & 0o111 != 0 && mode & 0o6000 == 0
}
fn verify_build(file: &File) -> Result<(), StoreError> {
    use std::os::unix::fs::FileExt;
    let size = file.metadata()?.len();
    if size > 64 * 1024 * 1024 {
        return Err(StoreError::Unsafe);
    }
    let mut buffer = [0u8; 65_536];
    let expected = bingsu_collect::build_id();
    let mut found = 0;
    let mut roles = 0;
    let mut offset = 0;
    let mut overlap = 0;
    while offset < size {
        let n = file.read_at(&mut buffer[overlap..], offset)?;
        if n == 0 {
            return Err(StoreError::Unsafe);
        }
        let length = overlap + n;
        let end = if offset + n as u64 == size {
            length.saturating_sub(15)
        } else {
            length.saturating_sub(48)
        };
        for at in 0..end {
            let window = &buffer[at..length];
            if window[..16] == bingsu_collect::manifest_tag()[..16] {
                if window.get(16..48) != Some(expected.0.as_slice()) {
                    return Err(StoreError::Unsafe);
                }
                found += 1;
            }
            if window[..16] == std::hint::black_box(&super::ROLE_TAG)[..16] {
                if window.get(16) != Some(&bingsu_collect::COLLECTOR_ROLE)
                    || window.get(17..49) != Some(expected.0.as_slice())
                {
                    return Err(StoreError::Unsafe);
                }
                roles += 1;
            }
        }
        overlap = length - end;
        buffer.copy_within(length - overlap..length, 0);
        offset += n as u64;
    }
    if found != 1 || roles != 1 {
        return Err(StoreError::Unsafe);
    }
    Ok(())
}

/// The caller has already acquired a close-only, read-only collection lock.
pub fn spawn(
    exe: &PinnedCollector,
    request: bingsu_core::collection::wire::Request,
    lock: File,
    watchdog: &super::helper_limits::Watchdog,
) -> Result<super::collector_supervisor::CollectorJob, StoreError> {
    let started_ns = super::collector_process::now_ns()?;
    Ok(super::collector_supervisor::CollectorJob::new(
        exe.executable()?,
        request,
        lock,
        watchdog,
        started_ns,
    )?)
}

#[cfg(test)]
mod tests {
    use super::*;

    // 이것을 실패시키는 것: 실행 비트를 요구하지 않거나 setuid/setgid를 허용하는 것.
    #[test]
    fn collector_executable_mode_rejects_special_bits() {
        assert!(executable_mode(0o100700));
        for mode in [0o100600, 0o104700, 0o102700, 0o106700] {
            assert!(!executable_mode(mode), "mode {mode:o}");
        }
    }

    // 이것을 실패시키는 것: 고정 실행 파일의 manifest·권한·부모 교체 검사를 생략하는 것.
    #[test]
    fn collector_path_never_uses_prompt_environment() {
        use std::os::unix::fs::PermissionsExt;
        let base = std::env::current_dir()
            .unwrap()
            .join(format!("bingsu-worker-pin-{}", std::process::id()));
        std::fs::create_dir(&base).unwrap();
        let base = std::fs::canonicalize(base).unwrap();
        let directory = base.join("install");
        std::fs::create_dir(&directory).unwrap();
        let path = directory.join("bingsu-collect");
        let me = sys::current_uid();
        let check = || PinnedCollector::verify(path.as_os_str(), me, &mut RefuseGroupWrite);
        assert!(check().is_err());
        std::fs::write(&path, collector_fixture()).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        let pin = check().unwrap();
        assert_eq!(pin.executable().unwrap(), path.as_os_str());
        assert!(
            PinnedCollector::verify(
                directory.join("other").as_os_str(),
                me,
                &mut RefuseGroupWrite
            )
            .is_err()
        );
        // Some macOS hosts silently clear special bits on chmod. The pure
        // predicate above always covers them; Linux also checks actual files.
        let modes: &[u32] = if cfg!(target_os = "linux") {
            &[0o600, 0o4700, 0o2700]
        } else {
            &[0o600]
        };
        for &mode in modes {
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
            assert_eq!(std::fs::metadata(&path).unwrap().mode() & 0o7777, mode);
            assert!(check().is_err());
        }
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o702)).unwrap();
        assert!(check().is_err());
        assert!(pin.executable().is_err());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        let pin = check().unwrap();
        let old = base.join("old");
        std::fs::rename(&directory, &old).unwrap();
        std::fs::create_dir(&directory).unwrap();
        std::fs::copy(old.join("bingsu-collect"), &path).unwrap();
        assert!(pin.executable().is_err());
        assert!(check().is_ok());
        std::fs::remove_dir_all(base).unwrap();
    }

    fn collector_fixture() -> Vec<u8> {
        [
            bingsu_collect::manifest_tag().as_slice(),
            &bingsu_collect::role_tag(bingsu_collect::COLLECTOR_ROLE),
        ]
        .concat()
    }

    // 이것을 실패시키는 것: 실행 파일에 runtime-root의 sticky 예외를 적용하는 것.
    #[test]
    fn collector_refuses_sticky_ancestor() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = std::fs::canonicalize("/tmp").unwrap();
        let md = std::fs::metadata(&tmp).unwrap();
        assert_eq!((md.uid(), md.mode() & 0o1777), (0, 0o1777));
        let base = tmp.join(format!("bingsu-sticky-pin-{}", std::process::id()));
        std::fs::create_dir(&base).unwrap();
        std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = base.join("bingsu-collect");
        std::fs::write(&path, collector_fixture()).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        let result =
            PinnedCollector::verify(path.as_os_str(), sys::current_uid(), &mut RefuseGroupWrite);
        std::fs::remove_dir_all(base).unwrap();
        assert!(result.is_err());
    }

    // 이것을 실패시키는 것: 같은 wire 버전의 다른 build-id나 중복 tag를 받는 것.
    #[test]
    fn sibling_build_id_is_exact() {
        let path = std::env::temp_dir().join(format!("bingsu-worker-build-{}", std::process::id()));
        let valid = collector_fixture();
        for offset in (16..48).chain(64..97) {
            let mut bad = valid.clone();
            bad[offset] ^= 1;
            std::fs::write(&path, bad).unwrap();
            assert!(verify_build(&File::open(&path).unwrap()).is_err());
        }
        for bad in [
            bingsu_collect::manifest_tag().to_vec(),
            [
                valid.as_slice(),
                &bingsu_collect::role_tag(bingsu_collect::BINGSU_ROLE),
            ]
            .concat(),
            [
                valid.as_slice(),
                &bingsu_collect::role_tag(bingsu_collect::COLLECTOR_ROLE),
            ]
            .concat(),
            valid[..96].to_vec(),
        ] {
            std::fs::write(&path, bad).unwrap();
            assert!(verify_build(&File::open(&path).unwrap()).is_err());
        }
        for prefix in [0, 65_480, 65_520, 65_535, 65_536] {
            let mut bytes = vec![0; prefix];
            bytes.extend(&valid);
            std::fs::write(&path, &bytes).unwrap();
            assert!(verify_build(&File::open(&path).unwrap()).is_ok());
            bytes.extend(&valid);
            std::fs::write(&path, bytes).unwrap();
            assert!(verify_build(&File::open(&path).unwrap()).is_err());
        }
        std::fs::remove_file(path).unwrap();
    }
}
