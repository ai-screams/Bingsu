//! Helper-owned immutable responses. The worker receives only a read-only,
//! close-only duplicate of the acquired open file description.
use super::{
    collection_gc,
    snapshot_store::{self, CheckedContextFd, StoreError},
    sys,
};
use bingsu_core::{
    collection::{
        response::Completed,
        wire::{Binding, STREAM_MAX},
    },
    field::SegmentDecl,
    snapshot::Clock,
};
use std::{
    ffi::OsStr,
    fs::File,
    io::{self, Read},
    os::fd::AsFd,
};

pub(crate) const RESPONSE: &str = "response";
pub(crate) const PREVIOUS: &str = "previous";
pub(crate) const STAGE: &str = ".response.stage";
pub(crate) const LOCK: &str = "collection.lock";
pub(crate) const LEGACY_REQUEST: &str = ".stage-request";
pub(crate) const FILES: [&str; 5] = [RESPONSE, PREVIOUS, STAGE, LEGACY_REQUEST, LOCK];

#[allow(
    clippy::large_enum_variant,
    reason = "admission transfers the owned store without a second allocation"
)]
pub(crate) enum Admission {
    Admitted(CollectionStore),
    Deferred(collection_gc::GcStop),
}
#[cfg(test)]
impl Admission {
    fn into_store(self) -> Result<CollectionStore, StoreError> {
        match self {
            Self::Admitted(store) => Ok(store),
            Self::Deferred(_) => Err(StoreError::Busy),
        }
    }
}

pub(crate) struct CollectionStore {
    chain: Vec<File>,
    names: [String; 3],
    lock: File,
    binding: Binding,
    catalog: &'static [SegmentDecl],
    me: u32,
    pub(crate) lock_acquired: Option<u64>,
    pub(crate) response_renamed: std::sync::Arc<std::sync::atomic::AtomicU64>,
}
impl CollectionStore {
    pub(crate) fn admit(
        context: &CheckedContextFd,
        binding: &Binding,
        now: Clock,
    ) -> Result<Admission, StoreError> {
        Self::admit_inner(
            context,
            binding,
            now,
            bingsu_core::field::BUILTIN,
            None,
            || collection_gc::GcBudget::default().start(),
            &mut |_| {},
        )
    }
    #[cfg(test)]
    #[allow(dead_code, reason = "native collection_store integration target")]
    pub(crate) fn fixture(
        context: &CheckedContextFd,
        binding: &Binding,
        now: Clock,
        catalog: &'static [SegmentDecl],
        address: Option<String>,
    ) -> Result<Self, StoreError> {
        Self::admit_inner(
            context,
            binding,
            now,
            catalog,
            address,
            Self::fixture_inventory_meter,
            &mut |_| {},
        )?
        .into_store()
    }
    #[cfg(test)]
    #[allow(dead_code, reason = "native admission race fixture")]
    pub(crate) fn fixture_admission_hook(
        context: &CheckedContextFd,
        binding: &Binding,
        now: Clock,
        catalog: &'static [SegmentDecl],
        hook: &mut dyn FnMut(&str),
    ) -> Result<Self, StoreError> {
        Self::admit_inner(
            context,
            binding,
            now,
            catalog,
            None,
            Self::fixture_inventory_meter,
            hook,
        )?
        .into_store()
    }
    #[cfg(test)]
    fn fixture_inventory_meter() -> sys::CollectionMeter {
        // Functional admission checks share the production operation budget,
        // without depending on how long the test thread is descheduled.
        sys::CollectionMeter::fixture_operations(collection_gc::GcBudget::default().max_ops)
    }
    #[cfg(test)]
    #[allow(dead_code, reason = "native collection_store integration target")]
    pub(crate) fn fixture_admit(
        context: &CheckedContextFd,
        binding: &Binding,
        now: Clock,
        catalog: &'static [SegmentDecl],
        budget: collection_gc::GcBudget,
        clock: Option<fn() -> u64>,
    ) -> Result<Admission, StoreError> {
        Self::admit_inner(
            context,
            binding,
            now,
            catalog,
            None,
            || match clock {
                Some(clock) => {
                    sys::CollectionMeter::fixture_clock(budget.max_ops, budget.max_ns, clock)
                }
                None => sys::CollectionMeter::fixture_operations(budget.max_ops),
            },
            &mut |_| {},
        )
    }
    fn admit_inner(
        context: &CheckedContextFd,
        binding: &Binding,
        now: Clock,
        catalog: &'static [SegmentDecl],
        address: Option<String>,
        start_inventory_meter: impl FnOnce() -> sys::CollectionMeter,
        hook: &mut dyn FnMut(&str),
    ) -> Result<Admission, StoreError> {
        let result = Self::admit_work(
            context,
            binding,
            now,
            catalog,
            address,
            start_inventory_meter,
            hook,
        );
        match result {
            Err(StoreError::Busy) => Ok(Admission::Deferred(collection_gc::GcStop::Busy)),
            other => other,
        }
    }
    fn admit_work(
        context: &CheckedContextFd,
        binding: &Binding,
        now: Clock,
        catalog: &'static [SegmentDecl],
        address: Option<String>,
        start_inventory_meter: impl FnOnce() -> sys::CollectionMeter,
        hook: &mut dyn FnMut(&str),
    ) -> Result<Admission, StoreError> {
        // Encoding validates all raw paths and the context CRC before any mkdir.
        let probe = Completed {
            progress: Default::default(),
            request_id: bingsu_core::collection::wire::M3B_REQUEST_ID,
            binding: binding.clone(),
            completed_at_ns: now.now,
            reason: bingsu_core::collection::wire::EndReason::WorkerExit,
            updates: vec![],
        };
        probe
            .encode_with_catalog(catalog)
            .map_err(|_| StoreError::Unsafe)?;
        if context.config != binding.config
            || context.state != binding.state
            || now.boot != binding.snapshot.boot
            || now.kind != binding.clock_kind
            || now.domain != binding.domain
            || now.resume != binding.resume
        {
            return Err(StoreError::Unsafe);
        }
        let me = sys::current_uid();
        let mut names = binding.components();
        if let Some(address) = address {
            names[1] = address;
        }
        // This lock order also covers the gap before the collection flock.
        let mut registration = match collection_gc::Registration::open(
            &context.runtime,
            me,
            now,
            catalog,
            start_inventory_meter,
        )? {
            Ok(registration) => registration,
            Err(stop) => return Ok(Admission::Deferred(stop)),
        };
        registration.reserve(context, binding, &names[1], now)?;
        hook("reserved_before_mkdir");
        let mut chain = vec![context.dir.try_clone()?];
        let mut created = 0;
        for name in &names {
            let parent = chain.last().unwrap();
            created += u64::from(sys::mkdir_at(parent.as_fd(), OsStr::new(name), 0o700)?);
            let child = sys::open_dir_at_nofollow(parent.as_fd(), OsStr::new(name))?;
            snapshot_store::check_directory(&child, me)?;
            snapshot_store::same_name(&child, parent.as_fd(), name)?;
            chain.push(child);
        }
        let dir = chain.last().unwrap();
        let lock = close_only_lock(dir, LOCK, me, true)?;
        let lock_acquired = super::collector_process::now_ns().ok();
        registration.attach(dir, created)?;
        let store = Self {
            chain,
            names,
            lock,
            binding: binding.clone(),
            catalog,
            me,
            lock_acquired,
            response_renamed: std::sync::Arc::default(),
        };
        store.verify()?;
        // Check raw cwd even when a catalog entry points to the right hash.
        for name in [RESPONSE, PREVIOUS] {
            store.read_response(name)?;
        }
        store.recover_stage()?;
        Ok(Admission::Admitted(store))
    }
    pub(crate) fn worker_lock(&self) -> io::Result<File> {
        self.lock.try_clone()
    }
    fn dir(&self) -> &File {
        self.chain.last().unwrap()
    }
    fn verify(&self) -> Result<(), StoreError> {
        for (i, name) in self.names.iter().enumerate() {
            snapshot_store::check_directory(&self.chain[i], self.me)?;
            snapshot_store::check_directory(&self.chain[i + 1], self.me)?;
            snapshot_store::same_name(&self.chain[i + 1], self.chain[i].as_fd(), name)?;
        }
        snapshot_store::check_data(&self.lock, 0, self.me)?;
        snapshot_store::same_name(&self.lock, self.dir().as_fd(), LOCK)
    }
    fn read_response(
        &self,
        name: &str,
    ) -> Result<Option<(File, Completed, sys::Stamp)>, StoreError> {
        let Some((file, bytes)) = read_checked(self.dir(), name, STREAM_MAX, self.me)? else {
            return Ok(None);
        };
        let Ok(completed) = Completed::decode_with_catalog(&bytes, self.catalog) else {
            // Only content damage is absence. read_checked already enforced
            // safe metadata and immutable fd/name identity; we retain the lock.
            snapshot_store::same_name(&file, self.dir().as_fd(), name)?;
            sys::unlink_at(self.dir().as_fd(), OsStr::new(name))?;
            return Ok(None);
        };
        if completed.binding.config != self.binding.config
            || completed.binding.state != self.binding.state
            || completed.binding.cwd != self.binding.cwd
        {
            return Err(StoreError::Busy);
        }
        let stamp = sys::file_stamp(&file)?;
        Ok(Some((file, completed, stamp)))
    }
    fn recover_stage(&self) -> Result<(), StoreError> {
        self.verify()?;
        remove_checked(self.dir(), STAGE, STREAM_MAX, self.me)?;
        remove_checked(self.dir(), LEGACY_REQUEST, STREAM_MAX, self.me)?;
        Ok(())
    }
    pub(crate) fn publish(&mut self, result: &Completed) -> Result<(), StoreError> {
        self.publish_inner(result, &mut |_| {})
    }
    #[cfg(test)]
    #[allow(dead_code, reason = "native collection_store integration target")]
    pub(crate) fn publish_with_hook(
        &mut self,
        result: &Completed,
        hook: &mut dyn FnMut(&str),
    ) -> Result<(), StoreError> {
        self.publish_inner(result, hook)
    }
    fn publish_inner(
        &mut self,
        result: &Completed,
        hook: &mut dyn FnMut(&str),
    ) -> Result<(), StoreError> {
        if !result.binding.matches(&self.binding) {
            return Err(StoreError::Unsafe);
        }
        self.verify()?;
        let current = self.read_response(RESPONSE)?;
        let previous = self.read_response(PREVIOUS)?;
        self.recover_stage()?;
        let bytes = result
            .encode_with_catalog(self.catalog)
            .map_err(|_| StoreError::Unsafe)?;
        let staged = snapshot_store::stage_verified(
            self.dir(),
            self.me,
            STAGE,
            &bytes,
            STREAM_MAX,
            &mut |actual| {
                let decoded = Completed::decode_with_catalog(actual, self.catalog)
                    .map_err(|_| StoreError::Unsafe)?;
                if decoded != *result {
                    return Err(StoreError::Unsafe);
                }
                Ok(())
            },
            hook,
        )?;
        self.verify()?;
        staged.verify(self.dir(), self.me, STAGE, STREAM_MAX)?;
        hook("before_rotate");
        staged.verify(self.dir(), self.me, STAGE, STREAM_MAX)?;
        for (name, record) in [(RESPONSE, &current), (PREVIOUS, &previous)] {
            match record {
                Some((file, _, stamp)) => {
                    if sys::file_stamp(file)? != *stamp {
                        return Err(StoreError::Unsafe);
                    }
                    snapshot_store::check_data(file, STREAM_MAX, self.me)?;
                    snapshot_store::same_name(file, self.dir().as_fd(), name)?;
                }
                None if sys::at_stamp(self.dir().as_fd(), OsStr::new(name))
                    .is_err_and(|e| e.kind() == io::ErrorKind::NotFound) => {}
                None => return Err(StoreError::Unsafe),
            }
        }
        if current.is_some() {
            sys::rename_at(
                self.dir().as_fd(),
                OsStr::new(RESPONSE),
                OsStr::new(PREVIOUS),
            )?;
        }
        hook("after_rotate");
        self.verify()?;
        hook("before_install");
        staged.install(self.dir(), self.me, STAGE, RESPONSE, STREAM_MAX)?;
        if let Ok(now) = super::collector_process::now_ns() {
            self.response_renamed
                .store(now, std::sync::atomic::Ordering::Release);
        }
        hook("after_install");
        Ok(())
    }
}
// Deliberately no Drop unlock. The supervisor retains its duplicate until both
// publication and reap, or its existing absolute helper deadline.
pub(crate) fn close_only_lock(
    dir: &File,
    name: &str,
    me: u32,
    create: bool,
) -> Result<File, StoreError> {
    if create {
        drop(sys::open_lock_at(dir.as_fd(), OsStr::new(name))?);
    }
    let file = sys::open_data_at_nofollow(dir.as_fd(), OsStr::new(name))?;
    snapshot_store::check_data(&file, 0, me)?;
    snapshot_store::same_name(&file, dir.as_fd(), name)?;
    let lock = sys::try_lock(file)
        .map_err(snapshot_store::lock_error)?
        .into_inherited_file();
    snapshot_store::same_name(&lock, dir.as_fd(), name)?;
    Ok(lock)
}
pub(crate) fn read_checked(
    dir: &File,
    name: &str,
    cap: usize,
    me: u32,
) -> Result<Option<(File, Vec<u8>)>, StoreError> {
    let mut file = match sys::open_data_at_nofollow(dir.as_fd(), OsStr::new(name)) {
        Ok(file) => file,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    let before = sys::file_stamp(&file)?;
    let len = snapshot_store::check_data(&file, cap, me)?;
    let mut bytes = Vec::new();
    // The trusted metadata length caps allocation and reads. Header/declared
    // length errors belong to decoding, after all metadata/identity checks.
    bytes
        .try_reserve_exact(len)
        .map_err(|_| StoreError::Unsafe)?;
    bytes.resize(len, 0);
    bounded_read(&mut file, &mut bytes)?;
    snapshot_store::check_data(&file, cap, me)?;
    if before != sys::file_stamp(&file)? {
        return Err(StoreError::Unsafe);
    }
    snapshot_store::same_name(&file, dir.as_fd(), name)?;
    Ok(Some((file, bytes)))
}
pub(crate) fn remove_checked(
    dir: &File,
    name: &str,
    cap: usize,
    me: u32,
) -> Result<bool, StoreError> {
    let file = match sys::open_data_at_nofollow(dir.as_fd(), OsStr::new(name)) {
        Ok(file) => file,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(e.into()),
    };
    snapshot_store::check_data(&file, cap, me)?;
    snapshot_store::same_name(&file, dir.as_fd(), name)?;
    sys::unlink_at(dir.as_fd(), OsStr::new(name))?;
    Ok(true)
}

// Immutable names are read only to their checked length, without an EOF probe.
fn bounded_read(file: &mut File, mut bytes: &mut [u8]) -> Result<(), StoreError> {
    while !bytes.is_empty() {
        sys::collection_ops(1)?;
        let count = bytes.len().min(16_384);
        let n = file.read(&mut bytes[..count])?;
        if n == 0 {
            return Err(StoreError::Unsafe);
        }
        bytes = &mut bytes[n..];
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bingsu_core::fs_trust::{AclFacts, Facts};
    // 이것을 실패시키는 것: helper의 데이터 판정에서 owner·device·nlink·ACL·locality·ownership 중 하나를 허용하는 것.
    #[test]
    fn publication_metadata_verdict() {
        let facts = Facts {
            dev: 1,
            ino: 2,
            uid: 3,
            gid: 4,
            mode: 0o100600,
            acl: AclFacts::None,
            ownership: Some(true),
        };
        let verdict = |facts, regular, links, local| {
            snapshot_store::data_verdict(facts, regular, links, 1, STREAM_MAX, local, 3)
        };
        assert!(verdict(facts, true, 1, Some(true)).is_ok());
        assert!(
            snapshot_store::data_verdict(facts, true, 1, 262_145, STREAM_MAX, Some(true), 3)
                .is_err()
        );
        assert!(verdict(Facts { uid: 4, ..facts }, true, 1, Some(true)).is_err());
        assert!(verdict(facts, false, 1, Some(true)).is_err());
        assert!(verdict(facts, true, 2, Some(true)).is_err());
        assert!(
            verdict(
                Facts {
                    acl: AclFacts::Unknown,
                    ..facts
                },
                true,
                1,
                Some(true)
            )
            .is_err()
        );
        assert!(verdict(facts, true, 1, Some(false)).is_err());
        assert!(
            verdict(
                Facts {
                    ownership: None,
                    ..facts
                },
                true,
                1,
                Some(true)
            )
            .is_err()
        );
    }
}

/// A fixed, tiny namespace beside contexts-v2, outside collection accounting.
/// Never repairs an existing object in place: an unsafe/incomplete fixture
/// simply leaves the worker in StageAOnly. Concurrent creators may safely lose.
#[cfg(target_os = "macos")]
#[allow(
    unsafe_code,
    reason = "fixed private fixture linkat/symlinkat, helper only"
)]
pub(super) fn prepare_collector_probe(runtime: &File) -> Result<File, StoreError> {
    use std::{ffi::CStr, os::fd::AsRawFd, os::unix::fs::MetadataExt};
    let me = sys::current_uid();
    snapshot_store::check_directory(runtime, me)?;
    let directory = |parent: &File, name: &str| -> Result<File, StoreError> {
        sys::mkdir_at(parent.as_fd(), OsStr::new(name), 0o700)?;
        let child = sys::open_dir_at_nofollow(parent.as_fd(), OsStr::new(name))?;
        snapshot_store::check_directory(&child, me)?;
        snapshot_store::same_name(&child, parent.as_fd(), name)?;
        Ok(child)
    };
    let namespace = directory(runtime, "collector-probes-v1")?;
    let parent = directory(&namespace, "open-flags")?;
    let root = directory(&parent, "root")?;
    let _outside = directory(&parent, "outside")?;
    let dir = directory(&root, "dir")?;
    let data = |parent: &File, name: &str, bytes: &[u8]| -> Result<(), StoreError> {
        match sys::create_file_at(parent.as_fd(), OsStr::new(name), 0o600) {
            Ok(file) => {
                if sys::write_fd(file.as_raw_fd(), bytes) != sys::WriteOutcome::Done {
                    return Err(io::Error::other("probe sentinel write").into());
                }
            }
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e.into()),
        }
        Ok(())
    };
    data(&root, "value", b"inside")?;
    data(&dir, "file", b"inside")?;
    data(&root, "hard", b"linked")?;
    // SAFETY: held private directory, fixed single-component names; no follow.
    if unsafe {
        libc::linkat(
            root.as_raw_fd(),
            c"hard".as_ptr(),
            root.as_raw_fd(),
            c"hard2".as_ptr(),
            0,
        )
    } != 0
        && io::Error::last_os_error().kind() != io::ErrorKind::AlreadyExists
    {
        return Err(io::Error::last_os_error().into());
    }
    for (base, name, target) in [
        (&dir, c"inner", c"../value"),
        (&dir, c"up", c"../../outside"),
        (&root, c"linkdir", c"dir"),
        (&root, c"absolute", c"/"),
        (&root, c"escape", c"../outside"),
    ] {
        let (name, target): (&CStr, &CStr) = (name, target);
        // SAFETY: fixed bounded targets and held private parent; existing entries
        // are never overwritten and are checked below.
        if unsafe { libc::symlinkat(target.as_ptr(), base.as_raw_fd(), name.as_ptr()) } != 0
            && io::Error::last_os_error().kind() != io::ErrorKind::AlreadyExists
        {
            return Err(io::Error::last_os_error().into());
        }
        use std::os::unix::ffi::OsStrExt;
        if sys::read_link_at(base.as_fd(), OsStr::from_bytes(name.to_bytes()))?
            .as_os_str()
            .as_bytes()
            != target.to_bytes()
        {
            return Err(StoreError::Unsafe);
        }
    }
    // Fixed SHA-256 sentinels; total file contents + link targets are < 4 KiB.
    // Hash on the same no-follow fd after metadata validation, including nlink.
    for (base, name, expected, links) in [
        (&root, "value", b"inside".as_slice(), 1),
        (&dir, "file", b"inside".as_slice(), 1),
        (&root, "hard", b"linked".as_slice(), 2),
        (&root, "hard2", b"linked".as_slice(), 2),
    ] {
        let mut file = sys::open_data_at_nofollow(base.as_fd(), OsStr::new(name))?;
        let md = file.metadata()?;
        let facts = sys::fd_facts(file.as_fd())?;
        if !md.is_file()
            || md.uid() != me
            || md.mode() & 0o7777 != 0o600
            || md.nlink() != links
            || md.len() != expected.len() as u64
            || facts.acl != bingsu_core::fs_trust::AclFacts::None
            || sys::fd_is_local(file.as_raw_fd()) != Some(true)
        {
            return Err(StoreError::Unsafe);
        }
        let mut bytes = [0; 7];
        let n = file.read(&mut bytes)?;
        if bingsu_core::collection::cwd_hash::sha256(&bytes[..n])
            != bingsu_core::collection::cwd_hash::sha256(expected)
        {
            return Err(StoreError::Unsafe);
        }
        snapshot_store::same_name(&file, base.as_fd(), name)?;
    }
    for (child, base, name) in [
        (&namespace, runtime, "collector-probes-v1"),
        (&parent, &namespace, "open-flags"),
        (&root, &parent, "root"),
        (&dir, &root, "dir"),
    ] {
        snapshot_store::check_directory(child, me)?;
        snapshot_store::same_name(child, base.as_fd(), name)?;
    }
    Ok(root)
}

#[cfg(all(test, target_os = "macos"))]
mod probe_tests {
    use super::*;
    use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
    struct Cleanup(std::path::PathBuf);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    // 이것을 실패시키는 것: helper가 기존 symlink·불안전 부모·변조 sentinel을 고치거나 신뢰하는 것.
    #[test]
    fn probe_fixture_is_private_bounded_and_reusable() {
        let runtime = std::env::temp_dir().join(format!("b2-helper-probe-{}", std::process::id()));
        std::fs::create_dir(&runtime).unwrap();
        let _cleanup = Cleanup(runtime.clone());
        std::fs::set_permissions(&runtime, std::fs::Permissions::from_mode(0o700)).unwrap();
        let fd = File::open(&runtime).unwrap();
        let first = prepare_collector_probe(&fd).unwrap();
        let second = prepare_collector_probe(&fd).unwrap();
        assert_eq!(
            first.metadata().unwrap().ino(),
            second.metadata().unwrap().ino()
        );
        let root = runtime.join("collector-probes-v1/open-flags/root");
        let mut bytes = 0;
        for path in [
            "value",
            "dir/file",
            "hard",
            "hard2",
            "dir/inner",
            "dir/up",
            "linkdir",
            "absolute",
            "escape",
        ] {
            bytes += std::fs::symlink_metadata(root.join(path)).unwrap().len();
        }
        assert!(bytes <= 4096);
        assert!(!runtime.join("contexts-v2").exists());
        std::fs::write(root.join("value"), b"spoof!").unwrap();
        assert!(prepare_collector_probe(&fd).is_err());
        assert_eq!(std::fs::read(root.join("value")).unwrap(), b"spoof!");
        std::fs::write(root.join("value"), b"inside").unwrap();
        std::fs::remove_file(root.join("dir/inner")).unwrap();
        symlink("../hard", root.join("dir/inner")).unwrap();
        assert!(prepare_collector_probe(&fd).is_err());
        std::fs::remove_file(root.join("dir/inner")).unwrap();
        symlink("../value", root.join("dir/inner")).unwrap();
        std::fs::set_permissions(
            root.parent().unwrap(),
            std::fs::Permissions::from_mode(0o777),
        )
        .unwrap();
        assert!(prepare_collector_probe(&fd).is_err());
        std::fs::set_permissions(
            root.parent().unwrap(),
            std::fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        std::fs::remove_file(root.join("value")).unwrap();
        symlink("hard", root.join("value")).unwrap();
        assert!(prepare_collector_probe(&fd).is_err());
        std::fs::remove_dir_all(runtime).unwrap();
    }
}
