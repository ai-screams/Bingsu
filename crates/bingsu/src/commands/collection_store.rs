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

/// macOS-only fixture; Linux never calls this or needs a renameat2 fallback.
/// Every use verifies the files again; there is no cached capability result.
#[cfg(target_os = "macos")]
pub(super) fn prepare_collector_probe(runtime: &File) -> Result<File, StoreError> {
    collector_probe::prepare(runtime, &mut sys::write_fd, &mut |_| {})
}

#[cfg(target_os = "macos")]
#[allow(
    unsafe_code,
    reason = "helper-only fd-relative fixture creation and exclusive publication"
)]
mod collector_probe {
    use super::*;
    use std::{
        ffi::{CStr, CString, OsString},
        os::{
            fd::AsRawFd,
            unix::{ffi::OsStrExt, fs::MetadataExt},
        },
    };

    const FINAL: &str = "open-flags";
    // Includes live staging and quarantined entries, even after SIGKILL.
    pub(super) const MAX_RETIRED: usize = 4;
    const LINKS: [(&str, &CStr, &CStr); 5] = [
        ("dir", c"inner", c"../value"),
        ("dir", c"up", c"../../outside"),
        ("root", c"linkdir", c"dir"),
        ("root", c"absolute", c"/"),
        ("root", c"escape", c"../outside"),
    ];

    fn directory(parent: &File, name: &str) -> Result<File, StoreError> {
        let child = sys::open_dir_at_nofollow(parent.as_fd(), OsStr::new(name))?;
        snapshot_store::check_directory(&child, sys::current_uid())?;
        snapshot_store::same_name(&child, parent.as_fd(), name)?;
        Ok(child)
    }

    fn unique(prefix: &str) -> Result<String, StoreError> {
        let bytes = sys::random_bytes16().ok_or(StoreError::Unsafe)?;
        Ok(format!(".{prefix}-{:032x}", u128::from_ne_bytes(bytes)))
    }

    fn rename_exclusive(parent: &File, from: &str, to: &str) -> io::Result<()> {
        let from = CString::new(from)?;
        let to = CString::new(to)?;
        // SAFETY: held parent, terminated single-component names. RENAME_EXCL
        // is essential: a losing publisher must never replace the winner.
        if unsafe {
            libc::renameatx_np(
                parent.as_raw_fd(),
                from.as_ptr(),
                parent.as_raw_fd(),
                to.as_ptr(),
                libc::RENAME_EXCL,
            )
        } == 0
        {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    fn names(parent: &File, cap: usize) -> Result<Vec<OsString>, StoreError> {
        let mut cursor = sys::DirectoryCursor::open(parent.as_fd())?;
        let mut names = Vec::new();
        // Includes the two dot entries; do not enumerate an unbounded tree.
        for _ in 0..cap + 3 {
            match cursor.next()? {
                None => return Ok(names),
                Some(name) if name != "." && name != ".." => names.push(name),
                Some(_) => {}
            }
            if names.len() > cap {
                return Err(StoreError::Unsafe);
            }
        }
        Err(StoreError::Unsafe)
    }

    // Reclamation never follows symlinks or crosses devices. Refuse hostile
    // trees beyond 3 levels / 64 entries; they still occupy a bounded slot.
    fn remove(
        parent: &File,
        name: &OsStr,
        depth: usize,
        budget: &mut usize,
    ) -> Result<(), StoreError> {
        if *budget == 0 {
            return Err(StoreError::Unsafe);
        }
        *budget -= 1;
        let stamp = match sys::at_stamp(parent.as_fd(), name) {
            Ok(stamp) => stamp,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(e.into()),
        };
        if stamp.mode & u32::from(libc::S_IFMT) != u32::from(libc::S_IFDIR) {
            return Ok(sys::unlink_at(parent.as_fd(), name)?);
        }
        if depth == 0 {
            return Err(StoreError::Unsafe);
        }
        let child = sys::open_dir_at_nofollow(parent.as_fd(), name)?;
        let md = child.metadata()?;
        if md.uid() != sys::current_uid()
            || md.dev() != parent.metadata()?.dev()
            || md.ino() != stamp.ino
            || md.dev() != stamp.dev
        {
            return Err(StoreError::Unsafe);
        }
        for entry in names(&child, 16)? {
            remove(&child, &entry, depth - 1, budget)?;
        }
        if sys::at_stamp(parent.as_fd(), name)?.ino != md.ino() {
            return Err(StoreError::Unsafe);
        }
        Ok(sys::remove_dir_at(parent.as_fd(), name)?)
    }

    fn reclaim(namespace: &File) -> Result<usize, StoreError> {
        let mut retained = 0;
        for name in names(namespace, MAX_RETIRED + 1)? {
            if name == FINAL {
                continue;
            }
            if !name.as_bytes().starts_with(b".stage-") && !name.as_bytes().starts_with(b".aside-")
            {
                return Err(StoreError::Unsafe);
            }
            // A live builder keeps its directory flock until publication or
            // cleanup. The namespace lock closes the mkdir-to-flock window.
            let result = match sys::open_dir_at_nofollow(namespace.as_fd(), &name) {
                Ok(dir) => match sys::try_lock(dir) {
                    Ok(_guard) => remove(namespace, &name, 3, &mut 64),
                    // Any lock error means exclusivity was not established.
                    Err(_) => Err(StoreError::Busy),
                },
                Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
                // Unlink a quarantined non-directory without following it.
                // If open failed on a directory, unlink refuses it as well.
                Err(_) => sys::unlink_at(namespace.as_fd(), &name).map_err(StoreError::Io),
            };
            if result.is_err() {
                retained += 1;
            }
        }
        Ok(retained)
    }

    struct Stage<'a> {
        namespace: &'a File,
        name: String,
        dir: sys::FileLock,
    }
    impl Drop for Stage<'_> {
        fn drop(&mut self) {
            // Includes write/verification failures and losing RENAME_EXCL.
            // A killed helper's unlocked stage is reclaimed on the next call.
            let _ = remove(self.namespace, OsStr::new(&self.name), 3, &mut 64);
        }
    }

    pub(super) fn prepare(
        runtime: &File,
        write: &mut dyn FnMut(i32, &[u8]) -> sys::WriteOutcome,
        hook: &mut dyn FnMut(&str),
    ) -> Result<File, StoreError> {
        snapshot_store::check_directory(runtime, sys::current_uid())?;
        let namespace = match directory(runtime, "collector-probes-v1") {
            Err(StoreError::Io(e)) if e.kind() == io::ErrorKind::NotFound => {
                sys::mkdir_at(runtime.as_fd(), OsStr::new("collector-probes-v1"), 0o700)?;
                directory(runtime, "collector-probes-v1")?
            }
            result => result?,
        };
        // A separate OFD is required for each flock, including concurrent calls.
        let lock = || {
            sys::try_lock(sys::open_dir_at_nofollow(
                namespace.as_fd(),
                OsStr::new("."),
            )?)
            .map_err(snapshot_store::lock_error)
        };
        let guard = lock()?;
        let retained = reclaim(&namespace)?;
        if let Ok(root) = verify(&namespace, FINAL) {
            return Ok(root);
        }
        // Leave room for both the aside and the new stage before moving anything.
        let present = match sys::at_stamp(namespace.as_fd(), OsStr::new(FINAL)) {
            Ok(_) => true,
            Err(e) if e.kind() == io::ErrorKind::NotFound => false,
            Err(e) => return Err(e.into()),
        };
        if retained + usize::from(present) + 1 > MAX_RETIRED {
            return Err(StoreError::Busy);
        }
        snapshot_store::check_directory(&namespace, sys::current_uid())?;
        snapshot_store::same_name(&namespace, runtime.as_fd(), "collector-probes-v1")?;
        if present {
            let aside = unique("aside")?;
            rename_exclusive(&namespace, FINAL, &aside)?;
            hook("quarantined");
        }
        let name = unique("stage")?;
        if !sys::mkdir_at(namespace.as_fd(), OsStr::new(&name), 0o700)? {
            return Err(StoreError::Busy);
        }
        let dir =
            sys::try_lock(directory(&namespace, &name)?).map_err(snapshot_store::lock_error)?;
        let stage = Stage {
            namespace: &namespace,
            name,
            dir,
        };
        drop(guard);
        build(&stage.dir, write)?;
        verify(&namespace, &stage.name)?;
        hook("before_publish");
        let _guard = lock()?;
        snapshot_store::check_directory(&namespace, sys::current_uid())?;
        snapshot_store::same_name(&namespace, runtime.as_fd(), "collector-probes-v1")?;
        match rename_exclusive(&namespace, &stage.name, FINAL) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e.into()),
        }
        verify(&namespace, FINAL)
    }

    fn build(
        parent: &File,
        write: &mut dyn FnMut(i32, &[u8]) -> sys::WriteOutcome,
    ) -> Result<(), StoreError> {
        for name in ["root", "outside"] {
            sys::mkdir_at(parent.as_fd(), OsStr::new(name), 0o700)?;
        }
        let root = directory(parent, "root")?;
        sys::mkdir_at(root.as_fd(), OsStr::new("dir"), 0o700)?;
        let dir = directory(&root, "dir")?;
        for (base, name, bytes) in [
            (&root, "value", b"inside"),
            (&dir, "file", b"inside"),
            (&root, "hard", b"linked"),
        ] {
            let file = sys::create_file_at(base.as_fd(), OsStr::new(name), 0o600)?;
            if write(file.as_raw_fd(), bytes) != sys::WriteOutcome::Done {
                return Err(io::Error::other("probe sentinel write").into());
            }
        }
        // SAFETY: held private directory, fixed single-component names.
        if unsafe {
            libc::linkat(
                root.as_raw_fd(),
                c"hard".as_ptr(),
                root.as_raw_fd(),
                c"hard2".as_ptr(),
                0,
            )
        } != 0
        {
            return Err(io::Error::last_os_error().into());
        }
        for (base, name, target) in LINKS {
            let base = if base == "dir" { &dir } else { &root };
            // SAFETY: held private directory, fixed terminated names and targets.
            if unsafe { libc::symlinkat(target.as_ptr(), base.as_raw_fd(), name.as_ptr()) } != 0 {
                return Err(io::Error::last_os_error().into());
            }
        }
        Ok(())
    }

    fn verify(namespace: &File, name: &str) -> Result<File, StoreError> {
        let me = sys::current_uid();
        let parent = directory(namespace, name)?;
        let root = directory(&parent, "root")?;
        let _outside = directory(&parent, "outside")?;
        let dir = directory(&root, "dir")?;
        for (base, name, target) in LINKS {
            let base = if base == "dir" { &dir } else { &root };
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
            (&parent, namespace, name),
            (&root, &parent, "root"),
            (&dir, &root, "dir"),
        ] {
            snapshot_store::check_directory(child, me)?;
            snapshot_store::same_name(child, base.as_fd(), name)?;
        }
        Ok(root)
    }
}

#[cfg(all(test, target_os = "macos"))]
mod probe_tests {
    use super::*;
    use std::{
        fs,
        os::unix::fs::{MetadataExt, PermissionsExt, symlink},
        path::PathBuf,
    };

    struct Fixture(PathBuf);
    impl Fixture {
        fn new() -> Self {
            static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
            let path = std::env::temp_dir().join(format!(
                "b2-helper-probe-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
            Self(path)
        }
        fn fd(&self) -> File {
            File::open(&self.0).unwrap()
        }
        fn namespace(&self) -> PathBuf {
            self.0.join("collector-probes-v1")
        }
        fn root(&self) -> PathBuf {
            self.namespace().join("open-flags/root")
        }
        fn retired(&self) -> Vec<PathBuf> {
            fs::read_dir(self.namespace())
                .unwrap()
                .map(|e| e.unwrap().path())
                .filter(|p| p.file_name().unwrap() != "open-flags")
                .collect()
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    // 이것을 실패시키는 것: 검증된 fixture 재사용 대신 매번 교체하거나 불안전 부모를 허용하는 것.
    #[test]
    fn probe_fixture_is_private_bounded_and_reusable() {
        let f = Fixture::new();
        let first = prepare_collector_probe(&f.fd()).unwrap();
        let second = prepare_collector_probe(&f.fd()).unwrap();
        assert_eq!(
            first.metadata().unwrap().ino(),
            second.metadata().unwrap().ino()
        );
        let bytes: u64 = [
            "value",
            "dir/file",
            "hard",
            "hard2",
            "dir/inner",
            "dir/up",
            "linkdir",
            "absolute",
            "escape",
        ]
        .into_iter()
        .map(|p| fs::symlink_metadata(f.root().join(p)).unwrap().len())
        .sum();
        assert!(bytes <= 4096);
        assert!(!f.0.join("contexts-v2").exists());
        fs::set_permissions(f.namespace(), fs::Permissions::from_mode(0o777)).unwrap();
        assert!(prepare_collector_probe(&f.fd()).is_err());
        fs::set_permissions(f.namespace(), fs::Permissions::from_mode(0o700)).unwrap();
    }

    // 이것을 실패시키는 것: 쓰기/검증 실패 전에 최종 이름을 게시하거나 실패한 staging을 회수하지 않는 것.
    #[test]
    fn interrupted_probe_creation_recovers_on_next_call() {
        for fail_at in 0..3 {
            let f = Fixture::new();
            let mut count = 0;
            let mut write = |fd, bytes: &[u8]| {
                let current = count;
                count += 1;
                if current == fail_at {
                    sys::WriteOutcome::Failed
                } else {
                    sys::write_fd(fd, bytes)
                }
            };
            assert!(collector_probe::prepare(&f.fd(), &mut write, &mut |_| {}).is_err());
            assert!(!f.namespace().join("open-flags").exists());
            assert!(f.retired().is_empty());
            let recovered = prepare_collector_probe(&f.fd()).unwrap();
            assert_eq!(fs::read(f.root().join("value")).unwrap(), b"inside");
            assert_eq!(
                recovered.metadata().unwrap().ino(),
                fs::metadata(f.root()).unwrap().ino()
            );
        }
        let f = Fixture::new();
        // Even a writer reporting success must pass the same sentinel check
        // as a reused final fixture before the final name becomes visible.
        assert!(
            collector_probe::prepare(&f.fd(), &mut |_, _| sys::WriteOutcome::Done, &mut |_| {},)
                .is_err()
        );
        assert!(!f.namespace().join("open-flags").exists());
        prepare_collector_probe(&f.fd()).unwrap();
    }

    // 이것을 실패시키는 것: 경쟁 게시자가 승자의 inode를 덮어쓰거나 패자의 staging을 남기는 것.
    #[test]
    fn racing_probe_publisher_preserves_winner_and_removes_own_stage() {
        let f = Fixture::new();
        let mut winner = None;
        // Deterministically pause A after verification; B sees A's locked stage,
        // builds independently and publishes first. A must lose RENAME_EXCL.
        let root = collector_probe::prepare(&f.fd(), &mut sys::write_fd, &mut |event| {
            if event == "before_publish" {
                assert_eq!(f.retired().len(), 1);
                winner = Some(std::thread::scope(|scope| {
                    scope
                        .spawn(|| prepare_collector_probe(&f.fd()).unwrap())
                        .join()
                        .unwrap()
                }));
                assert_eq!(f.retired().len(), 1, "B must not reclaim A's live stage");
            }
        })
        .unwrap();
        assert_eq!(
            root.metadata().unwrap().ino(),
            winner.unwrap().metadata().unwrap().ino()
        );
        assert!(f.retired().is_empty());
    }

    // 이것을 실패시키는 것: 변조된 최종 namespace를 신뢰하거나 그 자리에서 sentinel을 고치는 것.
    #[test]
    fn tampered_probe_is_moved_aside_and_reclaimed() {
        let f = Fixture::new();
        let fd = f.fd();
        for tamper in 0..4 {
            let old_root = prepare_collector_probe(&fd).unwrap();
            match tamper {
                0 => fs::write(f.root().join("value"), b"spoof!").unwrap(),
                1 => {
                    fs::remove_file(f.root().join("dir/inner")).unwrap();
                    symlink("../hard", f.root().join("dir/inner")).unwrap();
                }
                2 => fs::set_permissions(
                    f.root().parent().unwrap(),
                    fs::Permissions::from_mode(0o777),
                )
                .unwrap(),
                _ => {
                    fs::remove_file(f.root().join("value")).unwrap();
                    symlink("hard", f.root().join("value")).unwrap();
                }
            }
            let old_inode = old_root.metadata().unwrap().ino();
            let mut quarantined = false;
            let fresh = collector_probe::prepare(&fd, &mut sys::write_fd, &mut |event| {
                if event == "quarantined" {
                    quarantined = true;
                    assert!(!f.namespace().join("open-flags").exists());
                    let aside = f.retired();
                    assert_eq!(aside.len(), 1);
                    assert_eq!(
                        fs::metadata(aside[0].join("root")).unwrap().ino(),
                        old_inode
                    );
                    if tamper == 0 {
                        assert_eq!(fs::read(aside[0].join("root/value")).unwrap(), b"spoof!");
                    }
                }
            })
            .unwrap();
            assert!(quarantined);
            assert_ne!(fresh.metadata().unwrap().ino(), old_inode);
            assert_eq!(fs::read(f.root().join("value")).unwrap(), b"inside");
            assert_eq!(f.retired().len(), 1);
            prepare_collector_probe(&fd).unwrap();
            assert!(f.retired().is_empty());
        }
    }

    // 이것을 실패시키는 것: 죽은 helper의 staging을 회수하지 않거나 격리 항목 상한을 무시하는 것.
    #[test]
    fn abandoned_stages_are_reclaimed_and_asides_are_bounded() {
        let f = Fixture::new();
        prepare_collector_probe(&f.fd()).unwrap();
        // On-disk state of a helper killed after create_file_at, before write.
        let stale = f.namespace().join(".stage-killed");
        fs::create_dir(&stale).unwrap();
        fs::create_dir(stale.join("root")).unwrap();
        fs::write(stale.join("root/value"), []).unwrap();
        let canary = f.0.join("canary");
        fs::create_dir(&canary).unwrap();
        fs::write(canary.join("value"), b"untouched").unwrap();
        symlink(&canary, stale.join("root/escape")).unwrap();
        prepare_collector_probe(&f.fd()).unwrap();
        assert!(!stale.exists());
        assert_eq!(fs::read(canary.join("value")).unwrap(), b"untouched");
        // Unreclaimable (over-depth) asides keep their slots.
        for i in 0..collector_probe::MAX_RETIRED {
            fs::create_dir_all(f.namespace().join(format!(".aside-{i}/a/b/c/d"))).unwrap();
        }
        fs::write(f.root().join("value"), b"spoof!").unwrap();
        assert!(matches!(
            prepare_collector_probe(&f.fd()),
            Err(StoreError::Busy)
        ));
        assert_eq!(f.retired().len(), collector_probe::MAX_RETIRED);
        assert_eq!(fs::read(f.root().join("value")).unwrap(), b"spoof!");
        fs::remove_dir_all(f.namespace().join(".aside-0")).unwrap();
        fs::remove_dir_all(f.namespace().join(".aside-1")).unwrap();
        prepare_collector_probe(&f.fd()).unwrap();
        assert_eq!(f.retired().len(), collector_probe::MAX_RETIRED - 1);
    }
}
