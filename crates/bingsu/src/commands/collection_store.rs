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

pub(crate) struct CollectionStore {
    chain: Vec<File>,
    names: [String; 3],
    lock: File,
    binding: Binding,
    catalog: &'static [SegmentDecl],
    me: u32,
}
impl CollectionStore {
    pub(crate) fn acquire(
        context: &CheckedContextFd,
        binding: &Binding,
        now: Clock,
    ) -> Result<Self, StoreError> {
        Self::acquire_inner(
            context,
            binding,
            now,
            bingsu_core::field::BUILTIN,
            None,
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
        Self::acquire_inner(context, binding, now, catalog, address, &mut |_| {})
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
        Self::acquire_inner(context, binding, now, catalog, None, hook)
    }
    fn acquire_inner(
        context: &CheckedContextFd,
        binding: &Binding,
        now: Clock,
        catalog: &'static [SegmentDecl],
        address: Option<String>,
        hook: &mut dyn FnMut(&str),
    ) -> Result<Self, StoreError> {
        // Encoding validates all raw paths and the context CRC before any mkdir.
        let probe = Completed {
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
        let mut registration = collection_gc::Registration::open(&context.runtime, me)?;
        registration.reserve(context, binding, &names[1], now)?;
        hook("reserved_before_mkdir");
        let mut chain = vec![context.dir.try_clone()?];
        for name in &names {
            let parent = chain.last().unwrap();
            sys::mkdir_at(parent.as_fd(), OsStr::new(name), 0o700)?;
            let child = sys::open_dir_at_nofollow(parent.as_fd(), OsStr::new(name))?;
            snapshot_store::check_directory(&child, me)?;
            snapshot_store::same_name(&child, parent.as_fd(), name)?;
            chain.push(child);
        }
        let dir = chain.last().unwrap();
        let lock = close_only_lock(dir, LOCK, me, true)?;
        registration.attach(dir)?;
        let store = Self {
            chain,
            names,
            lock,
            binding: binding.clone(),
            catalog,
            me,
        };
        store.verify()?;
        // Check raw cwd even when a catalog entry points to the right hash.
        for name in [RESPONSE, PREVIOUS] {
            store.read_response(name)?;
        }
        store.recover_stage()?;
        Ok(store)
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
        let completed =
            Completed::decode_with_catalog(&bytes, self.catalog).map_err(|_| StoreError::Unsafe)?;
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
    if matches!(name, RESPONSE | PREVIOUS) {
        let mut header = [0u8; bingsu_core::collection::response::HEADER];
        bounded_read(&mut file, &mut header)?;
        let declared = bingsu_core::collection::response::declared_len(&header)
            .map_err(|_| StoreError::Unsafe)?;
        if declared != len {
            return Err(StoreError::Unsafe);
        }
        bytes
            .try_reserve_exact(len)
            .map_err(|_| StoreError::Unsafe)?;
        bytes.extend_from_slice(&header);
    } else {
        bytes
            .try_reserve_exact(len)
            .map_err(|_| StoreError::Unsafe)?;
    }
    let prefix = bytes.len();
    bytes.resize(len, 0);
    bounded_read(&mut file, &mut bytes[prefix..])?;
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
