//! The only filesystem port available to git parsers.
use crate::{
    meter::Meter,
    safe_read::{self, Access, Listing, ReadCap, ReadError, Root},
};
use bingsu_core::collection::budget::Axis;
use std::cell::{Cell, RefCell};

#[path = "index.rs"]
pub mod index;
#[path = "objects.rs"]
pub mod objects;
#[path = "policy.rs"]
pub mod policy;
#[path = "worktree.rs"]
pub mod worktree;

pub const UNSUPPORTED: ReadError = ReadError::Io(libc::ENOTSUP);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RootId {
    Worktree,
    GitDir,
    CommonDir,
}

pub struct RepoPath {
    pub root: RootId,
    pub relative: Vec<u8>,
}
impl RepoPath {
    pub fn new(root: RootId, relative: &[u8]) -> Self {
        Self {
            root,
            relative: relative.to_vec(),
        }
    }
}

/// Only capabilities, never paths. C5 validates repository shape, owner and
/// mount before constructing this bundle; identical roots may share a borrow.
pub struct RepoRoots<'a> {
    pub worktree: &'a Root,
    pub gitdir: &'a Root,
    pub commondir: &'a Root,
}

pub struct RepoIo<'a> {
    roots: RepoRoots<'a>,
    access: &'a Access,
    meter: &'a RefCell<Meter>,
    stopped: Cell<Option<ReadError>>,
    worktree_stats: RefCell<Option<safe_read::WorktreeStats>>,
}

/// Owned, immutable bounded-read backing for the bytes-only pack constructors.
/// We deliberately use the plan's Vec alternative: hostile truncation cannot
/// SIGBUS a file mapping. No file mmap is made (MappedBytes remains zero), and
/// the safe-read fd is closed before this snapshot can escape its checks.
#[derive(Debug)]
pub struct ReadMap(Vec<u8>);

/// Fuzz and seed replay only: the bytes a bounded map would have returned.
/// collector_fuzz is set by fuzz/collector's build script, never a feature.
#[cfg(any(test, collector_fuzz))]
impl ReadMap {
    pub(crate) fn fuzz_bytes(bytes: &[u8]) -> Self {
        Self(bytes.to_vec())
    }
}

pub(crate) struct WorktreeEntry {
    pub name: std::ops::Range<usize>,
    pub metadata: Result<libc::stat, ReadError>,
}
pub(crate) struct WorktreeListing {
    pub entries: Vec<WorktreeEntry>,
    pub names: Vec<u8>,
    pub more: bool,
    _allocation: crate::meter::PathAllocation,
}

/// Grow bounded scratch before writing it. Charge the new capacity while the
/// old buffer is still live during reallocation; retain only the final capacity.
pub(super) fn reserve_scratch<T>(
    buffer: &mut Vec<T>,
    additional: usize,
    allocation: &mut crate::meter::PathAllocation,
    meter: &mut Meter,
) -> Result<(), ReadError> {
    let needed = buffer
        .len()
        .checked_add(additional)
        .ok_or(ReadError::Limit)?;
    if needed > buffer.capacity() {
        let extra = (needed - buffer.capacity()).max(buffer.capacity().max(16));
        let bytes = extra
            .checked_mul(std::mem::size_of::<T>())
            .ok_or(ReadError::Limit)?;
        allocation.reserve(bytes, meter)?;
        let mut growth = meter.path_allocation();
        growth.reserve(buffer.capacity() * std::mem::size_of::<T>(), meter)?;
        buffer
            .try_reserve_exact(buffer.capacity() + extra - buffer.len())
            .map_err(|_| ReadError::Limit)?;
    }
    Ok(())
}
impl std::ops::Deref for ReadMap {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.0
    }
}

// Move the ONE meter out for a syscall sequence, releasing the RefCell borrow.
// The expired placeholder rejects reentry, including from test callbacks.
// Unwinding restores the real counters/deadline/leases, just like normal return.
struct MeterLoan<'a> {
    slot: &'a RefCell<Meter>,
    value: Option<Meter>,
}
impl Drop for MeterLoan<'_> {
    fn drop(&mut self) {
        self.slot.replace(self.value.take().expect("owned meter"));
    }
}

impl<'a> RepoIo<'a> {
    pub fn new(roots: RepoRoots<'a>, access: &'a Access, meter: &'a RefCell<Meter>) -> Self {
        Self {
            roots,
            access,
            meter,
            stopped: Cell::new(None),
            worktree_stats: RefCell::new(None),
        }
    }

    /// Only at a stage boundary: a B-local Limit/Deadline must not suppress
    /// independent C/D work. All counters, live allocations and the absolute
    /// request deadline stay in the SAME meter; exhausted shared axes still fail.
    pub(crate) fn next_stage(&self) -> Self {
        Self::new(
            RepoRoots {
                worktree: self.roots.worktree,
                gitdir: self.roots.gitdir,
                commondir: self.roots.commondir,
            },
            self.access,
            self.meter,
        )
    }

    fn root(&self, id: RootId) -> &Root {
        match id {
            RootId::Worktree => self.roots.worktree,
            RootId::GitDir => self.roots.gitdir,
            RootId::CommonDir => self.roots.commondir,
        }
    }

    /// Pure accounting/parser work does not loan the meter across a syscall or
    /// callback. Avoid copying a request-sized sentinel for every index entry.
    pub(crate) fn account<T>(
        &self,
        operation: impl FnOnce(&mut Meter) -> Result<T, ReadError>,
    ) -> Result<T, ReadError> {
        if let Some(error) = self.stopped.get() {
            return Err(error);
        }
        let mut meter = self.meter.try_borrow_mut().map_err(|_| ReadError::Denied)?;
        meter.check()?;
        let result = operation(&mut meter);
        if let Err(error @ (ReadError::Limit | ReadError::Deadline)) = result {
            self.stopped.set(Some(error));
        }
        result
    }

    pub(crate) fn metered<T>(
        &self,
        operation: impl FnOnce(&mut Meter) -> Result<T, ReadError>,
    ) -> Result<T, ReadError> {
        if let Some(error) = self.stopped.get() {
            return Err(error);
        }
        self.loan_meter(operation)
    }

    fn loan_meter<T>(
        &self,
        operation: impl FnOnce(&mut Meter) -> Result<T, ReadError>,
    ) -> Result<T, ReadError> {
        let value = {
            let mut slot = self.meter.try_borrow_mut().map_err(|_| ReadError::Denied)?;
            slot.check()?;
            let placeholder = slot.expired_placeholder();
            std::mem::replace(&mut *slot, placeholder)
        };
        let mut loan = MeterLoan {
            slot: self.meter,
            value: Some(value),
        };
        let result = operation(loan.value.as_mut().expect("owned meter"));
        if let Err(error @ (ReadError::Limit | ReadError::Deadline)) = result {
            self.stopped.set(Some(error));
        }
        result
    }

    pub fn read(&self, path: RepoPath, cap: ReadCap) -> Result<Vec<u8>, ReadError> {
        if path.root != RootId::Worktree {
            return self.read_sized_with_cap(path, cap, None, None);
        }
        self.metered(|meter| {
            safe_read::read(
                self.root(path.root),
                &path.relative,
                cap,
                self.access,
                meter,
            )
        })
    }

    /// Reserve the inspected size before reading from that same fd. Growth is
    /// an error (cap+1 probe), never an uncharged extension of the reservation.
    pub(super) fn read_ref(&self, path: RepoPath, cap: u64) -> Result<Vec<u8>, ReadError> {
        self.read_ref_stat(path, cap).map(|(bytes, _)| bytes)
    }

    /// `read_ref` plus the same fd's metadata, so a caller can later tell
    /// whether the path still names the file these bytes came from.
    pub(super) fn read_ref_stat(
        &self,
        path: RepoPath,
        cap: u64,
    ) -> Result<(Vec<u8>, libc::stat), ReadError> {
        self.metered(|meter| {
            // Exhaustion forbids even another path lookup.
            if meter.budget.used(Axis::RefBytes) == Axis::RefBytes.limit() {
                return Err(ReadError::Limit);
            }
            let file =
                safe_read::resolve_with(self.root(path.root), &path.relative, self.access, meter)?;
            let metadata = file.metadata();
            let size = u64::try_from(metadata.st_size).map_err(|_| ReadError::Limit)?;
            if size > cap {
                return Err(ReadError::Limit);
            }
            meter.charge_axis(Axis::RefBytes, size)?;
            file.read_metadata(cap, meter)
                .map(|bytes| (bytes, metadata))
        })
    }

    /// A same-fd regular-file snapshot, not ambient stat or a worktree lstat.
    /// C4 supplies the no-follow worktree-stat operation separately.
    pub fn metadata(&self, path: RepoPath) -> Result<libc::stat, ReadError> {
        self.metered(|meter| {
            Ok(
                safe_read::resolve_with(self.root(path.root), &path.relative, self.access, meter)?
                    .metadata(),
            )
        })
    }

    pub(super) fn has_entry(&self, path: RepoPath) -> Result<bool, ReadError> {
        self.metered(|meter| {
            safe_read::has_entry(self.root(path.root), &path.relative, self.access, meter)
        })
    }

    pub fn worktree_metadata(&self, relative: &[u8]) -> Result<libc::stat, ReadError> {
        self.metered(|meter| {
            let mut scan = self
                .worktree_stats
                .try_borrow_mut()
                .map_err(|_| ReadError::Denied)?;
            if let Some(scan) = scan.as_mut() {
                return scan.metadata(self.roots.worktree, relative, self.access, meter);
            }
            safe_read::worktree_metadata(self.roots.worktree, relative, self.access, meter)
        })
    }

    /// One bounded batch of the shared tracked/untracked listing. The caller
    /// drops its scratch before requesting the next batch on the same OFD.
    pub(crate) fn worktree_listing(
        &self,
        parent: &[u8],
        first: bool,
    ) -> Result<WorktreeListing, ReadError> {
        self.metered(|meter| {
            let mut cached = self
                .worktree_stats
                .try_borrow_mut()
                .map_err(|_| ReadError::Denied)?;
            let scan = cached.as_mut().ok_or(ReadError::Denied)?;
            let mut entries: Vec<WorktreeEntry> = Vec::new();
            let mut names = Vec::new();
            let mut allocation = meter.path_allocation();
            // The safe layer lends its meter only after raw-entry/stat charging.
            let more = scan.visit_batch(
                self.roots.worktree,
                parent,
                self.access,
                meter,
                first,
                |raw, metadata, m| {
                    reserve_scratch(&mut entries, 1, &mut allocation, m)?;
                    reserve_scratch(&mut names, raw.len(), &mut allocation, m)?;
                    let start = names.len();
                    names.extend_from_slice(raw);
                    entries.push(WorktreeEntry {
                        name: start..names.len(),
                        metadata: metadata.copied(),
                    });
                    Ok(())
                },
            )?;
            meter.check()?;
            Ok(WorktreeListing {
                entries,
                names,
                more,
                _allocation: allocation,
            })
        })
    }

    /// Inspect only the fixed marker in the directory just listed. The safe
    /// layer does not reopen the path, enumerate .git, or follow a gitfile.
    pub(crate) fn worktree_embedded_repository(&self) -> Result<bool, ReadError> {
        self.metered(|meter| {
            self.worktree_stats
                .try_borrow()
                .map_err(|_| ReadError::Denied)?
                .as_ref()
                .ok_or(ReadError::Denied)?
                .embedded_repository(self.access, meter)
        })
    }

    /// Reuse verified directory fds across an index-order loop. The callback's
    /// observations must not be published until this returns Ok: directory
    /// transitions and finalization revalidate each edge against its held parent.
    /// Errors and unwind discard the cache. Nested scans are not allowed.
    pub fn with_worktree_stats<T>(
        &self,
        scan: impl FnOnce() -> Result<T, ReadError>,
    ) -> Result<T, ReadError> {
        if self.worktree_stats.borrow().is_some() {
            return Err(ReadError::Denied);
        }
        struct Clear<'a>(&'a RefCell<Option<safe_read::WorktreeStats>>);
        impl Drop for Clear<'_> {
            fn drop(&mut self) {
                self.0.borrow_mut().take();
            }
        }
        let _clear = Clear(&self.worktree_stats);
        self.worktree_stats
            .replace(Some(safe_read::WorktreeStats::default()));
        let result = scan()?;
        let mut stats = self
            .worktree_stats
            .borrow_mut()
            .take()
            .expect("active scan");
        // A caller may return a bounded partial result after Limit. Only the
        // held-edge finalizer may run past the stop latch: it performs no new
        // open/list/read/map and still charges the same stat/op/deadline budget.
        // Failure here invalidates even a proposed lower bound.
        self.loan_meter(|meter| stats.finish(self.roots.worktree, self.access, meter))?;
        Ok(result)
    }

    /// Batch stat for one sorted index directory. macOS uses getattrlistbulk;
    /// Linux keeps one fstatat per leaf. See worktree::directory_stats for the
    /// provisional-callback contract. Single-leaf worktree_metadata/compare
    /// retain fstatat on both systems; bulk failures never fall back to it.
    pub fn worktree_directory_stats(
        &self,
        parent: &[u8],
        leaves: &[&[u8]],
        names: policy::NamePolicy,
        visitor: impl FnMut(usize, Result<&libc::stat, ReadError>) -> Result<(), ReadError>,
    ) -> Result<(), ReadError> {
        self.metered(|meter| {
            let mut cached = self
                .worktree_stats
                .try_borrow_mut()
                .map_err(|_| ReadError::Denied)?;
            let mut local = safe_read::WorktreeStats::default();
            let scan = cached.as_mut().unwrap_or(&mut local);
            worktree::directory_stats(
                scan,
                self.roots.worktree,
                parent,
                leaves,
                names,
                self.access,
                meter,
                visitor,
            )?;
            if cached.is_none() {
                local.finish(self.roots.worktree, self.access, meter)?;
            }
            Ok(())
        })
    }

    // Darwin dev_t is signed 32-bit; Linux dev_t is already u64.
    #[allow(clippy::unnecessary_cast)]
    pub(super) fn worktree_device(&self) -> libc::dev_t {
        self.roots.worktree.device() as libc::dev_t
    }

    /// Hash the link itself, including dangling/absolute targets. The extra
    /// byte detects truncation; scratch is live, not cumulative per request.
    pub fn worktree_link_hash(
        &self,
        relative: &[u8],
        expected: &libc::stat,
    ) -> Result<gix_index::hash::ObjectId, ReadError> {
        self.metered(|meter| {
            if expected.st_dev != self.worktree_device()
                || expected.st_mode & libc::S_IFMT != libc::S_IFLNK
            {
                return Err(ReadError::Changed);
            }
            let size = u64::try_from(expected.st_size).map_err(|_| ReadError::Limit)?;
            let capacity = usize::try_from(size.checked_add(1).ok_or(ReadError::Limit)?)
                .map_err(|_| ReadError::Limit)?;
            // Match walk::target's 4097-byte buffer, including its truncation
            // sentinel. Reject hostile stat sizes before charging read bytes.
            if capacity > 4097 || capacity as u64 > bingsu_core::collection::budget::OBJECT_ALLOC {
                return Err(ReadError::Limit);
            }
            meter.charge_axis(Axis::WorktreeReadBytes, size)?;
            let mut scratch = meter.object_allocation();
            // ObjectAllocation enforces the existing per-blob OBJECT_ALLOC
            // cap as well as the request's live allocation limit.
            scratch.reserve(capacity, meter)?;
            let mut bytes = Vec::new();
            bytes
                .try_reserve_exact(capacity)
                .map_err(|_| ReadError::Limit)?;
            bytes.resize(capacity, 0);
            let mut cached = self
                .worktree_stats
                .try_borrow_mut()
                .map_err(|_| ReadError::Denied)?;
            let mut local = safe_read::WorktreeStats::default();
            let scan = cached.as_mut().unwrap_or(&mut local);
            let len = scan.read_link(
                self.roots.worktree,
                relative,
                expected,
                &mut bytes,
                self.access,
                meter,
            )?;
            if cached.is_none() {
                local.finish(self.roots.worktree, self.access, meter)?;
            }
            meter.event("before_worktree_hash");
            let id = gix_object::compute_hash(
                gix_index::hash::Kind::Sha1,
                gix_object::Kind::Blob,
                &bytes[..len],
            )
            .map_err(|_| ReadError::Io(libc::EINVAL))?;
            meter.check()?;
            Ok(id)
        })
    }

    /// Hash only bytes from the same validated fd. Worktree bytes are charged
    /// independently of repository snapshots; scratch is released each call.
    pub fn worktree_hash(
        &self,
        relative: &[u8],
        expected: &libc::stat,
    ) -> Result<gix_index::hash::ObjectId, ReadError> {
        use bingsu_core::collection::budget::OBJECT_ALLOC;
        self.metered(|meter| {
            if expected.st_dev != self.worktree_device() {
                return Err(ReadError::Changed);
            }
            if meter.budget.used(Axis::WorktreeReadBytes) == Axis::WorktreeReadBytes.limit() {
                return Err(ReadError::Limit);
            }
            let file = {
                let mut cached = self
                    .worktree_stats
                    .try_borrow_mut()
                    .map_err(|_| ReadError::Denied)?;
                let mut local = safe_read::WorktreeStats::default();
                let scan = cached.as_mut().unwrap_or(&mut local);
                let file = scan
                    .open_file(self.roots.worktree, relative, self.access, meter)
                    .map_err(|e| {
                        if e == ReadError::Symlink {
                            ReadError::Missing
                        } else {
                            e
                        }
                    })?;
                if cached.is_none() {
                    local.finish(self.roots.worktree, self.access, meter)?;
                }
                file
            };
            if !safe_read::same_worktree_stat(expected, &file.metadata()) {
                return Err(ReadError::Changed);
            }
            let size = u64::try_from(file.metadata().st_size).map_err(|_| ReadError::Limit)?;
            if size > OBJECT_ALLOC {
                return Err(ReadError::Limit);
            }
            meter.charge_axis(Axis::WorktreeReadBytes, size)?;
            // Reserve the blob before allocation. The EOF/growth probe uses
            // one stack byte and does not consume another content byte.
            let mut scratch = meter.object_allocation();
            scratch.reserve(size as usize, meter)?;
            let bytes = file.read_worktree(
                ReadCap {
                    bytes: size,
                    single_link: false,
                },
                meter,
            )?;
            if bytes.len() as u64 != size {
                return Err(ReadError::Changed);
            }
            meter.event("before_worktree_hash");
            let id = gix_object::compute_hash(
                gix_index::hash::Kind::Sha1,
                gix_object::Kind::Blob,
                &bytes,
            )
            .map_err(|_| ReadError::Io(libc::EINVAL))?;
            meter.check()?;
            Ok(id)
        })
    }

    pub fn list(&self, path: RepoPath, raw_limit: u32) -> Result<Listing, ReadError> {
        self.metered(|meter| {
            let dir =
                safe_read::directory(self.root(path.root), &path.relative, self.access, meter)?;
            safe_read::entries(&dir, raw_limit, meter)
        })
    }

    /// Fixed repository-format markers need an open, not a directory listing.
    pub(super) fn has_directory(&self, path: RepoPath) -> Result<bool, ReadError> {
        self.metered(|meter| {
            match safe_read::directory(self.root(path.root), &path.relative, self.access, meter) {
                Ok(_) => Ok(true),
                Err(ReadError::Missing) => Ok(false),
                Err(error) => Err(error),
            }
        })
    }

    /// Preserve the timestamp of the very descriptor whose index bytes were
    /// checked. A separate path stat would let a replacement hide racy entries.
    pub(crate) fn read_index(&self) -> Result<(Vec<u8>, libc::stat), ReadError> {
        self.metered(|meter| {
            use bingsu_core::collection::budget;
            if meter.budget.used(Axis::IndexBytes) == budget::INDEX_BYTES {
                return Err(ReadError::Limit);
            }
            let file = safe_read::resolve_with(self.roots.gitdir, b"index", self.access, meter)?;
            let metadata = file.metadata();
            let size = u64::try_from(metadata.st_size).map_err(|_| ReadError::Limit)?;
            meter.charge_axis(Axis::IndexBytes, size)?;
            let bytes = file.read_reserved(
                ReadCap {
                    bytes: size,
                    single_link: true,
                },
                meter,
            )?;
            if bytes.len() as u64 != size {
                return Err(ReadError::Changed);
            }
            Ok((bytes, metadata))
        })
    }

    pub(crate) fn read_budgeted(
        &self,
        path: RepoPath,
        cap: u64,
        axis: Axis,
    ) -> Result<Vec<u8>, ReadError> {
        self.read_sized(path, cap, Some(axis))
    }

    pub(super) fn read_patterns(
        &self,
        path: RepoPath,
        files: Axis,
        bytes: Axis,
    ) -> Result<Vec<u8>, ReadError> {
        self.read_sized_with_cap(
            path,
            ReadCap {
                bytes: bingsu_core::collection::budget::SMALL_FILE_BYTES,
                single_link: true,
            },
            Some(bytes),
            Some(files),
        )
    }

    pub(crate) fn read_sized(
        &self,
        path: RepoPath,
        cap: u64,
        axis: Option<Axis>,
    ) -> Result<Vec<u8>, ReadError> {
        self.read_sized_with_cap(
            path,
            ReadCap {
                bytes: cap,
                single_link: true,
            },
            axis,
            None,
        )
    }

    fn read_sized_with_cap(
        &self,
        path: RepoPath,
        cap: ReadCap,
        axis: Option<Axis>,
        files: Option<Axis>,
    ) -> Result<Vec<u8>, ReadError> {
        self.metered(|meter| {
            if axis.is_some_and(|axis| meter.budget.used(axis) == axis.limit())
                || files.is_some_and(|axis| meter.budget.used(axis) == axis.limit())
            {
                return Err(ReadError::Limit);
            }
            let file = if path.root == RootId::Worktree {
                safe_read::resolve_nofollow(
                    self.root(path.root),
                    &path.relative,
                    self.access,
                    meter,
                )?
            } else {
                safe_read::resolve_with(self.root(path.root), &path.relative, self.access, meter)?
            };
            let size = u64::try_from(file.metadata().st_size).map_err(|_| ReadError::Limit)?;
            if size > cap.bytes {
                return Err(ReadError::Limit);
            }
            if let Some(files) = files {
                meter.charge_axis(files, 1)?;
            }
            if let Some(axis) = axis {
                meter.charge_axis(axis, size)?;
            }
            if axis.is_none() && files.is_none() && cap.single_link {
                return file.read_metadata(cap.bytes, meter);
            }
            let bytes = file.read_reserved(
                ReadCap {
                    bytes: size,
                    single_link: cap.single_link,
                },
                meter,
            )?;
            if bytes.len() as u64 != size {
                return Err(ReadError::Changed);
            }
            Ok(bytes)
        })
    }

    /// Stream a stable prefix from ONE fd, with a separately charged reflog
    /// axis and one extra EOF probe. False means unexamined bytes remain.
    /// Visitor false stops parsing, but still verifies the held file metadata.
    pub(crate) fn stream_reflog(
        &self,
        present: impl FnOnce() -> Result<bool, ReadError>,
        mut visit: impl FnMut(&[u8], &mut Meter) -> Result<bool, ReadError>,
    ) -> Result<bool, ReadError> {
        let file = self.metered(|meter| {
            let file = safe_read::resolve_with(
                self.roots.commondir,
                b"logs/refs/stash",
                self.access,
                meter,
            )?;
            if file.metadata().st_nlink != 1 {
                return Err(ReadError::Special);
            }
            Ok(file)
        })?;
        let size = u64::try_from(file.metadata().st_size).map_err(|_| ReadError::Limit)?;
        // Only nonempty reflogs need a ref lookup (and possibly packed-refs).
        // Keep this same fd, but release the meter borrow before nested I/O.
        if size != 0 && !present()? {
            return Ok(true);
        }
        self.metered(|meter| {
            let remaining = Axis::ReflogBytes.limit() - meter.budget.used(Axis::ReflogBytes);
            let reserved = size.min(remaining);
            meter.charge_axis(Axis::ReflogBytes, reserved)?;
            meter.event("before_reflog_read");
            let mut buffer = [0; crate::meter::READ_CHUNK];
            let mut read = 0;
            while read < reserved {
                let len = (reserved - read).min(buffer.len() as u64) as usize;
                let n = file.stream_chunk(&mut buffer[..len], meter)?;
                if n == 0 {
                    return Err(ReadError::Changed);
                }
                read += n as u64;
                if !visit(&buffer[..n], meter)? {
                    file.verify_stream(meter)?;
                    return Ok(false);
                }
            }
            let n = file.stream_chunk(&mut buffer[..1], meter)?;
            file.verify_stream(meter)?;
            if size <= reserved && n != 0 {
                return Err(ReadError::Changed);
            }
            if size > reserved && n == 0 {
                return Err(ReadError::Changed);
            }
            Ok(n == 0)
        })
    }

    pub fn map(&self, path: RepoPath, cap: u64) -> Result<ReadMap, ReadError> {
        self.read_budgeted(path, cap, Axis::PackBytes).map(ReadMap)
    }
}

#[cfg(test)]
mod scratch_tests {
    use super::*;

    // Mutations: grow at exact capacity; omit either the retained capacity or
    // the transient old-buffer charge; reserve after allocating; lose bytes.
    #[test]
    fn scratch_capacity_is_live_and_precharged_through_growth() {
        for limit in [31, 32, 47, 48] {
            let mut meter =
                Meter::new(std::time::Instant::now() + std::time::Duration::from_secs(30));
            let mut allocation = meter.path_allocation();
            let mut bytes = Vec::<u8>::new();
            reserve_scratch(&mut bytes, 16, &mut allocation, &mut meter).unwrap();
            bytes.extend(0..16);
            assert_eq!(meter.live_allocated(), 16);
            meter.allocation_limit = 16;
            reserve_scratch(&mut bytes, 0, &mut allocation, &mut meter).unwrap();
            meter.allocation_limit = limit;
            let result = reserve_scratch(&mut bytes, 1, &mut allocation, &mut meter);
            assert_eq!(
                result,
                if limit < 48 {
                    Err(ReadError::Limit)
                } else {
                    Ok(())
                }
            );
            assert_eq!(bytes, (0..16).collect::<Vec<_>>());
            assert_eq!(bytes.capacity(), if limit < 48 { 16 } else { 32 });
            if result.is_ok() {
                assert_eq!(meter.live_allocated(), 32);
            }
            drop(bytes);
            drop(allocation);
            assert_eq!(meter.live_allocated(), 0);
        }
    }
}

#[cfg(test)]
#[path = "io_test_support.rs"]
pub(crate) mod test_support;
