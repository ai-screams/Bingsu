//! Bounded, resumable inventory and eviction in the private runtime namespace.
//! Catalog entries are hints: deletion always reopens and checks the actual
//! parent/name, data and collection lock. Snapshot names are never candidates.
use super::{
    collection_store::{self, FILES, LOCK, PREVIOUS, RESPONSE, STAGE},
    snapshot_store::{self, CheckedContextFd, StoreError},
    sys,
};
use bingsu_core::{
    collection::{
        cwd_hash,
        response::Completed,
        wire::{Binding, STREAM_MAX},
    },
    field::SegmentDecl,
    snapshot::{self, Clock},
};
use std::{ffi::OsStr, fs::File, io, os::fd::AsFd};

pub(crate) const MAX_STORES: u64 = 128;
pub(crate) const MAX_NODES: u64 = 8_192;
pub(crate) const MAX_BYTES: u64 = 10_000_000;
pub(crate) const CATALOG_MAX: usize = 1_048_576;
pub(crate) const RESERVATION: u64 = 4 * STREAM_MAX as u64;
const CATALOG: &str = ".collections.catalog";
const CATALOG_STAGE: &str = ".collections.catalog.stage";
const GC_LOCK: &str = ".collections.gc.lock";
const TOMBSTONE: &str = ".store.gc";
const DAY_NS: u64 = 86_400_000_000_000;
const MAX_DEPTH: usize = 3_300;
// Reopening two ancestry chains for eviction must leave room for the locked
// contents, tombstone and catalog checkpoint inside a 4,096-operation sweep.
const MAX_SCAN_DEPTH: usize = 48;
const MAX_ADDRESS_NODES: u64 = 65_536u64.div_ceil(60) + 1;

#[derive(Clone, Copy)]
pub(crate) struct GcBudget {
    pub max_ops: u32,
    pub max_ns: u64,
}
impl Default for GcBudget {
    fn default() -> Self {
        Self {
            max_ops: 4_096,
            max_ns: 20_000_000,
        }
    }
}
impl GcBudget {
    pub(super) fn start(self) -> sys::CollectionMeter {
        sys::CollectionMeter::start(self.max_ops.min(4_096), self.max_ns.min(20_000_000))
    }
    fn max_depth(self) -> usize {
        // Allow two checked ancestor walks plus fixed inspection/checkpoint work.
        // Smaller test/maintenance budgets must not save an unreopenable cursor.
        // Keep the short context/hash/store grammar reachable after a tiny sweep.
        (self.max_ops.saturating_sub(440) / 44).clamp(10, MAX_SCAN_DEPTH as u32) as usize
    }
}
#[derive(Debug, Default)]
pub(crate) struct GcReport {
    pub visited: u32,
    pub removed_files: u32,
    pub removed_dirs: u32,
    pub incomplete: bool,
    pub skipped: u32,
    #[cfg(test)]
    pub ops: u32,
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct Entry {
    path: Vec<String>,
    cwd: Vec<u8>,
    dev: u64,
    ino: u64,
    bytes: u64,
    reserved: bool,
    used: Clock,
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct Cursor {
    name: String,
    after: String,
    dev: u64,
    ino: u64,
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct Catalog {
    dev: u64,
    ino: u64,
    ready: bool,
    unsafe_seen: bool,
    stores: u64,
    nodes: u64,
    bytes: u64,
    next: u32,
    entries: Vec<Entry>,
    cursor: Vec<Cursor>,
    prune: Vec<String>,
    unknown: Vec<Vec<String>>,
}
impl Catalog {
    fn empty(runtime: &File) -> Result<Self, StoreError> {
        let stamp = sys::file_stamp(runtime)?;
        Ok(Self {
            dev: stamp.dev,
            ino: stamp.ino,
            ready: false,
            unsafe_seen: false,
            stores: 0,
            nodes: 0,
            bytes: 0,
            next: 0,
            entries: vec![],
            prune: vec![],
            unknown: vec![],
            cursor: vec![Cursor {
                name: String::new(),
                after: String::new(),
                dev: stamp.dev,
                ino: stamp.ino,
            }],
        })
    }
    fn capacity(&self, stores: u64, nodes: u64, bytes: u64) -> bool {
        capacity(
            self.stores.saturating_add(stores),
            self.nodes.saturating_add(nodes),
            self.bytes
                .saturating_add(bytes)
                .saturating_add(2 * CATALOG_MAX as u64),
        )
    }
}
pub(crate) fn capacity(stores: u64, nodes: u64, bytes: u64) -> bool {
    stores <= MAX_STORES && nodes <= MAX_NODES && bytes <= MAX_BYTES
}

pub(super) struct Registration<'a> {
    runtime: &'a File,
    _lock: File,
    catalog: Catalog,
    me: u32,
    selected: Option<usize>,
}
impl<'a> Registration<'a> {
    pub(super) fn open(
        runtime: &'a File,
        me: u32,
        now: Clock,
        schema: &[SegmentDecl],
        start_meter: fn() -> sys::CollectionMeter,
    ) -> Result<Self, StoreError> {
        snapshot_store::check_directory(runtime, me)?;
        let lock = collection_store::close_only_lock(runtime, GC_LOCK, me, true)?;
        let mut catalog = match load(runtime, me)? {
            Some(catalog) => catalog,
            None => Catalog::empty(runtime)?,
        };
        if catalog.entries.iter().any(|entry| entry.ino == 0) || !catalog.prune.is_empty() {
            // A pre-mkdir reservation or unfinished empty suffix can outlive
            // collections-v1. Rebuild accounting under the global lock before
            // admitting another store, without waiting for a reclamation sweep.
            catalog = Catalog::empty(runtime)?;
        }
        if !catalog.ready {
            // The first actual admission initializes the runtime catalog.
            // An empty product selection never needs this filesystem work.
            let budget = GcBudget::default();
            let meter = start_meter();
            let result = inventory(
                runtime,
                me,
                now,
                schema,
                budget,
                &mut catalog,
                &mut GcReport::default(),
            );
            meter.checkpoint();
            save(runtime, me, &catalog)?;
            result?;
        }
        if !catalog.ready || catalog.unsafe_seen {
            return Err(StoreError::Busy);
        }
        Ok(Self {
            runtime,
            _lock: lock,
            catalog,
            me,
            selected: None,
        })
    }
    pub(super) fn reserve(
        &mut self,
        context: &CheckedContextFd,
        binding: &Binding,
        address: &str,
        now: Clock,
    ) -> Result<(), StoreError> {
        let mut path = snapshot::context_components(&context.config, &context.state)?;
        path.extend(["collections-v1".into(), address.into(), "store".into()]);
        if path.len() >= GcBudget::default().max_depth() {
            // Inventory skips this depth before inspecting a store. Unknown
            // occupation covers legacy/same-uid trees, never new admissions.
            return Err(StoreError::Busy);
        }
        if self
            .catalog
            .unknown
            .iter()
            .any(|prefix| path.starts_with(prefix))
        {
            // Unknown occupation is charged, but never authorizes a new store
            // inside the skipped namespace or deletion of anything below it.
            return Err(StoreError::Busy);
        }
        let index = self.catalog.entries.iter().position(|e| e.path == path);
        if let Some(index) = index {
            let old = &self.catalog.entries[index];
            // The raw bytes, not a digest or build id, select this lock owner.
            if !old.cwd.is_empty() && old.cwd != binding.cwd {
                return Err(StoreError::Busy);
            }
            let dir = open_path(self.runtime, &path, self.me)?;
            let actual = sys::file_stamp(&dir)?;
            if (actual.dev, actual.ino) != (old.dev, old.ino) {
                return Err(StoreError::Unsafe);
            }
            let additional = RESERVATION.saturating_sub(old.bytes);
            if !self.catalog.capacity(0, 0, additional) {
                return Err(StoreError::Busy);
            }
            self.catalog.bytes = self.catalog.bytes.saturating_add(additional);
            let entry = &mut self.catalog.entries[index];
            entry.cwd = binding.cwd.clone();
            entry.bytes = entry.bytes.max(RESERVATION);
            entry.reserved = true;
            entry.used = now;
            self.selected = Some(index);
        } else {
            if !self.catalog.capacity(1, 3, RESERVATION) {
                return Err(StoreError::Busy);
            }
            // Unindexed occupants and tombstones never become new admissions.
            let mut parent_path = path.clone();
            parent_path.pop();
            match open_path(self.runtime, &parent_path, self.me) {
                Ok(parent) => {
                    for name in ["store", TOMBSTONE] {
                        if !sys::at_stamp(parent.as_fd(), OsStr::new(name))
                            .is_err_and(|e| e.kind() == io::ErrorKind::NotFound)
                        {
                            return Err(StoreError::Busy);
                        }
                    }
                }
                Err(StoreError::Io(e)) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(e),
            }
            self.catalog.entries.push(Entry {
                path,
                cwd: binding.cwd.clone(),
                dev: 0,
                ino: 0,
                bytes: RESERVATION,
                reserved: true,
                used: now,
            });
            self.catalog.stores += 1;
            self.catalog.nodes += 3;
            self.catalog.bytes += RESERVATION;
            self.selected = Some(self.catalog.entries.len() - 1);
        }
        // The catalog and both its staging copies are included in admission.
        // This durable-in-process reservation precedes every collection mkdir.
        save(self.runtime, self.me, &self.catalog)
    }
    pub(super) fn attach(&mut self, dir: &File, created: u64) -> Result<(), StoreError> {
        let entry = &mut self.catalog.entries[self.selected.ok_or(StoreError::Unsafe)?];
        let stamp = sys::file_stamp(dir)?;
        if entry.ino != 0 && (entry.dev, entry.ino) != (stamp.dev, stamp.ino) {
            return Err(StoreError::Unsafe);
        }
        if entry.ino == 0 {
            // A new admission reserves all three components before mkdir.
            // Shared or already inventoried directories consume no new nodes.
            self.catalog.nodes -= 3 - created;
        }
        entry.dev = stamp.dev;
        entry.ino = stamp.ino;
        save(self.runtime, self.me, &self.catalog)
    }
}

pub(crate) fn reclaim(
    runtime: &File,
    now: Clock,
    budget: GcBudget,
) -> Result<GcReport, StoreError> {
    reclaim_inner(
        runtime,
        now,
        budget,
        bingsu_core::field::BUILTIN,
        budget.start(),
    )
}
#[cfg(test)]
#[allow(dead_code, reason = "native collection_store integration target")]
pub(crate) fn fixture_reclaim(
    context: &CheckedContextFd,
    now: Clock,
    max_ops: u32,
    schema: &[SegmentDecl],
) -> Result<GcReport, StoreError> {
    // Functional fixtures retain the operation cap and checkpoint reserve,
    // but never depend on scheduler latency. Time caps use reclaim itself.
    let budget = GcBudget {
        max_ops: max_ops.min(4_096),
        ..GcBudget::default()
    };
    reclaim_inner(
        &context.runtime,
        now,
        budget,
        schema,
        sys::CollectionMeter::fixture_operations(budget.max_ops),
    )
}
fn reclaim_inner(
    runtime: &File,
    now: Clock,
    budget: GcBudget,
    schema: &[SegmentDecl],
    meter: sys::CollectionMeter,
) -> Result<GcReport, StoreError> {
    let mut report = GcReport::default();
    // This is the first filesystem operation. A runtime that never collected
    // needs no global lock or inventory. Existing stores in any context can
    // need reclamation even before the current context's first admission.
    match sys::open_data_at_nofollow(runtime.as_fd(), OsStr::new(CATALOG)) {
        Ok(file) => drop(file),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            #[cfg(test)]
            {
                report.ops = meter.used();
            }
            return Ok(report);
        }
        Err(_) => {
            report.incomplete = true;
            #[cfg(test)]
            {
                report.ops = meter.used();
            }
            return Ok(report);
        }
    }
    if sys::collection_ops(1).is_err() {
        report.incomplete = true;
        return Ok(report);
    }
    let me = sys::current_uid();
    let mut state = None;
    let mut held_lock = None;
    let work = (|| {
        snapshot_store::check_directory(runtime, me)?;
        held_lock = Some(collection_store::close_only_lock(
            runtime, GC_LOCK, me, true,
        )?);
        let mut catalog = match load(runtime, me) {
            Ok(Some(catalog)) => catalog,
            Ok(None) | Err(StoreError::Unsafe) => Catalog::empty(runtime)?,
            Err(e) => return Err(e),
        };
        let result = if !catalog.ready {
            inventory(runtime, me, now, schema, budget, &mut catalog, &mut report)
        } else {
            evict(runtime, me, now, schema, &mut catalog, &mut report)
        };
        // A reservation may precede mkdir, or a completed rmdir may precede
        // the catalog checkpoint. Rebuild counts instead of trusting either
        // stale path or permanently stranding its reserved capacity.
        if catalog.ready
            && matches!(&result, Err(StoreError::Io(e)) if e.kind() == io::ErrorKind::NotFound)
        {
            catalog = Catalog::empty(runtime)?;
        }
        state = Some(catalog);
        result
    })();
    if work.is_err() {
        report.incomplete = true;
    }
    if let Some(catalog) = state {
        report.incomplete |= !catalog.ready || catalog.unsafe_seen;
        meter.checkpoint();
        if save(runtime, me, &catalog).is_err() {
            report.incomplete = true;
        }
    }
    #[cfg(test)]
    {
        report.ops = meter.used();
    }
    // Release the global lock before ending the accounting scope. Neither
    // lock owner explicitly unlocks an OFD that another owner may retain.
    drop(held_lock);
    Ok(report)
}

fn load(runtime: &File, me: u32) -> Result<Option<Catalog>, StoreError> {
    let Some((_, bytes)) = collection_store::read_checked(runtime, CATALOG, CATALOG_MAX, me)?
    else {
        return Ok(None);
    };
    let catalog = decode(&bytes)?;
    let actual = sys::file_stamp(runtime)?;
    if (catalog.dev, catalog.ino) != (actual.dev, actual.ino) {
        return Err(StoreError::Unsafe);
    }
    Ok(Some(catalog))
}
fn save(runtime: &File, me: u32, catalog: &Catalog) -> Result<(), StoreError> {
    let bytes = encode(catalog)?;
    collection_store::remove_checked(runtime, CATALOG_STAGE, CATALOG_MAX, me)?;
    let stage = snapshot_store::stage_verified(
        runtime,
        me,
        CATALOG_STAGE,
        &bytes,
        CATALOG_MAX,
        &mut |bytes| {
            if decode(bytes)? != *catalog {
                return Err(StoreError::Unsafe);
            }
            Ok(())
        },
        &mut |_| {},
    )?;
    // Rebuilding may replace a damaged length/CRC, but never unsafe metadata.
    match sys::open_data_at_nofollow(runtime.as_fd(), OsStr::new(CATALOG)) {
        Ok(file) => {
            snapshot_store::check_data(&file, usize::MAX, me)?;
            snapshot_store::same_name(&file, runtime.as_fd(), CATALOG)?;
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }
    stage.install(runtime, me, CATALOG_STAGE, CATALOG, CATALOG_MAX)
}
fn open_path(runtime: &File, path: &[String], me: u32) -> Result<File, StoreError> {
    sys::collection_ops(2)?;
    let mut dir = runtime.try_clone()?;
    for name in path {
        if !component(name) {
            return Err(StoreError::Unsafe);
        }
        let next = sys::open_dir_at_nofollow(dir.as_fd(), OsStr::new(name))?;
        snapshot_store::check_directory(&next, me)?;
        snapshot_store::same_name(&next, dir.as_fd(), name)?;
        dir = next;
    }
    Ok(dir)
}
fn component(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 120
        && name != "."
        && name != ".."
        && !name.as_bytes().contains(&0)
        && !name.as_bytes().contains(&b'/')
}
fn hex(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 120
        && s.len() % 2 == 0
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn unhex(parts: &[String]) -> Result<Vec<u8>, StoreError> {
    let mut bytes = Vec::new();
    for (i, part) in parts.iter().enumerate() {
        if !hex(part) || (i + 1 != parts.len() && part.len() != 120) {
            return Err(StoreError::Unsafe);
        }
        for pair in part.as_bytes().chunks_exact(2) {
            let n = |b: u8| if b <= b'9' { b - b'0' } else { b - b'a' + 10 };
            bytes.push((n(pair[0]) << 4) | n(pair[1]));
        }
        if bytes.len() > 65_536 {
            return Err(StoreError::Unsafe);
        }
    }
    if bytes.first() != Some(&b'/') || bytes.contains(&0) {
        return Err(StoreError::Unsafe);
    }
    Ok(bytes)
}
struct Location {
    config: Vec<u8>,
    state: Vec<u8>,
    address: Vec<String>,
}
fn location(path: &[String]) -> Result<Location, StoreError> {
    if path.len() < 9
        || path[0] != "contexts-v2"
        || path[1] != "config"
        || !matches!(path.last().map(String::as_str), Some("store" | TOMBSTONE))
    {
        return Err(StoreError::Unsafe);
    }
    let state = path
        .iter()
        .position(|s| s == "state")
        .ok_or(StoreError::Unsafe)?;
    let context = path
        .iter()
        .skip(state + 1)
        .position(|s| s == "store")
        .map(|p| p + state + 1)
        .ok_or(StoreError::Unsafe)?;
    if path.get(context + 1).map(String::as_str) != Some("collections-v1") {
        return Err(StoreError::Unsafe);
    }
    let config_bytes = unhex(&path[2..state])?;
    let state_bytes = unhex(&path[state + 1..context])?;
    let address = path[context + 2..path.len() - 1].to_vec();
    if address.len() != 1 || address[0].len() != 64 || !hex(&address[0]) {
        unhex(&address)?;
    }
    Ok(Location {
        config: config_bytes,
        state: state_bytes,
        address,
    })
}
fn identity(location: &Location, binding: &Binding) -> bool {
    location.config == binding.config
        && location.state == binding.state
        && (location.address == [cwd_hash::address(&binding.cwd)]
            || unhex(&location.address).is_ok_and(|bytes| bytes == binding.cwd))
}
fn entry_valid(entry: &Entry) -> bool {
    let Ok(loc) = location(&entry.path) else {
        return false;
    };
    if entry.cwd.is_empty() {
        return loc.address.len() == 1 && loc.address[0].len() == 64;
    }
    loc.address == [cwd_hash::address(&entry.cwd)]
        || unhex(&loc.address).is_ok_and(|cwd| cwd == entry.cwd)
}

// Only names belonging to the context/collection grammar are traversed.
fn descend(path: &[String], name: &str) -> bool {
    if !component(name) {
        return false;
    }
    if path.is_empty() {
        return name == "contexts-v2";
    }
    if path.len() == 1 {
        return name == "config";
    }
    if path.iter().any(|p| p == "collections-v1") {
        return hex(name) || name == "store" || name == TOMBSTONE;
    }
    if path.last().is_some_and(|p| p == "store") {
        return name == "collections-v1";
    }
    if path.iter().any(|p| p == "state") {
        return hex(name) || name == "store";
    }
    hex(name) || name == "state"
}
fn next_name(dir: &File, after: &str) -> Result<Option<String>, StoreError> {
    let mut stream = sys::DirectoryCursor::open(dir.as_fd())?;
    let mut best: Option<String> = None;
    while let Some(name) = stream.next()? {
        if name == "." || name == ".." {
            continue;
        }
        // Non-UTF-8 entries are never path components in this hex namespace.
        let Some(name) = name.to_str() else {
            return Err(StoreError::Unsafe);
        };
        if name > after && best.as_ref().is_none_or(|b| name < b.as_str()) {
            best = Some(name.to_owned());
        }
    }
    Ok(best)
}
fn inventory(
    runtime: &File,
    me: u32,
    now: Clock,
    schema: &[SegmentDecl],
    budget: GcBudget,
    catalog: &mut Catalog,
    report: &mut GcReport,
) -> Result<(), StoreError> {
    let max_depth = budget.max_depth();
    // Reopen and verify every saved ancestor, never trust a path in the cursor.
    let mut path = Vec::new();
    let mut dirs = Vec::new();
    sys::collection_ops(2)?;
    dirs.push(runtime.try_clone()?);
    for (i, cursor) in catalog.cursor.iter().enumerate() {
        if i > 0 {
            if !descend(&path, &cursor.name) {
                return Err(StoreError::Unsafe);
            }
            let dir = match sys::open_dir_at_nofollow(
                dirs.last().unwrap().as_fd(),
                OsStr::new(&cursor.name),
            ) {
                Ok(dir) => dir,
                Err(e) if e.kind() == io::ErrorKind::NotFound => {
                    *catalog = Catalog::empty(runtime)?;
                    return Err(StoreError::Busy);
                }
                Err(e) => return Err(e.into()),
            };
            snapshot_store::check_directory(&dir, me)?;
            snapshot_store::same_name(&dir, dirs.last().unwrap().as_fd(), &cursor.name)?;
            path.push(cursor.name.clone());
            dirs.push(dir);
        }
        let stamp = sys::file_stamp(dirs.last().unwrap())?;
        if (stamp.dev, stamp.ino) != (cursor.dev, cursor.ino) {
            *catalog = Catalog::empty(runtime)?;
            return Err(StoreError::Busy);
        }
    }
    while !catalog.cursor.is_empty() {
        let dir = dirs.last().unwrap();
        let after = catalog.cursor.last().unwrap().after.clone();
        let name = next_name(dir, &after)?;
        let Some(name) = name else {
            // A crash can leave only empty address directories. rmdir under
            // the global lock cannot remove a live or unknown child entry.
            if path.iter().any(|n| n == "collections-v1") {
                let parent = &dirs[dirs.len() - 2];
                let name = path.last().unwrap();
                snapshot_store::check_directory(dir, me)?;
                snapshot_store::same_name(dir, parent.as_fd(), name)?;
                match sys::remove_dir_at(parent.as_fd(), OsStr::new(name)) {
                    Ok(()) => {
                        report.removed_dirs += 1;
                        catalog.nodes = catalog.nodes.saturating_sub(1);
                    }
                    Err(e) if matches!(e.raw_os_error(), Some(libc::ENOTEMPTY | libc::EEXIST)) => {}
                    Err(e) => return Err(e.into()),
                }
            }
            catalog.cursor.pop();
            dirs.pop();
            path.pop();
            continue;
        };
        if !descend(&path, &name) {
            if path.iter().any(|n| n == "collections-v1") {
                catalog.unsafe_seen = true;
            }
            catalog.cursor.last_mut().unwrap().after = name;
            continue;
        }
        let child = match sys::open_dir_at_nofollow(dir.as_fd(), OsStr::new(&name)) {
            Ok(child) => child,
            Err(e) if e.kind() == io::ErrorKind::TimedOut => return Err(e.into()),
            Err(_) => {
                catalog.unsafe_seen = true;
                catalog.cursor.last_mut().unwrap().after = name;
                continue;
            }
        };
        snapshot_store::check_directory(&child, me)?;
        snapshot_store::same_name(&child, dir.as_fd(), &name)?;
        let stamp = sys::file_stamp(&child)?;
        let mut child_path = path.clone();
        child_path.push(name.clone());
        if child_path.len() >= max_depth {
            // Reserve the rest of one maximal canonical address chain and all
            // four bounded data files. This is unknown logical occupation,
            // not a deletable entry and not a runtime-wide unsafe flag.
            // Only the same uid can construct branching subtrees: the bound
            // deliberately covers one legacy address per unfinished subtree.
            let remaining = child_path
                .iter()
                .position(|n| n == "collections-v1")
                .map_or(MAX_ADDRESS_NODES + 1, |root| {
                    (MAX_ADDRESS_NODES + 2).saturating_sub((child_path.len() - root) as u64)
                });
            catalog.nodes = catalog.nodes.saturating_add(remaining);
            catalog.bytes = catalog.bytes.saturating_add(RESERVATION);
            catalog.stores = catalog.stores.saturating_add(1);
            if catalog.unknown.len() < MAX_STORES as usize {
                catalog.unknown.push(child_path);
            }
            report.skipped += 1;
            catalog.cursor.last_mut().unwrap().after = name;
            continue;
        }
        if location(&child_path).is_ok() {
            if next_name(&child, "")?.is_none() {
                snapshot_store::same_name(&child, dir.as_fd(), &name)?;
                sys::remove_dir_at(dir.as_fd(), OsStr::new(&name))?;
                report.removed_dirs += 1;
                catalog.cursor.last_mut().unwrap().after = name;
                continue;
            }
            let entry = inspect(&child, child_path.clone(), me, now, schema)?;
            report.visited += 1;
            catalog.stores = catalog.stores.saturating_add(1);
            catalog.bytes = catalog.bytes.saturating_add(entry.bytes);
            if catalog.entries.len() < MAX_STORES as usize {
                catalog.entries.push(entry);
                if encode(catalog).is_err() {
                    catalog.entries.pop();
                    catalog.unsafe_seen = true;
                }
            } else {
                catalog.unsafe_seen = true;
            }
        } else {
            catalog.cursor.last_mut().unwrap().after = name.clone();
            catalog.cursor.push(Cursor {
                name,
                after: String::new(),
                dev: stamp.dev,
                ino: stamp.ino,
            });
            if child_path.iter().any(|n| n == "collections-v1") {
                catalog.nodes = catalog.nodes.saturating_add(1);
            }
            dirs.push(child);
            path = child_path;
            continue;
        }
        if child_path.iter().any(|n| n == "collections-v1") {
            catalog.nodes = catalog.nodes.saturating_add(1);
        }
        catalog.cursor.last_mut().unwrap().after = name;
    }
    catalog.ready = true;
    Ok(())
}
fn inspect(
    dir: &File,
    path: Vec<String>,
    me: u32,
    now: Clock,
    schema: &[SegmentDecl],
) -> Result<Entry, StoreError> {
    let loc = location(&path)?;
    let stamp = sys::file_stamp(dir)?;
    let lock = match collection_store::close_only_lock(dir, LOCK, me, false) {
        Ok(lock) => Some(lock),
        Err(StoreError::Busy) => None,
        Err(StoreError::Io(e))
            if e.kind() == io::ErrorKind::NotFound && path.last().unwrap() == TOMBSTONE =>
        {
            None
        }
        Err(e) => return Err(e),
    };
    if lock.is_none() && path.last().unwrap() != TOMBSTONE {
        return Ok(Entry {
            path,
            cwd: if loc.address.len() == 1 && loc.address[0].len() == 64 {
                vec![]
            } else {
                unhex(&loc.address)?
            },
            dev: stamp.dev,
            ino: stamp.ino,
            bytes: RESERVATION,
            reserved: true,
            used: now,
        });
    }
    let mut bytes = 0u64;
    let mut cwd = if loc.address.len() == 1 && loc.address[0].len() == 64 {
        vec![]
    } else {
        unhex(&loc.address)?
    };
    let mut used = now;
    let mut stream = sys::DirectoryCursor::open(dir.as_fd())?;
    while let Some(name) = stream.next()? {
        if name == "." || name == ".." {
            continue;
        }
        let name = name.to_str().ok_or(StoreError::Unsafe)?;
        if !FILES.contains(&name) {
            return Err(StoreError::Unsafe);
        }
        let cap = if name == LOCK { 0 } else { STREAM_MAX };
        let Some((_, content)) = collection_store::read_checked(dir, name, cap, me)? else {
            return Err(StoreError::Unsafe);
        };
        bytes = bytes.saturating_add(content.len() as u64);
        if name == RESPONSE || name == PREVIOUS {
            let Ok(response) = Completed::decode_with_catalog(&content, schema) else {
                // Metadata and fd/name identity passed under the store lock.
                // Eviction will recheck and tombstone this incomplete response.
                continue;
            };
            if !identity(&loc, &response.binding)
                || (!cwd.is_empty() && cwd != response.binding.cwd)
            {
                return Err(StoreError::Unsafe);
            }
            cwd = response.binding.cwd.clone();
            used = Clock {
                boot: response.binding.snapshot.boot,
                kind: response.binding.clock_kind,
                domain: response.binding.domain,
                resume: response.binding.resume,
                now: response.completed_at_ns,
            };
        }
    }
    let reserved = lock.is_none();
    if reserved {
        bytes = bytes.max(RESERVATION);
    }
    Ok(Entry {
        path,
        cwd,
        dev: stamp.dev,
        ino: stamp.ino,
        bytes,
        reserved,
        used,
    })
}
fn old(entry: &Entry, now: Clock) -> bool {
    entry.used.boot != now.boot
        || (entry.used.kind == now.kind
            && entry.used.domain == now.domain
            && entry.used.resume == now.resume
            && now.now.saturating_sub(entry.used.now) >= DAY_NS)
}
fn evict(
    runtime: &File,
    me: u32,
    now: Clock,
    schema: &[SegmentDecl],
    catalog: &mut Catalog,
    report: &mut GcReport,
) -> Result<(), StoreError> {
    prune(runtime, me, catalog, report)?;
    catalog.entries.sort_by_key(|e| (!old(e, now), e.used.now));
    let mut i = if catalog.capacity(1, 3, RESERVATION) {
        catalog.next as usize
    } else {
        0
    };
    while i < catalog.entries.len() {
        catalog.next = i as u32;
        let entry = catalog.entries[i].clone();
        if !entry_valid(&entry) {
            return Err(StoreError::Unsafe);
        }
        let parent = open_path(runtime, &entry.path[..entry.path.len() - 1], me)?;
        let name = entry.path.last().unwrap();
        let dir = match sys::open_dir_at_nofollow(parent.as_fd(), OsStr::new(name)) {
            Ok(dir) => dir,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                *catalog = Catalog::empty(runtime)?;
                return Ok(());
            }
            Err(e) => return Err(e.into()),
        };
        snapshot_store::check_directory(&dir, me)?;
        let stamp = sys::file_stamp(&dir)?;
        if (stamp.dev, stamp.ino) != (entry.dev, entry.ino) {
            *catalog = Catalog::empty(runtime)?;
            return Err(StoreError::Unsafe);
        }
        let lock = match collection_store::close_only_lock(&dir, LOCK, me, false) {
            Ok(lock) => Some(lock),
            Err(StoreError::Busy) => {
                i += 1;
                catalog.next = i as u32;
                continue;
            }
            Err(StoreError::Io(e)) if e.kind() == io::ErrorKind::NotFound && name == TOMBSTONE => {
                None
            }
            Err(e) => return Err(e),
        };
        report.visited += 1;
        // The inspection's lock would be a second OFD: inspect the contents
        // under this retained lock instead, with the same bounded checks.
        let mut actual_bytes = 0u64;
        let mut corrupt = false;
        let mut stream = sys::DirectoryCursor::open(dir.as_fd())?;
        while let Some(file_name) = stream.next()? {
            if file_name == "." || file_name == ".." {
                continue;
            }
            let file_name = file_name.to_str().ok_or(StoreError::Unsafe)?;
            if !FILES.contains(&file_name) {
                return Err(StoreError::Unsafe);
            }
            let Some((_, content)) = collection_store::read_checked(
                &dir,
                file_name,
                if file_name == LOCK { 0 } else { STREAM_MAX },
                me,
            )?
            else {
                return Err(StoreError::Unsafe);
            };
            actual_bytes += content.len() as u64;
            if file_name == RESPONSE || file_name == PREVIOUS {
                let Ok(response) = Completed::decode_with_catalog(&content, schema) else {
                    corrupt = true;
                    continue;
                };
                if !identity(&location(&entry.path)?, &response.binding)
                    || (!catalog.entries[i].cwd.is_empty()
                        && response.binding.cwd != catalog.entries[i].cwd)
                {
                    return Err(StoreError::Unsafe);
                }
                catalog.entries[i].cwd = response.binding.cwd;
            }
        }
        catalog.bytes = catalog
            .bytes
            .saturating_sub(entry.bytes)
            .saturating_add(actual_bytes);
        catalog.entries[i].bytes = actual_bytes;
        catalog.entries[i].reserved = false;
        let pressure = !catalog.capacity(1, 3, RESERVATION);
        if name != TOMBSTONE
            && !corrupt
            && !old(&entry, now)
            && !pressure
            && !catalog.entries[i].cwd.is_empty()
        {
            // Recover abandoned stage/request files only while locked.
            for file_name in [STAGE, collection_store::LEGACY_REQUEST] {
                let before = sys::at_stamp(dir.as_fd(), OsStr::new(file_name))
                    .ok()
                    .map_or(0, |s| s.size);
                if collection_store::remove_checked(&dir, file_name, STREAM_MAX, me)? {
                    report.removed_files += 1;
                    catalog.bytes = catalog.bytes.saturating_sub(before);
                    catalog.entries[i].bytes = catalog.entries[i].bytes.saturating_sub(before);
                }
            }
            i += 1;
            catalog.next = i as u32;
            continue;
        }
        #[cfg(test)]
        BEFORE_EVICTION.with(|hook| {
            if let Some(mut hook) = hook.borrow_mut().take() {
                hook();
            }
        });
        let parent_now = open_path(runtime, &entry.path[..entry.path.len() - 1], me)?;
        if sys::fd_facts(parent_now.as_fd())? != sys::fd_facts(parent.as_fd())? {
            return Err(StoreError::Unsafe);
        }
        snapshot_store::same_name(&dir, parent.as_fd(), name)?;
        if let Some(lock) = &lock {
            snapshot_store::same_name(lock, dir.as_fd(), LOCK)?;
        }
        if name != TOMBSTONE {
            if !sys::at_stamp(parent.as_fd(), OsStr::new(TOMBSTONE))
                .is_err_and(|e| e.kind() == io::ErrorKind::NotFound)
            {
                return Err(StoreError::Busy);
            }
            sys::rename_at(parent.as_fd(), OsStr::new(name), OsStr::new(TOMBSTONE))?;
            *catalog.entries[i].path.last_mut().unwrap() = TOMBSTONE.into();
        }
        snapshot_store::same_name(&dir, parent.as_fd(), TOMBSTONE)?;
        // Lock is last, after the public store name has disappeared. An
        // interrupted tombstone can never be reopened for a worker spawn.
        for file_name in FILES {
            if collection_store::remove_checked(
                &dir,
                file_name,
                if file_name == LOCK { 0 } else { STREAM_MAX },
                me,
            )? {
                report.removed_files += 1;
            }
        }
        sys::remove_dir_at(parent.as_fd(), OsStr::new(TOMBSTONE))?;
        report.removed_dirs += 1;
        catalog.bytes = catalog.bytes.saturating_sub(actual_bytes);
        catalog.stores = catalog.stores.saturating_sub(1);
        catalog.nodes = catalog.nodes.saturating_sub(1);
        catalog.entries.remove(i);
        catalog.next = i.min(catalog.entries.len()) as u32;
        drop(lock);
        catalog.prune = entry.path[..entry.path.len() - 1].to_vec();
        prune(runtime, me, catalog, report)?;
    }
    catalog.next = 0;
    Ok(())
}

// The suffix is checkpointed before its first removal, so a budget stop
// after deleting a store cannot strand its now-empty legacy ancestors.
fn prune(
    runtime: &File,
    me: u32,
    catalog: &mut Catalog,
    report: &mut GcReport,
) -> Result<(), StoreError> {
    while !catalog.prune.is_empty() {
        let depth = catalog.prune.len() - 1;
        let name = catalog.prune[depth].clone();
        let parent = open_path(runtime, &catalog.prune[..depth], me)?;
        let child = sys::open_dir_at_nofollow(parent.as_fd(), OsStr::new(&name))?;
        snapshot_store::check_directory(&child, me)?;
        snapshot_store::same_name(&child, parent.as_fd(), &name)?;
        match sys::remove_dir_at(parent.as_fd(), OsStr::new(&name)) {
            Ok(()) => {
                report.removed_dirs += 1;
                catalog.nodes = catalog.nodes.saturating_sub(1);
                catalog.prune.pop();
            }
            Err(e) if matches!(e.raw_os_error(), Some(libc::ENOTEMPTY | libc::EEXIST)) => {
                catalog.prune.clear();
                break;
            }
            Err(e) => return Err(e.into()),
        }
        if name == "collections-v1" {
            catalog.prune.clear();
        }
    }
    Ok(())
}

// A small checked binary catalog, independent of the worker wire. No input
// string is a filesystem path until the grammar and exact root bytes validate.
fn put_bytes(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), StoreError> {
    if out.len().saturating_add(4).saturating_add(bytes.len()) > CATALOG_MAX {
        return Err(StoreError::Unsafe);
    }
    out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}
fn put_clock(out: &mut Vec<u8>, clock: Clock) {
    out.extend_from_slice(&clock.boot);
    out.push(clock.kind);
    out.extend_from_slice(&clock.domain);
    out.extend_from_slice(&clock.resume.to_le_bytes());
    out.extend_from_slice(&clock.now.to_le_bytes());
}
fn encode(c: &Catalog) -> Result<Vec<u8>, StoreError> {
    let mut out = b"BNGCGC02\0\0\0\0".to_vec();
    for n in [c.dev, c.ino, c.stores, c.nodes, c.bytes] {
        out.extend_from_slice(&n.to_le_bytes());
    }
    out.extend_from_slice(&c.next.to_le_bytes());
    out.extend_from_slice(&[u8::from(c.ready), u8::from(c.unsafe_seen)]);
    out.extend_from_slice(&(c.entries.len() as u32).to_le_bytes());
    for e in &c.entries {
        out.extend_from_slice(&(e.path.len() as u32).to_le_bytes());
        for part in &e.path {
            put_bytes(&mut out, part.as_bytes())?;
        }
        put_bytes(&mut out, &e.cwd)?;
        for n in [e.dev, e.ino, e.bytes] {
            out.extend_from_slice(&n.to_le_bytes());
        }
        out.push(u8::from(e.reserved));
        put_clock(&mut out, e.used);
    }
    out.extend_from_slice(&(c.prune.len() as u32).to_le_bytes());
    for part in &c.prune {
        put_bytes(&mut out, part.as_bytes())?;
    }
    out.extend_from_slice(&(c.cursor.len() as u32).to_le_bytes());
    for cursor in &c.cursor {
        put_bytes(&mut out, cursor.name.as_bytes())?;
        put_bytes(&mut out, cursor.after.as_bytes())?;
        out.extend_from_slice(&cursor.dev.to_le_bytes());
        out.extend_from_slice(&cursor.ino.to_le_bytes());
    }
    out.extend_from_slice(&(c.unknown.len() as u32).to_le_bytes());
    for path in &c.unknown {
        out.extend_from_slice(&(path.len() as u32).to_le_bytes());
        for part in path {
            put_bytes(&mut out, part.as_bytes())?;
        }
    }
    if out.len() > CATALOG_MAX {
        return Err(StoreError::Unsafe);
    }
    let crc = snapshot::crc32c(&[&out[12..]]);
    out[8..12].copy_from_slice(&crc);
    Ok(out)
}
struct Reader<'a>(&'a [u8]);
impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], StoreError> {
        let out = self.0.get(..n).ok_or(StoreError::Unsafe)?;
        self.0 = &self.0[n..];
        Ok(out)
    }
    fn u64(&mut self) -> Result<u64, StoreError> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }
    fn count(&mut self, max: usize) -> Result<usize, StoreError> {
        let n = u32::from_le_bytes(self.take(4)?.try_into().unwrap()) as usize;
        if n > max {
            return Err(StoreError::Unsafe);
        }
        Ok(n)
    }
    fn flag(&mut self) -> Result<bool, StoreError> {
        match self.take(1)?[0] {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(StoreError::Unsafe),
        }
    }
    fn bytes(&mut self, cap: usize) -> Result<Vec<u8>, StoreError> {
        let n = self.count(cap)?;
        Ok(self.take(n)?.to_vec())
    }
    fn string(&mut self) -> Result<String, StoreError> {
        String::from_utf8(self.bytes(120)?).map_err(|_| StoreError::Unsafe)
    }
    fn clock(&mut self) -> Result<Clock, StoreError> {
        let boot = self.take(16)?.try_into().unwrap();
        let kind = self.take(1)?[0];
        let domain = self.take(16)?.try_into().unwrap();
        if !matches!(kind, 1 | 2) {
            return Err(StoreError::Unsafe);
        }
        Ok(Clock {
            boot,
            kind,
            domain,
            resume: self.u64()?,
            now: self.u64()?,
        })
    }
}
fn decode(bytes: &[u8]) -> Result<Catalog, StoreError> {
    if bytes.len() < 12
        || bytes.len() > CATALOG_MAX
        || &bytes[..8] != b"BNGCGC02"
        || snapshot::crc32c(&[&bytes[12..]]) != bytes[8..12]
    {
        return Err(StoreError::Unsafe);
    }
    let mut r = Reader(&bytes[12..]);
    let mut c = Catalog {
        dev: r.u64()?,
        ino: r.u64()?,
        stores: r.u64()?,
        nodes: r.u64()?,
        bytes: r.u64()?,
        next: r.count(MAX_STORES as usize)? as u32,
        ready: r.flag()?,
        unsafe_seen: r.flag()?,
        entries: vec![],
        prune: vec![],
        cursor: vec![],
        unknown: vec![],
    };
    let count = r.count(MAX_STORES as usize)?;
    for _ in 0..count {
        let count = r.count(MAX_DEPTH)?;
        let mut path = Vec::new();
        for _ in 0..count {
            let part = r.string()?;
            if !component(&part) {
                return Err(StoreError::Unsafe);
            }
            path.push(part);
        }
        let e = Entry {
            path,
            cwd: r.bytes(65_536)?,
            dev: r.u64()?,
            ino: r.u64()?,
            bytes: r.u64()?,
            reserved: r.flag()?,
            used: r.clock()?,
        };
        if !entry_valid(&e)
            || e.bytes > RESERVATION
            || c.entries.iter().any(|other| other.path == e.path)
        {
            return Err(StoreError::Unsafe);
        }
        c.entries.push(e);
    }
    let count = r.count(MAX_DEPTH)?;
    for _ in 0..count {
        c.prune.push(r.string()?);
    }
    if !c.prune.is_empty() {
        let mut path = c.prune.clone();
        if path.last().is_some_and(|n| n == "collections-v1") {
            path.push("0".repeat(64));
        }
        path.push("store".into());
        location(&path)?;
    }
    let count = r.count(MAX_DEPTH)?;
    let mut path = Vec::new();
    for i in 0..count {
        let cursor = Cursor {
            name: r.string()?,
            after: r.string()?,
            dev: r.u64()?,
            ino: r.u64()?,
        };
        if (i == 0 && !cursor.name.is_empty())
            || (i > 0 && !descend(&path, &cursor.name))
            || (!cursor.after.is_empty() && !component(&cursor.after))
        {
            return Err(StoreError::Unsafe);
        }
        if i > 0 {
            path.push(cursor.name.clone());
        }
        c.cursor.push(cursor);
    }
    let count = r.count(MAX_STORES as usize)?;
    for _ in 0..count {
        let count = r.count(MAX_SCAN_DEPTH)?;
        if count < 2 {
            return Err(StoreError::Unsafe);
        }
        let mut path = Vec::new();
        for _ in 0..count {
            let name = r.string()?;
            if !descend(&path, &name) {
                return Err(StoreError::Unsafe);
            }
            path.push(name);
        }
        c.unknown.push(path);
    }
    if c.next > c.entries.len() as u32
        || !r.0.is_empty()
        || c.ready != c.cursor.is_empty()
        || c.stores < c.entries.len() as u64
        || c.bytes < c.entries.iter().map(|e| e.bytes).sum::<u64>()
    {
        return Err(StoreError::Unsafe);
    }
    Ok(c)
}

#[cfg(test)]
thread_local! {
    static BEFORE_EVICTION: std::cell::RefCell<Option<Box<dyn FnMut()>>> = const { std::cell::RefCell::new(None) };
}
#[cfg(test)]
#[allow(dead_code, reason = "native parent/name replacement fixture")]
pub(crate) fn fixture_eviction_hook(hook: Box<dyn FnMut()>) {
    BEFORE_EVICTION.with(|slot| *slot.borrow_mut() = Some(hook));
}
