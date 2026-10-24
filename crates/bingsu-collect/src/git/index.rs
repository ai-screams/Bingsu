//! Bounded index input. Keep only the optional, bounded TREE cache and sparse
//! marker; other extension parsers cannot allocate or recurse through input.
use super::{RepoIo, UNSUPPORTED};
use crate::{meter::Meter, safe_read::ReadError};
use bingsu_core::collection::budget::{self, Axis};
use gix_index::hash::{self, Kind};

const INVALID: ReadError = ReadError::Io(libc::EINVAL);
pub(crate) const CACHE_DEPTH: usize = 64;

/// Framing only, before gix's recursive TREE decoder. In particular gix sorts
/// children, so check their original order here, before that evidence is lost.
/// Bad/too-deep optional caches are discarded, never evidence of staged-clean.
fn tree_reservation(mut bytes: &[u8]) -> Option<usize> {
    let mut stack = [(1usize, &b""[..]); CACHE_DEPTH];
    let mut depth = 0;
    let mut nodes = 0usize;
    let mut allocation = std::mem::size_of::<gix_index::extension::Tree>();
    while !bytes.is_empty() {
        let end = bytes.iter().position(|b| *b == 0)?;
        let name = &bytes[..end];
        let root = nodes == 0;
        if (root && !name.is_empty())
            || (!root && (name.is_empty() || name == b"." || name == b".." || name.contains(&b'/')))
            // Git's cache-tree.c subtree_name_cmp orders by length, then
            // memcmp. gix re-sorts decoded children by bytes for lookup.
            // Equality is a duplicate and must be rejected before decoding.
            || (!stack[depth].1.is_empty()
                && (stack[depth].1.len(), stack[depth].1) >= (name.len(), name))
        {
            return None;
        }
        stack[depth].1 = name;
        stack[depth].0 = stack[depth].0.checked_sub(1)?;
        bytes = &bytes[end + 1..];
        let end = bytes.iter().position(|b| *b == b' ')?;
        let entries = std::str::from_utf8(&bytes[..end])
            .ok()?
            .parse::<i32>()
            .ok()?;
        bytes = &bytes[end + 1..];
        let end = bytes.iter().position(|b| *b == b'\n')?;
        let children = std::str::from_utf8(&bytes[..end])
            .ok()?
            .parse::<usize>()
            .ok()?;
        bytes = bytes.get(end + 1 + if entries >= 0 { 20 } else { 0 }..)?;
        nodes += 1;
        if nodes > budget::INDEX_ENTRIES as usize || children > budget::INDEX_ENTRIES as usize {
            return None;
        }
        // Vec minimum capacity and stable-sort scratch, plus SmallVec names
        // rounded up by reserve(). Bound the aggregate, not one child Vec.
        allocation = allocation.checked_add(2 * name.len())?;
        if children != 0 {
            allocation = allocation.checked_add(
                2 * children.max(4) * std::mem::size_of::<gix_index::extension::Tree>(),
            )?;
            depth += 1;
            if depth == CACHE_DEPTH {
                return None;
            }
            stack[depth] = (children, b"");
        } else {
            while stack[depth].0 == 0 {
                if depth == 0 {
                    return bytes.is_empty().then_some(allocation);
                }
                depth -= 1;
            }
        }
    }
    None
}

pub fn load(io: &RepoIo<'_>) -> Result<gix_index::State, ReadError> {
    let (mut bytes, metadata) = match io.read_index() {
        Ok(input) => input,
        // A repository without an index is an empty staging area, including
        // unborn repositories. Other failures must never become empty/clean.
        Err(ReadError::Missing) => return Ok(gix_index::State::new(Kind::Sha1)),
        Err(error) => return Err(error),
    };
    let mut state = io.metered(|meter| parse(&mut bytes, meter))?;
    let secs = u64::try_from(metadata.st_mtime).map_err(|_| INVALID)?;
    let nanos = u32::try_from(metadata.st_mtime_nsec).map_err(|_| INVALID)?;
    if nanos >= 1_000_000_000 {
        return Err(INVALID);
    }
    let timestamp = std::time::UNIX_EPOCH
        .checked_add(std::time::Duration::new(secs, nanos))
        .ok_or(INVALID)?;
    state.set_timestamp(timestamp.into());
    Ok(state)
}

/// The expanded state owns its live reservations. Dropping it releases both
/// entry and path capacity, including on a failed expansion.
pub struct ExpandedIndex {
    state: gix_index::State,
    entries: crate::meter::PathAllocation,
    paths: crate::meter::PathAllocation,
    entry_capacity: usize,
}
impl std::ops::Deref for ExpandedIndex {
    type Target = gix_index::State;
    fn deref(&self) -> &Self::Target {
        &self.state
    }
}
impl ExpandedIndex {
    fn push(
        &mut self,
        io: &RepoIo<'_>,
        stat: gix_index::entry::Stat,
        id: hash::ObjectId,
        flags: gix_index::entry::Flags,
        mode: gix_index::entry::Mode,
        path: &[u8],
    ) -> Result<(), ReadError> {
        // gix-index 0.56 appends entries with Vec::push (capacity doubles).
        // The pinned decoder's initial capacity is recorded below. Reserve
        // the NEW capacity while the old allocation is still live, and release
        // the old reservation as soon as the push has finished reallocating.
        // Original decoded capacity is already covered by parse's reservation.
        let growing = self.state.entries().len() == self.entry_capacity;
        let next = if growing {
            (2 * self.entry_capacity).max(4)
        } else {
            self.entry_capacity
        };
        let replacement = if growing {
            Some(io.account(|m| {
                let mut a = m.path_allocation();
                a.reserve(next * std::mem::size_of::<gix_index::Entry>(), m)?;
                Ok(a)
            })?)
        } else {
            None
        };
        // PathStorage is a public Vec: reserve explicitly, inspect its real
        // capacity, and return it even on error. No per-leaf cumulative charge.
        let mut backing = self.state.take_path_backing();
        let reserved = (|| {
            let needed = backing
                .len()
                .checked_add(path.len())
                .ok_or(ReadError::Limit)?;
            if needed > backing.capacity() {
                let capacity = needed.max(backing.capacity() * 2).max(4096);
                let allocation = io.account(|m| {
                    let mut a = m.path_allocation();
                    a.reserve(capacity, m)?;
                    Ok(a)
                })?;
                backing
                    .try_reserve_exact(capacity - backing.len())
                    .map_err(|_| ReadError::Limit)?;
                self.paths = allocation;
            }
            Ok(())
        })();
        self.state.return_path_backing(backing);
        reserved?;
        self.state
            .dangerously_push_entry(stat, id, flags, mode, path.into());
        if let Some(allocation) = replacement {
            self.entries = allocation;
            self.entry_capacity = next;
        }
        Ok(())
    }
}

/// Expand only tree objects, never sparse worktree paths. Both the original
/// index and every derived entry/path consume the same request's index axes.
/// Build an owned result so reservations cannot outlive or precede its state.
pub fn expand_sparse(
    repo: &crate::git::GuardedRepository<'_>,
    state: gix_index::State,
) -> Result<ExpandedIndex, ReadError> {
    use gix_index::entry::Flags;
    let io = &repo.io;
    io.account(|m| validate(&state, m))?;
    let (entries, paths) = io.account(|m| Ok((m.path_allocation(), m.path_allocation())))?;
    let mut expanded = ExpandedIndex {
        state: gix_index::State::new(Kind::Sha1),
        entries,
        paths,
        entry_capacity: 0,
    };
    if !state.entries().iter().any(|e| e.mode.is_sparse()) {
        expanded.state = state;
        return Ok(expanded);
    }
    // load() uses gix's single-thread decoder: an empty Entry Vec reserves
    // the declared count once (minimum four). Only this module appends during
    // expansion, so its actual capacity is known without a private gix API.
    expanded.entry_capacity = state.entries().len().max(4);
    expanded.state = state;
    let original = expanded.entries().len();
    let db = repo.objects(io);
    for i in 0..original {
        let entry = &expanded.entries()[i];
        if !entry.mode.is_sparse() {
            continue;
        }
        if entry.stage_raw() != 0 || !entry.flags.contains(Flags::SKIP_WORKTREE) {
            return Err(INVALID);
        }
        let id = entry.id;
        let mut scratch = io.account(|m| Ok(m.path_allocation()))?;
        let path = entry.path(&expanded);
        io.account(|m| scratch.reserve(path.len(), m))?;
        let prefix = path.to_vec();
        let before = expanded.entries().len();
        expand_tree(io, &db, &mut expanded, &prefix, id, 0)?;
        let added = expanded.entries().len() - before;
        if let Some(tree) = expanded.state.tree_mut() {
            // Expansion replaces one placeholder with exactly these leaves.
            // Preserve cache OIDs and invalidation; shift existing counts by
            // the same delta as the index ranges, never repair a bad count.
            expand_cache_counts(tree, &prefix, added as i32 - 1);
        }
    }
    expanded.state.remove_entries(|_, _, e| e.mode.is_sparse());
    // In-place ordering needs no full-entry sort scratch.
    let (entries, paths) = expanded.state.entries_mut_and_pathbacking();
    entries.sort_unstable_by(|a, b| {
        a.path_in(paths)
            .cmp(b.path_in(paths))
            .then_with(|| a.stage_raw().cmp(&b.stage_raw()))
    });
    io.account(|m| {
        if expanded.entries().len() > budget::INDEX_ENTRIES as usize
            || expanded.path_backing().len() > budget::INDEX_BYTES as usize
        {
            return Err(ReadError::Limit);
        }
        validate(&expanded, m)
    })?;
    Ok(expanded)
}

fn expand_cache_counts(tree: &mut gix_index::extension::Tree, mut path: &[u8], delta: i32) {
    let mut tree = tree;
    loop {
        tree.num_entries = tree.num_entries.and_then(|n| n.checked_add_signed(delta));
        let Some(end) = path.iter().position(|b| *b == b'/') else {
            break;
        };
        let Some(child) = tree
            .children
            .iter_mut()
            .find(|c| c.name.as_slice() == &path[..end])
        else {
            break;
        };
        tree = child;
        path = &path[end + 1..];
    }
}

fn expand_tree(
    io: &RepoIo<'_>,
    db: &super::objects::SafeObjectDb<'_>,
    state: &mut ExpandedIndex,
    prefix: &[u8],
    id: hash::ObjectId,
    depth: usize,
) -> Result<(), ReadError> {
    use gix_index::entry::{Flags, Mode, Stat};
    use gix_object::tree::EntryKind;
    io.account(|m| {
        if depth >= CACHE_DEPTH
            || m.budget.used(Axis::IndexEntries) == budget::INDEX_ENTRIES
            || m.budget.used(Axis::IndexBytes) == budget::INDEX_BYTES
        {
            return Err(ReadError::Limit);
        }
        Ok(())
    })?;
    let mut buffer = Vec::new();
    let mut children = Vec::new();
    let mut scratch = io.account(|m| Ok(m.path_allocation()))?;
    let mut previous = None;
    for entry in db.tree(&id, &mut buffer)? {
        let entry = entry.map_err(|_| INVALID)?;
        if previous.is_some_and(|p: gix_object::tree::EntryRef<'_>| {
            p >= entry || p.filename == entry.filename
        }) {
            return Err(INVALID);
        }
        previous = Some(entry);
        let length = prefix
            .len()
            .checked_add(entry.filename.len())
            .ok_or(ReadError::Limit)?;
        let directory = entry.mode.is_tree();
        io.account(|m| {
            if length >= budget::SMALL_FILE_BYTES as usize {
                return Err(ReadError::Limit);
            }
            // tree() charged the leaf name and one entry before returning it.
            m.charge_axis(
                Axis::IndexBytes,
                (prefix.len() + usize::from(directory)) as u64,
            )?;
            if directory {
                scratch.reserve(length + 1, m)?;
                // Vec geometric capacity plus its possible old allocation.
                scratch.reserve(3 * std::mem::size_of::<(Vec<u8>, hash::ObjectId)>(), m)
            } else {
                Ok(())
            }
        })?;
        let _path_scratch = io.account(|m| {
            let mut s = m.path_allocation();
            if !directory {
                s.reserve(length + 1, m)?;
            }
            Ok(s)
        })?;
        let mut path = Vec::with_capacity(length + 1);
        path.extend_from_slice(prefix);
        path.extend_from_slice(entry.filename);
        if directory {
            path.push(b'/');
            children.push((path, entry.oid.to_owned()));
        } else {
            let mode = match entry.mode.kind() {
                EntryKind::Blob => Mode::FILE,
                EntryKind::BlobExecutable => Mode::FILE_EXECUTABLE,
                EntryKind::Link => Mode::SYMLINK,
                EntryKind::Commit => Mode::COMMIT,
                _ => return Err(INVALID),
            };
            state.push(
                io,
                Stat::default(),
                entry.oid.to_owned(),
                Flags::SKIP_WORKTREE,
                mode,
                &path,
            )?;
        }
    }
    // Release the decoded parent before looking up a child (the object adapter
    // owns one live scratch slot). Retain only bounded child paths and OIDs.
    drop(buffer);
    for (path, id) in children {
        expand_tree(io, db, state, &path, id, depth + 1)?;
    }
    Ok(())
}

pub(crate) fn checksum(bytes: &[u8]) -> Result<(), ReadError> {
    let end = bytes.len().checked_sub(20).ok_or(INVALID)?;
    let mut digest = hash::hasher(Kind::Sha1);
    digest.update(&bytes[..end]);
    if digest.try_finalize().map_err(|_| INVALID)?.as_slice() != &bytes[end..] {
        return Err(INVALID);
    }
    Ok(())
}

fn u32_at(bytes: &[u8], offset: usize) -> Result<usize, ReadError> {
    Ok(u32::from_be_bytes(
        bytes
            .get(offset..offset + 4)
            .ok_or(INVALID)?
            .try_into()
            .map_err(|_| INVALID)?,
    ) as usize)
}

/// A framing/size pass only: gix still interprets all entry fields. V4's path
/// expansion is counted before its unchecked Vec growth. No path copies here.
pub(crate) fn parse(bytes: &mut [u8], meter: &mut Meter) -> Result<gix_index::State, ReadError> {
    meter.check()?;
    if bytes.len() > budget::INDEX_BYTES as usize {
        return Err(ReadError::Limit);
    }
    if bytes.len() < 32 || &bytes[..4] != b"DIRC" {
        return Err(INVALID);
    }
    let version = u32_at(bytes, 4)?;
    if !(2..=4).contains(&version) {
        return Err(UNSUPPORTED);
    }
    let entries = u32_at(bytes, 8)?;
    meter.charge_axis(Axis::IndexEntries, entries as u64)?;
    // Git's skipHash is allowed for the ordinary index, never a shared index.
    if bytes[bytes.len() - 20..].iter().any(|b| *b != 0) {
        checksum(bytes)?;
    }
    let end = bytes.len() - 20;
    let mut pos = 12usize;
    let mut previous = 0usize;
    let mut paths = 0usize;
    let mut longest = 0usize;
    for _ in 0..entries {
        meter.check()?;
        let start = pos;
        let fixed = bytes.get(pos..pos + 62).ok_or(INVALID)?;
        let flags = u16::from_be_bytes([fixed[60], fixed[61]]);
        pos += 62;
        if flags & 0x4000 != 0 {
            pos += 2;
        }
        let mut prefix = 0;
        if version == 4 {
            let mut strip = 0usize;
            loop {
                let byte = *bytes.get(pos).ok_or(INVALID)?;
                pos += 1;
                strip = strip
                    .checked_mul(128)
                    .and_then(|n| n.checked_add((byte & 127) as usize))
                    .ok_or(INVALID)?;
                if byte & 128 == 0 {
                    break;
                }
                strip = strip.checked_add(1).ok_or(INVALID)?;
            }
            prefix = previous.checked_sub(strip).ok_or(INVALID)?;
        }
        let suffix = bytes
            .get(pos..end)
            .ok_or(INVALID)?
            .iter()
            .position(|b| *b == 0)
            .ok_or(INVALID)?;
        let length = prefix.checked_add(suffix).ok_or(ReadError::Limit)?;
        if length > budget::SMALL_FILE_BYTES as usize {
            return Err(ReadError::Limit);
        }
        paths = paths.checked_add(length).ok_or(ReadError::Limit)?;
        if paths > budget::INDEX_BYTES as usize {
            return Err(ReadError::Limit);
        }
        longest = longest.max(length);
        previous = length;
        pos += suffix + 1;
        if version < 4 {
            if flags & 0xfff != 0xfff && usize::from(flags & 0xfff) != suffix {
                return Err(INVALID);
            }
            // Match gix 0.56's long-path framing; otherwise use Git's padding.
            if flags & 0xfff != 0xfff {
                pos = start + (pos - start).next_multiple_of(8);
            }
        }
        if pos > end {
            return Err(INVALID);
        }
    }
    meter.charge_axis(Axis::IndexBytes, paths as u64)?;
    let entry_end = pos;
    let mut sparse = false;
    let mut tree = None;
    let mut trees = 0;
    // Reject split indexes as B Partial before bitmap decoding. In particular,
    // do not ever follow link with gix_index::File or regard it as an empty index.
    while pos < end {
        let signature: [u8; 4] = bytes
            .get(pos..pos + 4)
            .ok_or(INVALID)?
            .try_into()
            .map_err(|_| INVALID)?;
        let size = u32_at(bytes, pos + 4)?;
        let next = pos
            .checked_add(8)
            .and_then(|p| p.checked_add(size))
            .filter(|p| *p <= end)
            .ok_or(INVALID)?;
        if &signature == b"link" {
            return Err(UNSUPPORTED);
        }
        if &signature == b"TREE" {
            trees += 1;
            tree =
                tree_reservation(&bytes[pos + 8..next]).map(|reservation| (pos..next, reservation));
        }
        if &signature == b"sdir" {
            if size != 0 {
                return Err(INVALID);
            }
            sparse = true;
        } else if !signature[0].is_ascii_uppercase() {
            return Err(UNSUPPORTED);
        }

        pos = next;
    }
    if trees != 1 {
        tree = None;
    }
    let tree_bytes = tree.as_ref().map_or(0, |(range, _)| range.len());
    let tree_allocation = tree.as_ref().map_or(0, |(_, reservation)| *reservation);
    // gix estimates path capacity from the entire supplied slice, extensions
    // included. Charge that estimate as well as bounded TREE decoding scratch.
    let backing = paths.max(entry_end.saturating_sub(12 + entries * 62) + tree_bytes);
    let reservation = entries
        .checked_mul(std::mem::size_of::<gix_index::Entry>())
        .and_then(|n| n.checked_add(3 * backing + 3 * longest + tree_allocation + 4096))
        .ok_or(ReadError::Limit)?;
    meter.allocation(reservation)?;
    // Compact the same safe-read bytes only after checking the original hash.
    // No second pathname read and no independent cache-tree object parser.
    if let Some((range, _)) = tree {
        bytes.copy_within(range, entry_end);
    }
    let mut parser_end = entry_end + tree_bytes;
    if sparse {
        bytes[parser_end..parser_end + 8].copy_from_slice(b"sdir\0\0\0\0");
        parser_end += 8;
    }
    bytes[parser_end..parser_end + 20].fill(0);
    let (state, _) = gix_index::State::from_bytes(
        &bytes[..parser_end + 20],
        std::time::UNIX_EPOCH.into(),
        Kind::Sha1,
        gix_index::decode::Options {
            thread_limit: Some(1),
            alloc_limit_bytes: Some(reservation),
            ..Default::default()
        },
    )
    .map_err(|_| INVALID)?;
    validate(&state, meter)?;
    Ok(state)
}

/// Also validate caller-supplied (including later sparse-expanded) states.
pub(crate) fn validate(state: &gix_index::State, meter: &mut Meter) -> Result<(), ReadError> {
    let mut last = None;
    let has_gitlinks = state
        .entries()
        .iter()
        .any(|e| e.mode == gix_index::entry::Mode::COMMIT);
    for entry in state.entries() {
        meter.check()?;
        let path: &[u8] = entry.path(state).as_ref();
        if path.is_empty()
            || path.contains(&0)
            || path
                .split(|b| *b == b'/')
                .any(|p| p == b".." || p == b"." || p.is_empty())
        {
            // Sparse directory entries have exactly one trailing slash.
            if !entry.mode.is_sparse()
                || path.len() < 2
                || !path.ends_with(b"/")
                || path[..path.len() - 1]
                    .split(|b| *b == b'/')
                    .any(|p| p.is_empty() || p == b"." || p == b"..")
            {
                return Err(INVALID);
            }
        }
        let key = (path, entry.stage_raw());
        if last.is_some_and(|previous| previous >= key) {
            return Err(INVALID);
        }
        if last.is_some_and(|(previous, stage)| previous == path && stage == 0) {
            return Err(INVALID);
        }
        // A gitlink cannot own index children. Ordinary conflicted file/directory
        // pairs can coexist and must still count as distinct conflict paths.
        // Checking every ancestor also catches sub, sub-foo, sub/x ordering.
        for (end, _) in path
            .iter()
            .enumerate()
            .filter(|(_, b)| has_gitlinks && **b == b'/')
        {
            let ancestor = &path[..end];
            let i = state
                .entries()
                .partition_point(|e| e.path(state) < ancestor);
            if state.entries()[i..]
                .iter()
                .take_while(|e| e.path(state) == ancestor)
                .any(|e| e.mode == gix_index::entry::Mode::COMMIT)
            {
                return Err(INVALID);
            }
        }
        last = Some(key);
    }
    Ok(())
}
