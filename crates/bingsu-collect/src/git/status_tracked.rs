//! Bounded, read-only tracked comparison. All I/O belongs to the shared RepoIo;
//! no rename detection, index refresh, submodule traversal or git subprocess.
use super::{
    GuardedRepository,
    io::{
        RepoIo, RepoPath, RootId, UNSUPPORTED, index,
        policy::{PatternKind, Patterns, Policies},
        worktree::{self, Comparison},
    },
};
use crate::{meter::PathAllocation, safe_read::ReadError};
use bingsu_core::{
    collection::budget::{self, Axis},
    field::{Field, FieldValue},
};
use gix_index::{
    State,
    entry::{Flags, Mode},
    hash::ObjectId,
};

const INVALID: ReadError = ReadError::Io(libc::EINVAL);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StatusCounts {
    pub staged: Field,
    pub modified: Field,
    pub untracked: Field,
    pub conflicted: Field,
    /// Provisional until modified comparison completes; Stage B also requires
    /// a complete shared walk before publishing this as a known Bool.
    pub filtered: bool,
}
impl Default for StatusCounts {
    fn default() -> Self {
        Self {
            staged: Field::PENDING,
            modified: Field::PENDING,
            untracked: Field::PENDING,
            conflicted: Field::PENDING,
            filtered: false,
        }
    }
}
fn count(n: u32) -> Field {
    Field::known(FieldValue::Count {
        n,
        saturated: false,
    })
}

/// Split, corrupt, inaccessible and over-budget inputs remain Pending. Missing
/// ordinary index is explicitly empty; index::load never follows a split link.
pub fn load_status(repo: &GuardedRepository<'_>) -> StatusCounts {
    match index::load(&repo.io) {
        Ok(index) => tracked_status(repo, &index),
        Err(_) => StatusCounts::default(),
    }
}

/// Caller supplies C3's bounded state (D1b may expand sparse entries first).
/// Callers editing entries must invalidate/remove their cache-tree as Git does.
/// Preflight/ownership and the B deadline are the caller's responsibility.
/// Exact independent counts survive later failure; untracked belongs to D1b.
pub fn tracked_status(repo: &GuardedRepository<'_>, index: &State) -> StatusCounts {
    let (mut result, policies) = index_counts(repo, index);
    if let Some(policies) = policies
        && let Ok(n) = modified(&repo.io, index, policies, &mut result.filtered)
    {
        result.modified = count(n);
    }
    result
}

/// D1b supplies modified and untracked from one shared worktree scan.
pub(crate) fn index_status(
    repo: &GuardedRepository<'_>,
    index: &index::ExpandedIndex,
) -> StatusCounts {
    index_counts_validated(repo, index).0
}

fn index_counts(repo: &GuardedRepository<'_>, index: &State) -> (StatusCounts, Option<Policies>) {
    let io = &repo.io;
    if io.account(|m| index::validate(index, m)).is_err() {
        return (StatusCounts::default(), None);
    }
    index_counts_validated(repo, index)
}

fn index_counts_validated(
    repo: &GuardedRepository<'_>,
    index: &State,
) -> (StatusCounts, Option<Policies>) {
    let mut result = StatusCounts::default();
    let mut conflicts = 0;
    let mut previous = None;
    for entry in index.entries() {
        if entry.stage_raw() != 0 && previous != Some(entry.path(index)) {
            conflicts += 1;
        }
        previous = Some(entry.path(index));
    }
    result.conflicted = count(conflicts);
    // Never treat a sparse directory's tree OID as a tracked file.
    if index.entries().iter().any(|e| e.mode.is_sparse()) {
        return (result, None);
    }
    let policies = match Policies::from_config(&repo.config) {
        Ok(p) => p,
        Err(_) => return (result, None),
    };
    match staged(repo, index) {
        Ok(n) => result.staged = count(n),
        Err(ReadError::Limit | ReadError::Deadline) => return (result, None),
        Err(_) => {}
    }
    (result, Some(policies))
}

struct TreeEntry {
    path: Vec<u8>,
    id: ObjectId,
    mode: Mode,
}

struct HeadEntries {
    entries: Vec<TreeEntry>,
    clean: Vec<std::ops::Range<usize>>,
    _allocation: PathAllocation,
}

// Derive ranges from sorted index paths, never from the cache's claimed count.
fn index_range(index: &State, prefix: &[u8]) -> std::ops::Range<usize> {
    let entries = index.entries();
    let start = entries.partition_point(|e| e.path(index) < prefix);
    let length = entries[start..].partition_point(|e| e.path(index).starts_with(prefix));
    start..start + length
}

fn cache_shape(tree: &gix_index::extension::Tree, range: &std::ops::Range<usize>) -> bool {
    tree.num_entries.is_none_or(|n| n as usize == range.len())
        && tree.children.iter().all(|child| {
            !child.name.is_empty()
                && child.name.as_slice() != b"."
                && child.name.as_slice() != b".."
                && !child.name.contains(&b'/')
                && !child.name.contains(&0)
        })
        && tree
            .children
            .windows(2)
            .all(|pair| pair[0].name < pair[1].name)
}

#[derive(Clone, Copy, Default)]
struct CacheNode {
    shape: bool,
    consistent: bool,
    children: usize,
}

/// One result per TREE node, with contiguous slots for each sibling group.
/// Compute descendants even below an invalidated parent: valid siblings must
/// remain reusable. A bad deepest node must not cause repeated subtree scans.
struct CacheConsistency {
    nodes: Vec<CacheNode>,
    allocation: PathAllocation,
}
fn cache_consistency(
    io: &RepoIo<'_>,
    index: &State,
    tree: &gix_index::extension::Tree,
    prefix: &[u8],
    depth: usize,
    slot: usize,
    memo: &mut CacheConsistency,
) -> Result<(), ReadError> {
    #[cfg(test)]
    observations::consistency_call();
    io.account(|m| m.check())?;
    if depth >= index::CACHE_DEPTH || !cache_shape(tree, &index_range(index, prefix)) {
        return Ok(());
    }
    // parse() already caps the TREE node count. Keep the same bound for
    // callers supplying an edited State, and charge all memo capacity live.
    if tree.children.len() > budget::INDEX_ENTRIES as usize - memo.nodes.len() {
        return Err(ReadError::Limit);
    }
    let children = memo.nodes.len();
    for _ in &tree.children {
        push(
            io,
            &mut memo.allocation,
            &mut memo.nodes,
            CacheNode::default(),
        )?;
    }
    let mut consistent = tree.num_entries.is_some();
    for (i, child) in tree.children.iter().enumerate() {
        let length = prefix.len() + child.name.len() + 1;
        if length > budget::SMALL_FILE_BYTES as usize {
            consistent = false;
            continue;
        }
        let _scratch = io.account(|m| {
            let mut scratch = m.path_allocation();
            scratch.reserve(length, m)?;
            Ok(scratch)
        })?;
        let mut path = Vec::with_capacity(length);
        path.extend_from_slice(prefix);
        path.extend_from_slice(&child.name);
        path.push(b'/');
        cache_consistency(io, index, child, &path, depth + 1, children + i, memo)?;
        consistent &= memo.nodes[children + i].consistent;
    }
    memo.nodes[slot] = CacheNode {
        shape: true,
        consistent,
        children,
    };
    Ok(())
}

/// Capacity growth is charged before reserve; no per-entry scratch survives
/// the object it describes. Sorting is in memory and uses no extra buffer.
fn push<T>(
    io: &RepoIo<'_>,
    allocation: &mut PathAllocation,
    entries: &mut Vec<T>,
    value: T,
) -> Result<(), ReadError> {
    if entries.len() == entries.capacity() {
        let extra = entries.capacity().max(16);
        let _growth = io.account(|m| {
            allocation.reserve(extra * std::mem::size_of::<T>(), m)?;
            let mut growth = m.path_allocation();
            growth.reserve(entries.capacity() * std::mem::size_of::<T>(), m)?;
            Ok(growth)
        })?;
        entries
            .try_reserve_exact(extra)
            .map_err(|_| ReadError::Limit)?;
    }
    entries.push(value);
    Ok(())
}
fn head_entries(repo: &GuardedRepository<'_>, index: &State) -> Result<HeadEntries, ReadError> {
    let io = &repo.io;
    let mut entries = Vec::new();
    let mut allocation = io.account(|m| Ok(m.path_allocation()))?;
    let mut clean = Vec::new();
    let Some(head) = repo.refs.resolve(io, b"HEAD")? else {
        return Ok(HeadEntries {
            entries,
            clean,
            _allocation: allocation,
        });
    };
    let db = repo.objects(io);
    #[cfg(test)]
    observations::find(false);
    let tree = db.head_tree(&head)?;
    let cache = index.tree().filter(|t| t.name.is_empty());
    let mut memo = CacheConsistency {
        nodes: Vec::new(),
        allocation: io.account(|m| Ok(m.path_allocation()))?,
    };
    if let Some(cache) = cache {
        push(
            io,
            &mut memo.allocation,
            &mut memo.nodes,
            CacheNode::default(),
        )?;
        cache_consistency(io, index, cache, b"", 0, 0, &mut memo)?;
    }
    let mut pending = Vec::new();
    let root_allocation = io.account(|m| Ok(m.path_allocation()))?;
    push(
        io,
        &mut allocation,
        &mut pending,
        (
            Vec::<u8>::new(),
            tree,
            cache.map(|t| (t, 0)),
            root_allocation,
        ),
    )?;
    let mut buffer = Vec::new();
    let mut cached_id = None;
    while let Some((prefix, id, cache, _prefix_allocation)) = pending.pop() {
        let range = index_range(index, &prefix);
        let cache = cache.filter(|(_, slot)| memo.nodes[*slot].shape);
        if let Some((cache, slot)) = cache
            && memo.nodes[slot].consistent
            && cache.id == id
            && index.entries()[range.clone()]
                .iter()
                .all(|e| e.stage_raw() == 0 && !e.flags.contains(Flags::INTENT_TO_ADD))
        {
            // Like Git, trust the structurally checked cache OID. Re-hashing
            // entries would undo this optimization. A hostile index can hide
            // its own staged changes, not worktree changes or conflict/ITA
            // flags, and gains no I/O authority. Never read this HEAD subtree.
            push(io, &mut allocation, &mut clean, range)?;
            continue;
        }
        let cached = cached_id == Some(id);
        let tree = if cached {
            gix_object::TreeRefIter::from_bytes(&buffer, gix_index::hash::Kind::Sha1)
        } else {
            cached_id = Some(id);
            #[cfg(test)]
            observations::find(true);
            db.tree(&id, &mut buffer)?
        };
        let mut previous = None;
        for entry in tree {
            let entry = entry.map_err(|_| INVALID)?;
            if cached {
                // The immutable last decoded object can be reused, but each
                // expanded tree entry still consumes the shared index budget.
                io.account(|m| {
                    m.charge_axis(Axis::IndexEntries, 1)?;
                    m.charge_axis(Axis::IndexBytes, entry.filename.len() as u64)
                })?;
            }
            if previous.is_some_and(|p: gix_object::tree::EntryRef<'_>| {
                p >= entry || p.filename == entry.filename
            }) {
                return Err(INVALID);
            }
            previous = Some(entry);
            let name: &[u8] = entry.filename.as_ref();
            let length = prefix
                .len()
                .checked_add(name.len())
                .ok_or(ReadError::Limit)?;
            if length > budget::SMALL_FILE_BYTES as usize {
                return Err(ReadError::Limit);
            }
            // tree() already charged the leaf name and entry; charge the joined
            // prefix and actual retained allocation before constructing it.
            let prefix_allocation = io.account(|m| {
                m.charge_axis(Axis::IndexBytes, prefix.len() as u64)?;
                let mut pending = m.path_allocation();
                if entry.mode.is_tree() {
                    pending.reserve(length + 1, m)?;
                } else {
                    allocation.reserve(length + 1, m)?;
                }
                Ok(pending)
            })?;
            let mut path = Vec::with_capacity(length + 1);
            path.extend_from_slice(&prefix);
            path.extend_from_slice(name);
            if entry.mode.is_tree() {
                path.push(b'/');
                let child_cache = cache.and_then(|(tree, slot)| {
                    tree.children
                        .binary_search_by(|child| child.name.as_slice().cmp(name))
                        .ok()
                        .map(|i| (&tree.children[i], memo.nodes[slot].children + i))
                });
                push(
                    io,
                    &mut allocation,
                    &mut pending,
                    (path, entry.oid.to_owned(), child_cache, prefix_allocation),
                )?;
            } else {
                let mode = match entry.mode.kind() {
                    gix_object::tree::EntryKind::Blob => Mode::FILE,
                    gix_object::tree::EntryKind::BlobExecutable => Mode::FILE_EXECUTABLE,
                    gix_object::tree::EntryKind::Link => Mode::SYMLINK,
                    gix_object::tree::EntryKind::Commit => Mode::COMMIT,
                    _ => return Err(INVALID),
                };
                push(
                    io,
                    &mut allocation,
                    &mut entries,
                    TreeEntry {
                        path,
                        id: entry.oid.to_owned(),
                        mode,
                    },
                )?;
            }
        }
    }
    io.account(|m| m.check())?;
    entries.sort_unstable_by(|a, b| a.path.cmp(&b.path));
    clean.sort_unstable_by_key(|range| range.start);
    if entries.windows(2).any(|p| p[0].path == p[1].path) {
        return Err(INVALID);
    }
    io.account(|m| m.check())?;
    Ok(HeadEntries {
        entries,
        clean,
        _allocation: allocation,
    })
}
fn staged(repo: &GuardedRepository<'_>, index: &State) -> Result<u32, ReadError> {
    let HeadEntries {
        entries: head,
        clean,
        _allocation,
    } = head_entries(repo, index)?;
    let mut clean = clean.iter().peekable();
    let mut h = 0;
    let mut n = 0;
    let mut i = 0;
    while i < index.entries().len() {
        repo.io.account(|m| m.check())?;
        while clean.peek().is_some_and(|range| range.end <= i) {
            clean.next();
        }
        if let Some(range) = clean.peek()
            && range.start == i
        {
            i = range.end;
            continue;
        }
        let entry = &index.entries()[i];
        let path: &[u8] = entry.path(index).as_ref();
        while h < head.len() && head[h].path.as_slice() < path {
            n += u32::from(head[h].mode != Mode::COMMIT);
            h += 1;
        }
        let old = head.get(h).filter(|e| e.path == path);
        let conflict = entry.stage_raw() != 0;
        if !conflict {
            // ITA is absent from the staging area (porcelain-v2 default).
            let changed = if entry.flags.contains(Flags::INTENT_TO_ADD) {
                old.is_some_and(|old| old.mode != Mode::COMMIT)
            } else {
                old.map_or(entry.mode != Mode::COMMIT, |old| {
                    old.mode != entry.mode || (entry.mode != Mode::COMMIT && old.id != entry.id)
                })
            };
            n += u32::from(changed);
        }
        h += usize::from(old.is_some());
        i += 1;
        while i < index.entries().len() && index.entries()[i].path(index) == path {
            i += 1;
        }
    }
    // --ignore-submodules=all ignores absent <-> gitlink and gitlink OID
    // changes, but a gitlink <-> ordinary entry type change still counts.
    n += head[h..].iter().filter(|e| e.mode != Mode::COMMIT).count() as u32;
    Ok(n)
}
fn split(path: &[u8]) -> (&[u8], &[u8]) {
    path.iter()
        .rposition(|b| *b == b'/')
        .map_or((b"", path), |i| (&path[..i], &path[i + 1..]))
}
fn attributes(io: &RepoIo<'_>, patterns: &mut Patterns, parent: &[u8]) -> Result<(), ReadError> {
    let _scratch = io.account(|m| {
        let mut s = m.path_allocation();
        s.reserve(2 * (parent.len() + 16), m)?;
        Ok(s)
    })?;
    let mut path = Vec::with_capacity(parent.len() + 16);
    path.extend_from_slice(parent);
    if !path.is_empty() {
        path.push(b'/');
    }
    path.extend_from_slice(b".gitattributes");
    match io.worktree_metadata(&path) {
        Ok(metadata) if metadata.st_mode & libc::S_IFMT == libc::S_IFREG => patterns.add(
            io,
            RepoPath::new(RootId::Worktree, &path),
            PatternKind::Attributes,
        ),
        // Git ignores symlinked attributes; never read their target. Other
        // kinds (including directories) still leave the result unresolved.
        Ok(metadata) if metadata.st_mode & libc::S_IFMT == libc::S_IFLNK => Ok(()),
        Ok(_) | Err(ReadError::Symlink) => Err(UNSUPPORTED),
        Err(ReadError::Missing) => Ok(()),
        Err(error) => Err(error),
    }?;
    // Keep the path reservation until its owned bytes are no longer needed.
    Ok(())
}
/// Directory groups alone cannot see aliases in different parent spellings.
/// Normalize comparison keys only; all actual I/O still uses raw index bytes.
fn unique_names(io: &RepoIo<'_>, index: &State, policies: Policies) -> Result<(), ReadError> {
    let names = policies.names;
    let changes = |p: &[u8]| {
        (names.ignore_case && p.iter().any(u8::is_ascii_uppercase))
            || (names.precompose() && !p.is_ascii())
    };
    if !index
        .entries()
        .iter()
        .any(|e| changes(e.path(index).as_ref()))
    {
        return Ok(());
    }
    let _scratch = io.account(|m| {
        let bytes = index
            .entries()
            .iter()
            .filter(|e| changes(e.path(index).as_ref()))
            .try_fold(0usize, |n, e| {
                n.checked_add(e.path(index).len()).ok_or(ReadError::Limit)
            })?;
        let mut s = m.path_allocation();
        s.reserve(
            bytes
                .checked_mul(33)
                .and_then(|n| {
                    n.checked_add(
                        index.entries().len() * std::mem::size_of::<std::borrow::Cow<'_, [u8]>>(),
                    )
                })
                .ok_or(ReadError::Limit)?,
            m,
        )?;
        Ok(s)
    })?;
    // Conflict stages intentionally share a raw name; collapse those first.
    let mut previous = None;
    let mut keys = Vec::with_capacity(index.entries().len());
    for entry in index.entries() {
        let path = entry.path(index);
        if previous != Some(path) {
            keys.push(names.key(path.as_ref()));
        }
        previous = Some(path);
    }
    keys.sort_unstable();
    io.account(|m| m.check())?;
    if keys.windows(2).any(|p| p[0] == p[1]) {
        return Err(ReadError::Changed);
    }
    Ok(())
}

fn modified(
    io: &RepoIo<'_>,
    index: &State,
    policies: Policies,
    filtered: &mut bool,
) -> Result<u32, ReadError> {
    unique_names(io, index, policies)?;
    let _scratch = io.account(|m| {
        let mut s = m.path_allocation();
        s.reserve(
            index.entries().len() * std::mem::size_of::<&gix_index::Entry>(),
            m,
        )?;
        Ok(s)
    })?;
    let mut eligible = Vec::with_capacity(index.entries().len());
    eligible.extend(index.entries().iter().filter(|e| {
        e.stage_raw() == 0 && e.mode != Mode::COMMIT && !e.flags.contains(Flags::SKIP_WORKTREE)
    }));
    eligible
        .sort_unstable_by(|a, b| split(a.path(index).as_ref()).cmp(&split(b.path(index).as_ref())));
    io.with_worktree_stats(|| {
        let mut patterns = Patterns::default();
        let mut n = 0;
        let mut previous: &[u8] = b"";
        if eligible.is_empty() {
            return Ok(n);
        }
        attributes(io, &mut patterns, b"")?;
        patterns.add(
            io,
            RepoPath::new(RootId::CommonDir, b"info/attributes"),
            PatternKind::Attributes,
        )?;
        let mut start = 0;
        while start < eligible.len() {
            let parent = split(eligible[start].path(index).as_ref()).0;
            // Enter each ancestor once in directory order, including ancestors
            // without direct tracked leaves. Never resolve a gitlink child.
            for end in parent
                .iter()
                .enumerate()
                .filter_map(|(i, b)| (*b == b'/').then_some(i))
                .chain(std::iter::once(parent.len()))
                .filter(|i| *i != 0)
            {
                let dir = &parent[..end];
                if !(previous == dir
                    || (previous.starts_with(dir) && previous.get(dir.len()) == Some(&b'/')))
                {
                    attributes(io, &mut patterns, dir)?;
                }
            }
            previous = parent;
            let end = start
                + eligible[start..].partition_point(|e| split(e.path(index).as_ref()).0 == parent);
            let group = &eligible[start..end];
            let _group_scratch = io.account(|m| {
                let mut s = m.path_allocation();
                s.reserve(
                    group.len()
                        * (std::mem::size_of::<&[u8]>()
                            + std::mem::size_of::<Result<libc::stat, ReadError>>()),
                    m,
                )?;
                Ok(s)
            })?;
            let leaves: Vec<_> = group
                .iter()
                .map(|e| split(e.path(index).as_ref()).1)
                .collect();
            let mut observed = vec![Err(ReadError::Missing); group.len()];
            match io.worktree_directory_stats(parent, &leaves, policies.names, |i, stat| {
                observed[i] = stat.copied();
                Ok(())
            }) {
                Ok(()) => {}
                Err(ReadError::Missing | ReadError::Symlink) => {
                    observed.fill(Err(ReadError::Missing))
                }
                Err(error) => return Err(error),
            }
            n += compare_group(io, index, policies, &patterns, group, &observed, filtered)?;
            start = end;
        }
        Ok(n)
    })
}

fn compare_group(
    io: &RepoIo<'_>,
    index: &State,
    policies: Policies,
    patterns: &Patterns,
    entries: &[&gix_index::Entry],
    observed: &[Result<libc::stat, ReadError>],
    filtered: &mut bool,
) -> Result<u32, ReadError> {
    let mut n = 0;
    for (entry, metadata) in entries.iter().zip(observed) {
        io.account(|_| Ok(()))?;
        let path = entry.path(index).as_ref();
        let conversion = patterns.conversion(io, path, policies)?;
        let current = Policies {
            conversion,
            ..policies
        };
        let comparison = if entry.flags.contains(Flags::INTENT_TO_ADD) {
            Comparison::Exact { modified: true }
        } else {
            worktree::compare_observed(
                io,
                path,
                entry,
                index,
                current,
                metadata.as_ref().map_err(|e| *e),
            )?
        };
        match comparison {
            Comparison::Skipped => {}
            Comparison::Exact { modified } => n += u32::from(modified),
            Comparison::Approximate { modified } => {
                n += u32::from(modified);
                *filtered = true;
            }
        }
    }
    Ok(n)
}

#[cfg(test)]
mod deadline_tests {
    use super::*;

    #[test]
    fn tracked_entries_check_expired_deadline_before_comparison() {
        super::super::io::test_support::with_io(|io, meter, index, policies| {
            let entries: Vec<_> = index.entries().iter().collect();
            let observed = vec![Err(ReadError::Missing); entries.len()];
            *meter.borrow_mut() = crate::meter::Meter::new(std::time::Instant::now());
            assert_eq!(
                compare_group(
                    io,
                    index,
                    policies,
                    &Patterns::default(),
                    &entries,
                    &observed,
                    &mut false
                ),
                Err(ReadError::Deadline)
            );
        });
    }
}

// Per-thread test observations do not change the product's meter or deadline.
// SafeObjectDb::head_tree and ::tree each invoke find exactly once; count at
// their call sites, excluding reuse of the last decoded tree buffer.
#[cfg(test)]
pub(crate) mod observations {
    use std::cell::Cell;
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    pub struct Counts {
        pub tree_reads: usize,
        pub finds: usize,
        pub consistency_calls: usize,
    }
    thread_local! { static COUNTS: Cell<Counts> = Cell::new(Counts::default()); }
    pub fn take() -> Counts {
        COUNTS.take()
    }
    pub(super) fn consistency_call() {
        COUNTS.with(|slot| {
            let mut c = slot.get();
            c.consistency_calls += 1;
            slot.set(c);
        });
    }
    pub(super) fn find(tree: bool) {
        COUNTS.with(|slot| {
            let mut c = slot.get();
            c.finds += 1;
            c.tree_reads += usize::from(tree);
            slot.set(c);
        });
    }
}
