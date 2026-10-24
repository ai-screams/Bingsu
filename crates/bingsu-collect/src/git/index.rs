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
