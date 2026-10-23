//! Bounded index input. Extension caches are never needed for a read-only
//! comparison; discard them before gix can allocate or recurse through them.
use super::{RepoIo, RepoPath, RootId, UNSUPPORTED};
use crate::{meter::Meter, safe_read::ReadError};
use bingsu_core::collection::budget::{self, Axis};
use gix_index::hash::{self, Kind};

const INVALID: ReadError = ReadError::Io(libc::EINVAL);

pub fn load(io: &RepoIo<'_>) -> Result<gix_index::State, ReadError> {
    let mut bytes = io.read_budgeted(
        RepoPath::new(RootId::GitDir, b"index"),
        budget::INDEX_BYTES,
        Axis::IndexBytes,
    )?;
    io.metered(|meter| parse(&mut bytes, meter))
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
    // 3x covers Vec old+new growth, plus the V4 delta scratch. Entry Vec is
    // exact-sized. Optional extension parsers (recursive TREE/UNTR etc.) cannot
    // run. The fixed margin includes error construction; tested by allocator.
    let backing = paths.max(entry_end.saturating_sub(12 + entries * 62));
    let reservation = entries
        .checked_mul(std::mem::size_of::<gix_index::Entry>())
        .and_then(|n| n.checked_add(3 * backing + 3 * longest + 4096))
        .ok_or(ReadError::Limit)?;
    meter.allocation(reservation)?;
    // Drop caches entirely: gix estimates initial path backing from the input
    // length, even for unknown extensions. Signature replacement alone would
    // leave their payloads as an uncharged allocation estimate.
    let parser_end = entry_end + if sparse { 8 } else { 0 };
    if sparse {
        bytes[entry_end..parser_end].copy_from_slice(b"sdir\0\0\0\0");
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
    // A malformed ordering/path must not become a clean staged comparison.
    let mut last = None;
    for entry in state.entries() {
        let path: &[u8] = entry.path(&state).as_ref();
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
        last = Some(key);
    }
    Ok(state)
}
