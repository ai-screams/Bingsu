//! Complete stash reflog lines from one confined fd. D3 supplies D's deadline.
use super::{
    discover::RepoRoots,
    io::RepoIo,
    refs::RefSnapshot,
    stage_c::{count, result},
};
use crate::{meter::Meter, safe_read::ReadError};
use bingsu_core::{
    collection::{
        budget::{self, Axis},
        git::StageResult,
    },
    field::Field,
};
use std::cell::RefCell;

pub fn stage_d(roots: &RepoRoots, refs: &RefSnapshot, meter: &RefCell<Meter>) -> StageResult {
    if roots.head_policy() != super::stage_a::HeadPolicy::OwnedMetadata
        || roots.a_only_reason().is_some()
    {
        return result(b"D", true, &[("stash", Field::PENDING)]);
    }
    let io = RepoIo::new(roots.io_roots(), &roots.access, meter);
    match stash(&io, refs) {
        Ok((n, saturated)) => result(b"D", saturated, &[("stash", count(n, saturated))]),
        Err(_) => result(b"D", true, &[("stash", Field::PENDING)]),
    }
}

pub(crate) fn stash(io: &RepoIo<'_>, refs: &RefSnapshot) -> Result<(u32, bool), ReadError> {
    let _allocation = io.metered(|meter| {
        let mut allocation = meter.path_allocation();
        // A single line can occupy the whole byte budget. Never grow from an
        // attacker-supplied length or accumulate entries across the stream.
        // Line storage plus bounded parser-error diagnostics (which can copy
        // the hostile line); the counted allocator regression covers this.
        allocation.reserve(budget::REFLOG_BYTES as usize * 3 + 16_384, meter)?;
        Ok(allocation)
    })?;
    let mut line = Vec::new();
    line.try_reserve_exact(budget::REFLOG_BYTES as usize)
        .map_err(|_| ReadError::Limit)?;
    let mut n = 0;
    let mut malformed = false;
    let complete = match io.stream_reflog(
        || Ok(refs.load(io)?.resolve(io, b"refs/stash")?.is_some()),
        |chunk, meter| {
            meter.check()?;
            for byte in chunk {
                if meter.budget.used(Axis::StashEntries) == budget::STASH_ENTRIES {
                    return Ok(false);
                }
                if *byte != b'\n' {
                    line.push(*byte);
                    continue;
                }
                let valid = !line.contains(&0)
                    && gix_ref::file::log::LineRef::from_bytes(&line).is_ok_and(|entry| {
                        entry.previous_oid.len() == 40 && entry.new_oid.len() == 40
                    });
                if !valid {
                    malformed = true;
                    return Ok(false);
                }
                meter.charge_axis(Axis::StashEntries, 1)?;
                n += 1;
                line.clear();
            }
            Ok(true)
        },
    ) {
        Ok(complete) => complete,
        Err(ReadError::Missing) => return Ok((0, false)),
        Err(error) => return Err(error),
    };
    let partial = !complete || malformed || !line.is_empty();
    if partial && n == 0 {
        return Err(ReadError::Io(libc::EINVAL));
    }
    Ok((n, partial))
}
