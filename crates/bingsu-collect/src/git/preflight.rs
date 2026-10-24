//! Runs only after the first A Update. There is no object adapter here.
use super::{
    CollectError,
    config::Config,
    discover::RepoRoots,
    io::{RepoIo, RepoPath, RootId},
    refs::Refs,
    stage_a::HeadPolicy,
};
use crate::{
    meter::Meter,
    safe_read::{ReadError, ReadScope},
};
use std::cell::RefCell;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GitAccess {
    HeadOnly,
    StageAOnly,
    Objects,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AOnlyReason {
    ForeignOwner,
    MetadataShape,
    NoGuarantee,
    CoreWorktree,
    UseReplaceRefs,
    Alternates,
    LooseReplace,
    PackedReplace,
    Read(ReadError),
}

pub fn preflight(roots: &RepoRoots, meter: &mut Meter) -> Result<GitAccess, CollectError> {
    if roots.policy == HeadPolicy::HeadOnly {
        return Ok(GitAccess::HeadOnly);
    }
    if roots.reason.get().is_some() {
        return Ok(GitAccess::StageAOnly);
    }
    if matches!(roots.access.scope(), ReadScope::StageAOnly) {
        roots.reason.set(Some(AOnlyReason::NoGuarantee));
        return Ok(GitAccess::StageAOnly);
    }
    meter.event("preflight_start");
    // RepoIo borrows a RefCell; move and restore the SAME meter and its live
    // accounting, including failures. No second request budget is created.
    let placeholder = meter.expired_placeholder();
    let slot = RefCell::new(std::mem::replace(meter, placeholder));
    let io = RepoIo::new(roots.io_roots(), &roots.access, &slot);
    let result = inspect(&io, roots);
    drop(io);
    *meter = slot.into_inner();
    match result {
        Ok(None) => Ok(GitAccess::Objects),
        Ok(Some(reason)) => {
            roots.reason.set(Some(reason));
            Ok(GitAccess::StageAOnly)
        }
        Err(error) => {
            roots.reason.set(Some(AOnlyReason::Read(error)));
            Err(CollectError::Read(error))
        }
    }
}

fn inspect(io: &RepoIo<'_>, roots: &RepoRoots) -> Result<Option<AOnlyReason>, ReadError> {
    let config = Config::load(io)?;
    let risky_worktree = if config.has_core_worktree() {
        io.metered(|meter| {
            let mut scratch = meter.path_allocation();
            scratch.reserve(2 * 65_536 + 4096 * std::mem::size_of::<&[u8]>(), meter)?;
            Ok(config.risky_worktree(roots))
        })?
    } else {
        false
    };
    if risky_worktree {
        return Ok(Some(AOnlyReason::CoreWorktree));
    }
    if config.has_use_replace_refs() {
        return Ok(Some(AOnlyReason::UseReplaceRefs));
    }
    config.ensure_supported(io)?;
    // The files' presence is sufficient, even empty. Never interpret a path
    // found inside one; objects/pack and object payloads remain unopened.
    for name in [
        b"objects/info/alternates".as_slice(),
        b"objects/info/http-alternates",
    ] {
        if io.has_entry(RepoPath::new(RootId::CommonDir, name))? {
            return Ok(Some(AOnlyReason::Alternates));
        }
    }
    // Opening the actual path also observes case folding on the host FS.
    // Even an empty replace namespace conservatively prevents object access.
    if io.has_directory(RepoPath::new(RootId::CommonDir, b"refs/replace"))? {
        return Ok(Some(AOnlyReason::LooseReplace));
    }
    let refs = Refs::load_with_config(io, &config)?;
    if refs.contains_replace() {
        return Ok(Some(AOnlyReason::PackedReplace));
    }
    // A loose ref's absence is inconclusive while packed-refs exists. Resolve
    // only after the first A and all risk checks, reusing this bounded buffer.
    roots.unborn.set(refs.resolve(io, b"HEAD")?.is_none());
    Ok(None)
}
