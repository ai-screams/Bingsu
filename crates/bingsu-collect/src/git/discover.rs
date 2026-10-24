//! Fixed-marker discovery and reciprocal worktree/submodule capabilities.
use super::{CollectError, preflight::AOnlyReason, stage_a::HeadPolicy};
use crate::{
    meter::Meter,
    safe_read::{self, Access, ReadError, Root, StageAFile},
};
use bingsu_core::collection::wire::Request;
use std::cell::Cell;

pub struct RepoRoots {
    pub(super) worktree: Root,
    pub(super) gitdir: Root,
    pub(super) commondir: Option<Root>,
    pub(super) access: Access,
    pub(super) policy: HeadPolicy,
    pub(super) reason: Cell<Option<AOnlyReason>>,
    pub(super) unborn: Cell<bool>,
    refs: super::refs::RefSnapshot,
    binding: Option<WorktreeBinding>,
}

struct WorktreeBinding {
    gitdir: Vec<u8>,
    worktree: Vec<u8>,
    _allocation: crate::meter::PathAllocation,
}

impl RepoRoots {
    pub fn ref_snapshot(&self) -> &super::refs::RefSnapshot {
        &self.refs
    }
    pub(super) fn matches_worktree(&self, value: &[u8]) -> bool {
        self.binding.as_ref().is_some_and(|binding| {
            normalize(&binding.gitdir, value).is_ok_and(|path| path == binding.worktree)
        })
    }
    pub fn head_policy(&self) -> HeadPolicy {
        self.policy
    }
    pub fn a_only_reason(&self) -> Option<AOnlyReason> {
        self.reason.get()
    }
    pub(super) fn common(&self) -> &Root {
        self.commondir.as_ref().unwrap_or(&self.gitdir)
    }
    pub(super) fn io_roots(&self) -> super::io::RepoRoots<'_> {
        super::io::RepoRoots {
            worktree: &self.worktree,
            gitdir: &self.gitdir,
            commondir: self.common(),
        }
    }

    /// Discovery and its unselected ancestor descriptors are already gone.
    /// Access is !Send/!Sync; no collection thread can precede this layer.
    pub(super) fn restrict(&mut self, meter: &mut Meter) -> Result<(), ReadError> {
        meter.event("before_read_layer");
        #[cfg(target_os = "linux")]
        {
            let mut roots = vec![&self.worktree, &self.gitdir];
            if let Some(common) = &self.commondir {
                roots.push(common);
            }
            self.access.restrict_to(&roots, meter)?;
        }
        meter.check()
    }
}

pub fn discover(input: &Request, meter: &mut Meter) -> Result<Option<RepoRoots>, CollectError> {
    let access = Access::probe(meter).map_err(CollectError::Read)?;
    discover_with_access(input, access, meter)
}

pub fn discover_with_access(
    input: &Request,
    access: Access,
    meter: &mut Meter,
) -> Result<Option<RepoRoots>, CollectError> {
    match select(input, access, meter)? {
        Selection::Repository(roots) => Ok(Some(roots)),
        Selection::Outside(_, _) => Ok(None),
    }
}

pub(super) enum Selection {
    Repository(RepoRoots),
    Outside(Root, Access),
}

pub(super) fn select(
    input: &Request,
    access: Access,
    meter: &mut Meter,
) -> Result<Selection, CollectError> {
    select_inner(input, access, meter).map_err(CollectError::Read)
}

fn select_inner(
    input: &Request,
    access: Access,
    meter: &mut Meter,
) -> Result<Selection, ReadError> {
    let cwd = &input.binding.cwd;
    let query = input.binding.path_query;
    let discovery = safe_read::acquire(cwd, query, meter)?;
    let logical = discovery.logical();
    let mut scratch = meter.path_allocation();
    scratch.reserve(cwd.len() * 2 + 4096 * std::mem::size_of::<&[u8]>(), meter)?;
    let parts: Vec<_> = cwd
        .split(|b| *b == b'/')
        .filter(|p| !p.is_empty())
        .collect();
    let max_levels = if logical {
        query
            .home_component
            .map_or(32, |home| parts.len().saturating_sub(usize::from(home) + 1))
    } else {
        0
    }; // a logical HOME boundary cannot be proved through a symlink
    let (worktree, level) = discovery.repository(max_levels, meter)?;
    meter.event("discovery_consumed");
    let Some(level) = level else {
        return Ok(Selection::Outside(worktree, access));
    };
    let worktree_path = absolute(&parts[..parts.len() - level]);
    let location = Location {
        path: &worktree_path,
        logical,
        ancestors: max_levels.min(32).saturating_sub(level),
        depth: 0,
    };
    let metadata = metadata(&worktree, location, &access, meter)?;
    let binding = if metadata.submodule {
        let mut allocation = meter.path_allocation();
        allocation.reserve(metadata.path.len() + worktree_path.len(), meter)?;
        Some(WorktreeBinding {
            gitdir: metadata.path,
            worktree: worktree_path,
            _allocation: allocation,
        })
    } else {
        None
    };
    Ok(Selection::Repository(RepoRoots {
        worktree,
        gitdir: metadata.gitdir,
        commondir: metadata.commondir,
        access,
        policy: metadata.policy,
        reason: Cell::new(metadata.reason),
        unborn: Cell::new(false),
        refs: super::refs::RefSnapshot::default(),
        binding,
    }))
}

// At most eight gitfile validations can be live. Every recursive ancestor
// search also spends the original HOME/32-level distance budget, so neither
// recursion nor an ancestor chain can reset discovery's bound.
const GITFILE_DEPTH: usize = 8;
#[derive(Clone, Copy)]
struct Location<'a> {
    path: &'a [u8],
    logical: bool,
    ancestors: usize,
    depth: usize,
}
struct Metadata {
    gitdir: Root,
    commondir: Option<Root>,
    policy: HeadPolicy,
    reason: Option<AOnlyReason>,
    path: Vec<u8>,
    submodule: bool,
}

fn metadata(
    worktree: &Root,
    location: Location<'_>,
    access: &Access,
    meter: &mut Meter,
) -> Result<Metadata, ReadError> {
    let worktree_owned = worktree.owned(meter)?;
    let gitdir = match worktree.git_directory(meter) {
        Ok(gitdir) => gitdir,
        Err(ReadError::Missing) => {
            // Foreign worktrees may read an in-place HEAD, never a gitfile.
            if !worktree_owned || !location.logical {
                return Err(ReadError::Denied);
            }
            if location.depth == GITFILE_DEPTH {
                return Err(ReadError::Escape);
            }
            let bytes = safe_read::read_stage_a(worktree, StageAFile::GitPointer, access, meter)?;
            let pointer = line(&bytes)?
                .strip_prefix(b"gitdir: ")
                .ok_or(ReadError::Escape)?;
            return gitfile(worktree, location, pointer, access, meter);
        }
        Err(error) => return Err(error),
    };
    // HEAD policy is decided only by owners, before config, refs or any gix.
    let gitdir_owned = gitdir.owned(meter)?;
    let policy = if worktree_owned && gitdir_owned {
        HeadPolicy::OwnedMetadata
    } else {
        HeadPolicy::HeadOnly
    };
    let reason = if policy == HeadPolicy::HeadOnly {
        Some(AOnlyReason::ForeignOwner)
    } else {
        match safe_read::read_stage_a(&gitdir, StageAFile::CommonDir, access, meter) {
            Err(ReadError::Missing) => None,
            Ok(_) => Some(AOnlyReason::MetadataShape),
            Err(error) => Some(AOnlyReason::Read(error)),
        }
    };
    let mut path = location.path.to_vec();
    path.extend_from_slice(b"/.git");
    Ok(Metadata {
        gitdir,
        commondir: None,
        policy,
        reason,
        path,
        submodule: false,
    })
}

fn gitfile(
    worktree: &Root,
    location: Location<'_>,
    pointer: &[u8],
    access: &Access,
    meter: &mut Meter,
) -> Result<Metadata, ReadError> {
    // Three bounded pointer buffers, their normalized paths and component
    // vectors coexist only during this selection; release them on return.
    let mut scratch = meter.path_allocation();
    scratch.reserve(6 * 65_536 + 6 * 4096 * std::mem::size_of::<&[u8]>(), meter)?;
    let git_path = normalize(location.path, pointer)?;
    let parts: Vec<_> = git_path
        .split(|b| *b == b'/')
        .filter(|p| !p.is_empty())
        .collect();
    // An arbitrary owned directory (HOME, a parent, another repository's .git)
    // is not a metadata capability. Validate the shape BEFORE acquisition and
    // select_metadata; the reciprocal registration then binds the one slot.
    if parts.len() < 3 || parts[parts.len() - 2] != b"worktrees" {
        return submodule(worktree, location, &git_path, access, meter);
    }
    let common_path = absolute(&parts[..parts.len() - 2]);
    let candidate = safe_read::acquire_metadata(&git_path, meter)?;
    if !candidate.pointer_is_logical() {
        return Err(ReadError::Escape);
    }
    let common = match candidate.metadata_pointer(StageAFile::CommonDir, worktree, meter) {
        Ok(common) => common,
        // A submodule name may itself end in worktrees/<name>. Its reciprocal
        // core.worktree binding, not the suffix spelling, decides the layout.
        Err(ReadError::Missing) => {
            drop(candidate);
            return submodule(worktree, location, &git_path, access, meter);
        }
        Err(error) => return Err(error),
    };
    if normalize(&git_path, line(&common)?)? != common_path {
        return Err(ReadError::Escape);
    }
    let backlink = candidate.metadata_pointer(StageAFile::WorktreePointer, worktree, meter)?;
    let mut expected = location.path.to_vec();
    expected.extend_from_slice(b"/.git");
    if normalize(&git_path, line(&backlink)?)? != expected {
        return Err(ReadError::Escape);
    }
    let common = safe_read::acquire_metadata(&common_path, meter)?;
    // No commondir chain/cycle, and never turn a parent into an allow rule.
    match common.metadata_pointer(StageAFile::CommonDir, worktree, meter) {
        Err(ReadError::Missing) => {}
        Ok(_) => return Err(ReadError::Escape),
        Err(error) => return Err(error),
    }
    common.metadata_signature(worktree, meter)?;
    let commondir = common.select_metadata(worktree, meter)?;
    let gitdir = candidate.select_metadata(worktree, meter)?;
    meter.event("metadata_shape_validated");
    Ok(Metadata {
        gitdir,
        commondir: Some(commondir),
        policy: HeadPolicy::OwnedMetadata,
        reason: None,
        path: git_path,
        submodule: false,
    })
}

fn submodule(
    worktree: &Root,
    location: Location<'_>,
    git_path: &[u8],
    access: &Access,
    meter: &mut Meter,
) -> Result<Metadata, ReadError> {
    // Reject arbitrary pointers before acquiring their target (notably HOME).
    if !git_path
        .windows(b"/modules/".len())
        .any(|s| s == b"/modules/")
    {
        return Err(ReadError::Escape);
    }
    let mut path = location.path;
    let mut remaining = location.ancestors;
    loop {
        if remaining == 0 {
            return Err(ReadError::Escape);
        }
        path = &path[..path
            .iter()
            .rposition(|b| *b == b'/')
            .ok_or(ReadError::Escape)?];
        remaining -= 1;
        if path.is_empty() {
            return Err(ReadError::Escape);
        }
        let discovery = safe_read::acquire(path, Default::default(), meter)?;
        if !discovery.logical() {
            return Err(ReadError::Escape);
        }
        let (ancestor, level) = discovery.ancestor_repository(worktree, remaining, meter)?;
        let Some(level) = level else {
            return Err(ReadError::Escape);
        };
        for _ in 0..level {
            path = &path[..path
                .iter()
                .rposition(|b| *b == b'/')
                .ok_or(ReadError::Escape)?];
        }
        remaining -= level;
        let parent = metadata(
            &ancestor,
            Location {
                path,
                logical: true,
                ancestors: remaining,
                depth: location.depth + 1,
            },
            access,
            meter,
        )?;
        if parent.policy != HeadPolicy::OwnedMetadata || parent.reason.is_some() {
            return Err(ReadError::Escape);
        }
        let matches = module_suffix(git_path, &parent.path);
        // Parent capabilities prove shape only; they never reach restrict().
        drop(parent);
        drop(ancestor);
        if matches {
            break;
        }
    }
    let candidate = safe_read::acquire_metadata(git_path, meter)?;
    match candidate.metadata_pointer(StageAFile::CommonDir, worktree, meter) {
        Err(ReadError::Missing) => {}
        Ok(_) => return Err(ReadError::Escape),
        Err(error) => return Err(error),
    }
    let backlink = super::config::submodule_worktree(&candidate, worktree, access, meter)?;
    if normalize(git_path, &backlink)? != location.path {
        return Err(ReadError::Escape);
    }
    let gitdir = candidate.select_metadata(worktree, meter)?;
    meter.event("metadata_shape_validated");
    Ok(Metadata {
        gitdir,
        commondir: None,
        policy: HeadPolicy::OwnedMetadata,
        reason: None,
        path: git_path.to_vec(),
        submodule: true,
    })
}

fn module_suffix(path: &[u8], parent: &[u8]) -> bool {
    let Some(suffix) = path
        .strip_prefix(parent)
        .and_then(|p| p.strip_prefix(b"/modules/"))
    else {
        return false;
    };
    // Git defaults the submodule name to its entire worktree path. Authority
    // comes from the verified ancestor prefix and reciprocal binding.
    path.len() <= 65_536
        && !suffix.contains(&0)
        && suffix
            .split(|b| *b == b'/')
            .all(|part| !matches!(part, b"" | b"." | b".."))
}

fn absolute(parts: &[&[u8]]) -> Vec<u8> {
    let mut path = Vec::new();
    for part in parts {
        path.push(b'/');
        path.extend_from_slice(part);
    }
    path
}

fn normalize(base: &[u8], path: &[u8]) -> Result<Vec<u8>, ReadError> {
    if path.is_empty() || path.contains(&0) || path.len() > 65_536 {
        return Err(ReadError::Escape);
    }
    let mut parts: Vec<_> = if path.starts_with(b"/") {
        Vec::new()
    } else {
        base.split(|b| *b == b'/')
            .filter(|p| !p.is_empty())
            .collect()
    };
    for part in path.split(|b| *b == b'/') {
        match part {
            b"" | b"." => {}
            b".." => {
                parts.pop().ok_or(ReadError::Escape)?;
            }
            _ => {
                if parts.len() == 4096 {
                    return Err(ReadError::Limit);
                }
                parts.push(part);
            }
        }
    }
    let result = absolute(&parts);
    if result.is_empty() || result.len() > 65_536 {
        return Err(ReadError::Escape);
    }
    Ok(result)
}

fn line(bytes: &[u8]) -> Result<&[u8], ReadError> {
    let bytes = bytes.strip_suffix(b"\n").unwrap_or(bytes);
    let bytes = bytes.strip_suffix(b"\r").unwrap_or(bytes);
    if bytes.is_empty() || bytes.contains(&0) || bytes.contains(&b'\n') || bytes.contains(&b'\r') {
        return Err(ReadError::Escape);
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    // 이것을 실패시키는 것: modules 접두 경계·정규 suffix·길이 상한을 생략.
    #[test]
    fn module_suffix_uses_the_ancestor_prefix_not_name_pairs() {
        for suffix in [
            "vendor/foo",
            "a/b/c",
            "a/modules/b",
            "x/modules",
            "worktrees/x",
        ] {
            assert!(module_suffix(
                format!("/repo/.git/modules/{suffix}").as_bytes(),
                b"/repo/.git"
            ));
        }
        for path in [
            "/repo/.git/modules/",
            "/repo/.git/modules",
            "/repo/.git/modules/./x",
            "/repo/.git/modules/../x",
            "/repo/.git/modules/x//y",
            "/repo/.git-other/modules/x",
            "/repo/.git/modulesevil/x",
            "/other/.git/modules/x",
            "/repo/.git/modules/x\0y",
        ] {
            assert!(!module_suffix(path.as_bytes(), b"/repo/.git"), "{path:?}");
        }
        assert!(!module_suffix(
            format!("/repo/.git/modules/{}", "x".repeat(65_536)).as_bytes(),
            b"/repo/.git"
        ));
    }

    // 이것을 실패시키는 것: acquisition의 두 번째 방어 이전 pointer scratch 상한 제거.
    #[test]
    fn pointer_normalization_is_bounded_before_acquisition() {
        let path = format!("/{}.git/worktrees/name", "x/".repeat(4096));
        assert_eq!(normalize(b"/base", path.as_bytes()), Err(ReadError::Limit));
    }
}
