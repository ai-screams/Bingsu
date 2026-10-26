//! Local divergence only. D3 supplies the C deadline and merges these fields.
//! Graph has no commit-graph cache or graft interpretation. Present grafts and
//! unresolved config includes make divergence unknown.
use super::{
    GuardedRepository, config,
    io::{RepoIo, RepoPath, RootId},
    refs::{self, ObjectId, Target},
};
use crate::safe_read::{ReadCap, ReadError};
use bingsu_core::{
    collection::{
        budget::{self, Axis},
        git::StageResult,
    },
    field::{self, Field, FieldValue, Value},
    width::WidthProfile,
};
use gix_error::ErrorExt;
use gix_object::bstr::ByteSlice;
use std::cell::Cell;

const INVALID: ReadError = ReadError::Io(libc::EINVAL);

pub fn stage_c(repo: &GuardedRepository<'_>) -> StageResult {
    match divergence(repo) {
        Ok(Some((ahead, behind))) => result(
            b"C",
            false,
            &[
                ("ahead", count(ahead, false)),
                ("behind", count(behind, false)),
            ],
        ),
        Ok(None) => result(
            b"C",
            false,
            &[("ahead", Field::ABSENT), ("behind", Field::ABSENT)],
        ),
        Err(_) => result(
            b"C",
            true,
            &[("ahead", Field::PENDING), ("behind", Field::PENDING)],
        ),
    }
}

pub(crate) fn divergence(repo: &GuardedRepository<'_>) -> Result<Option<(u32, u32)>, ReadError> {
    let io = repo.io.next_stage();
    let head = io.read_ref(
        RepoPath::new(RootId::GitDir, b"HEAD"),
        budget::SMALL_FILE_BYTES,
    )?;
    let Target::Symbolic(branch) = refs::parse_loose(&head)? else {
        return Ok(None);
    };
    let Some(branch_name) = branch.strip_prefix(b"refs/heads/") else {
        return Err(INVALID);
    };
    let Some(upstream) = upstream(&io, branch_name)? else {
        return Ok(None);
    };
    // Presence (even empty) is conservatively unknown. No shallow boundary is
    // treated as a root, and no missing parent is skipped by Graph::insert_parents.
    match io.metadata(RepoPath::new(RootId::CommonDir, b"shallow")) {
        Ok(_) => return Err(super::io::UNSUPPORTED),
        Err(ReadError::Missing) => {}
        Err(error) => return Err(error),
    }
    // lstat-level presence includes dangling symlinks and special entries.
    if io.has_entry(RepoPath::new(RootId::CommonDir, b"info/grafts"))? {
        return Err(super::io::UNSUPPORTED);
    }
    let head = repo.refs.resolve(&io, &branch)?.ok_or(ReadError::Missing)?;
    let upstream = repo
        .refs
        .resolve(&io, &upstream)?
        .ok_or(ReadError::Missing)?;
    let objects = repo.objects(&io);
    walk(&io, &objects, head, upstream).map(Some)
}

fn read_config(io: &RepoIo<'_>, root: RootId, name: &[u8]) -> Result<Vec<u8>, ReadError> {
    match io.read(
        RepoPath::new(root, name),
        ReadCap {
            bytes: budget::CONFIG_BYTES,
            single_link: true,
        },
    ) {
        Ok(bytes) => Ok(bytes),
        Err(ReadError::Missing) => Ok(Vec::new()),
        Err(error) => Err(error),
    }
}

/// Resolve branch.merge through repository fetch refspecs. URLs, includes,
/// push refspecs and commands are never consumed. Ambiguous mappings are unknown.
fn upstream(io: &RepoIo<'_>, branch: &[u8]) -> Result<Option<Vec<u8>>, ReadError> {
    let common = read_config(io, RootId::CommonDir, b"config")?;
    let worktree = read_config(io, RootId::GitDir, b"config.worktree")?;
    io.metered(|meter| {
        let (common, _common_allocation) = config::isolated(&common, meter)?;
        let active = common
            .boolean("extensions.worktreeConfig")
            .map_err(|_| INVALID)?
            .unwrap_or(false);
        let (worktree, _worktree_allocation) = config::isolated(&worktree, meter)?;
        // Includes remain inert: their effective upstream cannot be inferred
        // from local bytes, even if a condition appears inactive or empty.
        for file in [&common, &worktree] {
            for section in file.sections() {
                meter.check()?;
                let name = section.header().name();
                if name.eq_ignore_ascii_case(b"include") || name.eq_ignore_ascii_case(b"includeIf")
                {
                    return Err(super::io::UNSUPPORTED);
                }
            }
        }
        let files = std::iter::once(&common).chain(active.then_some(&worktree));
        let mut remote: Option<Vec<u8>> = None;
        let mut merges = Vec::new();
        for file in files.clone() {
            for section in file.sections() {
                let header = section.header();
                if header.name().eq_ignore_ascii_case(b"branch")
                    && header.subsection_name().map(|s| s.as_bytes()) == Some(branch)
                {
                    if let Some(value) = section.value_implicit("remote") {
                        remote = Some(value.map(Into::into).ok_or(INVALID)?);
                    }
                    if section.contains_value_name("merge") {
                        let values = section.values("merge");
                        if values.is_empty() {
                            return Err(INVALID);
                        }
                        merges.extend(values);
                    }
                }
            }
        }
        if merges.is_empty() || remote.is_none() {
            return Ok(None);
        }
        if merges.len() != 1 {
            return Err(INVALID);
        }
        let source: &[u8] = merges[0].as_ref();
        valid_ref(source)?;
        let remote = remote.expect("configured remote");
        if remote == b"." {
            return Ok(Some(source.to_vec()));
        }
        if remote.is_empty() {
            return Err(INVALID);
        }
        let mut target = None;
        for file in files {
            for section in file.sections() {
                meter.check()?;
                let header = section.header();
                if !header.name().eq_ignore_ascii_case(b"remote")
                    || header.subsection_name().map(|s| s.as_bytes()) != Some(remote.as_slice())
                {
                    continue;
                }
                if section.contains_value_name("fetch") && section.values("fetch").is_empty() {
                    return Err(INVALID);
                }
                for spec in section.values("fetch") {
                    let spec: &[u8] = spec.as_ref();
                    if let Some(negative) = spec.strip_prefix(b"^") {
                        if matches_pattern(negative, source)?.is_some() {
                            return Err(INVALID);
                        }
                        continue;
                    }
                    let spec = spec.strip_prefix(b"+").unwrap_or(spec);
                    let Some(colon) = spec.iter().position(|b| *b == b':') else {
                        continue;
                    };
                    let (from, to) = (&spec[..colon], &spec[colon + 1..]);
                    let Some(capture) = matches_pattern(from, source)? else {
                        continue;
                    };
                    let mapped = if let Some(star) = to.iter().position(|b| *b == b'*') {
                        if !from.contains(&b'*') || to[star + 1..].contains(&b'*') {
                            return Err(INVALID);
                        }
                        [&to[..star], capture, &to[star + 1..]].concat()
                    } else {
                        if from.contains(&b'*') {
                            return Err(INVALID);
                        }
                        to.to_vec()
                    };
                    valid_ref(&mapped)?;
                    if target.as_ref().is_some_and(|old| old != &mapped) {
                        return Err(INVALID);
                    }
                    target = Some(mapped);
                }
            }
        }
        target.map(Some).ok_or(ReadError::Missing)
    })
}
fn valid_ref(name: &[u8]) -> Result<(), ReadError> {
    if !name.starts_with(b"refs/") {
        return Err(INVALID);
    }
    gix_index::validate::reference::name(name.as_bstr())
        .map(|_| ())
        .map_err(|_| INVALID)
}
fn matches_pattern<'a>(pattern: &[u8], value: &'a [u8]) -> Result<Option<&'a [u8]>, ReadError> {
    if let Some(star) = pattern.iter().position(|b| *b == b'*') {
        if pattern[star + 1..].contains(&b'*') {
            return Err(INVALID);
        }
        Ok(value
            .strip_prefix(&pattern[..star])
            .and_then(|v| v.strip_suffix(&pattern[star + 1..])))
    } else {
        Ok((pattern == value).then_some(b""))
    }
}

#[derive(Default)]
struct Node {
    parents: Vec<ObjectId>,
    reach: u8,
    active: bool,
    next: usize,
}
struct CheckedFind<'a, T> {
    objects: &'a T,
    error: &'a Cell<Option<ReadError>>,
    io: &'a RepoIo<'a>,
}
impl<T: gix_object::Find> gix_object::Find for CheckedFind<'_, T> {
    fn try_find<'b>(
        &self,
        id: &gix_index::hash::oid,
        buffer: &'b mut Vec<u8>,
    ) -> gix_error::ExnResult<Option<gix_object::Data<'b>>> {
        let data = self.objects.try_find(id, buffer).inspect_err(|error| {
            if let Some(error) = error.downcast_any_ref::<super::io::objects::ObjectError>() {
                self.error.set(Some(error.0));
            }
        })?;
        if let Some(data) = &data {
            let checked = self.io.metered(|meter| checked_commit(data, meter));
            if let Err(error) = checked {
                self.error.set(Some(error));
                return Err(super::io::objects::ObjectError(error).raise_erased());
            }
        }
        Ok(data)
    }
}

/// The history walk's per-object check, before any parent is retained.
pub(crate) fn checked_commit(
    data: &gix_object::Data<'_>,
    meter: &mut crate::meter::Meter,
) -> Result<(), ReadError> {
    if data.kind != gix_object::Kind::Commit {
        return Err(INVALID);
    }
    let mut message = false;
    for token in gix_object::CommitRefIter::from_bytes(data.data, data.object_hash) {
        meter.check()?;
        message |= matches!(
            token.map_err(|_| INVALID)?,
            gix_object::commit::ref_iter::Token::Message(_)
        );
    }
    if !message {
        return Err(INVALID);
    }
    Ok(())
}

/// Retain each unique commit once, then color both reachable sets. The active
/// DFS color rejects cycles; no discovered count is published before BOTH walks
/// finish. Graph::insert_parents would silently skip missing parents, so use
/// explicit lookup instead. Grafts and commit-graph are not I/O inputs here.
pub(crate) fn walk(
    io: &RepoIo<'_>,
    objects: &impl gix_object::Find,
    head: ObjectId,
    upstream: ObjectId,
) -> Result<(u32, u32), ReadError> {
    let mut allocation = io.metered(|meter| {
        let mut allocation = meter.path_allocation();
        allocation.reserve(
            budget::COMMITS as usize * std::mem::size_of::<ObjectId>() + 1024,
            meter,
        )?;
        Ok(allocation)
    })?;
    let error = Cell::new(None);
    let mut graph = gix_revwalk::Graph::<Node>::new(
        CheckedFind {
            objects,
            error: &error,
            io,
        },
        None,
    );
    let mut stack = Vec::new();
    stack
        .try_reserve_exact(budget::COMMITS as usize)
        .map_err(|_| ReadError::Limit)?;
    for (tip, color) in [(head, 1), (upstream, 2)] {
        stack.push(tip);
        while let Some(id) = stack.last().copied() {
            io.metered(|meter| meter.check())?;
            if !graph.contains(&id) {
                io.metered(|meter| {
                    meter.charge_axis(Axis::Commits, 1)?;
                    // Hash-map node and overlapping rehash capacity, reserved
                    // before insertion. Parent arrays are accounted separately.
                    allocation.reserve(384, meter)
                })?;
                let commit = graph
                    .try_lookup(&id)
                    .map_err(|_| error.get().unwrap_or(INVALID))?
                    .ok_or(ReadError::Missing)?;
                commit.committer_timestamp().map_err(|_| INVALID)?;
                let count = commit.iter_parents().try_fold(0usize, |n, parent| {
                    parent.map_err(|_| INVALID)?;
                    n.checked_add(1).ok_or(ReadError::Limit)
                })?;
                io.metered(|meter| {
                    allocation.reserve(
                        count
                            .checked_mul(std::mem::size_of::<ObjectId>())
                            .ok_or(ReadError::Limit)?,
                        meter,
                    )
                })?;
                let mut parents = Vec::new();
                parents
                    .try_reserve_exact(count)
                    .map_err(|_| ReadError::Limit)?;
                for parent in commit.iter_parents() {
                    parents.push(parent.map_err(|_| INVALID)?);
                }
                graph.insert(
                    id,
                    Node {
                        parents,
                        ..Node::default()
                    },
                );
            }
            let node = graph.get_mut(&id).expect("inserted");
            if node.reach & color != 0 {
                stack.pop();
                continue;
            }
            node.active = true;
            let mut next = None;
            loop {
                let node = graph.get_mut(&id).expect("inserted");
                let Some(parent) = node.parents.get(node.next).copied() else {
                    break;
                };
                node.next += 1;
                let parent_node = graph.get(&parent);
                if parent_node.is_some_and(|n| n.active) {
                    return Err(INVALID);
                }
                if parent_node.is_none_or(|n| n.reach & color == 0) {
                    next = Some(parent);
                    break;
                }
            }
            if let Some(parent) = next {
                if stack.len() == budget::COMMITS as usize {
                    return Err(ReadError::Limit);
                }
                stack.push(parent);
            } else {
                let node = graph.get_mut(&id).expect("inserted");
                node.active = false;
                node.next = 0;
                node.reach |= color;
                stack.pop();
            }
        }
    }
    let (mut ahead, mut behind) = (0, 0);
    for node in graph.detach().into_values() {
        io.metered(|meter| meter.check())?;
        ahead += u32::from(node.reach == 1);
        behind += u32::from(node.reach == 2);
    }
    Ok((ahead, behind))
}

pub(super) fn count(n: u32, saturated: bool) -> Field {
    Field::known(FieldValue::Count { n, saturated })
}
/// Stage-local fields; the D3 stream merges only the owning stage's fields
/// into its cumulative snapshot before publishing an Update.
pub(super) fn result(stage: &[u8], partial: bool, fields: &[(&str, Field)]) -> StageResult {
    let decl = &field::BUILTIN[3];
    let mut value = Value::new(b"", vec![Field::PENDING; decl.fields.len()]);
    for (name, field) in fields.iter().cloned().chain([
        ("no_repo", Field::ABSENT),
        ("stage", Field::text(stage, 1, WidthProfile::DEFAULT)),
        ("partial", Field::known(FieldValue::Bool(partial))),
    ]) {
        value.fields[decl.field_index(name).expect("fixed field")] = field;
    }
    if partial {
        StageResult::Partial(value)
    } else {
        StageResult::Value(value)
    }
}
