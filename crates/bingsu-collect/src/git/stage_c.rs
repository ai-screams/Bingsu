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
use std::{cell::Cell, cmp::Reverse, collections::BinaryHeap};

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
    io.account(|meter| meter.check())?;
    if head == upstream && repo.head_with_tree.get() == Some(head) {
        return Ok(Some((0, 0)));
    }
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
    sent: u8,
    queued: bool,
    timestamp: i64,
    proof: usize,
    reaches_boundary: bool,
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
            let checked = self.io.account(|meter| checked_commit(data, meter));
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

// Timestamp is only a scheduling hint, never an ancestry bound. FIFO ties keep
// equally dated tips moving together instead of draining one complete history.
type QueueEntry = (i64, Reverse<usize>, ObjectId);

// Count every candidate scan and DFS step (including parent edges), across
// all boundaries. Exhaustion disables cuts permanently for this walk.
const PROOF_WORK_PER_NODE: usize = 4;

struct Paint<'a> {
    io: &'a RepoIo<'a>,
    graph: gix_revwalk::Graph<'a, 'a, Node>,
    error: &'a Cell<Option<ReadError>>,
    allocation: crate::meter::PathAllocation,
    queue: BinaryHeap<QueueEntry>,
    common: Vec<ObjectId>,
    repaint: Vec<ObjectId>,
    ids: Vec<ObjectId>,
    stack: Vec<ObjectId>,
    sequence: usize,
    proof: usize,
    proof_work: usize,
    full_walk: bool,
}

impl Paint<'_> {
    fn proof_step(&mut self) -> bool {
        if self.proof_work >= PROOF_WORK_PER_NODE * self.ids.len() {
            self.full_walk = true;
            self.stack.clear();
            #[cfg(test)]
            observations::fallback();
            return false;
        }
        self.proof_work += 1;
        #[cfg(test)]
        observations::proof_step(self.ids.len());
        true
    }

    fn paint(&mut self, id: ObjectId, color: u8) -> Result<(), ReadError> {
        self.io.account(|meter| meter.check())?;
        if !self.graph.contains(&id) {
            self.io.account(|meter| {
                meter.charge_axis(Axis::Commits, 1)?;
                // Hash-map node and overlapping rehash capacity. The frontier
                // and proof scratch are reserved separately before the walk.
                self.allocation.reserve(384, meter)
            })?;
            // insert_parents silently skips missing objects; explicitly look
            // up and validate each unique commit before retaining its parents.
            let commit = self
                .graph
                .try_lookup(&id)
                .map_err(|_| self.error.get().unwrap_or(INVALID))?
                .ok_or(ReadError::Missing)?;
            let timestamp = commit.committer_timestamp().map_err(|_| INVALID)?;
            let count = commit.iter_parents().try_fold(0usize, |n, parent| {
                self.io.account(|meter| meter.check())?;
                parent.map_err(|_| INVALID)?;
                n.checked_add(1).ok_or(ReadError::Limit)
            })?;
            self.io.account(|meter| {
                self.allocation.reserve(
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
                self.io.account(|meter| meter.check())?;
                parents.push(parent.map_err(|_| INVALID)?);
            }
            self.graph.insert(
                id,
                Node {
                    parents,
                    timestamp,
                    ..Node::default()
                },
            );
            self.ids.push(id);
        }
        let node = self.graph.get_mut(&id).expect("inserted");
        let previous = node.reach;
        node.reach |= color;
        if node.reach == 3 && previous != 3 && node.sent != 0 {
            // Common paint must catch up through already expanded nodes before
            // another exclusive step; otherwise equal timestamps drain history.
            node.queued = true;
            self.repaint.push(id);
        } else if node.reach != node.sent && !node.queued {
            node.queued = true;
            self.queue
                .push((node.timestamp, Reverse(self.sequence), id));
            self.sequence += 1;
        }
        Ok(())
    }

    fn expand(&mut self, id: ObjectId) -> Result<(), ReadError> {
        let node = self.graph.get_mut(&id).expect("painted");
        let color = node.reach;
        let count = node.parents.len();
        node.sent = color;
        node.queued = false;
        for n in 0..count {
            self.io.account(|meter| meter.check())?;
            let parent = self.graph.get(&id).expect("painted").parents[n];
            self.paint(parent, color)?;
        }
        Ok(())
    }

    /// Prove ancestry using ONLY retained edges, with memoized iterative DFS.
    /// Unknown parents cannot prove a path. The active color also rejects cycles
    /// in the observed graph (verified SHA-1 objects cannot construct cycles).
    fn reaches(&mut self, start: ObjectId, boundary: Option<ObjectId>) -> Result<bool, ReadError> {
        self.io.account(|meter| meter.check())?;
        if boundary.is_some() && !self.proof_step() {
            return Ok(false);
        }
        if Some(start) == boundary {
            return Ok(true);
        }
        if self.graph.get(&start).expect("retained").proof == self.proof {
            return Ok(self.graph.get(&start).expect("retained").reaches_boundary);
        }
        self.stack.push(start);
        while let Some(id) = self.stack.last().copied() {
            self.io.account(|meter| meter.check())?;
            if boundary.is_some() && !self.proof_step() {
                return Ok(false);
            }
            let node = self.graph.get_mut(&id).expect("retained");
            if node.proof != self.proof {
                node.proof = self.proof;
                node.next = 0;
                node.active = true;
                node.reaches_boundary = false;
            }
            if let Some(parent) = node.parents.get(node.next).copied() {
                node.next += 1;
                if Some(parent) == boundary {
                    node.reaches_boundary = true;
                    continue;
                }
                let Some(parent_node) = self.graph.get(&parent) else {
                    continue;
                };
                if parent_node.proof == self.proof {
                    if parent_node.active {
                        return Err(INVALID);
                    }
                    let reaches = parent_node.reaches_boundary;
                    self.graph.get_mut(&id).expect("retained").reaches_boundary |= reaches;
                } else {
                    if self.stack.len() == budget::COMMITS as usize {
                        return Err(ReadError::Limit);
                    }
                    self.stack.push(parent);
                }
            } else {
                node.active = false;
                let reaches = node.reaches_boundary;
                self.stack.pop();
                if let Some(child) = self.stack.last() {
                    self.graph
                        .get_mut(child)
                        .expect("retained")
                        .reaches_boundary |= reaches;
                }
            }
        }
        Ok(self.graph.get(&start).expect("retained").reaches_boundary)
    }

    /// Every still-exclusive commit must be a descendant of this boundary.
    /// Otherwise its unread ancestry might recolor a previously counted commit,
    /// even though the pending frontier is entirely common (clock skew/merges).
    fn can_stop_at(&mut self, boundary: ObjectId) -> Result<bool, ReadError> {
        self.proof += 1;
        for n in 0..self.ids.len() {
            self.io.account(|meter| meter.check())?;
            if !self.proof_step() {
                return Ok(false);
            }
            let id = self.ids[n];
            if self.graph.get(&id).expect("retained").reach != 3
                && !self.reaches(id, Some(boundary))?
            {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

/// Two-color merge-base walk. Common frontiers are deferred while any exclusive
/// paint remains. A common boundary can be cut only after the retained graph
/// proves that every exclusive candidate descends from it: no ancestor of that
/// boundary can then be exclusive without forming a cycle. If the proof fails,
/// propagate common paint further and retry within a cumulative linear work
/// allowance. On exhaustion, finish the full colouring walk from the current
/// state without attempting further cuts. This also removes candidates
/// visited too early under clock skew; timestamps never justify a cut.
///
/// Once exclusive paint is drained, further expansion only adds common nodes,
/// so a successful cut stays valid. All unseen ancestry is behind such cuts;
/// all retained exclusive nodes are therefore exact. No count escapes a failed
/// read, charge, deadline, or proof. Grafts and commit-graph are not I/O inputs.
pub(crate) fn walk(
    io: &RepoIo<'_>,
    objects: &impl gix_object::Find,
    head: ObjectId,
    upstream: ObjectId,
) -> Result<(u32, u32), ReadError> {
    io.account(|meter| meter.check())?;
    let allocation = io.account(|meter| {
        let mut allocation = meter.path_allocation();
        allocation.reserve(
            budget::COMMITS as usize
                * (std::mem::size_of::<QueueEntry>() + 4 * std::mem::size_of::<ObjectId>())
                + 1024,
            meter,
        )?;
        Ok(allocation)
    })?;
    let error = Cell::new(None);
    let mut paint = Paint {
        io,
        graph: gix_revwalk::Graph::new(
            CheckedFind {
                objects,
                error: &error,
                io,
            },
            None,
        ),
        error: &error,
        allocation,
        queue: BinaryHeap::new(),
        common: Vec::new(),
        repaint: Vec::new(),
        ids: Vec::new(),
        stack: Vec::new(),
        sequence: 0,
        proof: 0,
        proof_work: 0,
        full_walk: false,
    };
    paint
        .queue
        .try_reserve_exact(budget::COMMITS as usize)
        .map_err(|_| ReadError::Limit)?;
    for scratch in [
        &mut paint.common,
        &mut paint.repaint,
        &mut paint.ids,
        &mut paint.stack,
    ] {
        scratch
            .try_reserve_exact(budget::COMMITS as usize)
            .map_err(|_| ReadError::Limit)?;
    }
    paint.paint(head, 1)?;
    paint.paint(upstream, 2)?;
    loop {
        while !paint.queue.is_empty() || !paint.repaint.is_empty() {
            if let Some(id) = paint.repaint.pop() {
                paint.expand(id)?;
                continue;
            }
            let (_, _, id) = paint.queue.pop().expect("nonempty frontier");
            io.account(|meter| meter.check())?;
            if paint.graph.get(&id).expect("queued").reach == 3 {
                paint.common.push(id);
            } else {
                paint.expand(id)?;
            }
        }
        let Some(id) = paint.common.pop() else {
            break;
        };
        if !paint.full_walk && paint.can_stop_at(id)? {
            let node = paint.graph.get_mut(&id).expect("common");
            node.sent = 3;
            node.queued = false;
        } else {
            paint.expand(id)?;
        }
    }
    // Validate every retained edge, including duplicate parents and edges into
    // cut nodes. Unread ancestry is excluded by the proof, not assumed acyclic
    // from an untrusted timestamp. Object hashes are verified by the adapter.
    paint.proof += 1;
    for n in 0..paint.ids.len() {
        paint.reaches(paint.ids[n], None)?;
    }
    let (mut ahead, mut behind) = (0, 0);
    for node in paint.graph.detach().into_values() {
        io.account(|meter| meter.check())?;
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

#[cfg(test)]
pub(crate) mod observations {
    use std::cell::Cell;
    #[derive(Clone, Copy, Debug, Default)]
    pub struct Counts {
        pub proof_work: usize,
        pub max_work_per_node: usize,
        pub fallbacks: usize,
    }
    thread_local! { static COUNTS: Cell<Counts> = Cell::new(Counts::default()); }
    pub fn take() -> Counts {
        COUNTS.take()
    }
    pub(super) fn proof_step(nodes: usize) {
        COUNTS.with(|slot| {
            let mut c = slot.get();
            c.proof_work += 1;
            c.max_work_per_node = c.max_work_per_node.max(c.proof_work.div_ceil(nodes));
            slot.set(c);
        });
    }
    pub(super) fn fallback() {
        COUNTS.with(|slot| {
            let mut c = slot.get();
            c.fallbacks += 1;
            slot.set(c);
        });
    }
}
