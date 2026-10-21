//! N4 sans-I/O continuation. Only this module chooses names, descriptors and read
//! lengths. An executor observes facts, never manufactures a safety verdict.
//! The CLI preopens `Prefetch` before confinement, then satisfies this continuation
//! from the held descriptors and cached facts (N4 option 3, 2026-10-17).
use super::output::Deadline;
use crate::collection::{
    response::{self, Completed},
    selection::{Catalog, PRODUCT},
    wire::{Binding, BuildId, STREAM_MAX},
};
use crate::color::palette::Mode;
use crate::config::compile::ExecUnit;
use crate::envelope::{self, Envelope, EnvelopeError};
use crate::fs_trust::{self, Facts, Last, NextOwner, PinnedGroupWrite};
use crate::handoff::Permit;
use crate::snapshot::{self, Clock, FrontDecoder, FrontSnapshot, Marker, Refusal};
use crate::status::Status;
use alloc::{boxed::Box, string::String, vec, vec::Vec};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CollectionCopy {
    Current,
    Previous,
}
impl CollectionCopy {
    pub fn index(self) -> usize {
        match self {
            Self::Current => 0,
            Self::Previous => 1,
        }
    }
    pub fn name(self) -> &'static [u8] {
        match self {
            Self::Current => b"response",
            Self::Previous => b"previous",
        }
    }
}

/// Three slots suffice: parent, child, and one file. These are NOT raw OS fds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Slot {
    Directory0,
    Directory1,
    File,
}
impl Slot {
    pub fn index(self) -> usize {
        match self {
            Self::Directory0 => 0,
            Self::Directory1 => 1,
            Self::File => 2,
        }
    }
    fn other(self) -> Self {
        match self {
            Self::Directory0 => Self::Directory1,
            _ => Self::Directory0,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SnapshotCopy {
    Current,
    LastGood,
}
impl SnapshotCopy {
    fn name(self) -> &'static [u8] {
        match self {
            Self::Current => b"snapshot",
            Self::LastGood => b"last-good",
        }
    }
}
/// All possible data sources, authorized only after the runtime walk. The OS
/// adapter prepares these before confinement; choosing which bytes to consume
/// remains with the ordinary continuation below.
pub struct Prefetch {
    parent: Slot,
    uid: u32,
    cwd: Option<Vec<u8>>,
}
impl Prefetch {
    /// Advance only after successfully opening and validating the preceding
    /// directory: an absent collections-v1 root must not hash the cwd.
    pub fn collection_components(&self) -> Option<impl Iterator<Item = String> + '_> {
        let cwd = self.cwd.as_deref()?;
        Some(collection_components_with_address(move || {
            crate::collection::cwd_hash::address(cwd)
        }))
    }
    pub fn accepts_collection_directory(&self, facts: FdFacts) -> bool {
        fs_trust::final_verdict(
            &facts.entry,
            self.uid,
            0,
            NextOwner::Any,
            Last::PrivateFolder,
            facts.local,
            &mut PinnedGroupWrite(&[]),
        )
        .is_ok()
            && facts.entry.mode == 0o040700
    }
    pub fn accepts_collection(&self, facts: FdFacts) -> bool {
        trusted_file(self.uid, facts)
            && (response::HEADER as u64..=STREAM_MAX as u64).contains(&facts.size)
    }
    pub fn parent(&self) -> Slot {
        self.parent
    }
    pub fn names(&self) -> [&'static [u8]; 3] {
        [b"snapshot", b"last-good", b"marker"]
    }
    pub fn index(&self, effect: &Effect) -> Option<usize> {
        match effect.operation() {
            Operation::OpenFile {
                parent,
                name,
                into: Slot::File,
            } if *parent == self.parent => self.names().iter().position(|n| n == name),
            _ => None,
        }
    }
    /// Check every retained file before the filter, even a fallback that the
    /// decoder may never select. No content allocation is made here.
    pub fn accepts(&self, index: usize, facts: FdFacts) -> bool {
        trusted_file(self.uid, facts)
            && match index {
                0 | 1 => FrontDecoder::new(facts.size).is_ok(),
                2 => facts.size == snapshot::MARKER as u64,
                _ => false,
            }
    }
}

fn collection_components_with_address(
    address: impl FnOnce() -> String,
) -> impl Iterator<Item = String> {
    core::iter::once_with(|| String::from("collections-v1"))
        .chain(core::iter::once_with(address))
        .chain(core::iter::once_with(|| String::from("store")))
}

fn trusted_file(uid: u32, f: FdFacts) -> bool {
    let e = f.entry;
    e.uid == uid
        && e.mode == 0o100600
        && f.nlink == 1
        && e.ownership == Some(true)
        && f.local == Some(true)
        && matches!(
            e.acl,
            fs_trust::AclFacts::None
                | fs_trust::AclFacts::DenyOnly
                | fs_trust::AclFacts::PosixExtended
        )
}

/// Read-only operations. Directory names are single canonical components;
/// only the initial root open has no parent and names `/`.
#[derive(Debug, PartialEq, Eq)]
pub enum Operation {
    Uid,
    Clock,
    OpenDirectory {
        parent: Option<Slot>,
        name: Vec<u8>,
        into: Slot,
    },
    OpenFile {
        parent: Slot,
        name: &'static [u8],
        into: Slot,
    },
    /// Consume one of the two separately prefetched collection descriptors.
    OpenCollection(CollectionCopy),
    Inspect(Slot),
    Read {
        slot: Slot,
        len: usize,
    },
    Close(Slot),
}
/// Cannot be constructed outside core. No raw arguments or source paths go to
/// the executor, only a reference to this one approved operation.
pub struct Effect {
    operation: Operation,
}
impl Effect {
    pub fn operation(&self) -> &Operation {
        &self.operation
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FdFacts {
    pub entry: Facts,
    pub local: Option<bool>,
    pub nlink: u64,
    pub size: u64,
}
/// `Opened` means the executor has retained the descriptor in the requested
/// empty slot. Inspect/read use that SAME descriptor. A failed close must still
/// relinquish the slot, never retry a possibly recycled descriptor.
pub enum Observation {
    Uid(u32),
    Clock(Option<Clock>),
    Opened,
    Facts(FdFacts),
    Bytes(Vec<u8>),
    Closed,
    Failed,
}
pub enum Step {
    Read(Effect),
    Done(Observed),
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Start,
    Uid,
    StartClock,
    OpenDirectory,
    DirectoryFacts,
    CloseParent,
    OpenFile,
    FileFacts,
    ReadFile,
    CloseFile,
    FinalClock,
    Cleanup,
    Done,
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum File {
    Snapshot(SnapshotCopy),
    Marker,
    Collection(CollectionCopy),
}
impl File {
    fn name(self) -> &'static [u8] {
        match self {
            Self::Snapshot(c) => c.name(),
            Self::Marker => b"marker",
            Self::Collection(copy) => copy.name(),
        }
    }
}
/// Every field is private, including pending-operation and slot ownership state.
pub struct ReadPlan {
    deadline: Option<Deadline>,
    parsed: Result<Envelope, EnvelopeError>,
    phase: Phase,
    after_close: Phase,
    pending: bool,
    names: Vec<Vec<u8>>,
    runtime_at: usize,
    at: usize,
    directory: Slot,
    live: [bool; 3],
    owner: NextOwner,
    uid: Option<u32>,
    context: Option<[u8; 4]>,
    start: Option<Clock>,
    entry: Option<Clock>,
    build_id: Option<BuildId>,
    catalog: Catalog<'static>,
    render_config: Option<super::CompiledConfig>,
    collection_bytes: Vec<u8>,
    collection_len: usize,
    collection_end: usize,
    observed: Observed,
    file: File,
    decoder: Option<FrontDecoder>,
    marker_bytes: Vec<u8>,
    read_len: usize,
}
/// Only `next` can construct a successful observation. Default is fail-closed.
#[derive(Default)]
pub struct Observed {
    runtime_ok: bool,
    selected: Option<Box<FrontSnapshot>>,
    last_good: bool,
    marker: Option<Marker>,
    clock: Option<Clock>,
    boot_changed: bool,
    collection: Option<Box<Completed>>,
}

pub fn prepare(argv: &[&[u8]]) -> ReadPlan {
    ReadPlan {
        deadline: None,
        parsed: envelope::parse(argv),
        phase: Phase::Start,
        after_close: Phase::OpenFile,
        pending: false,
        names: Vec::new(),
        runtime_at: 0,
        at: 0,
        directory: Slot::Directory0,
        live: [false; 3],
        owner: NextOwner::Any,
        uid: None,
        context: None,
        start: None,
        entry: None,
        build_id: None,
        catalog: PRODUCT,
        render_config: None,
        collection_bytes: Vec::new(),
        collection_len: 0,
        collection_end: response::HEADER,
        observed: Observed::default(),
        file: File::Snapshot(SnapshotCopy::Current),
        decoder: None,
        marker_bytes: Vec::new(),
        read_len: 0,
    }
}
impl ReadPlan {
    pub fn with_entry(mut self, entry: Clock) -> Self {
        self.entry = Some(entry);
        self
    }
    pub fn with_build_id(mut self, build_id: BuildId) -> Self {
        self.build_id = Some(build_id);
        self
    }
    /// Pure adapter policy seam. The product adapter uses only `prepare` and
    /// the fixed snapshot decoder; catalogs and render inputs never come from argv.
    pub fn with_catalog(
        mut self,
        catalog: Catalog<'static>,
        config: super::CompiledConfig,
    ) -> Self {
        self.catalog = catalog;
        self.render_config = Some(config);
        self
    }
    /// Carry the adapter's entry deadline unchanged through decoding/rendering.
    /// The adapter must check it before every OS effect; core does not read time.
    pub fn with_deadline(mut self, deadline: Deadline) -> Self {
        self.deadline = Some(deadline);
        self
    }

    /// Available at exactly the first file-open boundary, after every ancestor
    /// and the init dev/ino pin have been approved. Invalid envelopes never get
    /// a prefetch capability.
    pub fn prefetch(&self, effect: &Effect) -> Option<Prefetch> {
        if self.pending
            && self.phase == Phase::OpenFile
            && self.file == File::Snapshot(SnapshotCopy::Current)
            && self.observed.runtime_ok
            && matches!(effect.operation(), Operation::OpenFile { parent, name: b"snapshot", into: Slot::File } if *parent == self.directory)
        {
            Some(Prefetch {
                parent: self.directory,
                uid: self.uid?,
                cwd: self
                    .parsed
                    .as_ref()
                    .ok()?
                    .pwd
                    .clone()
                    .filter(|p| p.first() == Some(&b'/') && p.len() <= 65_536 && !p.contains(&0)),
            })
        } else {
            None
        }
    }
    fn initialize(&mut self) -> Option<()> {
        let e = self.parsed.as_ref().ok()?;
        e.shell?;
        let root = e.runtime_root.as_ref()?;
        let config = e.config_root.as_deref()?;
        let state = e.state_root.as_deref()?;
        let contexts = snapshot::context_components(config, state).ok()?;
        self.context = snapshot::context_crc(config, state).ok();
        // Canonical spelling from init: no normalization and no source I/O.
        if root.path.first() != Some(&b'/')
            || root.path.contains(&0)
            || root.path.len() > snapshot::COMPILED_MAX
        {
            return None;
        }
        self.names.push(vec![b'/']);
        if root.path != b"/" {
            for part in root.path[1..].split(|b| *b == b'/') {
                if part.is_empty() || part == b"." || part == b".." {
                    return None;
                }
                self.names.push(part.to_vec());
            }
        }
        self.runtime_at = self.names.len() - 1;
        self.names
            .extend(contexts.into_iter().map(|s| s.into_bytes()));
        Some(())
    }
    fn stop(&mut self) {
        self.phase = Phase::Cleanup;
    }
    fn refuse_runtime(&mut self) {
        self.observed = Observed::default();
        self.stop();
    }
    fn next_file(&mut self) {
        self.decoder = None;
        self.after_close = Phase::OpenFile;
        match self.file {
            File::Snapshot(SnapshotCopy::Current) if self.observed.selected.is_none() => {
                self.file = File::Snapshot(SnapshotCopy::LastGood);
            }
            File::Snapshot(_) => self.file = File::Marker,
            File::Marker if self.expected_binding().is_some() => {
                self.file = File::Collection(CollectionCopy::Current)
            }
            File::Collection(CollectionCopy::Current) if self.observed.collection.is_none() => {
                self.file = File::Collection(CollectionCopy::Previous)
            }
            File::Marker | File::Collection(_) => self.after_close = Phase::FinalClock,
        }
        self.phase = if self.live[Slot::File.index()] {
            Phase::CloseFile
        } else {
            self.after_close
        };
    }
    fn file_facts(&mut self, f: FdFacts) -> bool {
        let Some(uid) = self.uid else {
            return false;
        };
        if !trusted_file(uid, f) {
            return false;
        }
        match self.file {
            File::Marker => f.size == snapshot::MARKER as u64,
            File::Snapshot(_) => match FrontDecoder::new(f.size) {
                Ok(d) => {
                    self.decoder = Some(d);
                    true
                }
                Err(_) => false,
            },
            File::Collection(_) => {
                if !(response::HEADER as u64..=STREAM_MAX as u64).contains(&f.size) {
                    return false;
                }
                self.collection_bytes.clear();
                self.collection_len = f.size as usize;
                self.collection_end = response::HEADER;
                true
            }
        }
    }
    fn expected_binding(&self) -> Option<Binding> {
        let e = self.parsed.as_ref().ok()?;
        let selected = self.observed.selected.as_ref()?;
        let entry = self.entry?;
        let start = self.start?;
        if entry.boot != start.boot
            || entry.kind != start.kind
            || entry.domain != start.domain
            || entry.resume != start.resume
            || entry.now > start.now
            || ![1, 2].contains(&entry.kind)
        {
            return None;
        }
        Some(Binding {
            build_id: self.build_id?,
            snapshot: selected.id,
            clock_kind: entry.kind,
            domain: entry.domain,
            resume: entry.resume,
            config: e.config_root.clone()?,
            state: e.state_root.clone()?,
            cwd: e.pwd.clone()?,
            mask: self.catalog.worker_mask(&selected.config, e.width, false),
        })
    }
    fn collection_bytes(&mut self, bytes: &[u8]) {
        self.collection_bytes.extend_from_slice(bytes);
        if self.collection_bytes.len() != self.collection_end {
            return;
        }
        if self.collection_end == response::HEADER {
            if response::declared_len(&self.collection_bytes).ok() != Some(self.collection_len) {
                self.next_file();
                return;
            }
            if self
                .collection_bytes
                .try_reserve_exact(self.collection_len - self.collection_bytes.len())
                .is_err()
            {
                self.next_file();
                return;
            }
            self.collection_end = self.collection_len;
            if self.collection_bytes.len() < self.collection_end {
                return;
            }
        }
        self.observed.collection =
            Completed::decode_with_catalog(&self.collection_bytes, self.catalog.segments)
                .ok()
                .filter(|r| {
                    self.expected_binding()
                        .zip(self.entry)
                        .is_some_and(|(binding, entry)| r.eligible(&binding, entry))
                })
                .map(|r| {
                    // Keep ownership explicit without exposing a function address.
                    Box::new(r)
                });
        self.next_file();
    }
    fn directory_facts(&mut self, f: FdFacts) -> bool {
        let (Some(uid), Ok(e)) = (self.uid, self.parsed.as_ref()) else {
            return false;
        };
        if f.entry.mode & 0o170000 != 0o040000 {
            return false;
        }
        let mut groups = PinnedGroupWrite(&e.runtime_groups);
        if self.at < self.runtime_at {
            match fs_trust::ancestor_verdict(&f.entry, uid, self.at, self.owner, &mut groups) {
                Ok(owner) => self.owner = owner,
                Err(_) => return false,
            }
        } else {
            if fs_trust::final_verdict(
                &f.entry,
                uid,
                self.at,
                self.owner,
                Last::PrivateFolder,
                f.local,
                &mut groups,
            )
            .is_err()
            {
                return false;
            }
            self.owner = NextOwner::Any;
            if self.at == self.runtime_at {
                let Some(pin) = e.runtime_root.as_ref() else {
                    return false;
                };
                if (pin.dev, pin.ino) != (f.entry.dev, f.entry.ino) {
                    return false;
                }
                self.observed.runtime_ok = true;
            }
        }
        true
    }
    fn accept(&mut self, o: Observation) {
        match (self.phase, o) {
            (Phase::Uid, Observation::Uid(uid)) => {
                self.uid = Some(uid);
                self.phase = Phase::StartClock;
            }
            (Phase::StartClock, Observation::Clock(c)) => {
                self.start = c;
                self.phase = Phase::OpenDirectory;
            }
            (Phase::StartClock, Observation::Failed) => {
                self.start = None;
                self.phase = Phase::OpenDirectory;
            }
            (Phase::OpenDirectory, Observation::Opened) => {
                self.live[self.directory.index()] = true;
                self.phase = Phase::DirectoryFacts;
            }
            (Phase::OpenDirectory, Observation::Failed) => self.stop(),
            (Phase::DirectoryFacts, Observation::Facts(f)) => {
                if !self.directory_facts(f) {
                    self.refuse_runtime();
                } else if self.at > 0 {
                    self.phase = Phase::CloseParent;
                } else {
                    self.after_directory();
                }
            }
            (Phase::CloseParent, Observation::Closed) => {
                self.live[self.directory.other().index()] = false;
                self.after_directory();
            }
            (Phase::OpenFile, Observation::Opened) => {
                self.live[Slot::File.index()] = true;
                self.phase = Phase::FileFacts;
            }
            (Phase::OpenFile, Observation::Failed) => self.next_file(),
            (Phase::FileFacts, Observation::Facts(f)) => {
                if self.file_facts(f) {
                    self.phase = Phase::ReadFile;
                } else {
                    self.next_file();
                }
            }
            (Phase::ReadFile, Observation::Bytes(bytes)) => {
                if bytes.is_empty() || bytes.len() > self.read_len {
                    self.next_file();
                    return;
                }
                match self.file {
                    File::Collection(_) => self.collection_bytes(&bytes),
                    File::Marker => {
                        self.marker_bytes.extend_from_slice(&bytes);
                        if self.marker_bytes.len() == snapshot::MARKER {
                            self.observed.marker = Marker::decode(&self.marker_bytes).ok();
                            self.next_file();
                        }
                    }
                    File::Snapshot(copy) => {
                        let Some(d) = self.decoder.as_mut() else {
                            self.next_file();
                            return;
                        };
                        if d.push(&bytes).is_err() {
                            self.next_file();
                            return;
                        }
                        if d.read_len() == 0 {
                            self.observed.selected = self
                                .decoder
                                .take()
                                .and_then(|d| match d.finish() {
                                    Ok(plan) => Some(Box::new(plan)),
                                    Err(_) => None,
                                })
                                .filter(|s| {
                                    snapshot::same_boot(
                                        s.id,
                                        self.start.map(|c| c.boot),
                                        self.context.unwrap_or([0; 4]),
                                    )
                                });
                            if let Some(selected) = self.observed.selected.as_mut() {
                                if let Some(config) = self.render_config.take() {
                                    selected.config = config;
                                }
                            }
                            self.observed.last_good =
                                copy == SnapshotCopy::LastGood && self.observed.selected.is_some();
                            self.next_file();
                        }
                    }
                }
            }
            (Phase::FileFacts | Phase::ReadFile, Observation::Failed) => self.next_file(),
            (Phase::CloseFile, Observation::Closed) => {
                self.live[Slot::File.index()] = false;
                self.phase = self.after_close;
            }
            (Phase::FinalClock, Observation::Clock(c)) => {
                // A backwards or changed clock during this prompt cannot authorize
                // execution, even when the marker would otherwise still match.
                self.observed.boot_changed =
                    c.is_some_and(|end| self.start.is_none_or(|start| start.boot != end.boot));
                self.observed.clock = c.filter(|end| {
                    self.start.is_some_and(|start| {
                        start.boot == end.boot
                            && start.kind == end.kind
                            && start.domain == end.domain
                            && start.resume == end.resume
                            && start.now <= end.now
                    })
                });
                if self.observed.clock.is_none() {
                    self.observed.collection = None;
                }
                self.stop();
            }
            (Phase::FinalClock, Observation::Failed) => {
                self.observed.clock = None;
                self.observed.collection = None;
                self.stop();
            }
            (Phase::CloseParent, _) => {
                self.live[self.directory.other().index()] = false;
                self.refuse_runtime();
            }
            (Phase::CloseFile, _) => {
                self.live[Slot::File.index()] = false;
                self.refuse_runtime();
            }
            (Phase::Cleanup, Observation::Closed) => {
                if let Some(i) = self.live.iter().position(|x| *x) {
                    self.live[i] = false;
                }
            }
            (Phase::Cleanup, _) => {
                if let Some(i) = self.live.iter().position(|x| *x) {
                    self.live[i] = false;
                }
                self.refuse_runtime();
            }
            // Failed or malformed observation is never inferred to be success.
            _ => self.refuse_runtime(),
        }
    }
    fn after_directory(&mut self) {
        if self.at + 1 == self.names.len() {
            // Without a boot identity no saved screen can be reused.
            if self.start.is_none_or(|c| c.boot == [0; 16]) {
                self.stop();
            } else {
                self.phase = Phase::OpenFile;
            }
        } else {
            self.at += 1;
            self.directory = self.directory.other();
            self.phase = Phase::OpenDirectory;
        }
    }
    fn operation(&mut self) -> Option<Operation> {
        Some(match self.phase {
            Phase::Uid => Operation::Uid,
            Phase::StartClock | Phase::FinalClock => Operation::Clock,
            Phase::OpenDirectory => Operation::OpenDirectory {
                parent: (self.at > 0).then(|| self.directory.other()),
                name: self.names.get(self.at)?.clone(),
                into: self.directory,
            },
            Phase::DirectoryFacts => Operation::Inspect(self.directory),
            Phase::CloseParent => Operation::Close(self.directory.other()),
            Phase::OpenFile if matches!(self.file, File::Collection(_)) => {
                let File::Collection(copy) = self.file else {
                    return None;
                };
                Operation::OpenCollection(copy)
            }
            Phase::OpenFile => Operation::OpenFile {
                parent: self.directory,
                name: self.file.name(),
                into: Slot::File,
            },
            Phase::FileFacts => Operation::Inspect(Slot::File),
            Phase::ReadFile => {
                self.read_len = match self.file {
                    File::Marker => snapshot::MARKER.saturating_sub(self.marker_bytes.len()),
                    File::Snapshot(_) => self.decoder.as_ref()?.read_len(),
                    File::Collection(_) => self
                        .collection_end
                        .saturating_sub(self.collection_bytes.len())
                        .min(16_384),
                };
                if self.read_len == 0 {
                    return None;
                }
                Operation::Read {
                    slot: Slot::File,
                    len: self.read_len,
                }
            }
            Phase::CloseFile => Operation::Close(Slot::File),
            Phase::Cleanup => Operation::Close(match self.live.iter().position(|x| *x)? {
                0 => Slot::Directory0,
                1 => Slot::Directory1,
                _ => Slot::File,
            }),
            _ => return None,
        })
    }
}

pub fn next(plan: &mut ReadPlan, previous: Option<Observation>) -> Step {
    if plan.phase == Phase::Done {
        return Step::Done(Observed::default());
    }
    if plan.phase == Phase::Start && previous.is_none() {
        plan.phase = if plan.initialize().is_some() {
            Phase::Uid
        } else {
            Phase::Cleanup
        };
    } else if plan.pending {
        plan.pending = false;
        if let Some(o) = previous {
            plan.accept(o);
        } else {
            plan.refuse_runtime();
        }
    } else {
        plan.refuse_runtime();
    }
    if let Some(operation) = plan.operation() {
        plan.pending = true;
        Step::Read(Effect { operation })
    } else {
        plan.phase = Phase::Done;
        Step::Done(core::mem::take(&mut plan.observed))
    }
}

/// Execution is permission for these decoded units only, never for arbitrary
/// caller-supplied policies. A relay permit alone does not grant a unit.
#[derive(Default)]
pub struct Eligibility {
    permit: Option<Permit>,
    units: Vec<ExecUnit>,
}
impl Eligibility {
    pub fn permit(&self) -> Option<Permit> {
        self.permit
    }
    pub fn units(&self) -> &[ExecUnit] {
        &self.units
    }
}
pub struct Response {
    pub record: Vec<u8>,
    /// The prompt entry deadline, distinct from the snapshot's execution permit.
    /// Informational: the adapter enforces the deadline itself (its pre-filter
    /// timer, the per-step clock check and the write loop); nothing reads this
    /// field to stop work, so later code must not assume it does.
    pub deadline: Option<Deadline>,
    /// Snapshot trust expiry; it must never extend the prompt's output deadline.
    pub execution: Eligibility,
    pub worker_mask: u32,
    pub status: Status,
}

fn trust_status(refusal: Refusal) -> Status {
    match refusal {
        Refusal::Missing => Status::DEGRADED_TRUST_UNVERIFIED,
        Refusal::Invalid => Status::DEGRADED_TRUST_INVALID,
        Refusal::Pair => Status::DEGRADED_TRUST_MISMATCH,
        Refusal::Expired => Status::DEGRADED_TRUST_EXPIRED,
        Refusal::Boot | Refusal::Clock | Refusal::Resume | Refusal::Future => {
            Status::DEGRADED_TRUST_CLOCK
        }
    }
}
/// Finish never observes the OS. COLORFGBG comes only from the display envelope,
/// separate from snapshot identity. Saved OSC 11 observation is deferred until
/// its observation file and address are defined (N4 review ruling).
pub fn finish(plan: ReadPlan, observed: Observed) -> Response {
    let catalog = Catalog {
        segments: plan.catalog.segments,
        workers: plan.catalog.workers,
    };
    finish_with_catalog(plan, observed, &catalog)
}

/// Pure adapter seam. The shipped adapter always uses `finish` and its fixed
/// product catalog; declarations and worker capability are not shell input.
pub fn finish_with_catalog(
    plan: ReadPlan,
    mut observed: Observed,
    catalog: &crate::collection::selection::Catalog<'_>,
) -> Response {
    let mut response = Response {
        record: Vec::new(),
        deadline: plan.deadline,
        execution: Eligibility::default(),
        worker_mask: 0,
        status: Status::ERROR_CONFIG_DEFAULT,
    };
    let e = match plan.parsed {
        Err(EnvelopeError::NoSupportedRecordVersion) => return response,
        Err(EnvelopeError::BadArgs(_)) => {
            response.status = Status::ERROR_BAD_ARGS;
            crate::record::write_minimal_b1(response.status, &mut response.record);
            return response;
        }
        Ok(e) => e,
    };
    // Binding to the current envelope is independent of the reader's address.
    let context = e
        .config_root
        .as_deref()
        .zip(e.state_root.as_deref())
        .and_then(|(c, s)| snapshot::context_crc(c, s).ok());
    if plan.phase != Phase::Done || !observed.runtime_ok {
        observed.selected = None;
        response.status = Status::DEGRADED_RUNTIME_ROOT;
    } else {
        observed.selected = observed.selected.filter(|s| {
            !observed.boot_changed
                && context.is_some_and(|context| {
                    snapshot::same_boot(s.id, plan.start.map(|c| c.boot), context)
                })
        });
        if let Some(s) = &observed.selected {
            let eligibility = if observed.marker.is_some_and(|m| m.invalid) {
                Err(Refusal::Invalid)
            } else if observed.marker.is_none() {
                Err(Refusal::Missing)
            } else if observed.marker.is_some_and(|m| m.id != s.id) {
                Err(Refusal::Pair)
            } else {
                observed
                    .clock
                    .ok_or(Refusal::Clock)
                    .and_then(|clock| s.eligible(observed.marker, clock, context.unwrap_or([0; 4])))
            };
            response.status = if observed.last_good {
                Status::ERROR_CONFIG_LAST_GOOD
            } else {
                match eligibility {
                    Err(why) => trust_status(why),
                    Ok(_) => Status::OK_NONE,
                }
            };
            response.worker_mask = catalog.worker_mask(&s.config, e.width, e.redraw);
            if let (Ok(deadline), Some(clock)) = (eligibility, observed.clock) {
                response.execution.permit = Some(Permit {
                    deadline,
                    kind: clock.kind,
                    boot: clock.boot,
                    domain: clock.domain,
                    resume: clock.resume,
                });
                response.execution.units = s
                    .config
                    .exec_units
                    .iter()
                    .filter(|u| u.not_run.is_none())
                    .cloned()
                    .collect();
            }
        }
    }
    if let Some(shell) = e.shell {
        super::render_selected_with_catalog(
            &e,
            shell,
            response.status,
            observed.selected.as_ref().map(|s| &s.config),
            e.colorfgbg.unwrap_or(Mode::Dark),
            observed
                .collection
                .as_deref()
                .filter(|_| observed.selected.is_some()),
            catalog,
            &mut response.record,
        );
    } else {
        crate::record::write_minimal_b1(response.status, &mut response.record);
    }
    response
}

#[cfg(test)]
mod tests;
