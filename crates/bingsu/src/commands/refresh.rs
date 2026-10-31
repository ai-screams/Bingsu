//! One publication engine for init/reload/edit and the refresh helper. No
//! configured command is executed here. N3 owns process resource enforcement.
use super::{
    config_load::{Loader, Places, Verified},
    group_policy::SystemGroups,
    init::roots::ConfigRootPin,
    io_meter::{AxisUse, IoMeter},
    runtime_root::Pinned,
    snapshot_store::{CheckedContextFd, DataFile, LockedStore, Slot, StoreError},
    sys,
    trust_record::SelectionLock,
};
use bingsu_core::{
    color::palette::Mode,
    config::{compile::BUILTIN_TOML, report, source},
    envelope::Envelope,
    snapshot::{self, Action, Clock, ClockSource, Identity, Marker, Outcome, Sequence, Snapshot},
};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::PathBuf;

const WORK_NS: u64 = 500_000_000;
const LIFE_NS: u64 = 2_000_000_000;
#[derive(Clone)]
pub struct RefreshRequest {
    pub runtime: Pinned,
    pub config_written: PathBuf,
    pub config_canonical: PathBuf,
    pub config_root_shape_only: bool,
    pub state_root: PathBuf,
    pub home: PathBuf,
    pub me: u32,
    pub user: Vec<u8>,
    pub version: [u32; 3],
    /// Cache discriminator only; None always requires compilation.
    pub build: Option<super::build_identity::BuildIdentity>,
    /// Captured at process entry, before root/NSS observations. N3 also
    /// enforces this deadline with its independent watchdog.
    pub process_started: Clock,
}
impl RefreshRequest {
    pub fn from_envelope(
        exe: &std::path::Path,
        e: &Envelope,
        user: &sys::Passwd,
        process_started: Clock,
        version: [u32; 3],
    ) -> Option<Self> {
        let path = |b: &Vec<u8>| PathBuf::from(std::ffi::OsString::from_vec(b.clone()));
        let r = e.runtime_root.as_ref()?;
        Some(Self {
            runtime: Pinned {
                dev: r.dev,
                ino: r.ino,
                path: path(&r.path),
            },
            config_written: path(e.config_root_written.as_ref()?),
            config_canonical: path(e.config_root.as_ref()?),
            config_root_shape_only: e.config_root_shape_only,
            state_root: path(e.state_root.as_ref()?),
            home: path(e.home.as_ref()?),
            me: sys::current_uid(),
            user: user.name.clone(),
            version,
            build: super::build_identity::read(exe),
            process_started,
        })
    }
}
#[derive(Debug, PartialEq, Eq)]
pub enum RefreshResult {
    Published {
        generation: u64,
        left_out: Vec<PathBuf>,
    },
    Revalidated {
        generation: u64,
    },
    Invalid,
    Incomplete,
    Busy,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Checkpoint {
    Locked,
    Read,
    Staged,
    Validated,
    Before(Slot),
    After(Slot),
    Published,
}
struct Budget {
    last: std::cell::Cell<u64>,
    start: Clock,
    end: u64,
}
impl Budget {
    fn new(start: Clock, process: Clock) -> Option<Self> {
        let end = start
            .now
            .checked_add(WORK_NS)?
            .min(process.now.checked_add(LIFE_NS)?);
        let b = Self {
            last: std::cell::Cell::new(start.now),
            start,
            end,
        };
        (same_clock(start, process) && start.now >= process.now && start.now < end).then_some(b)
    }
    fn check(&self, clock: &mut dyn ClockSource) -> Result<Clock, StoreError> {
        let now = clock.observe().map_err(|_| StoreError::Unsafe)?;
        if !same_clock(now, self.start)
            || now.now < self.last.get()
            || now.now >= self.end
            || self
                .start
                .now
                .checked_add(snapshot::T_NS)
                .is_none_or(|end| now.now >= end)
        {
            return Err(StoreError::Unsafe);
        }
        self.last.set(now.now);
        Ok(now)
    }
}
fn same_clock(a: Clock, b: Clock) -> bool {
    a.boot == b.boot
        && a.kind == b.kind
        && a.domain == b.domain
        && a.resume == b.resume
        && [1, 2].contains(&a.kind)
}
pub fn refresh(request: RefreshRequest, clock: &mut dyn ClockSource) -> RefreshResult {
    refresh_with(request, clock, &mut |_| {})
}
pub fn refresh_broker(
    request: RefreshRequest,
    clock: &mut dyn ClockSource,
    broker: &mut Broker<'_>,
) -> RefreshResult {
    refresh_with_broker(request, clock, &mut |_| {}, broker)
}
// The broker may start supervision here but must return without joining it.
// All snapshot/source owners are released before refresh_broker returns.
type Broker<'a> = dyn FnMut(
        &CheckedContextFd,
        Option<(&bingsu_core::config::compile::CompiledConfig, Identity)>,
        Clock,
    ) -> Result<(), StoreError>
    + 'a;
fn refresh_with(
    request: RefreshRequest,
    clock: &mut dyn ClockSource,
    hook: &mut dyn FnMut(Checkpoint),
) -> RefreshResult {
    refresh_with_broker(request, clock, hook, &mut |_, _, _| Ok(()))
}
fn refresh_with_broker(
    request: RefreshRequest,
    clock: &mut dyn ClockSource,
    hook: &mut dyn FnMut(Checkpoint),
    broker: &mut Broker<'_>,
) -> RefreshResult {
    // This observation must precede even the runtime root's group queries.
    let Ok(start) = clock.observe() else {
        return RefreshResult::Incomplete;
    };
    let Some(budget) = Budget::new(start, request.process_started) else {
        return RefreshResult::Incomplete;
    };
    match run(&request, clock, budget, hook, broker) {
        Ok(r) => r,
        Err(StoreError::Busy) => RefreshResult::Busy,
        Err(_) => RefreshResult::Incomplete,
    }
}
fn run(
    r: &RefreshRequest,
    clock: &mut dyn ClockSource,
    b: Budget,
    hook: &mut dyn FnMut(Checkpoint),
    broker: &mut Broker<'_>,
) -> Result<RefreshResult, StoreError> {
    let mut groups = SystemGroups::new(&r.user);
    let context = snapshot::context_crc(
        r.config_canonical.as_os_str().as_bytes(),
        r.state_root.as_os_str().as_bytes(),
    )?;
    let root = CheckedContextFd::open(
        &r.runtime,
        r.config_canonical.as_os_str().as_bytes(),
        r.state_root.as_os_str().as_bytes(),
        r.me,
        &mut groups,
        true,
    )?;
    let store = root.try_lock()?;
    hook(Checkpoint::Locked);
    b.check(clock)?;
    // Snapshot lock -> state selection lock, also across distinct runtimes.
    super::runtime_root::ensure_root(
        &r.state_root,
        r.me,
        &mut groups,
        bingsu_core::fs_trust::Last::Mine,
    )?;
    let selection = SelectionLock::try_lock(&r.state_root, r.me, &mut groups)
        .map_err(super::snapshot_store::lock_error)?;
    let record = selection
        .read(&mut groups)
        .map_err(|_| StoreError::Unsafe)?;
    let selection_evidence = selection.evidence_export()?;
    // Other contexts sharing this state root may compile concurrently. The
    // immutable record fd (or checked absence) survives this short lock.
    drop(selection);
    // One meter for the round's config-source I/O, the root walk included.
    let mut meter = IoMeter::session();
    let pin = ConfigRootPin::reopen_metered(
        &r.config_written,
        &r.config_canonical,
        r.config_root_shape_only,
        r.me,
        &mut groups,
        &mut meter,
    )?;
    let places = Places {
        config_root: pin,
        home: r.home.clone(),
        me: r.me,
        user: r.user.clone(),
    };
    let mut loader = match record {
        Some(e) => Loader::with_record_metered(places, e, meter),
        None => Loader::new_metered(places, meter),
    };
    b.check(clock)?;
    let previous = store.read(DataFile::Snapshot)?;
    let old = previous
        .as_deref()
        .and_then(|v| Snapshot::decode(v).ok())
        .filter(|s| snapshot::same_boot(s.id, Some(b.start.boot), context));
    let seq = store
        .read(DataFile::Sequence)?
        .as_deref()
        .and_then(|v| Sequence::decode(v).ok())
        .filter(|s| s.boot == b.start.boot);
    let seq = match seq {
        Some(s) => s,
        None => Sequence {
            boot: b.start.boot,
            epoch: sys::random_bytes16().ok_or(StoreError::Unsafe)?,
            generation: 0,
            verified: 0,
        },
    };
    b.check(clock)?;
    let roots = loader.roots(BUILTIN_TOML.as_bytes());
    let loaded = source::load(roots, &mut loader, r.version);
    b.check(clock)?;
    let files = match &loaded {
        Ok(l) => &l.files,
        Err(e) => &e.files,
    };
    let export = loader.evidence_export(
        files,
        &r.state_root,
        r.version,
        r.build.as_ref().map_or(&[], |id| id.as_slice()),
        &selection_evidence,
    )?;
    let unchanged = r.build.is_some()
        && loaded.is_ok()
        && old.as_ref().is_some_and(|s| {
            s.id.epoch == seq.epoch
                && s.id.generation <= seq.generation
                && export.matches(&s.metadata)
        });
    hook(Checkpoint::Read);
    let mut left_out = Vec::new();
    let report = if unchanged {
        None
    } else {
        Some(report::from_loaded(loaded, Mode::Dark))
    };
    b.check(clock)?;
    let compiled = unchanged || report.as_ref().is_some_and(|r| r.snapshot.is_some());
    // Revalidate before considering publication or invalidation.
    let before = loader.io_used();
    loader.revalidate().map_err(|_| StoreError::Unsafe)?;
    let after = loader.io_used();
    // Two more revalidations follow, each repeating the work just measured in
    // this round: `verified` below and the last one before the marker. Both
    // must fit now, before the sequence moves; a source tree that changes in
    // between still ends at the last one, on the path of any other change.
    let remaining: AxisUse = std::array::from_fn(|i| (after[i] - before[i]).saturating_mul(2));
    loader.io_fits(&remaining).map_err(|_| StoreError::Unsafe)?;
    let verification = loader.verified(
        report.as_ref().map_or(&[], |r| r.files.as_slice()),
        compiled,
    );
    let outcome = match verification {
        Verified::Publish { left_out: paths } => {
            left_out = paths;
            Outcome::Publish
        }
        Verified::Invalid => Outcome::Invalid,
        Verified::Incomplete => return Ok(RefreshResult::Incomplete),
    };
    let now = b.check(clock)?;
    let action = snapshot::decide(
        outcome,
        !unchanged,
        seq.generation,
        seq.verified,
        b.start.now,
        now.now,
        b.end,
    );
    let (generation, verified) = match action {
        Action::Replace { generation, seq } => (generation, seq),
        Action::Refresh { seq, .. } | Action::Invalidate { seq } => {
            (old.as_ref().map_or(0, |s| s.id.generation), seq)
        }
        Action::Keep => return Ok(RefreshResult::Incomplete),
    };
    let reserved = Sequence {
        generation: if matches!(action, Action::Replace { .. }) {
            generation
        } else {
            seq.generation
        },
        verified,
        ..seq
    };
    store.stage(Slot::Sequence, &reserved.encode())?;
    install(&store, Slot::Sequence, hook)?;
    b.check(clock)?;
    let replace = matches!(action, Action::Replace { .. });
    let id = if replace {
        let report = report.as_ref().ok_or(StoreError::Unsafe)?;
        let metadata = export.metadata(report)?;
        let id = Identity {
            boot: b.start.boot,
            epoch: seq.epoch,
            context,
            generation,
            source: snapshot::source_crc(snapshot::decode_metadata(&metadata)?),
        };
        let new = Snapshot {
            id,
            config: report.snapshot.clone().ok_or(StoreError::Unsafe)?,
            metadata,
        };
        let bytes = new.encode(b.start.kind, b.start.resume)?;
        b.check(clock)?;
        store.stage(Slot::Snapshot, &bytes)?;
        b.check(clock)?;
        // A damaged or foreign current snapshot can never poison last-good.
        let last = if old.is_some() {
            previous.as_deref().ok_or(StoreError::Unsafe)?
        } else {
            &bytes
        };
        store.stage(Slot::LastGood, last)?;
        id
    } else {
        old.as_ref().map_or(
            Identity {
                boot: b.start.boot,
                epoch: seq.epoch,
                context,
                generation,
                source: [0; 4],
            },
            |s| s.id,
        )
    };
    let marker = Marker {
        id,
        seq: verified,
        verified_at: b.start.now,
        kind: b.start.kind,
        domain: b.start.domain,
        resume: b.start.resume,
        invalid: outcome == Outcome::Invalid,
    };
    store.stage(Slot::Marker, &marker.encode())?;
    b.check(clock)?;
    hook(Checkpoint::Staged);
    // Fully checked source/display state, before the helper's own filter.
    // The collector uses this identity even if a later race cancels publication;
    // a future front can only consume a response for its selected snapshot.
    let fallback = if outcome == Outcome::Invalid && old.is_none() {
        store
            .read(DataFile::LastGood)?
            .as_deref()
            .and_then(|v| Snapshot::decode(v).ok())
            .filter(|s| snapshot::same_boot(s.id, Some(b.start.boot), context))
    } else {
        None
    };
    let display = if replace && old.is_none() {
        // A cold prompt had no compiled screen. Publish first; its next prompt
        // can select collection from that snapshot without waiting for us.
        None
    } else if replace {
        report
            .as_ref()
            .and_then(|r| r.snapshot.as_ref())
            .map(|c| (c, id))
    } else {
        old.as_ref()
            .or(fallback.as_ref())
            .map(|s| (&s.config, s.id))
    };
    broker(&root, display, b.check(clock)?)?;
    b.check(clock)?;
    // Contention now is Incomplete: a sequence reservation may already exist.
    // Reacquire in the same context -> selection order through marker+renew.
    let selection = SelectionLock::try_lock(&r.state_root, r.me, &mut SystemGroups::new(&r.user))?;
    if selection.evidence_export()? != selection_evidence {
        return Err(StoreError::Unsafe);
    }
    // No compile, digest or large copy after this point. Every source and
    // selection descriptor remains owned through the last marker rename.
    loader.revalidate().map_err(|_| StoreError::Unsafe)?;
    selection.unchanged(
        loader.record_evidence.as_ref(),
        &mut SystemGroups::new(&r.user),
    )?;
    let current = CheckedContextFd::open(
        &r.runtime,
        r.config_canonical.as_os_str().as_bytes(),
        r.state_root.as_os_str().as_bytes(),
        r.me,
        &mut SystemGroups::new(&r.user),
        false,
    )?;
    root.same_directory(&current)?;
    store.verify_lock()?;
    store.verify_snapshot()?;
    // Compare the exact original file, including absence, under the lock.
    // Reading a large snapshot here would violate the final-copy boundary;
    // the store's retained identity check below covers the name instead.
    hook(Checkpoint::Validated);
    b.check(clock)?;
    if replace {
        install(&store, Slot::LastGood, hook)?;
        install(&store, Slot::Snapshot, hook)?;
    }
    hook(Checkpoint::Before(Slot::Marker));
    b.check(clock)?;
    store.install(Slot::Marker)?;
    hook(Checkpoint::After(Slot::Marker));
    hook(Checkpoint::Published);
    // Failure here is retryable next round and cannot undo publication.
    if let (Some(next), Some(expected)) = (&loader.renew, &loader.record_evidence) {
        let _ = selection.renew(expected, next, &mut SystemGroups::new(&r.user));
    }
    Ok(match action {
        Action::Replace { .. } => RefreshResult::Published {
            generation,
            left_out,
        },
        Action::Refresh { .. } => RefreshResult::Revalidated { generation },
        Action::Invalidate { .. } => RefreshResult::Invalid,
        Action::Keep => RefreshResult::Incomplete,
    })
}
fn install(
    store: &LockedStore<'_>,
    slot: Slot,
    hook: &mut dyn FnMut(Checkpoint),
) -> Result<(), StoreError> {
    hook(Checkpoint::Before(slot));
    store.install(slot)?;
    hook(Checkpoint::After(slot));
    Ok(())
}

#[cfg(test)]
mod tests;
