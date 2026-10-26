//! Repository identity and bytes-only Git readers for the fixed product workers.
pub mod config;
pub mod discover;
pub mod io;
#[path = "../path_facts.rs"]
pub mod path_facts;
pub mod preflight;
pub mod refs;
pub mod stage_a;
pub mod stage_b;
pub mod stage_c;
pub mod stage_d;
pub mod status_tracked;
pub mod untracked;

pub(crate) use crate::update_sink::UpdateSink;

use crate::safe_read::ReadError;
use bingsu_core::collection::budget::Axis;
use std::cell::RefCell;

#[derive(Debug)]
pub enum CollectError {
    Read(ReadError),
    Budget(Axis),
    Deadline,
    Sink(std::io::Error),
    Panic,
}

pub fn collect(
    request: &bingsu_core::collection::wire::Request,
    sink: &mut dyn UpdateSink,
    mut meter: crate::meter::Meter,
) -> Result<(), CollectError> {
    let access = crate::safe_read::Access::probe(&mut meter).map_err(CollectError::Read)?;
    collect_with_access(request, sink, meter, access)
}

/// Startup's validated macOS probe (or Linux probe) is passed by value, never
/// repeated under repository confinement. There is no environment lookup.
pub fn collect_with_access(
    request: &bingsu_core::collection::wire::Request,
    sink: &mut dyn UpdateSink,
    meter: crate::meter::Meter,
    access: crate::safe_read::Access,
) -> Result<(), CollectError> {
    collect_with_deadlines(request, sink, meter, access, StageDeadlines::PRODUCT)
}

/// Stage allowances remain bounded by the Meter's absolute request deadline.
/// Semantic tests inject ample time so scheduling cannot select their errors.
#[derive(Clone, Copy)]
pub(crate) struct StageDeadlines {
    pub a_ms: u64,
    pub b_ms: u64,
    pub c_ms: u64,
    pub d_ms: u64,
    pub path_ms: u64,
}

impl StageDeadlines {
    pub const PRODUCT: Self = Self {
        a_ms: bingsu_core::collection::budget::A_MS,
        b_ms: bingsu_core::collection::budget::B_MS,
        c_ms: bingsu_core::collection::budget::C_MS,
        d_ms: bingsu_core::collection::budget::D_MS,
        path_ms: bingsu_core::collection::budget::PATH_MS,
    };
}

pub(crate) fn collect_with_deadlines(
    request: &bingsu_core::collection::wire::Request,
    sink: &mut dyn UpdateSink,
    meter: crate::meter::Meter,
    access: crate::safe_read::Access,
    deadlines: StageDeadlines,
) -> Result<(), CollectError> {
    use bingsu_core::collection::{
        git::{self, StageResult},
        wire::{Progress, Update},
    };
    let wants_git = request.binding.mask & (1 << git::SEGMENT) != 0;
    let wants_dir = request.binding.mask & (1 << 1) != 0;
    let meter = RefCell::new(meter);
    let (selected, mut snapshot) = within_stage(&meter, sink, deadlines.a_ms, |sink| {
        let mut meter = meter.borrow_mut();
        let selected = discover::select(request, access, &mut meter)?;
        let (result, device) = match &selected {
            discover::Selection::Outside(cwd, _, _) => {
                (StageResult::Value(git::no_repo()), cwd.device())
            }
            discover::Selection::Repository(roots, _) if wants_git => (
                stage_a::stage_a(roots, roots.head_policy(), &mut meter),
                roots.worktree.device(),
            ),
            discover::Selection::Repository(roots, _) => {
                (StageResult::Value(git::no_repo()), roots.worktree.device())
            }
        };
        meter.check().map_err(CollectError::Read)?;
        let value = match result {
            StageResult::Hidden => return Err(CollectError::Read(ReadError::Denied)),
            StageResult::Partial(value) | StageResult::Value(value) => value,
        };
        meter.check().map_err(CollectError::Read)?;
        if wants_git {
            sink.update(Update {
                segment: git::SEGMENT,
                value: Some(value.clone()),
                facts: None,
            })
            .map_err(CollectError::Sink)?;
            meter.check().map_err(CollectError::Read)?;
            sink.progress(Progress {
                stage_a_complete: true,
                device: Some(device),
            })
            .map_err(CollectError::Sink)?;
        }
        Ok((selected, value))
    })?;
    // A path-local failure cannot erase A or prevent independent Git stages.
    // Keep the error until the end so an unfinished requested stage never sends Complete.
    let mut completion = Ok(());
    if wants_dir {
        let path = within_stage(&meter, sink, deadlines.path_ms, |sink| {
            let mut meter = meter.borrow_mut();
            meter.event("path_facts");
            let discovery = match &selected {
                discover::Selection::Outside(_, _, discovery)
                | discover::Selection::Repository(_, discovery) => discovery,
            };
            let facts = path_facts::collect(discovery, request.binding.path_query, &mut meter);
            let device = match &selected {
                discover::Selection::Outside(root, _, _) => root.device(),
                discover::Selection::Repository(roots, _) => roots.worktree.device(),
            };
            let discovery_complete = facts.in_repo.is_some();
            meter.check().map_err(CollectError::Read)?;
            sink.update(Update {
                segment: 1,
                value: None,
                facts: Some(facts),
            })
            .map_err(CollectError::Sink)?;
            if !wants_git {
                meter.check().map_err(CollectError::Read)?;
                sink.progress(Progress {
                    stage_a_complete: discovery_complete,
                    device: Some(device),
                })
                .map_err(CollectError::Sink)?;
            }
            Ok(())
        });
        match path {
            // A failed wire write latches the sink; no later frame is safe.
            Err(error @ CollectError::Sink(_)) => return Err(error),
            other => completion = other,
        }
    }
    match selected {
        discover::Selection::Outside(cwd, access, discovery) => {
            drop(discovery);
            let mut meter = meter.borrow_mut();
            meter.event("discovery_consumed");
            // No Discovery survives into restriction. The only root is cwd.
            meter.event("before_read_layer");
            #[cfg(target_os = "linux")]
            {
                let mut access = access;
                access
                    .restrict_to(&[&cwd], &mut meter)
                    .map_err(CollectError::Read)?;
            }
            #[cfg(not(target_os = "linux"))]
            let _ = (cwd, access);
            completion
        }
        discover::Selection::Repository(mut roots, discovery) => {
            drop(discovery);
            meter.borrow_mut().event("discovery_consumed");
            roots
                .restrict(&mut meter.borrow_mut())
                .map_err(CollectError::Read)?;
            if !wants_git {
                return completion;
            }
            // PathFacts and ancestor release precede read restriction. B preflight
            // cannot consume the first A's budget or delay its immediate write.
            let mut repo = None;
            let mut objects_allowed = false;
            let b = within_stage(&meter, sink, deadlines.b_ms, |sink| {
                let access = preflight::preflight(&roots, &mut meter.borrow_mut())?;
                if access != preflight::GitAccess::Objects {
                    return Ok(());
                }
                objects_allowed = true;
                // A packed-only repository proves unborn only after preflight.
                // Carry the correction in the next cumulative snapshot.
                if roots.unborn.get() {
                    let branch = field_index("branch");
                    if snapshot.fields[branch] != bingsu_core::field::Field::ABSENT {
                        snapshot.fields[branch] = bingsu_core::field::Field::ABSENT;
                        meter.borrow().check().map_err(CollectError::Read)?;
                        sink.update(Update {
                            segment: git::SEGMENT,
                            value: Some(snapshot.clone()),
                            facts: None,
                        })
                        .map_err(CollectError::Sink)?;
                    }
                }
                meter.borrow_mut().event("repository_init");
                repo = GuardedRepository::from_roots(&roots, &meter).ok();
                meter.borrow_mut().event("stage_b");
                // Unknown global rules yield a completed partial B value. They
                // do not stop C/D or make this stage's execution unfinished.
                let result = repo.as_ref().map_or(StageResult::Hidden, |repo| {
                    stage_b::stage_b(
                        repo,
                        &request.global_excludes,
                        request.global_excludes_known,
                    )
                });
                publish(
                    &meter,
                    sink,
                    &mut snapshot,
                    b"B",
                    &["staged", "modified", "untracked", "conflicted", "filtered"],
                    result,
                )
            });
            if let Err(error) = b {
                // A failed safety preflight never grants access to later work.
                if !objects_allowed || !matches!(error, CollectError::Read(ReadError::Deadline)) {
                    return Err(error);
                }
                completion = completion.and(Err(error));
            }
            if !objects_allowed {
                return completion;
            }
            for (stage, millis, fields) in [
                (b"C", deadlines.c_ms, &["ahead", "behind"][..]),
                (b"D", deadlines.d_ms, &["stash"][..]),
            ] {
                meter.borrow().check().map_err(CollectError::Read)?;
                let result = within_stage(&meter, sink, millis, |sink| {
                    meter
                        .borrow_mut()
                        .event(if stage == b"C" { "stage_c" } else { "stage_d" });
                    let result = if stage == b"C" {
                        // A B-local constructor timeout must not cache failure
                        // across the stage boundary or prevent independent D.
                        if repo.is_none() {
                            repo = GuardedRepository::from_roots(&roots, &meter).ok();
                        }
                        repo.as_ref().map_or(StageResult::Hidden, stage_c::stage_c)
                    } else {
                        stage_d::stage_d(&roots, roots.ref_snapshot(), &meter)
                    };
                    publish(&meter, sink, &mut snapshot, stage, fields, result)
                });
                match result {
                    Err(error @ CollectError::Read(ReadError::Deadline)) => {
                        completion = completion.and(Err(error));
                    }
                    other => other?,
                }
            }
            completion
        }
    }
}

/// Loan the same meter to a stage without keeping a RefCell borrow across its
/// adapters. Catch unwinding at this boundary and restore the request deadline,
/// and report panic to the caller. Counters survive only if the active Meter is
/// returned to this slot: preflight moves it into its own RefCell without a drop
/// guard, so an unwind there drops it. This boundary then restores the deadline
/// on the placeholder, but cannot restore the lost counters.
/// Abort/OOM and blocked calls are exclusively the supervisor's responsibility.
fn within_stage<T>(
    meter: &RefCell<crate::meter::Meter>,
    sink: &mut dyn UpdateSink,
    millis: u64,
    run: impl FnOnce(&mut dyn UpdateSink) -> Result<T, CollectError>,
) -> Result<T, CollectError> {
    sink.stage_deadline(std::time::Instant::now() + std::time::Duration::from_millis(millis));
    let placeholder = meter.borrow().expired_placeholder();
    let mut owner = meter.replace(placeholder);
    let result = owner.stage(millis, |active| {
        std::mem::swap(active, &mut *meter.borrow_mut());
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| run(sink)));
        std::mem::swap(active, &mut *meter.borrow_mut());
        result.unwrap_or(Err(CollectError::Panic))
    });
    meter.replace(owner);
    result
}

fn field_index(name: &str) -> usize {
    bingsu_core::field::BUILTIN[3]
        .field_index(name)
        .expect("fixed git field")
}

/// Only the owning stage's fields replace the previous snapshot. Pending future
/// stages, saturation and approximation all keep the cumulative partial bit set.
fn publish(
    meter: &RefCell<crate::meter::Meter>,
    sink: &mut dyn UpdateSink,
    snapshot: &mut bingsu_core::field::Value,
    stage: &[u8],
    fields: &[&str],
    result: bingsu_core::collection::git::StageResult,
) -> Result<(), CollectError> {
    use bingsu_core::{
        collection::{git::StageResult, wire::Update},
        field::{Field, FieldValue, ValueState},
        width::WidthProfile,
    };
    meter.borrow().check().map_err(CollectError::Read)?;
    let mut next = snapshot.clone();
    for name in fields {
        let index = field_index(name);
        next.fields[index] = match &result {
            StageResult::Hidden => Field::PENDING,
            StageResult::Partial(value) | StageResult::Value(value) => value.fields[index].clone(),
        };
    }
    next.fields[field_index("stage")] = Field::text(stage, 1, WidthProfile::DEFAULT);
    let partial = next.fields.iter().enumerate().any(|(index, field)| {
        index != field_index("partial")
            && (field.state == ValueState::Pending
                || matches!(
                    field.value,
                    FieldValue::Count {
                        saturated: true,
                        ..
                    }
                ))
    }) || next.fields[field_index("filtered")]
        == Field::known(FieldValue::Bool(true));
    next.fields[field_index("partial")] = Field::known(FieldValue::Bool(partial));
    meter.borrow().check().map_err(CollectError::Read)?;
    sink.update(Update {
        segment: 3,
        value: Some(next.clone()),
        facts: None,
    })
    .map_err(CollectError::Sink)?;
    *snapshot = next;
    Ok(())
}

/// Bingsu state, not a gix repository. C5 supplies validated capabilities after
/// ownership/preflight policy. No lazy ambient-path constructor is stored here.
pub struct GuardedRepository<'a> {
    pub io: io::RepoIo<'a>,
    pub config: config::Config,
    pub refs: std::rc::Rc<refs::Refs>,
    /// B read this HEAD as a commit and successfully decoded its root tree.
    /// Keep the OID, not a bool, so C can match its resolved tip explicitly.
    head_with_tree: std::cell::Cell<Option<refs::ObjectId>>,
    packs: io::objects::PackSnapshot,
}

impl<'a> GuardedRepository<'a> {
    pub fn from_roots(
        roots: &'a discover::RepoRoots,
        meter: &'a std::cell::RefCell<crate::meter::Meter>,
    ) -> Result<Self, ReadError> {
        Self::new(
            io::RepoIo::new(roots.io_roots(), &roots.access, meter),
            roots.ref_snapshot(),
        )
    }

    /// Pass the selected roots' request snapshot, also used by preflight and D.
    pub fn new(io: io::RepoIo<'a>, snapshot: &refs::RefSnapshot) -> Result<Self, ReadError> {
        let config = config::Config::load(&io)?;
        let refs = snapshot.load_with_config(&io, &config)?;
        Ok(Self {
            io,
            config,
            refs,
            head_with_tree: std::cell::Cell::new(None),
            packs: io::objects::PackSnapshot::default(),
        })
    }

    /// B uses `repo.objects(&repo.io)`; C supplies its fresh stage port. Both
    /// retain one lazy pack snapshot while scratch and stop state stay local.
    pub fn objects<'b>(&self, io: &'b io::RepoIo<'b>) -> io::objects::SafeObjectDb<'b> {
        io::objects::SafeObjectDb::with_snapshot(io, &self.packs)
    }

    /// Never fall back to a path-based store.
    pub fn object(&self, _id: &[u8]) -> Result<Vec<u8>, ReadError> {
        Err(io::UNSUPPORTED)
    }
}
