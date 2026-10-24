//! Repository identity and bytes-only Git readers. Product mask stays zero.
pub mod config;
pub mod discover;
pub mod io;
pub mod preflight;
pub mod refs;
pub mod stage_a;
pub mod stage_c;
pub mod stage_d;
pub mod status_tracked;

pub(crate) use crate::update_sink::UpdateSink;

use crate::safe_read::ReadError;
use bingsu_core::collection::budget::Axis;

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
}

impl StageDeadlines {
    pub const PRODUCT: Self = Self {
        a_ms: bingsu_core::collection::budget::A_MS,
        b_ms: bingsu_core::collection::budget::B_MS,
    };
}

pub(crate) fn collect_with_deadlines(
    request: &bingsu_core::collection::wire::Request,
    sink: &mut dyn UpdateSink,
    mut meter: crate::meter::Meter,
    access: crate::safe_read::Access,
    deadlines: StageDeadlines,
) -> Result<(), CollectError> {
    use bingsu_core::collection::{
        git::{self, StageResult},
        wire::{Progress, Update},
    };
    let (selected, mut snapshot) = meter.stage(deadlines.a_ms, |meter| {
        let selected = discover::select(request, access, meter)?;
        let (result, device) = match &selected {
            discover::Selection::Outside(cwd, _) => {
                (StageResult::Value(git::no_repo()), cwd.device())
            }
            discover::Selection::Repository(roots) => (
                stage_a::stage_a(roots, roots.head_policy(), meter),
                roots.worktree.device(),
            ),
        };
        meter.check().map_err(CollectError::Read)?;
        let value = match result {
            StageResult::Hidden => return Err(CollectError::Read(ReadError::Denied)),
            StageResult::Partial(value) | StageResult::Value(value) => value,
        };
        meter.check().map_err(CollectError::Read)?;
        sink.update(Update {
            segment: git::SEGMENT,
            value: Some(value.clone()),
            facts: None,
        })
        .map_err(CollectError::Sink)?;
        sink.progress(Progress {
            stage_a_complete: true,
            device: Some(device),
        })
        .map_err(CollectError::Sink)?;
        Ok((selected, value))
    })?;
    match selected {
        discover::Selection::Outside(cwd, access) => {
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
            Ok(())
        }
        discover::Selection::Repository(mut roots) => {
            roots.restrict(&mut meter).map_err(CollectError::Read)?;
            // E1 inserts bounded PathFacts before restriction. B preflight
            // cannot consume the first A's budget or delay its immediate write.
            let access =
                meter.stage(deadlines.b_ms, |meter| preflight::preflight(&roots, meter))?;
            // A packed-only repository can prove unborn only after preflight.
            // Publish a corrected cumulative A without delaying the first one.
            let decl = &bingsu_core::field::BUILTIN[usize::from(git::SEGMENT)];
            let branch = decl.field_index("branch").expect("fixed git field");
            if access == preflight::GitAccess::Objects
                && roots.unborn.get()
                && snapshot.fields[branch] != bingsu_core::field::Field::ABSENT
            {
                snapshot.fields[branch] = bingsu_core::field::Field::ABSENT;
                sink.update(Update {
                    segment: git::SEGMENT,
                    value: Some(snapshot),
                    facts: None,
                })
                .map_err(CollectError::Sink)?;
            }
            Ok(())
        }
    }
}

/// Bingsu state, not a gix repository. C5 supplies validated capabilities after
/// ownership/preflight policy. No lazy ambient-path constructor is stored here.
pub struct GuardedRepository<'a> {
    pub io: io::RepoIo<'a>,
    pub config: config::Config,
    pub refs: std::rc::Rc<refs::Refs>,
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
