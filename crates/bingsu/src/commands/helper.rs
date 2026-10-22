//! Detached fixed refresh command. All NSS, source I/O and publication live here.
use super::{
    clock::SystemClock,
    collection_gc,
    collection_store::{Admission, CollectionStore},
    collector,
    group_policy::SystemGroups,
    helper_filter, helper_limits, log,
    refresh::{self, RefreshRequest, RefreshResult},
    sys,
};
use bingsu_core::{collection, envelope::LogLevel, snapshot::ClockSource};
use std::{
    ffi::{OsStr, OsString},
    os::unix::ffi::OsStrExt,
    path::Path,
    process::ExitCode,
    time::Instant,
};

pub fn run(exe: &OsStr, args: &[OsString]) -> ExitCode {
    let started = Instant::now();
    std::panic::set_hook(Box::new(|_| {}));
    if detach().is_err() {
        return ExitCode::from(1);
    }
    let Ok(_watchdog) = helper_limits::start(started) else {
        return ExitCode::from(1);
    };
    let raw: Vec<_> = args.iter().map(|a| a.as_bytes()).collect();
    let Ok(e) = bingsu_core::helper::validate(&raw) else {
        return ExitCode::from(1);
    };
    // Capture clock identity before the first trust observation (including NSS).
    let mut clock = SystemClock;
    let process_started = clock.observe();
    let Some(user) = sys::passwd_entry(sys::current_uid()) else {
        return ExitCode::from(1);
    };
    let mut groups = SystemGroups::new(&user.name);
    let log_root = e
        .log_root
        .as_deref()
        .map(|b| Path::new(OsStr::from_bytes(b)));
    let report = |groups: &mut SystemGroups, severity, text| {
        log::event(
            e.log_level,
            log_root,
            sys::current_uid(),
            groups,
            severity,
            text,
        )
    };
    let Ok(process_started) = process_started else {
        report(
            &mut groups,
            LogLevel::Error,
            "refresh incomplete: clock observation",
        );
        return ExitCode::from(1);
    };
    let version = bingsu_core::VERSION
        .split('.')
        .take(3)
        .map(|n| n.parse().unwrap_or(0))
        .collect::<Vec<_>>();
    let Some(request) = RefreshRequest::from_envelope(
        Path::new(exe),
        &e,
        &user,
        process_started,
        [version[0], version[1], version[2]],
    ) else {
        return ExitCode::from(1);
    };
    let mut filter_failed = false;
    let mut supervisor = None;
    let mut collection_runtime = None;
    let mut collection_outcome = None;
    let mut verification = Verification::start();
    let result = refresh::refresh_broker(request, &mut clock, &mut |context, display, now| {
        verification.verified();
        let request = selected_request(&collection::selection::PRODUCT, &e, display, now)?;
        if let Some(request) = request {
            // Collection admission failure does not invalidate independent
            // snapshot publication. No product catalog grants a worker yet.
            let admission = (|| {
                collection_runtime = Some(context.runtime.try_clone()?);
                let path = e
                    .collector_exe
                    .as_deref()
                    .ok_or(super::snapshot_store::StoreError::Unsafe)?;
                let pin = collector::PinnedCollector::verify(
                    OsStr::from_bytes(path),
                    sys::current_uid(),
                    &mut groups,
                )?;
                let mut store = match CollectionStore::admit(context, &request.binding, now)? {
                    Admission::Admitted(store) => store,
                    Admission::Deferred(stop) => return Ok(Err(stop)),
                };
                let lock = store.worker_lock()?;
                let job =
                    verification.attach(collector::spawn(&pin, request, lock, &_watchdog)?, &store);
                Ok::<_, super::snapshot_store::StoreError>(Ok(
                    job.start(Box::new(move |result| store.publish(&result)))?
                ))
            })();
            (supervisor, collection_outcome) = collection_result(admission);
        }
        let child_pidfd = supervisor.as_ref().and_then(|handle| handle.child_pidfd());
        let confinement =
            helper_limits::install(&_watchdog).and_then(|()| helper_filter::install(child_pidfd));
        if let Err(error) = confinement {
            filter_failed = true;
            drop(supervisor.take());
            return Err(error.into());
        }
        if let Some(handle) = &supervisor {
            handle.confirm_confinement()?;
        }
        Ok(())
    });
    // refresh_broker has released the snapshot lock and source descriptors.
    if let Some(handle) = supervisor {
        let _ = handle.finish();
    }
    if let Some(runtime) = collection_runtime
        && let Ok(now) = clock.observe()
    {
        let outcome = collection_gc::reclaim(&runtime, now, collection_gc::GcBudget::default())
            .map(|gc| match gc.stop {
                collection_gc::GcStop::Complete => Ok(()),
                stop => Err(stop),
            });
        let (_, message) = collection_result(outcome);
        if let Some((severity, text)) = message {
            report(&mut groups, severity, text);
        }
    }
    if let Some((severity, text)) = collection_outcome {
        report(&mut groups, severity, text);
    }
    if filter_failed {
        report(
            &mut groups,
            LogLevel::Error,
            "refresh incomplete: helper TSYNC filter unavailable",
        );
    }
    match result {
        RefreshResult::Published { .. } => report(&mut groups, LogLevel::Info, "refresh published"),
        RefreshResult::Revalidated { .. } => {
            report(&mut groups, LogLevel::DebugLog, "refresh revalidated")
        }
        RefreshResult::Busy => report(&mut groups, LogLevel::DebugLog, "refresh busy"),
        RefreshResult::Invalid => report(&mut groups, LogLevel::Error, "refresh invalid"),
        RefreshResult::Incomplete => report(&mut groups, LogLevel::Error, "refresh incomplete"),
    }
    if matches!(result, RefreshResult::Incomplete | RefreshResult::Invalid) {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}

// Collection observations never become refresh trust/publication results.
pub(crate) fn collection_result<T>(
    result: Result<Result<T, collection_gc::GcStop>, super::snapshot_store::StoreError>,
) -> (Option<T>, Option<(LogLevel, &'static str)>) {
    use super::snapshot_store::StoreError;
    use collection_gc::GcStop;
    let (level, text) = match result {
        Ok(Ok(value)) => return (Some(value), None),
        Ok(Err(GcStop::YieldTime)) => (LogLevel::DebugLog, "collection deferred: time budget"),
        Ok(Err(GcStop::YieldOps)) => (LogLevel::DebugLog, "collection deferred: operation budget"),
        Ok(Err(GcStop::Busy)) | Err(StoreError::Busy) => (LogLevel::DebugLog, "collection busy"),
        Ok(Err(GcStop::Complete)) => (LogLevel::Error, "collection invalid deferred state"),
        Err(StoreError::Unsafe | StoreError::Root(_)) => (LogLevel::Error, "collection unsafe"),
        Err(StoreError::Io(_)) => (LogLevel::Error, "collection I/O failure"),
        Err(_) => (LogLevel::Error, "collection invalid data"),
    };
    (None, Some((level, text)))
}

/// Observation-only seam shared with the test catalog. Neither a missing
/// timestamp nor report consumption changes collection admission or deadlines.
pub(crate) struct Verification {
    pub start: Option<u64>,
    pub end: Option<u64>,
}
impl Verification {
    pub(crate) fn start() -> Self {
        Self {
            start: super::collector_process::now_ns().ok(),
            end: None,
        }
    }
    pub(crate) fn verified(&mut self) {
        self.end = super::collector_process::now_ns().ok();
    }
    pub(crate) fn attach(
        &self,
        job: super::collector_supervisor::CollectorJob,
        store: &CollectionStore,
    ) -> super::collector_supervisor::CollectorJob {
        job.observations(
            self.start,
            self.end,
            store.lock_acquired,
            store.response_renamed.clone(),
        )
    }
}

pub(super) fn detach() -> Result<(), ()> {
    let core = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: own child process; initialized limits and a fixed absolute path.
    if unsafe { libc::setrlimit(libc::RLIMIT_CORE, &core) } != 0
        // SAFETY: NUL-terminated static path, no cwd-dependent work follows.
        || unsafe { libc::chdir(c"/".as_ptr()) } != 0
    {
        return Err(());
    }
    // SAFETY: own fresh child process; no pointers. Failure aborts before NSS/I/O.
    if unsafe { libc::setsid() } < 0 {
        Err(())
    } else {
        // SAFETY: helper-local creation policy; never changes the prompt/shell.
        unsafe { libc::umask(0o077) };
        Ok(())
    }
}

pub(crate) fn selected_request(
    catalog: &collection::selection::Catalog<'_>,
    e: &bingsu_core::envelope::Envelope,
    display: Option<(
        &bingsu_core::config::compile::CompiledConfig,
        bingsu_core::snapshot::Identity,
    )>,
    now: bingsu_core::snapshot::Clock,
) -> Result<Option<collection::wire::Request>, super::snapshot_store::StoreError> {
    let (Some((config, id)), Some(cwd)) = (display, e.pwd.as_deref()) else {
        return Ok(None);
    };
    collection::request(
        catalog,
        collection::wire::Binding {
            path_query: collection::path_facts::PathQuery::for_path(
                cwd,
                e.home.as_deref(),
                config.setup[1]
                    .methods
                    .contains(&bingsu_core::shorten::Method::Unique),
            ),
            build_id: bingsu_identity::build_id(),
            snapshot: id,
            clock_kind: now.kind,
            domain: now.domain,
            resume: now.resume,
            config: e.config_root.as_deref().unwrap_or(b"").to_vec(),
            state: e.state_root.as_deref().unwrap_or(b"").to_vec(),
            cwd: cwd.to_vec(),
            mask: catalog.worker_mask(config, e.width, e.redraw),
        },
        collection::wire::M3B_REQUEST_ID,
        50,
    )
    .map_err(|_| super::snapshot_store::StoreError::Unsafe)
}
