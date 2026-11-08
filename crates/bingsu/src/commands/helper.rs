//! Detached fixed refresh command. All NSS, source I/O and publication live here.
use super::{
    clock::SystemClock,
    collection_breaker, collection_gc,
    collection_store::{Admission, CollectionStore},
    collector, command_grant,
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
    #[cfg(test)]
    let fixture = FIXTURE_RUN.with(|slot| slot.borrow_mut().take());
    let started = Instant::now();
    std::panic::set_hook(Box::new(|_| {}));
    if detach().is_err() {
        return ExitCode::from(1);
    }
    let Ok(_watchdog) = helper_limits::start(started) else {
        return ExitCode::from(1);
    };
    // After the watchdog, so a read that blocks (fd 4 handed over by
    // something other than the prompt) ends with the helper's lifetime;
    // starting it opens no file and uses no NSS. Before anything here opens
    // a descriptor: on the cold init path there is no fd 4, and a later read
    // could take one of the helper's own. The command supervisor (C2) is the
    // consumer; locations never come from it.
    #[cfg(test)]
    let command_env = if fixture.is_none() {
        read_env_why(ENV_FD)
    } else {
        Err(NoEnv::Missing)
    };
    #[cfg(not(test))]
    let command_env = read_env_why(ENV_FD);
    let raw: Vec<_> = args.iter().map(|a| a.as_bytes()).collect();
    let Ok(e) = bingsu_core::helper::validate(&raw) else {
        return ExitCode::from(1);
    };
    // Capture clock identity before the first trust observation (including NSS).
    #[cfg(not(test))]
    let mut clock = SystemClock;
    #[cfg(test)]
    let mut clock = FixtureClock(fixture.as_ref().map(|f| f.now));
    let process_started = clock.observe();
    let Some(user) = sys::passwd_entry(sys::current_uid()) else {
        return ExitCode::from(1);
    };
    let mut groups = SystemGroups::new(&user.name);
    let log_root = e
        .log_root
        .as_deref()
        .map(|b| Path::new(OsStr::from_bytes(b)));
    let report = |groups: &mut SystemGroups, severity, text: &'static str| {
        #[cfg(test)]
        if let Some(fixture) = &fixture {
            fixture.events.borrow_mut().push((severity, text));
            return;
        }
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
    let runtime_path = request.runtime.path.clone();
    let collected_repo: std::sync::Arc<std::sync::Mutex<Option<u16>>> = Default::default();
    // This round's language answers, by the asked language's id (U-3 L2).
    let collected_languages: std::sync::Arc<std::sync::Mutex<command_grant::Languages>> =
        Default::default();
    let mut command_round = None;
    let mut command_skip = None;
    let reapply = std::cell::Cell::new(None);
    let mut round_marker = None;
    let mut filter_failed = false;
    let mut supervisor = None;
    let mut collection_runtime = None;
    let mut command_runtime = None;
    let mut breaker_ticket = None;
    let mut collection_outcome = None;
    let mut verification = Verification::start();
    let mut broker = |context: &super::snapshot_store::CheckedContextFd,
                      display: Option<(
        &bingsu_core::config::compile::CompiledConfig,
        bingsu_core::snapshot::Identity,
    )>,
                      now,
                      marker: &bingsu_core::snapshot::Marker| {
        verification.verified();
        let request = selected_request(&collection::selection::PRODUCT, &e, display, now)?;
        let selected = request.is_some();
        #[cfg(test)]
        let selected = selected || fixture.is_some();
        if selected {
            // Collection admission failure does not invalidate independent
            // snapshot publication.
            let admission = (|| {
                #[cfg(test)]
                if let Some(fixture) = &fixture {
                    return fixture
                        .admission
                        .borrow_mut()
                        .take()
                        .unwrap()
                        .map(|result| result.map(|()| unreachable!("fixture has no worker")));
                }
                let mut request = request.unwrap();
                if request.binding.mask & (1 << collection::git::SEGMENT) != 0 {
                    let reason = super::git_global::attach(&mut request, &e);
                    report(&mut groups, reason.log_level(), reason.message());
                }
                // D1 (ruling Q1): the user-defined languages' detect_files;
                // the built-in four are asked for by their segments (D3). After
                // the global excludes, so queries that do not fit what the
                // request leaves are the ones dropped, never the excludes.
                if let Some((config, _)) = display {
                    // After the builtin languages: a user query that does
                    // not fit drops the user queries, never the builtins.
                    let builtins = request.languages.len();
                    request.languages.extend(user_queries(&config.exec_units));
                    if request.encode_body().is_err() {
                        request.languages.truncate(builtins);
                    }
                }
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
                match collection_breaker::begin(
                    &context.runtime,
                    e.session.as_deref(),
                    e.seq,
                    &request.binding.cwd,
                    now,
                ) {
                    collection_breaker::Decision::Blocked => return Ok(Ok(None)),
                    collection_breaker::Decision::Deferred => {
                        return Ok(Err(collection_gc::GcStop::Busy));
                    }
                    collection_breaker::Decision::Run(ticket) => breaker_ticket = ticket,
                }
                let job = verification.attach(
                    collector::spawn(&pin, request, lock, &_watchdog, context)?,
                    &store,
                );
                // The repository root this collection reports for the shell's
                // folder, for the command round's PATH rules (C2 ruling J9).
                let slot = collected_repo.clone();
                let languages = collected_languages.clone();
                Ok::<_, super::snapshot_store::StoreError>(Ok(Some(job.start(Box::new(
                    move |result| {
                        let repo = result
                            .updates
                            .iter()
                            .find_map(|u| u.facts.as_ref())
                            .and_then(|f| f.repo_component);
                        // Before the record: a round with only language
                        // answers publishes none, and its answers still go
                        // to the builtin probes (D3a ruling Q-B).
                        *languages.lock().unwrap_or_else(|e| e.into_inner()) =
                            command_grant::Languages::from_result(&result);
                        store.publish(&result)?;
                        *slot.lock().unwrap_or_else(|e| e.into_inner()) = repo;
                        Ok(())
                    },
                ))?)))
            })();
            let (started, outcome) = collection_result(admission);
            supervisor = started.flatten();
            collection_outcome = outcome;
        }
        #[cfg(test)]
        if fixture.is_some() {
            return Ok(());
        }
        // The command supervisor, like the collector, is spawned before the
        // helper's filter; its grant waits for the marker's installation.
        if let Some((config, _)) = display {
            let inputs = command_grant::Inputs {
                config,
                context,
                identity: display.map(|(_, id)| id).unwrap_or(marker.id),
                now,
                session: e.session.as_deref(),
                pwd: e.pwd.as_deref(),
                environment: &command_env,
                runtime: &context.runtime,
                runtime_path: &runtime_path,
                exe,
                me: sys::current_uid(),
                helper_deadline: _watchdog.expires_ns(),
                builtins: &drawn_builtins(config, &e),
                reapply: &reapply,
            };
            match command_grant::prepare(&inputs) {
                Ok(round) => {
                    command_round = Some(round);
                    command_runtime = context.runtime.try_clone().ok();
                }
                Err(skip) => command_skip = Some(skip),
            }
            round_marker = Some(*marker);
        }
        let child_pidfd = supervisor.as_ref().and_then(|handle| handle.child_pidfd());
        let confinement =
            helper_limits::install(&_watchdog).and_then(|()| helper_filter::install(child_pidfd));
        if let Err(error) = confinement {
            filter_failed = true;
            drop(supervisor.take());
            if let Some(round) = command_round.take() {
                let _ = round.abandon();
            }
            return Err(error.into());
        }
        if let Some(handle) = &supervisor {
            handle.confirm_confinement()?;
        }
        Ok(())
    };
    #[cfg(not(test))]
    let result = refresh::refresh_broker(request, &mut clock, &mut broker);
    #[cfg(test)]
    let result = if let Some(fixture) = &fixture {
        // Only the external refresh/admission inputs are injected. The run
        // path above and reporting/exit below are shared with production.
        let published = broker(
            &fixture.context,
            None,
            fixture.now,
            &fixture_marker(fixture.now),
        )
        .and_then(|()| {
            let lock = fixture.context.try_lock()?;
            lock.stage(super::snapshot_store::Slot::Snapshot, &fixture.snapshot)?;
            lock.install(super::snapshot_store::Slot::Snapshot)
        });
        if published.is_ok() {
            RefreshResult::Published {
                generation: 1,
                left_out: vec![],
            }
        } else {
            RefreshResult::Incomplete
        }
    } else {
        refresh::refresh_broker(request, &mut clock, &mut broker)
    };
    // refresh_broker has released the snapshot lock and source descriptors.
    // The collection ends first: its repository root feeds the grant.
    if let Some(handle) = supervisor {
        let supervision = handle.finish();
        if let Some(ticket) = breaker_ticket.take()
            && let Ok(now) = clock.observe()
        {
            let (progress, reason) = supervision.breaker_observation();
            // Persistence failure affects only the next optional breaker lookup.
            let _ = ticket.finish(progress, reason, now);
        }
    }
    // The grant goes out only once this round's marker is installed.
    if let Some(round) = command_round.take() {
        match grant_permit(round_marker, &result) {
            Some(permit) => {
                if round.neutral_refused > 0 {
                    report(&mut groups, LogLevel::Info, command_grant::NEUTRAL_REFUSED);
                }
                let repo = *collected_repo.lock().unwrap_or_else(|e| e.into_inner());
                let languages = collected_languages
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .clone();
                let done = round.grant(permit, repo, &languages, sys::current_uid(), &mut groups);
                for why in &done.hidden {
                    report(&mut groups, LogLevel::Info, why);
                }
                // What the round read (D3a re-review M3): a round with
                // nothing to decide walks no PATH and resolves no folder.
                if done.searched {
                    report(
                        &mut groups,
                        LogLevel::DebugLog,
                        "command round: PATH searched",
                    );
                }
                for _ in 0..done.resolved {
                    report(
                        &mut groups,
                        LogLevel::DebugLog,
                        "command round: shell folder resolved for rustup",
                    );
                }
                if done.unresolved > 0 {
                    report(
                        &mut groups,
                        LogLevel::Info,
                        "command round: a unit's executable was not found or failed the checks",
                    );
                }
                if done.failed {
                    report(
                        &mut groups,
                        LogLevel::Error,
                        "command round failed: the shell's folder could not be read",
                    );
                }
                if done.send_failed {
                    report(
                        &mut groups,
                        LogLevel::Error,
                        "command round failed: the grant could not be sent in time",
                    );
                }
                if done.oversize > 0 {
                    report(
                        &mut groups,
                        LogLevel::Info,
                        "command round: a unit's environment is over the relay input cap",
                    );
                }
                if done.repo_fallback {
                    report(
                        &mut groups,
                        LogLevel::Info,
                        "command round: no collected repository root; the shell's folder stands for it",
                    );
                }
                let dropped = done.dropped;
                if dropped.malformed + dropped.duplicate > 0 {
                    let text = format!(
                        "command environment: {} malformed entries and {} duplicated names left out",
                        dropped.malformed, dropped.duplicate
                    );
                    log::event(
                        e.log_level,
                        log_root,
                        sys::current_uid(),
                        &mut groups,
                        LogLevel::Info,
                        &text,
                    );
                }
                // A command response reserves GC capacity like a collection
                // response: a round that published (or tried to) runs the
                // reclaim too, or command-only layouts fill the budget and
                // every later publication fails (C4a review H1).
                if (done.published.is_some() || done.publish_failed) && collection_runtime.is_none()
                {
                    collection_runtime = command_runtime.take();
                }
                if done.publish_failed {
                    report(
                        &mut groups,
                        LogLevel::Info,
                        "command round: results not published; the store was busy or refused",
                    );
                }
                if done.rejected > 0 {
                    report(
                        &mut groups,
                        LogLevel::Error,
                        "command round: results rejected",
                    );
                }
                for note in &done.notes {
                    report(&mut groups, LogLevel::Info, note);
                }
                report(&mut groups, LogLevel::DebugLog, "command round finished");
            }
            None => {
                for note in round.abandon() {
                    report(&mut groups, LogLevel::Info, note);
                }
            }
        }
    }
    // A round that runs nothing but re-matched cached entries under a
    // changed `match` (U-9c) publishes them once its marker stands.
    if let Some(publish) = reapply.take()
        && grant_permit(round_marker, &result).is_some()
    {
        let text = match publish.publish_reapplied() {
            Ok(_) => "command round: values matched again under a changed match",
            Err(_) => "command round: results not published; the store was busy or refused",
        };
        report(&mut groups, LogLevel::Info, text);
    }
    if let Some(text) = command_skip.and_then(command_grant::Skip::message) {
        report(&mut groups, LogLevel::Info, text);
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

#[cfg(test)]
pub(crate) struct FixtureRun {
    pub context: super::snapshot_store::CheckedContextFd,
    pub now: bingsu_core::snapshot::Clock,
    pub admission: std::cell::RefCell<
        Option<Result<Result<(), collection_gc::GcStop>, super::snapshot_store::StoreError>>,
    >,
    pub snapshot: Vec<u8>,
    pub events: std::rc::Rc<std::cell::RefCell<Vec<(LogLevel, &'static str)>>>,
}
#[cfg(test)]
thread_local! {
    static FIXTURE_RUN: std::cell::RefCell<Option<FixtureRun>> = const { std::cell::RefCell::new(None) };
}
#[cfg(test)]
#[allow(dead_code, reason = "native helper run integration test")]
pub(crate) fn fixture_run(fixture: FixtureRun) {
    FIXTURE_RUN.with(|slot| {
        assert!(slot.borrow().is_none());
        *slot.borrow_mut() = Some(fixture);
    });
}
#[cfg(test)]
fn fixture_marker(now: bingsu_core::snapshot::Clock) -> bingsu_core::snapshot::Marker {
    bingsu_core::snapshot::Marker {
        id: bingsu_core::snapshot::Identity {
            boot: now.boot,
            epoch: [0; 16],
            context: [0; 4],
            generation: 0,
            source: [0; 4],
        },
        seq: 0,
        verified_at: now.now,
        kind: now.kind,
        domain: now.domain,
        resume: now.resume,
        invalid: false,
    }
}
#[cfg(test)]
struct FixtureClock(Option<bingsu_core::snapshot::Clock>);
#[cfg(test)]
impl ClockSource for FixtureClock {
    fn observe(
        &mut self,
    ) -> Result<bingsu_core::snapshot::Clock, bingsu_core::snapshot::ClockError> {
        self.0.map_or_else(|| SystemClock.observe(), Ok)
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

const ENV_FD: i32 = bingsu_core::command::env_frame::FD;

/// The environment frame's body from `fd`, which is then closed, or `None`
/// (no environment this round). See `read_env_why`.
#[cfg(test)]
pub(crate) fn read_env(fd: i32) -> Option<Vec<u8>> {
    read_env_why(fd).ok()
}

/// Why a round has no command environment; the helper logs it, since every
/// config unit is then left out of the grant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NoEnv {
    /// No descriptor at fd 4 (the helper was not started by a prompt).
    Missing,
    /// End of file before any byte: the prompt wrote nothing, because the
    /// environment is over the frame cap.
    Unwritten,
    /// Fewer bytes than the frame declares: the prompt's single write was
    /// cut, as with a pipe smaller than the frame (pipe-user-pages-soft
    /// leaves 4 KB pipes, m6-C1a).
    Cut,
    /// Another magic, a wrong checksum, or more than the cap.
    Damaged,
}
impl NoEnv {
    pub(crate) fn message(self) -> &'static str {
        match self {
            Self::Missing => "command environment: none handed over",
            Self::Unwritten => "command environment: not written (over 64 KB)",
            Self::Cut => "command environment: frame cut short (pipe smaller than the frame)",
            Self::Damaged => "command environment: frame damaged",
        }
    }
}

/// The environment frame's body from `fd`, which is then closed, or why
/// there is none: no fd, a frame never written, cut short or damaged.
/// Reads stop once the declared frame is in, so a whole frame costs one
/// read. The prompt wrote the frame and closed its end before the spawn,
/// so a read returns data or end of file and never waits.
pub(crate) fn read_env_why(fd: i32) -> Result<Vec<u8>, NoEnv> {
    use bingsu_core::command::env_frame;
    let mut buf = vec![0u8; env_frame::FRAME_MAX];
    let mut got = 0;
    let mut missing = false;
    while got < buf.len() {
        // SAFETY: writable bytes from got to the end of buf. fd 4 is not a Rust-owned
        // descriptor (it may not exist at all), so it is read and closed as a raw int.
        let n = unsafe { libc::read(fd, buf[got..].as_mut_ptr().cast(), buf.len() - got) };
        let Ok(n) = usize::try_from(n) else {
            missing =
                got == 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EBADF);
            break;
        };
        if n == 0 {
            break;
        }
        got += n;
        if env_frame::declared(&buf[..got]).is_some_and(|total| got >= total) {
            break;
        }
    }
    // SAFETY: closes the inherited descriptor once; EBADF when it was never there.
    unsafe { libc::close(fd) };
    buf.truncate(got);
    if let Some(body) = env_frame::body(&buf) {
        return Ok(body.to_vec());
    }
    Err(if missing {
        NoEnv::Missing
    } else if got == 0 {
        NoEnv::Unwritten
    } else if env_frame::declared(&buf).is_none_or(|total| got < total) {
        NoEnv::Cut
    } else {
        NoEnv::Damaged
    })
}

/// The permit of this round's grant, or `None` when no grant goes out
/// (U-1 C+): only a round that installed its marker (Published,
/// Revalidated, Invalid) sends one, under that marker's clock and trust
/// deadline. Busy and Incomplete (a failed filter, a source that changed
/// before the final revalidation, a lost lock) send none.
fn grant_permit(
    marker: Option<bingsu_core::snapshot::Marker>,
    result: &RefreshResult,
) -> Option<bingsu_core::handoff::Permit> {
    let installed = matches!(
        result,
        RefreshResult::Published { .. }
            | RefreshResult::Revalidated { .. }
            | RefreshResult::Invalid
    );
    marker
        .filter(|_| installed)
        .map(|m| command_grant::permit(&m))
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

/// The builtin languages whose segments this width draws (D3 ruling Q6),
/// the same ones the collection request asks about; none on a redraw.
fn drawn_builtins(
    config: &bingsu_core::config::compile::CompiledConfig,
    e: &bingsu_core::envelope::Envelope,
) -> Vec<&'static bingsu_core::command::builtin::Language> {
    if e.redraw {
        return Vec::new();
    }
    collection::builtin_languages(collection::selection::builtin_mask(config, e.width))
        .iter()
        .filter_map(|q| bingsu_core::command::builtin::language(&q.id))
        .collect()
}

/// The user-defined languages the round asks the collection about: only
/// units that may run (`plan::runnable`), so a language that cannot run
/// yet costs the collection no marker lookups and no share of its time
/// (D3c-1 review M1). Fails without the filter:
/// a_language_that_cannot_run_is_not_asked_about.
fn user_queries(
    units: &[bingsu_core::config::compile::ExecUnit],
) -> Vec<collection::language::LanguageQuery> {
    let runnable: Vec<_> = units
        .iter()
        .filter(|u| bingsu_core::command::plan::runnable(u).is_some())
        .cloned()
        .collect();
    collection::language::user_queries(&runnable)
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
    // The builtin language segments this width draws (D3a ruling Q6); a
    // redraw collects nothing.
    let languages = if e.redraw {
        Vec::new()
    } else {
        collection::builtin_languages(collection::selection::builtin_mask(config, e.width))
    };
    collection::request_with_languages(
        catalog,
        collection::wire::Binding {
            path_query: collection::selection::path_query(config, e.width, cwd, e.home.as_deref()),
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
        languages,
    )
    .map_err(|_| super::snapshot_store::StoreError::Unsafe)
}

#[cfg(test)]
mod query_tests {
    use bingsu_core::config::compile::{ExecPolicy, ExecUnit};

    // 실행할 수 없는 사용자 언어(interpreter 없음, not_run)는 수집 질의에 싣지 않는다. 표시 파일 조회가 수집 시간을
    // 쓰지 않게 하려는 것이다. 실행할 수 있는 것은 싣는다(D3c-2). 이것을 실패시키는 것: helper의 runnable 거르기를
    // 지우는 것(실행할 수 없는 것도 실림), 실행할 수 있는 것을 빼는 것.
    #[test]
    fn a_language_that_cannot_run_is_not_asked_about() {
        let unit = |id: &str, interpreter: Option<&str>| ExecUnit {
            id: id.into(),
            policy: ExecPolicy::Language {
                interpreter: interpreter.map(Into::into),
                version_argv: vec!["--version".into()],
                detect_files: vec!["deno.json".into()],
                cwd: None,
                env_allow: Vec::new(),
            },
            timeout_ms: None,
            cache_ms: None,
            origins: Vec::new(),
            approved_by: Vec::new(),
            shown_at: Vec::new(),
            not_run: None,
            pattern: None,
        };
        let mut off = unit("custom/off", Some("deno"));
        off.not_run = Some(bingsu_core::config::compile::NotRun::Disabled);
        let units = [
            unit("custom/deno", Some("deno")),
            unit("custom/none", None),
            off,
        ];
        let ids: Vec<Vec<u8>> = super::user_queries(&units)
            .into_iter()
            .map(|q| q.id)
            .collect();
        assert_eq!(ids, [b"custom/deno".to_vec()]);
    }
}

#[cfg(test)]
mod grant_tests {
    use super::{RefreshResult, grant_permit};

    // GATE-CMD-GRANT.2(허가 없음): 발행 실패·필터 실패·마지막 재검증 실패(chmod, 원본 교체)는 Incomplete이고,
    // 잠금 경합은 Busy다. 둘 다 permit이 없어 허가를 보내지 않는다. 표식을 설치한 회차는 그 표식의 permit을
    // 보낸다. 이것을 실패시키는 것: grant_permit의 결과 판정에 Incomplete나 Busy를 더하는 것, 표식 대신 다른
    // 시계로 permit을 만드는 것. 계획 표의 변이("허가 전송을 broker 안으로 옮김")는 제품 바이너리에 회차 사이
    // hook이 없어 죽일 수 없다(K4 판정). 그 자리는 이 함수와 helper::run의 호출 위치(refresh_broker 반환 뒤)로
    // 고정한다.
    #[test]
    fn grant_only_after_the_marker_is_installed() {
        let marker = super::fixture_marker(bingsu_core::snapshot::Clock {
            boot: [3; 16],
            domain: [4; 16],
            kind: 1,
            resume: 0,
            now: 77,
        });
        let want = Some(super::command_grant::permit(&marker));
        for r in [
            RefreshResult::Published {
                generation: 1,
                left_out: vec![],
            },
            RefreshResult::Revalidated { generation: 1 },
            RefreshResult::Invalid,
        ] {
            assert_eq!(grant_permit(Some(marker), &r), want, "{r:?}");
            assert_eq!(grant_permit(None, &r), None, "{r:?}");
        }
        for r in [RefreshResult::Incomplete, RefreshResult::Busy] {
            assert_eq!(grant_permit(Some(marker), &r), None, "{r:?}");
        }
    }
}

#[cfg(test)]
mod env_tests {
    use super::{NoEnv, read_env_why};
    use bingsu_core::command::env_frame;

    /// A pipe holding `bytes`, its write end closed; returns the read end.
    fn pipe_with(bytes: &[u8]) -> i32 {
        let (read, write) = crate::commands::collector_process::pipe().unwrap();
        assert!(matches!(
            crate::commands::sys::write_fd(std::os::fd::AsRawFd::as_raw_fd(&write), bytes),
            crate::commands::sys::WriteOutcome::Done
        ));
        drop(write);
        std::os::fd::IntoRawFd::into_raw_fd(read)
    }

    // m6-C1a·C1 수용 조건: 환경 없음의 이유를 나눠 알린다. 이것을 실패시키는 것: Missing 판정(EBADF)을
    // 지우는 것, `got == 0`을 Unwritten으로 보지 않는 것, 선언 길이 비교(Cut)를 지우는 것(잘린 프레임이
    // Damaged로 보고됨).
    #[test]
    fn no_environment_reasons() {
        let frame = env_frame::encode([b"HOME=/h\0".as_slice()]).unwrap();
        assert_eq!(
            read_env_why(pipe_with(&frame)).as_deref(),
            Ok(&b"HOME=/h\0"[..])
        );
        // A descriptor number nothing holds.
        assert_eq!(read_env_why(1_000_000), Err(NoEnv::Missing));
        assert_eq!(read_env_why(pipe_with(b"")), Err(NoEnv::Unwritten));
        assert_eq!(read_env_why(pipe_with(&frame[..5])), Err(NoEnv::Cut));
        assert_eq!(
            read_env_why(pipe_with(&frame[..frame.len() - 1])),
            Err(NoEnv::Cut)
        );
        let mut bad = frame.clone();
        *bad.last_mut().unwrap() ^= 1;
        assert_eq!(read_env_why(pipe_with(&bad)), Err(NoEnv::Damaged));
    }
}
