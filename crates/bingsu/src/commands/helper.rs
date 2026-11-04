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
    let mut command_round = None;
    let mut command_skip = None;
    let mut round_marker = None;
    let mut filter_failed = false;
    let mut supervisor = None;
    let mut collection_runtime = None;
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
                Ok::<_, super::snapshot_store::StoreError>(Ok(Some(
                    job.start(Box::new(move |result| store.publish(&result)))?,
                )))
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
            let cwd = e.pwd.as_deref().map(|p| Path::new(OsStr::from_bytes(p)));
            let inputs = command_grant::Inputs {
                config,
                session: e.session.as_deref(),
                pwd: e.pwd.as_deref(),
                environment: &command_env,
                runtime: &context.runtime,
                runtime_path: &runtime_path,
                // Until the repository root has a source (C2 ruling J9), the
                // shell's own folder is excluded from PATH and executables.
                repo: super::exec_path::repo_id(cwd).ok().flatten(),
                exe,
                me: sys::current_uid(),
                helper_deadline: _watchdog.expires_ns(),
            };
            match command_grant::prepare(&inputs, &mut groups) {
                Ok(round) => command_round = Some(round),
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
                round.abandon();
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
    // The grant goes out only once this round's marker is installed.
    if let Some(round) = command_round.take() {
        match (&result, round_marker) {
            (
                RefreshResult::Published { .. }
                | RefreshResult::Revalidated { .. }
                | RefreshResult::Invalid,
                Some(marker),
            ) => {
                if round.unresolved > 0 {
                    report(
                        &mut groups,
                        LogLevel::Info,
                        "command round: a unit's executable was not found or failed the checks",
                    );
                }
                let done = round.grant(command_grant::permit(&marker));
                if done.rejected > 0 {
                    report(
                        &mut groups,
                        LogLevel::Error,
                        "command round: results rejected",
                    );
                }
                report(&mut groups, LogLevel::DebugLog, "command round finished");
            }
            _ => round.abandon(),
        }
    }
    if let Some(text) = command_skip.and_then(command_grant::Skip::message) {
        report(&mut groups, LogLevel::Info, text);
    }
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
    )
    .map_err(|_| super::snapshot_store::StoreError::Unsafe)
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
