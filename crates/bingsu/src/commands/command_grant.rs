//! The refresh helper's side of a command round: whether
//! this round has config units to run, the session lock, the grant built in
//! memory from the compiled config the helper holds (never by decoding the
//! published snapshot again), the supervisor spawned before the helper's
//! filter, and, once the marker is installed, the one grant, the results
//! and the done frame. The helper keeps the grant channel's write end until
//! it has every result, so its end of file tells the supervisor the helper
//! is gone. The grant and result channels are pipes, Unix stream socket
//! pairs on macOS (`command_process::channel`). Results are checked and
//! dropped here; publishing them is C4.
use super::{
    builtin_probe::{self, Action, Planned},
    collection_store::close_only_lock,
    collector_process::{OwnedChild, now_ns},
    command_process, exec_path,
    group_policy::SystemGroups,
    helper::NoEnv,
    snapshot_store::StoreError,
    sys,
};

use bingsu_core::{
    command::{
        builtin::Language,
        plan::{self, Environ},
        response,
        wire::{self, Grant, Message, Outcome, Policy, Unit, policy_digest},
    },
    config::compile::CompiledConfig,
    handoff::{self, Cwd, ExecFrame, Origin, Permit},
    snapshot::{Marker, T_NS},
};

use std::{
    ffi::{CString, OsStr},
    fs::File,
    os::{
        fd::{AsFd, AsRawFd},
        unix::ffi::OsStrExt,
    },
    path::Path,
};

mod channel;
mod entries;
mod languages;
mod scripts;
mod session;
mod units;

#[cfg(test)]
use channel::send_with;
use channel::{send, wait};
pub(crate) use languages::{Languages, Root};
use languages::{gate_languages, language_entry, undetected};
use scripts::Scripts;
#[cfg(target_os = "linux")]
use session::session_reclaim;
use session::{lock_name, neutral, root_id};
#[cfg(target_os = "macos")]
use session::{nofollow_any, probe_nofollow_any, session_tag};
pub(crate) use units::{Search, search};
use units::{fits, searches, units};

/// The shell to run an `unsafe_shell` script with: a fixed path, resolved
/// by the same rules as any executable, never looked up in `PATH`.
const SHELL: &[u8] = b"/bin/sh";

/// The neutral working folder in the runtime root (spec: empty).
const NEUTRAL: &str = "neutral";

pub(crate) const NEUTRAL_REFUSED: &str =
    "command round: the neutral folder is not empty, the user's and 0500; its units do not run";

/// A unit that did not start, said once for the round: the supervisor could
/// not spawn the relay, the relay could not execute the program, or the
/// unit's exit status was lost. The supervisor has no log of its own and the
/// result carries no finer reason, so the helper says what it knows.
const SPAWN_FAILED: &str = "command round: a unit did not start (the relay could not be spawned, it could not execute the program, or its exit status was lost)";

/// The one line for a round in which a unit could not be started.
fn spawn_failed_note(results: &[Outcome]) -> Option<&'static str> {
    results
        .iter()
        .any(|o| matches!(o.reason, wire::Reason::SpawnFailed))
        .then_some(SPAWN_FAILED)
}

/// What the helper knows before it decides on a round.
pub(crate) struct Inputs<'a> {
    pub config: &'a CompiledConfig,
    /// The checked config context, where the command response lives.
    pub context: &'a super::snapshot_store::CheckedContextFd,
    /// The published snapshot's identity and the round's clock: the
    /// command response is bound to them (C4).
    pub identity: bingsu_core::snapshot::Identity,
    pub now: bingsu_core::snapshot::Clock,
    pub session: Option<&'a [u8]>,
    pub pwd: Option<&'a [u8]>,
    pub environment: &'a Result<Vec<u8>, NoEnv>,
    pub runtime: &'a File,
    pub runtime_path: &'a Path,
    pub exe: &'a OsStr,
    pub me: u32,
    pub helper_deadline: u64,
    /// The builtin languages whose segments this round draws; empty on a redraw.
    pub builtins: &'a [&'static Language],
    /// Where `prepare` leaves the re-matched entries of a round that runs
    /// nothing (`Skip::Reapplied`), for the helper to publish once the
    /// round's marker stands.
    pub reapply: &'a std::cell::Cell<Option<Box<Publish>>>,
}

/// Why a round runs no supervisor, for the helper's log.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Skip {
    /// No config unit may run (none, all with a `not_run` reason, or every
    /// one a cache hit) and no builtin language is drawn.
    NoUnits,
    NoEnvironment(NoEnv),
    /// No session value or no shell folder in the envelope.
    NoSession,
    /// Another supervisor of this session holds the lock.
    Busy,
    /// No trusted relay on this platform: a unix other than Linux and
    /// macOS.
    NoRelay,
    /// This macOS refuses `AT_SYMLINK_NOFOLLOW_ANY`, without which the
    /// relay's name check refuses every target.
    #[cfg(target_os = "macos")]
    NoNofollowAny,
    /// Every unit runs in the neutral folder, which is not empty, the
    /// user's and 0500.
    Neutral,
    Failed,
    /// Nothing runs, but cache hits were re-matched under a changed `match`
    /// : the helper publishes them once this round's marker stands.
    Reapplied,
}

impl Skip {
    pub(crate) fn message(self) -> Option<&'static str> {
        Some(match self {
            Self::NoUnits | Self::Reapplied => return None,
            Self::NoSession => "command round skipped: no session value from the shell",
            Self::NoRelay => "command round skipped: no trusted relay on this platform",
            #[cfg(target_os = "macos")]
            Self::NoNofollowAny => {
                "command round skipped: this macOS has no AT_SYMLINK_NOFOLLOW_ANY, which the relay's name check needs"
            }
            Self::Neutral => NEUTRAL_REFUSED,
            Self::NoEnvironment(why) => why.message(),
            Self::Busy => "command round busy: the session's supervisor is still running",
            Self::Failed => "command round failed: supervisor not started",
        })
    }
}

/// A started supervisor waiting for its grant. The grant's units are
/// resolved only after publication: walking the sanitized `PATH` and the
/// shell's folder can block on a stopped mount, which must never hold the
/// marker back.
pub(crate) struct Round {
    child: OwnedChild,
    /// Everything but the units and the permit.
    grant: Grant,
    runnable: Vec<(String, plan::Runnable)>,
    environment: Vec<u8>,
    grant_pipe: File,
    results: File,
    /// The session's cgroup parent on the atomic path (Linux); the
    /// supervisor gets a copy at descriptor 6.
    #[cfg(target_os = "linux")]
    cgroup: Option<super::command_cgroup::fs::Dir>,
    /// Units left out because the neutral folder failed its check.
    pub neutral_refused: usize,
    scripts: Scripts,
    /// Diagnostic lines of this round's reclaims, for the helper's log.
    pub notes: Vec<&'static str>,
    /// Where and how the round's results are published (C4).
    publish: Publish,
    /// The builtin languages drawn this round (D3a).
    builtins: Vec<&'static Language>,
    /// Whether probes may run: the neutral folder they run in passed.
    probes_allowed: bool,
    /// The command response read before the round, for the probes' cache.
    current: Option<response::Response>,
    /// The plan of each probe in `grant.probes`, by index.
    probes: Vec<Planned>,
    /// Builtin entries decided without running anything (shown or hidden).
    decided: Vec<response::Entry>,
    /// The user-defined language units that may run, cache hits included:
    /// each runs only where its marker files were found (D3c-2).
    language_units: Vec<String>,
    /// Why builtin languages were hidden, for the helper's log.
    pub hidden: Vec<&'static str>,
    /// The session lock; the supervisor holds its own copy. Dropped last:
    /// the reclaim after the supervisor runs while it is still held.
    _lock: File,
}

/// The command response of a round: its context, binding, and for each
/// unit to run the original environment digest it is bound to; the attempt
/// times of the units for round robin; when the round started.
pub(crate) struct Publish {
    context: super::snapshot_store::CheckedContextFd,
    binding: response::Binding,
    clock: bingsu_core::snapshot::Clock,
    environments: Vec<(String, [u8; 32])>,
    attempts: Vec<(String, u64)>,
    /// Each runnable unit's `match`, applied to its result.
    patterns: Vec<(String, Option<String>)>,
    /// Cache hits re-matched under a changed `match`, published with the
    /// round's results without running.
    reapplied: Vec<response::Entry>,
    /// The round's match time, shared by re-matching and results.
    budget: super::command_match::Budget,
}

/// Decides the round and, when it has units, takes the session lock and
/// spawns the supervisor. Only the runtime root is touched here, before the
/// marker; the units are resolved in `Round::grant`, after it.
pub(crate) fn prepare(i: &Inputs<'_>) -> Result<Round, Skip> {
    let language_units: Vec<String> = i
        .config
        .exec_units
        .iter()
        .filter(|u| {
            matches!(
                u.policy,
                bingsu_core::config::compile::ExecPolicy::Language { .. }
            )
        })
        .filter(|u| plan::runnable(u).is_some())
        .map(|u| u.id.clone())
        .collect();
    let runnable: Vec<_> = i
        .config
        .exec_units
        .iter()
        .filter_map(|u| {
            plan::runnable(u).map(|r| (u.id.as_str(), r, u.cache_ms, u.pattern.as_deref()))
        })
        .collect();
    let patterns: Vec<(String, Option<String>)> = runnable
        .iter()
        .map(|(id, _, _, p)| (id.to_string(), p.map(str::to_owned)))
        .collect();
    let binding = i.pwd.map(|cwd| response::Binding {
        build_id: bingsu_core::collection::wire::BuildId(bingsu_identity::build_id().0),
        boot: i.identity.boot,
        epoch: i.identity.epoch,
        context: i.identity.context,
        clock_kind: i.now.kind,
        domain: i.now.domain,
        resume: i.now.resume,
        config: i.context.config.clone(),
        state: i.context.state.clone(),
        cwd: cwd.to_vec(),
    });
    // The cache: a unit whose entry is bound to this round, to its
    // policy and to this shell's original environment, and still stands,
    // runs nothing. Read without the lock; a damaged one is no cache.
    let current = match (&binding, runnable.is_empty() && i.builtins.is_empty()) {
        // Only a response bound to exactly this binding (built from this
        // round's clock) is returned.
        (Some(b), false) => super::collection_store::read_commands(i.context, b)
            .ok()
            .flatten(),
        _ => None,
    };
    let vars = i.environment.as_ref().ok().map(|body| Environ::parse(body));
    let mut environments = Vec::new();
    let mut reapplied = Vec::new();
    let budget = super::command_match::Budget::new();
    let runnable: Vec<_> = runnable
        .into_iter()
        .filter(|(id, r, cache_ms, pattern)| {
            let Some(vars) = &vars else { return true };
            let env = plan::env_digest(vars, &r.env_allow);
            environments.push((id.to_string(), env));
            let policy = plan::entry_digest(r);
            let cache_ns = cache_ms.unwrap_or(0).saturating_mul(1_000_000);
            let entry = current.as_ref().and_then(|c| c.entry(Origin::Config, id));
            let hit = entry.is_some_and(|e| e.hit(&policy, &env, i.now.now, cache_ns));
            // A hit matched under another `match` is re-matched, not run
            // again.
            if let (true, Some(e)) = (hit, entry) {
                reapplied.extend(budget.reapplied(e, *pattern));
            }
            !hit
        })
        .map(|(id, r, _, _)| (id, r))
        .collect();
    let attempts = current
        .as_ref()
        .map(|c| {
            c.entries
                .iter()
                .filter(|e| e.origin == Origin::Config)
                .map(|e| (e.id.clone(), e.attempted_at))
                .collect()
        })
        .unwrap_or_default();
    let builtins = i.builtins.to_vec();
    // A drawn builtin language spawns the supervisor even with no config
    // unit: whether it runs is known only once the
    // collection answered, after the marker.
    // Fails without it: test_builtin_probe_runs_once_and_is_cached.
    if runnable.is_empty() && builtins.is_empty() {
        // A config with command units reclaims what an earlier supervisor of
        // the session left even when no unit runs this round;
        // one without any touches nothing. A busy lock is a live supervisor.
        #[cfg(target_os = "linux")]
        if let (false, Some(session)) = (i.config.exec_units.is_empty(), i.session)
            && let Some(root) = root_id(i)
            && let Ok(_lock) = close_only_lock(i.runtime, &lock_name(session, root), i.me, true)
        {
            let _ = session_reclaim(i, session, root);
        }
        // The context is duplicated only for entries to publish: a round
        // with nothing to do keeps the helper's descriptor calls (fsbudget).
        // Fails without the order: test_live_helper_calls_match_stage_formula.
        if !reapplied.is_empty()
            && let Some(binding) = binding
            && let Ok(context) = i.context.try_clone()
        {
            i.reapply.set(Some(Box::new(Publish {
                context,
                binding,
                clock: i.now,
                environments,
                attempts,
                patterns,
                reapplied,
                budget,
            })));
            return Err(Skip::Reapplied);
        }
        return Err(Skip::NoUnits);
    }
    // Another unix has no trusted relay and runs nothing. No CI target is
    // such a unix, so no test runs this branch; `cfg!` keeps it compiled on
    // Linux and macOS too.
    if cfg!(not(any(target_os = "linux", target_os = "macos"))) {
        return Err(Skip::NoRelay);
    }
    // The behavior probe. Every macOS CI runner has the
    // flag, so no test removes this call and fails; `nofollow_any` itself
    // is tested (nofollow_any_probe_decides).
    #[cfg(target_os = "macos")]
    if !nofollow_any(probe_nofollow_any(c"/"), probe_nofollow_any(c"/var/empty")) {
        return Err(Skip::NoNofollowAny);
    }
    let (Some(session), Some(pwd)) = (i.session, i.pwd) else {
        return Err(Skip::NoSession);
    };
    let root = root_id(i).ok_or(Skip::Failed)?;
    let lock =
        close_only_lock(i.runtime, &lock_name(session, root), i.me, true).map_err(|e| match e {
            StoreError::Busy => Skip::Busy,
            _ => Skip::Failed,
        })?;
    // Right after the lock, before any other check can end the round: a
    // round that cannot run (no environment frame) still reclaims.
    #[cfg(target_os = "linux")]
    let (cgroup, notes) = session_reclaim(i, session, root);
    let body = i
        .environment
        .as_ref()
        .map_err(|why| Skip::NoEnvironment(*why))?;
    #[cfg(not(target_os = "linux"))]
    let notes = Vec::new();
    #[cfg(target_os = "macos")]
    let scripts = Scripts::new(i.runtime, i.me, session_tag(session));
    #[cfg(not(target_os = "macos"))]
    let scripts = Scripts::default();
    let mut runnable = runnable;
    let mut neutral_refused = 0;
    let mut probes_allowed = true;
    if !neutral(i.runtime, i.me).map_err(|_| Skip::Failed)? {
        let before = runnable.len();
        runnable.retain(|(_, r)| r.cwd != Cwd::Neutral);
        neutral_refused = before - runnable.len();
        // Probes run in the neutral folder too: none runs, but a value
        // decided without running is still published.
        // Fails without it: test_builtin_fast_value_survives_a_bad_neutral_folder.
        probes_allowed = false;
        if runnable.is_empty() && builtins.is_empty() {
            return Err(Skip::Neutral);
        }
    }
    let grant = Grant {
        permit: Permit {
            kind: 0,
            deadline: 0,
            boot: [0; 16],
            resume: 0,
            domain: [0; 16],
        },
        helper_deadline: i.helper_deadline,
        cwd: pwd.to_vec(),
        neutral: i
            .runtime_path
            .join(NEUTRAL)
            .into_os_string()
            .into_encoded_bytes(),
        units: Vec::new(),
        probes: Vec::new(),
    };
    let (grant_read, grant_pipe) = command_process::channel().map_err(|_| Skip::Failed)?;
    let (results, results_write) = command_process::channel().map_err(|_| Skip::Failed)?;
    super::collector_process::nonblocking(&grant_pipe).map_err(|_| Skip::Failed)?;
    super::collector_process::nonblocking(&results).map_err(|_| Skip::Failed)?;
    let exe = CString::new(i.exe.as_bytes()).map_err(|_| Skip::Failed)?;
    let args = [
        i.exe.as_bytes().to_vec(),
        super::command_supervisor::ENTRY.as_bytes().to_vec(),
    ];
    let child = command_process::spawn_supervisor(
        &exe,
        &args,
        &grant_read,
        &results_write,
        &lock,
        #[cfg(target_os = "linux")]
        cgroup.as_ref().map(|d| &d.folder),
        #[cfg(not(target_os = "linux"))]
        None,
        i.helper_deadline,
    )
    .map_err(|_| Skip::Failed)?;
    Ok(Round {
        child,
        grant,
        runnable: runnable
            .into_iter()
            .map(|(id, r)| (id.to_owned(), r))
            .collect(),
        environment: body.clone(),
        grant_pipe,
        results,
        #[cfg(target_os = "linux")]
        cgroup,
        neutral_refused,
        scripts,
        notes,
        publish: Publish {
            context: i.context.try_clone().map_err(|_| Skip::Failed)?,
            binding: binding.ok_or(Skip::NoSession)?,
            clock: i.now,
            environments,
            attempts,
            patterns,
            reapplied,
            budget,
        },
        builtins,
        probes_allowed,
        current,
        probes: Vec::new(),
        decided: Vec::new(),
        language_units,
        hidden: Vec::new(),
        _lock: lock,
    })
}

/// The permit of the marker this round installed: its clock and trust
/// deadline `verified_at + T`, or deadline 0 for an invalid marker (config
/// units are then refused; builtin probes still run).
pub(crate) fn permit(marker: &Marker) -> Permit {
    Permit {
        kind: marker.kind,
        deadline: if marker.invalid {
            0
        } else {
            marker.verified_at.saturating_add(T_NS)
        },
        boot: marker.id.boot,
        resume: marker.resume,
        domain: marker.domain,
    }
}

/// What came back from one round.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Report {
    pub results: Vec<Outcome>,
    /// Frames that did not decode or did not name a place in the grant.
    pub rejected: usize,
    /// Units left out because their executable was not found or failed the checks.
    pub unresolved: usize,
    /// The shell's folder could not be read: no grant.
    pub failed: bool,
    /// Units over the relay input cap or past the grant frame's room.
    pub oversize: usize,
    /// No collected repository root; the shell's folder stood for it.
    pub repo_fallback: bool,
    /// Environment entries left out (`=` missing, empty, duplicate names).
    pub dropped: plan::Dropped,
    /// The grant could not be written in time: nothing ran.
    pub send_failed: bool,
    /// Diagnostic lines of the round's reclaims.
    pub notes: Vec<&'static str>,
    /// The command response this round published, if any.
    pub published: Option<response::Response>,
    /// Results came back but could not be published (store busy or unsafe).
    pub publish_failed: bool,
    /// Why builtin languages were hidden this round (the reason goes to the log, never to the prompt).
    pub hidden: Vec<&'static str>,
    /// The round walked `PATH` (debug log; D3a re-review M3).
    pub searched: bool,
    /// Shell folders made canonical for rustup (debug log).
    pub resolved: u32,
}

impl Round {
    /// Without publication: no grant. Closing the pipe tells the supervisor
    /// to run nothing; it is then waited for until the helper's deadline.
    /// Returns the round's diagnostic lines.
    pub(crate) fn abandon(self) -> Vec<&'static str> {
        self.end()
    }

    /// `abandon`, then the round's script copies are removed once the
    /// supervisor has ended (reaped: its end of the result pipe is closed,
    /// so it runs nothing more). A supervisor still alive at the helper's
    /// deadline may still be starting an interpreter on one: its copies
    /// stay for the next round of the session to sweep. Then, still under
    /// the lock and only when it was reaped, its unit cgroups are reclaimed
    /// (Linux).
    fn end(self) -> Vec<&'static str> {
        let deadline = self.grant.helper_deadline;
        let Self {
            mut child,
            grant_pipe,
            scripts,
            #[cfg_attr(not(target_os = "linux"), allow(unused_mut, reason = "Linux reclaims"))]
            mut notes,
            #[cfg(target_os = "linux")]
            mut cgroup,
            _lock,
            ..
        } = self;
        drop(grant_pipe);
        // Fails without the check: test_macos_copy_outlives_a_stopped_supervisor_until_the_sweep
        // (a copy removed under a live supervisor).
        let ended = wait(&mut child, deadline);
        if ended {
            scripts.remove_all();
        }
        drop(child);
        // Only a supervisor seen reaped leaves leftovers: one still there at
        // the deadline may outlive the drop's kill (a wait the kill cannot
        // end), and its units are live. The session's next helper reclaims
        // them under the lock once it is gone.
        #[cfg(target_os = "linux")]
        if let Some(parent) = cgroup.as_mut().filter(|_| ended) {
            let r = super::command_cgroup::reclaim(&mut super::command_cgroup::fs::Fs, parent);
            notes.extend(r.messages());
        }
        drop(_lock);
        notes
    }

    /// Sends the grant under `permit`, reads every result until the helper's
    /// deadline less the reserve, then writes done and closes the pipe.
    /// `repo`: the repository component this round's collection reported
    /// for the shell's folder, if it ran.
    pub(crate) fn grant(
        mut self,
        permit: Permit,
        repo: Option<u16>,
        languages: &Languages,
        me: u32,
        groups: &mut SystemGroups,
    ) -> Report {
        self.grant.permit = permit;
        let mut report = Report::default();
        let builtins = !self.builtins.is_empty() && languages.ready(repo);
        // A user-defined language runs only where this round found its
        // marker files; where the files are gone, its shown value is
        // replaced by a hidden one.
        let (skip, hide) = gate_languages(&self.language_units, languages, repo);
        self.runnable.retain(|(id, _)| !skip.contains(id));
        if let Ok(now) = now_ns() {
            for id in &hide {
                if let Some(e) = self.undetected_entry(id, now) {
                    self.decided.push(e);
                }
            }
        }
        // Nothing to search for: no PATH walk, no folder read (D3a security
        // review S-M3).
        if !searches(!self.runnable.is_empty(), builtins) {
            // Fails without it: test_user_language_only_layout_draws_its_version_where_its_files_are.
            if !self.decided.is_empty() {
                self.publish_results(&mut report, &[]);
            }
            report.notes = self.abandon();
            return report;
        }
        report.searched = true;
        let Ok(found) = search(&self.environment, &self.grant.cwd, repo, me, groups) else {
            report.failed = true;
            report.notes = self.abandon();
            return report;
        };
        let resolved = units(
            &self.runnable,
            &self.publish.attempts,
            &self.environment,
            &self.grant,
            &found,
            me,
            groups,
            &mut self.scripts,
        );
        report.unresolved = resolved.unresolved;
        report.oversize = resolved.oversize;
        report.repo_fallback = resolved.repo_fallback;
        report.dropped = resolved.dropped;
        self.grant.units = resolved.units;
        if builtins {
            report.resolved = self.plan_builtins(languages, &found, me, groups);
        }
        report.hidden = std::mem::take(&mut self.hidden);
        // Fails without the probes: test_builtin_probe_runs_once_and_is_cached.
        if self.grant.units.is_empty() && self.grant.probes.is_empty() {
            self.publish_results(&mut report, &resolved.unresolved_ids);
            report.notes = self.abandon();
            return report;
        }
        let unresolved = resolved.unresolved_ids;
        let end = self
            .grant
            .helper_deadline
            .saturating_sub(super::command_supervisor::BUDGET.reserve / 2);
        // units() kept the grant within one frame, so this encodes.
        let Ok(frame) = wire::encode(&Message::Grant(self.grant.clone())) else {
            report.send_failed = true;
            report.notes = self.abandon();
            return report;
        };
        // A short grant is a cut one, which the supervisor refuses whole.
        if !send(self.grant_pipe.as_raw_fd(), &frame, end) {
            report.send_failed = true;
            report.notes = self.abandon();
            return report;
        }
        let want = self.grant.units.len() + self.grant.probes.len();
        let mut bytes = Vec::new();
        let mut chunk = vec![0u8; wire::FRAME_MAX];
        while report.results.len() + report.rejected < want {
            let Ok(now) = now_ns() else { break };
            if now >= end {
                break;
            }
            let mut fds = [libc::pollfd {
                fd: self.results.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            }];
            let wait = i32::try_from((end - now).div_ceil(1_000_000)).unwrap_or(i32::MAX);
            // SAFETY: one valid pollfd.
            if unsafe { libc::poll(fds.as_mut_ptr(), 1, wait) } < 0 {
                break;
            }
            // SAFETY: `chunk` is writable for its length.
            let n = unsafe {
                libc::read(
                    self.results.as_raw_fd(),
                    chunk.as_mut_ptr().cast(),
                    chunk.len(),
                )
            };
            match usize::try_from(n) {
                Ok(0) => break,
                Ok(n) => bytes.extend_from_slice(&chunk[..n]),
                Err(_) => continue,
            }
            while bytes.len() >= wire::HEADER {
                let Ok(total) = wire::frame_len(&bytes[..wire::HEADER]) else {
                    report.rejected = want;
                    break;
                };
                if bytes.len() < total {
                    break;
                }
                match wire::decode(&bytes[..total]) {
                    Ok(Message::Result(o)) if plan::accept(&self.grant, &report.results, &o) => {
                        report.results.push(o)
                    }
                    _ => report.rejected += 1,
                }
                bytes.drain(..total);
            }
        }
        if let Ok(done) = wire::encode(&Message::Done) {
            let _ = sys::write_fd(self.grant_pipe.as_raw_fd(), &done);
        }
        self.publish_results(&mut report, &unresolved);
        // The note joins the round's own, which `abandon` returns: a note put
        // on the report first would be overwritten by that.
        self.notes.extend(spawn_failed_note(&report.results));
        report.notes = self.abandon();
        report
    }
}

#[cfg(test)]
mod tests {
    use super::super::collector_process::pipe;
    use super::*;

    // 이것을 실패시키는 것: 시작하지 못한 단위가 있어도 알리지 않는 것, 시작한 단위(정상 종료·시간 초과)만 있는데
    // 알리는 것.
    #[test]
    fn a_unit_that_could_not_start_is_said_once() {
        let outcome = |reason| Outcome {
            origin: Origin::Config,
            index: 0,
            reason,
            approved_at: 1,
            ended_at: 2,
            stdout: Vec::new(),
        };
        assert_eq!(spawn_failed_note(&[]), None);
        assert_eq!(
            spawn_failed_note(&[
                outcome(wire::Reason::Exited(0)),
                outcome(wire::Reason::Timeout)
            ]),
            None
        );
        let failed = [
            outcome(wire::Reason::SpawnFailed),
            outcome(wire::Reason::SpawnFailed),
            outcome(wire::Reason::Exited(0)),
        ];
        assert_eq!(spawn_failed_note(&failed), Some(SPAWN_FAILED));
    }
    use bingsu_core::snapshot::Identity;

    fn runnable(id: &str, env_allow: &[&str]) -> (String, plan::Runnable) {
        (
            id.to_owned(),
            plan::Runnable {
                policy: Policy::Argv {
                    argv: vec![b"/usr/bin/true".to_vec()],
                },
                cwd: Cwd::Neutral,
                timeout: plan::TIMEOUT_DEFAULT,
                env_allow: env_allow.iter().map(|n| n.as_bytes().to_vec()).collect(),
                detect: Vec::new(),
            },
        )
    }
    // 폴더 사실이 저장소를 확정했을 때만 내장 언어를 정한다. in_repo를 모르거나(탐색 깊이 제한) 저장소 안인데 뿌리
    // 위치를 모르면(별칭 경로) 미확정이다. 이것을 실패시키는 것: 미확정을 저장소 밖으로 보는 것,
    // 뿌리 위치 없는 저장소 안을 받는 것.
    #[test]
    fn roots_stay_unknown_unless_settled() {
        use bingsu_core::collection::path_facts::PathFactInput;
        let of = |in_repo, repo_component| {
            Root::of(&PathFactInput {
                in_repo,
                repo_component,
                ..PathFactInput::default()
            })
        };
        assert_eq!(of(Some(false), None), Root::Outside);
        assert_eq!(of(Some(true), Some(1)), Root::Repo(1));
        assert_eq!(of(None, None), Root::Unknown);
        assert_eq!(of(Some(true), None), Root::Unknown);
        assert_eq!(of(None, Some(1)), Root::Unknown);
    }

    // 수집 답과 같은 저장소의 폴더 사실이 있을 때만 내장 언어를 정하고, 할 일이 없는 회차는 PATH를
    // 걷지 않는다. 이것을 실패시키는 것: 폴더 사실 없이 내장 언어를 정하는 것(셸 폴더가 저장소를
    // 대신함), 다른 저장소의 사실을 받는 것, 답 없는 회차를 정하는 것, 할 일이 없어도 탐색하는 것.
    // 사용자 정의 language는 이 회차가 그 표시 파일을 찾았을 때만 돈다. 찾지 못한 것은 건너뛰고 숨김
    // 항목 대상이며, 답이 없거나 뿌리가 미확정이면 건너뛰기만 한다(숨기지도 않음). 이것을 실패시키는 것: 찾지 못한
    // 단위를 실행 목록에 남기는 것, 답 없는 단위를 숨김으로 보내는 것, 뿌리 미확정에서 정하는 것.
    // 사용자 정의 language 항목은 출력 첫 줄의 버전 단어만 값으로 남기고, 버전 단어가 없으면 값 없는 실패
    // 항목이다. 실패 항목은 그대로 둔다. 이것을 실패시키는 것: 첫 줄을 그대로 값으로 쓰는 것, 버전이 없는 줄을
    // 성공으로 남기는 것.
    #[test]
    fn a_language_entry_keeps_only_its_version() {
        let entry = |status, raw: &str| response::Entry {
            origin: Origin::Config,
            id: "custom/deno".into(),
            policy: [1; 32],
            environment: [2; 32],
            pattern: [0; 32],
            attempted_at: 1,
            completed_at: 2,
            status,
            value: raw.into(),
            raw: raw.into(),
        };
        let e = language_entry(entry(response::Status::Ok, "deno 2.1.4 (stable)"));
        assert_eq!(
            (e.status, e.value.as_str()),
            (response::Status::Ok, "2.1.4")
        );
        let e = language_entry(entry(response::Status::Ok, "no version here"));
        assert_eq!(
            (e.status, e.value.as_str(), e.raw.as_str()),
            (response::Status::Failed, "", "")
        );
        let e = language_entry(entry(response::Status::Failed, ""));
        assert_eq!(e.status, response::Status::Failed);
    }

    // 감지 파일이 있는 곳에서만 사용자 language를 돌리고, 정하지 못한 회차(폴더 사실이 저장소를 확정하지 않음,
    // 수집 답 없음)는 숨기지 않아 그리던 값이 남는다. 이것을 실패시키는 것: 미확정을 숨김으로
    // 보는 것, 답 없는 회차를 감지 결과로 정하는 것.
    #[test]
    fn a_language_runs_only_where_its_files_were_found() {
        use bingsu_core::collection::language::Version;
        let units = [
            "custom/a".to_string(),
            "custom/b".to_string(),
            "custom/c".to_string(),
        ];
        let answered = |root| Languages {
            answers: vec![
                (b"custom/a".to_vec(), Version::None),
                (b"custom/b".to_vec(), Version::None),
            ],
            found: vec![(b"custom/a".to_vec(), true), (b"custom/b".to_vec(), false)],
            root,
        };
        let (skip, hide) = gate_languages(&units, &answered(Root::Outside), None);
        assert_eq!(skip, ["custom/b", "custom/c"]);
        assert_eq!(hide, ["custom/b"]);
        let (skip, hide) = gate_languages(&units, &answered(Root::Unknown), None);
        assert_eq!(skip, ["custom/a", "custom/b", "custom/c"]);
        assert!(hide.is_empty());
        let (skip, _) = gate_languages(&units, &answered(Root::Repo(2)), Some(3));
        assert_eq!(skip.len(), 3);
        // No answer from the collection: undecided, so nothing is hidden and
        // the shown values stay, even beside a marker result.
        let unanswered = Languages {
            answers: Vec::new(),
            ..answered(Root::Outside)
        };
        let (skip, hide) = gate_languages(&units, &unanswered, None);
        assert_eq!(skip, ["custom/a", "custom/b", "custom/c"]);
        assert!(hide.is_empty());
    }

    #[test]
    fn a_round_with_nothing_to_decide_searches_nothing() {
        use bingsu_core::collection::language::Version;
        let answered = |root| Languages {
            answers: vec![(b"node".to_vec(), Version::None)],
            found: Vec::new(),
            root,
        };
        assert!(answered(Root::Outside).ready(None));
        assert!(!answered(Root::Outside).ready(Some(2)));
        assert!(answered(Root::Repo(2)).ready(Some(2)));
        assert!(!answered(Root::Unknown).ready(None));
        assert!(!answered(Root::Repo(2)).ready(Some(3)));
        assert!(
            !Languages {
                answers: Vec::new(),
                found: Vec::new(),
                root: Root::Outside
            }
            .ready(None)
        );
        assert!(!searches(false, false));
        assert!(searches(true, false));
        assert!(searches(false, true));
    }

    // 허가 프레임을 거의 채운 grant에는 probe를 더하지 않는다(그 probe만 빠지고 회차는 그대로). 이것을 실패시키는
    // 것: fits가 인코딩 실패를 보지 않는 것.
    #[test]
    fn a_probe_past_the_frame_is_left_out() {
        let probe = wire::Probe {
            profile: bingsu_core::command::profile::NODE,
            executable: b"/usr/bin/node".to_vec(),
            pin: None,
            toolchain: None,
        };
        let mut g = base();
        assert!(fits(&g, &probe));
        // The longest shell folder that still encodes: the grant is full.
        let full = (1..wire::FRAME_MAX)
            .rev()
            .find(|n| {
                g.cwd = [b"/".as_slice(), &vec![b'a'; *n]].concat();
                wire::encode(&Message::Grant(g.clone())).is_ok()
            })
            .unwrap();
        g.cwd = [b"/".as_slice(), &vec![b'a'; full]].concat();
        assert!(!fits(&g, &probe));
    }

    fn base() -> Grant {
        Grant {
            permit: Permit {
                kind: 1,
                deadline: 9,
                boot: [1; 16],
                resume: 0,
                domain: [2; 16],
            },
            helper_deadline: 9,
            // A folder of its own stands for the repository (no collected root).
            cwd: std::env::temp_dir().into_os_string().into_encoded_bytes(),
            neutral: b"/tmp".to_vec(),
            units: Vec::new(),
            probes: Vec::new(),
        }
    }
    fn groups() -> SystemGroups {
        SystemGroups::new(&sys::passwd_entry(sys::current_uid()).unwrap().name)
    }

    // "/"는 0, 링크를 지나는 "/var/empty"는 ELOOP일 때만 relay를 쓴다(EINVAL은 그 플래그가 없는
    // macOS, 받기만 하고 지키지 않는 플래그는 링크 쪽에서 걸림). 이 Mac의 탐침 결과도 기록한다. 이것을 실패시키는
    // 것: nofollow_any의 두 조건 가운데 하나를 지우는 것.
    #[cfg(target_os = "macos")]
    #[test]
    fn nofollow_any_probe_decides() {
        assert!(nofollow_any(0, libc::ELOOP));
        assert!(!nofollow_any(libc::EINVAL, libc::EINVAL));
        assert!(!nofollow_any(0, 0));
        assert!(!nofollow_any(libc::EPERM, libc::ELOOP));
        let (root, link) = (probe_nofollow_any(c"/"), probe_nofollow_any(c"/var/empty"));
        eprintln!("AT_SYMLINK_NOFOLLOW_ANY probe on this host: / {root}, /var/empty {link}");
        assert!(nofollow_any(root, link), "this macOS runs no command round");
    }

    #[cfg(target_os = "macos")]
    fn scratch_runtime(tag: &str) -> (std::path::PathBuf, File) {
        let base = std::fs::canonicalize(std::env::temp_dir()).unwrap();
        let t = base.join(format!("bingsu-grant-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&t);
        std::fs::create_dir(&t).unwrap();
        std::fs::set_permissions(&t, std::os::unix::fs::PermissionsExt::from_mode(0o700)).unwrap();
        let root = File::open(&t).unwrap();
        (t, root)
    }

    // macOS 스크립트는 세션 이름이 붙은 사본으로, 핀 없이 넘긴다. 네이티브 파일은 그대로다. 빠진 단위의
    // 사본과 회차의 사본은 지운다. 이것을 실패시키는 것: executable()의 사본 분기를 지우는 것(원본 경로가 넘어감),
    // forget_last나 remove_all의 unlink를 지우는 것.
    #[cfg(target_os = "macos")]
    #[test]
    fn macos_scripts_run_as_tagged_private_copies() {
        let (t, root) = scratch_runtime("scripts");
        let tool = t.join("tool");
        std::fs::write(&tool, b"#!/bin/sh\necho hi\n").unwrap();
        std::fs::set_permissions(&tool, std::os::unix::fs::PermissionsExt::from_mode(0o700))
            .unwrap();
        let me = sys::current_uid();
        let mut g = groups();
        let mut scripts = Scripts::new(&root, me, "abcd".to_owned());
        let (found, checked) = exec_path::resolve_open(&tool, &[], me, &mut g).unwrap();
        let (exe, pin) = scripts.executable(&found, &checked).unwrap();
        let exe = std::path::PathBuf::from(OsStr::from_bytes(&exe));
        assert_ne!(exe, tool);
        assert!(
            exe.file_name().unwrap().as_bytes().starts_with(b"abcd-"),
            "{exe:?}"
        );
        assert_eq!(pin, None);
        assert_eq!(std::fs::read(&exe).unwrap(), std::fs::read(&tool).unwrap());
        let (native, checked) =
            exec_path::resolve_open(Path::new("/bin/ls"), &[], me, &mut g).unwrap();
        let (path, _) = scripts.executable(&native, &checked).unwrap();
        assert_eq!(path, native.executable.as_os_str().as_bytes());
        let (found2, checked2) = exec_path::resolve_open(&tool, &[], me, &mut g).unwrap();
        let (left_out, _) = scripts.executable(&found2, &checked2).unwrap();
        scripts.forget_last(&left_out);
        assert!(!Path::new(OsStr::from_bytes(&left_out)).exists());
        assert!(exe.exists());
        scripts.remove_all();
        assert!(!exe.exists());
        std::fs::remove_dir_all(&t).unwrap();
    }

    // 상한을 넘는 단위만 빠지고 나머지는 돈다. 이것을 실패시키는 것: units()의 relay 입력 상한 검사를
    // 지우는 것(20 KB 환경 단위가 허가에 남음), 허가 전체 encode 검사를 지우는 것(여덟 단위 × 15 KB가 한 프레임을
    // 넘어 회차 전체가 실패함).
    #[test]
    fn oversize_units_are_left_out_alone() {
        let big = |n: usize| {
            [
                b"PATH=/usr/bin:/bin\0BIG=".as_slice(),
                &vec![b'x'; n],
                b"\0",
            ]
            .concat()
        };
        let units20 = vec![
            runnable("custom/big", &["BIG"]),
            runnable("custom/small", &[]),
        ];
        let got = units(
            &units20,
            &[],
            &big(20 * 1024),
            &base(),
            &search(
                &big(20 * 1024),
                &base().cwd,
                None,
                sys::current_uid(),
                &mut groups(),
            )
            .unwrap(),
            sys::current_uid(),
            &mut groups(),
            &mut Scripts::default(),
        );
        assert_eq!((got.units.len(), got.oversize), (1, 1));
        assert_eq!(got.units[0].id, "custom/small");
        let eight: Vec<_> = (0..8)
            .map(|i| runnable(&format!("custom/u{i}"), &["BIG"]))
            .collect();
        let got = units(
            &eight,
            &[],
            &big(15 * 1024),
            &base(),
            &search(
                &big(15 * 1024),
                &base().cwd,
                None,
                sys::current_uid(),
                &mut groups(),
            )
            .unwrap(),
            sys::current_uid(),
            &mut groups(),
            &mut Scripts::default(),
        );
        assert!(
            got.oversize > 0 && !got.units.is_empty(),
            "{} {}",
            got.units.len(),
            got.oversize
        );
        let mut g = base();
        g.units = got.units;
        assert!(wire::encode(&Message::Grant(g)).is_ok());
    }

    // J9·L5: 수집 루트가 없으면 대체를 알리고, 버린 환경 항목 수를 센다. 이것을 실패시키는 것: repo_fallback을
    // 늘 false로 두는 것, dropped를 옮기지 않는 것.
    #[test]
    fn units_report_the_fallback_and_dropped_entries() {
        let env = b"PATH=/usr/bin:/bin\0NOEQ\0X=1\0X=2\0";
        let got = units(
            &[runnable("custom/a", &[])],
            &[],
            env,
            &base(),
            &search(env, &base().cwd, None, sys::current_uid(), &mut groups()).unwrap(),
            sys::current_uid(),
            &mut groups(),
            &mut Scripts::default(),
        );
        assert!(got.repo_fallback);
        assert_eq!(
            got.dropped,
            plan::Dropped {
                malformed: 1,
                duplicate: 1
            }
        );
        let got = units(
            &[runnable("custom/a", &[])],
            &[],
            env,
            &base(),
            &search(env, &base().cwd, Some(0), sys::current_uid(), &mut groups()).unwrap(),
            sys::current_uid(),
            &mut groups(),
            &mut Scripts::default(),
        );
        assert!(!got.repo_fallback);
    }

    // 수집 루트가 없는 회차에도 셸 폴더 위의 `.git` 조상이 저장소다. 셸이 저장소 하위 폴더에 있으면 저장소
    // 뿌리 아래 PATH 폴더의 실행 파일을 찾지 않는다. 대조: `.git`이 없으면 같은 폴더의 실행 파일을 찾는다(J9 대체는
    // 셸 폴더만 뺀다). 셸 폴더까지 걷지 못하면 회차를 거부한다. 이것을 실패시키는 것: units()에서 찾은
    // 조상을 저장소 목록에 넣지 않는 것. 조상 검사의 거부를 "저장소 없음"으로 바꾸는 변이는 이 칸이 잡지 못한다:
    // 걷지 못하는 셸 폴더는 그 앞의 셸 폴더 정체 조회(repo_id)도 실패하기 때문이다(경합에서만 갈림).
    #[test]
    fn units_keep_a_repository_bin_out_without_a_collected_root() {
        use std::os::unix::fs::PermissionsExt;
        let t = std::env::temp_dir().join(format!("bingsu-grant-scan-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&t);
        let repo = t.join("repo");
        for d in [&t, &repo, &repo.join("bin"), &repo.join("sub")] {
            std::fs::create_dir_all(d).unwrap();
            std::fs::set_permissions(d, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let t = std::fs::canonicalize(&t).unwrap();
        let repo = t.join("repo");
        let probe = repo.join("bin/probe-scan");
        std::fs::copy(std::fs::canonicalize("/usr/bin/true").unwrap(), &probe).unwrap();
        std::fs::set_permissions(&probe, std::fs::Permissions::from_mode(0o755)).unwrap();
        let env = [
            b"PATH=".as_slice(),
            repo.join("bin").as_os_str().as_bytes(),
            b"\0",
        ]
        .concat();
        let unit = (
            "custom/a".to_owned(),
            plan::Runnable {
                policy: Policy::Argv {
                    argv: vec![b"probe-scan".to_vec()],
                },
                cwd: Cwd::Neutral,
                timeout: plan::TIMEOUT_DEFAULT,
                env_allow: Vec::new(),
                detect: Vec::new(),
            },
        );
        let run = |cwd: &Path| {
            let mut grant = base();
            grant.cwd = cwd.as_os_str().as_bytes().to_vec();
            let found = search(&env, &grant.cwd, None, sys::current_uid(), &mut groups())?;
            Ok::<_, Skip>(units(
                std::slice::from_ref(&unit),
                &[],
                &env,
                &grant,
                &found,
                sys::current_uid(),
                &mut groups(),
                &mut Scripts::default(),
            ))
        };
        let sub = repo.join("sub");
        assert_eq!(run(&sub).unwrap().unresolved, 0, "control: no repository");
        std::fs::create_dir(repo.join(".git")).unwrap();
        let got = run(&sub).unwrap();
        assert!(got.repo_fallback);
        assert_eq!(got.unresolved, 1, "the repository's bin was searched");
        // A shell folder that cannot be walked refuses the round.
        let locked = repo.join("locked");
        if sys::current_uid() != 0 {
            std::fs::create_dir_all(locked.join("in")).unwrap();
            std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();
            let got = run(&locked.join("in"));
            std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o755)).unwrap();
            assert!(matches!(got, Err(Skip::Failed)));
        }
        let _ = std::fs::remove_dir_all(&t);
    }

    // M4: 허가는 4 KB 파이프에서도 감독이 읽는 동안 이어 써서 끝까지 간다. 읽는 쪽이 없으면 마감에 실패한다.
    // 이것을 실패시키는 것: send가 EAGAIN이나 부분 쓰기에서 멈추는 것(write 한 번만).
    #[cfg(target_os = "linux")]
    #[test]
    fn grant_send_waits_for_a_small_pipe() {
        let (read, write) = pipe().unwrap();
        super::super::collector_process::nonblocking(&write).unwrap();
        // SAFETY: F_SETPIPE_SZ on the test's own pipe.
        assert!(unsafe { libc::fcntl(write.as_raw_fd(), libc::F_SETPIPE_SZ, 4096) } >= 4096);
        let frame = vec![7u8; 40 * 1024];
        let reader = std::thread::spawn(move || {
            use std::io::Read;
            let mut got = Vec::new();
            let mut read = read;
            let mut buf = [0u8; 1024];
            while let Ok(n) = read.read(&mut buf) {
                if n == 0 {
                    break;
                }
                got.extend_from_slice(&buf[..n]);
                std::thread::sleep(std::time::Duration::from_micros(200));
            }
            got.len()
        });
        let until = now_ns().unwrap() + 2_000_000_000;
        assert!(send(write.as_raw_fd(), &frame, until));
        drop(write);
        assert_eq!(reader.join().unwrap(), frame.len());
        // Nobody reads: the deadline ends it.
        let (_read, write) = pipe().unwrap();
        super::super::collector_process::nonblocking(&write).unwrap();
        // SAFETY: as above.
        unsafe { libc::fcntl(write.as_raw_fd(), libc::F_SETPIPE_SZ, 4096) };
        let until = now_ns().unwrap() + 50_000_000;
        assert!(!send(write.as_raw_fd(), &frame, until));
    }

    // 첫 부분 쓰기 뒤에 마감이 지나면 다음 write를 하지 않는다(시계·write 주입). 이것을 실패시키는 것:
    // send_with의 쓰기 전 마감 검사를 지우는 것(둘째 write가 일어남).
    #[test]
    fn grant_send_stops_writing_once_its_deadline_passes() {
        let mut calls = 0;
        let mut clock = [10, 200, 300].into_iter();
        let mut writes = 0;
        let sent = send_with(
            b"0123456789",
            100,
            &mut || {
                calls += 1;
                clock.next()
            },
            &mut |b: &[u8]| {
                writes += 1;
                Ok(3.min(b.len()))
            },
            &mut |_| {},
        );
        assert!(!sent);
        assert_eq!(writes, 1, "the partial write, then the deadline");
        assert_eq!(calls, 2);
    }

    // EAGAIN 뒤에는 기다리기 직전에 시계를 다시 읽고, 그사이 마감이 지났으면 기다리지 않고 false다. 이것을
    // 실패시키는 것: 기다릴 시간을 write 전 시각으로 계산하는 것(기다리기 전 재확인 삭제).
    #[test]
    fn grant_send_rereads_the_clock_before_waiting() {
        let mut clock = [10, 200, 300].into_iter();
        let mut waits = 0;
        let sent = send_with(
            b"grant",
            100,
            &mut || clock.next(),
            &mut |_: &[u8]| Err(libc::EAGAIN),
            &mut |_| waits += 1,
        );
        assert!(!sent);
        assert_eq!(waits, 0, "the deadline passed during the write");
    }

    /// CPU time of this thread.
    fn thread_cpu() -> std::time::Duration {
        // SAFETY: an all-zero timespec is a valid value for the call to fill.
        let mut t: libc::timespec = unsafe { std::mem::zeroed() };
        // SAFETY: `t` is writable; the clock id is a constant.
        let rc = unsafe { libc::clock_gettime(libc::CLOCK_THREAD_CPUTIME_ID, &mut t) };
        assert_eq!(rc, 0);
        std::time::Duration::new(t.tv_sec as u64, t.tv_nsec as u32)
    }

    // 회차의 허가·결과 통로는 command_process::channel로 만든다(macOS는 소켓). prepare를 끝까지 도는 단위 시험이
    // 없어 소스로 본다. 이것을 실패시키는 것: 둘 중 하나를 파이프로 만드는 것(macOS에서 512바이트 파이프가 가득
    // 차면 감독과 도우미가 마감까지 돎).
    #[test]
    fn a_round_makes_its_channels_with_channel() {
        let src = include_str!("command_grant.rs").replace("\r\n", "\n");
        let body = &src[src.find("pub(crate) fn prepare(").unwrap()..];
        let body = &body[..body.find("\n}\n").unwrap()];
        assert_eq!(body.matches("command_process::channel()").count(), 2);
        assert!(!body.contains("pipe()"));
    }

    // 읽는 쪽이 읽지 않는 동안 send는 마감까지 기다리되 CPU를 쓰지 않는다. 이것을 실패시키는 것: macOS에서
    // 통로를 파이프로 되돌리는 것(커널 파이프 메모리가 모자라 파이프가 512바이트에 머문 Mac에서는 poll이 가득 찬
    // 파이프를 쓰기 가능이라 하고 write는 EAGAIN이라, 마감까지 CPU를 다 씀). 파이프가 정상으로 커지는 Mac과
    // Linux에서는 그 변이가 이 시험으로는 잡히지 않고, 통로 종류 시험(command_process)이 잡는다.
    #[test]
    fn a_grant_waiting_for_its_reader_uses_no_cpu() {
        let (_read, write) = command_process::channel().unwrap();
        super::super::collector_process::nonblocking(&write).unwrap();
        // More than any channel takes, so the write waits.
        let frame = vec![7u8; 1 << 20];
        let (cpu, wall) = (thread_cpu(), std::time::Instant::now());
        let until = now_ns().unwrap() + 300_000_000;
        assert!(!send(write.as_raw_fd(), &frame, until));
        let (cpu, wall) = (thread_cpu() - cpu, wall.elapsed());
        assert!(wall >= std::time::Duration::from_millis(290), "{wall:?}");
        assert!(cpu * 5 < wall, "cpu {cpu:?} over {wall:?}");
    }

    // 마감이 지난 뒤에는 빈 파이프라도 쓰지 않는다. 이것을 실패시키는 것: send의 쓰기 전 마감 검사를 지우는 것.
    #[test]
    fn grant_send_writes_nothing_past_its_deadline() {
        let (read, write) = pipe().unwrap();
        super::super::collector_process::nonblocking(&write).unwrap();
        super::super::collector_process::nonblocking(&read).unwrap();
        let past = now_ns().unwrap() - 1;
        assert!(!send(write.as_raw_fd(), b"grant", past));
        let mut b = [0u8; 8];
        // SAFETY: writable buffer; non-blocking read end.
        let n = unsafe { libc::read(read.as_raw_fd(), b.as_mut_ptr().cast(), b.len()) };
        assert!(n < 0, "nothing was written");
    }

    // 무효 표식 회차의 permit은 deadline 0이라 설정 단위가 모두 거부된다(내장 조사만). 이것을 실패시키는
    // 것: permit()의 `marker.invalid` 분기를 지우는 것, T를 더하지 않는 것.
    #[test]
    fn permit_follows_the_installed_marker() {
        let marker = Marker {
            id: Identity {
                boot: [7; 16],
                epoch: [0; 16],
                context: [0; 4],
                generation: 3,
                source: [0; 4],
            },
            seq: 1,
            verified_at: 1_000,
            kind: 1,
            domain: [9; 16],
            resume: 2,
            invalid: false,
        };
        assert_eq!(
            permit(&marker),
            Permit {
                kind: 1,
                deadline: 1_000 + T_NS,
                boot: [7; 16],
                resume: 2,
                domain: [9; 16],
            }
        );
        let invalid = Marker {
            invalid: true,
            ..marker
        };
        assert_eq!(permit(&invalid).deadline, 0);
    }

    // 파일 이름에는 세션 값이 아니라 고정 길이 요약값만, 그리고 그 요약값은 세션 cgroup 부모의 것과 같다
    // (m6-C4a7: 잠금이 부모를 가리킴). 이것을 실패시키는 것: lock_name이 세션 값을 그대로 쓰는 것, 부모와
    // 다른 요약값(세션만, runtime 없이)을 쓰는 것.
    #[test]
    fn lock_name_is_the_parent_digest() {
        let root = (7, 9);
        let name = lock_name(b"0123456789abcdef0123456789abcdef", root);
        assert_eq!(name.len(), "command-".len() + 32 + ".lock".len());
        assert!(!name.contains("0123456789abcdef"));
        assert_ne!(name, lock_name(b"fedcba9876543210fedcba9876543210", root));
        assert_ne!(
            name,
            lock_name(b"0123456789abcdef0123456789abcdef", (7, 10))
        );
        let parent =
            bingsu_core::command::cgroup::parent_name(b"0123456789abcdef0123456789abcdef", root);
        assert_eq!(
            name["command-".len()..name.len() - ".lock".len()],
            parent["bingsu-cmd-".len()..]
        );
    }
}
