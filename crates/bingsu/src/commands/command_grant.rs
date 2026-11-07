//! The refresh helper's side of a command round (U-1 C+, U-15 Q1): whether
//! this round has config units to run, the session lock, the grant built in
//! memory from the compiled config the helper holds (never by decoding the
//! published snapshot again), the supervisor spawned before the helper's
//! filter, and, once the marker is installed, the one grant, the results
//! and the done frame. The helper keeps the grant pipe's write end until it
//! has every result, so its end of file tells the supervisor the helper is
//! gone. Results are checked and dropped here; publishing them is C4.
use super::{
    builtin_probe::{self, Action, Language, Planned},
    collection_store::close_only_lock,
    collector_process::{OwnedChild, now_ns, pipe},
    command_process, exec_path,
    group_policy::SystemGroups,
    helper::NoEnv,
    snapshot_store::StoreError,
    sys,
};
use bingsu_core::{
    command::{
        cgroup,
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

/// The shell to run an `unsafe_shell` script with: a fixed path, resolved
/// by the same rules as any executable, never looked up in `PATH`.
const SHELL: &[u8] = b"/bin/sh";
/// The neutral working folder in the runtime root (spec: empty).
const NEUTRAL: &str = "neutral";
pub(crate) const NEUTRAL_REFUSED: &str =
    "command round: the neutral folder is not empty, the user's and 0500; its units do not run";

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
    /// The builtin languages whose segments this round draws (D3 ruling
    /// Q6); empty on a redraw.
    pub builtins: &'a [&'static Language],
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
    /// macOS (C2 ruling Q2).
    NoRelay,
    /// This macOS refuses `AT_SYMLINK_NOFOLLOW_ANY`, without which the
    /// relay's name check refuses every target (C2 ruling Q3).
    #[cfg(target_os = "macos")]
    NoNofollowAny,
    /// Every unit runs in the neutral folder, which is not empty, the
    /// user's and 0500.
    Neutral,
    Failed,
}
impl Skip {
    pub(crate) fn message(self) -> Option<&'static str> {
        Some(match self {
            Self::NoUnits => return None,
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
    /// Why builtin languages were hidden, for the helper's log.
    pub hidden: Vec<&'static str>,
    /// The session lock; the supervisor holds its own copy. Dropped last:
    /// the reclaim after the supervisor runs while it is still held.
    _lock: File,
}

/// The command response of a round: its context, binding, and for each
/// unit to run the original environment digest it is bound to; the attempt
/// times of the units for round robin; when the round started.
struct Publish {
    context: super::snapshot_store::CheckedContextFd,
    binding: response::Binding,
    clock: bingsu_core::snapshot::Clock,
    environments: Vec<(String, [u8; 32])>,
    attempts: Vec<(String, u64)>,
}

/// Script copies of one round. Linux runs a script through a sealed memfd
/// the relay makes, so this holds nothing there. macOS runs the helper's
/// private copy (C2 ruling Q1): made after the marker from the descriptor
/// the checks ran on, named after the session, removed once the
/// supervisor has ended, or by a later round of the same session. The
/// `scripts` folder is opened (and swept) at the round's first script.
#[derive(Default)]
struct Scripts {
    #[cfg(target_os = "macos")]
    runtime: Option<File>,
    #[cfg(target_os = "macos")]
    me: u32,
    #[cfg(target_os = "macos")]
    tag: String,
    /// `None` until the first script; then the folder, if it passed.
    #[cfg(target_os = "macos")]
    copies: Option<Option<exec_path::ScriptCopies>>,
    #[cfg(target_os = "macos")]
    made: Vec<std::path::PathBuf>,
}

impl Scripts {
    /// macOS: the round's script copies in the runtime root. Only the
    /// holder of the session lock makes one.
    #[cfg(target_os = "macos")]
    fn new(runtime: &File, me: u32, tag: String) -> Self {
        Self {
            runtime: runtime.try_clone().ok(),
            me,
            tag,
            copies: None,
            made: Vec::new(),
        }
    }

    /// macOS: the `scripts` folder, opened at the first call after the
    /// copies an earlier round of this session left were swept. A folder
    /// that fails its checks leaves scripts unresolved; other units run.
    /// Fails without the laziness: test_macos_unit_is_one_process_the_relay_execs_into
    /// (a round without scripts makes no folder).
    #[cfg(target_os = "macos")]
    fn copies(&mut self) -> Option<&exec_path::ScriptCopies> {
        if self.copies.is_none() {
            let opened = self
                .runtime
                .as_ref()
                .and_then(|r| exec_path::ScriptCopies::open(r.as_fd(), self.me).ok());
            if let Some(c) = &opened {
                c.sweep(&self.tag);
            }
            self.copies = Some(opened);
        }
        self.copies.as_ref()?.as_ref()
    }

    /// The executable the relay runs for `found` and its pin: the file
    /// itself, or on macOS a script's private copy (no pin: the copy is the
    /// user's 0600 file). `None` when the copy cannot be made.
    fn executable(
        &mut self,
        found: &exec_path::Found,
        checked: &exec_path::Checked,
    ) -> Option<(Vec<u8>, Option<bingsu_core::command::path::ExecPin>)> {
        #[cfg(target_os = "macos")]
        if found.interpreter.is_some() {
            let tag = self.tag.clone();
            let copy = self.copies()?.copy(checked, &tag).ok()?;
            self.made.push(copy.clone());
            return Some((copy.into_os_string().into_encoded_bytes(), None));
        }
        let _ = checked;
        Some((
            found
                .executable
                .clone()
                .into_os_string()
                .into_encoded_bytes(),
            found.pin,
        ))
    }

    /// The copy `executable` just made, for a unit left out after all.
    fn forget_last(&mut self, executable: &[u8]) {
        #[cfg(target_os = "macos")]
        if let (Some(Some(c)), Some(last)) = (&self.copies, self.made.last())
            && last.as_os_str().as_encoded_bytes() == executable
        {
            c.remove(last);
            self.made.pop();
        }
        let _ = executable;
    }

    /// Removes every copy this round made.
    fn remove_all(self) {
        #[cfg(target_os = "macos")]
        if let Some(Some(c)) = &self.copies {
            for copy in &self.made {
                c.remove(copy);
            }
        }
    }
}

/// This round's language answers, by the asked language's id (U-3 L2): what
/// the collector found for each version selection file. Empty when the
/// collection did not run or did not finish.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Languages {
    answers: Vec<(Vec<u8>, bingsu_core::collection::language::Version)>,
    /// What the folder facts say of the repository (D3a review H1).
    root: Root,
}

/// The repository the folder facts found for the shell's folder.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum Root {
    /// No facts, or facts that could not settle it: an alias folder path,
    /// a search cut at its depth limit. Builtin languages are not decided.
    #[default]
    Unknown,
    /// Confirmed outside any repository.
    Outside,
    /// Inside, the root at this component of the shell's folder.
    Repo(u16),
}

impl Root {
    /// From one round's folder facts (re-review H1: `in_repo` unknown, or
    /// in a repository whose root component is not known, is unknown).
    pub(crate) fn of(facts: &bingsu_core::collection::path_facts::PathFactInput) -> Self {
        // Fails without each: roots_stay_unknown_unless_settled.
        match (facts.in_repo, facts.repo_component) {
            (Some(false), _) => Self::Outside,
            (Some(true), Some(component)) => Self::Repo(component),
            _ => Self::Unknown,
        }
    }
}

impl Languages {
    /// The answers of a finished collection, by the asked language's id.
    pub(crate) fn from_result(c: &bingsu_core::collection::response::Completed) -> Self {
        let answers = c
            .languages
            .iter()
            .filter_map(|l| {
                let q = c.language_queries.get(usize::from(l.index))?;
                Some((q.id.clone(), l.version.clone()))
            })
            .collect();
        let root = c
            .updates
            .iter()
            .find_map(|u| u.facts.as_ref())
            .map_or(Root::Unknown, Root::of);
        Self { answers, root }
    }

    /// Whether the builtin languages may be decided this round: the
    /// collection answered them, and its folder facts name the same
    /// repository the round searches with (`repo`). Without the facts the
    /// shell's folder would stand for the repository, and an executable
    /// inside the real one could run (D3a review H1).
    pub(crate) fn ready(&self, repo: Option<u16>) -> bool {
        // Fails without each: a_round_with_nothing_to_decide_searches_nothing,
        // and test_builtin_probe_never_runs_from_the_repository (no facts).
        !self.answers.is_empty()
            && match self.root {
                Root::Unknown => false,
                Root::Outside => repo.is_none(),
                Root::Repo(component) => repo == Some(component),
            }
    }

    /// Answers and a root as a collection would give them (tests).
    #[cfg(test)]
    pub(crate) fn of(
        answers: Vec<(Vec<u8>, bingsu_core::collection::language::Version)>,
        root: Root,
    ) -> Self {
        Self { answers, root }
    }

    /// What the folder facts say of the repository.
    pub(crate) fn root(&self) -> Root {
        self.root
    }

    /// The answer for language `id`, if the collection gave one.
    pub(crate) fn get(&self, id: &[u8]) -> Option<&bingsu_core::collection::language::Version> {
        self.answers.iter().find(|(a, _)| a == id).map(|(_, v)| v)
    }
}

/// The first 16 bytes of sha256(session), hex: names the session's lock and
/// its script copies, never the raw session value.
fn session_tag(session: &[u8]) -> String {
    cgroup::session_digest(session)
}

/// `command-<first 16 bytes of sha256(session), hex>.lock`: a fixed-length
/// name, never the raw session value.
fn lock_name(session: &[u8]) -> String {
    format!("command-{}.lock", session_tag(session))
}

/// The neutral folder (spec: an empty private folder): made 0500 when
/// missing, so read and search work and nothing can be written in it, by
/// a unit either. One that is there must be empty, the user's and exactly
/// 0500; otherwise `neutral` units do not run this round. It is never
/// repaired or emptied.
fn neutral(runtime: &File, me: u32) -> Result<bool, StoreError> {
    let name = OsStr::new(NEUTRAL);
    let made = sys::mkdir_at(runtime.as_fd(), name, 0o500)?;
    let dir = sys::open_dir_at_nofollow(runtime.as_fd(), name)?;
    // Only a folder this call made is set (a umask can take bits from it).
    if made {
        use std::os::unix::fs::PermissionsExt;
        dir.set_permissions(std::fs::Permissions::from_mode(0o500))?;
    }
    let facts = sys::fd_facts(dir.as_fd())?;
    Ok(facts.uid == me
        && facts.mode & 0o7777 == 0o500
        && sys::directory_names(dir.as_fd())?.is_empty())
}

/// Under the session lock no supervisor of the session is alive: whatever
/// its cgroup parent holds is left over (C3 ruling R1, U-15 Q1). The
/// parent, for the round's supervisor, and the reclaim's log lines.
#[cfg(target_os = "linux")]
fn session_reclaim(
    i: &Inputs<'_>,
    session: &[u8],
) -> (Option<super::command_cgroup::fs::Dir>, Vec<&'static str>) {
    let mut cgroup = sys::fd_facts(i.runtime.as_fd()).ok().and_then(|root| {
        super::command_cgroup::fs::open_session(&super::command_cgroup::fs::Who {
            session,
            runtime: (root.dev, root.ino),
            me: i.me,
            pid: std::process::id(),
        })
    });
    let mut notes = Vec::new();
    if let Some(parent) = &mut cgroup {
        let r = super::command_cgroup::reclaim(&mut super::command_cgroup::fs::Fs, parent);
        notes.extend(r.messages());
    }
    (cgroup, notes)
}

/// Decides the round and, when it has units, takes the session lock and
/// spawns the supervisor. Only the runtime root is touched here, before the
/// marker; the units are resolved in `Round::grant`, after it.
pub(crate) fn prepare(i: &Inputs<'_>) -> Result<Round, Skip> {
    let runnable: Vec<_> = i
        .config
        .exec_units
        .iter()
        .filter_map(|u| plan::runnable(u).map(|r| (u.id.as_str(), r, u.cache_ms)))
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
    // The cache (U-16 K1): a unit whose entry is bound to this round, to its
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
    let runnable: Vec<_> = runnable
        .into_iter()
        .filter(|(id, r, cache_ms)| {
            let Some(vars) = &vars else { return true };
            let env = plan::env_digest(vars, &r.env_allow);
            environments.push((id.to_string(), env));
            let policy = policy_digest(&r.policy, r.cwd, r.timeout, &r.env_allow);
            let cache_ns = cache_ms.unwrap_or(0).saturating_mul(1_000_000);
            let hit = current
                .as_ref()
                .and_then(|c| c.entry(Origin::Config, id))
                .is_some_and(|e| e.hit(&policy, &env, i.now.now, cache_ns));
            !hit
        })
        .map(|(id, r, _)| (id, r))
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
    // unit (D3a ruling Q-C (a)): whether it runs is known only once the
    // collection answered, after the marker.
    // Fails without it: test_builtin_probe_runs_once_and_is_cached.
    if runnable.is_empty() && builtins.is_empty() {
        // A config with command units reclaims what an earlier supervisor of
        // the session left even when no unit runs this round (C4 ruling Q4);
        // one without any touches nothing. A busy lock is a live supervisor.
        #[cfg(target_os = "linux")]
        if let (false, Some(session)) = (i.config.exec_units.is_empty(), i.session)
            && let Ok(_lock) = close_only_lock(i.runtime, &lock_name(session), i.me, true)
        {
            let _ = session_reclaim(i, session);
        }
        return Err(Skip::NoUnits);
    }
    // Another unix has no trusted relay and runs nothing. No CI target is
    // such a unix, so no test runs this branch; `cfg!` keeps it compiled on
    // Linux and macOS too (C2 ruling Q2).
    if cfg!(not(any(target_os = "linux", target_os = "macos"))) {
        return Err(Skip::NoRelay);
    }
    // The behavior probe of C2 ruling Q3. Every macOS CI runner has the
    // flag, so no test removes this call and fails; `nofollow_any` itself
    // is tested (nofollow_any_probe_decides).
    #[cfg(target_os = "macos")]
    if !nofollow_any(probe_nofollow_any(c"/"), probe_nofollow_any(c"/var/empty")) {
        return Err(Skip::NoNofollowAny);
    }
    let (Some(session), Some(pwd)) = (i.session, i.pwd) else {
        return Err(Skip::NoSession);
    };
    let lock =
        close_only_lock(i.runtime, &lock_name(session), i.me, true).map_err(|e| match e {
            StoreError::Busy => Skip::Busy,
            _ => Skip::Failed,
        })?;
    // Right after the lock, before any other check can end the round: a
    // round that cannot run (no environment frame) still reclaims.
    #[cfg(target_os = "linux")]
    let (cgroup, notes) = session_reclaim(i, session);
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
    let (grant_read, grant_pipe) = pipe().map_err(|_| Skip::Failed)?;
    let (results, results_write) = pipe().map_err(|_| Skip::Failed)?;
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
        },
        builtins,
        probes_allowed,
        current,
        probes: Vec::new(),
        decided: Vec::new(),
        hidden: Vec::new(),
        _lock: lock,
    })
}

/// The behavior probe for `AT_SYMLINK_NOFOLLOW_ANY` on `path`: the result
/// of `fstatat` (0 or its errno).
#[cfg(target_os = "macos")]
fn probe_nofollow_any(path: &std::ffi::CStr) -> i32 {
    // SAFETY: an all-zero stat is a valid out-parameter value.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: fixed NUL-terminated path, writable `st`.
    let rc = unsafe {
        libc::fstatat(
            libc::AT_FDCWD,
            path.as_ptr(),
            &mut st,
            sys::AT_SYMLINK_NOFOLLOW_ANY,
        )
    };
    if rc == 0 {
        0
    } else {
        std::io::Error::last_os_error().raw_os_error().unwrap_or(-1)
    }
}

/// Whether the probes say the flag works both ways: "/" (no symlink) is
/// found, and `/var/empty` (through the `/var -> private/var` link) is
/// refused with ELOOP. EINVAL is a macOS without the flag; a flag that is
/// accepted but not enforced passes "/" and fails the link.
#[cfg(target_os = "macos")]
fn nofollow_any(root: i32, link: i32) -> bool {
    root == 0 && link == libc::ELOOP
}

/// The grant's units and what was left out.
#[derive(Debug, Default)]
struct Resolved {
    units: Vec<Unit>,
    /// Executable not found or failed the checks.
    unresolved: usize,
    /// The ids of units that cannot run however often they are picked (not
    /// resolved, or over the relay input cap): each is published as a
    /// failed attempt, so the round robin moves past it; otherwise it would
    /// hold its slot among the first `CONFIG_MAX` forever. A unit left out
    /// only because the grant frame is full is not one: never tried, it
    /// comes first next round.
    unresolved_ids: Vec<String>,
    /// Over the relay's input cap, or past the grant frame's room.
    oversize: usize,
    /// No collected repository root: the shell's folder stood for it.
    repo_fallback: bool,
    dropped: plan::Dropped,
}

/// The grant's units: at most `CONFIG_MAX` runnable units whose executable
/// resolves from the sanitized `PATH` (or `/bin/sh` for a script), each with
/// its target environment and the digest of its policy before `{dir}`. A
/// unit whose relay input would pass `RELAY_INPUT_MAX`, or that would push
/// the grant past one frame, is left out alone; the others still run.
/// The repository and the sanitized `PATH` folders of one round, which
/// the config units and the builtin languages share: walking every `PATH`
/// entry under the ancestor and group rules is the round's largest cost
/// (about 30 ms on macOS with a long `PATH`, D3a measurement), so it runs
/// once.
pub(crate) struct Search {
    /// Every repository the shell is in, by identity (`search`).
    pub(crate) repo: Vec<bingsu_core::command::path::Id>,
    pub(crate) folders: Vec<std::path::PathBuf>,
    /// No collected repository root: the shell's folder stood for it.
    fallback: bool,
}

/// The repositories the shell is in, by identity, for the PATH and
/// executable rules: the root this round's collection reported, else the
/// shell's own folder (C2 ruling J9), and every folder at or above the
/// shell's that holds `.git` (U-24), so a round without a collected root
/// still keeps a repository's folders out. The config units and the builtin
/// languages share this one list and its one walk. A folder that cannot be
/// read refuses the round, both its units and its languages.
pub(crate) fn search(
    environment: &[u8],
    cwd: &[u8],
    collected: Option<u16>,
    me: u32,
    groups: &mut SystemGroups,
) -> Result<Search, Skip> {
    let folder = plan::repo_folder(cwd, collected);
    let mut repo: Vec<_> = exec_path::repo_id(Some(Path::new(OsStr::from_bytes(&folder))))
        .map_err(|_| Skip::Failed)?
        .into_iter()
        .collect();
    let scanned =
        exec_path::repo_ancestors(Path::new(OsStr::from_bytes(cwd))).map_err(|_| Skip::Failed)?;
    for id in scanned {
        if !repo.contains(&id) {
            repo.push(id);
        }
    }
    let vars = Environ::parse(environment);
    let folders = exec_path::sanitize(vars.get(b"PATH").unwrap_or_default(), &repo, me, groups);
    Ok(Search {
        repo,
        folders,
        fallback: collected.is_none(),
    })
}

#[allow(clippy::too_many_arguments, reason = "one round's fixed inputs")]
fn units(
    runnable: &[(String, plan::Runnable)],
    tried: &[(String, u64)],
    environment: &[u8],
    base: &Grant,
    found: &Search,
    me: u32,
    groups: &mut SystemGroups,
    scripts: &mut Scripts,
) -> Resolved {
    let mut out = Resolved {
        repo_fallback: found.fallback,
        ..Resolved::default()
    };
    let vars = Environ::parse(environment);
    out.dropped = vars.dropped;
    let (repo, folders) = (found.repo.as_slice(), &found.folders);
    let path = exec_path::path_value(folders);
    // Round robin: never tried first, then the attempt longest ago.
    let attempts: Vec<(&str, Option<u64>)> = runnable
        .iter()
        .map(|(id, _)| {
            let at = tried.iter().find(|(t, _)| t == id).map(|(_, at)| *at);
            (id.as_str(), at)
        })
        .collect();
    let mut trial = base.clone();
    for at in plan::pick(&attempts, plan::CONFIG_MAX) {
        let (id, r) = &runnable[at];
        let word = match &r.policy {
            Policy::Argv { argv } => argv[0].as_slice(),
            Policy::UnsafeShell { .. } => SHELL,
        };
        let Ok((found, checked)) = exec_path::lookup_open(word, folders, repo, me, groups) else {
            out.unresolved += 1;
            out.unresolved_ids.push(id.clone());
            continue;
        };
        let Some((executable, pin)) = scripts.executable(&found, &checked) else {
            out.unresolved += 1;
            out.unresolved_ids.push(id.clone());
            continue;
        };
        let unit = Unit {
            id: id.clone(),
            digest: policy_digest(&r.policy, r.cwd, r.timeout, &r.env_allow),
            policy: r.policy.clone(),
            cwd: r.cwd,
            environment: plan::target_environment(&vars, &r.env_allow, &path),
            timeout: r.timeout,
            env_allow: r.env_allow.clone(),
            executable,
            pin,
            interpreter: found.interpreter,
        };
        let frame = ExecFrame {
            origin: Origin::Config,
            run_deadline: 0,
            environment: unit.environment.clone(),
            pin: unit.pin,
            interpreter: unit.interpreter.clone(),
            cwd: match unit.cwd {
                Cwd::Neutral => base.neutral.clone(),
                Cwd::UntrustedCurrent => base.cwd.clone(),
            },
        };
        if handoff::relay_input(base.permit, &frame, handoff::RELAY_INPUT_MAX).is_err() {
            scripts.forget_last(&unit.executable);
            out.oversize += 1;
            out.unresolved_ids.push(id.clone());
            continue;
        }
        trial.units.push(unit);
        if wire::encode(&Message::Grant(trial.clone())).is_err() {
            if let Some(unit) = trial.units.pop() {
                scripts.forget_last(&unit.executable);
            }
            out.oversize += 1;
        }
    }
    out.units = trial.units;
    out
}

/// Writes all of `bytes` to the non-blocking `fd` by `until_ns`, waiting in
/// `poll` when the pipe is full: the supervisor reads the grant while it
/// arrives, and a pipe can be smaller than the frame (pipe-user-pages-soft
/// leaves 4 KB pipes, m6-C1a).
fn send(fd: i32, bytes: &[u8], until_ns: u64) -> bool {
    send_with(
        bytes,
        until_ns,
        &mut || now_ns().ok(),
        &mut |b: &[u8]| {
            // SAFETY: `b` is readable for its length.
            let n = unsafe { libc::write(fd, b.as_ptr().cast(), b.len()) };
            usize::try_from(n)
                .map_err(|_| std::io::Error::last_os_error().raw_os_error().unwrap_or(0))
        },
        &mut |wait_ms| {
            let mut fds = [libc::pollfd {
                fd,
                events: libc::POLLOUT,
                revents: 0,
            }];
            // SAFETY: one valid pollfd.
            unsafe { libc::poll(fds.as_mut_ptr(), 1, wait_ms) };
        },
    )
}

/// `send` with its clock, write and wait passed in (tests replace them).
fn send_with(
    mut bytes: &[u8],
    until_ns: u64,
    now: &mut dyn FnMut() -> Option<u64>,
    write: &mut dyn FnMut(&[u8]) -> Result<usize, i32>,
    wait: &mut dyn FnMut(i32),
) -> bool {
    while !bytes.is_empty() {
        // Before the first write and every retry: a late grant is no grant.
        if now().is_none_or(|at| at >= until_ns) {
            return false;
        }
        match write(bytes) {
            Ok(n) => {
                bytes = &bytes[n..];
                continue;
            }
            Err(libc::EAGAIN | libc::EINTR) => {}
            Err(_) => return false,
        }
        // The clock again right before the wait: the write itself took time.
        let Some(at) = now().filter(|&at| at < until_ns) else {
            return false;
        };
        wait(i32::try_from((until_ns - at).div_ceil(1_000_000)).unwrap_or(i32::MAX));
    }
    true
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
    /// Why builtin languages were hidden this round (D3 ruling Q4: the
    /// reason goes to the log, never to the prompt).
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
    /// (Linux, C3 ruling R1).
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
    /// for the shell's folder, if it ran (C2 ruling J9).
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
        // Nothing to search for: no PATH walk, no folder read (D3a security
        // review S-M3).
        if !searches(!self.runnable.is_empty(), builtins) {
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
        report.notes = self.abandon();
        report
    }

    /// The builtin languages of this round (D3a): each decided without
    /// running (shown or hidden), or a probe added to the grant unless its
    /// cached result stands. A language the collection did not answer
    /// (it did not run or did not finish) is left as it was.
    /// Returns how many times the shell's folder was made canonical.
    fn plan_builtins(
        &mut self,
        languages: &Languages,
        found: &Search,
        me: u32,
        groups: &mut SystemGroups,
    ) -> u32 {
        if self.builtins.is_empty() {
            return 0;
        }
        let environment = self.environment.clone();
        let vars = Environ::parse(&environment);
        let shell_folder = self.grant.cwd.clone();
        let resolved = std::cell::Cell::new(0);
        let c = builtin_probe::Context {
            vars: builtin_probe::whole(&vars),
            folders: &found.folders,
            repo: &found.repo,
            cwd: &shell_folder,
            me,
            xcode_link: Path::new(builtin_probe::XCODE_SELECT_LINK),
            command_line_tools: Path::new(builtin_probe::COMMAND_LINE_TOOLS),
            resolved: &resolved,
        };
        let now = now_ns().unwrap_or(self.publish.clock.now);
        for language in self.builtins.clone() {
            let Some(version) = languages.get(language.id.as_bytes()) else {
                continue;
            };
            let p = builtin_probe::plan(language, version, &c, groups);
            let current = self
                .current
                .as_ref()
                .and_then(|r| r.entry(Origin::Builtin, language.id))
                .cloned();
            let current = current.as_ref();
            let (status, value) = match &p.action {
                Action::Show(value) => (response::Status::Ok, value.clone()),
                Action::Hide(why) => {
                    self.hidden.push(why);
                    (response::Status::Failed, String::new())
                }
                Action::Run(probe) => {
                    self.run_probe(&p, probe.clone(), current);
                    continue;
                }
            };
            // The same decision already published is not written again: a
            // fast or hidden value costs a store write only when it changes.
            // Fails without it: test_builtin_fast_value_is_written_once.
            let same = current.is_some_and(|e| {
                e.policy == p.policy
                    && e.environment == p.environment
                    && e.status == status
                    && e.value == value
            });
            if !same {
                self.decided.push(decided(&p, now, status, value));
            }
        }
        resolved.get()
    }

    /// Adds `probe` to the grant unless its cached result stands or it does
    /// not fit the grant frame.
    fn run_probe(&mut self, p: &Planned, probe: wire::Probe, current: Option<&response::Entry>) {
        if !self.probes_allowed {
            self.hidden.push(NEUTRAL_REFUSED);
            return;
        }
        {
            // Fails without it: test_builtin_probe_runs_once_and_is_cached.
            let hit = current.is_some_and(|e| {
                e.hit(
                    &p.policy,
                    &p.environment,
                    self.publish.clock.now,
                    builtin_probe::PROBE_CACHE_NS,
                )
            });
            if hit {
                return;
            }
            if !fits(&self.grant, &probe) {
                self.hidden
                    .push("a builtin probe does not fit the grant frame");
                return;
            }
            self.grant.probes.push(probe);
            self.probes.push(p.clone());
        }
    }

    /// Publishes the round's results and, as failed attempts at this time,
    /// the units that could not run (C4a review M2: not resolved, or over
    /// the relay input cap).
    fn publish_results(&self, report: &mut Report, unresolved: &[String]) {
        let mut entries = self.entries(&report.results);
        entries.extend(self.decided.iter().cloned());
        if let Ok(now) = now_ns() {
            entries.extend(
                unresolved
                    .iter()
                    .filter_map(|id| self.unresolved_entry(id, now)),
            );
        }
        if !entries.is_empty() {
            match self.publish_entries(&entries) {
                Ok(published) => report.published = Some(published),
                Err(_) => report.publish_failed = true,
            }
        }
    }

    /// A failed entry for unit `id`, attempted and ended at `now`: the
    /// failure cache keeps it 10 s, then it is the unit tried longest ago.
    fn unresolved_entry(&self, id: &str, now: u64) -> Option<response::Entry> {
        let (_, r) = self.runnable.iter().find(|(u, _)| u == id)?;
        let env = self.publish.environments.iter().find(|(u, _)| u == id)?.1;
        let failed = Outcome {
            origin: Origin::Config,
            index: 0,
            reason: wire::Reason::SpawnFailed,
            approved_at: now,
            ended_at: now,
            stdout: Vec::new(),
        };
        let policy = policy_digest(&r.policy, r.cwd, r.timeout, &r.env_allow);
        response::entry_for(id.to_owned(), policy, env, now, &failed)
    }

    /// The response entries of this round's config results (builtin probes
    /// are D3's): each bound to the unit's policy digest and the original
    /// environment digest it ran with.
    fn entries(&self, results: &[Outcome]) -> Vec<response::Entry> {
        let probes = results
            .iter()
            .filter(|o| o.origin == Origin::Builtin)
            .filter_map(|o| self.probe_entry(o));
        results
            .iter()
            .filter(|o| o.origin == Origin::Config)
            .filter_map(|o| {
                let unit = self.grant.units.get(usize::from(o.index))?;
                let env = self
                    .publish
                    .environments
                    .iter()
                    .find(|(id, _)| *id == unit.id)?
                    .1;
                response::entry_for(unit.id.clone(), unit.digest, env, self.publish.clock.now, o)
            })
            .chain(probes)
            .collect()
    }

    /// A probe's entry: its version cut from the first line it printed
    /// (`Python 3.12.1` shows `3.12.1`); a line with no version is a failed
    /// probe with no value.
    fn probe_entry(&self, o: &Outcome) -> Option<response::Entry> {
        let p = self.probes.get(usize::from(o.index))?;
        let mut e = response::entry_for(
            p.language.id.to_owned(),
            p.policy,
            p.environment,
            self.publish.clock.now,
            o,
        )?;
        if e.status == response::Status::Ok {
            // Fails without it: test_builtin_probe_publishes_only_a_version.
            match bingsu_core::command::profile::version(p.language.profile, &e.raw) {
                Some(v) => e.value = v.to_owned(),
                None => {
                    e.status = response::Status::Failed;
                    e.value.clear();
                    e.raw.clear();
                }
            }
        }
        Some(e)
    }

    /// Publishes `entries` into the command response of this context and
    /// cwd: the store of the collection response, under its lock (C4 ruling
    /// P1). A store another round holds is no publication: the next round
    /// runs those units again.
    fn publish_entries(
        &self,
        entries: &[response::Entry],
    ) -> Result<response::Response, StoreError> {
        let p = &self.publish;
        let now = bingsu_core::snapshot::Clock {
            now: now_ns().map_err(StoreError::Io)?,
            ..p.clock
        };
        match super::collection_store::CollectionStore::admit_commands(&p.context, &p.binding, now)?
        {
            super::collection_store::Admission::Admitted(mut store) => {
                store.publish_commands(&p.binding, entries)
            }
            super::collection_store::Admission::Deferred(_) => Err(StoreError::Busy),
        }
    }
}

/// Whether `grant` with `probe` added still encodes as one frame; the
/// units were fitted first, so a probe that does not fit is left out alone.
fn fits(grant: &Grant, probe: &wire::Probe) -> bool {
    let mut trial = grant.clone();
    trial.probes.push(probe.clone());
    // Fails without it: a_probe_past_the_frame_is_left_out.
    wire::encode(&Message::Grant(trial)).is_ok()
}

/// Whether a round walks `PATH` at all: only for config units to run or
/// builtin languages the collection answered (D3a security review S-M3).
fn searches(config_units: bool, builtins: bool) -> bool {
    // Fails without it: a_round_with_nothing_to_decide_searches_nothing.
    config_units || builtins
}

/// A builtin entry decided without running anything, at `now`.
fn decided(p: &Planned, now: u64, status: response::Status, value: String) -> response::Entry {
    response::Entry {
        origin: Origin::Builtin,
        id: p.language.id.to_owned(),
        policy: p.policy,
        environment: p.environment,
        pattern: [0; 32],
        attempted_at: now,
        completed_at: now,
        status,
        raw: value.clone(),
        value,
    }
}

/// Waits for the supervisor to exit (it ends its children first) until the
/// helper's deadline; the drop then kills and reaps whatever is left.
/// Whether it exited.
fn wait(child: &mut OwnedChild, deadline: u64) -> bool {
    loop {
        match child.reap() {
            Ok(true) => return true,
            Ok(false) if now_ns().is_ok_and(|now| now < deadline) => {
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
            _ => return false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
            },
        )
    }
    // 폴더 사실이 저장소를 확정했을 때만 내장 언어를 정한다. in_repo를 모르거나(탐색 깊이 제한) 저장소 안인데 뿌리
    // 위치를 모르면(별칭 경로) 미확정이다(D3a 재리뷰 H1). 이것을 실패시키는 것: 미확정을 저장소 밖으로 보는 것,
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

    // 수집 답과 같은 저장소의 폴더 사실이 있을 때만 내장 언어를 정하고(D3a 리뷰 H1), 할 일이 없는 회차는 PATH를
    // 걷지 않는다(보안 리뷰 S-M3). 이것을 실패시키는 것: 폴더 사실 없이 내장 언어를 정하는 것(셸 폴더가 저장소를
    // 대신함), 다른 저장소의 사실을 받는 것, 답 없는 회차를 정하는 것, 할 일이 없어도 탐색하는 것.
    #[test]
    fn a_round_with_nothing_to_decide_searches_nothing() {
        use bingsu_core::collection::language::Version;
        let answered = |root| Languages {
            answers: vec![(b"node".to_vec(), Version::None)],
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

    // C2 판정 Q3: "/"는 0, 링크를 지나는 "/var/empty"는 ELOOP일 때만 relay를 쓴다(EINVAL은 그 플래그가 없는
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

    // C2 판정 Q1: macOS 스크립트는 세션 이름이 붙은 사본으로, 핀 없이 넘긴다. 네이티브 파일은 그대로다. 빠진 단위의
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

    // M4·M-2: 상한을 넘는 단위만 빠지고 나머지는 돈다. 이것을 실패시키는 것: units()의 relay 입력 상한 검사를
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

    // U-24: 수집 루트가 없는 회차에도 셸 폴더 위의 `.git` 조상이 저장소다. 셸이 저장소 하위 폴더에 있으면 저장소
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

    // 파일 이름에는 세션 값이 아니라 고정 길이 요약값만. 이것을 실패시키는 것: lock_name이 세션 값을
    // 그대로 쓰는 것.
    #[test]
    fn lock_name_is_a_digest() {
        let name = lock_name(b"0123456789abcdef0123456789abcdef");
        assert_eq!(name.len(), "command-".len() + 32 + ".lock".len());
        assert!(!name.contains("0123456789abcdef"));
        assert_ne!(name, lock_name(b"fedcba9876543210fedcba9876543210"));
    }
}
