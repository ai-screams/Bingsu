//! Finding the executables of a round and building its grant units from them.
use super::*;

/// The grant's units and what was left out.
#[derive(Debug, Default)]
pub(super) struct Resolved {
    pub(super) units: Vec<Unit>,
    /// Executable not found or failed the checks.
    pub(super) unresolved: usize,
    /// The ids of units that cannot run however often they are picked (not
    /// resolved, or over the relay input cap): each is published as a
    /// failed attempt, so the round robin moves past it; otherwise it would
    /// hold its slot among the first `CONFIG_MAX` forever. A unit left out
    /// only because the grant frame is full is not one: never tried, it
    /// comes first next round.
    pub(super) unresolved_ids: Vec<String>,
    /// Over the relay's input cap, or past the grant frame's room.
    pub(super) oversize: usize,
    /// No collected repository root: the shell's folder stood for it.
    pub(super) repo_fallback: bool,
    pub(super) dropped: plan::Dropped,
}

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
/// shell's own folder, and every folder at or above the
/// shell's that holds `.git`, so a round without a collected root
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

/// The grant's units: at most `CONFIG_MAX` runnable units whose executable
/// resolves from the sanitized `PATH` (or `/bin/sh` for a script), each with
/// its target environment and the digest of its policy before `{dir}`. A
/// unit whose relay input would pass `RELAY_INPUT_MAX`, or that would push
/// the grant past one frame, is left out alone; the others still run.
#[allow(clippy::too_many_arguments, reason = "one round's fixed inputs")]
pub(super) fn units(
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

/// Whether `grant` with `probe` added still encodes as one frame; the
/// units were fitted first, so a probe that does not fit is left out alone.
pub(super) fn fits(grant: &Grant, probe: &wire::Probe) -> bool {
    let mut trial = grant.clone();
    trial.probes.push(probe.clone());
    // Fails without it: a_probe_past_the_frame_is_left_out.
    wire::encode(&Message::Grant(trial)).is_ok()
}

/// Whether a round walks `PATH` at all: only for config units to run or
/// builtin languages the collection answered (D3a security review S-M3).
pub(super) fn searches(config_units: bool, builtins: bool) -> bool {
    // Fails without it: a_round_with_nothing_to_decide_searches_nothing.
    config_units || builtins
}
