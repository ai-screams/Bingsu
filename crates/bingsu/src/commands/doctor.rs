//! `bingsu doctor`: a table of checks of the installation and the shell
//! setup, each with a status, one line and (when there is something to do)
//! a diagnostic code that `bingsu help <code>` explains. It only reads: it
//! runs no other executable (no version query, no shell, no helper), writes
//! no file and starts no process, and it never guesses a version from a path
//! or a folder name; a fact only a shell can give is `unknown` until the
//! shell says it. The one thing it does besides reading is to ask the
//! terminal (`terminal-width`, `terminal-background`): a few characters are
//! written to the screen and the answers read back, only when standard
//! output is a terminal or `--terminal` is given.
//!
//! The checks are rows of `ITEMS`: a later change adds a row. Each row reads
//! its facts and hands them to a pure `judge_*` function, which the tests
//! feed with good and bad facts.
use super::{
    collection_breaker::{self, Peek},
    collector::Sibling,
    config_inspect::{Inspection, exit_for, inspect_config, refusal_text},
    ctx::{self, EXIT_FAILED, EXIT_UNFINISHED, EXIT_USAGE, User},
    doctor_evidence::{self, Given},
    group_policy::SystemGroups,
    init::{
        exe_path::{self, invocation_path},
        pinned,
        trusted_env::TrustedEnv,
    },
    runtime_root::{self, RootError},
    sys::{self, SeccompKernel},
    terminal::{self, BackgroundOutcome, Why, WidthOutcome},
    tty::{Terminal, Tty},
};
use bingsu_core::{
    color::palette::Mode,
    diag::{DiagCode, Severity},
    diag_codes as codes,
    envelope::{colorfgbg_mode, display_mode},
    fs_trust::{Last, Verdict, walk_verdict},
    sanitize::sanitize,
    terminal_width::{self as width, Cells, Mismatch, PROBES},
    width::WidthProfile,
};
use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

const USAGE: &str = "usage: bingsu doctor [--format json|text] [--terminal] [--evidence-stdin]";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Status {
    Ok,
    Warn,
    Fail,
    /// The fact is not available here (it needs a shell, or could not be read).
    Unknown,
    /// The check does not apply here.
    Skipped,
}

impl Status {
    pub(super) const fn word(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Warn => "warn",
            Self::Fail => "fail",
            Self::Unknown => "unknown",
            Self::Skipped => "skipped",
        }
    }
}

/// What one check found: the status, one line (not yet sanitized) and the
/// code that explains the way out, if there is one.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct Finding {
    pub status: Status,
    pub text: String,
    pub fix: Option<DiagCode>,
    /// What a measurement saw, for the JSON only (the two terminal rows).
    pub details: Option<Details>,
}

/// The numbers behind a terminal row. Only measured values and fixed words:
/// nothing the terminal answered is kept as text.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Details {
    Width {
        cells: Cells,
        recommended: width::Recommended,
        inside_tmux: bool,
    },
    Background {
        terminal: Mode,
        prompt: Mode,
    },
}

fn finding(status: Status, text: impl Into<String>, fix: Option<DiagCode>) -> Finding {
    Finding {
        status,
        text: text.into(),
        fix,
        details: None,
    }
}

/// What the checks may read. Nothing here is a process or a write.
pub(super) struct Ctx {
    pub evidence: Given,
    pub user: User,
    pub env: TrustedEnv,
    pub exe: Option<PathBuf>,
    pub terminal: TerminalCtx,
}

/// The facts for the two terminal rows. Asking the terminal is the one thing
/// `doctor` does besides reading (it writes a few characters to the screen
/// and reads the answers back, and writes no file).
pub(super) struct TerminalCtx {
    /// Measure through the terminal: standard output is one, or `--terminal`.
    pub measure: bool,
    /// Opens the controlling terminal; `None`: there is none, or this
    /// process is not its foreground job.
    pub open: fn() -> Option<Box<dyn Controlling>>,
    /// `COLORFGBG`, as the prompt's envelope reads it.
    pub colorfgbg: Option<OsString>,
    pub tmux: bool,
    /// The settings the terminal is compared with; read once, by the first
    /// terminal row that needs it.
    pub settings: std::cell::OnceCell<Option<TerminalSettings>>,
    /// A Ctrl-C ended a measurement: the run stops with 130.
    pub cancelled: std::cell::Cell<bool>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct TerminalSettings {
    pub profile: WidthProfile,
    /// `colors.mode = "auto"`: the prompt picks light or dark by itself.
    pub auto: bool,
}

pub(super) struct Item {
    pub id: &'static str,
    pub title: &'static str,
    pub run: fn(&Ctx) -> Finding,
}

/// Every check, in the order they are shown. Add a row to add a check.
pub(super) const ITEMS: &[Item] = &[
    Item {
        id: "executable",
        title: "executable",
        run: run_executable,
    },
    Item {
        id: "path-bingsu",
        title: "bingsu on PATH",
        run: run_path_bingsu,
    },
    Item {
        id: "roots-pin",
        title: "pinned folders",
        run: run_roots_pin,
    },
    Item {
        id: "build-identity",
        title: "one build",
        run: run_build_identity,
    },
    Item {
        id: "shell",
        title: "shell",
        run: |c| doctor_evidence::judge_shell(&c.evidence),
    },
    Item {
        id: "hook-compat",
        title: "hook version",
        run: |c| doctor_evidence::judge_compat(&c.evidence),
    },
    Item {
        id: "hook-order",
        title: "hook order",
        run: |c| doctor_evidence::judge_order(&c.evidence),
    },
    Item {
        id: "envelope",
        title: "envelope",
        run: |c| doctor_evidence::judge_envelope(&c.evidence),
    },
    Item {
        id: "breaker",
        title: "breaker",
        run: run_breaker,
    },
    Item {
        id: "seccomp",
        title: "seccomp",
        run: run_seccomp,
    },
    Item {
        id: "settings",
        title: "settings",
        run: run_settings,
    },
    Item {
        id: "terminal-width",
        title: "terminal width",
        run: run_terminal_width,
    },
    Item {
        id: "terminal-background",
        title: "background",
        run: run_terminal_background,
    },
];

// ---- executable ----------------------------------------------------------

/// The worst verdict over every path the executable can be reached by, and
/// the path that earned it: the running file (links resolved) and the path
/// the user ran or `PATH` finds (its link and the folders above the link),
/// since a link in a folder others can write is the way in, whatever the
/// target is.
fn judge_executable(paths: &[(PathBuf, Verdict)]) -> Finding {
    let Some((path, verdict)) = paths.iter().max_by_key(|(_, v)| *v) else {
        return finding(
            Status::Unknown,
            "the path of the running executable could not be read",
            None,
        );
    };
    let shown = ctx::show(path);
    match verdict {
        Verdict::Safe => finding(
            Status::Ok,
            format!("{shown}: only you and root can change it or the folders above it"),
            None,
        ),
        Verdict::Unknown => finding(
            Status::Unknown,
            format!("{shown}: who can change it could not be confirmed"),
            None,
        ),
        Verdict::Tamperable => finding(
            Status::Warn,
            format!(
                "{shown}: it, a link to it or a folder above it can be changed by another user"
            ),
            Some(codes::EXE_FOLDER_CHANGEABLE),
        ),
    }
}

/// Every path to check: the running file, the path this process was started
/// by, and the `bingsu` that `PATH` finds when it is this file.
fn executable_paths(c: &Ctx) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = Vec::new();
    let mut add = |p: PathBuf| {
        if !out.contains(&p) {
            out.push(p);
        }
    };
    let Ok(cwd) = std::env::current_dir() else {
        return c.exe.iter().cloned().collect();
    };
    if let Some(exe) = &c.exe {
        add(exe.clone());
        if let Some(argv0) = std::env::args_os().next()
            && let Some(p) = invocation_path(&argv0, c.env.path.as_deref(), &cwd)
        {
            add(p);
        }
        if let Some(p) = invocation_path(OsStr::new("bingsu"), c.env.path.as_deref(), &cwd)
            && same_file(&p, exe)
        {
            add(p);
        }
    }
    out
}

fn run_executable(c: &Ctx) -> Finding {
    let paths: Vec<(PathBuf, Verdict)> = executable_paths(c)
        .into_iter()
        .map(|p| {
            let v = exe_path::check_path(&p, c.user.me, &c.user.pw.name);
            (p, v)
        })
        .collect();
    judge_executable(&paths)
}

// ---- bingsu on PATH --------------------------------------------------------

/// Where `bingsu` is found on `PATH` and whether that is the running file.
#[derive(Debug)]
pub(super) enum OnPath {
    /// Not found, or a relative `PATH` entry came first (the shell's own
    /// folder decides there, which a command cannot see).
    NotFound,
    Same(PathBuf),
    Other(PathBuf),
}

fn judge_path_bingsu(found: &OnPath) -> Finding {
    match found {
        OnPath::NotFound => finding(
            Status::Skipped,
            "no bingsu is found on PATH here; the hook uses the path pinned by init",
            None,
        ),
        OnPath::Same(p) => finding(
            Status::Ok,
            format!("{}: the bingsu on PATH is this executable", ctx::show(p)),
            None,
        ),
        OnPath::Other(p) => finding(
            Status::Warn,
            format!(
                "{}: the bingsu on PATH is not this executable; the prompt uses the path pinned by init",
                ctx::show(p)
            ),
            Some(codes::PATH_BINGSU_DIFFERS),
        ),
    }
}

fn same_file(a: &Path, b: &Path) -> bool {
    match (std::fs::metadata(a), std::fs::metadata(b)) {
        (Ok(x), Ok(y)) => (x.dev(), x.ino()) == (y.dev(), y.ino()),
        _ => false,
    }
}

fn run_path_bingsu(c: &Ctx) -> Finding {
    let (Some(exe), Ok(cwd)) = (&c.exe, std::env::current_dir()) else {
        return judge_path_bingsu(&OnPath::NotFound);
    };
    let found = match invocation_path(OsStr::new("bingsu"), c.env.path.as_deref(), &cwd) {
        None => OnPath::NotFound,
        Some(p) if same_file(&p, exe) => OnPath::Same(p),
        Some(p) => OnPath::Other(p),
    };
    judge_path_bingsu(&found)
}

// ---- pinned folders ----------------------------------------------------------

/// What `BINGSU_ROOTS` says now.
#[derive(Debug)]
pub(super) enum Pin {
    /// `init` has not run in this shell.
    Absent,
    /// Every pinned folder is the same and still passes its checks.
    Matches(PathBuf),
    /// The value cannot be read as init's.
    Garbled,
    /// The runtime folder is gone.
    RuntimeGone(PathBuf),
    /// The runtime folder is another folder now.
    RuntimeChanged {
        path: PathBuf,
        pinned: (u64, u64),
        now: (u64, u64),
    },
    /// The runtime folder is the same; another pinned folder or a check failed.
    OtherChanged,
    /// The state or log folder fails the same checks the helper makes of it.
    FolderRefused {
        which: &'static str,
        path: PathBuf,
        why: String,
    },
}

fn judge_roots_pin(pin: &Pin) -> Finding {
    match pin {
        Pin::Absent => finding(
            Status::Warn,
            "init has not run in this shell; commands read the current environment",
            Some(codes::NO_PINNED_ROOTS),
        ),
        Pin::Matches(p) => finding(
            Status::Ok,
            format!("runtime folder {} is the one init pinned", ctx::show(p)),
            None,
        ),
        Pin::Garbled => finding(
            Status::Fail,
            "BINGSU_ROOTS is not a value init wrote",
            Some(codes::ROOTS_NO_LONGER_MATCH),
        ),
        Pin::RuntimeGone(p) => finding(
            Status::Fail,
            format!("the pinned runtime folder {} is gone", ctx::show(p)),
            Some(codes::ROOTS_NO_LONGER_MATCH),
        ),
        Pin::RuntimeChanged { path, pinned, now } => finding(
            Status::Fail,
            format!(
                "the runtime folder {} was pinned as device {} inode {} and is device {} inode {} now",
                ctx::show(path),
                pinned.0,
                pinned.1,
                now.0,
                now.1
            ),
            Some(codes::ROOTS_NO_LONGER_MATCH),
        ),
        Pin::OtherChanged => finding(
            Status::Fail,
            "a pinned folder no longer passes its checks",
            Some(codes::ROOTS_NO_LONGER_MATCH),
        ),
        Pin::FolderRefused { which, path, why } => finding(
            Status::Fail,
            format!(
                "the {which} folder {} fails its checks: {why}",
                ctx::show(path)
            ),
            Some(codes::ROOTS_NO_LONGER_MATCH),
        ),
    }
}

fn read_pin(c: &Ctx) -> Pin {
    let Some(value) = TrustedEnv::pinned_roots() else {
        return Pin::Absent;
    };
    let bytes = value.as_bytes();
    if let Some(roots) = pinned::decode(bytes, c.user.me, &c.user.pw.name, &c.user.pw.home) {
        // `decode` re-checked the runtime and settings folders; the state and
        // log folders it only copies, so they get the helper's own checks here.
        let mut groups = SystemGroups::new(&c.user.pw.name);
        if let Some(state) = &roots.state
            && let Folder::Refused(why) = check_folder(state, Last::Mine, c.user.me, &mut groups)
        {
            return Pin::FolderRefused {
                which: "state",
                path: state.clone(),
                why,
            };
        }
        if let Some(log) = &roots.log
            && let Folder::Refused(why) =
                check_folder(log, Last::PrivateFolder, c.user.me, &mut groups)
        {
            return Pin::FolderRefused {
                which: "log",
                path: log.clone(),
                why,
            };
        }
        let path = roots.runtime.map(|r| r.path).unwrap_or_default();
        return Pin::Matches(path);
    }
    let Some(pin) = pinned::runtime_pin(bytes, &c.user.pw.home) else {
        return Pin::Garbled;
    };
    match std::fs::symlink_metadata(&pin.path) {
        Err(_) => Pin::RuntimeGone(pin.path),
        Ok(m) if (m.dev(), m.ino()) != (pin.dev, pin.ino) => Pin::RuntimeChanged {
            now: (m.dev(), m.ino()),
            pinned: (pin.dev, pin.ino),
            path: pin.path,
        },
        Ok(_) => Pin::OtherChanged,
    }
}

/// A folder the helper uses, looked at without making or changing anything.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Folder {
    Fine,
    /// It does not exist (yet): the helper makes it when it first needs it.
    NotMade,
    Refused(String),
}

fn check_folder(
    path: &Path,
    last: Last,
    me: u32,
    groups: &mut dyn bingsu_core::fs_trust::GroupOracle,
) -> Folder {
    use std::os::fd::AsRawFd as _;
    let chain = match runtime_root::open_chain(path) {
        Ok(chain) => chain,
        Err(RootError::Open { errno, .. }) if errno == libc::ENOENT => return Folder::NotMade,
        Err(RootError::Open { errno, .. }) => {
            return Folder::Refused(format!(
                "it cannot be opened without following a link (error {errno})"
            ));
        }
        Err(e) => return Folder::Refused(format!("{e:?}")),
    };
    let local = sys::fd_is_local(chain.last().as_raw_fd());
    match walk_verdict(&chain.facts, me, last, local, groups) {
        Ok(()) => Folder::Fine,
        Err(r) => Folder::Refused(refusal_text(r).to_owned()),
    }
}

fn run_roots_pin(c: &Ctx) -> Finding {
    judge_roots_pin(&read_pin(c))
}

// ---- one build ---------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Sib {
    /// Beside `bingsu`, from this build, in a folder that passes the checks.
    Verified,
    Missing,
    /// There, but not verified (another build, another role, a folder that
    /// others can change).
    Unverified,
}

fn judge_build_identity(collector: Sib, prompt: Sib) -> Finding {
    match (collector, prompt) {
        (Sib::Verified, Sib::Verified) => finding(
            Status::Ok,
            "bingsu, bingsu-prompt and bingsu-collect are from one build",
            None,
        ),
        (Sib::Verified, Sib::Missing) => finding(
            Status::Ok,
            "bingsu-prompt is not installed here; the hook calls `bingsu prompt`; bingsu-collect is from this build",
            None,
        ),
        (Sib::Missing | Sib::Unverified, _) => finding(
            Status::Warn,
            "bingsu-collect beside bingsu is missing or not from this build; no git or folder facts are collected",
            Some(codes::SIBLING_UNVERIFIED),
        ),
        (Sib::Verified, Sib::Unverified) => finding(
            Status::Warn,
            "bingsu-prompt beside bingsu is not from this build or fails the safety check",
            Some(codes::SIBLING_UNVERIFIED),
        ),
    }
}

fn sibling_state(c: &Ctx, exe: &Path, kind: Sibling) -> Sib {
    let mut groups = SystemGroups::new(&c.user.pw.name);
    if exe_path::sibling(kind, exe, c.user.me, &mut groups).is_some() {
        return Sib::Verified;
    }
    let beside = std::fs::canonicalize(exe)
        .ok()
        .and_then(|p| p.parent().map(|d| d.join(kind.name())));
    match beside.map(|p| std::fs::symlink_metadata(p).is_ok()) {
        Some(true) => Sib::Unverified,
        _ => Sib::Missing,
    }
}

fn run_build_identity(c: &Ctx) -> Finding {
    let Some(exe) = &c.exe else {
        return finding(
            Status::Unknown,
            "the path of the running executable could not be read",
            None,
        );
    };
    judge_build_identity(
        sibling_state(c, exe, Sibling::COLLECTOR),
        sibling_state(c, exe, Sibling::PROMPT),
    )
}

// ---- the collection breaker -------------------------------------------------------

/// What reading this session's breaker gave: `Err` when it could not be read
/// safely.
fn judge_breaker(read: Result<Peek, ()>) -> Finding {
    match read {
        Ok(Peek::Blocked) => finding(
            Status::Warn,
            "collection is switched off for this folder in this shell session for a while (the same mount missed its deadline three times in a row); the prompt still draws",
            Some(codes::COLLECTION_BREAKER_ON),
        ),
        Ok(Peek::NoRecord) => finding(
            Status::Ok,
            "this session has no breaker record for this folder: collection is not switched off",
            None,
        ),
        Ok(Peek::Allowed) => finding(Status::Ok, "collection is on for this folder", None),
        Ok(Peek::Probe) => finding(
            Status::Ok,
            "the wait is over: the next prompt tries collection in this folder again",
            None,
        ),
        Ok(Peek::Disabled) => finding(
            Status::Unknown,
            "the breaker record is from another boot or clock, so it says nothing about now",
            None,
        ),
        Err(()) => finding(
            Status::Unknown,
            "the breaker record could not be read safely; the pinned folders check says whether the runtime folder is safe",
            None,
        ),
    }
}

/// A breaker row that cannot be confirmed, with the reason.
fn breaker_unknown(why: &str) -> Finding {
    finding(
        Status::Unknown,
        format!("the collection breaker is not confirmed: {why}"),
        None,
    )
}

/// The folder key the prompt used: the shell's `PWD`, as the prompt's own
/// envelope rule takes it (an absolute path of a bounded length). The string is
/// the key as it is: the helper keys the breaker by the `$PWD` the shell passed,
/// and the folder is never looked at here, since a stopped mount is exactly
/// when the breaker is on and a look at it would stop this command too.
fn shell_pwd(pwd: Option<&OsStr>) -> Result<Vec<u8>, &'static str> {
    let Some(pwd) = pwd else {
        return Err(
            "the shell does not export PWD to its commands, so the folder the prompt used is not known",
        );
    };
    // `--width` is a required word of the envelope; its value does not matter here.
    let argv: [&[u8]; 8] = [
        b"--ctx",
        b"1",
        b"--record",
        b"B1",
        b"--width",
        b"80",
        b"--pwd",
        pwd.as_bytes(),
    ];
    match bingsu_core::envelope::parse(&argv) {
        Ok(e) => e.pwd.ok_or(
            "PWD is not an absolute path the prompt accepts, so the folder it used is not known",
        ),
        Err(_) => Err("PWD could not be read as the prompt reads it"),
    }
}

fn run_breaker(c: &Ctx) -> Finding {
    let session = match doctor_evidence::session_of(&c.evidence) {
        Ok(s) => s,
        Err(f) => return f,
    };
    // The runtime folder is the one init pinned in this shell and nothing else:
    // a pin that no longer holds (the folder was made again) must not let the
    // folder in its place stand in for it, since an empty folder has no record.
    let Some(value) = TrustedEnv::pinned_roots() else {
        return breaker_unknown(
            "init has not pinned the folders in this shell (see the pinned folders check)",
        );
    };
    let Some(runtime) = pinned::open_runtime(
        value.as_bytes(),
        c.user.me,
        &c.user.pw.name,
        &c.user.pw.home,
    ) else {
        return breaker_unknown(
            "the folders init pinned do not hold now (see the pinned folders check)",
        );
    };
    let (_, pwd) = TrustedEnv::shell();
    let cwd = match shell_pwd(pwd.as_deref()) {
        Ok(cwd) => cwd,
        Err(why) => return breaker_unknown(why),
    };
    let Ok(now) = crate::prompt_io::observe_clock() else {
        return judge_breaker(Err(()));
    };
    judge_breaker(collection_breaker::peek(&runtime, &session, &cwd, now).map_err(|_| ()))
}

// ---- seccomp -------------------------------------------------------------------

fn judge_seccomp(k: SeccompKernel) -> Finding {
    match k {
        SeccompKernel::Supported => finding(Status::Ok, "the kernel supports seccomp", None),
        SeccompKernel::Absent => finding(
            Status::Warn,
            "the kernel has no seccomp; the prompt runs without its system call filter",
            Some(codes::NO_KERNEL_SECCOMP),
        ),
        SeccompKernel::NotApplicable => {
            finding(Status::Skipped, "this platform has no seccomp", None)
        }
        SeccompKernel::Failed(errno) => finding(
            Status::Unknown,
            format!("the kernel's answer could not be read (error {errno})"),
            None,
        ),
    }
}

fn run_seccomp(_: &Ctx) -> Finding {
    judge_seccomp(sys::seccomp_kernel())
}

// ---- settings --------------------------------------------------------------------

fn judge_settings(code: u8, errors: usize, warnings: usize) -> Finding {
    match code {
        0 => finding(
            Status::Ok,
            format!("the settings check out ({warnings} warning(s))"),
            None,
        ),
        EXIT_FAILED => finding(
            Status::Fail,
            format!("the settings have {errors} error(s); the prompt keeps the last good ones"),
            Some(codes::SETTINGS_INVALID),
        ),
        _ => finding(
            Status::Unknown,
            "the settings could not be read to the end",
            None,
        ),
    }
}

/// The settings could not be opened at all: a confirmed refusal (a folder
/// that fails its checks, a missing one) is a failure, as `config check`
/// exits 1 for it; anything else is not known.
fn judge_settings_unread(code: u8, text: &str) -> Finding {
    if code == EXIT_FAILED {
        finding(Status::Fail, text, Some(codes::SETTINGS_INVALID))
    } else {
        finding(Status::Unknown, text, None)
    }
}

fn judge_inspection(i: &Inspection) -> Finding {
    let count = |s: Severity| {
        i.report
            .diagnostics
            .iter()
            .filter(|d| d.severity() == s)
            .count()
    };
    judge_settings(
        exit_for(i),
        count(Severity::Error),
        count(Severity::Warning),
    )
}

fn run_settings(c: &Ctx) -> Finding {
    match inspect_config(&c.user, &c.env) {
        Ok(i) => judge_inspection(&i),
        Err((text, code)) => judge_settings_unread(code, &text),
    }
}

// ---- terminal -------------------------------------------------------------------

/// Exit code of a run ended by Ctrl-C (128 + SIGINT).
const EXIT_CANCELLED: u8 = 130;

fn terminal_settings(c: &Ctx) -> Option<TerminalSettings> {
    *c.terminal.settings.get_or_init(|| {
        let i = inspect_config(&c.user, &c.env).ok()?;
        let snap = i.report.snapshot?;
        // An explicit `colors.mode` makes both palettes the same one.
        Some(TerminalSettings {
            profile: snap.profile,
            auto: snap.palette != snap.light_palette,
        })
    })
}

/// The row for a run that asks no terminal: a Ctrl-C ended an earlier
/// question, or standard output is not a terminal and `--terminal` is not
/// given.
fn no_question(c: &Ctx) -> Option<Finding> {
    let skipped = |text: &str| finding(Status::Skipped, text, None);
    if c.terminal.cancelled.get() {
        return Some(skipped("stopped"));
    }
    (!c.terminal.measure).then(|| {
        skipped(
            "standard output is not a terminal; `--terminal` asks the controlling terminal anyway",
        )
    })
}

/// Runs `measure` on the controlling terminal in raw mode, or gives the row
/// that says why there is none. The terminal is back in its mode when this
/// returns; each row asks on a guard of its own.
fn with_terminal<T>(c: &Ctx, measure: impl FnOnce(&mut dyn Terminal) -> T) -> Result<T, Finding> {
    if let Some(f) = no_question(c) {
        return Err(f);
    }
    let skipped = |text: &str| finding(Status::Skipped, text, None);
    let Some(tty) = (c.terminal.open)() else {
        return Err(skipped(
            "there is no terminal to ask (none is attached, or this is not its foreground job)",
        ));
    };
    let Ok(mut guard) = tty.raw_terminal() else {
        return Err(finding(
            Status::Unknown,
            "the terminal could not be put in the mode the questions need",
            None,
        ));
    };
    Ok(measure(&mut *guard))
}

/// A controlling terminal that can be put in raw mode for the questions.
/// `Tty` is the real one; the tests put another in its place.
pub(super) trait Controlling {
    fn raw_terminal(&self) -> std::io::Result<Box<dyn Terminal + '_>>;
}

impl Controlling for Tty {
    fn raw_terminal(&self) -> std::io::Result<Box<dyn Terminal + '_>> {
        Ok(Box::new(self.raw()?))
    }
}

/// The controlling terminal, when this process may ask it.
fn open_controlling_terminal() -> Option<Box<dyn Controlling>> {
    Tty::open().map(|t| Box::new(t) as Box<dyn Controlling>)
}

fn why_text(why: Why) -> &'static str {
    match why {
        Why::Silent => "the terminal did not answer in time",
        Why::Garbled => "the terminal answered with something that is not a cursor position",
        Why::Moved => "the cursor left the line while measuring",
    }
}

fn mismatch_text(m: &Mismatch) -> String {
    match *m {
        Mismatch::AmbiguousWidth {
            measured,
            configured,
        } => format!(
            "ambiguous-width characters take {measured} cell(s), the settings say {configured}"
        ),
        Mismatch::AmbiguousMixed => {
            "ambiguous-width characters do not all take the same number of cells".into()
        }
        Mismatch::EmojiWidth {
            measured,
            configured,
        } => format!("emoji take {measured} cell(s), the settings say {configured}"),
        Mismatch::EmojiCells { cells, expected } => {
            format!("a plain emoji takes {cells} cell(s), bingsu counts {expected}")
        }
        Mismatch::Vs16Differs { plain, vs16 } => {
            format!("an emoji made by U+FE0F takes {vs16} cell(s), a plain one {plain}")
        }
        Mismatch::ZwjCells { cells, expected } => {
            format!("a joined emoji takes {cells} cell(s), bingsu counts {expected}")
        }
        Mismatch::FlagCells { cells, expected } => {
            format!("a flag takes {cells} cell(s), bingsu counts {expected}")
        }
        Mismatch::CombiningCells { cells } => {
            format!("a letter with a combining mark takes {cells} cell(s), bingsu counts 1")
        }
        Mismatch::NerdCells { cells } => {
            format!("an icon takes {cells} cell(s), bingsu counts 1")
        }
    }
}

fn judge_width(outcome: &WidthOutcome, profile: WidthProfile, tmux: bool) -> Finding {
    let cells = match outcome {
        WidthOutcome::Measured(cells) => cells,
        WidthOutcome::TooNarrow(c) => {
            return finding(
                Status::Skipped,
                format!(
                    "the terminal is {c} columns wide; the measurement needs {} or more",
                    width::MIN_COLUMNS
                ),
                None,
            );
        }
        WidthOutcome::NoAnswer(why) => return finding(Status::Unknown, why_text(*why), None),
        WidthOutcome::Cancelled => return finding(Status::Skipped, "stopped", None),
        WidthOutcome::Failed => {
            return finding(
                Status::Unknown,
                "the terminal could not be written to",
                None,
            );
        }
    };
    let recommended = width::recommended(cells);
    let details = Some(Details::Width {
        cells: *cells,
        recommended,
        inside_tmux: tmux,
    });
    let via = if tmux {
        " (inside tmux, which answers for its own pane)"
    } else {
        ""
    };
    let mut f = if !width::reliable(cells) {
        finding(
            Status::Unknown,
            format!(
                "the control characters moved the cursor by {} and {} cell(s), not 1 and 2, so the measurement is not trusted{via}",
                cells[0], cells[1]
            ),
            None,
        )
    } else {
        let bad = width::mismatches(cells, profile);
        if bad.is_empty() {
            finding(
                Status::Ok,
                format!(
                    "{} probe characters moved the cursor as the settings say (ambiguous {}, emoji {}){via}",
                    PROBES.len(),
                    profile.ambiguous(),
                    profile.emoji()
                ),
                None,
            )
        } else {
            let list: Vec<String> = bad.iter().map(mismatch_text).collect();
            let set = match (recommended.ambiguous, recommended.emoji) {
                (Some(a), Some(e)) => {
                    format!("; this terminal fits `width.ambiguous = {a}` and `width.emoji = {e}`")
                }
                (Some(a), None) => format!("; this terminal fits `width.ambiguous = {a}`"),
                (None, Some(e)) => format!("; this terminal fits `width.emoji = {e}`"),
                (None, None) => String::new(),
            };
            finding(
                Status::Warn,
                format!("{}{set}{via}", list.join("; ")),
                Some(codes::TERMINAL_WIDTH_DIFFERS),
            )
        }
    };
    f.details = details;
    f
}

fn mode_word(m: Mode) -> &'static str {
    match m {
        Mode::Dark => "dark",
        Mode::Light => "light",
    }
}

fn judge_background(outcome: &BackgroundOutcome, prompt: Mode, hint_set: bool) -> Finding {
    let terminal = match outcome {
        BackgroundOutcome::Dark => Mode::Dark,
        BackgroundOutcome::Light => Mode::Light,
        BackgroundOutcome::NoAnswer(why) => {
            return finding(Status::Unknown, why_text(*why), None);
        }
        BackgroundOutcome::Cancelled => return finding(Status::Skipped, "stopped", None),
        BackgroundOutcome::Failed => {
            return finding(
                Status::Unknown,
                "the terminal could not be written to",
                None,
            );
        }
    };
    let hint = if hint_set {
        "from COLORFGBG"
    } else {
        "COLORFGBG is not set"
    };
    let mut f = if terminal == prompt {
        finding(
            Status::Ok,
            format!(
                "the terminal is {} and the prompt draws for {} ({hint})",
                mode_word(terminal),
                mode_word(prompt)
            ),
            None,
        )
    } else {
        finding(
            Status::Warn,
            format!(
                "the terminal is {} but the prompt draws for {} ({hint})",
                mode_word(terminal),
                mode_word(prompt)
            ),
            Some(codes::TERMINAL_BACKGROUND_DIFFERS),
        )
    };
    f.details = Some(Details::Background { terminal, prompt });
    f
}

fn run_terminal_width(c: &Ctx) -> Finding {
    if let Some(f) = no_question(c) {
        return f;
    }
    let Some(settings) = terminal_settings(c) else {
        return finding(
            Status::Unknown,
            "the settings could not be read, so there is nothing to compare with",
            None,
        );
    };
    let outcome = match with_terminal(c, |t| terminal::measure_widths(t)) {
        Ok(o) => o,
        Err(f) => return f,
    };
    if outcome == WidthOutcome::Cancelled {
        c.terminal.cancelled.set(true);
    }
    judge_width(&outcome, settings.profile, c.terminal.tmux)
}

/// The brightness hint the prompt gets: what the shell's last prompt call
/// carried when it handed its evidence (a variable that was never exported
/// is not in the environment, but the hook passes it), else the environment's.
fn colorfgbg_hint(evidence: &Given, env: Option<&OsStr>) -> Option<Mode> {
    doctor_evidence::envelope_colorfgbg(evidence)
        .or_else(|| env.and_then(|v| colorfgbg_mode(v.as_bytes())))
}

fn run_terminal_background(c: &Ctx) -> Finding {
    let Some(settings) = terminal_settings(c) else {
        return finding(
            Status::Unknown,
            "the settings could not be read, so there is nothing to compare with",
            None,
        );
    };
    if !settings.auto {
        return finding(
            Status::Skipped,
            "`colors.mode` is not auto, so the prompt does not guess the background",
            None,
        );
    }
    let outcome = match with_terminal(c, |t| terminal::measure_background(t)) {
        Ok(o) => o,
        Err(f) => return f,
    };
    if outcome == BackgroundOutcome::Cancelled {
        c.terminal.cancelled.set(true);
    }
    // The prompt draws by what its envelope carries: the same two functions.
    let hint = colorfgbg_hint(&c.evidence, c.terminal.colorfgbg.as_deref());
    judge_background(&outcome, display_mode(hint), hint.is_some())
}

// ---- output ----------------------------------------------------------------------

/// The text of a run: one line per check and a summary line.
pub(super) fn render(rows: &[(&Item, Finding)]) -> String {
    use std::fmt::Write as _;
    let mut out = String::from("bingsu doctor\n");
    for (item, f) in rows {
        let code = f
            .fix
            .map(|c| format!(" ({c}; bingsu help {c})"))
            .unwrap_or_default();
        let _ = writeln!(
            out,
            "  {:<8}{:<16}{}{}",
            f.status.word(),
            item.title,
            sanitize(f.text.as_bytes()),
            code
        );
    }
    let n = |s: Status| rows.iter().filter(|(_, f)| f.status == s).count();
    let _ = writeln!(
        out,
        "result: {} ok, {} warning(s), {} failed, {} unknown, {} skipped",
        n(Status::Ok),
        n(Status::Warn),
        n(Status::Fail),
        n(Status::Unknown),
        n(Status::Skipped)
    );
    out
}

/// 1 when any check failed, else 0 (a warning or an unknown is not a failure).
pub(super) fn exit_of(rows: &[(&Item, Finding)]) -> u8 {
    u8::from(rows.iter().any(|(_, f)| f.status == Status::Fail))
}

/// What the command line asked for.
#[derive(Debug, PartialEq, Eq)]
struct Opts {
    json: bool,
    /// The shell function hands its evidence on standard input.
    evidence: bool,
    /// `--terminal`: ask the controlling terminal even when standard output
    /// is not one.
    terminal: bool,
}

/// `--format json|text`, `--terminal` and `--evidence-stdin`, each at most
/// once, in any order.
fn parse(args: &[OsString]) -> Option<Opts> {
    let mut o = Opts {
        json: false,
        evidence: false,
        terminal: false,
    };
    let (mut format_seen, mut it) = (false, args.iter());
    while let Some(a) = it.next() {
        match a.to_str()? {
            "--evidence-stdin" if !o.evidence => o.evidence = true,
            "--terminal" if !o.terminal => o.terminal = true,
            "--format" if !format_seen => {
                format_seen = true;
                o.json = match it.next()?.to_str()? {
                    "json" => true,
                    "text" => false,
                    _ => return None,
                };
            }
            _ => return None,
        }
    }
    Some(o)
}

/// The record on standard input, read once: at most `MAX + 1` bytes.
fn read_evidence() -> Given {
    use std::io::Read as _;
    let mut bytes = Vec::new();
    let read = std::io::stdin()
        .lock()
        .take(doctor_evidence::MAX as u64 + 1)
        .read_to_end(&mut bytes);
    match read {
        Ok(_) => doctor_evidence::parse(&bytes),
        Err(_) => Given::Bad("it could not be read"),
    }
}

fn write_details(w: &mut bingsu_core::diag_json::Writer, d: &Details) {
    w.key("details").begin_object();
    match d {
        Details::Width {
            cells,
            recommended,
            inside_tmux,
        } => {
            w.key("probes").begin_array();
            for (p, c) in PROBES.iter().zip(cells) {
                w.begin_object();
                w.key("name").string(p.name);
                w.key("cells").number(u64::from(*c));
                w.end_object();
            }
            w.end_array();
            w.key("recommended").begin_object();
            for (k, v) in [
                ("ambiguous", recommended.ambiguous),
                ("emoji", recommended.emoji),
            ] {
                w.key(k);
                match v {
                    Some(n) => w.number(u64::from(n)),
                    None => w.null(),
                };
            }
            w.end_object();
            w.key("inside_tmux").boolean(*inside_tmux);
        }
        Details::Background { terminal, prompt } => {
            w.key("terminal").string(mode_word(*terminal));
            w.key("prompt").string(mode_word(*prompt));
            w.key("colors_mode").string("auto");
        }
    }
    w.end_object();
}

/// The JSON document of a run: the same rows as the text, as data. A
/// finding's `fix` is its diagnostic code. No value of the environment is in
/// a `Finding`, so none can be here.
pub(super) fn render_json(rows: &[(&Item, Finding)], error: Option<&str>) -> String {
    use bingsu_core::diag_json::{SCHEMA, Writer};
    // A run that could not make its checks is invalid too (`error` says why).
    let code = if error.is_some() { 1 } else { exit_of(rows) };
    let mut w = Writer::new();
    w.begin_object();
    w.key("schema").number(u64::from(SCHEMA));
    w.key("command").string("doctor");
    w.key("result")
        .string(if code == 0 { "valid" } else { "invalid" });
    w.key("items").begin_array();
    for (item, f) in rows {
        w.begin_object();
        w.key("id").string(item.id);
        w.key("title").string(item.title);
        w.key("status").string(f.status.word());
        w.key("text").string(&f.text);
        w.key("fix")
            .opt_string(f.fix.map(|c| c.to_string()).as_deref());
        if let Some(d) = &f.details {
            write_details(&mut w, d);
        }
        w.end_object();
    }
    w.end_array();
    w.key("exit_code").number(u64::from(code));
    w.key("error").opt_string(error);
    w.end_object();
    w.finish()
}

pub fn run(args: &[OsString]) -> ExitCode {
    let Some(opts) = parse(args) else {
        eprintln!("{USAGE}");
        return ctx::code(EXIT_USAGE);
    };
    let json = opts.json;
    // The evidence comes from the shell function through a pipe. A terminal
    // on standard input means a person started this by hand: say so, and do
    // not wait for them to type a record.
    if opts.evidence && sys::fd_is_tty(0) {
        eprintln!(
            "bingsu doctor: --evidence-stdin takes the shell's record; run bingsu_doctor in your shell instead"
        );
        return ctx::code(EXIT_USAGE);
    }
    let evidence = if opts.evidence {
        read_evidence()
    } else {
        Given::No
    };
    let Some(user) = User::current() else {
        if json {
            let doc = render_json(&[], Some("the account or its home folder cannot be read"));
            let _ = ctx::print(&doc);
            return ctx::code(EXIT_FAILED);
        }
        eprintln!("bingsu doctor: the account or its home folder cannot be read");
        return ctx::code(EXIT_FAILED);
    };
    let (colorfgbg, tmux) = TrustedEnv::terminal_hints();
    let c = Ctx {
        evidence,
        user,
        env: TrustedEnv::capture(),
        exe: std::env::current_exe().ok(),
        terminal: TerminalCtx {
            measure: opts.terminal || std::io::IsTerminal::is_terminal(&std::io::stdout()),
            open: open_controlling_terminal,
            colorfgbg,
            tmux,
            settings: std::cell::OnceCell::new(),
            cancelled: std::cell::Cell::new(false),
        },
    };
    let rows: Vec<(&Item, Finding)> = ITEMS.iter().map(|i| (i, (i.run)(&c))).collect();
    if c.terminal.cancelled.get() {
        // Ctrl-C: the terminal is restored; the table is not printed.
        return ctx::code(EXIT_CANCELLED);
    }
    let out = if json {
        render_json(&rows, None)
    } else {
        render(&rows)
    };
    if !ctx::print(&out) {
        return ctx::code(EXIT_UNFINISHED);
    }
    ctx::code(exit_of(&rows))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn is(f: &Finding, status: Status, fix: Option<DiagCode>) {
        assert_eq!((f.status, f.fix), (status, fix), "{}", f.text);
        assert!(!f.text.is_empty());
    }

    // 이것을 실패시키는 것: 안전 판정을 경고로, 바꿀 수 있음을 정상으로 매기는 것, 경고에서 진단 코드를 빼는 것,
    // 안전한 대상이 남이 바꿀 수 있는 폴더의 링크를 덮게 하는 것(가장 나쁜 경로가 정해야 한다).
    #[test]
    fn executable_follows_the_worst_path_verdict() {
        let p = |name: &str, v| (PathBuf::from(name), v);
        is(&judge_executable(&[]), Status::Unknown, None);
        is(
            &judge_executable(&[p("/opt/bingsu/bingsu", Verdict::Safe)]),
            Status::Ok,
            None,
        );
        is(
            &judge_executable(&[p("/opt/bingsu/bingsu", Verdict::Unknown)]),
            Status::Unknown,
            None,
        );
        is(
            &judge_executable(&[p("/opt/bingsu/bingsu", Verdict::Tamperable)]),
            Status::Warn,
            Some(codes::EXE_FOLDER_CHANGEABLE),
        );
        let f = judge_executable(&[
            p("/opt/bingsu/bingsu", Verdict::Safe),
            p("/shared/bin/bingsu", Verdict::Tamperable),
        ]);
        is(&f, Status::Warn, Some(codes::EXE_FOLDER_CHANGEABLE));
        assert!(f.text.contains("/shared/bin/bingsu"), "{}", f.text);
    }

    // 이것을 실패시키는 것: 다른 bingsu를 정상으로, 못 찾음을 경고로 매기는 것.
    #[test]
    fn the_bingsu_on_path_is_compared_with_the_running_one() {
        let p = PathBuf::from("/usr/local/bin/bingsu");
        is(&judge_path_bingsu(&OnPath::NotFound), Status::Skipped, None);
        is(
            &judge_path_bingsu(&OnPath::Same(p.clone())),
            Status::Ok,
            None,
        );
        is(
            &judge_path_bingsu(&OnPath::Other(p)),
            Status::Warn,
            Some(codes::PATH_BINGSU_DIFFERS),
        );
    }

    // 이것을 실패시키는 것: 고정값이 없는 것을 정상으로, 바뀐 것을 경고로 매기는 것, 바뀐 폴더의 두 inode를 문구에서 빼는 것.
    #[test]
    fn pinned_folders_say_what_changed() {
        let p = PathBuf::from("/run/user/1/bingsu");
        is(
            &judge_roots_pin(&Pin::Absent),
            Status::Warn,
            Some(codes::NO_PINNED_ROOTS),
        );
        is(&judge_roots_pin(&Pin::Matches(p.clone())), Status::Ok, None);
        for pin in [
            Pin::Garbled,
            Pin::RuntimeGone(p.clone()),
            Pin::OtherChanged,
            Pin::FolderRefused {
                which: "log",
                path: p.clone(),
                why: "x".into(),
            },
        ] {
            is(
                &judge_roots_pin(&pin),
                Status::Fail,
                Some(codes::ROOTS_NO_LONGER_MATCH),
            );
        }
        let f = judge_roots_pin(&Pin::RuntimeChanged {
            path: p,
            pinned: (1, 22),
            now: (1, 33),
        });
        is(&f, Status::Fail, Some(codes::ROOTS_NO_LONGER_MATCH));
        assert!(
            f.text.contains("inode 22") && f.text.contains("inode 33"),
            "{}",
            f.text
        );
    }

    // 이것을 실패시키는 것: 수집기가 없거나 다른 빌드인데 정상으로 매기는 것, 프롬프트 실행 파일이 없는 것을 경고로 매기는 것.
    #[test]
    fn the_three_executables_must_be_one_build() {
        use Sib::{Missing, Unverified, Verified};
        is(&judge_build_identity(Verified, Verified), Status::Ok, None);
        is(&judge_build_identity(Verified, Missing), Status::Ok, None);
        for (c, p) in [
            (Missing, Verified),
            (Unverified, Verified),
            (Missing, Missing),
        ] {
            is(
                &judge_build_identity(c, p),
                Status::Warn,
                Some(codes::SIBLING_UNVERIFIED),
            );
        }
        is(
            &judge_build_identity(Verified, Unverified),
            Status::Warn,
            Some(codes::SIBLING_UNVERIFIED),
        );
    }

    // 이것을 실패시키는 것: 커널에 seccomp가 없는 것을 정상으로, 이 플랫폼에 없는 것을 경고로 매기는 것.
    #[test]
    fn seccomp_follows_the_kernel_answer() {
        is(&judge_seccomp(SeccompKernel::Supported), Status::Ok, None);
        is(
            &judge_seccomp(SeccompKernel::Absent),
            Status::Warn,
            Some(codes::NO_KERNEL_SECCOMP),
        );
        is(
            &judge_seccomp(SeccompKernel::NotApplicable),
            Status::Skipped,
            None,
        );
        is(
            &judge_seccomp(SeccompKernel::Failed(13)),
            Status::Unknown,
            None,
        );
    }

    // 이것을 실패시키는 것: 설정 오류를 정상으로, 다 못 읽은 것을 실패로 매기는 것.
    #[test]
    fn settings_follow_the_check_verdict() {
        is(&judge_settings(0, 0, 2), Status::Ok, None);
        is(
            &judge_settings(EXIT_FAILED, 3, 0),
            Status::Fail,
            Some(codes::SETTINGS_INVALID),
        );
        is(
            &judge_settings(EXIT_UNFINISHED, 0, 0),
            Status::Unknown,
            None,
        );
        is(
            &judge_settings_unread(EXIT_FAILED, "the settings folder fails its checks"),
            Status::Fail,
            Some(codes::SETTINGS_INVALID),
        );
        is(
            &judge_settings_unread(EXIT_UNFINISHED, "could not read"),
            Status::Unknown,
            None,
        );
    }

    // 이것을 실패시키는 것: 경고·모름·건너뜀을 실패 종료로 세는 것, 실패를 세지 않는 것.
    #[test]
    fn only_a_failure_fails_the_run() {
        let item = &ITEMS[0];
        let row = |s| (item, finding(s, "x", None));
        for s in [Status::Ok, Status::Warn, Status::Unknown, Status::Skipped] {
            assert_eq!(exit_of(&[row(s)]), 0, "{s:?}");
        }
        assert_eq!(exit_of(&[row(Status::Ok), row(Status::Fail)]), 1);
    }

    // 이것을 실패시키는 것: 문구의 제어 문자를 그대로 내보내는 것, 진단 코드와 help 안내를 빼는 것, 요약 줄의 수를 틀리게 세는 것.
    #[test]
    fn the_text_is_sanitized_and_names_the_code() {
        let rows = [
            (
                &ITEMS[0],
                finding(
                    Status::Warn,
                    "a\u{1b}[2Jb",
                    Some(codes::PATH_BINGSU_DIFFERS),
                ),
            ),
            (&ITEMS[1], finding(Status::Ok, "fine", None)),
        ];
        let t = render(&rows);
        assert!(!t.contains('\u{1b}'), "{t:?}");
        assert!(t.contains("(W602; bingsu help W602)"), "{t}");
        assert!(
            t.contains("result: 1 ok, 1 warning(s), 0 failed, 0 unknown, 0 skipped"),
            "{t}"
        );
    }

    // 이것을 실패시키는 것: 점검을 못 한 실행의 JSON에서 `items`·`exit_code`·`error`를 빼거나 result를 valid로 두는 것.
    #[test]
    fn a_run_that_could_not_check_still_has_the_whole_shape() {
        let doc = render_json(&[], Some("cannot read the account"));
        assert_eq!(
            doc,
            "{\"schema\":1,\"command\":\"doctor\",\"result\":\"invalid\",\"items\":[],\"exit_code\":1,\"error\":\"cannot read the account\"}\n"
        );
    }

    // 이것을 실패시키는 것: 차단을 정상으로 매기는 것, 기록이 없는 것을 경고로 매기는 것, 읽기 실패·다른 부팅 기록을 정상이나
    // 경고로 매기는 것(모름이어야 한다), 경고에서 진단 코드를 빼는 것.
    #[test]
    fn the_breaker_follows_what_peek_found() {
        is(
            &judge_breaker(Ok(Peek::Blocked)),
            Status::Warn,
            Some(codes::COLLECTION_BREAKER_ON),
        );
        for p in [Peek::NoRecord, Peek::Allowed, Peek::Probe] {
            is(&judge_breaker(Ok(p)), Status::Ok, None);
        }
        is(&judge_breaker(Ok(Peek::Disabled)), Status::Unknown, None);
        let f = judge_breaker(Err(()));
        is(&f, Status::Unknown, None);
        assert!(f.text.contains("pinned folders"), "{}", f.text);
    }

    // 이것을 실패시키는 것: PWD가 없는데 다른 값(현재 폴더, 물리 경로)으로 키를 만드는 것, 프롬프트의 봉투 규칙을 어기는 PWD(상대 경로,
    // 너무 긴 값)를 키로 쓰는 것, PWD 문자열을 고치는 것(링크로 들어간 폴더의 논리 경로를 그대로 써야 helper와 같은 키가 된다).
    #[test]
    fn the_folder_key_is_the_shells_pwd_string_or_nothing() {
        assert_eq!(
            shell_pwd(Some(OsStr::new("/home/me/link/dir"))).unwrap(),
            b"/home/me/link/dir"
        );
        assert!(shell_pwd(None).is_err());
        assert!(shell_pwd(Some(OsStr::new(""))).is_err());
        assert!(shell_pwd(Some(OsStr::new("relative"))).is_err());
        let long = format!("/{}", "a".repeat(70_000));
        assert!(shell_pwd(Some(OsStr::new(&long))).is_err());
    }

    const NORMAL: Cells = [1, 2, 1, 1, 1, 2, 2, 2, 2, 1, 1, 1];

    // 이것을 실패시키는 것: 설정과 같은 터미널을 경고로, 다른 터미널을 정상으로 매기는 것, 경고에서 W613이나 권장 값을 빼는 것,
    // 통제 글자(a, 한)가 어긋난 측정을 믿는 것, 시간 초과·잘못된 응답·줄 이동을 불일치로 읽는 것, 좁은 터미널을 모름으로 매기는 것.
    #[test]
    fn the_width_row_follows_the_measurement() {
        let p = WidthProfile::DEFAULT;
        let f = judge_width(&WidthOutcome::Measured(NORMAL), p, false);
        is(&f, Status::Ok, None);
        assert!(f.details.is_some());
        // ambiguous characters take 2 cells here.
        let wide = [1, 2, 2, 2, 2, 2, 2, 2, 2, 1, 1, 1];
        let f = judge_width(&WidthOutcome::Measured(wide), p, false);
        is(&f, Status::Warn, Some(codes::TERMINAL_WIDTH_DIFFERS));
        assert!(f.text.contains("`width.ambiguous = 2`"), "{}", f.text);
        // The settings that match it are fine.
        let two = WidthProfile::new(2, 2).unwrap();
        is(
            &judge_width(&WidthOutcome::Measured(wide), two, false),
            Status::Ok,
            None,
        );
        // A control that moved the wrong way: no verdict at all.
        let mut bad = NORMAL;
        bad[1] = 1;
        let f = judge_width(&WidthOutcome::Measured(bad), p, false);
        is(&f, Status::Unknown, None);
        for why in [Why::Silent, Why::Garbled, Why::Moved] {
            let f = judge_width(&WidthOutcome::NoAnswer(why), p, false);
            is(&f, Status::Unknown, None);
            assert!(f.details.is_none());
        }
        is(
            &judge_width(&WidthOutcome::TooNarrow(30), p, false),
            Status::Skipped,
            None,
        );
        is(
            &judge_width(&WidthOutcome::Failed, p, false),
            Status::Unknown,
            None,
        );
        let f = judge_width(&WidthOutcome::Measured(wide), p, true);
        assert!(f.text.contains("tmux"), "{}", f.text);
    }

    // 이것을 실패시키는 것: 밝기가 같은데 경고, 다른데 정상으로 매기는 것, 힌트가 없을 때 그 사실을 문구에서 빼는 것,
    // 응답이 없는데 비교하는 것.
    #[test]
    fn the_background_row_compares_the_two_brightnesses() {
        let (d, l) = (BackgroundOutcome::Dark, BackgroundOutcome::Light);
        is(&judge_background(&d, Mode::Dark, true), Status::Ok, None);
        is(&judge_background(&l, Mode::Light, true), Status::Ok, None);
        let f = judge_background(&l, Mode::Dark, false);
        is(&f, Status::Warn, Some(codes::TERMINAL_BACKGROUND_DIFFERS));
        assert!(f.text.contains("COLORFGBG is not set"), "{}", f.text);
        assert_eq!(
            f.details,
            Some(Details::Background {
                terminal: Mode::Light,
                prompt: Mode::Dark
            })
        );
        let f = judge_background(&BackgroundOutcome::NoAnswer(Why::Silent), Mode::Dark, true);
        is(&f, Status::Unknown, None);
        assert!(f.details.is_none());
    }

    // 이것을 실패시키는 것: `--terminal`을 받지 않는 것, 같은 플래그나 모르는 플래그를 받는 것, 순서를 고정하는 것.
    #[test]
    fn the_command_line_takes_format_and_terminal_once_in_any_order() {
        let a = |v: &[&str]| parse(&v.iter().map(OsString::from).collect::<Vec<_>>());
        let o = |json, terminal| {
            Some(Opts {
                json,
                evidence: false,
                terminal,
            })
        };
        assert_eq!(a(&[]), o(false, false));
        assert_eq!(a(&["--terminal"]), o(false, true));
        assert_eq!(a(&["--format", "json", "--terminal"]), o(true, true));
        assert_eq!(a(&["--terminal", "--format", "text"]), o(false, true));
        for bad in [
            &["--terminal", "--terminal"][..],
            &["--evidence-stdin", "--evidence-stdin"],
            &["--format"],
            &["--format", "yaml"],
            &["--format", "json", "--format", "text"],
            &["--probe"],
        ] {
            assert_eq!(a(bad), None, "{bad:?}");
        }
    }

    // 이것을 실패시키는 것: 두 터미널 행의 details를 JSON에서 빼는 것, 다른 행에 details를 붙이는 것,
    // 측정하지 않은 행에 details를 붙이는 것, 시험 글자 이름·칸 수를 순서대로 싣지 않는 것.
    #[test]
    fn only_a_measured_terminal_row_has_details_in_the_json() {
        let item = |id: &str| ITEMS.iter().find(|i| i.id == id).unwrap();
        let rows = [
            (item("settings"), finding(Status::Ok, "fine", None)),
            (
                item("terminal-width"),
                judge_width(&WidthOutcome::Measured(NORMAL), WidthProfile::DEFAULT, true),
            ),
            (
                item("terminal-background"),
                judge_background(&BackgroundOutcome::Light, Mode::Dark, true),
            ),
            (
                item("executable"),
                judge_width(
                    &WidthOutcome::NoAnswer(Why::Silent),
                    WidthProfile::DEFAULT,
                    false,
                ),
            ),
        ];
        let doc = render_json(&rows, None);
        assert_eq!(doc.matches("\"details\"").count(), 2, "{doc}");
        assert!(
            doc.contains("\"probes\":[{\"name\":\"control-narrow\",\"cells\":1},{\"name\":\"control-wide\",\"cells\":2}"),
            "{doc}"
        );
        assert!(
            doc.contains("\"recommended\":{\"ambiguous\":1,\"emoji\":2},\"inside_tmux\":true"),
            "{doc}"
        );
        assert!(
            doc.contains(
                "\"details\":{\"terminal\":\"light\",\"prompt\":\"dark\",\"colors_mode\":\"auto\"}"
            ),
            "{doc}"
        );
    }

    struct Fake {
        raw_fails: bool,
    }
    impl Controlling for Fake {
        fn raw_terminal(&self) -> std::io::Result<Box<dyn Terminal + '_>> {
            if self.raw_fails {
                return Err(std::io::Error::other("no raw mode"));
            }
            Ok(Box::new(super::super::terminal::fake::Fake::new([
                1, 2, 1, 1, 1, 2, 2, 2, 2, 1, 1, 1,
            ])))
        }
    }

    fn context(measure: bool, open: fn() -> Option<Box<dyn Controlling>>) -> Ctx {
        Ctx {
            evidence: Given::No,
            user: User::current().unwrap(),
            env: TrustedEnv::capture(),
            exe: None,
            terminal: TerminalCtx {
                measure,
                open,
                colorfgbg: None,
                tmux: false,
                settings: std::cell::OnceCell::new(),
                cancelled: std::cell::Cell::new(false),
            },
        }
    }

    fn asked(c: &Ctx) -> Result<u16, Finding> {
        with_terminal(c, |t| t.columns().unwrap_or(0))
    }

    // 이것을 실패시키는 것: raw 모드를 못 켰는데 질문을 계속하는 것(Ok가 돌아옴), 그 경우를 건너뜀이나 실패로 매기는 것
    // (모름이어야 함), 제어 터미널이 없을 때(`open`이 None) 건너뜀이 아닌 상태를 내는 것, 표준 출력이 터미널이 아닌데
    // `open`을 부르는 것, 취소 뒤에도 묻는 것.
    #[test]
    fn a_terminal_that_cannot_be_asked_gives_the_row_that_says_why() {
        fn none() -> Option<Box<dyn Controlling>> {
            None
        }
        fn raw_fails() -> Option<Box<dyn Controlling>> {
            Some(Box::new(Fake { raw_fails: true }))
        }
        fn works() -> Option<Box<dyn Controlling>> {
            Some(Box::new(Fake { raw_fails: false }))
        }
        fn never() -> Option<Box<dyn Controlling>> {
            panic!("opened the terminal when it must not")
        }
        assert_eq!(asked(&context(true, works)).unwrap(), 80);
        let f = asked(&context(true, none)).unwrap_err();
        is(&f, Status::Skipped, None);
        assert!(f.text.contains("no terminal to ask"), "{}", f.text);
        let f = asked(&context(true, raw_fails)).unwrap_err();
        is(&f, Status::Unknown, None);
        assert!(f.text.contains("mode the questions need"), "{}", f.text);
        let f = asked(&context(false, never)).unwrap_err();
        is(&f, Status::Skipped, None);
        assert!(f.text.contains("not a terminal"), "{}", f.text);
        let c = context(true, never);
        c.terminal.cancelled.set(true);
        let f = asked(&c).unwrap_err();
        is(&f, Status::Skipped, None);
        assert_eq!(f.text, "stopped");
    }

    // 이것을 실패시키는 것: 셸이 증거에 실어 보낸 `COLORFGBG`(내보내지 않은 변수라 환경에는 없음)를 무시하고 환경만 보는 것(밝은
    // 터미널로 맞게 설정된 셸이 어둡다고 판정됨), 증거가 있는데도 환경을 앞세우는 것, 증거에 힌트가 없을 때 환경으로 돌아가지
    // 않는 것.
    #[test]
    fn the_hint_the_hook_passed_is_the_one_doctor_judges() {
        use doctor_evidence::{Evidence, Given};
        let evidence = |hint: &str| {
            let mut envelope: Vec<Vec<u8>> = [
                "--width",
                "80",
                "--status",
                "0",
                "--pipestatus",
                "0",
                "--jobs",
                "0",
                "--keymap",
                "main",
            ]
            .iter()
            .map(|w| w.as_bytes().to_vec())
            .collect();
            envelope.extend([b"--colorfgbg".to_vec(), hint.as_bytes().to_vec()]);
            Given::Yes(Evidence {
                shell: b"zsh".to_vec(),
                version: b"5.9".to_vec(),
                session: Vec::new(),
                ctx: b"1".to_vec(),
                record: b"B1".to_vec(),
                precmd: Vec::new(),
                preexec: Vec::new(),
                envelope,
                separators: false,
            })
        };
        // 0;15: a white background, set in the shell and not exported.
        assert_eq!(colorfgbg_hint(&evidence("0;15"), None), Some(Mode::Light));
        // The environment has another value: the hook's is the one the prompt used.
        assert_eq!(
            colorfgbg_hint(&evidence("0;15"), Some(OsStr::new("15;0"))),
            Some(Mode::Light)
        );
        // No hint in the envelope (empty value): the environment's.
        assert_eq!(
            colorfgbg_hint(&evidence(""), Some(OsStr::new("0;15"))),
            Some(Mode::Light)
        );
        // No evidence: the environment's, or none.
        assert_eq!(
            colorfgbg_hint(&Given::No, Some(OsStr::new("15;0"))),
            Some(Mode::Dark)
        );
        assert_eq!(colorfgbg_hint(&Given::No, None), None);
    }

    // 이것을 실패시키는 것: 터미널 행이 맨 앞이나 사이에 끼는 것(출력 순서가 바뀜), 터미널 행 id를 바꾸는 것.
    #[test]
    fn the_terminal_rows_come_last() {
        let ids: Vec<&str> = ITEMS.iter().map(|i| i.id).collect();
        assert_eq!(
            &ids[ids.len() - 2..],
            ["terminal-width", "terminal-background"]
        );
    }

    // 이것을 실패시키는 것: 점검 id나 제목을 겹치게 등록하는 것(JSON과 사람용 줄이 한 점검을 가리지 못함).
    #[test]
    fn items_are_unique() {
        for (i, a) in ITEMS.iter().enumerate() {
            for b in &ITEMS[i + 1..] {
                assert!(a.id != b.id && a.title != b.title, "{} {}", a.id, b.id);
            }
        }
    }
}
