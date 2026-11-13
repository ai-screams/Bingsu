//! `bingsu doctor`: a table of checks of the installation and the shell
//! setup, each with a status, one line and (when there is something to do)
//! a diagnostic code that `bingsu help <code>` explains. It only reads: it
//! runs no other executable (no version query, no shell, no helper), writes
//! nothing and starts no process, and it never guesses a version from a path
//! or a folder name; a fact only a shell can give is `unknown` until the
//! shell says it.
//!
//! The checks are rows of `ITEMS`: a later change adds a row. Each row reads
//! its facts and hands them to a pure `judge_*` function, which the tests
//! feed with good and bad facts.
use super::{
    collector::Sibling,
    config_inspect::{Inspection, exit_for, inspect_config, refusal_text},
    ctx::{self, EXIT_FAILED, EXIT_UNFINISHED, EXIT_USAGE, User},
    group_policy::SystemGroups,
    init::{
        exe_path::{self, invocation_path},
        pinned,
        trusted_env::TrustedEnv,
    },
    runtime_root::{self, RootError},
    sys::{self, SeccompKernel},
};
use bingsu_core::{
    diag::{DiagCode, Severity},
    diag_codes as codes,
    fs_trust::{Last, Verdict, walk_verdict},
    sanitize::sanitize,
};
use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

const USAGE: &str = "usage: bingsu doctor [--format json|text]";

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
}

fn finding(status: Status, text: impl Into<String>, fix: Option<DiagCode>) -> Finding {
    Finding {
        status,
        text: text.into(),
        fix,
    }
}

/// What the checks may read. Nothing here is a process or a write.
pub(super) struct Ctx {
    pub user: User,
    pub env: TrustedEnv,
    pub exe: Option<PathBuf>,
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
        run: run_shell,
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

// ---- shell ---------------------------------------------------------------------

fn run_shell(_: &Ctx) -> Finding {
    // Only the shell can say which shell and version it is. Nothing is read
    // from the shell variable, a path or a folder name: a version guessed from a name is
    // wrong after the first upgrade.
    finding(
        Status::Unknown,
        "shell version not confirmed: no shell passed it to this command",
        None,
    )
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

/// `--format json|text`, at most once; `Some(json)`.
fn parse(args: &[OsString]) -> Option<bool> {
    match args {
        [] => Some(false),
        [flag, value] if flag == "--format" => match value.to_str()? {
            "json" => Some(true),
            "text" => Some(false),
            _ => None,
        },
        _ => None,
    }
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
        w.end_object();
    }
    w.end_array();
    w.key("exit_code").number(u64::from(code));
    w.key("error").opt_string(error);
    w.end_object();
    w.finish()
}

pub fn run(args: &[OsString]) -> ExitCode {
    let Some(json) = parse(args) else {
        eprintln!("{USAGE}");
        return ctx::code(EXIT_USAGE);
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
    let c = Ctx {
        user,
        env: TrustedEnv::capture(),
        exe: std::env::current_exe().ok(),
    };
    let rows: Vec<(&Item, Finding)> = ITEMS.iter().map(|i| (i, (i.run)(&c))).collect();
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
