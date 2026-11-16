//! The installation rows: the executable and the folders above it, the `bingsu` on
//! `PATH`, the pinned folders and the build identity of the three binaries.
use super::*;

// ---- executable ----------------------------------------------------------

/// The worst verdict over every path the executable can be reached by, and
/// the path that earned it: the running file (links resolved) and the path
/// the user ran or `PATH` finds (its link and the folders above the link),
/// since a link in a folder others can write is the way in, whatever the
/// target is.
pub(super) fn judge_executable(paths: &[(PathBuf, Verdict)]) -> Finding {
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

pub(super) fn run_executable(c: &Ctx) -> Finding {
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

pub(super) fn judge_path_bingsu(found: &OnPath) -> Finding {
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

pub(super) fn run_path_bingsu(c: &Ctx) -> Finding {
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

pub(super) fn judge_roots_pin(pin: &Pin) -> Finding {
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

pub(super) fn run_roots_pin(c: &Ctx) -> Finding {
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

pub(super) fn judge_build_identity(collector: Sib, prompt: Sib) -> Finding {
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

pub(super) fn run_build_identity(c: &Ctx) -> Finding {
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
