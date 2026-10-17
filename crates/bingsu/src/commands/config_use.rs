//! `bingsu config use PATH`: record which file stands in `config.toml`'s
//! place (spec section 4 "config edit loop"). Only the choice is saved; the
//! file is never copied, and `conf.d/*.toml` and `config.local.toml` keep
//! applying. The save is the R record procedure (state `selection.lock`,
//! temporary file, fsync, rename, folder fsync); the new choice is then
//! applied by the same N2 engine as `reload`, and the two outcomes are
//! reported apart. Exit 0: saved and applied; 1: refused, or saved and the
//! settings it gives are invalid; 2: usage; 3: nothing saved, or saved and
//! not applied yet.
use super::{
    clock::SystemClock,
    config_inspect::refusal_text,
    ctx::{self, Applied, EXIT_FAILED, EXIT_UNFINISHED, EXIT_USAGE, User},
    group_policy::SystemGroups,
    messages::{MsgId, en},
    reload, runtime_root,
    source_path::Resolved,
    trust_record::{self, Record},
};
use bingsu_core::fs_trust::Last;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, Instant};

/// The selection lock is held for an instant by the helper; waiting this
/// long for it is invisible to the user and keeps a race from failing a save.
const LOCK_WAIT: Duration = Duration::from_millis(500);

fn refused(what: &str, path: &Path) -> (String, u8) {
    (
        format!("bingsu: not using {}: {what}", ctx::show(path)),
        EXIT_FAILED,
    )
}

/// Checks the path as the helper will when it reads the file: every link and
/// folder on the way, the owner, the mode and the ACL. `Ok` carries the
/// canonical path and the identity to record.
fn vet(path: &Path, user: &User, shape_only_root: Option<&Path>) -> Result<Record, (String, u8)> {
    let mut groups = SystemGroups::new(&user.pw.name);
    let evidence = Resolved::open(path, user.me, &mut groups).map_err(|e| {
        let why = match e.raw_os_error() {
            Some(n) if n == libc::ENOENT => "there is no such file".to_owned(),
            Some(n) if n == libc::ELOOP => "too many links on the way".to_owned(),
            Some(n) => format!("it cannot be opened (errno {n})"),
            None => format!("it is not a plain file you can read ({e})"),
        };
        refused(&why, path)
    })?;
    if let Some(r) = evidence.refusal {
        return Err(refused(
            &format!("it is not safe to run commands from: {}", refusal_text(r)),
            path,
        ));
    }
    evidence
        .revalidate(user.me, &mut groups)
        .map_err(|_| refused("it changed while it was checked", path))?;
    // Nothing under a settings folder that could not be confirmed safe may
    // run, so choosing a file there would save a choice that cannot work.
    if let Some(root) = shape_only_root
        && evidence.canonical.starts_with(root)
    {
        return Err(refused(
            "it is inside the settings folder, which could not be confirmed safe, so nothing in it runs. Run: bingsu doctor",
            path,
        ));
    }
    Ok(Record {
        dev: evidence.stamp.dev,
        ino: evidence.stamp.ino,
        path: evidence.canonical.clone(),
    })
}

/// Saves the record; the state folder is made first when it is missing, by
/// the same rule as the helper's.
fn save(state: &Path, user: &User, record: &Record) -> Result<(), String> {
    let mut groups = SystemGroups::new(&user.pw.name);
    runtime_root::ensure_root(state, user.me, &mut groups, Last::Mine)
        .map_err(|_| "the state folder cannot be used".to_owned())?;
    let end = Instant::now() + LOCK_WAIT;
    loop {
        let mut groups = SystemGroups::new(&user.pw.name);
        match trust_record::write(state, user.me, &mut groups, record) {
            Ok(()) => return Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock && Instant::now() < end => {
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                return Err("another bingsu process is busy with the choice; try again".to_owned());
            }
            Err(_) => return Err("the choice could not be saved".to_owned()),
        }
    }
}

pub fn run(args: &[OsString]) -> ExitCode {
    let [arg] = args else {
        eprintln!("usage: bingsu config use PATH");
        return ctx::code(EXIT_USAGE);
    };
    let Some(started) = ctx::start() else {
        eprintln!("{}", en(MsgId::ReloadIncomplete));
        return ctx::code(EXIT_UNFINISHED);
    };
    ctx::arm_deadline(
        ctx::COMMAND_LIMIT,
        format!("{}\n", en(MsgId::DeadlineReached)),
    );
    let Some(user) = User::current() else {
        eprintln!("{}", en(MsgId::NoHome));
        return ctx::code(EXIT_FAILED);
    };
    let Ok(cwd) = std::env::current_dir() else {
        eprintln!("bingsu: cannot read the current folder");
        return ctx::code(EXIT_FAILED);
    };
    let path: PathBuf = cwd.join(arg);
    let roots = ctx::roots_for_publishing(&user);
    let Some(state) = roots.state.clone() else {
        eprintln!("{}", en(MsgId::UnconfirmedRoot));
        return ctx::code(EXIT_FAILED);
    };
    let shape_only_root = roots
        .config
        .as_ref()
        .filter(|c| c.shape_only)
        .map(|c| c.path.clone());
    let record = match vet(&path, &user, shape_only_root.as_deref()) {
        Ok(r) => r,
        Err((text, code)) => {
            eprintln!("{text}");
            return ctx::code(code);
        }
    };
    if let Err(why) = save(&state, &user, &record) {
        eprintln!("bingsu: nothing was saved: {why}");
        return ctx::code(EXIT_UNFINISHED);
    }
    let shown = ctx::show(&record.path);
    let applied = ctx::apply(&roots, &user, started, &mut SystemClock);
    match (&applied, reload::report(&applied, "applied")) {
        (_, Ok(text)) => {
            let line = format!("bingsu: using {shown} in place of config.toml\n{text}");
            if ctx::print(&line) {
                ExitCode::SUCCESS
            } else {
                ctx::code(EXIT_FAILED)
            }
        }
        (Applied::Invalid, Err(_)) => {
            eprintln!("bingsu: using {shown} in place of config.toml");
            eprintln!("{}", en(MsgId::UseSavedInvalid));
            ctx::code(EXIT_FAILED)
        }
        (_, Err(_)) => {
            eprintln!("bingsu: using {shown} in place of config.toml");
            eprintln!("{}", en(MsgId::UseSavedUnfinished));
            ctx::code(EXIT_UNFINISHED)
        }
    }
}
