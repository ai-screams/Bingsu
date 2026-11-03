//! `bingsu config check` and `bingsu config path`: one read of the settings
//! through the same pieces the helper uses (R's `Loader` and `trust_record`
//! session, S's `report`), shown instead of published. Nothing is written:
//! no folder is made, no lock is taken, no snapshot, marker, sequence or
//! selection record changes, and no configured command runs.
use super::{
    config_load::{Loader, Places, Untrusted, Verified},
    ctx::{self, EXIT_FAILED, EXIT_UNFINISHED, User},
    group_policy::SystemGroups,
    init::{
        roots::{self, ConfigRootPin, Roots},
        trusted_env::TrustedEnv,
    },
    messages::{MsgId, en},
    runtime_root::RootError,
    trust_record::{self, Record, RecordError},
};
use crate::commands::io_meter::AxisUse;
use bingsu_core::{
    color::palette::Mode,
    config::{
        compile::BUILTIN_TOML,
        report::{self, ConfigReport},
        source::{Catalog, FileKey, Found, Status, Trust, load},
    },
    diag::{Diagnostic, Place, Severity, render_human},
    diag_codes as codes,
    fs_trust::Refusal,
};
use std::fmt::Write as _;
use std::path::PathBuf;
use std::process::ExitCode;

/// Which file stands in `config.toml`'s place.
pub enum Selection {
    /// `config use` was never run.
    None,
    Chosen(Record),
    /// A record is there but fails the trust rules; the text says which.
    Unusable(String),
    /// The record could not be read; this says nothing about its trust.
    Incomplete,
}

pub struct FileLine {
    pub written: Option<PathBuf>,
    /// Why nothing in it runs, when the safety check refused it.
    pub unsafe_reason: Option<String>,
}

pub struct Inspection {
    pub root: PathBuf,
    pub root_written: PathBuf,
    pub root_notice: Option<[String; 2]>,
    pub selection: Selection,
    pub report: ConfigReport,
    pub lines: Vec<FileLine>,
    pub verdict: Verified,
    /// A cap refused this reading, or the two source checks a refresh adds to
    /// it would pass one.
    pub over_cap: bool,
    pub remedies: Vec<String>,
}

pub fn refusal_text(r: Refusal) -> &'static str {
    match r {
        Refusal::Ancestor { .. } => "a folder above it can be changed by another user",
        Refusal::Undecided { .. } => {
            "who can change it or a folder above it could not be confirmed"
        }
        Refusal::StickyNext { .. } => "a shared folder above it holds a name that is not yours",
        Refusal::Last => "it is not yours alone to change",
        Refusal::NotLocal => "it is not on a local file system",
    }
}

fn record_text(e: &RecordError) -> String {
    match e {
        RecordError::Io(_) => "reading it did not finish".into(),
        RecordError::Absent => "no record".into(),
        RecordError::StateRoot(_) => "the state folder is not safe".into(),
        RecordError::NotAFile => "it is not a plain file".into(),
        RecordError::Owner => "it is not owned by you".into(),
        RecordError::Mode(m) => format!("its mode is {m:o}, not 600"),
        RecordError::Links(n) => format!("it has {n} links"),
        RecordError::TooBig(_) => "it is too big".into(),
        RecordError::Format => "it is in another format".into(),
        RecordError::Acl => "an access list lets others change it".into(),
        RecordError::Ownership => "ownership could not be confirmed".into(),
        RecordError::Changed => "it changed while it was read".into(),
    }
}

/// Reads the settings the way the helper does, writing nothing. `Err` is
/// the fixed message and exit code of a root that cannot be used at all.
pub fn inspect_config(user: &User, env: &TrustedEnv) -> Result<Inspection, (String, u8)> {
    let mut groups = SystemGroups::new(&user.pw.name);
    let (pin, state, written) = match ctx::pinned_roots(user)? {
        Some(Roots {
            config: Some(pin),
            state,
            ..
        }) => {
            let written = pin.written.clone();
            (pin, state, written)
        }
        _ => {
            let written = roots::config_candidate(env, &user.pw.home);
            let pin = ConfigRootPin::check(&written, user.me, &mut groups)
                .map_err(|e| (en(MsgId::UnconfirmedRoot).to_owned(), ctx::io_exit(&e)))?;
            (pin, roots::state_root(env, &user.pw.home), written)
        }
    };
    let (root, root_notice) = (pin.path.clone(), pin.shape_only_notice());
    let session = state
        .as_deref()
        .map(|s| trust_record::read_session(s, user.me, &mut groups));
    let places = Places {
        config_root: pin,
        home: user.pw.home.clone(),
        me: user.me,
        user: user.pw.name.clone(),
    };
    let (mut loader, selection) = match session {
        Some(Ok(evidence)) => {
            let record = evidence.record.clone();
            (
                Loader::with_record(places, evidence),
                Selection::Chosen(record),
            )
        }
        Some(Err(RecordError::Absent))
        | Some(Err(RecordError::StateRoot(RootError::Open {
            errno: libc::ENOENT,
            ..
        })))
        | None => (Loader::new(places), Selection::None),
        Some(Err(e)) if e.incomplete() => (Loader::new(places), Selection::Incomplete),
        Some(Err(e)) => (Loader::new(places), Selection::Unusable(record_text(&e))),
    };
    let roots_in = loader.roots(BUILTIN_TOML.as_bytes());
    let loaded = load(roots_in, &mut loader, ctx::version());
    let report = report::from_loaded(loaded, Mode::Dark);
    let before = loader.io_used();
    let verdict = if matches!(selection, Selection::Incomplete) {
        Verified::Incomplete
    } else {
        loader.verified(&report.files, report.snapshot.is_some())
    };
    // A refresh round checks its sources three times, this reading once: the
    // other two count here, so `check` refuses what a refresh would.
    let after = loader.io_used();
    let remaining: AxisUse = std::array::from_fn(|i| (after[i] - before[i]).saturating_mul(2));
    let over_cap = loader.io_fits(&remaining).is_err();
    let mut remedies: Vec<String> = Vec::new();
    if over_cap {
        remedies.push(en(MsgId::ReloadOverCap).to_owned());
    }
    for (_, r) in &loader.remedies {
        if !remedies.contains(r) {
            remedies.push(r.clone());
        }
    }
    let reason = |key: FileKey| {
        loader
            .untrusted
            .iter()
            .find(|(k, _, _)| *k == key)
            .map(|(_, _, Untrusted::Unsafe(r))| refusal_text(*r).to_owned())
    };
    let lines = report
        .files
        .iter()
        .map(|f| FileLine {
            written: loader
                .written_path(f.opened.key)
                .filter(|w| w.as_os_str().as_encoded_bytes() != f.opened.display)
                .map(std::path::Path::to_path_buf),
            unsafe_reason: reason(f.opened.key),
        })
        .collect();
    if let Selection::Chosen(r) = &selection {
        let still = report.files.iter().any(|f| {
            f.opened.display == r.path.as_os_str().as_encoded_bytes()
                && f.trust == Trust::Executable
        });
        if !still {
            remedies.push(format!(
                "your chosen settings file {} is not trusted any more (it moved, changed owner or became writable by others); choose it again with: bingsu config use {}",
                ctx::show(&r.path),
                ctx::show(&r.path)
            ));
        }
    }
    if let Selection::Unusable(why) = &selection {
        remedies.push(format!(
            "the record of your chosen settings file cannot be used ({why}); choose the file again with: bingsu config use PATH"
        ));
    }
    Ok(Inspection {
        root,
        root_written: written,
        root_notice,
        selection,
        report,
        lines,
        verdict,
        over_cap,
        remedies,
    })
}

fn trust_label(f: &Found, line: &FileLine) -> String {
    match f.trust {
        Trust::Executable => "trusted".into(),
        Trust::ShapeOnly => "colors and layout only".into(),
        Trust::Unsafe => format!(
            "nothing in it runs: {}",
            line.unsafe_reason
                .as_deref()
                .unwrap_or("it failed the safety check")
        ),
    }
}

fn selection_line(s: &Selection) -> String {
    match s {
        Selection::Incomplete => {
            "selection: could not read the choice; inspection is incomplete".into()
        }
        Selection::None => "selection: config.toml in the settings folder".into(),
        Selection::Chosen(r) => format!(
            "selection: {} (from bingsu config use; it stands in config.toml's place, conf.d and config.local.toml still apply)",
            ctx::show(&r.path)
        ),
        Selection::Unusable(why) => {
            format!("selection: record unusable ({why}); config.toml is read")
        }
    }
}

fn applied_order(i: &Inspection) -> Vec<usize> {
    i.report.order.iter().map(|id| id.0 as usize).collect()
}

/// `config path`: what is read, in which order, and why a file is left out.
pub fn render_path(i: &Inspection) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "{}", selection_line(&i.selection));
    out.push_str("applied, in order:\n");
    let order = applied_order(i);
    for (n, idx) in order.iter().enumerate() {
        let (Some(f), Some(line)) = (i.report.files.get(*idx), i.lines.get(*idx)) else {
            continue;
        };
        let shown = ctx::show(&PathBuf::from(
            <std::ffi::OsStr as std::os::unix::ffi::OsStrExt>::from_bytes(&f.opened.display),
        ));
        let _ = writeln!(out, "  {}. {shown}", n + 1);
        if let Some(w) = &line.written {
            let _ = writeln!(out, "     written as: {}", ctx::show(w));
        }
        let _ = writeln!(out, "     {}", trust_label(f, line));
    }
    let left: Vec<usize> = (0..i.report.files.len())
        .filter(|idx| !order.contains(idx))
        .collect();
    if !left.is_empty() {
        out.push_str("not applied:\n");
        for idx in left {
            let (f, line) = (&i.report.files[idx], &i.lines[idx]);
            let shown = ctx::show(&PathBuf::from(
                <std::ffi::OsStr as std::os::unix::ffi::OsStrExt>::from_bytes(&f.opened.display),
            ));
            let why = match f.status {
                Status::Dropped => {
                    "left out: an error in a file that only shapes the look; see bingsu config check"
                }
                Status::Failed => "failed: see bingsu config check",
                Status::Applied => "read but not applied",
            };
            let _ = writeln!(out, "  {shown}\n     {why}\n     {}", trust_label(f, line));
        }
    }
    if matches!(i.verdict, Verified::Incomplete) {
        out.push_str("result: could not read everything; the applied list is incomplete\n");
    }
    out
}

fn width_line(from: u16, to: u16, band: Option<&str>) -> String {
    let span = if to == u16::MAX {
        format!("{from}+")
    } else if from == to {
        format!("{from}")
    } else {
        format!("{from}-{to}")
    };
    let name = band.map_or("(default layout)".to_owned(), |b| {
        bingsu_core::sanitize::sanitize(b.as_bytes())
    });
    format!("  {span:<10} {name}")
}

/// `config check`: the report, every diagnostic, the way out of each
/// problem, the width table and the verdict.
pub fn render_check(i: &Inspection) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "settings folder: {}", ctx::show(&i.root));
    if i.root_written != i.root {
        let _ = writeln!(out, "  written as: {}", ctx::show(&i.root_written));
    }
    if let Some([what, why]) = &i.root_notice {
        let _ = writeln!(out, "  {what}\n  {why}");
    }
    let _ = writeln!(out, "{}", selection_line(&i.selection));
    out.push_str("files, in the order they apply:\n");
    let order = applied_order(i);
    for (n, idx) in order.iter().enumerate() {
        let (f, line) = (&i.report.files[*idx], &i.lines[*idx]);
        let shown = ctx::show(&PathBuf::from(
            <std::ffi::OsStr as std::os::unix::ffi::OsStrExt>::from_bytes(&f.opened.display),
        ));
        let _ = writeln!(out, "  {}. {shown} ({})", n + 1, trust_label(f, line));
    }
    let d = &i.report.diagnostics;
    let count = |s: Severity| d.iter().filter(|x| x.severity() == s).count();
    let _ = writeln!(
        out,
        "diagnostics: {} error(s), {} warning(s), {} note(s)",
        count(Severity::Error),
        count(Severity::Warning),
        count(Severity::Note)
    );
    let catalog = Catalog(&i.report.files);
    for x in d {
        let _ = writeln!(out, "{}\n", render_human(x, &catalog));
    }
    if !i.remedies.is_empty() {
        out.push_str("how to fix:\n");
        for r in &i.remedies {
            let _ = writeln!(out, "  - {}", bingsu_core::sanitize::sanitize(r.as_bytes()));
        }
    }
    out.push_str("widths (columns -> layout):\n");
    if i.report.widths.is_empty() {
        out.push_str("  (not available while an error remains)\n");
    }
    for w in &i.report.widths {
        let _ = writeln!(out, "{}", width_line(w.from, w.to, w.band.as_deref()));
    }
    let _ = writeln!(out, "result: {}", verdict_text(i));
    out
}

fn verdict_text(i: &Inspection) -> &'static str {
    match (&i.selection, &i.verdict) {
        (Selection::Unusable(_), _) => "not usable until the selection record is fixed",
        _ if i.over_cap => "too many file reads for one refresh; nothing would be published",
        (_, Verified::Incomplete) => "could not read everything; nothing would be published",
        (_, Verified::Invalid) => "invalid; the prompt keeps the last good settings",
        (_, Verified::Publish { left_out }) if left_out.is_empty() => "valid",
        (_, Verified::Publish { .. }) => "valid; some files are left out (see above)",
    }
}

/// 0 valid, 1 a confirmed settings or trust problem, 3 not read to the end.
pub fn exit_for(i: &Inspection) -> u8 {
    match (&i.selection, &i.verdict) {
        (Selection::Unusable(_), _) => EXIT_FAILED,
        _ if i.over_cap => EXIT_UNFINISHED,
        (_, Verified::Invalid) => EXIT_FAILED,
        (_, Verified::Incomplete) => EXIT_UNFINISHED,
        (_, Verified::Publish { .. }) => 0,
    }
}

/// Where `word` (a unit's `argv[0]`) would be found: an absolute path as
/// written, a bare name in the first absolute `PATH` folder that has it as a
/// file. A relative path is never looked up. Only `config check` asks, to
/// warn early; finding the file a unit runs is the executor's own step.
fn locate(word: &str, path: Option<&std::ffi::OsStr>) -> Option<PathBuf> {
    if word.starts_with('/') {
        return Some(PathBuf::from(word));
    }
    if word.contains('/') {
        return None;
    }
    std::env::split_paths(path?)
        .filter(|d| d.is_absolute())
        .map(|d| d.join(word))
        .find(|f| f.is_file())
}

/// Whether the file starts with `#!/usr/bin/env`. Read like other optional
/// inputs of this crate: nonblocking, no controlling terminal, a regular file
/// only, and at most the first line's worth of bytes.
fn starts_with_env_shebang(file: &std::path::Path) -> bool {
    use std::io::Read as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    let Ok(mut f) = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_NOCTTY | libc::O_CLOEXEC)
        .open(file)
    else {
        return false;
    };
    if !f.metadata().is_ok_and(|m| m.is_file()) {
        return false;
    }
    // One read: a regular file gives the whole first 256 bytes at once.
    let mut head = [0u8; 256];
    let Ok(n) = f.read(&mut head) else {
        return false;
    };
    let Some(rest) = head[..n].strip_prefix(b"#!") else {
        return false;
    };
    let rest = rest.trim_ascii_start();
    let end = rest
        .iter()
        .position(|b| b.is_ascii_whitespace())
        .unwrap_or(rest.len());
    &rest[..end] == b"/usr/bin/env"
}

/// W411 for each unit that would run a script whose first line is
/// `#!/usr/bin/env`: the executor refuses such a script, so `config check`
/// says so before it is ever tried. Reads files only here, never in a
/// refresh or the prompt.
fn env_shebang_notes(report: &ConfigReport, path: Option<&std::ffi::OsStr>) -> Vec<Diagnostic> {
    use bingsu_core::config::compile::ExecPolicy;
    let Some(c) = &report.snapshot else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for u in c.exec_units.iter().filter(|u| u.not_run.is_none()) {
        let ExecPolicy::Command { argv, .. } = &u.policy else {
            continue;
        };
        let (Some(word), Some((_, o))) =
            (argv.first(), u.origins.iter().find(|(k, _)| k == "command"))
        else {
            continue;
        };
        let Some(file) = locate(word, path).filter(|f| starts_with_env_shebang(f)) else {
            continue;
        };
        out.push(
            Diagnostic::new(
                codes::ENV_SHEBANG,
                Place::Source {
                    id: o.source,
                    span: o.span,
                },
            )
            .arg("id", u.id.clone())
            .arg("path", ctx::show(&file)),
        );
    }
    out
}

fn run_with(
    render: fn(&Inspection) -> String,
    exit: fn(&Inspection) -> u8,
    scripts: bool,
) -> ExitCode {
    let Some(user) = User::current() else {
        eprintln!("{}", en(MsgId::NoHome));
        return ctx::code(EXIT_FAILED);
    };
    let env = TrustedEnv::capture();
    match inspect_config(&user, &env) {
        Ok(mut i) => {
            if scripts {
                let notes = env_shebang_notes(&i.report, env.path.as_deref());
                i.report.diagnostics.extend(notes);
            }
            if !ctx::print(&render(&i)) {
                return ctx::code(EXIT_FAILED);
            }
            ctx::code(exit(&i))
        }
        Err((text, code)) => {
            eprintln!("{text}");
            ctx::code(code)
        }
    }
}

pub fn check() -> ExitCode {
    run_with(render_check, exit_for, true)
}

/// `config path` lists; it does not judge, so it succeeds whenever it could
/// read the folder.
pub fn path() -> ExitCode {
    run_with(render_path, path_exit, false)
}

fn path_exit(i: &Inspection) -> u8 {
    if matches!(i.verdict, Verified::Incomplete) {
        EXIT_UNFINISHED
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bingsu_core::config::source::{ExtendsRef, OpenError, Opened, Resolver};

    struct NoFiles;
    impl Resolver for NoFiles {
        fn open(&mut self, _: &Opened, _: &ExtendsRef) -> Result<Opened, OpenError> {
            panic!("no source files")
        }
    }

    fn report_of(user: &str) -> ConfigReport {
        let roots: Vec<_> = [BUILTIN_TOML, user]
            .iter()
            .enumerate()
            .map(|(i, text)| Opened {
                key: FileKey {
                    dev: 1,
                    ino: i as u64,
                },
                bytes: text.as_bytes().to_vec(),
                trust: Trust::Executable,
                display: vec![b'a' + i as u8],
            })
            .collect();
        report::report(roots, &mut NoFiles, [0, 3, 0], Mode::Dark)
    }

    // 실행 파일의 첫 줄이 `#!/usr/bin/env`이면 config check가 W411로 미리 알린다(실행기는 그 스크립트를 거부).
    // 이것을 실패시키는 것: W411 push를 지우는 것, 인터프리터 비교를 `starts_with(b"/usr/bin/env")`로 넓히는 것
    // (`/usr/bin/envx`도 경고), PATH 찾기를 지우는 것(맨 이름이 경고 없이 지나감), 상대 PATH 폴더 제외를 지우는 것,
    // PATH 폴더에 그 파일이 있는지 보지 않는 것(빈 폴더에서 멈춤), 일반 파일 검사를 지우는 것(FIFO를 읽음),
    // 실행하지 않는 단위까지 보는 것, 상대 argv[0]을 PATH에서 찾는 것.
    #[test]
    fn test_env_shebang_warned() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = std::env::temp_dir().join(format!("bingsu-env-shebang-{}", std::process::id()));
        std::fs::create_dir(&dir).unwrap();
        let script = |name: &str, text: &str| {
            let f = dir.join(name);
            std::fs::write(&f, text).unwrap();
            std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o755)).unwrap();
            f
        };
        let env = script("env-py", "#!/usr/bin/env python3\nprint(1)\n");
        let spaced = script("env-sp", "#! /usr/bin/env  sh\n");
        let abs = script("abs-sh", "#!/bin/sh\necho 1\n");
        let other = script("envx", "#!/usr/bin/envx sh\n");
        let seg = |id: &str, word: &str| {
            format!(
                "[segment.\"custom/{id}\"]\nkind = \"command\"\ncommand = [\"{word}\"]\n[layout.line1]\nleft = [\"custom/{id}\"]\n"
            )
        };
        let warned = |user: &str, path: Option<&std::ffi::OsStr>| -> Vec<String> {
            env_shebang_notes(&report_of(user), path)
                .iter()
                .map(|d| {
                    assert_eq!(d.code, codes::ENV_SHEBANG);
                    d.args
                        .iter()
                        .find(|a| a.name == "id")
                        .unwrap()
                        .value
                        .clone()
                })
                .collect()
        };
        let path = |f: &std::path::Path| f.to_str().unwrap().to_owned();
        assert_eq!(warned(&seg("a", &path(&env)), None), ["custom/a"]);
        assert_eq!(warned(&seg("a", &path(&spaced)), None), ["custom/a"]);
        assert_eq!(warned(&seg("a", &path(&abs)), None), Vec::<String>::new());
        assert_eq!(warned(&seg("a", &path(&other)), None), Vec::<String>::new());
        // A bare name is looked up in PATH: the first absolute folder that
        // has it as a file. A relative folder is skipped even when it names
        // the same folder from here.
        let empty = dir.join("empty");
        std::fs::create_dir(&empty).unwrap();
        let up = std::env::current_dir().unwrap().components().count() - 1;
        let relative = format!(
            "{}{}",
            "../".repeat(up),
            dir.to_str().unwrap().trim_start_matches('/')
        );
        assert!(std::path::Path::new(&relative).join("env-py").is_file());
        let found = std::ffi::OsString::from(format!("{}:{}", empty.display(), dir.display()));
        assert_eq!(warned(&seg("a", "env-py"), Some(&found)), ["custom/a"]);
        // A relative argv[0] is never looked up, even where PATH has it.
        assert_eq!(
            warned(&seg("a", "./env-py"), Some(&found)),
            Vec::<String>::new()
        );
        let rel = std::ffi::OsString::from(relative);
        assert_eq!(
            warned(&seg("a", "env-py"), Some(&rel)),
            Vec::<String>::new()
        );
        // Only a regular file is read: a FIFO holding the same first line is not.
        let fifo = dir.join("fifo");
        assert!(
            std::process::Command::new("mkfifo")
                .arg(&fifo)
                .status()
                .unwrap()
                .success()
        );
        let keep = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&fifo)
            .unwrap();
        assert!(matches!(
            crate::commands::sys::write_fd(
                std::os::fd::AsRawFd::as_raw_fd(&keep),
                b"#!/usr/bin/env sh\n"
            ),
            crate::commands::sys::WriteOutcome::Done
        ));
        assert!(!starts_with_env_shebang(&fifo));
        drop(keep);
        // A unit that does not run is not looked at.
        let off = seg("a", &path(&env)).replace("kind = ", "enabled = false\nkind = ");
        assert_eq!(warned(&off, None), Vec::<String>::new());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn incomplete_path_explains_the_partial_list_and_exits_3() {
        let mut i = Inspection {
            root: "/config".into(),
            root_written: "/config".into(),
            root_notice: None,
            selection: Selection::None,
            report: ConfigReport {
                files: vec![],
                order: vec![],
                diagnostics: vec![],
                widths: vec![],
                snapshot: None,
            },
            lines: vec![],
            verdict: Verified::Incomplete,
            over_cap: false,
            remedies: vec![],
        };
        assert_eq!(path_exit(&i), 3);
        assert!(
            render_path(&i).contains("could not read everything; the applied list is incomplete")
        );
        i.verdict = Verified::Invalid;
        assert_eq!(path_exit(&i), 0);
    }
}
