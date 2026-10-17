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
use bingsu_core::{
    color::palette::Mode,
    config::{
        compile::BUILTIN_TOML,
        report::{self, ConfigReport},
        source::{Catalog, FileKey, Found, Status, Trust, load},
    },
    diag::{Severity, render_human},
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
    let verdict = if matches!(selection, Selection::Incomplete) {
        Verified::Incomplete
    } else {
        loader.verified(&report.files, report.snapshot.is_some())
    };
    let mut remedies: Vec<String> = Vec::new();
    for r in &loader.remedies {
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
        (_, Verified::Incomplete) => "could not read everything; nothing would be published",
        (_, Verified::Invalid) => "invalid; the prompt keeps the last good settings",
        (_, Verified::Publish { left_out }) if left_out.is_empty() => "valid",
        (_, Verified::Publish { .. }) => "valid; some files are left out (see above)",
    }
}

/// 0 valid, 1 a confirmed settings or trust problem, 3 not read to the end.
pub fn exit_for(i: &Inspection) -> u8 {
    match (&i.selection, &i.verdict) {
        (Selection::Unusable(_), _) | (_, Verified::Invalid) => EXIT_FAILED,
        (_, Verified::Incomplete) => EXIT_UNFINISHED,
        (_, Verified::Publish { .. }) => 0,
    }
}

fn run_with(render: fn(&Inspection) -> String, exit: fn(&Inspection) -> u8) -> ExitCode {
    let Some(user) = User::current() else {
        eprintln!("{}", en(MsgId::NoHome));
        return ctx::code(EXIT_FAILED);
    };
    match inspect_config(&user, &TrustedEnv::capture()) {
        Ok(i) => {
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
    run_with(render_check, exit_for)
}

/// `config path` lists; it does not judge, so it succeeds whenever it could
/// read the folder.
pub fn path() -> ExitCode {
    run_with(render_path, path_exit)
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
