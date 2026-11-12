//! `bingsu config check` and `bingsu config path`: one read of the settings
//! through the same pieces the helper uses (R's `Loader` and `trust_record`
//! session, S's `report`), shown instead of published. Nothing is written:
//! no folder is made, no lock is taken, no snapshot, marker, sequence or
//! selection record changes, and no configured command runs.
use super::{
    config_load::{Loader, Places, Untrusted, Verified},
    ctx::{self, EXIT_FAILED, EXIT_UNFINISHED, User},
    exec_path,
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
    let mut report = report::from_loaded(loaded, Mode::Dark);
    // The same `match` check the published snapshot gets (C4c ruling Q1).
    super::command_match::check(&mut report);
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

/// The `execution` array of the JSON output: the same units and the same
/// verdicts as `render_explain`, as data. Environment names only.
pub(super) fn units_json(
    w: &mut bingsu_core::diag_json::Writer,
    report: &ConfigReport,
    found: &[(String, exec_path::Explained)],
    only: Option<&str>,
) {
    use bingsu_core::config::explain::{self, From};
    use bingsu_core::diag::SourceView as _;
    let Some(c) = &report.snapshot else {
        w.null();
        return;
    };
    let catalog = Catalog(&report.files);
    let place = |f: &From| -> String {
        match f {
            From::Default => "default".into(),
            From::KeepList => "keep list".into(),
            From::Source(o) => {
                let (l, _) = bingsu_core::diag::line_col(catalog.bytes(o.source), o.span.start);
                format!(
                    "{}:{l}",
                    bingsu_core::sanitize::sanitize(catalog.display(o.source))
                )
            }
        }
    };
    w.begin_array();
    for u in explain::units(c)
        .iter()
        .filter(|u| only.is_none_or(|o| o == u.id))
    {
        let looked = found.iter().find(|(id, _)| *id == u.id).map(|(_, f)| f);
        // (runs, reason, code)
        let (runs, reason, code): (bool, Option<String>, Option<String>) = match &u.not_run {
            Some(n) => {
                let (text, code) = explain::not_run_text(n);
                (false, Some(text.to_owned()), code.map(|c| c.to_string()))
            }
            None => match looked {
                Some(exec_path::Explained::Absent) => (
                    false,
                    Some("not found on the sanitized PATH".to_owned()),
                    None,
                ),
                Some(exec_path::Explained::Refused { .. }) => {
                    (false, Some("its file is refused".to_owned()), None)
                }
                _ if u.kind == "language" => (
                    true,
                    Some("runs where its detect files are found".to_owned()),
                    None,
                ),
                _ => (true, None, None),
            },
        };
        w.begin_object();
        w.key("id").string(&u.id);
        w.key("kind").string(u.kind);
        w.key("runs").boolean(runs);
        w.key("reason").opt_string(reason.as_deref());
        w.key("code").opt_string(code.as_deref());
        w.key("rows").begin_array();
        for r in &u.rows {
            w.begin_object();
            w.key("key").string(r.key);
            w.key("value").string(&r.value);
            w.key("from").string(&place(&r.from));
            w.end_object();
        }
        w.end_array();
        w.key("environment").begin_array();
        for e in &u.environment {
            w.begin_object();
            w.key("name").string(&e.name);
            w.key("from").string(&place(&e.from));
            w.end_object();
        }
        w.end_array();
        let executable = match looked {
            Some(exec_path::Explained::Runs(f)) => Some(ctx::show(&f.executable)),
            Some(exec_path::Explained::Refused { file: Some(f), .. }) => Some(ctx::show(f)),
            _ => None,
        };
        w.key("executable").opt_string(executable.as_deref());
        w.end_object();
    }
    w.end_array();
}

/// `config check --format json`: the same facts as the text, as data.
fn check_json(i: &Inspection, units: Option<&[(String, exec_path::Explained)]>) -> String {
    use bingsu_core::diag_json::{self as j, Writer};
    use std::os::unix::ffi::OsStrExt as _;
    let mut w = Writer::new();
    w.begin_object();
    w.key("schema").number(u64::from(j::SCHEMA));
    w.key("command").string("config-check");
    w.key("settings_folder").string(&ctx::show(&i.root));
    let (kind, path, reason) = match &i.selection {
        Selection::None => ("none", None, None),
        Selection::Chosen(r) => ("chosen", Some(ctx::show(&r.path)), None),
        Selection::Unusable(why) => ("unusable", None, Some(why.clone())),
        Selection::Incomplete => ("incomplete", None, None),
    };
    w.key("selection").begin_object();
    w.key("kind").string(kind);
    w.key("path").opt_string(path.as_deref());
    w.key("reason").opt_string(reason.as_deref());
    w.end_object();
    w.key("files").begin_array();
    let order = applied_order(i);
    let rest: Vec<usize> = (0..i.report.files.len())
        .filter(|idx| !order.contains(idx))
        .collect();
    for idx in order.iter().chain(rest.iter()) {
        let (Some(f), Some(line)) = (i.report.files.get(*idx), i.lines.get(*idx)) else {
            continue;
        };
        w.begin_object();
        w.key("display").bytes(&f.opened.display);
        w.key("trust").string(match f.trust {
            Trust::Executable => "trusted",
            Trust::ShapeOnly => "shape-only",
            Trust::Unsafe => "unsafe",
        });
        w.key("status").string(match f.status {
            Status::Applied => "applied",
            Status::Dropped => "dropped",
            Status::Failed => "failed",
        });
        w.key("written_as");
        match &line.written {
            Some(p) => w.bytes(p.as_os_str().as_bytes()),
            None => w.null(),
        };
        w.key("unsafe_reason")
            .opt_string(line.unsafe_reason.as_deref());
        w.end_object();
    }
    w.end_array();
    w.key("diagnostics");
    j::diagnostics(&mut w, &i.report.diagnostics, &Catalog(&i.report.files));
    w.key("remedies").begin_array();
    for r in &i.remedies {
        w.string(r);
    }
    w.end_array();
    w.key("widths").begin_array();
    for x in &i.report.widths {
        w.begin_object();
        w.key("from").number(u64::from(x.from));
        w.key("to").number(u64::from(x.to));
        w.key("band").opt_string(x.band.as_deref());
        w.end_object();
    }
    w.end_array();
    w.key("result").string(verdict_text(i));
    w.key("exit_code").number(u64::from(exit_for(i)));
    w.key("execution");
    match units {
        Some(found) => units_json(&mut w, &i.report, found, None),
        None => {
            w.null();
        }
    }
    w.end_object();
    w.finish()
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

/// What the executor's own lookup finds for each unit that may run, by
/// unit id: the sanitized `PATH`, the same checks, nothing run. No folder
/// stands for a repository: a round leaves out what lies inside the one the
/// shell is in, which depends on where the prompt is, not on the settings
/// (the explain section says so). Only `config check` asks; the files are opened and read,
/// so a stopped mount on the way can hold the command (it never holds a
/// prompt or a refresh, which do not come here).
pub(super) fn lookups(
    report: &ConfigReport,
    path: Option<&std::ffi::OsStr>,
    me: u32,
    groups: &mut SystemGroups,
) -> Vec<(String, exec_path::Explained)> {
    use bingsu_core::config::compile::ExecPolicy;
    use std::os::unix::ffi::OsStrExt as _;
    let Some(c) = &report.snapshot else {
        return Vec::new();
    };
    // The units to look up first: with none, `PATH` is not walked at all
    // (E2 review M2; a stopped mount on it cannot hold a plain check).
    let words: Vec<(String, &str)> = c
        .exec_units
        .iter()
        .filter(|u| u.not_run.is_none())
        .filter_map(|u| {
            let word: &str = match &u.policy {
                ExecPolicy::Command { shell: Some(_), .. } => "/bin/sh",
                ExecPolicy::Command { argv, .. } => argv.first()?,
                // A language unit runs its interpreter (D3c-2).
                // Fails without it: explain_shows_shell_relative_and_language_units.
                ExecPolicy::Language { interpreter, .. } => interpreter.as_deref()?,
            };
            Some((u.id.clone(), word))
        })
        .collect();
    // Fails without it: test_check_walks_no_path_without_commands.
    if words.is_empty() {
        return Vec::new();
    }
    let repo: &[_] = &[];
    #[cfg(test)]
    tests::PATH_WALKS.with(|n| n.set(n.get() + 1));
    let folders = exec_path::sanitize(path.map_or(&b""[..], |p| p.as_bytes()), repo, me, groups);
    words
        .into_iter()
        .map(|(id, word)| {
            let found = exec_path::explain(word.as_bytes(), &folders, repo, me, groups);
            (id, found)
        })
        .collect()
}

/// Why the executor refuses a setuid, setgid or file-capability program
/// (U-33), for W411 and `--explain`.
const SET_ID_REASON: &str = "setuid, setgid or file capabilities (bingsu runs no such program)";

/// W411 for each unit whose script the executor refuses by its first line,
/// or whose program is set-id (U-33) (D3a/E2 ruling Q2: one code, the reason
/// as its argument). The decision is the executor's (`exec_path::explain`,
/// core `head`), so `config check` warns about exactly what will not run.
fn env_shebang_notes(
    report: &ConfigReport,
    found: &[(String, exec_path::Explained)],
) -> Vec<Diagnostic> {
    let Some(c) = &report.snapshot else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (id, f) in found {
        let (file, why) = match f {
            exec_path::Explained::Refused {
                file: Some(file),
                set_id: true,
                ..
            } => (file, SET_ID_REASON),
            exec_path::Explained::Refused {
                file: Some(file),
                script: Some(why),
                ..
            } => (file, why.text()),
            _ => continue,
        };
        let Some(u) = c.exec_units.iter().find(|u| &u.id == id) else {
            continue;
        };
        let Some((_, o)) = u
            .origins
            .iter()
            .find(|(k, _)| k == "command" || k == "shell")
        else {
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
            .arg("id", id.clone())
            .arg("path", ctx::show(file))
            .arg("reason", why),
        );
    }
    out
}

/// `config check --explain`: for each command and language segment, whether
/// it runs and why not, what it runs, and each value with its origin
/// (`file:line`). Environment names only: the model holds no value.
pub(super) fn render_explain(
    report: &ConfigReport,
    found: &[(String, exec_path::Explained)],
    only: Option<&str>,
) -> String {
    use bingsu_core::config::explain::{self, From};
    let mut out = String::from(
        "execution (--explain; executables as found outside any repository, which a prompt inside one may leave out):\n",
    );
    let Some(c) = &report.snapshot else {
        out.push_str("  (not available while an error remains)\n");
        return out;
    };
    let mut units = explain::units(c);
    if let Some(only) = only {
        units.retain(|u| u.id == only);
    }
    if units.is_empty() {
        out.push_str("  no command or language segments\n");
    }
    let catalog = Catalog(&report.files);
    let clean = |t: &str| bingsu_core::sanitize::sanitize(t.as_bytes());
    let place = |f: &From| -> String {
        use bingsu_core::diag::SourceView as _;
        match f {
            From::Default => "default".into(),
            From::KeepList => "keep list".into(),
            From::Source(o) => {
                let (l, _) = bingsu_core::diag::line_col(catalog.bytes(o.source), o.span.start);
                format!(
                    "{}:{l}",
                    bingsu_core::sanitize::sanitize(catalog.display(o.source))
                )
            }
        }
    };
    for u in &units {
        let looked = found.iter().find(|(id, _)| *id == u.id).map(|(_, f)| f);
        match &u.not_run {
            // The lookup decides too: a unit whose file is refused or not
            // found will not run, as W411 says (E2 review M1).
            // Fails without it: explain_shows_limits_cwd_shell_and_the_sanitized_lookup.
            None => match looked {
                Some(exec_path::Explained::Absent) => {
                    let _ = writeln!(
                        out,
                        "{}  {}, will not run: not found on the sanitized PATH",
                        clean(&u.id),
                        u.kind
                    );
                }
                Some(exec_path::Explained::Refused { .. }) => {
                    let _ = writeln!(
                        out,
                        "{}  {}, will not run: its file is refused (see executable)",
                        clean(&u.id),
                        u.kind
                    );
                }
                // A language unit runs only where its marker files are
                // found (D3c-2). Fails without it:
                // explain_shows_shell_relative_and_language_units.
                _ if u.kind == "language" => {
                    let _ = writeln!(
                        out,
                        "{}  {}, runs where its detect files are found",
                        clean(&u.id),
                        u.kind
                    );
                }
                _ => {
                    let _ = writeln!(out, "{}  {}, runs", clean(&u.id), u.kind);
                }
            },
            Some(n) => {
                let (text, code) = explain::not_run_text(n);
                let code = code.map(|c| format!(" ({c})")).unwrap_or_default();
                let _ = writeln!(out, "{}  {}, not run: {text}{code}", clean(&u.id), u.kind);
            }
        }
        for r in &u.rows {
            let _ = writeln!(
                out,
                "  {:<10} {:<36} {}",
                r.key,
                clean(&r.value),
                place(&r.from)
            );
        }
        for e in &u.environment {
            let _ = writeln!(
                out,
                "  {:<10} {:<36} {}",
                "env",
                clean(&e.name),
                place(&e.from)
            );
        }
        if let Some(f) = looked {
            let line = match f {
                exec_path::Explained::Runs(found) => ctx::show(&found.executable).to_string(),
                exec_path::Explained::Absent => "not found on the sanitized PATH".into(),
                exec_path::Explained::Refused {
                    file,
                    script,
                    set_id,
                } => format!(
                    "{} refused{}",
                    file.as_deref().map(ctx::show).unwrap_or_default(),
                    if *set_id {
                        format!(": {SET_ID_REASON}")
                    } else {
                        script
                            .map(|s| format!(": {}", s.text()))
                            .unwrap_or_default()
                    }
                ),
            };
            let _ = writeln!(out, "  {:<10} {line}", "executable");
        }
    }
    out
}

/// The builtin language section of `--explain` (`explain_builtin`), from
/// the roots init pinned (else the current ones, found without making or
/// changing anything), this process's environment and the shell's folder.
/// With no builtin language drawn, nothing is looked up.
fn builtin_section(i: &Inspection, user: &User, env: &TrustedEnv) -> String {
    use super::explain_builtin as b;
    let Some(c) = &i.report.snapshot else {
        return String::new();
    };
    // With the roots now read only, no test fails without this return (the
    // output and the files are the same); it stays so a layout without a
    // builtin language reads nothing more and waits on no stalled mount.
    if b::drawn(c).is_empty() {
        return String::new();
    }
    let place = place_of(user, env);
    let (environment, pwd) = TrustedEnv::shell();
    let cwd = b::shell_folder(pwd.as_deref());
    b::section(
        c,
        place.as_ref(),
        &environment,
        cwd.as_deref(),
        crate::prompt_io::observe_clock().ok(),
        user.me,
        &mut SystemGroups::new(&user.pw.name),
    )
}

/// The runtime folder and roots of the saved folder facts. The pinned
/// roots when init exported them (asked only then: without a pin
/// `pinned_roots` says so on stderr); else the current candidates, read
/// only: `roots::resolve` would make the runtime folder or fix its mode,
/// which a check must not do. Fails without it: explain_writes_nothing.
pub(super) fn place_of(user: &User, env: &TrustedEnv) -> Option<super::explain_builtin::Place> {
    use std::os::unix::{ffi::OsStrExt, fs::MetadataExt};
    let pinned = TrustedEnv::pinned_roots()
        .is_some()
        .then(|| ctx::pinned_roots(user).ok().flatten())
        .flatten();
    let (runtime, config, state) = match pinned {
        Some(r) => {
            let rt = r.runtime?;
            (
                super::runtime_root::Pinned {
                    dev: rt.dev,
                    ino: rt.ino,
                    path: rt.path,
                },
                r.config?.path,
                r.state?,
            )
        }
        None => {
            let path = std::fs::canonicalize(roots::runtime_candidate(env, &user.pw.home)).ok()?;
            let m = std::fs::symlink_metadata(&path).ok()?;
            let config = ConfigRootPin::check(
                &roots::config_candidate(env, &user.pw.home),
                user.me,
                &mut SystemGroups::new(&user.pw.name),
            )
            .ok()?
            .path;
            (
                super::runtime_root::Pinned {
                    dev: m.dev(),
                    ino: m.ino(),
                    path,
                },
                config,
                roots::state_root(env, &user.pw.home)?,
            )
        }
    };
    Some(super::explain_builtin::Place {
        runtime,
        config: config.as_os_str().as_bytes().to_vec(),
        state: state.as_os_str().as_bytes().to_vec(),
    })
}

/// What `run_with` adds to the reading: nothing (`config path`), the
/// executor's lookups and W411 (`config check`), and the execution section
/// (`config check --explain`).
#[derive(Clone, Copy, PartialEq, Eq)]
enum Extra {
    None,
    Scripts,
    Explain,
}

fn run_with(
    render: fn(&Inspection) -> String,
    exit: fn(&Inspection) -> u8,
    extra: Extra,
    json: bool,
) -> ExitCode {
    let Some(user) = User::current() else {
        eprintln!("{}", en(MsgId::NoHome));
        return ctx::code(EXIT_FAILED);
    };
    let env = TrustedEnv::capture();
    match inspect_config(&user, &env) {
        Ok(mut i) => {
            let found = match extra {
                Extra::None => Vec::new(),
                Extra::Scripts | Extra::Explain => lookups(
                    &i.report,
                    env.path.as_deref(),
                    user.me,
                    &mut SystemGroups::new(&user.pw.name),
                ),
            };
            let notes = env_shebang_notes(&i.report, &found);
            i.report.diagnostics.extend(notes);
            if json {
                let units = (extra == Extra::Explain).then_some(found.as_slice());
                if !ctx::print(&check_json(&i, units)) {
                    return ctx::code(EXIT_FAILED);
                }
                return ctx::code(exit(&i));
            }
            let mut text = render(&i);
            // Fails without it: explain_shows_not_run_reason.
            if extra == Extra::Explain {
                text.push_str(&render_explain(&i.report, &found, None));
                text.push_str(&builtin_section(&i, &user, &env));
            }
            if !ctx::print(&text) {
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

pub fn check(json: bool) -> ExitCode {
    run_with(render_check, exit_for, Extra::Scripts, json)
}

/// `config check --explain`: `check`, then the execution section.
pub fn check_explain(json: bool) -> ExitCode {
    run_with(render_check, exit_for, Extra::Explain, json)
}

/// `config path` lists; it does not judge, so it succeeds whenever it could
/// read the folder.
pub fn path() -> ExitCode {
    run_with(render_path, path_exit, Extra::None, false)
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
    thread_local! {
        /// `PATH` walks of `lookups` (E2 review M2).
        pub(super) static PATH_WALKS: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
    }

    // 실행할 명령 단위가 없으면 config check는 PATH를 걷지 않는다(멈춘 마운트가 기본 설정의 check까지 붙잡지
    // 않게, E2 리뷰 M2). 이것을 실패시키는 것: 조회할 단위를 고르기 전에 PATH를 정제하는 것.
    #[test]
    fn test_check_walks_no_path_without_commands() {
        let me = crate::commands::sys::current_uid();
        let mut groups = SystemGroups::new(&crate::commands::sys::passwd_entry(me).unwrap().name);
        let path = std::ffi::OsString::from("/usr/bin:/bin");
        let walks = || PATH_WALKS.with(std::cell::Cell::get);
        let before = walks();
        let none = report_of("[layout.line1]\nleft = [\"dir\"]\n");
        assert!(lookups(&none, Some(&path), me, &mut groups).is_empty());
        let off = report_of(
            "[segment.\"custom/a\"]\nkind = \"command\"\nenabled = false\ncommand = [\"/bin/echo\"]\n[layout.line1]\nleft = [\"custom/a\"]\n",
        );
        assert!(lookups(&off, Some(&path), me, &mut groups).is_empty());
        assert_eq!(walks(), before);
        let one = report_of(
            "[segment.\"custom/a\"]\nkind = \"command\"\ncommand = [\"echo\"]\n[layout.line1]\nleft = [\"custom/a\"]\n",
        );
        assert_eq!(lookups(&one, Some(&path), me, &mut groups).len(), 1);
        assert_eq!(walks(), before + 1);
    }

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

    // 실행기가 거부하는 첫 줄이면 config check가 W411로 미리 알린다. 판정은 실행기의 찾기·검사(exec_path::explain,
    // core head)이고 PATH는 정제한 것이다(E2, known-issues m6-A4a). 이것을 실패시키는 것: W411 push를 지우는 것,
    // `/usr/bin/envx`까지 경고하는 것, 맨 이름을 PATH에서 찾지 않는 것, 상대 PATH 폴더를 쓰는 것, FIFO를 읽는 것,
    // 실행하지 않는 단위까지 보는 것, 상대 argv[0]을 PATH에서 찾는 것, merged-/usr의 `/bin/env` 별칭을 놓치는 것.
    #[test]
    fn test_env_shebang_warned() {
        // It spawns mkfifo: between fork and exec the child holds every
        // descriptor of this process, a fixture's close-only flock included,
        // so a store test in another thread would see Busy. Spawning tests
        // hold the serial lock (sys::test_inherited_fd_lock).
        let _serial = crate::commands::sys::test_inherited_fd_lock();
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
            let report = report_of(user);
            let me = crate::commands::sys::current_uid();
            let mut groups =
                SystemGroups::new(&crate::commands::sys::passwd_entry(me).unwrap().name);
            env_shebang_notes(&report, &lookups(&report, path, me, &mut groups))
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
        // `/usr/bin/env` under another name (merged-/usr `/bin/env`) is the
        // same refusal; where `/bin/env` is not that file it is not.
        let alias = script("env-alias", "#!/bin/env sh\n");
        let merged = std::fs::canonicalize("/bin/env")
            .is_ok_and(|p| p == std::path::Path::new("/usr/bin/env"));
        assert_eq!(
            warned(&seg("a", &path(&alias)), None).len(),
            usize::from(merged),
            "/bin/env merged: {merged}"
        );
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
        let named = |f: &std::path::Path| seg("a", f.to_str().unwrap());
        assert_eq!(warned(&named(&fifo), None), Vec::<String>::new());
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
