//! `bingsu explain [SEGMENT] [--width N] [--config FILE]`: what the layout
//! decides at one width, in words. It makes the decisions with the prompt's
//! own render (`front::render_selected_recorded`, the one function body the
//! prompt uses) and a `DecisionLog`, so the report is what the prompt would
//! do with the same settings and values.
//!
//! It runs nothing: no collector, no helper, no configured command, no
//! snapshot is published, and nothing is written. Values a collector or a
//! command would bring are not there, so those segments show as `no-value`.
//! `--config FILE` reads that one file in place of the selected settings
//! (a file that uses `extends` is refused: it would read other files).
use super::{
    config_inspect::{inspect_config, lookups, place_of, render_explain},
    ctx::{self, EXIT_FAILED, EXIT_USAGE, User},
    group_policy::SystemGroups,
    init::trusted_env::TrustedEnv,
    messages::{MsgId, en},
    snapshot_store::{CheckedContextFd, DataFile},
};
use bingsu_core::{
    color::palette::Mode,
    config::{
        compile::{BUILTIN_TOML, CompiledConfig},
        report::{self, ConfigReport},
        source::{Catalog, ExtendsRef, FileKey, OpenError, Opened, Resolver, Root, Trust, load},
    },
    decision_text::{self, Names},
    diag::{Severity, render_human},
    envelope::Envelope,
    field::BUILTIN,
    recorder::DecisionLog,
    shell_word::Shell,
    shorten::Method,
    snapshot::{self, Snapshot},
};
use std::ffi::{OsStr, OsString};
use std::io::Read as _;
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::MetadataExt as _;
use std::process::ExitCode;

const USAGE: &str =
    "usage: bingsu explain [SEGMENT] [--width N] [--config FILE] [--format json|text]";
/// The widest file `--config` reads (the cap of one config file).
const FILE_MAX: u64 = 256 * 1024;
const DEFAULT_WIDTH: u16 = 80;

/// What the arguments asked for.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct Args {
    pub segment: Option<String>,
    pub width: Option<u16>,
    pub config: Option<OsString>,
    pub json: bool,
}

pub(super) fn parse(args: &[OsString]) -> Option<Args> {
    let mut out = Args {
        segment: None,
        width: None,
        config: None,
        json: false,
    };
    let mut format_seen = false;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.to_str()? {
            "--width" => {
                let n: u16 = it.next()?.to_str()?.parse().ok()?;
                if n == 0 || out.width.replace(n).is_some() {
                    return None;
                }
            }
            "--config" => {
                if out.config.replace(it.next()?.clone()).is_some() {
                    return None;
                }
            }
            "--format" => {
                out.json = match it.next()?.to_str()? {
                    "json" => true,
                    "text" => false,
                    _ => return None,
                };
                if std::mem::replace(&mut format_seen, true) {
                    return None;
                }
            }
            w if !w.starts_with('-') => {
                if out.segment.replace(w.to_owned()).is_some() {
                    return None;
                }
            }
            _ => return None,
        }
    }
    Some(out)
}

/// A resolver for a single file: `extends` is not followed.
struct NoExtends;

impl Resolver for NoExtends {
    fn open(&mut self, _: &Opened, _: &ExtendsRef) -> Result<Opened, OpenError> {
        Err(OpenError {
            reason: "explain --config does not follow `extends`".into(),
            trust: Trust::Executable,
        })
    }
}

fn read_file(path: &OsStr) -> Result<Opened, String> {
    let shown = ctx::show(std::path::Path::new(path));
    let f = std::fs::File::open(path).map_err(|e| format!("cannot open {shown}: {e}"))?;
    let m = f
        .metadata()
        .map_err(|e| format!("cannot read {shown}: {e}"))?;
    if !m.is_file() {
        return Err(format!("{shown} is not a regular file"));
    }
    let mut bytes = Vec::new();
    f.take(FILE_MAX + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| format!("cannot read {shown}: {e}"))?;
    Ok(Opened {
        key: FileKey {
            dev: m.dev(),
            ino: m.ino(),
        },
        bytes,
        // Nothing is run, so the file is read as the settings you would
        // have chosen; its ownership is not checked.
        trust: Trust::Executable,
        display: path.as_bytes().to_vec(),
    })
}

fn report_of_file(path: &OsStr) -> Result<ConfigReport, String> {
    let file = read_file(path)?;
    let builtin = Opened {
        key: FileKey { dev: 0, ino: 0 },
        bytes: BUILTIN_TOML.as_bytes().to_vec(),
        trust: Trust::Executable,
        display: b"(built-in)".to_vec(),
    };
    let roots = vec![Root::Read(builtin), Root::Read(file)];
    let mut report = report::from_loaded(load(roots, &mut NoExtends, ctx::version()), Mode::Dark);
    super::command_match::check(&mut report);
    Ok(report)
}

/// The settings the prompt draws with now: the snapshot the helper last
/// published for this boot and these roots, read through the store's own
/// checked reads. `None` when there is none (nothing published yet, another
/// boot, or a folder that fails the store's checks).
fn published(user: &User, env: &TrustedEnv) -> Option<CompiledConfig> {
    let place = place_of(user, env)?;
    let mut groups = SystemGroups::new(&user.pw.name);
    let store = CheckedContextFd::open(
        &place.runtime,
        &place.config,
        &place.state,
        user.me,
        &mut groups,
        false,
    )
    .ok()?;
    let context = snapshot::context_crc(&place.config, &place.state).ok()?;
    let boot = crate::prompt_io::observe_clock().ok()?.boot;
    let found = Snapshot::decode(&store.read(DataFile::Snapshot).ok()?).ok()?;
    snapshot::same_boot(found.id, Some(boot), context).then_some(found.config)
}

/// The decisions of `compiled` at `width`, with the prompt's own render.
pub(super) fn decide(
    compiled: &CompiledConfig,
    width: u16,
    pwd: Option<Vec<u8>>,
    home: Option<Vec<u8>>,
) -> (DecisionLog, Vec<u8>) {
    let env = Envelope {
        width,
        pwd,
        home,
        shell: Some(Shell::Zsh),
        ..Envelope::default()
    };
    decision_text::decide(compiled, &env, Mode::Dark)
}

/// The catalog order the prompt lays out with: built-ins, then user
/// segments in `custom` order.
pub(super) fn segment_ids(compiled: &CompiledConfig) -> Vec<&str> {
    BUILTIN
        .iter()
        .map(|d| d.id)
        .chain(compiled.custom.iter().map(|c| c.id.as_str()))
        .collect()
}

pub(super) fn text(
    compiled: &CompiledConfig,
    log: &DecisionLog,
    width: u16,
    only: Option<usize>,
) -> String {
    let ids = segment_ids(compiled);
    let methods: Vec<&[Method]> = compiled
        .setup
        .iter()
        .map(|s| s.methods.as_slice())
        .collect();
    decision_text::render(
        log,
        &Names {
            segments: &ids,
            bands: &compiled.band_names,
            methods: &methods,
        },
        width,
        only,
    )
}

/// What the decisions are made from (`basis` of the JSON output).
#[derive(Clone, Copy, PartialEq, Eq)]
enum Basis {
    Published,
    PublishedFilesChanged,
    PublishedFilesInvalid,
    FilesOnly,
    File,
}

impl Basis {
    const fn word(self) -> &'static str {
        match self {
            Self::Published => "published",
            Self::PublishedFilesChanged => "published-files-changed",
            Self::PublishedFilesInvalid => "published-files-invalid",
            Self::FilesOnly => "files-only",
            Self::File => "file",
        }
    }
    /// The line of the text output; none for a file given with `--config`.
    const fn line(self) -> Option<&'static str> {
        match self {
            Self::Published => {
                Some("basis: the published settings, which are the ones in your files\n")
            }
            Self::PublishedFilesChanged => Some(
                "basis: the published settings, which the prompt draws now; your files have changed since, and the next prompt draws the changed settings (bingsu config check shows them)\n",
            ),
            Self::PublishedFilesInvalid => Some(
                "basis: the published settings, which the prompt draws now; your files have errors, so the prompt keeps drawing these until they are fixed (bingsu config check shows the errors)\n",
            ),
            Self::FilesOnly => Some(
                "basis: nothing is published yet, so this is what your files give; the next prompt publishes them\n",
            ),
            Self::File => None,
        }
    }
}

const EXEC_NOT_SHOWN: &str =
    "not shown for --config; the file is not trusted, so no executable is looked up";
const FOOTER: &str = "explain runs no command and collects no git or folder facts; a segment that needs them shows as no-value.";

pub fn run(args: &[OsString]) -> ExitCode {
    let Some(a) = parse(args) else {
        eprintln!("{USAGE}");
        return ctx::code(EXIT_USAGE);
    };
    let Some(user) = User::current() else {
        eprintln!("{}", en(MsgId::NoHome));
        return ctx::code(EXIT_FAILED);
    };
    let env = TrustedEnv::capture();
    let (report, source) = match &a.config {
        Some(p) => match report_of_file(p) {
            Ok(r) => (r, Some(ctx::show(std::path::Path::new(p)))),
            Err(e) => {
                eprintln!("bingsu explain: {e}");
                return ctx::code(EXIT_FAILED);
            }
        },
        None => match inspect_config(&user, &env) {
            Ok(i) => (i.report, None),
            Err((text, code)) => {
                eprintln!("{text}");
                return ctx::code(code);
            }
        },
    };
    // The prompt draws with the published snapshot, not with the files: use
    // it when there is one, and say so when the files have moved on.
    let published = if a.config.is_none() {
        published(&user, &env)
    } else {
        None
    };
    let fail_with_errors = || {
        let catalog = Catalog(&report.files);
        for d in report
            .diagnostics
            .iter()
            .filter(|d| d.severity() == Severity::Error)
        {
            eprintln!("{}", render_human(d, &catalog));
        }
        eprintln!("bingsu explain: the settings have errors; fix them first (bingsu config check)");
        ctx::code(EXIT_FAILED)
    };
    let (compiled, basis) = match (&report.snapshot, &published) {
        _ if a.config.is_some() => match &report.snapshot {
            Some(c) => (c, Basis::File),
            None => return fail_with_errors(),
        },
        (Some(fresh), Some(p)) if p == fresh => (p, Basis::Published),
        (Some(_), Some(p)) => (p, Basis::PublishedFilesChanged),
        (None, Some(p)) => (p, Basis::PublishedFilesInvalid),
        (Some(fresh), None) => (fresh, Basis::FilesOnly),
        (None, None) => return fail_with_errors(),
    };
    let ids = segment_ids(compiled);
    let only = match &a.segment {
        Some(s) => match ids.iter().position(|i| i == s) {
            Some(i) => Some(i),
            None => {
                eprintln!(
                    "bingsu explain: there is no segment `{}` in these settings",
                    bingsu_core::sanitize::sanitize(s.as_bytes())
                );
                return ctx::code(EXIT_USAGE);
            }
        },
        None => None,
    };
    let width = a.width.unwrap_or(DEFAULT_WIDTH);
    let pwd = std::env::current_dir()
        .ok()
        .map(|p| p.as_os_str().as_bytes().to_vec());
    let (log, _) = decide(
        compiled,
        width,
        pwd,
        Some(user.pw.home.as_os_str().as_bytes().to_vec()),
    );
    // The execution section: only for a command or language segment named on
    // the command line, from the files (a `--config` file is not trusted, so
    // nothing is looked up for it), and only when the files compile.
    let wants_units = a
        .segment
        .as_ref()
        .is_some_and(|seg| compiled.exec_units.iter().any(|u| &u.id == seg));
    let from_config = a.config.is_some();
    let found = if wants_units && !from_config && report.snapshot.is_some() {
        lookups(
            &report,
            env.path.as_deref(),
            user.me,
            &mut SystemGroups::new(&user.pw.name),
        )
    } else {
        Vec::new()
    };
    let text_out = if a.json {
        explain_json(&Doc {
            compiled,
            report: &report,
            log: &log,
            width,
            width_flag: a.width.is_some(),
            basis,
            source: source.as_deref(),
            only,
            segment: a.segment.as_deref(),
            wants_units,
            from_config,
            found: &found,
        })
    } else {
        let mut out = match &source {
            Some(f) => format!("settings: {f} (only that file)\n"),
            None => "settings: the ones `bingsu config path` lists\n".to_owned(),
        };
        if let Some(b) = basis.line() {
            out.push_str(b);
        }
        let note = if a.width.is_some() {
            ""
        } else {
            " (assumed; give --width N)"
        };
        let body = text(compiled, &log, width, only);
        // `width: N cells` carries where N came from.
        out.push_str(&body.replacen(" cells\n", &format!(" cells{note}\n"), 1));
        if basis == Basis::PublishedFilesInvalid {
            let catalog = Catalog(&report.files);
            for d in report
                .diagnostics
                .iter()
                .filter(|d| d.severity() == Severity::Error)
            {
                out.push_str(&render_human(d, &catalog));
                out.push_str("\n\n");
            }
        }
        if wants_units {
            if from_config {
                out.push_str("execution: ");
                out.push_str(EXEC_NOT_SHOWN);
                out.push('\n');
            } else if let Some(seg) = &a.segment
                && report.snapshot.is_some()
            {
                out.push_str(&render_explain(&report, &found, Some(seg)));
            }
        }
        out.push_str(FOOTER);
        out.push('\n');
        out
    };
    if ctx::print(&text_out) {
        ExitCode::SUCCESS
    } else {
        ctx::code(EXIT_FAILED)
    }
}

/// Everything the JSON document is made of.
struct Doc<'a> {
    compiled: &'a CompiledConfig,
    report: &'a ConfigReport,
    log: &'a DecisionLog,
    width: u16,
    width_flag: bool,
    basis: Basis,
    source: Option<&'a str>,
    only: Option<usize>,
    segment: Option<&'a str>,
    wants_units: bool,
    from_config: bool,
    found: &'a [(String, super::exec_path::Explained)],
}

fn explain_json(d: &Doc<'_>) -> String {
    use bingsu_core::diag_json::{self as j, Writer};
    let mut w = Writer::new();
    w.begin_object();
    w.key("schema").number(u64::from(j::SCHEMA));
    w.key("command").string("explain");
    w.key("settings").begin_object();
    w.key("source")
        .string(if d.source.is_some() { "file" } else { "files" });
    w.key("file").opt_string(d.source);
    w.end_object();
    w.key("basis").string(d.basis.word());
    w.key("width").number(u64::from(d.width));
    w.key("width_source")
        .string(if d.width_flag { "flag" } else { "default" });
    let ids = segment_ids(d.compiled);
    let methods: Vec<&[Method]> = d
        .compiled
        .setup
        .iter()
        .map(|s| s.methods.as_slice())
        .collect();
    j::decisions(
        &mut w,
        d.log,
        &Names {
            segments: &ids,
            bands: &d.compiled.band_names,
            methods: &methods,
        },
        d.only,
    );
    w.key("diagnostics");
    let errors: Vec<_> = if d.basis == Basis::PublishedFilesInvalid {
        d.report
            .diagnostics
            .iter()
            .filter(|x| x.severity() == Severity::Error)
            .cloned()
            .collect()
    } else {
        Vec::new()
    };
    j::diagnostics(&mut w, &errors, &Catalog(&d.report.files));
    w.key("execution");
    if d.wants_units && !d.from_config && d.report.snapshot.is_some() {
        super::config_inspect::units_json(&mut w, d.report, d.found, d.segment);
    } else {
        w.null();
    }
    w.key("execution_note")
        .opt_string((d.wants_units && d.from_config).then_some(EXEC_NOT_SHOWN));
    w.key("notes").begin_array();
    w.string(FOOTER);
    w.end_array();
    w.end_object();
    w.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn a(w: &[&str]) -> Vec<OsString> {
        w.iter().map(OsString::from).collect()
    }

    // 이것을 실패시키는 것: 폭 0·중복 옵션·모르는 옵션·값 없는 옵션·세그먼트 둘을 받는 것.
    #[test]
    fn arguments_are_strict() {
        let ok = parse(&a(&["git", "--width", "40", "--config", "f.toml"])).unwrap();
        assert_eq!(ok.segment.as_deref(), Some("git"));
        assert_eq!(ok.width, Some(40));
        assert_eq!(ok.config.as_deref(), Some(OsStr::new("f.toml")));
        assert!(!ok.json);
        assert!(parse(&a(&["--format", "json"])).unwrap().json);
        assert_eq!(
            parse(&[]).unwrap(),
            Args {
                segment: None,
                width: None,
                config: None,
                json: false
            }
        );
        for bad in [
            &["--width", "0"][..],
            &["--width"],
            &["--width", "x"],
            &["--width", "70000"],
            &["--width", "5", "--width", "6"],
            &["--config"],
            &["--bogus"],
            &["git", "dir"],
            &["--format", "xml"],
            &["--format"],
            &["--format", "json", "--format", "json"],
        ] {
            assert!(parse(&a(bad)).is_none(), "{bad:?}");
        }
    }
}
