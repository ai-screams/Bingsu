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

const USAGE: &str = "usage: bingsu explain [SEGMENT] [--width N] [--config FILE]";
/// The widest file `--config` reads (the cap of one config file).
const FILE_MAX: u64 = 256 * 1024;
const DEFAULT_WIDTH: u16 = 80;

/// What the arguments asked for.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct Args {
    pub segment: Option<String>,
    pub width: Option<u16>,
    pub config: Option<OsString>,
}

pub(super) fn parse(args: &[OsString]) -> Option<Args> {
    let mut out = Args {
        segment: None,
        width: None,
        config: None,
    };
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

const BASIS_CURRENT: &str = "basis: the published settings, which are the ones in your files\n";
const BASIS_CHANGED: &str = "basis: the published settings, which the prompt draws now; your files have changed since, and the next prompt draws the changed settings (bingsu config check shows them)\n";
const BASIS_NONE: &str = "basis: nothing is published yet, so this is what your files give; the next prompt publishes them\n";
const EXEC_NOT_SHOWN: &str =
    "execution: not shown for --config; the file is not trusted, so no executable is looked up\n";
const FOOTER: &str = "explain runs no command and collects no git or folder facts; a segment that needs them shows as no-value.\n";

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
            Ok(r) => (
                r,
                format!(
                    "settings: {} (only that file)",
                    ctx::show(std::path::Path::new(p))
                ),
            ),
            Err(e) => {
                eprintln!("bingsu explain: {e}");
                return ctx::code(EXIT_FAILED);
            }
        },
        None => match inspect_config(&user, &env) {
            Ok(i) => (
                i.report,
                "settings: the ones `bingsu config path` lists".to_owned(),
            ),
            Err((text, code)) => {
                eprintln!("{text}");
                return ctx::code(code);
            }
        },
    };
    let Some(fresh) = &report.snapshot else {
        let catalog = Catalog(&report.files);
        for d in report
            .diagnostics
            .iter()
            .filter(|d| d.severity() == Severity::Error)
        {
            eprintln!("{}", render_human(d, &catalog));
        }
        eprintln!("bingsu explain: the settings have errors; fix them first (bingsu config check)");
        return ctx::code(EXIT_FAILED);
    };
    // The prompt draws with the published snapshot, not with the files: use
    // it when there is one, and say so when the files have moved on.
    let published = if a.config.is_none() {
        published(&user, &env)
    } else {
        None
    };
    let (compiled, basis) = match &published {
        _ if a.config.is_some() => (fresh, None),
        Some(p) if p == fresh => (p, Some(BASIS_CURRENT)),
        Some(p) => (p, Some(BASIS_CHANGED)),
        None => (fresh, Some(BASIS_NONE)),
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
    let (width, width_note) = match a.width {
        Some(w) => (w, ""),
        None => (DEFAULT_WIDTH, " (assumed; give --width N)"),
    };
    let pwd = std::env::current_dir()
        .ok()
        .map(|p| p.as_os_str().as_bytes().to_vec());
    let (log, _) = decide(
        compiled,
        width,
        pwd,
        Some(user.pw.home.as_os_str().as_bytes().to_vec()),
    );
    let mut out = format!("{source}\n");
    if let Some(b) = basis {
        out.push_str(b);
    }
    let body = text(compiled, &log, width, only);
    // `width: N cells` carries where N came from.
    out.push_str(&body.replacen(" cells\n", &format!(" cells{width_note}\n"), 1));
    if let Some(seg) = &a.segment
        && compiled.exec_units.iter().any(|u| &u.id == seg)
    {
        if a.config.is_some() {
            // A file given with `--config` is not yours to trust yet: its
            // executables are not looked up, so none is opened.
            out.push_str(EXEC_NOT_SHOWN);
        } else {
            let found = lookups(
                &report,
                env.path.as_deref(),
                user.me,
                &mut SystemGroups::new(&user.pw.name),
            );
            out.push_str(&render_explain(&report, &found, Some(seg)));
        }
    }
    out.push_str(FOOTER);
    if ctx::print(&out) {
        ExitCode::SUCCESS
    } else {
        ctx::code(EXIT_FAILED)
    }
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
        assert_eq!(
            parse(&[]).unwrap(),
            Args {
                segment: None,
                width: None,
                config: None
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
        ] {
            assert!(parse(&a(bad)).is_none(), "{bad:?}");
        }
    }
}
