//! What `config check --explain` shows for each command and language
//! segment (`explain <segment>` uses the same model): whether it
//! runs and why not, its command, working folder, time limits and the names
//! of the environment it gets, each with where it came from. The model holds
//! no environment value: it is built from the compiled config alone, which
//! never sees one, so no output can print one.
use super::compile::{CompiledConfig, ExecPolicy, NotRun};
use super::merge::Origin;
use crate::command::keep::{KEEP, KEEP_PREFIX};
use crate::diag::DiagCode;
use crate::diag_codes as codes;
use alloc::{string::String, vec::Vec};

/// Where a shown value came from.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum From {
    /// Nothing set it; the built-in default applies.
    Default,
    /// The key at this place in a settings file.
    Source(Origin),
    /// The names every command gets.
    KeepList,
}

/// One shown line: the key, its value, where it came from.
#[derive(Clone, Debug, PartialEq)]
pub struct Row {
    pub key: &'static str,
    pub value: String,
    pub from: From,
}

/// One environment name a unit gets, and where it came from. There is no
/// value field: the model never holds one (E2 review M3).
#[derive(Clone, Debug, PartialEq)]
pub struct EnvName {
    pub name: String,
    pub from: From,
}

/// One unit.
#[derive(Clone, Debug, PartialEq)]
pub struct UnitView {
    pub id: String,
    pub kind: &'static str,
    /// `None`: it runs.
    pub not_run: Option<NotRun>,
    pub rows: Vec<Row>,
    pub environment: Vec<EnvName>,
}

/// Why a unit does not run, in words, and the diagnostic that reports it.
pub fn not_run_text(n: &NotRun) -> (&'static str, Option<DiagCode>) {
    match n {
        NotRun::Disabled => ("turned off with `enabled = false`", None),
        NotRun::NotInTrustedLayout => (
            "no layout from a trusted file draws it",
            Some(codes::NOT_RUN_UNTRUSTED_LAYOUT),
        ),
        NotRun::UnsafeFile { .. } => (
            "one of its execution keys comes from a file that failed the safety check",
            Some(codes::NOT_RUN_UNSAFE_FILE),
        ),
        NotRun::UnknownBand => (
            "a layout reference names a width band that does not exist",
            None,
        ),
        NotRun::ShellNotAllowed => (
            "`shell` is set without `unsafe_shell = true`",
            Some(codes::SHELL_NOT_ALLOWED),
        ),
        NotRun::MatchInvalid => (
            "`match` is not a regular expression within the size limit",
            Some(codes::BAD_VALUE),
        ),
    }
}

/// Every unit of `c`, in the compiled order.
pub fn units(c: &CompiledConfig) -> Vec<UnitView> {
    c.exec_units
        .iter()
        .map(|u| {
            let from = |key: &str| {
                u.origins
                    .iter()
                    .find(|(k, _)| k == key)
                    .map_or(From::Default, |(_, o)| From::Source(*o))
            };
            let mut rows = Vec::new();
            let mut environment = Vec::new();
            let kind = match &u.policy {
                ExecPolicy::Command {
                    argv,
                    cwd,
                    env_allow,
                    shell,
                    ..
                } => {
                    match shell {
                        Some(script) => rows.push(Row {
                            key: "shell",
                            value: script.clone(),
                            from: from("shell"),
                        }),
                        None => rows.push(Row {
                            key: "command",
                            value: argv.join(" "),
                            from: from("command"),
                        }),
                    }
                    rows.push(Row {
                        key: "cwd",
                        value: cwd.clone().unwrap_or_else(|| "neutral".into()),
                        from: from("cwd"),
                    });
                    rows.push(limit("timeout", u.timeout_ms, from("timeout")));
                    rows.push(limit("cache", u.cache_ms, from("cache")));
                    // Names only: the values are the shell's, read when the
                    // unit runs, and never part of this model.
                    // Fails without it: explain_shows_origin_per_key.
                    for name in env_allow {
                        environment.push(EnvName {
                            name: name.clone(),
                            from: from("env_allow"),
                        });
                    }
                    environment.push(EnvName {
                        name: keep_names(),
                        from: From::KeepList,
                    });
                    "command"
                }
                ExecPolicy::Language {
                    interpreter,
                    version_argv,
                    detect_files,
                    cwd,
                    env_allow,
                } => {
                    // Fails without it: explain_shows_shell_relative_and_language_units.
                    rows.push(Row {
                        key: "detect",
                        value: detect_files.join(" "),
                        from: from("detect_files"),
                    });
                    // Each key with its own origin: `extends` can bring
                    // them from different files (D3c-1 review L1).
                    rows.push(Row {
                        key: "interpreter",
                        value: interpreter.clone().unwrap_or_default(),
                        from: from("interpreter"),
                    });
                    rows.push(Row {
                        key: "version",
                        value: version_argv.join(" "),
                        from: from("version"),
                    });
                    rows.push(Row {
                        key: "cwd",
                        value: cwd.clone().unwrap_or_else(|| "neutral".into()),
                        from: from("cwd"),
                    });
                    rows.push(limit("timeout", u.timeout_ms, from("timeout")));
                    rows.push(limit("cache", u.cache_ms, from("cache")));
                    for name in env_allow {
                        environment.push(EnvName {
                            name: name.clone(),
                            from: from("env_allow"),
                        });
                    }
                    environment.push(EnvName {
                        name: keep_names(),
                        from: From::KeepList,
                    });
                    "language"
                }
            };
            UnitView {
                id: u.id.clone(),
                kind,
                not_run: u.not_run.clone(),
                rows,
                environment,
            }
        })
        .collect()
}

fn limit(key: &'static str, ms: Option<u64>, from: From) -> Row {
    Row {
        key,
        value: match ms {
            Some(ms) => alloc::format!("{ms} ms"),
            None => "default".into(),
        },
        from,
    }
}

/// `HOME USER LANG TERM TZ PATH LC_*`: the keep list as one line.
fn keep_names() -> String {
    let mut out = String::new();
    for name in KEEP {
        out.push_str(&String::from_utf8_lossy(name));
        out.push(' ');
    }
    out.push_str(&String::from_utf8_lossy(KEEP_PREFIX));
    out.push('*');
    out
}
