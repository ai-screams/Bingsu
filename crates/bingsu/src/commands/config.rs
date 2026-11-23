//! `bingsu config …`: `schema` prints core's JSON Schema, `check` and `path`
//! read the settings and write nothing, `use` records which file stands in
//! `config.toml`'s place and applies it.
use super::{config_edit, config_inspect, config_use, sys};
use bingsu_core::config::schema::{Which, schema};
use std::ffi::{OsStr, OsString};
use std::process::ExitCode;

/// What a `config` command line asks for.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Verb<'a> {
    Check {
        explain: bool,
        json: bool,
    },
    Edit,
    Path,
    Schema(Which),
    /// `use` and the words after it, which `config_use` reads.
    Use(&'a [OsString]),
}

/// The subcommand and its flags; `None` for a wrong use.
pub(super) fn parse(args: &[OsString]) -> Option<Verb<'_>> {
    if let [verb, rest @ ..] = args
        && verb == "use"
    {
        return Some(Verb::Use(rest));
    }
    let words: Vec<Option<&str>> = args.iter().map(|a| a.to_str()).collect();
    match words.as_slice() {
        [Some("check"), flags @ ..] => {
            let (explain, json) = check_flags(flags)?;
            Some(Verb::Check { explain, json })
        }
        [Some("edit")] => Some(Verb::Edit),
        [Some("path")] => Some(Verb::Path),
        [Some("schema")] => Some(Verb::Schema(Which::Config)),
        [Some("schema"), Some("--theme")] => Some(Verb::Schema(Which::Theme)),
        _ => None,
    }
}

pub fn run(exe: &OsStr, args: &[OsString]) -> ExitCode {
    let which = match parse(args) {
        Some(Verb::Use(rest)) => return config_use::run(exe, rest),
        Some(Verb::Check {
            explain: true,
            json,
        }) => return config_inspect::check_explain(json),
        Some(Verb::Check {
            explain: false,
            json,
        }) => return config_inspect::check(json),
        Some(Verb::Edit) => return config_edit::run(exe),
        Some(Verb::Path) => return config_inspect::path(),
        Some(Verb::Schema(which)) => which,
        None => {
            eprintln!("{}", super::usage::line(&["config"]));
            return ExitCode::from(super::ctx::EXIT_USAGE);
        }
    };
    match sys::write_fd(1, schema(which).as_bytes()) {
        sys::WriteOutcome::Done => ExitCode::SUCCESS,
        sys::WriteOutcome::Failed => ExitCode::from(1),
    }
}

/// The flags of `config check`: `--explain` and `--format json|text`, each
/// at most once, in any order. `(explain, json)`.
fn check_flags(flags: &[Option<&str>]) -> Option<(bool, bool)> {
    let (mut explain, mut format) = (false, None);
    let mut it = flags.iter();
    while let Some(f) = it.next() {
        match (*f)? {
            "--explain" if !explain => explain = true,
            "--format" if format.is_none() => {
                format = Some(match (*it.next()?)? {
                    "json" => true,
                    "text" => false,
                    _ => return None,
                });
            }
            _ => return None,
        }
    }
    Some((explain, format.unwrap_or(false)))
}
