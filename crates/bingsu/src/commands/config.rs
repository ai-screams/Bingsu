//! `bingsu config …`: `schema` prints core's JSON Schema, `check` and `path`
//! read the settings and write nothing, `use` records which file stands in
//! `config.toml`'s place and applies it.
use super::{config_inspect, config_use, sys};
use bingsu_core::config::schema::{Which, schema};
use std::ffi::{OsStr, OsString};
use std::process::ExitCode;

const USAGE: &str =
    "usage: bingsu config <check [--explain] [--format json|text]|path|schema [--theme]|use PATH>";

pub fn run(exe: &OsStr, args: &[OsString]) -> ExitCode {
    if let [verb, rest @ ..] = args
        && verb == "use"
    {
        return config_use::run(exe, rest);
    }
    let words: Vec<Option<&str>> = args.iter().map(|a| a.to_str()).collect();
    let which = match words.as_slice() {
        [Some("check"), flags @ ..] => match check_flags(flags) {
            Some((explain, json)) => {
                return if explain {
                    config_inspect::check_explain(json)
                } else {
                    config_inspect::check(json)
                };
            }
            None => {
                eprintln!("{USAGE}");
                return ExitCode::from(super::ctx::EXIT_USAGE);
            }
        },
        [Some("path")] => return config_inspect::path(),
        [Some("schema")] => Which::Config,
        [Some("schema"), Some("--theme")] => Which::Theme,
        _ => {
            eprintln!("{USAGE}");
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
