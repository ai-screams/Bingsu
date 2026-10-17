//! `bingsu config …`: `schema` prints core's JSON Schema, `check` and `path`
//! read the settings and write nothing, `use` records which file stands in
//! `config.toml`'s place and applies it.
use super::{config_inspect, config_use, sys};
use bingsu_core::config::schema::{Which, schema};
use std::ffi::OsString;
use std::process::ExitCode;

const USAGE: &str = "usage: bingsu config <check|path|schema [--theme]|use PATH>";

pub fn run(args: &[OsString]) -> ExitCode {
    if let [verb, rest @ ..] = args
        && verb == "use"
    {
        return config_use::run(rest);
    }
    let words: Vec<Option<&str>> = args.iter().map(|a| a.to_str()).collect();
    let which = match words.as_slice() {
        [Some("check")] => return config_inspect::check(),
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
