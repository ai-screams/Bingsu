//! `bingsu config …` (spec section 2 "JSON Schema"; the editing loop and
//! `config use` come with Task N5).
use super::sys;
use bingsu_core::config::schema::{Which, schema};
use std::ffi::OsString;
use std::process::ExitCode;

pub fn run(args: &[OsString]) -> ExitCode {
    let words: Vec<Option<&str>> = args.iter().map(|a| a.to_str()).collect();
    let which = match words.as_slice() {
        [Some("schema")] => Which::Config,
        [Some("schema"), Some("--theme")] => Which::Theme,
        _ => {
            eprintln!("usage: bingsu config schema [--theme]");
            return ExitCode::from(2);
        }
    };
    match sys::write_fd(1, schema(which).as_bytes()) {
        sys::WriteOutcome::Done => ExitCode::SUCCESS,
        sys::WriteOutcome::Failed => ExitCode::from(1),
    }
}
