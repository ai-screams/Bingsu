//! `bingsu` binary. `prompt` is dispatched before anything else (fast path).
#![deny(unsafe_code)]
use std::process::ExitCode;

#[cfg(unix)]
mod envelope;
#[cfg(unix)]
mod init;
#[cfg(unix)]
mod messages;
#[cfg(unix)]
mod prompt;
#[cfg(unix)]
#[allow(unsafe_code)]
mod sys;

// The prompt dispatch runs here: the clippy.toml rules are forbidden for the
// body of main only (an item attribute, so init's own #[expect] in
// trusted_env stays valid). scripts/check_cli_prompt_forbid.py checks it.
#[forbid(
    clippy::disallowed_methods,
    clippy::disallowed_types,
    clippy::disallowed_macros
)]
fn main() -> ExitCode {
    let mut all = std::env::args_os();
    let argv0 = all.next().unwrap_or_default();
    let args: Vec<std::ffi::OsString> = all.collect();
    #[cfg(not(unix))]
    let _ = &argv0;
    match args.first().and_then(|a| a.to_str()) {
        #[cfg(unix)]
        Some("prompt") => prompt::run(&args[1..]),
        #[cfg(unix)]
        Some("init") => init::run(&argv0, &args[1..]),
        _ => {
            eprintln!("usage: bingsu <init|prompt> ...");
            ExitCode::from(2)
        }
    }
}
