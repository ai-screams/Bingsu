//! `bingsu` binary. `prompt` is dispatched before anything else (fast path).
#![deny(unsafe_code)]
use std::process::ExitCode;

#[cfg(unix)]
mod envelope;
#[cfg(unix)]
mod prompt;
#[cfg(unix)]
#[allow(unsafe_code)]
mod sys;

fn main() -> ExitCode {
    let args: Vec<std::ffi::OsString> = std::env::args_os().skip(1).collect();
    match args.first().and_then(|a| a.to_str()) {
        #[cfg(unix)]
        Some("prompt") => prompt::run(&args[1..]),
        _ => {
            eprintln!("usage: bingsu <init|prompt> ...");
            ExitCode::from(2)
        }
    }
}
