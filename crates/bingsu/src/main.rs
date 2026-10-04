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
