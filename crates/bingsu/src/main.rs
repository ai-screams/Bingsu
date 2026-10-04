//! `bingsu` binary. `prompt` is dispatched before anything else (fast path).
use std::process::ExitCode;

fn main() -> ExitCode {
    // Commands are added by Task A5 (prompt) and Task A7 (init).
    eprintln!("usage: bingsu <init|prompt> ...");
    ExitCode::from(2)
}
