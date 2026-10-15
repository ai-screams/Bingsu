//! `bingsu` binary. The first and only thing `main` does is
//! `prompt::dispatch(sandbox::enter)`: for `bingsu prompt` it never returns (fast path,
//! the adapter is the whole prompt process); any other command gets the
//! arguments back for `commands::run`. core-cfg-check --binary checks this
//! shape (one `fn main`, this body).
#![deny(unsafe_code)]
use std::process::ExitCode;

mod commands;
// The prompt adapter: the trusted computing base of `bingsu prompt`. Its
// system calls are crates/bingsu/prompt-syscalls.tsv; every decision is
// bingsu_core::front.
#[cfg(unix)]
#[allow(unsafe_code)]
mod prompt;
// Linux: the prompt's seccomp filter. Elsewhere there is no filter.
#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
mod sandbox;
#[cfg(not(target_os = "linux"))]
mod sandbox {
    pub fn enter() -> bingsu_core::front::Sandbox {
        bingsu_core::front::Sandbox::Absent
    }
}
// Without a prompt path (Windows), the arguments go straight to commands.
#[cfg(not(unix))]
mod prompt {
    use std::ffi::OsString;

    pub struct NonPromptArgs {
        pub argv0: OsString,
        pub args: Vec<OsString>,
    }

    pub fn dispatch(_enter_sandbox: fn() -> bingsu_core::front::Sandbox) -> NonPromptArgs {
        let mut all = std::env::args_os();
        let argv0 = all.next().unwrap_or_default();
        NonPromptArgs {
            argv0,
            args: all.collect(),
        }
    }
}

fn main() -> ExitCode {
    commands::run(prompt::dispatch(sandbox::enter))
}
