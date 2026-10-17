//! Every command but `prompt`. `main` hands over the arguments that
//! `prompt::dispatch` gave back; `init`, `messages` and `sys` are private
//! here, so neither `main` nor the prompt adapter can name them.
use crate::prompt::NonPromptArgs;
use std::process::ExitCode;

#[cfg(unix)]
#[cfg_attr(
    not(test),
    allow(dead_code, reason = "N2 connects the store and clock")
)]
mod clock;
#[cfg(unix)]
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "S3b/N2 config session integration")
)]
mod config_load;
#[cfg(unix)]
#[cfg_attr(not(test), allow(dead_code, reason = "N2 evidence serialization"))]
mod evidence;
#[cfg(unix)]
mod group_policy;
#[cfg(unix)]
mod init;
#[cfg(unix)]
mod messages;
#[cfg(unix)]
#[cfg_attr(
    not(test),
    allow(dead_code, reason = "N3/N5 call the publication engine")
)]
mod refresh;
#[cfg(unix)]
mod runtime_root;
#[cfg(unix)]
#[cfg_attr(not(test), allow(dead_code, reason = "N2 connects publication"))]
mod snapshot_store;
#[cfg(unix)]
#[cfg_attr(not(test), expect(dead_code, reason = "N2 source session integration"))]
mod source_path;
#[cfg(unix)]
#[allow(unsafe_code)]
mod sys;
#[cfg(unix)]
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "N2/N5 approval record integration")
)]
mod trust_record;

pub fn run(a: NonPromptArgs) -> ExitCode {
    #[cfg(not(unix))]
    let _ = &a.argv0;
    match a.args.first().and_then(|w| w.to_str()) {
        #[cfg(unix)]
        Some("init") => init::run(&a.argv0, &a.args[1..]),
        #[cfg(feature = "bench-stubs")]
        Some("__collect-stub") => {
            ExitCode::from(u8::try_from(bingsu_collect::stub_main(&a.args[1..])).unwrap_or(1))
        }
        _ => {
            eprintln!("usage: bingsu <init|prompt> ...");
            ExitCode::from(2)
        }
    }
}
