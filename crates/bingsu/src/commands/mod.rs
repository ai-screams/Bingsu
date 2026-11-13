//! Every command but `prompt`. `main` hands over the arguments that
//! `prompt::dispatch` gave back; `init`, `messages` and `sys` are private
//! here, so neither `main` nor the prompt adapter can name them.
use crate::prompt::NonPromptArgs;
use std::process::ExitCode;

#[cfg(unix)]
mod build_identity;
#[cfg(unix)]
pub(crate) mod builtin_probe;
#[cfg(unix)]
#[cfg_attr(
    not(test),
    allow(dead_code, reason = "N2 connects the store and clock")
)]
mod clock;
#[cfg(unix)]
pub(crate) mod collection_breaker;
#[cfg(unix)]
pub(crate) mod collection_gc;
#[cfg(unix)]
pub(crate) mod collection_store;
#[cfg(unix)]
#[allow(unsafe_code)]
mod collector;
#[cfg(unix)]
#[allow(unsafe_code)]
pub(crate) mod collector_process;
#[cfg(unix)]
#[allow(unsafe_code)]
pub(crate) mod collector_supervisor;
#[cfg(unix)]
#[allow(unsafe_code)]
#[cfg_attr(
    not(test),
    allow(dead_code, reason = "the helper calls it from the next change")
)]
pub(crate) mod command_cgroup;
#[cfg(unix)]
#[allow(unsafe_code)]
pub(crate) mod command_grant;
#[cfg(unix)]
pub(crate) mod command_match;
#[cfg(unix)]
#[allow(unsafe_code)]
pub(crate) mod command_process;
#[cfg(unix)]
pub(crate) mod command_sessions;
#[cfg(unix)]
#[allow(unsafe_code)]
pub(crate) mod command_supervisor;
#[cfg(unix)]
mod config;
#[cfg(unix)]
mod config_inspect;
#[cfg(unix)]
mod config_load;
#[cfg(unix)]
mod config_use;
#[cfg(unix)]
mod ctx;
#[cfg(unix)]
mod doctor;
#[cfg(unix)]
#[cfg_attr(not(test), allow(dead_code, reason = "N2 evidence serialization"))]
mod evidence;
#[cfg(unix)]
#[allow(dead_code, reason = "C2 connects the resolver")]
pub(crate) mod exec_path;
#[cfg(unix)]
mod explain;
#[cfg(unix)]
mod explain_builtin;
#[cfg(unix)]
mod git_global;
#[cfg(unix)]
mod group_policy;
mod help;
#[cfg(unix)]
#[allow(unsafe_code)]
pub(crate) mod helper;
#[cfg(unix)]
#[allow(unsafe_code)]
pub(crate) mod helper_filter;
#[cfg(unix)]
#[allow(unsafe_code)]
pub(crate) mod helper_limits;
#[cfg(unix)]
mod init;
#[cfg(unix)]
pub(crate) mod io_meter;
#[cfg(unix)]
mod list;
#[cfg(unix)]
mod log;
#[cfg(unix)]
mod messages;
#[cfg(unix)]
pub(crate) mod refresh;
#[cfg(unix)]
mod reload;
#[cfg(unix)]
pub(crate) mod runtime_root;
#[cfg(unix)]
mod setup;
#[cfg(unix)]
#[cfg_attr(not(test), allow(dead_code, reason = "N2 connects publication"))]
pub(crate) mod snapshot_store;
#[cfg(unix)]
mod source_path;
#[cfg(unix)]
#[allow(unsafe_code)]
pub(crate) mod sys;
#[cfg(unix)]
mod trust_record;
#[cfg(unix)]
#[allow(unsafe_code)]
pub(crate) mod tty;
#[cfg(unix)]
pub(crate) mod version_manager;

#[used]
static ROLE_TAG: [u8; 49] = bingsu_identity::role_tag(bingsu_identity::BINGSU_ROLE);

pub fn run(a: NonPromptArgs) -> ExitCode {
    std::hint::black_box(&ROLE_TAG);
    #[cfg(not(unix))]
    let _ = &a.argv0;
    match a.args.first().and_then(|w| w.to_str()) {
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        Some(bingsu_core::handoff::ENTRY) => crate::relay::run(&a.args),
        #[cfg(unix)]
        Some("__refresh-v1") => helper::run(&a.argv0, &a.args[1..]),
        #[cfg(unix)]
        Some(command_supervisor::ENTRY) => command_supervisor::run(&a.argv0),
        #[cfg(unix)]
        Some("config") => config::run(&a.argv0, &a.args[1..]),
        #[cfg(unix)]
        Some("doctor") => doctor::run(&a.args[1..]),
        #[cfg(unix)]
        Some("explain") => explain::run(&a.args[1..]),
        Some("help") => help::run(&a.args[1..]),
        #[cfg(unix)]
        Some("init") => init::run(&a.argv0, &a.args[1..]),
        #[cfg(unix)]
        Some("list") => list::run(&a.args[1..]),
        #[cfg(unix)]
        Some("setup") => setup::run(&a.args[1..]),
        #[cfg(unix)]
        Some("reload") => reload::run(&a.argv0, &a.args[1..]),
        #[cfg(feature = "bench-stubs")]
        Some("__collect-stub") => ExitCode::from(
            u8::try_from(bingsu_bench::collector_stub::stub_main(&a.args[1..])).unwrap_or(1),
        ),
        _ => {
            eprintln!(
                "usage: bingsu <config|doctor|explain|help|init|list|prompt|reload|setup> ..."
            );
            ExitCode::from(2)
        }
    }
}

#[cfg(test)]
pub(crate) mod n3_test;
