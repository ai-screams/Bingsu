//! Test-only entry before libtest can create threads or non-main malloc arenas.
#![allow(dead_code, unused_imports)]

#[cfg(unix)]
#[path = "../src/commands/mod.rs"]
mod commands;
#[cfg(unix)]
#[path = "../src/prompt.rs"]
mod prompt;
#[cfg(unix)]
#[path = "../src/prompt_io.rs"]
mod prompt_io;
#[cfg(unix)]
#[path = "../src/prompt_read.rs"]
mod prompt_read;
#[cfg(unix)]
#[path = "../src/prompt_spawn.rs"]
mod prompt_spawn;
#[cfg(target_os = "linux")]
#[path = "../src/sandbox.rs"]
mod sandbox;
#[cfg(not(target_os = "linux"))]
mod sandbox {
    pub fn enter() -> bingsu_core::front::Sandbox {
        bingsu_core::front::Sandbox::Absent
    }
}

fn main() {
    #[cfg(unix)]
    match std::env::args().nth(1).as_deref() {
        Some("--list") => println!("collection_reader: main-thread trace helper"),
        Some("--collection-trace") => prompt_read::tests::collection_trace_child(),
        // Ordinary cargo test must not wait for fixture input or install a
        // process-wide filter. pytest explicitly selects the isolated child.
        None => {}
        Some(arg) => panic!("unexpected collection_reader argument: {arg}"),
    }
}
