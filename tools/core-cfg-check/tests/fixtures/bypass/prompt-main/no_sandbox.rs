//! `bingsu-prompt`: the prompt path of `bingsu` and nothing else. The prompt
//! files of crates/bingsu/src are compiled here as they are (hash-pinned
//! there), so this binary links none of the other commands or their
//! dependencies, and starts faster. Init writes its path into the hook when it
//! sits beside `bingsu` with the same build; otherwise the hook calls
//! `bingsu prompt`. scripts/check_cli_prompt_forbid.py pins this file's shape.
#![deny(unsafe_code)]
#[cfg(unix)]
#[allow(dead_code, unsafe_code)]
#[path = "../../bingsu/src/prompt.rs"]
mod prompt;
#[cfg(unix)]
#[allow(dead_code, unsafe_code)]
#[path = "../../bingsu/src/prompt_io.rs"]
mod prompt_io;
#[cfg(unix)]
#[allow(dead_code, unsafe_code)]
#[path = "../../bingsu/src/prompt_read.rs"]
mod prompt_read;
#[cfg(unix)]
#[allow(dead_code, unsafe_code)]
#[path = "../../bingsu/src/prompt_spawn.rs"]
mod prompt_spawn;
#[cfg(unix)]
mod sandbox {
    pub fn enter() -> bingsu_core::front::Sandbox {
        bingsu_core::front::Sandbox::Absent
    }
}

// test_prompt_binary.py finds exactly one role marker, the prompt's, in the
// built file; init's sibling check needs it.
#[used]
static ROLE_TAG: [u8; 49] = bingsu_identity::role_tag(bingsu_identity::PROMPT_ROLE);

#[cfg(unix)]
fn main() {
    prompt::dedicated(sandbox::enter)
}

#[cfg(not(unix))]
fn main() -> std::process::ExitCode {
    std::process::ExitCode::from(2)
}
