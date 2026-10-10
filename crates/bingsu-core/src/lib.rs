//! I/O-free core of bingsu. No files, processes, clocks, environment,
//! network or threads (enforced by `clippy.toml` and `deny.toml` here).
#![forbid(unsafe_code)]

// New modules name alloc paths (alloc::string::String, alloc::vec::Vec) so a
// later `#![no_std]` switch (decided with the M3 parser) only touches this file, the M1
// modules record, shell_word and status, and the unqualified `String` in the
// root_arg tests.
extern crate alloc;

/// Crate version, used by `bingsu --version` later.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub mod record;
pub mod root_arg;
pub mod sanitize;
pub mod shell_word;
pub mod status;
// sanitize reads REMOVED_FORMAT (Task A3); width (Task A4) reads the rest. Drop
// this attribute when the last reader lands.
#[expect(dead_code, reason = "readers land in later M2 tasks")]
mod ucd;
