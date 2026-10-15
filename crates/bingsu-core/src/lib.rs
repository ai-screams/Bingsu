//! I/O-free core of bingsu. No files, processes, clocks, environment,
//! network or threads: the crate is `no_std` (only `core` and `alloc`), so
//! std's I/O APIs do not exist here, and `clippy.toml` and `deny.toml` keep
//! the rules for anything std brings back (scripts/check-core-purity.sh).
#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

/// Crate version, used by `bingsu --version` later.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub mod bands;
pub mod color;
pub mod emit;
pub mod field;
pub mod icons;
pub mod layout;
pub mod record;
pub mod recorder;
pub mod render;
pub mod root_arg;
pub mod sanitize;
pub mod shell_word;
pub mod shorten;
pub mod status;
pub mod style;
pub mod template;
mod ucd;
pub mod width;
