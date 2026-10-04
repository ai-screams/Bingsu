//! I/O-free core of bingsu. No files, processes, clocks, environment,
//! network or threads (enforced by `clippy.toml` and `deny.toml` here).
#![forbid(unsafe_code)]
#![forbid(clippy::disallowed_methods)]
#![forbid(clippy::disallowed_types)]
#![forbid(clippy::disallowed_macros)]

/// Crate version, used by `bingsu --version` later.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
