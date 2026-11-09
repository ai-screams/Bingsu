//! Command execution contract: helper to supervisor frames, the approval
//! decision the supervisor makes before each relay spawn, and the run
//! deadline formulas. Types and pure decisions only; nothing here runs.
pub mod builtin;
pub mod cgroup;
pub mod deadline;
pub mod display;
pub mod env_frame;
pub mod grant;
pub mod keep;
pub mod path;
pub mod plan;
pub mod profile;
pub mod response;
pub mod wire;

/// Why a command frame was refused. Errors never produce reply bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// Fewer bytes than the header or the declared length.
    Short,
    Magic,
    Version,
    /// A kind byte outside the defined set.
    Kind,
    /// Reserved bytes are not zero.
    Flags,
    /// Declared length disagrees with the bytes, or exceeds a cap.
    Length,
    Checksum,
    /// A count or size above what the caller allows.
    Limit,
    /// Not UTF-8, or a NUL byte in a word, script, path or name.
    Utf8,
    /// Bytes after the last field.
    Trailing,
}
