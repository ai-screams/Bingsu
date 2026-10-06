//! The only module in this crate allowed to use `unsafe`.
#[cfg(target_os = "linux")]
pub mod fs;
