//! The only module in this crate allowed to use `unsafe`.
#[cfg(target_os = "linux")]
pub mod cgroup;
#[cfg(target_os = "linux")]
pub mod fs;
// Linux and macOS only: the child-side close (closefrom / CLOEXEC_DEFAULT)
// is defined for those two.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub mod spawn;
