//! The only module in this crate allowed to use `unsafe`.

/// The unit tests that open or close fds run one at a time: a closed fd
/// number a test checks could otherwise be reused by a parallel test's
/// file, pipe or spawn.
#[cfg(test)]
pub(crate) static FD_TESTS: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(target_os = "linux")]
pub mod cgroup;
#[cfg(target_os = "linux")]
pub mod fs;
// Linux and macOS only: the ACL lookup is defined for those two.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub mod meta;
// Linux and macOS only: the child-side close (closefrom / CLOEXEC_DEFAULT)
// is defined for those two.
#[cfg(target_os = "macos")]
pub mod macos;
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub mod spawn;
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub mod stdio;
