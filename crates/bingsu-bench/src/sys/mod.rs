//! The only module in this crate allowed to use `unsafe`.

/// The unit tests that open or close fds run one at a time: a closed fd
/// number a test checks could otherwise be reused by a parallel test's
/// file, pipe or spawn.
#[cfg(test)]
static FD_TESTS: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Takes `FD_TESTS`. A test that failed while holding it poisons it; the
/// next test still runs (and reports its own result) instead of failing on
/// the poison.
#[cfg(test)]
pub(crate) fn fd_tests_lock() -> std::sync::MutexGuard<'static, ()> {
    FD_TESTS.lock().unwrap_or_else(|e| e.into_inner())
}

#[cfg(test)]
mod tests {
    // 이것을 실패시키는 것: poison된 잠금에서 unwrap해, 앞 시험 하나의 실패가 뒤 fd 시험들로 번지는 것.
    #[test]
    fn poisoned_fd_lock_still_serializes() {
        let _ = std::thread::spawn(|| {
            let _g = super::fd_tests_lock();
            panic!("poison FD_TESTS on purpose");
        })
        .join();
        drop(super::fd_tests_lock());
    }
}

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
