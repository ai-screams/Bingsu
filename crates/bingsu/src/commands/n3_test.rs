//! Test-only native spawn probe compilation.
use std::{path::PathBuf, process::Command};

thread_local! {
    static LOCK_OBSERVER: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        std::cell::RefCell::new(None);
}
pub fn on_lock_scope(observer: impl FnOnce() + 'static) {
    LOCK_OBSERVER.with(|slot| {
        assert!(slot.borrow_mut().replace(Box::new(observer)).is_none());
    });
}
pub fn observe_lock_scope() {
    let observer = LOCK_OBSERVER.with(|slot| slot.borrow_mut().take());
    if let Some(observer) = observer {
        observer();
    }
}
pub fn probe(tag: &str) -> (PathBuf, PathBuf) {
    let base = std::env::temp_dir().join(format!("bingsu-n3-{tag}-{}", std::process::id()));
    std::fs::create_dir_all(&base).unwrap();
    let base = std::fs::canonicalize(base).unwrap();
    let exe = base.join("probe-bin");
    let source = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/n3_probe.c");
    let out = Command::new("cc")
        .args(["-O2", "-o"])
        .arg(&exe)
        .arg(source)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    (base, exe)
}
pub fn wait_report(path: &std::path::Path) -> Vec<i32> {
    let end = std::time::Instant::now() + std::time::Duration::from_secs(3);
    loop {
        if let Ok(s) = std::fs::read_to_string(path) {
            if s.ends_with('\n') {
                return s.split_whitespace().map(|n| n.parse().unwrap()).collect();
            }
        }
        assert!(
            std::time::Instant::now() < end,
            "missing probe report {path:?}"
        );
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
}

#[cfg(test)]
mod tests {
    // 이것을 실패시키는 것: bootstrap이 존재하는 상대 실행 경로를 허용하는 것.
    // Unix only: the bootstrap and symlinks exist only there.
    #[cfg(unix)]
    #[test]
    fn n7_relative_executable_is_rejected() {
        let _inherited_fds = crate::commands::sys::test_inherited_fd_lock();
        let (base, exe) = super::probe("n7-relative");
        let relative = std::path::PathBuf::from(format!(".n7-relative-{}", std::process::id()));
        std::os::unix::fs::symlink(&exe, &relative).unwrap();
        let home = format!("--home={}", base.display());
        let raw = [
            b"--runtime-root=1:2:/r".as_slice(),
            b"--config-root=/c",
            b"--config-root-written=/c",
            b"--state-root=/s",
            home.as_bytes(),
        ];
        let result = crate::prompt_spawn::spawn_for_test(relative.as_os_str(), &raw);
        // A successful spawn is already a failure, even if the child has not
        // been scheduled or finished scanning its descriptor table yet.
        if result.is_ok() {
            super::wait_report(&base.join("probe"));
        }
        std::fs::remove_file(relative).unwrap();
        std::fs::remove_dir_all(base).unwrap();
        assert!(result.is_err(), "relative executable spawned");
    }
}
