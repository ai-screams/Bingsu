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
