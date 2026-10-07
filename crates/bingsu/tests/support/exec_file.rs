//! Making a file that a test executes next, without this test process ever
//! holding a write fd on it. Shared by the bingsu and bingsu-bench tests
//! (`#[path]`); not a test target itself (a subfolder of tests/).
//!
//! Why: test threads run in parallel and spawn children. If one thread
//! holds a write fd on a file (as `std::fs::copy` or `std::fs::write` does
//! while it runs) when another thread forks, the child carries that fd
//! until it execs. An exec of the file in that window fails with ETXTBSY
//! (Linux, "Text file busy"). The write here happens in a separate `cp`
//! process, so this process has no such fd to pass on. A retry at the exec
//! would not cover execs that happen inside a child program (a probe that
//! runs a stub script, bash running a shim).
#![allow(dead_code)] // each test binary uses its own subset

use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;

/// Copies `src` to the new path `dst` with `/bin/cp` (another process;
/// the absolute path so a test's PATH cannot change it). The mode follows
/// `src`. Panics if the copy fails.
pub fn copy_exe(src: &Path, dst: &Path) {
    let st = Command::new("/bin/cp")
        .arg("--")
        .arg(src)
        .arg(dst)
        .status()
        .unwrap_or_else(|e| panic!("/bin/cp {}: {e}", dst.display()));
    assert!(
        st.success(),
        "/bin/cp {} {}: {st}",
        src.display(),
        dst.display()
    );
}

/// Writes `body` to the new path `dst` as an executable (mode 0755): the
/// bytes go to a staging file that is never executed, `/bin/cp` makes
/// `dst`, and the mode is set by path (no fd).
pub fn write_exe(dst: &Path, body: &[u8]) {
    let staging = std::path::PathBuf::from(format!("{}.staging", dst.display()));
    std::fs::write(&staging, body).unwrap();
    copy_exe(&staging, dst);
    std::fs::remove_file(&staging).unwrap();
    std::fs::set_permissions(dst, std::fs::Permissions::from_mode(0o755)).unwrap();
}
