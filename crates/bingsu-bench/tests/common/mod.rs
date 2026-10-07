//! Helpers shared by the integration tests.
#![allow(dead_code)] // each test binary uses its own subset

use std::path::PathBuf;

/// A new folder under the temp dir, removed on drop (also on a failed
/// assertion). The name carries the pid, the time and an attempt number,
/// and `create_dir` refuses one that already exists (the next attempt is
/// tried), so a folder planted there in advance is not used. Test-only:
/// unlike the runner's `new_dir`, no test pins this behaviour.
pub struct TempDir(pub PathBuf);

impl TempDir {
    pub fn new(tag: &str) -> TempDir {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        for attempt in 0..100 {
            let p = std::env::temp_dir().join(format!(
                "bingsu-{tag}-{}-{nanos}-{attempt}",
                std::process::id()
            ));
            match std::fs::create_dir(&p) {
                Ok(()) => return TempDir(p),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => panic!("{}: {e}", p.display()),
            }
        }
        panic!("no free temp folder name for {tag}");
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Gives `p` an extended POSIX ACL under `name` (the access ACL, or a
/// folder's default ACL that new files inherit): owner, one named user,
/// mask, group, other, in the xattr layout of <linux/posix_acl_xattr.h>.
/// Execute bits are set so a folder made under a default ACL can still be
/// entered. A minimal ACL would be folded into the mode bits and not stored.
#[cfg(target_os = "linux")]
pub fn set_posix_acl(p: &std::path::Path, name: &std::ffi::CStr) {
    use std::os::unix::ffi::OsStrExt;
    let mut blob = 2u32.to_le_bytes().to_vec(); // POSIX_ACL_XATTR_VERSION
    // SAFETY: getuid has no preconditions.
    let uid = unsafe { libc::getuid() };
    for (tag, perm, id) in [
        (0x01u16, 7u16, u32::MAX), // ACL_USER_OBJ
        (0x02, 5, uid),            // ACL_USER
        (0x04, 5, u32::MAX),       // ACL_GROUP_OBJ
        (0x10, 5, u32::MAX),       // ACL_MASK
        (0x20, 5, u32::MAX),       // ACL_OTHER
    ] {
        blob.extend(tag.to_le_bytes());
        blob.extend(perm.to_le_bytes());
        blob.extend(id.to_le_bytes());
    }
    let c = std::ffi::CString::new(p.as_os_str().as_bytes()).unwrap();
    // SAFETY: path and name are NUL-terminated; `blob` is readable for its length.
    let rc = unsafe {
        libc::setxattr(
            c.as_ptr(),
            name.as_ptr(),
            blob.as_ptr().cast(),
            blob.len(),
            0,
        )
    };
    assert_eq!(rc, 0, "setxattr: {}", std::io::Error::last_os_error());
}
