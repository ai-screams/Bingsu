//! The only module in this crate allowed to use `unsafe` (the allow is on
//! `mod sys;` in main.rs). Every block carries a SAFETY comment (workspace lint).

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WriteOutcome {
    Done,
    /// EPIPE or another error: the shell will see a truncated record and
    /// fall back to its minimal prompt. We stay silent (spec section 6).
    /// EAGAIN is not retried and ends as `Failed`: on a non-blocking fd the
    /// record may be cut short and the shell falls back to its minimal prompt.
    Failed,
}

/// Hand-written write(2) loop. `write_all` retries EINTR on its own, which
/// a timer could not interrupt (spec section 4 "output rules"). M3a adds
/// the deadline-flag check on EINTR; M1 has no timer yet.
pub fn write_fd(fd: i32, mut buf: &[u8]) -> WriteOutcome {
    while !buf.is_empty() {
        // SAFETY: `buf` is an initialized slice valid for `buf.len()` bytes.
        let n = unsafe { libc::write(fd, buf.as_ptr().cast(), buf.len()) };
        if n < 0 {
            if std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return WriteOutcome::Failed;
        }
        let n = usize::try_from(n).unwrap_or(0);
        // A zero return on a non-empty buffer means no progress on an
        // ordinary fd; retrying would spin and the prompt must never block.
        // Not reproducible from a test, so no mutation was run for this arm.
        if n == 0 {
            return WriteOutcome::Failed;
        }
        buf = &buf[n.min(buf.len())..];
    }
    WriteOutcome::Done
}

/// `_exit` without atexit handlers (spec section 4, `std::process::exit`
/// is rejected).
pub fn exit_now(code: i32) -> ! {
    // SAFETY: _exit never returns and takes no pointers.
    unsafe { libc::_exit(code) }
}

use crate::init::exe_path::{AclFacts, Group};
use std::ffi::{CStr, OsString};
use std::os::unix::ffi::OsStringExt;
use std::path::PathBuf;

pub fn current_uid() -> u32 {
    // SAFETY: getuid has no preconditions and cannot fail.
    unsafe { libc::getuid() }
}

pub struct Passwd {
    pub name: Vec<u8>,
    pub home: PathBuf,
}

/// getpwuid_r, so `~` never comes from $HOME (spec section 2 extends rules).
pub fn passwd_entry(uid: u32) -> Option<Passwd> {
    let mut buf = vec![0u8; 4096];
    loop {
        // SAFETY: an all-zero passwd is a valid out-parameter value.
        let mut pw: libc::passwd = unsafe { std::mem::zeroed() };
        let mut res: *mut libc::passwd = std::ptr::null_mut();
        // SAFETY: every pointer refers to a live buffer of the stated size.
        let rc =
            unsafe { libc::getpwuid_r(uid, &mut pw, buf.as_mut_ptr().cast(), buf.len(), &mut res) };
        if rc == libc::ERANGE && buf.len() < (1 << 20) {
            buf.resize(buf.len() * 2, 0);
            continue;
        }
        if rc != 0 || res.is_null() {
            return None;
        }
        // SAFETY: on success pw_name is a NUL-terminated string inside `buf`.
        let name = unsafe { CStr::from_ptr(pw.pw_name) }.to_bytes().to_vec();
        // SAFETY: on success pw_dir is a NUL-terminated string inside `buf`.
        let dir = unsafe { CStr::from_ptr(pw.pw_dir) }.to_bytes().to_vec();
        return Some(Passwd {
            name,
            home: PathBuf::from(OsString::from_vec(dir)),
        });
    }
}

/// Membership of `gid` for the group-write rule (spec section 2 safety row,
/// decision 6 review): supplementary members (`gr_mem`) plus every user whose
/// primary group is `gid`. `Unknown` if the group lookup fails or the user
/// enumeration ends with an error. init is single-threaded, so the
/// non-reentrant getpwent walk is acceptable here.
pub fn group_membership(gid: u32, user: &[u8]) -> Group {
    let ok = |n: &[u8]| n == b"root" || n == user;
    let mut buf = vec![0u8; 4096];
    loop {
        // SAFETY: an all-zero group is a valid out-parameter value.
        let mut gr: libc::group = unsafe { std::mem::zeroed() };
        let mut res: *mut libc::group = std::ptr::null_mut();
        // SAFETY: every pointer refers to a live buffer of the stated size.
        let rc =
            unsafe { libc::getgrgid_r(gid, &mut gr, buf.as_mut_ptr().cast(), buf.len(), &mut res) };
        if rc == libc::ERANGE && buf.len() < (1 << 20) {
            buf.resize(buf.len() * 2, 0);
            continue;
        }
        if rc != 0 || res.is_null() {
            return Group::Unknown;
        }
        let mut p = gr.gr_mem;
        loop {
            // SAFETY: gr_mem is a NULL-terminated array of pointers inside `buf`.
            let m = unsafe { *p };
            if m.is_null() {
                break;
            }
            // SAFETY: each member is a NUL-terminated string inside `buf`.
            if !ok(unsafe { CStr::from_ptr(m) }.to_bytes()) {
                return Group::HasOthers;
            }
            // SAFETY: the terminator has not been reached, so p+1 is in bounds.
            p = unsafe { p.add(1) };
        }
        break;
    }
    // Primary-group members: walk the user database.
    // SAFETY: resets the iterator; no pointers involved.
    unsafe { libc::setpwent() };
    let mut verdict = Group::OnlyRootAndUser;
    loop {
        // SAFETY: clears errno so a NULL return can be told apart from an error.
        unsafe { *errno_location() = 0 };
        // SAFETY: getpwent returns NULL or a pointer valid until the next call.
        let pw = unsafe { libc::getpwent() };
        if pw.is_null() {
            if std::io::Error::last_os_error().raw_os_error().unwrap_or(0) != 0 {
                verdict = Group::Unknown;
            }
            break;
        }
        // SAFETY: `pw` is non-null and points to a valid passwd record.
        let rec = unsafe { &*pw };
        // SAFETY: pw_name is a NUL-terminated string owned by the record.
        let name = unsafe { CStr::from_ptr(rec.pw_name) }.to_bytes().to_vec();
        let pgid = rec.pw_gid;
        if pgid == gid && !ok(&name) {
            verdict = Group::HasOthers;
            break;
        }
    }
    // SAFETY: closes the iterator opened above.
    unsafe { libc::endpwent() };
    verdict
}

#[cfg(target_os = "linux")]
fn errno_location() -> *mut libc::c_int {
    // SAFETY: returns this thread's errno slot.
    unsafe { libc::__errno_location() }
}

#[cfg(target_os = "macos")]
fn errno_location() -> *mut libc::c_int {
    // SAFETY: returns this thread's errno slot.
    unsafe { libc::__error() }
}

#[cfg(target_os = "macos")]
mod macos_acl {
    unsafe extern "C" {
        pub fn acl_get_link_np(path: *const libc::c_char, ty: libc::c_int) -> *mut libc::c_void;
        pub fn acl_get_entry(
            acl: *mut libc::c_void,
            id: libc::c_int,
            e: *mut *mut libc::c_void,
        ) -> libc::c_int;
        pub fn acl_get_tag_type(e: *mut libc::c_void, t: *mut libc::c_int) -> libc::c_int;
        pub fn acl_get_permset(e: *mut libc::c_void, p: *mut *mut libc::c_void) -> libc::c_int;
        pub fn acl_get_perm_np(p: *mut libc::c_void, perm: libc::c_int) -> libc::c_int;
        pub fn acl_free(o: *mut libc::c_void) -> libc::c_int;
    }
    // <sys/acl.h>, verified against the SDK on 2026-10-04.
    pub const ACL_TYPE_EXTENDED: libc::c_int = 0x100;
    pub const ACL_FIRST_ENTRY: libc::c_int = 0;
    pub const ACL_NEXT_ENTRY: libc::c_int = -1;
    pub const ACL_EXTENDED_ALLOW: libc::c_int = 1;
    pub const WRITE_CLASS: [libc::c_int; 8] = [
        1 << 2,
        1 << 4,
        1 << 5,
        1 << 6,
        1 << 8,
        1 << 10,
        1 << 12,
        1 << 13,
    ];
}

/// macOS extended ACL of `path` (not following a final symlink).
#[cfg(target_os = "macos")]
pub fn acl_facts(path: &std::path::Path) -> AclFacts {
    use macos_acl::*;
    use std::os::unix::ffi::OsStrExt;
    let Ok(c) = std::ffi::CString::new(path.as_os_str().as_bytes()) else {
        return AclFacts::Unknown;
    };
    // SAFETY: `c` is NUL-terminated; NULL means "no extended ACL" or an error.
    let acl = unsafe { acl_get_link_np(c.as_ptr(), ACL_TYPE_EXTENDED) };
    if acl.is_null() {
        let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        return if e == libc::ENOENT || e == 0 {
            AclFacts::None
        } else {
            AclFacts::Unknown
        };
    }
    let mut facts = AclFacts::None;
    let mut id = ACL_FIRST_ENTRY;
    loop {
        let mut entry = std::ptr::null_mut();
        // SAFETY: `acl` is a live ACL; `entry` receives a pointer into it.
        if unsafe { acl_get_entry(acl, id, &mut entry) } != 0 {
            break;
        }
        id = ACL_NEXT_ENTRY;
        let mut tag = 0;
        let mut perms = std::ptr::null_mut();
        // SAFETY: `entry` is valid until the ACL is freed.
        let t = unsafe { acl_get_tag_type(entry, &mut tag) };
        // SAFETY: as above.
        let q = unsafe { acl_get_permset(entry, &mut perms) };
        if t != 0 || q != 0 {
            facts = AclFacts::Unknown;
            break;
        }
        if tag == ACL_EXTENDED_ALLOW {
            let allows = |w| {
                // SAFETY: `perms` belongs to `entry`.
                unsafe { acl_get_perm_np(perms, w) == 1 }
            };
            if WRITE_CLASS.iter().any(|&w| allows(w)) {
                facts = AclFacts::AllowsWrite;
                break;
            }
        } else if facts == AclFacts::None {
            facts = AclFacts::DenyOnly;
        }
    }
    // SAFETY: `acl` was returned by acl_get_link_np and is freed once.
    unsafe { acl_free(acl) };
    facts
}

/// Linux: a POSIX access ACL makes the verdict "unknown" until X-28 (M3a)
/// shows whether the group mask bits already cover it.
#[cfg(target_os = "linux")]
pub fn acl_facts(path: &std::path::Path) -> AclFacts {
    use std::os::unix::ffi::OsStrExt;
    let Ok(c) = std::ffi::CString::new(path.as_os_str().as_bytes()) else {
        return AclFacts::Unknown;
    };
    // SAFETY: names are NUL-terminated; size 0 asks only for the length.
    let n = unsafe {
        libc::lgetxattr(
            c.as_ptr(),
            c"system.posix_acl_access".as_ptr(),
            std::ptr::null_mut(),
            0,
        )
    };
    if n > 0 {
        return AclFacts::Unknown;
    }
    let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
    if n == 0 || e == libc::ENODATA || e == libc::ENOTSUP {
        AclFacts::None
    } else {
        AclFacts::Unknown
    }
}

/// 16 random bytes for the session value (spec section 3 "session").
pub fn random_bytes16() -> Option<[u8; 16]> {
    let mut b = [0u8; 16];
    // SAFETY: `b` is 16 writable bytes; getentropy accepts up to 256.
    if unsafe { libc::getentropy(b.as_mut_ptr().cast(), b.len()) } == 0 {
        return Some(b);
    }
    use std::io::Read;
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut b))
        .ok()
        .map(|()| b)
}
