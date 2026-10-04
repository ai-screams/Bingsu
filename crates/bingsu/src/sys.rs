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

#[cfg(target_os = "macos")]
use crate::init::exe_path::{AclEntry, fold_acl};
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

/// More users than this and the enumeration counts as failed (`Unknown`).
/// Linux too: a large directory-service setup gets the "could not confirm"
/// warning rather than a long walk.
const MAX_USERS: usize = 4096;

/// One local account, as the group-write rule needs it.
pub struct UserEntry {
    name: Vec<u8>,
    gid: u32,
    /// macOS: the account's membership uuid (`None` if it could not be
    /// converted; any question about this user is then unanswered).
    #[cfg(target_os = "macos")]
    uuid: Option<[u8; 16]>,
}

/// Every account `getpwent` returns, read once per init. `None` if the
/// enumeration ends with an error or passes `MAX_USERS`. init is
/// single-threaded, so the non-reentrant getpwent walk is acceptable here.
pub fn local_users() -> Option<Vec<UserEntry>> {
    let mut out = Vec::new();
    let failed;
    // SAFETY: resets the iterator; no pointers involved.
    unsafe { libc::setpwent() };
    loop {
        // SAFETY: clears errno so a NULL return can be told apart from an error.
        unsafe { *errno_location() = 0 };
        // SAFETY: getpwent returns NULL or a pointer valid until the next call.
        let pw = unsafe { libc::getpwent() };
        if pw.is_null() {
            failed = std::io::Error::last_os_error().raw_os_error().unwrap_or(0) != 0;
            break;
        }
        if out.len() == MAX_USERS {
            failed = true;
            break;
        }
        // SAFETY: `pw` is non-null and points to a valid passwd record.
        let rec = unsafe { &*pw };
        // SAFETY: pw_name is a NUL-terminated string owned by the record.
        let name = unsafe { CStr::from_ptr(rec.pw_name) }.to_bytes().to_vec();
        out.push(UserEntry {
            name,
            gid: rec.pw_gid,
            #[cfg(target_os = "macos")]
            uuid: macos_mbr::uid_uuid(rec.pw_uid),
        });
    }
    // SAFETY: closes the iterator opened above.
    unsafe { libc::endpwent() };
    (!failed).then_some(out)
}

/// Membership of `gid` for the group-write rule (spec section 2 safety row,
/// decision 6 review): supplementary members (`gr_mem`) plus every user whose
/// primary group is `gid`. On macOS each user is also asked of the system
/// (`mbr_check_membership`), because groups such as `everyone`,
/// `localaccounts` and `_developer` have their members computed by the
/// system: `gr_mem` is empty and no user has them as primary group.
/// `users` is `local_users()`, read once by the caller. `Unknown` if the
/// group lookup fails, `users` is `None`, or a membership question fails.
pub fn group_membership(gid: u32, user: &[u8], users: Option<&[UserEntry]>) -> Group {
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
            // SAFETY: gr_mem is a NULL-terminated array of pointers inside
            // `buf`. libinfo places it at an arbitrary offset right after the
            // name strings, so alignment is not assumed (aligning `buf` would
            // not help: libinfo picks the offset).
            let m = unsafe { p.read_unaligned() };
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
    let Some(users) = users else {
        return Group::Unknown;
    };
    #[cfg(target_os = "macos")]
    let Some(group_uuid) = macos_mbr::gid_uuid(gid) else {
        return Group::Unknown;
    };
    // Only the macOS membership question can lower this to `Unknown`.
    #[cfg(target_os = "macos")]
    let mut verdict = Group::OnlyRootAndUser;
    #[cfg(not(target_os = "macos"))]
    let verdict = Group::OnlyRootAndUser;
    for u in users {
        if ok(&u.name) {
            continue;
        }
        if u.gid == gid {
            return Group::HasOthers;
        }
        #[cfg(target_os = "macos")]
        match u.uuid.and_then(|uu| macos_mbr::is_member(&uu, &group_uuid)) {
            Some(true) => return Group::HasOthers,
            Some(false) => {}
            // Keep looking: a member found later is worse than unknown.
            None => verdict = Group::Unknown,
        }
    }
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
mod macos_mbr {
    type Uuid = [u8; 16];
    unsafe extern "C" {
        // <membership.h>; uuid_t is unsigned char[16].
        fn mbr_uid_to_uuid(uid: libc::uid_t, uu: *mut u8) -> libc::c_int;
        fn mbr_gid_to_uuid(gid: libc::gid_t, uu: *mut u8) -> libc::c_int;
        fn mbr_check_membership(
            user: *const u8,
            group: *const u8,
            ismember: *mut libc::c_int,
        ) -> libc::c_int;
    }

    pub fn gid_uuid(gid: u32) -> Option<Uuid> {
        let mut u = [0u8; 16];
        // SAFETY: `u` is the 16-byte uuid_t the function fills.
        (unsafe { mbr_gid_to_uuid(gid, u.as_mut_ptr()) } == 0).then_some(u)
    }

    pub fn uid_uuid(uid: u32) -> Option<Uuid> {
        let mut u = [0u8; 16];
        // SAFETY: `u` is the 16-byte uuid_t the function fills.
        (unsafe { mbr_uid_to_uuid(uid, u.as_mut_ptr()) } == 0).then_some(u)
    }

    /// The system's answer to "is this user a member of the group",
    /// including computed and nested membership. `None` if the call fails.
    pub fn is_member(user: &Uuid, group: &Uuid) -> Option<bool> {
        let mut is = 0;
        // SAFETY: both uuids are 16 readable bytes; `is` is a writable int.
        let rc = unsafe { mbr_check_membership(user.as_ptr(), group.as_ptr(), &mut is) };
        (rc == 0).then_some(is != 0)
    }
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
    pub const ACL_EXTENDED_DENY: libc::c_int = 2;
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
    let mut entries: Vec<Result<AclEntry, ()>> = Vec::new();
    let mut id = ACL_FIRST_ENTRY;
    loop {
        let mut entry = std::ptr::null_mut();
        // SAFETY: clears errno so the -1 at the end can be told from an error.
        unsafe { *errno_location() = 0 };
        // SAFETY: `acl` is a live ACL; `entry` receives a pointer into it.
        if unsafe { acl_get_entry(acl, id, &mut entry) } != 0 {
            // EINVAL means "no more entries" (acl_get_entry(3)); any other
            // error leaves the ACL unread.
            if std::io::Error::last_os_error().raw_os_error() != Some(libc::EINVAL) {
                entries.push(Err(()));
            }
            break;
        }
        id = ACL_NEXT_ENTRY;
        let mut tag = 0;
        let mut perms = std::ptr::null_mut();
        // SAFETY: `entry` is valid until the ACL is freed.
        let t = unsafe { acl_get_tag_type(entry, &mut tag) };
        // SAFETY: as above.
        let q = unsafe { acl_get_permset(entry, &mut perms) };
        let item = if t != 0 || q != 0 {
            Err(())
        } else if tag == ACL_EXTENDED_ALLOW {
            let mut writes = Ok(false);
            for &w in &WRITE_CLASS {
                // SAFETY: `perms` belongs to `entry`.
                match unsafe { acl_get_perm_np(perms, w) } {
                    1 => writes = writes.map(|_| true),
                    0 => {}
                    _ => writes = Err(()),
                }
            }
            writes.map(|writes| AclEntry::Allow { writes })
        } else if tag == ACL_EXTENDED_DENY {
            Ok(AclEntry::Deny)
        } else {
            Err(())
        };
        let failed = item.is_err();
        entries.push(item);
        if failed {
            break;
        }
    }
    let facts = fold_acl(entries);
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

/// Whether the file system holding `path` is local (macOS `MNT_LOCAL`).
/// `None` if statfs fails.
#[cfg(target_os = "macos")]
pub fn fs_is_local(path: &std::path::Path) -> Option<bool> {
    use std::os::unix::ffi::OsStrExt;
    let c = std::ffi::CString::new(path.as_os_str().as_bytes()).ok()?;
    // SAFETY: an all-zero statfs is a valid out-parameter value.
    let mut st: libc::statfs = unsafe { std::mem::zeroed() };
    // SAFETY: `c` is NUL-terminated and `st` is a writable statfs.
    (unsafe { libc::statfs(c.as_ptr(), &mut st) } == 0).then(|| flags_are_local(st.f_flags))
}

/// As `fs_is_local`, for an open descriptor.
#[cfg(target_os = "macos")]
pub fn fd_is_local(fd: std::os::fd::RawFd) -> Option<bool> {
    // SAFETY: an all-zero statfs is a valid out-parameter value.
    let mut st: libc::statfs = unsafe { std::mem::zeroed() };
    // SAFETY: `st` is a writable statfs; a bad fd only makes fstatfs fail.
    (unsafe { libc::fstatfs(fd, &mut st) } == 0).then(|| flags_are_local(st.f_flags))
}

#[cfg(target_os = "macos")]
fn flags_are_local(f_flags: u32) -> bool {
    f_flags & (libc::MNT_LOCAL as u32) != 0
}

/// Linux: rejecting NFS, CIFS and FUSE by `f_type` is M3; until then every
/// file system counts as local.
#[cfg(target_os = "linux")]
pub fn fs_is_local(_path: &std::path::Path) -> Option<bool> {
    Some(true)
}

#[cfg(target_os = "linux")]
pub fn fd_is_local(_fd: std::os::fd::RawFd) -> Option<bool> {
    Some(true)
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::*;

    // 이것을 실패시키는 것: MNT_LOCAL 비트를 보지 않는 것(네트워크 FS를 로컬로 봄).
    #[test]
    fn mnt_local_bit_decides() {
        assert!(!flags_are_local(0));
        assert!(!flags_are_local(0x1));
        assert!(flags_are_local(libc::MNT_LOCAL as u32 | 0x1));
        assert_eq!(fs_is_local(std::path::Path::new("/")), Some(true));
    }

    // `everyone` (gid 12) lists no members and is nobody's primary group;
    // the system computes its members (nobody, daemon, ...). Called with the
    // gid of a real group-writable folder.
    // 이것을 실패시키는 것: 시스템 판정(mbr_check_membership)을 빼고 gr_mem·기본 gid만 보는 것,
    // gr_mem 배열을 정렬된 포인터로 읽는 것(debug에서 misaligned 패닉).
    #[test]
    fn computed_group_everyone_has_others() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let d = std::env::temp_dir().join(format!("bingsu-everyone-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        std::os::unix::fs::chown(&d, None, Some(12)).unwrap();
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o775)).unwrap();
        let gid = std::fs::metadata(&d).unwrap().gid();
        let me = passwd_entry(current_uid()).unwrap().name;
        let users = local_users();
        assert_eq!(
            group_membership(gid, &me, users.as_deref()),
            Group::HasOthers
        );
        std::fs::remove_dir_all(&d).unwrap();
    }
}

/// `mkdirat(dir, name, mode)`; an existing entry counts as success (the
/// caller opens it without following and checks what it is).
pub fn mkdir_at(
    dir: std::os::fd::BorrowedFd<'_>,
    name: &std::ffi::OsStr,
    mode: u32,
) -> std::io::Result<()> {
    use std::os::fd::AsRawFd;
    use std::os::unix::ffi::OsStrExt;
    let c = std::ffi::CString::new(name.as_bytes())?;
    let mode = libc::mode_t::try_from(mode).map_err(|_| std::io::Error::other("mode"))?;
    // SAFETY: `dir` is an open descriptor and `c` is NUL-terminated.
    if unsafe { libc::mkdirat(dir.as_raw_fd(), c.as_ptr(), mode) } == 0 {
        return Ok(());
    }
    let e = std::io::Error::last_os_error();
    if e.raw_os_error() == Some(libc::EEXIST) {
        Ok(())
    } else {
        Err(e)
    }
}

/// Opens the folder `name` inside `dir` without following a symlink at that
/// last name (`O_NOFOLLOW`): a symlink fails with ELOOP, anything other
/// than a folder with ENOTDIR.
pub fn open_dir_at_nofollow(
    dir: std::os::fd::BorrowedFd<'_>,
    name: &std::ffi::OsStr,
) -> std::io::Result<std::fs::File> {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::os::unix::ffi::OsStrExt;
    let c = std::ffi::CString::new(name.as_bytes())?;
    let flags = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC;
    // SAFETY: `dir` is an open descriptor and `c` is NUL-terminated.
    let fd = unsafe { libc::openat(dir.as_raw_fd(), c.as_ptr(), flags) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: openat returned a fresh descriptor that nothing else owns.
    Ok(std::fs::File::from(unsafe { OwnedFd::from_raw_fd(fd) }))
}
