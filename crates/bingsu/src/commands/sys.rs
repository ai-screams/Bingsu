//! System calls of the commands other than `prompt` (the allow for
//! `unsafe` is on `mod sys;` in commands/mod.rs; the prompt makes its own
//! in crate::prompt and crate::sandbox and cannot name this module). Every
//! block carries a SAFETY comment (workspace lint).
// The clippy.toml rules (environment reads among them, spec 4 rule 7, F-01)
// are forbidden here. Unlike the crate-wide deny, forbid cannot
// be switched off with #[expect] or #[allow].
#![forbid(
    clippy::disallowed_methods,
    clippy::disallowed_types,
    clippy::disallowed_macros
)]

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

use crate::commands::group_policy::Account;
#[cfg(target_os = "macos")]
use bingsu_core::fs_trust::{AclEntry, fold_acl};
use bingsu_core::fs_trust::{AclFacts, Facts};
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
    pub gid: u32,
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
            gid: pw.pw_gid,
            home: PathBuf::from(OsString::from_vec(dir)),
        });
    }
}

/// More entries than this and the enumeration counts as failed (`Unknown`).
/// Linux too: a large directory-service setup gets the "could not confirm"
/// warning rather than a long walk.
const MAX_USERS: usize = 4096;

/// Every account `getpwent` returns, read at most once per `SystemGroups`
/// walk. `None` if enumeration ends with an error or passes `MAX_USERS`.
/// Callers must serialize these non-reentrant walks (init is single-threaded).
///
/// macOS `getpwent` returns each local account twice (265 entries for 133
/// accounts on the development Mac, all exact repeats), so entries equal in
/// uid, name and primary gid are kept once; entries that differ in any of
/// them are all kept, so no check is dropped. The uuid is converted once per
/// uid. `MAX_USERS` counts entries as returned, repeats included, so an
/// enumeration that keeps returning the same entries still ends.
pub fn local_users() -> Option<Vec<Account>> {
    let mut out = Vec::new();
    let mut returned = 0usize;
    let mut kept = std::collections::HashSet::<(u32, Vec<u8>, u32)>::new();
    #[cfg(target_os = "macos")]
    let mut uuids = std::collections::HashMap::<u32, Option<[u8; 16]>>::new();
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
        if returned == MAX_USERS {
            failed = true;
            break;
        }
        returned += 1;
        // SAFETY: `pw` is non-null and points to a valid passwd record.
        let rec = unsafe { &*pw };
        // SAFETY: pw_name is a NUL-terminated string owned by the record.
        let name = unsafe { CStr::from_ptr(rec.pw_name) }.to_bytes().to_vec();
        if !kept.insert((rec.pw_uid, name.clone(), rec.pw_gid)) {
            continue;
        }
        out.push(Account {
            name,
            gid: rec.pw_gid,
            #[cfg(target_os = "macos")]
            uuid: *uuids
                .entry(rec.pw_uid)
                .or_insert_with(|| macos_mbr::uid_uuid(rec.pw_uid)),
        });
    }
    // SAFETY: closes the iterator opened above.
    unsafe { libc::endpwent() };
    (!failed).then_some(out)
}

/// The supplementary members (`gr_mem`) of `gid`, `None` if the lookup
/// fails. The rule that judges them is `group_policy::membership`.
pub fn group_info(gid: u32) -> Option<(Vec<u8>, Vec<Vec<u8>>)> {
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
            return None;
        }
        let mut out = Vec::new();
        let mut p = gr.gr_mem;
        loop {
            // SAFETY: gr_mem is a NULL-terminated array of pointers inside
            // `buf`. libinfo places it at an arbitrary offset right after the
            // name strings, so alignment is not assumed (aligning `buf` would
            // not help: libinfo picks the offset).
            let m = unsafe { p.read_unaligned() };
            if m.is_null() {
                // SAFETY: successful getgrgid_r returned a NUL-terminated name.
                let name = unsafe { CStr::from_ptr(gr.gr_name) }.to_bytes().to_vec();
                return Some((name, out));
            }
            // SAFETY: each member is a NUL-terminated string inside `buf`.
            out.push(unsafe { CStr::from_ptr(m) }.to_bytes().to_vec());
            // SAFETY: the terminator has not been reached, so p+1 is in bounds.
            p = unsafe { p.add(1) };
        }
    }
}

/// A question about one account (see `computed_member`).
pub type MemberQuestion = Box<dyn FnMut(&Account) -> Option<bool>>;

/// The system's answer to "is this account a member of `gid`" for groups
/// whose members the system computes. macOS: `everyone`, `localaccounts`
/// and `_developer` list no members and are nobody's primary group, so each
/// account is asked (`mbr_check_membership`); `None` when a question fails.
/// Elsewhere there is no such question (`Some(false)`).
pub fn computed_member(gid: u32) -> MemberQuestion {
    #[cfg(target_os = "macos")]
    {
        let group = macos_mbr::gid_uuid(gid);
        Box::new(move |a: &Account| macos_mbr::is_member(&a.uuid?, &group?))
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = gid;
        Box::new(|_: &Account| Some(false))
    }
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
    acl_entries(acl)
}

/// Folds and frees an ACL returned by `acl_get_link_np` or `acl_get_fd_np`.
#[cfg(target_os = "macos")]
fn acl_entries(acl: *mut libc::c_void) -> AclFacts {
    use macos_acl::*;
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

/// Linux: whether `path` has an extended POSIX access ACL. X-28 (Debian 12
/// on the colima kernel, 2026-10-15): the mode's group bits are then the
/// ACL mask, the upper bound of every named user and group entry (`setfacl
/// -m u:nobody:rwx` then `chmod g-w`: nobody could not create a file). So
/// the ACL matters only under group write, where `fs_trust` treats it as
/// undecided (`PosixExtended`): the group rule speaks for the owning group,
/// not for named entries.
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
    posix_acl_answer(n)
}

/// Linux: the answer of a `getxattr` length query for the access ACL.
#[cfg(target_os = "linux")]
fn posix_acl_answer(n: libc::ssize_t) -> AclFacts {
    if n > 0 {
        return AclFacts::PosixExtended;
    }
    let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
    if n == 0 || e == libc::ENODATA || e == libc::ENOTSUP {
        AclFacts::None
    } else {
        AclFacts::Unknown
    }
}

/// macOS extended ACL of an open descriptor (`acl_get_fd_np`; works on an
/// `O_SEARCH` descriptor, observed 2026-10-15 on macOS 27, also for a 0711
/// folder).
#[cfg(target_os = "macos")]
pub fn acl_facts_fd(fd: std::os::fd::BorrowedFd<'_>) -> AclFacts {
    use std::os::fd::AsRawFd;
    unsafe extern "C" {
        fn acl_get_fd_np(fd: libc::c_int, ty: libc::c_int) -> *mut libc::c_void;
    }
    // SAFETY: `fd` is open for the duration of the call; NULL means "no
    // extended ACL" (ENOENT) or an error.
    let acl = unsafe { acl_get_fd_np(fd.as_raw_fd(), macos_acl::ACL_TYPE_EXTENDED) };
    acl_entries(acl)
}

/// Linux: as `acl_facts`, for an open descriptor. `fgetxattr` fails with
/// EBADF on an `O_PATH` descriptor (observed 2026-10-15), so that case asks
/// through `/proc/self/fd/N`, which names the same object.
#[cfg(target_os = "linux")]
pub fn acl_facts_fd(fd: std::os::fd::BorrowedFd<'_>) -> AclFacts {
    use std::os::fd::AsRawFd;
    let name = c"system.posix_acl_access";
    // SAFETY: `fd` is open; size 0 asks only for the length.
    let n = unsafe { libc::fgetxattr(fd.as_raw_fd(), name.as_ptr(), std::ptr::null_mut(), 0) };
    if n >= 0 || std::io::Error::last_os_error().raw_os_error() != Some(libc::EBADF) {
        return posix_acl_answer(n);
    }
    let Ok(p) = std::ffi::CString::new(format!("/proc/self/fd/{}", fd.as_raw_fd())) else {
        return AclFacts::Unknown;
    };
    // SAFETY: names are NUL-terminated; size 0 asks only for the length.
    let n = unsafe { libc::getxattr(p.as_ptr(), name.as_ptr(), std::ptr::null_mut(), 0) };
    posix_acl_answer(n)
}

/// `fstat` and the ACL of an open descriptor (search-only descriptors
/// included).
#[allow(
    clippy::useless_conversion,
    clippy::unnecessary_cast,
    reason = "st_mode, st_dev and st_ino differ in type between macOS and Linux"
)]
pub fn fd_facts(fd: std::os::fd::BorrowedFd<'_>) -> std::io::Result<Facts> {
    use std::os::fd::AsRawFd;
    // SAFETY: an all-zero stat is a valid out-parameter value.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: `fd` is open and `st` is a writable stat.
    if unsafe { libc::fstat(fd.as_raw_fd(), &mut st) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(Facts {
        dev: st.st_dev as u64,
        ino: st.st_ino as u64,
        uid: st.st_uid,
        gid: st.st_gid,
        mode: u32::from(st.st_mode),
        ownership: fd_ownership(fd),
        // Linux: the ACL matters only under group write (see `acl_facts`).
        acl: if cfg!(target_os = "linux") && u32::from(st.st_mode) & 0o020 == 0 {
            AclFacts::None
        } else {
            acl_facts_fd(fd)
        },
    })
}

/// Mount ownership is a separate fact from locality. A failed fstatfs is
/// undecidable. Linux ownership follows the platform filesystem contract.
#[cfg(target_os = "macos")]
pub fn fd_ownership(fd: std::os::fd::BorrowedFd<'_>) -> Option<bool> {
    use std::os::fd::AsRawFd;
    // SAFETY: zero is valid for this out parameter; fd is borrowed and open.
    let mut st: libc::statfs = unsafe { std::mem::zeroed() };
    // SAFETY: st is writable for the duration of the call.
    (unsafe { libc::fstatfs(fd.as_raw_fd(), &mut st) } == 0)
        .then(|| bingsu_core::fs_trust::macos_ownership_enforced(st.f_flags))
}

#[cfg(target_os = "linux")]
pub fn fd_ownership(_: std::os::fd::BorrowedFd<'_>) -> Option<bool> {
    Some(true)
}

/// 16 random bytes for the session value (spec section 3 "session").
pub fn random_bytes16() -> Option<[u8; 16]> {
    let mut b = [0u8; 16];
    // musl has no getentropy in the libc crate; getrandom never returns a
    // short read or EINTR for 256 bytes or fewer once the pool is ready
    // (getrandom(2)), so anything but 16 falls back to /dev/urandom.
    #[cfg(target_os = "linux")]
    // SAFETY: `b` is 16 writable bytes and the length passed is its length.
    let filled = unsafe { libc::getrandom(b.as_mut_ptr().cast(), b.len(), 0) } == 16;
    #[cfg(not(target_os = "linux"))]
    // SAFETY: `b` is 16 writable bytes; getentropy accepts up to 256.
    let filled = unsafe { libc::getentropy(b.as_mut_ptr().cast(), b.len()) } == 0;
    if filled {
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
    bingsu_core::fs_trust::macos_fs_is_local(f_flags)
}

/// Linux: `statfs.f_type` against the allowlist in
/// `bingsu_core::fs_trust::LINUX_LOCAL_TYPES` (NFS, CIFS, FUSE and any type
/// not listed are not local). `None` if statfs fails.
#[cfg(target_os = "linux")]
pub fn fs_is_local(path: &std::path::Path) -> Option<bool> {
    use std::os::unix::ffi::OsStrExt;
    let c = std::ffi::CString::new(path.as_os_str().as_bytes()).ok()?;
    // SAFETY: an all-zero statfs is a valid out-parameter value.
    let mut st: libc::statfs = unsafe { std::mem::zeroed() };
    // SAFETY: `c` is NUL-terminated and `st` is a writable statfs.
    (unsafe { libc::statfs(c.as_ptr(), &mut st) } == 0).then(|| f_type_is_local(&st))
}

/// As `fs_is_local`, for an open descriptor (`O_PATH` included: fstatfs
/// works on it, observed 2026-10-15 on the colima kernel).
#[cfg(target_os = "linux")]
pub fn fd_is_local(fd: std::os::fd::RawFd) -> Option<bool> {
    // SAFETY: an all-zero statfs is a valid out-parameter value.
    let mut st: libc::statfs = unsafe { std::mem::zeroed() };
    // SAFETY: `st` is a writable statfs; a bad fd only makes fstatfs fail.
    (unsafe { libc::fstatfs(fd, &mut st) } == 0).then(|| f_type_is_local(&st))
}

/// `f_type` is `__fsword_t` on glibc and `c_ulong` on musl; magic numbers
/// are 32-bit, so the low 32 bits are compared.
#[cfg(target_os = "linux")]
#[allow(
    clippy::unnecessary_cast,
    reason = "f_type differs between glibc and musl"
)]
fn f_type_is_local(st: &libc::statfs) -> bool {
    bingsu_core::fs_trust::linux_fs_is_local(st.f_type as u64 & 0xffff_ffff)
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
        let mut groups = crate::commands::group_policy::SystemGroups::new(&me);
        assert_eq!(groups.gid(gid), bingsu_core::fs_trust::Group::HasOthers);
        let users = local_users();
        // Exact repeats from getpwent are dropped: on this Mac every account
        // comes twice, and every kept entry differs in name or primary gid.
        // 이것을 실패시키는 것: 열거 결과의 중복을 없애지 않는 것(질의가 두 배).
        let users = users.unwrap();
        let mut keys: Vec<_> = users.iter().map(|u| (u.name.clone(), u.gid)).collect();
        keys.sort();
        keys.dedup();
        assert_eq!(keys.len(), users.len());
        std::fs::remove_dir_all(&d).unwrap();
    }
}

/// `mkdirat(dir, name, mode)`. `Ok(true)` if this call created it,
/// `Ok(false)` if the entry already existed (the caller opens it without
/// following and checks what it is).
pub fn mkdir_at(
    dir: std::os::fd::BorrowedFd<'_>,
    name: &std::ffi::OsStr,
    mode: u32,
) -> std::io::Result<bool> {
    use std::os::fd::AsRawFd;
    use std::os::unix::ffi::OsStrExt;
    let c = std::ffi::CString::new(name.as_bytes())?;
    let mode = libc::mode_t::try_from(mode).map_err(|_| std::io::Error::other("mode"))?;
    // SAFETY: `dir` is an open descriptor and `c` is NUL-terminated.
    if unsafe { libc::mkdirat(dir.as_raw_fd(), c.as_ptr(), mode) } == 0 {
        return Ok(true);
    }
    let e = std::io::Error::last_os_error();
    if e.raw_os_error() == Some(libc::EEXIST) {
        Ok(false)
    } else {
        Err(e)
    }
}

/// `unlinkat(dir, name, AT_REMOVEDIR)`: removes an empty folder.
pub fn remove_dir_at(
    dir: std::os::fd::BorrowedFd<'_>,
    name: &std::ffi::OsStr,
) -> std::io::Result<()> {
    use std::os::fd::AsRawFd;
    use std::os::unix::ffi::OsStrExt;
    let c = std::ffi::CString::new(name.as_bytes())?;
    // SAFETY: `dir` is an open descriptor and `c` is NUL-terminated.
    if unsafe { libc::unlinkat(dir.as_raw_fd(), c.as_ptr(), libc::AT_REMOVEDIR) } == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

/// Opens the folder `name` inside `dir` without following a symlink at that
/// last name (`O_NOFOLLOW`): a symlink fails with ELOOP, anything other
/// than a folder with ENOTDIR.
pub fn open_dir_at_nofollow(
    dir: std::os::fd::BorrowedFd<'_>,
    name: &std::ffi::OsStr,
) -> std::io::Result<std::fs::File> {
    open_at(Some(dir), name, libc::O_RDONLY | libc::O_DIRECTORY)
}

/// Search-only access for a walk descriptor: it can serve as the folder
/// that `openat` and `mkdirat` resolve names in, and needs only search (x)
/// permission, never read (r). An ancestor like `/home` at 0711 is
/// searchable but not readable. Linux `O_PATH`; macOS `O_SEARCH`
/// (`O_EXEC | O_DIRECTORY`).
#[cfg(target_os = "linux")]
const SEARCH_ONLY: libc::c_int = libc::O_PATH;
#[cfg(target_os = "macos")]
const SEARCH_ONLY: libc::c_int = libc::O_SEARCH;

/// Like `open_dir_at_nofollow`, but the descriptor is search-only (see
/// `SEARCH_ONLY`); `dir = None` opens "/" itself. The descriptor is only a
/// base for further `*at` calls: reading entries and (on Linux) `fchmod`
/// do not work through it. `fstatfs` works, as required by `fd_is_local`.
pub fn open_dir_at_search_nofollow(
    dir: Option<std::os::fd::BorrowedFd<'_>>,
    name: &std::ffi::OsStr,
) -> std::io::Result<std::fs::File> {
    open_at(dir, name, SEARCH_ONLY | libc::O_DIRECTORY)
}

/// `openat(dir, name, access | O_NOFOLLOW | O_CLOEXEC)`; `dir = None` means
/// `name` must be absolute and is opened as given.
fn open_at(
    dir: Option<std::os::fd::BorrowedFd<'_>>,
    name: &std::ffi::OsStr,
    access: libc::c_int,
) -> std::io::Result<std::fs::File> {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::os::unix::ffi::OsStrExt;
    let c = std::ffi::CString::new(name.as_bytes())?;
    let base = match dir {
        Some(d) => d.as_raw_fd(),
        None if name.as_bytes().starts_with(b"/") => libc::AT_FDCWD,
        None => {
            return Err(std::io::Error::other(
                "open_at: relative name without a folder",
            ));
        }
    };
    let flags = access | libc::O_NOFOLLOW | libc::O_CLOEXEC;
    // SAFETY: `base` is an open descriptor borrowed for this call (or
    // AT_FDCWD with an absolute name, where it is ignored) and `c` is
    // NUL-terminated.
    let fd = unsafe { libc::openat(base, c.as_ptr(), flags) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: openat returned a fresh descriptor that nothing else owns.
    Ok(std::fs::File::from(unsafe { OwnedFd::from_raw_fd(fd) }))
}

#[cfg(test)]
mod open_at_tests {
    use super::*;

    // Without a folder only an absolute name may be opened; a relative one
    // would otherwise resolve against the current directory.
    // 이것을 실패시키는 것: `dir = None`의 상대 경로 가드를 빼는 것(AT_FDCWD로 cwd가 열린다).
    #[test]
    fn open_at_refuses_relative_name_without_folder() {
        let got = open_at(
            None,
            std::ffi::OsStr::new("."),
            SEARCH_ONLY | libc::O_DIRECTORY,
        );
        assert!(got.is_err());
    }
}

#[cfg(test)]
mod random_tests {
    use super::*;

    // 이것을 실패시키는 것: random_bytes16이 고정값을 내는 것(예: `return Some([0; 16])`),
    // 둘째 호출만 0을 내는 것.
    #[test]
    fn random_bytes16_gives_distinct_nonzero_values() {
        let a = random_bytes16().expect("entropy");
        let b = random_bytes16().expect("entropy");
        assert_ne!(a, [0; 16]);
        assert_ne!(b, [0; 16]);
        assert_ne!(a, b);
    }
}

#[cfg(test)]
mod facts_tests {
    use super::*;
    use std::os::fd::AsFd;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    // 이것을 실패시키는 것: 열린 fd의 정체·소유자·그룹·mode·소유권 집행·ACL을 다른 값으로 보고하는 것.
    #[test]
    fn descriptor_facts_match_the_open_entry() {
        let path = std::env::temp_dir().join(format!("bingsu-r2-facts-{}", std::process::id()));
        std::fs::create_dir(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o750)).unwrap();
        let dir = open_dir_at_search_nofollow(None, path.as_os_str()).unwrap();
        let md = dir.metadata().unwrap();
        let got = fd_facts(dir.as_fd()).unwrap();
        assert_eq!((got.dev, got.ino), (md.dev(), md.ino()));
        assert_eq!(
            (got.uid, got.gid, got.mode),
            (md.uid(), md.gid(), md.mode())
        );
        assert_eq!(got.ownership, Some(true));
        assert_eq!(got.acl, AclFacts::None);
        std::fs::remove_dir(&path).unwrap();
    }

    // 이것을 실패시키는 것: 경로에서만 ACL을 읽고 열린 search fd의 쓰기 ACL을 빠뜨리는 것.
    #[cfg(target_os = "macos")]
    #[test]
    fn descriptor_acl_reports_write_permission() {
        let path = std::env::temp_dir().join(format!("bingsu-r2-acl-{}", std::process::id()));
        std::fs::create_dir(&path).unwrap();
        let dir = open_dir_at_search_nofollow(None, path.as_os_str()).unwrap();
        assert!(
            std::process::Command::new("/bin/chmod")
                .args(["+a", "everyone allow write"])
                .arg(&path)
                .status()
                .unwrap()
                .success()
        );
        assert_eq!(fd_facts(dir.as_fd()).unwrap().acl, AclFacts::AllowsWrite);
        assert_eq!(acl_facts(&path), AclFacts::AllowsWrite);
        std::fs::remove_dir(&path).unwrap();
    }
}

/// Stable name/descriptor evidence retained by the N2 read session.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Stamp {
    pub dev: u64,
    pub ino: u64,
    pub uid: u32,
    pub gid: u32,
    pub mode: u32,
    pub size: u64,
    pub ctime: (i64, i64),
    pub mtime: (i64, i64),
}

/// Inspect the name itself, relative to a held parent, never its target.
#[allow(
    clippy::unnecessary_cast,
    reason = "stat fields differ across Unix targets"
)]
pub fn at_stamp(
    dir: std::os::fd::BorrowedFd<'_>,
    name: &std::ffi::OsStr,
) -> std::io::Result<Stamp> {
    use std::os::fd::AsRawFd;
    use std::os::unix::ffi::OsStrExt;
    let c = std::ffi::CString::new(name.as_bytes())?;
    // SAFETY: zero initializes the out parameter; dir is open and c terminated.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: all pointers remain valid throughout this call.
    if unsafe {
        libc::fstatat(
            dir.as_raw_fd(),
            c.as_ptr(),
            &mut st,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error());
    }
    Ok(Stamp {
        dev: st.st_dev as u64,
        ino: st.st_ino as u64,
        uid: st.st_uid,
        gid: st.st_gid,
        mode: st.st_mode as u32,
        size: st.st_size as u64,
        ctime: (st.st_ctime, st.st_ctime_nsec),
        mtime: (st.st_mtime, st.st_mtime_nsec),
    })
}
