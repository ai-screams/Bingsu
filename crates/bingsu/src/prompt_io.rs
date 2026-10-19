//! Fixed kernel observations shared by publisher clocks and the front reader.
//! No environment, configurable paths, wall-clock fallback or command module access.
#![forbid(
    clippy::disallowed_methods,
    clippy::disallowed_types,
    clippy::disallowed_macros
)]
use bingsu_core::front::output::Deadline;
use bingsu_core::snapshot::{Clock, ClockError};
use std::sync::atomic::{AtomicBool, Ordering};

/// Provisional whole-prompt budget (N6 ruling, 2026-10-18); N7 measures it.
const PROMPT_BUDGET_NS: u64 = 50_000_000;

// AtomicBool is lock-free on the supported aarch64/x86_64 targets. No other
// operation, including errno access, allocation or a lock, belongs in this handler.
static EXPIRED: AtomicBool = AtomicBool::new(false);
extern "C" fn alarm_handler(_: i32) {
    EXPIRED.store(true, Ordering::Relaxed);
}

/// Sample at dispatch entry, before collecting/parsing argv or doing any I/O.
pub(crate) fn entry_deadline() -> Option<Deadline> {
    Deadline::from_entry(monotonic_ns().ok()?, PROMPT_BUDGET_NS)
}

/// Post-filter observation: only the already-allowed monotonic clock call.
pub(crate) fn deadline_now(deadline: Deadline) -> Option<u64> {
    if EXPIRED.load(Ordering::Relaxed) {
        return None;
    }
    let now = monotonic_ns().ok()?;
    deadline.remaining(now)?;
    Some(now)
}

/// Pre-filter ONLY, once per prompt. A failed setup never permits a write.
/// Keep the timer armed until _exit: disarming after confinement would require
/// a new syscall. Repeating alarms close the signal-before-write race.
pub(crate) fn arm_deadline(deadline: Deadline) -> bool {
    // SAFETY: zeroed signal action storage, with masks initialized below.
    let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
    // SAFETY: writable signal set.
    if unsafe { libc::sigemptyset(&mut action.sa_mask) } != 0 {
        return false;
    }
    // Direct exec preserves ITIMER_REAL. Install ALRM before PIPE setup so
    // an inherited timer expiring there is recorded, not fatal. This cannot
    // protect the loader, argv collection, or any earlier entry window.
    action.sa_sigaction = alarm_handler as *const () as usize;
    action.sa_flags = 0; // In particular, no SA_RESTART.
    // SAFETY: the handler has C ABI and process lifetime; mask is initialized.
    if unsafe { libc::sigaction(libc::SIGALRM, &action, std::ptr::null_mut()) } != 0 {
        return false;
    }
    action.sa_sigaction = libc::SIG_IGN;
    // SAFETY: initialized action and a valid signal; no old action requested.
    if unsafe { libc::sigaction(libc::SIGPIPE, &action, std::ptr::null_mut()) } != 0 {
        return false;
    }
    // SAFETY: initialize a signal set containing only SIGALRM.
    if unsafe { libc::sigaddset(&mut action.sa_mask, libc::SIGALRM) } != 0 {
        return false;
    }
    // SAFETY: this front end is single threaded. Undo an inherited blocked alarm.
    if unsafe { libc::sigprocmask(libc::SIG_UNBLOCK, &action.sa_mask, std::ptr::null_mut()) } != 0 {
        return false;
    }
    // Do not clear EXPIRED: a pending or early alarm must remain fail-closed.
    let Some(us) = deadline_now(deadline).and_then(|now| deadline.timer_micros(now)) else {
        return false;
    };
    let Ok(seconds) = (us / 1_000_000).try_into() else {
        return false;
    };
    let timer = libc::itimerval {
        it_value: libc::timeval {
            tv_sec: seconds,
            tv_usec: (us % 1_000_000) as _,
        },
        it_interval: libc::timeval {
            tv_sec: 0,
            tv_usec: 1_000,
        },
    };
    // SAFETY: initialized nonzero relative timer, repeating every 1 ms; no old timer.
    unsafe { libc::setitimer(libc::ITIMER_REAL, &timer, std::ptr::null_mut()) == 0 }
}

/// The held-fd executor uses None only in untimed unit fixtures. Production
/// always supplies the one entry deadline. Exit directly, without new cleanup
/// I/O or a replacement record, when no time/usable clock remains.
pub(crate) fn check_deadline(deadline: Option<Deadline>) {
    if deadline.is_some_and(|d| deadline_now(d).is_none()) {
        // SAFETY: _exit has no pointer arguments and never returns.
        unsafe { libc::_exit(0) }
    }
}

pub fn observe_clock() -> Result<Clock, ClockError> {
    observe_clock_until(None)
}

pub(crate) fn observe_clock_until(deadline: Option<Deadline>) -> Result<Clock, ClockError> {
    check_deadline(deadline);
    let boot = boot_id()?;
    check_deadline(deadline);
    let domain = clock_domain()?;
    check_deadline(deadline);
    let now = monotonic_ns()?;
    Ok(Clock {
        boot,
        domain,
        now,
        kind: CLOCK_KIND,
        resume: 0,
    })
}

#[cfg(target_os = "linux")]
const CLOCK_KIND: u8 = 1;
#[cfg(target_os = "macos")]
const CLOCK_KIND: u8 = 2;

pub(crate) fn monotonic_ns() -> Result<u64, ClockError> {
    #[cfg(target_os = "linux")]
    let kind = libc::CLOCK_BOOTTIME;
    #[cfg(target_os = "macos")]
    let kind = libc::CLOCK_MONOTONIC_RAW;
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: ts is an initialized, writable timespec for this call.
    if unsafe { libc::clock_gettime(kind, &mut ts) } != 0 {
        return Err(ClockError::Time);
    }
    let sec = u64::try_from(ts.tv_sec).map_err(|_| ClockError::Time)?;
    let ns = u64::try_from(ts.tv_nsec).map_err(|_| ClockError::Time)?;
    if ns >= 1_000_000_000 {
        return Err(ClockError::Time);
    }
    sec.checked_mul(1_000_000_000)
        .and_then(|n| n.checked_add(ns))
        .ok_or(ClockError::Time)
}

pub(crate) fn uuid(bytes: &[u8]) -> Result<[u8; 16], ClockError> {
    if bytes.len() != 36 {
        return Err(ClockError::Boot);
    }
    let mut out = [0; 16];
    let mut digits = 0;
    for (i, &b) in bytes.iter().enumerate() {
        if [8, 13, 18, 23].contains(&i) {
            if b != b'-' {
                return Err(ClockError::Boot);
            }
        } else {
            let nibble = match b {
                b'0'..=b'9' => b - b'0',
                b'a'..=b'f' => b - b'a' + 10,
                b'A'..=b'F' => b - b'A' + 10,
                _ => return Err(ClockError::Boot),
            };
            out[digits / 2] = (out[digits / 2] << 4) | nibble;
            digits += 1;
        }
    }
    if out == [0; 16] {
        return Err(ClockError::Boot);
    }
    Ok(out)
}

// Shared publisher/reader judgements. Callers verify the procfs walk and file
// kinds before passing observations; errors retain their errno so only
// three ENOENT observations prove that time namespaces are unavailable.
#[cfg(any(test, target_os = "linux"))]
fn time_domain(
    time: Result<u64, i32>,
    child: Result<u64, i32>,
    offsets: Result<(), i32>,
) -> Result<[u8; 16], ClockError> {
    let missing = [
        time == Err(libc::ENOENT),
        child == Err(libc::ENOENT),
        offsets == Err(libc::ENOENT),
    ];
    if time.is_ok() && (child.is_err() || offsets.is_err()) {
        return Err(ClockError::Domain);
    }
    // readlink exposes the same inode as fstat, but no st_dev. Use a fixed
    // nsfs discriminator instead of a mount's device number. Both adapters
    // use this encoding; old device-based markers become stale and refresh.
    let identity = time.ok().map(|ino| (0x6e736673, ino));
    bingsu_core::snapshot::namespace_domain(identity, true, missing)
}

// "time:[" + at most 20 decimal u64 digits + "]". One extra read byte
// ensures even a valid maximum-length prefix with trailing data is refused.
#[cfg(any(test, target_os = "linux"))]
const TIME_LINK_MAX: usize = 27;

#[cfg(any(test, target_os = "linux"))]
fn time_inode(bytes: &[u8]) -> Result<u64, i32> {
    if bytes.len() > TIME_LINK_MAX {
        return Err(libc::EIO);
    }
    let digits = bytes
        .strip_prefix(b"time:[")
        .and_then(|b| b.strip_suffix(b"]"))
        .ok_or(libc::EIO)?;
    let mut ino = 0u64;
    for &digit in digits {
        if !digit.is_ascii_digit() {
            return Err(libc::EIO);
        }
        ino = ino
            .checked_mul(10)
            .and_then(|n| n.checked_add(u64::from(digit - b'0')))
            .ok_or(libc::EIO)?;
    }
    if ino == 0 {
        // also rejects an empty decimal field
        return Err(libc::EIO);
    }
    Ok(ino)
}

#[cfg(any(test, target_os = "linux"))]
fn time_link(ns: i32, name: &std::ffi::CStr) -> Result<u64, i32> {
    let mut bytes = [0; TIME_LINK_MAX + 1];
    // SAFETY: borrowed directory fd, terminated fixed name and writable buffer.
    // This reads the link itself; opening its nsfs target can fail in a userns.
    let n = unsafe { libc::readlinkat(ns, name.as_ptr(), bytes.as_mut_ptr().cast(), bytes.len()) };
    let n = usize::try_from(n).map_err(|_| {
        std::io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::EIO)
    })?;
    time_inode(&bytes[..n])
}

/// Pre-filter only. `ns` must be the current process's verified procfs ns
/// directory. Publisher and reader share both link observation and judgement.
#[cfg(any(test, target_os = "linux"))]
pub(crate) fn time_namespace_domain(
    ns: i32,
    offsets: Result<(), i32>,
) -> Result<[u8; 16], ClockError> {
    time_namespace_domain_until(ns, offsets, None)
}

#[cfg(any(test, target_os = "linux"))]
pub(crate) fn time_namespace_domain_until(
    ns: i32,
    offsets: Result<(), i32>,
    deadline: Option<Deadline>,
) -> Result<[u8; 16], ClockError> {
    check_deadline(deadline);
    let time = time_link(ns, c"time");
    check_deadline(deadline);
    let children = time_link(ns, c"time_for_children");
    time_domain(time, children, offsets)
}

#[cfg(any(test, target_os = "linux"))]
pub(crate) fn boot_file(f: bingsu_core::fs_trust::Facts, magic: u64) -> bool {
    // uid is mapped by user namespaces (often to 65534). procfs proves the
    // origin; a host uid spelling adds no protection against local users.
    magic == 0x9fa0 && f.mode & 0o170022 == 0o100000
}

#[cfg(any(test, target_os = "linux"))]
pub(crate) fn boot_bytes(bytes: &[u8]) -> Result<[u8; 16], ClockError> {
    if bytes.len() != 37 || bytes[36] != b'\n' {
        return Err(ClockError::Boot);
    }
    uuid(&bytes[..36])
}

#[cfg(target_os = "macos")]
fn boot_id() -> Result<[u8; 16], ClockError> {
    let mut bytes = [0u8; 37];
    let mut len = bytes.len();
    // SAFETY: the name is NUL terminated; bytes and len are valid output buffers;
    // null newp and zero newlen request a read only.
    let rc = unsafe {
        libc::sysctlbyname(
            c"kern.bootsessionuuid".as_ptr(),
            bytes.as_mut_ptr().cast(),
            &mut len,
            std::ptr::null_mut(),
            0,
        )
    };
    if rc != 0 || len != 37 || bytes[36] != 0 {
        return Err(ClockError::Boot);
    }
    uuid(&bytes[..36])
}
#[cfg(target_os = "macos")]
fn clock_domain() -> Result<[u8; 16], ClockError> {
    Ok([0; 16])
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use std::ffi::CStr;
    use std::fs::File;
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::fs::MetadataExt;

    // Private effects accept only the constant names below. /proc/self is the
    // sole followed link; namespace magic links are read, never opened.
    fn open_at(base: i32, name: &CStr, flags: i32) -> std::io::Result<File> {
        // SAFETY: base is borrowed or AT_FDCWD; name is terminated; no O_CREAT.
        let fd = unsafe { libc::openat(base, name.as_ptr(), flags | libc::O_CLOEXEC) };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: successful openat gives unique ownership of fd.
        Ok(unsafe { File::from_raw_fd(fd) })
    }
    fn on_fs(f: &File, magic: libc::c_long) -> bool {
        // SAFETY: zeroed statfs is a valid output buffer.
        let mut st: libc::statfs = unsafe { std::mem::zeroed() };
        // SAFETY: f is open and st is writable.
        unsafe {
            libc::fstatfs(f.as_raw_fd(), &mut st) == 0 && st.f_type as i128 == i128::from(magic)
        }
    }
    fn facts(f: &File) -> Result<bingsu_core::fs_trust::Facts, i32> {
        let m = f.metadata().map_err(|_| libc::EIO)?;
        Ok(bingsu_core::fs_trust::Facts {
            dev: m.dev(),
            ino: m.ino(),
            uid: m.uid(),
            gid: m.gid(),
            mode: m.mode(),
            ownership: Some(true),
            // Kernel identity judgement does not use ACLs. The reader also
            // checks ACLs as part of its pre-filter held-file inspection.
            acl: bingsu_core::fs_trust::AclFacts::Unknown,
        })
    }
    fn namespace_entry(
        base: i32,
        name: &CStr,
        magic: libc::c_long,
        flags: i32,
    ) -> Result<(u64, u64), i32> {
        let f = open_at(base, name, flags).map_err(|e| e.raw_os_error().unwrap_or(0))?;
        let m = facts(&f)?;
        if !on_fs(&f, magic) || m.mode & 0o170000 != 0o100000 {
            return Err(libc::EIO);
        }
        Ok((m.dev, m.ino))
    }
    fn proc_self() -> Result<File, ClockError> {
        let f = open_at(
            libc::AT_FDCWD,
            c"/proc/self",
            libc::O_RDONLY | libc::O_DIRECTORY,
        )
        .map_err(|_| ClockError::Domain)?;
        if !on_fs(&f, 0x9fa0) {
            return Err(ClockError::Domain);
        }
        Ok(f)
    }
    pub(super) fn domain() -> Result<[u8; 16], ClockError> {
        let process = proc_self()?;
        let ns = open_at(
            process.as_raw_fd(),
            c"ns",
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW,
        )
        .map_err(|_| ClockError::Domain)?;
        if !on_fs(&ns, 0x9fa0) {
            return Err(ClockError::Domain);
        }
        let offsets = namespace_entry(
            process.as_raw_fd(),
            c"timens_offsets",
            0x9fa0,
            libc::O_RDONLY | libc::O_NOFOLLOW,
        );
        time_namespace_domain(ns.as_raw_fd(), offsets.map(|_| ()))
    }
    pub(super) fn boot() -> Result<[u8; 16], ClockError> {
        use std::io::Read;
        let mut f = open_at(
            libc::AT_FDCWD,
            c"/proc/sys/kernel/random/boot_id",
            libc::O_RDONLY | libc::O_NOFOLLOW,
        )
        .map_err(|_| ClockError::Boot)?;
        let facts = facts(&f).map_err(|_| ClockError::Boot)?;
        if !boot_file(facts, if on_fs(&f, 0x9fa0) { 0x9fa0 } else { 0 }) {
            return Err(ClockError::Boot);
        }
        let mut b = [0; 38];
        let mut n = 0;
        while n < b.len() {
            let got = f.read(&mut b[n..]).map_err(|_| ClockError::Boot)?;
            if got == 0 {
                break;
            }
            n += got;
        }
        boot_bytes(&b[..n])
    }
}
#[cfg(target_os = "linux")]
fn boot_id() -> Result<[u8; 16], ClockError> {
    linux::boot()
}
#[cfg(target_os = "linux")]
fn clock_domain() -> Result<[u8; 16], ClockError> {
    linux::domain()
}

#[cfg(test)]
mod tests {
    // 이것을 실패시키는 것: 제품 예산 상수 변경 또는 진입 시각 외 기준으로 마감 계산.
    #[test]
    fn entry_uses_the_provisional_whole_prompt_budget() {
        let before = super::monotonic_ns().unwrap();
        let deadline = super::entry_deadline().unwrap();
        let after = super::monotonic_ns().unwrap();
        assert!((before + 50_000_000..=after + 50_000_000).contains(&deadline.end()));
    }

    #[test]
    #[ignore = "child: changes the process-wide signal flag"]
    fn early_alarm_child() {
        let deadline = super::entry_deadline().unwrap();
        super::alarm_handler(libc::SIGALRM);
        let code = if super::deadline_now(deadline).is_none() {
            0
        } else {
            88
        };
        // SAFETY: child process exits; no global flag leaks into parallel tests.
        unsafe { libc::_exit(code) }
    }

    // 이것을 실패시키는 것: handler가 만료 플래그를 세우지 않거나 writer가 그것을 무시하는 것.
    #[test]
    fn early_alarm_flag_stops_before_the_clock_deadline() {
        let out = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--ignored",
                "--exact",
                "prompt_io::tests::early_alarm_child",
                "--test-threads=1",
                "--nocapture",
                "-q",
            ])
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(0));
        assert!(out.stderr.is_empty());
    }
    use super::*;
    use std::{
        fs::{self, File},
        os::{fd::AsRawFd, unix::fs::symlink},
        path::PathBuf,
    };

    struct Links(PathBuf);
    impl Links {
        fn new(time: Option<&str>, child: Option<&str>) -> Self {
            static COUNT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
            let path = std::env::temp_dir().join(format!(
                "bingsu-time-links-{}-{}",
                std::process::id(),
                COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            for (name, text) in [("time", time), ("time_for_children", child)] {
                if let Some(text) = text {
                    symlink(text, path.join(name)).unwrap();
                }
            }
            Self(path)
        }
        fn directory(&self) -> File {
            File::open(&self.0).unwrap()
        }
    }
    impl Drop for Links {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }

    // 이것을 실패시키는 것: 길이·접두/접미·빈 숫자·ASCII 숫자·오버플로·영 inode 검사 제거.
    #[test]
    fn time_link_parser_is_strict_and_bounded() {
        for (text, ino) in [
            ("time:[123]", 123),
            ("time:[4026532442]", 4026532442),
            ("time:[000123]", 123), // decimal digits, still within the bound
            ("time:[18446744073709551615]", u64::MAX),
        ] {
            assert_eq!(time_inode(text.as_bytes()), Ok(ino), "{text}");
        }
        for bad in [
            "",
            "time:[]",
            "time:[0]",
            "time:[000]",
            "mnt:[123]",
            "TIME:[123]",
            "time:123]",
            "time:[123",
            "time:[123]]",
            "time:[+123]",
            "time:[-123]",
            "time:[ 123]",
            "time:[123 ]",
            "time:[1a3]",
            "time:[１２３]",
            " time:[123]",
            "time:[123]\n",
            "time:[123]\0",
            "time:[123]extra",
            "time:[000000000000000000001]",
            "time:[18446744073709551617]",
            "time:[99999999999999999999]",
        ] {
            assert_eq!(time_inode(bad.as_bytes()), Err(libc::EIO), "{bad:?}");
        }
        assert_eq!(time_inode(b"time:[\xff]"), Err(libc::EIO));
    }

    // Both callers supply a procfs-verified ns fd and the offsets result to
    // this same routine. Independent descriptors model their separate walks;
    // the table exercises actual readlinkat, including errors and truncation.
    // 이것을 실패시키는 것: 두 링크 중 하나를 생략·교환, readlink 오류 은폐, 버퍼 여유 제거.
    #[test]
    fn publisher_reader_readlink_domain_table() {
        let domain = |ino| {
            bingsu_core::snapshot::namespace_domain(Some((0x6e736673, ino)), true, [false; 3])
        };
        for (time, child, offsets, want) in [
            (Some("time:[123]"), Some("time:[123]"), Ok(()), domain(123)),
            // A child may be in another time namespace; the current one wins.
            (Some("time:[123]"), Some("time:[456]"), Ok(()), domain(123)),
            (
                Some("time:[18446744073709551615]"),
                Some("time:[1]"),
                Ok(()),
                domain(u64::MAX),
            ),
            (
                Some("time:[18446744073709551615]x"),
                Some("time:[1]"),
                Ok(()),
                Err(ClockError::Domain),
            ),
            (
                Some("mnt:[123]"),
                Some("time:[123]"),
                Ok(()),
                Err(ClockError::Domain),
            ),
            (
                Some("time:[123]"),
                Some("mnt:[123]"),
                Ok(()),
                Err(ClockError::Domain),
            ),
            (Some("time:[123]"), None, Ok(()), Err(ClockError::Domain)),
            (None, Some("time:[123]"), Ok(()), Err(ClockError::Domain)),
            (
                Some("time:[123]"),
                Some("time:[123]"),
                Err(libc::EACCES),
                Err(ClockError::Domain),
            ),
            (None, None, Err(libc::ENOENT), Ok([0; 16])),
            (None, None, Err(libc::EACCES), Err(ClockError::Domain)),
        ] {
            let links = Links::new(time, child);
            let publisher = time_namespace_domain(links.directory().as_raw_fd(), offsets);
            let reader = time_namespace_domain(links.directory().as_raw_fd(), offsets);
            assert_eq!(publisher, want, "{time:?}, {child:?}, {offsets:?}");
            assert_eq!(reader, publisher);
        }
        assert_eq!(time_link(-1, c"time"), Err(libc::EBADF));
    }

    // 이것을 실패시키는 것: namespace 링크의 readlink를 open/fstat으로 되돌리는 것.
    #[test]
    fn namespace_open_permission_denied_does_not_affect_readlink() {
        use std::os::unix::fs::PermissionsExt;
        let links = Links::new(Some("time:[123]"), Some("time:[123]"));
        let target = links.0.join("time:[123]");
        fs::write(&target, b"unreadable nsfs stand-in").unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o000)).unwrap();
        // Root can bypass file permissions; non-root CI/macOS exercises EACCES.
        // The real Linux probe below also covers parent-userns nsfs permissions.
        // SAFETY: geteuid has no preconditions.
        if unsafe { libc::geteuid() } != 0 {
            for name in ["time", "time_for_children"] {
                assert_eq!(
                    File::open(links.0.join(name)).unwrap_err().raw_os_error(),
                    Some(libc::EACCES)
                );
            }
        }
        let ns = links.directory();
        assert_eq!(time_link(ns.as_raw_fd(), c"time"), Ok(123));
        assert_eq!(
            time_namespace_domain(ns.as_raw_fd(), Ok(())),
            bingsu_core::snapshot::namespace_domain(Some((0x6e736673, 123)), true, [false; 3])
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn native_readlink_matches_opened_namespace_inode() {
        use std::os::unix::fs::MetadataExt;
        let ns = File::open("/proc/self/ns").unwrap();
        for name in [c"time", c"time_for_children"] {
            let inode = time_link(ns.as_raw_fd(), name);
            let path = format!("/proc/self/ns/{}", name.to_str().unwrap());
            match File::open(path) {
                Ok(f) => assert_eq!(inode, Ok(f.metadata().unwrap().ino())),
                Err(e) if e.raw_os_error() == Some(libc::ENOENT) => {
                    assert_eq!(inode, Err(libc::ENOENT));
                }
                Err(e) => {
                    assert_eq!(e.raw_os_error(), Some(libc::EACCES));
                    assert!(inode.is_ok(), "readlink still works in a user namespace");
                }
            }
        }
    }

    // Both adapters call these exact judgements: user namespace uid mapping
    // cannot change the decision, and a partially observed domain fails closed.
    // 이것을 실패시키는 것: uid==0 복원, procfs/파일 종류/쓰기 비트/세 관찰 조건 제거.
    #[test]
    fn publisher_reader_boot_domain_table() {
        use bingsu_core::fs_trust::{AclFacts, Facts};
        let f = Facts {
            dev: 1,
            ino: 9,
            uid: 0,
            gid: 0,
            mode: 0o100444,
            ownership: Some(true),
            acl: AclFacts::None,
        };
        for uid in [0, 501, 65534] {
            for (mode, magic, expected) in [
                (0o100444, 0x9fa0, true),
                (0o100444, 0x6e736673, false),
                (0o100446, 0x9fa0, false),
                (0o100464, 0x9fa0, false),
                (0o040444, 0x9fa0, false),
            ] {
                assert_eq!(
                    boot_file(Facts { uid, mode, ..f }, magic),
                    expected,
                    "uid={uid} mode={mode:o}"
                );
            }
        }
        let identity = (0x6e736673, f.ino);
        let expected = bingsu_core::snapshot::namespace_domain(Some(identity), true, [false; 3]);
        let entries = [Ok(()), Err(libc::ENOENT), Err(libc::EACCES), Err(libc::EIO)];
        for time in entries {
            for child in entries {
                for offsets in entries {
                    let want = if [time, child, offsets] == [Ok(()); 3] {
                        expected
                    } else if [time, child, offsets] == [Err(libc::ENOENT); 3] {
                        Ok([0; 16])
                    } else {
                        Err(ClockError::Domain)
                    };
                    assert_eq!(
                        time_domain(time.map(|_| f.ino), child.map(|_| f.ino), offsets),
                        want,
                        "time={time:?}, child={child:?}, offsets={offsets:?}"
                    );
                }
            }
        }
        let uuid = b"00112233-4455-6677-8899-aabbccddeeff\n";
        assert!(boot_bytes(uuid).is_ok());
        for bytes in [
            &uuid[..36],
            b"00112233-4455-6677-8899-aabbccddeeff ",
            b"00112233-4455-6677-8899-aabbccddeeff\nextra",
            b"00000000-0000-0000-0000-000000000000\n".as_slice(),
        ] {
            assert!(boot_bytes(bytes).is_err());
        }
    }

    // 이것을 실패시키는 것: UUID 길이·구분자·hex·영 UUID 검사 또는 바이트 순서를 바꾸는 것.
    #[test]
    fn kernel_uuid_is_strict() {
        let good = b"00112233-4455-6677-8899-AaBbCcDdEeFf";
        assert_eq!(
            uuid(good),
            Ok([
                0, 17, 34, 51, 68, 85, 102, 119, 136, 153, 170, 187, 204, 221, 238, 255
            ])
        );
        for bad in [
            b"00000000-0000-0000-0000-000000000000".as_slice(),
            &good[..35],
            b"00112233_4455-6677-8899-aabbccddeeff",
            b"00112233-4455-6677-8899-aabbccddeezz",
        ] {
            assert_eq!(uuid(bad), Err(ClockError::Boot));
        }
    }
    // 이것을 실패시키는 것: 실제 OS 시각을 고정된 0으로 돌리거나 다른 시계로 대체하는 것.
    #[test]
    fn native_clock_observation() {
        let a = monotonic_ns().unwrap();
        let b = monotonic_ns().unwrap();
        assert!(a > 0 && b >= a);
        match observe_clock() {
            Ok(c) => {
                assert_eq!(c.kind, CLOCK_KIND);
                assert!(c.now >= b);
                assert_ne!(c.boot, [0; 16]);
            }
            Err(e) => {
                eprintln!("native boot/domain observation unavailable: {e:?}");
                assert!(matches!(e, ClockError::Boot | ClockError::Domain));
            }
        }
    }
}
