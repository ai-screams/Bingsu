//! Fixed kernel observations shared by command clocks and the future front reader.
//! No environment, configurable paths, wall-clock fallback or command module access.
#![forbid(
    clippy::disallowed_methods,
    clippy::disallowed_types,
    clippy::disallowed_macros
)]
use bingsu_core::snapshot::{Clock, ClockError};

pub fn observe_clock() -> Result<Clock, ClockError> {
    let boot = boot_id()?;
    let domain = clock_domain()?;
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

    // Private effects accept only the constant names below. Namespace magic links
    // are the one deliberate follow operation; snapshot paths use another adapter.
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
        let time = open_at(ns.as_raw_fd(), c"time", libc::O_RDONLY);
        match time {
            Ok(f) => {
                if !on_fs(&f, 0x6e736673) {
                    return Err(ClockError::Domain);
                }
                let m = f.metadata().map_err(|_| ClockError::Domain)?;
                bingsu_core::snapshot::namespace_domain(Some((m.dev(), m.ino())), true, [false; 3])
            }
            Err(e) => {
                // ENOENT alone is not feature absence: both proc directories are
                // verified and all three kernel entries must be absent.
                let child = open_at(ns.as_raw_fd(), c"time_for_children", libc::O_RDONLY);
                let offsets = open_at(
                    process.as_raw_fd(),
                    c"timens_offsets",
                    libc::O_RDONLY | libc::O_NOFOLLOW,
                );
                let missing = [
                    e.raw_os_error() == Some(libc::ENOENT),
                    child
                        .err()
                        .is_some_and(|e| e.raw_os_error() == Some(libc::ENOENT)),
                    offsets
                        .err()
                        .is_some_and(|e| e.raw_os_error() == Some(libc::ENOENT)),
                ];
                bingsu_core::snapshot::namespace_domain(None, true, missing)
            }
        }
    }
    pub(super) fn boot() -> Result<[u8; 16], ClockError> {
        use std::io::Read;
        let mut f = open_at(
            libc::AT_FDCWD,
            c"/proc/sys/kernel/random/boot_id",
            libc::O_RDONLY | libc::O_NOFOLLOW,
        )
        .map_err(|_| ClockError::Boot)?;
        if !on_fs(&f, 0x9fa0) {
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
        if n != 37 || b[36] != b'\n' {
            return Err(ClockError::Boot);
        }
        uuid(&b[..36])
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
    use super::*;
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
