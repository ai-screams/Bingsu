//! Additive filesystem write denial, installed after NNP and before seccomp.
//! UAPI definitions are limited to ABI 1–3; syscall numbers come from libc.
use std::io;

// Each definition below comes from Linux v6.2 include/uapi/linux/landlock.h:
// https://github.com/torvalds/linux/blob/v6.2/include/uapi/linux/landlock.h
const CREATE_RULESET_VERSION: u32 = 1; // LANDLOCK_CREATE_RULESET_VERSION (1U << 0)
const WRITE_FILE: u64 = 1 << 1; // LANDLOCK_ACCESS_FS_WRITE_FILE, ABI 1
const REMOVE_DIR: u64 = 1 << 4; // LANDLOCK_ACCESS_FS_REMOVE_DIR, ABI 1
const REMOVE_FILE: u64 = 1 << 5; // LANDLOCK_ACCESS_FS_REMOVE_FILE, ABI 1
const MAKE_CHAR: u64 = 1 << 6; // LANDLOCK_ACCESS_FS_MAKE_CHAR, ABI 1
const MAKE_DIR: u64 = 1 << 7; // LANDLOCK_ACCESS_FS_MAKE_DIR, ABI 1
const MAKE_REG: u64 = 1 << 8; // LANDLOCK_ACCESS_FS_MAKE_REG, ABI 1
const MAKE_SOCK: u64 = 1 << 9; // LANDLOCK_ACCESS_FS_MAKE_SOCK, ABI 1
const MAKE_FIFO: u64 = 1 << 10; // LANDLOCK_ACCESS_FS_MAKE_FIFO, ABI 1
const MAKE_BLOCK: u64 = 1 << 11; // LANDLOCK_ACCESS_FS_MAKE_BLOCK, ABI 1
const MAKE_SYM: u64 = 1 << 12; // LANDLOCK_ACCESS_FS_MAKE_SYM, ABI 1
const REFER: u64 = 1 << 13; // LANDLOCK_ACCESS_FS_REFER, ABI 2
const TRUNCATE: u64 = 1 << 14; // LANDLOCK_ACCESS_FS_TRUNCATE, ABI 3

// include/uapi/linux/landlock.h: struct landlock_ruleset_attr in ABI 1–3
// contains exactly one __u64. Later fields are intentionally not supplied.
#[repr(C)]
struct RulesetAttr {
    handled_access_fs: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LandlockState {
    Installed { abi: u32 },
    Absent,
}

/// Only a successful read-layer installation can construct this evidence.
/// Neither ABI detection nor the write-deny installer returns it. !Send/!Sync.
#[cfg(target_os = "linux")]
pub struct ReadLayerInstalled {
    _thread: std::marker::PhantomData<std::rc::Rc<()>>,
}

/// B3 supplies exactly the validated content root fds, after the openat2 probe.
/// This entry point is not called by the product worker until B3 is wired.
#[cfg(target_os = "linux")]
#[allow(dead_code)]
pub fn restrict_reads(roots: &[std::os::fd::BorrowedFd<'_>]) -> io::Result<ReadLayerInstalled> {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    #[repr(C, packed)]
    struct Beneath {
        allowed: u64,
        parent: i32,
    }
    let rights = (1 << 2) | (1 << 3); // READ_FILE | READ_DIR, ABI 1
    let rules = RulesetAttr {
        handled_access_fs: rights,
    };
    // SAFETY: initialized ABI 1 record; fixed flags; returns a new descriptor.
    let fd = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            &rules,
            std::mem::size_of::<RulesetAttr>(),
            0u32,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful create returned a fresh, uniquely owned descriptor.
    let fd = unsafe { OwnedFd::from_raw_fd(fd as i32) };
    for root in roots {
        let beneath = Beneath {
            allowed: rights,
            parent: root.as_raw_fd(),
        };
        // SAFETY: live root/ruleset fds and initialized packed UAPI record.
        if unsafe {
            libc::syscall(
                libc::SYS_landlock_add_rule,
                fd.as_raw_fd(),
                1u32,
                &beneath,
                0u32,
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
    }
    // SAFETY: live ruleset fd; startup has set NNP; restricts this thread.
    if unsafe { libc::syscall(libc::SYS_landlock_restrict_self, fd.as_raw_fd(), 0u32) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(ReadLayerInstalled {
        _thread: std::marker::PhantomData,
    })
}

fn rights(abi: u32) -> u64 {
    let mut mask = WRITE_FILE
        | REMOVE_DIR
        | REMOVE_FILE
        | MAKE_CHAR
        | MAKE_DIR
        | MAKE_REG
        | MAKE_SOCK
        | MAKE_FIFO
        | MAKE_BLOCK
        | MAKE_SYM;
    if abi >= 2 {
        mask |= REFER;
    }
    if abi >= 3 {
        mask |= TRUNCATE;
    }
    mask
}

fn install_with<T>(
    query: impl FnOnce() -> io::Result<u32>,
    create: impl FnOnce(RulesetAttr) -> io::Result<T>,
    restrict: impl FnOnce(&T) -> io::Result<()>,
) -> io::Result<LandlockState> {
    let abi = match query() {
        // Linux errno values, including when this logic is tested on another OS.
        Err(e) if matches!(e.raw_os_error(), Some(38 | 95)) => return Ok(LandlockState::Absent),
        other => other?,
    };
    if abi == 0 {
        return Err(io::Error::other("invalid Landlock ABI"));
    }
    let fd = create(RulesetAttr {
        handled_access_fs: rights(abi),
    })?;
    // Zero allow rules: every handled write right is denied everywhere. A
    // ruleset fd is closed on both success and failure by its unique owner.
    restrict(&fd)?;
    Ok(LandlockState::Installed { abi })
}

#[cfg(target_os = "linux")]
pub fn install_read_only() -> io::Result<LandlockState> {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    install_with(
        || {
            // SAFETY: VERSION query has no attribute pointer or output storage.
            let n = unsafe {
                libc::syscall(
                    libc::SYS_landlock_create_ruleset,
                    std::ptr::null::<RulesetAttr>(),
                    0usize,
                    CREATE_RULESET_VERSION,
                )
            };
            u32::try_from(n).map_err(|_| io::Error::last_os_error())
        },
        |attr| {
            // SAFETY: live, initialized ABI 1 structure; no unsupported fields.
            let fd = unsafe {
                libc::syscall(
                    libc::SYS_landlock_create_ruleset,
                    &attr,
                    std::mem::size_of::<RulesetAttr>(),
                    0u32,
                )
            };
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: a new ruleset descriptor is transferred exactly once.
            Ok(unsafe { OwnedFd::from_raw_fd(fd as i32) })
        },
        |fd| {
            // SAFETY: live ruleset with no allow rules; NNP was set by startup.
            if unsafe { libc::syscall(libc::SYS_landlock_restrict_self, fd.as_raw_fd(), 0u32) } != 0
            {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    // 이것을 실패시키는 것: UAPI 권한 비트나 ABI 1 구조체의 배치를 바꾸는 것.
    #[test]
    fn landlock_uapi_constants_and_layout_are_pinned() {
        assert_eq!(CREATE_RULESET_VERSION, 1);
        assert_eq!(
            [
                WRITE_FILE,
                REMOVE_DIR,
                REMOVE_FILE,
                MAKE_CHAR,
                MAKE_DIR,
                MAKE_REG,
                MAKE_SOCK,
                MAKE_FIFO,
                MAKE_BLOCK,
                MAKE_SYM,
                REFER,
                TRUNCATE
            ],
            [2, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384]
        );
        assert_eq!(std::mem::size_of::<RulesetAttr>(), 8);
        assert_eq!(std::mem::align_of::<RulesetAttr>(), 8);
        assert_eq!(std::mem::offset_of!(RulesetAttr, handled_access_fs), 0);
    }
    // 이것을 실패시키는 것: ABI별 권한 누락 또는 지원/설치 오류를 부재로 삼키는 것.
    #[test]
    fn landlock_abi_and_failure_matrix() {
        for (abi, expected) in [(1, 0x1ff2), (2, 0x3ff2), (3, 0x7ff2), (99, 0x7ff2)] {
            let state = install_with(
                || Ok(abi),
                |attr| {
                    assert_eq!(attr.handled_access_fs, expected);
                    Ok(())
                },
                |_| Ok(()),
            )
            .unwrap();
            assert_eq!(state, LandlockState::Installed { abi });
        }
        for errno in [38, 95, 1, 22, 7, 5] {
            let result = install_with::<()>(
                || Err(io::Error::from_raw_os_error(errno)),
                |_| panic!("create after failed query"),
                |_| panic!("restrict after failed query"),
            );
            if matches!(errno, 38 | 95) {
                assert_eq!(result.unwrap(), LandlockState::Absent);
            } else {
                assert_eq!(result.unwrap_err().raw_os_error(), Some(errno));
            }
            let create = install_with(
                || Ok(3),
                |_| Err::<(), _>(io::Error::from_raw_os_error(errno)),
                |_| panic!("restrict after failed create"),
            );
            assert_eq!(create.unwrap_err().raw_os_error(), Some(errno));
            let restrict = install_with(
                || Ok(3),
                |_| Ok(()),
                |_| Err(io::Error::from_raw_os_error(errno)),
            );
            assert_eq!(restrict.unwrap_err().raw_os_error(), Some(errno));
        }
        assert!(
            install_with::<()>(|| Ok(0), |_| panic!("ABI zero"), |_| panic!("ABI zero")).is_err()
        );
    }
}
