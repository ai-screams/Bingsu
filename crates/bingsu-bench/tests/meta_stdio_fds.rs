//! `sys::meta` and `sys::stdio` calls on real files and descriptors:
//! failures are errors, never a timed success, and the saved copies of fds
//! 1/2 are close-on-exec. A separate test binary because these tests open
//! and close fds, which would race the unit tests that check closed fd
//! numbers.
#![cfg(any(target_os = "linux", target_os = "macos"))]
use bingsu_bench::sys::meta::{
    acl_probe_path, lock_and_read_generation, lstat_path, open_dir, open_fstat_read_close,
    stat_path, statfs_path,
};
use common::TempDir;
use std::io;
use std::os::fd::AsFd;

mod common;

// 이것을 실패시키는 것: 머리 파일이 없거나, 디렉터리거나, 16바이트보다 짧은데 "세대 다름"(false)으로
// 넘기는 것, 잠금 파일이 symlink인데 따라가는 것. 실제 파일 시스템에서 `lock_and_read_generation`을 부른다.
#[test]
fn lock_check_header_faults_are_errors() {
    let dir = TempDir::new("lockhdr");
    let fd = open_dir(&dir.0).unwrap();
    let check = |lock: &std::ffi::CStr, generation| {
        lock_and_read_generation(fd.as_fd(), lock, c"header", generation)
    };
    let (lock, header) = (dir.0.join("lock"), dir.0.join("header"));
    std::fs::write(&lock, b"").unwrap();
    let mut good = [0u8; 16];
    good[8..].copy_from_slice(&7u64.to_le_bytes());
    std::fs::write(&header, good).unwrap();
    assert!(check(c"lock", 7).unwrap());
    assert!(!check(c"lock", 8).unwrap());
    std::os::unix::fs::symlink(&lock, dir.0.join("lock-link")).unwrap();
    assert!(check(c"lock-link", 7).is_err(), "followed a symlinked lock");
    std::fs::write(&header, &good[..12]).unwrap();
    assert_eq!(
        check(c"lock", 7).unwrap_err().kind(),
        io::ErrorKind::UnexpectedEof
    );
    std::fs::remove_file(&header).unwrap();
    assert_eq!(
        check(c"lock", 7).unwrap_err().kind(),
        io::ErrorKind::NotFound
    );
    std::fs::create_dir(&header).unwrap();
    assert!(
        check(c"lock", 7).is_err(),
        "a directory header must be an error"
    );
}

// 이것을 실패시키는 것: 읽을 수 없는 머리(권한 0)를 "세대 다름"(false)으로 넘기는 것.
// root는 0000 파일도 읽으므로 root로 돌면 건너뛴다. 단 BINGSU_REQUIRE_NONROOT_TESTS=1(CI)이면 그것이 실패다.
// 이것을 실패시키는 것(root): 변수가 켜진 채 root로 돌 때 건너뛰는 것.
#[test]
fn unreadable_header_is_an_error() {
    // SAFETY: geteuid has no preconditions.
    if unsafe { libc::geteuid() } == 0 {
        assert!(
            std::env::var_os("BINGSU_REQUIRE_NONROOT_TESTS").is_none_or(|v| v != "1"),
            "unreadable_header_is_an_error runs as root, but BINGSU_REQUIRE_NONROOT_TESTS=1 requires a non-root run"
        );
        eprintln!("skipped: a non-root user (root reads a 0000 file) not present on this host");
        return;
    }
    use std::os::unix::fs::PermissionsExt;
    let dir = TempDir::new("unreadable");
    let (lock, header) = (dir.0.join("lock"), dir.0.join("header"));
    std::fs::write(&lock, b"").unwrap();
    let mut good = [0u8; 16];
    good[8..].copy_from_slice(&7u64.to_le_bytes());
    std::fs::write(&header, good).unwrap();
    std::fs::set_permissions(&header, std::fs::Permissions::from_mode(0o000)).unwrap();
    let fd = open_dir(&dir.0).unwrap();
    let e = lock_and_read_generation(fd.as_fd(), c"lock", c"header", 7).unwrap_err();
    assert_eq!(e.kind(), io::ErrorKind::PermissionDenied);
}

// 이것을 실패시키는 것: 실제로 짧은 fixture 파일을 정상 읽기로 재는 것, symlink fixture를 따라가는 것.
#[test]
fn short_file_is_unexpected_eof() {
    let dir = TempDir::new("short");
    let fd = open_dir(&dir.0).unwrap();
    std::fs::write(dir.0.join("header"), [0u8; 10]).unwrap();
    let mut buf = [0u8; 4096];
    let e = open_fstat_read_close(fd.as_fd(), c"header", 64, &mut buf).unwrap_err();
    assert_eq!(e.kind(), io::ErrorKind::UnexpectedEof);
    std::fs::write(dir.0.join("header"), [0u8; 64]).unwrap();
    assert_eq!(
        open_fstat_read_close(fd.as_fd(), c"header", 64, &mut buf).unwrap(),
        1
    );
    std::os::unix::fs::symlink(dir.0.join("header"), dir.0.join("link")).unwrap();
    assert!(open_fstat_read_close(fd.as_fd(), c"link", 64, &mut buf).is_err());
    // Relative to the folder fd, not the working directory.
    assert_eq!(
        open_fstat_read_close(fd.as_fd(), c"header", 64, &mut buf).unwrap(),
        1
    );
    assert_ne!(std::env::current_dir().unwrap(), dir.0);
}

// 이것을 실패시키는 것: 메타데이터·ACL 조회의 실패를 삼키는 것(ENOTDIR을 성공이나 "ACL 없음"으로 보는 것),
// lstat이 마지막 symlink를 따라가는 것, ACL이 없는 파일(Linux procfs의 ENOTSUP 포함)을 오류로 보는 것,
// ACL이 있는 파일을 "없음"으로 보는 것.
#[test]
fn metadata_calls_report_failures() {
    let dir = TempDir::new("metadata");
    let file = dir.0.join("f");
    std::fs::write(&file, b"x").unwrap();
    let through_file = file.join("x"); // ENOTDIR on both systems
    for f in [stat_path, lstat_path, statfs_path] {
        f(&file).unwrap();
        assert_eq!(
            f(&through_file).unwrap_err().raw_os_error(),
            Some(libc::ENOTDIR)
        );
    }
    assert!(!acl_probe_path(&file).unwrap());
    #[cfg(target_os = "macos")]
    {
        let st = std::process::Command::new("/bin/chmod")
            .args(["+a", "everyone allow read"])
            .arg(&file)
            .status()
            .unwrap();
        assert!(st.success());
        assert!(acl_probe_path(&file).unwrap(), "extended ACL not seen");
    }
    // procfs has no xattr support: ENOTSUP is "no ACL", not an error.
    #[cfg(target_os = "linux")]
    {
        assert!(!acl_probe_path(std::path::Path::new("/proc/self/status")).unwrap());
        common::set_posix_acl(&file, c"system.posix_acl_access");
        assert!(acl_probe_path(&file).unwrap(), "POSIX ACL not seen");
    }
    assert_eq!(
        acl_probe_path(&through_file).unwrap_err().raw_os_error(),
        Some(libc::ENOTDIR)
    );
    let dangling = dir.0.join("dangling");
    std::os::unix::fs::symlink(dir.0.join("missing"), &dangling).unwrap();
    lstat_path(&dangling).unwrap();
    assert_eq!(
        stat_path(&dangling).unwrap_err().kind(),
        io::ErrorKind::NotFound
    );
}

// 이것을 실패시키는 것: 저장본을 close-on-exec 없이 복제하는 것(F_DUPFD),
// 유출용 복제에 close-on-exec를 붙이거나 min보다 낮은 번호를 쓰는 것.
#[test]
fn saved_copies_are_cloexec_and_leak_is_not() {
    use bingsu_bench::sys::spawn::dup_inheritable_at;
    use bingsu_bench::sys::stdio::save_stdout_stderr;
    use std::os::fd::{AsRawFd, OwnedFd, RawFd};
    let flags = |fd: RawFd| {
        // SAFETY: querying the flags of a descriptor this test owns.
        let f = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        assert!(f >= 0, "fd {fd} not open");
        f & libc::FD_CLOEXEC
    };
    let saved = save_stdout_stderr().unwrap();
    for fd in saved.raw() {
        assert!(fd >= 3, "saved copy at {fd}");
        assert_eq!(
            flags(fd),
            libc::FD_CLOEXEC,
            "saved copy {fd} is inheritable"
        );
    }
    let null: OwnedFd = std::fs::File::open("/dev/null").unwrap().into();
    let leak = dup_inheritable_at(&null, 200).unwrap();
    assert!(leak.as_raw_fd() >= 200);
    assert_eq!(flags(leak.as_raw_fd()), 0);
}
