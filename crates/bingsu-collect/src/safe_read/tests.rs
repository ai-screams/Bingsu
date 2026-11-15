use super::*;
// 이것을 실패시키는 것: ancestor 재획득이 원래 worktree의 device/mount 경계를 초기화.
#[test]
fn ancestor_repository_preserves_mount_boundary() {
    use std::os::unix::ffi::OsStrExt;
    let path = std::env::temp_dir().join(format!("bingsu-ancestor-mount-{}", std::process::id()));
    std::fs::create_dir(&path).unwrap();
    let path = std::fs::canonicalize(path).unwrap();
    let mut meter = Meter::new(std::time::Instant::now() + std::time::Duration::from_secs(30));
    for device in [true, false] {
        let query = acquire(
            path.as_os_str().as_bytes(),
            DiscoveryQuery::default(),
            &mut meter,
        )
        .unwrap();
        let mut anchor = acquire(
            path.as_os_str().as_bytes(),
            DiscoveryQuery::default(),
            &mut meter,
        )
        .unwrap()
        .select_cwd()
        .unwrap();
        if device {
            anchor.identity.device ^= 1;
        } else {
            anchor.identity.mount[0] ^= 1;
        }
        let before = meter.operations();
        assert!(matches!(
            query.ancestor_repository(&anchor, 0, &mut meter),
            Err(ReadError::Escape)
        ));
        assert_eq!(meter.operations(), before);
    }
    std::fs::remove_dir(path).unwrap();
}

// 이것을 실패시키는 것: CString의 선예약 또는 drop 시 live 예약 반환을 생략하는 것.
#[test]
fn path_cstring_reservation_is_live_and_precharged() {
    let mut meter = Meter::new(std::time::Instant::now() + std::time::Duration::from_secs(30));
    meter.allocation(17).unwrap();
    let baseline = meter.live_allocated();
    meter.allocation_limit = baseline + 5;
    for _ in 0..4096 {
        let name = cstring(b"name", &mut meter).unwrap();
        assert_eq!(name.to_bytes(), b"name");
        assert_eq!(meter.live_allocated(), baseline + 5);
        assert_eq!(cstring(b"x", &mut meter).err(), Some(ReadError::Limit));
        drop(name);
        assert_eq!(meter.live_allocated(), baseline);
    }
    assert_eq!(cstring(b"bad\0", &mut meter).err(), Some(ReadError::Escape));
    assert_eq!(meter.live_allocated(), baseline);
}

// 이것을 실패시키는 것: 미지원 readonly를 true/false로 만들거나 권한 거부를 쓰기 가능으로 보고하는 것.
#[test]
fn readonly_observation_preserves_unknown_and_errors() {
    assert_eq!(readonly_status(Ok(())), Ok(Some(false)));
    for error in [libc::ENOSYS, libc::EPERM] {
        assert_eq!(readonly_status(Err(error)), Ok(None));
    }
    for error in [libc::EACCES, libc::EROFS] {
        assert_eq!(readonly_status(Err(error)), Ok(Some(true)));
    }
    assert_eq!(readonly_status(Err(libc::ENOENT)), Err(ReadError::Missing));
    assert_eq!(
        readonly_status(Err(libc::EIO)),
        Err(ReadError::Io(libc::EIO))
    );
}
