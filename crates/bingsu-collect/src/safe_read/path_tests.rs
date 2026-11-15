use super::*;
fn meter() -> Meter {
    Meter::new(std::time::Instant::now() + std::time::Duration::from_secs(60))
}
// Fails if name/step caps happen after allocation, or scratch accumulates.
#[test]
fn sibling_name_and_step_limits_precede_allocation() {
    let mut m = meter();
    for _ in 0..4096 {
        let mut names = Names::new(Some(16_384), &m);
        for _ in 0..8 {
            assert!(names.push(&[b'x'; 1024], &mut m).unwrap());
        }
        let baseline = m.live_allocated();
        assert!(!names.push(b"x", &mut m).unwrap());
        assert_eq!(m.live_allocated(), baseline);
        drop(names);
        assert_eq!(m.live_allocated(), 0);
    }
    let mut names = Names::new(Some(8192), &m);
    assert!(!names.push(&[b'x'; 1025], &mut m).unwrap());
    assert_eq!(m.live_allocated(), 0);
    assert!(names.push(&[b'x'; 1023], &mut m).unwrap());
    assert!(names.push(&[b'x'; 1024], &mut m).unwrap());
    let mut names = Names::new(Some(1023), &m);
    assert!(!names.push(&[b'x'; 1024], &mut m).unwrap());
    m.allocation_limit = 0;
    assert_eq!(names.push(b"x", &mut m), Err(ReadError::Limit));
}
// Mount and effective access are independent observations; failure is unknown.
#[test]
fn readonly_mount_and_failed_observations_stay_conservative() {
    for access in [
        Ok(None),
        Ok(Some(false)),
        Ok(Some(true)),
        Err(ReadError::Denied),
    ] {
        assert_eq!(readonly_observation(access, Some(true)), Ok(Some(true)));
        assert_eq!(readonly_observation(access, None), Ok(None));
        assert_eq!(readonly_observation(access, Some(false)), access);
    }
    #[cfg(target_os = "linux")]
    assert_eq!(libc::ST_RDONLY, 1);
    #[cfg(target_os = "macos")]
    assert_eq!(libc::MNT_RDONLY, 1);
}
