use super::*;

fn caps(n: u64) -> AxisCaps {
    AxisCaps {
        f: n,
        p: n,
        l: n,
        r: n,
        d: n,
        e_n: n,
        e_b: n,
        m: n,
        b: n,
    }
}

// 이것을 실패시키는 것: U2(사용자 결정 2026-10-30) 값 하나라도 바꾸는 것, 의미 상한(32 files, 1 MiB)을
// F·B에 대입하는 것.
#[test]
fn axis_caps_are_the_user_decision_values() {
    assert_eq!(
        AXIS_CAPS,
        AxisCaps {
            f: 256,
            p: 8_192,
            l: 1_024,
            r: 256,
            d: 2,
            e_n: 1_024,
            e_b: 131_072,
            m: 16,
            b: 2_097_152,
        }
    );
    let fields = [
        AXIS_CAPS.f,
        AXIS_CAPS.p,
        AXIS_CAPS.l,
        AXIS_CAPS.r,
        AXIS_CAPS.d,
        AXIS_CAPS.e_n,
        AXIS_CAPS.e_b,
        AXIS_CAPS.m,
        AXIS_CAPS.b,
    ];
    for (axis, field) in HelperAxis::ALL.into_iter().zip(fields) {
        assert_eq!(AXIS_CAPS.cap(axis), field, "{axis:?}");
    }
}

// 축마다 cap까지는 받고 cap+1은 그 축 이름으로 거부한다. 다른 축을 cap까지 채워도 이 축의 여유는 그대로다.
// 이것을 실패시키는 것: 두 축이 한 칸을 함께 쓰는 것(예: E_n과 E_b), `>`를 `>=`로 바꾸는 것(cap에서 거부),
// 한 축의 cap을 다른 축에서 읽는 것, 거부한 양을 used에 더하는 것.
#[test]
fn axis_slack_never_covers_another_axis() {
    for axis in HelperAxis::ALL {
        let mut m = IoMeter::new(caps(10));
        for other in HelperAxis::ALL.into_iter().filter(|o| *o != axis) {
            m.charge(other, 10).unwrap();
        }
        m.charge(axis, 9).unwrap();
        m.charge(axis, 1).unwrap();
        assert_eq!(m.used(axis), 10, "{axis:?}");
        assert_eq!(
            m.charge(axis, 1),
            Err(AxisExceeded {
                axis,
                used: 11,
                cap: 10
            })
        );
        assert_eq!(m.used(axis), 10, "{axis:?}");
        // A fresh meter: filling every other axis leaves this axis's room alone.
        let mut m = IoMeter::new(caps(10));
        for other in HelperAxis::ALL.into_iter().filter(|o| *o != axis) {
            m.charge(other, 10).unwrap();
            assert_eq!(m.room(axis), 10, "{axis:?} after {other:?}");
        }
    }
}

// 이것을 실패시키는 것: 거부 뒤에도 다른 축의 계수를 받는 것(초과 뒤 I/O가 이어짐), 고유 키 축이 이미 본 키에서
// 걸쇠를 건너뛰는 것.
#[test]
fn a_refused_charge_latches_every_axis() {
    let mut m = IoMeter::new(caps(1));
    m.charge_file(Path::new("/a")).unwrap();
    m.charge_folder(Path::new("/d")).unwrap();
    m.charge_mount(7).unwrap();
    let refused = m.charge(HelperAxis::R, 2).unwrap_err();
    assert_eq!(refused.axis, HelperAxis::R);
    assert_eq!(m.exceeded(), Some(refused));
    for axis in HelperAxis::ALL {
        assert_eq!(m.charge(axis, 0), Err(refused), "{axis:?}");
    }
    assert_eq!(m.charge_file(Path::new("/a")), Err(refused));
    assert_eq!(m.charge_folder(Path::new("/d")), Err(refused));
    assert_eq!(m.charge_mount(7), Err(refused));
    assert_eq!(m.fits(&[0; 9]), Err(refused));
    assert_eq!(m.check(), Err(refused));
}

// F·D·M은 고유 키 수다. 같은 정규 경로·폴더·장치를 다시 보면 늘지 않는다.
// 이것을 실패시키는 것: D를 목록 작업마다 세는 것(오늘 회차마다 목록 4번이 D 4가 됨), F를 열기마다 세는 것,
// 키를 넣지 않는 것.
#[test]
fn distinct_axes_count_keys_not_visits() {
    let mut m = IoMeter::new(caps(2));
    for _ in 0..4 {
        m.charge_folder(Path::new("/c/conf.d")).unwrap();
        m.charge_file(Path::new("/c/config.toml")).unwrap();
        m.charge_mount(1).unwrap();
    }
    assert_eq!(
        [HelperAxis::D, HelperAxis::F, HelperAxis::M].map(|a| m.used(a)),
        [1, 1, 1]
    );
    m.charge_folder(Path::new("/c/other")).unwrap();
    assert_eq!(
        m.charge_folder(Path::new("/c/third")).unwrap_err().axis,
        HelperAxis::D
    );
}

// fits는 세지 않고 판정한다. 거부하면 걸쇠를 건다.
// 이것을 실패시키는 것: fits가 used를 바꾸는 것, 한 축이라도 넘는데 Ok를 내는 것, 축 칸을 잘못 읽는 것,
// 거부 뒤 걸쇠를 걸지 않는 것.
#[test]
fn fits_judges_without_charging() {
    let mut m = IoMeter::new(caps(10));
    m.charge(HelperAxis::Eb, 6).unwrap();
    let mut more = [0; 9];
    more[HelperAxis::Eb as usize] = 4;
    assert_eq!(m.fits(&more), Ok(()));
    more[HelperAxis::Eb as usize] = 5;
    assert_eq!(
        m.fits(&more),
        Err(AxisExceeded {
            axis: HelperAxis::Eb,
            used: 11,
            cap: 10
        })
    );
    assert_eq!(m.used(HelperAxis::Eb), 6);
    assert_eq!(m.exceeded().map(|e| e.axis), Some(HelperAxis::Eb));
    assert!(m.charge(HelperAxis::F, 0).is_err());
}

// 목록 계수는 걸러내기 전 원시 항목(`.`·`..` 포함)과 그 d_reclen 합이다. 기대 바이트는 이 시험이 libc readdir로
// 따로 센다.
// 이것을 실패시키는 것: `.toml` 걸러낸 뒤에만 E_n을 세는 것, `.`·`..`를 빼는 것, E_b에 이름 길이를 쓰는 것,
// 초과 뒤에도 항목을 계속 읽는 것, 걸쇠가 걸린 계수기로 목록을 시작하는 것.
#[test]
fn listing_charges_raw_entries_before_filtering() {
    use std::os::fd::AsFd;
    let dir = std::env::temp_dir().join(format!("bingsu-meter-list-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir(&dir).unwrap();
    for name in ["a.toml", ".hidden.toml", "notes.txt", "b.toml.bak"] {
        std::fs::write(dir.join(name), b"").unwrap();
    }
    std::fs::create_dir(dir.join("sub")).unwrap();
    let expected_bytes = reclen_sum(&dir);
    let file = std::fs::File::open(&dir).unwrap();
    let mut m = IoMeter::new(AXIS_CAPS);
    let mut names = crate::commands::sys::directory_names_metered(file.as_fd(), &mut m).unwrap();
    names.sort();
    assert_eq!(names.len(), 5);
    assert_eq!(m.used(HelperAxis::En), 7);
    assert_eq!(m.used(HelperAxis::Eb), expected_bytes);
    // Cap 3: the fourth raw entry is refused and the listing ends there.
    let mut m = IoMeter::new(AxisCaps {
        e_n: 3,
        ..AXIS_CAPS
    });
    let e = crate::commands::sys::directory_names_metered(file.as_fd(), &mut m).unwrap_err();
    assert_eq!(e.kind(), std::io::ErrorKind::Other);
    assert_eq!(m.used(HelperAxis::En), 3);
    assert_eq!(m.exceeded().unwrap().axis, HelperAxis::En);
    // A latched meter lists nothing: not even a descriptor that is no folder
    // reaches fdopendir (which would answer ENOTDIR).
    let not_a_folder = std::fs::File::open(dir.join("notes.txt")).unwrap();
    let e =
        crate::commands::sys::directory_names_metered(not_a_folder.as_fd(), &mut m).unwrap_err();
    assert!(e.to_string().starts_with("helper I/O budget"), "{e}");
    std::fs::remove_dir_all(&dir).unwrap();
}

/// The `d_reclen` sum of one listing, counted with libc directly.
#[allow(unsafe_code)]
fn reclen_sum(dir: &Path) -> u64 {
    use std::os::unix::ffi::OsStrExt;
    let c = std::ffi::CString::new(dir.as_os_str().as_bytes()).unwrap();
    // SAFETY: c is NUL-terminated; the stream is closed below.
    let stream = unsafe { libc::opendir(c.as_ptr()) };
    assert!(!stream.is_null());
    let mut sum = 0;
    loop {
        // SAFETY: stream is live until closedir.
        let entry = unsafe { libc::readdir(stream) };
        if entry.is_null() {
            break;
        }
        // SAFETY: entry is readdir's live record.
        sum += u64::from(unsafe { (*entry).d_reclen });
    }
    // SAFETY: closes the stream opened above once.
    unsafe { libc::closedir(stream) };
    sum
}
