//! Resolver tests deliberately run outside the product BPF. Linux mount tests
//! require a separate child with CAP_SYS_ADMIN; unavailable hosts are BLOCKED.
#![cfg(unix)]
#[cfg(target_os = "linux")]
#[allow(dead_code)]
#[path = "../src/landlock.rs"]
mod landlock;
#[allow(dead_code)]
#[path = "../src/meter.rs"]
mod meter;
#[allow(dead_code)]
#[path = "../src/safe_read/mod.rs"]
mod safe_read;

use meter::{Meter, Phase};
use safe_read::{DiscoveryQuery, ReadCap, ReadError as E, Resolver, acquire, read_with};
use std::{
    fs,
    os::unix::{ffi::OsStrExt, fs::symlink},
    path::PathBuf,
    time::{Duration, Instant},
};

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!(
            "bingsu-safe-read-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(fs::canonicalize(path).unwrap())
    }
    fn root(&self, meter: &mut Meter) -> safe_read::Root {
        acquire(
            self.0.as_os_str().as_bytes(),
            DiscoveryQuery::default(),
            meter,
        )
        .unwrap()
        .select_cwd()
        .unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}
fn meter() -> Meter {
    Meter::new(Instant::now() + Duration::from_secs(30))
}
fn cap(bytes: u64) -> ReadCap {
    ReadCap {
        bytes,
        single_link: false,
    }
}
fn backends() -> Vec<Resolver> {
    #[cfg(target_os = "linux")]
    {
        vec![Resolver::Stepwise, Resolver::Openat2]
    }
    #[cfg(not(target_os = "linux"))]
    {
        vec![Resolver::Stepwise, Resolver::DarwinBeneath]
    }
}
fn test_access(backend: Resolver) -> safe_read::Access {
    #[cfg(target_os = "macos")]
    if backend == Resolver::DarwinBeneath {
        use std::os::fd::AsFd;
        let (_fixture, fd) = darwin_fixture();
        let access =
            safe_read::macos::probe_unvalidated_for_test(Some(fd.as_fd()), &mut meter()).unwrap();
        assert_eq!(
            access.guarantee(),
            Some(safe_read::Guarantee::DarwinBeneath)
        );
        return access;
    }
    safe_read::unchecked_backend_for_test(backend)
}
fn result(
    root: &safe_read::Root,
    path: &[u8],
    backend: Resolver,
    meter: &mut Meter,
) -> Result<Vec<u8>, E> {
    read_with(root, path, cap(65_536), &test_access(backend), meter)
}

// 이것을 실패시키는 것: symlink 깊이·절대 링크·root pop·파일 종류 검사를 제거하거나 안전한 상대 링크를 거부하는 것.
#[test]
fn x13_resolvers_share_static_verdicts() {
    let fixture = Fixture::new();
    fs::create_dir(fixture.0.join("dir")).unwrap();
    fs::write(fixture.0.join("value"), b"inside").unwrap();
    // APFS rejects this filename; the real byte-path fixture runs on Linux.
    #[cfg(target_os = "linux")]
    fs::write(
        fixture.0.join(std::ffi::OsStr::from_bytes(b"raw-\xff")),
        b"inside",
    )
    .unwrap();
    symlink("value", fixture.0.join("relative")).unwrap();
    symlink("../value", fixture.0.join("dir/parent")).unwrap();
    symlink("/etc/passwd", fixture.0.join("absolute")).unwrap();
    symlink("../outside", fixture.0.join("escape")).unwrap();
    symlink("loop", fixture.0.join("loop")).unwrap();
    symlink("/proc/self/fd/0", fixture.0.join("magic")).unwrap();
    for n in 1..=41 {
        symlink(
            if n == 1 {
                "value".to_owned()
            } else {
                format!("link{}", n - 1)
            },
            fixture.0.join(format!("link{n}")),
        )
        .unwrap();
    }
    let fifo = std::ffi::CString::new(fixture.0.join("fifo").as_os_str().as_bytes()).unwrap();
    // SAFETY: fixture-owned absolute path and fixed FIFO permissions.
    assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
    type Verdict<'a> = (&'a [u8], Result<&'a [u8], E>);
    let rows: &[Verdict<'_>] = &[
        (b"value", Ok(b"inside")),
        #[cfg(target_os = "linux")]
        (b"raw-\xff", Ok(b"inside")),
        (b"relative", Ok(b"inside")),
        (b"dir/parent", Ok(b"inside")),
        (b"dir/../value", Ok(b"inside")),
        (b"link40", Ok(b"inside")),
        (b"link41", Err(E::Symlink)),
        (b"loop", Err(E::Symlink)),
        (b"absolute", Err(E::Escape)),
        (b"magic", Err(E::Escape)),
        (b"escape", Err(E::Escape)),
        (b"../value", Err(E::Escape)),
        (b"/value", Err(E::Escape)),
        (b"a\0b", Err(E::Escape)),
        (b"missing", Err(E::Missing)),
        (b"value/child", Err(E::Missing)),
        (b"fifo", Err(E::Special)),
        (b"dir", Err(E::Special)),
    ];
    for backend in backends() {
        for &(path, expected) in rows {
            let mut budget = meter();
            let root = fixture.root(&mut budget);
            assert_eq!(
                result(&root, path, backend, &mut budget).as_deref(),
                expected.as_deref(),
                "{backend:?} {path:?}"
            );
        }
        let mut budget = meter();
        let dev = acquire(b"/dev", DiscoveryQuery::default(), &mut budget)
            .unwrap()
            .select_cwd()
            .unwrap();
        assert_eq!(result(&dev, b"null", backend, &mut budget), Err(E::Special));
        assert_eq!(budget.counts[Phase::Content as usize].read, 0);
    }
}

// 이것을 실패시키는 것: 같은 fd 대신 경로를 다시 열거나 single_link의 nlink 검사를 빼는 것.
#[test]
fn same_fd_read_and_single_link_policy() {
    for backend in backends() {
        let fixture = Fixture::new();
        fs::write(fixture.0.join("value"), b"original").unwrap();
        let mut budget = meter();
        let root = fixture.root(&mut budget);
        let file =
            safe_read::resolve_with(&root, b"value", &test_access(backend), &mut budget).unwrap();
        fs::rename(fixture.0.join("value"), fixture.0.join("old")).unwrap();
        fs::write(fixture.0.join("value"), b"replacement").unwrap();
        assert_eq!(file.read(cap(8), &mut budget).unwrap(), b"original");
        fs::hard_link(fixture.0.join("value"), fixture.0.join("hard")).unwrap();
        assert_eq!(
            read_with(
                &root,
                b"hard",
                ReadCap {
                    bytes: 64,
                    single_link: true
                },
                &test_access(backend),
                &mut budget
            ),
            Err(E::Special)
        );
        assert_eq!(
            result(&root, b"hard", backend, &mut budget).unwrap(),
            b"replacement"
        );
    }
}

// 이것을 실패시키는 것: cap+1 overflow·크기 사전 검사·byte budget 확인을 할당 뒤로 옮기는 것.
#[test]
fn read_limit_checks_before_allocation() {
    let fixture = Fixture::new();
    fs::write(fixture.0.join("large"), [b'x'; 1024]).unwrap();
    for backend in backends() {
        let mut budget = meter();
        let root = fixture.root(&mut budget);
        let before = budget.counts;
        assert_eq!(
            read_with(
                &root,
                b"large",
                cap(u64::MAX),
                &test_access(backend),
                &mut budget
            ),
            Err(E::Limit)
        );
        assert_eq!(budget.counts, before);
        budget.byte_limit = 8;
        assert_eq!(
            read_with(&root, b"large", cap(8), &test_access(backend), &mut budget),
            Err(E::Limit)
        );
        assert_eq!(budget.counts, before);
        budget.byte_limit = 4096;
        assert_eq!(
            read_with(
                &root,
                b"large",
                cap(1023),
                &test_access(backend),
                &mut budget
            ),
            Err(E::Limit)
        );
        assert_eq!(budget.counts[Phase::Content as usize].read, 0);
        budget.allocation_limit = 0;
        assert_eq!(
            read_with(
                &root,
                b"large",
                cap(1024),
                &test_access(backend),
                &mut budget
            ),
            Err(E::Limit)
        );
    }
}

// 이것을 실패시키는 것: fstat 크기를 신뢰해 EOF/cap+1 읽기를 빼거나 요청한 cap보다 많은 바이트를 읽는 것.
#[test]
fn growing_file_stops_at_cap_plus_one() {
    for backend in backends() {
        let fixture = Fixture::new();
        fs::write(fixture.0.join("growing"), b"x").unwrap();
        let mut budget = meter();
        let root = fixture.root(&mut budget);
        let path = fixture.0.join("growing");
        budget.hook = Some(Box::new(move |event| {
            if event == "before_read" {
                fs::write(&path, [b'x'; 100]).unwrap();
            }
        }));
        assert_eq!(
            read_with(
                &root,
                b"growing",
                cap(8),
                &test_access(backend),
                &mut budget
            ),
            Err(E::Limit)
        );
        assert_eq!(budget.counts[Phase::Content as usize].read_bytes, 9);
    }
}

// 이것을 실패시키는 것: FIFO를 blocking open하거나 fstat 종류 확인 전에 read하는 것.
#[test]
fn fifo_open_never_waits_for_writer() {
    let fixture = Fixture::new();
    let path = std::ffi::CString::new(fixture.0.join("fifo").as_os_str().as_bytes()).unwrap();
    // SAFETY: fixture-owned pathname and fixed mode.
    assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
    for backend in backends() {
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "fifo_child", "--ignored", "--test-threads=1"])
            .env("BINGSU_FIFO_ROOT", &fixture.0)
            .env(
                "BINGSU_FIFO_FAST",
                match backend {
                    Resolver::Openat2 => "openat2",
                    Resolver::DarwinBeneath => "darwin",
                    Resolver::Stepwise => "stepwise",
                },
            )
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                assert!(status.success());
                break;
            }
            if Instant::now() >= deadline {
                child.kill().unwrap();
                child.wait().unwrap();
                panic!("FIFO open waited for a writer");
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }
}

#[test]
#[ignore = "isolated timeout child of fifo_open_never_waits_for_writer"]
// 이것을 실패시키는 것: FIFO의 종류 검사 없이 read를 시도하는 것(부모 시험이 자식 실패를 단언).
fn fifo_child() {
    let mut budget = meter();
    let path = std::env::var_os("BINGSU_FIFO_ROOT").unwrap();
    let root = acquire(path.as_bytes(), DiscoveryQuery::default(), &mut budget)
        .unwrap()
        .select_cwd()
        .unwrap();
    let backend = match std::env::var("BINGSU_FIFO_FAST").unwrap().as_str() {
        "openat2" => Resolver::Openat2,
        "darwin" => Resolver::DarwinBeneath,
        "stepwise" => Resolver::Stepwise,
        other => panic!("unknown fixture backend: {other}"),
    };
    assert_eq!(
        result(&root, b"fifo", backend, &mut budget),
        Err(E::Special)
    );
    assert_eq!(budget.counts[Phase::Content as usize].read, 0);
}

// 이것을 실패시키는 것: live fd 상한을 제거하거나 소유 fd를 닫은 뒤에도 예산을 반환하지 않는 것.
#[test]
fn fd_budget_is_released_on_drop() {
    let fixture = Fixture::new();
    let mut budget = meter();
    let mut roots = Vec::new();
    let mut refused = false;
    for _ in 0..64 {
        match acquire(
            fixture.0.as_os_str().as_bytes(),
            DiscoveryQuery::default(),
            &mut budget,
        ) {
            Ok(discovery) => roots.push(discovery.select_cwd().unwrap()),
            Err(E::Limit) => {
                refused = true;
                break;
            }
            Err(error) => panic!("unexpected acquisition failure: {error:?}"),
        }
    }
    assert!(refused);
    assert_eq!(budget.peak_fds, meter::LIVE_FDS);
    drop(roots);
    assert!(
        acquire(
            fixture.0.as_os_str().as_bytes(),
            DiscoveryQuery::default(),
            &mut budget
        )
        .is_ok()
    );
}

// 이것을 실패시키는 것: deadline·component 방문·보유 ancestor fd 상한을 제거하는 것.
#[test]
fn acquisition_and_deadline_are_bounded() {
    let fixture = Fixture::new();
    let mut budget = Meter::new(Instant::now());
    assert!(matches!(
        acquire(
            fixture.0.as_os_str().as_bytes(),
            DiscoveryQuery::default(),
            &mut budget
        ),
        Err(E::Deadline)
    ));
    let mut deep = fixture.0.clone();
    for _ in 0..70 {
        deep.push("d");
        fs::create_dir(&deep).unwrap();
    }
    let mut budget = meter();
    let discovered = acquire(
        deep.as_os_str().as_bytes(),
        DiscoveryQuery::default(),
        &mut budget,
    )
    .unwrap();
    assert_eq!(discovered.ancestors().len(), 32);
    assert!(budget.peak_fds <= 34);
    let mut path = b"/".to_vec();
    path.extend(b"./".repeat(4097));
    assert!(matches!(
        acquire(&path, DiscoveryQuery::default(), &mut meter()),
        Err(E::Limit)
    ));
    // The retained ancestor stack cannot safely pop an already discarded fd.
    deep.push("../".repeat(40));
    assert!(matches!(
        acquire(
            deep.as_os_str().as_bytes(),
            DiscoveryQuery::default(),
            &mut meter()
        ),
        Err(E::Limit)
    ));
}

// 이것을 실패시키는 것: procfs의 fd를 root나 acquisition 중간 폴더로 받아들이는 것.
#[test]
#[cfg(target_os = "linux")]
fn root_procfs_is_refused() {
    for path in [b"/proc".as_slice(), b"/proc/self/fd"] {
        assert!(matches!(
            acquire(path, DiscoveryQuery::default(), &mut meter()),
            Err(E::Escape)
        ));
    }
}

// 이것을 실패시키는 것: statx 성공만 보고 MNT_ID 비트 부재·ENOSYS·EPERM을 허용하는 것.
#[test]
#[cfg(target_os = "linux")]
fn missing_mount_identity_refuses_collection() {
    let fixture = Fixture::new();
    for fault in [0, libc::ENOSYS, libc::EPERM] {
        let mut budget = meter();
        budget.mount_fault = Some(fault);
        assert!(matches!(
            acquire(
                fixture.0.as_os_str().as_bytes(),
                DiscoveryQuery::default(),
                &mut budget
            ),
            Err(E::Denied)
        ));
        assert_eq!(budget.counts[Phase::Acquisition as usize].read, 0);
    }
}

// 이것을 실패시키는 것: ENOSYS/EPERM 외 오류를 미지원으로 낮추거나 파일별 EPERM에서 backend를 전환하는 것.
#[test]
#[cfg(target_os = "linux")]
fn x15_enosys_and_eperm_select_stepwise() {
    for error in [libc::ENOSYS, libc::EPERM] {
        let mut budget = meter();
        budget.openat2_errors.push_back(error);
        let choice = safe_read::ResolverChoice::default();
        assert_eq!(choice.get(&mut budget), Ok(Resolver::Stepwise));
        assert_eq!(budget.counts[Phase::Probe as usize].open, 2);
        budget.openat2_errors.push_back(libc::EINVAL);
        assert_eq!(choice.get(&mut budget), Ok(Resolver::Stepwise));
        assert_eq!(budget.openat2_errors.len(), 1);
    }
    for error in [libc::EINVAL, libc::E2BIG] {
        let mut budget = meter();
        budget.openat2_errors.push_back(error);
        assert_eq!(safe_read::probe_for_test(&mut budget), Err(E::Io(error)));
    }
    let mut denied = meter();
    denied.openat2_errors.push_back(libc::EACCES);
    assert_eq!(safe_read::probe_for_test(&mut denied), Err(E::Denied));
    // This is mandatory native evidence; ENOSYS/EPERM is BLOCKED, not a pass.
    assert_eq!(
        safe_read::probe_for_test(&mut meter()),
        Ok(Resolver::Openat2),
        "BLOCKED: native openat2 success is required"
    );
    let fixture = Fixture::new();
    fs::write(fixture.0.join("value"), b"inside").unwrap();
    let mut budget = meter();
    let root = fixture.root(&mut budget);
    budget.openat2_errors.push_back(libc::EPERM);
    assert_eq!(
        result(&root, b"value", Resolver::Openat2, &mut budget),
        Err(E::Denied)
    );
    assert_eq!(budget.counts[Phase::Content as usize].open, 1);
    assert_eq!(budget.counts[Phase::Content as usize].read, 0);
}

// 이것을 실패시키는 것: EAGAIN 3회·EINTR 9회 뒤에도 syscall을 계속 재시도하는 것.
#[test]
#[cfg(target_os = "linux")]
fn retries_are_finite() {
    let fixture = Fixture::new();
    for (error, attempts) in [(libc::EAGAIN, 3), (libc::EINTR, 9)] {
        let mut budget = meter();
        let root = fixture.root(&mut budget);
        budget
            .openat2_errors
            .extend(std::iter::repeat_n(error, attempts + 1));
        assert_eq!(
            result(&root, b"value", Resolver::Openat2, &mut budget),
            Err(E::Changed)
        );
        assert_eq!(budget.counts[Phase::Content as usize].open, attempts as u64);
        assert_eq!(budget.openat2_errors.len(), 1);
    }
}

// 이것을 실패시키는 것: dot 항목을 raw cap에서 빼거나 names에 넣는 것,
// cap 밖 이름을 할당·getdents를 추가 호출하거나 EOF 확인 없이 complete로 만드는 것.
#[test]
#[cfg(target_os = "linux")]
fn entries_limit_precedes_filtering_and_allocation() {
    let fixture = Fixture::new();
    for n in 0..300 {
        fs::write(fixture.0.join(format!("f{n}")), b"").unwrap();
    }
    // Use libc's independent iterator as the raw-order oracle, including dots.
    // The fixture stays unchanged: ext4/overlay may put dots anywhere in this order.
    let path = std::ffi::CString::new(fixture.0.as_os_str().as_bytes()).unwrap();
    // SAFETY: NUL-terminated path to the fixture directory.
    let stream = unsafe { libc::opendir(path.as_ptr()) };
    assert!(!stream.is_null());
    let mut raw_names = Vec::new();
    loop {
        // SAFETY: live directory stream, used only by this test thread.
        let entry = unsafe { libc::readdir(stream) };
        if entry.is_null() {
            break;
        }
        // SAFETY: readdir supplies a NUL-terminated name valid until the next call.
        let name_ptr = unsafe { (*entry).d_name.as_ptr() };
        // SAFETY: name_ptr is the terminated name provided by readdir.
        let name = unsafe { std::ffi::CStr::from_ptr(name_ptr) };
        raw_names.push(name.to_bytes().to_vec());
    }
    // SAFETY: close this stream exactly once after the last readdir.
    assert_eq!(unsafe { libc::closedir(stream) }, 0);
    let mut all_names = raw_names.clone();
    all_names.sort();
    let mut expected_all = vec![b".".to_vec(), b"..".to_vec()];
    expected_all.extend((0..300).map(|n| format!("f{n}").into_bytes()));
    expected_all.sort();
    assert_eq!(all_names, expected_all);

    for limit in [0, 1, 2, 256, 301, 302, 303, 512] {
        let mut budget = meter();
        let root = fixture.root(&mut budget);
        let dir =
            safe_read::directory_with(&root, b".", &test_access(Resolver::Stepwise), &mut budget)
                .unwrap();
        let before = budget.counts[Phase::Content as usize];
        let listing = safe_read::entries(&dir, limit, &mut budget).unwrap();
        let counts = budget.counts[Phase::Content as usize];
        let expected: Vec<_> = raw_names
            .iter()
            .take(limit as usize)
            .filter(|name| name.as_slice() != b"." && name.as_slice() != b"..")
            .cloned()
            .collect();
        assert_eq!(
            counts.raw_entries,
            u64::from(limit).min(raw_names.len() as u64)
        );
        assert_eq!(listing.complete, limit as usize > raw_names.len());
        assert_eq!(listing.names, expected, "raw cap {limit}");
        assert_eq!(
            counts.allocated - before.allocated,
            expected
                .iter()
                .map(|name| (name.len() + std::mem::size_of::<Vec<u8>>()) as u64)
                .sum::<u64>()
        );
        if limit == 0 {
            assert_eq!(counts.list, 0);
        }
    }
}

// 이것을 실패시키는 것: acquisition에서 mount 이동을 금지하거나 content에서 같은 st_dev의 bind mount를 허용하는 것.
#[test]
#[cfg(target_os = "linux")]
#[ignore = "required Linux mount namespace child: run explicitly with CAP_SYS_ADMIN and --test-threads=1"]
fn cwd_on_other_mount_is_allowed() {
    // This process must be an isolated test invocation, never a shared runner.
    assert_eq!(
        // SAFETY: creates a private mount namespace in this disposable test child.
        unsafe { libc::unshare(libc::CLONE_NEWNS) },
        0,
        "BLOCKED: CAP_SYS_ADMIN required"
    );
    assert_eq!(
        // SAFETY: fixed mount propagation change in the private namespace.
        unsafe {
            libc::mount(
                std::ptr::null(),
                c"/".as_ptr(),
                std::ptr::null(),
                libc::MS_REC | libc::MS_PRIVATE,
                std::ptr::null(),
            )
        },
        0
    );
    let fixture = Fixture::new();
    fs::create_dir(fixture.0.join("volume")).unwrap();
    let volume = std::ffi::CString::new(fixture.0.join("volume").as_os_str().as_bytes()).unwrap();
    assert_eq!(
        // SAFETY: fixture-owned directory, tmpfs without device source, private namespace.
        unsafe {
            libc::mount(
                c"tmpfs".as_ptr(),
                volume.as_ptr(),
                c"tmpfs".as_ptr(),
                0,
                std::ptr::null(),
            )
        },
        0
    );
    fs::write(fixture.0.join("volume/value"), b"inside").unwrap();
    fs::create_dir(fixture.0.join("volume/bind")).unwrap();
    fs::create_dir(fixture.0.join("volume/source")).unwrap();
    fs::write(fixture.0.join("volume/source/value"), b"outside").unwrap();
    let bind =
        std::ffi::CString::new(fixture.0.join("volume/bind").as_os_str().as_bytes()).unwrap();
    let source =
        std::ffi::CString::new(fixture.0.join("volume/source").as_os_str().as_bytes()).unwrap();
    assert_eq!(
        // SAFETY: two fixture-owned directories on the same tmpfs.
        unsafe {
            libc::mount(
                source.as_ptr(),
                bind.as_ptr(),
                std::ptr::null(),
                libc::MS_BIND,
                std::ptr::null(),
            )
        },
        0
    );
    let mut budget = meter();
    let outer = fixture.root(&mut budget);
    let inner = acquire(volume.as_bytes(), DiscoveryQuery::default(), &mut budget)
        .unwrap()
        .select_cwd()
        .unwrap();
    assert_ne!(outer.device(), inner.device());
    use std::os::unix::fs::MetadataExt;
    assert_eq!(
        fs::metadata(fixture.0.join("volume/source")).unwrap().dev(),
        fs::metadata(fixture.0.join("volume/bind")).unwrap().dev()
    );
    for backend in backends() {
        assert_eq!(
            result(&inner, b"value", backend, &mut budget).unwrap(),
            b"inside"
        );
        assert_eq!(
            result(&outer, b"volume/value", backend, &mut budget),
            Err(E::Escape)
        );
        assert_eq!(
            result(&inner, b"bind/value", backend, &mut budget),
            Err(E::Escape)
        );
    }
    // SAFETY: detach only the two mounts created in this private namespace.
    assert_eq!(unsafe { libc::umount2(bind.as_ptr(), libc::MNT_DETACH) }, 0);
    assert_eq!(
        // SAFETY: detach the fixture-owned tmpfs after its nested bind mount.
        unsafe { libc::umount2(volume.as_ptr(), libc::MNT_DETACH) },
        0
    );
}

// 이것을 실패시키는 것: 실제 read를 생략하거나 16KiB chunk 대신 전체 파일을 한 번에 읽는 것.
#[test]
#[ignore = "observations: run explicitly with --nocapture --test-threads=1"]
fn resolver_observations() {
    let fixture = Fixture::new();
    fs::write(fixture.0.join("small"), vec![b'x'; 1024]).unwrap();
    fs::write(fixture.0.join("large"), vec![b'x'; 65_536]).unwrap();
    for backend in backends() {
        let access = test_access(backend);
        let mut acquire_ns = Vec::new();
        let mut small_ns = Vec::new();
        let mut large_ns = Vec::new();
        for sample in 0..=200 {
            let mut budget = meter();
            let start = Instant::now();
            let root = fixture.root(&mut budget);
            let acquisition = start.elapsed().as_nanos();
            let start = Instant::now();
            assert_eq!(
                read_with(&root, b"small", cap(1024), &access, &mut budget)
                    .unwrap()
                    .len(),
                1024
            );
            let small = start.elapsed().as_nanos();
            let start = Instant::now();
            assert_eq!(
                read_with(&root, b"large", cap(65_536), &access, &mut budget)
                    .unwrap()
                    .len(),
                65_536
            );
            let large = start.elapsed().as_nanos();
            assert_eq!(budget.counts[Phase::Content as usize].read, 7);
            // 이것을 실패시키는 것: fd 검사나 mount 확인을 생략하거나 중복하는 것.
            let components = fixture
                .0
                .as_os_str()
                .as_bytes()
                .split(|&byte| byte == b'/')
                .filter(|part| !part.is_empty())
                .count() as u64;
            let acquisition_counts = budget.counts[Phase::Acquisition as usize];
            assert_eq!(acquisition_counts.open, components + 1);
            assert_eq!(acquisition_counts.stat, 2 * components + 1);
            assert_eq!(acquisition_counts.filesystem, components + 1);
            let content_counts = budget.counts[Phase::Content as usize];
            assert_eq!(
                content_counts.open,
                if backend == Resolver::DarwinBeneath {
                    4
                } else {
                    2
                }
            );
            assert_eq!(
                content_counts.stat,
                match backend {
                    Resolver::Stepwise => 4,
                    Resolver::DarwinBeneath => 6,
                    Resolver::Openat2 => 2,
                }
            );
            assert_eq!(
                content_counts.filesystem,
                if backend == Resolver::DarwinBeneath {
                    4
                } else {
                    2
                }
            );
            assert_eq!(content_counts.read_bytes, 1024 + 65_536);
            #[cfg(target_os = "linux")]
            {
                assert_eq!(acquisition_counts.mount, components + 1);
                assert_eq!(content_counts.mount, 2);
            }
            if sample == 0 {
                println!(
                    "OBSERVE first {backend:?} acquisition_ns={acquisition} small_ns={small} large_ns={large} counts={:?} peak_fds={}",
                    budget.counts, budget.peak_fds
                );
            } else {
                acquire_ns.push(acquisition);
                small_ns.push(small);
                large_ns.push(large);
            }
        }
        for (label, mut samples) in [
            ("acquisition", acquire_ns),
            ("1KiB", small_ns),
            ("64KiB", large_ns),
        ] {
            println!("RAW {backend:?} {label} {samples:?}");
            samples.sort_unstable();
            let mean = samples.iter().sum::<u128>() as f64 / samples.len() as f64;
            let variance = samples
                .iter()
                .map(|&n| (n as f64 - mean).powi(2))
                .sum::<f64>()
                / samples.len() as f64;
            println!(
                "OBSERVE warm {backend:?} {label} n=200 p50_ns={} p95_ns={} variance_ns2={variance}",
                samples[99], samples[189]
            );
        }
    }
}

// 이것을 실패시키는 것: 보장 없는 Access에 전체 read·resolve·directory 권한을 주는 것.
#[test]
fn no_guarantee_exposes_only_stage_a() {
    use safe_read::{Access, ReadScope, StageAFile};
    let fixture = Fixture::new();
    fs::write(fixture.0.join("HEAD"), b"ref: refs/heads/main\n").unwrap();
    fs::write(fixture.0.join("index"), b"NOT_STAGE_A").unwrap();
    fs::create_dir(fixture.0.join(".git")).unwrap();
    fs::write(fixture.0.join(".git/HEAD"), b"nested head").unwrap();
    let access = Access::stage_a_only();
    assert_eq!(access.scope(), ReadScope::StageAOnly);
    let mut budget = meter();
    let root = fixture.root(&mut budget);
    assert_eq!(
        safe_read::read_stage_a(&root, StageAFile::Head, &access, &mut budget).unwrap(),
        b"ref: refs/heads/main\n"
    );
    let git =
        safe_read::directory_stage_a(&root, safe_read::StageADirectory::Git, &access, &mut budget)
            .unwrap();
    assert_eq!(
        git.read(StageAFile::Head, &access, &mut budget).unwrap(),
        b"nested head"
    );
    let before = budget.counts;
    for path in [
        b"HEAD".as_slice(),
        b"index",
        b"objects/ab/value",
        b"worktree",
    ] {
        assert_eq!(
            safe_read::read(&root, path, cap(64), &access, &mut budget),
            Err(E::StageAOnly)
        );
        assert!(matches!(
            safe_read::resolve_with(&root, path, &access, &mut budget),
            Err(E::StageAOnly)
        ));
        assert!(matches!(
            safe_read::directory(&root, path, &access, &mut budget),
            Err(E::StageAOnly)
        ));
    }
    assert_eq!(budget.counts, before, "refuse before any IO or allocation");
}

// 이것을 실패시키는 것: 정상 git 쓰기의 directory ctime 변화를 Changed로 취급하는 것.
#[test]
fn normal_git_writes_do_not_invalidate_held_directories() {
    let fixture = Fixture::new();
    fs::create_dir_all(fixture.0.join("a/b")).unwrap();
    fs::write(fixture.0.join("a/b/value"), b"inside").unwrap();
    let mut budget = meter();
    let root = fixture.root(&mut budget);
    let path = fixture.0.clone();
    budget.hook = Some(Box::new(move |event| {
        if event == "after_open_component" {
            fs::write(path.join("index.lock"), b"normal git write").unwrap();
            fs::rename(path.join("index.lock"), path.join("index")).unwrap();
        }
    }));
    assert_eq!(
        result(&root, b"a/b/value", Resolver::Stepwise, &mut budget).unwrap(),
        b"inside"
    );
    let counts = budget.counts[Phase::Content as usize];
    assert_eq!(counts.stat, 6, "one lstat and one fstat per component");
    assert_eq!(counts.open, 3);
}

#[cfg(target_os = "macos")]
fn darwin_fixture() -> (Fixture, fs::File) {
    let fixture = Fixture::new();
    fs::create_dir(fixture.0.join("dir")).unwrap();
    fs::write(fixture.0.join("value"), b"inside").unwrap();
    fs::write(fixture.0.join("dir/file"), b"inside").unwrap();
    fs::write(fixture.0.join("hard"), b"linked").unwrap();
    fs::hard_link(fixture.0.join("hard"), fixture.0.join("hard2")).unwrap();
    symlink("../value", fixture.0.join("dir/inner")).unwrap();
    symlink("dir", fixture.0.join("linkdir")).unwrap();
    symlink("/", fixture.0.join("absolute")).unwrap();
    symlink("../outside", fixture.0.join("escape")).unwrap();
    symlink("../../outside", fixture.0.join("dir/up")).unwrap();
    let fd = fs::File::open(&fixture.0).unwrap();
    (fixture, fd)
}

// 이것을 실패시키는 것: SDK 상수·양성 open만 보고 flag 보장을 부여하거나 없는 fixture를 신뢰하는 것.
#[test]
#[cfg(target_os = "macos")]
fn darwin_each_flag_requires_negative_semantics() {
    use safe_read::macos::{self, BENEATH, DarwinCaps, NOFOLLOW_ANY, UNIQUE};
    use std::os::fd::AsFd;
    let (_fixture, fd) = darwin_fixture();
    let access = macos::probe_unvalidated_for_test(Some(fd.as_fd()), &mut meter()).unwrap();
    assert_eq!(
        access.darwin_caps(),
        DarwinCaps {
            beneath: true,
            nofollow_any: true,
            unique: true
        },
        "BLOCKED: current Darwin runtime semantics required"
    );
    assert_eq!(
        access.guarantee(),
        Some(safe_read::Guarantee::DarwinBeneath)
    );
    assert_eq!(
        macos::probe_unvalidated_for_test(None, &mut meter())
            .unwrap()
            .scope(),
        safe_read::ReadScope::StageAOnly
    );
    for flags in [
        [0, NOFOLLOW_ANY, UNIQUE],
        [BENEATH, 0, UNIQUE],
        [BENEATH, NOFOLLOW_ANY, 0],
    ] {
        let access = macos::probe_flags_for_test(fd.as_fd(), flags, &mut meter()).unwrap();
        assert_eq!(
            access.darwin_caps(),
            DarwinCaps {
                beneath: flags[0] != 0,
                nofollow_any: flags[1] != 0,
                unique: flags[2] != 0
            }
        );
        assert_eq!(access.guarantee().is_some(), flags[0] != 0);
    }
}

// 이것을 실패시키는 것: BENEATH가 no-xdev라는 가정·NOFOLLOW_ANY|NOFOLLOW 병용·errno 계약 변경.
#[test]
#[cfg(target_os = "macos")]
fn darwin_flag_behavior_and_mount_backstop() {
    use safe_read::macos::{self, BENEATH, NOFOLLOW_ANY, UNIQUE};
    use std::os::fd::{AsFd, AsRawFd};
    let (fixture, fd) = darwin_fixture();
    let rows = [
        ("value", BENEATH, None),
        ("dir/../value", BENEATH, None),
        ("dir/inner", BENEATH, None),
        ("../outside", BENEATH, Some(libc::ENOTCAPABLE)),
        ("/", BENEATH, Some(libc::ENOTCAPABLE)),
        ("absolute", BENEATH, Some(libc::ENOTCAPABLE)),
        ("escape", BENEATH, Some(libc::ENOTCAPABLE)),
        ("dir/up", BENEATH, Some(libc::ENOTCAPABLE)),
        ("/dev/fd/0", BENEATH, Some(libc::ENOTCAPABLE)),
        ("linkdir/file", NOFOLLOW_ANY, Some(libc::ELOOP)),
        ("dir/file", NOFOLLOW_ANY, None),
        ("hard", UNIQUE, Some(libc::ENOTCAPABLE)),
        ("value", UNIQUE, None),
        (
            "dir/file",
            NOFOLLOW_ANY | libc::O_NOFOLLOW,
            Some(libc::EINVAL),
        ),
    ];
    for (path, flags, error) in rows {
        let name = std::ffi::CString::new(path).unwrap();
        // SAFETY: held fixture dirfd, terminated path, no write/create flags.
        let opened = unsafe { libc::openat(fd.as_raw_fd(), name.as_ptr(), libc::O_RDONLY | flags) };
        let actual = if opened < 0 {
            std::io::Error::last_os_error().raw_os_error()
        } else {
            // SAFETY: successful open returned this fresh fd.
            unsafe { libc::close(opened) };
            None
        };
        println!("DARWIN path={path} flags={flags:#x} errno={actual:?}");
        assert_eq!(actual, error, "{path}");
    }
    let access = macos::probe_unvalidated_for_test(Some(fd.as_fd()), &mut meter()).unwrap();
    let mut budget = meter();
    let root = fixture.root(&mut budget);
    for path in [
        b"value".as_slice(),
        b"dir/../value",
        b"dir/inner",
        b"linkdir/file",
    ] {
        assert_eq!(
            safe_read::read(&root, path, cap(64), &access, &mut budget).unwrap(),
            b"inside"
        );
    }
    assert_eq!(
        safe_read::read(
            &root,
            b"hard",
            ReadCap {
                bytes: 64,
                single_link: true
            },
            &access,
            &mut budget
        ),
        Err(E::Special)
    );
    assert_eq!(
        safe_read::read(&root, b"hard", cap(64), &access, &mut budget).unwrap(),
        b"linked"
    );
    let slash_fd = fs::File::open("/").unwrap();
    // SAFETY: fixed path beneath a live root descriptor, read-only directory.
    let dev = unsafe {
        libc::openat(
            slash_fd.as_raw_fd(),
            c"dev".as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | BENEATH,
        )
    };
    assert!(dev >= 0, "BENEATH permits crossing into /dev");
    // SAFETY: dev was returned by successful openat.
    unsafe { libc::close(dev) };
    let slash = acquire(b"/", DiscoveryQuery::default(), &mut budget)
        .unwrap()
        .unchecked_cwd_for_test();
    assert!(matches!(
        safe_read::directory(&slash, b"dev", &access, &mut budget),
        Err(E::Escape)
    ));
    let dev_root = acquire(b"/dev", DiscoveryQuery::default(), &mut budget)
        .unwrap()
        .select_cwd()
        .unwrap();
    assert!(safe_read::directory(&dev_root, b".", &access, &mut budget).is_ok());
}

// 이것을 실패시키는 것: Darwin에서 이동한 중간 fd를 기준으로 BENEATH를 열거나 최종 root open을 생략하는 것.
#[test]
#[cfg(target_os = "macos")]
fn coarse_rename_with_guarantee_reads_zero_external_bytes() {
    use std::os::fd::AsFd;
    let (fixture, probe_fd) = darwin_fixture();
    let access =
        safe_read::macos::probe_unvalidated_for_test(Some(probe_fd.as_fd()), &mut meter()).unwrap();
    assert!(access.guarantee().is_some());
    fs::create_dir_all(fixture.0.join("root/a/b")).unwrap();
    fs::write(fixture.0.join("canary"), b"EXTERNAL").unwrap();
    let mut budget = meter();
    let root = acquire(
        fixture.0.join("root").as_os_str().as_bytes(),
        DiscoveryQuery::default(),
        &mut budget,
    )
    .unwrap()
    .select_cwd()
    .unwrap();
    let path = fixture.0.clone();
    let mut visits = 0;
    budget.hook = Some(Box::new(move |event| {
        if event == "after_open_component" {
            visits += 1;
            if visits == 2 {
                // Same held root->a->b and never-in-root canary as the coarse
                // reproduction; ctime is irrelevant and no longer sampled.
                fs::rename(path.join("root/a"), path.join("moved-a")).unwrap();
                fs::rename(path.join("canary"), path.join("moved-a/b/value")).unwrap();
            }
            if visits == 3 {
                // Alternate the two disconnected links without ever placing
                // the canary beneath root, defeating sequential revalidation.
                fs::rename(path.join("moved-a/b"), path.join("moved-b")).unwrap();
                fs::rename(path.join("moved-a"), path.join("root/a")).unwrap();
            }
        }
    }));
    let result = safe_read::read(&root, b"a/b/value", cap(64), &access, &mut budget);
    println!(
        "COARSE guarantee={:?} result={result:?} bytes={}",
        access.guarantee(),
        budget.counts[Phase::Content as usize].read_bytes
    );
    assert!(matches!(
        result,
        Err(E::Missing | E::Changed | E::Escape | E::Denied)
    ));
    assert_eq!(budget.counts[Phase::Content as usize].read_bytes, 0);
}

// 이것을 실패시키는 것: lstat/fstat dev·ino 대조를 빼서 검사 직후 교체된 leaf를 받아들이는 것.
#[test]
fn component_replacement_is_changed() {
    let fixture = Fixture::new();
    fs::write(fixture.0.join("value"), b"original").unwrap();
    let mut budget = meter();
    let root = fixture.root(&mut budget);
    let path = fixture.0.clone();
    budget.hook = Some(Box::new(move |event| {
        if event == "before_open_component" {
            fs::rename(path.join("value"), path.join("old")).unwrap();
            fs::write(path.join("value"), b"replacement").unwrap();
        }
    }));
    assert_eq!(
        result(&root, b"value", Resolver::Stepwise, &mut budget),
        Err(E::Changed)
    );
    assert_eq!(budget.counts[Phase::Content as usize].read_bytes, 0);
}

// 이것을 실패시키는 것: 탐침이 검증한 UNIQUE를 최종 open에서 빼거나 ANY 없이 안전한 fallback을 거부하는 것.
#[test]
#[cfg(target_os = "macos")]
fn darwin_optional_flags_are_used_only_when_probed() {
    use safe_read::macos::{self, BENEATH};
    use std::os::fd::AsFd;
    let (fixture, fd) = darwin_fixture();
    let mut budget = meter();
    let root = fixture.root(&mut budget);
    let access = macos::probe_flags_for_test(fd.as_fd(), [BENEATH, 0, 0], &mut budget).unwrap();
    assert_eq!(
        safe_read::read(&root, b"dir/inner", cap(64), &access, &mut budget).unwrap(),
        b"inside"
    );
    let access = macos::probe_unvalidated_for_test(Some(fd.as_fd()), &mut budget).unwrap();
    let path = fixture.0.clone();
    budget.hook = Some(Box::new(move |event| {
        if event == "before_beneath_open" {
            fs::hard_link(path.join("value"), path.join("new-link")).unwrap();
        }
    }));
    assert_eq!(
        safe_read::read(
            &root,
            b"value",
            ReadCap {
                bytes: 64,
                single_link: true
            },
            &access,
            &mut budget
        ),
        Err(E::Escape)
    );
}

// 이것을 실패시키는 것: Darwin 최종 root open의 fd 정체를 사전 walk와 대조하지 않는 것.
#[test]
#[cfg(target_os = "macos")]
fn darwin_atomic_reopen_checks_identity() {
    use std::os::fd::AsFd;
    let (fixture, fd) = darwin_fixture();
    let mut budget = meter();
    let access =
        safe_read::macos::probe_unvalidated_for_test(Some(fd.as_fd()), &mut budget).unwrap();
    let root = fixture.root(&mut budget);
    let path = fixture.0.clone();
    budget.hook = Some(Box::new(move |event| {
        if event == "before_beneath_open" {
            fs::rename(path.join("value"), path.join("old")).unwrap();
            fs::write(path.join("value"), b"replacement").unwrap();
        }
    }));
    assert_eq!(
        safe_read::read(&root, b"value", cap(64), &access, &mut budget),
        Err(E::Changed)
    );
    assert_eq!(budget.counts[Phase::Content as usize].read_bytes, 0);
}

// 이것을 실패시키는 것: 보장 없는 HEAD를 일반 walk로 열어 index symlink를 따라가는 것.
#[test]
fn stage_a_symlink_head_is_unknown() {
    let fixture = Fixture::new();
    fs::write(fixture.0.join("index"), b"NOT_STAGE_A").unwrap();
    symlink("index", fixture.0.join("HEAD")).unwrap();
    let mut budget = meter();
    let root = fixture.root(&mut budget);
    let access = safe_read::Access::stage_a_only();
    assert_eq!(
        safe_read::read_stage_a(&root, safe_read::StageAFile::Head, &access, &mut budget),
        Err(E::Symlink)
    );
    assert_eq!(budget.counts[Phase::Content as usize].read_bytes, 0);
}

// 이것을 실패시키는 것: 단계 A를 일반 walk로 돌려 HEAD의 상대 링크와 교대 rename으로 외부 canary를 읽는 것.
#[test]
fn stage_a_symlink_coarse_rename_reads_zero_external_bytes() {
    let fixture = Fixture::new();
    fs::create_dir_all(fixture.0.join("root/a/b")).unwrap();
    fs::write(fixture.0.join("canary"), b"EXTERNAL").unwrap();
    symlink("a/b/value", fixture.0.join("root/HEAD")).unwrap();
    let mut budget = meter();
    let root = acquire(
        fixture.0.join("root").as_os_str().as_bytes(),
        DiscoveryQuery::default(),
        &mut budget,
    )
    .unwrap()
    .select_cwd()
    .unwrap();
    let path = fixture.0.clone();
    let mut visits = 0;
    budget.hook = Some(Box::new(move |event| {
        if event == "after_open_component" {
            visits += 1;
            if visits == 2 {
                fs::rename(path.join("root/a"), path.join("moved-a")).unwrap();
                fs::rename(path.join("canary"), path.join("moved-a/b/value")).unwrap();
            }
            if visits == 3 {
                fs::rename(path.join("moved-a/b"), path.join("moved-b")).unwrap();
                fs::rename(path.join("moved-a"), path.join("root/a")).unwrap();
            }
        }
    }));
    let result = safe_read::read_stage_a(
        &root,
        safe_read::StageAFile::Head,
        &safe_read::Access::stage_a_only(),
        &mut budget,
    );
    println!(
        "STAGE_A result={result:?} outside_bytes={}",
        budget.counts[Phase::Content as usize].read_bytes
    );
    assert_eq!(budget.counts[Phase::Content as usize].read_bytes, 0);
    assert_eq!(result, Err(E::Symlink));
}

// 이것을 실패시키는 것: 고정 파일·폴더 open의 O_NOFOLLOW를 빼서 lstat 뒤 symlink 교체를 허용하는 것.
#[test]
fn stage_a_nofollow_survives_leaf_and_directory_replacement() {
    for directory in [false, true] {
        let fixture = Fixture::new();
        let name = if directory { ".git" } else { "HEAD" };
        if directory {
            fs::create_dir(fixture.0.join(name)).unwrap();
        } else {
            fs::write(fixture.0.join(name), b"inside").unwrap();
        }
        let mut budget = meter();
        let root = fixture.root(&mut budget);
        let path = fixture.0.clone();
        budget.hook = Some(Box::new(move |event| {
            if event == "before_open_component" {
                fs::rename(path.join(name), path.join("moved")).unwrap();
                symlink("moved", path.join(name)).unwrap();
            }
        }));
        let access = safe_read::Access::stage_a_only();
        let result = if directory {
            safe_read::directory_stage_a(
                &root,
                safe_read::StageADirectory::Git,
                &access,
                &mut budget,
            )
            .map(|_| ())
        } else {
            safe_read::read_stage_a(&root, safe_read::StageAFile::Head, &access, &mut budget)
                .map(|_| ())
        };
        assert!(matches!(result, Err(E::Symlink | E::Missing)), "{result:?}");
        assert_eq!(budget.counts[Phase::Content as usize].read_bytes, 0);
    }
}

// 이것을 실패시키는 것: 작업 폴더를 일반 walk로 열거나 typed 폴더와 다른 파일 enum을 허용하는 것.
#[test]
fn stage_a_operation_directories_are_typed_and_nofollow() {
    use safe_read::{Access, StageADirectory as D, StageAFile as F};
    let fixture = Fixture::new();
    let mut budget = meter();
    let root = fixture.root(&mut budget);
    let access = Access::stage_a_only();
    for (name, dir, file) in [
        ("rebase-merge", D::RebaseMerge, F::RebaseMergeHeadName),
        ("rebase-apply", D::RebaseApply, F::RebaseApplyHeadName),
    ] {
        fs::create_dir(fixture.0.join(name)).unwrap();
        fs::write(fixture.0.join(name).join("head-name"), b"branch").unwrap();
        assert_eq!(
            safe_read::read_stage_a(&root, file, &access, &mut budget).unwrap(),
            b"branch"
        );
        let held = safe_read::directory_stage_a(&root, dir, &access, &mut budget).unwrap();
        assert_eq!(held.read(F::Head, &access, &mut budget), Err(E::Denied));
        fs::rename(fixture.0.join(name), fixture.0.join("moved")).unwrap();
        symlink("moved", fixture.0.join(name)).unwrap();
        assert_eq!(
            safe_read::read_stage_a(&root, file, &access, &mut budget),
            Err(E::Symlink)
        );
        fs::remove_file(fixture.0.join(name)).unwrap();
        fs::rename(fixture.0.join("moved"), fixture.0.join(name)).unwrap();
    }
    symlink("rebase-merge", fixture.0.join(".git")).unwrap();
    assert!(matches!(
        safe_read::directory_stage_a(&root, D::Git, &access, &mut budget),
        Err(E::Symlink)
    ));
}

// 이것을 실패시키는 것: '/'나 .git 없는 조상을 content root로 승격하거나 mount/owner 검증을 빼는 것.
#[test]
fn content_roots_require_validated_selection() {
    let fixture = Fixture::new();
    fs::create_dir(fixture.0.join("child")).unwrap();
    let discover = |budget: &mut Meter| {
        acquire(
            fixture.0.join("child").as_os_str().as_bytes(),
            DiscoveryQuery::default(),
            budget,
        )
        .unwrap()
    };
    let mut budget = meter();
    assert!(matches!(
        acquire(b"/", DiscoveryQuery::default(), &mut budget)
            .unwrap()
            .select_cwd(),
        Err(E::Escape)
    ));
    let access = safe_read::Access::stage_a_only();
    assert!(matches!(
        discover(&mut budget).select_worktree(1, &access, &mut budget),
        Err(E::Missing)
    ));
    assert!(matches!(
        discover(&mut budget).select_worktree(usize::MAX, &access, &mut budget),
        Err(E::Escape)
    ));
    fs::create_dir(fixture.0.join(".git")).unwrap();
    for access in [access, test_access(backends()[1])] {
        let selected = discover(&mut budget)
            .select_worktree(1, &access, &mut budget)
            .unwrap();
        let meta = acquire(
            fixture.0.join(".git").as_os_str().as_bytes(),
            DiscoveryQuery::default(),
            &mut budget,
        )
        .unwrap()
        .select_metadata(&selected, &mut budget)
        .unwrap();
        assert_eq!(meta.device(), selected.device());
    }
    let selected = fixture.root(&mut budget);
    // /dev is a different mount on both required hosts; the negative cell is mandatory.
    assert!(matches!(
        acquire(b"/dev", DiscoveryQuery::default(), &mut budget)
            .unwrap()
            .select_metadata(&selected, &mut budget),
        Err(E::Escape)
    ));
    fs::remove_dir(fixture.0.join(".git")).unwrap();
    fs::write(fixture.0.join(".git"), b"gitdir: metadata\n").unwrap();
    assert!(
        discover(&mut budget)
            .select_worktree(1, &safe_read::Access::stage_a_only(), &mut budget)
            .is_ok()
    );
    fs::hard_link(fixture.0.join(".git"), fixture.0.join("other")).unwrap();
    assert!(matches!(
        discover(&mut budget).select_worktree(1, &safe_read::Access::stage_a_only(), &mut budget),
        Err(E::Special)
    ));
}

// 이것을 실패시키는 것: ENOSYS의 Stepwise 결과를 Access::probe_with에서 커널 보장으로 승격하는 것.
#[test]
#[cfg(target_os = "linux")]
fn access_probe_stepwise_has_no_guarantee() {
    let mut budget = meter();
    budget.openat2_errors.push_back(libc::ENOSYS);
    let choice = safe_read::ResolverChoice::default();
    let access = safe_read::Access::probe_with(&choice, &mut budget).unwrap();
    assert_eq!(access.guarantee(), None);
    assert_eq!(access.scope(), safe_read::ReadScope::StageAOnly);
    assert_eq!(choice.get(&mut budget), Ok(Resolver::Stepwise));
    assert!(budget.openat2_errors.is_empty());
    let fixture = Fixture::new();
    let root = fixture.root(&mut budget);
    let before = budget.counts;
    assert_eq!(
        read_with(&root, b"index", cap(64), &access, &mut budget),
        Err(E::StageAOnly)
    );
    assert_eq!(budget.counts, before);
}

// 이것을 실패시키는 것: ancestor 목록에 raw256 상한을 빼거나 entries 중 entry별 stat/read를 추가하는 것.
#[test]
#[cfg(target_os = "linux")]
fn ancestors_only_list_bounded_names() {
    let fixture = Fixture::new();
    fs::create_dir(fixture.0.join("child")).unwrap();
    for i in 0..300 {
        fs::write(fixture.0.join(format!("file-{i}")), b"x").unwrap();
    }
    let mut budget = meter();
    let discovery = acquire(
        fixture.0.join("child").as_os_str().as_bytes(),
        DiscoveryQuery {
            home_component: Some(2),
            unique: true,
        },
        &mut budget,
    )
    .unwrap();
    assert!(discovery.logical());
    assert_eq!(discovery.query().home_component, Some(2));
    assert!(discovery.query().unique);
    let before = budget.counts[Phase::Content as usize];
    let listing = discovery
        .ancestors()
        .last()
        .unwrap()
        .entries(999, &mut budget)
        .unwrap();
    let after = budget.counts[Phase::Content as usize];
    assert!(!listing.complete);
    assert_eq!(after.raw_entries - before.raw_entries, 256);
    assert_eq!(after.stat, before.stat);
    assert_eq!(after.read, before.read);
}

// 이것을 실패시키는 것: strict 단계 A의 regular/nlink 검사 또는 dev/ino 교체 검사를 빼는 것.
#[test]
fn stage_a_checks_file_kind_links_and_identity() {
    let fixture = Fixture::new();
    let mut budget = meter();
    let root = fixture.root(&mut budget);
    let access = safe_read::Access::stage_a_only();
    fs::create_dir(fixture.0.join("HEAD")).unwrap();
    assert_eq!(
        safe_read::read_stage_a(&root, safe_read::StageAFile::Head, &access, &mut budget),
        Err(E::Special)
    );
    fs::remove_dir(fixture.0.join("HEAD")).unwrap();
    let fifo = std::ffi::CString::new(fixture.0.join("HEAD").as_os_str().as_bytes()).unwrap();
    // SAFETY: fixed fixture path and mode; O_NONBLOCK prevents waiting for a writer.
    assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
    assert_eq!(
        safe_read::read_stage_a(&root, safe_read::StageAFile::Head, &access, &mut budget),
        Err(E::Special)
    );
    fs::remove_file(fixture.0.join("HEAD")).unwrap();
    fs::write(fixture.0.join("HEAD"), b"inside").unwrap();
    fs::hard_link(fixture.0.join("HEAD"), fixture.0.join("hard")).unwrap();
    assert_eq!(
        safe_read::read_stage_a(&root, safe_read::StageAFile::Head, &access, &mut budget),
        Err(E::Special)
    );
    fs::remove_file(fixture.0.join("hard")).unwrap();
    let path = fixture.0.clone();
    budget.hook = Some(Box::new(move |event| {
        if event == "before_open_component" {
            fs::rename(path.join("HEAD"), path.join("old")).unwrap();
            fs::write(path.join("HEAD"), b"changed").unwrap();
        }
    }));
    assert_eq!(
        safe_read::read_stage_a(&root, safe_read::StageAFile::Head, &access, &mut budget),
        Err(E::Changed)
    );
    assert_eq!(budget.counts[Phase::Content as usize].read_bytes, 0);
}

// 이것을 실패시키는 것: 보장 있는 단계 A에서 이동된 작업 폴더 fd를 새 confinement root로 사용하는 것.
#[test]
fn stage_a_held_directory_keeps_selected_root() {
    use safe_read::{StageADirectory as D, StageAFile as F};
    #[cfg(target_os = "macos")]
    let access = test_access(Resolver::DarwinBeneath);
    #[cfg(target_os = "linux")]
    let access = safe_read::Access::probe(&mut meter()).unwrap();
    assert!(
        access.guarantee().is_some(),
        "BLOCKED: native confinement required"
    );
    for (name, dir, file, leaf) in [
        (".git", D::Git, F::Head, "HEAD"),
        (
            "rebase-merge",
            D::RebaseMerge,
            F::RebaseMergeHeadName,
            "head-name",
        ),
        (
            "rebase-apply",
            D::RebaseApply,
            F::RebaseApplyHeadName,
            "head-name",
        ),
    ] {
        let fixture = Fixture::new();
        fs::create_dir_all(fixture.0.join("root").join(name)).unwrap();
        fs::write(fixture.0.join("root").join(name).join(leaf), b"inside").unwrap();
        let mut budget = meter();
        let root = acquire(
            fixture.0.join("root").as_os_str().as_bytes(),
            DiscoveryQuery::default(),
            &mut budget,
        )
        .unwrap()
        .select_cwd()
        .unwrap();
        let held = safe_read::directory_stage_a(&root, dir, &access, &mut budget).unwrap();
        assert_eq!(held.read(file, &access, &mut budget).unwrap(), b"inside");
        fs::rename(fixture.0.join("root").join(name), fixture.0.join("moved")).unwrap();
        fs::write(fixture.0.join("moved").join(leaf), b"EXTERNAL").unwrap();
        let before = budget.counts[Phase::Content as usize].read_bytes;
        assert_eq!(held.read(file, &access, &mut budget), Err(E::Missing));
        assert_eq!(budget.counts[Phase::Content as usize].read_bytes, before);
    }
}
