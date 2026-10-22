//! X-11 current-runtime evidence. Minimum-version evidence remains decision 24.
#![cfg(target_os = "macos")]
#[allow(dead_code)]
#[path = "../src/meter.rs"]
mod meter;
#[allow(dead_code)]
#[path = "../src/safe_read/mod.rs"]
mod safe_read;
use meter::{Meter, Phase};
use safe_read::{
    macos::{self, BENEATH, DarwinCaps, NOFOLLOW_ANY, UNIQUE},
    *,
};
use std::{
    fs::{self, File},
    io::Read,
    os::{
        fd::{AsFd, AsRawFd, FromRawFd, OwnedFd},
        unix::{
            ffi::OsStrExt,
            fs::{PermissionsExt, symlink},
            process::CommandExt,
        },
    },
    path::PathBuf,
    process::{Command, Stdio},
    time::{Duration, Instant},
};

struct Fixture {
    runtime: PathBuf,
    root: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let runtime = std::env::temp_dir().join(format!(
            "b2-x11-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        fs::create_dir(&runtime).unwrap();
        let runtime = fs::canonicalize(runtime).unwrap();
        let root = runtime.join("collector-probes-v1/open-flags/root");
        for dir in [
            &runtime,
            &runtime.join("collector-probes-v1"),
            &runtime.join("collector-probes-v1/open-flags"),
            &root,
            &root.join("dir"),
            &root.parent().unwrap().join("outside"),
        ] {
            fs::create_dir_all(dir).unwrap();
            fs::set_permissions(dir, fs::Permissions::from_mode(0o700)).unwrap();
        }
        for (name, bytes) in [
            ("value", b"inside"),
            ("dir/file", b"inside"),
            ("hard", b"linked"),
        ] {
            fs::write(root.join(name), bytes).unwrap();
            fs::set_permissions(root.join(name), fs::Permissions::from_mode(0o600)).unwrap();
        }
        fs::hard_link(root.join("hard"), root.join("hard2")).unwrap();
        for (name, target) in [
            ("dir/inner", "../value"),
            ("dir/up", "../../outside"),
            ("linkdir", "dir"),
            ("absolute", "/"),
            ("escape", "../outside"),
        ] {
            symlink(target, root.join(name)).unwrap();
        }
        Self { runtime, root }
    }
    fn fd(&self) -> File {
        File::open(&self.root).unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.runtime).unwrap();
    }
}
fn meter() -> Meter {
    Meter::new(Instant::now() + Duration::from_secs(30))
}
fn cap(single_link: bool) -> ReadCap {
    ReadCap {
        bytes: 64,
        single_link,
    }
}

// 이것을 실패시키는 것: 양성 open만으로 capability를 주거나 음성 errno/ANY 병용 검사를 제거하는 것.
#[test]
fn x11_each_flag_requires_negative_semantics() {
    let f = Fixture::new();
    let fd = f.fd();
    let access = macos::probe(Some(fd.as_fd()), &mut meter()).unwrap();
    assert_eq!(
        access.darwin_caps(),
        DarwinCaps {
            beneath: true,
            nofollow_any: true,
            unique: true
        },
        "BLOCKED: current runtime X-11 semantics"
    );
    assert_eq!(
        access.scope(),
        ReadScope::AllStages(Guarantee::DarwinBeneath)
    );
    let rows = [
        ("value", BENEATH, 0),
        ("dir/../value", BENEATH, 0),
        ("dir/inner", BENEATH, 0),
        ("../outside", BENEATH, libc::ENOTCAPABLE),
        ("/", BENEATH, libc::ENOTCAPABLE),
        ("absolute", BENEATH, libc::ENOTCAPABLE),
        ("escape", BENEATH, libc::ENOTCAPABLE),
        ("dir/up", BENEATH, libc::ENOTCAPABLE),
        ("/dev/fd/0", BENEATH, libc::ENOTCAPABLE),
        ("dir/file", NOFOLLOW_ANY, 0),
        ("linkdir/file", NOFOLLOW_ANY, libc::ELOOP),
        ("value", UNIQUE, 0),
        ("hard", UNIQUE, libc::ENOTCAPABLE),
        ("dir/file", NOFOLLOW_ANY | libc::O_NOFOLLOW, libc::EINVAL),
    ];
    for (path, flags, expected) in rows {
        let name = std::ffi::CString::new(path).unwrap();
        // SAFETY: held fixture, terminated fixed path, no write/create flags.
        let raw = unsafe {
            libc::openat(
                fd.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_NONBLOCK | flags,
            )
        };
        let actual = if raw < 0 {
            std::io::Error::last_os_error().raw_os_error().unwrap()
        } else {
            // SAFETY: newly owned fd.
            drop(unsafe { OwnedFd::from_raw_fd(raw) });
            0
        };
        println!("X11 path={path} flags={flags:#x} errno={actual}");
        assert_eq!(actual, expected, "{path}");
    }
    // Change one observed row at a time: every individual gate is necessary.
    for (bad_path, bad_flags, expected) in rows {
        for wrong in [if expected == 0 { libc::EINVAL } else { 0 }, libc::EXDEV] {
            let caps = macos::caps_for_test(|path, flags| {
                let expected = rows
                    .iter()
                    .find(|r| r.0.as_bytes() == path.to_bytes() && r.1 == flags)
                    .unwrap()
                    .2;
                Ok(
                    if path.to_bytes() == bad_path.as_bytes() && flags == bad_flags {
                        wrong
                    } else {
                        expected
                    },
                )
            })
            .unwrap();
            assert_eq!(
                caps,
                DarwinCaps {
                    beneath: bad_flags & BENEATH == 0,
                    nofollow_any: bad_flags & NOFOLLOW_ANY == 0,
                    unique: bad_flags & UNIQUE == 0,
                },
                "missing semantic gate: {bad_path} {bad_flags:#x}"
            );
        }
    }
    let root = acquire(
        f.root.as_os_str().as_bytes(),
        DiscoveryQuery::default(),
        &mut meter(),
    )
    .unwrap()
    .select_cwd()
    .unwrap();
    for path in [
        b"value".as_slice(),
        b"dir/../value",
        b"dir/inner",
        b"linkdir/file",
    ] {
        assert_eq!(
            read(&root, path, cap(true), &access, &mut meter()).unwrap(),
            b"inside"
        );
    }
    assert_eq!(
        read(&root, b"hard", cap(true), &access, &mut meter()),
        Err(ReadError::Special)
    );
    assert_eq!(
        read(&root, b"hard", cap(false), &access, &mut meter()).unwrap(),
        b"linked"
    );
}

// 이것을 실패시키는 것: 무시된 flag를 지원으로 간주하거나 BENEATH 없이 일반 읽기를 허용하는 것.
#[test]
fn unknown_darwin_flags_do_not_enable_fast_path() {
    let f = Fixture::new();
    let fd = f.fd();
    // Zero models a flag silently ignored by an old kernel; 0x40000000 is
    // separately exercised as an unknown bit, never assumed unsupported.
    for flags in [
        [0, 0, 0],
        [0x4000_0000; 3],
        [0, NOFOLLOW_ANY, UNIQUE],
        [BENEATH, 0, 0],
    ] {
        let access = macos::probe_flags_for_test(fd.as_fd(), flags, &mut meter()).unwrap();
        assert_eq!(
            access.darwin_caps(),
            DarwinCaps {
                beneath: flags[0] == BENEATH,
                nofollow_any: flags[1] == NOFOLLOW_ANY,
                unique: flags[2] == UNIQUE
            }
        );
        if flags[0] != BENEATH {
            assert_eq!(access.scope(), ReadScope::StageAOnly);
            let root = acquire(
                f.root.as_os_str().as_bytes(),
                DiscoveryQuery::default(),
                &mut meter(),
            )
            .unwrap()
            .select_cwd()
            .unwrap();
            let mut m = meter();
            assert_eq!(
                read(&root, b"value", cap(false), &access, &mut m),
                Err(ReadError::StageAOnly)
            );
            assert_eq!(m.counts[Phase::Content as usize].open, 0);
        }
    }
}

// 이것을 실패시키는 것: fd 부재·sentinel 변조·부모 mode·링크 구조 검증을 생략하는 것.
#[test]
fn invalid_probe_fixture_falls_back_without_authority() {
    assert_eq!(
        macos::probe(None, &mut meter()).unwrap().scope(),
        ReadScope::StageAOnly
    );
    for case in [
        "sentinel",
        "mode",
        "parent",
        "symlink",
        "hard",
        "layout",
        "directory",
    ] {
        let f = Fixture::new();
        let fd = f.fd();
        match case {
            "sentinel" => fs::write(f.root.join("value"), b"spoof!").unwrap(),
            "mode" => fs::set_permissions(&f.root, fs::Permissions::from_mode(0o755)).unwrap(),
            "parent" => {
                fs::set_permissions(f.root.parent().unwrap(), fs::Permissions::from_mode(0o777))
                    .unwrap()
            }
            "symlink" => {
                fs::remove_file(f.root.join("dir/inner")).unwrap();
                symlink("../hard", f.root.join("dir/inner")).unwrap();
            }
            "hard" => {
                fs::remove_file(f.root.join("hard2")).unwrap();
                fs::write(f.root.join("hard2"), b"linked").unwrap();
            }
            "layout" => fs::rename(
                f.root.parent().unwrap(),
                f.root.parent().unwrap().with_file_name("wrong"),
            )
            .unwrap(),
            "directory" => {
                fs::remove_file(f.root.join("value")).unwrap();
                fs::create_dir(f.root.join("value")).unwrap();
            }
            _ => unreachable!(),
        }
        assert_eq!(
            macos::probe(Some(fd.as_fd()), &mut meter())
                .unwrap()
                .scope(),
            ReadScope::StageAOnly,
            "{case}"
        );
    }
}

// 이것을 실패시키는 것: BENEATH를 NO_XDEV로 오인하여 component fsid 검사를 생략하는 것.
#[test]
fn darwin_mount_and_devfd_are_refused() {
    let f = Fixture::new();
    let fd = f.fd();
    let a = macos::probe(Some(fd.as_fd()), &mut meter()).unwrap();
    let slash = acquire(b"/", DiscoveryQuery::default(), &mut meter())
        .unwrap()
        .unchecked_cwd_for_test();
    let raw_slash = File::open("/").unwrap();
    // SAFETY: read-only fixed directory under a live fd.
    let raw = unsafe {
        libc::openat(
            raw_slash.as_raw_fd(),
            c"dev".as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | BENEATH,
        )
    };
    assert!(raw >= 0, "BENEATH alone permits /dev crossing");
    // SAFETY: fresh fd.
    drop(unsafe { OwnedFd::from_raw_fd(raw) });
    println!("X11 beneath_dev_crossing=success adapter_dev_crossing=Escape");
    assert!(matches!(
        directory(&slash, b"dev", &a, &mut meter()),
        Err(ReadError::Escape)
    ));
    assert_eq!(
        read(&slash, b"dev/fd/0", cap(false), &a, &mut meter()),
        Err(ReadError::Escape)
    );
}

// 이것을 실패시키는 것: acquisition에도 mount 동일성 조건을 적용하거나 선택 root 아래 crossing을 허용하는 것.
#[test]
fn cwd_on_other_mount_is_allowed() {
    use std::os::unix::fs::MetadataExt;
    let volumes_device = fs::metadata("/Volumes").unwrap().dev();
    let volume = fs::read_dir("/Volumes")
        .unwrap()
        .filter_map(Result::ok)
        .find_map(|entry| {
            let metadata = fs::symlink_metadata(entry.path()).ok()?;
            (metadata.is_dir() && metadata.dev() != volumes_device).then(|| entry.path())
        })
        .expect("BLOCKED: X-11 needs a real mounted directory under /Volumes");
    let root = acquire(
        volume.as_os_str().as_bytes(),
        DiscoveryQuery::default(),
        &mut meter(),
    )
    .unwrap()
    .select_cwd()
    .unwrap();
    assert_ne!(root.device(), volumes_device);
    println!(
        "X11 volume={} device={} parent_device={volumes_device}",
        volume.display(),
        root.device()
    );
    let f = Fixture::new();
    let a = macos::probe(Some(f.fd().as_fd()), &mut meter()).unwrap();
    let slash = acquire(b"/", DiscoveryQuery::default(), &mut meter())
        .unwrap()
        .unchecked_cwd_for_test();
    assert!(matches!(
        directory(&slash, b"dev", &a, &mut meter()),
        Err(ReadError::Escape)
    ));
}

// 이것을 실패시키는 것: probe 처리 비용·읽기·임시 fd가 무제한이거나 probe phase 복원을 생략하는 것.
#[test]
fn probe_observations_are_bounded() {
    let f = Fixture::new();
    let fd = f.fd();
    let mut samples = Vec::new();
    for _ in 0..201 {
        let mut m = meter();
        let start = Instant::now();
        let a = macos::probe(Some(fd.as_fd()), &mut m).unwrap();
        samples.push(start.elapsed().as_nanos());
        assert_eq!(a.scope(), ReadScope::AllStages(Guarantee::DarwinBeneath));
        assert_eq!(m.phase, Phase::Content);
        assert!(m.peak_fds <= 7);
        assert_eq!(m.counts[Phase::Probe as usize].read_bytes, 24);
        assert_eq!(m.counts[Phase::Content as usize].open, 0);
        if samples.len() == 1 {
            println!(
                "X11 cold_ns={} counts={:?} peak_fds={}",
                samples[0], m.counts[0], m.peak_fds
            );
        }
    }
    let cold = samples.remove(0);
    samples.sort();
    let mean = samples.iter().sum::<u128>() as f64 / samples.len() as f64;
    let variance = samples
        .iter()
        .map(|n| (*n as f64 - mean).powi(2))
        .sum::<f64>()
        / samples.len() as f64;
    println!(
        "X11 n=200 cold_ns={cold} p50_ns={} p95_ns={} variance_ns2={variance}",
        samples[100], samples[190]
    );
    let mut expired = Meter::new(Instant::now());
    assert!(matches!(
        macos::probe(Some(fd.as_fd()), &mut expired),
        Err(ReadError::Deadline)
    ));
}

// 이것을 실패시키는 것: 보호 전 probe·probe 생략·Ready까지 fd6 유지·추가 fd 상속.
#[test]
fn startup_probe_is_closed_before_ready() {
    use bingsu_core::collection::wire;
    let f = Fixture::new();
    let interposer = f.runtime.join("order.dylib");
    let output = Command::new("cc")
        .args([
            "-dynamiclib",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-DPROBE_ORDER_INTERPOSER",
        ])
        .arg(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../bench/probes/m3c-path-probe.c"))
        .arg("-o")
        .arg(&interposer)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let lock = File::create(f.runtime.join("lock")).unwrap();
    lock.set_permissions(fs::Permissions::from_mode(0o600))
        .unwrap();
    let mut pipes = [0; 2];
    // SAFETY: writable fd pair.
    assert_eq!(unsafe { libc::pipe(pipes.as_mut_ptr()) }, 0);
    // SAFETY: both newly owned endpoints.
    let input = unsafe { OwnedFd::from_raw_fd(pipes[0]) };
    // SAFETY: newly owned write endpoint.
    let _writer = unsafe { OwnedFd::from_raw_fd(pipes[1]) };
    let probe = f.fd();
    let copies: Vec<_> = [input.as_raw_fd(), lock.as_raw_fd(), probe.as_raw_fd()]
        .into_iter()
        .map(|fd| {
            // SAFETY: live sources, disjoint from destinations.
            let fd = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 10) };
            assert!(fd >= 10);
            // SAFETY: fresh owned duplicate.
            unsafe { OwnedFd::from_raw_fd(fd) }
        })
        .collect();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_bingsu-collect"));
    cmd.arg("__collect-v1")
        .env_clear()
        .env("DYLD_INSERT_LIBRARIES", &interposer)
        .current_dir("/")
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .stdout(Stdio::piped());
    let setup = move || {
        for (fd, to) in copies.iter().zip([3, 5, 6]) {
            // SAFETY: live duplicated source, reserved child slot.
            if unsafe { libc::dup2(fd.as_raw_fd(), to) } < 0 {
                return Err(std::io::Error::last_os_error());
            }
        }
        // SAFETY: live lock, deliberate inheritable high fd.
        if unsafe { libc::fcntl(5, libc::F_DUPFD, 1025) } < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    };
    // SAFETY: setup only performs async-signal-safe descriptor operations.
    unsafe {
        cmd.pre_exec(setup);
    }
    // 이것을 실패시키는 것: DYLD_INSERT_LIBRARIES 제거로 interposer가 로드되지 않는 것.
    // The same command/setup must reject Ready when no probe was possible.
    let mut absent = Command::new(cmd.get_program());
    absent
        .args(cmd.get_args())
        .env_clear()
        .envs(
            cmd.get_envs()
                .filter_map(|(key, value)| value.map(|value| (key, value))),
        )
        .current_dir("/")
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .stdout(Stdio::piped());
    let input_fd = input.as_raw_fd();
    let lock_fd = lock.as_raw_fd();
    // SAFETY: duplicate sources before spawn; child only uses descriptor calls.
    let absent_copies: Vec<_> = [input_fd, lock_fd]
        .into_iter()
        .map(|fd| {
            // SAFETY: live sources, disjoint from child destinations.
            let copy = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 10) };
            assert!(copy >= 10);
            // SAFETY: uniquely owned duplicate.
            unsafe { OwnedFd::from_raw_fd(copy) }
        })
        .collect();
    let absent_setup = move || {
        for (fd, to) in absent_copies.iter().zip([3, 5]) {
            // SAFETY: live duplicated source, reserved child slot.
            if unsafe { libc::dup2(fd.as_raw_fd(), to) } < 0 {
                return Err(std::io::Error::last_os_error());
            }
        }
        // SAFETY: intentionally remove the probe capability from this child.
        unsafe {
            libc::close(6);
        }
        Ok(())
    };
    // SAFETY: only async-signal-safe fd operations after fork.
    unsafe {
        absent.pre_exec(absent_setup);
    }
    let negative = absent.output().unwrap();
    assert_eq!(
        negative.status.code(),
        Some(89),
        "interposer must be active"
    );
    assert!(
        negative.stdout.is_empty(),
        "Ready must not escape the canary"
    );
    let start = Instant::now();
    let mut child = cmd.spawn().unwrap();
    let mut bytes = [0; wire::HEADER + 24];
    let result = child.stdout.as_mut().unwrap().read_exact(&mut bytes);
    let elapsed = start.elapsed();
    // SAFETY: integer-only writable census output.
    let mut records: [libc::proc_fdinfo; 64] = unsafe { std::mem::zeroed() };
    // SAFETY: read-only child census with exactly sized writable buffer.
    let n = unsafe {
        libc::proc_pidinfo(
            child.id() as i32,
            libc::PROC_PIDLISTFDS,
            0,
            records.as_mut_ptr().cast(),
            std::mem::size_of_val(&records) as i32,
        )
    };
    child.kill().unwrap();
    child.wait().unwrap();
    result.unwrap();
    assert_eq!(wire::decode_frame(&bytes).unwrap().kind, wire::Kind::Ready);
    assert!(n > 0 && (n as usize) < std::mem::size_of_val(&records));
    let mut fds: Vec<_> = records[..n as usize / std::mem::size_of::<libc::proc_fdinfo>()]
        .iter()
        .map(|r| r.proc_fd)
        .collect();
    fds.sort();
    assert_eq!(fds, [0, 1, 2, 3, 5]);
    println!("X11 spawn_to_ready_ns={} fds={fds:?}", elapsed.as_nanos());
}

// 이것을 실패시키는 것: probe 전용 fd 타입을 content Root로 읽을 수 있게 만드는 것.
#[test]
fn probe_fd_cannot_become_repository_root() {
    let source = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
    let deps = std::env::current_exe()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf();
    let libc = fs::read_dir(&deps)
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| {
            p.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("liblibc-")
                && p.extension().is_some_and(|e| e == "rlib")
        })
        .unwrap();
    let f = Fixture::new();
    let prefix = format!(
        "#![allow(dead_code)]\n#[path={:?}] mod meter;\n#[path={:?}] mod safe_read;\n#[path={:?}] mod sys;\nuse safe_read::*;\n",
        source.join("meter.rs"),
        source.join("safe_read/mod.rs"),
        source.join("sys.rs")
    );
    for (name, body, valid) in [
        (
            "positive",
            "fn ok(p: sys::CollectorProbeFd, m: &mut meter::Meter) { let _ = safe_read::macos::probe(Some(p.fixture()), m); }",
            true,
        ),
        (
            "probe_read",
            "fn bad(p: sys::CollectorProbeFd, a: &Access, m: &mut meter::Meter) { let _ = read(&p, b\"value\", ReadCap { bytes: 64, single_link: true }, a, m); }",
            false,
        ),
    ] {
        let file = f.runtime.join(format!("{name}.rs"));
        fs::write(&file, format!("{prefix}{body}")).unwrap();
        let out = Command::new("rustc")
            .args(["--edition=2024", "--crate-type=lib", "--emit=metadata"])
            .arg(&file)
            .arg("--out-dir")
            .arg(&f.runtime)
            .arg("--extern")
            .arg(format!("libc={}", libc.display()))
            .arg("-L")
            .arg(format!("dependency={}", deps.display()))
            .output()
            .unwrap();
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.success(), valid, "{name}: {stderr}");
        if !valid {
            assert!(stderr.contains("E0308"), "{stderr}");
        }
    }
}
