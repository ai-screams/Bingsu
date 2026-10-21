use crate::{filter, landlock};
use std::{io, process::Command};
#[allow(dead_code)]
#[path = "../../src/limits.rs"]
mod limits;
#[path = "../support/process.rs"]
mod process;
#[allow(dead_code)]
#[path = "../../src/sys.rs"]
mod sys;
fn errno() -> i32 {
    io::Error::last_os_error().raw_os_error().unwrap()
}
// Every raw probe uses scalar arguments or live buffers. Invalid pointers are
// deliberate kernel validation probes; they are never dereferenced by Rust.
fn raw(n: libc::c_long, a: [u64; 6]) -> libc::c_long {
    // SAFETY: six scalar ABI words; each caller keeps pointed-to storage live.
    unsafe { libc::syscall(n, a[0], a[1], a[2], a[3], a[4], a[5]) }
}
fn denied(n: libc::c_long, a: [u64; 6], expected: i32) {
    assert_eq!(raw(n, a), -1, "syscall {n}");
    assert_eq!(errno(), expected, "syscall {n}");
}
fn nnp() {
    // SAFETY: process-local irreversible restriction with integer arguments.
    assert_eq!(
        // SAFETY: integer-only privilege restriction.
        unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) },
        0
    );
}
fn protect() {
    limits::install_base().unwrap();
    limits::drop_capabilities().unwrap();
    nnp();
    let abi = sys::initial_filter().unwrap();
    if std::env::var_os("BINGSU_REQUIRE_LANDLOCK").is_some() {
        assert!(abi >= 3);
    }
    let installed = limits::lower_as_under_filter().unwrap();
    assert!(installed.baseline_bytes > 0);
    assert!(installed.memory_limit_bytes <= installed.baseline_bytes + limits::MEMORY_ALLOWANCE);
    sys::final_filter().unwrap();
}
fn child(case: &str) -> std::process::Output {
    let out = process::output(
        Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "runtime::kernel_child",
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .env("BINGSU_FILTER_CASE", case),
        case,
        process::PROBE_TIMEOUT,
    )
    .unwrap();
    assert!(out.status.success(), "{case}: {out:?}");
    assert!(
        String::from_utf8_lossy(&out.stdout)
            .lines()
            .any(|s| s == format!("B2 {case} PASS")),
        "probe did not run: {out:?}"
    );
    out
}
// 이것을 실패시키는 것: clone3 필터 대신 바깥 컨테이너 ENOSYS를 수용하는 것.
fn clone3_control() {
    let rc = raw(libc::SYS_clone3, [0; 6]);
    assert_eq!(rc, -1);
    let e = errno();
    if std::env::var_os("BINGSU_REQUIRE_CLONE3_CONTROL").is_some() {
        assert_eq!(
            e,
            libc::EINVAL,
            "BLOCKED: clone3 control must reach the host kernel"
        );
    } else {
        assert!(matches!(e, libc::EINVAL | libc::ENOSYS | libc::EPERM));
    }
}
fn limits_refused() {
    for resource in [
        libc::RLIMIT_CPU,
        libc::RLIMIT_NOFILE,
        libc::RLIMIT_FSIZE,
        libc::RLIMIT_AS,
    ] {
        // SAFETY: integer-only output structure.
        let mut before: libc::rlimit = unsafe { std::mem::zeroed() };
        let mut args = [
            0,
            resource as u64,
            0,
            (&mut before as *mut libc::rlimit) as u64,
            0,
            0,
        ];
        assert_eq!(raw(libc::SYS_prlimit64, args), 0);
        // Both unchanged and raised values must be refused, even to root.
        for value in [
            before,
            libc::rlimit {
                rlim_cur: before.rlim_cur + 1,
                rlim_max: before.rlim_max + 1,
            },
        ] {
            denied(
                libc::SYS_setrlimit,
                [
                    resource as u64,
                    (&value as *const libc::rlimit) as u64,
                    0,
                    0,
                    0,
                    0,
                ],
                libc::EPERM,
            );
            args[2] = (&value as *const libc::rlimit) as u64;
            denied(libc::SYS_prlimit64, args, libc::EPERM);
        }
        args[2] = 1 << 32;
        denied(libc::SYS_prlimit64, args, libc::EPERM);
        // SAFETY: integer-only output structure.
        let mut after: libc::rlimit = unsafe { std::mem::zeroed() };
        args[2] = 0;
        args[3] = (&mut after as *mut libc::rlimit) as u64;
        assert_eq!(raw(libc::SYS_prlimit64, args), 0);
        assert_eq!(
            (before.rlim_cur, before.rlim_max),
            (after.rlim_cur, after.rlim_max)
        );
    }
    denied(libc::SYS_seccomp, [1, 0, 0, 0, 0, 0], libc::EPERM);
    denied(
        libc::SYS_prctl,
        [libc::PR_SET_SECCOMP as u64, 2, 0, 0, 0, 0],
        libc::EPERM,
    );
    denied(libc::SYS_capset, [0; 6], libc::EPERM);
    denied(libc::SYS_execve, [0; 6], libc::EPERM);
    denied(libc::SYS_execveat, [0; 6], libc::EPERM);
}
fn fork_refused() {
    // SAFETY: should be rejected; an accidental child exits immediately so a
    // missing filter cannot leave processes behind or duplicate the harness.
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        // SAFETY: exit the unexpected child without running Rust destructors.
        unsafe { libc::_exit(91) };
    }
    assert_eq!(pid, -1, "libc fork unexpectedly created a process");
    assert_eq!(errno(), libc::EPERM);
    #[cfg(target_arch = "x86_64")]
    for n in [libc::SYS_fork, libc::SYS_vfork] {
        denied(n, [0; 6], libc::EPERM);
    }
    denied(
        libc::SYS_clone,
        [libc::SIGCHLD as u64, 0, 0, 0, 0, 0],
        libc::EPERM,
    );
    denied(libc::SYS_clone3, [0; 6], libc::ENOSYS);
}
// 이것을 실패시키는 것: 필터 뒤 스레드가 생성되지 않거나 자식 스레드에서 보호 우회.
#[test]
fn x14_threads_and_status_survive_fork_is_refused() {
    child("x14");
}
// 이것을 실패시키는 것: seal 생략·prlimit64 상위32 누락·root의 변경 성공.
#[test]
fn filter_installed_before_threads_and_ready() {
    let out = child("limits");
    // The privileged CI invocation also uses this bounded parent. Forward the
    // child's already-validated marker for the workflow's exact grep check.
    print!("{}", String::from_utf8(out.stdout).unwrap());
}
// 이것을 실패시키는 것: 실제 커널에서 잘못된 arch 또는 x32 호출을 살려두는 것.
#[test]
fn wrong_arch_and_x32_kill_the_child() {
    use std::os::unix::process::ExitStatusExt;
    let cases: &[&str] = if cfg!(target_arch = "x86_64") {
        &["wrong-arch", "x32", "legacy-x32"]
    } else {
        &["wrong-arch"]
    };
    for case in cases {
        let out = process::output(
            Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "runtime::kernel_child",
                    "--ignored",
                    "--nocapture",
                    "--test-threads=1",
                ])
                .env("BINGSU_FILTER_CASE", case),
            case,
            process::PROBE_TIMEOUT,
        )
        .unwrap();
        assert_eq!(out.status.signal(), Some(libc::SIGSYS), "{case}: {out:?}");
    }
}
// 이것을 실패시키는 것: Landlock 계층을 실제로 설치하지 않고 성공을 보고하는 것.
#[test]
fn landlock_kernel_denies_write_without_seccomp() {
    child("landlock");
}

#[test]
#[ignore = "only the isolated parent invokes this child, with an exact PASS marker"]
fn kernel_child() {
    let case = std::env::var("BINGSU_FILTER_CASE").unwrap();
    // libtest's "test runtime::kernel_child ... " has no trailing newline.
    // Keep every machine-readable record on its own line, including timing.
    println!();
    if std::env::var_os("BINGSU_REQUIRE_ROOT_FILTER").is_some() {
        // SAFETY: read-only identity query before the isolated protection step.
        assert_eq!(unsafe { libc::geteuid() }, 0, "BLOCKED: root required");
        let status = std::fs::read_to_string("/proc/self/status").unwrap();
        let caps = status
            .lines()
            .find_map(|s| s.strip_prefix("CapEff:\t"))
            .unwrap();
        assert_eq!(
            u64::from_str_radix(caps, 16).unwrap() & 0x1000100,
            0x1000100,
            "BLOCKED: CAP_SYS_RESOURCE and CAP_SETPCAP required"
        );
    }
    if case == "landlock" {
        let path = std::env::temp_dir().join(format!("b2-landlock-{}", std::process::id()));
        // Parent owns cleanup via a pre-opened directory? This child cannot
        // unlink after Landlock, so unlink the fixture before restricting and
        // test creation at the now-absent name instead.
        std::fs::write(&path, b"sentinel").unwrap();
        std::fs::remove_file(&path).unwrap();
        nnp();
        match landlock::install_read_only().unwrap() {
            landlock::LandlockState::Installed { .. } => {
                assert_eq!(
                    std::fs::write(&path, b"forbidden")
                        .unwrap_err()
                        .raw_os_error(),
                    Some(libc::EACCES)
                );
            }
            landlock::LandlockState::Absent => assert!(
                std::env::var_os("BINGSU_REQUIRE_LANDLOCK").is_none(),
                "BLOCKED: Landlock required"
            ),
        }
    } else if case == "timing" {
        limits::install_base().unwrap();
        limits::drop_capabilities().unwrap();
        let start = std::time::Instant::now();
        nnp();
        let after_nnp = std::time::Instant::now();
        let state = landlock::install_read_only().unwrap();
        if std::env::var_os("BINGSU_REQUIRE_LANDLOCK").is_some() {
            assert!(matches!(state, landlock::LandlockState::Installed { .. }));
        }
        let after_landlock = std::time::Instant::now();
        filter::install_bootstrap().unwrap();
        let after_initial = std::time::Instant::now();
        limits::lower_as_under_filter().unwrap();
        let before_final = std::time::Instant::now();
        filter::seal_limits().unwrap();
        let end = std::time::Instant::now();
        println!(
            "B2 timing ns {} {} {} {} {}",
            (after_nnp - start).as_nanos(),
            (after_landlock - after_nnp).as_nanos(),
            (after_initial - after_landlock).as_nanos(),
            (end - before_final).as_nanos(),
            (end - start).as_nanos()
        );
    } else if case == "wrong-arch" {
        limits::install_base().unwrap();
        nnp();
        let other = if filter::AuditArch::native() == filter::AuditArch::X86_64 {
            filter::AuditArch::Aarch64
        } else {
            filter::AuditArch::X86_64
        };
        let p = filter::program(other);
        let fp = libc::sock_fprog {
            len: p.len() as u16,
            filter: p.as_ptr().cast_mut(),
        };
        // SAFETY: the kernel copies the live BPF buffer.
        assert_eq!(unsafe { libc::syscall(libc::SYS_seccomp, 1, 0, &fp) }, 0);
        raw(libc::SYS_getpid, [0; 6]);
        panic!("wrong architecture survived");
    } else {
        if case == "x14" {
            clone3_control();
            #[cfg(target_env = "gnu")]
            {
                // SAFETY: read-only libc version query.
                let version = unsafe { libc::gnu_get_libc_version() };
                // SAFETY: libc returns a static, NUL-terminated version string.
                let v = unsafe { std::ffi::CStr::from_ptr(version) }
                    .to_str()
                    .unwrap();
                let mut parts = v.split('.').map(|s| s.parse::<u32>().unwrap());
                assert!((parts.next().unwrap(), parts.next().unwrap()) >= (2, 35));
                println!(
                    "X-14 libc=glibc version={v} arch={}",
                    std::env::consts::ARCH
                );
            }
            #[cfg(target_env = "musl")]
            println!("X-14 libc=musl arch={}", std::env::consts::ARCH);
        }
        protect();
        match case.as_str() {
            "x14" => {
                fork_refused();
                assert_eq!(
                    std::thread::spawn(|| {
                        fork_refused();
                        limits_refused();
                        42
                    })
                    .join()
                    .unwrap(),
                    42
                );
            }
            "limits" => {
                limits_refused();
                assert_eq!(
                    std::thread::spawn(|| {
                        limits_refused();
                        7
                    })
                    .join()
                    .unwrap(),
                    7
                );
            }
            "x32" => {
                raw(0x40000027, [0; 6]);
                panic!("x32 survived");
            }
            "legacy-x32" => {
                raw(512, [0; 6]);
                panic!("legacy x32 survived");
            }
            _ => panic!("unknown case"),
        }
    }
    println!("B2 {case} PASS");
    // SAFETY: this isolated subprocess must not return to the test scheduler.
    unsafe { libc::_exit(0) };
}

// 이것을 실패시키는 것: 표의 허용 행이 실제 필터에서는 거부되거나 probe가 미실행.
#[test]
fn every_table_row_reaches_the_kernel() {
    use std::os::unix::process::ExitStatusExt;
    for row in filter::rows(filter::AuditArch::native()) {
        let out = process::output(
            Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "runtime::row_child",
                    "--ignored",
                    "--nocapture",
                    "--test-threads=1",
                ])
                .env("BINGSU_ROW_PROBE", row.probe),
            row.probe,
            process::PROBE_TIMEOUT,
        )
        .unwrap();
        assert_eq!(
            String::from_utf8_lossy(&out.stdout)
                .lines()
                .filter(|line| *line == format!("B2 ROW {} ENTER", row.probe))
                .count(),
            1,
            "row not run: {out:?}"
        );
        if row.name == "rt_sigreturn" {
            assert_eq!(
                out.status.signal(),
                Some(libc::SIGSEGV),
                "{}: {out:?}",
                row.probe
            );
        } else {
            assert_eq!(out.status.code(), Some(73), "{}: {out:?}", row.probe);
        }
    }
}
#[test]
#[ignore = "one isolated subprocess per TSV row"]
fn row_child() {
    let probe = std::env::var("BINGSU_ROW_PROBE").unwrap();
    let row = filter::rows(filter::AuditArch::native())
        .into_iter()
        .find(|r| r.probe == probe)
        .unwrap();
    limits::install_base().unwrap();
    limits::drop_capabilities().unwrap();
    nnp();
    landlock::install_read_only().unwrap();
    if row.name == "exit" {
        exit_row_child(&row);
    }
    filter::install_bootstrap().unwrap();
    limits::lower_as_under_filter().unwrap();
    if !row.condition.starts_with("bootstrap_") {
        filter::seal_limits().unwrap();
    }
    println!("\nB2 ROW {} ENTER", row.probe);
    if row.name == "clone" {
        assert_eq!(std::thread::spawn(|| 11).join().unwrap(), 11);
    } else {
        let mut args = super::positive(row.condition);
        // A safe zero/invalid-argument call must reach kernel validation, not
        // get EPERM from seccomp. Terminating syscalls use an exact exit code.
        if row.name == "exit_group" {
            args[0] = 73;
        }
        if row.name == "futex" {
            args[1] = libc::FUTEX_WAKE as u64;
        }
        if row.name == "rt_sigreturn" {
            // SAFETY: reset this isolated child's SIGSEGV before a deliberately
            // malformed signal frame; no Rust handler may obscure the result.
            unsafe {
                libc::signal(libc::SIGSEGV, libc::SIG_DFL);
            }
        }
        let rc = raw(row.nr as libc::c_long, args);
        assert_ne!(row.name, "exit_group", "{} returned: {rc}", row.probe);
        if row.condition == "enosys" {
            assert_eq!((rc, errno()), (-1, libc::ENOSYS));
        } else {
            assert!(
                rc != -1 || errno() != libc::EPERM,
                "{} was refused",
                row.probe
            );
        }
    }
    // SAFETY: exact completion code proves the selected row ran.
    unsafe { libc::_exit(73) };
}

fn exit_row_child(row: &filter::Row<'_>) -> ! {
    // SYS_exit kills only its calling thread. Running it on libtest's worker
    // strands the harness waiting for a completion message. Fork BEFORE the
    // filter, then install both real BPF layers in a single-threaded child.
    // Base limits, dropped capabilities, NNP and Landlock are inherited.
    // Prepare all allocation/formatting before fork; the child uses only raw
    // syscalls and _exit, never Rust locks, allocation or unwinding.
    let bootstrap = filter::bootstrap_program(filter::AuditArch::native());
    let final_filter = filter::program(filter::AuditArch::native());
    let programs = [&bootstrap, &final_filter].map(|p| libc::sock_fprog {
        len: p.len() as u16,
        filter: p.as_ptr().cast_mut(),
    });
    let marker = format!("\nB2 ROW {} ENTER\n", row.probe);
    // SAFETY: the child only uses prebuilt buffers and async-signal-safe calls.
    let pid = unsafe { libc::fork() };
    assert!(
        pid >= 0,
        "{}: fork: {}",
        row.probe,
        io::Error::last_os_error()
    );
    if pid == 0 {
        for program in &programs {
            if raw(
                libc::SYS_seccomp,
                [1, 0, (program as *const libc::sock_fprog) as u64, 0, 0, 0],
            ) != 0
            {
                // SAFETY: terminate this isolated child without destructors.
                unsafe { libc::_exit(90) };
            }
        }
        if raw(
            libc::SYS_write,
            [1, marker.as_ptr() as u64, marker.len() as u64, 0, 0, 0],
        ) == marker.len() as libc::c_long
        {
            raw(row.nr as libc::c_long, [73, 0, 0, 0, 0, 0]);
        }
        // A returning/denied SYS_exit must never masquerade as exit code 73.
        // SAFETY: terminate this isolated child without destructors.
        unsafe { libc::_exit(91) };
    }
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    let mut status = 0;
    loop {
        // SAFETY: exclusively owned child and valid status storage.
        let rc = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
        if rc == pid {
            assert!(libc::WIFEXITED(status), "{}: status {status}", row.probe);
            assert_eq!(libc::WEXITSTATUS(status), 73, "{}", row.probe);
            // SAFETY: propagate the verified syscall's exit code to our parent.
            unsafe { libc::_exit(73) };
        }
        let error = (rc == -1).then(io::Error::last_os_error);
        if error
            .as_ref()
            .is_some_and(|e| e.kind() != io::ErrorKind::Interrupted)
            || std::time::Instant::now() >= deadline
        {
            // SAFETY: kill our own still-unreaped child before reporting failure.
            unsafe { libc::kill(pid, libc::SIGKILL) };
            loop {
                // SAFETY: reap the killed child; retry only interrupted waits.
                if unsafe { libc::waitpid(pid, &mut status, 0) } != -1
                    || io::Error::last_os_error().kind() != io::ErrorKind::Interrupted
                {
                    break;
                }
            }
            panic!(
                "{}: child {pid} timed out after 5s or waitpid failed: {error:?}; killed and reaped",
                row.probe
            );
        }
        std::thread::sleep(std::time::Duration::from_millis(2));
    }
}

// 이것을 실패시키는 것: FSIZE 0을 쓰기 차단으로 오인하거나 X-16 한 행을 실행하지 않는 것.
#[test]
fn x16_all_mutations_are_denied_with_fsize_zero() {
    use std::{io::Read, os::unix::fs::MetadataExt};
    let dir = std::env::temp_dir().join(format!("b2-x16-{}", std::process::id()));
    std::fs::create_dir(&dir).unwrap();
    let sentinel = dir.join("sentinel");
    std::fs::write(&sentinel, b"unchanged sentinel\n").unwrap();
    std::fs::write(
        dir.join("control"),
        b"FSIZE alone does not prevent truncation",
    )
    .unwrap();
    let before = std::fs::metadata(&sentinel).unwrap();
    let program = filter::program(filter::AuditArch::native());
    let bytes: Vec<_> = program
        .iter()
        .flat_map(|i| {
            let mut b = Vec::from(i.code.to_ne_bytes());
            b.push(i.jt);
            b.push(i.jf);
            b.extend(i.k.to_ne_bytes());
            b
        })
        .collect();
    std::fs::write(dir.join("filter.bpf"), bytes).unwrap();
    let source = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../bench/probes/x16-write-denial.c");
    let cc = std::env::var("CC").unwrap_or_else(|_| "cc".into());
    let compiled = process::output(
        Command::new(cc)
            .args(["-std=c11", "-Wall", "-Wextra", "-Werror", "-O2"])
            // musl-gcc leaves out the kernel UAPI headers; CI passes them here.
            .args(
                std::env::var("BINGSU_X16_CFLAGS")
                    .unwrap_or_default()
                    .split_whitespace(),
            )
            .arg(source)
            .arg("-o")
            .arg(dir.join("probe")),
        "X-16 compiler",
        std::time::Duration::from_secs(30),
    )
    .unwrap();
    assert!(compiled.status.success(), "X-16 compiler: {compiled:?}");
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let out = process::output(
        Command::new(dir.join("probe"))
            .arg(&dir)
            .arg(listener.local_addr().unwrap().port().to_string()),
        "X-16 probe",
        process::PROBE_TIMEOUT,
    )
    .unwrap();
    assert!(out.status.success(), "{out:?}");
    let text = String::from_utf8(out.stdout).unwrap();
    for cell in [
        "O_RDONLY|O_TRUNC",
        "O_WRONLY|O_TRUNC",
        "unlink",
        "rename",
        "socket",
        "connect",
    ] {
        assert_eq!(
            text.lines()
                .filter(|line| *line == format!("X-16 {cell} EPERM unchanged"))
                .count(),
            1,
            "{text}"
        );
    }
    assert!(
        text.lines()
            .any(|line| line == "X-16 PASS cells=6 fsize=0 control_truncated=1")
    );
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
    let mut data = Vec::new();
    std::fs::File::open(&sentinel)
        .unwrap()
        .read_to_end(&mut data)
        .unwrap();
    assert_eq!(data, b"unchanged sentinel\n");
    let after = std::fs::metadata(&sentinel).unwrap();
    assert_eq!(
        (before.dev(), before.ino(), before.nlink()),
        (after.dev(), after.ino(), after.nlink())
    );
    assert!(!dir.join("renamed").exists());
    assert_eq!(std::fs::metadata(dir.join("control")).unwrap().len(), 0);
    std::fs::remove_dir_all(dir).unwrap();
    // Forward validated raw probe records to the standalone acceptance ledger.
    println!("\n{text}");
}

// 이것을 실패시키는 것: 설치 비용의 필수 200개 표본을 누락하거나 일부 단계 측정 생략.
#[test]
fn protection_installation_cost_has_200_samples() {
    let mut columns: [Vec<u128>; 5] = std::array::from_fn(|_| Vec::new());
    for _ in 0..200 {
        let out = child("timing");
        let text = String::from_utf8(out.stdout).unwrap();
        let lines: Vec<_> = text
            .lines()
            .filter_map(|s| s.strip_prefix("B2 timing ns "))
            .collect();
        assert_eq!(lines.len(), 1);
        let values: Vec<u128> = lines[0]
            .split_whitespace()
            .map(|n| n.parse().unwrap())
            .collect();
        assert_eq!(values.len(), 5);
        assert!(values.iter().all(|n| *n > 0));
        assert!(values[4] >= values[..4].iter().sum::<u128>());
        for (col, value) in columns.iter_mut().zip(values) {
            col.push(value);
        }
    }
    for (name, mut col) in ["nnp", "landlock", "initial_filter", "final_filter", "total"]
        .into_iter()
        .zip(columns)
    {
        assert_eq!(col.len(), 200);
        col.sort();
        println!(
            "B2 install_ns {name} samples=200 median={} p95={}",
            col[99], col[189]
        );
    }
}
