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
        filter::install_bootstrap(filter::Openat2Policy::Deny).unwrap();
        let after_initial = std::time::Instant::now();
        limits::lower_as_under_filter().unwrap();
        let before_final = std::time::Instant::now();
        filter::seal_limits(filter::Openat2Policy::Deny).unwrap();
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
        let p = filter::program(other, filter::Openat2Policy::Deny);
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
    let state = landlock::install_read_only().unwrap();
    let mode = if state.covers_openat2_writes() {
        filter::Openat2Policy::WriteSetCovered
    } else {
        filter::Openat2Policy::Deny
    };
    if row.name == "openat2" {
        assert!(state.covers_openat2_writes(), "BLOCKED: TRUNCATE required");
    }
    if row.name == "exit" {
        exit_row_child(&row);
    }
    filter::install_bootstrap(mode).unwrap();
    limits::lower_as_under_filter().unwrap();
    if !row.condition.starts_with("bootstrap_") {
        filter::seal_limits(mode).unwrap();
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
    let bootstrap =
        filter::bootstrap_program(filter::AuditArch::native(), filter::Openat2Policy::Deny);
    let final_filter = filter::program(filter::AuditArch::native(), filter::Openat2Policy::Deny);
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
    let program = filter::program(filter::AuditArch::native(), filter::Openat2Policy::Deny);
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
    // Inspect the actual C ELF, not just Cargo's Rust target name. Static or
    // unidentified linkage is deliberately insufficient for this experiment.
    let elf = process::output(
        Command::new("readelf").args(["-lW"]).arg(dir.join("probe")),
        "X-16 C linkage",
        std::time::Duration::from_secs(30),
    )
    .unwrap();
    assert!(elf.status.success(), "X-16 readelf: {elf:?}");
    let elf_text = String::from_utf8(elf.stdout).unwrap();
    let loader = elf_text
        .lines()
        .find_map(|line| {
            line.trim()
                .strip_prefix("[Requesting program interpreter: ")
        })
        .and_then(|line| line.strip_suffix(']'))
        .expect("X-16 needs an identifiable dynamic C ELF interpreter");
    let musl = loader.contains("/ld-musl-") && loader.ends_with(".so.1");
    assert_eq!(
        musl,
        cfg!(target_env = "musl"),
        "X-16 C/Rust libc mismatch: {loader}"
    );
    assert!(
        musl || loader.contains("/ld-linux"),
        "unknown C libc: {loader}"
    );
    let cc = std::env::var("CC").unwrap_or_else(|_| "cc".into());
    let version = process::output(
        Command::new(&cc).arg("--version"),
        "X-16 compiler identity",
        std::time::Duration::from_secs(30),
    )
    .unwrap();
    assert!(version.status.success());
    let version = String::from_utf8(version.stdout).unwrap();
    println!("\nX-16 compiler={cc}: {}", version.lines().next().unwrap());
    println!(
        "X-16 cflags=-std=c11 -Wall -Wextra -Werror -O2 {}",
        std::env::var("BINGSU_X16_CFLAGS").unwrap_or_default()
    );
    println!("X-16 elf_interpreter={loader}");
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

fn repository_case(case: &str) -> String {
    use std::io::{BufRead, Write};
    let name = format!("b3-{}-{case}", std::process::id());
    let dir = if matches!(case, "covered" | "missing-truncate" | "absent") {
        super::tmpfile::select(
            &name,
            std::env::temp_dir(),
            std::env::var_os("BINGSU_B3_TMPDIR").map(std::path::PathBuf::from),
            |directory| {
                use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
                std::fs::DirBuilder::new().mode(0o700).create(directory)?;
                let result = std::fs::OpenOptions::new()
                    .read(true)
                    .write(true)
                    .mode(0o600)
                    .custom_flags(libc::O_TMPFILE | libc::O_CLOEXEC)
                    .open(directory)
                    .map(drop);
                if result.is_err() {
                    std::fs::remove_dir(directory)?;
                }
                result
            },
        )
        .unwrap_or_else(|error| panic!("{error}"))
    } else {
        std::env::temp_dir().join(name)
    };
    std::fs::create_dir_all(dir.join("worktree/a")).unwrap();
    for name in ["gitdir", "commondir", "outside", "home"] {
        std::fs::create_dir(dir.join(name)).unwrap();
        std::fs::write(dir.join(name).join("HEAD"), b"sentinel").unwrap();
    }
    std::fs::write(dir.join("worktree/HEAD"), b"sentinel").unwrap();
    std::fs::write(dir.join("worktree/a/leaf"), b"EXTERNAL").unwrap();
    std::os::unix::fs::symlink("../outside/HEAD", dir.join("worktree/escape")).unwrap();
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args([
            "--exact",
            "runtime::repository_child",
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("BINGSU_B3_CASE", case)
        .env("BINGSU_B3_PATH", &dir)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped());
    let mut child = command.spawn().unwrap();
    let mut input = child.stdin.take().unwrap();
    let mut output = std::io::BufReader::new(child.stdout.take().unwrap());
    let mut report = String::new();
    loop {
        let mut line = String::new();
        if output.read_line(&mut line).unwrap() == 0 {
            break;
        }
        if line.trim() == "B3 MOVE" {
            std::fs::rename(dir.join("worktree/a"), dir.join("outside/a")).unwrap();
            input.write_all(b"x").unwrap();
        }
        report.push_str(&line);
    }
    let status = child.wait().unwrap();
    let sentinel = std::fs::read(dir.join("worktree/HEAD")).unwrap();
    std::fs::remove_dir_all(&dir).unwrap();
    assert!(status.success(), "{case}: {report}");
    assert_eq!(sentinel, b"sentinel");
    assert!(
        report.lines().any(|l| l == format!("B3 {case} PASS")),
        "{report}"
    );
    report
}

// 이것을 실패시키는 것: 쓰기 집합 검사/설치를 없애거나 TRUNCATE 누락에도 openat2를 허용하는 것.
#[test]
fn openat2_never_bypasses_write_denial() {
    for case in ["covered", "missing-truncate", "absent"] {
        print!("{}", repository_case(case));
    }
}
// 이것을 실패시키는 것: read layer 설치를 생략하거나 부모 root를 규칙에 더하는 것.
#[test]
fn read_landlock_grants_only_selected_roots() {
    repository_case("roots");
    repository_case("duplicate");
}
// 이것을 실패시키는 것: probe를 read layer 뒤로 옮겨 EACCES를 OnceLock에 저장하는 것.
#[test]
fn openat2_probe_precedes_read_layer() {
    repository_case("ordered");
    repository_case("reversed");
}
// 이것을 실패시키는 것: 개별 파일 EPERM 뒤 backend를 다시 탐침하는 것.
#[test]
fn resolver_is_selected_once_per_process() {
    repository_case("once");
}
// 이것을 실패시키는 것: mount identity가 없어도 Ready/수집을 허용하는 것.
#[test]
fn linux_collection_floor_requires_capabilities() {
    for case in ["no-mount", "no-pidfd", "no-close-range"] {
        repository_case(case);
    }
}

#[test]
#[ignore = "isolated irreversible B3 child, invoked by its parent"]
fn repository_child() {
    use crate::{
        meter::Meter,
        safe_read::{self, Access, DiscoveryQuery, ReadCap, ReadError, Resolver},
    };
    use std::{
        fs::File,
        os::{
            fd::{AsFd, AsRawFd},
            unix::ffi::OsStrExt,
        },
        time::{Duration, Instant},
    };
    let case = std::env::var("BINGSU_B3_CASE").unwrap();
    let dir = std::path::PathBuf::from(std::env::var_os("BINGSU_B3_PATH").unwrap());
    // Bound failed mutations too; the parent never waits indefinitely.
    // SAFETY: process-local alarm; no signal handler is installed for SIGALRM.
    unsafe { libc::alarm(10) };
    let mut meter = Meter::new(Instant::now() + Duration::from_secs(5));
    if case.starts_with("no-") {
        // Refuse exactly one real prerequisite before the normal startup path.
        let nr = match case.as_str() {
            "no-mount" => libc::SYS_statx,
            "no-pidfd" => libc::SYS_pidfd_open,
            _ => libc::SYS_close_range,
        };
        nnp();
        let mut p = [
            libc::sock_filter {
                code: 0x20,
                jt: 0,
                jf: 0,
                k: 0,
            },
            libc::sock_filter {
                code: 0x15,
                jt: 0,
                jf: 1,
                k: nr as u32,
            },
            libc::sock_filter {
                code: 0x06,
                jt: 0,
                jf: 0,
                k: filter::DENY,
            },
            libc::sock_filter {
                code: 0x06,
                jt: 0,
                jf: 0,
                k: filter::ALLOW,
            },
        ];
        let program = libc::sock_fprog {
            len: p.len() as u16,
            filter: p.as_mut_ptr(),
        };
        assert_eq!(
            raw(
                libc::SYS_seccomp,
                [1, 0, &program as *const _ as u64, 0, 0, 0]
            ),
            0
        );
        if case == "no-mount" {
            protect();
            assert!(matches!(Access::probe(&mut meter), Err(ReadError::Denied)));
        } else {
            assert!(sys::required_features_for_test().is_err());
        }
    } else if matches!(case.as_str(), "covered" | "missing-truncate" | "absent") {
        let directory = File::open(dir.join("worktree")).unwrap();
        // Positive O_TMPFILE control: filesystem support, independent of FSIZE.
        // SAFETY: zero-initialized UAPI input record, including reserved bits.
        let mut how: libc::open_how = unsafe { std::mem::zeroed() };
        how.flags = (libc::O_TMPFILE | libc::O_RDWR | libc::O_CLOEXEC) as u64;
        how.mode = 0o600;
        let tmp = raw(
            libc::SYS_openat2,
            [
                directory.as_raw_fd() as u64,
                c".".as_ptr() as u64,
                &how as *const _ as u64,
                24,
                0,
                0,
            ],
        );
        assert!(
            tmp >= 0,
            "BLOCKED: selected test filesystem {} failed the pre-filter openat2 O_TMPFILE control: {}",
            dir.display(),
            errno()
        );
        // SAFETY: fresh positive-control descriptor.
        unsafe { libc::close(tmp as i32) };
        limits::install_base().unwrap();
        nnp();
        let state = match case.as_str() {
            "absent" => landlock::LandlockState::Absent,
            "missing-truncate" => landlock::install_without_truncate_for_test().unwrap(),
            _ => landlock::install_read_only().unwrap(),
        };
        if case != "absent" {
            assert!(
                matches!(state, landlock::LandlockState::Installed { abi: 3.., .. }),
                "BLOCKED: ABI3 required"
            );
        }
        let mode = if state.covers_openat2_writes() {
            filter::Openat2Policy::WriteSetCovered
        } else {
            filter::Openat2Policy::Deny
        };
        filter::install_bootstrap(mode).unwrap();
        limits::lower_as_under_filter().unwrap();
        filter::seal_limits(mode).unwrap();
        let selected = safe_read::resolver(&mut meter).unwrap();
        assert_eq!(
            selected,
            if case == "covered" {
                Resolver::Openat2
            } else {
                Resolver::Stepwise
            }
        );
        println!("B3 write_state {state:?} resolver={selected:?}");
        if case == "covered" {
            how.flags = libc::O_RDONLY as u64;
            how.mode = 0;
            let file = raw(
                libc::SYS_openat2,
                [
                    directory.as_raw_fd() as u64,
                    c"HEAD".as_ptr() as u64,
                    &how as *const _ as u64,
                    24,
                    0,
                    0,
                ],
            );
            assert!(file >= 0);
            let mut bytes = [0u8; 8];
            assert_eq!(
                raw(
                    libc::SYS_read,
                    [file as u64, bytes.as_mut_ptr() as u64, 8, 0, 0, 0]
                ),
                8
            );
            assert_eq!(&bytes, b"sentinel");
            // SAFETY: newly opened positive-control fd.
            unsafe { libc::close(file as i32) };
        }
        // 이것을 실패시키는 것: write layer 설치 제거. TMPFILE을 먼저 검사해
        // TRUNCATE 실패가 이 단언을 가리지 않으며 FSIZE=0만으로는 통과 못 한다.
        for (flags, path, mode) in [
            (libc::O_TMPFILE | libc::O_RDWR, c".", 0o600),
            (libc::O_TRUNC, c"HEAD", 0),
            (libc::O_CREAT | libc::O_WRONLY, c"created", 0o600),
        ] {
            how.flags = (flags | libc::O_CLOEXEC) as u64;
            how.mode = mode;
            denied(
                libc::SYS_openat2,
                [
                    directory.as_raw_fd() as u64,
                    path.as_ptr() as u64,
                    &how as *const _ as u64,
                    24,
                    0,
                    0,
                ],
                if case == "covered" {
                    libc::EACCES
                } else {
                    libc::EPERM
                },
            );
        }
        assert_eq!(
            std::fs::read(dir.join("worktree/HEAD")).unwrap(),
            b"sentinel"
        );
    } else {
        protect();
        let mut roots = Vec::new();
        for name in ["worktree", "gitdir", "commondir"] {
            roots.push(
                safe_read::acquire(
                    dir.join(name).as_os_str().as_bytes(),
                    DiscoveryQuery::default(),
                    &mut meter,
                )
                .unwrap()
                .select_cwd()
                .unwrap(),
            );
        }
        let root_fds: Vec<_> = roots.iter().map(|r| r.read_rule_fd()).collect();
        let cap = ReadCap {
            bytes: 64,
            single_link: true,
        };
        if case == "trace" || case == "trace-stepwise" {
            println!("\nB3_PHASE probe");
            let mut access = Access::probe(&mut meter).unwrap();
            println!("B3_PHASE end");
            if case == "trace-stepwise" {
                access = Access::stage_a_only();
            }
            println!("B3_PHASE read-layer");
            access
                .restrict_to(&roots.iter().collect::<Vec<_>>(), &mut meter)
                .unwrap();
            println!("B3_PHASE end");
            println!("B3_PHASE content");
            assert_eq!(
                safe_read::read(&roots[0], b"HEAD", cap, &access, &mut meter).unwrap(),
                b"sentinel"
            );
            assert_eq!(roots[0].readonly(&mut meter).unwrap(), Some(false));
            println!("B3_PHASE end");
        } else if case == "reversed" {
            landlock::restrict_reads(&root_fds).unwrap();
            assert!(matches!(Access::probe(&mut meter), Err(ReadError::Denied)));
            let before = meter.counts;
            assert!(matches!(Access::probe(&mut meter), Err(ReadError::Denied)));
            assert_eq!(meter.counts, before); // the cached EACCES would block stage A
        } else if case == "ordered" {
            let mut access = Access::stage_a_only();
            access
                .restrict_to(&roots.iter().collect::<Vec<_>>(), &mut meter)
                .unwrap();
            Access::probe(&mut meter).unwrap(); // root probe was cached before confinement
            assert_eq!(
                safe_read::read(&roots[0], b"HEAD", cap, &access, &mut meter).unwrap(),
                b"sentinel"
            );
        } else if case == "once" {
            let choice = safe_read::ResolverChoice::default();
            let access = Access::probe_with(&choice, &mut meter).unwrap();
            meter.openat2_errors.push_back(libc::EPERM);
            assert_eq!(
                safe_read::read(&roots[0], b"HEAD", cap, &access, &mut meter),
                Err(ReadError::Denied)
            );
            let before = meter.counts;
            assert_eq!(choice.get(&mut meter), Ok(Resolver::Openat2));
            assert_eq!(meter.counts, before);
        } else {
            let slash = File::open("/").unwrap();
            assert!(landlock::restrict_reads(&[slash.as_fd()]).is_err());
            assert!(landlock::restrict_reads(&[]).is_err());
            assert!(landlock::restrict_reads(&[root_fds[0]; 4]).is_err());
            let held = File::open(dir.join("worktree/a")).unwrap();
            let mut access = Access::probe(&mut meter).unwrap();
            let start = Instant::now();
            let proof = if case == "duplicate" {
                landlock::restrict_reads(&[root_fds[0], root_fds[0]]).unwrap()
            } else {
                landlock::restrict_reads(&root_fds).unwrap()
            };
            let elapsed = start.elapsed().as_nanos();
            assert_eq!(proof.rule_count(), if case == "duplicate" { 1 } else { 3 });
            access.landlock_reads_installed(proof);
            for root in roots.iter().take(if case == "duplicate" { 1 } else { 3 }) {
                assert_eq!(
                    safe_read::read(root, b"HEAD", cap, &access, &mut meter).unwrap(),
                    b"sentinel"
                );
            }
            for name in ["outside", "home"] {
                assert_eq!(
                    File::open(dir.join(name).join("HEAD"))
                        .unwrap_err()
                        .raw_os_error(),
                    Some(libc::EACCES)
                );
            }
            assert!(safe_read::read(&roots[0], b"escape", cap, &access, &mut meter).is_err());
            if case == "duplicate" {
                assert_eq!(
                    File::open(dir.join("gitdir/HEAD"))
                        .unwrap_err()
                        .raw_os_error(),
                    Some(libc::EACCES)
                );
            }
            println!("\nB3 MOVE");
            let mut ack = [0u8];
            assert_eq!(
                raw(libc::SYS_read, [0, ack.as_mut_ptr() as u64, 1, 0, 0, 0]),
                1
            );
            denied(
                libc::SYS_openat,
                [
                    held.as_raw_fd() as u64,
                    c"leaf".as_ptr() as u64,
                    (libc::O_RDONLY | libc::O_CLOEXEC) as u64,
                    0,
                    0,
                    0,
                ],
                libc::EACCES,
            );
            println!("B3 read_layer_ns {elapsed} external_reads=0");
        }
    }
    println!("\nB3 {case} PASS");
    // SAFETY: terminate the isolated child without returning to libtest.
    unsafe { libc::_exit(0) };
}

// 이것을 실패시키는 것: fixture에서 read/map/query를 더 하거나 단계 경계를 섞는 것.
#[test]
fn repository_trace_has_exact_effects() {
    for case in ["trace", "trace-stepwise"] {
        print!("{}", repository_case(case));
    }
}

// 이것을 실패시키는 것: read ruleset 비용 표본을 누락하거나 설치를 생략하는 것.
#[test]
fn repository_read_layer_cost_has_200_samples() {
    let mut samples = Vec::new();
    for _ in 0..=199 {
        let report = repository_case("roots");
        let value: u128 = report
            .lines()
            .find_map(|l| l.strip_prefix("B3 read_layer_ns "))
            .unwrap()
            .split_whitespace()
            .next()
            .unwrap()
            .parse()
            .unwrap();
        assert!(value > 0);
        println!("B3 raw_read_layer_ns {value}");
        samples.push(value);
    }
    assert_eq!(samples.len(), 200);
    samples.sort();
    let mean = samples.iter().sum::<u128>() as f64 / 200.0;
    let variance = samples
        .iter()
        .map(|n| (*n as f64 - mean).powi(2))
        .sum::<f64>()
        / 200.0;
    println!(
        "B3 read_layer_ns samples=200 p50={} p95={} variance={variance}",
        samples[99], samples[189]
    );
}
