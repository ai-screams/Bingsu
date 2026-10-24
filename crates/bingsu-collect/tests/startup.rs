//! Irreversible checks run only in isolated, single-threaded child processes.
#![cfg(unix)]
#[allow(dead_code)]
#[path = "../src/git/mod.rs"]
mod git;
#[allow(dead_code)]
#[path = "../src/update_sink.rs"]
mod update_sink;
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd},
        unix::{
            fs::PermissionsExt,
            process::{CommandExt, ExitStatusExt},
        },
    },
    path::PathBuf,
    process::{Command, Stdio},
};
// Include the same implementation in this test-only target, allowing failure
// injection and a fixture entry without a shipped feature or public test API.
#[cfg(target_os = "linux")]
#[allow(dead_code)]
#[path = "../src/filter.rs"]
mod filter;
#[cfg(target_os = "linux")]
#[allow(dead_code)]
#[path = "../src/landlock.rs"]
mod landlock;
#[allow(dead_code)]
#[path = "../src/limits.rs"]
mod limits;
#[allow(dead_code)]
#[path = "../src/meter.rs"]
mod meter;
#[allow(dead_code)]
#[path = "../src/safe_read/mod.rs"]
mod safe_read;
#[allow(dead_code)]
#[path = "../src/sys.rs"]
mod sys;
#[allow(dead_code)]
#[path = "../src/worker.rs"]
mod worker;
pub use bingsu_identity::build_id;

fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_bingsu-collect")
}
fn pipe() -> (OwnedFd, OwnedFd) {
    let mut fds = [0; 2];
    // SAFETY: pipe writes two descriptors to valid storage.
    assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
    // SAFETY: both descriptors are new and transferred exactly once.
    (unsafe { OwnedFd::from_raw_fd(fds[0]) }, unsafe {
        OwnedFd::from_raw_fd(fds[1])
    })
}
struct Fixture {
    path: PathBuf,
    lock: File,
    read: OwnedFd,
    write: OwnedFd,
}
impl Fixture {
    fn new(tag: &str) -> Self {
        let path =
            std::env::temp_dir().join(format!("collector-startup-{tag}-{}", std::process::id()));
        let lock = OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        lock.set_permissions(fs::Permissions::from_mode(0o600))
            .unwrap();
        #[cfg(target_os = "linux")]
        let lock = File::open(&path).unwrap();
        let (read, write) = pipe();
        Self {
            path,
            lock,
            read,
            write,
        }
    }
    fn prepare(&self, command: &mut Command, high: bool) {
        command
            .env_clear()
            .current_dir("/")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        let inherited_lock = &self.lock;
        // Copies outside reserved slots avoid pre_exec's dup2 clobbering sources.
        let copies: Vec<_> = [self.read.as_raw_fd(), inherited_lock.as_raw_fd()]
            .iter()
            .map(|fd| {
                // SAFETY: live fd, owned duplicate above destination slots.
                let copy = unsafe { libc::fcntl(*fd, libc::F_DUPFD_CLOEXEC, 10) };
                assert!(copy >= 10);
                // SAFETY: duplicate is newly owned.
                unsafe { OwnedFd::from_raw_fd(copy) }
            })
            .collect();
        let setup = move || {
            for (source, target) in copies.iter().zip([3, 5]) {
                // SAFETY: live duplicate and reserved child-only destination.
                if unsafe { libc::dup2(source.as_raw_fd(), target) } < 0 {
                    return Err(std::io::Error::last_os_error());
                }
            }
            // SAFETY: create a deliberately inheritable high child descriptor.
            if high && unsafe { libc::fcntl(5, libc::F_DUPFD, 1025) } < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        };
        // SAFETY: setup uses only async-signal-safe descriptor operations.
        unsafe {
            command.pre_exec(setup);
        }
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_file(&self.path).unwrap();
    }
}

// 이것을 실패시키는 것: 제품 entry가 측정 옵션·인자 누락·추가를 받아들이는 것.
#[test]
fn dedicated_entry_refuses_stub_and_unknown_arguments() {
    for args in [
        vec![],
        vec!["--mode", "bare"],
        vec!["--mode", "sandbox"],
        vec!["__collect-v1", "--probe-exec"],
        vec!["__collect-v1", "extra"],
        vec!["__collect-stub"],
        vec!["__collect-legacy-v1"],
    ] {
        let out = Command::new(binary()).args(args).output().unwrap();
        assert_eq!(out.status.code(), Some(2));
        assert!(out.stdout.is_empty() && out.stderr.is_empty());
    }
    assert_eq!(
        Command::new(binary())
            .arg("__collect-v1")
            .output()
            .unwrap()
            .status
            .code(),
        Some(1)
    );
}

// 이것을 실패시키는 것: 일반 파일 stdout 또는 보호 실패 뒤 Ready/요청 읽기를 허용하는 것.
#[test]
fn protection_failure_never_consumes_request() {
    let fixture = Fixture::new("failure");
    let mut writer = File::from(fixture.write.try_clone().unwrap());
    writer.write_all(&[b'x'; 80]).unwrap();
    let mut command = Command::new(binary());
    fixture.prepare(&mut command, false);
    command.arg("__collect-v1").stdout(Stdio::null());
    let out = command.output().unwrap();
    assert!(!out.status.success());
    assert!(out.stdout.is_empty());
    let mut left = [0u8; 80];
    assert_eq!(
        // SAFETY: child has exited; make a failed mutation report an error, not hang.
        unsafe { libc::fcntl(fixture.read.as_raw_fd(), libc::F_SETFL, libc::O_NONBLOCK) },
        0
    );
    File::from(fixture.read.try_clone().unwrap())
        .read_exact(&mut left)
        .unwrap();
    assert_eq!(&left, &[b'x'; 80]);
}

fn child(name: &str) -> std::process::Output {
    Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            name,
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .output()
        .unwrap()
}

fn assert_one_passed(out: &std::process::Output) {
    assert!(
        out.status.success()
            && String::from_utf8_lossy(&out.stdout).contains("test result: ok. 1 passed;"),
        "{out:?}"
    );
}
// 이것을 실패시키는 것: 기본 한도 중 하나를 생략하거나 상속 soft/hard를 올리는 것.
#[test]
fn limits_are_irreversible_and_owned_by_worker() {
    // SAFETY: output storage for read-only parent limit snapshot.
    let mut before: libc::rlimit = unsafe { std::mem::zeroed() };
    // SAFETY: valid resource and storage.
    assert_eq!(
        // SAFETY: valid resource and writable output storage.
        unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut before) },
        0
    );
    let out = child("base_limits_child");
    assert_one_passed(&out);
    // SAFETY: output storage for read-only parent limit snapshot.
    let mut after: libc::rlimit = unsafe { std::mem::zeroed() };
    // SAFETY: valid resource and storage.
    assert_eq!(
        // SAFETY: valid resource and writable output storage.
        unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut after) },
        0
    );
    assert_eq!(
        (before.rlim_cur, before.rlim_max),
        (after.rlim_cur, after.rlim_max)
    );
}
#[test]
#[ignore = "invoked by limits_are_irreversible_and_owned_by_worker"]
fn base_limits_child() {
    let low = libc::rlimit {
        rlim_cur: 16,
        rlim_max: 32,
    };
    // SAFETY: isolated child only, lowers its inherited NOFILE limits.
    assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &low) }, 0);
    limits::install_base().unwrap();
    limits::drop_capabilities().unwrap();
    for (resource, soft, hard) in [
        (libc::RLIMIT_CPU, 1, 1),
        (libc::RLIMIT_NOFILE, 16, 32),
        (libc::RLIMIT_FSIZE, 0, 0),
        (libc::RLIMIT_CORE, 0, 0),
    ] {
        // SAFETY: integer-only writable rlimit.
        let mut got: libc::rlimit = unsafe { std::mem::zeroed() };
        // SAFETY: valid resource and storage.
        assert_eq!(unsafe { libc::getrlimit(resource, &mut got) }, 0);
        assert_eq!((got.rlim_cur, got.rlim_max), (soft, hard));
        let higher = libc::rlimit {
            rlim_cur: soft + 1,
            rlim_max: hard + 1,
        };
        // SAFETY: isolated child attempts to restore its own hard limit.
        assert_eq!(unsafe { libc::setrlimit(resource, &higher) }, -1);
    }
}

// 이것을 실패시키는 것: 실제 CPU 1초 제한 또는 fd64 상한을 제거하는 것.
#[test]
fn worker_limits_fail_without_blocking_front() {
    #[cfg(target_os = "linux")]
    {
        let memory = child("as_limit_child");
        assert_one_passed(&memory);
    }
    let fd = child("fd_ceiling_child");
    assert_one_passed(&fd);
    let cpu = child("cpu_limit_child");
    assert!(
        matches!(cpu.status.signal(), Some(libc::SIGKILL | libc::SIGXCPU)),
        "{:?}",
        cpu
    );
}
// 이것을 실패시키는 것: AS 하강을 생략해 허용량보다 큰 실제 매핑을 허용하는 것.
// This probes the limit primitive only, without Ready or collection. B2 owns
// the separate assertion that the same primitive runs between both filters.
#[test]
#[cfg(target_os = "linux")]
#[ignore = "invoked by worker_limits_fail_without_blocking_front"]
fn as_limit_child() {
    limits::install_base().unwrap();
    limits::drop_capabilities().unwrap();
    sys::no_new_privs().unwrap();
    let installed = limits::lower_as_under_filter().unwrap();
    assert!(installed.memory_limit_bytes <= installed.baseline_bytes + limits::MEMORY_ALLOWANCE);
    // SAFETY: anonymous private mapping, no fixed address or aliased Rust data.
    let allocation = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            (limits::MEMORY_ALLOWANCE * 2) as usize,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    assert_eq!(allocation, libc::MAP_FAILED);
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::ENOMEM)
    );
}
#[test]
#[ignore = "invoked by worker_limits_fail_without_blocking_front"]
fn fd_ceiling_child() {
    limits::install_base().unwrap();
    let mut files = Vec::new();
    loop {
        match File::open("/dev/null") {
            Ok(file) => {
                assert!(file.as_raw_fd() < 64);
                files.push(file);
            }
            Err(error) => {
                assert_eq!(error.raw_os_error(), Some(libc::EMFILE));
                break;
            }
        }
    }
    assert!(!files.is_empty());
}
#[test]
#[ignore = "invoked by worker_limits_fail_without_blocking_front"]
fn cpu_limit_child() {
    limits::install_base().unwrap();
    loop {
        std::hint::black_box(1u64.wrapping_add(1));
    }
}

// 이것을 실패시키는 것: 높은 fd·fd4를 남기거나 lock을 LOCK_UN으로 놓는 것.
#[test]
fn worker_fd_contract_has_no_shell_or_authority_fds() {
    let fixture = Fixture::new("fds");
    // SAFETY: exclusively lock this fixture's descriptor.
    assert_eq!(
        // SAFETY: live fixture descriptor and nonblocking lock operation.
        unsafe { libc::flock(fixture.lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
        0
    );
    let mut command = Command::new(std::env::current_exe().unwrap());
    fixture.prepare(&mut command, true);
    command.args([
        "--exact",
        "fd_contract_child",
        "--ignored",
        "--nocapture",
        "--test-threads=1",
    ]);
    let out = command.output().unwrap();
    // The worker owns stdout and closes it before libtest can print a summary.
    assert!(
        out.status.success()
            && out
                .stdout
                .windows(b"fd_contract_child: passed".len())
                .any(|word| word == b"fd_contract_child: passed"),
        "{out:?}"
    );
    let competing = File::open(&fixture.path).unwrap();
    // SAFETY: separate description must still be excluded by the parent lock.
    assert_eq!(
        // SAFETY: live fixture descriptor and nonblocking lock operation.
        unsafe { libc::flock(competing.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
        -1
    );
}
#[test]
#[ignore = "invoked by worker_fd_contract_has_no_shell_or_authority_fds"]
fn fd_contract_child() {
    let fds = sys::validate_worker_fds().unwrap_or_else(|error| {
        println!("fd validation: {error}");
        panic!("invalid fds")
    });
    assert!(
        sys::validate_worker_fds().is_err(),
        "one descriptor owner only"
    );
    assert!(std::env::vars_os().next().is_none());
    assert_eq!(std::env::current_dir().unwrap(), PathBuf::from("/"));
    for fd in 0..=1100 {
        // SAFETY: read-only query, invalid descriptors are expected.
        let open = unsafe { libc::fcntl(fd, libc::F_GETFD) } >= 0;
        assert_eq!(open, [0, 1, 2, 3, 5].contains(&fd), "fd {fd}");
    }
    println!("fd_contract_child: passed");
    std::io::stdout().flush().unwrap();
    drop(fds);
}

// 이것을 실패시키는 것: Ready의 build-id가 공유된 빌드 manifest와 다르게 나오는 것.
#[test]
fn sibling_build_id_is_exact() {
    use bingsu_core::collection::wire;
    let fixture = Fixture::new("identity");
    let mut command = Command::new(binary());
    fixture.prepare(&mut command, false);
    let mut process = command.arg("__collect-v1").spawn().unwrap();
    let mut ready = [0; 104];
    process
        .stdout
        .as_mut()
        .unwrap()
        .read_exact(&mut ready)
        .unwrap();
    let ready = wire::decode_frame(&ready).unwrap();
    assert_eq!(ready.kind, wire::Kind::Ready);
    assert_eq!(ready.build_id, bingsu_identity::build_id());
    assert_eq!(&ready.payload[8..12], &0u32.to_le_bytes());
    let mut mismatched = [0; wire::FRAME_MAX];
    let frame = wire::Frame {
        kind: wire::Kind::RequestBegin,
        build_id: wire::BuildId([0; 32]),
        request_id: wire::M3B_REQUEST_ID,
        payload: &[0; 12],
    };
    let len = wire::encode_frame(frame, &mut mismatched).unwrap();
    File::from(fixture.write.try_clone().unwrap())
        .write_all(&mismatched[..len])
        .unwrap();
    let result = process.wait_with_output().unwrap();
    assert!(!result.status.success());
    assert!(result.stdout.is_empty());
}

#[test]
#[ignore = "macOS no-spawn harness invokes the common-path test worker"]
fn fixture_worker_child() {
    worker::fixture_entry().unwrap();
}

// 이것을 실패시키는 것: pipe 아닌 stdout·빈 환경/cwd 계약·잠금 속성 검사를 빼는 것.
#[test]
fn worker_rejects_invalid_handoff_before_ready() {
    use std::os::unix::net::UnixStream;
    let fixture = Fixture::new("bad-handoff");
    // Exercise validation itself: FSIZE=0 would independently suppress a
    // regular-file Ready and could otherwise mask a missing pipe check.
    let output_path = fixture.path.with_extension("validation");
    let mut check = Command::new(std::env::current_exe().unwrap());
    fixture.prepare(&mut check, false);
    check
        .args([
            "--exact",
            "fd_reject_child",
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .stdout(File::create(&output_path).unwrap());
    let status = check.status().unwrap();
    assert!(status.success());
    assert!(
        fs::read_to_string(&output_path)
            .unwrap()
            .contains("test result: ok. 1 passed;")
    );
    fs::remove_file(output_path).unwrap();
    for condition in [
        "environment",
        "cwd",
        "lock-mode",
        "lock-size",
        "regular",
        "socket",
        "tty",
    ] {
        let mut command = Command::new(binary());
        fixture.prepare(&mut command, false);
        command.arg("__collect-v1");
        let output_path = fixture.path.with_extension("output");
        let output = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&output_path)
            .unwrap();
        let (socket, mut peer) = UnixStream::pair().unwrap();
        peer.set_nonblocking(true).unwrap();
        let (mut master, mut slave) = (-1, -1);
        assert_eq!(
            // SAFETY: two writable descriptor outputs; default termios and window size.
            unsafe {
                libc::openpty(
                    &mut master,
                    &mut slave,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                )
            },
            0
        );
        // SAFETY: newly created pseudo-terminal descriptors, each transferred once.
        let mut master = unsafe { File::from_raw_fd(master) };
        // SAFETY: new descriptor with unique ownership.
        let slave = unsafe { OwnedFd::from_raw_fd(slave) };
        assert_eq!(
            // SAFETY: this fixture owns the master's description.
            unsafe { libc::fcntl(master.as_raw_fd(), libc::F_SETFL, libc::O_NONBLOCK) },
            0
        );
        match condition {
            "environment" => {
                command.env("GIT_DIR", "/untrusted");
            }
            "cwd" => {
                command.current_dir(std::env::temp_dir());
            }
            "lock-mode" => fixture
                .lock
                .set_permissions(fs::Permissions::from_mode(0o640))
                .unwrap(),
            "lock-size" => OpenOptions::new()
                .write(true)
                .open(&fixture.path)
                .unwrap()
                .set_len(1)
                .unwrap(),
            "regular" => {
                command.stdout(output.try_clone().unwrap());
            }
            "socket" => {
                command.stdout(OwnedFd::from(socket));
            }
            "tty" => {
                command.stdout(slave);
            }
            _ => unreachable!(),
        }
        // A complete malformed header prevents a regressed worker from waiting
        // forever while making any forbidden Ready observable.
        File::from(fixture.write.try_clone().unwrap())
            .write_all(&[b'x'; 80])
            .unwrap();
        let out = command.output().unwrap();
        assert!(
            !out.status.success() && out.stdout.is_empty(),
            "{condition}: {out:?}"
        );
        assert_eq!(output.metadata().unwrap().len(), 0, "{condition}");
        let mut byte = [0];
        assert!(!matches!(peer.read(&mut byte), Ok(1)), "socket Ready");
        assert!(!matches!(master.read(&mut byte), Ok(1)), "tty Ready");
        // Drain only what the failed worker was forbidden to read.
        assert_eq!(
            // SAFETY: the child has exited, parent observation of its private pipe.
            unsafe { libc::fcntl(fixture.read.as_raw_fd(), libc::F_SETFL, libc::O_NONBLOCK) },
            0
        );
        let mut request = [0; 80];
        File::from(fixture.read.try_clone().unwrap())
            .read_exact(&mut request)
            .unwrap();
        assert_eq!(request, [b'x'; 80], "{condition}");
        fixture
            .lock
            .set_permissions(fs::Permissions::from_mode(0o600))
            .unwrap();
        OpenOptions::new()
            .write(true)
            .open(&fixture.path)
            .unwrap()
            .set_len(0)
            .unwrap();
        fs::remove_file(output_path).unwrap();
    }
}

#[test]
#[ignore = "invoked by worker_rejects_invalid_handoff_before_ready"]
fn fd_reject_child() {
    assert!(sys::validate_worker_fds().is_err());
}

// 이것을 실패시키는 것: exec로 상속된 ignored/blocked limit 신호를 그대로 두는 것.
#[test]
fn worker_resets_inherited_limit_signals() {
    let mut command = Command::new(std::env::current_exe().unwrap());
    command.args([
        "--exact",
        "inherited_limit_signals_child",
        "--ignored",
        "--nocapture",
        "--test-threads=1",
    ]);
    let inherit = || {
        // SAFETY: plain C signal storage, initialized before use.
        let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
        action.sa_sigaction = libc::SIG_IGN;
        // SAFETY: writable signal set.
        if unsafe { libc::sigemptyset(&mut action.sa_mask) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        let mut mask = action.sa_mask;
        for signal in [libc::SIGXCPU, libc::SIGXFSZ, libc::SIGALRM] {
            // SAFETY: supported signal and initialized action.
            if unsafe { libc::sigaction(signal, &action, std::ptr::null_mut()) } != 0 {
                return Err(std::io::Error::last_os_error());
            }
            // SAFETY: initialized set and supported signal.
            if unsafe { libc::sigaddset(&mut mask, signal) } != 0 {
                return Err(std::io::Error::last_os_error());
            }
        }
        // SAFETY: initialized set; changes only the exec child's mask.
        if unsafe { libc::sigprocmask(libc::SIG_BLOCK, &mask, std::ptr::null_mut()) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    };
    // SAFETY: the child closure only uses async-signal-safe signal operations.
    unsafe {
        command.pre_exec(inherit);
    }
    assert_one_passed(&command.output().unwrap());
}

#[test]
#[ignore = "invoked by worker_resets_inherited_limit_signals"]
fn inherited_limit_signals_child() {
    fn check(disposition: libc::sighandler_t, blocked: libc::c_int) {
        // SAFETY: plain C output storage for read-only signal queries.
        let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
        // SAFETY: plain C output storage initialized by sigprocmask.
        let mut mask: libc::sigset_t = unsafe { std::mem::zeroed() };
        assert_eq!(
            // SAFETY: null input leaves the mask unchanged; output is writable.
            unsafe { libc::sigprocmask(libc::SIG_BLOCK, std::ptr::null(), &mut mask) },
            0
        );
        for signal in [libc::SIGXCPU, libc::SIGXFSZ, libc::SIGALRM] {
            assert_eq!(
                // SAFETY: supported signal, read-only query with writable output.
                unsafe { libc::sigaction(signal, std::ptr::null(), &mut action) },
                0
            );
            assert_eq!(action.sa_sigaction, disposition, "signal {signal}");
            assert_eq!(
                // SAFETY: initialized mask and supported signal.
                unsafe { libc::sigismember(&mask, signal) },
                blocked,
                "signal {signal}"
            );
        }
    }
    check(libc::SIG_IGN, 1);
    limits::install_base().unwrap();
    check(libc::SIG_DFL, 0);
}

// 이것을 실패시키는 것: Linux worker가 쓰기 가능한 일반 파일을 상속하는 것.
#[test]
#[cfg(target_os = "linux")]
fn writable_lock_is_rejected_on_linux() {
    let fixture = Fixture::new("writable-lock");
    let writable = OpenOptions::new().write(true).open(&fixture.path).unwrap();
    // SAFETY: owned duplicate above all reserved protocol slots.
    let fd = unsafe { libc::fcntl(writable.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 20) };
    assert!(fd >= 20);
    // SAFETY: the duplicate has exactly one owner.
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    let mut command = Command::new(binary());
    fixture.prepare(&mut command, false);
    let setup = move || {
        // SAFETY: live duplicate and a reserved descriptor in this child only.
        if unsafe { libc::dup2(fd.as_raw_fd(), 5) } < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    };
    // SAFETY: setup uses only async-signal-safe descriptor duplication.
    unsafe {
        command.pre_exec(setup);
    }
    File::from(fixture.write.try_clone().unwrap())
        .write_all(&[b'x'; 80])
        .unwrap();
    let out = command.arg("__collect-v1").output().unwrap();
    assert!(!out.status.success() && out.stdout.is_empty());
}
