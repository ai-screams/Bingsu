use super::hook::{HOOK, Stage};
use super::*;
use bingsu_core::handoff::{Cwd, Interpreter, Origin, relay_args, relay_input};
use std::io::Read;
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const SECOND: i64 = 1_000_000_000;

/// A pipe whose ends sit at 100 or above and are close-on-exec, so the
/// child's dup2 onto 3 and 5 never overwrites another of them.
fn pipe() -> (OwnedFd, OwnedFd) {
    let mut fds = [0; 2];
    // SAFETY: `fds` is writable for two descriptors.
    assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
    let high = |fd: i32| {
        // SAFETY: `fd` is open; the duplicate is close-on-exec.
        let h = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 100) };
        assert!(h >= 100);
        // SAFETY: `fd` was returned by pipe above and is closed once.
        unsafe { libc::close(fd) };
        // SAFETY: `h` is a fresh descriptor nothing else owns.
        unsafe { OwnedFd::from_raw_fd(h) }
    };
    (high(fds[0]), high(fds[1]))
}

fn put(fd: &OwnedFd, mut bytes: &[u8]) {
    while !bytes.is_empty() {
        // SAFETY: `bytes` is readable for its length; `fd` is open.
        let n = unsafe { libc::write(fd.as_raw_fd(), bytes.as_ptr().cast(), bytes.len()) };
        bytes = &bytes[usize::try_from(n).unwrap()..];
    }
}

fn scratch(tag: &str) -> PathBuf {
    let base = std::fs::canonicalize(std::env::temp_dir()).unwrap();
    let dir = base.join(format!("bingsu-relay-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir(&dir).unwrap();
    dir
}

fn copy_mode(from: &Path, to: &Path, mode: u32) {
    std::fs::copy(from, to).unwrap();
    std::fs::set_permissions(to, std::fs::Permissions::from_mode(mode)).unwrap();
}

fn frame_input(run_ns: i64, interpreter: Option<Interpreter>) -> Vec<u8> {
    frame_input_pinned(run_ns, interpreter, None)
}

fn frame_input_pinned(
    run_ns: i64,
    interpreter: Option<Interpreter>,
    pin: Option<ExecPin>,
) -> Vec<u8> {
    let clock = crate::prompt_io::observe_clock().unwrap();
    let permit = Permit {
        kind: clock.kind,
        // Far: the first run of a fresh copy of this binary can take
        // seconds on macOS (its code is checked on first exec).
        deadline: clock.now.checked_add_signed(60 * SECOND).unwrap(),
        boot: clock.boot,
        resume: clock.resume,
        domain: clock.domain,
    };
    let frame = ExecFrame {
        origin: Origin::Config,
        run_deadline: clock.now.checked_add_signed(run_ns).unwrap(),
        environment: Vec::new(),
        pin,
        interpreter,
        cwd: b"/".to_vec(),
    };
    relay_input(permit, &frame, INPUT_CAP).unwrap()
}

fn live() -> Vec<u8> {
    frame_input(60 * SECOND, None)
}

/// What one relay run left: its exit code, the bytes on its status pipe
/// and the target's stdout.
#[derive(Debug)]
struct Run {
    code: i32,
    status: Vec<u8>,
    stdout: Vec<u8>,
}

fn read_all(fd: i32) -> Vec<u8> {
    let mut out = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        // SAFETY: `buf` is writable for its length.
        let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
        match usize::try_from(n).unwrap() {
            0 => return out,
            n => out.extend_from_slice(&buf[..n]),
        }
    }
}

/// A `relay_child` hook: its mode, the path it acts on and the other one.
type Swap<'a> = Option<(&'a str, &'a Path, &'a Path)>;

/// The supervisor's side for one relay: fd 3 holds `input`, fd 2 the
/// status pipe, fd 4 the `relay_child` hook and the relay argv as
/// NUL-terminated words, fd 5 a pipe end left open without close-on-exec
/// (an fd the relay must not pass on). SIGUSR1 is ignored and SIGUSR2
/// blocked, which the relay must undo.
fn run_relay(input: &[u8], exe: &Path, argv: &[&[u8]], swap: Swap<'_>) -> Run {
    let _inherited_fds = crate::commands::sys::test_inherited_fd_lock();
    let words: Vec<Vec<u8>> = relay_args(exe.as_os_str().as_bytes(), Cwd::Neutral, argv)
        .unwrap()
        .into_iter()
        .map(<[u8]>::to_vec)
        .collect();
    let (r3, w3) = pipe();
    put(&w3, input);
    drop(w3);
    let (r4, w4) = pipe();
    let (mode, target, with) = swap.unwrap_or(("", Path::new(""), Path::new("")));
    let hook = [
        mode.as_bytes(),
        target.as_os_str().as_bytes(),
        with.as_os_str().as_bytes(),
    ];
    for word in hook.into_iter().chain(words.iter().map(Vec::as_slice)) {
        put(&w4, word);
        put(&w4, b"\0");
    }
    drop(w4);
    let (status_r, status_w) = pipe();
    let (r5, _w5) = pipe();
    let (r3n, r4n, r5n) = (r3.as_raw_fd(), r4.as_raw_fd(), r5.as_raw_fd());
    let mut cmd = Command::new(std::env::current_exe().unwrap());
    cmd.args([
        "relay::macos_tests::relay_child",
        "--exact",
        "--ignored",
        "--nocapture",
        "--test-threads=1",
        "-q",
    ])
    .env_clear()
    .stdin(Stdio::null())
    .stdout(Stdio::piped())
    .stderr(Stdio::from(status_w));
    // Runs in the forked child: only async-signal-safe calls.
    let setup = move || {
        for (from, to) in [(r3n, 3), (r4n, 4), (r5n, 5)] {
            // SAFETY: both descriptors are valid; dup2 clears close-on-exec on `to`.
            if unsafe { libc::dup2(from, to) } != to {
                return Err(std::io::Error::last_os_error());
            }
        }
        // SAFETY: plain disposition change.
        unsafe { libc::signal(libc::SIGUSR1, libc::SIG_IGN) };
        // SAFETY: an all-zero sigset_t is a valid buffer for sigemptyset.
        let mut set: libc::sigset_t = unsafe { std::mem::zeroed() };
        // SAFETY: `set` is writable.
        unsafe { libc::sigemptyset(&mut set) };
        // SAFETY: `set` is initialized.
        unsafe { libc::sigaddset(&mut set, libc::SIGUSR2) };
        // SAFETY: `set` is initialized; the old mask is not requested.
        unsafe { libc::pthread_sigmask(libc::SIG_BLOCK, &set, std::ptr::null_mut()) };
        Ok(())
    };
    // SAFETY: `setup` is async-signal-safe (above).
    unsafe { cmd.pre_exec(setup) };
    let mut child = cmd.spawn().unwrap();
    drop((r3, r4, r5));
    let mut stdout = Vec::new();
    child
        .stdout
        .take()
        .unwrap()
        .read_to_end(&mut stdout)
        .unwrap();
    let code = child.wait().unwrap().code().unwrap_or(-1);
    drop(cmd);
    let mut status = Vec::new();
    std::fs::File::from(status_r)
        .read_to_end(&mut status)
        .unwrap();
    Run {
        code,
        status,
        stdout,
    }
}

/// The relay process: reads its hook and argv from fd 4 (the relay
/// reads no environment, so neither does this), then runs the relay.
#[test]
#[ignore = "child: one relay run"]
fn relay_child() {
    let words = read_all(4);
    // SAFETY: fd 4 is this child's argument pipe, read to the end above.
    unsafe { libc::close(4) };
    let mut words: Vec<OsString> = words
        .strip_suffix(b"\0")
        .unwrap()
        .split(|&b| b == 0)
        .map(|w| OsString::from_vec(w.to_vec()))
        .collect();
    let args = words.split_off(3);
    let [mode, target, with] = <[OsString; 3]>::try_from(words).unwrap();
    let (target, with) = (PathBuf::from(target), PathBuf::from(with));
    let mode = mode.into_string().unwrap();
    if !mode.is_empty() {
        // Once: a script run checks two names.
        let mut once = Some(mode);
        HOOK.with(|h| {
            *h.borrow_mut() = Some(Box::new(move |stage| {
                if stage != Stage::Recheck {
                    return;
                }
                let Some(mode) = once.take() else { return };
                match mode.as_str() {
                    // Another file under the checked name.
                    "rename" => std::fs::rename(&with, &target).unwrap(),
                    // The checked folder moved to `with`, a symlink in
                    // its place: the same inode through a link.
                    "folder-link" => {
                        std::fs::rename(&target, &with).unwrap();
                        std::os::unix::fs::symlink(&with, &target).unwrap();
                    }
                    // The name check takes long: the deadline passes.
                    "late" => std::thread::sleep(std::time::Duration::from_millis(400)),
                    other => panic!("{other}"),
                }
            }));
        });
    }
    let code = relay(&args);
    // SAFETY: child exit without the harness's atexit work.
    unsafe { libc::_exit(i32::from(code)) }
}

/// The target side: prints what it was started with on one line.
#[test]
#[ignore = "child: the relay's target"]
fn probe_child() {
    let fds: Vec<i32> = open_fds().unwrap().into_iter().collect();
    // SAFETY: an all-zero sigset_t is a valid out-parameter value.
    let mut mask: libc::sigset_t = unsafe { std::mem::zeroed() };
    // SAFETY: only reads this thread's mask into `mask`.
    unsafe { libc::pthread_sigmask(libc::SIG_BLOCK, std::ptr::null(), &mut mask) };
    // SAFETY: an all-zero sigaction is a valid out-parameter value.
    let mut old: libc::sigaction = unsafe { std::mem::zeroed() };
    // SAFETY: only reads SIGUSR1's action into `old`.
    unsafe { libc::sigaction(libc::SIGUSR1, std::ptr::null(), &mut old) };
    let cwd = std::env::current_dir().unwrap();
    let argv0 = std::env::args_os().next().unwrap();
    println!(
        "SEEN fds={fds:?} mask={mask} usr1={} cwd={} argv0={}",
        old.sa_sigaction,
        cwd.display(),
        argv0.to_string_lossy()
    );
}

fn me_exe() -> PathBuf {
    std::fs::canonicalize(std::env::current_exe().unwrap()).unwrap()
}

/// The probe target as `exe` (a path to this test binary or a copy).
fn probe(exe: &Path, input: &[u8]) -> Run {
    let argv: [&[u8]; 6] = [
        b"probe-word",
        b"relay::macos_tests::probe_child",
        b"--exact",
        b"--ignored",
        b"--nocapture",
        b"-q",
    ];
    run_relay(input, exe, &argv, None)
}

fn seen(run: &Run) -> String {
    let out = String::from_utf8_lossy(&run.stdout);
    out.lines()
        .find_map(|l| l.strip_prefix("SEEN "))
        .unwrap_or_else(|| panic!("the target did not run: {run:?}"))
        .to_owned()
}

// 양성 대조와 계약: 대상은 fd {0,1,2}만, 빈 신호 마스크와 기본 처리, frame의 작업 폴더, 사용자가 쓴 argv[0]으로
// 돈다. 상태 파이프는 exec에서 닫혀 0바이트다. 이것을 실패시키는 것: cloexec_all을 늘 참으로(fd 5와 상태
// 파이프가 남음), reset_signals를 지우는 것.
#[test]
fn test_macos_relay_runs_the_target_clean() {
    let run = probe(&me_exe(), &live());
    let line = seen(&run);
    assert_eq!(run.code, 0, "{run:?}");
    assert!(run.status.is_empty(), "{run:?}");
    assert!(line.contains("fds=[0, 1, 2] "), "{line}");
    assert!(line.contains(" mask=0 usr1=0 "), "{line}");
    assert!(line.contains(" cwd=/ "), "{line}");
    assert!(line.ends_with(" argv0=probe-word"), "{line}");
}

// 거부하면 상태 파이프에 코드 1바이트를 쓰고 대상은 돌지 않는다. 이것을 실패시키는 것: relay의 상태 쓰기를
// 지우는 것, prepare의 시계 확인을 지우는 것(만료 frame이 돈다).
#[test]
fn test_macos_relay_refuses_an_expired_frame() {
    let run = probe(&me_exe(), &frame_input(-1, None));
    assert_eq!(run.code, i32::from(RELAY_EXPIRED), "{run:?}");
    assert_eq!(run.status, [RELAY_EXPIRED]);
    assert!(!String::from_utf8_lossy(&run.stdout).contains("SEEN "));
}

// macOS: setuid·setgid 비트가 있는 대상은 거부한다. 양성 대조: 같은 사본 0755는 돈다. 이것을
// 실패시키는 것: allowed의 set-id 조건을 지우는 것, 또는 두 비트 가운데 하나만 보는 것.
#[test]
fn test_set_id_targets_are_refused() {
    let dir = scratch("set-id");
    for (mode, code) in [(0o755, 0), (0o4755, RELAY_TARGET), (0o2755, RELAY_TARGET)] {
        let exe = dir.join(format!("probe-{mode:o}"));
        copy_mode(&me_exe(), &exe, mode);
        let run = probe(&exe, &live());
        assert_eq!(run.code, i32::from(code), "{mode:o}: {run:?}");
    }
    std::fs::remove_dir_all(&dir).unwrap();
}

// macOS: 조회한 뒤 대상이 바뀌면(이름 위로 다른 사본을 옮김, chmod) relay가 조회의 pin으로 거부한다.
// 양성 대조: 바뀌지 않은 대상은 돈다. 이것을 실패시키는 것: helper가 그룹 쓰기를 비운 대상에만 pin을 주는 것.
#[test]
fn test_relay_refuses_a_target_changed_after_its_lookup() {
    let dir = scratch("after-lookup");
    let exe = dir.join("probe");
    copy_mode(&me_exe(), &exe, 0o755);
    let look = || {
        crate::commands::exec_path::lookup(
            b"probe",
            std::slice::from_ref(&dir),
            &[],
            crate::commands::sys::current_uid(),
            &mut bingsu_core::fs_trust::RefuseGroupWrite,
        )
        .unwrap()
        .pin
    };
    let run = |pin| probe(&exe, &frame_input_pinned(60 * SECOND, None, pin)).code;
    let pin = look();
    assert_eq!(run(pin), 0, "unchanged");
    copy_mode(&me_exe(), &dir.join("other"), 0o755);
    std::fs::rename(dir.join("other"), &exe).unwrap();
    assert_eq!(run(pin), i32::from(RELAY_TARGET), "replaced");
    let pin = look();
    assert_eq!(run(pin), 0, "looked up again");
    std::fs::set_permissions(&exe, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
    assert_eq!(run(pin), i32::from(RELAY_TARGET), "chmod");
    std::fs::remove_dir_all(&dir).unwrap();
}

// 읽을 수 없는 실행 전용 대상은 거부한다(경로 execve면 커널이 그 `#!` 줄의 인터프리터를 검사 없이
// 띄운다). 양성 대조: 같은 사본 0711(소유자가 읽음)은 돈다. 이것을 실패시키는 것: 읽기 열기의 EACCES에서
// O_EXEC로 다시 열어 네이티브로 실행하는 대체 경로.
#[test]
fn test_macos_execute_only_target_refused() {
    let dir = scratch("xonly");
    for (mode, code) in [(0o711, 0), (0o111, RELAY_TARGET)] {
        let exe = dir.join(format!("probe-{mode:o}"));
        copy_mode(&me_exe(), &exe, mode);
        let run = probe(&exe, &live());
        assert_eq!(run.code, i32::from(code), "{mode:o}: {run:?}");
    }
    std::fs::remove_dir_all(&dir).unwrap();
}

fn swapped(mode: &str, input: &[u8]) -> Run {
    let dir = scratch(&format!("swap-{mode}"));
    let folder = dir.join("bin");
    std::fs::create_dir(&folder).unwrap();
    let exe = folder.join("probe");
    copy_mode(&me_exe(), &exe, 0o755);
    // The first exec of a fresh copy is slow (its code is checked): done
    // here, so the short deadline of "late" measures the name check alone.
    assert!(
        Command::new(&exe)
            .arg("--list")
            .output()
            .unwrap()
            .status
            .success()
    );
    let (target, with) = match mode {
        "rename" => {
            let other = folder.join("other");
            copy_mode(&me_exe(), &other, 0o755);
            (exe.clone(), other)
        }
        "folder-link" => (folder.clone(), dir.join("moved")),
        _ => (exe.clone(), exe.clone()),
    };
    let argv: [&[u8]; 6] = [
        b"probe-word",
        b"relay::macos_tests::probe_child",
        b"--exact",
        b"--ignored",
        b"--nocapture",
        b"-q",
    ];
    let run = run_relay(input, &exe, &argv, Some((mode, &target, &with)));
    std::fs::remove_dir_all(&dir).unwrap();
    run
}

// 재확인 바로 앞에 이름 자리에 다른 파일이 오면 거부한다. 이것을 실패시키는 것: still_named를 늘 참으로.
#[test]
fn test_macos_swap_before_the_name_check_is_refused() {
    let run = swapped("rename", &live());
    assert_eq!(run.code, i32::from(RELAY_TARGET), "{run:?}");
}

// 검사한 폴더를 옮기고 그 자리에 링크를 두면 같은 inode·ctime이라도 거부한다(execve는 경로 전체를
// 다시 해석한다). 이것을 실패시키는 것: 재확인의 AT_SYMLINK_NOFOLLOW_ANY를 AT_SYMLINK_NOFOLLOW로 바꾸는 것.
#[test]
fn test_macos_link_on_the_way_is_refused() {
    let run = swapped("folder-link", &live());
    assert_eq!(run.code, i32::from(RELAY_TARGET), "{run:?}");
}

// 재확인이 늦어 마감이 지나면 실행하지 않는다(시계는 재확인 뒤). 이것을 실패시키는 것: exec의
// 시계 확인을 still_named 앞으로 옮기는 것.
#[test]
fn test_macos_deadline_passing_during_the_name_check_is_refused() {
    let run = swapped("late", &frame_input(300_000_000, None));
    assert_eq!(run.code, i32::from(RELAY_EXPIRED), "{run:?}");
}

// 이름 자리의 FIFO는 열지 않는다(열면 기다리던 쓰는 쪽이 풀린다). macOS에는 쓰는 쪽이 open 안에서 기다리는지
// 볼 /proc이 없어 200 ms를 먼저 기다린다(늦은 쓰는 쪽은 통과로 보일 수 있을 뿐 거짓 실패는 없다). 이것을
// 실패시키는 것: open_target의 열기 전 형식 검사(stat_at)를 지우는 것.
#[test]
fn test_macos_relay_never_opens_a_fifo() {
    let dir = scratch("fifo");
    let fifo = dir.join("fifo");
    let c = CString::new(fifo.as_os_str().as_bytes()).unwrap();
    // SAFETY: `c` is NUL-terminated.
    assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o755) }, 0);
    let (tx, rx) = std::sync::mpsc::channel();
    let writer = std::thread::spawn(move || {
        // SAFETY: `c` is NUL-terminated; no O_CREAT. Blocks until a reader opens it.
        let w = unsafe { libc::open(c.as_ptr(), libc::O_WRONLY | libc::O_CLOEXEC) };
        assert!(w >= 0);
        tx.send(()).unwrap();
        // SAFETY: `w` was opened above and is closed once.
        unsafe { libc::close(w) };
    });
    std::thread::sleep(std::time::Duration::from_millis(200));
    let run = probe(&fifo, &live());
    let opened = rx
        .recv_timeout(std::time::Duration::from_millis(300))
        .is_ok();
    // Release a writer still waiting, without waiting for one.
    let c = CString::new(fifo.as_os_str().as_bytes()).unwrap();
    // SAFETY: `c` is NUL-terminated; no O_CREAT.
    let r = unsafe {
        libc::open(
            c.as_ptr(),
            libc::O_RDONLY | libc::O_NONBLOCK | libc::O_CLOEXEC,
        )
    };
    writer.join().unwrap();
    // SAFETY: `r` was opened above and is closed once.
    unsafe { libc::close(r) };
    assert_eq!(run.code, i32::from(RELAY_TARGET), "{run:?}");
    assert!(!opened, "the relay opened the FIFO for reading");
    std::fs::remove_dir_all(&dir).unwrap();
}

fn sh() -> PathBuf {
    std::fs::canonicalize("/bin/sh").unwrap()
}

fn interpreter(line: &str) -> Option<Interpreter> {
    Some(Interpreter {
        line: line.as_bytes().to_vec(),
        path: sh().as_os_str().as_bytes().to_vec(),
        pin: None,
    })
}

/// A script copy as the helper makes one (the user's, 0600 unless
/// `mode` says otherwise) that prints its argv.
fn script_copy(dir: &Path, mode: u32) -> PathBuf {
    let copy = dir.join("copy");
    std::fs::write(&copy, b"#!/bin/sh\necho \"SEEN $0 $*\"\n").unwrap();
    std::fs::set_permissions(&copy, std::fs::Permissions::from_mode(mode)).unwrap();
    copy
}

// 스크립트 복사본은 검사한 인터프리터로 돌고, 인터프리터는 복사본 경로를 인자로 받는다. 이것을 실패시키는 것:
// script_argv에 복사본 경로 대신 다른 값을 넣는 것.
#[test]
fn test_macos_script_copy_runs_through_its_interpreter() {
    let dir = scratch("script");
    let copy = script_copy(&dir, 0o600);
    let run = run_relay(
        &frame_input(60 * SECOND, interpreter("/bin/sh")),
        &copy,
        &[b"tool", b"x"],
        None,
    );
    assert_eq!(run.code, 0, "{run:?}");
    assert_eq!(seen(&run), format!("{} x", copy.display()));
    std::fs::remove_dir_all(&dir).unwrap();
}

// 복사본은 사용자의 0600 파일이어야 한다. 이것을 실패시키는 것: script()의 private 조건을 지우는 것.
#[test]
fn test_script_copy_must_be_private() {
    let dir = scratch("script-0644");
    let copy = script_copy(&dir, 0o644);
    let run = run_relay(
        &frame_input(60 * SECOND, interpreter("/bin/sh")),
        &copy,
        &[b"tool"],
        None,
    );
    assert_eq!(run.code, i32::from(RELAY_TARGET), "{run:?}");
    std::fs::remove_dir_all(&dir).unwrap();
}

// frame의 줄과 다른 `#!` 줄, 그리고 인터프리터가 다시 스크립트인 경우는 거부한다. 이것을 실패시키는 것:
// script()의 줄 비교를 지우는 것, 인터프리터의 Opened::Native 요구를 지우는 것.
#[test]
fn test_macos_script_line_and_nesting_refused() {
    let dir = scratch("script-refused");
    let copy = script_copy(&dir, 0o600);
    let other = run_relay(
        &frame_input(60 * SECOND, interpreter("/bin/zsh")),
        &copy,
        &[b"tool"],
        None,
    );
    assert_eq!(other.code, i32::from(RELAY_TARGET), "{other:?}");
    let nested = dir.join("nested");
    std::fs::write(&nested, b"#!/bin/sh\n").unwrap();
    std::fs::set_permissions(&nested, std::fs::Permissions::from_mode(0o755)).unwrap();
    let mut frame = interpreter("/bin/sh");
    if let Some(i) = frame.as_mut() {
        i.path = nested.as_os_str().as_bytes().to_vec();
    }
    let copy2 = dir.join("copy2");
    std::fs::write(&copy2, format!("#!{}\n", nested.display())).unwrap();
    std::fs::set_permissions(&copy2, std::fs::Permissions::from_mode(0o600)).unwrap();
    if let Some(i) = frame.as_mut() {
        i.line = nested.as_os_str().as_bytes().to_vec();
    }
    let run = run_relay(&frame_input(60 * SECOND, frame), &copy2, &[b"tool"], None);
    assert_eq!(run.code, i32::from(RELAY_TARGET), "{run:?}");
    std::fs::remove_dir_all(&dir).unwrap();
}

// 최종 재확인은 스크립트 사본도 본다. 인터프리터 재확인 때 사본 자리에 다른 0600 스크립트가
// 오면 거부한다. 양성 대조: test_macos_script_copy_runs_through_its_interpreter. 이것을 실패시키는 것: exec의
// 사본 still_named 검사를 지우는 것(바뀐 사본이 돈다).
#[test]
fn test_macos_copy_swapped_before_the_exec_is_refused() {
    let dir = scratch("copy-swap");
    let copy = script_copy(&dir, 0o600);
    let other = dir.join("other");
    std::fs::write(&other, b"#!/bin/sh\necho \"SEEN swapped\"\n").unwrap();
    std::fs::set_permissions(&other, std::fs::Permissions::from_mode(0o600)).unwrap();
    let run = run_relay(
        &frame_input(60 * SECOND, interpreter("/bin/sh")),
        &copy,
        &[b"tool"],
        Some(("rename", &copy, &other)),
    );
    assert_eq!(run.code, i32::from(RELAY_TARGET), "{run:?}");
    std::fs::remove_dir_all(&dir).unwrap();
}

// 소유권을 무시하는 볼륨(`hdiutil attach -owners off`) 위의 대상은 거부한다(그 볼륨에서는 모든
// 파일이 지금 사용자 소유로 보인다). 양성 대조: 같은 dmg를 소유권을 지키게 붙이면 돈다. 이것을 실패시키는 것:
// mount_ownership이 MNT_IGNORE_OWNERSHIP을 보지 않는 것.
#[test]
fn test_macos_target_on_a_volume_ignoring_owners_refused() {
    for (owners, code) in [(true, 0), (false, RELAY_TARGET)] {
        let dir = scratch(if owners { "owners-on" } else { "owners-off" });
        let volume = crate::commands::sys::TestVolume::new(&dir, owners, false);
        // A small target: the image holds 4 MB.
        let exe = volume.mount.join("true");
        copy_mode(Path::new("/usr/bin/true"), &exe, 0o755);
        let run = run_relay(&live(), &exe, &[b"true"], None);
        assert_eq!(run.code, i32::from(code), "owners {owners}: {run:?}");
        drop(volume);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}

// 로컬이 아닌 마운트는 판정 불가(None), 소유권을 무시하는 로컬 마운트는 false다. 이것을 실패시키는 것:
// mount_ownership의 MNT_LOCAL 조건이나 MNT_IGNORE_OWNERSHIP 조건을 지우는 것.
#[test]
fn mount_flags_decide_ownership() {
    let local = libc::MNT_LOCAL as u32;
    let ignore = libc::MNT_IGNORE_OWNERSHIP as u32;
    assert_eq!(mount_ownership(local), Some(true));
    assert_eq!(mount_ownership(local | ignore), Some(false));
    assert_eq!(mount_ownership(0), None);
    assert_eq!(mount_ownership(ignore), None);
}
