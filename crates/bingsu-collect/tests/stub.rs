#![cfg(unix)]
use std::process::Command;

fn run(args: &[&str]) -> Vec<u8> {
    let out = Command::new(env!("CARGO_BIN_EXE_bingsu-collect"))
        .args(args)
        .output()
        .unwrap();
    assert!(out.status.success(), "{args:?}: {:?}", out.status);
    out.stdout
}

fn code(args: &[&str]) -> Option<i32> {
    Command::new(env!("CARGO_BIN_EXE_bingsu-collect"))
        .args(args)
        .output()
        .unwrap()
        .status
        .code()
}

// 이것을 실패시키는 것: --mode 없을 때의 기본값을 bare가 아니게 바꾸는 것, exit 갈래를 지우는 것(알 수 없는 모드로 2).
#[test]
fn modes_print_ready_byte() {
    assert_eq!(run(&[]), b"R");
    assert_eq!(run(&["--mode", "bare"]), b"R");
    assert_eq!(run(&["--mode", "limits"]), b"R");
    assert_eq!(run(&["--mode", "exit"]), b"");
}

// 이것을 실패시키는 것: 알 수 없는 모드를 bare처럼 받아들이는 것.
#[test]
fn unknown_mode_exits_2() {
    assert_eq!(code(&["--mode", "nope"]), Some(2));
}

// RLIMIT_FSIZE 0 is observable: writing the ready byte to a regular file
// raises SIGXFSZ. (The cost harness reads stdout through a pipe, which the
// limit does not cover.) RLIMIT_CPU and RLIMIT_NOFILE are not observed here.
// 이것을 실패시키는 것: limits 모드에서 set_limits를 부르지 않거나 RLIMIT_FSIZE를 목록에서 빼는 것.
#[test]
fn limits_mode_applies_fsize_zero() {
    use std::os::unix::process::{CommandExt, ExitStatusExt};
    let path = std::env::temp_dir().join(format!("bingsu-collect-fsize-{}", std::process::id()));
    let file = std::fs::File::create(&path).unwrap();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_bingsu-collect"));
    cmd.args(["--mode", "limits"]).stdout(file);
    // SIGXFSZ dumps core by default; with core_pattern "core" (Linux
    // containers) that leaves an empty `core` in the crate directory.
    let no_core = || {
        let zero = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: `zero` is a valid rlimit value for setrlimit.
        if unsafe { libc::setrlimit(libc::RLIMIT_CORE, &zero) } == 0 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error())
        }
    };
    // SAFETY: the hook runs in the forked child and calls only setrlimit,
    // which is async-signal-safe.
    unsafe { cmd.pre_exec(no_core) };
    let st = cmd.status().unwrap();
    let len = std::fs::metadata(&path).unwrap().len();
    std::fs::remove_file(&path).unwrap();
    assert_eq!((st.signal(), len), (Some(libc::SIGXFSZ), 0), "{st:?}");
}

// macOS has no execution ban to install; the stub reports it with exit 4.
// 이것을 실패시키는 것: macOS의 sandbox()가 Ok를 돌려주는 것(아무것도 막지 않은 채 R을 냄).
#[cfg(not(target_os = "linux"))]
#[test]
fn sandbox_is_unsupported_off_linux() {
    assert_eq!(code(&["--mode", "sandbox"]), Some(4));
}

// 이것을 실패시키는 것: seccomp 필터를 설치하지 않는 것(exec이 성공해 /bin/true로 바뀌고 아무것도 출력하지 않음).
#[cfg(target_os = "linux")]
#[test]
fn sandbox_blocks_exec() {
    assert_eq!(run(&["--mode", "sandbox", "--probe-exec"]), b"PR");
}

// 이것을 실패시키는 것: --report-vm 갈래를 지우거나, VmSize 줄을 찾지 못해 "unknown"을 내는 것.
// 이것을 실패시키는 것: clone3 필터(ENOSYS)를 설치하지 않는 것. 단 host가 이미 clone3를 막으면
// (docker 기본 seccomp 프로필) 대조인 bare도 C를 내어 가려진다; 그런 곳에서는 판별력이 없음을 알린다.
#[cfg(target_os = "linux")]
#[test]
fn sandbox_blocks_clone3() {
    let control = run(&["--mode", "bare", "--probe-clone3"]);
    assert!(control == b"R" || control == b"CR", "{control:?}");
    if control == b"CR" {
        eprintln!(
            "clone3 is already ENOSYS without the filter here; this test cannot tell the filter apart"
        );
    }
    assert_eq!(run(&["--mode", "sandbox", "--probe-clone3"]), b"CR");
}

#[cfg(target_os = "linux")]
#[test]
fn report_vm_prints_kib() {
    let out = run(&["--mode", "limits", "--report-vm"]);
    let s = String::from_utf8(out).unwrap();
    let kib = s
        .strip_prefix("VM ")
        .and_then(|r| r.strip_suffix("\nR"))
        .and_then(|n| n.parse::<u64>().ok());
    assert!(kib.is_some_and(|k| k > 0), "{s:?}");
}
