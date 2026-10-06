#![cfg(unix)]
use std::os::unix::process::CommandExt;
use std::process::Command;

/// The stub with RLIMIT_CORE 0: a signal death (SIGXFSZ below) would
/// otherwise leave a `core` file wherever core_pattern points (a bare
/// "core" in Linux containers lands in the crate directory).
fn stub(args: &[&str]) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_bingsu-collect"));
    cmd.args(args);
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
    // SAFETY: the hook runs in the forked child and makes a single system
    // call, with no allocation or locks.
    unsafe { cmd.pre_exec(no_core) };
    cmd
}

fn run(args: &[&str]) -> Vec<u8> {
    let out = stub(args).output().unwrap();
    assert!(out.status.success(), "{args:?}: {:?}", out.status);
    out.stdout
}

fn code(args: &[&str]) -> Option<i32> {
    stub(args).output().unwrap().status.code()
}

// 이것을 실패시키는 것: --mode 없을 때의 기본값을 bare가 아니게 바꾸는 것, exit 갈래를 지우는 것(알 수 없는 모드로 2).
#[test]
fn modes_have_expected_output() {
    assert_eq!(run(&[]), b"R");
    assert_eq!(run(&["--mode", "bare"]), b"R");
    assert_eq!(run(&["--mode", "limits"]), b"R");
    assert_eq!(run(&["--mode", "exit"]), b"");
}

// 이것을 실패시키는 것: 알 수 없는 모드나 값 없는 --mode를 bare처럼 받아들이는 것.
#[test]
fn bad_arguments_exit_2() {
    assert_eq!(code(&["--mode", "nope"]), Some(2));
    assert_eq!(code(&["--mode"]), Some(2));
    assert_eq!(code(&["--report-vm", "--report-vm"]), Some(2));
}

// The ready byte is the readiness contract: a run that cannot write it
// must not exit 0. stdout is a read-only fd, so write(2) fails with EBADF.
// (A closed fd 1 would not do: std reopens closed stdio on /dev/null.)
// 이것을 실패시키는 것: write 실패를 무시하는 것(쓸 수 없는 stdout에서도 exit 0).
#[test]
fn unwritable_stdout_exits_nonzero() {
    let read_only = std::fs::File::open("/dev/null").unwrap();
    let st = stub(&["--mode", "bare"])
        .stdout(read_only)
        .status()
        .unwrap();
    assert_eq!(st.code(), Some(5));
}

// A hard RLIMIT_NOFILE below 64 makes the stub's setrlimit fail with EPERM
// (an unprivileged process cannot raise a hard limit; root can, so the
// check needs a non-root user). Limits fail with 3 in both modes that set
// them; 4 is kept for the sandbox step itself.
// 이것을 실패시키는 것: sandbox 모드에서 set_limits 실패를 sandbox 실패(4)와 합치는 것.
#[test]
fn limits_failure_exits_3() {
    use std::io::Write;
    // SAFETY: geteuid has no preconditions.
    if unsafe { libc::geteuid() } == 0 {
        let _ = writeln!(
            std::io::stderr().lock(),
            "NOTE: limits_failure_exits_3 needs a non-root user; skipped as root"
        );
        return;
    }
    for mode in ["limits", "sandbox"] {
        let mut cmd = stub(&["--mode", mode]);
        let low_nofile = || {
            let low = libc::rlimit {
                rlim_cur: 32,
                rlim_max: 32,
            };
            // SAFETY: `low` is a valid rlimit value for setrlimit.
            if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &low) } == 0 {
                Ok(())
            } else {
                Err(std::io::Error::last_os_error())
            }
        };
        // SAFETY: the hook runs in the forked child and makes a single system
        // call, with no allocation or locks.
        unsafe { cmd.pre_exec(low_nofile) };
        assert_eq!(cmd.output().unwrap().status.code(), Some(3), "{mode}");
    }
}

// RLIMIT_FSIZE 0 is observable: writing the ready byte to a regular file
// raises SIGXFSZ. (The cost harness reads stdout through a pipe, which the
// limit does not cover.) RLIMIT_CPU and RLIMIT_NOFILE are not observed here.
// 이것을 실패시키는 것: limits 모드에서 set_limits를 부르지 않거나 RLIMIT_FSIZE를 목록에서 빼는 것.
#[test]
fn limits_mode_applies_fsize_zero() {
    use std::os::unix::process::ExitStatusExt;
    let path = std::path::Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("bingsu-collect-fsize-{}", std::process::id()));
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .unwrap();
    let st = stub(&["--mode", "limits"]).stdout(file).status().unwrap();
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

// 이것을 실패시키는 것: exec 거부 필터를 설치하지 않는 것(exec이 성공해 /bin/true로 바뀌고 아무것도 출력하지 않음).
#[cfg(target_os = "linux")]
#[test]
fn sandbox_blocks_exec() {
    assert_eq!(run(&["--mode", "sandbox", "--probe-exec"]), b"PR");
}

// An unfiltered raw vfork would share the stub's stack, so the fork probe
// runs under the sandbox only. Elsewhere than x86_64 Linux the probe is
// refused anyway (below), which would hide this rule, so it is checked there.
// 이것을 실패시키는 것: sandbox가 아닌 모드에서 --probe-fork를 받아들이는 것.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[test]
fn fork_probe_needs_sandbox() {
    assert_eq!(code(&["--probe-fork"]), Some(2));
    assert_eq!(code(&["--mode", "bare", "--probe-fork"]), Some(2));
    assert_eq!(code(&["--mode", "limits", "--probe-fork"]), Some(2));
    assert_eq!(code(&["--mode", "exit", "--probe-fork"]), Some(2));
}

// A probe that cannot run here exits 2 instead of passing as a no-op.
// 이것을 실패시키는 것: 지원하지 않는 플랫폼의 프로브를 no-op로 받아들이는 것(probes_supported 검사 삭제).
#[test]
fn unsupported_probes_exit_2() {
    let x86_64_linux = cfg!(all(target_os = "linux", target_arch = "x86_64"));
    if !x86_64_linux {
        assert_eq!(code(&["--mode", "sandbox", "--probe-x32"]), Some(2));
        assert_eq!(code(&["--probe-x32"]), Some(2));
        assert_eq!(code(&["--mode", "sandbox", "--probe-fork"]), Some(2));
    }
    if !cfg!(target_os = "linux") {
        assert_eq!(code(&["--probe-clone3"]), Some(2));
    }
}

// 이것을 실패시키는 것: x86_64에서 x32 필터 설치 줄을 지우는 것(프로브가 살아남아 R을 냄).
// 대조: 필터 없는 bare에서는 같은 프로브가 살아남는다.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[test]
fn sandbox_kills_x32_calls() {
    use std::os::unix::process::ExitStatusExt;
    assert_eq!(run(&["--mode", "bare", "--probe-x32"]), b"R");
    let st = stub(&["--mode", "sandbox", "--probe-x32"])
        .output()
        .unwrap()
        .status;
    assert_eq!(st.signal(), Some(libc::SIGSYS), "{st:?}");
}

// 이것을 실패시키는 것: x86_64의 fork·vfork 거부 규칙 중 하나를 빼는 것.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[test]
fn sandbox_blocks_legacy_fork_calls() {
    assert_eq!(run(&["--mode", "sandbox", "--probe-fork"]), b"FR");
}

// 이것을 실패시키는 것: clone3 필터(ENOSYS)를 설치하지 않는 것. host가 이미 clone3를 막으면
// (docker 기본 seccomp 프로필) 대조인 bare도 C를 내어 가려진다. 그때는 캡처되지 않는 stderr에
// 알리고, BINGSU_REQUIRE_CLONE3_CONTROL=1(CI)이면 실패한다.
// 이것을 실패시키는 것(대조): 변수가 켜진 채 판별 불가인 곳에서 통과하는 것.
#[cfg(target_os = "linux")]
#[test]
fn sandbox_blocks_clone3() {
    use std::io::Write;
    let control = run(&["--mode", "bare", "--probe-clone3"]);
    assert!(control == b"R" || control == b"CR", "{control:?}");
    if control == b"CR" {
        let msg = "clone3 is ENOSYS without the filter on this host (docker's default seccomp profile?): sandbox_blocks_clone3 cannot tell the filter apart";
        assert!(
            std::env::var_os("BINGSU_REQUIRE_CLONE3_CONTROL").is_none_or(|v| v != "1"),
            "{msg}"
        );
        // Bypasses the test harness capture so a passing run still shows it.
        let _ = writeln!(std::io::stderr().lock(), "NOTE: {msg}");
    }
    assert_eq!(run(&["--mode", "sandbox", "--probe-clone3"]), b"CR");
}

// 이것을 실패시키는 것: --report-vm 갈래를 지우거나, VmSize 줄을 찾지 못해 "unknown"을 내는 것.
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
