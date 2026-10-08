//! `spawn_in_cgroup` starts the child inside the given cgroup, in a new
//! session, with only fds 0, 1 and 2, and returns a pidfd for it.
//!
//! Needs a delegated cgroup v2 area: BINGSU_TEST_CGROUP_DIR names it (for
//! example inside `systemd-run --user --scope -p Delegate=yes`). Without it
//! the test is skipped with a NOTE, unless BINGSU_REQUIRE_CGROUP_TESTS=1
//! makes that a failure.
#![cfg(target_os = "linux")]
use bingsu_bench::sys::cgroup::spawn_in_cgroup;
use bingsu_bench::sys::spawn::{pipe_cloexec, reap};
use std::io::Read;
use std::os::fd::{AsRawFd, OwnedFd};

// 이것을 실패시키는 것: flags에서 CLONE_INTO_CGROUP을 빼는 것(자식이 부모 cgroup에서 시작),
// setsid를 빼는 것, close_range를 빼는 것(물려받은 fd가 보임), CLONE_PIDFD를 빼는 것.
// 자식은 셸이 아니라 m1-fd-report다. 셸이 `ls /proc/$$/fd | …`로 자기 fd를 나열하면 ls가 읽는 순간 셸이
// 아직 파이프라인의 파이프 fd를 쥐고 있을 수 있어(CI에서 `0 1 2 3 4 5`로 실패), 관측이 경쟁한다.
// 이것을 실패시키는 것(변수 없음): BINGSU_REQUIRE_CGROUP_TESTS=1인데 건너뛰는 것.
#[test]
fn child_starts_inside_the_cgroup() {
    let Some(area) = std::env::var_os("BINGSU_TEST_CGROUP_DIR") else {
        assert!(
            std::env::var_os("BINGSU_REQUIRE_CGROUP_TESTS").is_none_or(|v| v != "1"),
            "BINGSU_REQUIRE_CGROUP_TESTS=1 but BINGSU_TEST_CGROUP_DIR is not set"
        );
        eprintln!("NOTE: child_starts_inside_the_cgroup needs BINGSU_TEST_CGROUP_DIR; skipped");
        return;
    };
    let path = std::path::Path::new(&area).join(format!("bingsu-test-{}", std::process::id()));
    std::fs::create_dir(&path).unwrap();
    let cg: OwnedFd = std::fs::File::open(&path).unwrap().into();
    // An inheritable fd (no FD_CLOEXEC) that only close_range removes.
    let leak = bingsu_bench::sys::spawn::dup_inheritable(&cg).unwrap();
    let (r, w) = pipe_cloexec().unwrap();
    let devnull = std::fs::File::open("/dev/null").unwrap();
    let report = std::ffi::CString::new(env!("CARGO_BIN_EXE_m1-fd-report")).unwrap();
    let argv = [report.as_c_str(), c"--cgroup"];
    let envp: [&std::ffi::CStr; 0] = [];
    let (pid, pidfd) = spawn_in_cgroup(
        &cg,
        &report,
        &argv,
        &envp,
        w.as_raw_fd(),
        devnull.as_raw_fd(),
    )
    .unwrap();
    drop(w);
    drop(leak);
    let mut out = String::new();
    std::fs::File::from(r).read_to_string(&mut out).unwrap();
    // The pidfd becomes readable when the child exits.
    let mut pfd = libc::pollfd {
        fd: pidfd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: one valid pollfd; waits at most 5 s.
    let polled = unsafe { libc::poll(&mut pfd, 1, 5000) };
    let status = reap(pid).unwrap();
    drop(cg);
    std::fs::remove_dir(&path).unwrap();
    assert!(
        libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
        "status {status:#x}: {out}"
    );
    assert_eq!(
        (polled, pfd.revents & libc::POLLIN),
        (1, libc::POLLIN),
        "pidfd"
    );
    let want = path
        .strip_prefix("/sys/fs/cgroup")
        .unwrap()
        .display()
        .to_string();
    // The child's own fds >= 3 ("-": none, only stdio is left), its session
    // (a leader: its sid is its pid) and its cgroup.
    assert_eq!(
        out,
        format!("FDS -\nSID {pid}\nCGROUP 0::/{want}\n"),
        "child report"
    );
}

// Same area rule as above. 이것을 실패시키는 것: 자식 쪽 dup2 실패를 무시하는 것(그러면 자식이
// 부모의 fd 1을 물려받은 채 exec해 0으로 끝난다).
#[test]
fn failed_stdio_setup_exits_126() {
    let Some(area) = std::env::var_os("BINGSU_TEST_CGROUP_DIR") else {
        assert!(
            std::env::var_os("BINGSU_REQUIRE_CGROUP_TESTS").is_none_or(|v| v != "1"),
            "BINGSU_REQUIRE_CGROUP_TESTS=1 but BINGSU_TEST_CGROUP_DIR is not set"
        );
        eprintln!("NOTE: failed_stdio_setup_exits_126 needs BINGSU_TEST_CGROUP_DIR; skipped");
        return;
    };
    let path = std::path::Path::new(&area).join(format!("bingsu-test-126-{}", std::process::id()));
    std::fs::create_dir(&path).unwrap();
    let cg: OwnedFd = std::fs::File::open(&path).unwrap().into();
    let devnull = std::fs::File::open("/dev/null").unwrap();
    let sh = c"/bin/sh";
    let argv = [sh, c"-c", c"exit 0"];
    let envp: [&std::ffi::CStr; 0] = [];
    // Not an open fd: dup2 onto fd 1 fails with EBADF.
    let (pid, _pidfd) =
        spawn_in_cgroup(&cg, sh, &argv, &envp, 1_000_000, devnull.as_raw_fd()).unwrap();
    let status = reap(pid).unwrap();
    drop(cg);
    std::fs::remove_dir(&path).unwrap();
    assert!(
        libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 126,
        "status {status:#x}"
    );
}
