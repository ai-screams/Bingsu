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
    let sh = c"/bin/sh";
    let script = c"cat /proc/self/cgroup; \
        set -- $(cut -d' ' -f6 /proc/$$/stat); echo sid=$1 pid=$$; \
        ls /proc/$$/fd | sort -n | tr '\\n' ' '";
    let argv = [
        sh.as_ptr(),
        c"-c".as_ptr(),
        script.as_ptr(),
        std::ptr::null(),
    ];
    let envp = [c"PATH=/usr/bin:/bin".as_ptr(), std::ptr::null()];
    let (pid, pidfd) =
        spawn_in_cgroup(&cg, sh, &argv, &envp, w.as_raw_fd(), devnull.as_raw_fd()).unwrap();
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
    assert!(out.starts_with(&format!("0::/{want}\n")), "cgroup: {out}");
    let line = out.lines().nth(1).unwrap();
    let ids: Vec<&str> = line
        .split(' ')
        .map(|f| f.split('=').nth(1).unwrap())
        .collect();
    assert_eq!(ids[0], ids[1], "not a session leader: {line}");
    // The shell's own fds ($$, not ls): only stdio is left.
    assert_eq!(
        out.lines().nth(2).unwrap().trim_end(),
        "0 1 2",
        "fds: {out}"
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
    let argv = [
        sh.as_ptr(),
        c"-c".as_ptr(),
        c"exit 0".as_ptr(),
        std::ptr::null(),
    ];
    let envp = [std::ptr::null()];
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
