//! Golden vectors for the shell input envelope and version negotiation
//! (spec section 5 "shell input envelope", section 3 "record version
//! negotiation"). M1 has no renderer, so every accepted envelope yields the
//! minimal record with a status.
#![cfg(unix)]
use std::os::unix::ffi::OsStrExt;
use std::process::{Command, Stdio};

const BASE: &[&str] = &[
    "--ctx",
    "1",
    "--record",
    "B1",
    "--width",
    "80",
    "--runtime-root=1:2:/r",
];

fn run(args: &[&[u8]]) -> std::process::Output {
    let os: Vec<&std::ffi::OsStr> = args
        .iter()
        .map(|a| std::ffi::OsStr::from_bytes(a))
        .collect();
    Command::new(env!("CARGO_BIN_EXE_bingsu"))
        .arg("prompt")
        .args(os)
        .stdin(Stdio::null())
        .output()
        .unwrap()
}

fn minimal(status: &str) -> Vec<u8> {
    let mut v = b"B1\x1f7\x1f> \x1f\x1f\x1f\x1f\x1f\x1f".to_vec();
    v.extend_from_slice(status.as_bytes());
    v.push(0x1e);
    v
}

fn with(extra: &[&str]) -> Vec<Vec<u8>> {
    BASE.iter()
        .chain(extra)
        .map(|s| s.as_bytes().to_vec())
        .collect()
}

fn check(name: &str, args: Vec<Vec<u8>>, want: &[u8]) {
    let refs: Vec<&[u8]> = args.iter().map(Vec::as_slice).collect();
    let out = run(&refs);
    assert_eq!(out.status.code(), Some(0), "{name}: exit code");
    assert!(
        out.stderr.is_empty(),
        "{name}: stderr {:?}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        out.stdout,
        want,
        "{name}: stdout {:?}",
        String::from_utf8_lossy(&out.stdout)
    );
}

fn without(drop: &[&str]) -> Vec<Vec<u8>> {
    let mut v: Vec<Vec<u8>> = Vec::new();
    let mut skip = false;
    for a in BASE {
        if skip {
            skip = false;
            continue;
        }
        if drop.contains(a) {
            skip = !a.contains('=');
            continue;
        }
        v.push(a.as_bytes().to_vec());
    }
    v
}

// 이것을 실패시키는 것: 봉투 규칙 하나라도 다르게 구현하는 것(벡터마다 기대 바이트가 고정돼 있음).
#[test]
fn envelope_golden_vectors() {
    let ok = minimal("ok:none");
    let bad = minimal("error:bad-args");
    check("ok_minimal", with(&[]), &ok);
    check(
        "no_runtime_root",
        without(&["--runtime-root=1:2:/r"]),
        &minimal("degraded:runtime-root"),
    );
    check("record_missing", without(&["--record"]), b"");
    check(
        "record_out_of_window",
        {
            let mut v = with(&[]);
            v[3] = b"B2".to_vec();
            v
        },
        b"",
    );
    check("record_dup", with(&["--record", "B1"]), &bad);
    check("ctx_missing", without(&["--ctx"]), &bad);
    check(
        "ctx_2",
        {
            let mut v = with(&[]);
            v[1] = b"2".to_vec();
            v
        },
        &bad,
    );
    check("ctx_dup", with(&["--ctx", "1"]), &bad);
    check("width_missing", without(&["--width"]), &bad);
    check("width_dup", with(&["--width", "81"]), &bad);
    // width comes from the terminal: unusable values mean "unknown" (0), never bad-args.
    check(
        "width_leading_zero",
        {
            let mut v = with(&[]);
            v[5] = b"080".to_vec();
            v
        },
        &ok,
    );
    check(
        "width_huge",
        {
            let mut v = with(&[]);
            v[5] = b"65536".to_vec();
            v
        },
        &ok,
    );
    check(
        "width_70000",
        {
            let mut v = with(&[]);
            v[5] = b"70000".to_vec();
            v
        },
        &ok,
    );
    check(
        "width_non_numeric",
        {
            let mut v = with(&[]);
            v[5] = b"abc".to_vec();
            v
        },
        &ok,
    );
    check(
        "width_zero",
        {
            let mut v = with(&[]);
            v[5] = b"0".to_vec();
            v
        },
        &ok,
    );
    check("unknown_arg", with(&["--frobnicate"]), &bad);
    check("value_missing_at_end", with(&["--status"]), &bad);
    check(
        "ext_unknown_name_ignored",
        with(&["--ctx-ext", "future-thing=1"]),
        &ok,
    );
    check("ext_bad_name", with(&["--ctx-ext", "Bad=1"]), &bad);
    check("ext_no_eq", with(&["--ctx-ext", "name"]), &bad);
    check(
        "ext_reserved_root_id",
        with(&["--ctx-ext", "config-root-id=12:34"]),
        &ok,
    );
    check(
        "ext_reserved_root_id_bad",
        with(&["--ctx-ext", "state-root-id=012:3"]),
        &bad,
    );
    check(
        "runtime_root_malformed",
        {
            let mut v = with(&[]);
            v[6] = b"--runtime-root=012:3:/a".to_vec();
            v
        },
        &bad,
    );
    check("runtime_root_dup", with(&["--runtime-root=1:2:/s"]), &bad);
    check("config_root_relative", with(&["--config-root=rel"]), &bad);
    check("session_bad", with(&["--session", "XYZ"]), &bad);
    check("pipestatus_bad", with(&["--pipestatus", "1,,2"]), &bad);
    check("status_256", with(&["--status", "256"]), &bad);
    check("keymap_upper", with(&["--keymap", "Vicmd"]), &bad);
    check(
        "all_fields",
        with(&[
            "--status",
            "1",
            "--pipestatus",
            "0,1,141",
            "--duration-ms",
            "2500",
            "--jobs",
            "2",
            "--keymap",
            "vicmd",
            "--session",
            "0123456789abcdef0123456789abcdef",
            "--seq",
            "7",
            "--redraw",
            "--config-root=/c",
            "--state-root=/s",
            "--log-root=/s/log",
        ]),
        &ok,
    );
    check(
        "non_utf8_root",
        {
            let mut v = with(&[]);
            v[6] = b"--runtime-root=1:2:/\xff dir".to_vec();
            v
        },
        &ok,
    );
}

// 이것을 실패시키는 것: prompt가 fd 1에 O_NONBLOCK 등 상태 플래그를 바꾸는 것.
#[test]
fn prompt_does_not_change_stdout_flags() {
    let mut fds = [0i32; 2];
    // SAFETY: fds is a valid two-element array for pipe(2).
    assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
    // macOS sets an internal status bit (0x10000) on a pipe after its first
    // write by any process; prime it so the baseline already has it.
    // SAFETY: fds[1] is an open descriptor we own and the buffer is one valid byte.
    assert_eq!(unsafe { libc::write(fds[1], b"x".as_ptr().cast(), 1) }, 1);
    // SAFETY: fds[1] is an open descriptor we own.
    let before = unsafe { libc::fcntl(fds[1], libc::F_GETFL) };
    use std::os::fd::FromRawFd;
    // SAFETY: fds[1] was just returned by pipe(2) and is not owned elsewhere.
    let w = unsafe { std::os::fd::OwnedFd::from_raw_fd(fds[1]) };
    let status = Command::new(env!("CARGO_BIN_EXE_bingsu"))
        .arg("prompt")
        .args(BASE)
        .stdout(Stdio::from(w.try_clone().unwrap()))
        .status()
        .unwrap();
    assert!(status.success());
    // SAFETY: fds[1] is still open (owned by `w`).
    let after = unsafe { libc::fcntl(fds[1], libc::F_GETFL) };
    assert_eq!(before, after);
    // SAFETY: fds[0] is an open descriptor we own and no longer need.
    unsafe { libc::close(fds[0]) };
}

// 이것을 실패시키는 것: EPIPE에서 stderr에 쓰거나 0이 아닌 코드로 끝나는 것.
#[test]
fn closed_stdout_is_silent_and_exits_zero() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_bingsu"))
        .arg("prompt")
        .args(BASE)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    drop(child.stdout.take());
    let out = child.wait_with_output().unwrap();
    assert_eq!(out.status.code(), Some(0));
    assert!(out.stderr.is_empty());
}
