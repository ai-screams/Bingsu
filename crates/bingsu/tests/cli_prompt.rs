//! Golden vectors for the shell input envelope and version negotiation
//! (spec section 5 "shell input envelope", section 3 "record version
//! negotiation"). An envelope without `--shell` (every vector below but
//! `rendered_*`) yields the minimal record with a status; with `--shell` the
//! built-in default theme is rendered.
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
    let mut v = b"B1\x1f8\x1f> \x1f\x1f\x1f\x1f\x1f\x1f\x1f".to_vec();
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
    // /r is a syntax fixture, not an init-pinned runtime directory.
    let ok = minimal("degraded:runtime-root");
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
    check(
        "unknown_flag_before_record",
        ["--foo", "--record", "B1", "--ctx", "1", "--width", "80"]
            .iter()
            .map(|s| s.as_bytes().to_vec())
            .collect(),
        &bad,
    );
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
    // A shape-only root (R3 I-1) leaves the B1 record byte for byte unchanged.
    // 이것을 실패시키는 것: 프롬프트가 모양 전용 표식을 모르는 인자로 거부하는 것, 중복을 받아 주는 것.
    check(
        "config_root_shape_only",
        with(&[
            "--config-root=/c",
            "--config-root-written=/w/c",
            "--config-root-shape-only",
        ]),
        &ok,
    );
    check(
        "config_root_shape_only_dup",
        with(&["--config-root-shape-only", "--config-root-shape-only"]),
        &bad,
    );
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

// 이것을 실패시키는 것: 쓰기가 실패했을 때 0이 아닌 코드로 끝나거나 EPIPE에서 stderr에 쓰는 것.
// read end를 자식 spawn 전에 닫아 첫 write가 반드시 EPIPE가 된다(경쟁 없음).
#[test]
fn closed_stdout_is_silent_and_exits_zero() {
    use std::os::fd::FromRawFd;
    let mut fds = [0i32; 2];
    // SAFETY: fds is a valid two-element array for pipe(2).
    assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
    // SAFETY: fds[0] is an open descriptor we own and no longer need.
    assert_eq!(unsafe { libc::close(fds[0]) }, 0);
    // SAFETY: fds[1] was just returned by pipe(2) and is not owned elsewhere.
    let w = unsafe { std::os::fd::OwnedFd::from_raw_fd(fds[1]) };
    let out = Command::new(env!("CARGO_BIN_EXE_bingsu"))
        .arg("prompt")
        .args(BASE)
        .stdout(Stdio::from(w))
        .stderr(Stdio::piped())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0));
    assert!(out.stderr.is_empty());
}

// 이것을 실패시키는 것: `--shell`이 있는 봉투에 최소 레코드를 내는 것, 레코드 틀(머리·필드 수·끝)이나 상태를 바꾸는 것,
// 프롬프트 중 stderr에 쓰는 것.
#[test]
fn rendered_record_for_each_shell() {
    for shell in ["zsh", "bash", "fish"] {
        let args = with(&[
            "--shell",
            shell,
            "--pwd",
            "/srv/vis-prompt",
            "--status",
            "1",
        ]);
        let refs: Vec<&[u8]> = args.iter().map(Vec::as_slice).collect();
        let out = run(&refs);
        assert_eq!(out.status.code(), Some(0), "{shell}");
        assert!(out.stderr.is_empty(), "{shell}");
        let rec = out.stdout;
        assert!(
            rec.starts_with(b"B1\x1f8\x1f") && rec.ends_with(b"\x1fdegraded:runtime-root\x1e"),
            "{shell}"
        );
        assert_eq!(rec.iter().filter(|&&b| b == 0x1f).count(), 9, "{shell}");
        let text = String::from_utf8_lossy(&rec);
        assert!(
            text.contains("vis-prompt") && text.contains('\u{2717}'),
            "{shell}: {text:?}"
        );
    }
}

// The prompt path reads no environment variable (spec section 4 "runtime
// root" 7): the same arguments give the same bytes with an empty
// environment and with a hostile one. strace cannot see environment reads
// (they are memory reads) or vDSO clock reads; this behavior test can.
// 이것을 실패시키는 것: 앞단(어댑터나 core)이 환경 변수나 시계로 출력을 바꾸는 것.
#[test]
fn output_does_not_depend_on_the_environment() {
    let hostile: [(&str, &str); 15] = [
        ("HOME", "/repo/evil"),
        ("PWD", "/repo/evil/$(touch x)"),
        ("BINGSU_LOG", "trace"),
        ("BINGSU_CONFIG", "/repo/evil/c.toml"),
        ("COLORTERM", "truecolor"),
        ("LC_ALL", "ko_KR.UTF-8"),
        ("LANG", "tr_TR.UTF-8"),
        ("TZ", "Asia/Seoul"),
        ("XDG_RUNTIME_DIR", "/repo/evil/run"),
        ("XDG_CONFIG_HOME", "/repo/evil/cfg"),
        ("XDG_STATE_HOME", "/repo/evil/state"),
        ("XDG_CACHE_HOME", "/repo/evil/cache"),
        ("USER", "repo-controlled-user"),
        ("COLUMNS", "3"),
        ("NO_COLOR", "1"),
    ];
    let cases: [&[&str]; 4] = [
        &[],
        &["--shell", "zsh", "--pwd", "/srv/p", "--status", "1"],
        &["--shell", "bash", "--pwd", "/srv/p"],
        &["--shell", "fish", "--pwd", "/srv/p"],
    ];
    for extra in cases {
        let args = with(extra);
        let run = |envs: &[(&str, &str)]| {
            let mut c = Command::new(env!("CARGO_BIN_EXE_bingsu"));
            c.arg("prompt").env_clear().envs(envs.iter().copied());
            for a in &args {
                c.arg(std::ffi::OsStr::from_bytes(a));
            }
            c.stdin(Stdio::null()).output().unwrap()
        };
        let clean = run(&[]);
        let dirty = run(&hostile);
        assert_eq!(clean.status.code(), Some(0));
        assert!(!clean.stdout.is_empty(), "{extra:?}");
        // 이것을 실패시키는 것: 중복 width로 bad-args를 비교하거나 셸 렌더를 건너뛰는 것.
        assert!(
            !clean.stdout.windows(14).any(|w| w == b"error:bad-args\x1e"),
            "{extra:?}"
        );
        if !extra.is_empty() {
            assert!(clean.stdout.windows(5).any(|w| w == b"/srv/"), "{extra:?}");
        }
        assert_eq!(clean.stdout, dirty.stdout, "{extra:?}");
        assert_eq!(
            (clean.stderr.len(), dirty.stderr.len()),
            (0, 0),
            "{extra:?}"
        );
    }
}

// 이것을 실패시키는 것: sticky 다음 소유자 의무 또는 상위 권한·로컬 검사를 생략하는 것.
#[test]
fn runtime_root_path_examples() {
    use bingsu_core::fs_trust::{AclFacts, Facts, Last, RefuseGroupWrite, walk_verdict};
    let me = 1000;
    let fact = |uid: u32, mode: u32| Facts {
        dev: 1,
        ino: 1,
        uid,
        gid: uid,
        mode: 0o040000 | mode,
        acl: AclFacts::None,
        ownership: Some(true),
    };
    let root = fact(0, 0o755);
    let mine = fact(me, 0o700);
    let sticky = fact(0, 0o1777);
    let examples = [
        (
            "/run/user/<uid>/bingsu",
            vec![root, root, root, mine, mine],
            true,
        ),
        (
            "/private/var/folders/xx/yyy/T/bingsu",
            vec![root, root, root, root, root, mine, mine, mine],
            true,
        ),
        (
            "/tmp/<user-owned>/bingsu",
            vec![root, sticky, mine, mine],
            true,
        ),
        (
            "/tmp/<root-or-other-owned>/bingsu",
            vec![root, sticky, root, mine],
            false,
        ),
        (
            "~/.cache/bingsu/run",
            vec![root, root, mine, mine, mine, mine],
            true,
        ),
    ];
    for (path, facts, accepted) in examples {
        let verdict = walk_verdict(
            &facts,
            me,
            Last::PrivateFolder,
            Some(true),
            &mut RefuseGroupWrite,
        );
        assert_eq!(verdict.is_ok(), accepted, "{path}: {verdict:?}");
        println!("{path}: {accepted}");
    }
    // The cache example is conditional: neither a writable home nor a network home passes.
    for (mode, local) in [(0o775, Some(true)), (0o700, Some(false)), (0o700, None)] {
        assert!(
            walk_verdict(
                &[root, fact(me, mode), mine, mine, mine],
                me,
                Last::PrivateFolder,
                local,
                &mut RefuseGroupWrite
            )
            .is_err()
        );
    }
    assert!(
        walk_verdict(
            &[root, sticky, fact(2000, 0o700), mine],
            me,
            Last::PrivateFolder,
            Some(true),
            &mut RefuseGroupWrite
        )
        .is_err()
    );
}
