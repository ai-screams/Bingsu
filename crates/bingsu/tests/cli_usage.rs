//! `-h` and `--help` through the real binary: the help on stdout and exit 0
//! when it is the only word after a command, a wrong use as before
//! otherwise. On Unix the environment is cleared: a help reads nothing.
use std::process::{Command, Output};

fn run(args: &[&str]) -> Output {
    let mut c = Command::new(env!("CARGO_BIN_EXE_bingsu"));
    c.args(args);
    // Windows needs some of its environment to start a process.
    if cfg!(unix) {
        c.env_clear();
    }
    c.output().unwrap()
}

/// Every command line that has a help.
const HELPED: [&[&str]; 14] = [
    &[],
    &["config"],
    &["config", "check"],
    &["config", "edit"],
    &["config", "path"],
    &["config", "schema"],
    &["config", "use"],
    &["doctor"],
    &["explain"],
    &["help"],
    &["init"],
    &["list"],
    &["reload"],
    &["setup"],
];

// 이것을 실패시키는 것: 도움말 분기를 지우는 것(사용법 오류 2), 도움말을 stderr로 보내는 것, 0이 아닌 코드로 끝내는 것,
// -h와 --help가 다른 글을 내는 것.
#[test]
fn help_goes_to_stdout_and_exits_0() {
    for path in HELPED {
        let mut with = path.to_vec();
        with.push("--help");
        let long = run(&with);
        assert_eq!(long.status.code(), Some(0), "{with:?} {long:?}");
        assert!(long.stderr.is_empty(), "{with:?}");
        let text = String::from_utf8(long.stdout).unwrap();
        let head = if path.is_empty() {
            String::from("bingsu: ")
        } else {
            format!("bingsu {}: ", path.join(" "))
        };
        assert!(text.starts_with(&head), "{with:?}: {text}");
        assert!(text.contains("-h, --help"), "{with:?}");
        assert!(text.lines().all(|l| l.len() <= 80), "{with:?}: {text}");
        with.pop();
        with.push("-h");
        let short = run(&with);
        assert_eq!(short.status.code(), Some(0), "{with:?}");
        assert_eq!(short.stdout, text.as_bytes(), "{with:?}");
    }
}

// 이것을 실패시키는 것: 최상위 도움말에서 사용자 명령 하나를 빼먹는 것.
#[test]
fn the_top_help_lists_every_command() {
    let text = String::from_utf8(run(&["--help"]).stdout).unwrap();
    for name in [
        "config",
        "doctor",
        "explain",
        "help",
        "init",
        "list",
        "prompt",
        "reload",
        "setup",
        "--version",
    ] {
        assert!(text.contains(&format!("\n  {name} ")), "{name}: {text}");
    }
}

// 이것을 실패시키는 것: -h·--help를 유일한 단어가 아닐 때도 도움말로 보는 것, 모르는 플래그를 0으로 끝내는 것.
// Windows builds only `help` and `--version`.
#[cfg(unix)]
#[test]
fn a_help_word_among_others_is_a_wrong_use() {
    for (args, usage) in [
        (&["setup", "--yes", "--help"][..], "usage: bingsu setup "),
        (&["setup", "--help", "--yes"], "usage: bingsu setup "),
        (&["setup", "--nope"], "usage: bingsu setup "),
        (&["--help", "setup"], "usage: bingsu <config|"),
        (&["list", "presets", "--help"], "usage: bingsu list "),
        (&["--version", "--help"], "usage: bingsu --version"),
        (&["doctor", "--help", "--terminal"], "usage: bingsu doctor "),
        (
            &["config", "check", "--explain", "-h"],
            "usage: bingsu config ",
        ),
        (&["reload", "-h", "-h"], "usage: bingsu reload"),
    ] {
        let out = run(args);
        assert_eq!(out.status.code(), Some(2), "{args:?} {out:?}");
        assert!(out.stdout.is_empty(), "{args:?}");
        let err = String::from_utf8(out.stderr).unwrap();
        assert!(err.contains(usage), "{args:?}: {err}");
    }
}

// 이것을 실패시키는 것: 도움말을 쓰지 못했는데(읽는 쪽이 닫힌 소켓) 0으로 끝내는 것.
#[cfg(unix)]
#[test]
fn a_help_that_cannot_be_written_exits_1() {
    let (ours, theirs) = std::os::unix::net::UnixStream::pair().unwrap();
    drop(ours);
    let out = Command::new(env!("CARGO_BIN_EXE_bingsu"))
        .args(["setup", "--help"])
        .env_clear()
        .stdout(std::os::fd::OwnedFd::from(theirs))
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1), "{out:?}");
}
