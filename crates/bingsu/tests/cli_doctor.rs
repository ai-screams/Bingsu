//! `bingsu doctor` through the real binary: the checks and their statuses
//! on good and bad fixtures, the exit code, and that it runs no other
//! program, writes nothing and never reads a version from a path.
#![cfg(unix)]

#[path = "support/user_env.rs"]
mod user_env;
use user_env::{Env, frame, quiet, text};

fn doctor(e: &Env, extra: &[(&str, &str)]) -> std::process::Output {
    let mut c = e.cmd(&["doctor"]);
    for (k, v) in extra {
        c.env(k, v);
    }
    c.output().unwrap()
}

fn line<'a>(out: &'a str, title: &str) -> &'a str {
    out.lines()
        .find(|l| l.split_whitespace().nth(1) == title.split_whitespace().next())
        .unwrap_or_else(|| panic!("no line for {title}: {out}"))
}

// 이것을 실패시키는 것: 점검 하나를 표에서 빼는 것, 정상 설치에서 실패 종료(1)를 내는 것, 요약 줄을 빼는 것.
#[test]
fn a_plain_run_lists_every_check_and_exits_0() {
    let e = Env::new("cli_doctor", "plain");
    e.put_config("config.toml", "icons = \"ascii\"\n");
    let o = doctor(&e, &[]);
    assert_eq!(o.status.code(), Some(0), "{}", text(&o.stderr));
    let t = text(&o.stdout);
    for title in [
        "executable",
        "bingsu on PATH",
        "pinned folders",
        "one build",
        "shell",
        "seccomp",
        "settings",
    ] {
        assert!(t.contains(title), "{title}: {t}");
    }
    assert!(
        t.trim_end().lines().last().unwrap().starts_with("result: "),
        "{t}"
    );
    // No pin in this shell: a warning with its code, not a failure.
    assert!(line(&t, "pinned folders").contains("W603"), "{t}");
}

// With init's pin, the pinned folder passes; after the runtime folder is made again the check fails with both
// identities and the exit code is 1.
// 이것을 실패시키는 것: 다시 만든 런타임 폴더를 같은 폴더로 보는 것, 실패인데 종료 0, 문구에서 옛·새 inode를 빼는 것.
#[test]
fn a_remade_runtime_folder_fails_the_pin_check() {
    let e = Env::new("cli_doctor", "pin");
    e.put_config("config.toml", "icons = \"ascii\"\n");
    let var = frame(&e.pinned_words());
    let run = |e: &Env| e.cmd_pinned(&["doctor"], &var).output().unwrap();
    let o = run(&e);
    let t = text(&o.stdout);
    assert!(
        line(&t, "pinned folders").trim_start().starts_with("ok"),
        "{t}"
    );
    assert_eq!(o.status.code(), Some(0), "{t}");
    let runtime = e.base.join("run/bingsu");
    // The old folder is kept under another name, so the new one cannot get its inode back.
    std::fs::rename(&runtime, e.base.join("run/bingsu-old")).unwrap();
    std::fs::create_dir(&runtime).unwrap();
    user_env::chmod(&runtime, 0o700);
    let o = run(&e);
    let t = text(&o.stdout);
    let l = line(&t, "pinned folders");
    assert!(l.trim_start().starts_with("fail"), "{t}");
    assert!(l.contains("E604") && l.contains("inode"), "{l}");
    assert_eq!(o.status.code(), Some(1), "{t}");
    // Gone altogether.
    std::fs::remove_dir(&runtime).unwrap();
    let t = text(&run(&e).stdout);
    assert!(line(&t, "pinned folders").contains("is gone"), "{t}");
}

// 이것을 실패시키는 것: 읽을 수 없는 BINGSU_ROOTS를 정상이나 "init 안 함"으로 보는 것.
#[test]
fn a_garbled_pin_fails() {
    let e = Env::new("cli_doctor", "garbled");
    let o = doctor(&e, &[("BINGSU_ROOTS", "not-a-pin")]);
    let t = text(&o.stdout);
    assert!(
        line(&t, "pinned folders").trim_start().starts_with("fail"),
        "{t}"
    );
    assert_eq!(o.status.code(), Some(1));
}

// A settings error is a failure of the settings check, with its code.
// 이것을 실패시키는 것: 설정 오류가 있는데 settings 점검이 정상이거나 종료 0.
#[test]
fn a_settings_error_fails_the_settings_check() {
    let e = Env::new("cli_doctor", "settings");
    e.put_config("config.toml", "colr = 1\n");
    let o = doctor(&e, &[]);
    let t = text(&o.stdout);
    let l = line(&t, "settings");
    assert!(
        l.trim_start().starts_with("fail") && l.contains("E607"),
        "{t}"
    );
    assert_eq!(o.status.code(), Some(1));
}

// A version that only a path or a folder name could give is never shown: the shell check stays "not confirmed".
// 이것을 실패시키는 것: $SHELL이나 PATH의 폴더 이름(.../zsh/5.9/..., bash-5.3.9)에서 셸 버전을 뽑는 것.
#[test]
fn no_version_is_read_from_a_path() {
    let e = Env::new("cli_doctor", "version");
    let fake = e.base.join("Cellar/zsh/5.9/bin");
    std::fs::create_dir_all(&fake).unwrap();
    std::fs::create_dir_all(e.base.join("bash-5.3.9/bin")).unwrap();
    let o = e
        .cmd(&["doctor"])
        .env("SHELL", fake.join("zsh"))
        .env(
            "PATH",
            format!(
                "{}:{}:/usr/bin:/bin",
                fake.display(),
                e.base.join("bash-5.3.9/bin").display()
            ),
        )
        .output()
        .unwrap();
    let t = text(&o.stdout);
    assert!(line(&t, "shell").contains("not confirmed"), "{t}");
    assert!(!t.contains("5.9") && !t.contains("5.3"), "{t}");
}

// doctor reads and reports: nothing under the settings, state and runtime folders changes.
// 이것을 실패시키는 것: doctor가 상태·런타임 폴더를 만들거나 스냅샷을 발행하는 것.
#[test]
fn doctor_writes_nothing() {
    let e = Env::new("cli_doctor", "readonly");
    e.put_config("config.toml", "icons = \"ascii\"\n");
    let before = e.tree();
    let o = doctor(&e, &[]);
    assert_eq!(o.status.code(), Some(0));
    assert_eq!(quiet(&o.stderr), "");
    assert_eq!(e.tree(), before);
}

/// The source of `doctor.rs` without its test module.
fn doctor_source() -> String {
    let all = include_str!("../src/commands/doctor.rs").replace("\r\n", "\n");
    all.split("#[cfg(test)]").next().unwrap().to_owned()
}

// doctor starts no program: its source names no way to start one, and (Linux) no `execve` happens under it.
// 이것을 실패시키는 것: doctor 소스에 `Command`나 spawn·exec를 넣는 것, 경로·셸 이름에서 버전을 읽는 `SHELL`·`Cellar` 참조.
// 확인 명령: grep -nE "Command|spawn|exec[lv]|fork|SHELL|Cellar" crates/bingsu/src/commands/doctor.rs (시험 모듈 앞부분)
#[test]
fn the_source_starts_no_program_and_reads_no_version() {
    let src = doctor_source();
    for word in [
        "Command",
        "spawn",
        "execv",
        "execl",
        "fork(",
        "SHELL",
        "Cellar",
        "--version",
    ] {
        assert!(!src.contains(word), "doctor.rs names `{word}`");
    }
}

#[cfg(target_os = "linux")]
#[test]
fn doctor_executes_nothing_under_strace() {
    use std::process::Command;
    if Command::new("strace").arg("-V").output().is_err() {
        eprintln!("skipped: strace is not installed");
        return;
    }
    let e = Env::new("cli_doctor", "strace");
    e.put_config("config.toml", "icons = \"ascii\"\n");
    // A settings file that names a command: a check must not run it.
    let canary = e.base.join("CANARY");
    e.put_config(
        "work.toml",
        &format!(
            "[segment.\"custom/c\"]\nkind = \"command\"\ncommand = [\"/bin/sh\", \"-c\", \"echo x > {}\"]\n[layout.line2]\nleft = [\"custom/c\", \"char\"]\n",
            canary.display()
        ),
    );
    let trace = e.base.join("trace.txt");
    let o = Command::new("strace")
        .args(["-f", "-qq", "-e", "trace=execve,execveat", "-o"])
        .arg(&trace)
        .arg(env!("CARGO_BIN_EXE_bingsu"))
        .arg("doctor")
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("XDG_RUNTIME_DIR", e.base.join("run"))
        .env("XDG_CONFIG_HOME", e.base.join("cfg"))
        .env("XDG_STATE_HOME", e.base.join("state"))
        .env("XDG_CACHE_HOME", e.base.join("cache"))
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(0), "{}", text(&o.stderr));
    let t = std::fs::read_to_string(&trace).unwrap();
    assert_eq!(t.lines().filter(|l| l.contains(" = 0")).count(), 1, "{t}");
    assert!(!canary.exists());
}
