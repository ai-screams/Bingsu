//! `bingsu doctor` through the real binary: the checks and their statuses
//! on good and bad fixtures, the exit code, and that it runs no other
//! program, writes nothing and never reads a version from a path.
#![cfg(unix)]

#[path = "support/user_env.rs"]
mod user_env;
use user_env::{Env, frame, quiet, text};

/// Settings with a command segment drawn by the layout: reading them runs nothing.
fn canary_config(canary: &std::path::Path) -> String {
    format!(
        "version = 1\n[segment.\"custom/c\"]\nkind = \"command\"\ncommand = [\"/bin/sh\", \"-c\", \"echo x > {}\"]\n[layout.line2]\nleft = [\"custom/c\", \"char\"]\n",
        canary.display()
    )
}

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
    // The settings that are read name a command: a check must not run it.
    let canary = e.base.join("CANARY");
    e.put_config("config.toml", &canary_config(&canary));
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

// The settings check reads the settings and runs no command in them, on every platform.
// 이것을 실패시키는 것: doctor의 설정 점검이 설정의 명령 세그먼트를 실행하는 것(카나리 파일이 생김).
#[test]
fn doctor_does_not_run_a_configured_command() {
    let e = Env::new("cli_doctor", "canary");
    let canary = e.base.join("CANARY");
    e.put_config("config.toml", &canary_config(&canary));
    let o = doctor(&e, &[]);
    assert_eq!(o.status.code(), Some(0), "{}", text(&o.stderr));
    let t = text(&o.stdout);
    assert!(line(&t, "settings").starts_with("  ok"), "{t}");
    assert!(!canary.exists(), "the command ran");
}

// A link in a folder that others can write is a way in whatever the target is: started through such a link, the
// executable check warns and names the link.
// 이것을 실패시키는 것: 실제 대상(current_exe)만 검사해 링크 자리의 폴더를 보지 않는 것.
#[test]
fn a_link_in_a_writable_folder_is_warned_about() {
    use std::os::unix::fs::symlink;
    let e = Env::new("cli_doctor", "link");
    e.put_config("config.toml", "icons = \"ascii\"\n");
    let shared = e.base.join("shared");
    std::fs::create_dir_all(&shared).unwrap();
    user_env::chmod(&shared, 0o777);
    let link = shared.join("bingsu");
    symlink(env!("CARGO_BIN_EXE_bingsu"), &link).unwrap();
    let base = e.cmd(&["doctor"]);
    let mut c = std::process::Command::new(&link);
    c.arg("doctor").current_dir(&e.base).env_clear();
    for (k, v) in base.get_envs() {
        if let Some(v) = v {
            c.env(k, v);
        }
    }
    let o = c.output().unwrap();
    let t = text(&o.stdout);
    let l = line(&t, "executable");
    assert!(l.contains("W601") && l.contains("shared/bingsu"), "{t}");
    assert!(l.starts_with("  warn"), "{t}");
}

// The state and log folders get the checks the helper makes, not only a copy of their names.
// 이것을 실패시키는 것: 고정한 state·log 폴더를 검사 없이 통과시키는 것(남이 쓸 수 있는 폴더, 링크로 바뀐 경로).
#[test]
fn a_state_or_log_folder_that_fails_its_checks_fails_the_pin() {
    use std::os::unix::fs::symlink;
    let e = Env::new("cli_doctor", "folders");
    e.put_config("config.toml", "icons = \"ascii\"\n");
    let words = e.pinned_words();
    let run = |words: &[Vec<u8>]| {
        let o = e.cmd_pinned(&["doctor"], &frame(words)).output().unwrap();
        (o.status.code(), text(&o.stdout))
    };
    // Baseline: the state folder does not exist yet and there is no log folder.
    let (code, t) = run(&words);
    assert!(line(&t, "pinned folders").starts_with("  ok"), "{t}");
    assert_eq!(code, Some(0));
    // A state folder that others can write.
    std::fs::create_dir_all(e.state_dir()).unwrap();
    user_env::chmod(&e.state_dir(), 0o777);
    let (code, t) = run(&words);
    let l = line(&t, "pinned folders");
    assert!(
        l.starts_with("  fail") && l.contains("state") && l.contains("E604"),
        "{t}"
    );
    assert_eq!(code, Some(1));
    user_env::chmod(&e.state_dir(), 0o700);
    // A log folder that others can write.
    let log = e.base.join("state/logs");
    std::fs::create_dir_all(&log).unwrap();
    user_env::chmod(&log, 0o777);
    let mut with_log = words.clone();
    with_log.push(
        [
            b"--log-root=".as_slice(),
            log.as_os_str().as_encoded_bytes(),
        ]
        .concat(),
    );
    let (code, t) = run(&with_log);
    let l = line(&t, "pinned folders");
    assert!(l.starts_with("  fail") && l.contains("log"), "{t}");
    assert_eq!(code, Some(1));
    // The same log folder reached through a link.
    user_env::chmod(&log, 0o700);
    let via = e.base.join("state/via-link");
    symlink(&log, &via).unwrap();
    let mut linked = words.clone();
    linked.push(
        [
            b"--log-root=".as_slice(),
            via.as_os_str().as_encoded_bytes(),
        ]
        .concat(),
    );
    let (code, t) = run(&linked);
    assert!(line(&t, "pinned folders").starts_with("  fail"), "{t}");
    assert_eq!(code, Some(1));
    // Fine again.
    let mut fine = words;
    fine.push(
        [
            b"--log-root=".as_slice(),
            log.as_os_str().as_encoded_bytes(),
        ]
        .concat(),
    );
    let (code, t) = run(&fine);
    assert!(line(&t, "pinned folders").starts_with("  ok"), "{t}");
    assert_eq!(code, Some(0));
}

// A settings folder that fails its checks is a confirmed failure of the settings check (as `config check`
// exits 1), not "unknown".
// 이것을 실패시키는 것: 설정 뿌리의 확인된 거부를 모름·종료 0으로 매기는 것.
#[test]
fn a_refused_settings_folder_fails_the_settings_check() {
    let e = Env::new("cli_doctor", "refused");
    user_env::chmod(&e.config_dir(), 0o777);
    let o = doctor(&e, &[]);
    let t = text(&o.stdout);
    let l = line(&t, "settings");
    assert!(l.starts_with("  fail") && l.contains("E607"), "{t}");
    assert_eq!(o.status.code(), Some(1), "{t}");
    let c = e.run(&["config", "check"]);
    assert_eq!(c.status.code(), Some(1), "config check agrees");
}
