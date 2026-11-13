//! `bingsu doctor` through the real binary: the checks and their statuses
//! on good and bad fixtures, the exit code, and that it runs no other
//! program, writes nothing and never reads a version from a path.
#![cfg(unix)]

#[path = "../../bingsu-core-tests/src/json_schema.rs"]
mod json_schema;
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

/// The line of the check titled `title` (the title column is 16 wide after the 10-wide status).
fn line<'a>(out: &'a str, title: &str) -> &'a str {
    out.lines()
        .find(|l| l.get(10..26).map(str::trim) == Some(title))
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
        "hook version",
        "hook order",
        "envelope",
        "breaker",
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

/// The source of `doctor.rs` and `doctor_evidence.rs` without their test modules.
fn doctor_source() -> String {
    [
        include_str!("../src/commands/doctor.rs"),
        include_str!("../src/commands/doctor_evidence.rs"),
    ]
    .iter()
    .map(|all| {
        let all = all.replace("\r\n", "\n");
        all.split("#[cfg(test)]").next().unwrap().to_owned()
    })
    .collect()
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

/// The string value of `"name":"…"` in one item's JSON text (`None` for null).
fn field(item: &str, name: &str) -> Option<String> {
    let key = format!("\"{name}\":");
    let rest = &item[item.find(&key)? + key.len()..];
    let rest = rest.strip_prefix('"')?;
    let mut out = String::new();
    let mut chars = rest.chars();
    while let Some(c) = chars.next() {
        match c {
            '"' => return Some(out),
            '\\' => out.push(chars.next()?),
            c => out.push(c),
        }
    }
    None
}

fn json_run(e: &Env, extra: &[(&str, &str)]) -> (Option<i32>, String) {
    let mut c = e.cmd(&["doctor", "--format", "json"]);
    for (k, v) in extra {
        c.env(k, v);
    }
    let o = c.output().unwrap();
    (o.status.code(), text(&o.stdout))
}

// The JSON has the same checks, statuses, lines and codes as the text, matches the schema, and carries the same
// exit code.
// 이것을 실패시키는 것: json의 항목·상태·문구·코드가 사람용 출력과 갈라지는 것, 필드 이름을 바꾸거나 더하는 것(스키마),
// result·exit_code가 실패 종료와 어긋나는 것.
#[test]
fn doctor_json_says_what_the_text_says() {
    let e = Env::new("cli_doctor", "json");
    e.put_config("config.toml", "colr = 1\n");
    let (code, doc) = json_run(&e, &[]);
    assert_eq!(code, Some(1), "{doc}");
    if let Err(err) = json_schema::validate(None, &[&doc]) {
        panic!("{err}\n{doc}");
    }
    let t = text(&doctor(&e, &[]).stdout);
    assert!(
        doc.contains("\"result\":\"invalid\"") && doc.contains("\"exit_code\":1"),
        "{doc}"
    );
    let items: Vec<&str> = doc.split("{\"id\":").skip(1).collect();
    assert_eq!(
        items.len(),
        t.lines().filter(|l| l.starts_with("  ")).count(),
        "{doc}"
    );
    for item in &items {
        let title = field(item, "title").unwrap();
        let l = line(&t, &title);
        assert!(l.contains(&field(item, "text").unwrap()), "{l} / {item}");
        assert!(
            l.starts_with(&format!("  {}", field(item, "status").unwrap())),
            "{l} / {item}"
        );
        match field(item, "fix") {
            Some(code) => assert!(l.contains(&format!("({code}; bingsu help {code})")), "{l}"),
            None => assert!(!l.contains("bingsu help"), "{l}"),
        }
    }
    let settings = items
        .iter()
        .find(|i| i.starts_with("\"settings\""))
        .unwrap();
    assert_eq!(
        (
            field(settings, "status").as_deref(),
            field(settings, "fix").as_deref()
        ),
        (Some("fail"), Some("E607"))
    );
    // A run with nothing failed is valid, exit 0.
    e.put_config("config.toml", "icons = \"ascii\"\n");
    let (code, doc) = json_run(&e, &[]);
    assert_eq!(code, Some(0), "{doc}");
    assert!(
        doc.contains("\"result\":\"valid\"") && doc.contains("\"exit_code\":0"),
        "{doc}"
    );
    json_schema::validate(None, &[&doc]).unwrap();
}

// A value of the environment is never in the output: a pin variable that is garbled is reported as garbled, not shown.
// 이것을 실패시키는 것: BINGSU_ROOTS·PATH의 값을 json(또는 text)에 그대로 넣는 것.
#[test]
fn doctor_never_prints_an_environment_value() {
    let e = Env::new("cli_doctor", "envvalue");
    let secret = "topsecretvalue";
    let (_, doc) = json_run(&e, &[("BINGSU_ROOTS", secret)]);
    assert!(doc.contains("\"id\":\"roots-pin\""), "{doc}");
    assert!(!doc.contains(secret), "{doc}");
    let t = text(&doctor(&e, &[("BINGSU_ROOTS", secret)]).stdout);
    assert!(!t.contains(secret), "{t}");
}

// 이것을 실패시키는 것: 모르는 형식·중복·값 없는 `--format`, 그 밖의 인자를 받는 것.
#[test]
fn a_wrong_format_exits_2() {
    let e = Env::new("cli_doctor", "usage");
    for args in [
        vec!["doctor", "--format"],
        vec!["doctor", "--format", "xml"],
        vec!["doctor", "--format", "json", "--format", "json"],
        vec!["doctor", "extra"],
    ] {
        let o = e.cmd(&args).output().unwrap();
        assert_eq!(o.status.code(), Some(2), "{args:?}");
        assert!(o.stdout.is_empty(), "{args:?}");
    }
}

// A value that is not init's gives no folder path and no "gone" verdict: the check says it cannot read the value.
// 이것을 실패시키는 것: 전체 해석이 실패한 BINGSU_ROOTS에서 런타임 폴더 경로를 뽑아 "사라짐"·"바뀜"으로 판정하거나 그 경로를 출력하는 것.
#[test]
fn a_value_that_is_not_inits_gives_no_path() {
    let e = Env::new("cli_doctor", "notinits");
    let mut words = e.pinned_words();
    // Right framing and every word valid, but the home is another user's: not what init wrote for this account.
    for w in &mut words {
        if w.starts_with(b"--home=") {
            *w = b"--home=/nonexistent/other-user".to_vec();
        }
    }
    let o = e.cmd_pinned(&["doctor"], &frame(&words)).output().unwrap();
    let t = text(&o.stdout);
    let l = line(&t, "pinned folders");
    assert!(
        l.starts_with("  fail") && l.contains("E604") && l.contains("not a value init wrote"),
        "{t}"
    );
    assert!(
        !t.contains(e.base.to_str().unwrap()) || !l.contains(e.base.to_str().unwrap()),
        "{l}"
    );
    assert!(!l.contains("gone") && !l.contains("inode"), "{l}");
    let (_, doc) = {
        let mut c = e.cmd_pinned(&["doctor", "--format", "json"], &frame(&words));
        let o = c.output().unwrap();
        (o.status.code(), text(&o.stdout))
    };
    assert!(!doc.contains("run/bingsu"), "{doc}");
}

// The doctor document says invalid exactly when a check failed or none could be made.
// 이것을 실패시키는 것: fail 항목이 있는데 valid·종료 0을 받는 스키마, 점검을 못 한 문서가 items·exit_code 없이 통과하는 것,
// 일반 실패 문서가 doctor 이름으로 통과하는 것.
#[test]
fn the_schema_ties_result_and_exit_code_to_the_items() {
    let item = |status: &str| {
        format!(
            "{{\"id\":\"x\",\"title\":\"x\",\"status\":\"{status}\",\"text\":\"t\",\"fix\":null}}"
        )
    };
    let doc = |result: &str, items: &str, code: u8, error: &str| {
        format!(
            "{{\"schema\":1,\"command\":\"doctor\",\"result\":\"{result}\",\"items\":[{items}],\"exit_code\":{code},\"error\":{error}}}"
        )
    };
    let ok = [
        doc("valid", &item("ok"), 0, "null"),
        doc(
            "valid",
            &format!("{},{}", item("warn"), item("unknown")),
            0,
            "null",
        ),
        doc(
            "invalid",
            &format!("{},{}", item("ok"), item("fail")),
            1,
            "null",
        ),
        doc("invalid", "", 1, "\"cannot read the account\""),
    ];
    let bad = [
        doc("valid", &item("fail"), 0, "null"),
        doc(
            "valid",
            &format!("{},{}", item("ok"), item("fail")),
            1,
            "null",
        ),
        doc("invalid", &item("fail"), 0, "null"),
        doc("invalid", &item("ok"), 1, "null"),
        doc("valid", "", 0, "\"cannot read the account\""),
        r#"{"schema":1,"command":"doctor","result":"invalid","diagnostics":[],"error":"x"}"#
            .to_owned(),
        r#"{"schema":1,"command":"doctor","result":"invalid","items":[],"exit_code":1}"#.to_owned(),
    ];
    for d in &ok {
        json_schema::validate(None, &[d]).unwrap_or_else(|e| panic!("{e}\n{d}"));
    }
    for d in &bad {
        assert!(json_schema::validate(None, &[d]).is_err(), "accepted: {d}");
    }
}

const GOOD: [&str; 10] = [
    "doctor-evidence-v1",
    "zsh",
    "5.9",
    "0123456789abcdef0123456789abcdef",
    "1",
    "B1",
    "_bingsu_save\x1dother\x1d_bingsu_install",
    "_bingsu_preexec",
    "--width\x1d80\x1d--status\x1d0\x1d--pipestatus\x1d0\x1d--jobs\x1d0\x1d--keymap\x1dmain",
    "",
];

fn record(f: &[&str; 10]) -> Vec<u8> {
    let mut out = f.join("\x1f").into_bytes();
    out.push(0x1e);
    out
}

/// `bingsu doctor --evidence-stdin` with `input` on standard input.
#[allow(clippy::disallowed_methods, reason = "a test feeding a child's stdin")]
fn with_evidence(e: &Env, input: &[u8], extra: &[&str]) -> (Option<i32>, String, String) {
    use std::io::Write as _;
    use std::process::Stdio;
    let mut c = e.cmd(&["doctor", "--evidence-stdin"]);
    c.args(extra)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = c.spawn().unwrap();
    // A thread writes: doctor stops reading at its limit and answers while a longer record is still being
    // written, and its answer must be read meanwhile (a full pipe on both sides would stand still). Writing
    // after it has stopped reading is expected to fail.
    let mut stdin = child.stdin.take().unwrap();
    let data = input.to_vec();
    let writer = std::thread::spawn(move || {
        let _ = stdin.write_all(&data);
    });
    let o = child.wait_with_output().unwrap();
    writer.join().unwrap();
    (o.status.code(), text(&o.stdout), quiet(&o.stderr))
}

// With a good record the four shell checks say ok and show what the shell said; the run exits 0.
// 이것을 실패시키는 것: 증거를 읽지 않고 unknown으로 두는 것, 정상 증거에서 경고·실패를 내는 것.
#[test]
fn good_evidence_makes_the_shell_checks_ok() {
    let e = Env::new("cli_doctor", "evidence-ok");
    e.put_config("config.toml", "icons = \"ascii\"\n");
    let (code, t, err) = with_evidence(&e, &record(&GOOD), &[]);
    assert_eq!((code, err.as_str()), (Some(0), ""), "{t}");
    for title in ["shell", "hook version", "hook order", "envelope"] {
        assert!(line(&t, title).starts_with("  ok"), "{title}: {t}");
    }
    assert!(line(&t, "shell").contains("zsh 5.9"), "{t}");
    assert!(
        line(&t, "envelope").contains("--width 80 --status 0"),
        "{t}"
    );
}

// Each shell check fails or warns on its own bad evidence and the others stay ok.
// 이것을 실패시키는 것: 항목이 다른 항목의 증거를 읽는 것, 가로챈 hook·바뀐 봉투·낡은 셸·모르는 레코드 버전을 놓치는 것.
#[test]
fn bad_evidence_is_found_by_the_check_it_belongs_to() {
    let e = Env::new("cli_doctor", "evidence-bad");
    e.put_config("config.toml", "icons = \"ascii\"\n");
    let cases: [(usize, &str, &str, &str, &str); 5] = [
        (2, "5.7", "shell", "  warn", "W611"),
        (5, "B2", "hook version", "  fail", "E608"),
        (
            6,
            "other\x1d_bingsu_save\x1d_bingsu_install",
            "hook order",
            "  warn",
            "W609",
        ),
        (
            8,
            "--width\x1d80\x1d--status\x1d0\x1d--pipestatus\x1d0\x1d--keymap\x1dmain",
            "envelope",
            "  warn",
            "W610",
        ),
        (
            8,
            "--width\x1d80\x1d--status\x1d256\x1d--pipestatus\x1d0\x1d--jobs\x1d0\x1d--keymap\x1dmain",
            "envelope",
            "  warn",
            "W610",
        ),
    ];
    for (at, value, title, status, code) in cases {
        let mut f = GOOD;
        f[at] = value;
        let (exit, t, _) = with_evidence(&e, &record(&f), &[]);
        let l = line(&t, title);
        assert!(l.starts_with(status) && l.contains(code), "{title}: {t}");
        for other in ["shell", "hook version", "hook order", "envelope"]
            .into_iter()
            .filter(|o| *o != title)
        {
            assert!(
                line(&t, other).starts_with("  ok"),
                "{other} with a bad {title}: {t}"
            );
        }
        assert_eq!(exit, Some(i32::from(status == "  fail")), "{t}");
    }
}

// A record that is not one is refused by the shell checks only; the other checks run as always.
// 이것을 실패시키는 것: 형식이 틀린 증거로 전체를 실패시키는 것, 거부 사실을 숨기는 것, 값을 정상으로 읽는 것.
#[test]
fn a_refused_record_leaves_the_other_checks_alone() {
    let e = Env::new("cli_doctor", "evidence-refused");
    e.put_config("config.toml", "icons = \"ascii\"\n");
    let mut no_end = record(&GOOD);
    no_end.pop();
    for input in [Vec::new(), no_end, b"garbage".to_vec(), vec![b'a'; 70_000]] {
        let (code, t, _) = with_evidence(&e, &input, &[]);
        assert_eq!(code, Some(0), "{t}");
        for title in ["shell", "hook version", "hook order", "envelope"] {
            let l = line(&t, title);
            assert!(
                l.starts_with("  unknown") && l.contains("refused"),
                "{title}: {t}"
            );
        }
        assert!(line(&t, "settings").starts_with("  ok"), "{t}");
    }
}

// Without the evidence flag the shell checks say how to get it, and nothing reads standard input.
// 이것을 실패시키는 것: 플래그 없이 표준 입력을 읽는 것(터미널을 붙잡음), 안내를 빼는 것.
#[test]
fn without_evidence_the_shell_checks_say_how_to_get_it() {
    let e = Env::new("cli_doctor", "evidence-none");
    let o = e
        .cmd(&["doctor"])
        .stdin(std::process::Stdio::null())
        .output()
        .unwrap();
    let t = text(&o.stdout);
    for title in ["shell", "hook version", "hook order", "envelope"] {
        let l = line(&t, title);
        assert!(
            l.starts_with("  unknown") && l.contains("bingsu_doctor"),
            "{title}: {t}"
        );
    }
    // The flag may come with the format, in either order, once each.
    let (code, doc, _) = with_evidence(&e, &record(&GOOD), &["--format", "json"]);
    assert_eq!(code, Some(0));
    assert!(
        doc.contains("\"id\":\"hook-order\"") && doc.contains("\"status\":\"ok\""),
        "{doc}"
    );
    json_schema::validate(None, &[&doc]).unwrap();
    let o = e
        .cmd(&["doctor", "--evidence-stdin", "--evidence-stdin"])
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(2));
}

// The evidence is shown cleaned: a control character in a function name never reaches the terminal.
// 이것을 실패시키는 것: 증거의 이름을 정제하지 않고 출력하는 것.
#[test]
fn evidence_is_cleaned_in_the_output() {
    let e = Env::new("cli_doctor", "evidence-clean");
    let mut f = GOOD;
    f[6] = "evil\u{1b}[2J\x1d_bingsu_install";
    let (_, t, _) = with_evidence(&e, &record(&f), &[]);
    assert!(!t.contains('\u{1b}'), "{t:?}");
    assert!(line(&t, "hook order").contains("W609"), "{t}");
}

/// The record of `GOOD` with its version field padded so the whole record is `total` bytes.
fn padded_to(total: usize) -> Vec<u8> {
    let base = record(&GOOD).len();
    let version = format!("5.9{}", "x".repeat(total - base));
    let mut f = GOOD;
    f[2] = &version;
    let out = record(&f);
    assert_eq!(out.len(), total);
    out
}

// The size limit is 64 KiB, exactly: a record of that size is read, one byte more is refused.
// 이것을 실패시키는 것: 상한을 한 바이트 낮추거나 높이는 것(`>`를 `>=`로, 상한에 1을 더함).
#[test]
fn the_record_limit_is_exactly_64_kib() {
    let e = Env::new("cli_doctor", "evidence-limit");
    e.put_config("config.toml", "icons = \"ascii\"\n");
    let (_, at, _) = with_evidence(&e, &padded_to(64 * 1024), &[]);
    assert!(line(&at, "shell").starts_with("  ok"), "{at}");
    let (_, over, _) = with_evidence(&e, &padded_to(64 * 1024 + 1), &[]);
    let l = line(&over, "shell");
    assert!(
        l.starts_with("  unknown") && l.contains("refused"),
        "{over}"
    );
}

// A second record behind the first is refused, even when each looks fine.
// 이것을 실패시키는 것: 레코드 안의 두 번째 끝 표지(0x1e)를 보지 않는 것.
#[test]
fn a_second_record_is_refused() {
    let e = Env::new("cli_doctor", "evidence-two");
    let mut f = GOOD;
    f[2] = "5.9\x1e";
    let (_, t, _) = with_evidence(&e, &record(&f), &[]);
    let l = line(&t, "shell");
    assert!(
        l.starts_with("  unknown") && l.contains("refused") && l.contains("more than one"),
        "{t}"
    );
}

/// Waits for `child` up to `secs` seconds (polling on a short sleep); `None` when it is still running.
fn wait_for(child: &mut std::process::Child, secs: u64) -> Option<std::process::ExitStatus> {
    let end = std::time::Instant::now() + std::time::Duration::from_secs(secs);
    loop {
        if let Some(st) = child.try_wait().unwrap() {
            return Some(st);
        }
        if std::time::Instant::now() >= end {
            return None;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
}

// An input that never ends is read only up to the limit: doctor answers (refused) instead of reading on.
// 이것을 실패시키는 것: 읽는 양을 제한하는 `.take(...)`를 없애는 것(끝없는 입력에서 doctor가 끝나지 않는다).
#[test]
fn an_endless_input_is_cut_at_the_limit() {
    use std::process::{Command, Stdio};
    let e = Env::new("cli_doctor", "evidence-endless");
    let mut yes = Command::new("yes")
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut doctor = e
        .cmd(&["doctor", "--evidence-stdin"])
        .stdin(Stdio::from(yes.stdout.take().unwrap()))
        // A file, not a pipe: nothing reads the output while this waits.
        .stdout(Stdio::from(
            std::fs::File::create(e.base.join("endless.out")).unwrap(),
        ))
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let done = wait_for(&mut doctor, 10);
    let _ = yes.kill();
    let _ = yes.wait();
    if done.is_none() {
        let _ = doctor.kill();
        let _ = doctor.wait();
        panic!("doctor did not stop reading an endless input");
    }
    let out = std::fs::read_to_string(e.base.join("endless.out")).unwrap();
    let l = line(&out, "shell");
    assert!(l.starts_with("  unknown") && l.contains("refused"), "{out}");
}

// With a terminal on standard input doctor does not wait for a record: it says what to run and exits 2.
// 이것을 실패시키는 것: 표준 입력이 터미널인지 보지 않는 것(사람이 친 입력을 기다리며 멈춘다).
#[test]
fn a_terminal_on_standard_input_is_refused() {
    use std::os::fd::{FromRawFd as _, OwnedFd};
    use std::process::Stdio;
    let e = Env::new("cli_doctor", "evidence-tty");
    let (mut master, mut slave) = (0, 0);
    // SAFETY: openpty writes two descriptors; the null pointers ask for no name, termios or size.
    let rc = unsafe {
        libc::openpty(
            &mut master,
            &mut slave,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    assert_eq!(rc, 0);
    // SAFETY: both descriptors are new and owned here.
    let master = unsafe { OwnedFd::from_raw_fd(master) };
    // SAFETY: as above.
    let slave = unsafe { OwnedFd::from_raw_fd(slave) };
    let mut c = e
        .cmd(&["doctor", "--evidence-stdin"])
        .stdin(Stdio::from(slave))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let done = wait_for(&mut c, 20);
    if done.is_none() {
        let _ = c.kill();
        let _ = c.wait();
        panic!("doctor waited for a record on a terminal");
    }
    let o = c.wait_with_output().unwrap();
    drop(master);
    assert_eq!(o.status.code(), Some(2));
    assert!(o.stdout.is_empty());
    assert!(
        text(&o.stderr).contains("bingsu_doctor"),
        "{}",
        text(&o.stderr)
    );
}

// The breaker row reads the session the shell passed: with a session and no record it is ok, without a
// session of the right shape it says it cannot tell (and shows no other session's state).
// 이것을 실패시키는 것: 세션 없이 아무 세션의 차단기를 보이는 것, 기록이 없는 것을 경고로 매기는 것, 증거가 없는데 정상으로 매기는 것.
#[test]
fn the_breaker_row_needs_the_session() {
    let e = Env::new("cli_doctor", "breaker");
    e.put_config("config.toml", "icons = \"ascii\"\n");
    let _ = e.pinned_words();
    let (code, t, _) = with_evidence(&e, &record(&GOOD), &[]);
    assert_eq!(code, Some(0), "{t}");
    let l = line(&t, "breaker");
    assert!(
        l.starts_with("  ok") && l.contains("no breaker record"),
        "{t}"
    );
    let mut f = GOOD;
    f[3] = "";
    let (_, t, _) = with_evidence(&e, &record(&f), &[]);
    let l = line(&t, "breaker");
    assert!(
        l.starts_with("  unknown") && l.contains("another session"),
        "{t}"
    );
    let o = e
        .cmd(&["doctor"])
        .stdin(std::process::Stdio::null())
        .output()
        .unwrap();
    let t = text(&o.stdout);
    assert!(line(&t, "breaker").starts_with("  unknown"), "{t}");
}
