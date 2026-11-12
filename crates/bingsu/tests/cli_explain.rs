//! `bingsu explain` through the real binary: the text at several widths
//! (golden), that it reads and runs nothing (canary, env value, tree
//! unchanged, no exec under strace), the segment argument and the usage
//! errors.
#![cfg(unix)]
use std::path::Path;

#[path = "support/user_env.rs"]
mod user_env;
use user_env::{Env, text};

const GOLDEN: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/golden/explain/widths.txt"
);

/// Two long text segments, a band up to 40 cells, and `dir` drawn.
const LAYOUT: &str = r#"version = 1
[segment."custom/a"]
kind = "text"
text = "AAAAAAAAAAAAAAAA"
[segment."custom/b"]
kind = "text"
text = "BBBBBBBBBBBBBBBB"
[layout.line2]
left = ["custom/a", "dir", "char"]
right = ["custom/b"]
[layout.when.narrow]
max_cols = 40
"#;

/// `LAYOUT` without the band.
const LAYOUT_NO_BAND: &str = r#"version = 1
[segment."custom/a"]
kind = "text"
text = "AAAAAAAAAAAAAAAA"
[layout.line2]
left = ["custom/a", "dir", "char"]
"#;

fn canary_config(canary: &Path) -> String {
    format!(
        "version = 1\n[segment.\"custom/c\"]\nkind = \"command\"\ncommand = [\"/bin/sh\", \"-c\", \"echo x > {}\"]\n[layout.line2]\nleft = [\"custom/c\", \"char\"]\n",
        canary.display()
    )
}

fn explain(e: &Env, args: &[&str]) -> std::process::Output {
    // The folder `dir` shows is the current one: `/` keeps the text the same everywhere.
    e.cmd(&[&["explain"], args].concat())
        .current_dir("/")
        .output()
        .unwrap()
}

// 이것을 실패시키는 것: 폭마다 다른 구간·넘침 단계·숨김 이유가 문구로 나오는 길을 바꾸는 것(golden), 폭 경계(40·41)의 구간 선택.
#[allow(clippy::disallowed_methods, reason = "golden update switch of a test")]
#[test]
fn text_at_several_widths_matches_the_golden() {
    let e = Env::new("cli_explain", "golden");
    let file = e.put("layout.toml", LAYOUT);
    let shown = file.to_str().unwrap();
    let mut got = String::new();
    for w in ["120", "60", "41", "40", "20", "1"] {
        let o = explain(&e, &["--config", shown, "--width", w]);
        assert_eq!(o.status.code(), Some(0), "{w}: {}", text(&o.stderr));
        got.push_str(&format!("== width {w} ==\n"));
        got.push_str(&text(&o.stdout).replace(shown, "<file>"));
    }
    if std::env::var_os("BINGSU_UPDATE_GOLDEN").is_some() {
        std::fs::write(GOLDEN, &got).unwrap();
        return;
    }
    let want = std::fs::read_to_string(GOLDEN)
        .unwrap()
        .replace("\r\n", "\n");
    assert_eq!(
        got, want,
        "run with BINGSU_UPDATE_GOLDEN=1 and review the diff"
    );
}

// explain reads settings and runs nothing: not the configured command (the canary file stays absent), with
// `--config` or with the selected settings, and the settings, state and runtime folders do not change.
// 이것을 실패시키는 것: explain 경로에서 명령 세그먼트를 실행하는 것(카나리 파일이 생김), helper를 띄우거나
// 스냅샷·표식을 발행하는 것(폴더 목록이 바뀜).
#[test]
fn explain_runs_nothing_and_writes_nothing() {
    let e = Env::new("cli_explain", "canary");
    let canary = e.base.join("CANARY");
    let cfg = canary_config(&canary);
    let file = e.put("work.toml", &cfg);
    e.put_config("config.toml", &cfg);
    let before = e.tree();
    for args in [
        vec!["--config", file.to_str().unwrap(), "--width", "80"],
        vec!["--width", "80"],
        vec!["custom/c", "--width", "80"],
        vec!["custom/c", "--config", file.to_str().unwrap()],
    ] {
        let o = explain(&e, &args);
        assert_eq!(o.status.code(), Some(0), "{args:?}: {}", text(&o.stderr));
        assert!(!canary.exists(), "{args:?} ran the command");
        assert_eq!(e.tree(), before, "{args:?} changed a folder");
    }
}

// Under strace nothing but `bingsu` itself is executed, and no state folder appears.
// 이것을 실패시키는 것: explain 경로가 프로세스를 하나라도 실행하는 것(helper, collector, 설정 명령, git).
#[cfg(target_os = "linux")]
#[test]
fn explain_executes_no_process_under_strace() {
    use std::process::Command;
    if Command::new("strace").arg("-V").output().is_err() {
        eprintln!("skipped: strace is not installed");
        return;
    }
    let e = Env::new("cli_explain", "strace");
    let canary = e.base.join("CANARY");
    let file = e.put("work.toml", &canary_config(&canary));
    let trace = e.base.join("trace.txt");
    let o = Command::new("strace")
        .args(["-f", "-qq", "-e", "trace=execve,execveat", "-o"])
        .arg(&trace)
        .arg(env!("CARGO_BIN_EXE_bingsu"))
        .args(["explain", "--width", "80", "--config"])
        .arg(&file)
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
    let ok = t.lines().filter(|l| l.contains(" = 0")).count();
    assert_eq!(ok, 1, "{t}");
    assert!(!canary.exists());
    assert!(!e.state_dir().exists());
}

// The text never carries an environment value: an `env` segment is named, its value is not read.
// 이것을 실패시키는 것: env 세그먼트의 값을 explain 출력에 넣는 것.
#[test]
fn explain_never_prints_environment_values() {
    let e = Env::new("cli_explain", "env");
    let file = e.put(
        "env.toml",
        "version = 1\n[segment.\"custom/e\"]\nkind = \"env\"\nenv = \"BINGSU_SECRET_PROBE\"\n[layout.line2]\nleft = [\"custom/e\", \"char\"]\n",
    );
    let o = e
        .cmd(&["explain", "custom/e", "--width", "80", "--config"])
        .arg(&file)
        .env("BINGSU_SECRET_PROBE", "topsecretvalue")
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(0), "{}", text(&o.stderr));
    let all = format!("{}{}", text(&o.stdout), text(&o.stderr));
    assert!(!all.contains("topsecretvalue"), "{all}");
    assert!(all.contains("custom/e"), "{all}");
}

// A segment argument names one segment: its hide and shorten records only, and for a command segment the
// execution section (of your own settings; a `--config` file is not trusted, so nothing is looked up for it).
// An unknown name exits 2.
// 이것을 실패시키는 것: 세그먼트 거름을 무시하는 것, 모르는 세그먼트를 0으로 끝내는 것, 명령 세그먼트의 실행 절을 빼는 것,
// `--config`의 실행 파일을 조회하는 것.
#[test]
fn a_segment_argument_filters_and_is_checked() {
    let e = Env::new("cli_explain", "segment");
    let canary = e.base.join("CANARY");
    let cfg = canary_config(&canary);
    let file = e.put("work.toml", &cfg);
    e.put_config("config.toml", &cfg);
    let f = file.to_str().unwrap();
    let o = explain(&e, &["custom/c", "--width", "80"]);
    let out = text(&o.stdout);
    assert_eq!(o.status.code(), Some(0), "{out}");
    assert!(out.contains("execution"), "{out}");
    assert!(out.contains("custom/c  command"), "{out}");
    let o = explain(&e, &["custom/c", "--config", f, "--width", "80"]);
    let out = text(&o.stdout);
    assert_eq!(o.status.code(), Some(0), "{out}");
    assert!(out.contains("execution: not shown for --config"), "{out}");
    assert!(!out.contains("custom/c  command"), "{out}");
    let o = explain(&e, &["dir", "--config", f, "--width", "80"]);
    assert_eq!(o.status.code(), Some(0));
    assert!(!text(&o.stdout).contains("execution"));
    let o = explain(&e, &["nope", "--config", f]);
    assert_eq!((o.status.code(), o.stdout.is_empty()), (Some(2), true));
    assert!(text(&o.stderr).contains("no segment `nope`"));
}

// A `--config` file's executable is never opened: under strace no file call names it.
// 이것을 실패시키는 것: `--config`로 읽은 설정의 명령 파일을 조회하려고 여는 것.
#[cfg(target_os = "linux")]
#[test]
fn a_config_files_executable_is_not_opened() {
    use std::process::Command;
    if Command::new("strace").arg("-V").output().is_err() {
        eprintln!("skipped: strace is not installed");
        return;
    }
    let e = Env::new("cli_explain", "no-lookup");
    let exe = e.put("probe-exe-name", "#!/bin/sh\n");
    user_env::chmod(&exe, 0o755);
    let cfg = format!(
        "version = 1\n[segment.\"custom/c\"]\nkind = \"command\"\ncommand = [\"{}\"]\n[layout.line2]\nleft = [\"custom/c\", \"char\"]\n",
        exe.display()
    );
    let file = e.put("work.toml", &cfg);
    let trace = e.base.join("trace.txt");
    let o = Command::new("strace")
        .args(["-f", "-qq", "-e", "trace=file", "-o"])
        .arg(&trace)
        .arg(env!("CARGO_BIN_EXE_bingsu"))
        .args(["explain", "custom/c", "--width", "80", "--config"])
        .arg(&file)
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
    assert!(t.contains("work.toml"), "the trace sees file calls: {t}");
    assert!(!t.contains("probe-exe-name"), "{t}");
}

// With settings published, explain draws what the prompt draws now: the snapshot. A change in the files that
// is not published yet is said, not applied.
// 이것을 실패시키는 것: 발행된 snapshot 대신 파일로 결정하는 것(구간이 이미 보임), 바뀐 설정에 알림을 빼는 것,
// 발행이 없을 때 알림을 빼는 것, 발행된 것과 같은 설정을 바뀐 것으로 알리는 것.
#[test]
fn explain_follows_the_published_settings() {
    const BASIS: &str = "basis: ";
    let e = Env::new("cli_explain", "published");
    e.put_config("config.toml", LAYOUT_NO_BAND);
    let o = explain(&e, &["--width", "120"]);
    let none = text(&o.stdout);
    assert_eq!(o.status.code(), Some(0), "{}", text(&o.stderr));
    assert!(none.contains("nothing is published yet"), "{none}");
    assert!(!none.contains("band `wide`"), "{none}");
    let r = e.run(&["reload"]);
    assert_eq!(r.status.code(), Some(0), "{}", text(&r.stderr));
    let o = explain(&e, &["--width", "120"]);
    let same = text(&o.stdout);
    assert!(same.contains("the ones in your files"), "{same}");
    assert!(same.contains("layout: the default layout"), "{same}");
    // The band is added to the files; nothing is published.
    e.put_config(
        "config.toml",
        &format!("{LAYOUT_NO_BAND}[layout.when.wide]\nmin_cols = 100\n"),
    );
    let o = explain(&e, &["--width", "120"]);
    let moved = text(&o.stdout);
    assert!(moved.contains("your files have changed since"), "{moved}");
    assert!(moved.contains("layout: the default layout"), "{moved}");
    assert!(!moved.contains("band `wide`"), "{moved}");
    // Published, the band is what the prompt draws.
    let r = e.run(&["reload"]);
    assert_eq!(r.status.code(), Some(0), "{}", text(&r.stderr));
    let o = explain(&e, &["--width", "120"]);
    let now = text(&o.stdout);
    assert!(now.contains("layout: band `wide`"), "{now}");
    assert!(now.contains("the ones in your files"), "{now}");
    assert!(now.matches(BASIS).count() == 1);
}

// 이것을 실패시키는 것: 폭 0·모르는 옵션·값 없는 옵션·없는 파일·extends를 쓰는 파일을 0으로 끝내는 것.
#[test]
fn wrong_use_fails_without_output() {
    let e = Env::new("cli_explain", "usage");
    let with_extends = e.put("x.toml", "version = 1\nextends = [\"other.toml\"]\n");
    for args in [
        vec!["--width", "0"],
        vec!["--width"],
        vec!["--bogus"],
        vec!["a", "b"],
    ] {
        let o = explain(&e, &args);
        assert_eq!(o.status.code(), Some(2), "{args:?}");
        assert!(o.stdout.is_empty());
        assert!(text(&o.stderr).contains("usage: bingsu explain"));
    }
    for args in [
        vec!["--config", "/nonexistent/none.toml"],
        vec!["--config", with_extends.to_str().unwrap()],
    ] {
        let o = explain(&e, &args);
        assert_eq!(o.status.code(), Some(1), "{args:?}: {}", text(&o.stderr));
        assert!(o.stdout.is_empty());
    }
}
