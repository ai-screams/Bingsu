//! `bingsu config schema` prints the JSON Schema core makes from the key
//! table (spec section 2 "JSON Schema"); `check`, `path` and `use` are the
//! settings commands of Task N5.
#![cfg(unix)]
use bingsu_core::config::schema::{Which, schema};
use std::process::Command;

#[path = "support/user_env.rs"]
mod user_env;
use user_env::{Env, chmod, quiet, text};

fn run(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_bingsu"))
        .args(args)
        .env_clear()
        .output()
        .expect("run bingsu")
}

// 이것을 실패시키는 것: 명령이 core 스키마와 다른 바이트를 내거나, `--theme`을 설정 스키마로 답하는 것,
// 모르는 인자를 받는 것.
#[test]
fn prints_the_core_schemas() {
    let c = run(&["config", "schema"]);
    assert_eq!(
        (c.status.code(), c.stdout, c.stderr.is_empty()),
        (Some(0), schema(Which::Config).into_bytes(), true)
    );
    let t = run(&["config", "schema", "--theme"]);
    assert_eq!(
        (t.status.code(), t.stdout),
        (Some(0), schema(Which::Theme).into_bytes())
    );
    for args in [
        vec!["config"],
        vec!["config", "--theme"],
        vec!["config", "schema", "--yaml"],
        vec!["config", "schema", "--theme", "extra"],
        vec!["config", "check", "--explain", "extra"],
        vec!["config", "check", "--verbose"],
    ] {
        let bad = run(&args);
        assert_eq!((bad.status.code(), bad.stdout.is_empty()), (Some(2), true));
        assert_eq!(
            bad.stderr,
            b"usage: bingsu config <check [--explain] [--format json|text]|path|schema [--theme]|use PATH>\n"
        );
    }
    use std::os::unix::ffi::OsStringExt;
    let bad = Command::new(env!("CARGO_BIN_EXE_bingsu"))
        .args(["config", "schema"])
        .arg(std::ffi::OsString::from_vec(vec![0xff]))
        .env_clear()
        .output()
        .unwrap();
    assert_eq!((bad.status.code(), bad.stdout.is_empty()), (Some(2), true));
}
// 이것을 실패시키는 것: 스키마 출력이 실패했는데 성공 종료 코드를 반환하는 것.
#[test]
fn schema_write_failure_exits_1() {
    use std::os::fd::OwnedFd;
    use std::os::unix::net::UnixStream;
    use std::process::Stdio;
    let (reader, writer) = UnixStream::pair().unwrap();
    drop(reader);
    let output = Command::new(env!("CARGO_BIN_EXE_bingsu"))
        .args(["config", "schema"])
        .env_clear()
        .stdout(Stdio::from(OwnedFd::from(writer)))
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stderr.is_empty());
}

const VALID: &str = "icons = \"ascii\"\n";
// An unknown top-level key is an error (E201), which no layer may carry.
const INVALID: &str = "colr = 1\n";

fn n7_read_only_without_runtime(verb: &str) {
    let e = Env::new("cli_config", &format!("n7-cold-{verb}"));
    e.put_config("config.toml", VALID);
    let before = e.tree();
    let result = e.run(&["config", verb]);
    assert_eq!(result.status.code(), Some(0));
    assert_eq!(quiet(&result.stderr), "");
    assert_eq!(e.tree(), before);
}
// 이것을 실패시키는 것: check가 fresh 환경에서 refresh를 호출하는 것.
#[test]
fn n7_check_is_read_only_without_runtime() {
    n7_read_only_without_runtime("check");
}
// 이것을 실패시키는 것: path가 fresh 환경에서 refresh/renew를 호출하는 것.
#[test]
fn n7_path_is_read_only_without_runtime() {
    n7_read_only_without_runtime("path");
}

fn out(o: &std::process::Output) -> (Option<i32>, String, String) {
    (o.status.code(), text(&o.stdout), quiet(&o.stderr))
}

// config check and config path are reads: on a machine that has no state, runtime or cache folders yet
// they make none, and with everything in place they change nothing (kind, mode, size, inode, mtime).
// 이것을 실패시키는 것: check나 path가 상태·런타임 폴더를 만들거나, 잠금 파일을 만들거나, 발행(스냅샷·표식)을 하거나, 선택 기록을 다시 쓰는 것.
#[test]
fn check_and_path_write_nothing() {
    let e = Env::new("cli_config", "readonly");
    e.put_config("config.toml", VALID);
    let before = e.tree();
    for verb in ["check", "path"] {
        let o = e.run(&["config", verb]);
        assert_eq!(o.status.code(), Some(0), "{verb}: {}", text(&o.stderr));
        assert_eq!(e.tree(), before, "{verb} on a fresh machine");
    }
    // Everything in place: published settings, a chosen file, a lock.
    let chosen = e.put("other/work.toml", VALID);
    e.put_config("conf.d/10-a.toml", VALID);
    let o = e.run(&["config", "use", chosen.to_str().unwrap()]);
    assert_eq!(o.status.code(), Some(0), "{}", text(&o.stderr));
    let before = e.tree();
    assert!(
        before
            .iter()
            .any(|l| l.starts_with("state/bingsu/config-use "))
    );
    assert!(before.iter().any(|l| l.contains("/marker ")));
    for verb in ["check", "path"] {
        let o = e.run(&["config", verb]);
        assert_eq!(o.status.code(), Some(0), "{verb}: {}", text(&o.stderr));
        assert_eq!(e.tree(), before, "{verb} with everything in place");
    }
}

// config check --explain is a read too, with or without a builtin language drawn: on a fresh machine
// it makes no runtime, state or cache folder, and with everything in place it changes nothing.
// 이것을 실패시키는 것: 내장 언어 절이 뿌리를 찾으며 런타임 폴더를 만들거나 권한을 바꾸는 것(roots::resolve),
// 그리는 언어가 없는데도 뿌리를 찾는 것.
#[test]
fn explain_writes_nothing() {
    const NODE: &str = "[layout.line2]\nleft=['node','char']\n";
    for (tag, toml) in [("plain", VALID), ("node", NODE)] {
        let e = Env::new("cli_config", &format!("explain-ro-{tag}"));
        e.put_config("config.toml", toml);
        let before = e.tree();
        let o = e.run(&["config", "check", "--explain"]);
        assert_eq!(o.status.code(), Some(0), "{tag}: {}", text(&o.stderr));
        assert_eq!(e.tree(), before, "{tag} on a fresh machine");
        let chosen = e.put("other/work.toml", toml);
        let o = e.run(&["config", "use", chosen.to_str().unwrap()]);
        assert_eq!(o.status.code(), Some(0), "{}", text(&o.stderr));
        let before = e.tree();
        let o = e.run(&["config", "check", "--explain"]);
        assert_eq!(o.status.code(), Some(0), "{tag}: {}", text(&o.stderr));
        assert_eq!(e.tree(), before, "{tag} with everything in place");
    }
}

// check prints the files in apply order, the diagnostics, the width table and a verdict; a valid
// settings folder exits 0, an error exits 1 and names the code.
// 이것을 실패시키는 것: 오류가 있는데 종료 코드 0, 진단·폭 표를 출력에서 빼는 것, 적용 순서를 바꾸는 것.
#[test]
fn check_reports_and_judges() {
    let e = Env::new("cli_config", "check");
    e.put_config("config.toml", VALID);
    e.put_config("conf.d/10-a.toml", VALID);
    e.put_config("config.local.toml", VALID);
    let (code, stdout, stderr) = out(&e.run(&["config", "check"]));
    assert_eq!((code, stderr.as_str()), (Some(0), ""), "{stdout}");
    let at = |needle: &str| {
        stdout
            .find(needle)
            .unwrap_or_else(|| panic!("{needle}: {stdout}"))
    };
    assert!(at("(built-in)") < at("config.toml (trusted)"));
    assert!(at("config.toml (trusted)") < at("conf.d/10-a.toml"));
    assert!(at("conf.d/10-a.toml") < at("config.local.toml"));
    assert!(stdout.contains("diagnostics: 0 error(s)"), "{stdout}");
    assert!(
        stdout.contains("widths (columns -> layout):\n  0-59"),
        "{stdout}"
    );
    assert!(stdout.contains("60+"), "{stdout}");
    assert!(stdout.trim_end().ends_with("result: valid"), "{stdout}");

    e.put_config("config.toml", INVALID);
    let (code, stdout, _) = out(&e.run(&["config", "check"]));
    assert_eq!(code, Some(1), "{stdout}");
    assert!(stdout.contains("E201"), "{stdout}");
    assert!(stdout.contains("colr"), "{stdout}");
    assert!(
        stdout.contains("how to fix") || stdout.contains("fix:"),
        "{stdout}"
    );
    assert!(stdout.contains("result: invalid"), "{stdout}");
}

// A command whose script starts with `#!/usr/bin/env` is warned about by check (W411), which stays
// valid; the warning names the segment.
// 이것을 실패시키는 것: check 경로에서 W411 진단을 보고서에 더하지 않는 것, 경고를 오류로 세는 것.
#[test]
fn check_warns_about_env_shebang_scripts() {
    let e = Env::new("cli_config", "shebang");
    let script = e.put("bin/tool", "#!/usr/bin/env sh\necho 1\n");
    // Executable, as a unit's file must be: one the executor would skip
    // is not what W411 is about.
    chmod(&script, 0o755);
    e.put_config(
        "config.toml",
        &format!(
            "[segment.\"custom/tool\"]\nkind = \"command\"\ncommand = [\"{}\"]\n[layout.line1]\nleft = [\"dir\", \"custom/tool\"]\n",
            script.display()
        ),
    );
    let (code, stdout, _) = out(&e.run(&["config", "check"]));
    assert_eq!(code, Some(0), "{stdout}");
    assert!(stdout.contains("W411: segment `custom/tool`"), "{stdout}");
    assert!(
        stdout.contains("diagnostics: 0 error(s), 1 warning(s)"),
        "{stdout}"
    );
    assert!(stdout.trim_end().ends_with("result: valid"), "{stdout}");
}

// A file others can change keeps its colors but runs nothing; check names the file and why, and the
// result says files were left out (still exit 0: the rest is valid).
// 이것을 실패시키는 것: 안전 검사에 걸린 이유를 지우거나, 남이 쓸 수 있는 파일을 "trusted"로 표시하는 것.
#[test]
fn check_names_a_file_nothing_runs_from() {
    let e = Env::new("cli_config", "unsafe");
    let f = e.put_config("config.toml", VALID);
    chmod(&f, 0o666);
    let (code, stdout, _) = out(&e.run(&["config", "check"]));
    assert_eq!(code, Some(0), "{stdout}");
    assert!(
        stdout.contains("config.toml (nothing in it runs: it is not yours alone to change)"),
        "{stdout}"
    );
    assert!(
        stdout.contains("result: valid; some files are left out"),
        "{stdout}"
    );
}

// config use records the chosen file in config.toml's place and leaves conf.d and config.local.toml in the
// list; config path shows the choice, the order and the canonical path.
// 이것을 실패시키는 것: use가 선택 파일 대신 다른 경로(원래 config.toml, 부모 폴더)를 기록하는 것, conf.d·local을 목록에서 빼는 것,
// 선택 뒤에도 원래 config.toml을 읽는 것.
#[test]
fn select_keeps_layers() {
    let e = Env::new("cli_config", "layers");
    e.put_config("config.toml", VALID);
    e.put_config("conf.d/10-a.toml", VALID);
    e.put_config("config.local.toml", VALID);
    let chosen = e.put("other/work.toml", VALID);
    let before = text(&e.run(&["config", "path"]).stdout);
    assert!(
        before.starts_with("selection: config.toml or config.json in the settings folder\n"),
        "{before}"
    );
    let o = e.run(&["config", "use", "other/work.toml"]);
    let (code, stdout, stderr) = out(&o);
    assert_eq!((code, stderr.as_str()), (Some(0), ""), "{stdout}");
    assert!(stdout.contains("published"), "{stdout}");
    let record = std::fs::read(e.state_dir().join("config-use")).unwrap();
    assert!(record.ends_with(chosen.to_str().unwrap().as_bytes()));
    let after = text(&e.run(&["config", "path"]).stdout);
    assert!(
        after.starts_with(&format!("selection: {}", chosen.display())),
        "{after}"
    );
    let list = &after[after.find("applied, in order:").unwrap()..];
    let at = |needle: &str| {
        list.find(needle)
            .unwrap_or_else(|| panic!("{needle}: {after}"))
    };
    assert!(at("(built-in)") < at("other/work.toml"));
    assert!(at("other/work.toml") < at("conf.d/10-a.toml"));
    assert!(at("conf.d/10-a.toml") < at("config.local.toml"));
    assert!(!list.contains("cfg/bingsu/config.toml"), "{after}");
}

// A choice that is missing, a folder, writable by others, or behind an unsafe link is refused and nothing is saved.
// 이것을 실패시키는 것: use가 안전 검사(소유·모드·링크)를 건너뛰고 기록하는 것, 거부하고도 기록을 남기는 것.
#[test]
fn use_refuses_what_cannot_run() {
    let e = Env::new("cli_config", "refuse");
    e.put_config("config.toml", VALID);
    let open = e.put("open/work.toml", VALID);
    chmod(&open, 0o666);
    let dir = e.base.join("a-folder");
    std::fs::create_dir(&dir).unwrap();
    for (arg, why) in [
        ("missing.toml", "there is no such file"),
        ("a-folder", "not a plain file"),
        (
            "open/work.toml",
            "it is not safe to run commands from: it is not yours alone to change",
        ),
    ] {
        let (code, stdout, stderr) = out(&e.run(&["config", "use", arg]));
        assert_eq!(code, Some(1), "{arg}");
        assert_eq!(stdout, "", "{arg}");
        assert!(stderr.starts_with("bingsu: not using "), "{arg}: {stderr}");
        assert!(stderr.contains(why), "{arg}: {stderr}");
        assert!(!e.state_dir().join("config-use").exists(), "{arg}");
    }
    let (code, _, stderr) = out(&e.run(&["config", "use"]));
    assert_eq!(code, Some(2));
    assert_eq!(stderr, "usage: bingsu config use PATH\n");
    let (code, _, _) = out(&e.run(&["config", "use", "a", "b"]));
    assert_eq!(code, Some(2));
}

// The choice is saved first and applied second; when applying cannot finish the user is told the choice
// stays (exit 3), and when the chosen settings are invalid, that (exit 1). Both leave the record.
// 이것을 실패시키는 것: 적용 실패를 선택 실패로 되돌려(기록 삭제) 알리거나, 저장 뒤 적용 실패를 성공(0)으로 보고하는 것,
// 두 경우의 문구·종료 코드를 같게 하는 것.
#[test]
fn selection_partial_success() {
    let e = Env::new("cli_config", "partial");
    e.put_config("config.toml", VALID);
    let good = e.put("other/good.toml", VALID);
    // The runtime root cannot be made (a plain file in the way): applying cannot finish.
    let blocker = e.put("run", "not a folder");
    let mut c = e.cmd(&["config", "use", good.to_str().unwrap()]);
    let (code, stdout, stderr) = out(&c.output().unwrap());
    assert_eq!(code, Some(3), "{stderr}");
    assert!(
        stderr.contains("your choice was saved, but applying it is not finished"),
        "{stderr}"
    );
    assert_eq!(stdout, "");
    assert!(
        std::fs::read(e.state_dir().join("config-use"))
            .unwrap()
            .ends_with(good.to_str().unwrap().as_bytes())
    );
    std::fs::remove_file(blocker).unwrap();

    let bad = e.put("other/bad.toml", INVALID);
    let (code, _, stderr) = out(&e.run(&["config", "use", bad.to_str().unwrap()]));
    assert_eq!(code, Some(1), "{stderr}");
    assert!(
        stderr.contains("your choice was saved, but the settings it gives are not valid"),
        "{stderr}"
    );
    assert!(
        std::fs::read(e.state_dir().join("config-use"))
            .unwrap()
            .ends_with(bad.to_str().unwrap().as_bytes())
    );
}

// A chosen path that now leads elsewhere (replaced by a link to another file) is not inherited, and
// check says how to choose again; the same path with a new inode (an editor's save) needs nothing.
// 이것을 실패시키는 것: 다른 정규 경로로 바뀐 선택을 계속 신뢰하는 것(색만 쓰는 파일로 표시하지 않는 것), 다시 고르라는 안내를 빼는 것,
// 같은 경로의 새 inode(편집기 저장)에 재승인을 요구하는 것.
#[test]
fn moved_selection_is_not_inherited() {
    let e = Env::new("cli_config", "moved");
    e.put_config("config.toml", VALID);
    let chosen = e.put("other/work.toml", VALID);
    let other = e.put("other/elsewhere.toml", VALID);
    let o = e.run(&["config", "use", chosen.to_str().unwrap()]);
    assert_eq!(o.status.code(), Some(0), "{}", text(&o.stderr));
    // An editor saves a new file at the same path: still trusted, nothing to say.
    e.put("other/work.toml", "icons = \"unicode\"\n");
    let (code, stdout, _) = out(&e.run(&["config", "check"]));
    assert_eq!(code, Some(0), "{stdout}");
    assert!(stdout.contains("work.toml (trusted)"), "{stdout}");
    assert!(!stdout.contains("choose it again"), "{stdout}");
    // The path becomes a link to another file.
    std::fs::remove_file(&chosen).unwrap();
    std::os::unix::fs::symlink(&other, &chosen).unwrap();
    let (code, stdout, _) = out(&e.run(&["config", "check"]));
    assert_eq!(code, Some(0), "{stdout}");
    assert!(stdout.contains("colors and layout only"), "{stdout}");
    assert!(
        stdout.contains(&format!(
            "choose it again with: bingsu config use {}",
            chosen.display()
        )),
        "{stdout}"
    );
}

// Paths in the output cannot carry terminal escapes.
// 이것을 실패시키는 것: 경로를 정제하지 않고 출력하는 것.
#[test]
fn paths_are_shown_sanitized() {
    let e = Env::new("cli_config", "escape");
    e.put_config("config.toml", VALID);
    let weird = e.put("other/we\u{1b}[31mird.toml", VALID);
    let o = e.run(&["config", "use", weird.to_str().unwrap()]);
    assert_eq!(o.status.code(), Some(0), "{}", text(&o.stderr));
    for verb in ["check", "path"] {
        let o = e.run(&["config", verb]);
        assert!(!o.stdout.contains(&0x1b), "{verb}");
    }
    assert!(
        !e.run(&["config", "use", weird.to_str().unwrap()])
            .stdout
            .contains(&0x1b)
    );
}

fn hold_selection_lock(e: &Env) -> std::fs::File {
    use std::os::fd::AsRawFd;
    let lock = std::fs::File::open(e.state_dir().join("selection.lock")).unwrap();
    // SAFETY: flock on a descriptor this test owns, no pointers.
    let rc = unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    assert_eq!(rc, 0);
    lock
}

// The helper holds the selection lock for an instant while it reads the record; config use waits that
// out instead of failing, and when the lock stays held it gives up with "nothing was saved" (exit 3) and
// leaves the old record.
// 이것을 실패시키는 것: 잠금이 잠깐 잡혀 있을 때 바로 포기하는 것(renew와 use의 경쟁이 저장 실패가 됨), 오래 잡혀 있어도 기다리며 막히는 것,
// 포기하면서 기록을 지우거나 바꾸는 것.
#[test]
fn use_waits_out_a_short_selection_lock_and_gives_up_on_a_long_one() {
    let e = Env::new("cli_config", "lock");
    e.put_config("config.toml", VALID);
    let first = e.put("other/first.toml", VALID);
    let second = e.put("other/second.toml", VALID);
    assert_eq!(
        e.run(&["config", "use", first.to_str().unwrap()])
            .status
            .code(),
        Some(0)
    );
    let lock = hold_selection_lock(&e);
    let child = e
        .cmd(&["config", "use", second.to_str().unwrap()])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    std::thread::sleep(std::time::Duration::from_millis(150));
    drop(lock);
    let o = child.wait_with_output().unwrap();
    assert_eq!(o.status.code(), Some(0), "{}", text(&o.stderr));
    let record = std::fs::read(e.state_dir().join("config-use")).unwrap();
    assert!(record.ends_with(second.to_str().unwrap().as_bytes()));

    let lock = hold_selection_lock(&e);
    let t = std::time::Instant::now();
    let (code, stdout, stderr) = out(&e.run(&["config", "use", first.to_str().unwrap()]));
    assert!(t.elapsed() < std::time::Duration::from_secs(2));
    assert_eq!((code, stdout.as_str()), (Some(3), ""));
    assert_eq!(
        stderr,
        "bingsu: nothing was saved: another bingsu process is busy with the choice; try again\n"
    );
    drop(lock);
    assert_eq!(
        std::fs::read(e.state_dir().join("config-use")).unwrap(),
        record
    );
}

fn set_fd_limit(limit: libc::rlim_t) -> std::io::Result<()> {
    let limits = libc::rlimit {
        rlim_cur: limit,
        rlim_max: limit,
    };
    // SAFETY: setrlimit reads a valid rlimit pointer for the calling child.
    if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limits) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

fn limited(mut cmd: Command, limit: libc::rlim_t) -> std::process::Output {
    use std::os::unix::process::CommandExt;
    // SAFETY: the closure only calls setrlimit, with no allocation or locks.
    unsafe {
        cmd.pre_exec(move || set_fd_limit(limit));
    }
    cmd.output().unwrap()
}

#[test]
fn fd_exhaustion_during_inspection_is_incomplete_and_read_only() {
    let e = Env::new("cli_config", "fd-inspect");
    e.put_config("config.toml", VALID);
    let chosen = e.put("chosen.toml", VALID);
    use std::os::unix::fs::MetadataExt;
    let md = std::fs::metadata(&chosen).unwrap();
    e.put(
        "state/bingsu/config-use",
        &format!(
            "bingsu-config-use 1\n{} {}\n{}",
            md.dev(),
            md.ino(),
            chosen.display()
        ),
    );
    for n in 0..16 {
        e.put_config(&format!("conf.d/{n:02}.toml"), VALID);
    }
    let before = e.tree();
    let mut incomplete = 0;
    for limit in [32, 48, 64, 80, 96] {
        for verb in ["check", "path"] {
            let o = limited(e.cmd(&["config", verb]), limit);
            assert!(
                matches!(o.status.code(), Some(0 | 3)),
                "{limit} {verb}: {:?} {} {}",
                o.status.code(),
                text(&o.stdout),
                text(&o.stderr)
            );
            if o.status.code() == Some(3) {
                incomplete += 1;
                assert!(text(&o.stdout).contains("could not read") || !o.stderr.is_empty());
                assert!(!text(&o.stdout).contains("choose the file again"));
            }
            assert_eq!(e.tree(), before);
        }
    }
    assert!(incomplete > 0);
}

// GATE-EXPLAIN.1: 설명은 환경 이름과 출처만 보이고 값은 보이지 않는다. 이것을 실패시키는 것: 설명 절에 환경
// 값을 싣는 것(이름 대신 NAME=VALUE).
#[test]
fn explain_never_prints_env_values() {
    let e = Env::new("cli_config", "explain-env");
    e.put_config(
        "config.toml",
        "[segment.\"custom/kube\"]\nkind = \"command\"\ncommand = [\"/bin/echo\", \"hi\"]\nenv_allow = [\"BINGSU_EXPLAIN_CANARY\"]\n[layout.line1]\nleft = [\"dir\", \"custom/kube\"]\n",
    );
    let o = e
        .cmd(&["config", "check", "--explain"])
        .env("BINGSU_EXPLAIN_CANARY", "canary-7f3")
        .output()
        .unwrap();
    let stdout = text(&o.stdout);
    assert_eq!(o.status.code(), Some(0), "{stdout}");
    assert!(stdout.contains("execution (--explain"), "{stdout}");
    assert!(stdout.contains("BINGSU_EXPLAIN_CANARY"), "{stdout}");
    assert!(!stdout.contains("canary-7f3"), "{stdout}");
    assert!(!text(&o.stderr).contains("canary-7f3"));
}

// GATE-EXPLAIN.2: 키마다 출처를 보인다. command는 config.toml에서, env_allow는 conf.d 파일에서 왔으면 두 파일이
// 각 줄에 따로 나온다. 이것을 실패시키는 것: 출처 칸을 빼는 것, 모든 키에 단위 하나의 출처를 쓰는 것.
#[test]
fn explain_shows_origin_per_key() {
    let e = Env::new("cli_config", "explain-origin");
    e.put_config(
        "config.toml",
        "[segment.\"custom/kube\"]\nkind = \"command\"\ncommand = [\"/bin/echo\", \"hi\"]\n[layout.line1]\nleft = [\"dir\", \"custom/kube\"]\n",
    );
    e.put_config(
        "conf.d/20-env.toml",
        "[segment.\"custom/kube\"]\nenv_allow = [\"KUBECONFIG\"]\n",
    );
    let (code, stdout, _) = out(&e.run(&["config", "check", "--explain"]));
    assert_eq!(code, Some(0), "{stdout}");
    let line = |key: &str, value: &str| {
        stdout
            .lines()
            .find(|l| l.trim_start().starts_with(key) && l.contains(value))
            .unwrap_or_else(|| panic!("{key} {value}: {stdout}"))
            .to_owned()
    };
    assert!(
        line("command", "/bin/echo hi").contains("config.toml:3"),
        "{stdout}"
    );
    assert!(
        line("env", "KUBECONFIG").contains("20-env.toml:2"),
        "{stdout}"
    );
    assert!(line("cwd", "neutral").ends_with("default"), "{stdout}");
    assert!(line("env", "HOME USER").ends_with("keep list"), "{stdout}");
    assert!(line("executable", "echo").contains("/bin/echo"), "{stdout}");
}

// language 단위의 interpreter와 version은 각자 자기 파일과 줄을 출처로 보인다(extends나 conf.d로 다른 파일에서
// 올 수 있음, D3c-1 리뷰 L1). 이것을 실패시키는 것: version 줄의 출처를 interpreter의 것으로 쓰는 것, 두 키를 한
// 줄로 합치는 것.
#[test]
fn explain_shows_each_language_key_from_its_file() {
    let e = Env::new("cli_config", "explain-lang-origin");
    e.put_config(
        "config.toml",
        "[segment.\"custom/deno\"]\nkind = \"language\"\ndetect_files = [\"deno.json\"]\ninterpreter = \"deno\"\n[layout.line1]\nleft = [\"dir\", \"custom/deno\"]\n",
    );
    e.put_config(
        "conf.d/20-version.toml",
        "[segment.\"custom/deno\"]\nversion = [\"-V\"]\n",
    );
    let (code, stdout, _) = out(&e.run(&["config", "check", "--explain"]));
    assert_eq!(code, Some(0), "{stdout}");
    let line = |key: &str| {
        stdout
            .lines()
            .find(|l| l.split_whitespace().next() == Some(key))
            .unwrap_or_else(|| panic!("{key}: {stdout}"))
            .to_owned()
    };
    assert!(line("interpreter").contains("config.toml:4"), "{stdout}");
    assert!(line("version").contains("20-version.toml:2"), "{stdout}");
    assert!(line("detect").contains("config.toml:3"), "{stdout}");
}

// GATE-EXPLAIN.3: 실행하지 않는 단위는 이유와 그 진단 코드를 보인다(남이 쓸 수 있는 파일의 command → W405).
// 이것을 실패시키는 것: 이유 칸을 빼는 것, check --explain이 설명 절을 붙이지 않는 것.
#[test]
fn explain_shows_not_run_reason() {
    let e = Env::new("cli_config", "explain-notrun");
    e.put_config(
        "config.toml",
        "[layout.line1]\nleft = [\"dir\", \"custom/kube\"]\n[segment.\"custom/kube\"]\nkind = \"command\"\n",
    );
    let f = e.put_config(
        "conf.d/30-cmd.toml",
        "[segment.\"custom/kube\"]\ncommand = [\"/bin/echo\", \"hi\"]\n",
    );
    chmod(&f, 0o666);
    let (_, stdout, _) = out(&e.run(&["config", "check", "--explain"]));
    assert!(
        stdout.contains("custom/kube  command, not run: one of its execution keys comes from a file that failed the safety check (W405)"),
        "{stdout}"
    );
}

// GATE-EXPLAIN.4: W411은 실행기와 같은 판정(core head)으로 첫 줄을 본다. /usr/bin/env, 상대 인터프리터, 256바이트를
// 넘는 줄, NUL은 각 이유와 함께 경고하고, `#!/bin/sh`는 경고하지 않는다(known-issues m6-A4a·m6-B3a). 이것을
// 실패시키는 것: W411을 자체 첫 줄 파서로 되돌리는 것(env만 잡음), 이유를 잘못 붙이는 것.
#[test]
fn explain_names_why_a_script_is_refused() {
    let cases: [(&str, &[u8], Option<&str>); 5] = [
        (
            "env",
            b"#!/usr/bin/env sh\necho 1\n",
            Some("starts with `#!/usr/bin/env`"),
        ),
        (
            "relative",
            b"#!sh\necho 1\n",
            Some("interpreter is not an absolute path"),
        ),
        ("nul", b"#!/bin/sh\0x\necho 1\n", Some("holds a NUL byte")),
        ("long", &[], Some("longer than 256 bytes")),
        ("plain", b"#!/bin/sh\necho 1\n", None),
    ];
    for (tag, body, want) in cases {
        let e = Env::new("cli_config", &format!("w411-{tag}"));
        let long = [b"#!/bin/sh ".as_slice(), &vec![b'x'; 300], b"\necho 1\n"].concat();
        let script = e.put("bin/tool", "");
        std::fs::write(&script, if tag == "long" { &long[..] } else { body }).unwrap();
        chmod(&script, 0o755);
        e.put_config(
            "config.toml",
            &format!(
                "[segment.\"custom/tool\"]\nkind = \"command\"\ncommand = [\"{}\"]\n[layout.line1]\nleft = [\"dir\", \"custom/tool\"]\n",
                script.display()
            ),
        );
        let (code, stdout, _) = out(&e.run(&["config", "check"]));
        assert_eq!(code, Some(0), "{tag}: {stdout}");
        match want {
            Some(reason) => {
                assert!(
                    stdout.contains("W411: segment `custom/tool`"),
                    "{tag}: {stdout}"
                );
                assert!(stdout.contains(reason), "{tag}: {stdout}");
            }
            None => assert!(!stdout.contains("W411"), "{tag}: {stdout}"),
        }
    }
}

// 셸 단위는 /bin/sh를, 상대 이름(`./tool`)은 찾지 않고 거부로, 언어 단위는 그 종류와 interpreter의 실행 파일로
// 보인다. 이것을 실패시키는 것:
// 셸 단위의 첫 단어를 argv에서 찾는 것(실행 파일 줄이 없음), 거부된 이름을 "찾지 못함"으로 보이는 것, 언어 단위를
// command로 보이는 것.
#[test]
fn explain_shows_shell_relative_and_language_units() {
    let e = Env::new("cli_config", "explain-kinds");
    e.put_config(
        "config.toml",
        "[segment.\"custom/sh\"]\nkind = \"command\"\nshell = \"echo hi\"\nunsafe_shell = true\n[segment.\"custom/rel\"]\nkind = \"command\"\ncommand = [\"./tool\"]\n[segment.\"custom/lang\"]\nkind = \"language\"\ndetect_files = [\"deno.json\"]\ninterpreter = \"/bin/echo\"\nversion = [\"--version\"]\ntimeout = \"123ms\"\ncache = \"7s\"\n[layout.line1]\nleft = [\"dir\", \"custom/sh\", \"custom/rel\", \"custom/lang\"]\n",
    );
    let (_, stdout, _) = out(&e.run(&["config", "check", "--explain"]));
    let section = |id: &str| {
        let start = stdout
            .find(&format!("\n{id}  "))
            .unwrap_or_else(|| panic!("{id}: {stdout}"));
        let rest = &stdout[start + 1..];
        let end = rest[1..].find("\ncustom/").map_or(rest.len(), |i| i + 1);
        rest[..end].to_owned()
    };
    // The file /bin/sh is (dash on Debian).
    let shell = std::fs::canonicalize("/bin/sh").unwrap();
    let sh = section("custom/sh");
    assert!(
        sh.lines().any(|l| l.trim_start().starts_with("executable")
            && l.trim_end().ends_with(shell.to_str().unwrap())),
        "{sh}"
    );
    let rel = section("custom/rel");
    assert!(
        rel.lines()
            .any(|l| l.trim_start().starts_with("executable") && l.contains("refused")),
        "{rel}"
    );
    let lang = section("custom/lang");
    assert!(
        lang.starts_with("custom/lang  language, runs where its detect files are found"),
        "{stdout}"
    );
    let echo = std::fs::canonicalize("/bin/echo").unwrap();
    assert!(
        lang.lines()
            .any(|l| l.trim_start().starts_with("executable")
                && l.trim_end().ends_with(echo.to_str().unwrap())),
        "{lang}"
    );
    assert!(
        lang.lines()
            .any(|l| l.split_whitespace().take(2).eq(["detect", "deno.json"])),
        "{lang}"
    );
    assert!(
        lang.lines().any(|l| l
            .split_whitespace()
            .take(2)
            .eq(["interpreter", "/bin/echo"])),
        "{lang}"
    );
    assert!(
        lang.lines()
            .any(|l| l.split_whitespace().take(2).eq(["version", "--version"])),
        "{lang}"
    );
    for (key, value) in [("timeout", "123 ms"), ("cache", "7000 ms")] {
        assert!(
            lang.lines()
                .any(|l| l.trim_start().starts_with(key) && l.contains(value)),
            "{key} {value}: {lang}"
        );
    }
}

// 시간 상한·캐시·명시한 cwd는 각자 값과 출처를 보이고, 셸 단위는 셸 본문을 보인다. 정제한 PATH로 찾으므로, 앞쪽
// 폴더가 남이 쓸 수 있으면 뒤쪽 안전한 폴더의 같은 이름이 실행 파일이다. 찾은 파일이 거부되면 상태도 "will not
// run"이다(E2 리뷰 M1, L4). 이것을 실패시키는 것: timeout·cache 줄을 빼는 것, 셸 본문 줄을 빼는 것, cwd 출처를
// 기본값으로 두는 것, 정제하지 않은 PATH로 찾는 것, 조회 결과를 상태에 합치지 않는 것.
#[test]
fn explain_shows_limits_cwd_shell_and_the_sanitized_lookup() {
    use std::os::unix::fs::PermissionsExt as _;
    let e = Env::new("cli_config", "explain-limits");
    let open = e.put("open/tool", "#!/bin/sh\necho open\n");
    let safe = e.put("safe/tool", "#!/bin/sh\necho safe\n");
    let env = e.put("envbin/envtool", "#!/usr/bin/env sh\necho 1\n");
    for f in [&open, &safe, &env] {
        chmod(f, 0o755);
    }
    std::fs::set_permissions(
        open.parent().unwrap(),
        std::fs::Permissions::from_mode(0o777),
    )
    .unwrap();
    e.put_config(
        "config.toml",
        &format!(
            "[segment.\"custom/a\"]\nkind = \"command\"\ncommand = [\"tool\"]\ntimeout = \"2s\"\ncache = \"30s\"\n\
             [segment.\"custom/sh\"]\nkind = \"command\"\nshell = \"echo hi\"\nunsafe_shell = true\n\
             [segment.\"custom/env\"]\nkind = \"command\"\ncommand = [\"{}\"]\n\
             [segment.\"custom/gone\"]\nkind = \"command\"\ncommand = [\"bingsu-no-such-tool\"]\n\
             [layout.line1]\nleft = [\"dir\", \"custom/a\", \"custom/sh\", \"custom/env\", \"custom/gone\"]\n",
            env.display()
        ),
    );
    e.put_config(
        "conf.d/10-cwd.toml",
        "[segment.\"custom/a\"]\ncwd = \"neutral\"\n",
    );
    let path = format!(
        "{}:{}:/usr/bin:/bin",
        open.parent().unwrap().display(),
        safe.parent().unwrap().display()
    );
    let o = e
        .cmd(&["config", "check", "--explain"])
        .env("PATH", &path)
        .output()
        .unwrap();
    let stdout = text(&o.stdout);
    let line = |key: &str, value: &str| {
        stdout
            .lines()
            .find(|l| l.trim_start().starts_with(key) && l.contains(value))
            .unwrap_or_else(|| panic!("{key} {value}: {stdout}"))
            .to_owned()
    };
    assert!(
        line("timeout", "2000 ms").contains("config.toml:"),
        "{stdout}"
    );
    assert!(
        line("cache", "30000 ms").contains("config.toml:"),
        "{stdout}"
    );
    assert!(line("cwd", "neutral").contains("10-cwd.toml:2"), "{stdout}");
    assert!(
        line("shell", "echo hi").contains("config.toml:"),
        "{stdout}"
    );
    let safe_dir = std::fs::canonicalize(safe.parent().unwrap()).unwrap();
    assert!(
        line("executable", "/tool").contains(safe_dir.to_str().unwrap()),
        "{stdout}"
    );
    assert!(
        stdout.contains("custom/env  command, will not run:"),
        "{stdout}"
    );
    assert!(
        stdout.contains("custom/gone  command, will not run: not found on the sanitized PATH"),
        "{stdout}"
    );
}

// U-33: setuid·setgid 프로그램은 실행하지 않고, `config check`(W411)와 `--explain`이 그 이유를 적는다. 대조: 0755
// 사본은 실행 파일로 보이고, 남이 쓸 수 있는 0757 사본은 이유 없이 거부된다(W411 없음). 이것을 실패시키는 것:
// explain이 SetId를 다른 거부처럼 다루는 것(이유가 빠짐), 이유를 다른 거부에도 붙이는 것, W411에 set-id를 더하지
// 않는 것, 상태 줄을 "will not run"으로 두지 않는 것.
#[test]
fn check_and_explain_name_set_id_programs() {
    let why = "setuid, setgid or file capabilities (bingsu runs no such program)";
    for (mode, refused, set_id) in [
        (0o755, false, false),
        (0o757, true, false),
        (0o4755, true, true),
        (0o2755, true, true),
    ] {
        let e = Env::new("cli_config", &format!("set-id-{mode:o}"));
        let tool = e.put("bin/tool", "#!/bin/sh\necho tool\n");
        chmod(&tool, mode);
        e.put_config(
            "config.toml",
            "[segment.\"custom/a\"]\nkind = \"command\"\ncommand = [\"tool\"]\n\
             [layout.line1]\nleft = [\"custom/a\"]\n",
        );
        let path = format!("{}:/usr/bin:/bin", tool.parent().unwrap().display());
        let check = |extra: &[&str]| {
            let mut a = vec!["config", "check"];
            a.extend_from_slice(extra);
            text(&e.cmd(&a).env("PATH", &path).output().unwrap().stdout)
        };
        let plain = check(&[]);
        assert_eq!(
            plain.contains("W411: segment `custom/a`") && plain.contains(why),
            set_id,
            "{mode:o}: {plain}"
        );
        let stdout = check(&["--explain"]);
        let executable = stdout
            .lines()
            .find(|l| l.trim_start().starts_with("executable"))
            .unwrap_or_else(|| panic!("{mode:o}: {stdout}"));
        assert!(executable.contains("/bin/tool"), "{mode:o}: {stdout}");
        assert_eq!(
            executable.ends_with(" refused"),
            refused && !set_id,
            "{mode:o}: {stdout}"
        );
        assert_eq!(executable.ends_with(why), set_id, "{mode:o}: {stdout}");
        assert_eq!(
            stdout.contains("custom/a  command, will not run: its file is refused"),
            refused,
            "{mode:o}: {stdout}"
        );
    }
}

// U-33: set-id 인터프리터를 쓰는 script는 W411과 `--explain`이 인터프리터 이유를 적는다(script 자체가 set-id인 이유와
// 다름). 이것을 실패시키는 것: 인터프리터의 SetId를 이유 없는 거부로 바꾸는 것, 인터프리터 경우를 파일 자체로 보는 것.
#[test]
fn check_and_explain_name_a_set_id_interpreter() {
    let e = Env::new("cli_config", "set-id-interpreter");
    let interp = e.put("bin/interp", "");
    std::fs::copy("/bin/sh", &interp).unwrap();
    chmod(&interp, 0o4755);
    let tool = e.put("bin/tool", &format!("#!{}\necho tool\n", interp.display()));
    chmod(&tool, 0o755);
    e.put_config(
        "config.toml",
        "[segment.\"custom/a\"]\nkind = \"command\"\ncommand = [\"tool\"]\n\
         [layout.line1]\nleft = [\"custom/a\"]\n",
    );
    let path = format!("{}:/usr/bin:/bin", tool.parent().unwrap().display());
    let why =
        "its interpreter is setuid, setgid or has file capabilities (bingsu runs no such program)";
    let check = |extra: &[&str]| {
        let mut a = vec!["config", "check"];
        a.extend_from_slice(extra);
        text(&e.cmd(&a).env("PATH", &path).output().unwrap().stdout)
    };
    let plain = check(&[]);
    assert!(
        plain.contains("W411: segment `custom/a`") && plain.contains(why),
        "{plain}"
    );
    let stdout = check(&["--explain"]);
    let executable = stdout
        .lines()
        .find(|l| l.trim_start().starts_with("executable"))
        .unwrap_or_else(|| panic!("{stdout}"));
    assert!(
        executable.contains("/bin/tool") && executable.ends_with(why),
        "{stdout}"
    );
}
