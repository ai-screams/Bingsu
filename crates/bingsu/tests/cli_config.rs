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
    ] {
        let bad = run(&args);
        assert_eq!((bad.status.code(), bad.stdout.is_empty()), (Some(2), true));
        assert_eq!(
            bad.stderr,
            b"usage: bingsu config <check|path|schema [--theme]|use PATH>\n"
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
        before.starts_with("selection: config.toml in the settings folder\n"),
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
