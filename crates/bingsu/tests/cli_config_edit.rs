//! `bingsu config edit`: the editor is found without a shell, opens the
//! settings file in place, and what it saved is checked and published like
//! `reload`; an invalid save is not applied. The editor here is a short `sh`
//! script that records its arguments and copies the text in
//! `BINGSU_TEST_NEW` over the file it was given.
#![cfg(unix)]
use std::path::PathBuf;
use std::process::Output;

#[path = "support/user_env.rs"]
mod user_env;
use user_env::{Env, chmod, quiet, text};

const VALID: &str = "icons = \"ascii\"\n";
const OTHER: &str = "icons = \"unicode\"\n";
const INVALID: &str = "colr = 1\n";

struct Fixture {
    e: Env,
    log: PathBuf,
    script: PathBuf,
}

impl Fixture {
    fn new(tag: &str) -> Self {
        let e = Env::new("cli_config_edit", tag);
        e.put_config("config.toml", VALID);
        let log = e.base.join("editor.log");
        let script = e.put(
            "editor.sh",
            "#!/bin/sh\n\
             printf '%s\\n' \"$@\" > \"$BINGSU_TEST_LOG\"\n\
             echo \"TERM=$TERM\" >> \"$BINGSU_TEST_LOG\"\n\
             for last; do :; done\n\
             [ -n \"$BINGSU_TEST_FAIL\" ] && exit \"$BINGSU_TEST_FAIL\"\n\
             printf '%s' \"$BINGSU_TEST_NEW\" > \"$last\"\n",
        );
        chmod(&script, 0o700);
        Self { e, log, script }
    }

    fn run(&self, new: &str, editor: &str) -> Output {
        let mut c = self.e.cmd(&["config", "edit"]);
        c.env("EDITOR", editor)
            .env("BINGSU_TEST_LOG", &self.log)
            .env("BINGSU_TEST_NEW", new)
            .env("TERM", "test-term");
        c.output().unwrap()
    }

    fn config(&self) -> String {
        std::fs::read_to_string(self.e.config_dir().join("config.toml")).unwrap()
    }
}

fn out(o: &Output) -> (Option<i32>, String, String) {
    (o.status.code(), text(&o.stdout), quiet(&o.stderr))
}

// 이것을 실패시키는 것: 편집기를 열지 않거나 파일을 제자리에서 열지 않는 것(인자가 파일 경로 하나가 아님), 환경을
// 바꾸는 것(`TERM`이 전해지지 않음), 유효한 저장을 발행하지 않거나 `config check` 결과를 내지 않는 것,
// 바뀐 것이 없는데 새 세대라고 하는 것(같은 글자를 다시 저장하면 파일이 바뀐 것이라 새 세대다).
#[test]
fn a_valid_save_is_checked_and_published() {
    let f = Fixture::new("valid");
    let editor = f.script.to_str().unwrap().to_owned();
    let (code, stdout, stderr) = out(&f.run(OTHER, &editor));
    assert_eq!(code, Some(0), "{stdout}{stderr}");
    assert_eq!(f.config(), OTHER);
    assert!(stdout.contains("\nresult: valid\n"), "{stdout}");
    assert!(
        stdout.contains("edited; new settings published"),
        "{stdout}"
    );
    let log = std::fs::read_to_string(&f.log).unwrap();
    let file = f.e.config_dir().join("config.toml");
    assert_eq!(log, format!("{}\nTERM=test-term\n", file.display()));
    // An editor that changes nothing (`true`, found in PATH): nothing to publish.
    let (code, stdout, _) = out(&f.run(OTHER, "true"));
    assert_eq!(code, Some(0));
    assert!(stdout.contains("the settings did not change"), "{stdout}");
}

// 이것을 실패시키는 것: 무효한 저장을 적용하거나 성공(0)으로 내는 것, "적용하지 않았다"는 말을 빼는 것, 무효한 저장이
// 마지막 정상 스냅샷을 바꾸는 것, 무효한 저장 뒤에도 표식이 유효해 이전 설정의 명령이 계속 도는 것.
#[test]
fn an_invalid_save_is_not_applied() {
    let f = Fixture::new("invalid");
    let editor = f.script.to_str().unwrap().to_owned();
    assert_eq!(f.run(OTHER, &editor).status.code(), Some(0));
    let snapshot = f.e.context_dir().join("snapshot");
    let good = std::fs::read(&snapshot).unwrap();
    let (code, stdout, stderr) = out(&f.run(INVALID, &editor));
    assert_eq!(code, Some(1), "{stdout}{stderr}");
    assert!(stdout.contains("\nresult: invalid;"), "{stdout}");
    assert!(!stdout.contains("\nresult: valid"), "{stdout}");
    assert!(stderr.contains("not applied"), "{stderr}");
    assert!(
        stderr.contains("keeps the previous settings") || stderr.contains("last good"),
        "{stderr}"
    );
    assert!(!stdout.contains("published"), "{stdout}");
    assert_eq!(std::fs::read(&snapshot).unwrap(), good);
    // The commands of the previous settings stop running: the marker is invalidated.
    let marker = f.e.context_dir().join("marker");
    let marker = bingsu_core::snapshot::Marker::decode(&std::fs::read(marker).unwrap()).unwrap();
    assert!(
        marker.invalid,
        "an invalid save must revoke the right to run commands"
    );
    assert_eq!(
        f.config(),
        INVALID,
        "the file is the user's: it is not put back"
    );
}

// 이것을 실패시키는 것: 편집기가 0이 아닌 상태로 끝났는데 발행하는 것, 상태를 알리지 않는 것.
#[test]
fn a_failing_editor_applies_nothing() {
    let f = Fixture::new("fail");
    let editor = f.script.to_str().unwrap().to_owned();
    let mut c = f.e.cmd(&["config", "edit"]);
    c.env("EDITOR", &editor)
        .env("BINGSU_TEST_LOG", &f.log)
        .env("BINGSU_TEST_FAIL", "3");
    let o = c.output().unwrap();
    let (code, stdout, stderr) = out(&o);
    assert_eq!(code, Some(1), "{stdout}{stderr}");
    assert_eq!(stdout, "");
    assert!(
        stderr.contains("ended with") && stderr.contains("nothing was applied"),
        "{stderr}"
    );
    assert!(!f.e.base.join("run").exists(), "nothing was published");
}

// 이것을 실패시키는 것: 셸을 거쳐 실행하는 것(값의 `;touch`가 실행됨), 셸 문법을 거절하지 않는 것, 둘 다 없는데 기본
// 편집기로 넘어가는 것, 상대 경로·못 찾는 프로그램을 거절하지 않는 것. 거절한 뒤에는 파일도 발행도 건드리지 않는다.
#[test]
fn the_editor_value_is_never_run_by_a_shell() {
    let f = Fixture::new("shell");
    let canary = f.e.base.join("canary");
    let evil = format!("{} ; touch {}", f.script.display(), canary.display());
    let (code, _, stderr) = out(&f.run(OTHER, &evil));
    assert_eq!(code, Some(1));
    assert!(stderr.contains("shell character"), "{stderr}");
    assert!(!canary.exists());
    for (value, what) in [
        ("./editor.sh", "relative path"),
        ("no-such-editor-here", "not found"),
        ("'unfinished", "not finished"),
    ] {
        let (code, _, stderr) = out(&f.run(OTHER, value));
        assert_eq!(code, Some(1), "{value}: {stderr}");
        assert!(stderr.contains(what), "{value}: {stderr}");
    }
    assert_eq!(f.config(), VALID);
    // Neither variable set: no default editor.
    let o = f.e.cmd(&["config", "edit"]).output().unwrap();
    let (code, stdout, stderr) = out(&o);
    assert_eq!((code, stdout.as_str()), (Some(1), ""));
    assert!(stderr.contains("set $VISUAL or $EDITOR"), "{stderr}");
    assert!(!f.e.base.join("run").exists());
}

// 이것을 실패시키는 것: `VISUAL`보다 `EDITOR`를 먼저 쓰는 것, 편집기 값의 따옴표 안 공백 경로와 인자를 나누지 않는 것.
#[test]
fn visual_wins_and_quoted_arguments_are_passed() {
    let f = Fixture::new("visual");
    let value = format!("\"{}\" -w 'two words'", f.script.display());
    let mut c = f.e.cmd(&["config", "edit"]);
    c.env("VISUAL", &value)
        .env("EDITOR", "/nonexistent/editor")
        .env("BINGSU_TEST_LOG", &f.log)
        .env("BINGSU_TEST_NEW", OTHER);
    let (code, stdout, stderr) = out(&c.output().unwrap());
    assert_eq!(code, Some(0), "{stdout}{stderr}");
    let log = std::fs::read_to_string(&f.log).unwrap();
    let file = f.e.config_dir().join("config.toml");
    assert!(
        log.starts_with(&format!("-w\ntwo words\n{}\n", file.display())),
        "{log}"
    );
}

// 이것을 실패시키는 것: 파일이 없는데 만들어 주는 것, `setup`을 안내하지 않는 것, 편집기를 띄우는 것.
#[test]
fn no_settings_file_means_no_editor_and_no_new_file() {
    let f = Fixture::new("nofile");
    std::fs::remove_file(f.e.config_dir().join("config.toml")).unwrap();
    let editor = f.script.to_str().unwrap().to_owned();
    let (code, stdout, stderr) = out(&f.run(OTHER, &editor));
    assert_eq!((code, stdout.as_str()), (Some(1), ""));
    assert!(stderr.contains("bingsu setup"), "{stderr}");
    assert!(!f.log.exists(), "the editor must not start");
    assert!(!f.e.config_dir().join("config.toml").exists());
}

// 이것을 실패시키는 것: `config use`로 고른 파일 대신 `config.toml`을 여는 것.
#[test]
fn the_file_chosen_with_config_use_is_the_one_opened() {
    let f = Fixture::new("chosen");
    let chosen = f.e.put("other/work.toml", VALID);
    let o = f.e.run(&["config", "use", chosen.to_str().unwrap()]);
    assert_eq!(o.status.code(), Some(0), "{}", quiet(&o.stderr));
    let editor = f.script.to_str().unwrap().to_owned();
    let (code, stdout, stderr) = out(&f.run(OTHER, &editor));
    assert_eq!(code, Some(0), "{stdout}{stderr}");
    assert_eq!(std::fs::read_to_string(&chosen).unwrap(), OTHER);
    assert_eq!(f.config(), VALID, "config.toml is left alone");
    let log = std::fs::read_to_string(&f.log).unwrap();
    assert!(log.starts_with(&format!("{}\n", chosen.display())), "{log}");
}

// 고른 파일의 기록이 쓸 수 없게 되면(깨짐) 사용자가 고른 것이 아닌 `config.toml`을 열게 된다:
// 편집기를 띄우기 전에 그 사실과 이유를 알려야 한다. 이것을 실패시키는 것: 알림 없이 다른 파일을 여는 것,
// 쓸 수 없는 고른 파일을 그대로 여는 것.
#[test]
fn an_unusable_choice_is_said_before_config_toml_is_opened() {
    let f = Fixture::new("unusable");
    let chosen = f.e.put("other/work.toml", VALID);
    let o = f.e.run(&["config", "use", chosen.to_str().unwrap()]);
    assert_eq!(o.status.code(), Some(0), "{}", quiet(&o.stderr));
    // The record of the choice is damaged.
    std::fs::write(f.e.state_dir().join("config-use"), b"damaged").unwrap();
    let editor = f.script.to_str().unwrap().to_owned();
    let (code, stdout, stderr) = out(&f.run(OTHER, &editor));
    // The edit is saved, but nothing is applied until the record is fixed: the check says so, and
    // the edit ends with the code `config check` gives for the same state.
    let check = f.e.run(&["config", "check"]);
    assert_eq!(check.status.code(), Some(1));
    assert_eq!(code, check.status.code(), "{stdout}{stderr}");
    assert!(
        stdout.contains("not usable until the selection record is fixed"),
        "{stdout}"
    );
    assert!(
        stderr.contains("the file chosen with `config use` cannot be used ("),
        "{stderr}"
    );
    assert!(stderr.contains("opening "), "{stderr}");
    assert!(stderr.contains("config.toml"), "{stderr}");
    assert_eq!(f.config(), OTHER);
    assert_eq!(std::fs::read_to_string(&chosen).unwrap(), VALID);
}

// 이것을 실패시키는 것: `config.toml`이 끊긴 symlink일 때 편집기를 띄우는 것(저장이 링크 대상 자리에 새 파일을 만듦,
// 설정 폴더 밖일 수 있음), 대상이 일반 파일이 아닌 것(폴더)을 여는 것.
#[test]
fn a_dangling_link_is_no_settings_file() {
    let f = Fixture::new("dangling");
    let dir = f.e.config_dir();
    std::fs::remove_file(dir.join("config.toml")).unwrap();
    let target = f.e.base.join("elsewhere-missing.toml");
    std::os::unix::fs::symlink(&target, dir.join("config.toml")).unwrap();
    let editor = f.script.to_str().unwrap().to_owned();
    let (code, stdout, stderr) = out(&f.run(OTHER, &editor));
    assert_eq!((code, stdout.as_str()), (Some(1), ""));
    assert!(stderr.contains("bingsu setup"), "{stderr}");
    assert!(!f.log.exists(), "the editor must not start");
    assert!(!target.exists(), "no file may appear at the link's target");
    // A folder is no settings file either.
    std::fs::remove_file(dir.join("config.toml")).unwrap();
    std::fs::create_dir(dir.join("config.toml")).unwrap();
    let (code, _, stderr) = out(&f.run(OTHER, &editor));
    assert_eq!(code, Some(1), "{stderr}");
    assert!(!f.log.exists());
}

// 이것을 실패시키는 것: edit이 `config check`의 진단(실행기 조회로 더해지는 W411 등)을 빼먹는 것(check와 다른 출력).
#[test]
fn the_report_after_an_edit_is_the_one_config_check_gives() {
    let f = Fixture::new("same-report");
    let script = f.e.put("bin/tool", "#!/usr/bin/env sh\necho 1\n");
    chmod(&script, 0o755);
    let config = format!(
        "[segment.\"custom/tool\"]\nkind = \"command\"\ncommand = [\"{}\"]\n[layout.line1]\nleft = [\"dir\", \"custom/tool\"]\n",
        script.display()
    );
    f.e.put_config("config.toml", &config);
    let check = f.e.run(&["config", "check"]);
    let want = text(&check.stdout);
    assert!(want.contains("W411: segment `custom/tool`"), "{want}");
    // An editor that changes nothing.
    let (code, stdout, stderr) = out(&f.run(&config, "true"));
    assert_eq!(code, check.status.code(), "{stdout}{stderr}");
    assert!(stdout.starts_with(&want), "edit: {stdout}\ncheck: {want}");
}
