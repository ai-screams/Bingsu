//! `bingsu reload` publishes through the N2 engine now and says how it ended:
//! 0 applied or unchanged, 1 invalid (the last good settings stay), 2 usage,
//! 3 not finished.
#![cfg(unix)]
use std::os::fd::AsRawFd;

#[path = "support/user_env.rs"]
mod user_env;
use user_env::{Env, chmod, quiet, text};

const VALID: &str = "icons = \"ascii\"\n";
const INVALID: &str = "colr = 1\n";

fn out(o: &std::process::Output) -> (Option<i32>, String, String) {
    (o.status.code(), text(&o.stdout), quiet(&o.stderr))
}

// 이것을 실패시키는 것: 처음 발행을 세대 1로 알리지 않는 것, 바뀐 것이 없는데 다시 발행했다고 하는 것,
// 설정을 바꾼 뒤 새 세대를 알리지 않는 것.
#[test]
fn reload_publishes_then_reports_no_change() {
    let e = Env::new("cli_reload", "publish");
    e.put_config("config.toml", VALID);
    let (code, stdout, stderr) = out(&e.run(&["reload"]));
    assert_eq!((code, stderr.as_str()), (Some(0), ""));
    assert_eq!(
        stdout,
        "bingsu: reloaded; new settings published (generation 1)\n"
    );
    let (code, stdout, _) = out(&e.run(&["reload"]));
    assert_eq!(code, Some(0));
    assert_eq!(
        stdout,
        "bingsu: reloaded; the settings did not change (generation 1)\n"
    );
    e.put_config("config.toml", "icons = \"unicode\"\n");
    let (_, stdout, _) = out(&e.run(&["reload"]));
    assert_eq!(
        stdout,
        "bingsu: reloaded; new settings published (generation 2)\n"
    );
}

// 이것을 실패시키는 것: 잘못된 설정을 성공(0)으로 알리는 것, 문구에서 마지막 정상 설정이 남는다는 말과 확인 명령을 빼는 것,
// 잘못된 설정이 마지막 정상 snapshot을 바꾸는 것.
#[test]
fn reload_keeps_the_last_good_settings_when_invalid() {
    let e = Env::new("cli_reload", "invalid");
    e.put_config("config.toml", VALID);
    assert_eq!(e.run(&["reload"]).status.code(), Some(0));
    let ctx = e.context_dir();
    let good = std::fs::read(ctx.join("snapshot")).unwrap();
    e.put_config("config.toml", INVALID);
    let (code, stdout, stderr) = out(&e.run(&["reload"]));
    assert_eq!(code, Some(1), "{stdout}{stderr}");
    assert_eq!(stdout, "");
    assert_eq!(
        stderr,
        "bingsu: the settings are not valid, so nothing changed and the prompt keeps the last good settings. Run: bingsu config check\n"
    );
    assert_eq!(std::fs::read(ctx.join("snapshot")).unwrap(), good);
}

// 이것을 실패시키는 것: 사용법 오류(2)를 다른 코드로 내는 것, 인자를 무시하고 발행하는 것(stdout에 글자).
#[test]
fn reload_takes_no_arguments() {
    let e = Env::new("cli_reload", "usage");
    e.put_config("config.toml", VALID);
    let (code, stdout, stderr) = out(&e.run(&["reload", "now"]));
    assert_eq!((code, stdout.as_str()), (Some(2), ""));
    assert_eq!(stderr, "usage: bingsu reload\n");
    assert!(!e.base.join("run").exists());
}

// 이것을 실패시키는 것: 런타임 폴더를 못 만든 것(미완료)을 성공이나 확인된 실패(1)로 내는 것, 확인할 수 없는 설정 폴더(1)를 3으로 내는 것.
#[test]
fn reload_cannot_publish_without_trusted_roots() {
    let e = Env::new("cli_reload", "roots");
    e.put_config("config.toml", VALID);
    let blocker = e.put("run", "not a folder");
    let (code, stdout, stderr) = out(&e.run(&["reload"]));
    assert_eq!((code, stdout.as_str()), (Some(3), ""));
    assert!(
        stderr.starts_with("bingsu: no usable runtime folder"),
        "{stderr}"
    );
    std::fs::remove_file(blocker).unwrap();
    // Others can change the settings folder: it cannot be confirmed safe.
    chmod(&e.config_dir(), 0o777);
    let (code, stdout, stderr) = out(&e.run(&["reload"]));
    assert_eq!((code, stdout.as_str()), (Some(1), ""));
    assert!(
        stderr.starts_with("bingsu: a settings, state or log folder path could not be confirmed"),
        "{stderr}"
    );
    chmod(&e.config_dir(), 0o700);
}

// Another refresh holds the context lock: reload says so and exits 3 without changing anything.
// 이것을 실패시키는 것: Busy를 성공이나 잘못된 설정으로 내는 것, 잠금을 기다리며 막히는 것.
#[test]
fn reload_reports_a_refresh_in_progress() {
    let e = Env::new("cli_reload", "busy");
    e.put_config("config.toml", VALID);
    assert_eq!(e.run(&["reload"]).status.code(), Some(0));
    let ctx = e.context_dir();
    let lock = std::fs::File::open(ctx.join("snapshot.lock")).unwrap();
    // SAFETY: flock on a descriptor this test owns, no pointers.
    let rc = unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    assert_eq!(rc, 0);
    let before = e.tree();
    let (code, stdout, stderr) = out(&e.run(&["reload"]));
    assert_eq!((code, stdout.as_str()), (Some(3), ""));
    assert_eq!(
        stderr,
        "bingsu: another refresh is running, so nothing changed. Try again in a moment\n"
    );
    assert_eq!(e.tree(), before);
}
