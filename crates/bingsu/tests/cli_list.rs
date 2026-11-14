//! `bingsu list`: the rows, the usage exit, and that it starts no process.
use std::process::Command;

#[cfg(unix)]
#[path = "support/pty.rs"]
mod pty;

fn bingsu() -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_bingsu"));
    // No settings, no state: `list` reads none of them.
    c.env_clear();
    c
}

// 이것을 실패시키는 것: Windows에서 `list`가 사용법 오류(2) 대신 동작하는 것(그 분기는 unix에만 컴파일됨).
#[cfg(not(unix))]
#[test]
fn list_is_a_usage_error_without_unix() {
    let o = bingsu().args(["list", "presets"]).output().unwrap();
    assert_eq!(o.status.code(), Some(2), "{o:?}");
    assert!(o.stdout.is_empty());
}

// 이것을 실패시키는 것: `list` 분기를 지우는 것(사용법 오류 2), 종류 이름 하나를 받지 않는 것,
// 행을 stderr에 쓰는 것, 알 수 없는 종류나 남는 인자에 0으로 끝나는 것.
#[cfg(unix)]
#[test]
fn every_kind_prints_rows_and_a_bad_word_is_a_usage_error() {
    for kind in [
        "presets",
        "segments",
        "flavors",
        "roles",
        "shorteners",
        "icons",
    ] {
        let o = bingsu().args(["list", kind]).output().unwrap();
        assert_eq!(o.status.code(), Some(0), "{kind}: {o:?}");
        assert!(o.stderr.is_empty(), "{kind}");
        let out = String::from_utf8(o.stdout).unwrap();
        assert!(out.lines().count() > 0 && out.ends_with('\n'), "{kind}");
    }
    let presets = bingsu().args(["list", "presets"]).output().unwrap();
    assert_eq!(
        String::from_utf8(presets.stdout).unwrap(),
        "lean\ntriangle\npill\nslant\ndiamond\nblock\nbracket\n"
    );
    for args in [
        &["list"][..],
        &["list", "nope"],
        &["list", "roles", "extra"],
        &["list", "presets", "--preview", "--icons", "emoji"],
        &["list", "roles", "--preview"],
    ] {
        let o = bingsu().args(args).output().unwrap();
        assert_eq!(o.status.code(), Some(2), "{args:?}: {o:?}");
        assert!(o.stdout.is_empty(), "{args:?}");
    }
}

// 이것을 실패시키는 것: 미리보기가 현재 폴더를 쓰지 않는 것, 터미널이 아닌데 escape를 내는 것,
// 프리셋 줄 수가 일곱이 아닌 것.
#[cfg(unix)]
#[test]
fn preview_draws_one_plain_line_per_preset_for_the_current_folder() {
    let dir = std::env::temp_dir().join("bingsu-list-preview-dir");
    std::fs::create_dir_all(&dir).unwrap();
    let o = bingsu()
        .args(["list", "presets", "--preview", "--icons", "ascii"])
        .current_dir(&dir)
        .env("HOME", "/nonexistent-home")
        .env("COLUMNS", "100")
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(0), "{o:?}");
    let out = String::from_utf8(o.stdout).unwrap();
    assert_eq!(out.lines().count(), 7, "{out}");
    assert!(!out.contains('\x1b'), "{out}");
    for l in out.lines() {
        assert!(
            l.contains("bingsu-list-preview-dir") && l.contains("main"),
            "{l}"
        );
        assert!(l.chars().count() < 100, "{l}");
    }
}

// The preview takes its width as explain does: COLUMNS, else the terminal standard output is on,
// else 80. A line ends one cell short of the width (the last column stays empty).
// 이것을 실패시키는 것: 미리보기가 COLUMNS만 읽는 것(터미널에서도 80), COLUMNS=0을 폭으로 받는 것(60칸 바닥의
// 69칸), 터미널이 COLUMNS를 이기는 것.
#[cfg(unix)]
#[test]
fn preview_takes_the_width_from_columns_or_the_terminal() {
    let dir = std::env::temp_dir().join("bingsu-list-preview-width");
    std::fs::create_dir_all(&dir).unwrap();
    let widest = |columns: Option<&str>, terminal: Option<u16>| -> usize {
        let mut c = bingsu();
        c.args(["list", "presets", "--preview", "--icons", "ascii"])
            .current_dir(&dir)
            .env("HOME", "/nonexistent-home")
            .env("NO_COLOR", "1");
        if let Some(v) = columns {
            c.env("COLUMNS", v);
        }
        let out = match terminal {
            Some(cols) => {
                let (code, out) = pty::on_a_terminal(c, cols);
                assert_eq!(code, Some(0), "{out}");
                out
            }
            None => {
                let o = c.output().unwrap();
                assert_eq!(o.status.code(), Some(0), "{o:?}");
                String::from_utf8(o.stdout).unwrap()
            }
        };
        assert_eq!(out.lines().count(), 7, "{out}");
        out.lines().map(|l| l.chars().count()).max().unwrap()
    };
    assert_eq!(widest(None, Some(123)), 122);
    assert_eq!(widest(Some("100"), Some(123)), 99);
    assert_eq!(widest(Some("0"), Some(123)), 122);
    assert_eq!(widest(Some("0"), None), 79);
    assert_eq!(widest(None, None), 79);
}

// 이것을 실패시키는 것: 미리보기나 목록이 프로세스를 띄우는 것(명령·수집 작업·도우미·git). Linux에서
// strace로 execve를 센다: 처음 실행한 `bingsu` 하나뿐이어야 한다. strace가 없으면 건너뛰되
// BINGSU_REQUIRE_STRACE=1이면 실패한다.
#[cfg(target_os = "linux")]
#[test]
#[expect(
    clippy::disallowed_methods,
    reason = "test harness switch, not the prompt path"
)]
fn list_starts_no_process() {
    let strace = ["/usr/bin/strace", "/bin/strace", "/usr/local/bin/strace"]
        .into_iter()
        .find(|p| std::path::Path::new(p).exists());
    let Some(strace) = strace else {
        assert!(
            std::env::var_os("BINGSU_REQUIRE_STRACE").is_none_or(|v| v != "1"),
            "strace is required here"
        );
        eprintln!("skipped: no strace");
        return;
    };
    let dir = std::env::temp_dir().join("bingsu-list-strace");
    std::fs::create_dir_all(&dir).unwrap();
    for args in [
        &["list", "presets", "--preview"][..],
        &["list", "presets", "--preview", "--icons", "nerd"],
        &["list", "segments"],
        &["list", "icons"],
    ] {
        let trace = dir.join("trace");
        let _ = std::fs::remove_file(&trace);
        let o = Command::new(strace)
            .args([
                "-f",
                "-q",
                "-e",
                "trace=execve,execveat,clone,clone3,fork,vfork",
            ])
            .arg("-o")
            .arg(&trace)
            .arg(env!("CARGO_BIN_EXE_bingsu"))
            .args(args)
            .current_dir(&dir)
            .env_clear()
            .output()
            .unwrap();
        assert_eq!(o.status.code(), Some(0), "{args:?}: {o:?}");
        let text = std::fs::read_to_string(&trace).unwrap();
        let execs = text
            .lines()
            .filter(|l| l.contains("execve(") || l.contains("execveat("))
            .count();
        let forks = text
            .lines()
            .filter(|l| l.contains("clone") || l.contains("fork"))
            .count();
        assert_eq!(execs, 1, "{args:?}: {text}");
        assert_eq!(forks, 0, "{args:?}: {text}");
    }
}
