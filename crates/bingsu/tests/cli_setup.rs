//! `bingsu setup` without a terminal: every argument given, the file made
//! private and only when there is none, nothing else touched.
#![cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

#[path = "support/user_env.rs"]
mod user_env;

/// A new session has no controlling terminal, so `/dev/tty` cannot be opened
/// and `setup` takes its no-terminal path even when the test runs in one.
fn detach() -> std::io::Result<()> {
    // SAFETY: setsid takes no pointers.
    unsafe { libc::setsid() };
    Ok(())
}

struct Home(PathBuf);

impl Home {
    fn new(tag: &str) -> Self {
        let p = std::env::temp_dir().join(format!("bingsu-cli-setup-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o700)).unwrap();
        Self(p.canonicalize().unwrap())
    }
    fn config(&self) -> PathBuf {
        self.0.join("cfg/bingsu/config.toml")
    }
    fn run(&self, args: &[&str]) -> Output {
        self.cmd(args).output().unwrap()
    }
    fn cmd(&self, args: &[&str]) -> Command {
        let mut c = Command::new(env!("CARGO_BIN_EXE_bingsu"));
        c.env_clear()
            .env("HOME", &self.0)
            .env("XDG_CONFIG_HOME", self.0.join("cfg"))
            // The choice record lives under the state folder: without this
            // one the account's own (from its home, not $HOME) is read.
            .env("XDG_STATE_HOME", self.0.join("state"))
            .env("SHELL", "/bin/zsh");
        // `setup` unless the test names another command.
        if args.first() != Some(&"config") {
            c.arg("setup");
        }
        c.args(args);
        // SAFETY: `detach` only calls setsid, which is async-signal-safe.
        unsafe { c.pre_exec(detach) };
        c
    }
    /// Every path under the home with its mode, sorted.
    fn tree(&self) -> Vec<String> {
        fn walk(p: &Path, root: &Path, out: &mut Vec<String>) {
            for e in std::fs::read_dir(p).unwrap() {
                let e = e.unwrap();
                let m = e.metadata().unwrap();
                let rel = e.path().strip_prefix(root).unwrap().display().to_string();
                out.push(format!("{rel} {:o}", m.permissions().mode() & 0o7777));
                if m.is_dir() {
                    walk(&e.path(), root, out);
                }
            }
        }
        let mut out = Vec::new();
        walk(&self.0, &self.0, &mut out);
        out.sort();
        out
    }
}

impl Drop for Home {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn text(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

// 이것을 실패시키는 것: 터미널이 없는데 질문하려 하거나 기본값을 조용히 고르는 것, 빠진 인자를 이름으로 알리지
// 않는 것, 사용법 오류에서 폴더·파일을 만드는 것, 모르는 값을 받는 것.
#[test]
fn without_a_terminal_a_missing_argument_is_a_usage_error_and_writes_nothing() {
    let h = Home::new("usage");
    for (args, missing) in [
        (&["--yes", "--icons", "nerd"][..], "--mode"),
        (&["--yes", "--mode", "dark"], "--icons"),
        (&["--icons", "nerd", "--mode", "dark"], "--yes"),
        (&[][..], "--yes, --icons, --mode"),
    ] {
        let o = h.run(args);
        assert_eq!(o.status.code(), Some(2), "{args:?}: {o:?}");
        assert!(
            text(&o.stderr).contains(missing),
            "{args:?}: {}",
            text(&o.stderr)
        );
        assert!(o.stdout.is_empty(), "{args:?}");
        assert_eq!(h.tree(), Vec::<String>::new(), "{args:?}");
    }
    for bad in [
        &["--icons", "emoji", "--yes", "--mode", "auto"][..],
        &["--icons", "Light", "--yes", "--mode", "auto"],
        &["--bogus"],
    ] {
        let o = h.run(bad);
        assert_eq!(o.status.code(), Some(2), "{bad:?}");
        assert_eq!(h.tree(), Vec::<String>::new(), "{bad:?}");
    }
    let o = h.run(&["--icons", "emoji", "--yes", "--mode", "auto"]);
    assert!(
        text(&o.stderr).contains("--icons takes nerd, light, unicode or ascii"),
        "{}",
        text(&o.stderr)
    );
}

// 이것을 실패시키는 것: 아이콘 집합 넷 중 하나를 터미널 없는 경로에서 받지 않는 것, 파일에 다른 집합이나 다른
// 시작 프리셋(nerd·light → triangle, unicode·ascii → lean)을 쓰는 것, 만든 파일이 `config check`를 통과하지
// 못하는 것, 같은 선택으로 다시 부르면 차이를 알리는 것(시작 설정과 비교가 갈라짐).
#[test]
fn every_icon_set_writes_its_starter_and_it_checks() {
    for (icons, preset) in [
        ("nerd", "triangle"),
        ("light", "triangle"),
        ("unicode", "lean"),
        ("ascii", "lean"),
    ] {
        let h = Home::new(&format!("icons-{icons}"));
        let args = ["--yes", "--icons", icons, "--mode", "auto"];
        let o = h.run(&args);
        assert_eq!(o.status.code(), Some(0), "{icons}: {o:?}");
        let file = std::fs::read_to_string(h.config()).unwrap();
        assert_eq!(
            file.matches(&format!("\nicons = \"{icons}\"\n")).count(),
            1,
            "{file}"
        );
        assert_eq!(
            file.matches(&format!("\npreset = \"{preset}\"\n")).count(),
            1,
            "{file}"
        );
        let c = h.run(&["config", "check"]);
        assert_eq!(c.status.code(), Some(0), "{icons}: {}", text(&c.stderr));
        assert!(
            text(&c.stdout).contains("result: valid"),
            "{icons}: {}",
            text(&c.stdout)
        );
        let again = h.run(&args);
        assert_eq!(again.status.code(), Some(0), "{icons}: {again:?}");
        assert!(
            text(&again.stderr).contains("It already has the choices you made."),
            "{icons}: {}",
            text(&again.stderr)
        );
    }
}

// 이것을 실패시키는 것: 폴더가 0700이 아니거나 파일이 0600이 아닌 것, 임시 파일이 남는 것, 설정 폴더 밖
// (상태·캐시·런타임)에 무언가 만드는 것, `colors.mode`를 한 번이 아니게 쓰는 것, 고른 값이 파일에 없는 것,
// stdout에 시작 줄 말고 다른 것을 내는 것, 만든 파일이 `config check`를 통과하지 못하는 것.
#[test]
fn all_arguments_write_one_private_file_and_nothing_else() {
    let h = Home::new("write");
    let o = h.run(&["--yes", "--icons", "unicode", "--mode", "light"]);
    assert_eq!(o.status.code(), Some(0), "{o:?}");
    assert_eq!(text(&o.stdout), "eval \"$(bingsu init zsh)\"\n");
    assert_eq!(
        h.tree(),
        ["cfg 700", "cfg/bingsu 700", "cfg/bingsu/config.toml 600"]
    );
    let file = std::fs::read_to_string(h.config()).unwrap();
    assert!(file.starts_with("#:schema "), "{file}");
    assert_eq!(file.matches("mode = \"light\"").count(), 1, "{file}");
    assert_eq!(file.matches("mode = ").count(), 1, "{file}");
    assert!(file.contains("icons = \"unicode\"") && file.contains("preset = \"lean\""));
    // The file is a valid configuration.
    let c = h.run(&["config", "check"]);
    assert_eq!(c.status.code(), Some(0), "{}", text(&c.stderr));
    assert!(
        text(&c.stdout).contains("result: valid"),
        "{}",
        text(&c.stdout)
    );
}

// 이것을 실패시키는 것: 있는 설정을 덮어쓰거나 바꾸는 것, 차이를 알리지 않는 것, 같은 값인데 차이로 알리는 것,
// 있는 파일이 있을 때 종료 코드가 0이 아닌 것.
#[test]
fn an_existing_config_is_never_touched_and_only_differences_are_shown() {
    let h = Home::new("exists");
    std::fs::create_dir_all(h.config().parent().unwrap()).unwrap();
    std::fs::set_permissions(
        h.config().parent().unwrap(),
        std::fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    let mine = b"# mine\nicons = \"nerd\"\n[colors]\nmode = \"dark\"\n";
    std::fs::write(h.config(), mine).unwrap();
    std::fs::set_permissions(h.config(), std::fs::Permissions::from_mode(0o600)).unwrap();
    let before = h.tree();
    let o = h.run(&["--yes", "--icons", "unicode", "--mode", "dark"]);
    assert_eq!(o.status.code(), Some(0), "{o:?}");
    assert_eq!(std::fs::read(h.config()).unwrap(), mine);
    assert_eq!(h.tree(), before);
    let err = text(&o.stderr);
    assert!(err.contains("already there"), "{err}");
    assert!(
        err.contains("icons: \"nerd\" now, \"unicode\" suggested"),
        "{err}"
    );
    assert!(
        err.contains("style.preset: not set now, \"lean\" suggested"),
        "{err}"
    );
    assert!(
        !err.contains("colors.mode:"),
        "the same value is no difference: {err}"
    );
    // The startup line is still given.
    assert_eq!(text(&o.stdout), "eval \"$(bingsu init zsh)\"\n");
}

// 이것을 실패시키는 것: 이미 있는 설정 폴더에 새 파일을 만들 때 폴더 `fsync`가 실패하는 것(Linux에서 폴더를
// 검색 전용 `O_PATH`로 연 채 `sync_all`하면 EBADF: 파일은 만들어지는데 종료가 실패하고 시작 줄이 안 나옴).
#[test]
fn a_config_folder_that_is_already_there_gets_the_file() {
    let h = Home::new("folder");
    let dir = h.config().parent().unwrap().to_path_buf();
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    let o = h.run(&["--yes", "--icons", "nerd", "--mode", "auto"]);
    assert_eq!(o.status.code(), Some(0), "{o:?}");
    assert_eq!(text(&o.stdout), "eval \"$(bingsu init zsh)\"\n");
    assert!(text(&o.stderr).contains("wrote "), "{}", text(&o.stderr));
    assert_eq!(
        std::fs::metadata(h.config()).unwrap().permissions().mode() & 0o7777,
        0o600
    );
}

// `config.json` is the same place as `config.toml`: setup writes nothing beside it, compares the
// choices with it, and the settings still read afterwards.
// 이것을 실패시키는 것: setup이 `config.toml`만 보는 것(그 곁에 `config.toml`을 만들어 다음 읽기가 E308로
// 멈춤), JSON 파일의 차이를 TOML로 읽으려다 "does not parse"로 내는 것.
#[test]
fn a_json_config_is_the_settings_file_already_there() {
    let h = Home::new("json");
    let dir = h.config().parent().unwrap().to_path_buf();
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    let json = dir.join("config.json");
    let mine = b"{\"icons\": \"nerd\", \"colors\": {\"mode\": \"dark\"}}";
    std::fs::write(&json, mine).unwrap();
    std::fs::set_permissions(&json, std::fs::Permissions::from_mode(0o600)).unwrap();
    let before = h.tree();
    let o = h.run(&["--yes", "--icons", "unicode", "--mode", "dark"]);
    assert_eq!(o.status.code(), Some(0), "{o:?}");
    assert_eq!(h.tree(), before, "setup wrote beside config.json");
    assert_eq!(std::fs::read(&json).unwrap(), mine);
    let err = text(&o.stderr);
    assert!(err.contains("config.json is already there"), "{err}");
    assert!(
        err.contains("icons: \"nerd\" now, \"unicode\" suggested"),
        "{err}"
    );
    assert_eq!(text(&o.stdout), "eval \"$(bingsu init zsh)\"\n");
    let c = h.run(&["config", "check"]);
    assert_eq!(c.status.code(), Some(0), "{}", text(&c.stderr));
    let out = text(&c.stdout) + &text(&c.stderr);
    assert!(
        out.contains("result: valid") && !out.contains("E308"),
        "{out}"
    );
}

// 이것을 실패시키는 것: init이 고정한 값이 있는 셸에서 시작 줄을 새로 넣으라고 하는 것, 없는 셸에서 이미 돈다고
// 하는 것, 고정한 설정 폴더가 아닌 곳(지금의 XDG_CONFIG_HOME)에 쓰는 것, 시작 줄을 stdout 밖에 내는 것,
// bingsu가 도는 셸에서 쓴 뒤 발행하지 않는 것, 돌지 않는 셸에서 발행하는 것(런타임 폴더를 만듦), `--yes`로
// 다 준 경로에 doctor 안내를 내는 것.
#[test]
fn a_shell_that_runs_bingsu_gets_the_file_applied() {
    let e = user_env::Env::new("cli_setup", "runs-here");
    let var = user_env::frame(&e.pinned_words());
    let args = ["setup", "--yes", "--icons", "nerd", "--mode", "dark"];
    let mut c = e.cmd_pinned(&args, &var);
    c.env("SHELL", "/bin/zsh");
    // SAFETY: `detach` only calls setsid, which is async-signal-safe.
    unsafe { c.pre_exec(detach) };
    let o = c.output().unwrap();
    assert_eq!(o.status.code(), Some(0), "{}", text(&o.stderr));
    let err = text(&o.stderr);
    assert!(
        err.contains("bingsu already runs in this shell or the shell that started it; this line is only for a new setup:\n"),
        "{err}"
    );
    assert!(!err.contains("Add this"), "{err}");
    assert!(
        err.contains("bingsu: applied; the next prompt shows it\n"),
        "{err}"
    );
    assert!(!err.contains("bingsu doctor"), "{err}");
    assert_eq!(text(&o.stdout), "eval \"$(bingsu init zsh)\"\n");
    assert!(e.config_dir().join("config.toml").exists());
    assert!(e.context_dir().join("snapshot").exists(), "published");
    assert!(!e.base.join("elsewhere").exists());

    let h = Home::new("runs-not");
    let o = h.run(&args[1..]);
    assert_eq!(o.status.code(), Some(0), "{o:?}");
    let err = text(&o.stderr);
    assert!(
        err.contains("Add this to your shell's startup file to start bingsu:\n"),
        "{err}"
    );
    assert!(
        err.contains("bingsu: the new look shows once your shell loads bingsu\n"),
        "{err}"
    );
    assert!(
        !err.contains("applied") && !err.contains("bingsu doctor"),
        "{err}"
    );
    assert!(
        !err.contains("result:"),
        "the check is shown only when not valid: {err}"
    );
    assert_eq!(
        h.tree(),
        ["cfg 700", "cfg/bingsu 700", "cfg/bingsu/config.toml 600"],
        "nothing published"
    );
}

// 이것을 실패시키는 것: `config use`로 고른 파일이 있는데 설정 폴더에 읽히지 않을 config.toml을 만드는 것, 고른
// 파일과 비교하지 않는 것, 고른 파일이 없는데 쓰는 것, 그때 종료 코드가 1이 아니거나 시작 줄을 내는 것.
#[test]
fn the_chosen_settings_file_is_the_one_setup_looks_at() {
    let e = user_env::Env::new("cli_setup", "chosen");
    let chosen = e.put("other/work.toml", "icons = \"ascii\"\n");
    let o = e.run(&["config", "use", chosen.to_str().unwrap()]);
    assert_eq!(o.status.code(), Some(0), "{}", text(&o.stderr));
    let run = || {
        let mut c = e.cmd(&["setup", "--yes", "--icons", "nerd", "--mode", "dark"]);
        c.env("SHELL", "/bin/zsh");
        // SAFETY: `detach` only calls setsid, which is async-signal-safe.
        unsafe { c.pre_exec(detach) };
        c.output().unwrap()
    };
    let o = run();
    let err = text(&o.stderr);
    assert_eq!(o.status.code(), Some(0), "{err}");
    assert!(
        err.contains("other/work.toml is already there, so nothing was written."),
        "{err}"
    );
    assert!(
        err.contains("icons: \"ascii\" now, \"nerd\" suggested"),
        "{err}"
    );
    assert!(!e.config_dir().join("config.toml").exists());
    assert_eq!(text(&o.stdout), "eval \"$(bingsu init zsh)\"\n");

    std::fs::remove_file(&chosen).unwrap();
    let o = run();
    let err = text(&o.stderr);
    assert_eq!(o.status.code(), Some(1), "{err}");
    assert!(
        err.contains(&format!(
            "bingsu: your chosen settings file {} is missing; run bingsu config use again\n",
            chosen.display()
        )),
        "{err}"
    );
    assert!(!e.config_dir().join("config.toml").exists());
    assert!(o.stdout.is_empty());
}

// 이것을 실패시키는 것: `config use` 기록을 읽지 못했을 때(읽힐 파일을 모름) 설정 폴더에 쓰는 것, 그때 종료 코드가
// 1이 아닌 것.
#[test]
fn an_unreadable_settings_choice_writes_nothing() {
    let e = user_env::Env::new("cli_setup", "choice-unread");
    let long = e.base.join("x".repeat(300));
    let mut c = e.cmd(&["setup", "--yes", "--icons", "nerd", "--mode", "dark"]);
    // A name longer than a folder may hold: opening the state root fails
    // with ENAMETOOLONG, which says nothing about the record.
    c.env("XDG_STATE_HOME", &long).env("SHELL", "/bin/zsh");
    // SAFETY: `detach` only calls setsid, which is async-signal-safe.
    unsafe { c.pre_exec(detach) };
    let o = c.output().unwrap();
    let err = text(&o.stderr);
    assert_eq!(o.status.code(), Some(1), "{err}");
    assert!(
        err.contains("the settings choice could not be read"),
        "{err}"
    );
    assert!(!e.config_dir().join("config.toml").exists());
}

// 이것을 실패시키는 것: 다른 파일 때문에 유효하지 않은 설정을 쓴 뒤 검사 출력을 보이지 않는 것, 그것을 stdout에
// 내는 것, 그때 새 모습이 나온다고 하는 것, 쓴 파일이 있는데 종료 코드가 0이 아닌 것.
#[test]
fn another_invalid_file_is_shown_and_nothing_claims_to_apply() {
    let h = Home::new("invalid-other");
    let conf = h.config().parent().unwrap().join("conf.d");
    std::fs::create_dir_all(&conf).unwrap();
    for d in [h.0.join("cfg"), h.0.join("cfg/bingsu"), conf.clone()] {
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    std::fs::write(conf.join("10-bad.toml"), "[style]\ngap = 1234\n").unwrap();
    std::fs::set_permissions(
        conf.join("10-bad.toml"),
        std::fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    let o = h.run(&["--yes", "--icons", "nerd", "--mode", "dark"]);
    let err = text(&o.stderr);
    assert_eq!(o.status.code(), Some(0), "{err}");
    assert!(h.config().exists());
    assert!(err.contains("E202"), "{err}");
    assert!(
        err.contains("bingsu: not applied; the prompt keeps the last valid settings\n"),
        "{err}"
    );
    assert!(!err.contains("new look"), "{err}");
    assert_eq!(text(&o.stdout), "eval \"$(bingsu init zsh)\"\n");
}

// 이것을 실패시키는 것: 파일을 쓴 뒤 stdout이 시작 줄을 받지 못했는데 0으로 끝내는 것(시작 줄을 받는 스크립트가 빈 값을
// 모름), 쓴 파일과 시작 줄을 stderr에 알리지 않는 것, 그 때문에 파일을 지우거나 쓰지 않는 것.
#[test]
fn a_startup_line_stdout_does_not_take_is_an_error_but_the_file_stays() {
    use std::os::fd::FromRawFd;
    let h = Home::new("stdout-gone");
    let mut ends = [0; 2];
    // SAFETY: `ends` has room for the two descriptors.
    assert_eq!(unsafe { libc::pipe(ends.as_mut_ptr()) }, 0);
    // SAFETY: the read end, owned here and closed at once: writes fail (EPIPE).
    drop(unsafe { std::fs::File::from_raw_fd(ends[0]) });
    // SAFETY: the write end, owned here from now on.
    let write = unsafe { std::fs::File::from_raw_fd(ends[1]) };
    let o = h
        .cmd(&["--yes", "--icons", "nerd", "--mode", "dark"])
        .stdout(write)
        .output()
        .unwrap();
    let err = text(&o.stderr);
    assert_eq!(o.status.code(), Some(1), "{err}");
    assert!(h.config().exists());
    assert!(
        err.contains(&format!(
            "bingsu: {} was written, but standard output did not take the startup line; it is:\neval \"$(bingsu init zsh)\"\n",
            h.config().display()
        )),
        "{err}"
    );
}
