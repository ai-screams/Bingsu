//! `bingsu setup` without a terminal: every argument given, the file made
//! private and only when there is none, nothing else touched.
#![cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

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
        let mut c = Command::new(env!("CARGO_BIN_EXE_bingsu"));
        c.env_clear()
            .env("HOME", &self.0)
            .env("XDG_CONFIG_HOME", self.0.join("cfg"))
            .env("SHELL", "/bin/zsh");
        // `setup` unless the test names another command.
        if args.first() != Some(&"config") {
            c.arg("setup");
        }
        c.args(args);
        // SAFETY: `detach` only calls setsid, which is async-signal-safe.
        unsafe { c.pre_exec(detach) };
        c.output().unwrap()
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
        &["--bogus"],
    ] {
        assert_eq!(h.run(bad).status.code(), Some(2), "{bad:?}");
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
