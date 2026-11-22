use super::*;
use crate::commands::config_load::{Loader, Places};
use crate::commands::group_policy::SystemGroups;
use crate::commands::init::roots::ConfigRootPin;
use crate::commands::sys;
use bingsu_core::color::palette::Mode;
use bingsu_core::config::compile::BUILTIN_TOML;
use bingsu_core::config::report::{self, ConfigReport};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

const VERSION: Version = Version {
    numbers: [0, 1, 0],
    pre_release: true,
};

/// A settings folder with `conf.d` and a home folder for `~/` in
/// `extends`, private to the test.
struct Fx {
    base: PathBuf,
    root: PathBuf,
    home: PathBuf,
}

impl Fx {
    fn new(tag: &str) -> Self {
        let d = std::env::temp_dir().join(format!("bingsu-ss-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        // `/var` is a link on macOS; the loader shows canonical paths.
        let base = std::fs::canonicalize(&d).unwrap();
        std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o700)).unwrap();
        let root = base.join("config");
        let home = base.join("home");
        std::fs::create_dir_all(root.join("conf.d")).unwrap();
        std::fs::create_dir_all(&home).unwrap();
        Self { base, root, home }
    }

    fn put(&self, p: &Path, text: &str) {
        std::fs::write(p, text).unwrap();
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o600)).unwrap();
    }

    fn loader(&self) -> Loader {
        let me = sys::current_uid();
        let name = sys::passwd_entry(me).unwrap().name;
        Loader::new(Places {
            config_root: ConfigRootPin::check(&self.root, me, &mut SystemGroups::new(&name))
                .unwrap(),
            home: self.home.clone(),
            me,
            user: name,
        })
    }

    /// A reading of the folder as it is now, through the real loader.
    fn read(&self) -> (Tape, Result<LoadReport, LoadError>) {
        let mut loader = self.loader();
        let roots = loader.roots(BUILTIN_TOML.as_bytes());
        Tape::read(roots, &mut loader, VERSION)
    }

    fn sources(&self) -> Sources {
        let file = NewFile {
            display: self
                .root
                .join("config.toml")
                .into_os_string()
                .into_encoded_bytes(),
            trust: Trust::Executable,
        };
        Sources::new(self.read().0, file, VERSION)
    }
}

impl Drop for Fx {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.base);
    }
}

/// What a reading applies: each applied file's name and trust, and the
/// compiled settings.
fn applied(r: &ConfigReport) -> (Vec<(Vec<u8>, Trust)>, bool) {
    let names = r
        .order
        .iter()
        .map(|id| {
            let f = &r.files[id.0 as usize];
            (f.opened.display.clone(), f.trust)
        })
        .collect();
    (names, r.snapshot.is_some())
}

const NEW: &str = "[style]\npreset = \"pill\"\nouter_end = \"round\"\n";

/// Every kind of source the reader merges around the new file: a `conf.d`
/// file that extends a shape-only YAML file in the home folder, and a local
/// file.
fn layered(fx: &Fx) {
    fx.put(&fx.home.join("shape.yaml"), "style:\n  separator: slant\n");
    fx.put(
        &fx.root.join("conf.d/10-a.toml"),
        "extends = [\"~/shape.yaml\"]\n[style]\ngap = true\n",
    );
    fx.put(
        &fx.root.join("config.local.toml"),
        "[style]\ninner_end = \"flat\"\n",
    );
}

// 이것을 실패시키는 것: 새 파일을 내장 바로 뒤가 아닌 곳(끝, 맨 앞)에 두는 것, 새 파일에 다른 신뢰를 주는 것,
// 미리보기가 extends 답을 테이프에서 내지 않는 것(extends 파일이 빠져 컴파일 결과가 달라짐), 기록하거나
// 재생할 때 YAML을 읽지 않는 것.
#[test]
fn a_preview_is_what_the_reader_applies_once_the_file_is_there() {
    let fx = Fx::new("same");
    layered(&fx);
    let sources = fx.sources();
    let preview = report::from_loaded(sources.load(NEW.as_bytes()), Mode::Dark);
    let target = sources
        .target(&preview.files)
        .expect("the new file is in the catalog");
    assert_eq!(
        preview.order.get(1),
        Some(&target),
        "right after the built-in source"
    );

    fx.put(&fx.root.join("config.toml"), NEW);
    let real = report::from_loaded(fx.read().1, Mode::Dark);
    assert_eq!(applied(&preview), applied(&real));
    assert!(preview.snapshot.is_some(), "{:?}", preview.diagnostics);
    assert_eq!(preview.snapshot, real.snapshot);
    assert_eq!(preview.diagnostics, real.diagnostics);
}

// 이것을 실패시키는 것: 미리보기가 키마다 새 Loader로 디스크를 다시 읽는 것(시작 뒤 지운 파일이 빠짐).
#[test]
fn a_preview_opens_no_file() {
    let fx = Fx::new("nofile");
    layered(&fx);
    let sources = fx.sources();
    let before = report::from_loaded(sources.load(NEW.as_bytes()), Mode::Dark);
    for p in [
        fx.home.join("shape.yaml"),
        fx.root.join("conf.d/10-a.toml"),
        fx.root.join("config.local.toml"),
    ] {
        std::fs::remove_file(p).unwrap();
    }
    let after = report::from_loaded(sources.load(NEW.as_bytes()), Mode::Dark);
    assert_eq!(applied(&before), applied(&after));
    assert_eq!(before.snapshot, after.snapshot);
    assert_eq!(
        applied(&after).0.len(),
        5,
        "built-in, new, conf.d, its extends, local"
    );
}

// 이것을 실패시키는 것: 미리보기 경로에서 설정의 명령을 실행하는 것. fixture의 명령이 정말 표지를 만드는지
// 먼저 확인하므로, 표지가 없는 것은 명령이 돌지 않았다는 뜻이다.
#[test]
fn nothing_a_config_runs_runs_in_a_preview() {
    let fx = Fx::new("norun");
    let marker = fx.base.join("ran");
    fx.put(
        &fx.root.join("conf.d/20-cmd.toml"),
        &format!(
            "[segment.\"custom/mark\"]\nkind = \"command\"\ncommand = [\"/usr/bin/touch\", \"{}\"]\n\n[layout.line1]\nleft = [\"dir\", \"custom/mark\"]\n",
            marker.display()
        ),
    );
    let sources = fx.sources();
    let preview = report::from_loaded(sources.load(NEW.as_bytes()), Mode::Dark);
    let compiled = preview.snapshot.as_ref().expect("the settings compile");
    let unit = compiled
        .exec_units
        .iter()
        .find(|u| u.id == "custom/mark")
        .expect("the command segment is a unit");
    assert_eq!(unit.not_run, None, "the unit would run in the prompt");
    assert!(!marker.exists(), "a preview ran the command");
    // The fixture is live: running the unit leaves the marker.
    let bingsu_core::config::compile::ExecPolicy::Command { argv, .. } = &unit.policy else {
        panic!("a command unit");
    };
    let done = std::process::Command::new(&argv[0])
        .args(&argv[1..])
        .status()
        .unwrap();
    assert!(done.success() && marker.exists());
}

// 이것을 실패시키는 것: 다시 읽기 비교를 늘 같다고 하는 것, 뿌리 목록만 비교하는 것(파일 바이트가 바뀐 것을
// 놓침), 대상 자리에 새로 생긴 파일을 놓치는 것.
#[test]
fn a_changed_source_is_seen_before_the_file_is_written() {
    let fx = Fx::new("changed");
    layered(&fx);
    let sources = fx.sources();
    assert!(sources.unchanged(&fx.read().0), "nothing changed");
    // Same size, other bytes: only the read answers differ.
    fx.put(
        &fx.root.join("conf.d/10-a.toml"),
        "extends = [\"~/shape.yaml\"]\n[style]\ngap = 1234\n",
    );
    assert!(!sources.unchanged(&fx.read().0));
    layered(&fx);
    assert!(sources.unchanged(&fx.read().0));
    fx.put(&fx.home.join("shape.yaml"), "style:\n  separator: round\n");
    assert!(
        !sources.unchanged(&fx.read().0),
        "a file another one extends"
    );
    layered(&fx);
    fx.put(&fx.root.join("config.toml"), "");
    assert!(!sources.unchanged(&fx.read().0), "the file appeared");
}

fn opened(key: FileKey) -> Opened {
    Opened {
        key,
        bytes: Vec::new(),
        trust: Trust::ShapeOnly,
        display: b"/x".to_vec(),
    }
}

// 이것을 실패시키는 것: 새 파일의 열쇠를 테이프의 뿌리나 extends 답의 열쇠와 겹치게 고르는 것.
#[test]
fn the_new_file_gets_a_key_no_source_has() {
    let k = |ino| FileKey { dev: 0, ino };
    let tape = Tape {
        roots: vec![Root::Read(opened(k(0))), Root::Read(opened(k(1)))],
        calls: vec![Call::Edge {
            from: k(1),
            text: String::from("a"),
            got: Ok(opened(k(2))),
        }],
    };
    let file = NewFile {
        display: b"/c/config.toml".to_vec(),
        trust: Trust::Executable,
    };
    let s = Sources::new(tape, file, VERSION);
    assert_eq!(s.key, k(3));
}

// 이것을 실패시키는 것: 같은 extends를 두 번 연 답을 늘 첫 답으로 내는 것, 테이프에 없는 부름에 답을 지어내는 것.
#[test]
fn answers_come_back_in_the_order_they_were_given() {
    let from = opened(FileKey { dev: 9, ino: 9 });
    let first = Ok(opened(FileKey { dev: 9, ino: 1 }));
    let second = Err(OpenError {
        reason: String::from("over budget"),
        trust: Trust::ShapeOnly,
    });
    let edge = |got: &Result<Opened, OpenError>| Call::Edge {
        from: from.key,
        text: String::from("a.toml"),
        got: got.clone(),
    };
    let calls = [edge(&first), edge(&second)];
    let mut replay = Replay {
        calls: &calls,
        used: vec![false; 2],
    };
    let r = ExtendsRef {
        text: String::from("a.toml"),
        span: Default::default(),
    };
    assert_eq!(replay.open(&from, &r), first);
    assert_eq!(replay.open(&from, &r), second);
    assert_eq!(replay.open(&from, &r), second, "the last answer stays");
    let other = ExtendsRef {
        text: String::from("b.toml"),
        ..r
    };
    assert_eq!(
        replay.open(&from, &other).unwrap_err().reason,
        "not read when setup started"
    );
    let meta = RootMeta {
        key: FileKey { dev: 5, ino: 5 },
        size: 0,
        trust: Trust::Executable,
        display: Vec::new(),
    };
    assert_eq!(
        replay.open_root(&meta).unwrap_err().trust,
        Trust::Executable
    );
}
