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

// 이것을 실패시키는 것: 이름이 다른 뿌리의 바이트를 내는 것, 다른 뿌리를 읽은 답을 내는 것, 읽지 않은 뿌리에 바이트를
// 지어내는 것.
#[test]
fn a_root_gives_the_bytes_the_reading_got() {
    let fx = Fx::new("bytes");
    layered(&fx);
    let (tape, _) = fx.read();
    let name = |p: PathBuf| p.into_os_string().into_encoded_bytes();
    assert_eq!(
        tape.root_bytes(&name(fx.root.join("config.local.toml"))),
        Some(&b"[style]\ninner_end = \"flat\"\n"[..])
    );
    assert_eq!(
        tape.root_bytes(&name(fx.root.join("conf.d/10-a.toml"))),
        Some(&b"extends = [\"~/shape.yaml\"]\n[style]\ngap = true\n"[..])
    );
    assert_eq!(tape.root_bytes(&name(fx.root.join("config.toml"))), None);
    assert_eq!(tape.root_bytes(b"(built-in)"), None);
}

// 이것을 실패시키는 것: 다른 출처의 `extends`가 아직 없는 새 파일을 가리킬 때 미리보기가 시작 때의 "없음"을 그대로
// 돌려주는 것(저장 뒤에는 그 파일을 거쳐 합쳐짐), 그 길을 기록하지 않는 것.
#[test]
fn an_extends_entry_that_names_the_new_file_reaches_it() {
    let fx = Fx::new("ext-target");
    let target = fx.root.join("config.toml");
    fx.put(
        &fx.home.join("shape.toml"),
        &format!(
            "extends = [\"{}\"]\n[style]\npreset = \"lean\"\n",
            target.display()
        ),
    );
    fx.put(
        &fx.root.join("conf.d/10-a.toml"),
        "extends = [\"~/shape.toml\"]\n[style]\ngap = true\n",
    );
    let sources = fx.sources();
    let preview = report::from_loaded(sources.load(NEW.as_bytes()), Mode::Dark);
    fx.put(&target, NEW);
    let real = report::from_loaded(fx.read().1, Mode::Dark);
    assert_eq!(applied(&preview), applied(&real));
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

// 이것을 실패시키는 것: 새 파일의 열쇠를 내장 출처의 것(0, 0)이나 실제 파일이 가질 수 있는 것으로 하는 것,
// 미리보기가 그 열쇠를 Loader에 넘겨 다시 읽기에 남기는 것.
#[test]
fn the_new_file_key_is_reserved_and_never_reaches_the_loader() {
    assert_eq!(NEW_FILE_KEY.ino, 0, "no file has inode 0");
    assert_ne!(NEW_FILE_KEY, crate::commands::config_load::BUILTIN_KEY);
    assert_ne!(NEW_FILE_KEY.dev, u64::MAX, "the loader's stand-ins");
    let fx = Fx::new("key");
    layered(&fx);
    let sources = fx.sources();
    for _ in 0..3 {
        let r = report::from_loaded(sources.load(NEW.as_bytes()), Mode::Dark);
        let keys = r.files.iter().filter(|f| f.opened.key == NEW_FILE_KEY);
        assert_eq!(keys.count(), 1);
    }
    let (now, loaded) = fx.read();
    assert!(sources.unchanged(&now));
    let real = loaded.unwrap();
    assert!(real.files.iter().all(|f| f.opened.key != NEW_FILE_KEY));
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
        to: None,
        got: got.clone(),
    };
    let calls = [edge(&first), edge(&second)];
    let mut replay = Replay {
        calls: &calls,
        used: vec![false; 2],
        target: None,
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

/// The existing settings file's sources: the start's reading with the
/// settings place's root as the target.
fn existing_sources(fx: &Fx) -> Sources {
    let (tape, _) = fx.read();
    let (key, _, why) = tape
        .settings_root(&fx.root.join("config.toml"))
        .expect("a settings file");
    assert_eq!(why, None);
    Sources::existing(tape, key, VERSION).expect("read at the start")
}

// 이것을 실패시키는 것: 있는 파일의 미리보기가 그 파일 자리에 후보 바이트를 두지 않는 것(시작 때 바이트로 그림), 그
// 파일을 가리키는 `extends` 답에 후보를 주지 않는 것, 신뢰·이름을 바꾸는 것, 다른 파일의 바이트를 바꾸는 것. 후보를 실제로
// 쓴 뒤 읽은 결과와 같아야 한다.
#[test]
fn an_existing_file_previews_as_the_reader_reads_it_changed() {
    let fx = Fx::new("existing");
    let original = "# mine\n[style]\npreset = \"lean\"\n";
    let path = fx.root.join("config.toml");
    fx.put(&path, original);
    layered(&fx);
    // A conf.d file that extends the settings file too.
    fx.put(
        &fx.root.join("conf.d/20-b.toml"),
        &format!("extends = [\"{}\"]\n", path.display()),
    );
    let sources = existing_sources(&fx);
    assert_eq!(sources.original(), original.as_bytes());
    let changed = "# mine\n[style]\npreset = \"pill\"\nouter_end = \"round\"\n";
    let preview = report::from_loaded(sources.load(changed.as_bytes()), Mode::Dark);
    assert!(sources.target(&preview.files).is_some());
    fx.put(&path, changed);
    let real = report::from_loaded(fx.read().1, Mode::Dark);
    assert_eq!(applied(&preview), applied(&real));
    assert!(preview.snapshot.is_some(), "{:?}", preview.diagnostics);
    assert_eq!(preview.snapshot, real.snapshot);
    assert_eq!(preview.diagnostics, real.diagnostics);
}

// 이것을 실패시키는 것: 설정 파일의 뿌리를 읽은 답이 아닌 `extends` 답이 catalog의 그 자리를 가질 때(core는 더 강한 신뢰로
// 같은 FileKey를 연 답에 자리를 넘긴다) 그 답에 후보 바이트를 주지 않는 것(미리보기가 시작 때 바이트로 그림). 시작
// 기록의 뿌리 답을 모양만 신뢰로 바꿔 그 경우를 만든다. 실제 loader로 같은 파일에 더 강한 신뢰의 별칭을 만들지는 못했다
// (모양만 폴더의 링크와 믿는 폴더의 하드 링크는 별칭도 Unsafe로 읽혔다).
#[test]
fn every_answer_that_opened_the_settings_file_gets_the_changed_bytes() {
    let fx = Fx::new("existing-alias");
    let path = fx.root.join("config.toml");
    fx.put(&path, "[style]\npreset = \"lean\"\n");
    fx.put(
        &fx.root.join("conf.d/20-b.toml"),
        &format!("extends = [\"{}\"]\n", path.display()),
    );
    let (mut tape, _) = fx.read();
    let settings = |display: &[u8]| display == path.as_os_str().as_bytes();
    for r in &mut tape.roots {
        if let Root::File(m) = r
            && settings(&m.display)
        {
            m.trust = Trust::ShapeOnly;
        }
    }
    for c in &mut tape.calls {
        if let Call::Root(_, Ok(o)) = c
            && settings(&o.display)
        {
            o.trust = Trust::ShapeOnly;
        }
    }
    let (key, _, _) = tape.settings_root(&path).expect("the settings file");
    let sources = Sources::existing(tape, key, VERSION).unwrap();
    let changed = "[style]\npreset = \"pill\"\n";
    let r = report::from_loaded(sources.load(changed.as_bytes()), Mode::Dark);
    let f = r.files.iter().find(|f| f.opened.key == key).unwrap();
    assert_eq!(
        f.trust,
        Trust::Executable,
        "the trusted answer took the place"
    );
    assert_eq!(f.opened.bytes, changed.as_bytes());
}

// 이것을 실패시키는 것: 설정 자리의 파일을 읽지 못했는데 읽었다고 하는 것(그 파일로 편집판을 엶), 읽은 파일을 읽지
// 못했다고 하는 것, 설정 자리에 파일이 없을 때 다른 뿌리(conf.d)를 설정 파일로 보는 것.
#[test]
fn the_settings_root_says_whether_it_was_read() {
    let fx = Fx::new("settings-root");
    layered(&fx);
    let path = fx.root.join("config.toml");
    let (tape, _) = fx.read();
    assert!(
        tape.settings_root(&path).is_none(),
        "conf.d is not the settings file"
    );
    fx.put(&path, "[style]\npreset = \"lean\"\n");
    let (tape, _) = fx.read();
    let (key, name, why) = tape.settings_root(&path).unwrap();
    assert!(name.ends_with(b"config.toml"));
    assert_eq!(why, None);
    assert!(Sources::existing(tape, key, VERSION).is_some());
    // Root reads a file whatever its mode.
    if sys::current_uid() == 0 {
        return;
    }
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000)).unwrap();
    let (tape, _) = fx.read();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let (key, _, why) = tape.settings_root(&path).unwrap();
    assert!(why.is_some(), "a file the reader cannot open is not read");
    assert!(Sources::existing(tape, key, VERSION).is_none());
}

// 이것을 실패시키는 것: 다 읽지 못한 읽기(없는 `extends` 대상)를 다 읽은 것으로 기록하는 것, 다 읽은 읽기를 아니라고
// 기록하는 것, 시작 읽기의 그 기록을 Sources가 잃는 것.
#[test]
fn a_reading_says_whether_it_read_everything() {
    let fx = Fx::new("whole");
    layered(&fx);
    let (whole, _) = fx.read();
    assert!(whole.complete());
    assert!(fx.sources().complete());
    fx.put(
        &fx.root.join("conf.d/20-b.toml"),
        "extends = [\"missing.toml\"]\n",
    );
    let (partial, loaded) = fx.read();
    assert!(!partial.complete());
    let r = report::from_loaded(loaded, Mode::Dark);
    assert!(
        !r.order.is_empty(),
        "the missed source is dropped, an order stays"
    );
    let sources = fx.sources();
    assert!(!sources.complete());
    assert!(sources.unchanged(&partial));
    assert!(!sources.unchanged(&whole));
}
