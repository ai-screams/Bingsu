//! The helper's side of the version manager resolvers (plan D2, U-12 R2).
//! It gathers the facts the pure rules (`bingsu_core::collection::manager`)
//! decide on: which manager's shim the language's command is, the manager's
//! folders from the shell environment, rustup's settings file and one
//! install check. It runs in the helper before its filter, beside the
//! executable lookup, after the marker is installed (D2 ruling Q1); the
//! collector's read confinement is not widened.
//!
//! Nothing here runs a program. A wrong answer can only show a wrong
//! version without running it or run the version command (D3) when it was
//! not needed; what runs still passes the `PATH` and relay rules.
use bingsu_core::collection::manager::{self, Decision, Facts, Manager, Plan, Selection, Settings};
use bingsu_core::command::plan::Environ;
use std::{
    ffi::OsStr,
    fs::File,
    io::Read,
    os::{fd::AsFd, unix::ffi::OsStrExt},
    path::{Component, Path, PathBuf},
};

use super::sys;

/// The largest rustup settings file read; rustup's own is a few hundred
/// bytes plus one line per directory override.
pub(crate) const SETTINGS_MAX: u64 = 65_536;

/// The target triple this build runs as, in rustup's spelling, for a
/// settings file without `default_host_triple` (D2 ruling Q8). A different
/// rustup host only misses the install check.
pub(crate) const BUILD_HOST: &[u8] = build_host();

const fn build_host() -> &'static [u8] {
    if cfg!(all(target_arch = "aarch64", target_os = "macos")) {
        b"aarch64-apple-darwin"
    } else if cfg!(all(target_arch = "x86_64", target_os = "macos")) {
        b"x86_64-apple-darwin"
    } else if cfg!(all(
        target_arch = "aarch64",
        target_os = "linux",
        target_env = "musl"
    )) {
        b"aarch64-unknown-linux-musl"
    } else if cfg!(all(
        target_arch = "x86_64",
        target_os = "linux",
        target_env = "musl"
    )) {
        b"x86_64-unknown-linux-musl"
    } else if cfg!(all(target_arch = "aarch64", target_os = "linux")) {
        b"aarch64-unknown-linux-gnu"
    } else if cfg!(all(target_arch = "x86_64", target_os = "linux")) {
        b"x86_64-unknown-linux-gnu"
    } else {
        b""
    }
}

/// What the language's command on the sanitized `PATH` is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Shim {
    /// A manager with a resolver.
    Manager(Manager),
    /// A manager bingsu does not resolve (asdf, mise, volta): the value is
    /// hidden with a diagnostic (U-12 R2).
    Unsupported,
    /// Not a manager's shim: the version command runs (D3).
    None,
}

/// The managers' folders, from the shell environment, each absolute.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Homes {
    pub rustup: Option<PathBuf>,
    pub cargo: Option<PathBuf>,
    pub pyenv: Option<PathBuf>,
    /// Shim folders of managers without a resolver.
    pub unsupported: Vec<PathBuf>,
}

/// An environment value that names a folder: absolute, no `..` (an env
/// frame entry never holds a NUL: the frame splits on it).
fn folder(value: &[u8]) -> Option<PathBuf> {
    let path = Path::new(OsStr::from_bytes(value));
    // Fails without it: homes_follow_the_environment (a relative value, `..`).
    if !path.is_absolute() || path.components().any(|c| c == Component::ParentDir) {
        return None;
    }
    Some(path.to_path_buf())
}

/// `name` if set, else `fallback` below `HOME`.
fn home_of(vars: &Environ<'_>, name: &[u8], fallback: &str) -> Option<PathBuf> {
    match vars.get(name) {
        Some(value) => folder(value),
        None => folder(vars.get(b"HOME")?).map(|home| home.join(fallback)),
    }
}

pub(crate) fn homes(vars: &Environ<'_>) -> Homes {
    let unsupported = [
        home_of(vars, b"ASDF_DATA_DIR", ".asdf").map(|p| p.join("shims")),
        home_of(vars, b"MISE_DATA_DIR", ".local/share/mise").map(|p| p.join("shims")),
        home_of(vars, b"VOLTA_HOME", ".volta").map(|p| p.join("bin")),
    ];
    Homes {
        rustup: home_of(vars, b"RUSTUP_HOME", ".rustup"),
        cargo: home_of(vars, b"CARGO_HOME", ".cargo"),
        pyenv: home_of(vars, b"PYENV_ROOT", ".pyenv"),
        unsupported: unsupported.into_iter().flatten().collect(),
    }
}

/// Which shim `folder` (the first sanitized `PATH` folder holding the
/// command's name) is. `canonical`, when the lookup resolved the command,
/// is its canonical file: rustup installed by a package manager links
/// `rustc` to `rustup` elsewhere. Folders compare as given: the sanitized
/// `PATH` holds canonical folders, and a manager folder named through a
/// link is simply not recognized (the command then runs).
pub(crate) fn classify(
    command: Manager,
    folder: &Path,
    canonical: Option<&Path>,
    homes: &Homes,
) -> Shim {
    // Fails without it: classify_table (pyenv shims folder).
    if command == Manager::Pyenv
        && homes
            .pyenv
            .as_ref()
            .is_some_and(|root| folder == root.join("shims"))
    {
        return Shim::Manager(Manager::Pyenv);
    }
    // Fails without it: classify_table (cargo bin folder).
    if command == Manager::Rustup
        && homes
            .cargo
            .as_ref()
            .is_some_and(|cargo| folder == cargo.join("bin"))
    {
        return Shim::Manager(Manager::Rustup);
    }
    // Fails without it: classify_table (asdf shims folder).
    if homes.unsupported.iter().any(|shims| folder == shims) {
        return Shim::Unsupported;
    }
    // Fails without it: classify_table (a linked rustup).
    if command == Manager::Rustup
        && canonical
            .and_then(Path::file_name)
            .is_some_and(|name| name == "rustup" || name == "rustup-init")
    {
        return Shim::Manager(Manager::Rustup);
    }
    Shim::None
}

/// Opens a manager folder (the environment may name it through a link)
/// and, below it, one name: never a link, always a folder.
fn open_below(root: &Path, name: &OsStr) -> std::io::Result<File> {
    let root = File::open(root)?;
    sys::open_dir_at_nofollow(root.as_fd(), name)
}

/// rustup's settings, read from `<rustup home>/settings.toml`: never
/// through a link, a regular file, at most `SETTINGS_MAX` bytes (a FIFO
/// does not block the open). Anything else is `Unknown`.
pub(crate) fn read_settings(rustup_home: &Path, cwd: &[u8]) -> Settings {
    let read = || -> Option<Vec<u8>> {
        let root = File::open(rustup_home).ok()?;
        let file = sys::open_file_at_nofollow(root.as_fd(), OsStr::new("settings.toml")).ok()?;
        let meta = file.metadata().ok()?;
        // Fails without it: settings_reads_only_regular_bounded_files (FIFO).
        if !meta.file_type().is_file() || meta.len() > SETTINGS_MAX {
            return None;
        }
        #[cfg(test)]
        tests::after_stat();
        let mut bytes = Vec::new();
        file.take(SETTINGS_MAX + 1).read_to_end(&mut bytes).ok()?;
        // A file that changed size since the stat is read as unknown, not
        // parsed in part. Fails without it:
        // settings_reads_only_regular_bounded_files (grown after the stat).
        (bytes.len() as u64 == meta.len()).then_some(bytes)
    };
    match read() {
        Some(bytes) => manager::rustup_settings(&bytes, cwd),
        None => Settings::Unknown,
    }
}

/// The install check: `<manager folder>/<folder>/<name>` opened one name at
/// a time, never through a link, as a folder. Only a grammar-checked name
/// with no `/` is looked up.
pub(crate) fn installed(home: &Path, folder: &[u8], name: &[u8]) -> bool {
    // Fails without it: install_check_opens_one_folder (`../x`).
    if !version_install_name(name) {
        return false;
    }
    open_below(home, OsStr::from_bytes(folder))
        .and_then(|dir| sys::open_dir_at_nofollow(dir.as_fd(), OsStr::from_bytes(name)))
        .is_ok()
}

/// A planned folder name: the selection's grammar-checked value, perhaps
/// followed by `-<host triple>` (whose own bytes are the same set).
fn version_install_name(name: &[u8]) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && name[0].is_ascii_alphanumeric()
        && name
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'+' | b'-'))
        && !name.windows(2).any(|w| w == b"..")
}

/// One language's decision, given what its command is.
pub(crate) fn decide(
    shim: Shim,
    vars: Option<&Environ<'_>>,
    homes: &Homes,
    selection: Selection<'_>,
    cwd: &[u8],
) -> Option<Decision> {
    let manager = match shim {
        Shim::Manager(manager) => manager,
        // The caller hides the value and reports the shim (U-12 R2).
        Shim::Unsupported => return None,
        Shim::None => return Some(Decision::Run(None)),
    };
    let home = match manager {
        Manager::Rustup => homes.rustup.as_deref(),
        Manager::Pyenv => homes.pyenv.as_deref(),
    };
    let settings = match (manager, home) {
        (Manager::Rustup, Some(home)) => read_settings(home, cwd),
        _ => Settings::Unknown,
    };
    let facts = Facts {
        manager,
        override_set: vars.map(|v| v.get(manager.override_variable()).is_some()),
        selection,
        settings: &settings,
        build_host: BUILD_HOST,
    };
    Some(match manager::plan(&facts) {
        Plan::Done(decision) => decision,
        Plan::Check {
            folder,
            name,
            value,
        } => {
            let present = home.is_some_and(|home| installed(home, &folder, &name));
            manager::installed(&value, present)
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{cell::RefCell, fs, os::unix::fs::symlink};

    thread_local! {
        static AFTER_STAT: RefCell<Option<Box<dyn FnMut()>>> = const { RefCell::new(None) };
    }

    pub(super) fn after_stat() {
        AFTER_STAT.with(|h| {
            if let Some(f) = h.borrow_mut().as_mut() {
                f()
            }
        });
    }

    struct Scratch(PathBuf);
    impl Scratch {
        fn new(tag: &str) -> Self {
            let dir = std::env::temp_dir().join(format!(
                "bingsu-version-manager-{}-{tag}",
                std::process::id()
            ));
            let _ = fs::remove_dir_all(&dir);
            fs::create_dir_all(&dir).unwrap();
            Self(fs::canonicalize(dir).unwrap())
        }
    }
    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn environ(entries: &[&str]) -> Vec<u8> {
        entries
            .iter()
            .flat_map(|e| [e.as_bytes(), b"\0"].concat())
            .collect()
    }

    // 관리자 폴더는 셸 환경에서 온다: 변수가 있으면 그 값, 없으면 HOME 아래 기본값. 상대 경로와 `..`가 든 값은
    // 모른다. 이것을 실패시키는 것: folder()의 절대 경로 검사나 `..` 검사를 지우는 것, 변수보다 HOME 기본값을
    // 먼저 쓰는 것.
    #[test]
    fn homes_follow_the_environment() {
        let body = environ(&[
            "HOME=/h",
            "RUSTUP_HOME=/r",
            "PYENV_ROOT=rel",
            "CARGO_HOME=/a/../b",
        ]);
        let h = homes(&Environ::parse(&body));
        assert_eq!(h.rustup, Some(PathBuf::from("/r")));
        assert_eq!(h.pyenv, None);
        assert_eq!(h.cargo, None);
        assert_eq!(
            h.unsupported,
            [
                PathBuf::from("/h/.asdf/shims"),
                PathBuf::from("/h/.local/share/mise/shims"),
                PathBuf::from("/h/.volta/bin"),
            ]
        );
        let none = homes(&Environ::parse(b""));
        assert_eq!(none, Homes::default());
    }

    // shim 판별 표. 이것을 실패시키는 것: pyenv shims·cargo bin·asdf shims 폴더 비교를 지우는 것, 다른 언어의
    // 관리자 폴더를 받는 것(rustc가 pyenv shims에 있어도 pyenv가 아님), 연결된 rustup 바이너리를 놓치는 것.
    #[test]
    fn classify_table() {
        let body = environ(&["HOME=/h"]);
        let h = homes(&Environ::parse(&body));
        let p = Path::new;
        let cases = [
            (
                Manager::Pyenv,
                "/h/.pyenv/shims",
                None,
                Shim::Manager(Manager::Pyenv),
            ),
            (Manager::Rustup, "/h/.pyenv/shims", None, Shim::None),
            (
                Manager::Rustup,
                "/h/.cargo/bin",
                None,
                Shim::Manager(Manager::Rustup),
            ),
            (Manager::Pyenv, "/h/.cargo/bin", None, Shim::None),
            (Manager::Pyenv, "/h/.asdf/shims", None, Shim::Unsupported),
            (Manager::Rustup, "/h/.volta/bin", None, Shim::Unsupported),
            (
                Manager::Rustup,
                "/opt/homebrew/bin",
                Some(p("/opt/homebrew/Cellar/rustup/1.29.2/bin/rustup-init")),
                Shim::Manager(Manager::Rustup),
            ),
            (
                Manager::Rustup,
                "/usr/bin",
                Some(p("/usr/lib/rust/bin/rustc")),
                Shim::None,
            ),
        ];
        for (command, folder, canonical, want) in cases {
            assert_eq!(
                classify(command, p(folder), canonical, &h),
                want,
                "{command:?} {folder}"
            );
        }
    }

    // settings.toml은 링크가 아닌 일반 파일을 64 KiB까지만 읽는다. FIFO는 open에서 막히지 않고 모름이 되고,
    // stat 뒤 커진 파일도 모름이다. 이것을 실패시키는 것: 일반 파일 검사를 지우는 것(FIFO에서 읽기가 멈추거나
    // 실패), 크기 상한을 지우는 것, stat 뒤 크기 비교를 지우는 것, 링크를 따라가는 것.
    #[test]
    fn settings_reads_only_regular_bounded_files() {
        let s = Scratch::new("settings");
        let file = s.0.join("settings.toml");
        let good = b"default_host_triple = \"h\"\n[overrides]\n";
        fs::write(&file, good).unwrap();
        let known = Settings::Known {
            host: Some(b"h".to_vec()),
            overridden: false,
        };
        assert_eq!(read_settings(&s.0, b"/w"), known);
        let mut big = good.to_vec();
        big.resize(SETTINGS_MAX as usize, b'\n');
        fs::write(&file, &big).unwrap();
        assert_eq!(read_settings(&s.0, b"/w"), known);
        big.push(b'\n');
        fs::write(&file, &big).unwrap();
        assert_eq!(read_settings(&s.0, b"/w"), Settings::Unknown);
        fs::write(&file, good).unwrap();
        let grow = file.clone();
        AFTER_STAT.with(|h| {
            *h.borrow_mut() = Some(Box::new(move || {
                fs::write(&grow, [&good[..], b"\n"].concat()).unwrap();
            }))
        });
        assert_eq!(read_settings(&s.0, b"/w"), Settings::Unknown);
        AFTER_STAT.with(|h| *h.borrow_mut() = None);
        fs::remove_file(&file).unwrap();
        let elsewhere = s.0.join("real.toml");
        fs::write(&elsewhere, good).unwrap();
        symlink(&elsewhere, &file).unwrap();
        assert_eq!(read_settings(&s.0, b"/w"), Settings::Unknown);
        fs::remove_file(&file).unwrap();
        sys::make_test_fifo(&file).unwrap();
        assert_eq!(read_settings(&s.0, b"/w"), Settings::Unknown);
    }

    // 설치 확인은 관리자 폴더 아래 두 이름을 하나씩, 링크를 따르지 않고 폴더로만 연다. 이름은 문법을 통과한 것만
    // 쓴다. 이것을 실패시키는 것: 이름 검사를 지우는 것(`..`·`/`가 든 이름으로 밖을 확인), 링크를 따르는 것,
    // 폴더가 아닌 것을 받는 것.
    #[test]
    fn install_check_opens_one_folder() {
        let s = Scratch::new("install");
        let home = s.0.join("home");
        fs::create_dir_all(home.join("toolchains/1.80.0-h")).unwrap();
        fs::create_dir_all(s.0.join("outside/1.81.0-h")).unwrap();
        symlink(
            s.0.join("outside/1.81.0-h"),
            home.join("toolchains/1.81.0-h"),
        )
        .unwrap();
        fs::write(home.join("toolchains/1.82.0-h"), b"").unwrap();
        fs::create_dir_all(home.join("x")).unwrap();
        assert!(installed(&home, b"toolchains", b"1.80.0-h"));
        assert!(!installed(&home, b"toolchains", b"1.81.0-h"));
        assert!(!installed(&home, b"toolchains", b"1.82.0-h"));
        assert!(!installed(&home, b"toolchains", b"1.83.0-h"));
        assert!(!installed(&home, b"toolchains", b"../x"));
        assert!(!installed(&home, b"toolchains", b"1.80.0-h/."));
        // Each rule of the name alone: the first byte, the byte set, `..`,
        // the length and the empty name (which would index past the end).
        fs::create_dir_all(home.join("toolchains/-x")).unwrap();
        assert!(!installed(&home, b"toolchains", b"-x"));
        fs::create_dir_all(home.join("toolchains/a..b")).unwrap();
        assert!(!installed(&home, b"toolchains", b"a..b"));
        fs::create_dir_all(home.join("toolchains/a b")).unwrap();
        assert!(!installed(&home, b"toolchains", b"a b"));
        let long = "a".repeat(129);
        fs::create_dir_all(home.join("toolchains").join(&long)).unwrap();
        assert!(!installed(&home, b"toolchains", long.as_bytes()));
        fs::create_dir_all(home.join("toolchains").join(&long[..128])).unwrap();
        assert!(installed(&home, b"toolchains", &long.as_bytes()[..128]));
        assert!(!installed(&home, b"toolchains", b""));
        let linked = s.0.join("linked");
        fs::create_dir_all(&linked).unwrap();
        symlink(home.join("toolchains"), linked.join("toolchains")).unwrap();
        assert!(!installed(&linked, b"toolchains", b"1.80.0-h"));
    }

    // 빌드 triple은 이 build의 arch와 OS다(rustup 철자). 이것을 실패시키는 것: build_host의 arch나 OS 가지를
    // 바꾸는 것(macOS에서 x86_64, Linux에서 musl/gnu 혼동은 target_env로 가른다).
    #[test]
    fn build_host_names_this_build() {
        let host = std::str::from_utf8(BUILD_HOST).unwrap();
        assert!(host.starts_with(std::env::consts::ARCH), "{host}");
        let os = match std::env::consts::OS {
            "macos" => "-apple-darwin",
            "linux" if cfg!(target_env = "musl") => "-unknown-linux-musl",
            "linux" => "-unknown-linux-gnu",
            other => panic!("{other}"),
        };
        assert!(host.ends_with(os), "{host}");
    }

    // 결정까지: 환경이 없으면 실행, 지원하지 않는 shim은 숨김(None), shim이 아니면 실행, pyenv와 rustup은 설치된
    // 정확한 이름일 때만 빠른 경로. 이것을 실패시키는 것: 환경 없음을 override 없음으로 보는 것, 설치 확인 결과를
    // 무시하는 것, rustup이 settings를 읽지 않는 것.
    #[test]
    fn decide_reads_the_facts() {
        let s = Scratch::new("decide");
        let pyenv = s.0.join("pyenv");
        fs::create_dir_all(pyenv.join("versions/3.12.1")).unwrap();
        let rustup = s.0.join("rustup");
        let toolchain = format!("toolchains/1.80.0-{}", String::from_utf8_lossy(BUILD_HOST));
        fs::create_dir_all(rustup.join(toolchain)).unwrap();
        fs::write(rustup.join("settings.toml"), b"version = \"12\"\n").unwrap();
        let body = environ(&[
            &format!("PYENV_ROOT={}", pyenv.display()),
            &format!("RUSTUP_HOME={}", rustup.display()),
        ]);
        let vars = Environ::parse(&body);
        let h = homes(&vars);
        let py = Shim::Manager(Manager::Pyenv);
        let rs = Shim::Manager(Manager::Rustup);
        let v = Selection::Value;
        assert_eq!(
            decide(py, Some(&vars), &h, v(b"3.12.1"), b"/w"),
            Some(Decision::Fast(b"3.12.1".to_vec()))
        );
        assert_eq!(
            decide(py, Some(&vars), &h, v(b"3.12.2"), b"/w"),
            Some(Decision::Run(Some(b"3.12.2".to_vec())))
        );
        assert_eq!(
            decide(py, None, &h, v(b"3.12.1"), b"/w"),
            Some(Decision::Run(None))
        );
        assert_eq!(
            decide(rs, Some(&vars), &h, v(b"1.80.0"), b"/w"),
            Some(Decision::Fast(b"1.80.0".to_vec()))
        );
        fs::write(
            rustup.join("settings.toml"),
            b"[overrides]\n\"/w\" = \"nightly\"\n",
        )
        .unwrap();
        assert_eq!(
            decide(rs, Some(&vars), &h, v(b"1.80.0"), b"/w"),
            Some(Decision::Run(None))
        );
        assert_eq!(
            decide(Shim::Unsupported, Some(&vars), &h, v(b"3.12.1"), b"/w"),
            None
        );
        assert_eq!(
            decide(Shim::None, Some(&vars), &h, v(b"3.12.1"), b"/w"),
            Some(Decision::Run(None))
        );
    }
}
