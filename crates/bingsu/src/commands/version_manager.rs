//! The helper's side of the version manager resolvers (plan D2, U-12 R2).
//! It gathers the facts the pure rules (`bingsu_core::collection::manager`)
//! decide on: which manager's shim the language's command is, the manager's
//! folders from the shell environment, rustup's settings file and one
//! install check. It runs in the helper before its filter, beside the
//! executable lookup, once the marker is staged (D2 ruling Q1; the marker is
//! installed only after the filter); the collector's read confinement is not
//! widened.
//!
//! Nothing here runs a program. A wrong answer can only show a wrong
//! version without running it or run the version command (D3) when it was
//! not needed; what runs still passes the `PATH` and relay rules.
use bingsu_core::collection::{
    language::version_ok,
    manager::{self, Decision, Facts, Hidden, Install, Manager, Plan, Selection, Settings},
};
use bingsu_core::command::plan::Environ;
use bingsu_core::fs_trust::{RefuseGroupWrite, Verdict, entry_verdict};
use std::{
    ffi::OsStr,
    fs::File,
    io::Read,
    os::{
        fd::AsFd,
        unix::{ffi::OsStrExt, fs::MetadataExt},
    },
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

/// Shim folders of the managers without a resolver, by each one's own
/// defaults:
/// - asdf: `$ASDF_DATA_DIR`, else `$HOME/.asdf` (if it exists, else
///   `$ASDF_DIR`) (https://asdf-vm.com/manage/configuration.html);
/// - mise: `$MISE_DATA_DIR`, else `$XDG_DATA_HOME/mise`, else
///   `~/.local/share/mise`, shims in `shims/`, or `$MISE_SHIMS_DIR`, and
///   `/usr/local/share/mise/shims` for system shims
///   (https://mise.jdx.dev/directories.html);
/// - volta: `$VOLTA_HOME`, else `~/.volta`, shims in `bin/`
///   (https://docs.volta.sh/advanced/installers).
///
/// Every candidate is listed: a folder that does not exist matches nothing.
fn unsupported(vars: &Environ<'_>) -> Vec<PathBuf> {
    let shims = |p: PathBuf| p.join("shims");
    let mise = match (vars.get(b"MISE_DATA_DIR"), vars.get(b"XDG_DATA_HOME")) {
        (Some(dir), _) => folder(dir),
        // Fails without it: homes_follow_the_environment (XDG_DATA_HOME).
        (None, Some(xdg)) => folder(xdg).map(|p| p.join("mise")),
        (None, None) => home_of(vars, b"MISE_DATA_DIR", ".local/share/mise"),
    };
    [
        home_of(vars, b"ASDF_DATA_DIR", ".asdf").map(shims),
        vars.get(b"ASDF_DIR").and_then(folder).map(shims),
        mise.map(shims),
        vars.get(b"MISE_SHIMS_DIR").and_then(folder),
        Some(PathBuf::from("/usr/local/share/mise/shims")),
        home_of(vars, b"VOLTA_HOME", ".volta").map(|p| p.join("bin")),
    ]
    .into_iter()
    .flatten()
    .collect()
}

pub(crate) fn homes(vars: &Environ<'_>) -> Homes {
    Homes {
        rustup: home_of(vars, b"RUSTUP_HOME", ".rustup"),
        cargo: home_of(vars, b"CARGO_HOME", ".cargo"),
        pyenv: home_of(vars, b"PYENV_ROOT", ".pyenv"),
        unsupported: unsupported(vars),
    }
}

/// `(st_dev, st_ino)` of a folder, following links: the environment may
/// name a manager folder through a link, and the sanitized `PATH` holds
/// canonical folders, so folders compare by identity, not by name.
fn identity(path: &Path) -> Option<(u64, u64)> {
    let meta = std::fs::metadata(path).ok()?;
    Some((meta.dev(), meta.ino()))
}

/// Which shim `folder` (the first sanitized `PATH` folder holding the
/// command's name) is. `canonical`, when the lookup resolved the command,
/// is its canonical file: rustup installed by a package manager links
/// `rustc` to `rustup` elsewhere.
pub(crate) fn classify(
    command: Manager,
    folder: &Path,
    canonical: Option<&Path>,
    homes: &Homes,
) -> Shim {
    let here = identity(folder);
    let same = |candidate: &Path| here.is_some() && identity(candidate) == here;
    // Fails without it: classify_table (pyenv shims folder, also through a
    // link).
    if command == Manager::Pyenv
        && homes
            .pyenv
            .as_ref()
            .is_some_and(|root| same(&root.join("shims")))
    {
        return Shim::Manager(Manager::Pyenv);
    }
    // Fails without it: classify_table (cargo bin folder).
    if command == Manager::Rustup
        && homes
            .cargo
            .as_ref()
            .is_some_and(|cargo| same(&cargo.join("bin")))
    {
        return Shim::Manager(Manager::Rustup);
    }
    // Fails without it: classify_table (asdf shims folder).
    if homes.unsupported.iter().any(|shims| same(shims)) {
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

/// The helper's trust rule for one opened folder or file (D2 ruling):
/// owned by root or `me`, nobody else can write it (group write refused,
/// no ACL that allows writing), on a mount that enforces ownership.
fn trusted(file: &File, me: u32) -> bool {
    sys::fd_facts(file.as_fd())
        .is_ok_and(|facts| entry_verdict(&facts, me, false, &mut RefuseGroupWrite) == Verdict::Safe)
}

/// One opened name's answer: there and trusted, not there, or there but a
/// link, the wrong kind or failing the trust rule.
fn opened(result: std::io::Result<File>, me: u32) -> Result<File, Install> {
    match result {
        // Fails without it: owner_rules_refuse_writable_folders.
        Ok(file) if trusted(&file, me) => Ok(file),
        Ok(_) => Err(Install::Untrusted),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(Install::Absent),
        // A link (ELOOP), a file where a folder belongs (ENOTDIR), anything
        // else: not what the manager made.
        // Fails without it: install_check_opens_one_folder (a link leaf is
        // untrusted, not absent).
        Err(_) => Err(Install::Untrusted),
    }
}

/// A manager folder (the environment may name it through a link). Opened
/// as a folder that cannot block: a FIFO or a device in the folder's place
/// fails at once (`O_DIRECTORY`), and neither the open nor any later read
/// waits on it (`O_NONBLOCK`) or takes a terminal (`O_NOCTTY`); std adds
/// `O_CLOEXEC`. Opened once per decision and used for every read below it,
/// so the settings and the install check see the same folder.
fn open_home(home: &Path, me: u32) -> Result<File, Install> {
    use std::os::unix::fs::OpenOptionsExt;
    // Fails without both `O_DIRECTORY` and `O_NONBLOCK` (either alone keeps
    // a FIFO from blocking; they are kept as two layers): homes_never_block
    // (the FIFO open waits for a writer). No test reaches `O_NOCTTY`: it
    // matters only for a terminal device the helper could take as its own.
    opened(
        std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NONBLOCK | libc::O_NOCTTY)
            .open(home),
        me,
    )
}

/// rustup's settings, read from `settings.toml` in the opened home: the
/// file trusted, never through a link, a regular file, at most
/// `SETTINGS_MAX` bytes (a FIFO does not block the open) whose size did not
/// change while read. Anything else is `Unknown`.
pub(crate) fn read_settings(home: &File, cwd: &[u8], me: u32) -> Settings {
    let read = || -> Option<Vec<u8>> {
        let file = sys::open_file_at_nofollow(home.as_fd(), OsStr::new("settings.toml")).ok()?;
        let meta = file.metadata().ok()?;
        // Fails without it: settings_reads_only_regular_bounded_files (FIFO).
        if !meta.file_type().is_file() || meta.len() > SETTINGS_MAX {
            return None;
        }
        // Fails without it: owner_rules_refuse_writable_folders (settings).
        if !trusted(&file, me) {
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

/// The install check below the opened home: `<folder>/<value>[-<host>]`
/// opened one name at a time, never through a link, as folders, each
/// trusted; for pyenv also `bin/<command>` inside it, a trusted regular
/// file (pyenv itself looks for the command there). `value` and `host` each
/// pass the version grammar (D1), so the name has no `/` and no `..`;
/// joined it may reach 65 bytes, which is why the parts are checked and not
/// the whole.
pub(crate) fn installed(
    home: &File,
    folder: &[u8],
    value: &[u8],
    host: Option<&[u8]>,
    command: Option<&[u8]>,
    me: u32,
) -> Install {
    // Fails without it: install_check_opens_one_folder (`../x`, a host
    // with `/`).
    if !version_ok(value) || !host.is_none_or(version_ok) {
        return Install::Untrusted;
    }
    let name = match host {
        Some(host) => [value, b"-", host].concat(),
        None => value.to_vec(),
    };
    let check = || -> Result<(), Install> {
        let dir = opened(
            sys::open_dir_at_nofollow(home.as_fd(), OsStr::from_bytes(folder)),
            me,
        )?;
        // Fails without it: owner_rules_refuse_writable_folders (the leaf).
        let leaf = opened(
            sys::open_dir_at_nofollow(dir.as_fd(), OsStr::from_bytes(&name)),
            me,
        )?;
        let Some(command) = command else {
            return Ok(());
        };
        // Fails without it: pyenv_needs_the_command_in_the_version.
        let bin = opened(
            sys::open_dir_at_nofollow(leaf.as_fd(), OsStr::new("bin")),
            me,
        )?;
        let file = opened(
            sys::open_file_at_nofollow(bin.as_fd(), OsStr::from_bytes(command)),
            me,
        )?;
        // Fails without it: pyenv_needs_the_command_in_the_version (a
        // folder named like the command).
        if !file.metadata().is_ok_and(|m| m.file_type().is_file()) {
            return Err(Install::Untrusted);
        }
        Ok(())
    };
    match check() {
        Ok(()) => Install::Present,
        Err(answer) => answer,
    }
}

/// One language's decision, given what its command is. `command` is the
/// command name pyenv's version must hold in its `bin` (D3 runs it); `me`
/// is the helper's user.
pub(crate) fn decide(
    shim: Shim,
    vars: Option<&Environ<'_>>,
    homes: &Homes,
    selection: Selection<'_>,
    command: &[u8],
    cwd: &[u8],
    me: u32,
) -> Option<Decision> {
    let manager = match shim {
        Shim::Manager(manager) => manager,
        // The caller hides the value and reports the shim (U-12 R2).
        Shim::Unsupported => return None,
        Shim::None => return Some(Decision::Run(None)),
    };
    // Fails without it: decide_reads_the_facts (an override variable in the
    // env frame).
    let override_set = vars.map(|v| {
        manager
            .precedence_variables()
            .iter()
            .any(|name| v.get(name).is_some())
    });
    // What needs no file is decided before any is opened.
    // Fails without it: decide_reads_the_facts (no settings read for an
    // override).
    if let Some(decision) = manager::early(override_set, selection) {
        return Some(decision);
    }
    let path = match manager {
        Manager::Rustup => homes.rustup.as_deref(),
        Manager::Pyenv => homes.pyenv.as_deref(),
    };
    let home = match path.map(|p| open_home(p, me)) {
        Some(Ok(home)) => home,
        // Fails without it: decide_reads_the_facts (an untrusted home).
        Some(Err(Install::Untrusted)) => return Some(Decision::Hidden(Hidden::Untrusted)),
        _ => return Some(Decision::Run(None)),
    };
    let settings = match manager {
        Manager::Rustup => read_settings(&home, cwd, me),
        Manager::Pyenv => Settings::Unknown,
    };
    let facts = Facts {
        manager,
        override_set,
        selection,
        settings: &settings,
        build_host: BUILD_HOST,
    };
    Some(match manager::plan(&facts) {
        Plan::Done(decision) => decision,
        Plan::Check {
            folder,
            value,
            host,
        } => {
            let command = (manager == Manager::Pyenv).then_some(command);
            let install = installed(&home, &folder, &value, host.as_deref(), command, me);
            manager::installed(&value, install)
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

    fn me() -> u32 {
        sys::current_uid()
    }

    fn mode(path: &Path, bits: u32) {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(bits)).unwrap();
    }

    fn home(path: &Path) -> File {
        open_home(path, me()).unwrap()
    }

    // 관리자 폴더는 셸 환경에서 온다: 변수가 있으면 그 값, 없으면 각 도구 문서의 기본값. 상대 경로와 `..`가 든 값은
    // 모른다. mise는 MISE_DATA_DIR이 없으면 XDG_DATA_HOME/mise, asdf는 ASDF_DIR도, mise는 MISE_SHIMS_DIR과 시스템
    // shim 폴더도 본다(리뷰 M9). 이것을 실패시키는 것: folder()의 절대 경로 검사나 `..` 검사를 지우는 것, 변수보다
    // HOME 기본값을 먼저 쓰는 것, XDG_DATA_HOME·ASDF_DIR·MISE_SHIMS_DIR 칸을 지우는 것.
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
        let p = PathBuf::from;
        assert_eq!(
            h.unsupported,
            [
                p("/h/.asdf/shims"),
                p("/h/.local/share/mise/shims"),
                p("/usr/local/share/mise/shims"),
                p("/h/.volta/bin"),
            ]
        );
        let body = environ(&[
            "HOME=/h",
            "XDG_DATA_HOME=/x",
            "ASDF_DIR=/ad",
            "MISE_SHIMS_DIR=/ms",
        ]);
        let h = homes(&Environ::parse(&body));
        assert_eq!(
            h.unsupported,
            [
                p("/h/.asdf/shims"),
                p("/ad/shims"),
                p("/x/mise/shims"),
                p("/ms"),
                p("/usr/local/share/mise/shims"),
                p("/h/.volta/bin"),
            ]
        );
        let body = environ(&["HOME=/h", "XDG_DATA_HOME=/x", "MISE_DATA_DIR=/md"]);
        assert!(
            homes(&Environ::parse(&body))
                .unsupported
                .contains(&p("/md/shims"))
        );
        let none = homes(&Environ::parse(b""));
        assert_eq!(none.rustup, None);
        assert_eq!(none.unsupported, [p("/usr/local/share/mise/shims")]);
    }

    // shim 판별 표. 폴더는 (dev, ino)로 비교하므로 링크로 이름 붙인 관리자 폴더도 알아본다. 이것을 실패시키는
    // 것: pyenv shims·cargo bin·asdf shims 폴더 비교를 지우는 것, 다른 언어의 관리자 폴더를 받는 것(rustc가 pyenv
    // shims에 있어도 pyenv가 아님), 연결된 rustup 바이너리를 놓치는 것, 이름 문자열로 비교하는 것(링크 별칭을
    // 놓침), 둘 다 없는 폴더를 같다고 보는 것.
    #[test]
    fn classify_table() {
        let s = Scratch::new("classify");
        for d in [
            ".pyenv/shims",
            ".cargo/bin",
            ".asdf/shims",
            ".volta/bin",
            "usr/bin",
        ] {
            fs::create_dir_all(s.0.join(d)).unwrap();
        }
        symlink(s.0.join(".pyenv/shims"), s.0.join("alias")).unwrap();
        let body = environ(&[&format!("HOME={}", s.0.display())]);
        let h = homes(&Environ::parse(&body));
        let at = |d: &str| s.0.join(d);
        let missing = PathBuf::from("/nonexistent-bingsu");
        let lone = Homes {
            pyenv: Some(missing.clone()),
            ..Homes::default()
        };
        let cases: [(Manager, PathBuf, Option<PathBuf>, &Homes, Shim); 10] = [
            (
                Manager::Pyenv,
                at(".pyenv/shims"),
                None,
                &h,
                Shim::Manager(Manager::Pyenv),
            ),
            (
                Manager::Pyenv,
                at("alias"),
                None,
                &h,
                Shim::Manager(Manager::Pyenv),
            ),
            (Manager::Rustup, at(".pyenv/shims"), None, &h, Shim::None),
            (
                Manager::Rustup,
                at(".cargo/bin"),
                None,
                &h,
                Shim::Manager(Manager::Rustup),
            ),
            (Manager::Pyenv, at(".cargo/bin"), None, &h, Shim::None),
            (
                Manager::Pyenv,
                at(".asdf/shims"),
                None,
                &h,
                Shim::Unsupported,
            ),
            (
                Manager::Rustup,
                at(".volta/bin"),
                None,
                &h,
                Shim::Unsupported,
            ),
            (
                Manager::Rustup,
                at("usr/bin"),
                Some(PathBuf::from(
                    "/opt/homebrew/Cellar/rustup/1.29.2/bin/rustup-init",
                )),
                &h,
                Shim::Manager(Manager::Rustup),
            ),
            (
                Manager::Rustup,
                at("usr/bin"),
                Some(PathBuf::from("/usr/lib/rust/bin/rustc")),
                &h,
                Shim::None,
            ),
            (
                Manager::Pyenv,
                missing.join("shims"),
                None,
                &lone,
                Shim::None,
            ),
        ];
        for (command, folder, canonical, homes, want) in cases {
            assert_eq!(
                classify(command, &folder, canonical.as_deref(), homes),
                want,
                "{command:?} {}",
                folder.display()
            );
        }
    }

    // settings.toml은 링크가 아닌 일반 파일을 64 KiB까지만 읽는다. FIFO는 open에서 막히지 않고 모름이 되고,
    // stat 뒤 크기가 바뀐 파일도 모름이다. 이것을 실패시키는 것: 일반 파일 검사를 지우는 것, 크기 상한을 지우는
    // 것, stat 뒤 크기 비교를 지우는 것, 링크를 따라가는 것.
    #[test]
    fn settings_reads_only_regular_bounded_files() {
        let s = Scratch::new("settings");
        let file = s.0.join("settings.toml");
        let good = b"default_host_triple = \"h\"\n[overrides]\n";
        fs::write(&file, good).unwrap();
        mode(&file, 0o644);
        mode(&s.0, 0o755);
        let known = Settings::Known {
            host: Some(b"h".to_vec()),
            overridden: false,
        };
        let read = || read_settings(&home(&s.0), b"/w", me());
        assert_eq!(read(), known);
        let mut big = good.to_vec();
        big.resize(SETTINGS_MAX as usize, b'\n');
        fs::write(&file, &big).unwrap();
        assert_eq!(read(), known);
        big.push(b'\n');
        fs::write(&file, &big).unwrap();
        assert_eq!(read(), Settings::Unknown);
        fs::write(&file, good).unwrap();
        let grow = file.clone();
        AFTER_STAT.with(|h| {
            *h.borrow_mut() = Some(Box::new(move || {
                fs::write(&grow, [&good[..], b"\n"].concat()).unwrap();
            }))
        });
        assert_eq!(read(), Settings::Unknown);
        AFTER_STAT.with(|h| *h.borrow_mut() = None);
        fs::remove_file(&file).unwrap();
        let elsewhere = s.0.join("real.toml");
        fs::write(&elsewhere, good).unwrap();
        symlink(&elsewhere, &file).unwrap();
        assert_eq!(read(), Settings::Unknown);
        fs::remove_file(&file).unwrap();
        sys::make_test_fifo(&file).unwrap();
        assert_eq!(read(), Settings::Unknown);
    }

    // 설치 확인은 관리자 폴더 아래 두 이름을 하나씩, 링크를 따르지 않고 폴더로만 연다. 값과 host는 각각 D1 버전
    // 문법을 통과해야 한다. 없으면 Absent, 링크나 다른 종류면 Untrusted다(리뷰 H1: 신뢰 위반을 미설치와 나눔).
    // 이것을 실패시키는 것: 값이나 host의 문법 검사를 지우는 것(`..`·`/`가 든 이름으로 밖을 확인), 링크를 따르는
    // 것, 링크 leaf를 Absent로 보는 것, 폴더가 아닌 것을 받는 것.
    #[test]
    fn install_check_opens_one_folder() {
        let s = Scratch::new("install");
        let root = s.0.join("home");
        let tc = root.join("toolchains");
        fs::create_dir_all(tc.join("1.80.0-h")).unwrap();
        fs::create_dir_all(s.0.join("outside/1.81.0-h")).unwrap();
        symlink(s.0.join("outside/1.81.0-h"), tc.join("1.81.0-h")).unwrap();
        fs::write(tc.join("1.82.0-h"), b"").unwrap();
        fs::create_dir_all(root.join("x")).unwrap();
        fs::create_dir_all(tc.join("a/b")).unwrap();
        fs::create_dir_all(tc.join("a-..").join("x")).unwrap();
        for p in [&root, &tc] {
            mode(p, 0o755);
        }
        let h = home(&root);
        let ok = |v: &[u8], host: Option<&[u8]>| installed(&h, b"toolchains", v, host, None, me());
        assert_eq!(ok(b"1.80.0", Some(b"h")), Install::Present);
        assert_eq!(ok(b"1.81.0", Some(b"h")), Install::Untrusted);
        assert_eq!(ok(b"1.82.0", Some(b"h")), Install::Untrusted);
        assert_eq!(ok(b"1.83.0", Some(b"h")), Install::Absent);
        assert_eq!(ok(b"../x", None), Install::Untrusted);
        // A host with `/` would walk below the name: `a-..` then `x`.
        assert_eq!(ok(b"a", Some(b"../x")), Install::Untrusted);
        assert_eq!(ok(b"a/b", None), Install::Untrusted);
        let linked = s.0.join("linked");
        fs::create_dir_all(&linked).unwrap();
        mode(&linked, 0o755);
        symlink(&tc, linked.join("toolchains")).unwrap();
        assert_eq!(
            installed(
                &home(&linked),
                b"toolchains",
                b"1.80.0",
                Some(b"h"),
                None,
                me()
            ),
            Install::Untrusted
        );
        // A home without the folder at all: absent, not untrusted.
        let bare = s.0.join("bare");
        fs::create_dir_all(&bare).unwrap();
        mode(&bare, 0o755);
        assert_eq!(
            installed(&home(&bare), b"toolchains", b"1.80.0", None, None, me()),
            Install::Absent
        );
    }

    // D2 판정(소유자 검사)과 리뷰 M7: 관리자 폴더, settings.toml, toolchains 폴더, 설치 leaf 가운데 남(그룹)이 쓸
    // 수 있는 것이 있으면 settings는 모름, 설치 확인은 Untrusted다. 이것을 실패시키는 것: open_home·settings·
    // toolchains·leaf의 trusted 검사를 각각 지우는 것.
    #[test]
    fn owner_rules_refuse_writable_folders() {
        let s = Scratch::new("owner");
        let root = s.0.join("rustup");
        let leaf = root.join("toolchains/1.80.0-h");
        fs::create_dir_all(&leaf).unwrap();
        fs::write(root.join("settings.toml"), b"default_host_triple = \"h\"\n").unwrap();
        for p in [&root, &root.join("toolchains"), &leaf] {
            mode(p, 0o755);
        }
        mode(&root.join("settings.toml"), 0o644);
        let known = Settings::Known {
            host: Some(b"h".to_vec()),
            overridden: false,
        };
        let check = || {
            installed(
                &home(&root),
                b"toolchains",
                b"1.80.0",
                Some(b"h"),
                None,
                me(),
            )
        };
        assert_eq!(read_settings(&home(&root), b"/w", me()), known);
        assert_eq!(check(), Install::Present);
        mode(&root, 0o775);
        assert_eq!(open_home(&root, me()).err(), Some(Install::Untrusted));
        mode(&root, 0o755);
        mode(&root.join("settings.toml"), 0o664);
        assert_eq!(read_settings(&home(&root), b"/w", me()), Settings::Unknown);
        assert_eq!(check(), Install::Present);
        mode(&root.join("settings.toml"), 0o644);
        mode(&root.join("toolchains"), 0o777);
        assert_eq!(check(), Install::Untrusted);
        mode(&root.join("toolchains"), 0o755);
        mode(&leaf, 0o775);
        assert_eq!(check(), Install::Untrusted);
        assert_eq!(read_settings(&home(&root), b"/w", me()), known);
    }

    // 리뷰 M7: pyenv 버전은 bin/<명령>이 신뢰할 수 있는 일반 파일로 있어야 설치된 것이다(pyenv 자신이 거기서 찾는다).
    // 이것을 실패시키는 것: bin 확인을 지우는 것(명령 없는 버전을 Present로 봄), 명령 자리의 폴더를 받는 것, 쓰기
    // 가능한 명령 파일을 받는 것.
    #[test]
    fn pyenv_needs_the_command_in_the_version() {
        let s = Scratch::new("pyenv-bin");
        let root = s.0.join("pyenv");
        let bin = root.join("versions/3.12.1/bin");
        fs::create_dir_all(&bin).unwrap();
        for p in [
            &root,
            &root.join("versions"),
            &root.join("versions/3.12.1"),
            &bin,
        ] {
            mode(p, 0o755);
        }
        let check = || {
            installed(
                &home(&root),
                b"versions",
                b"3.12.1",
                None,
                Some(b"python3"),
                me(),
            )
        };
        assert_eq!(check(), Install::Absent);
        fs::create_dir(bin.join("python3")).unwrap();
        mode(&bin.join("python3"), 0o755);
        assert_eq!(check(), Install::Untrusted);
        fs::remove_dir(bin.join("python3")).unwrap();
        fs::write(bin.join("python3"), b"").unwrap();
        mode(&bin.join("python3"), 0o775);
        assert_eq!(check(), Install::Untrusted);
        mode(&bin.join("python3"), 0o755);
        assert_eq!(check(), Install::Present);
        // rustup's leaf is checked without a command inside.
        assert_eq!(
            installed(&home(&root), b"versions", b"3.12.1", None, None, me()),
            Install::Present
        );
    }

    // 보안 리뷰 M-1: 관리자 폴더 자리에 FIFO나 장치가 있어도 필터 전 helper가 멈추지 않는다(open_home이 바로
    // 실패). 이것을 실패시키는 것: open_home을 평범한 open으로 되돌리거나 O_DIRECTORY와 O_NONBLOCK을 함께 빼는 것
    // (FIFO open이 쓰는 쪽을 기다려 시간 안에 끝나지 않음). 둘 중 하나만 빼면 남은 하나가 막는다. 장치 칸
    // (/dev/null)은 O_DIRECTORY가 없으면 신뢰 규칙(남이 쓸 수 있음)이 따로 막으므로 이 변이를 죽이지 않는다.
    #[test]
    fn homes_never_block() {
        let s = Scratch::new("block");
        let fifo = s.0.join("fifo-home");
        sys::make_test_fifo(&fifo).unwrap();
        for path in [fifo, PathBuf::from("/dev/null")] {
            let (tx, rx) = std::sync::mpsc::channel();
            let me = me();
            let probe = path.clone();
            std::thread::spawn(move || {
                let _ = tx.send(open_home(&probe, me).is_err());
            });
            let got = rx.recv_timeout(std::time::Duration::from_secs(5));
            assert_eq!(got, Ok(true), "{}", path.display());
        }
    }

    // 빌드 triple은 이 build의 arch와 OS다(rustup 철자). 이것을 실패시키는 것: build_host의 arch나 OS 가지를
    // 바꾸는 것.
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

    // 결정까지. 환경이 없으면 실행, 지원하지 않는 shim은 숨김(None), shim이 아니면 실행, 설치된 정확한 이름일 때만
    // 빠른 경로. env frame에 RUSTUP_TOOLCHAIN·PYENV_VERSION·PYENV_DIR이 실제로 있으면 실행(리뷰 L10·M6). 신뢰할 수
    // 없는 홈은 숨김(H1). override가 있으면 settings를 읽지 않는다(M4). 이것을 실패시키는 것: 환경 없음을
    // override 없음으로 보는 것, env frame의 변수 연결을 지우는 것, early를 settings 뒤로 미루는 것(settings를
    // 읽음), 설치 확인 결과를 무시하는 것, rustup이 settings를 읽지 않는 것, 신뢰할 수 없는 홈을 실행으로 보내는 것.
    #[test]
    fn decide_reads_the_facts() {
        let s = Scratch::new("decide");
        let pyenv = s.0.join("pyenv");
        let bin = pyenv.join("versions/3.12.1/bin");
        fs::create_dir_all(&bin).unwrap();
        fs::write(bin.join("python3"), b"").unwrap();
        let rustup = s.0.join("rustup");
        let toolchain = format!("toolchains/1.80.0-{}", String::from_utf8_lossy(BUILD_HOST));
        fs::create_dir_all(rustup.join(&toolchain)).unwrap();
        fs::write(rustup.join("settings.toml"), b"version = \"12\"\n").unwrap();
        for p in [
            &pyenv,
            &pyenv.join("versions"),
            &pyenv.join("versions/3.12.1"),
            &bin,
            &rustup,
            &rustup.join("toolchains"),
            &rustup.join(&toolchain),
        ] {
            mode(p, 0o755);
        }
        mode(&bin.join("python3"), 0o755);
        mode(&rustup.join("settings.toml"), 0o644);
        let roots = [
            format!("PYENV_ROOT={}", pyenv.display()),
            format!("RUSTUP_HOME={}", rustup.display()),
        ];
        let body = environ(&[&roots[0], &roots[1]]);
        let vars = Environ::parse(&body);
        let h = homes(&vars);
        let py = Shim::Manager(Manager::Pyenv);
        let rs = Shim::Manager(Manager::Rustup);
        let v = Selection::Value;
        let d = |shim, vars, sel| decide(shim, vars, &h, sel, b"python3", b"/w", me());
        assert_eq!(
            d(py, Some(&vars), v(b"3.12.1")),
            Some(Decision::Fast(b"3.12.1".to_vec()))
        );
        assert_eq!(
            d(py, Some(&vars), v(b"3.12.2")),
            Some(Decision::Run(Some(b"3.12.2".to_vec())))
        );
        assert_eq!(d(py, None, v(b"3.12.1")), Some(Decision::Run(None)));
        assert_eq!(
            d(rs, Some(&vars), v(b"1.80.0")),
            Some(Decision::Fast(b"1.80.0".to_vec()))
        );
        for extra in [
            "RUSTUP_TOOLCHAIN=nightly",
            "PYENV_VERSION=3.11.9",
            "PYENV_DIR=/elsewhere",
            "PYENV_HOOK_PATH=/hooks",
        ] {
            let body = environ(&[&roots[0], &roots[1], extra]);
            let with = Environ::parse(&body);
            let shim = if extra.starts_with("RUSTUP") { rs } else { py };
            let sel = if extra.starts_with("RUSTUP") {
                v(b"1.80.0")
            } else {
                v(b"3.12.1")
            };
            assert_eq!(
                decide(shim, Some(&with), &h, sel, b"python3", b"/w", me()),
                Some(Decision::Run(None)),
                "{extra}"
            );
        }
        // An override decides before the settings are read: the hook that
        // runs once their stat passed must not run.
        let body = environ(&[&roots[1], "RUSTUP_TOOLCHAIN=nightly"]);
        let with = Environ::parse(&body);
        AFTER_STAT.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(|| panic!("settings read for an override")))
        });
        assert_eq!(
            decide(rs, Some(&with), &h, v(b"1.80.0"), b"python3", b"/w", me()),
            Some(Decision::Run(None))
        );
        AFTER_STAT.with(|hook| *hook.borrow_mut() = None);
        fs::remove_file(rustup.join("settings.toml")).unwrap();
        fs::write(
            rustup.join("settings.toml"),
            b"[overrides]\n\"/w\" = \"nightly\"\n",
        )
        .unwrap();
        mode(&rustup.join("settings.toml"), 0o644);
        assert_eq!(d(rs, Some(&vars), v(b"1.80.0")), Some(Decision::Run(None)));
        mode(&pyenv, 0o775);
        assert_eq!(
            d(py, Some(&vars), v(b"3.12.1")),
            Some(Decision::Hidden(Hidden::Untrusted))
        );
        mode(&pyenv, 0o755);
        // A manager folder that is not there: nothing to read, the command
        // runs (it reports what it finds).
        let gone = Homes {
            pyenv: Some(s.0.join("no-such-pyenv")),
            ..Homes::default()
        };
        assert_eq!(
            decide(
                py,
                Some(&vars),
                &gone,
                v(b"3.12.1"),
                b"python3",
                b"/w",
                me()
            ),
            Some(Decision::Run(None))
        );
        assert_eq!(d(Shim::Unsupported, Some(&vars), v(b"3.12.1")), None);
        assert_eq!(
            d(Shim::None, Some(&vars), v(b"3.12.1")),
            Some(Decision::Run(None))
        );
    }
}
