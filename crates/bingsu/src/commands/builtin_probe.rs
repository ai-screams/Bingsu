//! The builtin language versions of one command round (plan D3a, D3
//! rulings Q1–Q7): for each language whose segment is drawn, what the
//! helper shows without running anything (a version manager's fast path),
//! hides, or runs as a fixed-profile probe. A probe runs the real
//! executable the sanitized `PATH` or the manager's own install names,
//! never a manager's shim or the rustup proxy. Runs after the marker, in
//! the helper's `Round::grant`.
use super::{
    exec_path,
    version_manager::{self, Choice, Shim},
};
use bingsu_core::{
    collection::{language::Version, manager::Manager, manager::Selection},
    command::{
        path::Id,
        plan::{self, Environ},
        profile,
        wire::Probe,
    },
    fs_trust::GroupOracle,
};
use std::{
    ffi::OsStr,
    os::unix::{ffi::OsStrExt, fs::MetadataExt},
    path::{Path, PathBuf},
};

/// One builtin language: its id (the collector's query id and the
/// response entry's), its probe profile, the command its version comes
/// from and the manager bingsu resolves for it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Language {
    pub id: &'static str,
    pub profile: u8,
    pub word: &'static [u8],
    pub manager: Option<Manager>,
    /// The shell variables its answer depends on beyond the keep list
    /// (`PATH`, `HOME`, ...): the environment digest of its entry.
    pub variables: &'static [&'static [u8]],
}

/// Shell variables that name the folders of managers without a resolver
/// (asdf, mise, volta, nodenv, goenv): they change whether the command is
/// such a shim.
const UNSUPPORTED: [&[u8]; 8] = [
    b"ASDF_DATA_DIR",
    b"ASDF_DIR",
    b"MISE_DATA_DIR",
    b"MISE_SHIMS_DIR",
    b"XDG_DATA_HOME",
    b"VOLTA_HOME",
    b"NODENV_ROOT",
    b"GOENV_ROOT",
];

pub(crate) const LANGUAGES: [Language; 4] = [
    Language {
        id: "node",
        profile: profile::NODE,
        word: b"node",
        manager: None,
        variables: &[],
    },
    Language {
        id: "python",
        profile: profile::PYTHON,
        word: b"python3",
        manager: Some(Manager::Pyenv),
        variables: &[
            b"PYENV_ROOT",
            b"PYENV_VERSION",
            b"PYENV_DIR",
            b"PYENV_HOOK_PATH",
            // macOS: it picks the developer tools' python3 (D3a review M4).
            b"DEVELOPER_DIR",
        ],
    },
    Language {
        id: "rust",
        profile: profile::RUST,
        word: b"rustc",
        manager: Some(Manager::Rustup),
        variables: &[b"RUSTUP_HOME", b"CARGO_HOME", b"RUSTUP_TOOLCHAIN"],
    },
    Language {
        id: "go",
        profile: profile::GO,
        word: b"go",
        manager: None,
        variables: &[],
    },
];

impl Language {
    /// Whether `executable` (canonical) is this language's command by its
    /// file name: `node`, `python3` or `python3.<n>`, `rustc`, `go`.
    pub(crate) fn runs(&self, executable: &Path) -> bool {
        let Some(name) = executable.file_name().map(OsStr::as_bytes) else {
            return false;
        };
        if self.profile == profile::PYTHON {
            return name == b"python3"
                || name
                    .strip_prefix(b"python3.")
                    .is_some_and(|v| !v.is_empty() && v.iter().all(u8::is_ascii_digit));
        }
        name == self.word
    }
}

/// The language of a collector query id.
pub(crate) fn language(id: &[u8]) -> Option<&'static Language> {
    LANGUAGES.iter().find(|l| l.id.as_bytes() == id)
}

/// How a builtin value was decided: part of its policy digest, so a value
/// decided one way never stands for one decided another way (D3a ruling
/// Q-D: a hidden or failed result never holds back a fast one).
const KIND_FAST: u8 = 1;
const KIND_HIDDEN: u8 = 2;
const KIND_RUN: u8 = 3;

/// How long a probe's successful result stands. Its policy digest binds the
/// executable's identity (device, inode, size, modification time), the
/// toolchain and the selection file, so a new install or a changed file
/// runs it again at once; the time only bounds what the digest cannot see
/// (a library the executable loads).
pub(crate) const PROBE_CACHE_NS: u64 = 3_600_000_000_000;

/// What the round does about one language.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Action {
    /// Publish this version now; nothing runs.
    Show(String),
    /// Publish no value; the reason goes to the log.
    Hide(&'static str),
    /// Run this probe (unless its cached result stands).
    Run(Probe),
}

/// One language's decision with the digests its entry is bound to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Planned {
    pub language: &'static Language,
    pub policy: [u8; 32],
    pub environment: [u8; 32],
    pub action: Action,
}

/// The selection the collector answered, as the resolver takes it, and the
/// bytes that bind it into a digest (which file, at which level, and the
/// file's digest).
fn selection(version: &Version) -> (Selection<'_>, Vec<u8>) {
    match version {
        Version::None => (Selection::Absent, vec![0]),
        Version::Refused {
            file,
            level,
            digest,
        } => (
            Selection::Unusable,
            [&[1, *file, *level][..], digest].concat(),
        ),
        Version::Found {
            file,
            level,
            digest,
            value,
        } => (
            Selection::Value(value),
            [&[2, *file, *level][..], digest].concat(),
        ),
        Version::Path { file, level } => (Selection::Path, vec![3, *file, *level]),
    }
}

/// What the round knows for every language.
pub(crate) struct Context<'a> {
    /// The shell environment; `None` when the frame was not read whole
    /// (D3a acceptance: a frame with malformed or duplicate entries counts
    /// as no environment).
    pub vars: Option<&'a Environ<'a>>,
    /// The sanitized `PATH` folders.
    pub folders: &'a [PathBuf],
    /// Every repository the shell is in (`command_grant::search`).
    pub repo: &'a [Id],
    /// The shell's folder as the shell gave it; made canonical only for
    /// rustup's directory overrides, and only then (D3a security review
    /// S-M3).
    pub cwd: &'a [u8],
    pub me: u32,
    /// macOS: xcode-select's link and the Command Line Tools folder
    /// (`XCODE_SELECT_LINK`, `COMMAND_LINE_TOOLS`; tests give their own).
    pub xcode_link: &'a Path,
    pub command_line_tools: &'a Path,
    /// Counts the shell folders made canonical (the round's debug log).
    pub resolved: &'a std::cell::Cell<u32>,
}

/// The shell environment, when the frame held it whole: a frame with
/// entries left out (malformed, or a name given twice) is no environment
/// (D3a acceptance).
pub(crate) fn whole<'a>(vars: &'a Environ<'a>) -> Option<&'a Environ<'a>> {
    // Fails without it: plan_hides_without_whole_inputs.
    (vars.dropped.malformed + vars.dropped.duplicate == 0).then_some(vars)
}

/// One language's plan. `version` is the collector's answer for it.
pub(crate) fn plan(
    language: &'static Language,
    version: &Version,
    c: &Context<'_>,
    groups: &mut dyn GroupOracle,
) -> Planned {
    let (selection, selected) = selection(version);
    let environment = match c.vars {
        Some(vars) => {
            let names: Vec<Vec<u8>> = language
                .variables
                .iter()
                .chain(UNSUPPORTED.iter())
                .map(|n| n.to_vec())
                .collect();
            plan::env_digest(vars, &names)
        }
        None => [0; 32],
    };
    let hide = |why: &'static str| Planned {
        language,
        policy: profile::digest(language.profile, KIND_HIDDEN, &[why.as_bytes()]),
        environment,
        action: Action::Hide(why),
    };
    // Fails without it: plan_hides_without_whole_inputs.
    let Some(vars) = c.vars else {
        return hide("the shell environment was not read whole");
    };
    let Some((at, looked)) =
        exec_path::lookup_open_in(language.word, c.folders, c.repo, c.me, groups)
    else {
        return hide("the command was not found");
    };
    // Classified before the file is judged (D3a review M3): a manager's
    // shim is a script the checks refuse, and must still be known as one.
    // The folder the lookup stopped in and the file's own folder both count
    // (security review S-M1: a link or a renamed copy elsewhere on PATH).
    let homes = version_manager::homes(vars);
    let canonical_file =
        std::fs::canonicalize(c.folders[at].join(OsStr::from_bytes(language.word))).ok();
    let shim = version_manager::classify(
        language.manager,
        &c.folders[at],
        canonical_file.as_deref(),
        &homes,
    );
    // rustup reads directory overrides for the canonical folder; one that
    // could not be resolved leaves the overrides unknown.
    let canonical = match shim {
        Shim::Manager(Manager::Rustup) => {
            c.resolved.set(c.resolved.get() + 1);
            match canonical_cwd(c.cwd) {
                Some(cwd) => Some(cwd),
                None => return hide("the shell's folder could not be resolved"),
            }
        }
        _ => None,
    };
    let cwd = canonical.as_deref().unwrap_or_default();
    let choice = version_manager::choose(
        shim,
        Some(vars),
        &homes,
        selection,
        language.word,
        cwd,
        c.me,
    );
    let (found, checked, toolchain) = match choice {
        Choice::Fast(value) => {
            let Ok(text) = String::from_utf8(value.clone()) else {
                return hide("the selected version is not text");
            };
            return Planned {
                language,
                policy: profile::digest(language.profile, KIND_FAST, &[&value, &selected]),
                environment,
                action: Action::Show(text),
            };
        }
        Choice::Hidden(why) => return hide(why),
        Choice::Unsupported => return hide("a version manager bingsu does not resolve"),
        Choice::RunFound => {
            let Ok((found, checked)) = looked else {
                return hide("the command failed the checks");
            };
            // A link or a renamed copy of another program (a manager's own
            // binary, mise or proto) is not the language's command
            // (security review S-M1).
            // Fails without it: plan_follows_the_rulings (a node link to
            // another program).
            if !language.runs(&found.executable) {
                return hide("the command resolves to another program");
            }
            match developer_tool(
                &found.executable,
                c.xcode_link,
                c.command_line_tools,
                cfg!(target_os = "macos"),
            ) {
                Stub::Not => (found, checked, None),
                // DEVELOPER_DIR picks the developer folder ahead of
                // xcode-select's link (D3a review M4): not modelled, hidden.
                // Fails without it: developer_dir_hides_the_stub.
                Stub::Real(_) if vars.get(b"DEVELOPER_DIR").is_some() => {
                    return hide("DEVELOPER_DIR picks the developer tools");
                }
                // The real file the stub would hand the call to, judged
                // like any executable; the stub itself never runs (D3a
                // ruling i).
                Stub::Real(real) => match exec_path::resolve_open(&real, c.repo, c.me, groups) {
                    Ok((found, checked)) => (found, checked, None),
                    Err(_) => return hide("the developer tools' python3 failed the checks"),
                },
                Stub::Missing => {
                    return hide("python3 is the developer tools' stub and they are not installed");
                }
            }
        }
        // The manager's own file, judged by the same rules as any
        // executable (D3a acceptance: owner, pin).
        Choice::RunManaged {
            executable,
            toolchain,
        } => match exec_path::resolve_open(&executable, c.repo, c.me, groups) {
            Ok((found, checked)) => (found, checked, toolchain),
            Err(_) => return hide("the manager's executable failed the checks"),
        },
    };
    // A probe carries no interpreter: a `#!` script in the command's place
    // is no version command bingsu runs.
    // Fails without it: plan_follows_the_rulings.
    if found.interpreter.is_some() {
        return hide("the command is a script");
    }
    // The file the checks ran on, not the name again.
    let Ok(meta) = checked.file().metadata() else {
        return hide("the command was not found or failed the checks");
    };
    let path = found.executable.as_os_str().as_bytes();
    let identity = [
        meta.dev().to_le_bytes(),
        meta.ino().to_le_bytes(),
        meta.size().to_le_bytes(),
        meta.mtime().to_le_bytes(),
        meta.mtime_nsec().to_le_bytes(),
    ]
    .concat();
    let policy = profile::digest(
        language.profile,
        KIND_RUN,
        &[
            path,
            &identity,
            toolchain.as_deref().unwrap_or_default(),
            &[u8::from(toolchain.is_some())],
            &selected,
        ],
    );
    Planned {
        language,
        policy,
        environment,
        action: Action::Run(Probe {
            profile: language.profile,
            executable: path.to_vec(),
            pin: found.pin,
            toolchain,
        }),
    }
}

/// macOS's developer tool stubs bingsu meets among the builtin commands
/// (D3a ruling i). Every developer tool in `/usr/bin` (python3, pip3, git,
/// clang, make and 77 more on macOS 27.2) is the same file: equal sha256
/// (`ed6f5284033aa2aa…`), 196 KB, linking `/usr/lib/libxcselect.dylib`;
/// without the developer tools installed it asks to install them, a dialog
/// a background round must never raise. Of the four builtin commands only
/// `python3` is among them.
const DEVELOPER_STUBS: [&str; 1] = ["/usr/bin/python3"];
/// The selected developer folder (`xcode-select`'s root-owned link).
pub(crate) const XCODE_SELECT_LINK: &str = "/var/db/xcode_select_link";
/// The Command Line Tools, the developer folder when none is selected.
pub(crate) const COMMAND_LINE_TOOLS: &str = "/Library/Developer/CommandLineTools";

/// What a resolved command is with respect to the developer tool stubs.
#[derive(Debug, PartialEq, Eq)]
enum Stub {
    /// Not a stub: it runs as found.
    Not,
    /// A stub: run this file of the developer folder instead.
    Real(PathBuf),
    /// A stub with no developer folder holding its tool: hidden.
    Missing,
}

/// The developer folder's own file for a stub (`<folder>/usr/bin/<name>`),
/// the folder from `select_link`, else `tools` when that is a folder.
/// Off macOS (`macos` false) nothing is a stub: Linux's `/usr/bin/python3`
/// is the interpreter itself.
fn developer_tool(executable: &Path, select_link: &Path, tools: &Path, macos: bool) -> Stub {
    // Fails without each: developer_stubs_run_the_real_tool (off macOS, a
    // non-stub rerouted).
    if !macos || !DEVELOPER_STUBS.iter().any(|s| executable == Path::new(s)) {
        return Stub::Not;
    }
    let Some(name) = executable.file_name() else {
        return Stub::Missing;
    };
    // Fails without it: developer_stubs_run_the_real_tool (the selected
    // folder before the Command Line Tools).
    let folder = match std::fs::read_link(select_link) {
        Ok(target) => select_link
            .parent()
            .map_or(target.clone(), |p| p.join(&target)),
        Err(_) if tools.is_dir() => tools.to_path_buf(),
        // Fails without it: developer_stubs_run_the_real_tool (neither).
        Err(_) => return Stub::Missing,
    };
    let real = folder.join("usr/bin").join(name);
    // Fails without it: developer_stubs_run_the_real_tool (a folder
    // without the tool).
    if std::fs::symlink_metadata(&real).is_err() {
        return Stub::Missing;
    }
    Stub::Real(real)
}

/// The shell's folder, canonical (D3a acceptance: rustup's override
/// comparison uses the canonical path).
/// Fails without it: override_follows_settings_and_cwd_is_canonical.
pub(crate) fn canonical_cwd(cwd: &[u8]) -> Option<Vec<u8>> {
    std::fs::canonicalize(Path::new(OsStr::from_bytes(cwd)))
        .ok()
        .map(|p| p.into_os_string().into_encoded_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::{group_policy::SystemGroups, sys, version_manager::BUILD_HOST};
    use std::fs;

    struct Scratch(PathBuf);
    impl Scratch {
        fn new(tag: &str) -> Self {
            let dir = std::env::temp_dir()
                .join(format!("bingsu-builtin-probe-{}-{tag}", std::process::id()));
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

    fn file(path: &Path, body: &[u8]) {
        use std::os::unix::fs::PermissionsExt;
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, body).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
    }

    fn environ(entries: &[String]) -> Vec<u8> {
        entries
            .iter()
            .flat_map(|e| [e.as_bytes(), b"\0"].concat())
            .collect()
    }

    fn found(value: &str) -> Version {
        Version::Found {
            file: 0,
            level: 0,
            digest: [7; 16],
            value: value.as_bytes().to_vec(),
        }
    }

    fn lang(id: &str) -> &'static Language {
        language(id.as_bytes()).unwrap()
    }

    /// A home with a plain `node`, a `#!` `go`, rustup's proxy folder, a
    /// pyenv shim folder, two rustup toolchains and two pyenv versions.
    fn tree(s: &Scratch) {
        let at = |p: &str| s.0.join(p);
        file(&at("bin/node"), b"\x7fELF node");
        file(&at("bin/go"), b"#!/bin/sh\necho go\n");
        file(&at(".cargo/bin/rustc"), b"\x7fELF proxy");
        // As pyenv writes them: a script through env, which the
        // executable checks refuse (D3a review M3).
        file(
            &at(".pyenv/shims/python3"),
            b"#!/usr/bin/env bash\nexec pyenv exec python3\n",
        );
        // A program that is not the language's command, under its name.
        file(&at("mise/mise"), b"\x7fELF mise");
        fs::create_dir_all(at("other")).unwrap();
        std::os::unix::fs::symlink(at("mise/mise"), at("other/node")).unwrap();
        file(&at(".asdf/shims/node"), b"#!/bin/sh\n");
        file(&at(".nodenv/shims/node"), b"\x7fELF shim");
        let host = String::from_utf8_lossy(BUILD_HOST);
        for t in ["1.80.0", "stable"] {
            file(
                &at(&format!(".rustup/toolchains/{t}-{host}/bin/rustc")),
                b"\x7fELF rustc",
            );
        }
        file(&at(".rustup/settings.toml"), b"version = \"12\"\n");
        // `system` is no install, even where a folder bears its name.
        for v in ["3.12.1", "3.12", "system"] {
            file(
                &at(&format!(".pyenv/versions/{v}/bin/python3")),
                b"\x7fELF python",
            );
        }
        // The folders the tree made are the user's 0755; the files above
        // made them with the umask.
        for d in [
            "bin",
            ".cargo",
            ".cargo/bin",
            ".pyenv",
            ".pyenv/shims",
            ".pyenv/versions",
            ".asdf",
            ".asdf/shims",
            ".nodenv",
            ".nodenv/shims",
            "mise",
            "other",
            ".rustup",
            ".rustup/toolchains",
        ] {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(at(d), fs::Permissions::from_mode(0o755)).unwrap();
        }
        fs::set_permissions(
            at(".rustup/settings.toml"),
            std::os::unix::fs::PermissionsExt::from_mode(0o644),
        )
        .unwrap();
    }

    fn plan_with(s: &Scratch, path: &str, extra: &[&str], id: &str, v: &Version) -> Planned {
        let mut entries = vec![format!("HOME={}", s.0.display()), format!("PATH={}", path)];
        entries.extend(extra.iter().map(|e| e.to_string()));
        let body = environ(&entries);
        let vars = Environ::parse(&body);
        let mut groups = SystemGroups::new(&sys::passwd_entry(sys::current_uid()).unwrap().name);
        let me = sys::current_uid();
        let folders = exec_path::sanitize(vars.get(b"PATH").unwrap(), &[], me, &mut groups);
        let c = Context {
            vars: Some(&vars),
            folders: &folders,
            repo: &[],
            cwd: s.0.as_os_str().as_bytes(),
            me,
            xcode_link: &s.0.join("xcode_select_link"),
            command_line_tools: &s.0.join("CommandLineTools"),
            resolved: &std::cell::Cell::new(0),
        };
        plan(lang(id), v, &c, &mut groups)
    }

    fn run_of(p: &Planned) -> (Vec<u8>, Option<Vec<u8>>) {
        match &p.action {
            Action::Run(probe) => (probe.executable.clone(), probe.toolchain.clone()),
            other => panic!("{other:?}"),
        }
    }

    // 내장 언어 하나의 결정: 관리자가 정한 설치 파일이나 PATH의 실제 실행 파일만 실행하고, shim·프록시·스크립트·
    // 미설치·모르는 선택은 숨긴다(D3 판정 Q1·Q2, D3a 수용 조건). 이것을 실패시키는 것: 스크립트 거부를 지우는 것,
    // Run(None)을 숨기지 않는 것, 미설치를 숨기지 않는 것, override 값을 쓰지 않는 것(RUSTUP_TOOLCHAIN),
    // pyenv의 `system`을 쓰는 것, 지원하지 않는 관리자 shim을 실행하는 것, 정규 cwd가 없는데 rustup을 푸는 것.
    #[test]
    fn plan_follows_the_rulings() {
        if exec_path::test_skip_as_root() {
            return;
        }
        let s = Scratch::new("plan");
        tree(&s);
        let host = String::from_utf8_lossy(BUILD_HOST).into_owned();
        let at = |p: &str| s.0.join(p);
        let bin = at("bin").display().to_string();
        let cargo = at(".cargo/bin").display().to_string();
        let shims = at(".pyenv/shims").display().to_string();
        // Node on PATH: its real file runs.
        let p = plan_with(&s, &bin, &[], "node", &Version::None);
        assert_eq!(
            run_of(&p),
            (at("bin/node").as_os_str().as_bytes().to_vec(), None)
        );
        // An asdf shim in front: hidden, never run.
        let asdf = format!("{}:{bin}", at(".asdf/shims").display());
        let p = plan_with(&s, &asdf, &[], "node", &Version::None);
        assert_eq!(
            p.action,
            Action::Hide("a version manager bingsu does not resolve")
        );
        // A nodenv shim, even a binary one, is a manager without a resolver.
        let nodenv = format!("{}:{bin}", at(".nodenv/shims").display());
        let p = plan_with(&s, &nodenv, &[], "node", &Version::None);
        assert_eq!(
            p.action,
            Action::Hide("a version manager bingsu does not resolve")
        );
        // The language's command by file name (security review S-M1).
        let py = lang("python");
        for (name, ok) in [
            ("python3", true),
            ("python3.12", true),
            ("python3-config", false),
            ("python3.x", false),
            ("python3.", false),
            ("python", false),
        ] {
            assert_eq!(py.runs(Path::new(name)), ok, "{name}");
        }
        assert!(lang("node").runs(Path::new("/a/node")));
        assert!(!lang("node").runs(Path::new("/a/nodejs")));
        // A link named node to another program (security review S-M1).
        let other = at("other").display().to_string();
        let p = plan_with(&s, &other, &[], "node", &Version::None);
        assert_eq!(
            p.action,
            Action::Hide("the command resolves to another program")
        );
        // A `#!` script in the command's place.
        let p = plan_with(&s, &bin, &[], "go", &Version::None);
        assert_eq!(p.action, Action::Hide("the command is a script"));
        // rustup: an installed version is shown without running.
        let p = plan_with(&s, &cargo, &[], "rust", &found("1.80.0"));
        assert_eq!(p.action, Action::Show("1.80.0".into()));
        // A channel runs that install's own rustc with the toolchain name.
        let stable = at(&format!(".rustup/toolchains/stable-{host}/bin/rustc"));
        let p = plan_with(&s, &cargo, &[], "rust", &found("stable"));
        assert_eq!(
            run_of(&p),
            (
                stable.as_os_str().as_bytes().to_vec(),
                Some(b"stable".to_vec())
            )
        );
        // A `path` toolchain is never run (D2 ruling Q4).
        let path = Version::Path { file: 1, level: 0 };
        let p = plan_with(&s, &cargo, &[], "rust", &path);
        assert_eq!(p.action, Action::Hide("a path toolchain"));
        // Not installed, or no name known: hidden, never the proxy.
        let p = plan_with(&s, &cargo, &[], "rust", &found("1.81.0"));
        assert_eq!(
            p.action,
            Action::Hide("the selected version is not installed")
        );
        let p = plan_with(&s, &cargo, &[], "rust", &Version::None);
        assert_eq!(p.action, Action::Hide("the manager's choice is not known"));
        // RUSTUP_TOOLCHAIN names the toolchain (Q2); a path-shaped one is
        // not a name.
        let p = plan_with(
            &s,
            &cargo,
            &["RUSTUP_TOOLCHAIN=stable"],
            "rust",
            &found("1.80.0"),
        );
        assert_eq!(
            run_of(&p),
            (
                stable.as_os_str().as_bytes().to_vec(),
                Some(b"stable".to_vec())
            )
        );
        let p = plan_with(
            &s,
            &cargo,
            &["RUSTUP_TOOLCHAIN=/opt/t"],
            "rust",
            &found("1.80.0"),
        );
        assert_eq!(p.action, Action::Hide("the manager's choice is not known"));
        // pyenv: fast, a short name runs its install, `system` is hidden.
        let p = plan_with(&s, &shims, &[], "python", &found("3.12.1"));
        assert_eq!(p.action, Action::Show("3.12.1".into()));
        let p = plan_with(&s, &shims, &[], "python", &found("3.12"));
        assert_eq!(
            run_of(&p),
            (
                at(".pyenv/versions/3.12/bin/python3")
                    .as_os_str()
                    .as_bytes()
                    .to_vec(),
                None
            )
        );
        let p = plan_with(
            &s,
            &shims,
            &["PYENV_VERSION=3.12"],
            "python",
            &found("3.12.1"),
        );
        assert_eq!(
            run_of(&p).0,
            at(".pyenv/versions/3.12/bin/python3")
                .as_os_str()
                .as_bytes()
        );
        let p = plan_with(
            &s,
            &shims,
            &["PYENV_VERSION=system"],
            "python",
            &found("3.12.1"),
        );
        assert!(matches!(p.action, Action::Hide(_)), "{p:?}");
        // PYENV_DIR only moves the version file search, which an override
        // skips: the override still names the version (ruling P2).
        let p = plan_with(
            &s,
            &shims,
            &["PYENV_VERSION=3.12", "PYENV_DIR=/elsewhere"],
            "python",
            &found("3.12.1"),
        );
        assert_eq!(
            run_of(&p).0,
            at(".pyenv/versions/3.12/bin/python3")
                .as_os_str()
                .as_bytes()
        );
        // A hook can change pyenv's answer: no override value is used.
        let p = plan_with(
            &s,
            &shims,
            &["PYENV_VERSION=3.12", "PYENV_HOOK_PATH=/hooks"],
            "python",
            &found("3.12.1"),
        );
        assert!(matches!(p.action, Action::Hide(_)), "{p:?}");
    }

    // 환경이 통째로 오지 않았거나(frame의 일부만 읽힘: 잘못된 항목, 두 번 온 이름) rustup에 정규 cwd가 없으면
    // 숨긴다. 이것을 실패시키는 것: whole에서 잘못된 항목이나 중복 이름 검사를 지우는 것, vars가 None일 때 계속
    // 푸는 것, cwd 없는 rustup을 빈 cwd로 푸는 것.
    #[test]
    fn plan_hides_without_whole_inputs() {
        if exec_path::test_skip_as_root() {
            return;
        }
        let s = Scratch::new("inputs");
        tree(&s);
        let mut groups = SystemGroups::new(&sys::passwd_entry(sys::current_uid()).unwrap().name);
        let me = sys::current_uid();
        let folders = vec![s.0.join(".cargo/bin")];
        let resolved = std::cell::Cell::new(0);
        let c = Context {
            vars: None,
            folders: &folders,
            repo: &[],
            cwd: b"/",
            me,
            xcode_link: Path::new(XCODE_SELECT_LINK),
            command_line_tools: Path::new(COMMAND_LINE_TOOLS),
            resolved: &resolved,
        };
        let p = plan(lang("rust"), &found("1.80.0"), &c, &mut groups);
        assert_eq!(
            p.action,
            Action::Hide("the shell environment was not read whole")
        );
        for frame in [&b"HOME=/a\0HOME=/b\0"[..], b"HOME=/a\0broken\0"] {
            assert!(whole(&Environ::parse(frame)).is_none(), "{frame:?}");
        }
        assert!(whole(&Environ::parse(b"HOME=/a\0")).is_some());
        let body = environ(&[format!("HOME={}", s.0.display())]);
        let vars = Environ::parse(&body);
        let c = Context {
            vars: Some(&vars),
            cwd: b"/nonexistent-bingsu-cwd",
            ..c
        };
        let p = plan(lang("rust"), &found("1.80.0"), &c, &mut groups);
        assert_eq!(
            p.action,
            Action::Hide("the shell's folder could not be resolved")
        );
        assert_eq!(resolved.get(), 1);
        // Only rustup needs the canonical folder: node with the same
        // unresolvable folder still runs and resolves nothing (security
        // review S-M3).
        let bin = vec![s.0.join("bin")];
        let c = Context { folders: &bin, ..c };
        assert!(matches!(
            plan(lang("node"), &Version::None, &c, &mut groups).action,
            Action::Run(_)
        ));
        assert_eq!(resolved.get(), 1);
    }

    // 요약값: 빠른 값·숨김·실행은 서로 다른 정책이고(숨김이나 실패가 빠른 값을 막지 않음), 실행 정책은 실행 파일이
    // 바뀌면 달라진다. 환경 요약은 그 언어의 변수에 묶인다. 이것을 실패시키는 것: 실행 파일의 식별(크기·mtime)을
    // 요약에서 빼는 것, 언어 변수를 환경 요약에서 빼는 것.
    #[test]
    fn plan_digests_bind_the_decision() {
        if exec_path::test_skip_as_root() {
            return;
        }
        let s = Scratch::new("digests");
        tree(&s);
        let bin = s.0.join("bin").display().to_string();
        let cargo = s.0.join(".cargo/bin").display().to_string();
        let node = s.0.join("bin/node");
        let policy = || plan_with(&s, &bin, &[], "node", &Version::None).policy;
        let set_mtime = |secs: u64| {
            fs::File::options()
                .write(true)
                .open(&node)
                .unwrap()
                .set_modified(std::time::UNIX_EPOCH + std::time::Duration::from_secs(secs))
                .unwrap();
        };
        set_mtime(1_000_000);
        let first = policy();
        assert_eq!(policy(), first);
        // Each part of the executable's identity alone (D3a review L5).
        file(&node, b"\x7fELF node, rebuilt");
        set_mtime(1_000_000);
        assert_ne!(policy(), first, "size");
        file(&node, b"\x7fELF node");
        set_mtime(1_000_000);
        assert_eq!(policy(), first);
        set_mtime(2_000_000);
        assert_ne!(policy(), first, "mtime");
        set_mtime(1_000_000);
        // The nanoseconds alone (D3a re-review L5).
        fs::File::options()
            .write(true)
            .open(&node)
            .unwrap()
            .set_modified(std::time::UNIX_EPOCH + std::time::Duration::new(1_000_000, 500_000_000))
            .unwrap();
        assert_ne!(policy(), first, "mtime nanoseconds");
        set_mtime(1_000_000);
        assert_eq!(policy(), first);
        // A new inode with the same bytes, size and mtime.
        let copy = s.0.join("bin/node.new");
        fs::copy(&node, &copy).unwrap();
        fs::rename(&copy, &node).unwrap();
        set_mtime(1_000_000);
        assert_ne!(policy(), first, "inode");
        let fast = plan_with(&s, &cargo, &[], "rust", &found("1.80.0"));
        let run = plan_with(&s, &cargo, &[], "rust", &found("stable"));
        let hidden = plan_with(&s, &cargo, &[], "rust", &found("1.81.0"));
        assert_ne!(fast.policy, run.policy);
        assert_ne!(fast.policy, hidden.policy);
        // The selection file's digest alone (same value, other bytes).
        let other_file = Version::Found {
            file: 0,
            level: 0,
            digest: [8; 16],
            value: b"stable".to_vec(),
        };
        let run2 = plan_with(&s, &cargo, &[], "rust", &other_file);
        assert_ne!(run.policy, run2.policy, "selection digest");
        let other = plan_with(
            &s,
            &cargo,
            &["RUSTUP_HOME=/elsewhere"],
            "rust",
            &found("1.80.0"),
        );
        assert_ne!(fast.environment, other.environment);
    }

    // RUSTUP_TOOLCHAIN 오버라이드는 settings의 host로 설치 폴더를 찾고, 정규 cwd는 링크를 푼 경로다. 이것을
    // 실패시키는 것: run_override가 settings의 host 대신 빌드 host를 쓰는 것, canonical_cwd가 받은 경로를 그대로
    // 돌려주는 것(링크를 푼 경로가 아님), 없는 폴더에 값을 주는 것.
    #[test]
    fn override_follows_settings_and_cwd_is_canonical() {
        use std::os::unix::fs::symlink;
        if exec_path::test_skip_as_root() {
            return;
        }
        let s = Scratch::new("host");
        tree(&s);
        let at = |p: &str| s.0.join(p);
        file(
            &at(".rustup/toolchains/stable-zz-test-host/bin/rustc"),
            b"\x7fELF rustc",
        );
        fs::write(
            at(".rustup/settings.toml"),
            b"version = \"12\"\ndefault_host_triple = \"zz-test-host\"\n",
        )
        .unwrap();
        let cargo = at(".cargo/bin").display().to_string();
        let p = plan_with(
            &s,
            &cargo,
            &["RUSTUP_TOOLCHAIN=stable"],
            "rust",
            &found("1.80.0"),
        );
        assert_eq!(
            run_of(&p).0,
            at(".rustup/toolchains/stable-zz-test-host/bin/rustc")
                .as_os_str()
                .as_bytes()
        );
        symlink(at("bin"), at("link")).unwrap();
        assert_eq!(
            canonical_cwd(at("link").as_os_str().as_bytes()),
            Some(at("bin").into_os_string().into_encoded_bytes())
        );
        assert_eq!(canonical_cwd(at("missing").as_os_str().as_bytes()), None);
    }

    // macOS 개발 도구 stub(/usr/bin/python3)은 실행하지 않는다. 선택된 개발자 폴더(xcode_select_link)를 먼저,
    // 없으면 Command Line Tools를 쓰고, 그 아래 실제 python3가 없거나 둘 다 없으면 숨긴다(D3a 판정 i). stub 판정은
    // 경로만 보고, 실험으로 stub을 실행하지 않는다. 이것을 실패시키는 것: stub 이름 검사를 지우는 것(아무 명령이나
    // 개발자 폴더로 돌림), 선택 링크보다 CLT를 먼저 보는 것, 둘 다 없을 때 stub을 그대로 쓰는 것, 개발자 폴더에
    // 실제 도구가 없을 때 그 경로를 돌려주는 것, macOS 밖에서도 stub으로 보는 것(Linux의 /usr/bin/python3는
    // 인터프리터 자체다).
    #[test]
    fn developer_stubs_run_the_real_tool() {
        use std::os::unix::fs::symlink;
        let s = Scratch::new("xcode");
        let at = |p: &str| s.0.join(p);
        let stub = Path::new("/usr/bin/python3");
        for d in ["xcode/usr/bin", "clt/usr/bin", "empty"] {
            fs::create_dir_all(at(d)).unwrap();
        }
        file(&at("xcode/usr/bin/python3"), b"\x7fELF");
        file(&at("clt/usr/bin/python3"), b"\x7fELF");
        symlink(at("xcode"), at("link")).unwrap();
        symlink(at("empty"), at("link-empty")).unwrap();
        let d =
            |exe: &Path, link: &str, tools: &str| developer_tool(exe, &at(link), &at(tools), true);
        assert_eq!(
            developer_tool(stub, &at("link"), &at("clt"), false),
            Stub::Not
        );
        assert_eq!(d(Path::new("/usr/bin/node"), "link", "clt"), Stub::Not);
        assert_eq!(
            d(stub, "link", "clt"),
            Stub::Real(at("xcode/usr/bin/python3"))
        );
        assert_eq!(
            d(stub, "no-link", "clt"),
            Stub::Real(at("clt/usr/bin/python3"))
        );
        assert_eq!(d(stub, "no-link", "no-clt"), Stub::Missing);
        assert_eq!(d(stub, "link-empty", "clt"), Stub::Missing);
    }

    /// A Command Line Tools folder of the test's own with its python3, so
    /// the stub tests hold whatever this Mac has installed.
    #[cfg(target_os = "macos")]
    fn developer_fixture(s: &Scratch) -> PathBuf {
        let real = s.0.join("CommandLineTools/usr/bin/python3");
        file(&real, b"\x7fELF python");
        real
    }

    // 실제 /usr/bin을 PATH로 두면(macOS의 python3 stub) 결정은 stub이 아닌 개발자 폴더의 파일을 실행한다. 개발자
    // 폴더는 시험이 만든 fixture라 이 Mac에 도구가 있는지와 상관없다(D3a 재리뷰 L4). 이것을 실패시키는 것: RunFound에서
    // developer_tool의 답을 무시하고 찾은 stub을 그대로 쓰는 것.
    #[cfg(target_os = "macos")]
    #[test]
    fn plan_never_runs_the_developer_stub() {
        let s = Scratch::new("stub");
        let real = developer_fixture(&s);
        let p = plan_with(&s, "/usr/bin", &[], "python", &Version::None);
        assert_eq!(run_of(&p), (real.as_os_str().as_bytes().to_vec(), None));
    }

    // 셸에 DEVELOPER_DIR이 있으면 xcode-select 선택보다 그것이 우선하므로, stub 대신 고를 파일을 모른다: 숨긴다
    // (D3a 리뷰 M4). 환경 요약에도 그 이름이 들어간다. 개발자 폴더는 fixture다(재리뷰 L4). 이것을 실패시키는 것:
    // DEVELOPER_DIR 검사를 지우는 것, python 언어 변수에서 DEVELOPER_DIR을 빼는 것.
    #[cfg(target_os = "macos")]
    #[test]
    fn developer_dir_hides_the_stub() {
        let s = Scratch::new("devdir");
        developer_fixture(&s);
        let plain = plan_with(&s, "/usr/bin", &[], "python", &Version::None);
        let set = plan_with(
            &s,
            "/usr/bin",
            &["DEVELOPER_DIR=/x"],
            "python",
            &Version::None,
        );
        assert!(matches!(plain.action, Action::Run(_)), "{plain:?}");
        assert_eq!(
            set.action,
            Action::Hide("DEVELOPER_DIR picks the developer tools")
        );
        assert_ne!(plain.environment, set.environment);
    }
}
