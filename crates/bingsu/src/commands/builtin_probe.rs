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
    pub repo: Option<Id>,
    /// The shell's folder, canonical, for rustup's directory overrides;
    /// `None` when it could not be resolved.
    pub cwd: Option<&'a [u8]>,
    pub me: u32,
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
    let (at, found, checked) =
        match exec_path::lookup_open_in(language.word, c.folders, c.repo, c.me, groups) {
            Ok(hit) => hit,
            Err(_) => return hide("the command was not found or failed the checks"),
        };
    let homes = version_manager::homes(vars);
    let shim = version_manager::classify(
        language.manager,
        &c.folders[at],
        Some(&found.executable),
        &homes,
    );
    // rustup reads directory overrides for the canonical folder; one that
    // could not be resolved leaves the overrides unknown.
    let cwd = match (shim, c.cwd) {
        (Shim::Manager(Manager::Rustup), None) => {
            return hide("the shell's folder could not be resolved");
        }
        (_, cwd) => cwd.unwrap_or_default(),
    };
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
        Choice::RunFound => (found, checked, None),
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

/// The shell's folder, canonical (D3a acceptance: rustup's override
/// comparison uses the canonical path).
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
        file(&at(".pyenv/shims/python3"), b"#!/bin/sh\n");
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
        let folders = exec_path::sanitize(vars.get(b"PATH").unwrap(), None, me, &mut groups);
        let c = Context {
            vars: Some(&vars),
            folders: &folders,
            repo: None,
            cwd: Some(s.0.as_os_str().as_bytes()),
            me,
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
        let c = Context {
            vars: None,
            folders: &folders,
            repo: None,
            cwd: Some(b"/"),
            me,
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
            cwd: None,
            ..c
        };
        let p = plan(lang("rust"), &found("1.80.0"), &c, &mut groups);
        assert_eq!(
            p.action,
            Action::Hide("the shell's folder could not be resolved")
        );
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
        let first = plan_with(&s, &bin, &[], "node", &Version::None);
        file(&s.0.join("bin/node"), b"\x7fELF node, rebuilt");
        let again = plan_with(&s, &bin, &[], "node", &Version::None);
        assert_ne!(first.policy, again.policy);
        let fast = plan_with(&s, &cargo, &[], "rust", &found("1.80.0"));
        let run = plan_with(&s, &cargo, &[], "rust", &found("stable"));
        let hidden = plan_with(&s, &cargo, &[], "rust", &found("1.81.0"));
        assert_ne!(fast.policy, run.policy);
        assert_ne!(fast.policy, hidden.policy);
        let other = plan_with(
            &s,
            &cargo,
            &["RUSTUP_HOME=/elsewhere"],
            "rust",
            &found("1.80.0"),
        );
        assert_ne!(fast.environment, other.environment);
    }
}
