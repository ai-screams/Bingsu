//! `config check --explain`: the builtin language section (E2 rulings on
//! the builtin section, D3a ruling Q4). For each builtin language a trusted
//! layout draws at some width, what a prompt in this folder would decide
//! now: show a version without running anything, run a probe, or hide it
//! and why. The decision is the helper's own (`builtin_probe::plan`, with
//! the round's repository list and sanitized `PATH` from
//! `command_grant::search`); nothing is run. The selection file answers
//! and the repository root come from the folder facts the last round
//! saved for this folder, used only when they were collected by this build
//! for these roots and this folder in this boot, and shown with their age:
//! they may be out of date.
use super::{
    builtin_probe::{self, Action, Planned},
    collection_store,
    command_grant::{self, Languages, Root},
    group_policy::SystemGroups,
    snapshot_store::CheckedContextFd,
};
use bingsu_core::{
    collection::response::Completed,
    command::{
        builtin::{LANGUAGES, Language},
        plan::Environ,
        profile,
    },
    config::compile::CompiledConfig,
    field::BUILTIN,
    snapshot::Clock,
    template::compile::Node,
};
use std::{ffi::OsStr, fmt::Write as _, os::unix::ffi::OsStrExt, path::Path};

/// The builtin languages some line of some width draws.
pub(crate) fn drawn(config: &CompiledConfig) -> Vec<&'static Language> {
    LANGUAGES
        .iter()
        .filter(|l| {
            let Some(seg) = BUILTIN.iter().position(|d| d.id == l.id) else {
                return false;
            };
            config.variants.iter().flatten().any(|line| {
                line.nodes().iter().any(|n| match *n {
                    Node::Segment { seg: s, .. } | Node::Field { seg: s, .. } => {
                        usize::from(s) == seg
                    }
                    _ => false,
                })
            })
        })
        .collect()
}

/// Why a language was not decided at all.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NotDecided {
    NoFacts,
    Unsettled,
    NoAnswer,
    Environment,
    TooLarge,
    Folder,
    NoCwd,
}

impl NotDecided {
    fn text(self) -> &'static str {
        match self {
            Self::NoFacts => {
                "no folder facts were collected for this folder by this build in this boot"
            }
            Self::Unsettled => "the folder facts do not settle the repository",
            Self::NoAnswer => "the collection has no answer for it",
            Self::Environment => "the shell's environment has duplicate or malformed entries",
            Self::TooLarge => "the shell's environment is too large for the prompt to pass on",
            Self::Folder => "the shell's folder could not be read",
            Self::NoCwd => "the current folder cannot be read",
        }
    }
}

/// One language's outcome.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Decision {
    NotDecided(NotDecided),
    Planned(Planned),
}

/// The decision a round would make for `language` in this folder.
pub(crate) fn decide(
    language: &'static Language,
    languages: &Languages,
    environment: &[u8],
    cwd: &[u8],
    me: u32,
    groups: &mut SystemGroups,
) -> Decision {
    // The prompt hands the helper no environment past one frame
    // (`env_frame::encode`), and the helper then decides nothing.
    if environment.len() > bingsu_core::command::env_frame::BODY_MAX {
        return Decision::NotDecided(NotDecided::TooLarge);
    }
    let vars = Environ::parse(environment);
    // The helper decides nothing from such a frame (`builtin_probe::whole`).
    let Some(vars) = builtin_probe::whole(&vars) else {
        return Decision::NotDecided(NotDecided::Environment);
    };
    let collected = match languages.root() {
        Root::Unknown => return Decision::NotDecided(NotDecided::Unsettled),
        Root::Outside => None,
        Root::Repo(component) => Some(component),
    };
    let Some(version) = languages.get(language.id.as_bytes()) else {
        return Decision::NotDecided(NotDecided::NoAnswer);
    };
    let Ok(found) = command_grant::search(environment, cwd, collected, me, groups) else {
        return Decision::NotDecided(NotDecided::Folder);
    };
    let resolved = std::cell::Cell::new(0);
    let c = builtin_probe::Context {
        vars: Some(vars),
        folders: &found.folders,
        repo: &found.repo,
        cwd,
        me,
        xcode_link: Path::new(builtin_probe::XCODE_SELECT_LINK),
        command_line_tools: Path::new(builtin_probe::COMMAND_LINE_TOOLS),
        resolved: &resolved,
    };
    Decision::Planned(builtin_probe::plan(language, version, &c, groups))
}

/// The line of one decision: its words are the plan's own (the hidden
/// reason is the `Action::Hide` text, the run is the probe the grant would
/// carry).
pub(crate) fn line(language: &Language, d: &Decision) -> String {
    let clean = |b: &[u8]| bingsu_core::sanitize::sanitize(b);
    match d {
        Decision::NotDecided(why) => format!("{}  not decided: {}", language.id, why.text()),
        Decision::Planned(p) => match &p.action {
            Action::Show(version) => format!(
                "{}  shows {} without running anything",
                language.id,
                clean(version.as_bytes())
            ),
            Action::Hide(why) => format!("{}  hidden: {why}", language.id),
            Action::Run(probe) => {
                let mut words = vec![clean(&probe.executable)];
                if let Some(p) = profile::profile(probe.profile) {
                    words.extend(p.args.iter().map(|a| clean(a)));
                }
                format!("{}  runs {}", language.id, words.join(" "))
            }
        },
    }
}

/// Where the saved folder facts live: the runtime folder (as it is now,
/// found without making or changing anything) and the two roots.
pub(crate) struct Place {
    pub runtime: super::runtime_root::Pinned,
    pub config: Vec<u8>,
    pub state: Vec<u8>,
}

/// The folder facts the last round saved for `cwd`, if this build
/// collected them for these roots in this boot (E2 builtin ruling Q1: the
/// parts of the binding that do not depend on the terminal's width).
pub(crate) fn saved_facts(
    place: &Place,
    cwd: &[u8],
    now: Clock,
    me: u32,
    groups: &mut SystemGroups,
) -> Option<Completed> {
    let (config, state) = (place.config.as_slice(), place.state.as_slice());
    let context = CheckedContextFd::open(&place.runtime, config, state, me, groups, false).ok()?;
    let completed = collection_store::read_saved_response(&context, cwd).ok()??;
    let here = Here {
        build_id: bingsu_identity::build_id(),
        config,
        state,
        cwd,
        now,
    };
    here.fits(&completed.binding, completed.completed_at_ns)
        .then_some(completed)
}

/// What a saved collection must have been collected for.
pub(crate) struct Here<'a> {
    pub build_id: bingsu_core::collection::wire::BuildId,
    pub config: &'a [u8],
    pub state: &'a [u8],
    pub cwd: &'a [u8],
    pub now: Clock,
}

impl Here<'_> {
    /// The parts of a collection binding that do not depend on the
    /// terminal's width (the worker mask and path query do): this build,
    /// these roots, this folder, this clock (boot, kind, domain, resume),
    /// and completed no later than now.
    pub(crate) fn fits(
        &self,
        b: &bingsu_core::collection::wire::Binding,
        completed_at: u64,
    ) -> bool {
        b.build_id == self.build_id
            && b.config == self.config
            && b.state == self.state
            && b.cwd == self.cwd
            && b.snapshot.boot == self.now.boot
            && b.clock_kind == self.now.kind
            && b.domain == self.now.domain
            && b.resume == self.now.resume
            && completed_at <= self.now.now
    }
}

/// What `--explain` finds out about the builtin languages a layout draws.
pub(crate) struct Outcome {
    /// Seconds since the folder facts were collected; `None` without facts.
    pub age_s: Option<u64>,
    pub rows: Vec<(&'static Language, Decision)>,
}

/// The decisions for every builtin language the layout draws, or `None`
/// when it draws none (nothing is looked up then).
pub(crate) fn decisions(
    config: &CompiledConfig,
    place: Option<&Place>,
    environment: &[u8],
    cwd: Option<&[u8]>,
    now: Option<Clock>,
    me: u32,
    groups: &mut SystemGroups,
) -> Option<Outcome> {
    let languages = drawn(config);
    if languages.is_empty() {
        return None;
    }
    let facts = match (place, cwd, now) {
        (Some(place), Some(cwd), Some(now)) => {
            saved_facts(place, cwd, now, me, groups).map(|c| (c, now))
        }
        _ => None,
    };
    let answers = facts.as_ref().map(|(c, _)| Languages::from_result(c));
    let rows = languages
        .into_iter()
        .map(|language| {
            let d = match (&answers, cwd) {
                (_, None) => Decision::NotDecided(NotDecided::NoCwd),
                (Some(a), Some(cwd)) => decide(language, a, environment, cwd, me, groups),
                (None, Some(_)) => Decision::NotDecided(NotDecided::NoFacts),
            };
            (language, d)
        })
        .collect();
    Some(Outcome {
        age_s: facts
            .as_ref()
            .map(|(c, now)| now.now.saturating_sub(c.completed_at_ns) / 1_000_000_000),
        rows,
    })
}

/// The words of a decision's kind, for the JSON output.
pub(crate) fn outcome_word(d: &Decision) -> &'static str {
    match d {
        Decision::NotDecided(_) => "not-decided",
        Decision::Planned(p) => match &p.action {
            Action::Show(_) => "shows",
            Action::Hide(_) => "hidden",
            Action::Run(_) => "runs",
        },
    }
}

/// The section, or an empty string when the layout draws no builtin
/// language.
pub(crate) fn section(
    config: &CompiledConfig,
    place: Option<&Place>,
    environment: &[u8],
    cwd: Option<&[u8]>,
    now: Option<Clock>,
    me: u32,
    groups: &mut SystemGroups,
) -> String {
    let Some(found) = decisions(config, place, environment, cwd, now, me, groups) else {
        return String::new();
    };
    let mut out = String::from("builtin languages (--explain; ");
    match found.age_s {
        Some(age) => {
            let _ = write!(
                out,
                "decided as a prompt in this folder would decide now, from the folder facts collected {age} s ago, which may be out of date; "
            );
        }
        None => out.push_str("no folder facts for this folder; "),
    }
    out.push_str(
        "executables as a round finds them, inside the repository rules, which can differ from the execution section; \
         shell environment entries without '=' are not seen here, so a round can differ; nothing is run):\n",
    );
    for (language, d) in &found.rows {
        out.push_str(&line(language, d));
        out.push('\n');
    }
    out
}

/// The shell's folder: `pwd` when it names the current folder, as the shell
/// passes it to the prompt, else the current folder.
pub(crate) fn shell_folder(pwd: Option<&OsStr>) -> Option<Vec<u8>> {
    folder_of(pwd, &std::env::current_dir().ok()?)
}

/// `shell_folder` for a given `PWD` and current folder: a stale `PWD` (one
/// that names another folder) would read another folder's facts.
fn folder_of(pwd: Option<&OsStr>, here: &Path) -> Option<Vec<u8>> {
    use std::os::unix::fs::MetadataExt;
    let at = std::fs::metadata(here).ok()?;
    if let Some(pwd) = pwd.filter(|p| Path::new(p).is_absolute())
        && let Ok(m) = std::fs::metadata(pwd)
        && (m.dev(), m.ino()) == (at.dev(), at.ino())
    {
        return Some(pwd.as_bytes().to_vec());
    }
    Some(here.as_os_str().as_bytes().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bingsu_core::{
        collection::language::Version,
        color::palette::Mode,
        config::{
            compile::BUILTIN_TOML,
            report,
            source::{ExtendsRef, FileKey, OpenError, Opened, Resolver, Trust},
        },
    };
    use std::os::unix::fs::PermissionsExt;

    struct NoFiles;
    impl Resolver for NoFiles {
        fn open(&mut self, _: &Opened, _: &ExtendsRef) -> Result<Opened, OpenError> {
            panic!("no source files")
        }
    }
    fn compiled(user: &str) -> CompiledConfig {
        let roots: Vec<_> = [BUILTIN_TOML, user]
            .iter()
            .enumerate()
            .map(|(i, text)| Opened {
                key: FileKey {
                    dev: 1,
                    ino: i as u64,
                },
                bytes: text.as_bytes().to_vec(),
                trust: Trust::Executable,
                display: vec![b'a' + i as u8],
            })
            .collect();
        report::report(roots, &mut NoFiles, [0, 3, 0], Mode::Dark)
            .snapshot
            .unwrap()
    }
    fn ids(c: &CompiledConfig) -> Vec<&'static str> {
        drawn(c).iter().map(|l| l.id).collect()
    }

    // 그리는 언어가 없으면 절 자체가 없다. 현재 폴더를 읽지 못하면 절은 남기고 언어마다 그 이유를 쓴다. 머리말은
    // `=` 없는 환경 항목을 보지 못한다고 적는다. 이것을 실패시키는 것: 빈 목록에도 머리말을 쓰는 것, 현재 폴더가
    // 없을 때 절을 빼거나 "no folder facts"로 쓰는 것.
    #[test]
    fn no_drawn_language_writes_no_section() {
        let me = super::super::sys::current_uid();
        let none = section(
            &compiled(""),
            None,
            PATHLESS,
            Some(b"/"),
            None,
            me,
            &mut groups(),
        );
        assert_eq!(none, "");
        let node = compiled("[layout.line2]\nleft=['node','char']\n");
        let one = section(&node, None, PATHLESS, Some(b"/"), None, me, &mut groups());
        assert!(
            one.starts_with("builtin languages (--explain; no folder facts"),
            "{one}"
        );
        assert!(
            one.contains("entries without '=' are not seen here"),
            "{one}"
        );
        assert!(one.ends_with("node  not decided: no folder facts were collected for this folder by this build in this boot\n"));
        let gone = section(&node, None, PATHLESS, None, None, me, &mut groups());
        assert!(
            gone.ends_with("\nnode  not decided: the current folder cannot be read\n"),
            "{gone}"
        );
    }

    // 셸 환경이 프롬프트가 넘기는 frame 본문 상한을 넘으면 helper가 환경을 받지 못하므로 정하지 않는다. 상한까지는
    // 정한다. 이것을 실패시키는 것: 크기 검사를 지우는 것, 상한을 하나 줄이거나 늘리는 것.
    #[test]
    fn an_environment_past_the_frame_is_not_decided() {
        use bingsu_core::command::env_frame::BODY_MAX;
        let me = super::super::sys::current_uid();
        let outside = Languages::of(vec![(b"node".to_vec(), Version::None)], Root::Outside);
        let sized = |n: usize| {
            let mut e = PATHLESS.to_vec();
            let pad = n - e.len() - b"PAD=\0".len();
            e.extend_from_slice(b"PAD=");
            e.extend(std::iter::repeat_n(b'x', pad));
            e.push(0);
            assert_eq!(e.len(), n);
            e
        };
        assert!(matches!(
            decide(
                language("node"),
                &outside,
                &sized(BODY_MAX),
                b"/",
                me,
                &mut groups()
            ),
            Decision::Planned(_)
        ));
        assert_eq!(
            decide(
                language("node"),
                &outside,
                &sized(BODY_MAX + 1),
                b"/",
                me,
                &mut groups()
            ),
            Decision::NotDecided(NotDecided::TooLarge)
        );
    }

    // 그리는 언어만 보인다: 어느 폭의 줄이든 그 segment나 필드를 그리면 넣고, 그리지 않는 언어는 뺀다(E2 내장 판정
    // Q5). 이것을 실패시키는 것: 첫 band의 줄만 보는 것(좁은 폭에서만 그리는 go가 빠짐), 필드 노드를 놓치는 것,
    // 그리지 않는 언어까지 넣는 것.
    #[test]
    fn only_the_drawn_languages_are_explained() {
        assert!(ids(&compiled("")).is_empty());
        let c = compiled(
            "[layout.line2]\nleft=['node','char']\n\
             [layout.when.narrow]\nmax_cols=40\n[layout.when.narrow.style]\ntemplate=\"{go.version}{char}\"\n",
        );
        assert_eq!(ids(&c), ["node", "go"]);
    }

    fn language(id: &str) -> &'static Language {
        LANGUAGES.iter().find(|l| l.id == id).unwrap()
    }
    fn groups() -> SystemGroups {
        SystemGroups::new(
            &super::super::sys::passwd_entry(super::super::sys::current_uid())
                .unwrap()
                .name,
        )
    }
    const PATHLESS: &[u8] = b"PATH=/nonexistent-bingsu\0HOME=/nonexistent-bingsu\0";

    // 판정 전 단계는 회차와 같은 조건에서 멈추고 그 이유를 쓴다: 환경이 온전하지 않음, 뿌리 미확정, 그 언어의 답
    // 없음. 이것을 실패시키는 것: 환경 온전함 검사를 지우는 것(중복 PATH로도 정함), 뿌리 미확정을 저장소 밖으로 보는
    // 것, 답이 없는 언어를 정하는 것.
    #[test]
    fn a_round_that_would_not_decide_says_why() {
        let me = super::super::sys::current_uid();
        let outside = Languages::of(vec![(b"node".to_vec(), Version::None)], Root::Outside);
        let dup = b"PATH=/a\0PATH=/b\0";
        assert_eq!(
            decide(language("node"), &outside, dup, b"/", me, &mut groups()),
            Decision::NotDecided(NotDecided::Environment)
        );
        let unknown = Languages::of(vec![(b"node".to_vec(), Version::None)], Root::Unknown);
        assert_eq!(
            decide(
                language("node"),
                &unknown,
                PATHLESS,
                b"/",
                me,
                &mut groups()
            ),
            Decision::NotDecided(NotDecided::Unsettled)
        );
        assert_eq!(
            decide(language("go"), &outside, PATHLESS, b"/", me, &mut groups()),
            Decision::NotDecided(NotDecided::NoAnswer)
        );
        // Positive control: a settled root and an answer reach the plan.
        assert!(matches!(
            decide(
                language("node"),
                &outside,
                PATHLESS,
                b"/",
                me,
                &mut groups()
            ),
            Decision::Planned(_)
        ));
    }

    /// A folder outside any repository with `node` in it: a copy of `true`,
    /// or a script.
    fn tools(tag: &str, script: bool) -> std::path::PathBuf {
        let t = std::env::temp_dir().join(format!("bingsu-explain-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&t);
        std::fs::create_dir_all(t.join("bin")).unwrap();
        std::fs::create_dir_all(t.join("shell")).unwrap();
        let t = std::fs::canonicalize(&t).unwrap();
        for d in [&t, &t.join("bin")] {
            std::fs::set_permissions(d, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let node = t.join("bin/node");
        if script {
            std::fs::write(&node, "#!/bin/sh\necho v1.0.0\n").unwrap();
        } else {
            std::fs::copy(std::fs::canonicalize("/usr/bin/true").unwrap(), &node).unwrap();
        }
        std::fs::set_permissions(&node, std::fs::Permissions::from_mode(0o755)).unwrap();
        t
    }

    // 판정 줄은 helper의 plan이 낸 Action에서 바로 만든다: 숨김 이유는 plan의 문장 그대로이고, 실행은 그 probe의
    // 실행 파일과 프로필 인자다. 이것을 실패시키는 것: 줄이 Action 대신 따로 적은 문구를 쓰는 것, 실행 줄에 프로필
    // 인자를 빼는 것, 숨김을 실행으로 쓰는 것.
    #[test]
    fn each_line_is_the_plans_own_decision() {
        let me = super::super::sys::current_uid();
        let outside = Languages::of(vec![(b"node".to_vec(), Version::None)], Root::Outside);
        for script in [false, true] {
            let t = tools(if script { "script" } else { "binary" }, script);
            let env = format!("PATH={}\0HOME={}\0", t.join("bin").display(), t.display());
            let d = decide(
                language("node"),
                &outside,
                env.as_bytes(),
                // The shell beside the tools folder: its own folder stands for
                // the repository (J9), so it must not hold `bin`.
                t.join("shell").as_os_str().as_bytes(),
                me,
                &mut groups(),
            );
            let Decision::Planned(p) = &d else {
                panic!("{d:?}");
            };
            let got = line(language("node"), &d);
            match &p.action {
                Action::Run(probe) => {
                    assert!(!script);
                    let exe = String::from_utf8(probe.executable.clone()).unwrap();
                    assert_eq!(got, format!("node  runs {exe} --version"));
                    assert!(exe.ends_with("/bin/node"), "{exe}");
                }
                Action::Hide(why) => {
                    assert!(script, "{why}");
                    assert_eq!(got, format!("node  hidden: {why}"));
                    assert_eq!(got, "node  hidden: the command is a script");
                }
                Action::Show(v) => panic!("{v}"),
            }
            let _ = std::fs::remove_dir_all(&t);
        }
        let show = Decision::Planned(Planned {
            language: language("python"),
            policy: [0; 32],
            environment: [0; 32],
            action: Action::Show("3.12.1".into()),
        });
        assert_eq!(
            line(language("python"), &show),
            "python  shows 3.12.1 without running anything"
        );
        assert_eq!(
            line(language("go"), &Decision::NotDecided(NotDecided::NoFacts)),
            "go  not decided: no folder facts were collected for this folder by this build in this boot"
        );
    }

    // 저장된 수집 응답은 폭과 무관한 binding 칸이 모두 맞을 때만 쓴다(E2 내장 판정 Q1): build, 두 뿌리, cwd, 시계의
    // boot·kind·domain·resume, 지금보다 늦지 않은 완료. 폭에 따르는 mask와 path_query는 보지 않는다. 이것을
    // 실패시키는 것: 그 비교를 하나씩 지우는 것, mask나 path_query를 비교하는 것(폭이 다른 프롬프트의 응답을 버림).
    #[test]
    fn saved_facts_fit_only_this_build_roots_folder_and_boot() {
        use bingsu_core::collection::wire::{Binding, BuildId};
        let now = Clock {
            kind: 1,
            domain: [3; 16],
            resume: 4,
            boot: [5; 16],
            now: 1_000,
        };
        let here = Here {
            build_id: BuildId([7; 32]),
            config: b"/c",
            state: b"/s",
            cwd: b"/w",
            now,
        };
        let good = Binding {
            build_id: BuildId([7; 32]),
            snapshot: bingsu_core::snapshot::Identity {
                boot: [5; 16],
                context: [0; 4],
                epoch: [0; 16],
                generation: 1,
                source: [0; 4],
            },
            clock_kind: 1,
            domain: [3; 16],
            resume: 4,
            config: b"/c".to_vec(),
            state: b"/s".to_vec(),
            cwd: b"/w".to_vec(),
            mask: 8,
            path_query: Default::default(),
        };
        assert!(here.fits(&good, 1_000));
        let mut wide = good.clone();
        wide.mask = 0xff;
        assert!(here.fits(&wide, 1_000));
        let mut queried = good.clone();
        queried.path_query =
            bingsu_core::collection::path_facts::PathQuery::for_path(b"/w", Some(b"/w"), true);
        assert_ne!(queried.path_query, good.path_query);
        assert!(here.fits(&queried, 1_000));
        assert!(!here.fits(&good, 1_001));
        let moved: [fn(&mut Binding); 8] = [
            |b| b.build_id = BuildId([8; 32]),
            |b| b.config = b"/c2".to_vec(),
            |b| b.state = b"/s2".to_vec(),
            |b| b.cwd = b"/w2".to_vec(),
            |b| b.snapshot.boot = [6; 16],
            |b| b.clock_kind = 2,
            |b| b.domain = [9; 16],
            |b| b.resume = 5,
        ];
        for (i, m) in moved.iter().enumerate() {
            let mut b = good.clone();
            m(&mut b);
            assert!(!here.fits(&b, 1_000), "{i}");
        }
    }

    // 셸 폴더는 현재 폴더를 가리키는 PWD(셸이 프롬프트에 주는 그대로)이고, 다른 폴더를 가리키거나 상대 경로인 PWD는
    // 쓰지 않는다. 이것을 실패시키는 것: 같은 폴더인지 보지 않는 것(낡은 PWD로 다른 폴더의 사실을 읽음), 상대 PWD를
    // 받는 것.
    #[test]
    fn a_stale_pwd_is_not_the_shell_folder() {
        let t = tools("pwd", false);
        let link = t.join("alias");
        let _ = std::fs::remove_file(&link);
        std::os::unix::fs::symlink(t.join("shell"), &link).unwrap();
        let here = t.join("shell");
        let bytes = |p: &Path| p.as_os_str().as_bytes().to_vec();
        assert_eq!(folder_of(Some(link.as_os_str()), &here), Some(bytes(&link)));
        assert_eq!(
            folder_of(Some(t.join("bin").as_os_str()), &here),
            Some(bytes(&here))
        );
        assert_eq!(
            folder_of(Some(OsStr::new("shell")), &here),
            Some(bytes(&here))
        );
        assert_eq!(folder_of(None, &here), Some(bytes(&here)));
        // "." names the test's own current folder, the same inode as `cwd`.
        let cwd = std::env::current_dir().unwrap();
        assert_eq!(folder_of(Some(OsStr::new(".")), &cwd), Some(bytes(&cwd)));
        let _ = std::fs::remove_dir_all(&t);
    }
}
