#[cfg(test)]
mod cases {
    use super::super::*;
    use crate::{
        collection::wire::BuildId,
        command::response::Entry,
        config::compile::{ExecPolicy, NotRun},
        snapshot,
    };
    use alloc::{format, string::String, vec, vec::Vec};

    const ENV: &[u8] = b"PATH=/usr/bin\0KUBECONFIG=/a\0LC_TIME=C\0";

    fn binding() -> Binding {
        let config = b"/home/u/.config/bingsu".to_vec();
        let state = b"/home/u/.local/state/bingsu".to_vec();
        Binding {
            build_id: BuildId([7; 32]),
            boot: [1; 16],
            epoch: [2; 16],
            context: snapshot::context_crc(&config, &state).unwrap(),
            clock_kind: 1,
            domain: [3; 16],
            resume: 4,
            config,
            state,
            cwd: b"/home/u/repo".to_vec(),
        }
    }
    fn clock(now: u64) -> Clock {
        Clock {
            kind: 1,
            domain: [3; 16],
            resume: 4,
            boot: [1; 16],
            now,
        }
    }
    fn unit(argv: &[&str]) -> ExecUnit {
        ExecUnit {
            id: "custom/k".into(),
            policy: ExecPolicy::Command {
                argv: argv.iter().map(|w| String::from(*w)).collect(),
                cwd: None,
                env_allow: vec!["KUBECONFIG".into()],
                shell: None,
                unsafe_shell: false,
            },
            timeout_ms: None,
            cache_ms: None,
            origins: Vec::new(),
            approved_by: Vec::new(),
            shown_at: Vec::new(),
            not_run: None,
        }
    }
    /// The entry the helper publishes for `u` run in `environ`.
    fn ran(u: &ExecUnit, origin: Origin, environ: &[u8]) -> Entry {
        let r = plan::runnable(u).unwrap();
        Entry {
            origin,
            id: u.id.clone(),
            policy: plan::entry_digest(&r),
            environment: plan::env_digest(&Environ::parse(environ), &r.env_allow),
            pattern: [0; 32],
            attempted_at: 5,
            completed_at: 10,
            status: Status::Ok,
            value: "prod".into(),
            raw: "prod".into(),
        }
    }
    fn response(entry: Entry) -> Response {
        Response {
            binding: binding(),
            entries: vec![entry],
        }
    }
    fn shown(
        r: &Response,
        u: &ExecUnit,
        origin: Origin,
        eligible: bool,
        environ: &[u8],
        now: u64,
    ) -> Option<String> {
        shown_at(r, u, origin, eligible, environ, clock(now))
    }
    fn shown_at(
        r: &Response,
        u: &ExecUnit,
        origin: Origin,
        eligible: bool,
        environ: &[u8],
        entry: Clock,
    ) -> Option<String> {
        let expected = binding();
        let vars = Environ::parse(environ);
        let mut prompt = Prompt::new(r, &expected, entry, &vars, eligible)?;
        value(&mut prompt, u, origin).map(String::from)
    }

    // 양성 대조와 표식 조건. 이것을 실패시키는 것: 설정 단위의 표시 자격 검사를 지우는 것(자격 없는 회차에도
    // 그림), 그 검사를 내장 조사에도 거는 것(내장 값이 자격 없는 회차에 숨음, D3 판정 Q3).
    #[test]
    fn a_matching_entry_shows_and_config_needs_eligibility() {
        let u = unit(&["kubectx"]);
        let r = response(ran(&u, Origin::Config, ENV));
        assert_eq!(
            shown(&r, &u, Origin::Config, true, ENV, 11).as_deref(),
            Some("prod")
        );
        assert_eq!(shown(&r, &u, Origin::Config, false, ENV, 11), None);
        let b = response(ran(&u, Origin::Builtin, ENV));
        assert_eq!(
            shown(&b, &u, Origin::Builtin, false, ENV, 11).as_deref(),
            Some("prod")
        );
    }

    // 응답 묶음과 시계. 이것을 실패시키는 것: binding 비교를 지우는 것(다른 cwd 응답을 그림), 시계 비교를 지우는
    // 것(다른 부팅 응답을 그림), 완료 < 진입 비교를 지우는 것(진입 뒤 완료한 값을 그림).
    #[test]
    fn another_binding_clock_or_a_later_completion_shows_nothing() {
        let u = unit(&["kubectx"]);
        let mut r = response(ran(&u, Origin::Config, ENV));
        r.binding.cwd = b"/home/u/other".to_vec();
        assert_eq!(shown(&r, &u, Origin::Config, true, ENV, 11), None);
        let mut r = response(ran(&u, Origin::Config, ENV));
        r.binding.boot = [9; 16];
        assert_eq!(shown(&r, &u, Origin::Config, true, ENV, 11), None);
        let r = response(ran(&u, Origin::Config, ENV));
        assert_eq!(shown(&r, &u, Origin::Config, true, ENV, 10), None);
    }

    // 응답 묶음은 같고 이 프롬프트의 진입 시계만 다른 회차. 이것을 실패시키는 것: 진입 시계의 boot, kind,
    // domain, resume 비교를 하나씩 지우는 것, eligible을 binding 동등 비교로 줄이는 것.
    #[test]
    fn the_same_binding_under_another_entry_clock_shows_nothing() {
        let u = unit(&["kubectx"]);
        let r = response(ran(&u, Origin::Config, ENV));
        let moved: [fn(&mut Clock); 4] = [
            |c| c.boot = [9; 16],
            |c| c.kind = 2,
            |c| c.domain = [9; 16],
            |c| c.resume = 5,
        ];
        for (i, m) in moved.iter().enumerate() {
            let mut c = clock(11);
            m(&mut c);
            assert_eq!(shown_at(&r, &u, Origin::Config, true, ENV, c), None, "{i}");
        }
        assert_eq!(
            shown_at(&r, &u, Origin::Config, true, ENV, clock(11)).as_deref(),
            Some("prod")
        );
    }

    // 같은 id의 항목은 origin으로 가른다. 이것을 실패시키는 것: 항목 조회에서 origin 비교를 지우는 것(다른
    // origin의 값을 그리거나, 두 origin이 함께 있을 때 앞의 것을 고름).
    #[test]
    fn an_entry_of_the_other_origin_is_not_this_units() {
        let u = unit(&["kubectx"]);
        let r = response(ran(&u, Origin::Builtin, ENV));
        assert_eq!(shown(&r, &u, Origin::Config, true, ENV, 11), None);
        let r = response(ran(&u, Origin::Config, ENV));
        assert_eq!(shown(&r, &u, Origin::Builtin, true, ENV, 11), None);
        for first in [Origin::Config, Origin::Builtin] {
            let mut both = Response {
                binding: binding(),
                entries: Vec::new(),
            };
            for o in [
                first,
                if first == Origin::Config {
                    Origin::Builtin
                } else {
                    Origin::Config
                },
            ] {
                let mut e = ran(&u, o, ENV);
                e.value = if o == Origin::Config { "cfg" } else { "bin" }.into();
                both.entries.push(e);
            }
            assert_eq!(
                shown(&both, &u, Origin::Config, true, ENV, 11).as_deref(),
                Some("cfg")
            );
            assert_eq!(
                shown(&both, &u, Origin::Builtin, true, ENV, 11).as_deref(),
                Some("bin")
            );
        }
    }

    // 한 프롬프트가 여러 단위를 판정할 때 환경 요약값은 같은 env_allow 목록마다 한 번 계산하고, 결과는 단위마다
    // 따로 계산한 것과 같다. 이것을 실패시키는 것: 기억한 요약값을 목록 비교 없이 다른 목록의 단위에 쓰는 것(목록이
    // 다른 단위가 값을 잃음). Prompt는 셸 환경 하나에 묶이므로 다른 환경의 요약값을 기억할 수 없다.
    #[test]
    fn one_prompt_shares_digests_only_between_equal_allow_lists() {
        let mut units = Vec::new();
        for (id, allow) in [
            ("custom/a", "KUBECONFIG"),
            ("custom/b", "LC_TIME"),
            ("custom/c", "KUBECONFIG"),
        ] {
            let mut u = unit(&["kubectx"]);
            u.id = id.into();
            if let ExecPolicy::Command { env_allow, .. } = &mut u.policy {
                *env_allow = vec![allow.into(), "HOME".into()];
            }
            units.push(u);
        }
        let r = Response {
            binding: binding(),
            entries: units.iter().map(|u| ran(u, Origin::Config, ENV)).collect(),
        };
        let expected = binding();
        let vars = Environ::parse(ENV);
        for order in [[0, 1, 2], [1, 0, 2], [2, 1, 0]] {
            let mut prompt = Prompt::new(&r, &expected, clock(11), &vars, true).unwrap();
            for i in order {
                assert_eq!(
                    value(&mut prompt, &units[i], Origin::Config),
                    Some("prod"),
                    "{order:?} {i}"
                );
            }
        }
    }

    // 단위와 정책. 이것을 실패시키는 것: runnable 검사를 지우는 것(not_run 단위의 값을 그림), 정책 요약값 비교를
    // 지우는 것(argv를 바꾼 단위가 옛 값을 그림), 다른 단위 id의 항목을 받는 것.
    #[test]
    fn a_unit_that_does_not_run_or_changed_its_policy_shows_nothing() {
        let u = unit(&["kubectx"]);
        let r = response(ran(&u, Origin::Config, ENV));
        let mut off = u.clone();
        off.not_run = Some(NotRun::Disabled);
        assert_eq!(shown(&r, &off, Origin::Config, true, ENV, 11), None);
        assert_eq!(
            shown(&r, &unit(&["kubectx", "-c"]), Origin::Config, true, ENV, 11),
            None
        );
        let mut other = u.clone();
        other.id = "custom/x".into();
        assert_eq!(shown(&r, &other, Origin::Config, true, ENV, 11), None);
    }

    // 이 셸의 원본 환경. 이것을 실패시키는 것: 환경 요약값 비교를 지우는 것(다른 KUBECONFIG 셸의 값을 그림),
    // 요약값에서 LC_* 를 빼는 것(LC_TIME만 다른 셸의 값을 그림).
    #[test]
    fn another_shells_environment_shows_nothing() {
        let u = unit(&["kubectx"]);
        let r = response(ran(&u, Origin::Config, ENV));
        assert_eq!(
            shown(
                &r,
                &u,
                Origin::Config,
                true,
                b"PATH=/usr/bin\0KUBECONFIG=/b\0LC_TIME=C\0",
                11
            ),
            None
        );
        assert_eq!(
            shown(
                &r,
                &u,
                Origin::Config,
                true,
                b"PATH=/usr/bin\0KUBECONFIG=/a\0LC_TIME=ko_KR\0",
                11
            ),
            None
        );
    }

    // 실패와 패턴. 이것을 실패시키는 것: 상태 검사를 지우는 것(실패 항목을 그림), 빈 패턴 조건을 지우는 것(C4c
    // 패턴으로 맞춘 값을 앞단이 그대로 그림, C4b 판정 Q4).
    #[test]
    fn a_failure_or_a_patterned_entry_shows_nothing() {
        let u = unit(&["kubectx"]);
        let mut failed = ran(&u, Origin::Config, ENV);
        failed.status = Status::Failed;
        assert_eq!(
            shown(&response(failed), &u, Origin::Config, true, ENV, 11),
            None
        );
        let mut patterned = ran(&u, Origin::Config, ENV);
        patterned.pattern = [1; 32];
        assert_eq!(
            shown(&response(patterned), &u, Origin::Config, true, ENV, 11),
            None
        );
    }

    const PY_ENV: &[u8] = b"PATH=/usr/bin\0PYENV_VERSION=3.12.1\0HOME=/home/u\0";

    /// The entry the helper publishes for `python` decided in `environ`.
    fn python_entry(environ: &[u8]) -> Entry {
        let python = crate::command::builtin::language(b"python").unwrap();
        Entry {
            origin: Origin::Builtin,
            id: "python".into(),
            policy: [4; 32],
            environment: python.env_digest(&Environ::parse(environ)),
            pattern: [0; 32],
            attempted_at: 5,
            completed_at: 10,
            status: Status::Ok,
            value: "3.12.1".into(),
            raw: "3.12.1".into(),
        }
    }
    fn version(r: &Response, environ: &[u8], now: u64, eligible: bool) -> Option<String> {
        let expected = binding();
        let vars = Environ::parse(environ);
        let prompt = Prompt::new(r, &expected, clock(now), &vars, eligible)?;
        let python = crate::command::builtin::language(b"python").unwrap();
        builtin_value(&prompt, python).map(String::from)
    }

    // D3b Q1–Q3: 내장 언어 값은 응답 묶음·시계·완료 시각·성공·패턴 없음과, 이 셸의 그 언어 변수 환경 요약값이
    // 맞을 때만 그리고, 값은 버전 이름이어야 한다. 표식 자격과 정책 요약값은 보지 않는다. 이것을 실패시키는 것:
    // 환경 요약값 비교를 지우는 것(PYENV_VERSION이 다른 셸에 값이 샘), 상태·패턴·완료 시각·버전 문법 검사를 하나씩
    // 지우는 것, origin을 가리지 않는 것(같은 id의 설정 항목을 그림), 표식 자격을 거는 것.
    #[test]
    fn a_builtin_version_needs_this_shells_language_environment() {
        let r = response(python_entry(PY_ENV));
        assert_eq!(version(&r, PY_ENV, 11, true).as_deref(), Some("3.12.1"));
        assert_eq!(version(&r, PY_ENV, 11, false).as_deref(), Some("3.12.1"));
        // Another shell in the same folder: another PYENV_VERSION, another HOME,
        // a manager folder variable it sets.
        let other = b"PATH=/usr/bin\0PYENV_VERSION=3.11.0\0HOME=/home/u\0";
        assert_eq!(version(&r, other, 11, true), None);
        let home = b"PATH=/usr/bin\0PYENV_VERSION=3.12.1\0HOME=/home/v\0";
        assert_eq!(version(&r, home, 11, true), None);
        let asdf = b"PATH=/usr/bin\0PYENV_VERSION=3.12.1\0HOME=/home/u\0ASDF_DIR=/a\0";
        assert_eq!(version(&r, asdf, 11, true), None);
        // A variable no language reads does not hide it.
        let unrelated = b"PATH=/usr/bin\0PYENV_VERSION=3.12.1\0HOME=/home/u\0EDITOR=vi\0";
        assert_eq!(version(&r, unrelated, 11, true).as_deref(), Some("3.12.1"));
        assert_eq!(version(&r, PY_ENV, 10, true), None);
        let mut e = python_entry(PY_ENV);
        e.status = Status::Failed;
        assert_eq!(version(&response(e), PY_ENV, 11, true), None);
        let mut e = python_entry(PY_ENV);
        e.pattern = [1; 32];
        assert_eq!(version(&response(e), PY_ENV, 11, true), None);
        let mut e = python_entry(PY_ENV);
        e.value = "3.12 beta".into();
        assert_eq!(version(&response(e), PY_ENV, 11, true), None);
        let mut e = python_entry(PY_ENV);
        e.origin = Origin::Config;
        assert_eq!(version(&response(e), PY_ENV, 11, true), None);
    }

    // 환경을 온전히 읽지 못한 셸(같은 이름이 두 번, 잘못된 항목)은 내장 값을 그리지 않는다. helper도 그런 frame에서는
    // 정하지 않는다. 같은 이름 두 번은 둘 다 버려져 그 변수가 없는 셸과 요약값이 같아지기 때문이다. 이것을 실패시키는
    // 것: builtin_value에서 버린 항목 검사를 지우는 것(셸 B가 셸 A의 3.12.1을 그림), 중복이나 잘못된 항목 한쪽만 세는 것.
    #[test]
    fn a_shell_not_read_whole_shows_no_builtin_version() {
        let a = b"PATH=/usr/bin\0HOME=/home/u\0";
        let r = response(python_entry(a));
        assert_eq!(version(&r, a, 11, true).as_deref(), Some("3.12.1"));
        let twice = b"PATH=/usr/bin\0HOME=/home/u\0PYENV_VERSION=3.11.9\0PYENV_VERSION=3.10.14\0";
        assert_eq!(version(&r, twice, 11, true), None);
        let malformed = b"PATH=/usr/bin\0HOME=/home/u\0NOEQUALS\0";
        assert_eq!(version(&r, malformed, 11, true), None);
    }

    // 언어마다 값을 묶는 셸 변수를 공유 표와 따로 이 시험에 적는다. 각 변수가 없을 때 정한 값은, 그 변수를 빈 값으로
    // 두거나 넣은 셸에서 숨고, 값이 있을 때 정한 값은 다른 값을 넣은 셸에서 숨는다. 이것을 실패시키는 것: 공유 표에서
    // 변수 하나를 지우는 것(예: PYENV_DIR), 해석기 없는 관리자 변수 하나를 지우는 것.
    #[test]
    fn each_language_is_bound_by_its_own_variables() {
        const UNSUPPORTED: [&str; 8] = [
            "ASDF_DATA_DIR",
            "ASDF_DIR",
            "MISE_DATA_DIR",
            "MISE_SHIMS_DIR",
            "XDG_DATA_HOME",
            "VOLTA_HOME",
            "NODENV_ROOT",
            "GOENV_ROOT",
        ];
        let own: [(&str, &[&str]); 4] = [
            ("node", &[]),
            (
                "python",
                &[
                    "PYENV_ROOT",
                    "PYENV_VERSION",
                    "PYENV_DIR",
                    "PYENV_HOOK_PATH",
                    "DEVELOPER_DIR",
                ],
            ),
            ("rust", &["RUSTUP_HOME", "CARGO_HOME", "RUSTUP_TOOLCHAIN"]),
            ("go", &[]),
        ];
        let base = "PATH=/usr/bin\0HOME=/home/u\0";
        for (id, names) in own {
            let language = crate::command::builtin::language(id.as_bytes()).unwrap();
            let decided = |environ: &str| Entry {
                origin: Origin::Builtin,
                id: id.into(),
                policy: [4; 32],
                environment: language.env_digest(&Environ::parse(environ.as_bytes())),
                pattern: [0; 32],
                attempted_at: 5,
                completed_at: 10,
                status: Status::Ok,
                value: "1.2.3".into(),
                raw: String::new(),
            };
            let shows = |r: &Response, environ: &str| {
                let expected = binding();
                let vars = Environ::parse(environ.as_bytes());
                let prompt = Prompt::new(r, &expected, clock(11), &vars, true).unwrap();
                builtin_value(&prompt, language).is_some()
            };
            for name in names.iter().chain(UNSUPPORTED.iter()) {
                let without = response(decided(base));
                assert!(shows(&without, base), "{id} {name}");
                for value in ["", "/x"] {
                    let set = format!("{base}{name}={value}\0");
                    assert!(!shows(&without, &set), "{id} {name}={value:?}");
                }
                let with = format!("{base}{name}=/x\0");
                let decided_with = response(decided(&with));
                assert!(shows(&decided_with, &with), "{id} {name}");
                assert!(
                    !shows(&decided_with, &format!("{base}{name}=/y\0")),
                    "{id} {name}"
                );
            }
        }
    }

    // 사용자 정의 language 단위의 값은 감지 이름까지 묶인 요약값(plan::entry_digest)이 맞을 때만 그린다(D3c-2 Q3).
    // detect_files를 바꾼 설정에서는 이전 값을 그리지 않는다. 이것을 실패시키는 것: 앞단이 grant 요약값(감지 이름
    // 없음)으로 비교하는 것.
    #[test]
    fn a_language_value_is_bound_to_its_files() {
        let lang = |detect: &str| ExecUnit {
            id: "custom/deno".into(),
            policy: ExecPolicy::Language {
                interpreter: Some("deno".into()),
                version_argv: vec!["--version".into()],
                detect_files: vec![detect.into()],
                cwd: None,
                env_allow: Vec::new(),
            },
            timeout_ms: None,
            cache_ms: None,
            origins: Vec::new(),
            approved_by: Vec::new(),
            shown_at: Vec::new(),
            not_run: None,
        };
        let u = lang("deno.json");
        let mut e = ran(&u, Origin::Config, ENV);
        e.value = "2.1.4".into();
        let r = response(e);
        assert_eq!(
            shown(&r, &u, Origin::Config, true, ENV, 11).as_deref(),
            Some("2.1.4")
        );
        assert_eq!(
            shown(&r, &lang("deno.jsonc"), Origin::Config, true, ENV, 11),
            None
        );
    }
}
