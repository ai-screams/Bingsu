#[cfg(test)]
mod cases {
    use super::super::*;
    use crate::{
        collection::wire::BuildId,
        command::response::Entry,
        config::compile::{ExecPolicy, NotRun},
        snapshot,
    };
    use alloc::{string::String, vec, vec::Vec};

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
            policy: policy_digest(&r.policy, r.cwd, r.timeout, &r.env_allow),
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
        let prompt = Prompt {
            expected: &expected,
            entry,
            vars: &vars,
            eligible,
        };
        value(r, &prompt, u, origin).map(String::from)
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
}
