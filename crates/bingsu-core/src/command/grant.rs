//! The supervisor's approval right before each relay spawn. Builtin probes
//! skip only the trust deadline; the clock identity and the run budget apply
//! to both kinds.
use super::{
    deadline::{self, Budget},
    wire::{Grant, Policy, policy_digest},
};
use crate::{
    handoff::{Origin, Permit},
    snapshot::Clock,
};
use alloc::vec::Vec;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// Another clock kind, boot, resume generation or domain than the permit's.
    Clock,
    /// `now >= verified_at + T` (config units only).
    Trust,
    /// `now + min_run > H - reserve`.
    Budget,
    /// The carried policy does not hash to the approved digest, or the
    /// index is outside the grant's lists.
    Policy,
    /// Permit and exec frame together exceed the relay input cap. Never
    /// returned by `approve`; the supervisor reports it in the result.
    Limit,
}

/// Approve one spawn at `now` (`t_a`). Returns the run deadline `E`.
pub fn approve(
    now: Clock,
    permit: Permit,
    origin: Origin,
    helper_deadline: u64,
    timeout: u64,
    budget: Budget,
) -> Result<u64, Refusal> {
    if !permit.same_clock(now) {
        return Err(Refusal::Clock);
    }
    // A round without a valid marker sends deadline 0, so this refuses every
    // config unit while builtin probes keep the clock identity check.
    if origin == Origin::Config && now.now >= permit.deadline {
        return Err(Refusal::Trust);
    }
    let limit = deadline::run_limit(helper_deadline, budget.reserve).ok_or(Refusal::Budget)?;
    if !deadline::has_budget(now.now, budget.min_run, limit) {
        return Err(Refusal::Budget);
    }
    Ok(deadline::run_deadline(now.now, timeout, limit))
}

/// Names every config unit may pass (spec, sanitized environment: keep
/// list), plus every `LC_*`.
const KEEP: [&[u8]; 6] = [b"HOME", b"USER", b"LANG", b"TERM", b"TZ", b"PATH"];
const KEEP_PREFIX: &[u8] = b"LC_";
/// Never passed, not even through `env_allow` (U-13 V2, closed list S-24,
/// S-25): loader injection, then language and shell startup settings.
const FORBIDDEN: [&[u8]; 20] = [
    b"GLIBC_TUNABLES",
    b"GCONV_PATH",
    b"NODE_OPTIONS",
    b"PYTHONSTARTUP",
    b"PYTHONPATH",
    b"RUBYOPT",
    b"PERL5OPT",
    b"NODE_PATH",
    b"PYTHONHOME",
    b"PERL5LIB",
    b"PERLLIB",
    b"RUBYLIB",
    b"JAVA_TOOL_OPTIONS",
    b"_JAVA_OPTIONS",
    b"BASH_ENV",
    b"ENV",
    b"SHELLOPTS",
    b"BASHOPTS",
    b"PS4",
    b"ZDOTDIR",
];
const FORBIDDEN_PREFIX: [&[u8]; 3] = [b"LD_", b"DYLD_", b"BASH_FUNC_"];

fn forbidden(name: &[u8]) -> bool {
    FORBIDDEN.contains(&name) || FORBIDDEN_PREFIX.iter().any(|p| name.starts_with(p))
}

/// The target environment of a config unit: `NAME=VALUE\0` entries whose
/// names are in the keep list or the unit's `env_allow`, and an `env_allow`
/// with no forbidden name (such a unit is refused as a whole). A name may
/// appear once: with two `PATH` entries, which one a program reads depends
/// on how it searches its environment.
pub fn target_environment_allowed(environment: &[u8], env_allow: &[Vec<u8>]) -> bool {
    if env_allow.iter().any(|n| forbidden(n)) {
        return false;
    }
    if environment.is_empty() {
        return true;
    }
    let Some(body) = environment.strip_suffix(b"\0") else {
        return false;
    };
    let mut names = Vec::new();
    for entry in body.split(|&b| b == 0) {
        let Some(eq) = entry.iter().position(|&b| b == b'=') else {
            return false;
        };
        let name = &entry[..eq];
        if !(KEEP.contains(&name)
            || name.starts_with(KEEP_PREFIX)
            || env_allow.iter().any(|n| n.as_slice() == name))
        {
            return false;
        }
        names.push(name);
    }
    names.sort_unstable();
    !names.windows(2).any(|w| w[0] == w[1])
}

/// Approve config unit `index` of `grant`: a unit can only be named by its
/// place in the grant, its carried policy must hash to the digest the
/// helper approved, then the trust deadline and budget apply.
pub fn approve_unit(
    now: Clock,
    grant: &Grant,
    index: usize,
    budget: Budget,
) -> Result<u64, Refusal> {
    let unit = grant.units.get(index).ok_or(Refusal::Policy)?;
    // An empty argv would give the target argc 0.
    if matches!(&unit.policy, Policy::Argv { argv } if argv.is_empty()) {
        return Err(Refusal::Policy);
    }
    if policy_digest(&unit.policy, unit.cwd, unit.timeout, &unit.env_allow) != unit.digest {
        return Err(Refusal::Policy);
    }
    if !target_environment_allowed(&unit.environment, &unit.env_allow) {
        return Err(Refusal::Policy);
    }
    approve(
        now,
        grant.permit,
        Origin::Config,
        grant.helper_deadline,
        unit.timeout,
        budget,
    )
}

/// Approve builtin probe `index` of `grant`. Its timeout comes from the
/// profile table, so the caller passes it.
pub fn approve_probe(
    now: Clock,
    grant: &Grant,
    index: usize,
    timeout: u64,
    budget: Budget,
) -> Result<u64, Refusal> {
    if index >= grant.probes.len() {
        return Err(Refusal::Policy);
    }
    approve(
        now,
        grant.permit,
        Origin::Builtin,
        grant.helper_deadline,
        timeout,
        budget,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        command::wire::{Probe, Unit},
        handoff::Cwd,
    };
    use alloc::{vec, vec::Vec};

    const MS: u64 = 1_000_000;
    const H: u64 = 2_000 * MS;
    const B: Budget = Budget {
        reserve: 100 * MS,
        min_run: 10 * MS,
    };
    const TRUST: u64 = 1_500 * MS;

    fn clock(now: u64) -> Clock {
        Clock {
            kind: 1,
            domain: [2; 16],
            resume: 0,
            boot: [1; 16],
            now,
        }
    }
    fn permit(deadline: u64) -> Permit {
        Permit {
            kind: 1,
            deadline,
            boot: [1; 16],
            resume: 0,
            domain: [2; 16],
        }
    }
    fn unit(argv: &[&[u8]], timeout: u64) -> Unit {
        let policy = Policy::Argv {
            argv: argv.iter().map(|w| w.to_vec()).collect::<Vec<_>>(),
        };
        Unit {
            id: "custom/kube".into(),
            digest: policy_digest(&policy, Cwd::Neutral, timeout, &[]),
            policy,
            cwd: Cwd::Neutral,
            environment: b"HOME=/h\0".to_vec(),
            timeout,
            env_allow: Vec::new(),
        }
    }
    fn grant(deadline: u64) -> Grant {
        Grant {
            permit: permit(deadline),
            helper_deadline: H,
            units: vec![unit(&[b"kubectl", b"config", b"current-context"], 200 * MS)],
            probes: vec![Probe {
                profile: 1,
                executable: b"/usr/bin/python3".to_vec(),
            }],
        }
    }

    // 이것을 실패시키는 것: 신뢰 검사의 `>=`를 `>`로(= `now < deadline`을 `<=`로) 바꾸는 것.
    #[test]
    fn grant_rejects_after_trust_deadline() {
        let g = grant(TRUST);
        assert_eq!(approve_unit(clock(TRUST), &g, 0, B), Err(Refusal::Trust));
        assert!(approve_unit(clock(TRUST - 1), &g, 0, B).is_ok());
    }

    // 이것을 실패시키는 것: has_budget 검사를 지우는 것(두 종류 모두 1 ns 늦은 입력이 승인됨).
    #[test]
    fn grant_rejects_without_run_budget() {
        let g = grant(H);
        let edge = H - B.reserve - B.min_run;
        assert_eq!(
            approve_unit(clock(edge + 1), &g, 0, B),
            Err(Refusal::Budget)
        );
        assert_eq!(
            approve_probe(clock(edge + 1), &g, 0, 200 * MS, B),
            Err(Refusal::Budget)
        );
        assert!(approve_unit(clock(edge), &g, 0, B).is_ok());
        assert!(approve_probe(clock(edge), &g, 0, 200 * MS, B).is_ok());
        // A reserve longer than the helper deadline leaves no budget.
        let wide = Budget {
            reserve: H + 1,
            ..B
        };
        assert_eq!(
            approve_probe(clock(0), &g, 0, 200 * MS, wide),
            Err(Refusal::Budget)
        );
    }

    // 이것을 실패시키는 것: 신뢰 검사에서 `origin == Origin::Config &&`를 지우는 것
    // (내장 조사도 신뢰 마감을 받게 됨).
    #[test]
    fn grant_builtin_ignores_trust() {
        // No valid marker this round: deadline 0.
        let g = grant(0);
        assert!(approve_probe(clock(MS), &g, 0, 200 * MS, B).is_ok());
        assert_eq!(approve_unit(clock(MS), &g, 0, B), Err(Refusal::Trust));
    }

    // 이것을 실패시키는 것: approve의 신뢰 검사(`now.now >= permit.deadline`)를 지우는 것
    // (표식이 무효인 회차의 deadline 0 permit으로 설정 단위가 승인됨).
    #[test]
    fn grant_zero_deadline_permit_refuses_config() {
        let g = grant(0);
        for now in [0, MS, H - B.reserve - B.min_run] {
            assert_eq!(approve_unit(clock(now), &g, 0, B), Err(Refusal::Trust));
        }
    }

    // 이것을 실패시키는 것: approve_unit의 요약값에서 env_allow를 빼는 것(이름 목록만 바꾼 단위가
    // 승인됨).
    #[test]
    fn grant_env_allow_change_is_policy_mismatch() {
        let mut g = grant(TRUST);
        g.units[0].env_allow = vec![b"SSH_AUTH_SOCK".to_vec()];
        assert_eq!(approve_unit(clock(MS), &g, 0, B), Err(Refusal::Policy));
    }

    // 이것을 실패시키는 것: approve의 same_clock 검사를 지우는 것(내장 조사가 다른 깨어남 세대·
    // 부팅·domain에서 승인됨). 신뢰 마감을 보지 않는 내장 경로에서도 E는 같은 시계에서만 뜻이 있다.
    #[test]
    fn grant_builtin_checks_clock_identity() {
        let g = grant(0);
        let mut c = clock(MS);
        c.resume = 1;
        assert_eq!(approve_probe(c, &g, 0, 200 * MS, B), Err(Refusal::Clock));
        let mut c = clock(MS);
        c.boot[0] ^= 1;
        assert_eq!(approve_probe(c, &g, 0, 200 * MS, B), Err(Refusal::Clock));
        let mut c = clock(MS);
        c.domain[0] ^= 1;
        assert_eq!(approve_probe(c, &g, 0, 200 * MS, B), Err(Refusal::Clock));
    }

    // 이것을 실패시키는 것: approve_unit의 요약값 비교를 지우는 것.
    #[test]
    fn grant_policy_digest_mismatch() {
        let mut g = grant(TRUST);
        g.units[0].policy = Policy::Argv {
            argv: vec![b"rm".to_vec(), b"-rf".to_vec(), b"/".to_vec()],
        };
        assert_eq!(approve_unit(clock(MS), &g, 0, B), Err(Refusal::Policy));
        // Same argv, other timeout or cwd: the digest covers both.
        let mut g = grant(TRUST);
        g.units[0].timeout += 1;
        assert_eq!(approve_unit(clock(MS), &g, 0, B), Err(Refusal::Policy));
        let mut g = grant(TRUST);
        g.units[0].cwd = Cwd::UntrustedCurrent;
        assert_eq!(approve_unit(clock(MS), &g, 0, B), Err(Refusal::Policy));
    }

    // 이것을 실패시키는 것: approve_unit의 `.get(index)`를 마지막 단위로 대체하거나 approve_probe의
    // 순번 검사를 지우는 것(허가 목록 밖 순번이 승인됨).
    #[test]
    fn grant_refuses_index_outside_lists() {
        let g = grant(TRUST);
        assert!(approve_unit(clock(MS), &g, 0, B).is_ok());
        assert_eq!(approve_unit(clock(MS), &g, 1, B), Err(Refusal::Policy));
        assert!(approve_probe(clock(MS), &g, 0, 200 * MS, B).is_ok());
        assert_eq!(
            approve_probe(clock(MS), &g, 1, 200 * MS, B),
            Err(Refusal::Policy)
        );
    }

    fn reseal(u: &mut Unit) {
        u.digest = policy_digest(&u.policy, u.cwd, u.timeout, &u.env_allow);
    }

    // 이것을 실패시키는 것: 시계 검사를 신뢰·예산 검사 뒤로 옮기거나, 예산 검사를 신뢰 검사 앞으로
    // 옮기는 것(겹친 실패의 이유가 바뀜).
    #[test]
    fn grant_refusal_order() {
        let g = grant(TRUST);
        let late = H - B.reserve;
        let mut other = clock(late);
        other.resume = 1;
        assert_eq!(approve_unit(other, &g, 0, B), Err(Refusal::Clock));
        assert_eq!(approve_unit(clock(late), &g, 0, B), Err(Refusal::Trust));
    }

    // 이것을 실패시키는 것: approve_unit의 빈 argv 거부를 지우는 것(대상 argc 0).
    #[test]
    fn grant_refuses_empty_argv() {
        let mut g = grant(TRUST);
        g.units[0].policy = Policy::Argv { argv: Vec::new() };
        reseal(&mut g.units[0]);
        assert_eq!(approve_unit(clock(MS), &g, 0, B), Err(Refusal::Policy));
    }

    // 이것을 실패시키는 것: approve_unit의 target_environment_allowed 호출을 지우는 것.
    #[test]
    fn grant_refuses_environment_outside_rules() {
        let mut g = grant(TRUST);
        g.units[0].environment = b"SSH_AUTH_SOCK=/tmp/a\0".to_vec();
        assert_eq!(approve_unit(clock(MS), &g, 0, B), Err(Refusal::Policy));
        // Allowed by name: the same unit runs.
        g.units[0].env_allow = vec![b"SSH_AUTH_SOCK".to_vec()];
        reseal(&mut g.units[0]);
        assert!(approve_unit(clock(MS), &g, 0, B).is_ok());
        // A forbidden name in env_allow refuses the unit even with no value.
        g.units[0].env_allow.push(b"LD_PRELOAD".to_vec());
        reseal(&mut g.units[0]);
        assert_eq!(approve_unit(clock(MS), &g, 0, B), Err(Refusal::Policy));
    }

    // 이것을 실패시키는 것: env_allow 금지 검사(`env_allow.iter().any(forbidden)`)를 지우는 것,
    // FORBIDDEN 비교나 FORBIDDEN_PREFIX 비교를 지우는 것, FORBIDDEN에서 항목 하나를 빼는 것.
    // 기대 목록은 판정(U-13 V2, S-24, S-25)에서 따로 옮겨 적었다.
    #[test]
    fn target_environment_forbidden_names_never_pass() {
        for name in [
            &b"LD_PRELOAD"[..],
            b"LD_LIBRARY_PATH",
            b"DYLD_INSERT_LIBRARIES",
            b"GLIBC_TUNABLES",
            b"GCONV_PATH",
            b"NODE_OPTIONS",
            b"PYTHONSTARTUP",
            b"PYTHONPATH",
            b"RUBYOPT",
            b"PERL5OPT",
            b"NODE_PATH",
            b"PYTHONHOME",
            b"PERL5LIB",
            b"PERLLIB",
            b"RUBYLIB",
            b"JAVA_TOOL_OPTIONS",
            b"_JAVA_OPTIONS",
            b"BASH_ENV",
            b"ENV",
            b"SHELLOPTS",
            b"BASHOPTS",
            b"PS4",
            b"ZDOTDIR",
            b"BASH_FUNC_ls%%",
        ] {
            let mut entry = name.to_vec();
            entry.extend_from_slice(b"=x\0");
            assert!(!target_environment_allowed(&entry, &[name.to_vec()]));
            assert!(!target_environment_allowed(b"", &[name.to_vec()]));
        }
        // Credentials and tool settings can be allowed (V2).
        assert!(target_environment_allowed(
            b"GIT_DIR=/r\0",
            &[b"GIT_DIR".to_vec()]
        ));
    }

    // 이것을 실패시키는 것: 이름 중복 검사(`windows(2)` 비교)를 지우거나 정렬을 지우는 것
    // (떨어져 있는 같은 이름은 정렬 없이는 이웃이 아니다).
    #[test]
    fn target_environment_refuses_duplicate_names() {
        assert!(!target_environment_allowed(b"PATH=/a\0PATH=/b\0", &[]));
        assert!(!target_environment_allowed(
            b"PATH=/a\0HOME=/h\0PATH=/a\0",
            &[]
        ));
        assert!(target_environment_allowed(b"PATH=/a\0HOME=/h\0", &[]));
    }

    // 이것을 실패시키는 것: 빈 환경의 조기 승인을 지우는 것, 끝 NUL 요구(strip_suffix)를 지우는 것,
    // `=` 없는 항목 거부를 지우는 것, KEEP·LC_ 접두·env_allow 비교 하나를 지우거나 늘 참으로 하는 것.
    #[test]
    fn target_environment_format_and_names() {
        let allow = [b"KUBECONFIG".to_vec()];
        assert!(target_environment_allowed(b"", &allow));
        assert!(target_environment_allowed(
            b"HOME=/h\0USER=u\0LANG=C\0TERM=xterm\0TZ=UTC\0PATH=/usr/bin\0LC_ALL=C\0KUBECONFIG=/k\0",
            &allow
        ));
        // No final NUL, no `=`, an empty entry.
        assert!(!target_environment_allowed(b"HOME=/h", &allow));
        assert!(!target_environment_allowed(b"HOME\0", &allow));
        assert!(!target_environment_allowed(b"HOME=/h\0\0", &allow));
        // A name outside the keep list and env_allow.
        assert!(!target_environment_allowed(b"EDITOR=vi\0", &allow));
        assert!(!target_environment_allowed(b"KUBECONFIG=/k\0", &[]));
        // A name is compared whole: no prefix of a kept name passes.
        assert!(!target_environment_allowed(b"HOMEX=/h\0", &allow));
    }

    // 이것을 실패시키는 것: run_deadline의 `.min(limit)`을 지우는 것
    // (t_a + timeout > H - reserve에서 E가 t_a + timeout이 됨).
    #[test]
    fn exec_frame_e_formula() {
        let mut g = grant(H);
        g.units = vec![unit(&[b"slow"], 1_000 * MS), unit(&[b"fast"], 200 * MS)];
        let t_a = H - B.reserve - 300 * MS;
        assert_eq!(approve_unit(clock(t_a), &g, 0, B), Ok(H - B.reserve));
        assert_eq!(approve_unit(clock(t_a), &g, 1, B), Ok(t_a + 200 * MS));
    }
}
