//! The supervisor's approval right before each relay spawn. Builtin probes
//! skip only the trust deadline; the clock identity and the run budget apply
//! to both kinds.
use super::{
    deadline::{self, Budget},
    wire::{Grant, policy_digest},
};
use crate::{
    handoff::{Origin, Permit},
    snapshot::Clock,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// Another clock kind, boot, resume generation or domain than the permit's.
    Clock,
    /// `now >= verified_at + T` (config units only).
    Trust,
    /// `now + min_run > H - reserve`.
    Budget,
    /// The carried policy does not hash to the approved digest.
    Policy,
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
    if origin == Origin::Config && now.now >= permit.deadline {
        return Err(Refusal::Trust);
    }
    let limit = deadline::run_limit(helper_deadline, budget.reserve).ok_or(Refusal::Budget)?;
    if !deadline::has_budget(now.now, budget.min_run, limit) {
        return Err(Refusal::Budget);
    }
    Ok(deadline::run_deadline(now.now, timeout, limit))
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
    if policy_digest(&unit.policy, unit.cwd, unit.timeout) != unit.digest {
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
        command::wire::{Policy, Probe, Unit},
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
            digest: policy_digest(&policy, Cwd::Neutral, timeout),
            policy,
            cwd: Cwd::Neutral,
            environment: b"HOME=/h\0".to_vec(),
            timeout,
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
