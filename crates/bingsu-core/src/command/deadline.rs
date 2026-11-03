//! Time formulas of one command round. Every input is an absolute or relative
//! nanosecond count in the helper's clock domain; the budget values are
//! arguments so a new limit changes the expected values, never the format.

/// Reserve before the helper deadline and the shortest run worth starting.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Budget {
    pub reserve: u64,
    pub min_run: u64,
}

/// `H - reserve`: no command of the round runs past it. `None` when the
/// reserve is larger than the deadline itself (no budget at all).
pub fn run_limit(helper_deadline: u64, reserve: u64) -> Option<u64> {
    helper_deadline.checked_sub(reserve)
}

/// `now + min_run <= H - reserve`.
pub fn has_budget(now: u64, min_run: u64, limit: u64) -> bool {
    now.checked_add(min_run).is_some_and(|t| t <= limit)
}

/// Run deadline `E = min(t_a + timeout, H - reserve)`, which is also the stop
/// time `t_a + min(timeout, H - reserve - t_a)` when `t_a <= H - reserve`.
/// `t_a` is the moment right before the relay spawn call.
pub fn run_deadline(approved_at: u64, timeout: u64, limit: u64) -> u64 {
    approved_at.saturating_add(timeout).min(limit)
}

#[cfg(test)]
mod tests {
    use super::*;
    const MS: u64 = 1_000_000;

    // 이것을 실패시키는 것: run_deadline에서 `.min(limit)`을 지우는 것
    // (timeout 1,000 ms, t_a = H - reserve - 300 ms에서 종료가 H - reserve 대신 t_a + 1,000 ms가 됨).
    #[test]
    fn deadline_caps_at_helper_life() {
        let h = 2_000 * MS;
        let reserve = 100 * MS;
        let limit = run_limit(h, reserve).unwrap();
        let t_a = h - reserve - 300 * MS;
        assert_eq!(run_deadline(t_a, 1_000 * MS, limit), h - reserve);
        // Within the limit the timeout decides.
        assert_eq!(run_deadline(t_a, 200 * MS, limit), t_a + 200 * MS);
    }

    // 이것을 실패시키는 것: saturating_add를 wrapping_add로 바꾸는 것(끝 근처 t_a에서 마감이 0 근처로 돎).
    #[test]
    fn deadline_never_wraps() {
        assert_eq!(run_deadline(u64::MAX - 1, 10, u64::MAX), u64::MAX);
    }

    // 이것을 실패시키는 것: `<=`를 `<`로 바꾸는 것(같음 입력이 거부됨), 또는 checked_add를
    // wrapping_add로 바꾸는 것(now가 끝 근처일 때 예산이 있는 것으로 보임).
    #[test]
    fn budget_edge() {
        let limit = 1_000;
        assert!(has_budget(990, 10, limit));
        assert!(!has_budget(991, 10, limit));
        assert!(!has_budget(u64::MAX, 10, u64::MAX - 1));
        assert_eq!(run_limit(5, 10), None);
    }
}
