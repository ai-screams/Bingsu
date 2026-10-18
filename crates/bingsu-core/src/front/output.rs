//! N6 output policy. All times are nanoseconds in one monotonic clock domain;
//! the adapter observes the clock and translates errno, never the core.

pub type ClockValue = u64;

/// One interval fixed at prompt entry. Neither rendering nor retries extend it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Deadline {
    start: ClockValue,
    end: ClockValue,
}

impl Deadline {
    /// Zero budgets and overflow fail closed instead of wrapping or saturating.
    pub fn from_entry(start: ClockValue, budget_ns: u64) -> Option<Self> {
        if budget_ns == 0 {
            return None;
        }
        start.checked_add(budget_ns).map(|end| Self { start, end })
    }

    pub fn end(self) -> ClockValue {
        self.end
    }

    /// A clock moving behind entry is also unusable. Equality is expired.
    pub fn remaining(self, now: ClockValue) -> Option<u64> {
        if now < self.start || now >= self.end {
            None
        } else {
            Some(self.end - now)
        }
    }

    /// Relative microsecond timers must round UP and must never receive zero
    /// (zero disarms setitimer). The absolute deadline still governs each I/O.
    pub fn timer_micros(self, now: ClockValue) -> Option<u64> {
        self.remaining(now).map(|ns| ns.div_ceil(1_000))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IoResult {
    Written(usize),
    Interrupted,
    Failed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WriteStep {
    /// Advance by exactly this many bytes; never write an accepted prefix again.
    Continue(usize),
    /// Retry only after a fresh clock/flag observation, even for EINTR.
    Retry,
    Stop,
}

/// Decide after one write using a NEW clock/flag observation. Stop never means
/// undoing bytes already written, or appending a replacement B1 record.
pub fn write_decision(
    remaining: usize,
    result: IoResult,
    expired: bool,
    now: ClockValue,
    end: ClockValue,
) -> WriteStep {
    if remaining == 0 || expired || now >= end {
        return WriteStep::Stop;
    }
    match result {
        IoResult::Written(n) if n > 0 && n <= remaining => WriteStep::Continue(n),
        IoResult::Interrupted => WriteStep::Retry,
        _ => WriteStep::Stop,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // 이것을 실패시키는 것: 렌더 뒤 예산을 다시 주거나 now == end를 허용하는 것.
    #[test]
    fn one_deadline_counts_preparation_rendering_and_output() {
        let deadline = Deadline::from_entry(100, 50).unwrap();
        assert_eq!(deadline.end(), 150);
        for (now, want) in [
            (100, Some(50)),
            (120, Some(30)),
            (149, Some(1)),
            (150, None),
            (151, None),
        ] {
            assert_eq!(deadline.remaining(now), want);
        }
    }

    // 이것을 실패시키는 것: 시각 역행·덧셈 overflow·0 예산을 허용하는 것.
    #[test]
    fn unusable_clocks_and_budgets_fail_closed() {
        assert_eq!(Deadline::from_entry(10, 0), None);
        assert_eq!(Deadline::from_entry(u64::MAX, 1), None);
        assert_eq!(Deadline::from_entry(u64::MAX - 1, 2), None);
        let deadline = Deadline::from_entry(u64::MAX - 1, 1).unwrap();
        assert_eq!(deadline.remaining(u64::MAX - 2), None);
        assert_eq!(deadline.remaining(u64::MAX - 1), Some(1));
        assert_eq!(deadline.remaining(u64::MAX), None);
    }

    // 이것을 실패시키는 것: ns→us를 버림하여 타이머를 일찍 울리거나 0으로 끄는 것.
    #[test]
    fn relative_timer_rounds_up_without_overflow() {
        for (ns, us) in [
            (1, 1),
            (999, 1),
            (1_000, 1),
            (1_001, 2),
            (u64::MAX, 18_446_744_073_709_552),
        ] {
            assert_eq!(
                Deadline::from_entry(0, ns).unwrap().timer_micros(0),
                Some(us)
            );
        }
        assert_eq!(Deadline::from_entry(10, 1).unwrap().timer_micros(11), None);
    }

    // 이것을 실패시키는 것: 부분 쓰기 길이를 clamp하거나 0·범위 밖 길이·오류를 재시도하는 것.
    #[test]
    fn write_progress_is_exact_and_failures_stop() {
        for n in 1..=8 {
            assert_eq!(
                write_decision(8, IoResult::Written(n), false, 10, 20),
                WriteStep::Continue(n)
            );
        }
        for result in [
            IoResult::Written(0),
            IoResult::Written(9),
            IoResult::Written(usize::MAX),
            IoResult::Failed,
        ] {
            assert_eq!(write_decision(8, result, false, 10, 20), WriteStep::Stop);
        }
        assert_eq!(
            write_decision(0, IoResult::Interrupted, false, 10, 20),
            WriteStep::Stop
        );
        assert_eq!(
            write_decision(8, IoResult::Interrupted, false, 10, 20),
            WriteStep::Retry
        );
    }

    // 이것을 실패시키는 것: EINTR·부분 쓰기 뒤 만료 플래그나 새 시각을 무시하는 것.
    #[test]
    fn expiry_wins_over_every_write_result() {
        for result in [
            IoResult::Written(0),
            IoResult::Written(3),
            IoResult::Written(8),
            IoResult::Interrupted,
            IoResult::Failed,
        ] {
            assert_eq!(write_decision(8, result, true, 19, 20), WriteStep::Stop);
            assert_eq!(write_decision(8, result, false, 20, 20), WriteStep::Stop);
            assert_eq!(write_decision(8, result, false, 21, 20), WriteStep::Stop);
        }
    }

    // 이것을 실패시키는 것: EINTR 뒤 접두부를 다시 쓰거나 만료 뒤 두 번째 레코드를 붙이는 것.
    #[test]
    fn partial_writes_and_interrupts_preserve_the_record_prefix() {
        let record = b"B1\x1f8\x1f> \x1f\x1f\x1f\x1f\x1f\x1f\x1fok:none\x1e";
        let mut offset = 0;
        let mut written = alloc::vec::Vec::new();
        for (result, now) in [
            (IoResult::Written(2), 1),
            (IoResult::Interrupted, 2),
            (IoResult::Written(3), 3),
            (IoResult::Interrupted, 4),
            (IoResult::Written(1), 5),
        ] {
            if let IoResult::Written(n) = result {
                written.extend_from_slice(&record[offset..offset + n]);
            }
            match write_decision(record.len() - offset, result, false, now, 5) {
                WriteStep::Continue(n) => offset += n,
                WriteStep::Retry => {}
                WriteStep::Stop => break,
            }
        }
        // The final accepted byte remains on the pipe even though its syscall
        // returned at the deadline; Stop must not retry it or emit a fallback.
        assert_eq!(written, record[..6]);
        assert_eq!(offset, 5);
    }
}
