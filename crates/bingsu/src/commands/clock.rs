//! Command-side clock injection; the shared OS adapter never accesses commands.
use bingsu_core::snapshot::{Clock, ClockError, ClockSource};

pub struct SystemClock;
impl ClockSource for SystemClock {
    fn observe(&mut self) -> Result<Clock, ClockError> {
        crate::prompt_io::observe_clock()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // 이것을 실패시키는 것: OS 관찰 실패를 고정 UUID·벽시계로 대체하거나 DI의 boot A/B를 무시하는 것.
    #[test]
    fn clock_source_preserves_failure_and_boot() {
        struct Injected(Result<Clock, ClockError>);
        impl ClockSource for Injected {
            fn observe(&mut self) -> Result<Clock, ClockError> {
                self.0
            }
        }
        for error in [ClockError::Boot, ClockError::Time, ClockError::Domain] {
            assert_eq!(Injected(Err(error)).observe(), Err(error));
        }
        for boot in [[1; 16], [2; 16]] {
            let clock = Clock {
                kind: 1,
                domain: [0; 16],
                resume: 0,
                boot,
                now: 99,
            };
            assert_eq!(Injected(Ok(clock)).observe().unwrap().boot, boot);
        }
        let got = SystemClock.observe();
        let direct = crate::prompt_io::observe_clock();
        match (got, direct) {
            (Ok(a), Ok(b)) => {
                assert_eq!(a.boot, b.boot);
                assert_eq!(a.domain, b.domain);
                assert!(a.now <= b.now);
            }
            (Err(a), Err(b)) => assert_eq!(a, b),
            other => panic!("inconsistent clock: {other:?}"),
        }
    }
}
