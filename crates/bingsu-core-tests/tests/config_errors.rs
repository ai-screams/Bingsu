//! Error-heavy input must not rescan all preceding errors for every value.
use bingsu_core::config::tree::{SyntaxErrorKind, parse};
use std::time::{Duration, Instant};

// 이것을 실패시키는 것: TooDeep 보고 여부를 매번 누적 오류 목록에서 찾는 것.
#[test]
fn many_errors_and_overdeep_siblings_finish_within_the_budget() {
    let n = 16_000;
    let mut src = "q = @\n".repeat(n);
    for depth in 1..=16 {
        src.push_str(&format!("[[{}]]\n", vec!["a"; depth].join(".")));
    }
    for i in 0..n {
        src.push_str(&format!("k{i}=[]\n"));
    }
    assert_eq!(src.len(), 245_226);
    let started = Instant::now();
    for _ in 0..4 {
        let errors = parse(src.as_bytes()).unwrap_err();
        assert!(errors.len() >= n);
        assert_eq!(
            errors
                .iter()
                .filter(|e| e.kind == SyntaxErrorKind::TooDeep)
                .count(),
            1
        );
    }
    let elapsed = started.elapsed();
    // Four parses leave generous headroom for unoptimized CI builds while
    // still separating the linear path from repeated scans of 32,000 errors.
    assert!(
        elapsed < Duration::from_secs(3),
        "4 × 245 KB took {elapsed:?}"
    );
}
