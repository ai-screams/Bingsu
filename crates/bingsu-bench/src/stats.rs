//! Nearest-rank median and p95 (spec section 8: 200+ runs, median and p95).

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Summary {
    pub n: usize,
    pub median_ns: u64,
    pub p95_ns: u64,
    pub min_ns: u64,
    pub max_ns: u64,
}

/// Sorts `samples` in place. Panics on empty input.
pub fn summarize(samples: &mut [u64]) -> Summary {
    assert!(!samples.is_empty(), "no samples");
    samples.sort_unstable();
    let n = samples.len();
    let rank = |p: usize| samples[(p * n).div_ceil(100).max(1) - 1];
    Summary {
        n,
        median_ns: rank(50),
        p95_ns: rank(95),
        min_ns: samples[0],
        max_ns: samples[n - 1],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // 이것을 실패시키는 것: 0부터 센 순위(off-by-one)나 정렬하지 않은 입력.
    #[test]
    fn nearest_rank() {
        let mut v: Vec<u64> = (1..=100).rev().collect();
        let s = summarize(&mut v);
        assert_eq!(
            (s.n, s.median_ns, s.p95_ns, s.min_ns, s.max_ns),
            (100, 50, 95, 1, 100)
        );
        let mut one = vec![7];
        assert_eq!(summarize(&mut one).p95_ns, 7);
        let mut two = vec![10, 20];
        assert_eq!(
            (summarize(&mut two).median_ns, summarize(&mut two).p95_ns),
            (10, 20)
        );
    }
}
