//! Width bands (spec section 2 "폭 구간별 레이아웃", M2 rule, user decision
//! 2026-10-03). Order: a band properly contained in another comes first
//! (this covers "both max-only: smaller first" and "both min-only: larger
//! first"); bands that overlap without containment, or have the same
//! range, must both carry `order`, which then decides (lower first). Names
//! and file order never decide. Sorted once at compile time.
use alloc::vec::Vec;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Band {
    pub min_cols: Option<u16>,
    pub max_cols: Option<u16>,
    pub order: Option<i32>,
}

impl Band {
    fn lo(&self) -> u16 {
        self.min_cols.unwrap_or(0)
    }
    fn hi(&self) -> u16 {
        self.max_cols.unwrap_or(u16::MAX)
    }
    pub fn contains(&self, width: u16) -> bool {
        (self.lo()..=self.hi()).contains(&width)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BandError {
    /// `min_cols > max_cols`.
    Empty(usize),
    /// Two bands overlap without containment (or are equal) and not both
    /// have `order`.
    NeedsOrder(usize, usize),
    /// Two bands have the same `order` and overlap.
    SameOrder(usize, usize),
    /// `order` and containment disagree around a loop (for example C ⊂ A
    /// ⊂ B with B ordered before C): no order satisfies both.
    Cycle,
}

/// Must `a` be tried before `b`? None when they never compete (disjoint).
fn before(bands: &[Band], a: usize, b: usize) -> Result<Option<bool>, BandError> {
    let (x, y) = (&bands[a], &bands[b]);
    if x.hi() < y.lo() || y.hi() < x.lo() {
        return Ok(None);
    }
    if let (Some(ox), Some(oy)) = (x.order, y.order) {
        return if ox == oy {
            Err(BandError::SameOrder(a, b))
        } else {
            Ok(Some(ox < oy))
        };
    }
    let x_in_y = y.lo() <= x.lo() && x.hi() <= y.hi();
    let y_in_x = x.lo() <= y.lo() && y.hi() <= x.hi();
    match (x_in_y, y_in_x) {
        (true, false) => Ok(Some(true)),
        (false, true) => Ok(Some(false)),
        _ => Err(BandError::NeedsOrder(a, b)),
    }
}

/// Indices of `bands` in the order they are tried. Deterministic: a band is
/// placed once every band that must precede it is placed, ties broken by
/// (lo, hi), which only ever ties disjoint-or-ordered bands.
pub fn order_bands(bands: &[Band]) -> Result<Vec<usize>, BandError> {
    let n = bands.len();
    for (i, b) in bands.iter().enumerate() {
        if b.lo() > b.hi() {
            return Err(BandError::Empty(i));
        }
    }
    let mut preds = alloc::vec![0usize; n];
    let mut edges: Vec<(usize, usize)> = Vec::new();
    for a in 0..n {
        for b in a + 1..n {
            match before(bands, a, b)? {
                Some(true) => edges.push((a, b)),
                Some(false) => edges.push((b, a)),
                None => {}
            }
        }
    }
    for &(_, b) in &edges {
        preds[b] += 1;
    }
    let mut out = Vec::with_capacity(n);
    let mut placed = alloc::vec![false; n];
    while out.len() < n {
        // Containment and `order` are each acyclic, but mixed they can loop.
        let Some(next) = (0..n)
            .filter(|&i| !placed[i] && preds[i] == 0)
            .min_by_key(|&i| (bands[i].lo(), bands[i].hi(), i))
        else {
            return Err(BandError::Cycle);
        };
        placed[next] = true;
        out.push(next);
        for &(a, b) in &edges {
            if a == next {
                preds[b] -= 1;
            }
        }
    }
    Ok(out)
}

/// The band used at `width` (the shell's width, before the last column is
/// left empty), or None for the default layout. An index in `order` with
/// no band is passed over, so an order that does not match `bands` (it
/// comes from `order_bands`, but the arguments are public) never panics.
pub fn select(order: &[usize], bands: &[Band], width: u16) -> Option<usize> {
    order
        .iter()
        .copied()
        .find(|&i| bands.get(i).is_some_and(|b| b.contains(width)))
}

/// The choice for every width, as runs `(from, to, band)`. Widths are a
/// small integer range, so `config check` (M3) shows this table and finds
/// bands that are never chosen.
pub fn selection_table(order: &[usize], bands: &[Band]) -> Vec<(u16, u16, Option<usize>)> {
    let mut cuts: Vec<u32> = alloc::vec![0, u32::from(u16::MAX) + 1];
    for b in bands {
        cuts.push(u32::from(b.lo()));
        cuts.push(u32::from(b.hi()) + 1);
    }
    cuts.sort_unstable();
    cuts.dedup();
    let mut runs: Vec<(u16, u16, Option<usize>)> = Vec::new();
    for w in cuts.windows(2) {
        let (from, to) = (w[0] as u16, (w[1] - 1) as u16);
        let pick = select(order, bands, from);
        match runs.last_mut() {
            Some(last) if last.2 == pick && u32::from(last.1) + 1 == u32::from(from) => last.1 = to,
            _ => runs.push((from, to, pick)),
        }
    }
    runs
}

/// Bands that no width selects.
pub fn unreachable(order: &[usize], bands: &[Band]) -> Vec<usize> {
    let table = selection_table(order, bands);
    (0..bands.len())
        .filter(|i| !table.iter().any(|r| r.2 == Some(*i)))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn b(min: Option<u16>, max: Option<u16>, order: Option<i32>) -> Band {
        Band {
            min_cols: min,
            max_cols: max,
            order,
        }
    }

    // 이것을 실패시키는 것: 포함된 구간·작은 max·큰 min을 먼저 고르지 않는 것.
    #[test]
    fn containment_and_specificity() {
        let bands = [
            b(None, Some(99), None),
            b(None, Some(59), None),
            b(Some(120), None, None),
            b(Some(100), None, None),
        ];
        let o = order_bands(&bands).unwrap();
        assert_eq!(select(&o, &bands, 40), Some(1));
        assert_eq!(select(&o, &bands, 60), Some(0));
        assert_eq!(select(&o, &bands, 110), Some(3));
        assert_eq!(select(&o, &bands, 130), Some(2));
        let nested = [b(Some(0), Some(100), None), b(Some(40), Some(60), None)];
        let o = order_bands(&nested).unwrap();
        assert_eq!(select(&o, &nested, 50), Some(1));
        assert_eq!(select(&o, &nested, 61), Some(0));
    }

    // 이것을 실패시키는 것: 견줄 수 없는 겹침·같은 범위를 order 없이 받는 것, order를 무시하는 것.
    #[test]
    fn incomparable_needs_order() {
        let cross = [b(Some(0), Some(60), None), b(Some(40), Some(100), None)];
        assert_eq!(order_bands(&cross), Err(BandError::NeedsOrder(0, 1)));
        let same = [b(None, Some(59), None), b(None, Some(59), Some(1))];
        assert_eq!(order_bands(&same), Err(BandError::NeedsOrder(0, 1)));
        let ordered = [
            b(Some(0), Some(60), Some(2)),
            b(Some(40), Some(100), Some(1)),
        ];
        let o = order_bands(&ordered).unwrap();
        assert_eq!(select(&o, &ordered, 50), Some(1));
        assert_eq!(select(&o, &ordered, 30), Some(0));
        let clash = [
            b(Some(0), Some(60), Some(1)),
            b(Some(40), Some(100), Some(1)),
        ];
        assert_eq!(order_bands(&clash), Err(BandError::SameOrder(0, 1)));
        assert_eq!(
            order_bands(&[b(Some(9), Some(3), None)]),
            Err(BandError::Empty(0))
        );
        // C ⊂ A ⊂ B, A without order, B before C by order: a loop.
        let looped = [
            b(Some(20), Some(80), None),
            b(Some(0), Some(100), Some(1)),
            b(Some(40), Some(60), Some(2)),
        ];
        assert_eq!(order_bands(&looped), Err(BandError::Cycle));
    }

    // 이것을 실패시키는 것: 입력 순서(파일에 적힌 순서)가 결과를 바꾸는 것.
    #[test]
    fn input_order_does_not_matter() {
        let a = [
            b(None, Some(59), None),
            b(None, Some(99), None),
            b(Some(140), None, None),
        ];
        let r = [a[2], a[1], a[0]];
        let (oa, or) = (order_bands(&a).unwrap(), order_bands(&r).unwrap());
        for w in 0..=200u16 {
            assert_eq!(
                select(&oa, &a, w).map(|i| a[i]),
                select(&or, &r, w).map(|i| r[i]),
                "{w}"
            );
        }
    }

    // 이것을 실패시키는 것: 선택 표가 폭 전체(0–65535)를 빈틈없이 덮지 않거나, 덮인 구간을 놓치는 것.
    #[test]
    fn selection_table_and_unreachable() {
        let bands = [b(None, Some(99), Some(1)), b(None, Some(59), Some(2))];
        let o = order_bands(&bands).unwrap();
        let t = selection_table(&o, &bands);
        assert_eq!(t, [(0, 99, Some(0)), (100, u16::MAX, None)]);
        assert_eq!(unreachable(&o, &bands), [1]);
    }

    // 이것을 실패시키는 것: 한 칸짜리 구간(min == max)을 빈 구간으로 보는 것, 경계 한 칸이 겹치는 구간을 서로소로 보는 것.
    #[test]
    fn single_column_and_shared_edge() {
        let one = [b(Some(5), Some(5), None)];
        let o = order_bands(&one).unwrap();
        assert_eq!((select(&o, &one, 5), select(&o, &one, 6)), (Some(0), None));
        let touch = [b(Some(0), Some(50), None), b(Some(50), Some(100), None)];
        assert_eq!(order_bands(&touch), Err(BandError::NeedsOrder(0, 1)));
        let apart = [b(Some(0), Some(49), None), b(Some(50), Some(100), None)];
        assert!(order_bands(&apart).is_ok());
    }

    // 리뷰 #5. 이것을 실패시키는 것: `order`의 색인을 `bands[i]`로 읽어 길이가 어긋난 입력에서 패닉하는 것.
    #[test]
    fn mismatched_order_never_panics() {
        let all = [b(None, None, None)];
        assert_eq!(select(&[1], &[], 80), None);
        assert_eq!(select(&[5, 0], &all, 80), Some(0));
        assert_eq!(selection_table(&[3], &[]), alloc::vec![(0, u16::MAX, None)]);
        assert_eq!(unreachable(&[7], &all), alloc::vec![0]);
    }
}
