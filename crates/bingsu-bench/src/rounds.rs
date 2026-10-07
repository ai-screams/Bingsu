//! Round order shared by the cost-matrix runners: rows take turns within
//! each round, in alternating direction.

/// Calls `step(round, row)` for every row in every round. Even rounds go
/// forward and odd rounds backward, so each pair of rounds puts a row at
/// mirrored positions and the position bias cancels out in pairs (the
/// middle row of an odd count stays in place; the reference harness
/// alternates the same way).
pub fn drive(rows: usize, rounds: usize, mut step: impl FnMut(usize, usize)) {
    for round in 0..rounds {
        if round % 2 == 0 {
            (0..rows).for_each(|i| step(round, i));
        } else {
            (0..rows).rev().for_each(|i| step(round, i));
        }
    }
}

#[cfg(test)]
mod tests {
    // 이것을 실패시키는 것: 홀수 회차의 역순을 빼는 것, 회차나 행을 빠뜨리는 것.
    #[test]
    fn rounds_alternate_direction_and_cover_every_row() {
        let mut calls = Vec::new();
        super::drive(3, 4, |round, i| calls.push((round, i)));
        assert_eq!(
            calls,
            [
                (0, 0),
                (0, 1),
                (0, 2),
                (1, 2),
                (1, 1),
                (1, 0),
                (2, 0),
                (2, 1),
                (2, 2),
                (3, 2),
                (3, 1),
                (3, 0)
            ]
        );
    }
}
