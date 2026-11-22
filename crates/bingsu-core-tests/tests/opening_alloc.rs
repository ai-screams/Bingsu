//! A frame of the opening allocates its band and nothing else: the
//! accumulators live on the stack, bounded by the widest band. Its own
//! test binary; counters are thread-local, so harness and other-test
//! allocations are excluded.
use bingsu_core::color::palette::Mode;
use bingsu_core::opening::{Bowl, Cell, Inks, LENGTH, MAX_COLS, ROWS};
use core::time::Duration;
#[path = "support/allocation.rs"]
mod allocation;
use allocation::{Counting, counted};

#[global_allocator]
static GLOBAL: Counting = Counting;

// 이것을 실패시키는 것: 프레임마다 띠 말고 다른 것(누적 버퍼, 열마다의 얼음 높이)을 힙에 잡는 것, 띠를 자라게 하는 것.
#[test]
fn a_frame_allocates_only_its_band() {
    let bowl = Bowl::new();
    let inks = Inks::of(Mode::Dark);
    for cols in [1, 40, 80, MAX_COLS] {
        for time in [Duration::ZERO, Duration::from_millis(2000), LENGTH] {
            let mut band = None;
            let (allocs, reallocs, peak) = counted(|| band = Some(bowl.draw(time, cols, &inks)));
            let cells = usize::from(cols) * usize::from(ROWS);
            assert_eq!((allocs, reallocs), (1, 0), "{cols} columns at {time:?}");
            assert_eq!(
                peak,
                cells * size_of::<Cell>(),
                "{cols} columns at {time:?}"
            );
            drop(band);
        }
    }
}
