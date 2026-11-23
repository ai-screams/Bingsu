//! Instruction counts of the setup editor's shaved-ice opening: one frame
//! (80 columns, mid-build with snow, and the end frame) and the scene's
//! points, made once per editor. Each bench group is its own bench target,
//! so the code generation of one binary does not depend on the benches of
//! another.
use bingsu_core::color::palette::Mode;
use bingsu_core::opening::{Band, Bowl, Inks, LENGTH};
use gungraun::prelude::*;
use std::hint::black_box;
use std::time::Duration;

fn scene(ms: u64) -> (Bowl, Inks, Duration) {
    let time = if ms == u64::MAX {
        LENGTH
    } else {
        Duration::from_millis(ms)
    };
    (Bowl::new(), Inks::of(Mode::Dark), time)
}

// The measured calls sit behind `#[inline(never)]` (CLAUDE.md: inlined into
// the bench wrapper, Callgrind on aarch64 undercounts it).
#[inline(never)]
fn frame(bowl: &Bowl, inks: &Inks, time: Duration) -> Band {
    bowl.draw(time, 80, inks)
}

#[inline(never)]
fn points() -> Bowl {
    Bowl::new()
}

#[library_benchmark]
#[bench::build_2s(args = [2000], setup = scene)]
#[bench::end(args = [u64::MAX], setup = scene)]
fn opening_frame((bowl, inks, time): (Bowl, Inks, Duration)) -> ((Bowl, Inks), Band) {
    let band = black_box(frame(black_box(&bowl), black_box(&inks), black_box(time)));
    // Returned, so the scene and the band are freed outside the counted code.
    ((bowl, inks), band)
}

#[library_benchmark]
fn opening_points() -> Bowl {
    black_box(points())
}

library_benchmark_group!(
    name = setup_opening,
    benchmarks = [opening_frame, opening_points]
);

main!(library_benchmark_groups = setup_opening);
