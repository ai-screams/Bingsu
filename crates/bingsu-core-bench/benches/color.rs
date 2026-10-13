//! Instruction counts of color notation and palette resolution (spec section
//! 8 "측정과 게이트", section 9 M2 row). Each bench group is its own bench
//! target, so the code generation of one binary does not depend on the
//! benches of another.
use bingsu_core::color::notation::parse_color;
use bingsu_core::color::palette::{
    Knobs, Mode, PaletteError, PaletteInput, ResolvedPalette, resolve_palette,
};
use gungraun::prelude::*;
use std::hint::black_box;

// Only the code inside the benchmark function is counted (the runner
// collects within `__gungraun_wrapper_mod::*`). An owned input would be
// dropped, and freed, at the end of that function, so each bench returns
// its input: the caller drops the returned value outside the counted code.
fn specs(_: u32) -> Vec<String> {
    ["oklch(0.78 0.12 60)", "#8fb8f0", "208", "term.ansi.12"]
        .map(String::from)
        .to_vec()
}

#[library_benchmark]
#[bench::four(args = [4], setup = specs)]
fn color_notation(input: Vec<String>) -> (Vec<String>, usize) {
    let ok = black_box(&input)
        .iter()
        .filter(|s| parse_color(black_box(s)).is_ok())
        .count();
    (input, black_box(ok))
}

fn palette_input(_: u32) -> (Mode, Knobs) {
    (Mode::Dark, Knobs::default())
}

#[library_benchmark]
#[bench::dark(args = [0], setup = palette_input)]
fn palette_resolve(input: (Mode, Knobs)) -> ((Mode, Knobs), Result<ResolvedPalette, PaletteError>) {
    let p = black_box(resolve_palette(&PaletteInput {
        mode: input.0,
        knobs: input.1,
        overrides: &[],
        roles: &[],
    }));
    // Returned, so the palette is freed outside the counted code.
    (input, p)
}

library_benchmark_group!(
    name = core_m2,
    benchmarks = [color_notation, palette_resolve]
);

// main! defines `fn main` itself: wrapped in a fn of ours the bench would
// build, exit 0 and measure nothing.
main!(library_benchmark_groups = core_m2);
