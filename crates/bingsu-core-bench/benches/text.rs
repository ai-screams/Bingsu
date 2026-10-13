//! Instruction counts of sanitize and width (spec section 8 "측정과 게이트",
//! section 9 M2 row). Each bench group is its own bench target, so the code
//! generation of one binary does not depend on the benches of another.
use bingsu_core::sanitize::sanitize;
use bingsu_core::width::{WidthProfile, str_width};
use gungraun::prelude::*;
use std::hint::black_box;

/// Mixed text: ASCII, Hangul, an emoji ZWJ sequence, an ESC.
fn mixed(len: usize) -> Vec<u8> {
    let unit = "src/\u{D55C}\u{AE00}-\u{1F3F3}\u{FE0F}\u{200D}\u{1F308}\u{1b}[31m%!".as_bytes();
    unit.iter().copied().cycle().take(len).collect()
}

fn mixed_text(len: usize) -> String {
    sanitize(&mixed(len))
}

// Only the code inside the benchmark function is counted (the runner
// collects within `__gungraun_wrapper_mod::*`). An owned input would be
// dropped, and freed, at the end of that function, so each bench returns
// its input: the caller drops the returned value outside the counted code.
// The measured call sits behind an `#[inline(never)]` boundary. Inlined
// into the bench wrapper (fat LTO), Callgrind on aarch64 left part of the
// work out of the count (path_facts_new read 1,296 instead of about 6
// million); x86_64 counted it either way.
#[inline(never)]
fn sanitize_call(input: &[u8]) -> String {
    sanitize(input)
}

#[inline(never)]
fn width_call(input: &str) -> u32 {
    str_width(input, WidthProfile::DEFAULT)
}

#[library_benchmark]
#[bench::kib(args = [1024], setup = mixed)]
fn sanitize_bytes(input: Vec<u8>) -> (Vec<u8>, String) {
    let out = black_box(sanitize_call(black_box(&input)));
    (input, out)
}

#[library_benchmark]
#[bench::kib(args = [1024], setup = mixed_text)]
fn width_of_text(input: String) -> (String, u32) {
    let w = black_box(width_call(black_box(&input)));
    (input, w)
}

library_benchmark_group!(name = core_m2, benchmarks = [sanitize_bytes, width_of_text]);

// main! defines `fn main` itself: wrapped in a fn of ours the bench would
// build, exit 0 and measure nothing.
main!(library_benchmark_groups = core_m2);
