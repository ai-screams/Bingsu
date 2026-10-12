//! Instruction counts of the core paths the M2 gate covers (spec section 8
//! "측정과 게이트", section 9 M2 row). This file starts with sanitize, width
//! and field formatting; the color, shortener, layout and render tasks add
//! their benches to the same group.
use bingsu_core::field::{Field, FieldValue};
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

#[library_benchmark]
#[bench::kib(args = [1024], setup = mixed)]
fn sanitize_bytes(input: Vec<u8>) -> String {
    black_box(sanitize(black_box(&input)))
}

#[library_benchmark]
#[bench::kib(args = [1024], setup = mixed_text)]
fn width_of_text(input: String) -> u32 {
    black_box(str_width(black_box(&input), WidthProfile::DEFAULT))
}

fn fields(_: u32) -> Vec<Field> {
    vec![
        Field::known(FieldValue::Count {
            n: 1234,
            saturated: true,
        }),
        Field::known(FieldValue::Duration { ms: 3_723_000 }),
        Field::known(FieldValue::Int(-130)),
        Field::text(b"feature/very-long-branch-name", 24, WidthProfile::DEFAULT),
    ]
}

#[library_benchmark]
#[bench::four(args = [4], setup = fields)]
fn field_format(input: Vec<Field>) -> String {
    let mut s = String::new();
    for f in black_box(&input) {
        f.write_to(&mut s);
    }
    black_box(s)
}

library_benchmark_group!(
    name = core_m2,
    benchmarks = [sanitize_bytes, width_of_text, field_format]
);

fn main() {
    main!(library_benchmark_groups = core_m2);
}
