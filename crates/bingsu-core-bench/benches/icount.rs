//! Instruction counts of the core paths the M2 gate covers (spec section 8
//! "측정과 게이트", section 9 M2 row). This file starts with sanitize, width
//! and field formatting; the color, shortener, layout and render tasks add
//! their benches to the same group.
use bingsu_core::color::notation::parse_color;
use bingsu_core::color::palette::{
    Knobs, Mode, PaletteError, PaletteInput, ResolvedPalette, resolve_palette,
};
use bingsu_core::field::{Field, FieldValue};
use bingsu_core::sanitize::sanitize;
use bingsu_core::shorten::{Anchor, Method, PathFacts, ShortenResult, Source, shorten};
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
#[library_benchmark]
#[bench::kib(args = [1024], setup = mixed)]
fn sanitize_bytes(input: Vec<u8>) -> (Vec<u8>, String) {
    let out = black_box(sanitize(black_box(&input)));
    (input, out)
}

#[library_benchmark]
#[bench::kib(args = [1024], setup = mixed_text)]
fn width_of_text(input: String) -> (String, u32) {
    let w = black_box(str_width(black_box(&input), WidthProfile::DEFAULT));
    (input, w)
}

// The output buffer is reserved here, so the counted code formats without
// growing a String: the growth path (`RawVec::finish_grow`) is shared with
// every other bench in this binary and its inlining changes when a bench is
// added, which moved this count by 3.5% with no change in core.
fn fields(_: u32) -> (Vec<Field>, String) {
    let fields = vec![
        Field::known(FieldValue::Count {
            n: 1234,
            saturated: true,
        }),
        Field::known(FieldValue::Duration { ms: 3_723_000 }),
        Field::known(FieldValue::Int(-130)),
        Field::text(b"feature/very-long-branch-name", 24, WidthProfile::DEFAULT),
    ];
    (fields, String::with_capacity(256))
}

#[library_benchmark]
#[bench::four(args = [4], setup = fields)]
fn field_format((input, mut s): (Vec<Field>, String)) -> (Vec<Field>, String) {
    for f in black_box(&input) {
        f.write_to(&mut s);
    }
    (input, black_box(s))
}

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

fn deep_path(steps: usize) -> PathFacts {
    let names: Vec<String> = (0..steps).map(|i| format!("folder-{i}")).collect();
    let raw: Vec<&[u8]> = names.iter().map(|s| s.as_bytes()).collect();
    PathFacts::new(Anchor::Home, &raw, Some(steps / 2), &[])
}

// Validation cost of shortener results (M2 row): every built-in result is
// checked by `validate` inside `shorten`. Input and result are returned so
// they drop outside the counted code.
#[library_benchmark]
#[bench::steps_32(args = [32], setup = deep_path)]
fn shorten_validate(facts: PathFacts) -> (PathFacts, Option<(ShortenResult, usize, u32)>) {
    let m = [Method::Repo, Method::Abbrev(1), Method::Depth(2)];
    let r = black_box(shorten(
        Source::Path(black_box(&facts)),
        &m,
        40,
        WidthProfile::DEFAULT,
    ));
    (facts, r)
}

// Near worst case for `PathFacts::new` with `unique`: sibling lists at the
// raw caps (1 KiB names, 8 KiB per step, 16 KiB per path), names that
// sanitizing removes entirely, names sharing a long prefix with the step, a
// spent path budget with 256 more entries, and a name over the 1 KiB cap.
// The input is raw bytes made in setup; `new` runs inside the counted code.
struct FactsInput {
    steps: Vec<Vec<u8>>,
    siblings: Vec<Vec<Vec<u8>>>,
}

fn facts_input(_: u32) -> FactsInput {
    let shared = |n: usize| {
        let mut v = vec![b'a'; n];
        v[n - 1] = b'b';
        v
    };
    let steps: Vec<Vec<u8>> = vec![
        vec![b'a'; 1024],
        vec![b'a'; 1024],
        vec![b'a'; 1024],
        vec![b'a'; 64],
        b"last".to_vec(),
    ];
    let siblings = vec![
        (0..8).map(|_| vec![0x1b; 1024]).collect(),
        (0..8).map(|_| shared(1024)).collect(),
        (0..256).map(|_| shared(8)).collect(),
        vec![shared(1025)],
        Vec::new(),
    ];
    FactsInput { steps, siblings }
}

#[library_benchmark]
#[bench::capped(args = [0], setup = facts_input)]
fn path_facts_new(input: FactsInput) -> (FactsInput, PathFacts) {
    let steps: Vec<&[u8]> = input.steps.iter().map(Vec::as_slice).collect();
    let lists: Vec<Vec<&[u8]>> = input
        .siblings
        .iter()
        .map(|l| l.iter().map(Vec::as_slice).collect())
        .collect();
    let siblings: Vec<Option<&[&[u8]]>> = lists.iter().map(|l| Some(l.as_slice())).collect();
    let f = black_box(PathFacts::new(
        Anchor::Home,
        black_box(&steps),
        Some(1),
        black_box(&siblings),
    ));
    (input, f)
}

library_benchmark_group!(
    name = core_m2,
    benchmarks = [
        sanitize_bytes,
        width_of_text,
        field_format,
        color_notation,
        palette_resolve,
        shorten_validate,
        path_facts_new
    ]
);

// main! defines `fn main` itself: wrapped in a fn of ours the bench would
// build, exit 0 and measure nothing.
main!(library_benchmark_groups = core_m2);
