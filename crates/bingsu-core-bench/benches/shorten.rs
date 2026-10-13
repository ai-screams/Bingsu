//! Instruction counts of the path shortener (spec section 8 "측정과 게이트",
//! section 9 M2 row). Each bench group is its own bench target, so the code
//! generation of one binary does not depend on the benches of another.
use bingsu_core::shorten::{Anchor, Method, PathFacts, ShortenResult, Source, shorten};
use bingsu_core::width::WidthProfile;
use gungraun::prelude::*;
use std::hint::black_box;

fn deep_path(steps: usize) -> PathFacts {
    let names: Vec<String> = (0..steps).map(|i| format!("folder-{i}")).collect();
    let raw: Vec<&[u8]> = names.iter().map(|s| s.as_bytes()).collect();
    PathFacts::new(Anchor::Home, &raw, Some(steps / 2), &[])
}

// The measured call sits behind an `#[inline(never)]` boundary. Inlined
// into the bench wrapper (fat LTO), Callgrind on aarch64 left part of the
// work out of the count (path_facts_new read 1,296 instead of about 6
// million); x86_64 counted it either way.
#[inline(never)]
fn shorten_call(facts: &PathFacts) -> Option<(ShortenResult, usize, u32)> {
    let m = [Method::Repo, Method::Abbrev(1), Method::Depth(2)];
    shorten(Source::Path(facts), &m, 40, WidthProfile::DEFAULT)
}

// Validation cost of shortener results (M2 row): every built-in result is
// checked by `validate` inside `shorten`. Input and result are returned so
// they drop outside the counted code (the runner collects within
// `__gungraun_wrapper_mod::*`).
#[library_benchmark]
#[bench::steps_32(args = [32], setup = deep_path)]
fn shorten_validate(facts: PathFacts) -> (PathFacts, Option<(ShortenResult, usize, u32)>) {
    let r = black_box(shorten_call(black_box(&facts)));
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

#[inline(never)]
fn facts_call(input: &FactsInput) -> PathFacts {
    let steps: Vec<&[u8]> = input.steps.iter().map(Vec::as_slice).collect();
    let lists: Vec<Vec<&[u8]>> = input
        .siblings
        .iter()
        .map(|l| l.iter().map(Vec::as_slice).collect())
        .collect();
    let siblings: Vec<Option<&[&[u8]]>> = lists.iter().map(|l| Some(l.as_slice())).collect();
    PathFacts::new(
        Anchor::Home,
        black_box(&steps),
        Some(1),
        black_box(&siblings),
    )
}

#[library_benchmark]
#[bench::capped(args = [0], setup = facts_input)]
fn path_facts_new(input: FactsInput) -> (FactsInput, PathFacts) {
    let f = black_box(facts_call(black_box(&input)));
    (input, f)
}

library_benchmark_group!(
    name = core_m2,
    benchmarks = [shorten_validate, path_facts_new]
);

// main! defines `fn main` itself: wrapped in a fn of ours the bench would
// build, exit 0 and measure nothing.
main!(library_benchmark_groups = core_m2);
