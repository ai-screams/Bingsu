//! Instruction counts of drawing env segments in the prompt (M6 C5): parsing
//! the environment frame body the prompt already holds (about 60 KiB), and
//! for 32 env segments looking up the variable, keeping the part the cut
//! reads and cutting it to the segment's cells.
use bingsu_core::{
    command::plan::{Environ, env_segment_value},
    field::{CUSTOM_TEXT_CELLS, Field},
    width::WidthProfile,
};
use gungraun::prelude::*;
use std::hint::black_box;

const SEGMENTS: usize = 32;

struct Input {
    environ: Vec<u8>,
    names: Vec<String>,
}

/// 32 shown variables of about 1.7 KB each (Hangul mixed in) among 64
/// others: about 60 KiB of environment, near the frame's cap.
fn full() -> Input {
    let value: String = "kube-\u{D55C}\u{AE00}-ctx/"
        .chars()
        .cycle()
        .take(1300)
        .collect();
    let mut environ = Vec::new();
    let mut names = Vec::new();
    for i in 0..SEGMENTS {
        let name = format!("SHOW_{i:02}");
        environ.extend_from_slice(format!("{name}=s{i:02}-{value}\0").as_bytes());
        names.push(name);
    }
    for i in 0..64 {
        environ
            .extend_from_slice(format!("VAR_{i:02}=/usr/local/share/value/{i:040}\0").as_bytes());
    }
    assert!(
        (55 * 1024..64 * 1024).contains(&environ.len()),
        "{}",
        environ.len()
    );
    Input { environ, names }
}

// The measured call sits behind an `#[inline(never)]` boundary (see text.rs).
#[inline(never)]
fn draw(input: &Input) -> Vec<Field> {
    let vars = Environ::parse(&input.environ);
    input
        .names
        .iter()
        .filter_map(|name| env_segment_value(&vars, name))
        .map(|v| Field::text(v.as_bytes(), CUSTOM_TEXT_CELLS, WidthProfile::DEFAULT))
        .collect()
}

#[library_benchmark]
#[bench::full(setup = full)]
fn env_segment_render(input: Input) -> (Input, Vec<Field>) {
    let out = black_box(draw(black_box(&input)));
    assert_eq!(out.len(), SEGMENTS);
    (input, out)
}

library_benchmark_group!(name = env_segment, benchmarks = [env_segment_render]);

// main! defines `fn main` itself: wrapped in a fn of ours the bench would
// build, exit 0 and measure nothing.
main!(library_benchmark_groups = env_segment);
