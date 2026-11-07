//! Instruction counts of a command segment's `match` in the refresh helper
//! (M6 C4c): for 32 units, checking each pattern (`Matcher::new`) and
//! applying it to the sanitized first line (`Matcher::value`). The helper is
//! a new process each round, so every unit compiles its pattern once; this
//! measures exactly that. The prompt runs no pattern.
use bingsu_match::Matcher;
use gungraun::prelude::*;
use std::hint::black_box;

const UNITS: usize = 32;
const LINE: usize = 4096;

/// Patterns of version and path outputs, a Unicode class, and three of
/// many alternatives or repeats (research 2026-11-03-m6-regex-options).
const PATTERNS: [&str; 9] = [
    r"([^/]+)$",
    r"(?P<value>[0-9]+\.[0-9]+\.[0-9]+)",
    r"go version go([^ ]+)",
    r"Python ([^ ]+)",
    r"^(?:[a-z]+ )?v?(?P<value>[0-9]+(?:\.[0-9]+){1,3}(?:-[A-Za-z0-9.]+)?)(?:\+[0-9A-Za-z.]+)?",
    r"(?P<value>\w+)",
    r"(a|aa)*b",
    r"([A-Za-z0-9_]+[ \t]?)*$",
    r"(a+)+$",
];

/// A line of `LINE` bytes for pattern `i` that makes it scan to the end:
/// repeated `a` with no `b` or a closing `!` for the repeats, mixed text
/// with no version for the rest.
fn line(i: usize) -> String {
    let fill: &str = match i {
        6 | 8 => "a",
        7 => "word ",
        _ => "kube-\u{D55C}\u{AE00}-ctx/",
    };
    let mut s = String::with_capacity(LINE);
    while s.len() + fill.len() < LINE {
        s.push_str(fill);
    }
    s.push('!');
    s
}

struct Input {
    patterns: Vec<&'static str>,
    lines: Vec<String>,
}

/// 32 units, patterns in turn, each on its 4 KB worst line.
fn worst() -> Input {
    let patterns: Vec<_> = (0..UNITS).map(|u| PATTERNS[u % PATTERNS.len()]).collect();
    let lines = (0..UNITS).map(|u| line(u % PATTERNS.len())).collect();
    Input { patterns, lines }
}

/// 32 units, patterns in turn, on a short version line.
fn short() -> Input {
    let patterns: Vec<_> = (0..UNITS).map(|u| PATTERNS[u % PATTERNS.len()]).collect();
    let lines = (0..UNITS)
        .map(|_| String::from("go version go1.23.1 darwin/arm64 Python 3.12.4"))
        .collect();
    Input { patterns, lines }
}

// The measured call sits behind an `#[inline(never)]` boundary (see text.rs).
#[inline(never)]
fn round(input: &Input) -> usize {
    input
        .patterns
        .iter()
        .zip(&input.lines)
        .map(|(p, l)| Matcher::new(p).expect("checked pattern").value(l).len())
        .sum()
}

#[library_benchmark]
#[bench::worst(setup = worst)]
#[bench::short(setup = short)]
fn command_match_round(input: Input) -> (Input, usize) {
    let n = black_box(round(black_box(&input)));
    (input, n)
}

library_benchmark_group!(name = command_match, benchmarks = [command_match_round]);

// main! defines `fn main` itself: wrapped in a fn of ours the bench would
// build, exit 0 and measure nothing.
main!(library_benchmark_groups = command_match);
