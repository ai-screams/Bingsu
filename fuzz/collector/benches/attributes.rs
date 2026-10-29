//! Parse cost of one 15 KB .gitattributes file in the collector.
//!
//! This is not the shipped collector binary: the collector's modules are
//! compiled here again, with cfg(collector_fuzz) from this crate's build.rs,
//! because the product exposes no parsing entry. Same source and gix pins,
//! but its own codegen, so the counts are for comparing a change with its
//! base tip, not a figure of the product.
//! The fuzz library is not linked: its tests/support/allocation.rs installs a
//! counting #[global_allocator], which would add instructions to every
//! allocation; this bench uses the system allocator like the product.
//! Cargo builds every bench target with cfg(test) (without the test
//! harness), so the Meter's test-only hooks are in the count too, as in an
//! ignored unit test, and the modules' test imports go unused.
//! The fixture is written by fixtures/make_attributes_15k.py.
#![cfg(unix)]
#![allow(dead_code, unsafe_code, unused_imports)]
#[path = "../../../crates/bingsu-collect/src/git/mod.rs"]
mod git;
#[cfg(target_os = "linux")]
#[path = "../../../crates/bingsu-collect/src/landlock.rs"]
mod landlock;
#[path = "../../../crates/bingsu-collect/src/meter.rs"]
mod meter;
#[path = "../../../crates/bingsu-collect/src/safe_read/mod.rs"]
mod safe_read;
#[path = "../../../crates/bingsu-collect/src/update_sink.rs"]
mod update_sink;

use git::io::policy::{PatternKind, Patterns};
use gungraun::prelude::*;
use meter::Meter;
use safe_read::ReadError;
use std::{
    hint::black_box,
    path::PathBuf,
    time::{Duration, Instant},
};

const ATTRIBUTES: &[u8] = include_bytes!("fixtures/attributes-15k.txt");

/// Everything but the parse is built here and dropped after it, outside the
/// measured function: the Meter, the empty matcher and the source label.
struct Input {
    patterns: Patterns,
    meter: Meter,
    source: PathBuf,
}

fn input() -> Input {
    Input {
        patterns: Patterns::default(),
        // Ample: a deadline hit would end the parse early and lower the count.
        meter: Meter::new(Instant::now() + Duration::from_secs(600)),
        source: PathBuf::from(".gitattributes"),
    }
}

#[inline(never)]
fn parse(input: &mut Input, bytes: &[u8]) -> Result<(), ReadError> {
    let source = std::mem::take(&mut input.source);
    input
        .patterns
        .fuzz_bytes(bytes, PatternKind::Attributes, source, &mut input.meter)
}

#[library_benchmark]
#[bench::file_15k(setup = input)]
fn attributes_parse(mut input: Input) -> Input {
    black_box(parse(&mut input, black_box(ATTRIBUTES))).unwrap();
    input
}

library_benchmark_group!(name = attributes; benchmarks = attributes_parse);
main!(library_benchmark_groups = attributes);
