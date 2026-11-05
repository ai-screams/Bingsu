//! Parse cost of the language version selection files (D1) as the worker
//! parses them: extraction and grammar for each built-in format, plus a
//! `go.mod` at its 16 KiB cap with the toolchain line last.
//!
//! The parser is bingsu-core's (`collection::language`), which the worker
//! calls on the bytes it read; this crate compiles nothing of the worker for
//! it. The counts are for comparing a change with its base tip.
#![cfg(unix)]
use bingsu_core::collection::language::{Format, version};
use gungraun::prelude::*;
use std::hint::black_box;

struct Input {
    files: Vec<(Format, Vec<u8>)>,
}

fn input() -> Input {
    let mut go = b"module example.com/m\n\ngo 1.21\n\nrequire (\n".to_vec();
    while go.len() < 16_300 {
        go.extend_from_slice(b"\texample.com/dependency v1.2.3 // indirect\n");
    }
    go.extend_from_slice(b")\ntoolchain go1.22.1\n");
    go.truncate(16_384);
    Input {
        files: vec![
            (Format::Line, b"3.12.1\n".to_vec()),
            (Format::Line, b"# comment\n\n  lts/iron \n".to_vec()),
            (
                Format::ToolVersions(b"python".to_vec()),
                b"nodejs 20.11.0\nrust 1.80.0\npython 3.12.1 3.11.9\n".to_vec(),
            ),
            (
                Format::RustToolchainToml,
                b"[toolchain]\nchannel = \"1.80.0\"\ncomponents = [\"rustfmt\"]\n".to_vec(),
            ),
            (Format::GoMod, go),
        ],
    }
}

#[inline(never)]
fn parse(input: &Input) -> usize {
    input
        .files
        .iter()
        .map(|(format, bytes)| black_box(version(format, black_box(bytes), 0, 0)))
        .filter(|v| matches!(v, bingsu_core::collection::language::Version::Found { .. }))
        .count()
}

#[library_benchmark]
#[bench::builtin_formats(setup = input)]
fn language_parse(input: Input) -> Input {
    black_box(parse(&input));
    input
}

library_benchmark_group!(name = language; benchmarks = language_parse);
main!(library_benchmark_groups = language);
