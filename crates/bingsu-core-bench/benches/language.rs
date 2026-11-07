//! Instruction counts of drawing the builtin language versions in the
//! prompt (M6 D3b): decoding a full command response (28 config entries of
//! 4 KB and the 4 builtin entries), and for each of the four languages the
//! entry lookup, this shell's environment digest over the language's
//! variables and the cut to the `version` field's cells.
use bingsu_core::{
    collection::wire::BuildId,
    command::{
        builtin::LANGUAGES,
        display::{self, Prompt},
        plan::Environ,
        response::{Binding, ENTRIES_MAX, Entry, Response, Status, VALUE_MAX},
    },
    field::Field,
    handoff::Origin,
    snapshot::{Clock, context_crc},
    width::WidthProfile,
};
use gungraun::prelude::*;
use std::hint::black_box;

struct Input {
    bytes: Vec<u8>,
    binding: Binding,
    environ: Vec<u8>,
}

fn clock() -> Clock {
    Clock {
        kind: 1,
        domain: [3; 16],
        resume: 4,
        boot: [1; 16],
        now: 1_000,
    }
}

/// A full response whose four builtin entries this prompt draws, after 28
/// config entries the lookup walks past.
fn full() -> Input {
    let (config, state) = (
        b"/home/u/.config/bingsu".to_vec(),
        b"/home/u/.local/state/bingsu".to_vec(),
    );
    let binding = Binding {
        build_id: BuildId([7; 32]),
        boot: [1; 16],
        epoch: [2; 16],
        context: context_crc(&config, &state).unwrap(),
        clock_kind: 1,
        domain: [3; 16],
        resume: 4,
        config,
        state,
        cwd: b"/home/u/repo".to_vec(),
    };
    // About 3 KB of shell environment, as an interactive shell carries, with
    // every language's variables set.
    let mut environ = Vec::new();
    for i in 0..48 {
        environ
            .extend_from_slice(format!("VAR_{i:02}=/usr/local/share/value/{i:040}\0").as_bytes());
    }
    environ.extend_from_slice(
        b"PATH=/usr/bin:/bin\0HOME=/home/u\0LC_ALL=C.UTF-8\0PYENV_ROOT=/home/u/.pyenv\0\
          PYENV_VERSION=3.12.1\0RUSTUP_HOME=/home/u/.rustup\0CARGO_HOME=/home/u/.cargo\0",
    );
    let vars = Environ::parse(&environ);
    let value: String = "x".repeat(VALUE_MAX);
    let mut entries = Vec::new();
    for i in 0..ENTRIES_MAX - LANGUAGES.len() {
        entries.push(Entry {
            origin: Origin::Config,
            id: format!("custom/k{i:02}"),
            policy: [1; 32],
            environment: [2; 32],
            pattern: [0; 32],
            attempted_at: 5,
            completed_at: 10,
            status: Status::Ok,
            value: value.clone(),
            raw: value.clone(),
        });
    }
    for l in &LANGUAGES {
        entries.push(Entry {
            origin: Origin::Builtin,
            id: l.id.into(),
            policy: [3; 32],
            environment: l.env_digest(&vars),
            pattern: [0; 32],
            attempted_at: 5,
            completed_at: 10,
            status: Status::Ok,
            value: "1.80.0-beta.3+build-2026".into(),
            raw: String::new(),
        });
    }
    let bytes = Response {
        binding: binding.clone(),
        entries,
    }
    .encode()
    .unwrap();
    Input {
        bytes,
        binding,
        environ,
    }
}

// The measured call sits behind an `#[inline(never)]` boundary (see text.rs).
#[inline(never)]
fn draw(input: &Input) -> Vec<Field> {
    let response = Response::decode_shown(&input.bytes).unwrap();
    let vars = Environ::parse(&input.environ);
    let prompt = Prompt::new(&response, &input.binding, clock(), &vars, true).unwrap();
    LANGUAGES
        .iter()
        .filter_map(|l| display::builtin_value(&prompt, l))
        .map(|v| Field::text(v.as_bytes(), 32, WidthProfile::DEFAULT))
        .collect()
}

#[library_benchmark]
#[bench::full(setup = full)]
fn language_render(input: Input) -> (Input, Vec<Field>) {
    let out = black_box(draw(black_box(&input)));
    assert_eq!(out.len(), LANGUAGES.len());
    (input, out)
}

library_benchmark_group!(name = language, benchmarks = [language_render]);

// main! defines `fn main` itself: wrapped in a fn of ours the bench would
// build, exit 0 and measure nothing.
main!(library_benchmark_groups = language);
