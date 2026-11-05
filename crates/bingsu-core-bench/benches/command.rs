//! Instruction counts of drawing command values in the prompt (M6 C4b):
//! decoding a full command response (32 entries, 4 KB value and 4 KB first
//! line each), deciding each unit's value against this prompt's binding,
//! clock and environment digest, and cutting it to the segment's cells.
//! The helper's `match` work is not here (it is not on the prompt path).
use bingsu_core::{
    collection::wire::BuildId,
    command::{
        display::{self, Prompt},
        plan::{self, Environ},
        response::{Binding, ENTRIES_MAX, Entry, Response, Status, VALUE_MAX},
        wire::policy_digest,
    },
    config::compile::{ExecPolicy, ExecUnit},
    field::{CUSTOM_TEXT_CELLS, Field},
    handoff::Origin,
    snapshot::{Clock, context_crc},
    width::WidthProfile,
};
use gungraun::prelude::*;
use std::hint::black_box;

struct Input {
    bytes: Vec<u8>,
    binding: Binding,
    units: Vec<ExecUnit>,
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

/// A full response every unit of which this prompt may draw.
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
    // About 3 KB of shell environment, as an interactive shell carries.
    let mut environ = Vec::new();
    for i in 0..48 {
        environ
            .extend_from_slice(format!("VAR_{i:02}=/usr/local/share/value/{i:040}\0").as_bytes());
    }
    environ.extend_from_slice(
        b"PATH=/usr/bin:/bin\0KUBECONFIG=/home/u/.kube/config\0LC_ALL=C.UTF-8\0",
    );
    let vars = Environ::parse(&environ);
    let value: String = "kube-\u{D55C}\u{AE00}-ctx/"
        .chars()
        .cycle()
        .take(VALUE_MAX / 2)
        .collect();
    let mut value = value;
    while value.len() > VALUE_MAX {
        value.pop();
    }
    let mut units = Vec::new();
    let mut entries = Vec::new();
    for i in 0..ENTRIES_MAX {
        let unit = ExecUnit {
            id: format!("custom/k{i:02}"),
            policy: ExecPolicy::Command {
                argv: vec!["kubectx".into(), format!("--n={i}")],
                cwd: None,
                env_allow: vec!["KUBECONFIG".into()],
                shell: None,
                unsafe_shell: false,
            },
            timeout_ms: None,
            cache_ms: None,
            origins: Vec::new(),
            approved_by: Vec::new(),
            shown_at: Vec::new(),
            not_run: None,
        };
        let r = plan::runnable(&unit).unwrap();
        entries.push(Entry {
            origin: Origin::Config,
            id: unit.id.clone(),
            policy: policy_digest(&r.policy, r.cwd, r.timeout, &r.env_allow),
            environment: plan::env_digest(&vars, &r.env_allow),
            pattern: [0; 32],
            attempted_at: 5,
            completed_at: 10,
            status: Status::Ok,
            value: value.clone(),
            raw: value.clone(),
        });
        units.push(unit);
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
        units,
        environ,
    }
}

// The measured call sits behind an `#[inline(never)]` boundary (see text.rs).
#[inline(never)]
fn draw(input: &Input) -> Vec<Field> {
    let response = Response::decode_shown(&input.bytes).unwrap();
    let vars = Environ::parse(&input.environ);
    let mut prompt = Prompt::new(&input.binding, clock(), &vars, true);
    input
        .units
        .iter()
        .filter_map(|u| display::value(&response, &mut prompt, u, Origin::Config))
        .map(|v| Field::text(v.as_bytes(), CUSTOM_TEXT_CELLS, WidthProfile::DEFAULT))
        .collect()
}

#[library_benchmark]
#[bench::full(setup = full)]
fn command_render(input: Input) -> (Input, Vec<Field>) {
    let out = black_box(draw(black_box(&input)));
    assert_eq!(out.len(), ENTRIES_MAX);
    (input, out)
}

library_benchmark_group!(name = command, benchmarks = [command_render]);

// main! defines `fn main` itself: wrapped in a fn of ours the bench would
// build, exit 0 and measure nothing.
main!(library_benchmark_groups = command);
