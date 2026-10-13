//! Instruction counts of line layout (spec section 8 "측정과 게이트", section
//! 9 M2 row). Each bench group is its own bench target, so the code
//! generation of one binary does not depend on the benches of another.
use bingsu_core::field::{BUILTIN, Field, Value, segment};
use bingsu_core::icons::IconSet;
use bingsu_core::layout::{Inputs, LaidLine, Options, SegmentSetup, When, layout_into};
use bingsu_core::recorder::NoopRecorder;
use bingsu_core::shorten::{Anchor, Method, PathFacts};
use bingsu_core::style::{LineLayout, StyleOptions, generate, preset};
use bingsu_core::template::compile::{CompiledLine, compile};
use bingsu_core::width::WidthProfile;
use gungraun::prelude::*;
use std::hint::black_box;

struct LayoutCase {
    lines: Vec<CompiledLine>,
    values: Vec<Option<Value>>,
    facts: Vec<Option<PathFacts>>,
    setup: Vec<SegmentSetup<'static>>,
}

fn layout_inputs(case: &LayoutCase) -> Inputs<'_> {
    Inputs {
        catalog: BUILTIN,
        values: &case.values,
        facts: &case.facts,
        setup: &case.setup,
    }
}

fn layout_options(width: u16) -> Options {
    Options {
        width,
        profile: WidthProfile::DEFAULT,
        icons: IconSet::Nerd,
        use_last_column: false,
    }
}

// The output lines are laid out once here, so the counted call writes into
// run buffers that already have their size and never grows a String or a
// Vec of its own (benches/field.rs says why the growth path is kept out).
fn layout_case(width: u32) -> (LayoutCase, Vec<LaidLine>) {
    let i = |id: &str| BUILTIN.iter().position(|d| d.id == id).unwrap_or(0);
    let v = |id: &str, text: &[u8]| {
        segment(id).map(|d| Value::new(text, vec![Field::ABSENT; d.fields.len()]))
    };
    let mut values = vec![None; BUILTIN.len()];
    let mut facts = vec![None; BUILTIN.len()];
    let mut setup = vec![
        SegmentSetup {
            priority: 10,
            required: false,
            methods: &[],
            when: When::Needed
        };
        BUILTIN.len()
    ];
    values[i("char")] = v("char", b"");
    values[i("dir")] = v("dir", b"");
    let steps: [&[u8]; 5] = [b"Works", b"AiScream", b"themes", b"src", b"render"];
    facts[i("dir")] = Some(PathFacts::new(Anchor::Home, &steps, Some(2), &[]));
    values[i("git")] = v("git", b"feature/very-long-branch-name");
    values[i("time")] = v("time", b"12:34");
    setup[i("char")].required = true;
    setup[i("dir")] = SegmentSetup {
        priority: 100,
        required: true,
        methods: &[Method::Repo, Method::Abbrev(1), Method::Depth(1)],
        when: When::Needed,
    };
    let t = generate(
        preset("triangle").expect("preset"),
        &StyleOptions::default(),
        &[
            LineLayout {
                left: &["dir", "git"],
                right: &["time"],
            },
            LineLayout {
                left: &["char"],
                right: &[],
            },
        ],
    )
    .expect("template");
    let case = LayoutCase {
        lines: compile(&t, BUILTIN).expect("template"),
        values,
        facts,
        setup,
    };
    let mut out = Vec::new();
    let width = u16::try_from(width).unwrap_or(u16::MAX);
    layout_into(
        std::slice::from_ref(&case.lines),
        &[],
        &[],
        &layout_inputs(&case),
        &layout_options(width),
        &mut NoopRecorder,
        &mut out,
    );
    (case, out)
}

// The measured call sits behind an `#[inline(never)]` boundary, input
// processing included, so fat LTO cannot fold it into the bench wrapper
// (Callgrind on aarch64 then leaves part of the work out of the count).
#[inline(never)]
fn layout_call(case: &LayoutCase, width: u16, out: &mut Vec<LaidLine>) {
    layout_into(
        std::slice::from_ref(&case.lines),
        &[],
        &[],
        &layout_inputs(case),
        &layout_options(width),
        &mut NoopRecorder,
        out,
    );
}

// Two-line triangle layout at 40 columns: steps 1–4 run (the path is
// shortened, the time hidden, the branch cut). The shortener's own results
// are allocated inside the counted code; layout's buffers are not grown.
// Input and output are returned so they drop outside the counted code.
#[library_benchmark]
#[bench::narrow(args = [40], setup = layout_case)]
fn layout_two_lines((case, mut out): (LayoutCase, Vec<LaidLine>)) -> (LayoutCase, Vec<LaidLine>) {
    layout_call(black_box(&case), black_box(40), &mut out);
    (case, out)
}

library_benchmark_group!(name = core_m2, benchmarks = [layout_two_lines]);

// main! defines `fn main` itself: wrapped in a fn of ours the bench would
// build, exit 0 and measure nothing.
main!(library_benchmark_groups = core_m2);
