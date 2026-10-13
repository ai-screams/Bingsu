//! Instruction counts of one whole render (spec section 8 "측정과 게이트",
//! section 9 M2 row): layout, transient line, vi symbols and shell output.
//! Each bench group is its own bench target, so the code generation of one
//! binary does not depend on the benches of another.
use bingsu_core::color::palette::{Knobs, Mode, PaletteInput, ResolvedPalette, resolve_palette};
use bingsu_core::color::sgr::ColorDepth;
use bingsu_core::field::{BUILTIN, Field, Value, segment};
use bingsu_core::icons::IconSet;
use bingsu_core::layout::{Inputs, Options, SegmentSetup, When};
use bingsu_core::recorder::NoopRecorder;
use bingsu_core::render::{RenderedPrompt, Target, Theme, render_prompt};
use bingsu_core::shell_word::Shell;
use bingsu_core::shorten::{Anchor, Method, PathFacts};
use bingsu_core::style::{LineLayout, StyleOptions, generate, preset};
use bingsu_core::template::compile::{CompiledLine, compile};
use bingsu_core::width::WidthProfile;
use gungraun::prelude::*;
use std::hint::black_box;

struct RenderCase {
    lines: Vec<CompiledLine>,
    transient: CompiledLine,
    palette: ResolvedPalette,
    values: Vec<Option<Value>>,
    facts: Vec<Option<PathFacts>>,
    setup: Vec<SegmentSetup<'static>>,
}

// Everything the render reads is made here: the palette, the compiled
// lines and the inputs. Only `render_prompt` runs in the counted code.
fn render_case(_: u32) -> RenderCase {
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
    RenderCase {
        lines: compile(&t, BUILTIN).expect("template"),
        transient: compile("{char}", BUILTIN).expect("transient").remove(0),
        palette: resolve_palette(&PaletteInput {
            mode: Mode::Dark,
            knobs: Knobs::default(),
            overrides: &[],
            roles: &[],
        })
        .expect("palette"),
        values,
        facts,
        setup,
    }
}

// The measured call sits behind an `#[inline(never)]` boundary, input
// processing included, so fat LTO cannot fold it into the bench wrapper
// (Callgrind on aarch64 then leaves part of the work out of the count).
#[inline(never)]
fn render_call(case: &RenderCase, shell: Shell, width: u16) -> RenderedPrompt {
    let inputs = Inputs {
        catalog: BUILTIN,
        values: &case.values,
        facts: &case.facts,
        setup: &case.setup,
    };
    let theme = Theme {
        variants: std::slice::from_ref(&case.lines),
        bands: &[],
        band_order: &[],
        transient: &case.transient,
        vi: &case.transient,
        palette: &case.palette,
    };
    let t = Target {
        shell,
        depth: ColorDepth::TrueColor,
        options: Options {
            width,
            profile: WidthProfile::DEFAULT,
            icons: IconSet::Nerd,
            use_last_column: false,
        },
    };
    render_prompt(&theme, &inputs, &t, &mut NoopRecorder)
}

// Whole two-line triangle render at 80 columns. The fields are allocated
// inside the counted code (they are the output); input and output are
// returned so they drop outside it.
#[library_benchmark]
#[bench::zsh(args = [0], setup = render_case)]
fn render_zsh(case: RenderCase) -> (RenderCase, RenderedPrompt) {
    let r = render_call(black_box(&case), black_box(Shell::Zsh), black_box(80));
    (case, r)
}

#[library_benchmark]
#[bench::bash(args = [0], setup = render_case)]
fn render_bash(case: RenderCase) -> (RenderCase, RenderedPrompt) {
    let r = render_call(black_box(&case), black_box(Shell::Bash), black_box(80));
    (case, r)
}

library_benchmark_group!(name = core_m2, benchmarks = [render_zsh, render_bash]);

// main! defines `fn main` itself: wrapped in a fn of ours the bench would
// build, exit 0 and measure nothing.
main!(library_benchmark_groups = core_m2);
