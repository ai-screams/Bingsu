//! Instruction counts of the vi command mode lines (spec section 3, U-2 V1):
//! the second layout and field writing a prompt pays on top of `render_prompt`.
//! Each bench group is its own bench target, so the code generation of one
//! binary does not depend on the benches of another.
use bingsu_core::color::palette::{Knobs, Mode, PaletteInput, ResolvedPalette, resolve_palette};
use bingsu_core::color::sgr::ColorDepth;
use bingsu_core::field::{BUILTIN, Value};
use bingsu_core::icons::IconSet;
use bingsu_core::layout::{Inputs, Options, SegmentSetup, When};
use bingsu_core::recorder::NoopRecorder;
use bingsu_core::render::{
    RenderedPrompt, Target, Theme, ViInputs, ViVariants, render_prompt, render_vi_variants,
};
use bingsu_core::shell_word::Shell;
use bingsu_core::shorten::{Anchor, Method, PathFacts};
use bingsu_core::style::{LineLayout, StyleOptions, generate, preset};
use bingsu_core::template::compile::{CompiledLine, compile};
use bingsu_core::width::WidthProfile;
use gungraun::prelude::*;
use std::hint::black_box;

#[path = "support/catalog.rs"]
mod catalog;

struct RenderCase {
    lines: Vec<CompiledLine>,
    transient: CompiledLine,
    main: RenderedPrompt,
    palette: ResolvedPalette,
    values: Vec<Option<Value>>,
    facts: Vec<Option<PathFacts>>,
    setup: Vec<SegmentSetup<'static>>,
}

// Everything the render reads is made here: the palette, the compiled
// lines, the inputs and the main fields. Only `render_vi_variants` runs in the
// counted code.
fn render_case(input_left: &'static [&'static str]) -> (RenderCase, Vec<Option<Value>>) {
    let i = catalog::index;
    let v = catalog::value;
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
                left: input_left,
                right: &[],
            },
        ],
    )
    .expect("template");
    let mut case = RenderCase {
        lines: compile(&t, BUILTIN).expect("template"),
        transient: compile("{char}", BUILTIN).expect("transient").remove(0),
        main: RenderedPrompt::default(),
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
    };
    let (theme_inputs, target) = (inputs(&case), target(Shell::Zsh, 80));
    let main = render_prompt(&theme(&case), &theme_inputs, &target, &mut NoopRecorder);
    case.main = main;
    let values = case.values.clone();
    (case, values)
}

fn inputs(case: &RenderCase) -> Inputs<'_> {
    Inputs {
        catalog: BUILTIN,
        values: &case.values,
        facts: &case.facts,
        setup: &case.setup,
    }
}

fn theme(case: &RenderCase) -> Theme<'_> {
    Theme {
        variants: std::slice::from_ref(&case.lines),
        bands: &[],
        band_order: &[],
        transient: &case.transient,
        vi: &case.transient,
        palette: &case.palette,
    }
}

fn target(shell: Shell, width: u16) -> Target {
    Target {
        shell,
        depth: ColorDepth::TrueColor,
        options: Options {
            width,
            profile: WidthProfile::DEFAULT,
            icons: IconSet::Nerd,
            use_last_column: false,
        },
    }
}

// The measured call sits behind an `#[inline(never)]` boundary, input
// processing included, so fat LTO cannot fold it into the bench wrapper
// (Callgrind on aarch64 then leaves part of the work out of the count).
#[inline(never)]
fn vi_call(
    case: &RenderCase,
    values: &mut [Option<Value>],
    shell: Shell,
    width: u16,
) -> ViVariants {
    render_vi_variants(
        &theme(case),
        ViInputs {
            catalog: BUILTIN,
            values,
            facts: &case.facts,
            setup: &case.setup,
        },
        &target(shell, width),
        None,
        &case.main,
        &mut NoopRecorder,
    )
}

// The second layout of a two-line triangle prompt at 80 columns. The fields
// are allocated inside the counted code (they are the output); input and
// output are returned so they drop outside it.
#[library_benchmark]
#[bench::zsh(args = [&["char"]], setup = render_case)]
fn vi_variants_zsh(
    (case, mut values): (RenderCase, Vec<Option<Value>>),
) -> (RenderCase, ViVariants) {
    let r = vi_call(
        black_box(&case),
        black_box(&mut values),
        black_box(Shell::Zsh),
        black_box(80),
    );
    (case, r)
}

// The same prompt without `char`: nothing to change, so no second layout.
#[library_benchmark]
#[bench::zsh(args = [&["dir"]], setup = render_case)]
fn vi_variants_no_char(
    (case, mut values): (RenderCase, Vec<Option<Value>>),
) -> (RenderCase, ViVariants) {
    let r = vi_call(
        black_box(&case),
        black_box(&mut values),
        black_box(Shell::Zsh),
        black_box(80),
    );
    (case, r)
}

library_benchmark_group!(
    name = vi_variants,
    benchmarks = [vi_variants_zsh, vi_variants_no_char]
);

// main! defines `fn main` itself: wrapped in a fn of ours the bench would
// build, exit 0 and measure nothing.
main!(library_benchmark_groups = vi_variants);
