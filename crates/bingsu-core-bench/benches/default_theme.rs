//! Instruction counts of the built-in default theme (M3a Task V1): building
//! it (presets to templates, compile, palette) and one render with it. The
//! front end does both on every prompt until the compiled snapshot lands,
//! so the build count is the cost the snapshot is meant to remove.
use bingsu_core::color::palette::Mode;
use bingsu_core::color::sgr::ColorDepth;
use bingsu_core::default_theme::DefaultTheme;
use bingsu_core::field::{BUILTIN, Field, Value, segment};
use bingsu_core::layout::{Inputs, Options};
use bingsu_core::recorder::NoopRecorder;
use bingsu_core::render::{RenderedPrompt, Target, render_prompt};
use bingsu_core::shell_word::Shell;
use bingsu_core::shorten::{Anchor, PathFacts};
use bingsu_core::width::WidthProfile;
use gungraun::prelude::*;
use std::hint::black_box;

// The measured calls sit behind `#[inline(never)]` (CLAUDE.md: inlined into
// the bench wrapper, Callgrind on aarch64 undercounts them).
#[inline(never)]
fn build(mode: Mode) -> DefaultTheme {
    DefaultTheme::new(mode).expect("default theme")
}

struct Case {
    values: Vec<Option<Value>>,
    facts: Vec<Option<PathFacts>>,
}

fn case(_: u32) -> Case {
    let i = |id: &str| BUILTIN.iter().position(|d| d.id == id).unwrap_or(0);
    let v = |id: &str| segment(id).map(|d| Value::new(b"", vec![Field::ABSENT; d.fields.len()]));
    let mut values = vec![None; BUILTIN.len()];
    let mut facts = vec![None; BUILTIN.len()];
    values[i("char")] = v("char");
    values[i("dir")] = v("dir");
    let steps: [&[u8]; 3] = [b"Works", b"AiScream", b"themes"];
    facts[i("dir")] = Some(PathFacts::new(Anchor::Home, &steps, None, &[]));
    Case { values, facts }
}

#[inline(never)]
fn build_and_render(c: &Case, shell: Shell) -> RenderedPrompt {
    let d = build(Mode::Dark);
    let inputs = Inputs {
        catalog: BUILTIN,
        values: &c.values,
        facts: &c.facts,
        setup: d.setup(),
    };
    let t = Target {
        shell,
        depth: ColorDepth::Ansi256,
        options: Options {
            width: 80,
            profile: WidthProfile::DEFAULT,
            icons: bingsu_core::default_theme::ICONS,
            use_last_column: false,
        },
    };
    render_prompt(&d.theme(), &inputs, &t, &mut NoopRecorder)
}

#[library_benchmark]
fn default_theme_build() -> DefaultTheme {
    build(black_box(Mode::Dark))
}

#[library_benchmark]
#[bench::zsh(args = [0], setup = case)]
fn default_theme_prompt_zsh(c: Case) -> (Case, RenderedPrompt) {
    let r = build_and_render(black_box(&c), black_box(Shell::Zsh));
    (c, r)
}

library_benchmark_group!(
    name = core_m3a,
    benchmarks = [default_theme_build, default_theme_prompt_zsh]
);

main!(library_benchmark_groups = core_m3a);
