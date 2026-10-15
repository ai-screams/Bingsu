//! Where a 64 KiB `$PWD` spends its instructions (M3a decision P17): each
//! stage of the dir segment on its own, for two inputs of exactly 65,536
//! bytes: 32,768 one-letter steps, and one name of 65,535 bytes. The front
//! end passes at most the last 4,096 steps (P14, `shell_values::path_facts`).
//! Stages: sanitizing the `path` field text, building `PathFacts`, measuring
//! the display width, shortening it with the default theme's methods, and a
//! whole render with the default theme.
use bingsu_core::color::palette::Mode;
use bingsu_core::color::sgr::ColorDepth;
use bingsu_core::default_theme::DefaultTheme;
use bingsu_core::field::{BUILTIN, Field, Value, segment};
use bingsu_core::layout::{Inputs, Options};
use bingsu_core::recorder::NoopRecorder;
use bingsu_core::render::{RenderedPrompt, Target, render_prompt};
use bingsu_core::shell_values::path_facts;
use bingsu_core::shell_word::Shell;
use bingsu_core::shorten::{Method, PathFacts, ShortenResult, Source, shorten};
use bingsu_core::width::{WidthProfile, str_width};
use gungraun::prelude::*;
use std::hint::black_box;

const CAP: usize = 65_536;

fn steps_input(_: u32) -> Vec<u8> {
    b"/a".repeat(CAP / 2)
}

fn name_input(_: u32) -> Vec<u8> {
    let mut v = b"/".to_vec();
    v.extend(std::iter::repeat_n(b'a', CAP - 1));
    v
}

fn facts_of(pwd: &[u8]) -> PathFacts {
    path_facts(pwd, None)
}

#[inline(never)]
fn sanitize_field(pwd: &[u8]) -> Field {
    Field::text(pwd, 4096, WidthProfile::DEFAULT)
}

#[inline(never)]
fn build_facts(pwd: &[u8]) -> PathFacts {
    facts_of(pwd)
}

#[inline(never)]
fn display_width(f: &PathFacts) -> u32 {
    str_width(&f.display(), WidthProfile::DEFAULT)
}

#[inline(never)]
fn shorten_default(f: &PathFacts) -> Option<(ShortenResult, usize, u32)> {
    shorten(
        Source::Path(f),
        &[Method::Repo, Method::Abbrev(1), Method::Depth(1)],
        60,
        WidthProfile::DEFAULT,
    )
}

#[inline(never)]
fn render_default(pwd: &[u8]) -> RenderedPrompt {
    let d = DefaultTheme::new(Mode::Dark).expect("default theme");
    let i = |id: &str| BUILTIN.iter().position(|x| x.id == id).unwrap_or(0);
    let v = |id: &str| segment(id).map(|s| Value::new(b"", vec![Field::ABSENT; s.fields.len()]));
    let mut values = vec![None; BUILTIN.len()];
    let mut facts = vec![None; BUILTIN.len()];
    values[i("char")] = v("char");
    values[i("dir")] = v("dir");
    facts[i("dir")] = Some(facts_of(pwd));
    let inputs = Inputs {
        catalog: BUILTIN,
        values: &values,
        facts: &facts,
        setup: d.setup(),
    };
    let t = Target {
        shell: Shell::Zsh,
        depth: ColorDepth::Ansi256,
        options: Options {
            width: 100,
            profile: WidthProfile::DEFAULT,
            icons: bingsu_core::default_theme::ICONS,
            use_last_column: false,
        },
    };
    render_prompt(&d.theme(), &inputs, &t, &mut NoopRecorder)
}

#[library_benchmark]
#[bench::steps(args = [0], setup = steps_input)]
#[bench::one_name(args = [0], setup = name_input)]
fn pwd64_sanitize(pwd: Vec<u8>) -> (Vec<u8>, Field) {
    let r = sanitize_field(black_box(&pwd));
    (pwd, r)
}

#[library_benchmark]
#[bench::steps(args = [0], setup = steps_input)]
#[bench::one_name(args = [0], setup = name_input)]
fn pwd64_facts(pwd: Vec<u8>) -> (Vec<u8>, PathFacts) {
    let r = build_facts(black_box(&pwd));
    (pwd, r)
}

fn facts_steps(_: u32) -> PathFacts {
    facts_of(&steps_input(0))
}

fn facts_name(_: u32) -> PathFacts {
    facts_of(&name_input(0))
}

#[library_benchmark]
#[bench::steps(args = [0], setup = facts_steps)]
#[bench::one_name(args = [0], setup = facts_name)]
fn pwd64_width(f: PathFacts) -> (PathFacts, u32) {
    let r = display_width(black_box(&f));
    (f, r)
}

#[library_benchmark]
#[bench::steps(args = [0], setup = facts_steps)]
#[bench::one_name(args = [0], setup = facts_name)]
fn pwd64_shorten(f: PathFacts) -> (PathFacts, Option<(ShortenResult, usize, u32)>) {
    let r = shorten_default(black_box(&f));
    (f, r)
}

#[library_benchmark]
#[bench::steps(args = [0], setup = steps_input)]
#[bench::one_name(args = [0], setup = name_input)]
fn pwd64_render(pwd: Vec<u8>) -> (Vec<u8>, RenderedPrompt) {
    let r = render_default(black_box(&pwd));
    (pwd, r)
}

library_benchmark_group!(
    name = core_m3a_pwd64,
    benchmarks = [
        pwd64_sanitize,
        pwd64_facts,
        pwd64_width,
        pwd64_shorten,
        pwd64_render
    ]
);

main!(library_benchmark_groups = core_m3a_pwd64);
