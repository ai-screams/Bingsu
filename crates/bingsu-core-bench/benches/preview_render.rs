//! Instruction counts of the setup editor's preview: every line of a compiled
//! config laid out as runs with the sample values (`preview::lines`), once per
//! key the editor handles. The config is compiled in the setup, outside the
//! counted code; the design budget for merge, compile and this render is 2 ms
//! per key.
use bingsu_core::color::palette::Mode;
use bingsu_core::color::sgr::ColorDepth;
use bingsu_core::config::compile::CompiledConfig;
use bingsu_core::icons::IconSet;
use bingsu_core::preview::{PreviewLine, Request, Sample, lines};
use gungraun::prelude::*;
use std::hint::black_box;

#[path = "../../bingsu-core-tests/src/snapshot_fixture.rs"]
#[allow(
    dead_code,
    reason = "shared native/wasm fixture; this bench uses its compile only"
)]
mod fixture;

/// A capsule config with Nerd icons and one text segment, and the width:
/// at 80 the two lines with blocks on both sides of the fill, at 59 the
/// built-in `narrow` band.
fn case(width: u16) -> (CompiledConfig, u16) {
    let c = fixture::compile(
        "icons = \"nerd\"\n[style]\npreset = \"capsule\"\n\
         [segment.\"custom/tag\"]\nkind = \"text\"\ntext = \"prod\"\n\
         [layout.line1]\nleft = [\"host\", \"dir\", \"git\", \"custom/tag\"]\n\
         right = [\"status\", \"duration\", \"jobs\", \"venv\", \"time\"]\n",
    );
    (c, width)
}

// The measured call sits behind `#[inline(never)]` (CLAUDE.md: inlined into
// the bench wrapper, Callgrind on aarch64 undercounts it).
#[inline(never)]
fn preview(c: &CompiledConfig, width: u16) -> Vec<PreviewLine> {
    lines(
        c,
        &Request {
            mode: Mode::Dark,
            icons: IconSet::Nerd,
            depth: ColorDepth::TrueColor,
            width,
            sample: Sample {
                pwd: b"/home/u/Works/AiScream/themes/crates/bingsu-core",
                home: Some(b"/home/u"),
                host: Some(b"ice-box"),
            },
        },
    )
}

#[library_benchmark]
#[bench::w80(args = [80], setup = case)]
#[bench::narrow59(args = [59], setup = case)]
fn preview_lines((c, width): (CompiledConfig, u16)) -> (CompiledConfig, Vec<PreviewLine>) {
    let l = black_box(preview(black_box(&c), black_box(width)));
    // Returned, so the lines are freed outside the counted code.
    (c, l)
}

library_benchmark_group!(name = setup_preview, benchmarks = [preview_lines]);

main!(library_benchmark_groups = setup_preview);
