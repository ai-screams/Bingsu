//! Instruction counts of shell output (spec section 3 "셸 경계의 요구 행동",
//! section 8 "측정과 게이트", section 9 M2 row). Each bench group is its own
//! bench target, so the code generation of one binary does not depend on
//! the benches of another.
use bingsu_core::color::palette::{
    Knobs, Mode, PaletteInput, ResolvedPalette, resolve_palette, token_index,
};
use bingsu_core::color::sgr::{BOLD, Color, ColorDepth, Style};
use bingsu_core::emit::emit;
use bingsu_core::layout::Run;
use bingsu_core::shell_word::Shell;
use gungraun::prelude::*;
use std::hint::black_box;

// Only the code inside the benchmark function is counted (the runner
// collects within `__gungraun_wrapper_mod::*`). An owned input would be
// dropped, and freed, at the end of that function, so each bench returns
// its input: the caller drops the returned value outside the counted code.
// One prompt line of six runs (path with Hangul and a `%`, branch, status,
// time, prompt mark) written for one shell. Palette, runs and a reserved
// output buffer come from setup and are returned, so the counted code only
// escapes and writes SGRs.
fn emit_case(shell: Shell) -> (Shell, ResolvedPalette, Vec<Run>, Vec<u8>) {
    let p = resolve_palette(&PaletteInput {
        mode: Mode::Dark,
        knobs: Knobs::default(),
        overrides: &[],
        roles: &[],
    })
    .expect("palette");
    let tok = |name: &str| u16::try_from(token_index(name).unwrap_or(0)).unwrap_or(0);
    let run = |text: &str, fg: Color, bg: Color, attrs: u8| Run {
        text: text.into(),
        style: Style { fg, bg, attrs },
    };
    let runs = vec![
        run(
            " ~/src/\u{D55C}\u{AE00}/100%-done ",
            Color::Text(tok("prompt.ok")),
            Color::Default,
            BOLD,
        ),
        run(
            "\u{E0B0}",
            Color::Text(tok("prompt.ok")),
            Color::Block(tok("prompt.err")),
            0,
        ),
        run(
            " feature/very-long-branch ",
            Color::Text(tok("prompt.err")),
            Color::Default,
            0,
        ),
        run(" 3s ", Color::Default, Color::Default, 0),
        run(" 12:34 ", Color::Text(tok("prompt.ok")), Color::Default, 0),
        run(
            "\u{276F} ",
            Color::Text(tok("prompt.err")),
            Color::Default,
            BOLD,
        ),
    ];
    (shell, p, runs, Vec::with_capacity(1024))
}

#[library_benchmark]
#[bench::zsh(args = [Shell::Zsh], setup = emit_case)]
#[bench::bash(args = [Shell::Bash], setup = emit_case)]
#[bench::fish(args = [Shell::Fish], setup = emit_case)]
fn emit_line(
    (shell, p, runs, mut out): (Shell, ResolvedPalette, Vec<Run>, Vec<u8>),
) -> (Shell, ResolvedPalette, Vec<Run>, Vec<u8>) {
    emit_once(shell, &runs, &p, &mut out);
    (shell, p, runs, black_box(out))
}

// The measured call sits behind an `#[inline(never)]` boundary (see the
// CLAUDE.md icount notes): inlined into the wrapper, Callgrind on aarch64
// counted no SGR formatting for zsh and more for fish than for bash.
#[inline(never)]
fn emit_once(shell: Shell, runs: &[Run], p: &ResolvedPalette, out: &mut Vec<u8>) {
    emit(
        black_box(shell),
        black_box(runs),
        p,
        black_box(ColorDepth::TrueColor),
        out,
    );
}

library_benchmark_group!(name = core_m2, benchmarks = [emit_line]);

// main! defines `fn main` itself: wrapped in a fn of ours the bench would
// build, exit 0 and measure nothing.
main!(library_benchmark_groups = core_m2);
