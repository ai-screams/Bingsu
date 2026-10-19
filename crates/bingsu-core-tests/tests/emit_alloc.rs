//! Shell output writes into the caller's buffer only: with capacity
//! reserved, `emit` and `readline_mode_string` neither allocate nor grow.
//! Its counter excludes allocations from the harness and other threads.
use bingsu_core::color::palette::{Knobs, Mode, PaletteInput, resolve_palette, token_index};
use bingsu_core::color::sgr::{BOLD, Color, ColorDepth, Style};
use bingsu_core::emit::{emit, readline_mode_string};
use bingsu_core::layout::Run;
use bingsu_core::shell_word::Shell;
#[path = "support/allocation.rs"]
mod allocation;
use allocation::{Counting, counted};

#[global_allocator]
static GLOBAL: Counting = Counting;

// 이것을 실패시키는 것: emit 안에서 SGR용 임시 Vec을 만드는 것(계획 초안의 `Vec::with_capacity(32)`),
// 또는 readline 문자열을 만들며 임시 버퍼를 만드는 것.
#[test]
fn emit_does_not_allocate() {
    let p = resolve_palette(&PaletteInput {
        mode: Mode::Dark,
        knobs: Knobs::default(),
        overrides: &[],
        roles: &[],
    })
    .unwrap();
    let err = token_index("prompt.err").unwrap() as u16;
    let runs = [
        Run {
            text: "~/src/\u{D55C}\u{AE00} 50%".into(),
            style: Style::default(),
        },
        Run {
            text: " main ".into(),
            style: Style {
                fg: Color::Text(err),
                bg: Color::Block(err),
                attrs: BOLD,
            },
        },
        Run {
            text: "\u{276F} ".into(),
            style: Style {
                fg: Color::Text(err),
                ..Style::default()
            },
        },
    ];
    // Every readline text path: escaped `\\` and `"`, removed characters.
    let marks = [Run {
        text: "\\ \" \u{1}\u{2}\u{1b}[0m\n\u{202E} \u{276F}".into(),
        style: runs[2].style,
    }];
    let mut out = Vec::with_capacity(4096);
    let mut rl = Vec::with_capacity(4096);
    let counts = counted(|| {
        for shell in [Shell::Zsh, Shell::Fish, Shell::Bash] {
            for depth in [
                ColorDepth::TrueColor,
                ColorDepth::Ansi256,
                ColorDepth::Ansi16,
            ] {
                out.clear();
                emit(shell, &runs, &p, depth, &mut out);
            }
        }
        readline_mode_string(&marks, &p, ColorDepth::TrueColor, &mut rl);
    });
    assert!(!out.is_empty() && rl.len() > 2);
    assert_eq!((counts.0, counts.1), (0, 0));
}
