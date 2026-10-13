//! Shell output writes into the caller's buffer only: with capacity
//! reserved, `emit` and `readline_mode_string` neither allocate nor grow.
//! Its own test binary, so no other test allocates while counting.
use bingsu_core::color::palette::{Knobs, Mode, PaletteInput, resolve_palette, token_index};
use bingsu_core::color::sgr::{BOLD, Color, ColorDepth, Style};
use bingsu_core::emit::{emit, readline_mode_string};
use bingsu_core::layout::Run;
use bingsu_core::shell_word::Shell;
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

struct Counting;

static ARMED: AtomicBool = AtomicBool::new(false);
static CALLS: AtomicUsize = AtomicUsize::new(0);

// SAFETY: every method forwards to `System` with the caller's arguments
// unchanged; the counters are atomics and never allocate.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if ARMED.load(Ordering::Relaxed) {
            CALLS.fetch_add(1, Ordering::Relaxed);
        }
        // SAFETY: the caller's contract for `alloc` is passed on as is.
        unsafe { System.alloc(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: `ptr` came from `System` through this allocator.
        unsafe { System.dealloc(ptr, layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        if ARMED.load(Ordering::Relaxed) {
            CALLS.fetch_add(1, Ordering::Relaxed);
        }
        // SAFETY: `ptr` came from `System` with `layout`; passed on as is.
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static GLOBAL: Counting = Counting;

// 이것을 실패시키는 것: emit 안에서 SGR용 임시 Vec을 만드는 것(계획 초안의 `Vec::with_capacity(32)`),
// 또는 readline 문자열을 만들며 임시 String을 만드는 것.
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
    let mut out = Vec::with_capacity(4096);
    let mut rl = Vec::with_capacity(4096);
    ARMED.store(true, Ordering::Relaxed);
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
    // The last field is bash's, the input the vi mode string is made from.
    readline_mode_string(&out, &mut rl);
    ARMED.store(false, Ordering::Relaxed);
    assert!(!out.is_empty() && rl.len() > 2);
    assert_eq!(CALLS.load(Ordering::Relaxed), 0);
}
