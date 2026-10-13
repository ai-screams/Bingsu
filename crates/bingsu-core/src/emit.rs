//! Shell boundary output (spec section 3 "셸별 출력과 보안" step 3 and
//! "셸 경계의 요구 행동"). Text is sanitized before it gets here and widths
//! are counted before escaping. What each shell needs from the producer:
//!
//! | shell | invisible bytes | producer escaping | left to the hook (M1) |
//! | -- | -- | -- | -- |
//! | zsh | `%{` … `%}` | `%` → `%%` in all text, data and theme alike | `!` → `!!` when PROMPT_BANG is on |
//! | bash | SOH … STX (0x01, 0x02) | none | `\` → `\\` on the value-assign path |
//! | fish | none (no SOH or STX) | none | none |
//! | bash vi mode string | `\001` … `\002` | `\` → `\\`, `"` → `\"`, ESC → `\e`, in `"…"` | none |
//!
//! The hook knows the option state at install time; the producer does not,
//! so `!` and `\` stay with the hook (crates/bingsu/src/shell/zsh/hooks.zsh
//! and bash/hooks.bash).
use crate::color::palette::ResolvedPalette;
use crate::color::sgr::{ColorDepth, Style, write_sgr};
use crate::layout::Run;
use crate::sanitize::is_removed;
use crate::shell_word::Shell;
use alloc::vec::Vec;

/// Where the bytes go: a prompt field of one shell, or the readline
/// notation of a bash vi mode string.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Target {
    Shell(Shell),
    Readline,
}

/// The markers that hide the bytes between them from the width count; fish
/// counts escape sequences itself. Readline takes SOH and STX as three
/// octal digits because it reads up to three: `\2` before a `1` would be
/// `\21`, 0x11.
fn markers(t: Target) -> (&'static [u8], &'static [u8]) {
    match t {
        Target::Shell(Shell::Zsh) => (b"%{", b"%}"),
        Target::Shell(Shell::Bash) => (b"\x01", b"\x02"),
        Target::Shell(Shell::Fish) => (b"", b""),
        Target::Readline => (b"\\001", b"\\002"),
    }
}

/// One SGR inside its markers. Readline gets the ESC as `\e`: the slot of
/// the `\` is written first and the ESC that `write_sgr` puts after it
/// becomes the `e`, so nothing is copied or moved.
fn sgr(t: Target, style: Style, p: &ResolvedPalette, depth: ColorDepth, out: &mut Vec<u8>) {
    let (open, close) = markers(t);
    out.extend_from_slice(open);
    if t == Target::Readline {
        out.push(b'\\');
        let esc = out.len();
        write_sgr(style, p, depth, out);
        out[esc] = b'e';
    } else {
        write_sgr(style, p, depth, out);
    }
    out.extend_from_slice(close);
}

/// Escaped text. Text reaches here only through `Clean` and compiled
/// templates; a removed character (control, SOH, STX, ESC, format) is still
/// dropped here, one more layer in case a later change opens another path.
fn text(t: Target, s: &str, out: &mut Vec<u8>) {
    let mut buf = [0u8; 4];
    for c in s.chars().filter(|&c| !is_removed(c)) {
        match (t, c) {
            (Target::Shell(Shell::Zsh), '%') => out.push(b'%'),
            (Target::Readline, '\\' | '"') => out.push(b'\\'),
            _ => {}
        }
        out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
    }
}

/// Runs in the given notation. The first run always opens with an SGR (for
/// the default style that is a reset), so attributes a previous command
/// left on the terminal do not carry into the prompt; after a styled run a
/// reset closes the line. No runs, no bytes: an empty field stays empty.
fn runs_into(t: Target, runs: &[Run], p: &ResolvedPalette, depth: ColorDepth, out: &mut Vec<u8>) {
    let mut cur: Option<Style> = None;
    for r in runs {
        if cur != Some(r.style) {
            sgr(t, r.style, p, depth, out);
            cur = Some(r.style);
        }
        text(t, &r.text, out);
    }
    if cur.is_some_and(|s| s != Style::default()) {
        sgr(t, Style::default(), p, depth, out);
    }
}

/// Appends `runs` as one record field for `shell`: an SGR (wrapped as the
/// shell needs) whenever the style changes, escaped text, and a reset at
/// the end if any style was set. Writes only into `out`; with enough
/// capacity reserved it does not allocate.
pub fn emit(shell: Shell, runs: &[Run], p: &ResolvedPalette, depth: ColorDepth, out: &mut Vec<u8>) {
    runs_into(Target::Shell(shell), runs, p, depth, out);
}

/// bash vi mode string for `bind -- "set vi-ins-mode-string <this>"` (spec
/// section 5 "bash vi 모드 규칙" 3): the bytes `emit(Shell::Bash, …)` would
/// write, in readline notation and double quotes. It is built from the runs,
/// not from bytes, so only the SGRs and markers this function writes become
/// `\e`, `\001` and `\002`; text can never produce them.
pub fn readline_mode_string(
    runs: &[Run],
    p: &ResolvedPalette,
    depth: ColorDepth,
    out: &mut Vec<u8>,
) {
    out.push(b'"');
    runs_into(Target::Readline, runs, p, depth, out);
    out.push(b'"');
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::color::palette::{Knobs, Mode, PaletteInput, resolve_palette, token_index};
    use crate::color::sgr::{BOLD, Color};
    use alloc::string::String;

    fn pal() -> ResolvedPalette {
        resolve_palette(&PaletteInput {
            mode: Mode::Dark,
            knobs: Knobs::default(),
            overrides: &[],
            roles: &[],
        })
        .unwrap()
    }
    fn tok(name: &str) -> u16 {
        token_index(name).unwrap() as u16
    }
    fn red() -> Style {
        Style {
            fg: Color::Text(tok("prompt.err")),
            ..Style::default()
        }
    }
    fn runs(parts: &[(&str, Style)]) -> Vec<Run> {
        parts
            .iter()
            .map(|(t, s)| Run {
                text: String::from(*t),
                style: *s,
            })
            .collect()
    }
    fn out_at(shell: Shell, r: &[Run], depth: ColorDepth) -> Vec<u8> {
        let mut v = Vec::new();
        emit(shell, r, &pal(), depth, &mut v);
        v
    }
    fn out(shell: Shell, r: &[Run]) -> Vec<u8> {
        out_at(shell, r, ColorDepth::Ansi16)
    }
    fn rl(r: &[Run]) -> Vec<u8> {
        let mut v = Vec::new();
        readline_mode_string(r, &pal(), ColorDepth::Ansi16, &mut v);
        v
    }

    // 이것을 실패시키는 것: 셸별 감싸기(zsh `%{ %}`, bash SOH·STX, fish 없음)나 zsh `%` 이스케이프가 빠지는 것,
    // zsh·fish 필드에 SOH·STX가 들어가는 것(스펙 3절 만드는 쪽 시험).
    #[test]
    fn per_shell_bytes() {
        let r = runs(&[("50% ", Style::default()), ("\u{276F}", red())]);
        assert_eq!(
            out(Shell::Zsh, &r),
            b"%{\x1b[0m%}50%% %{\x1b[0;31m%}\xe2\x9d\xaf%{\x1b[0m%}"
        );
        assert_eq!(
            out(Shell::Bash, &r),
            b"\x01\x1b[0m\x0250% \x01\x1b[0;31m\x02\xe2\x9d\xaf\x01\x1b[0m\x02"
        );
        assert_eq!(
            out(Shell::Fish, &r),
            b"\x1b[0m50% \x1b[0;31m\xe2\x9d\xaf\x1b[0m"
        );
        for sh in [Shell::Zsh, Shell::Fish] {
            assert!(!out(sh, &r).iter().any(|b| *b == 1 || *b == 2));
        }
    }

    // 이것을 실패시키는 것: 첫 run이 기본 스타일일 때 맨 앞 RESET을 빼는 것(직전 명령이 남긴 SGR이 번짐),
    // 빈 run 목록에 바이트를 쓰는 것(빈 필드가 비지 않음).
    #[test]
    fn line_starts_with_a_reset() {
        let r = runs(&[("a", Style::default())]);
        assert_eq!(out(Shell::Zsh, &r), b"%{\x1b[0m%}a");
        assert_eq!(out(Shell::Bash, &r), b"\x01\x1b[0m\x02a");
        assert_eq!(out(Shell::Fish, &r), b"\x1b[0ma");
        assert_eq!(rl(&r), b"\"\\001\\e[0m\\002a\"");
        assert_eq!(out(Shell::Zsh, &[]), b"");
        assert_eq!(rl(&[]), b"\"\"");
    }

    // 이것을 실패시키는 것: 색 깊이를 무시하거나 깊이마다 다른 꼴(38;2 / 38;5 / 30+슬롯)을 섞는 것.
    // 값은 Dark 팔레트의 prompt.err 글자색과 prompt.ok 블록색이다.
    #[test]
    fn per_depth_bytes() {
        let s = Style {
            fg: Color::Text(tok("prompt.err")),
            bg: Color::Block(tok("prompt.ok")),
            attrs: BOLD,
        };
        let r = runs(&[("x", s)]);
        assert_eq!(
            out_at(Shell::Fish, &r, ColorDepth::TrueColor),
            b"\x1b[0;1;38;2;243;144;152;48;2;127;197;129mx\x1b[0m"
        );
        assert_eq!(
            out_at(Shell::Fish, &r, ColorDepth::Ansi256),
            b"\x1b[0;1;38;5;210;48;5;114mx\x1b[0m"
        );
        assert_eq!(
            out_at(Shell::Fish, &r, ColorDepth::Ansi16),
            b"\x1b[0;1;31;42mx\x1b[0m"
        );
    }

    // 이것을 실패시키는 것: 끝에 기본 스타일로 돌아왔는데 RESET을 한 번 더 붙이는 것, 또는 기본 스타일로
    // 돌아가는 run에서 SGR을 빼는 것(색이 다음 글자로 번짐).
    #[test]
    fn back_to_default_resets_once() {
        let r = runs(&[("a", red()), ("b", Style::default())]);
        assert_eq!(out(Shell::Fish, &r), b"\x1b[0;31ma\x1b[0mb");
    }

    // 이것을 실패시키는 것: `!`·`\`를 만드는 쪽에서 바꾸는 것(hook이 하므로 두 번 바뀜).
    #[test]
    fn bang_and_backslash_left_to_the_hook() {
        let r = runs(&[("!!\\u $(x) `y` %F{red}", Style::default())]);
        assert_eq!(out(Shell::Zsh, &r), b"%{\x1b[0m%}!!\\u $(x) `y` %%F{red}");
        assert_eq!(
            out(Shell::Bash, &r),
            b"\x01\x1b[0m\x02!!\\u $(x) `y` %F{red}"
        );
    }

    // 이것을 실패시키는 것: emit의 마지막 방어(정제 대상 글자 지우기)를 빼는 것. 위쪽 입구(Clean,
    // compile)를 우회한 글자가 와도 RLO·ZWSP·SOH·데이터 ESC가 필드에 남지 않아야 한다.
    #[test]
    fn emit_drops_removed_characters() {
        let r = runs(&[("a\u{202E}b\u{200B}c\u{1}d\x1b[31me%", Style::default())]);
        assert_eq!(out(Shell::Zsh, &r), b"%{\x1b[0m%}abcd[31me%%");
        assert_eq!(out(Shell::Bash, &r), b"\x01\x1b[0m\x02abcd[31me%");
        assert_eq!(out(Shell::Fish, &r), b"\x1b[0mabcd[31me%");
    }

    // 이것을 실패시키는 것: 스펙 5절 표의 바이트 예와 다른 readline 문자열(SOH·STX는 세 자리 `\001`·`\002`,
    // ESC는 `\e`), `"`·`\` 이스케이프가 빠지는 것.
    #[test]
    fn readline_spec_vector() {
        let r = runs(&[("\u{276F}", red())]);
        assert_eq!(
            rl(&r),
            b"\"\\001\\e[0;31m\\002\xe2\x9d\xaf\\001\\e[0m\\002\""
        );
        let r = runs(&[("a\"b\\c!", Style::default())]);
        assert_eq!(rl(&r), b"\"\\001\\e[0m\\002a\\\"b\\\\c!\"");
    }

    // 이것을 실패시키는 것: STX를 짧은 `\2`로 쓰는 것. 뒤 글자 `1`과 합쳐져 readline이 0x11을 만든다.
    #[test]
    fn readline_marker_before_a_digit() {
        let r = runs(&[("1", Style::default()), ("07", red())]);
        assert_eq!(
            rl(&r),
            b"\"\\001\\e[0m\\0021\\001\\e[0;31m\\00207\\001\\e[0m\\002\""
        );
    }

    // 이것을 실패시키는 것: readline 쪽 글자의 마지막 방어를 빼는 것. 글자 속 SOH·STX·ESC·줄바꿈·US·RS·
    // DEL·C1·RLO가 표기(`\001` 등)나 날 바이트로 나가는 것.
    #[test]
    fn readline_text_never_becomes_notation() {
        let r = runs(&[(
            "a\u{1}b\u{2}c\u{1b}d\ne\u{1f}f\u{1e}g\u{7f}h\u{85}i\u{202E}j",
            Style::default(),
        )]);
        assert_eq!(rl(&r), b"\"\\001\\e[0m\\002abcdefghij\"");
    }
}
