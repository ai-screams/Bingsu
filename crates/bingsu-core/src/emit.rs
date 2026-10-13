//! Shell boundary output (spec section 3 "셸별 출력과 보안" step 3 and
//! "셸 경계의 요구 행동"). Text is sanitized before it gets here and widths
//! are counted before escaping. What each shell needs from the producer:
//!
//! | shell | invisible bytes | producer escaping | left to the hook (M1) |
//! | -- | -- | -- | -- |
//! | zsh | `%{` … `%}` | `%` → `%%` in all text, data and theme alike | `!` → `!!` when PROMPT_BANG is on |
//! | bash | SOH … STX (0x01, 0x02) | none | `\` → `\\` on the value-assign path |
//! | fish | none (no SOH or STX) | none | none |
//!
//! The hook knows the option state at install time; the producer does not,
//! so `!` and `\` stay with the hook (crates/bingsu/src/shell/zsh/hooks.zsh
//! and bash/hooks.bash).
use crate::color::palette::ResolvedPalette;
use crate::color::sgr::{ColorDepth, RESET, Style, write_sgr};
use crate::layout::Run;
use crate::sanitize::is_removed;
use crate::shell_word::Shell;
use alloc::vec::Vec;

/// The markers that hide the bytes between them from the shell's width
/// count; fish counts escape sequences itself.
fn markers(shell: Shell) -> (&'static [u8], &'static [u8]) {
    match shell {
        Shell::Zsh => (b"%{", b"%}"),
        Shell::Bash => (b"\x01", b"\x02"),
        Shell::Fish => (b"", b""),
    }
}

/// Escaped text. Text reaches here only through `Clean` and compiled
/// templates; a removed character (control, SOH, STX, ESC, format) is still
/// dropped here, one more layer in case a later change opens another path.
fn text(shell: Shell, t: &str, out: &mut Vec<u8>) {
    let mut buf = [0u8; 4];
    for c in t.chars().filter(|&c| !is_removed(c)) {
        if shell == Shell::Zsh && c == '%' {
            out.push(b'%');
        }
        out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
    }
}

/// Appends `runs` as one record field for `shell`: an SGR (wrapped as the
/// shell needs) whenever the style changes, escaped text, and a reset at
/// the end if any style was set. Writes only into `out`; with enough
/// capacity reserved it does not allocate.
pub fn emit(shell: Shell, runs: &[Run], p: &ResolvedPalette, depth: ColorDepth, out: &mut Vec<u8>) {
    let (open, close) = markers(shell);
    let mut cur = Style::default();
    for r in runs {
        if r.style != cur {
            out.extend_from_slice(open);
            write_sgr(r.style, p, depth, out);
            out.extend_from_slice(close);
            cur = r.style;
        }
        text(shell, &r.text, out);
    }
    if cur != Style::default() {
        out.extend_from_slice(open);
        out.extend_from_slice(RESET);
        out.extend_from_slice(close);
    }
}

/// bash vi mode string for `bind -- "set vi-ins-mode-string <this>"` (spec
/// section 5 "bash vi 모드 규칙" 3), from the renderer's raw bytes, in
/// double quotes: `\` → `\\`, `"` → `\"`, SOH → `\001`, STX → `\002`,
/// ESC → `\e`. SOH and STX take three digits because readline reads up to
/// three octal digits: `\2` before a `1` would be `\21`, 0x11. Any other
/// removed character is dropped and invalid UTF-8 becomes U+FFFD (the
/// `sanitize_into` rule), so the result is printable and fits a B1 field.
pub fn readline_mode_string(raw: &[u8], out: &mut Vec<u8>) {
    out.push(b'"');
    let mut buf = [0u8; 4];
    for chunk in raw.utf8_chunks() {
        for c in chunk.valid().chars() {
            match c {
                '\\' => out.extend_from_slice(b"\\\\"),
                '"' => out.extend_from_slice(b"\\\""),
                '\x01' => out.extend_from_slice(b"\\001"),
                '\x02' => out.extend_from_slice(b"\\002"),
                '\x1b' => out.extend_from_slice(b"\\e"),
                c if is_removed(c) => {}
                c => out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes()),
            }
        }
        if !chunk.invalid().is_empty() {
            out.extend_from_slice("\u{FFFD}".as_bytes());
        }
    }
    out.push(b'"');
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::color::palette::{Knobs, Mode, PaletteInput, resolve_palette, token_index};
    use crate::color::sgr::Color;
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
    fn red() -> Style {
        Style {
            fg: Color::Text(token_index("prompt.err").unwrap() as u16),
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
    fn out(shell: Shell, r: &[Run]) -> Vec<u8> {
        let mut v = Vec::new();
        emit(shell, r, &pal(), ColorDepth::Ansi16, &mut v);
        v
    }
    fn rl(raw: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        readline_mode_string(raw, &mut v);
        v
    }

    // 이것을 실패시키는 것: 셸별 감싸기(zsh `%{ %}`, bash SOH·STX, fish 없음)나 zsh `%` 이스케이프가 빠지는 것,
    // zsh·fish 필드에 SOH·STX가 들어가는 것(스펙 3절 만드는 쪽 시험).
    #[test]
    fn per_shell_bytes() {
        let r = runs(&[("50% ", Style::default()), ("\u{276F}", red())]);
        assert_eq!(
            out(Shell::Zsh, &r),
            b"50%% %{\x1b[0;31m%}\xe2\x9d\xaf%{\x1b[0m%}"
        );
        assert_eq!(
            out(Shell::Bash, &r),
            b"50% \x01\x1b[0;31m\x02\xe2\x9d\xaf\x01\x1b[0m\x02"
        );
        assert_eq!(out(Shell::Fish, &r), b"50% \x1b[0;31m\xe2\x9d\xaf\x1b[0m");
        for sh in [Shell::Zsh, Shell::Fish] {
            assert!(!out(sh, &r).iter().any(|b| *b == 1 || *b == 2));
        }
    }

    // 이것을 실패시키는 것: `!`·`\`를 만드는 쪽에서 바꾸는 것(hook이 하므로 두 번 바뀜).
    #[test]
    fn bang_and_backslash_left_to_the_hook() {
        let r = runs(&[("!!\\u $(x) `y` %F{red}", Style::default())]);
        assert_eq!(out(Shell::Zsh, &r), b"!!\\u $(x) `y` %%F{red}");
        assert_eq!(out(Shell::Bash, &r), b"!!\\u $(x) `y` %F{red}");
    }

    // 이것을 실패시키는 것: emit의 마지막 방어(정제 대상 글자 지우기)를 빼는 것. 위쪽 입구(Clean,
    // compile)를 우회한 글자가 와도 RLO·ZWSP·SOH·데이터 ESC가 필드에 남지 않아야 한다.
    #[test]
    fn emit_drops_removed_characters() {
        let r = runs(&[("a\u{202E}b\u{200B}c\u{1}d\x1b[31me%", Style::default())]);
        assert_eq!(out(Shell::Zsh, &r), b"abcd[31me%%");
        assert_eq!(out(Shell::Bash, &r), b"abcd[31me%");
        assert_eq!(out(Shell::Fish, &r), b"abcd[31me%");
    }

    // 이것을 실패시키는 것: 끝에 기본 스타일로 돌아왔는데 RESET을 한 번 더 붙이는 것, 또는 기본 스타일로
    // 돌아가는 run에서 SGR을 빼는 것(색이 다음 글자로 번짐).
    #[test]
    fn back_to_default_resets_once() {
        let r = runs(&[("a", red()), ("b", Style::default())]);
        assert_eq!(out(Shell::Fish, &r), b"\x1b[0;31ma\x1b[0mb");
        assert_eq!(out(Shell::Fish, &[]), b"");
    }

    // 이것을 실패시키는 것: 스펙 5절 표의 바이트 예와 다른 readline 문자열, 이스케이프 순서 오류.
    // 계획의 벡터와 다른 점: SOH·STX는 `\1`·`\2`가 아니라 세 자리 `\001`·`\002`다. readline은 8진
    // 이스케이프를 세 자리까지 욕심껏 읽으므로 `\2` 뒤에 `1`이 오면 `\21`(0x11)이 된다(bash 5.3에서
    // `bind -v`로 확인).
    #[test]
    fn readline_spec_vector() {
        let raw = [
            0x01, 0x1b, b'[', b'3', b'1', b'm', 0x02, 0xe2, 0x9d, 0xaf, 0x01, 0x1b, b'[', b'0',
            b'm', 0x02,
        ];
        assert_eq!(
            rl(&raw),
            b"\"\\001\\e[31m\\002\xe2\x9d\xaf\\001\\e[0m\\002\""
        );
        assert_eq!(rl(b"a\"b\\c!"), b"\"a\\\"b\\\\c!\"");
    }

    // 이것을 실패시키는 것: STX를 짧은 `\2`로 쓰는 것. 뒤 글자 `1`과 합쳐져 readline이 0x11을 만든다.
    #[test]
    fn readline_marker_before_a_digit() {
        assert_eq!(rl(b"\x021\x0107"), b"\"\\0021\\00107\"");
    }

    // 이것을 실패시키는 것: readline 문자열의 마지막 방어를 빼는 것. 줄바꿈·US·RS·DEL·C1·RLO가
    // 레코드 필드나 터미널에 닿거나, 잘못된 UTF-8이 B1 문법을 깨는 것.
    #[test]
    fn readline_drops_removed_and_replaces_bad_utf8() {
        assert_eq!(
            rl(b"a\nb\x1fc\x1ed\x7fe\xc2\x85f\xe2\x80\xaeg\xffh"),
            "\"abcdefg\u{FFFD}h\"".as_bytes()
        );
    }
}
