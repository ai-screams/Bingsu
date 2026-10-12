//! SGR output (spec section 3 "색 출력"). The depth is chosen outside core
//! (`COLORTERM` is environment, read by the CLI side) and passed in.
use super::palette::{AnsiSlot, ResolvedPalette};
use alloc::vec::Vec;
use core::fmt::Write as _;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ColorDepth {
    /// `COLORTERM` is `truecolor` or `24bit`: the token's sRGB.
    TrueColor,
    /// Nearest of xterm 16..=255 by OKLab distance.
    Ansi256,
    /// `color = "ansi"`: the token's ANSI slot of the terminal scheme.
    Ansi16,
}

/// A color reference: the terminal default, a token's text color (read
/// tier) or a token's block color (display tier). Token = index in TOKENS.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum Color {
    #[default]
    Default,
    Text(u16),
    Block(u16),
}

pub const BOLD: u8 = 1;
pub const DIM: u8 = 2;
pub const ITALIC: u8 = 4;
pub const UNDERLINE: u8 = 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct Style {
    pub fg: Color,
    pub bg: Color,
    pub attrs: u8,
}

struct Buf<'a>(&'a mut Vec<u8>);
impl core::fmt::Write for Buf<'_> {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        self.0.extend_from_slice(s.as_bytes());
        Ok(())
    }
}

fn color(c: Color, bg: bool, p: &ResolvedPalette, depth: ColorDepth, w: &mut Buf<'_>) {
    let (i, block) = match c {
        Color::Default => return,
        Color::Text(i) => (i, false),
        Color::Block(i) => (i, true),
    };
    let Some(t) = p.tokens.get(usize::from(i)) else {
        return;
    };
    let base = if bg { 40 } else { 30 };
    let _ = match depth {
        ColorDepth::TrueColor => {
            let s = if block { t.bg } else { t.fg };
            write!(w, ";{};2;{};{};{}", base + 8, s.r, s.g, s.b)
        }
        ColorDepth::Ansi256 => write!(
            w,
            ";{};5;{}",
            base + 8,
            if block { t.bg256 } else { t.fg256 }
        ),
        ColorDepth::Ansi16 => match t.ansi {
            AnsiSlot::Default => Ok(()),
            AnsiSlot::Slot(n) if n < 8 => write!(w, ";{}", base + u32::from(n)),
            AnsiSlot::Slot(n) => write!(w, ";{}", base + 60 + u32::from(n - 8)),
        },
    };
}

/// Appends one SGR that sets `style` from scratch: `ESC [ 0 … m`. Always
/// the ABNF `sgr` form of the record (digits and `;` only).
pub fn write_sgr(style: Style, p: &ResolvedPalette, depth: ColorDepth, out: &mut Vec<u8>) {
    out.extend_from_slice(b"\x1b[0");
    let mut w = Buf(out);
    for (bit, code) in [(BOLD, 1), (DIM, 2), (ITALIC, 3), (UNDERLINE, 4)] {
        if style.attrs & bit != 0 {
            let _ = write!(w, ";{code}");
        }
    }
    color(style.fg, false, p, depth, &mut w);
    color(style.bg, true, p, depth, &mut w);
    out.push(b'm');
}

pub const RESET: &[u8] = b"\x1b[0m";

#[cfg(test)]
mod tests {
    use super::*;
    use crate::color::palette::{Knobs, Mode, PaletteInput, resolve_palette, token_index};

    fn palette() -> ResolvedPalette {
        resolve_palette(&PaletteInput {
            mode: Mode::Dark,
            knobs: Knobs::default(),
            overrides: &[],
            roles: &[],
        })
        .unwrap()
    }

    fn sgr(style: Style, depth: ColorDepth) -> Vec<u8> {
        let mut v = Vec::new();
        write_sgr(style, &palette(), depth, &mut v);
        v
    }

    // 이것을 실패시키는 것: 깊이별 코드(38;2·38;5·3x/9x)나 속성 번호가 틀리는 것, ABNF 밖 글자.
    #[test]
    fn sgr_by_depth() {
        let path = token_index("path").unwrap() as u16;
        let muted = token_index("muted").unwrap() as u16;
        let p = palette();
        let t = p.tokens[usize::from(path)];
        let s = Style {
            fg: Color::Text(path),
            bg: Color::Default,
            attrs: BOLD,
        };
        assert_eq!(
            sgr(s, ColorDepth::TrueColor),
            alloc::format!("\x1b[0;1;38;2;{};{};{}m", t.fg.r, t.fg.g, t.fg.b).into_bytes()
        );
        assert_eq!(
            sgr(s, ColorDepth::Ansi256),
            alloc::format!("\x1b[0;1;38;5;{}m", t.fg256).into_bytes()
        );
        assert_eq!(sgr(s, ColorDepth::Ansi16), b"\x1b[0;1;34m");
        let s = Style {
            fg: Color::Text(muted),
            bg: Color::Block(path),
            attrs: DIM | ITALIC | UNDERLINE,
        };
        assert_eq!(sgr(s, ColorDepth::Ansi16), b"\x1b[0;2;3;4;90;44m");
        let fg = token_index("fg").unwrap() as u16;
        assert_eq!(
            sgr(
                Style {
                    fg: Color::Text(fg),
                    ..Style::default()
                },
                ColorDepth::Ansi16
            ),
            b"\x1b[0m"
        );
        for depth in [
            ColorDepth::TrueColor,
            ColorDepth::Ansi256,
            ColorDepth::Ansi16,
        ] {
            let v = sgr(
                Style {
                    fg: Color::Text(path),
                    bg: Color::Block(muted),
                    attrs: 15,
                },
                depth,
            );
            assert!(v.starts_with(b"\x1b[") && v.ends_with(b"m"));
            assert!(
                v[2..v.len() - 1]
                    .iter()
                    .all(|b| b.is_ascii_digit() || *b == b';')
            );
        }
    }
}
