//! SGR output. The depth is chosen outside core
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
/// tier), a token's block color (display tier) or the text color picked
/// for that block (`ResolvedToken::on_block`). Token = index in TOKENS.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum Color {
    #[default]
    Default,
    Text(u16),
    Block(u16),
    OnBlock(u16),
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
    let i = match c {
        Color::Default => return,
        Color::Text(i) | Color::Block(i) | Color::OnBlock(i) => i,
    };
    let Some(t) = p.tokens.get(usize::from(i)) else {
        return;
    };
    let (s, s256, ansi) = match c {
        Color::Block(_) => (t.bg, t.bg256, t.ansi),
        Color::OnBlock(_) => (t.on_block, t.on_block256, t.on_block_ansi),
        _ => (t.fg, t.fg256, t.ansi),
    };
    let base = if bg { 40 } else { 30 };
    let _ = match depth {
        ColorDepth::TrueColor => write!(w, ";{};2;{};{};{}", base + 8, s.r, s.g, s.b),
        ColorDepth::Ansi256 => write!(w, ";{};5;{}", base + 8, s256),
        ColorDepth::Ansi16 => match ansi {
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

/// One color as the SGR of one depth names it: what `write_sgr` writes for a
/// `Color`, with the palette and the depth already applied.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum Ink {
    /// The terminal's own color: no parameter. A token whose ANSI slot is the
    /// terminal default (`AnsiSlot::Default`) resolves here too, so a
    /// default background reads as default whatever drew it.
    #[default]
    Default,
    /// `38;2;r;g;b` (or `48;2;…` for a background).
    Rgb(u8, u8, u8),
    /// An xterm 256-color index: `38;5;n` (`48;5;n`).
    Indexed(u8),
    /// An ANSI slot 0–15 of the terminal scheme: `30+n` or `90+n−8`
    /// (`40+n`, `100+n−8`).
    Ansi(u8),
}

/// A `Style` resolved against one palette at one depth: the colors and
/// attributes a cell shows. Two cells look alike exactly when their paints
/// are equal, so a cell grid can compare them across a mode or depth switch,
/// which a token `Style` (the same in dark and light) cannot tell.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct Paint {
    pub fg: Ink,
    pub bg: Ink,
    /// `BOLD`, `DIM`, `ITALIC`, `UNDERLINE`, as in `Style`.
    pub attrs: u8,
}

/// The ink `color` would write; kept apart from it so the prompt path
/// (`write_sgr`) stays as it is. Test `paint_writes_what_write_sgr_writes`
/// holds the two to the same bytes for every token, kind, depth and mode.
fn ink(c: Color, p: &ResolvedPalette, depth: ColorDepth) -> Ink {
    let i = match c {
        Color::Default => return Ink::Default,
        Color::Text(i) | Color::Block(i) | Color::OnBlock(i) => i,
    };
    // A token outside the palette writes nothing, as in `color`.
    let Some(t) = p.tokens.get(usize::from(i)) else {
        return Ink::Default;
    };
    let (s, s256, ansi) = match c {
        Color::Block(_) => (t.bg, t.bg256, t.ansi),
        Color::OnBlock(_) => (t.on_block, t.on_block256, t.on_block_ansi),
        _ => (t.fg, t.fg256, t.ansi),
    };
    match depth {
        ColorDepth::TrueColor => Ink::Rgb(s.r, s.g, s.b),
        ColorDepth::Ansi256 => Ink::Indexed(s256),
        ColorDepth::Ansi16 => match ansi {
            AnsiSlot::Default => Ink::Default,
            AnsiSlot::Slot(n) => Ink::Ansi(n),
        },
    }
}

/// `style` resolved against `p` at `depth`.
pub fn paint(style: Style, p: &ResolvedPalette, depth: ColorDepth) -> Paint {
    Paint {
        fg: ink(style.fg, p, depth),
        bg: ink(style.bg, p, depth),
        attrs: style.attrs,
    }
}

fn write_ink(ink: Ink, bg: bool, w: &mut Buf<'_>) {
    let base = if bg { 40 } else { 30 };
    let _ = match ink {
        Ink::Default => Ok(()),
        Ink::Rgb(r, g, b) => write!(w, ";{};2;{r};{g};{b}", base + 8),
        Ink::Indexed(n) => write!(w, ";{};5;{n}", base + 8),
        Ink::Ansi(n) if n < 8 => write!(w, ";{}", base + u32::from(n)),
        Ink::Ansi(n) => write!(w, ";{}", base + 60 + u32::from(n - 8)),
    };
}

/// Appends one SGR that sets `paint` from scratch: the bytes `write_sgr`
/// writes for the style `paint` was resolved from.
pub fn write_paint(paint: Paint, out: &mut Vec<u8>) {
    out.extend_from_slice(b"\x1b[0");
    let mut w = Buf(out);
    for (bit, code) in [(BOLD, 1), (DIM, 2), (ITALIC, 3), (UNDERLINE, 4)] {
        if paint.attrs & bit != 0 {
            let _ = write!(w, ";{code}");
        }
    }
    write_ink(paint.fg, false, &mut w);
    write_ink(paint.bg, true, &mut w);
    out.push(b'm');
}

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

    fn sgr_in(mode: Mode, style: Style, depth: ColorDepth) -> Vec<u8> {
        let p = resolve_palette(&PaletteInput {
            mode,
            knobs: Knobs::default(),
            overrides: &[],
            roles: &[],
        })
        .unwrap();
        let mut v = Vec::new();
        write_sgr(style, &p, depth, &mut v);
        v
    }

    // 이것을 실패시키는 것: 배경 코드(48;2·48;5)가 38 로 나가거나 fg256 과 bg256 이 바뀌는 것, 배경이 표시용 대신 읽기용을 쓰는 것.
    // 기대 RGB 는 palette 시험이 따로 고정한 flavor A light 의 path(읽기용 446b9c, 표시용 5188cd).
    #[test]
    fn background_bytes() {
        let path = token_index("path").unwrap() as u16;
        let bg = Style {
            fg: Color::Default,
            bg: Color::Block(path),
            attrs: 0,
        };
        assert_eq!(
            sgr_in(Mode::Light, bg, ColorDepth::TrueColor),
            b"\x1b[0;48;2;81;136;205m"
        );
        let p = resolve_palette(&PaletteInput {
            mode: Mode::Light,
            knobs: Knobs::default(),
            overrides: &[],
            roles: &[],
        })
        .unwrap();
        let t = p.tokens[usize::from(path)];
        assert_ne!(t.fg256, t.bg256);
        assert_eq!(
            sgr_in(Mode::Light, bg, ColorDepth::Ansi256),
            alloc::format!("\x1b[0;48;5;{}m", t.bg256).into_bytes()
        );
        let both = Style {
            fg: Color::Text(path),
            bg: Color::Block(path),
            attrs: 0,
        };
        assert_eq!(
            sgr_in(Mode::Light, both, ColorDepth::TrueColor),
            b"\x1b[0;38;2;68;107;156;48;2;81;136;205m"
        );
    }

    // 이것을 실패시키는 것: 밝은 슬롯 8..=15 의 접두(90–97 글자, 100–107 배경) 어긋남과 0..=7 의 30–37·40–47.
    // dark 의 block.text 는 슬롯 0, muted 는 슬롯 8. light 의 block.text 는 터미널 기본 글자색이라(2026-10-13)
    // 코드가 없다. 슬롯 15를 쓰는 token은 이제 없다.
    #[test]
    fn ansi16_bright_background() {
        let bt = token_index("block.text").unwrap() as u16;
        let muted = token_index("muted").unwrap() as u16;
        let s = Style {
            fg: Color::Text(bt),
            bg: Color::Block(bt),
            attrs: 0,
        };
        assert_eq!(sgr_in(Mode::Light, s, ColorDepth::Ansi16), b"\x1b[0m");
        assert_eq!(sgr_in(Mode::Dark, s, ColorDepth::Ansi16), b"\x1b[0;30;40m");
        let s = Style {
            fg: Color::Text(muted),
            bg: Color::Block(muted),
            attrs: 0,
        };
        assert_eq!(sgr_in(Mode::Dark, s, ColorDepth::Ansi16), b"\x1b[0;90;100m");
    }

    // 이것을 실패시키는 것: OnBlock 을 깊이마다 고른 색(on_block·on_block256·on_block_ansi)이 아닌 값으로 쓰는 것.
    // light `fg` 블록은 밝은 글자(#f2f3fc), path 블록은 잉크(#090917), 16색은 둘 다 기본 글자색.
    #[test]
    fn on_block_bytes() {
        let fg = token_index("fg").unwrap() as u16;
        let path = token_index("path").unwrap() as u16;
        let on = |i| Style {
            fg: Color::OnBlock(i),
            bg: Color::Default,
            attrs: 0,
        };
        assert_eq!(
            sgr_in(Mode::Light, on(fg), ColorDepth::TrueColor),
            b"\x1b[0;38;2;242;243;252m"
        );
        assert_eq!(
            sgr_in(Mode::Light, on(path), ColorDepth::TrueColor),
            b"\x1b[0;38;2;9;9;23m"
        );
        assert_eq!(
            sgr_in(Mode::Light, on(fg), ColorDepth::Ansi256),
            b"\x1b[0;38;5;255m"
        );
        assert_eq!(
            sgr_in(Mode::Light, on(path), ColorDepth::Ansi16),
            b"\x1b[0m"
        );
    }

    // 이것을 실패시키는 것: dark 블록 글자 바이트가 바뀌는 것. 모든 token·깊이에서 OnBlock 이 예전의
    // `Text(block.text)`와 같은 바이트를 쓴다.
    #[test]
    fn dark_block_text_bytes_unchanged() {
        let bt = token_index("block.text").unwrap() as u16;
        for i in 0..crate::color::palette::TOKENS.len() as u16 {
            for depth in [
                ColorDepth::TrueColor,
                ColorDepth::Ansi256,
                ColorDepth::Ansi16,
            ] {
                let new = Style {
                    fg: Color::OnBlock(i),
                    bg: Color::Block(i),
                    attrs: 0,
                };
                let old = Style {
                    fg: Color::Text(bt),
                    ..new
                };
                assert_eq!(
                    sgr_in(Mode::Dark, new, depth),
                    sgr_in(Mode::Dark, old, depth),
                    "{i} {depth:?}"
                );
            }
        }
    }

    // 이것을 실패시키는 것: RESET 바이트가 바뀌는 것, 빈 Style 의 SGR 이 RESET 과 달라지는 것.
    #[test]
    fn reset_bytes() {
        assert_eq!(RESET, b"\x1b[0m");
        assert_eq!(sgr(Style::default(), ColorDepth::TrueColor), RESET);
    }

    // 이것을 실패시키는 것: `ink`가 `color`와 다른 색을 고르는 것(Block에 fg를, OnBlock에 bg를 쓰는 것,
    // 256에 fg256 대신 bg256, 16색 밝은 슬롯의 90·100 접두, 기본 슬롯에 코드를 쓰는 것), 속성 번호가 어긋나는 것.
    // 두 모드의 모든 token × 네 종류(글자·배경 둘 다) × 세 깊이 × 속성 16가지를 write_sgr 바이트와 맞춘다.
    #[test]
    fn paint_writes_what_write_sgr_writes() {
        let n = crate::color::palette::TOKENS.len() as u16;
        let kinds = |i| {
            [
                Color::Default,
                Color::Text(i),
                Color::Block(i),
                Color::OnBlock(i),
            ]
        };
        for mode in [Mode::Dark, Mode::Light] {
            let p = resolve_palette(&PaletteInput {
                mode,
                knobs: Knobs::default(),
                overrides: &[],
                roles: &[],
            })
            .unwrap();
            for i in 0..n {
                // The background token is another one, so fg and bg differ.
                let j = (i + 1) % n;
                for depth in [
                    ColorDepth::TrueColor,
                    ColorDepth::Ansi256,
                    ColorDepth::Ansi16,
                ] {
                    for fg in kinds(i) {
                        for bg in kinds(j) {
                            for attrs in 0..16u8 {
                                let s = Style { fg, bg, attrs };
                                let (mut want, mut got) = (Vec::new(), Vec::new());
                                write_sgr(s, &p, depth, &mut want);
                                write_paint(paint(s, &p, depth), &mut got);
                                assert_eq!(got, want, "{mode:?} {s:?} {depth:?}");
                            }
                        }
                    }
                }
            }
        }
    }

    // 이것을 실패시키는 것: 색 없음과 기본 슬롯 token을 다른 값으로 푸는 것(기본 배경이 기본으로 읽히지 않는다),
    // 모드를 바꿔도 같은 paint가 나오는 것(칸 비교가 다시 그리기를 놓친다), 깊이를 무시하는 것.
    #[test]
    fn paint_tells_modes_and_depths_apart() {
        let pal = |mode| {
            resolve_palette(&PaletteInput {
                mode,
                knobs: Knobs::default(),
                overrides: &[],
                roles: &[],
            })
            .unwrap()
        };
        let (dark, light) = (pal(Mode::Dark), pal(Mode::Light));
        let path = token_index("path").unwrap() as u16;
        let s = Style {
            fg: Color::OnBlock(path),
            bg: Color::Block(path),
            attrs: BOLD,
        };
        assert_ne!(
            paint(s, &dark, ColorDepth::TrueColor),
            paint(s, &light, ColorDepth::TrueColor)
        );
        assert_ne!(
            paint(s, &dark, ColorDepth::TrueColor),
            paint(s, &dark, ColorDepth::Ansi256)
        );
        assert_eq!(
            paint(Style::default(), &dark, ColorDepth::TrueColor),
            Paint::default()
        );
        // light block.text is the terminal's own color in 16 colors.
        let bt = token_index("block.text").unwrap() as u16;
        let on_default = Style {
            fg: Color::Text(bt),
            ..Style::default()
        };
        assert_eq!(
            paint(on_default, &light, ColorDepth::Ansi16).fg,
            Ink::Default
        );
    }
}
