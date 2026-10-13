//! Color tokens, flavor A and the render-free palette resolution (spec
//! section 2 "색 token과 색 표기", ADR-0004, ADR-0005, ADR-0006, ADR-0007,
//! ADR-0016). `resolve_palette` is the one function the prompt and the
//! generators (sub-project 5) share.
use super::math::{
    Oklch, OklchQ, Srgb8, clamp_chroma, contrast_milli, nearest_256, oklch_q, oklch_to_linear,
    srgb8_to_oklch_q, to_srgb8, xterm,
};
use super::notation::ColorSpec;
use alloc::vec::Vec;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Dark,
    Light,
}

/// Where a token's ANSI color comes from in `color = "ansi"` mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AnsiSlot {
    /// The terminal's default foreground or background (SGR 39 / 49).
    Default,
    Slot(u8),
}

/// A prompt token: name, palette color it points to in each mode, and its
/// ANSI slot in each mode. Text drawn in a token uses the read tier in light
/// mode (ADR-0006); block backgrounds use the display tier.
#[derive(Debug)]
pub struct TokenDef {
    pub name: &'static str,
    pub dark: &'static str,
    pub light: &'static str,
    pub ansi: [AnsiSlot; 2],
}

const fn tk(
    name: &'static str,
    dark: &'static str,
    light: &'static str,
    d: AnsiSlot,
    l: AnsiSlot,
) -> TokenDef {
    TokenDef {
        name,
        dark,
        light,
        ansi: [d, l],
    }
}
use AnsiSlot::{Default as Df, Slot as S};

/// Prompt tokens, sorted by name. Names from the palette study (design
/// brief) plus the ones the built-in segments need; provisional until the
/// M3 schema and the M7 preset review.
pub const TOKENS: &[TokenDef] = &[
    // Light 16 colors: the terminal's default foreground. No slot of flavor
    // A light reaches 4.5:1 on slots 1–6 (the default text color comes
    // closest, about 3.2–3.6:1), and in 16-color mode the colors come from
    // the terminal's own scheme, so the contrast depends on it.
    tk("block.text", "neutral.crust", "neutral.ink", S(0), Df),
    tk("duration", "accent.yellow", "accent.yellow", S(3), S(3)),
    tk("fg", "neutral.text", "neutral.text", Df, Df),
    tk("git.ahead", "accent.teal", "accent.teal", S(6), S(6)),
    tk("git.behind", "accent.teal", "accent.teal", S(6), S(6)),
    tk("git.branch", "accent.mauve", "accent.mauve", S(5), S(5)),
    tk("git.conflicted", "accent.red", "accent.red", S(1), S(1)),
    tk("git.dirty", "accent.peach", "accent.peach", S(3), S(3)),
    tk("git.staged", "accent.green", "accent.green", S(2), S(2)),
    tk("host", "accent.pink", "accent.pink", S(5), S(5)),
    tk("jobs", "accent.teal", "accent.teal", S(6), S(6)),
    tk("muted", "neutral.overlay", "neutral.overlay", S(8), S(8)),
    tk("path", "accent.blue", "accent.blue", S(4), S(4)),
    tk("prompt.err", "accent.red", "accent.red", S(1), S(1)),
    tk("prompt.ok", "accent.green", "accent.green", S(2), S(2)),
    tk("readonly", "accent.red", "accent.red", S(1), S(1)),
    tk("status", "accent.red", "accent.red", S(1), S(1)),
    tk("venv", "accent.yellow", "accent.yellow", S(3), S(3)),
];

/// Reserved token prefixes (spec section 2): names under them are not
/// prompt tokens yet.
pub const RESERVED_PREFIXES: &[&str] = &["term.ansi.", "syntax.", "diff."];

pub fn token_index(name: &str) -> Option<usize> {
    TOKENS.binary_search_by(|t| t.name.cmp(name)).ok()
}

/// Knobs of ADR-0016 step 2. `None` keeps the flavor value.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Knobs {
    pub hue: Option<f64>,
    pub accent_l: Option<f64>,
    pub accent_c: Option<f64>,
}

#[derive(Clone, Copy, Debug)]
pub struct PaletteInput<'a> {
    pub mode: Mode,
    pub knobs: Knobs,
    /// ADR-0016 step 3: a palette color name (`accent.blue`) or a token
    /// name (`git.dirty`) and its new value.
    pub overrides: &'a [(&'a str, ColorSpec)],
    /// ADR-0016 step 4: token name to palette color name.
    pub roles: &'a [(&'a str, &'a str)],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResolvedToken {
    /// Text color (read tier).
    pub fg: Srgb8,
    /// Block background (display tier).
    pub bg: Srgb8,
    /// The colors actually shown (after gamut limiting) as OKLCH; colors
    /// given as hex, 256 or ANSI are converted back from their sRGB.
    pub fg_oklch: OklchQ,
    pub bg_oklch: OklchQ,
    /// 256-color approximations of `fg` and `bg`, computed here once.
    pub fg256: u8,
    pub bg256: u8,
    pub ansi: AnsiSlot,
    /// Text color on this token's block, picked once here: `block.text`,
    /// or in light mode, when `block.text` is not set by the user, the
    /// terminal background color if it contrasts more with `bg`.
    pub on_block: Srgb8,
    pub on_block256: u8,
    /// Always `block.text`'s slot: 16-color mode does not pick.
    pub on_block_ansi: AnsiSlot,
    /// Chroma was lowered to fit sRGB.
    pub clipped: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PaletteWarning {
    /// Text token on the terminal background below 4.5:1 (thousandths).
    TextContrast {
        token: usize,
        milli: u32,
    },
    /// A token's block text (`on_block`) on its block background below 4.5:1.
    BlockContrast {
        token: usize,
        milli: u32,
    },
    Clipped {
        token: usize,
    },
    /// A token's block background on the terminal background below 3:1
    /// (non-text marks, CLAUDE.md design rule 2).
    MarkContrast {
        token: usize,
        milli: u32,
    },
    /// The terminal background (`neutral.base`) was lowered to fit sRGB.
    BackgroundClipped,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PaletteError {
    UnknownName,
    Reserved,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedPalette {
    /// Same order as TOKENS.
    pub tokens: Vec<ResolvedToken>,
    pub background: Srgb8,
    pub warnings: Vec<PaletteWarning>,
}

impl ResolvedPalette {
    pub fn get(&self, name: &str) -> Option<&ResolvedToken> {
        token_index(name).map(|i| &self.tokens[i])
    }
}

const NEUTRALS: [&str; 7] = [
    "crust", "base", "surface0", "surface1", "overlay", "subtext", "text",
];
const ACCENTS: [(&str, f64); 8] = [
    ("red", 15.0),
    ("peach", 55.0),
    ("yellow", 92.0),
    ("green", 145.0),
    ("teal", 185.0),
    ("blue", 255.0),
    ("mauve", 305.0),
    ("pink", 350.0),
];

/// Flavor A palette color `name` (`neutral.*`, `accent.*`, `bright.*`) in
/// `mode` with `knobs`, display tier unless `read`.
fn flavor_a(name: &str, mode: Mode, k: Knobs, read: bool) -> Option<Oklch> {
    let nh = k.hue.unwrap_or(280.0);
    let (group, item) = name.split_once('.')?;
    match group {
        // Dark text on light blocks (2026-10-13): light `block.text`. The
        // same in both modes, so it can be overridden in either.
        "neutral" if item == "ink" => Some(Oklch {
            l: 0.15,
            c: 0.03,
            h: nh,
        }),
        "neutral" => {
            let i = NEUTRALS.iter().position(|n| *n == item)?;
            let (l, c) = match mode {
                Mode::Dark => (
                    [0.19, 0.235, 0.29, 0.345, 0.56, 0.76, 0.91][i],
                    [0.03, 0.03, 0.03, 0.03, 0.025, 0.02, 0.018][i],
                ),
                Mode::Light => (
                    [0.925, 0.965, 0.905, 0.86, 0.58, 0.45, 0.33][i],
                    [0.014, 0.012, 0.014, 0.016, 0.03, 0.03, 0.03][i],
                ),
            };
            Some(Oklch { l, c, h: nh })
        }
        "accent" => {
            let h = ACCENTS.iter().find(|a| a.0 == item)?.1;
            let (l, c) = match (mode, read) {
                (Mode::Dark, _) => (k.accent_l.unwrap_or(0.76), k.accent_c.unwrap_or(0.12)),
                // Teal's display tier is C 0.1092, the most sRGB holds at L
                // 0.62 H 185 (shown #009b8f either way), so the default
                // palette reports no clipping; the exception to ADR-0004
                // item 3 is recorded there (2026-10-13).
                (Mode::Light, false) => (
                    k.accent_l.unwrap_or(0.62),
                    k.accent_c
                        .unwrap_or(if item == "teal" { 0.1092 } else { 0.12 }),
                ),
                (Mode::Light, true) => (0.52, 0.09),
            };
            Some(Oklch { l, c, h })
        }
        "bright" if item == "overlay" => Some(match mode {
            Mode::Dark => Oklch {
                l: 0.62,
                c: 0.025,
                h: nh,
            },
            Mode::Light => Oklch {
                l: 0.52,
                c: 0.03,
                h: nh,
            },
        }),
        "bright" => {
            let h = ACCENTS.iter().find(|a| a.0 == item)?.1;
            // Design brief 2026-10-01: bright at L±0.05 limited to the common
            // sRGB chroma (dark L 0.81 C 0.095, light L 0.57 C 0.10).
            Some(match mode {
                Mode::Dark => Oklch {
                    l: 0.81,
                    c: 0.095,
                    h,
                },
                Mode::Light => Oklch {
                    l: 0.57,
                    c: 0.10,
                    h,
                },
            })
        }
        _ => None,
    }
}

/// ANSI 16 slots of flavor A (palette study; light 0, 7, 8, 15 per ADR-0007).
pub fn ansi_color(slot: u8, mode: Mode, k: Knobs) -> Srgb8 {
    const DARK: [&str; 16] = [
        "neutral.surface1",
        "accent.red",
        "accent.green",
        "accent.yellow",
        "accent.blue",
        "accent.pink",
        "accent.teal",
        "neutral.subtext",
        "bright.overlay",
        "bright.red",
        "bright.green",
        "bright.yellow",
        "bright.blue",
        "bright.pink",
        "bright.teal",
        "neutral.text",
    ];
    let name = match (mode, slot) {
        (Mode::Light, 0) => "neutral.subtext",
        (Mode::Light, 7) => "neutral.surface1",
        (Mode::Light, 15) => "neutral.surface0",
        _ => DARK[usize::from(slot & 15)],
    };
    let c = flavor_a(name, mode, k, false).unwrap_or(Oklch {
        l: 0.5,
        c: 0.0,
        h: 0.0,
    });
    from_oklch(c).0
}

/// A color as shown: sRGB, its OKLCH and whether chroma was lowered.
type Shown = (Srgb8, OklchQ, bool);

fn from_oklch(c: Oklch) -> Shown {
    let (c, clipped) = clamp_chroma(c);
    (to_srgb8(oklch_to_linear(c)), oklch_q(c), clipped)
}

fn from_srgb(s: Srgb8) -> Shown {
    (s, srgb8_to_oklch_q(s), false)
}

fn spec_to_shown(s: ColorSpec, mode: Mode, k: Knobs) -> Shown {
    match s {
        ColorSpec::Oklch(c) => from_oklch(c),
        ColorSpec::Rgb(c) => from_srgb(c),
        ColorSpec::Index256(i) => from_srgb(xterm(i)),
        ColorSpec::Ansi(i) => from_srgb(ansi_color(i, mode, k)),
    }
}

/// Settings to the resolved token table, without rendering anything.
/// Order: flavor and knobs, overrides, role reassignment (ADR-0016).
pub fn resolve_palette(input: &PaletteInput<'_>) -> Result<ResolvedPalette, PaletteError> {
    let check = |name: &str| {
        if RESERVED_PREFIXES.iter().any(|p| name.starts_with(p)) {
            Err(PaletteError::Reserved)
        } else {
            Ok(())
        }
    };
    for (name, _) in input.overrides {
        check(name)?;
        if token_index(name).is_none() && flavor_a(name, input.mode, input.knobs, false).is_none() {
            return Err(PaletteError::UnknownName);
        }
    }
    for (token, color) in input.roles {
        check(token)?;
        if token_index(token).is_none() || flavor_a(color, input.mode, input.knobs, false).is_none()
        {
            return Err(PaletteError::UnknownName);
        }
    }
    let color_of = |name: &str, read: bool| -> Shown {
        // Last override of a palette color wins.
        if let Some((_, s)) = input.overrides.iter().rev().find(|(n, _)| *n == name) {
            return spec_to_shown(*s, input.mode, input.knobs);
        }
        from_oklch(
            flavor_a(name, input.mode, input.knobs, read).unwrap_or(Oklch {
                l: 0.5,
                c: 0.0,
                h: 0.0,
            }),
        )
    };
    let (background, _, bg_clipped) = color_of("neutral.base", false);
    let mut tokens = Vec::with_capacity(TOKENS.len());
    let mut warnings = Vec::new();
    if bg_clipped {
        warnings.push(PaletteWarning::BackgroundClipped);
    }
    for (i, t) in TOKENS.iter().enumerate() {
        let ansi = t.ansi[input.mode as usize];
        // ADR-0016: a role reassignment (step 4) beats a color override of
        // the token itself (step 3); palette-name overrides apply to the
        // color the role picks.
        let role = input.roles.iter().rev().find(|(n, _)| *n == t.name);
        let token_override = input.overrides.iter().rev().find(|(n, _)| *n == t.name);
        let ((fg, fo, c1), (bg, bo, c2)) = match (role, token_override) {
            (None, Some((_, s))) => {
                let c = spec_to_shown(*s, input.mode, input.knobs);
                (c, c)
            }
            _ => {
                let base = match input.mode {
                    Mode::Dark => t.dark,
                    Mode::Light => t.light,
                };
                let name = role.map_or(base, |r| r.1);
                (color_of(name, true), color_of(name, false))
            }
        };
        let r = ResolvedToken {
            fg,
            bg,
            fg_oklch: fo,
            bg_oklch: bo,
            fg256: nearest_256(fg),
            bg256: nearest_256(bg),
            ansi,
            clipped: c1 || c2,
            on_block: fg,
            on_block256: 0,
            on_block_ansi: ansi,
        };
        if r.clipped {
            warnings.push(PaletteWarning::Clipped { token: i });
        }
        tokens.push(r);
    }
    let bt = tokens[token_index("block.text").unwrap_or(0)];
    // Light blocks (display tier, L 0.62) take the dark ink of `block.text`
    // and a dark block (such as `fg`) the background color, whichever
    // contrasts more. A `block.text` the user set is used as is, and dark
    // keeps its one block text.
    let user_set = input.roles.iter().any(|r| r.0 == "block.text")
        || input.overrides.iter().any(|o| o.0 == "block.text");
    let light =
        (input.mode == Mode::Light && !user_set).then(|| (background, nearest_256(background)));
    for (i, t) in tokens.iter_mut().enumerate() {
        (t.on_block, t.on_block256, t.on_block_ansi) = (bt.fg, bt.fg256, bt.ansi);
        if TOKENS[i].name == "block.text" {
            continue;
        }
        let mut m = contrast_milli(bt.fg, t.bg);
        if let Some((c, c256)) = light {
            let lm = contrast_milli(c, t.bg);
            if lm > m {
                (m, t.on_block, t.on_block256) = (lm, c, c256);
            }
        }
        let tm = contrast_milli(t.fg, background);
        if tm < 4_500 {
            warnings.push(PaletteWarning::TextContrast {
                token: i,
                milli: tm,
            });
        }
        if m < 4_500 {
            warnings.push(PaletteWarning::BlockContrast { token: i, milli: m });
        }
        let m = contrast_milli(t.bg, background);
        if m < 3_000 {
            warnings.push(PaletteWarning::MarkContrast { token: i, milli: m });
        }
    }
    Ok(ResolvedPalette {
        tokens,
        background,
        warnings,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::color::notation::parse_color;

    fn input(mode: Mode) -> PaletteInput<'static> {
        PaletteInput {
            mode,
            knobs: Knobs::default(),
            overrides: &[],
            roles: &[],
        }
    }

    // 이것을 실패시키는 것: 이름순이 아닌 token 표, 예약 접두사 아래 이름.
    #[test]
    fn tokens_sorted_not_reserved() {
        assert!(TOKENS.windows(2).all(|w| w[0].name < w[1].name));
        assert!(
            TOKENS
                .iter()
                .all(|t| RESERVED_PREFIXES.iter().all(|p| !t.name.starts_with(p)))
        );
    }

    // 이것을 실패시키는 것: 내장 세그먼트의 역할(field::BUILTIN role)이 token 표에 없는 것.
    #[test]
    fn segment_roles_are_tokens() {
        for d in crate::field::BUILTIN {
            assert!(token_index(d.role).is_some(), "{}: {}", d.id, d.role);
        }
    }

    // 이것을 실패시키는 것: light 7·15번이 ADR-0007의 L(0.86·0.905)·palette study의 C에서 벗어나는 것.
    // ADR-0007의 hex(#ced0de·#dddfed)는 같은 공식으로 나오지 않는다(사용자 결정 2026-10-08: 공식이 원본, ADR-0007 hex를 고침).
    #[test]
    fn light_ansi_7_15_follow_adr_0007_lightness() {
        assert_eq!(
            ansi_color(7, Mode::Light, Knobs::default()),
            Srgb8 {
                r: 0xcf,
                g: 0xd0,
                b: 0xdc
            }
        );
        assert_eq!(
            ansi_color(15, Mode::Light, Knobs::default()),
            Srgb8 {
                r: 0xdd,
                g: 0xdf,
                b: 0xe9
            }
        );
    }

    // 이것을 실패시키는 것: dark 강조색 최저 대비가 ADR-0004의 7.4:1 근처에서 벗어나는 것(값 회귀).
    #[test]
    fn dark_flavor_contrast_floor() {
        let p = resolve_palette(&input(Mode::Dark)).unwrap();
        let min = TOKENS
            .iter()
            .zip(&p.tokens)
            .filter(|(t, _)| t.dark.starts_with("accent."))
            .map(|(_, r)| contrast_milli(r.fg, p.background))
            .min()
            .unwrap();
        assert!((7_300..=7_500).contains(&min), "{min}");
        // muted (overlay, L 0.56) is 3.56:1 on the background: below the text
        // rule, so no built-in segment uses it for text (user decision 2026-10-08).
        let muted = token_index("muted").unwrap();
        let text_warn: Vec<usize> = p
            .warnings
            .iter()
            .filter_map(|w| match w {
                PaletteWarning::TextContrast { token, .. } => Some(*token),
                _ => None,
            })
            .collect();
        assert_eq!(text_warn, [muted]);
    }

    // 이것을 실패시키는 것: 덮어쓰기·역할 재배정의 순서, 예약·모르는 이름을 받는 것.
    #[test]
    fn overrides_and_roles() {
        let ov = [("git.dirty", parse_color("#ff0000").unwrap())];
        let roles = [("path", "accent.mauve")];
        let p = resolve_palette(&PaletteInput {
            overrides: &ov,
            roles: &roles,
            ..input(Mode::Dark)
        })
        .unwrap();
        assert_eq!(p.get("git.dirty").unwrap().fg, Srgb8 { r: 255, g: 0, b: 0 });
        assert_eq!(p.get("path").unwrap().fg, p.get("git.branch").unwrap().fg);
        let ov = [("accent.blue", parse_color("#8fb8f0").unwrap())];
        let p = resolve_palette(&PaletteInput {
            overrides: &ov,
            ..input(Mode::Dark)
        })
        .unwrap();
        assert_eq!(
            p.get("path").unwrap().fg,
            Srgb8 {
                r: 0x8f,
                g: 0xb8,
                b: 0xf0
            }
        );
        let bad = [("diff.add", parse_color("#000000").unwrap())];
        assert_eq!(
            resolve_palette(&PaletteInput {
                overrides: &bad,
                ..input(Mode::Dark)
            }),
            Err(PaletteError::Reserved)
        );
        let bad = [("nope", parse_color("#000000").unwrap())];
        assert_eq!(
            resolve_palette(&PaletteInput {
                overrides: &bad,
                ..input(Mode::Dark)
            }),
            Err(PaletteError::UnknownName)
        );
        let bad = [("path", "accent.purple")];
        assert_eq!(
            resolve_palette(&PaletteInput {
                roles: &bad,
                ..input(Mode::Dark)
            }),
            Err(PaletteError::UnknownName)
        );
    }

    // 이것을 실패시키는 것: light에서 글자 token이 읽기용 단계를 쓰지 않는 것(ADR-0006).
    #[test]
    fn light_text_uses_read_tier() {
        let p = resolve_palette(&input(Mode::Light)).unwrap();
        let path = p.get("path").unwrap();
        assert_ne!(path.fg, path.bg);
        assert!(contrast_milli(path.fg, p.background) >= 4_500);
    }

    // Expected values were computed apart from this code (a Python script that
    // applies the palette study's flavor A formulas and the ANSI map, with
    // ADR-0007's light 0, 7, 8 and 15), not copied from this code's output.
    fn hex(v: u32) -> Srgb8 {
        Srgb8 {
            r: (v >> 16) as u8,
            g: (v >> 8) as u8,
            b: v as u8,
        }
    }

    fn pin(mode: Mode, table: &[(&str, u32, u32, AnsiSlot)]) {
        let p = resolve_palette(&input(mode)).unwrap();
        assert_eq!(table.len(), TOKENS.len());
        for (t, r) in table.iter().zip(&p.tokens) {
            assert_eq!(p.get(t.0), Some(r), "table order is TOKENS order");
            assert_eq!(
                (r.fg, r.bg, r.ansi),
                (hex(t.1), hex(t.2), t.3),
                "{:?} {}",
                mode,
                t.0
            );
        }
    }

    // 이것을 실패시키는 것: flavor A dark 의 어느 token 의 fg·bg·ANSI 슬롯이든 바뀌는 것(L·C·H, 지도, 슬롯).
    #[test]
    fn flavor_a_dark_table() {
        pin(
            Mode::Dark,
            &[
                ("block.text", 0x111221, 0x111221, S(0)),
                ("duration", 0xccae4e, 0xccae4e, S(3)),
                ("fg", 0xdee0ed, 0xdee0ed, Df),
                ("git.ahead", 0x3bcabb, 0x3bcabb, S(6)),
                ("git.behind", 0x3bcabb, 0x3bcabb, S(6)),
                ("git.branch", 0xc39dee, 0xc39dee, S(5)),
                ("git.conflicted", 0xf39098, 0xf39098, S(1)),
                ("git.dirty", 0xec9c63, 0xec9c63, S(3)),
                ("git.staged", 0x7fc581, 0x7fc581, S(2)),
                ("host", 0xea91bc, 0xea91bc, S(5)),
                ("jobs", 0x3bcabb, 0x3bcabb, S(6)),
                ("muted", 0x717383, 0x717383, S(8)),
                ("path", 0x7cb4fc, 0x7cb4fc, S(4)),
                ("prompt.err", 0xf39098, 0xf39098, S(1)),
                ("prompt.ok", 0x7fc581, 0x7fc581, S(2)),
                ("readonly", 0xf39098, 0xf39098, S(1)),
                ("status", 0xf39098, 0xf39098, S(1)),
                ("venv", 0xccae4e, 0xccae4e, S(3)),
            ],
        );
    }

    // 이것을 실패시키는 것: flavor A light 의 읽기용(fg)·표시용(bg) 단계나 슬롯이 바뀌는 것.
    #[test]
    fn flavor_a_light_table() {
        pin(
            Mode::Light,
            &[
                ("block.text", 0x090917, 0x090917, Df),
                ("duration", 0x7c6722, 0xa08318, S(3)),
                ("fg", 0x323445, 0x323445, Df),
                ("git.ahead", 0x087970, 0x009b8f, S(6)),
                ("git.behind", 0x087970, 0x009b8f, S(6)),
                ("git.branch", 0x755b93, 0x9772c0, S(5)),
                ("git.conflicted", 0x965258, 0xc3656f, S(1)),
                ("git.dirty", 0x905a33, 0xbd7138, S(3)),
                ("git.staged", 0x467748, 0x549957, S(2)),
                ("host", 0x8f5270, 0xbb6690, S(5)),
                ("jobs", 0x087970, 0x009b8f, S(6)),
                ("muted", 0x76798c, 0x76798c, S(8)),
                ("path", 0x446b9c, 0x5188cd, S(4)),
                ("prompt.err", 0x965258, 0xc3656f, S(1)),
                ("prompt.ok", 0x467748, 0x549957, S(2)),
                ("readonly", 0x965258, 0xc3656f, S(1)),
                ("status", 0x965258, 0xc3656f, S(1)),
                ("venv", 0x7c6722, 0xa08318, S(3)),
            ],
        );
    }

    // 이것을 실패시키는 것: 16색 표의 어느 칸이든 바뀌는 것(light 0·7·8·15 포함).
    #[test]
    fn ansi_tables() {
        let dark = [
            0x363849, 0xf39098, 0x7fc581, 0xccae4e, 0x7cb4fc, 0xea91bc, 0x3bcabb, 0xaeb0be,
            0x838595, 0xf8a8ad, 0x9ad29b, 0xd7bf78, 0x97c4fe, 0xf0a8ca, 0x73d5c9, 0xdee0ed,
        ];
        let light = [
            0x525466, 0xc3656f, 0x549957, 0xa08318, 0x5188cd, 0xbb6690, 0x009b8f, 0xcfd0dc,
            0x65677a, 0xaa5d64, 0x4f8751, 0x8d7526, 0x4d79b1, 0xa35e80, 0x038a7f, 0xdddfe9,
        ];
        for (k, (d, l)) in dark.iter().zip(&light).enumerate() {
            assert_eq!(
                ansi_color(k as u8, Mode::Dark, Knobs::default()),
                hex(*d),
                "dark {k}"
            );
            assert_eq!(
                ansi_color(k as u8, Mode::Light, Knobs::default()),
                hex(*l),
                "light {k}"
            );
        }
    }

    // 이것을 실패시키는 것: 역할 재배정이 같은 token 의 덮어쓰기에 지는 것(ADR-0016 4단계가 3단계보다 뒤).
    // 역할이 고른 팔레트 색에 걸린 이름 덮어쓰기는 그대로 적용된다.
    #[test]
    fn role_beats_token_override() {
        let ov = [
            ("git.dirty", parse_color("#ff0000").unwrap()),
            ("accent.blue", parse_color("#8fb8f0").unwrap()),
        ];
        let roles = [("git.dirty", "accent.blue")];
        let p = resolve_palette(&PaletteInput {
            overrides: &ov,
            roles: &roles,
            ..input(Mode::Dark)
        })
        .unwrap();
        let d = p.get("git.dirty").unwrap();
        assert_eq!((d.fg, d.bg), (hex(0x8fb8f0), hex(0x8fb8f0)));
    }

    // 이것을 실패시키는 것: OKLCH 가 색역 제한 전 값이거나 ×1e6 반올림이 아닌 것, 역산의 회색 규칙(h = 0).
    // 기대값: Python 으로 OKLab 을 1e-6 으로 반올림한 뒤 L, C, H 로 옮긴 값(#8fb8f0 은 773909 92052 256325914).
    #[test]
    fn oklch_of_shown_colors() {
        let p = resolve_palette(&input(Mode::Dark)).unwrap();
        let path = p.get("path").unwrap();
        assert_eq!(
            path.fg_oklch,
            OklchQ {
                l: 760_000,
                c: 120_000,
                h: 255_000_000
            }
        );
        // Light teal display tier is C 0.1092, inside sRGB (C 0.12 was cut to
        // 0.109263, the same #009b8f).
        let p = resolve_palette(&input(Mode::Light)).unwrap();
        assert_eq!(
            p.get("jobs").unwrap().bg_oklch,
            OklchQ {
                l: 620_000,
                c: 109_200,
                h: 185_000_000
            }
        );
        let ov = [
            ("path", parse_color("#8fb8f0").unwrap()),
            ("host", parse_color("244").unwrap()),
        ];
        let p = resolve_palette(&PaletteInput {
            overrides: &ov,
            ..input(Mode::Dark)
        })
        .unwrap();
        let path = p.get("path").unwrap();
        assert_eq!(
            path.fg_oklch,
            OklchQ {
                l: 773_909,
                c: 92_052,
                h: 256_325_914
            }
        );
        assert_eq!(path.bg_oklch, path.fg_oklch);
        // 244 is #808080 (gray): chroma 0 and hue 0.
        assert_eq!(
            p.get("host").unwrap().fg_oklch,
            OklchQ {
                l: 599_871,
                c: 0,
                h: 0
            }
        );
    }

    fn marks(p: &ResolvedPalette) -> Vec<(usize, u32)> {
        p.warnings
            .iter()
            .filter_map(|w| match w {
                PaletteWarning::MarkContrast { token, milli } => Some((*token, *milli)),
                _ => None,
            })
            .collect()
    }

    // 이것을 실패시키는 것: 비글자 3:1 검사의 경계(2994 는 경고, 3039 는 경고 아님)·검사 대상 token.
    // 3,000 을 2,900 이나 3,100 으로 바꾸면 한쪽이 틀린다. 기본 flavor A 는 dark·light 모두 경고가 없다.
    #[test]
    fn mark_contrast_boundary() {
        assert!(marks(&resolve_palette(&input(Mode::Dark)).unwrap()).is_empty());
        assert!(marks(&resolve_palette(&input(Mode::Light)).unwrap()).is_empty());
        let path = token_index("path").unwrap();
        let dim = [("path", parse_color("#686868").unwrap())];
        let p = resolve_palette(&PaletteInput {
            overrides: &dim,
            ..input(Mode::Dark)
        })
        .unwrap();
        assert_eq!(marks(&p), [(path, 2_994)]);
        let ok = [("path", parse_color("#696969").unwrap())];
        let p = resolve_palette(&PaletteInput {
            overrides: &ok,
            ..input(Mode::Dark)
        })
        .unwrap();
        assert!(marks(&p).is_empty());
    }

    fn on_block(p: &ResolvedPalette, name: &str) -> Srgb8 {
        p.get(name).unwrap().on_block
    }

    // 이것을 실패시키는 것: light 블록 글자를 자동으로 고르지 않는 것(BlockContrast 16건), 대비가 작은 쪽을
    // 고르는 것(`fg` 블록에 잉크), teal 표시 단계를 C 0.12로 되돌리는 것(Clipped 3건).
    // 남는 경고는 muted 글자 하나다(2026-10-08 결정, 3890).
    #[test]
    fn light_default_warns_only_muted_text() {
        let p = resolve_palette(&input(Mode::Light)).unwrap();
        let muted = token_index("muted").unwrap();
        assert_eq!(
            p.warnings,
            [PaletteWarning::TextContrast {
                token: muted,
                milli: 3_890
            }]
        );
        assert_eq!(on_block(&p, "path"), hex(0x090917));
        assert_eq!(on_block(&p, "fg"), p.background);
        for (t, r) in TOKENS.iter().zip(&p.tokens) {
            if t.name != "block.text" {
                assert!(contrast_milli(r.on_block, r.bg) >= 4_500, "{}", t.name);
            }
        }
    }

    // 이것을 실패시키는 것: 사용자가 바꾼 블록 색에 처음 고른 잉크를 그대로 두는 것(대비 비교를 빼는 것).
    // 어두운 #202060 블록은 밝은 글자, 밝은 #c0d0ff 블록은 잉크를 받는다.
    #[test]
    fn light_pick_follows_a_changed_block() {
        let ov = [
            ("path", parse_color("#202060").unwrap()),
            ("host", parse_color("#c0d0ff").unwrap()),
        ];
        let p = resolve_palette(&PaletteInput {
            overrides: &ov,
            ..input(Mode::Light)
        })
        .unwrap();
        assert_eq!(on_block(&p, "path"), p.background);
        assert_eq!(on_block(&p, "host"), hex(0x090917));
        for name in ["path", "host"] {
            let r = p.get(name).unwrap();
            assert!(contrast_milli(r.on_block, r.bg) >= 4_500, "{name}");
        }
        assert!(
            !p.warnings
                .iter()
                .any(|w| matches!(w, PaletteWarning::BlockContrast { .. }))
        );
    }

    // 이것을 실패시키는 것: 사용자가 정한 `block.text`(token 덮어쓰기 또는 역할 재배정)를 자동 선택으로
    // 덮는 것. 고른 색은 path 블록에서 자동 선택이라면 지는 중간 회색이고, 낮은 대비 경고가 그대로 나간다.
    #[test]
    fn light_explicit_block_text_is_kept() {
        let ov = [("block.text", parse_color("#606060").unwrap())];
        let roles = [("block.text", "neutral.subtext")];
        let path = token_index("path").unwrap();
        for (ov, roles) in [(&ov[..], &[][..]), (&[][..], &roles[..])] {
            let p = resolve_palette(&PaletteInput {
                overrides: ov,
                roles,
                ..input(Mode::Light)
            })
            .unwrap();
            let set = p.get("block.text").unwrap().fg;
            assert_ne!(set, p.background);
            for name in ["path", "fg", "host"] {
                assert_eq!(on_block(&p, name), set, "{name}");
            }
            assert!(p.warnings.iter().any(
                |w| matches!(w, PaletteWarning::BlockContrast { token, .. } if *token == path)
            ));
        }
    }

    // 이것을 실패시키는 것: dark에도 자동 선택을 거는 것. dark에서 다른 후보는 어두운 터미널 바탕이라,
    // 거의 검은 #000000 블록에서만 갈린다. dark 기본 출력이 바뀌지 않는다는 것은 flavor_a_dark_table과
    // sgr 시험이 바이트로 고정한다.
    #[test]
    fn dark_keeps_one_block_text() {
        let ov = [("path", parse_color("#000000").unwrap())];
        let p = resolve_palette(&PaletteInput {
            overrides: &ov,
            ..input(Mode::Dark)
        })
        .unwrap();
        let bt = p.get("block.text").unwrap();
        assert!(
            contrast_milli(p.background, hex(0)) > contrast_milli(bt.fg, hex(0)),
            "the mutant would pick the background here"
        );
        for r in &p.tokens {
            assert_eq!(
                (r.on_block, r.on_block256, r.on_block_ansi),
                (bt.fg, bt.fg256, bt.ansi)
            );
        }
        let d = resolve_palette(&input(Mode::Dark)).unwrap();
        let muted = token_index("muted").unwrap();
        assert_eq!(
            d.warnings,
            [
                PaletteWarning::TextContrast {
                    token: muted,
                    milli: 3_560
                },
                PaletteWarning::BlockContrast {
                    token: muted,
                    milli: 3_958
                }
            ]
        );
    }

    // 이것을 실패시키는 것: 256색 블록 글자를 고른 색이 아닌 `block.text`의 근사로 두는 것, 16색 슬롯을
    // 고른 색에서 가져오는 것(light `fg` 블록에 슬롯 15 → 밝은 바탕에 밝은 글자).
    #[test]
    fn light_pick_256_and_16() {
        let p = resolve_palette(&input(Mode::Light)).unwrap();
        let fg = p.get("fg").unwrap();
        assert_eq!(fg.on_block256, nearest_256(p.background));
        assert_ne!(fg.on_block256, p.get("block.text").unwrap().fg256);
        assert_eq!(fg.on_block_ansi, Df);
        assert_eq!(p.get("path").unwrap().on_block_ansi, Df);
    }

    // 이것을 실패시키는 것: teal의 C 0.1092가 사용자 knob(accent_c)을 이기는 것. knob 0.12면 다시 잘린다.
    #[test]
    fn teal_exception_yields_to_the_knob() {
        let p = resolve_palette(&PaletteInput {
            knobs: Knobs {
                accent_c: Some(0.12),
                ..Knobs::default()
            },
            ..input(Mode::Light)
        })
        .unwrap();
        assert!(p.get("jobs").unwrap().clipped);
        assert_eq!(p.get("jobs").unwrap().bg_oklch.c, 109_263);
    }

    // 이것을 실패시키는 것: neutral.base 덮어쓰기의 색역 제한을 알리지 않는 것, 제한이 없는데 알리는 것.
    #[test]
    fn background_clipped_warning() {
        assert!(
            !resolve_palette(&input(Mode::Dark))
                .unwrap()
                .warnings
                .contains(&PaletteWarning::BackgroundClipped)
        );
        let ov = [("neutral.base", parse_color("oklch(0.7 0.35 150)").unwrap())];
        let p = resolve_palette(&PaletteInput {
            overrides: &ov,
            ..input(Mode::Dark)
        })
        .unwrap();
        assert!(p.warnings.contains(&PaletteWarning::BackgroundClipped));
    }
}
