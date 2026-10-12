//! Color tokens, flavor A and the render-free palette resolution (spec
//! section 2 "색 token과 색 표기", ADR-0004, ADR-0005, ADR-0006, ADR-0007,
//! ADR-0016). `resolve_palette` is the one function the prompt and the
//! generators (sub-project 5) share.
use super::math::{Oklch, Srgb8, contrast_milli, nearest_256, oklch_to_srgb8, xterm};
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
    tk("block.text", "neutral.crust", "neutral.base", S(0), S(15)),
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
    /// 256-color approximations of `fg` and `bg`, computed here once.
    pub fg256: u8,
    pub bg256: u8,
    pub ansi: AnsiSlot,
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
    /// `block.text` on a token's block background below 4.5:1.
    BlockContrast {
        token: usize,
        milli: u32,
    },
    Clipped {
        token: usize,
    },
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
                (Mode::Light, false) => (k.accent_l.unwrap_or(0.62), k.accent_c.unwrap_or(0.12)),
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
    oklch_to_srgb8(c).0
}

fn spec_to_srgb(s: ColorSpec, mode: Mode, k: Knobs) -> (Srgb8, bool) {
    match s {
        ColorSpec::Oklch(c) => oklch_to_srgb8(c),
        ColorSpec::Rgb(c) => (c, false),
        ColorSpec::Index256(i) => (xterm(i), false),
        ColorSpec::Ansi(i) => (ansi_color(i, mode, k), false),
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
    let color_of = |name: &str, read: bool| -> (Srgb8, bool) {
        // Last override of a palette color wins.
        if let Some((_, s)) = input.overrides.iter().rev().find(|(n, _)| *n == name) {
            return spec_to_srgb(*s, input.mode, input.knobs);
        }
        let c = flavor_a(name, input.mode, input.knobs, read).unwrap_or(Oklch {
            l: 0.5,
            c: 0.0,
            h: 0.0,
        });
        oklch_to_srgb8(c)
    };
    let background = color_of("neutral.base", false).0;
    let mut tokens = Vec::with_capacity(TOKENS.len());
    let mut warnings = Vec::new();
    for (i, t) in TOKENS.iter().enumerate() {
        let ansi = t.ansi[input.mode as usize];
        let token_override = input.overrides.iter().rev().find(|(n, _)| *n == t.name);
        let r = if let Some((_, s)) = token_override {
            let (c, clipped) = spec_to_srgb(*s, input.mode, input.knobs);
            ResolvedToken {
                fg: c,
                bg: c,
                fg256: 0,
                bg256: 0,
                ansi,
                clipped,
            }
        } else {
            let base = match input.mode {
                Mode::Dark => t.dark,
                Mode::Light => t.light,
            };
            let name = input
                .roles
                .iter()
                .rev()
                .find(|(n, _)| *n == t.name)
                .map_or(base, |r| r.1);
            let (fg, c1) = color_of(name, true);
            let (bg, c2) = color_of(name, false);
            ResolvedToken {
                fg,
                bg,
                fg256: 0,
                bg256: 0,
                ansi,
                clipped: c1 || c2,
            }
        };
        let r = ResolvedToken {
            fg256: nearest_256(r.fg),
            bg256: nearest_256(r.bg),
            ..r
        };
        if r.clipped {
            warnings.push(PaletteWarning::Clipped { token: i });
        }
        tokens.push(r);
    }
    let block_text = tokens[token_index("block.text").unwrap_or(0)].fg;
    for (i, t) in tokens.iter().enumerate() {
        if TOKENS[i].name == "block.text" {
            continue;
        }
        let m = contrast_milli(t.fg, background);
        if m < 4_500 {
            warnings.push(PaletteWarning::TextContrast { token: i, milli: m });
        }
        let m = contrast_milli(block_text, t.bg);
        if m < 4_500 {
            warnings.push(PaletteWarning::BlockContrast { token: i, milli: m });
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
}
