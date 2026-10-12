//! Icons by name (ADR-0009: themes name icons, never code points) and the
//! glyph width table for private use code points (spec section 3 "폭
//! 프로필", open question "아이콘 세트별 글리프와 폭 표"). The width is the
//! cells a terminal advances, which for a Nerd Font glyph is 1 whatever the
//! font draws (UNVERIFIED per terminal; `doctor` measures with CPR in M7).
//! Glyph choices are provisional until the M7 preset review.
use crate::width::{WidthProfile, is_private_use, str_width};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum IconSet {
    Nerd,
    Light,
    Unicode,
    Ascii,
}

impl IconSet {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "nerd" => Some(Self::Nerd),
            "light" => Some(Self::Light),
            "unicode" => Some(Self::Unicode),
            "ascii" => Some(Self::Ascii),
            _ => None,
        }
    }
    const fn next(self) -> Option<Self> {
        match self {
            Self::Nerd => Some(Self::Light),
            Self::Light => Some(Self::Unicode),
            Self::Unicode => Some(Self::Ascii),
            Self::Ascii => None,
        }
    }
}

/// Separators, heads and tails are exactly one cell (spec section 3).
/// A `OneCell` glyph is never empty in any set and its ASCII form is one
/// byte. A `Glyph` may be empty in a set that does not draw it (the
/// non-nerd sets of `git.branch` and `readonly`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IconKind {
    OneCell,
    Glyph,
}

/// Fields are private so an `Icon` only comes from the built-in `ICONS`
/// table, whose invariants the tests pin.
#[derive(Debug)]
pub struct Icon {
    name: &'static str,
    kind: IconKind,
    /// Glyph per set, in IconSet order: nerd, light, unicode, ascii.
    glyphs: [&'static str; 4],
}

impl Icon {
    pub const fn name(&self) -> &'static str {
        self.name
    }
    pub const fn kind(&self) -> IconKind {
        self.kind
    }
    pub const fn glyph(&self, set: IconSet) -> &'static str {
        self.glyphs[set as usize]
    }
}

const fn i(name: &'static str, kind: IconKind, glyphs: [&'static str; 4]) -> Icon {
    Icon { name, kind, glyphs }
}
use IconKind::{Glyph, OneCell};

/// Sorted by name (binary search; test `icons_sorted_and_ascii_complete`).
#[rustfmt::skip]
pub const ICONS: &[Icon] = &[
    i("char.err", OneCell, ["\u{2717}", "\u{2717}", "\u{2717}", "!"]),
    i("char.ok", OneCell, ["\u{276F}", "\u{276F}", "\u{276F}", ">"]),
    i("char.vicmd", OneCell, ["\u{276E}", "\u{276E}", "\u{276E}", "<"]),
    i("fill.dot", OneCell, ["\u{00B7}", "\u{00B7}", "\u{00B7}", "."]),
    i("fill.line", OneCell, ["\u{2500}", "\u{2500}", "\u{2500}", "-"]),
    i("fill.space", OneCell, [" ", " ", " ", " "]),
    i("frame.bottom", Glyph, ["\u{2570}\u{2500}", "\u{2570}\u{2500}", "\u{2570}\u{2500}", "+-"]),
    i("frame.top", Glyph, ["\u{256D}\u{2500}", "\u{256D}\u{2500}", "\u{256D}\u{2500}", "+-"]),
    i("git.ahead", Glyph, ["\u{21E1}", "\u{21E1}", "\u{21E1}", "^"]),
    i("git.behind", Glyph, ["\u{21E3}", "\u{21E3}", "\u{21E3}", "v"]),
    i("git.branch", Glyph, ["\u{E0A0}", "", "", ""]),
    i("git.conflicted", Glyph, ["=", "=", "=", "="]),
    i("git.modified", Glyph, ["!", "!", "!", "!"]),
    i("git.staged", Glyph, ["+", "+", "+", "+"]),
    i("git.stash", Glyph, ["$", "$", "$", "$"]),
    i("git.untracked", Glyph, ["?", "?", "?", "?"]),
    i("readonly", Glyph, ["\u{F023}", "", "", ""]),
    i("sep.flat", OneCell, [" ", " ", " ", " "]),
    i("sep.round.l", OneCell, ["\u{E0B6}", "\u{E0B6}", "\u{25C0}", "<"]),
    i("sep.round.r", OneCell, ["\u{E0B4}", "\u{E0B4}", "\u{25B6}", ">"]),
    i("sep.slant.l", OneCell, ["\u{E0BA}", "\u{E0BA}", "\u{25C0}", "<"]),
    i("sep.slant.r", OneCell, ["\u{E0BC}", "\u{E0BC}", "\u{25B6}", ">"]),
    i("sep.triangle.l", OneCell, ["\u{E0B2}", "\u{E0B2}", "\u{25C0}", "<"]),
    i("sep.triangle.r", OneCell, ["\u{E0B0}", "\u{E0B0}", "\u{25B6}", ">"]),
];

pub fn lookup(name: &str) -> Option<&'static Icon> {
    ICONS
        .binary_search_by(|ic| ic.name.cmp(name))
        .ok()
        .map(|i| &ICONS[i])
}

/// Cells for a private use code point that the icon table uses (1), or
/// None for one it does not know and for any char outside the private use
/// areas (1 cell plus a warning, src/width.rs).
/// Every set is searched: a set may carry a PUA glyph that the others lack.
pub fn pua_width(c: char) -> Option<u8> {
    pua_width_in(ICONS, c)
}

/// `pua_width` over an explicit table, so a test can build a table whose PUA
/// glyph sits in one set only. Only single code point glyphs match.
fn pua_width_in(table: &[Icon], c: char) -> Option<u8> {
    if !is_private_use(c as u32) {
        return None;
    }
    let mut buf = [0u8; 4];
    let s: &str = c.encode_utf8(&mut buf);
    table.iter().any(|ic| ic.glyphs.contains(&s)).then_some(1)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Resolved {
    pub text: &'static str,
    pub width: u8,
    /// The set actually used when the requested one broke the one-cell rule
    /// under the profile (ADR-0009 automatic fallback; `config check` shows
    /// it from M3).
    pub fell_back_to: Option<IconSet>,
}

/// The glyph for `icon` in `set` under `p`. A one-cell icon whose glyph is
/// not exactly one cell under `p` (an East Asian Ambiguous glyph with
/// `ambiguous = 2`) falls back to the next set; the ASCII set always fits.
pub fn resolve(icon: &Icon, set: IconSet, p: WidthProfile) -> Resolved {
    let mut s = set;
    loop {
        let text = icon.glyphs[s as usize];
        let width = str_width(text, p);
        let ok = icon.kind == IconKind::Glyph || width == 1;
        if ok {
            return Resolved {
                text,
                width: u8::try_from(width).unwrap_or(u8::MAX),
                fell_back_to: (s != set).then_some(s),
            };
        }
        match s.next() {
            Some(n) => s = n,
            None => {
                // Not reached for the built-in table: every ASCII one-cell
                // glyph is 1 cell (test `one_cell_icons_are_one_cell_everywhere`).
                return Resolved {
                    text,
                    width: u8::try_from(width).unwrap_or(u8::MAX),
                    fell_back_to: (s != set).then_some(s),
                };
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL: [IconSet; 4] = [
        IconSet::Nerd,
        IconSet::Light,
        IconSet::Unicode,
        IconSet::Ascii,
    ];

    // 이것을 실패시키는 것: 이름순이 아닌 표(이진 탐색이 놓침), 비었거나 ASCII가 아닌 ascii 글리프,
    // 1칸이 아닌 ascii 한 칸 아이콘, 어느 세트에서든 빈 한 칸 글리프, 같은 이름이 아닌 항목을 돌려주는 lookup.
    #[test]
    fn icons_sorted_and_ascii_complete() {
        assert!(ICONS.windows(2).all(|w| w[0].name < w[1].name));
        for ic in ICONS {
            let a = ic.glyphs[IconSet::Ascii as usize];
            assert!(a.bytes().all(|b| (0x20..=0x7E).contains(&b)), "{}", ic.name);
            assert!(!ic.glyphs[IconSet::Nerd as usize].is_empty(), "{}", ic.name);
            for g in ic.glyphs {
                assert!(!g.chars().any(crate::sanitize::is_removed), "{}", ic.name);
            }
            if ic.kind == IconKind::OneCell {
                assert_eq!(a.len(), 1, "{}", ic.name);
                for g in ic.glyphs {
                    assert!(!g.is_empty(), "{}", ic.name);
                }
            }
            assert_eq!(lookup(ic.name).map(|f| f.name), Some(ic.name));
        }
        assert!(lookup("sep.nope").is_none());
        assert!(lookup("").is_none());
    }

    // 이것을 실패시키는 것: 사슬 매핑 하나를 바꾸는 것(역행은 무한 루프가 아니라 여기서 FAILED).
    #[test]
    fn next_maps_each_set_to_the_following_one() {
        assert_eq!(IconSet::Nerd.next(), Some(IconSet::Light));
        assert_eq!(IconSet::Light.next(), Some(IconSet::Unicode));
        assert_eq!(IconSet::Unicode.next(), Some(IconSet::Ascii));
        assert_eq!(IconSet::Ascii.next(), None);
    }

    // 이것을 실패시키는 것: 사슬 끝 분기가 요청 세트가 Ascii일 때도 fell_back_to를 채우는 것.
    #[test]
    fn chain_end_reports_no_fallback_when_ascii_was_asked() {
        let a2 = WidthProfile::new(2, 2).unwrap();
        let bad = Icon {
            name: "probe",
            kind: IconKind::OneCell,
            glyphs: ["\u{2500}"; 4],
        };
        let r = resolve(&bad, IconSet::Ascii, a2);
        assert_eq!((r.text, r.width, r.fell_back_to), ("\u{2500}", 2, None));
        let r = resolve(&bad, IconSet::Unicode, a2);
        assert_eq!(r.fell_back_to, Some(IconSet::Ascii));
    }

    // 이것을 실패시키는 것: 이름을 잘못 해석하는 parse, 세트 순서(사슬 색인)를 바꾸는 enum 순서.
    #[test]
    fn icon_set_parse_and_order() {
        for (s, set, idx) in [
            ("nerd", IconSet::Nerd, 0),
            ("light", IconSet::Light, 1),
            ("unicode", IconSet::Unicode, 2),
            ("ascii", IconSet::Ascii, 3),
        ] {
            assert_eq!(IconSet::parse(s), Some(set));
            assert_eq!(set as usize, idx);
        }
        for bad in ["", "Nerd", "nerd ", "unknown"] {
            assert_eq!(IconSet::parse(bad), None, "{bad:?}");
        }
    }

    // 이것을 실패시키는 것: ambiguous=2에서 2칸이 된 한 칸 아이콘을 그대로 쓰는 것,
    // 폴백이 필요 없는데 폴백하는 것.
    #[test]
    fn one_cell_icons_fall_back_under_ambiguous_two() {
        let a2 = WidthProfile::new(2, 2).unwrap();
        let fill = lookup("fill.line").unwrap();
        assert_eq!(
            resolve(fill, IconSet::Nerd, WidthProfile::DEFAULT),
            Resolved {
                text: "\u{2500}",
                width: 1,
                fell_back_to: None
            }
        );
        assert_eq!(
            resolve(fill, IconSet::Nerd, a2),
            Resolved {
                text: "-",
                width: 1,
                fell_back_to: Some(IconSet::Ascii)
            }
        );
        let tri = lookup("sep.triangle.r").unwrap();
        assert_eq!(resolve(tri, IconSet::Nerd, a2).fell_back_to, None);
        assert_eq!(resolve(tri, IconSet::Unicode, a2).text, ">");
        let frame = lookup("frame.top").unwrap();
        assert_eq!(resolve(frame, IconSet::Nerd, a2).width, 4);
    }

    // 이것을 실패시키는 것: 사슬 순서(nerd, light, unicode, ascii)를 바꾸거나 한 단계를 건너뛰는 next,
    // 내려간 세트가 아닌 값을 담는 fell_back_to, 뒤로(위 세트로) 올라가는 사슬.
    #[test]
    fn fallback_chain_visits_sets_in_order() {
        let a2 = WidthProfile::new(2, 2).unwrap();
        let wide = "\u{2500}"; // 2 cells under ambiguous = 2
        let probe = |g: [&'static str; 4]| Icon {
            name: "probe",
            kind: IconKind::OneCell,
            glyphs: g,
        };
        let r = resolve(&probe([wide, "l", "u", "a"]), IconSet::Nerd, a2);
        assert_eq!((r.text, r.fell_back_to), ("l", Some(IconSet::Light)));
        let r = resolve(&probe([wide, wide, "u", "a"]), IconSet::Nerd, a2);
        assert_eq!((r.text, r.fell_back_to), ("u", Some(IconSet::Unicode)));
        let r = resolve(&probe([wide, wide, wide, "a"]), IconSet::Nerd, a2);
        assert_eq!((r.text, r.fell_back_to), ("a", Some(IconSet::Ascii)));
        // Starting at Unicode never looks at the sets above it.
        let r = resolve(&probe(["n", "l", wide, "a"]), IconSet::Unicode, a2);
        assert_eq!((r.text, r.fell_back_to), ("a", Some(IconSet::Ascii)));
        // A glyph that fits is used as is, whichever set was asked for.
        let r = resolve(&probe(["n", "l", "u", "a"]), IconSet::Light, a2);
        assert_eq!((r.text, r.fell_back_to), ("l", None));
    }

    // 이것을 실패시키는 것: 어떤 세트·프로필에서든 한 칸 아이콘이 1칸이 아닌 채로 나오는 것,
    // 기본 프로필에서 폴백하는 것.
    #[test]
    fn one_cell_icons_are_one_cell_everywhere() {
        let a2 = WidthProfile::new(2, 2).unwrap();
        for ic in ICONS.iter().filter(|ic| ic.kind == IconKind::OneCell) {
            for set in ALL {
                let d = resolve(ic, set, WidthProfile::DEFAULT);
                assert_eq!((d.width, d.fell_back_to), (1, None), "{} {set:?}", ic.name);
                assert_eq!(d.text, ic.glyphs[set as usize]);
                let r = resolve(ic, set, a2);
                assert_eq!(r.width, 1, "{} {set:?}", ic.name);
            }
        }
    }

    // 이것을 실패시키는 것: 표에 있는 Nerd Font 글리프를 모른다고 하거나 모르는 PUA를 안다고 하는 것.
    #[test]
    fn pua_width_knows_table_glyphs_only() {
        assert_eq!(pua_width('\u{E0B0}'), Some(1));
        assert_eq!(pua_width('\u{E0A0}'), Some(1));
        assert_eq!(pua_width('\u{E0C0}'), None);
        // Multi code point glyphs are not PUA entries.
        assert_eq!(pua_width('\u{2570}'), None);
        // Table glyphs outside the private use areas are not PUA entries.
        assert_eq!(pua_width('!'), None);
        assert_eq!(pua_width('\u{2500}'), None);
    }

    // 이것을 실패시키는 것: glyphs[0](nerd)만 보는 판독. light·unicode·ascii 칸에만 있는 PUA도 안다.
    #[test]
    fn pua_width_reads_every_set() {
        let probe = |g: [&'static str; 4]| Icon {
            name: "probe",
            kind: IconKind::Glyph,
            glyphs: g,
        };
        for slot in 0..4 {
            let mut g = ["", "", "", ""];
            g[slot] = "\u{E100}";
            let table = [probe(g)];
            assert_eq!(pua_width_in(&table, '\u{E100}'), Some(1), "slot {slot}");
            assert_eq!(pua_width_in(&table, '\u{E101}'), None, "slot {slot}");
        }
    }
}
