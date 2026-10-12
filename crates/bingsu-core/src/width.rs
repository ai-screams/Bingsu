//! Width profile (spec section 3 "폭 프로필"). Widths are counted per
//! extended grapheme cluster in terminal cells; alignment is guaranteed only
//! when the terminal draws the same way as the profile.
use crate::sanitize::{in_ranges, range_index};
use crate::ucd::{EMOJI_PRESENTATION, EXTENDED_PICTOGRAPHIC, WIDTH_CLASS};
use unicode_segmentation::UnicodeSegmentation;

/// Unicode version of the width and sanitize tables (shown by `doctor`).
pub use crate::ucd::UNICODE_VERSION;

/// `width.ambiguous` and `width.emoji`, each 1 or 2.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WidthProfile {
    ambiguous: u8,
    emoji: u8,
}

impl WidthProfile {
    /// Default profile: ambiguous 1 cell, emoji 2 cells.
    pub const DEFAULT: Self = Self {
        ambiguous: 1,
        emoji: 2,
    };

    pub const fn new(ambiguous: u8, emoji: u8) -> Option<Self> {
        match (ambiguous, emoji) {
            (1 | 2, 1 | 2) => Some(Self { ambiguous, emoji }),
            _ => None,
        }
    }
    pub const fn ambiguous(self) -> u8 {
        self.ambiguous
    }
    pub const fn emoji(self) -> u8 {
        self.emoji
    }
}

/// Why a grapheme got its width, for `config check` (M3) and `explain` (M7).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WidthSource {
    Table,
    Emoji,
    /// Private use area: the icon table decides (src/icons.rs). A glyph not
    /// in the table is 1 cell and gets a `config check` warning.
    PrivateUse,
    /// Unassigned code point: the profile default (1 cell, or 2 in a range
    /// whose East Asian Width default is W), with a `config check` warning.
    Unknown,
}

fn class(cp: u32) -> u8 {
    range_index(WIDTH_CLASS, cp, |&(lo, hi, _)| (lo, hi)).map_or(0, |i| WIDTH_CLASS[i].2)
}

pub(crate) fn is_private_use(cp: u32) -> bool {
    (0xE000..=0xF8FF).contains(&cp)
        || (0xF0000..=0xFFFFD).contains(&cp)
        || (0x100000..=0x10FFFD).contains(&cp)
}

/// Cells of one extended grapheme cluster `g` (non-empty, already
/// sanitized). The width is that of its first code point, except:
/// emoji presentation (Emoji_Presentation=Yes without VS15, VS16 after an
/// Extended_Pictographic or a keycap base, a ZWJ
/// sequence that starts with an Extended_Pictographic; regional indicators
/// are Emoji_Presentation, so a flag pair and a lone one both) takes
/// `emoji` cells; a cluster whose first code point is a
/// combining mark (no base) or a ZWJ (nothing to join) takes 0; private use takes `pua_width`.
pub fn grapheme_width(
    g: &str,
    p: WidthProfile,
    pua_width: impl Fn(char) -> Option<u8>,
) -> (u8, WidthSource) {
    let mut chars = g.chars();
    let Some(first) = chars.next() else {
        return (0, WidthSource::Table);
    };
    let cp = first as u32;
    if cp == 0x200D {
        // A cluster that starts with ZWJ draws nothing.
        return (0, WidthSource::Table);
    }
    let (mut vs15, mut vs16, mut zwj) = (false, false, false);
    for c in chars {
        match c {
            '\u{FE0E}' => vs15 = true,
            '\u{FE0F}' => vs16 = true,
            '\u{200D}' => zwj = true,
            _ => {}
        }
    }
    if !vs15 {
        // Only VS16 and ZWJ clusters need the table; plain text skips the search.
        let pictographic = (vs16 || zwj) && in_ranges(EXTENDED_PICTOGRAPHIC, cp);
        // VS16 only turns an emoji or a keycap base (#, *, 0-9) into emoji
        // presentation; after any other base it is ignored.
        let vs16_applies = vs16 && (pictographic || matches!(first, '#' | '*' | '0'..='9'));
        if vs16_applies || in_ranges(EMOJI_PRESENTATION, cp) || (zwj && pictographic) {
            return (p.emoji, WidthSource::Emoji);
        }
    }
    if is_private_use(cp) {
        return (pua_width(first).unwrap_or(1), WidthSource::PrivateUse);
    }
    match class(cp) {
        1 => (2, WidthSource::Table),
        2 => (p.ambiguous, WidthSource::Table),
        3 => (0, WidthSource::Table),
        4 => (1, WidthSource::Unknown),
        _ => (1, WidthSource::Table),
    }
}

/// Total cells of `s` under `p`, private use glyphs 1 cell each.
pub fn str_width(s: &str, p: WidthProfile) -> u32 {
    s.graphemes(true)
        .map(|g| u32::from(grapheme_width(g, p, |_| None).0))
        .sum()
}

/// Byte length of the longest prefix of `s` that fits in `max` cells, and
/// its width. Never splits a grapheme.
pub fn fit_prefix(s: &str, max: u32, p: WidthProfile) -> (usize, u32) {
    let mut used = 0u32;
    for (i, g) in s.grapheme_indices(true) {
        let w = u32::from(grapheme_width(g, p, |_| None).0);
        if used + w > max {
            return (i, used);
        }
        used += w;
    }
    (s.len(), used)
}

/// Byte offset where the longest suffix of `s` that fits in `max` cells
/// starts, and its width. Never splits a grapheme.
pub fn fit_suffix(s: &str, max: u32, p: WidthProfile) -> (usize, u32) {
    let mut used = 0u32;
    for (i, g) in s.grapheme_indices(true).rev() {
        let w = u32::from(grapheme_width(g, p, |_| None).0);
        if used + w > max {
            return (i + g.len(), used);
        }
        used += w;
    }
    (0, used)
}

/// The ellipsis for truncation under `p`: `…` (U+2026, East Asian
/// Ambiguous) when it fits in `room` cells, else ASCII `.`, else nothing
/// (spec section 3 "한 줄 조립과 넘칠 때").
pub fn ellipsis(p: WidthProfile, room: u32) -> &'static str {
    if u32::from(p.ambiguous) <= room {
        "\u{2026}"
    } else if room >= 1 {
        "."
    } else {
        ""
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const A2: WidthProfile = match WidthProfile::new(2, 2) {
        Some(p) => p,
        None => panic!(),
    };
    const E1: WidthProfile = match WidthProfile::new(1, 1) {
        Some(p) => p,
        None => panic!(),
    };
    const D: WidthProfile = WidthProfile::DEFAULT;

    // 이것을 실패시키는 것: 버전이 다른 표(분할 crate와 다른 유니코드 버전).
    #[test]
    fn ucd_version_matches_segmentation() {
        assert_eq!(
            crate::ucd::UNICODE_VERSION,
            unicode_segmentation::UNICODE_VERSION
        );
    }

    // 이것을 실패시키는 것: 프로필 값 1·2 밖을 받는 것.
    #[test]
    fn profile_accepts_only_one_and_two() {
        // 이것을 실패시키는 것: 허용 집합이 3을 받거나 emoji 0을 받는 것(각각 별도 변이).
        assert!(WidthProfile::new(0, 2).is_none() && WidthProfile::new(1, 3).is_none());
        assert!(WidthProfile::new(3, 2).is_none() && WidthProfile::new(2, 0).is_none());
        assert_eq!(
            WidthProfile::new(2, 1).map(|p| (p.ambiguous(), p.emoji())),
            Some((2, 1))
        );
    }

    // 이것을 실패시키는 것: 넓은 글자·모호한 폭·결합 문자·조합형 한글·이모지 규칙 중 하나가 틀린 것.
    #[test]
    fn widths_by_rule() {
        let cases: &[(&str, WidthProfile, u32)] = &[
            ("abc", D, 3),
            ("한글", D, 4),
            // NFD Hangul (macOS file names): leading jamo is W, the rest join it.
            ("\u{1112}\u{1161}\u{11AB}\u{1100}\u{1173}\u{11AF}", D, 4),
            ("e\u{0301}", D, 1),
            ("\u{0301}", D, 0),
            // 이것을 실패시키는 것: 맨 앞 ZWJ 분기 제거(표에서 NARROW라 1칸이 됨).
            ("\u{200D}", D, 0),
            ("\u{200D}a", D, 1),
            // 이것을 실패시키는 것: VS16 갈래에서 바탕 검사(Extended_Pictographic 또는 키캡 바탕) 삭제.
            // 이것을 실패시키는 것: ZWJ 플래그 무시(VS16 없는 Extended_Pictographic ZWJ 시퀀스).
            ("\u{2764}\u{200D}\u{1F525}", D, 2),
            ("a\u{FE0F}", D, 1),
            ("1\u{FE0F}\u{20E3}", D, 2),
            ("#\u{FE0F}", D, 2),
            // 프로필 값이다. 터미널은 0으로 그릴 수 있다. 정제 범위를 넓히면 바뀐다.
            ("\u{115F}", D, 2),
            ("\u{1160}", D, 1),
            ("\u{3164}", D, 2),
            ("\u{FFA0}", D, 1),
            ("\u{2065}", D, 1),
            // 이것을 실패시키는 것: ZWJ 조건에서 Extended_Pictographic 검사 제거.
            ("a\u{200D}", D, 1),
            ("\u{2026}", D, 1),
            ("\u{2026}", A2, 2),
            ("\u{2500}\u{2500}\u{2500}", A2, 6),
            ("\u{FFFD}", A2, 2),
            ("\u{276F}", A2, 1),
            ("\u{1F600}", D, 2),
            ("\u{1F600}", E1, 1),
            ("\u{2764}", D, 1),
            ("\u{2764}\u{FE0F}", D, 2),
            ("\u{2764}\u{FE0F}\u{FE0E}", D, 1),
            ("\u{1F3F3}\u{FE0F}\u{200D}\u{1F308}", D, 2),
            ("\u{1F468}\u{200D}\u{1F469}\u{200D}\u{1F467}", D, 2),
            ("\u{1F1F0}\u{1F1F7}", D, 2),
            ("\u{1F1F0}", D, 2),
            ("\u{E0B0}", A2, 1),
            ("\u{2FFF0}", D, 2),
            ("\u{40000}", D, 1),
            ("\u{E0080}", D, 1),
        ];
        for (s, p, want) in cases {
            assert_eq!(str_width(s, *p), *want, "{s:?} {p:?}");
        }
    }

    // 이것을 실패시키는 것: 사설 영역 세 범위 중 하나를 빼는 것, 아이콘 표 값을 무시하는 것.
    #[test]
    fn private_use_asks_the_icon_table() {
        for cp in [
            '\u{E000}',
            '\u{F8FF}',
            '\u{F0000}',
            '\u{FFFFD}',
            '\u{100000}',
            '\u{10FFFD}',
        ] {
            let g = cp.to_string();
            assert_eq!(
                grapheme_width(&g, D, |_| Some(2)),
                (2, WidthSource::PrivateUse),
                "{cp:?}"
            );
            assert_eq!(
                grapheme_width(&g, D, |_| None),
                (1, WidthSource::PrivateUse),
                "{cp:?}"
            );
        }
        for cp in ["\u{D7FF}", "\u{F900}", "\u{FFFFE}"] {
            assert_ne!(
                grapheme_width(cp, D, |_| Some(2)).1,
                WidthSource::PrivateUse,
                "{cp:?}"
            );
        }
    }

    // 이것을 실패시키는 것: Emoji 또는 Unknown 갈래가 Table을 돌려주는 것, 맨 앞 ZWJ의 source 변경.
    #[test]
    fn width_source_is_pinned() {
        let w = |g: &str| grapheme_width(g, D, |_| Some(2));
        assert_eq!(w("a"), (1, WidthSource::Table));
        assert_eq!(w("\u{AC00}"), (2, WidthSource::Table));
        assert_eq!(w("\u{0301}"), (0, WidthSource::Table));
        assert_eq!(w("\u{1F600}"), (2, WidthSource::Emoji));
        assert_eq!(w("\u{2764}\u{FE0F}"), (2, WidthSource::Emoji));
        assert_eq!(w("\u{E0B0}"), (2, WidthSource::PrivateUse));
        assert_eq!(w("\u{2065}"), (1, WidthSource::Unknown));
        assert_eq!(w("\u{200D}"), (0, WidthSource::Table));
    }

    // 이것을 실패시키는 것: pua_width에 실제 첫 글자가 아닌 값을 넘기는 것.
    #[test]
    fn private_use_callback_gets_the_glyph() {
        let f = |c: char| match c {
            '\u{E0B0}' => Some(2),
            '\u{E0B1}' => Some(1),
            _ => None,
        };
        assert_eq!(
            grapheme_width("\u{E0B0}", D, f),
            (2, WidthSource::PrivateUse)
        );
        assert_eq!(
            grapheme_width("\u{E0B1}", D, f),
            (1, WidthSource::PrivateUse)
        );
        assert_eq!(
            grapheme_width("\u{E0B2}", D, f),
            (1, WidthSource::PrivateUse)
        );
        assert_eq!(
            grapheme_width("\u{E0B0}\u{0301}", D, f),
            (2, WidthSource::PrivateUse)
        );
    }

    // 이것을 실패시키는 것: fit_prefix/fit_suffix를 상수로 바꾸는 것, 가장 긴 접두/접미를 고르지 않는 것.
    // "ab한c": 바이트 a0 b1 한2..5 c5, len 6, 칸 1 1 2 1.
    #[test]
    fn fit_picks_the_longest() {
        let s = "ab\u{D55C}c";
        let prefix = [
            (0, (0, 0)),
            (1, (1, 1)),
            (2, (2, 2)),
            (3, (2, 2)),
            (4, (5, 4)),
            (5, (6, 5)),
            (9, (6, 5)),
        ];
        for (max, want) in prefix {
            assert_eq!(fit_prefix(s, max, D), want, "prefix {max}");
        }
        let suffix = [
            (0, (6, 0)),
            (1, (5, 1)),
            (2, (5, 1)),
            (3, (2, 3)),
            (4, (1, 4)),
            (5, (0, 5)),
            (9, (0, 5)),
        ];
        for (max, want) in suffix {
            assert_eq!(fit_suffix(s, max, D), want, "suffix {max}");
        }
        assert_eq!(fit_prefix("", 3, D), (0, 0));
        assert_eq!(fit_suffix("", 3, D), (0, 0));
    }

    // 이것을 실패시키는 것: 공개 함수의 반환값을 상수로 바꾸는 것(str_width 0, ellipsis "", ambiguous()/emoji() 고정).
    #[test]
    fn accessors_and_str_width_are_not_constants() {
        assert_eq!(str_width("abc", D), 3);
        assert_eq!(str_width("", D), 0);
        assert_eq!(
            (A2.ambiguous(), A2.emoji(), E1.ambiguous(), E1.emoji()),
            (2, 2, 1, 1)
        );
        assert_eq!(WidthProfile::DEFAULT, WidthProfile::new(1, 2).unwrap());
        assert_eq!(WidthProfile::new(1, 1), Some(E1));
    }

    // 이것을 실패시키는 것: 잘라 낸 결과가 칸 상한을 넘거나 grapheme 가운데를 자르는 것.
    #[test]
    fn fit_never_splits_or_overflows() {
        let s = "a\u{1F468}\u{200D}\u{1F469}b한e\u{0301}";
        for max in 0..10 {
            let (end, w) = fit_prefix(s, max, D);
            assert!(w <= max && s.is_char_boundary(end));
            assert_eq!(str_width(&s[..end], D), w);
            let (start, w2) = fit_suffix(s, max, D);
            assert!(w2 <= max);
            assert_eq!(str_width(&s[start..], D), w2);
        }
        assert_eq!(fit_prefix(s, 2, D), (1, 1));
        assert_eq!(fit_prefix(s, 3, D), (12, 3));
    }

    // 이것을 실패시키는 것: 1칸만 남았을 때 ambiguous=2에서 `…`를 쓰는 것(스펙 "생략 기호도 폭 프로필로").
    #[test]
    fn ellipsis_by_profile() {
        assert_eq!(ellipsis(D, 1), "\u{2026}");
        assert_eq!(ellipsis(A2, 1), ".");
        assert_eq!(ellipsis(A2, 2), "\u{2026}");
        assert_eq!(ellipsis(D, 0), "");
    }
}
