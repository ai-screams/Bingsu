//! How many cells a terminal moves the cursor by for the characters
//! `bingsu doctor` writes as probes, and what that says about `width.ambiguous`
//! and `width.emoji`. Pure: the probes are a table, the measured cells go in,
//! the findings come out. Writing the characters and reading the cursor
//! position is the command's work.
//!
//! The cursor position report knows only how far the cursor moved. A glyph that
//! the font lacks still moves it, so this cannot say whether a Nerd Font is
//! installed.
use crate::width::WidthProfile;
use alloc::vec::Vec;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// Narrow ASCII: 1 cell on every terminal. When it is not, the method
    /// cannot be trusted.
    ControlNarrow,
    /// A Hangul syllable: 2 cells on every terminal that handles wide
    /// characters at all.
    ControlWide,
    /// East Asian Ambiguous: `width.ambiguous`.
    Ambiguous,
    /// Emoji presentation by default: `width.emoji`.
    Emoji,
    /// Text-default emoji made an emoji by U+FE0F: `width.emoji` too.
    Vs16,
    /// A zero-width-joiner sequence: bingsu counts one emoji width.
    Zwj,
    /// A flag (two regional indicators): one emoji width.
    Flag,
    /// A letter and a combining mark: 1 cell.
    Combining,
    /// A private use glyph of the icon table: 1 cell.
    Nerd,
}

#[derive(Clone, Copy, Debug)]
pub struct Probe {
    pub name: &'static str,
    pub text: &'static str,
    pub kind: Kind,
}

const fn p(name: &'static str, text: &'static str, kind: Kind) -> Probe {
    Probe { name, text, kind }
}

/// Written in this order, one after the other.
pub const PROBES: [Probe; 12] = [
    p("control-narrow", "a", Kind::ControlNarrow),
    p("control-wide", "\u{D55C}", Kind::ControlWide),
    p("ambiguous-box", "\u{2500}", Kind::Ambiguous),
    p("ambiguous-degree", "\u{00B0}", Kind::Ambiguous),
    p("ambiguous-arrow", "\u{2192}", Kind::Ambiguous),
    p("emoji-plain", "\u{1F600}", Kind::Emoji),
    p("emoji-vs16", "\u{2764}\u{FE0F}", Kind::Vs16),
    p("emoji-zwj", "\u{1F469}\u{200D}\u{1F4BB}", Kind::Zwj),
    p("emoji-flag", "\u{1F1F0}\u{1F1F7}", Kind::Flag),
    p("combining", "e\u{0301}", Kind::Combining),
    p("nerd-separator", "\u{E0B0}", Kind::Nerd),
    p("nerd-icon", "\u{F023}", Kind::Nerd),
];

/// Narrower than this the probes may wrap: about 20 cells are written.
pub const MIN_COLUMNS: u16 = 40;

/// The cells each probe moved the cursor by, in `PROBES` order.
pub type Cells = [u16; PROBES.len()];

fn cells_of(cells: &Cells, kind: Kind) -> Vec<u16> {
    PROBES
        .iter()
        .zip(cells)
        .filter(|(p, _)| p.kind == kind)
        .map(|(_, &c)| c)
        .collect()
}

/// A trustworthy measurement: the two controls moved the cursor 1 and 2 cells.
pub fn reliable(cells: &Cells) -> bool {
    cells_of(cells, Kind::ControlNarrow) == [1] && cells_of(cells, Kind::ControlWide) == [2]
}

/// What the terminal does differently from the settings, or from what
/// bingsu assumes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mismatch {
    /// The ambiguous characters agree on `measured` cells, not the configured.
    AmbiguousWidth { measured: u8, configured: u8 },
    /// The ambiguous characters do not all take the same number of cells.
    AmbiguousMixed,
    /// Emoji take `measured` cells, not the configured.
    EmojiWidth { measured: u8, configured: u8 },
    /// An emoji made by U+FE0F takes another number of cells than a plain one.
    Vs16Differs { plain: u16, vs16: u16 },
    /// A joined emoji sequence takes `cells`, not the configured emoji width.
    ZwjCells { cells: u16, expected: u8 },
    /// A flag takes `cells`, not the configured emoji width.
    FlagCells { cells: u16, expected: u8 },
    /// A letter with a combining mark takes `cells`, not 1.
    CombiningCells { cells: u16 },
    /// A private use glyph takes `cells`, not 1.
    NerdCells { cells: u16 },
}

/// The widths to set, when the measurement says so.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct Recommended {
    pub ambiguous: Option<u8>,
    pub emoji: Option<u8>,
}

fn one_or_two(v: u16) -> Option<u8> {
    match v {
        1 => Some(1),
        2 => Some(2),
        _ => None,
    }
}

/// `Some(v)` when every value is `v` and `v` is 1 or 2.
fn agreed(values: &[u16]) -> Option<u8> {
    let first = *values.first()?;
    values
        .iter()
        .all(|&v| v == first)
        .then(|| one_or_two(first))?
}

/// The widths the terminal draws with: ambiguous when all three ambiguous
/// probes agree, emoji from the plain emoji (a text-default emoji made an
/// emoji by U+FE0F is a separate mismatch).
pub fn recommended(cells: &Cells) -> Recommended {
    Recommended {
        ambiguous: agreed(&cells_of(cells, Kind::Ambiguous)),
        emoji: cells_of(cells, Kind::Emoji)
            .first()
            .and_then(|&v| one_or_two(v)),
    }
}

/// Everything that differs, in a fixed order. Empty: the terminal draws as the
/// settings say. Only for a `reliable` measurement.
pub fn mismatches(cells: &Cells, profile: WidthProfile) -> Vec<Mismatch> {
    let mut out = Vec::new();
    let ambiguous = cells_of(cells, Kind::Ambiguous);
    match agreed(&ambiguous) {
        Some(m) if m != profile.ambiguous() => out.push(Mismatch::AmbiguousWidth {
            measured: m,
            configured: profile.ambiguous(),
        }),
        Some(_) => {}
        None => out.push(Mismatch::AmbiguousMixed),
    }
    let plain = cells_of(cells, Kind::Emoji)[0];
    if let Some(m) = one_or_two(plain)
        && m != profile.emoji()
    {
        out.push(Mismatch::EmojiWidth {
            measured: m,
            configured: profile.emoji(),
        });
    }
    let vs16 = cells_of(cells, Kind::Vs16)[0];
    if vs16 != plain {
        out.push(Mismatch::Vs16Differs { plain, vs16 });
    }
    let expected = profile.emoji();
    let zwj = cells_of(cells, Kind::Zwj)[0];
    if zwj != u16::from(expected) {
        out.push(Mismatch::ZwjCells {
            cells: zwj,
            expected,
        });
    }
    let flag = cells_of(cells, Kind::Flag)[0];
    if flag != u16::from(expected) {
        out.push(Mismatch::FlagCells {
            cells: flag,
            expected,
        });
    }
    let combining = cells_of(cells, Kind::Combining)[0];
    if combining != 1 {
        out.push(Mismatch::CombiningCells { cells: combining });
    }
    if let Some(&bad) = cells_of(cells, Kind::Nerd).iter().find(|&&c| c != 1) {
        out.push(Mismatch::NerdCells { cells: bad });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // cells in PROBES order: a, 한, ─ ° →, 😀, ❤️, 👩‍💻, 🇰🇷, é, ,
    fn cells(amb: u16, emoji: u16) -> Cells {
        [1, 2, amb, amb, amb, emoji, emoji, emoji, emoji, 1, 1, 1]
    }

    // 이것을 실패시키는 것: 시험 글자 표의 개수·순서·종류가 바뀌어 `cells_of`가 엉뚱한 시험을 읽는 것.
    #[test]
    fn the_probe_table_has_the_expected_shape() {
        let count = |k| PROBES.iter().filter(|p| p.kind == k).count();
        assert_eq!(PROBES.len(), 12);
        assert_eq!(count(Kind::Ambiguous), 3);
        assert_eq!(count(Kind::Nerd), 2);
        for k in [
            Kind::ControlNarrow,
            Kind::ControlWide,
            Kind::Emoji,
            Kind::Vs16,
            Kind::Zwj,
            Kind::Flag,
            Kind::Combining,
        ] {
            assert_eq!(count(k), 1, "{k:?}");
        }
        let names: Vec<&str> = PROBES.iter().map(|p| p.name).collect();
        for (i, n) in names.iter().enumerate() {
            assert!(!names[..i].contains(n), "{n} twice");
        }
        // About 20 cells in all, well under MIN_COLUMNS.
        assert!(
            PROBES.iter().map(|p| p.text.chars().count()).sum::<usize>() < usize::from(MIN_COLUMNS)
        );
    }

    // 이것을 실패시키는 것: 통제 시험(1칸·2칸)이 틀렸는데 믿을 만하다고 하는 것.
    #[test]
    fn the_controls_decide_whether_to_trust_the_measurement() {
        assert!(reliable(&cells(1, 2)));
        let mut c = cells(1, 2);
        c[0] = 2;
        assert!(!reliable(&c));
        let mut c = cells(1, 2);
        c[1] = 1;
        assert!(!reliable(&c));
    }

    // 이것을 실패시키는 것: 세 모호 폭 시험이 일치하지 않는데 값을 추천하는 것, 이모지 폭을 VS16 시험에서 뽑는 것,
    // 1·2가 아닌 값을 추천하는 것.
    #[test]
    fn a_width_is_recommended_only_when_the_probes_agree() {
        let both = |a, e| Recommended {
            ambiguous: a,
            emoji: e,
        };
        assert_eq!(recommended(&cells(1, 2)), both(Some(1), Some(2)));
        assert_eq!(recommended(&cells(2, 1)), both(Some(2), Some(1)));
        let mut c = cells(1, 2);
        c[3] = 2;
        assert_eq!(recommended(&c).ambiguous, None);
        let mut c = cells(1, 2);
        c[6] = 1; // the VS16 emoji alone
        assert_eq!(recommended(&c).emoji, Some(2));
        let mut c = cells(1, 2);
        (c[2], c[3], c[4], c[5]) = (3, 3, 3, 3);
        assert_eq!(recommended(&c), both(None, None));
    }

    // 이것을 실패시키는 것: 설정과 같은 터미널에 불일치를 내는 것, 불일치 종류를 놓치는 것(모호 폭 다름·섞임, 이모지
    // 폭, VS16, ZWJ, 국기, 결합, Nerd), 기준을 설정 이모지 폭이 아니라 고정 2로 두는 것.
    #[test]
    fn every_difference_from_the_settings_is_found() {
        let default = WidthProfile::DEFAULT;
        assert_eq!(mismatches(&cells(1, 2), default), []);
        assert_eq!(
            mismatches(&cells(2, 2), default),
            [Mismatch::AmbiguousWidth {
                measured: 2,
                configured: 1
            }]
        );
        // The same terminal agrees with a profile that says 2.
        assert_eq!(
            mismatches(&cells(2, 2), WidthProfile::new(2, 2).unwrap()),
            []
        );
        let mut c = cells(1, 2);
        c[4] = 2;
        assert_eq!(mismatches(&c, default), [Mismatch::AmbiguousMixed]);
        // Emoji take 1 cell: every emoji probe follows, so only the width differs.
        assert_eq!(
            mismatches(&cells(1, 1), default),
            [
                Mismatch::EmojiWidth {
                    measured: 1,
                    configured: 2
                },
                Mismatch::ZwjCells {
                    cells: 1,
                    expected: 2
                },
                Mismatch::FlagCells {
                    cells: 1,
                    expected: 2
                },
            ]
        );
        assert_eq!(
            mismatches(&cells(1, 1), WidthProfile::new(1, 1).unwrap()),
            []
        );
        let mut c = cells(1, 2);
        (c[6], c[7], c[8], c[9], c[11]) = (1, 4, 4, 2, 2);
        let mut zero = cells(1, 2);
        zero[9] = 0;
        assert_eq!(
            mismatches(&zero, default),
            [Mismatch::CombiningCells { cells: 0 }]
        );
        assert_eq!(
            mismatches(&c, default),
            [
                Mismatch::Vs16Differs { plain: 2, vs16: 1 },
                Mismatch::ZwjCells {
                    cells: 4,
                    expected: 2
                },
                Mismatch::FlagCells {
                    cells: 4,
                    expected: 2
                },
                Mismatch::CombiningCells { cells: 2 },
                Mismatch::NerdCells { cells: 2 },
            ]
        );
    }
}
