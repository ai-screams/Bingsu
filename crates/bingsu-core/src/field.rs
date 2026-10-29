//! Field types and value states (spec section 4 "필드 타입과 값 상태", M2
//! types; the versioned schema is M3) and the public field names
//! of the built-in segments (spec section 4 "세그먼트 선언", confirmed in M3).
use crate::sanitize::sanitize_into_capped;
use crate::width::{WidthProfile, ellipsis_cells, grapheme_width};
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write as _;
use unicode_segmentation::UnicodeSegmentation;

/// The closed set of field types. Plugins cannot add structures.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FieldType {
    /// Sanitized text, at most `max_cells` cells (longer values are cut with
    /// an ellipsis when the value is made).
    Text {
        max_cells: u16,
    },
    /// u32 with a saturation flag, drawn `N+` when saturated (git budget).
    Count,
    Int,
    /// Milliseconds.
    Duration,
    /// Draws nothing; only conditional groups read it.
    Bool,
}

/// Text that went through sanitize and the length caps. The fields are
/// private: `Clean::new` (and so `Field::text`) is the only entry that makes
/// non-empty text (`Default` is the empty text), so no unsanitized text can
/// reach a Text field, a segment value or the shell (the single entry the
/// security table relies on). `cap` is the `max_cells` it was cut to, so a
/// value cut to 256 cells does not pass as a 16-cell field (`Field::fits`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Clean {
    text: String,
    cap: u16,
}

impl Clean {
    /// Sanitizes `raw` and, if it is wider than `max_cells` cells under `p`
    /// or longer than `max_cells * 4` bytes, cuts it at the longest grapheme
    /// boundary where the kept part plus the ellipsis that fits stays within
    /// both caps. The byte cap matters for a grapheme of many combining
    /// marks: one cell wide, any number of bytes.
    ///
    /// Sanitize stops only when what it keeps passes `max_cells * 4 + 16`
    /// bytes, so the work is bounded by the caps only for input that keeps
    /// that much. Input that keeps less is read to the end: all of it
    /// removed (1 MiB of ESC), or a short text followed by a long run of
    /// removed code points. The cut then stops at the first grapheme past a
    /// cap.
    pub fn new(raw: &[u8], max_cells: u16, p: WidthProfile) -> Self {
        // Stopping early gives the same result as sanitizing everything:
        // whether a grapheme boundary falls at byte i depends only on the
        // text before i and the code point at i (UAX #29 looks back, never
        // further ahead), so every boundary up to `max_cells * 4` is the same
        // in the prefix as in the full text, and the grapheme that crosses
        // that byte, read whole or not, ends past it and is cut. The 16 bytes
        // are a margin over the one code point the rule needs.
        let limit = usize::from(max_cells) * 4 + 16;
        let mut text = String::with_capacity(raw.len().min(limit + 4));
        sanitize_into_capped(raw, &mut text, limit);
        cut(&mut text, max_cells, p);
        Self {
            text,
            cap: max_cells,
        }
    }

    pub fn as_str(&self) -> &str {
        &self.text
    }
}

/// Cuts sanitized `text` as `Clean::new` describes, in one pass that stops at
/// the first grapheme over either cap.
fn cut(text: &mut String, max_cells: u16, p: WidthProfile) {
    let max = u32::from(max_cells);
    let max_bytes = usize::from(max_cells) * 4;
    let (e, ew) = ellipsis_cells(p, max);
    // The ellipsis fits both caps: it is chosen to fit `max` cells, and it
    // is at most 3 bytes, while any non-empty one needs `max >= 1` (the
    // ambiguous width is 1 or 2, `WidthProfile::new`).
    let (room, room_bytes) = (max - ew, max_bytes - e.len());
    let (mut used, mut keep) = (0u32, 0usize);
    for (i, g) in text.grapheme_indices(true) {
        let end = i + g.len();
        used += u32::from(grapheme_width(g, p, |_| None).0);
        if used > max || end > max_bytes {
            text.truncate(keep);
            text.push_str(e);
            return;
        }
        if used <= room && end <= room_bytes {
            keep = end;
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FieldValue {
    Text(Clean),
    Count {
        n: u32,
        saturated: bool,
    },
    Int(i64),
    Duration {
        ms: u64,
    },
    Bool(bool),
    /// The data has no value ("없음"), unlike `ValueState::Pending`.
    Absent,
}

/// Value state, separate from the data. `Stale` is reserved for
/// sub-project 2 and is not a variant yet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ValueState {
    Known,
    /// Not obtained before the deadline; drawn `?`.
    Pending,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Field {
    pub value: FieldValue,
    pub state: ValueState,
}

impl Field {
    pub const PENDING: Self = Self {
        value: FieldValue::Absent,
        state: ValueState::Pending,
    };
    pub const ABSENT: Self = Self {
        value: FieldValue::Absent,
        state: ValueState::Known,
    };

    pub fn known(value: FieldValue) -> Self {
        Self {
            value,
            state: ValueState::Known,
        }
    }

    /// A Text field made from untrusted bytes (`Clean::new`).
    pub fn text(raw: &[u8], max_cells: u16, p: WidthProfile) -> Self {
        Self::known(FieldValue::Text(Clean::new(raw, max_cells, p)))
    }

    /// Does this field type-check against `ty`? `Absent` fits every type; a
    /// Text fits only if it was cut to at most the declared `max_cells`.
    pub fn fits(&self, ty: FieldType) -> bool {
        match (&self.value, ty) {
            (FieldValue::Text(s), FieldType::Text { max_cells }) => s.cap <= max_cells,
            (FieldValue::Absent, _)
            | (FieldValue::Count { .. }, FieldType::Count)
            | (FieldValue::Int(_), FieldType::Int)
            | (FieldValue::Duration { .. }, FieldType::Duration)
            | (FieldValue::Bool(_), FieldType::Bool) => true,
            _ => false,
        }
    }

    /// Empty for a conditional group (see `template`): Absent, an empty
    /// Text, Count 0 and `false` are empty; Pending is not (it draws `?`).
    pub fn is_empty_for_group(&self) -> bool {
        if self.state == ValueState::Pending {
            return false;
        }
        match &self.value {
            FieldValue::Absent | FieldValue::Bool(false) => true,
            FieldValue::Text(s) => s.as_str().is_empty(),
            FieldValue::Count {
                n: 0,
                saturated: false,
            } => true,
            _ => false,
        }
    }

    /// Appends the drawn form: `?` when Pending, nothing when Absent or
    /// Bool, decimal for numbers (`N+` when saturated), a short duration.
    pub fn write_to(&self, out: &mut String) {
        if self.state == ValueState::Pending {
            out.push('?');
            return;
        }
        match &self.value {
            FieldValue::Text(s) => out.push_str(s.as_str()),
            FieldValue::Count { n, saturated } => {
                let _ = write!(out, "{n}");
                if *saturated {
                    out.push('+');
                }
            }
            FieldValue::Int(v) => {
                let _ = write!(out, "{v}");
            }
            FieldValue::Duration { ms } => write_duration(*ms, out),
            FieldValue::Bool(_) | FieldValue::Absent => {}
        }
    }
}

/// `850ms`, `2.3s` (tenths cut, not rounded), `1m5s`, `2h3m`, `4d5h`.
/// Integer arithmetic only, so every target prints the same.
pub fn write_duration(ms: u64, out: &mut String) {
    let s = ms / 1000;
    let _ = if ms < 1000 {
        write!(out, "{ms}ms")
    } else if s < 60 {
        write!(out, "{s}.{}s", (ms % 1000) / 100)
    } else if s < 3600 {
        write!(out, "{}m{}s", s / 60, s % 60)
    } else if s < 86_400 {
        write!(out, "{}h{}m", s / 3600, (s % 3600) / 60)
    } else {
        write!(out, "{}d{}h", s / 86_400, (s % 86_400) / 3600)
    };
}

#[derive(Debug)]
pub struct FieldDecl {
    pub name: &'static str,
    pub ty: FieldType,
}

/// Display contract of a built-in segment (no execution, permissions or
/// cost: sub-project 3). `role` is the color token for its text in plain
/// mode and its background in block mode.
#[derive(Debug)]
pub struct SegmentDecl {
    pub id: &'static str,
    pub role: &'static str,
    pub fields: &'static [FieldDecl],
}

const fn f(name: &'static str, ty: FieldType) -> FieldDecl {
    FieldDecl { name, ty }
}
const fn t(max_cells: u16) -> FieldType {
    FieldType::Text { max_cells }
}
use FieldType::{Bool, Count, Duration, Int};

/// Public builtin field names, including the git stage schema.
/// Names follow one rule: one concept of another tool, one field (starship
/// `git_status` variables ahead, behind, staged, modified, untracked,
/// conflicted, stashed). Sorted by id; fields sorted by name.
/// `git.no_repo` is a Known true discovery marker, with stage=A, partial=false,
/// empty display text and all repository fields Known Absent. It completes A
/// without a visible git segment. Hidden/None is not successful discovery.
/// Known branch text and Known commit text are mutually exclusive.
pub const BUILTIN: &[SegmentDecl] = &[
    SegmentDecl {
        id: "char",
        role: "prompt.ok",
        fields: &[f("failed", Bool), f("vicmd", Bool)],
    },
    SegmentDecl {
        id: "dir",
        role: "path",
        fields: &[f("in_repo", Bool), f("path", t(4096)), f("readonly", Bool)],
    },
    SegmentDecl {
        id: "duration",
        role: "duration",
        fields: &[f("ms", Duration)],
    },
    SegmentDecl {
        id: "git",
        role: "git.branch",
        fields: &[
            f("ahead", Count),
            f("behind", Count),
            f("branch", t(256)),
            f("commit", t(16)),
            f("conflicted", Count),
            f("detached", Bool),
            f("filtered", Bool),
            f("modified", Count),
            f("no_repo", Bool),
            f("operation", t(16)),
            f("partial", Bool),
            f("stage", t(1)),
            f("staged", Count),
            f("stash", Count),
            f("untracked", Count),
        ],
    },
    SegmentDecl {
        id: "host",
        role: "host",
        fields: &[
            f("name", t(64)),
            f("root", Bool),
            f("ssh", Bool),
            f("user", t(64)),
        ],
    },
    SegmentDecl {
        id: "jobs",
        role: "jobs",
        fields: &[f("count", Count)],
    },
    SegmentDecl {
        id: "status",
        role: "status",
        fields: &[f("code", Int), f("pipestatus", t(64)), f("signal", t(16))],
    },
    SegmentDecl {
        id: "time",
        role: "fg",
        fields: &[f("text", t(32))],
    },
    SegmentDecl {
        id: "venv",
        role: "venv",
        fields: &[f("name", t(64))],
    },
];

pub fn segment(id: &str) -> Option<&'static SegmentDecl> {
    BUILTIN
        .binary_search_by(|d| d.id.cmp(id))
        .ok()
        .map(|i| &BUILTIN[i])
}

impl SegmentDecl {
    pub fn field_index(&self, name: &str) -> Option<usize> {
        self.fields.binary_search_by(|d| d.name.cmp(name)).ok()
    }
}

/// Cap on a segment's display text, in cells under the default profile.
pub const VALUE_MAX_CELLS: u16 = 4096;

/// One segment's value as the renderer receives it: display text and one
/// field per declared field, in declaration order. The text is private so
/// that it can only be made through `Value::new`, which sanitizes it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Value {
    text: String,
    pub fields: Vec<Field>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ValueError {
    FieldCount { want: usize, got: usize },
    FieldType { index: usize },
}

impl Value {
    /// `raw` is untrusted (a branch name, an environment value): sanitized
    /// here (spec section 3 step 1) and cut to VALUE_MAX_CELLS cells and four
    /// times as many bytes, which bounds the work of every later step for a
    /// 1 MiB name.
    pub fn new(raw: &[u8], fields: Vec<Field>) -> Self {
        Self {
            text: Clean::new(raw, VALUE_MAX_CELLS, WidthProfile::DEFAULT).text,
            fields,
        }
    }

    pub fn text(&self) -> &str {
        &self.text
    }

    /// Checks the field list against `decl` (count and types).
    pub fn check(&self, decl: &SegmentDecl) -> Result<(), ValueError> {
        if self.fields.len() != decl.fields.len() {
            return Err(ValueError::FieldCount {
                want: decl.fields.len(),
                got: self.fields.len(),
            });
        }
        match self
            .fields
            .iter()
            .zip(decl.fields)
            .position(|(v, d)| !v.fits(d.ty))
        {
            Some(index) => Err(ValueError::FieldType { index }),
            None => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::width::str_width;

    fn drawn(fl: &Field) -> String {
        let mut s = String::new();
        fl.write_to(&mut s);
        s
    }

    fn clean(text: &str, cap: u16) -> FieldValue {
        FieldValue::Text(Clean {
            text: text.into(),
            cap,
        })
    }

    // 이것을 실패시키는 것: Pending을 `?` 아닌 것으로, 포화 Count를 `+` 없이, Absent·Bool을 글자로 그리는 것, Text·Duration을 그리지 않는 것.
    #[test]
    fn drawn_forms() {
        assert_eq!(drawn(&Field::PENDING), "?");
        assert_eq!(drawn(&Field::ABSENT), "");
        assert_eq!(
            drawn(&Field::known(FieldValue::Count {
                n: 42,
                saturated: true
            })),
            "42+"
        );
        assert_eq!(
            drawn(&Field::known(FieldValue::Count {
                n: 3,
                saturated: false
            })),
            "3"
        );
        assert_eq!(drawn(&Field::known(FieldValue::Int(-130))), "-130");
        assert_eq!(drawn(&Field::known(FieldValue::Bool(true))), "");
        assert_eq!(
            drawn(&Field::text(b"main", 8, WidthProfile::DEFAULT)),
            "main"
        );
        assert_eq!(
            drawn(&Field::known(FieldValue::Duration { ms: 65_000 })),
            "1m5s"
        );
    }

    // 이것을 실패시키는 것: 경계(999ms, 1s, 59.9s, 60s, 59m59s, 1h, 1d)에서 단위가 바뀌지 않거나 반올림하는 것.
    #[test]
    fn duration_boundaries() {
        for (ms, want) in [
            (0, "0ms"),
            (999, "999ms"),
            (1000, "1.0s"),
            (2399, "2.3s"),
            (59_999, "59.9s"),
            (60_000, "1m0s"),
            (65_000, "1m5s"),
            (3_600_000, "1h0m"),
            (86_399_999, "23h59m"),
            (3_599_999, "59m59s"),
            (86_400_000, "1d0h"),
            (u64::MAX, "213503982334d14h"),
        ] {
            let mut s = String::new();
            write_duration(ms, &mut s);
            assert_eq!(s, want, "{ms}");
        }
    }

    // 이것을 실패시키는 것: Text를 정제하지 않거나, 상한을 넘기거나, ambiguous=2에서 생략 기호 폭을 잘못 세는 것.
    #[test]
    fn text_field_sanitizes_and_caps() {
        let p2 = WidthProfile::new(2, 2).unwrap();
        assert_eq!(
            Field::text(b"ma\x1b[31min", 64, WidthProfile::DEFAULT).value,
            clean("ma[31min", 64)
        );
        assert_eq!(
            Field::text(b"abcdef", 4, WidthProfile::DEFAULT).value,
            clean("abc\u{2026}", 4)
        );
        assert_eq!(Field::text(b"abcdef", 4, p2).value, clean("ab\u{2026}", 4));
        assert_eq!(
            Field::text("가나다".as_bytes(), 5, WidthProfile::DEFAULT).value,
            clean("가나\u{2026}", 5)
        );
        let long = alloc::vec![b'a'; 1 << 20];
        let FieldValue::Text(s) = Field::text(&long, 256, WidthProfile::DEFAULT).value else {
            panic!()
        };
        assert_eq!(str_width(s.as_str(), WidthProfile::DEFAULT), 256);
        // One grapheme of 40,000 combining marks: 1 cell, but over the byte cap.
        let flood = [&b"a"[..], &"\u{301}".repeat(40_000).into_bytes()].concat();
        let FieldValue::Text(s) = Field::text(&flood, 256, WidthProfile::DEFAULT).value else {
            panic!()
        };
        assert!(s.as_str().len() <= 256 * 4, "{}", s.as_str().len());
    }

    // 이것을 실패시키는 것: Pending을 빈 것으로 보거나, 0이 아닌 Count·true·글자 있는 Text를 빈 것으로 보거나, false를 빈 것으로 보지 않는 것.
    #[test]
    fn group_emptiness() {
        assert!(!Field::PENDING.is_empty_for_group());
        assert!(Field::known(FieldValue::Bool(false)).is_empty_for_group());
        assert!(!Field::text(b"x", 8, WidthProfile::DEFAULT).is_empty_for_group());
        assert!(Field::ABSENT.is_empty_for_group());
        assert!(
            Field::known(FieldValue::Count {
                n: 0,
                saturated: false
            })
            .is_empty_for_group()
        );
        assert!(
            !Field::known(FieldValue::Count {
                n: 0,
                saturated: true
            })
            .is_empty_for_group()
        );
        assert!(!Field::known(FieldValue::Bool(true)).is_empty_for_group());
        assert!(Field::known(FieldValue::Text(Clean::default())).is_empty_for_group());
    }

    // 이것을 실패시키는 것: 정렬되지 않은 선언(이진 탐색이 놓침), 이름으로 찾지 못하는 것, 개수·타입이 틀린 값을 받는 것.
    #[test]
    fn declarations_sorted_and_checked() {
        assert!(BUILTIN.windows(2).all(|w| w[0].id < w[1].id));
        for d in BUILTIN {
            assert!(
                d.fields.windows(2).all(|w| w[0].name < w[1].name),
                "{}",
                d.id
            );
        }
        let git = segment("git").unwrap();
        assert_eq!(git.field_index("ahead"), Some(0));
        assert_eq!(git.field_index("untracked"), Some(14));
        assert_eq!(git.field_index("stashed"), None);
        assert_eq!(segment("venv").map(|d| d.id), Some("venv"));
        assert!(segment("custom/kube").is_none());
        let mut v = Value::new(b"ma\x1bin", alloc::vec![Field::ABSENT; git.fields.len()]);
        assert_eq!(v.text(), "main");
        assert_eq!(v.check(git), Ok(()));
        v.fields[0] = Field::known(FieldValue::Int(1));
        assert_eq!(v.check(git), Err(ValueError::FieldType { index: 0 }));
        v.fields.pop();
        assert_eq!(
            v.check(git),
            Err(ValueError::FieldCount { want: 15, got: 14 })
        );
    }

    // 이것을 실패시키는 것: 생략 기호의 칸이나 바이트를 빼고 자를 자리를 정하는 것, 바이트 상한만 넘을 때 칸을 다시
    // 세지 않는 것(ambiguous=2, 4칸에 `abcd` + 결합 문자 4만 개가 `abc…` 5칸이 됨).
    #[test]
    fn cut_stays_within_both_caps() {
        let p2 = WidthProfile::new(2, 2).unwrap();
        let marks = "\u{301}".repeat(40_000);
        let flood = alloc::format!("abcd{marks}");
        assert_eq!(
            Field::text(flood.as_bytes(), 4, p2).value,
            clean("ab\u{2026}", 4)
        );
        let inputs = [
            "abcdefghij",
            "가나다라마바",
            flood.as_str(),
            "\u{1F3F3}\u{FE0F}\u{200D}\u{1F308}\u{1F3F3}\u{FE0F}\u{200D}\u{1F308}x",
            "a\u{301}\u{301}\u{301}b\u{301}\u{301}\u{301}c\u{301}\u{301}\u{301}",
        ];
        for p in [WidthProfile::DEFAULT, p2] {
            for max in 0..=8u16 {
                for raw in inputs {
                    let FieldValue::Text(s) = Field::text(raw.as_bytes(), max, p).value else {
                        panic!()
                    };
                    let (w, len) = (str_width(s.as_str(), p), s.as_str().len());
                    assert!(
                        w <= u32::from(max) && len <= usize::from(max) * 4,
                        "{max} {raw:.40?}: {w} cells, {len} bytes"
                    );
                }
            }
        }
        // One cell left under ambiguous=2: the ASCII ellipsis, nothing kept.
        assert_eq!(
            Field::text("a\u{301}b".as_bytes(), 1, p2).value,
            clean(".", 1)
        );
        // A value within both caps is kept whole.
        assert_eq!(
            Field::text("가나".as_bytes(), 4, p2).value,
            clean("가나", 4)
        );
    }

    // 이것을 실패시키는 것: 정제를 멈추는 자리가 너무 일러 앞부분만 정제한 결과가 전체를 정제하고 자른 결과와 달라지는 것
    // (멈춘 뒤 남은 글자가 상한 근처 grapheme 경계를 바꾸는 경우).
    #[test]
    fn capped_sanitize_cuts_like_the_full_text() {
        let p2 = WidthProfile::new(2, 2).unwrap();
        let units: [&[u8]; 10] = [
            b"a",
            "\u{AC00}".as_bytes(),
            "e\u{301}".as_bytes(),
            "\u{1F1F0}\u{1F1F7}".as_bytes(),
            "\u{1F468}\u{200D}\u{1F469}\u{200D}\u{1F467}".as_bytes(),
            "\u{1112}\u{1161}\u{11AB}".as_bytes(),
            "\u{2764}\u{FE0F}".as_bytes(),
            b"a\x1b[31m",
            b"\xff\xe2\x82",
            "\u{915}\u{94D}\u{937}".as_bytes(),
        ];
        let mut inputs: Vec<Vec<u8>> = Vec::new();
        for k in 0..4 {
            for u in units {
                inputs.push([&b"aaa"[..k], &u.repeat(60)].concat());
            }
            inputs.push([&b"aaa"[..k], &units.concat().repeat(8)].concat());
            // Regional indicators after an odd number of them: pairing looks back.
            inputs.push([&b"aaa"[..k], &"\u{1F1F0}".repeat(61).into_bytes()].concat());
        }
        for p in [WidthProfile::DEFAULT, p2] {
            for max in (0..=12u16).chain([16, 64]) {
                for raw in &inputs {
                    let mut full = crate::sanitize::sanitize(raw);
                    cut(&mut full, max, p);
                    let FieldValue::Text(s) = Field::text(raw, max, p).value else {
                        panic!()
                    };
                    assert_eq!(s.as_str(), full, "{max} {raw:02x?}");
                }
            }
        }
    }

    // 이것을 실패시키는 것: 선언된 칸 상한을 보지 않고 Text면 받는 것(256칸으로 자른 값이 16칸 필드에 들어감).
    #[test]
    fn text_must_be_cut_to_the_declared_cap() {
        let git = segment("git").unwrap();
        let commit = git.field_index("commit").unwrap();
        let mut v = Value::new(b"", alloc::vec![Field::ABSENT; git.fields.len()]);
        v.fields[commit] = Field::text(b"0123456789abcdef0123", 256, WidthProfile::DEFAULT);
        assert_eq!(v.check(git), Err(ValueError::FieldType { index: commit }));
        v.fields[commit] = Field::text(b"0123456789abcdef0123", 16, WidthProfile::DEFAULT);
        assert_eq!(v.check(git), Ok(()));
        v.fields[commit] = Field::known(FieldValue::Text(Clean::default()));
        assert_eq!(v.check(git), Ok(()));
    }

    // 이것을 실패시키는 것: Value의 글자를 VALUE_MAX_CELLS 칸·그 4배 바이트에서 자르지 않는 것.
    #[test]
    fn value_text_is_capped() {
        let v = Value::new(&alloc::vec![b'a'; 1 << 20], Vec::new());
        assert_eq!(
            str_width(v.text(), WidthProfile::DEFAULT),
            u32::from(VALUE_MAX_CELLS)
        );
        // 1-cell graphemes of 7 bytes reach the 16 KiB cap first: 2,340 of
        // them and the ellipsis fit in 16,384 bytes.
        let v = Value::new("a\u{301}\u{301}\u{301}".repeat(4096).as_bytes(), Vec::new());
        assert_eq!(v.text().len(), 2340 * 7 + 3);
    }

    // 이것을 실패시키는 것: 임시 목록의 id·역할·필드 이름·타입이 바뀌는 것(M3 선언 전까지 바꾸려면 이 표도 고친다).
    #[test]
    fn builtin_table_is_pinned() {
        let mut got = String::new();
        for d in BUILTIN {
            let _ = write!(got, "{} {}:", d.id, d.role);
            for fd in d.fields {
                let _ = write!(got, " {}={:?}", fd.name, fd.ty);
            }
            got.push('\n');
        }
        let want = "\
char prompt.ok: failed=Bool vicmd=Bool
dir path: in_repo=Bool path=Text { max_cells: 4096 } readonly=Bool
duration duration: ms=Duration
git git.branch: ahead=Count behind=Count branch=Text { max_cells: 256 } commit=Text { max_cells: 16 } \
conflicted=Count detached=Bool filtered=Bool modified=Count no_repo=Bool operation=Text { max_cells: 16 } partial=Bool stage=Text { max_cells: 1 } staged=Count stash=Count \
untracked=Count
host host: name=Text { max_cells: 64 } root=Bool ssh=Bool user=Text { max_cells: 64 }
jobs jobs: count=Count
status status: code=Int pipestatus=Text { max_cells: 64 } signal=Text { max_cells: 16 }
time fg: text=Text { max_cells: 32 }
venv venv: name=Text { max_cells: 64 }
";
        assert_eq!(got, want);
    }
}
