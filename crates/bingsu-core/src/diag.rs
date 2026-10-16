//! Diagnostics (spec section 6 "진단 구조"): one structure for `config
//! check`, `explain` and `doctor`, with a stable code, a place, a severity
//! and an optional fix. Codes are versioned in `diag_codes`: a code is never
//! removed, only marked deprecated. A place is not tied to a bingsu config
//! file: a later import may point into another tool's file.
//!
//! The text here is the M3 frame (what, where, why, how to fix, code); the
//! wording is M7. Outside data (paths, keys, values) is sanitized before it
//! is put into the text.
use crate::config::tree::Span;
use crate::diag_codes::{CODES, CodeInfo};
use crate::sanitize::sanitize_into;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write as _;

/// A stable diagnostic code: `E`, `W` or `N` and three digits (`E101`).
/// The letter is the severity; `B` is never used (the record head is `B1`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct DiagCode {
    pub severity: Severity,
    pub number: u16,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Error,
    Warning,
    Note,
}

impl DiagCode {
    pub(crate) const fn new(severity: Severity, number: u16) -> Self {
        Self { severity, number }
    }
    pub fn letter(self) -> char {
        match self.severity {
            Severity::Error => 'E',
            Severity::Warning => 'W',
            Severity::Note => 'N',
        }
    }
    /// The registry entry (every code made in this crate has one; the
    /// registry test checks it).
    pub fn info(self) -> Option<&'static CodeInfo> {
        CODES.iter().find(|c| c.code == self)
    }
}

impl core::fmt::Display for DiagCode {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}{:03}", self.letter(), self.number)
    }
}

/// One file of one load, numbered by the caller in the order it opened them
/// (the config model's source list). Only compared, never interpreted.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct SourceId(pub u32);

/// Where a diagnostic points.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Place {
    /// The built-in theme or defaults (no file).
    Builtin,
    /// A bingsu config or theme file of this load.
    Source { id: SourceId, span: Span },
    /// Another tool's file (an import, later), numbered by the caller.
    Foreign { file: u32, span: Span },
}

/// A fix that can be applied as is: replace `span` of the same file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Fix {
    pub span: Span,
    pub text: String,
}

/// Named values the text refers to (`key`, `found`, `expected`, `path`).
/// Values come from files and are sanitized when the text is made.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Arg {
    pub name: &'static str,
    pub value: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Diagnostic {
    pub code: DiagCode,
    pub at: Place,
    pub args: Vec<Arg>,
    pub fix: Option<Fix>,
    /// The `extends` chain that brought the file in, outermost first.
    pub via: Vec<SourceId>,
}

impl Diagnostic {
    pub fn new(code: DiagCode, at: Place) -> Self {
        Self {
            code,
            at,
            args: Vec::new(),
            fix: None,
            via: Vec::new(),
        }
    }
    pub fn arg(mut self, name: &'static str, value: impl Into<String>) -> Self {
        self.args.push(Arg {
            name,
            value: value.into(),
        });
        self
    }
    pub fn severity(&self) -> Severity {
        self.code.severity
    }
}

/// What the human text needs to know about a source: the name to show and
/// the bytes, to turn a byte offset into line and column.
pub trait SourceView {
    fn display(&self, id: SourceId) -> &[u8];
    fn bytes(&self, id: SourceId) -> &[u8];
}

/// 1-based line and column (in chars) of byte `at` in `text`.
pub fn line_col(text: &[u8], at: u32) -> (u32, u32) {
    let at = (at as usize).min(text.len());
    let before = &text[..at];
    let line = before.iter().filter(|&&b| b == b'\n').count() as u32 + 1;
    let start = before
        .iter()
        .rposition(|&b| b == b'\n')
        .map_or(0, |i| i + 1);
    let col = before[start..]
        .iter()
        .filter(|&&b| b & 0xC0 != 0x80)
        .count() as u32
        + 1;
    (line, col)
}

fn fill(template: &str, args: &[Arg], out: &mut String) {
    let mut rest = template;
    while let Some(i) = rest.find('{') {
        out.push_str(&rest[..i]);
        let tail = &rest[i + 1..];
        match tail.find('}') {
            Some(j) => {
                let name = &tail[..j];
                match args.iter().find(|a| a.name == name) {
                    Some(a) => sanitize_into(a.value.as_bytes(), out),
                    None => {
                        out.push('{');
                        out.push_str(name);
                        out.push('}');
                    }
                }
                rest = &tail[j + 1..];
            }
            None => {
                out.push_str(&rest[i..]);
                rest = "";
            }
        }
    }
    out.push_str(rest);
}

/// The human frame, five parts in order: what (one line), where
/// (`file:line:col`, then the `extends` chain), why, how to fix, code.
pub fn render_human(d: &Diagnostic, files: &dyn SourceView) -> String {
    let mut out = String::new();
    let info = d.code.info();
    let _ = write!(out, "{}: ", d.code);
    fill(info.map_or("(unknown code)", |i| i.what), &d.args, &mut out);
    out.push('\n');
    out.push_str("  where: ");
    match d.at {
        Place::Builtin => out.push_str("built-in defaults"),
        Place::Source { id, span } => {
            sanitize_into(files.display(id), &mut out);
            let (l, c) = line_col(files.bytes(id), span.start);
            let _ = write!(out, ":{l}:{c}");
        }
        Place::Foreign { file, span } => {
            let _ = write!(out, "imported file {file} at byte {}", span.start);
        }
    }
    for v in &d.via {
        out.push_str("\n    via ");
        sanitize_into(files.display(*v), &mut out);
    }
    out.push('\n');
    out.push_str("  why: ");
    fill(info.map_or("", |i| i.why), &d.args, &mut out);
    out.push('\n');
    out.push_str("  fix: ");
    match &d.fix {
        Some(f) => {
            out.push_str("replace with `");
            sanitize_into(f.text.as_bytes(), &mut out);
            out.push('`');
        }
        None => fill(info.map_or("", |i| i.fix), &d.args, &mut out),
    }
    out.push('\n');
    let _ = write!(out, "  code: {} (bingsu help {})", d.code, d.code);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diag_codes::UNKNOWN_KEY;

    struct One(&'static [u8], &'static [u8]);
    impl SourceView for One {
        fn display(&self, _: SourceId) -> &[u8] {
            self.0
        }
        fn bytes(&self, _: SourceId) -> &[u8] {
            self.1
        }
    }

    // 이것을 실패시키는 것: 줄·칸을 바이트로 세거나(한글 칸), 줄 수를 0부터 세는 것.
    #[test]
    fn line_and_column_count_chars() {
        let t = "a = 1\n한글 = 2\n".as_bytes();
        assert_eq!(line_col(t, 0), (1, 1));
        let at = "a = 1\n한글".len() as u32;
        assert_eq!(line_col(t, at), (2, 3));
        assert_eq!(line_col(t, 10_000), (3, 1));
    }

    // 이것을 실패시키는 것: 다섯 칸의 순서를 바꾸거나 빠뜨리는 것, 바깥 값을 정제하지 않는 것(ESC가 그대로).
    #[test]
    fn human_frame_has_five_parts_and_sanitizes() {
        let d = Diagnostic {
            code: UNKNOWN_KEY,
            at: Place::Source {
                id: SourceId(1),
                span: Span { start: 6, end: 9 },
            },
            args: alloc::vec![Arg {
                name: "key",
                value: String::from("co\u{1b}[31mlor"),
            }],
            fix: None,
            via: alloc::vec![SourceId(0)],
        };
        let text = render_human(
            &d,
            &One(b"/home/u/.config/bingsu/config.toml", b"a = 1\ncolr = 2\n"),
        );
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 6, "{text}");
        assert!(lines[0].starts_with("E201: "), "{text}");
        assert!(lines[1].ends_with("config.toml:2:1"), "{text}");
        assert!(lines[2].starts_with("    via "), "{text}");
        assert!(lines[3].starts_with("  why: "), "{text}");
        assert!(lines[4].starts_with("  fix: "), "{text}");
        assert_eq!(lines[5], "  code: E201 (bingsu help E201)");
        assert!(!text.contains('\u{1b}'), "{text}");
    }

    // 이것을 실패시키는 것: 코드 글자·세 자리 번호·심각도·인자 빌더의 공개 계약을 바꾸는 것.
    #[test]
    fn codes_and_builder_keep_the_public_contract() {
        use crate::diag_codes::{BAND_NEVER_CHOSEN, TEMPLATE_REPLACES_STYLE};
        for (code, text, severity) in [
            (UNKNOWN_KEY, "E201", Severity::Error),
            (BAND_NEVER_CHOSEN, "W407", Severity::Warning),
            (TEMPLATE_REPLACES_STYLE, "N501", Severity::Note),
        ] {
            let d = Diagnostic::new(code, Place::Builtin).arg("key", "colr");
            assert_eq!(alloc::format!("{code}"), text);
            assert_eq!(d.severity(), severity);
            assert_eq!(d.at, Place::Builtin);
            assert_eq!(
                d.args,
                [Arg {
                    name: "key",
                    value: String::from("colr")
                }]
            );
            assert_eq!(d.fix, None);
            assert!(d.via.is_empty());
            assert_eq!(code.info().unwrap().code, code);
        }
        assert_eq!(
            alloc::format!("{}", DiagCode::new(Severity::Error, 7)),
            "E007"
        );
    }

    // 이것을 실패시키는 것: 파일 이름·extends 경로·수정안을 정제하지 않고 문구에 넣는 것.
    #[test]
    fn source_names_and_fixes_are_sanitized() {
        let mut d = Diagnostic::new(
            UNKNOWN_KEY,
            Place::Source {
                id: SourceId(0),
                span: Span { start: 0, end: 1 },
            },
        )
        .arg("key", "colr");
        d.via.push(SourceId(0));
        d.fix = Some(Fix {
            span: Span { start: 0, end: 1 },
            text: String::from("co\u{202e}lor\n"),
        });
        let text = render_human(&d, &One(b"a\x1b\n\xff.toml", b"x"));
        assert!(text.contains("  where: a\u{fffd}.toml:1:1\n"), "{text}");
        assert!(text.contains("    via a\u{fffd}.toml\n"), "{text}");
        assert!(text.contains("  fix: replace with `color`\n"), "{text}");
    }

    // 이것을 실패시키는 것: 기본·외부 위치나 미등록 코드·없는 인자의 표시를 잃는 것.
    #[test]
    fn builtin_foreign_and_unknown_codes_render() {
        let files = One(b"unused", b"");
        let builtin = render_human(&Diagnostic::new(UNKNOWN_KEY, Place::Builtin), &files);
        assert!(
            builtin.contains("  where: built-in defaults\n"),
            "{builtin}"
        );
        assert!(
            builtin.starts_with("E201: unknown key `{key}`\n"),
            "{builtin}"
        );
        assert!(builtin.contains("check the key name{suggest}"), "{builtin}");
        let unknown = DiagCode {
            severity: Severity::Warning,
            number: 999,
        };
        assert!(unknown.info().is_none());
        let foreign = render_human(
            &Diagnostic::new(
                unknown,
                Place::Foreign {
                    file: 9,
                    span: Span { start: 17, end: 20 },
                },
            ),
            &files,
        );
        assert_eq!(
            foreign,
            "W999: (unknown code)\n  where: imported file 9 at byte 17\n  why: \n  fix: \n  code: W999 (bingsu help W999)"
        );
    }
}
