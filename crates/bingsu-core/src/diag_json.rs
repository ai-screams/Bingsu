//! JSON text of diagnostics and of the layout decisions (`--format json` of
//! `explain` and `config check`). It is a second way to write the same
//! models as the human text (`diag::Diagnostic`, `recorder::DecisionLog`);
//! it decides nothing. Hand-written, so the core takes no JSON dependency.
//! Field names and their order are fixed by
//! `schema/diag-output-v1.json`, which a test checks the output against.
//!
//! Every string is passed through `sanitize` first (controls, bidi and
//! invisible characters are gone, invalid UTF-8 is U+FFFD) and then escaped,
//! so a value from a file can neither break the document nor reach a
//! terminal raw.
use crate::decision_text::{Names, reason_word, step_text};
use crate::diag::{Diagnostic, Place, Severity, SourceView, line_col, parts};
use crate::recorder::{DecisionLog, HideReason};
use crate::sanitize::sanitize_into;
use crate::shorten::Method;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write as _;

/// The output version. `code` is the stable identifier of a diagnostic;
/// `message`, `why` and `fix` are for people and may change between versions.
pub const SCHEMA: u32 = 1;

/// A JSON writer with a stack of "this level already has an item".
pub struct Writer {
    out: String,
    items: Vec<bool>,
    after_key: bool,
}

impl Default for Writer {
    fn default() -> Self {
        Self::new()
    }
}

fn escape_into(text: &str, out: &mut String) {
    out.push('"');
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if (c as u32) < 0x20 || matches!(c, '\u{7f}' | '\u{2028}' | '\u{2029}') => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

impl Writer {
    pub fn new() -> Self {
        Self {
            out: String::new(),
            items: Vec::new(),
            after_key: false,
        }
    }
    fn sep(&mut self) {
        if self.after_key {
            self.after_key = false;
        } else if let Some(has) = self.items.last_mut() {
            if *has {
                self.out.push(',');
            }
            *has = true;
        }
    }
    pub fn key(&mut self, name: &str) -> &mut Self {
        self.sep();
        escape_into(name, &mut self.out);
        self.out.push(':');
        self.after_key = true;
        self
    }
    pub fn begin_object(&mut self) -> &mut Self {
        self.sep();
        self.out.push('{');
        self.items.push(false);
        self
    }
    pub fn end_object(&mut self) -> &mut Self {
        self.items.pop();
        self.out.push('}');
        self
    }
    pub fn begin_array(&mut self) -> &mut Self {
        self.sep();
        self.out.push('[');
        self.items.push(false);
        self
    }
    pub fn end_array(&mut self) -> &mut Self {
        self.items.pop();
        self.out.push(']');
        self
    }
    /// A string value: sanitized, then escaped.
    pub fn string(&mut self, text: &str) -> &mut Self {
        self.sep();
        let mut clean = String::new();
        sanitize_into(text.as_bytes(), &mut clean);
        escape_into(&clean, &mut self.out);
        self
    }
    /// Like `string` for bytes that may not be UTF-8 (a file name).
    pub fn bytes(&mut self, text: &[u8]) -> &mut Self {
        self.sep();
        let mut clean = String::new();
        sanitize_into(text, &mut clean);
        escape_into(&clean, &mut self.out);
        self
    }
    pub fn number(&mut self, n: u64) -> &mut Self {
        self.sep();
        let _ = write!(self.out, "{n}");
        self
    }
    pub fn boolean(&mut self, b: bool) -> &mut Self {
        self.sep();
        self.out.push_str(if b { "true" } else { "false" });
        self
    }
    pub fn null(&mut self) -> &mut Self {
        self.sep();
        self.out.push_str("null");
        self
    }
    pub fn opt_string(&mut self, text: Option<&str>) -> &mut Self {
        match text {
            Some(t) => self.string(t),
            None => self.null(),
        }
    }
    /// The document, one line with a final newline.
    pub fn finish(mut self) -> String {
        self.out.push('\n');
        self.out
    }
}

const fn severity_word(s: Severity) -> &'static str {
    match s {
        Severity::Error => "error",
        Severity::Warning => "warning",
        Severity::Note => "note",
    }
}

/// One diagnostic: `code`, `severity`, `message`, `why`, `fix`, `at`, `via`,
/// `help`.
pub fn diagnostic(w: &mut Writer, d: &Diagnostic, files: &dyn SourceView) {
    let p = parts(d);
    w.begin_object();
    w.key("code").string(&alloc::format!("{}", d.code));
    w.key("severity").string(severity_word(d.severity()));
    w.key("message").string(&p.what);
    w.key("why").string(&p.why);
    w.key("fix").string(&p.fix);
    w.key("at").begin_object();
    match d.at {
        Place::Builtin => {
            w.key("kind").string("builtin");
        }
        Place::Source { id, span } => {
            let (l, c) = line_col(files.bytes(id), span.start);
            w.key("kind").string("source");
            w.key("file").bytes(files.display(id));
            w.key("line").number(u64::from(l));
            w.key("column").number(u64::from(c));
        }
        Place::Foreign { file, span } => {
            w.key("kind").string("foreign");
            w.key("file").number(u64::from(file));
            w.key("byte").number(u64::from(span.start));
        }
    }
    w.end_object();
    w.key("via").begin_array();
    for v in &d.via {
        w.bytes(files.display(*v));
    }
    w.end_array();
    w.key("help")
        .string(&alloc::format!("bingsu help {}", d.code));
    w.end_object();
}

/// The `diagnostics` array.
pub fn diagnostics(w: &mut Writer, list: &[Diagnostic], files: &dyn SourceView) {
    w.begin_array();
    for d in list {
        diagnostic(w, d, files);
    }
    w.end_array();
}

fn method_word(m: Option<&Method>) -> String {
    match m {
        None => String::from("unknown"),
        Some(Method::None) => String::from("none"),
        Some(Method::Depth(n)) => alloc::format!("depth {n}"),
        Some(Method::Abbrev(n)) => alloc::format!("abbrev {n}"),
        Some(Method::Unique) => String::from("unique"),
        Some(Method::Repo) => String::from("repo"),
        Some(Method::Truncate { max, .. }) => alloc::format!("truncate {max}"),
    }
}

fn reason_text(r: HideReason) -> &'static str {
    match r {
        HideReason::NoValue => "the segment sent no value",
        HideReason::Priority => "step 2: lower priority than what fits",
        HideReason::RightHidden => "step 3: the right side did not fit",
        HideReason::LeftOptional => "step 5: optional segment on the left",
        HideReason::Minimal => "step 7: only the prompt character is left",
        HideReason::EmptyGroup => "its group is empty (all its fields are empty)",
    }
}

/// `band` and `lines` of an explain document: the decisions of `log`, one
/// object per line the layout recorded anything for (lines are numbered
/// from 1). `only` keeps one segment's hide and shorten records.
pub fn decisions(w: &mut Writer, log: &DecisionLog, names: &Names<'_>, only: Option<usize>) {
    w.key("band");
    match log.band {
        Some(b) => w.string(names.bands.get(b).map_or("", |x| x.as_str())),
        None => w.null(),
    };
    let last = log
        .steps
        .iter()
        .map(|x| x.0)
        .chain(log.hidden.iter().map(|x| x.0))
        .chain(log.shortened.iter().map(|x| x.0))
        .max();
    w.key("lines").begin_array();
    if let Some(last) = last {
        let name = |i: usize| names.segments.get(i).copied().unwrap_or("");
        for line in 0..=last {
            w.begin_object();
            w.key("line").number(line as u64 + 1);
            w.key("steps").begin_array();
            for (_, s) in log.steps.iter().filter(|x| x.0 == line) {
                w.begin_object();
                w.key("step").number(u64::from(*s as u8));
                w.key("text").string(step_text(*s));
                w.end_object();
            }
            w.end_array();
            w.key("hidden").begin_array();
            for (_, seg, r) in log.hidden.iter().filter(|x| x.0 == line) {
                if only.is_some_and(|o| o != *seg) {
                    continue;
                }
                w.begin_object();
                w.key("segment").string(name(*seg));
                w.key("reason").string(reason_word(*r));
                w.key("reason_text").string(reason_text(*r));
                w.end_object();
            }
            w.end_array();
            w.key("shortened").begin_array();
            for (_, seg, m) in log.shortened.iter().filter(|x| x.0 == line) {
                if only.is_some_and(|o| o != *seg) {
                    continue;
                }
                w.begin_object();
                w.key("segment").string(name(*seg));
                let method = names.methods.get(*seg).and_then(|l| l.get(*m));
                w.key("method").string(&method_word(method));
                w.end_object();
            }
            w.end_array();
            w.end_object();
        }
    }
    w.end_array();
}
