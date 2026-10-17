//! Checking the merged config against the key table (spec section 2,
//! section 6 "오류 회복": an unknown key is a strict error). Every problem
//! is reported, with the file and range of the value that won the merge.
use crate::config::keys::{self, KeyDef, Ty};
use crate::config::merge::{MNode, MTable, MValue, Merged};
use crate::config::source::Trust;
use crate::config::tree::{Node, Table, Value};
use crate::diag::{Diagnostic, Place};
use crate::diag_codes as codes;
use crate::diag_suggest::{Suggestion, suggest};
use crate::field;
use crate::ident::{Namespace, parse_segment_id};
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

/// What `parse_duration_ms` accepts, as a JSON Schema pattern: 0–3600000
/// ms or 0–3600 s, no leading zeros. The shared corpus test keeps the two
/// equal.
pub const DURATION_PATTERN: &str = "^((0|[1-9][0-9]{0,5}|[1-2][0-9]{6}|3[0-5][0-9]{5}|3600000)ms|(0|[1-9][0-9]{0,2}|[1-2][0-9]{3}|3[0-5][0-9]{2}|3600)s)$(?![\\s\\S])";

/// `"200ms"` or `"2s"` in milliseconds, up to one hour. No leading zeros,
/// so the JSON Schema can say the same with `DURATION_PATTERN`.
pub fn parse_duration_ms(s: &str) -> Option<u64> {
    let (digits, mul) = if let Some(d) = s.strip_suffix("ms") {
        (d, 1)
    } else {
        (s.strip_suffix('s')?, 1000)
    };
    if digits.is_empty()
        || digits.len() > 7
        || !digits.bytes().all(|b| b.is_ascii_digit())
        || (digits.len() > 1 && digits.starts_with('0'))
    {
        return None;
    }
    let ms = digits.parse::<u64>().ok()? * mul;
    (ms <= 3_600_000).then_some(ms)
}

fn place(n: &MNode) -> Place {
    Place::Source {
        id: n.origin.source,
        span: n.origin.span,
    }
}

fn item_place(owner: &MNode, item: &Node) -> Place {
    Place::Source {
        id: owner.origin.source,
        span: item.span,
    }
}

fn suggestion(word: &str, known: &[&str], segments: bool) -> String {
    match suggest(word, known, segments) {
        Some(Suggestion::Spelling(k)) => format!(" (did you mean `{k}`?)"),
        Some(Suggestion::OtherTool { tool, ours }) => {
            format!(" ({tool} calls it `{word}`; here it is `{ours}`)")
        }
        None => String::new(),
    }
}

fn builtin_ids() -> Vec<&'static str> {
    field::BUILTIN.iter().map(|d| d.id).collect()
}

/// Checks one segment id where it is written; `Ok` with its namespace.
fn segment_id(id: &str, at: Place, out: &mut Vec<Diagnostic>) -> Option<Namespace> {
    match parse_segment_id(id) {
        Err(_) => {
            out.push(Diagnostic::new(codes::BAD_SEGMENT_ID, at).arg("id", id));
            None
        }
        Ok(sid) => match sid.namespace() {
            Namespace::Builtin if field::segment(id).is_none() => {
                let hint = suggestion(id, &builtin_ids(), true);
                out.push(
                    Diagnostic::new(codes::UNKNOWN_SEGMENT, at).arg("id", format!("{id}{hint}")),
                );
                None
            }
            // No plugin is installed in this milestone (plugins: later).
            Namespace::Plugin => {
                out.push(Diagnostic::new(codes::UNKNOWN_SEGMENT, at).arg("id", id));
                None
            }
            ns => Some(ns),
        },
    }
}

fn type_ok(ty: Ty, n: &MNode, path: &str, out: &mut Vec<Diagnostic>) {
    let wrong = |expected: &str, found: &str| {
        Diagnostic::new(codes::WRONG_TYPE, place(n))
            .arg("key", path)
            .arg("expected", expected)
            .arg("found", found)
    };
    let bad = |found: String, expected: String| {
        Diagnostic::new(codes::BAD_VALUE, place(n))
            .arg("key", path)
            .arg("found", found)
            .arg("expected", expected)
    };
    let kind = match &n.value {
        MValue::Scalar(v) => v.kind(),
        MValue::Array(_) => "array",
        MValue::Table(_) => "table",
    };
    match (ty, &n.value) {
        (Ty::Table, MValue::Table(_))
        | (Ty::Bool, MValue::Scalar(Value::Bool(_)))
        | (Ty::Str, MValue::Scalar(Value::Str(_))) => {}
        (Ty::Text, MValue::Scalar(Value::Str(s))) => {
            if let Some(c) = s.chars().find(|c| crate::sanitize::is_removed(*c)) {
                out.push(
                    Diagnostic::new(codes::CONTROL_IN_TEXT, place(n))
                        .arg("key", path)
                        .arg("char", format!("U+{:04X}", c as u32)),
                );
            }
        }
        (Ty::Int { min, max }, MValue::Scalar(Value::Int(i))) => {
            if *i < min || *i > max {
                out.push(bad(
                    format!("{i}"),
                    format!("an integer from {min} to {max}"),
                ));
            }
        }
        (Ty::Float { min, max }, MValue::Scalar(v @ (Value::Float(_) | Value::Int(_)))) => {
            let x = match v {
                Value::Float(x) => *x,
                Value::Int(i) => *i as f64,
                _ => 0.0,
            };
            if !(min..=max).contains(&x) {
                out.push(bad(format!("{x}"), format!("a number from {min} to {max}")));
            }
        }
        (Ty::Enum(list), MValue::Scalar(Value::Str(s))) => {
            if !list.contains(&s.as_str()) {
                out.push(bad(
                    format!("\"{s}\"{}", suggestion(s, list, false)),
                    list.join(", "),
                ));
            }
        }
        (Ty::Duration, MValue::Scalar(Value::Str(s))) => {
            if parse_duration_ms(s).is_none() {
                out.push(bad(
                    format!("\"{s}\""),
                    String::from("a duration like \"200ms\" or \"2s\", at most 1 hour"),
                ));
            }
        }
        (Ty::Color, MValue::Scalar(Value::Str(s))) => {
            if crate::color::notation::parse_color(s).is_err() {
                out.push(bad(
                    format!("\"{s}\""),
                    String::from("oklch(...), #rrggbb, 0-255 or term.ansi.N"),
                ));
            }
        }
        (Ty::Strings | Ty::Segments | Ty::EnumList(_), MValue::Array(items)) => {
            for it in items {
                match &it.value {
                    Value::Str(s) => {
                        if let Ty::EnumList(list) = ty {
                            if !list.contains(&s.as_str()) {
                                out.push(
                                    Diagnostic::new(codes::BAD_VALUE, item_place(n, it))
                                        .arg("key", path)
                                        .arg("found", format!("\"{s}\""))
                                        .arg("expected", list.join(", ")),
                                );
                            }
                        }
                        if ty == Ty::Segments {
                            segment_id(s, item_place(n, it), out);
                        }
                    }
                    v => out.push(
                        Diagnostic::new(codes::WRONG_TYPE, item_place(n, it))
                            .arg("key", path)
                            .arg("expected", "a string")
                            .arg("found", v.kind()),
                    ),
                }
            }
        }
        (Ty::Int { .. }, _) => out.push(wrong("an integer", kind)),
        (Ty::Float { .. }, _) => out.push(wrong("a number", kind)),
        (Ty::Bool, _) => out.push(wrong("true or false", kind)),
        (Ty::Table, _) => out.push(wrong("a table", kind)),
        (Ty::Strings | Ty::Segments | Ty::EnumList(_), _) => {
            out.push(wrong("an array of strings", kind))
        }
        (Ty::Str | Ty::Text | Ty::Enum(_) | Ty::Duration | Ty::Color, _) => {
            out.push(wrong("a string", kind))
        }
    }
}

fn is_line_name(k: &str) -> bool {
    k.strip_prefix("line")
        .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
}

fn walk(t: &MTable, path: &mut Vec<String>, out: &mut Vec<Diagnostic>) {
    for e in &t.entries {
        path.push(e.key.clone());
        let segs: Vec<&str> = path.iter().map(String::as_str).collect();
        let dotted = segs.join(".");
        let def: Option<&KeyDef> = keys::lookup(&segs);
        match (segs.as_slice(), def) {
            (["segment", id], _) => {
                segment_id(
                    id,
                    Place::Source {
                        id: e.node.origin.source,
                        span: e.node.origin.key_span,
                    },
                    out,
                );
            }
            (["layout", line] | ["layout", "when", _, line], None) if is_line_name(line) => {
                out.push(
                    Diagnostic::new(codes::BAD_LAYOUT_LINE, place(&e.node))
                        .arg("key", dotted.clone()),
                );
                path.pop();
                continue;
            }
            (_, None) => {
                let parent: Vec<&str> = segs[..segs.len() - 1].to_vec();
                let known = keys::children(&parent);
                let hint = suggestion(&e.key, &known, false);
                out.push(
                    Diagnostic::new(
                        codes::UNKNOWN_KEY,
                        Place::Source {
                            id: e.node.origin.source,
                            span: e.node.origin.key_span,
                        },
                    )
                    .arg("key", dotted.clone())
                    .arg("suggest", hint),
                );
                path.pop();
                continue;
            }
            _ => {}
        }
        if let Some(d) = def {
            type_ok(d.ty, &e.node, &dotted, out);
            if let Some(m) = d.planned {
                out.push(
                    Diagnostic::new(codes::KEY_PLANNED, place(&e.node))
                        .arg("key", dotted.clone())
                        .arg("milestone", m),
                );
            }
        }
        if let MValue::Table(inner) = &e.node.value {
            walk(inner, path, out);
        }
        path.pop();
    }
}

fn str_of(n: Option<&MNode>) -> Option<&str> {
    match n.map(|n| &n.value) {
        Some(MValue::Scalar(Value::Str(s))) => Some(s),
        _ => None,
    }
}

/// Segment rules: a user segment needs `kind`; a key must fit the kind; a
/// built-in segment has no kind and takes only its own keys and `enabled`.
fn segments(root: &MTable, out: &mut Vec<Diagnostic>) {
    let Some(MValue::Table(segs)) = root.get("segment").map(|n| &n.value) else {
        return;
    };
    for s in &segs.entries {
        let MValue::Table(t) = &s.node.value else {
            continue;
        };
        let builtin = !s.key.contains('/');
        let kind = str_of(t.get("kind"));
        if !builtin && kind.is_none() {
            // The table came from a shape-only file: its kind was dropped
            // there (P-S3), a warning; a trusted file that forgot `kind`, an
            // error.
            let shape = s.node.origin.trust == Trust::ShapeOnly;
            let code = if shape {
                codes::SEGMENT_DROPPED
            } else {
                codes::SEGMENT_NEEDS_KIND
            };
            out.push(Diagnostic::new(code, place(&s.node)).arg("id", s.key.clone()));
            continue;
        }
        if builtin && kind.is_some() {
            out.push(
                Diagnostic::new(
                    codes::KEY_NOT_FOR_KIND,
                    place(t.get("kind").unwrap_or(&s.node)),
                )
                .arg("key", "kind")
                .arg("kind", "built-in"),
            );
        }
        for e in &t.entries {
            let path = ["segment", s.key.as_str(), e.key.as_str()];
            let Some(d) = keys::lookup(&path) else {
                continue;
            };
            let fits = d.kinds.is_empty() || kind.is_some_and(|k| d.kinds.contains(&k));
            let own = builtin && d.path.starts_with("segment.") && !d.path.starts_with("segment.*");
            if !fits || (builtin && !own && e.key != "enabled") {
                out.push(
                    Diagnostic::new(codes::KEY_NOT_FOR_KIND, place(&e.node))
                        .arg("key", e.key.clone())
                        .arg("kind", kind.unwrap_or("built-in")),
                );
            }
        }
    }
}

/// `line2` without `line1` in `[layout]`. A band inherits the default
/// lines, so a band that writes only its `line2` is fine.
fn line_gaps(root: &MTable, out: &mut Vec<Diagnostic>) {
    let Some(MValue::Table(layout)) = root.get("layout").map(|n| &n.value) else {
        return;
    };
    if let (Some(l2), None) = (layout.get("line2"), layout.get("line1")) {
        out.push(
            Diagnostic::new(codes::BAD_LAYOUT_LINE, place(l2))
                .arg("key", "line2 (there is no line1)"),
        );
    }
}

/// Every `custom/…` id a layout names should be declared as
/// `[segment."custom/…"]`. An undeclared one is a warning and is not drawn:
/// a theme that removes a segment the user's layout names must not reject
/// the user's config (rule 5, decision 2026-10-15).
fn declared(root: &MTable, out: &mut Vec<Diagnostic>) {
    let has = |id: &str| {
        matches!(
            root.at(&["segment", id]).map(|n| &n.value),
            Some(MValue::Table(_))
        )
    };
    fn arrays<'a>(t: &'a MTable, out: &mut Vec<&'a MNode>) {
        for e in &t.entries {
            match &e.node.value {
                MValue::Table(inner) => arrays(inner, out),
                MValue::Array(_) if e.key == "left" || e.key == "right" => out.push(&e.node),
                _ => {}
            }
        }
    }
    let mut found = Vec::new();
    // Templates too: `style.template` and each band's.
    let mut templates: Vec<&MNode> = root.at(&["style", "template"]).into_iter().collect();
    if let Some(MValue::Table(layout)) = root.get("layout").map(|n| &n.value) {
        arrays(layout, &mut found);
        if let Some(MValue::Table(bands)) = layout.get("when").map(|n| &n.value) {
            for b in &bands.entries {
                if let MValue::Table(bt) = &b.node.value {
                    templates.extend(bt.at(&["style", "template"]));
                }
            }
        }
    }
    for n in templates {
        if let MValue::Scalar(Value::Str(text)) = &n.value {
            for id in crate::config::compile::template_ids(text) {
                if id.starts_with("custom/") && !has(&id) {
                    out.push(Diagnostic::new(codes::CUSTOM_UNDECLARED, place(n)).arg("id", id));
                }
            }
        }
    }
    for n in found {
        let MValue::Array(items) = &n.value else {
            continue;
        };
        for it in items {
            if let Value::Str(id) = &it.value {
                if id.starts_with("custom/") && !has(id) {
                    out.push(
                        Diagnostic::new(codes::CUSTOM_UNDECLARED, item_place(n, it))
                            .arg("id", id.clone()),
                    );
                }
            }
        }
    }
}

/// Every problem of the merged config.
pub fn check(m: &Merged) -> Vec<Diagnostic> {
    let mut out = Vec::new();
    walk(&m.root, &mut Vec::new(), &mut out);
    segments(&m.root, &mut out);
    line_gaps(&m.root, &mut out);
    declared(&m.root, &mut out);
    out
}

/// A theme file (spec section 2 "테마 스키마"): every check of a config,
/// and only the keys a theme may set, never an execution key or `extends`.
pub fn check_theme(id: crate::diag::SourceId, t: &Table) -> Vec<Diagnostic> {
    fn lift(t: &Table, id: crate::diag::SourceId) -> MTable {
        MTable {
            entries: t
                .entries
                .iter()
                .map(|e| crate::config::merge::MEntry {
                    key: e.key.clone(),
                    node: MNode {
                        value: match &e.node.value {
                            Value::Table(inner) => MValue::Table(lift(inner, id)),
                            Value::Array(a) => MValue::Array(a.clone()),
                            v => MValue::Scalar(v.clone()),
                        },
                        origin: crate::config::merge::Origin {
                            source: id,
                            key_span: e.key_span,
                            span: e.node.span,
                            trust: Trust::ShapeOnly,
                        },
                    },
                })
                .collect(),
        }
    }
    fn go(t: &Table, path: &mut Vec<String>, id: crate::diag::SourceId, out: &mut Vec<Diagnostic>) {
        for e in &t.entries {
            path.push(e.key.clone());
            let segs: Vec<&str> = path.iter().map(String::as_str).collect();
            let allowed = keys::lookup(&segs).is_none_or(|d| d.theme);
            let is_table = matches!(e.node.value, Value::Table(_));
            if !allowed
                || (!is_table && keys::classify(&segs) == crate::config::merge::KeyClass::Exec)
            {
                out.push(
                    Diagnostic::new(
                        codes::THEME_FORBIDDEN_KEY,
                        Place::Source {
                            id,
                            span: e.key_span,
                        },
                    )
                    .arg("key", segs.join(".")),
                );
            } else if let Value::Table(inner) = &e.node.value {
                go(inner, path, id, out);
            }
            path.pop();
        }
    }
    let mut out = Vec::new();
    go(t, &mut Vec::new(), id, &mut out);
    let forbidden: Vec<String> = out
        .iter()
        .filter_map(|d| d.args.first().map(|a| a.value.clone()))
        .collect();
    let lifted = Merged {
        root: lift(t, id),
        warnings: Vec::new(),
    };
    // A forbidden key is reported once, above, and not again by `check`.
    out.extend(check(&lifted).into_iter().filter(|d| {
        let key = d
            .args
            .iter()
            .find(|a| a.name == "key")
            .map(|a| a.value.as_str());
        let again = key.is_some_and(|k| {
            forbidden
                .iter()
                .any(|f| f == k || k.starts_with(&alloc::format!("{f}.")))
        });
        !again && d.code != codes::KEY_NOT_FOR_KIND
    }));
    out
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::config::merge::merge;
    use crate::config::source::load;
    use crate::config::source::tests::{files, opened};
    use crate::diag::{DiagCode, SourceId};
    use alloc::vec;

    pub(crate) fn merged_with(root: &str, list: &[(&'static str, &str)]) -> Merged {
        let mut f = files(list);
        let g = load(vec![opened("root", root, 1)], &mut f, [0, 3, 0]).unwrap();
        merge(&g, &[], &keys::slot)
    }

    fn codes_of(src: &str) -> Vec<DiagCode> {
        check(&merged_with(src, &[]))
            .iter()
            .map(|d| d.code)
            .collect()
    }

    // 스펙 2절 예시 파일 그대로. `layout.transient`는 M4·M5 키라 알림 N503 하나만 낸다.
    // 이것을 실패시키는 것: 스펙 예시 파일(키 이름은 이 표)을 오류로 보는 것, 뒤 마일스톤 키를 오류로 보는 것.
    #[test]
    fn the_spec_example_checks() {
        let src = r#"
version = 1
requires = ">=0.3"
theme = "bingsu-default"
icons = "nerd"
[colors]
flavor = "a"
mode = "auto"
knobs = { hue = 280, accent_l = 0.76, accent_c = 0.12 }
override = { "git.dirty" = "oklch(0.78 0.12 60)" }
roles = { path = "accent.blue" }
[layout]
frame = "none"
transient = "char"
fill = "space"
[layout.line1]
left  = ["dir", "git"]
right = ["status", "duration", "venv", "time"]
[layout.line2]
left  = ["char"]
[layout.when.narrow]
max_cols = 59
[layout.when.narrow.line1]
right = []
[layout.when.narrow.style]
preset = "lean"
[style]
preset = "triangle"
[width]
ambiguous = 1
emoji = 2
[segment.dir]
shorten = ["repo", "abbrev", "depth"]
when = "needed"
[segment.duration]
min = "2s"
[segment."custom/kube"]
kind = "command"
command = ["kubectl", "config", "current-context"]
timeout = "200ms"
cache = "30s"
"#;
        assert_eq!(codes_of(src), [codes::KEY_PLANNED]);
    }

    // 이것을 실패시키는 것: 모르는 키·틀린 타입·범위 밖 값·목록 밖 값을 받는 것, 비슷한 키를 권하지 않는 것.
    #[test]
    fn unknown_keys_and_bad_values_are_errors() {
        let m = merged_with(
            "colrs = 1\n[width]\nambiguous = 3\n[colors]\nmode = \"dakr\"\n[segment.duration]\nmin = 5\n",
            &[],
        );
        let d = check(&m);
        let got: Vec<DiagCode> = d.iter().map(|d| d.code).collect();
        assert_eq!(
            got,
            [
                codes::UNKNOWN_KEY,
                codes::BAD_VALUE,
                codes::BAD_VALUE,
                codes::WRONG_TYPE
            ]
        );
        assert!(
            d[0].args.iter().any(|a| a.value.contains("`colors`")),
            "{:?}",
            d[0]
        );
        assert!(
            d[2].args.iter().any(|a| a.value.contains("`dark`")),
            "{:?}",
            d[2]
        );
        let Place::Source { id, span } = d[0].at else {
            panic!()
        };
        assert_eq!((id, span.start), (SourceId(0), 0));
    }

    // 이것을 실패시키는 것: 없는 테마 이름을 받아 조용히 기본 테마로 그리는 것.
    #[test]
    fn unknown_theme_is_an_error() {
        assert_eq!(codes_of("theme = \"dracula\"\n"), [codes::BAD_VALUE]);
        assert_eq!(codes_of("theme = \"bingsu-default\"\n"), []);
    }

    // 이것을 실패시키는 것: id 문법 밖·없는 내장 세그먼트·플러그인 id를 레이아웃이나 표 이름으로 받는 것,
    // 다른 도구 이름을 알려 주지 않는 것.
    #[test]
    fn segment_ids_are_checked_where_written() {
        let m = merged_with(
            "[layout.line1]\nleft = [\"directory\", \"Dir\", \"acme/x\", \"custom/k\"]\n[segment.\"custom/k\"]\nkind = \"text\"\ntext = \"hi\"\n",
            &[],
        );
        let d = check(&m);
        let got: Vec<DiagCode> = d.iter().map(|d| d.code).collect();
        assert_eq!(
            got,
            [
                codes::UNKNOWN_SEGMENT,
                codes::BAD_SEGMENT_ID,
                codes::UNKNOWN_SEGMENT
            ]
        );
        assert!(d[0].args[0].value.contains("starship"), "{:?}", d[0]);
    }

    // 이것을 실패시키는 것: kind 없는 사용자 세그먼트를 받거나, kind에 맞지 않는 키·내장 세그먼트의 명령 키를 받는 것,
    // 모양 전용 파일에서 kind가 버려진 세그먼트를 오류로 보는 것(P-S3).
    #[test]
    fn kinds_decide_the_keys() {
        assert_eq!(
            codes_of("[segment.\"custom/a\"]\ntext = \"x\"\n"),
            [codes::SEGMENT_NEEDS_KIND]
        );
        assert_eq!(
            codes_of("[segment.\"custom/a\"]\nkind = \"text\"\ncommand = [\"ls\"]\n"),
            [codes::KEY_NOT_FOR_KIND]
        );
        assert_eq!(
            codes_of("[segment.dir]\ncommand = [\"ls\"]\n"),
            [codes::KEY_NOT_FOR_KIND]
        );
        assert_eq!(codes_of("[segment.dir]\nenabled = false\n"), []);
        assert_eq!(
            codes_of("[segment.\"custom/a\"]\nkind = \"shell\"\n")[0],
            codes::BAD_VALUE
        );
        let m = merged_with(
            "extends = [\"shape-t\"]\n",
            &[(
                "shape-t",
                "[segment.\"custom/a\"]\nkind = \"text\"\ntext = \"x\"\n",
            )],
        );
        let got: Vec<DiagCode> = check(&m).iter().map(|d| d.code).collect();
        assert_eq!(got, [codes::SEGMENT_DROPPED]);
    }

    // 이것을 실패시키는 것: line3·빈 줄 번호(line2만)를 받는 것.
    #[test]
    fn layout_lines_are_line1_and_line2() {
        assert_eq!(
            codes_of("[layout.line3]\nleft = [\"dir\"]\n"),
            [codes::BAD_LAYOUT_LINE]
        );
        assert_eq!(
            codes_of("[layout.line2]\nleft = [\"dir\"]\n"),
            [codes::BAD_LAYOUT_LINE]
        );
        // A band inherits the default lines: its own line2 alone is fine.
        assert_eq!(
            codes_of("[layout.when.n]\nmin_cols = 100\n[layout.when.n.line2]\nleft = [\"dir\"]\n"),
            []
        );
    }

    // 이것을 실패시키는 것: 테마가 실행 키·`extends`·`theme`을 쓰게 두거나 모양 키까지 막는 것.
    #[test]
    fn themes_cannot_run_anything() {
        let t = crate::config::tree::parse(
            b"extends = [\"x\"]\ntheme = \"y\"\n[colors]\nmode = \"dark\"\n[segment.\"custom/a\"]\nkind = \"command\"\ncommand = [\"ls\"]\n[segment.dir]\nwhen = \"always\"\n",
        )
        .unwrap();
        let d = check_theme(SourceId(0), &t);
        let keys: Vec<String> = d.iter().map(|d| d.args[0].value.clone()).collect();
        assert_eq!(
            keys,
            [
                "extends",
                "theme",
                "segment.custom/a.kind",
                "segment.custom/a.command"
            ]
        );
    }

    // 선언 없는 `custom/…`는 경고 W408이고 그리지 않는다(테마가 선언을 없애도 사용자 설정이 거부되지 않음).
    // 이것을 실패시키는 것: 선언을 확인하지 않는 것, 그것을 오류로 내는 것.
    #[test]
    fn custom_ids_need_a_declaration() {
        assert_eq!(
            codes_of("[layout.line1]\nleft = [\"custom/typo\"]\n"),
            [codes::CUSTOM_UNDECLARED]
        );
        let ok = "[segment.\"custom/k\"]\nkind = \"text\"\ntext = \"x\"\n[layout.line1]\nleft = [\"custom/k\"]\n";
        assert_eq!(codes_of(ok), []);
        // A template does not need a layout table to name a custom id.
        let text = "[style]\ntemplate = '{dir}{custom/missing}'\n";
        assert_eq!(codes_of(text), [codes::CUSTOM_UNDECLARED]);
        let theme = crate::config::tree::parse(text.as_bytes()).unwrap();
        assert_eq!(
            check_theme(SourceId(3), &theme)[0].code,
            codes::CUSTOM_UNDECLARED
        );
    }

    // 이것을 실패시키는 것: 그려지는 글에 제어·양방향·보이지 않는 문자를 받는 것, ZWJ·variation selector를 막는 것.
    #[test]
    fn drawn_text_has_no_control_characters() {
        let seg =
            |t: &str| alloc::format!("[segment.\"custom/k\"]\nkind = \"text\"\ntext = \"{t}\"\n");
        for bad in [
            "a\\u001b[31m",
            "a\\u202eb",
            "a\\u200bb",
            "a\\u0085b",
            "a\\u007fb",
        ] {
            assert_eq!(codes_of(&seg(bad)), [codes::CONTROL_IN_TEXT], "{bad}");
        }
        for ok in ["prod", "\\u2764\\ufe0f", "a\\u200db", "한글"] {
            assert_eq!(codes_of(&seg(ok)), [], "{ok}");
        }
    }

    // 이것을 실패시키는 것: 신뢰 파일의 빈 사용자 세그먼트 표를 "모양 전용에서 버려짐" 경고로 낮추는 것.
    #[test]
    fn an_empty_trusted_segment_needs_a_kind() {
        assert_eq!(
            codes_of("[segment.\"custom/x\"]\n"),
            [codes::SEGMENT_NEEDS_KIND]
        );
    }

    // 이것을 실패시키는 것: 테마 검사가 키·타입·값 규칙을 건너뛰는 것(`mode = 7`, 빈 모르는 표).
    #[test]
    fn themes_get_every_check() {
        let t = crate::config::tree::parse(b"[colors]\nmode = 7\n[bogus]\n").unwrap();
        let got: Vec<DiagCode> = check_theme(SourceId(0), &t)
            .iter()
            .map(|d| d.code)
            .collect();
        assert_eq!(got, [codes::WRONG_TYPE, codes::UNKNOWN_KEY]);
    }

    // 이것을 실패시키는 것: 단위 없는 값·1시간 넘는 값·소수를 받는 것.
    #[test]
    fn durations() {
        assert_eq!(parse_duration_ms("200ms"), Some(200));
        assert_eq!(parse_duration_ms("2s"), Some(2000));
        assert_eq!(parse_duration_ms("3600s"), Some(3_600_000));
        for bad in ["2", "3601s", "1.5s", "s", "-1s", "2m"] {
            assert_eq!(parse_duration_ms(bad), None, "{bad}");
        }
    }
}
