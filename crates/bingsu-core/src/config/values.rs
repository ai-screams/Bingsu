//! Reading a merged config table: the value at a key path, with the key
//! table's default, and the place a key came from for a diagnostic. Leaf
//! helpers shared by `compile`, `layouts`, `exec_units` and `check`, with the
//! duration grammar (`parse_duration_ms` and its schema pattern); they depend
//! only on the merge, the key table and the diagnostics.
use crate::config::keys;
use crate::config::merge::{MEntry, MNode, MTable, MValue};
use crate::config::tree::Value;
use crate::diag::{Diagnostic, Place};
use crate::diag_codes as codes;
use alloc::string::String;
use alloc::vec::Vec;

pub(super) fn get<'a>(t: &'a MTable, path: &[&str]) -> Option<&'a MNode> {
    t.at(path)
}

pub(super) fn s<'a>(t: &'a MTable, path: &[&str]) -> Option<&'a str> {
    match get(t, path).map(|n| &n.value) {
        Some(MValue::Scalar(Value::Str(v))) => Some(v),
        _ => None,
    }
}

pub(super) fn int(t: &MTable, path: &[&str]) -> Option<i64> {
    match get(t, path).map(|n| &n.value) {
        Some(MValue::Scalar(Value::Int(v))) => Some(*v),
        _ => None,
    }
}

pub(super) fn float(t: &MTable, path: &[&str]) -> Option<f64> {
    match get(t, path).map(|n| &n.value) {
        Some(MValue::Scalar(Value::Float(v))) => Some(*v),
        Some(MValue::Scalar(Value::Int(v))) => Some(*v as f64),
        _ => None,
    }
}

pub(super) fn boolean(t: &MTable, path: &[&str]) -> Option<bool> {
    match get(t, path).map(|n| &n.value) {
        Some(MValue::Scalar(Value::Bool(v))) => Some(*v),
        _ => None,
    }
}

pub(super) fn strings(n: &MNode) -> Vec<String> {
    match &n.value {
        MValue::Array(a) => a
            .iter()
            .filter_map(|i| match &i.value {
                Value::Str(s) => Some(s.clone()),
                _ => None,
            })
            .collect(),
        _ => Vec::new(),
    }
}

pub(super) fn entries<'a>(t: &'a MTable, path: &[&str]) -> &'a [MEntry] {
    match get(t, path).map(|n| &n.value) {
        Some(MValue::Table(t)) => &t.entries,
        _ => &[],
    }
}

/// The table's default for `path` as a string (`"auto"` → `auto`).
pub(super) fn default_str(path: &str) -> &'static str {
    keys::KEYS
        .iter()
        .find(|k| k.path == path)
        .and_then(|k| k.default)
        .map_or("", |d| d.trim_matches('"'))
}

pub(super) fn at(n: &MNode) -> Place {
    Place::Source {
        id: n.origin.source,
        span: n.origin.span,
    }
}

pub(super) fn optional_duration(text: Option<&str>) -> Option<u64> {
    match text {
        Some(text) => parse_duration_ms(text),
        None => None,
    }
}

pub(super) fn place_of(t: &MTable, path: &[&str]) -> Place {
    match get(t, path) {
        Some(n) => at(n),
        None => Place::Builtin,
    }
}

pub(super) fn bad(place: Place, key: &str, found: &str, expected: &str) -> Diagnostic {
    Diagnostic::new(codes::BAD_VALUE, place)
        .arg("key", key)
        .arg("found", found)
        .arg("expected", expected)
}

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
