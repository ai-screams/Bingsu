//! Git stage vocabulary; partial results use the existing logical Update.
use crate::field::{self, Field, FieldValue, Value, ValueState};
use crate::width::WidthProfile;

pub const SEGMENT: u16 = 3;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stage {
    A,
    B,
    C,
    D,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StageResult {
    Hidden,
    Partial(Value),
    Value(Value),
}

/// A completed discovery outside a repository. This present value is evidence;
/// Hidden/None still means that stage A has not produced a usable result.
/// Only no_repo=true, partial=false and stage=A are set; all repository fields
/// are Known Absent and display text is empty. The front hides the whole value.
pub fn no_repo() -> Value {
    let decl = &field::BUILTIN[usize::from(SEGMENT)];
    let mut fields = alloc::vec![Field::ABSENT; decl.fields.len()];
    for (name, field) in [
        ("no_repo", Field::known(FieldValue::Bool(true))),
        ("partial", Field::known(FieldValue::Bool(false))),
        ("stage", Field::text(b"A", 1, WidthProfile::DEFAULT)),
    ] {
        fields[decl.field_index(name).expect("fixed git field")] = field;
    }
    Value::new(b"", fields)
}

pub(crate) fn is_no_repo(value: &Value) -> bool {
    let decl = &field::BUILTIN[usize::from(SEGMENT)];
    value
        .fields
        .get(decl.field_index("no_repo").expect("fixed git field"))
        == Some(&Field::known(FieldValue::Bool(true)))
}

/// Semantic checks shared by wire input and completed response encode/decode.
pub(crate) fn valid(value: &Value) -> bool {
    let decl = &field::BUILTIN[usize::from(SEGMENT)];
    if value.check(decl).is_err() {
        return false;
    }
    let get = |name| &value.fields[decl.field_index(name).expect("fixed git field")];
    let known_text = |name| {
        let f = get(name);
        f.state == ValueState::Known && matches!(f.value, FieldValue::Text(_))
    };
    if known_text("branch") && known_text("commit") {
        return false;
    }
    if is_no_repo(value) {
        return value.text().is_empty()
            && value
                .fields
                .iter()
                .zip(decl.fields)
                .all(|(f, d)| match d.name {
                    "no_repo" => true,
                    "partial" => f == &Field::known(FieldValue::Bool(false)),
                    "stage" => {
                        f.state == ValueState::Known
                            && matches!(&f.value, FieldValue::Text(t) if t.as_str() == "A")
                    }
                    _ => f == &Field::ABSENT,
                });
    }
    true
}

/// A reported stage alone is not evidence: HEAD must have a known branch or
/// detached commit, the known absence of an unborn HEAD, or the explicit
/// no-repository marker. Completed files may retain a later repository snapshot.
pub(crate) fn stage_a_evidence(value: &Value, later: bool) -> bool {
    let decl = &field::BUILTIN[usize::from(SEGMENT)];
    if !valid(value) {
        return false;
    }
    if is_no_repo(value) {
        return true;
    }
    let get = |name| &value.fields[decl.field_index(name).expect("fixed git field")];
    let text = |name| {
        let f = get(name);
        match &f.value {
            FieldValue::Text(t) if f.state == ValueState::Known => Some(t.as_str()),
            _ => None,
        }
    };
    let stage = text("stage");
    if !(stage == Some("A") || later && matches!(stage, Some("B" | "C" | "D"))) {
        return false;
    }
    let detached = get("detached");
    if detached.state != ValueState::Known {
        return false;
    }
    match detached.value {
        FieldValue::Bool(false) => {
            text("branch").is_some_and(|s| !s.is_empty())
                || (get("branch") == &field::Field::ABSENT
                    && get("commit") == &field::Field::ABSENT)
        }
        FieldValue::Bool(true) => text("commit").is_some_and(|s| {
            s.len() == 12
                && s.bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        }),
        _ => false,
    }
}
