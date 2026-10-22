//! Git stage vocabulary; partial results use the existing logical Update.
use crate::field::{self, FieldValue, Value, ValueState};

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

/// A reported stage alone is not evidence: HEAD must have a known branch or
/// detached commit, or the known absence of an unborn HEAD. Completed files
/// may retain a later cumulative snapshot.
pub(crate) fn stage_a_evidence(value: &Value, later: bool) -> bool {
    let decl = &field::BUILTIN[usize::from(SEGMENT)];
    if value.check(decl).is_err() {
        return false;
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
