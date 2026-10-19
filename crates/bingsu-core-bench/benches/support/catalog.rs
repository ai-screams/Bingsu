//! Fixture mistakes must stop the benchmark before it measures another segment.
use bingsu_core::field::{BUILTIN, Field, Value, segment};

pub fn index(id: &str) -> usize {
    BUILTIN
        .iter()
        .position(|d| d.id == id)
        .expect("unknown benchmark segment id")
}

pub fn value(id: &str, text: &[u8]) -> Option<Value> {
    let d = segment(id).expect("unknown benchmark segment id");
    Some(Value::new(text, vec![Field::ABSENT; d.fields.len()]))
}
