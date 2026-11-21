//! The starter file `bingsu setup` writes, for every icon set and mode: the
//! engine reads it without a diagnostic, and the published schema its
//! `#:schema` line names accepts it.
use bingsu_core::config::starter::{Choices, Icons, Mode, SCHEMA_URL, starter};
use bingsu_core::config::tree::{self, Table, Value};
use bingsu_core_tests::json_schema::validate_against;
use bingsu_core_tests::snapshot_fixture::report;

fn all() -> Vec<Choices> {
    Icons::ALL
        .into_iter()
        .flat_map(|icons| {
            [Mode::Auto, Mode::Dark, Mode::Light]
                .into_iter()
                .map(move |mode| Choices { icons, mode })
        })
        .collect()
}

/// The parsed file as the JSON a schema validator reads.
fn json(t: &Table) -> serde_json::Value {
    fn value(v: &Value) -> serde_json::Value {
        match v {
            Value::Str(s) | Value::DateTime(s) => s.as_str().into(),
            Value::Int(i) => (*i).into(),
            Value::Float(f) => (*f).into(),
            Value::Bool(b) => (*b).into(),
            Value::Array(a) => a.iter().map(|n| value(&n.value)).collect(),
            Value::Table(t) => json(t),
        }
    }
    t.entries
        .iter()
        .map(|e| (e.key.clone(), value(&e.node.value)))
        .collect::<serde_json::Map<_, _>>()
        .into()
}

// 이것을 실패시키는 것: 시작 설정이 엔진에서 진단(오류·경고·알림)을 내는 것, compile되지 않는 것, 고른 집합과
// 다른 `icons`가 compile에 닿는 것, 공개 스키마(`#:schema` 줄이 가리키는 `config-v1.json`)가 어느 집합이나
// 시작 프리셋을 받지 않는 것, 스키마가 가리키는 파일 이름이 바뀌는 것.
#[test]
fn every_starter_reads_cleanly_and_passes_the_schema() {
    assert!(SCHEMA_URL.ends_with("/crates/bingsu-core/schema/config-v1.json"));
    let mut docs = Vec::new();
    for c in all() {
        let text = starter(c);
        let r = report(&text);
        assert!(r.diagnostics.is_empty(), "{c:?}: {:?}", r.diagnostics);
        let compiled = r.snapshot.unwrap_or_else(|| panic!("{c:?} compiles"));
        assert_eq!(
            Some(compiled.icons),
            bingsu_core::icons::IconSet::parse(c.icons.word()),
            "{c:?}"
        );
        let t = tree::parse(text.as_bytes()).unwrap();
        docs.push(json(&t).to_string());
    }
    let docs: Vec<&str> = docs.iter().map(String::as_str).collect();
    assert_eq!(docs.len(), 12);
    if let Err(e) = validate_against("config-v1.json", None, &docs) {
        panic!("{e}");
    }
}
