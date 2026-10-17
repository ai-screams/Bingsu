//! File-backed core checks live outside the no_std crate.
use bingsu_core::config::check::parse_duration_ms;
use bingsu_core::config::schema::{Which, schema};
use bingsu_core::diag_codes::{CODES, CodeStatus};

// 이것을 실패시키는 것: 코드를 지우는 것, 목록 파일에 적지 않고 코드를 더하는 것,
// 상태를 파일과 다르게 바꾸는 것, 번호 순서·중복을 어기는 것.
#[test]
fn registry_matches_the_listed_codes() {
    let listed = include_str!("../../bingsu-core/diag-codes.txt");
    let status = |s: CodeStatus| match s {
        CodeStatus::Stable => String::from("stable"),
        CodeStatus::Deprecated { since } => format!("deprecated {since}"),
    };
    let got: Vec<String> = CODES
        .iter()
        .map(|c| format!("{} {}", c.code, status(c.status)))
        .collect();
    let want: Vec<&str> = listed
        .lines()
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect();
    assert_eq!(got, want);
    assert!(CODES.windows(2).all(|p| p[0].code < p[1].code));
}

// 이것을 실패시키는 것: parse_duration_ms가 corpus와 다른 값을 받는 것, corpus 파일을 갱신하지 않는 것.
#[test]
fn duration_corpus_is_shared() {
    let corpus = include_str!("../../bingsu-core/schema/duration-corpus.json");
    let rows: Vec<(String, bool)> = serde_json::from_str(corpus).expect("duration corpus JSON");
    assert!(rows.len() >= 29);
    for (text, ok) in rows {
        assert_eq!(parse_duration_ms(&text).is_some(), ok, "{text:?}");
    }
}

/// The prompt path stays independent of config parsing and checking.
const PROMPT_PATH: [(&str, &str); 5] = [
    (
        "default_theme.rs",
        include_str!("../../bingsu-core/src/default_theme.rs"),
    ),
    ("render.rs", include_str!("../../bingsu-core/src/render.rs")),
    ("layout.rs", include_str!("../../bingsu-core/src/layout.rs")),
    ("front.rs", include_str!("../../bingsu-core/src/front.rs")),
    (
        "shell_values.rs",
        include_str!("../../bingsu-core/src/shell_values.rs"),
    ),
];

// 매 프롬프트는 설정을 파싱하지 않는다: 앞단은 컴파일된 snapshot만 읽는다(N4). 파서·합치기·검사는
// 설정이 바뀔 때 갱신 도우미에서만 돈다.
// 이것을 실패시키는 것: 앞단 경로의 파일이 `config` 모듈(파서·합치기·검사·컴파일)을 부르는 것.
#[test]
fn the_prompt_path_never_reads_config() {
    for (name, text) in PROMPT_PATH {
        for needle in ["config::", "toml::"] {
            assert!(!text.contains(needle), "{name} uses {needle}");
        }
    }
}

// 이것을 실패시키는 것: 생성 결과와 배포할 스키마 파일이 달라지는 것.
// 재생성: cargo run -j 2 -q -p bingsu -- config schema > crates/bingsu-core/schema/config-v1.json
// 테마: cargo run -j 2 -q -p bingsu -- config schema --theme > crates/bingsu-core/schema/theme-v1.json
#[test]
fn schemas_match_the_committed_files() {
    assert_eq!(
        schema(Which::Config),
        include_str!("../../bingsu-core/schema/config-v1.json")
    );
    assert_eq!(
        schema(Which::Theme),
        include_str!("../../bingsu-core/schema/theme-v1.json")
    );
}

// 이것을 실패시키는 것: 닫힌 표·값 범위·메타 패턴을 빼거나 잘못된 JSON 타입으로 내보내는 것.
#[test]
fn schemas_follow_the_key_table() {
    use bingsu_core::config::check::DURATION_PATTERN;
    use bingsu_core::config::keys::{KEYS, Ty};
    use bingsu_core::config::schema::{META, REQUIRES_PATTERN};
    for which in [Which::Config, Which::Theme] {
        let root: serde_json::Value = serde_json::from_str(&schema(which)).unwrap();
        assert_eq!(root["additionalProperties"], false);
        assert_eq!(
            root["$schema"],
            "https://json-schema.org/draft/2020-12/schema"
        );
        for k in META
            .iter()
            .chain(KEYS)
            .filter(|k| which == Which::Config || k.theme)
        {
            let mut node = &root;
            for part in k.path.split('.') {
                node = if part == "*" {
                    &node["additionalProperties"]
                } else {
                    &node["properties"][part]
                };
            }
            assert!(node.is_object(), "{}", k.path);
            assert_eq!(node["description"], k.en);
            assert_eq!(node["x-bingsu-description-ko"], k.ko);
            match k.ty {
                Ty::Text => assert_eq!(node["x-bingsu-type"], "text"),
                Ty::Color => assert_eq!(node["x-bingsu-type"], "color"),
                Ty::Duration => assert_eq!(node["x-bingsu-type"], "duration"),
                Ty::Segments => assert_eq!(node["items"]["x-bingsu-type"], "segment-id"),
                _ => {}
            }
            match k.ty {
                Ty::Table => {
                    assert_eq!(node["type"], "object");
                    assert!(
                        node["additionalProperties"] == false
                            || node["additionalProperties"].is_object()
                    );
                }
                Ty::Bool => assert_eq!(node["type"], "boolean"),
                Ty::Int { min, max } => {
                    assert_eq!(node["type"], "integer");
                    assert_eq!(node["minimum"], min);
                    assert_eq!(node["maximum"], max);
                }
                Ty::Float { min, max } => {
                    assert_eq!(node["type"], "number");
                    assert_eq!(node["minimum"], min);
                    assert_eq!(node["maximum"], max);
                }
                Ty::Str | Ty::Text | Ty::Color => assert_eq!(node["type"], "string"),
                Ty::Duration => {
                    assert_eq!(node["type"], "string");
                    assert_eq!(node["pattern"], DURATION_PATTERN);
                }
                Ty::Enum(values) => assert_eq!(node["enum"], serde_json::json!(values)),
                Ty::Strings | Ty::Segments => {
                    assert_eq!(node["type"], "array");
                    assert_eq!(node["items"]["type"], "string");
                }
                Ty::EnumList(values) => {
                    assert_eq!(node["type"], "array");
                    assert_eq!(node["items"]["enum"], serde_json::json!(values));
                }
            }
        }
        assert_eq!(root["properties"]["requires"]["pattern"], REQUIRES_PATTERN);
        let width = &root["properties"]["width"];
        assert_eq!(width["additionalProperties"], false);
        let colors = &root["properties"]["colors"]["properties"]["override"];
        assert_eq!(colors["additionalProperties"]["type"], "string");
    }
}

// 이것을 실패시키는 것: 내장 표가 자체 키와 enabled 외의 공통 키를 받는 것.
#[test]
fn builtin_tables_only_keep_own_keys_and_enabled() {
    use bingsu_core::config::keys::{KEYS, lookup};
    for which in [Which::Config, Which::Theme] {
        let root: serde_json::Value = serde_json::from_str(&schema(which)).unwrap();
        for decl in bingsu_core::field::BUILTIN {
            let node = &root["properties"]["segment"]["properties"][decl.id];
            assert_eq!(node["additionalProperties"], false);
            for key in KEYS.iter().filter(|k| k.path.starts_with("segment.*.")) {
                let name = key.path.rsplit('.').next().unwrap();
                let def = lookup(&["segment", decl.id, name]).unwrap();
                let allowed = (which == Which::Config || def.theme)
                    && def.kinds.is_empty()
                    && (!def.path.starts_with("segment.*.") || name == "enabled");
                assert_eq!(
                    node["properties"][name].is_object(),
                    allowed,
                    "{} {name}",
                    decl.id
                );
            }
        }
    }
}

fn merged_json(value: &serde_json::Value) -> bingsu_core::config::merge::Merged {
    use bingsu_core::config::merge::{MEntry, MNode, MTable, MValue, Merged, Origin};
    use bingsu_core::config::source::Trust;
    use bingsu_core::config::tree::{Node, Span, Value};
    use bingsu_core::diag::SourceId;
    fn convert(v: &serde_json::Value) -> MValue {
        match v {
            serde_json::Value::Object(map) => MValue::Table(MTable {
                entries: map
                    .iter()
                    .map(|(key, v)| MEntry {
                        key: key.clone(),
                        node: MNode {
                            value: convert(v),
                            origin: Origin {
                                source: SourceId(1),
                                key_span: Span::default(),
                                span: Span::default(),
                                trust: Trust::Executable,
                            },
                        },
                    })
                    .collect(),
            }),
            serde_json::Value::Array(a) => MValue::Array(
                a.iter()
                    .map(|v| {
                        let MValue::Scalar(value) = convert(v) else {
                            panic!("scalar corpus array")
                        };
                        Node {
                            value,
                            span: Span::default(),
                        }
                    })
                    .collect(),
            ),
            serde_json::Value::String(s) => MValue::Scalar(Value::Str(s.clone())),
            serde_json::Value::Bool(b) => MValue::Scalar(Value::Bool(*b)),
            serde_json::Value::Number(n) => MValue::Scalar(if let Some(i) = n.as_i64() {
                Value::Int(i)
            } else {
                Value::Float(n.as_f64().unwrap())
            }),
            serde_json::Value::Null => panic!("no null in config corpus"),
        }
    }
    let MValue::Table(root) = convert(value) else {
        panic!("config object")
    };
    Merged {
        root,
        warnings: Vec::new(),
    }
}

// 이것을 실패시키는 것: 엔진과 두 스키마 중 하나라도 같은 corpus를 다르게 판정하거나,
// KEYS.kinds·BUILTIN·ID 문법·색 파서·정제 함수 변경을 스키마가 따라가지 못하는 것.
#[test]
fn schema_corpora_match_engine_and_both_schemas() {
    use bingsu_core::config::check::check;
    use bingsu_core::config::keys::{KEYS, KINDS, Ty};
    use bingsu_core::diag_codes as codes;
    use serde_json::{Value, json};
    use std::io::Write;
    use std::process::{Command, Stdio};

    let rows = |text| serde_json::from_str::<Vec<(String, bool)>>(text).unwrap();
    let ids = rows(include_str!(
        "../../bingsu-core/schema/segment-id-corpus.json"
    ));
    for (id, ok) in ids {
        let parsed = bingsu_core::ident::parse_segment_id(&id);
        let known = parsed.is_ok_and(|s| match s.namespace() {
            bingsu_core::ident::Namespace::Builtin => bingsu_core::field::segment(&id).is_some(),
            bingsu_core::ident::Namespace::Custom => true,
            bingsu_core::ident::Namespace::Plugin => false,
        });
        assert_eq!(known, ok, "segment-id {id:?}");
        for config in [
            json!({"layout":{"line1":{"left":[id]}}}),
            json!({"segment":{&id:{"kind":"text"}}}),
        ] {
            let errors = check(&merged_json(&config));
            let bad_id = errors
                .iter()
                .any(|d| d.code == codes::BAD_SEGMENT_ID || d.code == codes::UNKNOWN_SEGMENT);
            assert_eq!(!bad_id, ok, "segment-id use {config}");
        }
    }
    for (text, ok) in rows(include_str!("../../bingsu-core/schema/color-corpus.json")) {
        assert_eq!(
            bingsu_core::color::notation::parse_color(&text).is_ok(),
            ok,
            "color {text:?}"
        );
        let diagnostics = check(&merged_json(
            &json!({"colors":{"override":{"git.dirty":text}}}),
        ));
        assert_eq!(
            !diagnostics.iter().any(|d| d.code == codes::BAD_VALUE),
            ok,
            "color checker {text:?}"
        );
    }
    for (text, ok) in rows(include_str!("../../bingsu-core/schema/text-corpus.json")) {
        assert_eq!(
            !text.chars().any(bingsu_core::sanitize::is_removed),
            ok,
            "text {text:?}"
        );
        let diagnostics = check(&merged_json(&json!({"style":{"template":text}})));
        assert_eq!(
            !diagnostics.iter().any(|d| d.code == codes::CONTROL_IN_TEXT),
            ok,
            "text checker {text:?}"
        );
    }

    let mut segment_cases = Vec::new();
    // Every builtin x key, and every user kind x key: expected acceptance
    // comes from the actual checker, not a second copy of its kinds rule.
    let definitions: Vec<_> = KEYS
        .iter()
        .filter(|k| k.path.starts_with("segment.") && k.ty != Ty::Table)
        .collect();
    for id in bingsu_core::field::BUILTIN
        .iter()
        .map(|d| d.id)
        .chain(["custom/probe"])
    {
        let kinds: Vec<_> = if id.contains('/') {
            KINDS.into_iter().map(Some).collect()
        } else {
            vec![None]
        };
        for kind in kinds {
            for key in &definitions {
                let name = key.path.rsplit('.').next().unwrap();
                if name == "kind" {
                    continue;
                }
                let example: Value =
                    serde_json::from_str(key.example.or(key.default).unwrap()).unwrap();
                let mut props = json!({name: example});
                if let Some(kind) = kind {
                    props["kind"] = json!(kind);
                }
                let segment = json!({id: props});
                let diagnostics = check(&merged_json(&json!({"segment": segment})));
                let ok = !diagnostics
                    .iter()
                    .any(|d| [codes::KEY_NOT_FOR_KIND, codes::UNKNOWN_KEY].contains(&d.code));
                let schemas = if kind.is_none() && key.theme {
                    json!(["config", "theme"])
                } else {
                    json!(["config"])
                };
                segment_cases.push(json!({"segment":segment,"ok":ok,"schemas":schemas}));
            }
        }
    }
    let fixtures: Vec<Value> = serde_json::from_str(include_str!(
        "../../bingsu-core/schema/segment-keys-corpus.json"
    ))
    .unwrap();
    for case in fixtures {
        let mut segment = case["segment"].clone();
        // A file may inherit its kind. Supply that inherited execution
        // context only to the merged checker, never to the schema input.
        for (id, props) in segment.as_object_mut().unwrap() {
            if id.starts_with("custom/") && props.get("kind").is_none() {
                props["kind"] = json!(if props.get("command").is_some() {
                    "command"
                } else {
                    "text"
                });
            }
        }
        let diagnostics = check(&merged_json(&json!({"segment":segment})));
        assert_eq!(
            diagnostics.iter().all(|d| d.code == codes::KEY_PLANNED),
            case["ok"].as_bool().unwrap(),
            "{case}: {diagnostics:?}"
        );
    }
    let data = json!({"schemas": {"config":serde_json::from_str::<Value>(&schema(Which::Config)).unwrap(), "theme":serde_json::from_str::<Value>(&schema(Which::Theme)).unwrap()}, "segment_cases":segment_cases});
    let script = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../scripts/check_schema_corpus.py"
    );
    let mut child = Command::new("python3")
        .args([script, "--stdin"])
        .stdin(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(data.to_string().as_bytes())
        .unwrap();
    assert!(
        child.wait().unwrap().success(),
        "fresh schemas disagree with corpus"
    );
}
