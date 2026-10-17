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

// 이것을 실패시키는 것: 고정 세그먼트 표에서 공통 키를 버려 유효한 설정을 편집기가 거부하는 것.
#[test]
fn literal_tables_keep_shared_segment_keys() {
    let root: serde_json::Value = serde_json::from_str(&schema(Which::Config)).unwrap();
    let segments = &root["properties"]["segment"];
    for name in ["dir", "duration"] {
        let p = &segments["properties"][name]["properties"];
        assert_eq!(
            p["enabled"],
            segments["additionalProperties"]["properties"]["enabled"]
        );
        assert_eq!(
            p["command"],
            segments["additionalProperties"]["properties"]["command"]
        );
        assert_eq!(segments["properties"][name]["additionalProperties"], false);
    }
    assert!(segments["properties"]["dir"]["properties"]["shorten"].is_object());
    assert!(segments["properties"]["duration"]["properties"]["min"].is_object());
}
