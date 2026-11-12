//! `bingsu list` rows come from the same tables as the published schemas
//! and the renderer (plan D2).
use bingsu_core::color::palette::TOKENS;
use bingsu_core::config::schema::{Which, schema};
use bingsu_core::field::BUILTIN;
use bingsu_core::icons::ICONS;
use bingsu_core::listing::{What, rows};
use bingsu_core::style::PRESETS;
use serde_json::Value;

fn enum_at(root: &Value, path: &[&str]) -> Vec<String> {
    let mut v = root;
    for k in path {
        v = &v["properties"][*k];
    }
    let e = if v["enum"].is_array() {
        &v["enum"]
    } else {
        &v["items"]["enum"]
    };
    e.as_array()
        .unwrap_or_else(|| panic!("no enum at {path:?}"))
        .iter()
        .map(|x| x.as_str().unwrap().to_string())
        .collect()
}

fn first_column(w: What) -> Vec<String> {
    rows(w)
        .iter()
        .map(|r| r.split('\t').next().unwrap().to_string())
        .collect()
}

// 이것을 실패시키는 것: `list`가 스키마와 따로 쓴 이름표를 갖는 것(프리셋·flavor·줄임 방법이 스키마 enum과 갈라짐),
// 세그먼트·역할·아이콘 행이 선언 표(`BUILTIN`, `TOKENS`, `ICONS`)에서 오지 않는 것, 종류가 비어 있는 것.
#[test]
fn rows_equal_the_tables_the_schema_and_renderer_read() {
    let root: Value = serde_json::from_str(&schema(Which::Config)).unwrap();
    assert_eq!(
        first_column(What::Presets),
        enum_at(&root, &["style", "preset"])
    );
    assert_eq!(
        first_column(What::Flavors),
        enum_at(&root, &["colors", "flavor"])
    );
    assert_eq!(
        first_column(What::Shorteners),
        enum_at(&root, &["segment", "dir", "shorten"])
    );
    let presets: Vec<&str> = PRESETS.iter().map(|p| p.name).collect();
    assert_eq!(first_column(What::Presets), presets);
    let ids: Vec<&str> = BUILTIN.iter().map(|d| d.id).collect();
    assert_eq!(first_column(What::Segments), ids);
    let roles: Vec<&str> = TOKENS.iter().map(|t| t.name).collect();
    assert_eq!(first_column(What::Roles), roles);
    let icons: Vec<&str> = ICONS.iter().map(|i| i.name()).collect();
    assert_eq!(first_column(What::Icons), icons);
    // Every role a segment names is a listed role.
    for d in BUILTIN {
        assert!(roles.contains(&d.role), "{} -> {}", d.id, d.role);
    }
    for w in What::ALL {
        assert!(!rows(w).is_empty(), "{}", w.word());
        assert_eq!(What::parse(w.word()), Some(w));
    }
}
