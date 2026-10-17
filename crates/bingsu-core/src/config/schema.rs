//! JSON Schema of the config and of a theme (spec section 2 "JSON Schema"),
//! made from the key table, so the editor, `config check` and the docs
//! agree. Every key carries `x-bingsu-level`, its default, an example
//! (`examples`) and a description in English (`description`) and Korean
//! (`x-bingsu-description-ko`); execution keys carry `x-bingsu-exec`, keys of
//! a later milestone `x-bingsu-planned`. Tables are closed
//! (`additionalProperties: false`): an unknown key is an error, as in
//! `config check`. Plugin fields cannot be listed ahead of time; `config
//! check` checks them from the installed declarations.
use crate::config::check::DURATION_PATTERN;
use crate::config::keys::{KEYS, KeyDef, Level, Ty};
use crate::config::merge::KeyClass;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write as _;

/// Version of the logical value and fact schema: `field::FieldValue`,
/// `field::ValueState`, `shorten::PathFacts` as of M2 (spec section 4 "필드
/// 타입과 값 상태"). It goes up when one of them changes in a way a reader
/// of an older version would misread; `FACT_SCHEMA` below is the shape it
/// stands for. The tests `fact_schema_matches_the_types` (here) and
/// `path_facts_fields_are_the_fact_schema` (`shorten.rs`) stop compiling
/// when a variant or field is added, removed or renamed, so the text and the
/// version are looked at in the same change.
pub const FACT_SCHEMA_VERSION: u16 = 1;
pub const FACT_SCHEMA: &str = "FieldType: Text{max_cells} Count Int Duration Bool; FieldValue: Text Count{n,saturated} Int Duration{ms} Bool Absent; ValueState: Known Pending; PathFacts: anchor steps repo_root unique";
/// Version of the config format (`version = 1`).
pub const CONFIG_VERSION: i64 = 1;

/// `requires = ">=MAJOR.MINOR[.PATCH]"` (`source::parse_requires`).
pub const REQUIRES_PATTERN: &str = "^>=[0-9]{1,9}\\.[0-9]{1,9}(\\.[0-9]{1,9})?$(?![\\s\\S])";

const fn meta(
    path: &'static str,
    ty: Ty,
    theme: bool,
    example: &'static str,
    en: &'static str,
    ko: &'static str,
) -> KeyDef {
    KeyDef {
        path,
        ty,
        class: KeyClass::Shape,
        theme,
        level: Level::Expert,
        default: None,
        example: Some(example),
        planned: None,
        kinds: &[],
        en,
        ko,
    }
}

/// Keys read per file and not merged (`config::source`).
pub const META: [KeyDef; 3] = [
    meta(
        "version",
        Ty::Int { min: 1, max: 1 },
        true,
        "1",
        "Config format version.",
        "설정 형식 버전.",
    ),
    meta(
        "requires",
        Ty::Str,
        true,
        "\">=0.3\"",
        "Minimum bingsu version.",
        "필요한 bingsu 최소 버전.",
    ),
    meta(
        "extends",
        Ty::Strings,
        false,
        "[\"~/dotfiles/bingsu-team.toml\"]",
        "Local files applied before this one.",
        "이 파일보다 먼저 적용할 로컬 파일.",
    ),
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Which {
    Config,
    Theme,
}

fn esc(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

fn level(l: Level) -> &'static str {
    match l {
        Level::Basic => "basic",
        Level::Advanced => "advanced",
        Level::Expert => "expert",
    }
}

fn strings(list: &[&str], out: &mut String) {
    out.push('[');
    for (i, s) in list.iter().enumerate() {
        if i > 0 {
            out.push_str(", ");
        }
        esc(s, out);
    }
    out.push(']');
}

fn pad(n: usize, out: &mut String) {
    for _ in 0..n {
        out.push_str("  ");
    }
}

// Literal tables inherit matching wildcard children, just as `keys::lookup`
// does for the checker. A more specific row replaces a generic child.
fn keys_under(prefix: &str, which: Which) -> Vec<&'static KeyDef> {
    children_under(prefix, which, META.iter().chain(KEYS))
}

fn children_under<'a>(
    prefix: &str,
    which: Which,
    rows: impl Iterator<Item = &'a KeyDef>,
) -> Vec<&'a KeyDef> {
    let mut children: Vec<&KeyDef> = Vec::new();
    for k in rows {
        let (parent, last) = k.path.rsplit_once('.').unwrap_or(("", k.path));
        let mut parts = prefix.split('.');
        let matches = if prefix.is_empty() {
            parent.is_empty()
        } else {
            parent
                .split('.')
                .all(|p| parts.next().is_some_and(|s| p == "*" || p == s))
                && parts.next().is_none()
        };
        if !matches {
            continue;
        }
        if let Some(old) = children
            .iter_mut()
            .find(|c| c.path.rsplit('.').next() == Some(last))
        {
            if k.path.matches('*').count() < old.path.matches('*').count() {
                *old = k;
            }
        } else {
            children.push(k);
        }
    }
    children.retain(|k| which == Which::Config || k.theme);
    children
}

fn node(k: &KeyDef, which: Which, depth: usize, out: &mut String) {
    out.push_str("{\n");
    let mut fields: Vec<(&str, String)> = Vec::new();
    let mut v = String::new();
    match k.ty {
        Ty::Bool => fields.push(("type", String::from("\"boolean\""))),
        Ty::Int { min, max } => {
            fields.push(("type", String::from("\"integer\"")));
            fields.push(("minimum", alloc::format!("{min}")));
            fields.push(("maximum", alloc::format!("{max}")));
        }
        Ty::Float { min, max } => {
            fields.push(("type", String::from("\"number\"")));
            fields.push(("minimum", alloc::format!("{min}")));
            fields.push(("maximum", alloc::format!("{max}")));
        }
        Ty::Str | Ty::Text | Ty::Color => {
            fields.push(("type", String::from("\"string\"")));
            if k.path == "requires" {
                esc(REQUIRES_PATTERN, &mut v);
                fields.push(("pattern", core::mem::take(&mut v)));
            }
        }
        Ty::Duration => {
            fields.push(("type", String::from("\"string\"")));
            esc(DURATION_PATTERN, &mut v);
            fields.push(("pattern", core::mem::take(&mut v)));
        }
        Ty::Enum(list) => {
            strings(list, &mut v);
            fields.push(("enum", core::mem::take(&mut v)));
        }
        Ty::Strings | Ty::Segments => {
            fields.push(("type", String::from("\"array\"")));
            fields.push(("items", String::from("{ \"type\": \"string\" }")));
        }
        Ty::EnumList(list) => {
            fields.push(("type", String::from("\"array\"")));
            strings(list, &mut v);
            fields.push((
                "items",
                alloc::format!("{{ \"enum\": {} }}", core::mem::take(&mut v)),
            ));
        }
        Ty::Table => {
            fields.push(("type", String::from("\"object\"")));
            let children = keys_under(k.path, which);
            let named: Vec<_> = children
                .iter()
                .filter(|c| !c.path.ends_with(".*"))
                .collect();
            if !named.is_empty() {
                let mut props = String::from("{\n");
                for (i, c) in named.iter().enumerate() {
                    pad(depth + 2, &mut props);
                    esc(c.path.rsplit('.').next().unwrap_or(""), &mut props);
                    props.push_str(": ");
                    node(c, which, depth + 2, &mut props);
                    props.push_str(if i + 1 < named.len() { ",\n" } else { "\n" });
                }
                pad(depth + 1, &mut props);
                props.push('}');
                fields.push(("properties", props));
            }
            let extra = match children.iter().find(|c| c.path.ends_with(".*")) {
                Some(star) => {
                    let mut s = String::new();
                    node(star, which, depth + 1, &mut s);
                    s
                }
                None => String::from("false"),
            };
            fields.push(("additionalProperties", extra));
        }
    }
    if let Some(d) = k.default {
        fields.push(("default", String::from(d)));
    }
    if let Some(e) = k.example.or(k.default) {
        fields.push(("examples", alloc::format!("[{e}]")));
    }
    let mut d = String::new();
    esc(k.en, &mut d);
    fields.push(("description", d));
    let mut d = String::new();
    esc(k.ko, &mut d);
    fields.push(("x-bingsu-description-ko", d));
    fields.push(("x-bingsu-level", alloc::format!("\"{}\"", level(k.level))));
    if k.class == KeyClass::Exec {
        fields.push(("x-bingsu-exec", String::from("true")));
    }
    if let Some(m) = k.planned {
        fields.push(("x-bingsu-planned", alloc::format!("\"{m}\"")));
    }
    for (i, (name, value)) in fields.iter().enumerate() {
        pad(depth + 1, out);
        esc(name, out);
        out.push_str(": ");
        out.push_str(value);
        out.push_str(if i + 1 < fields.len() { ",\n" } else { "\n" });
    }
    pad(depth, out);
    out.push('}');
}

/// The schema text (JSON, two-space indent, keys in table order).
pub fn schema(which: Which) -> String {
    let root = KeyDef {
        path: "",
        ty: Ty::Table,
        class: KeyClass::Shape,
        theme: true,
        level: Level::Basic,
        default: None,
        example: None,
        planned: None,
        kinds: &[],
        en: match which {
            Which::Config => "bingsu config",
            Which::Theme => "bingsu theme",
        },
        ko: match which {
            Which::Config => "bingsu 설정",
            Which::Theme => "bingsu 테마",
        },
    };
    let mut body = String::new();
    node(&root, which, 0, &mut body);
    // `body` is `{\n  "type": …}`: the schema line goes after its brace.
    let mut out =
        String::from("{\n  \"$schema\": \"https://json-schema.org/draft/2020-12/schema\",\n");
    out.push_str(&body[2..]);
    out.push('\n');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // 이것을 실패시키는 것: FieldType·FieldValue·ValueState의 변형이나 필드를 바꾸면서 FACT_SCHEMA와 버전을 그대로 두는 것
    // (match에 와일드카드가 없어 바꾸면 컴파일이 멈추고, 이 글을 고치게 된다).
    #[test]
    fn fact_schema_matches_the_types() {
        use crate::field::{FieldType, FieldValue, ValueState};
        let ty = |t: FieldType| match t {
            FieldType::Text { max_cells: _ } => "Text{max_cells}",
            FieldType::Count => "Count",
            FieldType::Int => "Int",
            FieldType::Duration => "Duration",
            FieldType::Bool => "Bool",
        };
        let value = |v: &FieldValue| match v {
            FieldValue::Text(_) => "Text",
            FieldValue::Count { n: _, saturated: _ } => "Count{n,saturated}",
            FieldValue::Int(_) => "Int",
            FieldValue::Duration { ms: _ } => "Duration{ms}",
            FieldValue::Bool(_) => "Bool",
            FieldValue::Absent => "Absent",
        };
        let state = |s: ValueState| match s {
            ValueState::Known => "Known",
            ValueState::Pending => "Pending",
        };
        let types = [
            FieldType::Text { max_cells: 1 },
            FieldType::Count,
            FieldType::Int,
            FieldType::Duration,
            FieldType::Bool,
        ];
        let values = [
            FieldValue::Text(Default::default()),
            FieldValue::Count {
                n: 0,
                saturated: false,
            },
            FieldValue::Int(0),
            FieldValue::Duration { ms: 0 },
            FieldValue::Bool(false),
            FieldValue::Absent,
        ];
        let text = alloc::format!(
            "FieldType: {}; FieldValue: {}; ValueState: {} {}; PathFacts: anchor steps repo_root unique",
            types.map(ty).join(" "),
            values.iter().map(value).collect::<Vec<_>>().join(" "),
            state(ValueState::Known),
            state(ValueState::Pending),
        );
        assert_eq!((text.as_str(), FACT_SCHEMA_VERSION), (FACT_SCHEMA, 1));
    }

    // 이것을 실패시키는 것: 테마 스키마에 실행 키·`extends`·`theme`이 들어가거나, 설정 스키마에서 실행 표시가 빠지는 것.
    #[test]
    fn the_theme_schema_has_no_execution_key() {
        let t = schema(Which::Theme);
        for k in [
            "\"command\"",
            "\"kind\"",
            "\"cwd\"",
            "\"extends\"",
            "\"theme\"",
            "x-bingsu-exec",
        ] {
            assert!(!t.contains(k), "{k}");
        }
        let c = schema(Which::Config);
        for k in KEYS.iter().filter(|k| k.class == KeyClass::Exec) {
            let mut rendered = String::new();
            node(k, Which::Config, 0, &mut rendered);
            assert!(rendered.contains("\"x-bingsu-exec\": true"), "{}", k.path);
        }
        assert!(c.contains("\"x-bingsu-level\": \"basic\""));
    }

    // 스펙 2절: 키마다 층·기본값·예시·두 언어 설명. 메타 키도 같은 틀.
    // 이것을 실패시키는 것: 예시나 층을 빠뜨린 키, 뒤 마일스톤 키의 표시를 빼먹는 것.
    #[test]
    fn every_key_has_an_example_and_a_level() {
        for k in META.iter().chain(KEYS) {
            let mut rendered = String::new();
            node(k, Which::Config, 0, &mut rendered);
            assert!(rendered.contains("\"x-bingsu-level\""), "{}", k.path);
            assert!(rendered.contains("\"description\""), "{}", k.path);
            assert!(
                rendered.contains("\"x-bingsu-description-ko\""),
                "{}",
                k.path
            );
            if k.ty != Ty::Table {
                let example = k.example.or(k.default).expect("value key needs an example");
                assert!(
                    rendered.contains(&alloc::format!("\"examples\": [{example}]")),
                    "{}",
                    k.path
                );
            }
            if let Some(default) = k.default {
                assert!(
                    rendered.contains(&alloc::format!("\"default\": {default}")),
                    "{}",
                    k.path
                );
            }
            if let Some(planned) = k.planned {
                assert!(
                    rendered.contains(&alloc::format!("\"x-bingsu-planned\": \"{planned}\"")),
                    "{}",
                    k.path
                );
            }
        }
    }

    // 이것을 실패시키는 것: 공통 자식이 고정 자식을 덮어쓰거나, 깊이가 다른 표의 자식이 섞이는 것.
    #[test]
    fn literal_children_win_at_the_exact_depth() {
        let rows = [
            KeyDef {
                path: "segment.*.enabled",
                ..META[0]
            },
            KeyDef {
                path: "segment.dir.enabled",
                ..META[0]
            },
            KeyDef {
                path: "segment.dir.more.enabled",
                ..META[0]
            },
            KeyDef {
                path: "segment.other.enabled",
                ..META[0]
            },
            KeyDef {
                path: "segment.enabled",
                ..META[0]
            },
        ];
        for selected in [
            children_under("segment.dir", Which::Config, rows.iter()),
            children_under("segment.dir", Which::Config, rows.iter().rev()),
        ] {
            assert_eq!(selected.len(), 1);
            assert_eq!(selected[0].path, "segment.dir.enabled");
        }
    }

    // 이것을 실패시키는 것: 글의 따옴표·역슬래시·제어 문자를 그대로 내보내는 것(JSON이 깨짐).
    #[test]
    fn strings_are_escaped() {
        let mut s = String::new();
        esc("a\"b\\c\nd\u{1}", &mut s);
        assert_eq!(s, "\"a\\\"b\\\\c\\nd\\u0001\"");
    }
}
