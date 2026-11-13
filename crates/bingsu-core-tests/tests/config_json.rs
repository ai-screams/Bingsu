//! The same settings written in TOML and in JSON compile to the same
//! snapshot once provenance is left out (which file and which bytes a value
//! came from differ by nature), and draw the same prompt. The format comes
//! from the file name.
use bingsu_core::color::palette::Mode;
use bingsu_core::color::sgr::ColorDepth;
use bingsu_core::config::compile::{BUILTIN_TOML, CompiledConfig};
use bingsu_core::config::merge::Origin;
use bingsu_core::config::report::{ConfigReport, report};
use bingsu_core::config::source::{ExtendsRef, FileKey, OpenError, Opened, Resolver, Trust};
use bingsu_core::config::tree::Span;
use bingsu_core::diag::SourceId;
use bingsu_core::field::{BUILTIN, Field, FieldValue, Value, segment};
use bingsu_core::layout::{Inputs, Options};
use bingsu_core::recorder::NoopRecorder;
use bingsu_core::render::{Target, render_prompt};
use bingsu_core::shell_word::Shell;
use bingsu_core::shorten::{Anchor, PathFacts};
use bingsu_core::snapshot_codec::encode_compiled;

struct NoFiles;
impl Resolver for NoFiles {
    fn open(&mut self, _: &Opened, _: &ExtendsRef) -> Result<Opened, OpenError> {
        panic!("the fixtures have no extends");
    }
}

fn read(name: &str, text: &str) -> ConfigReport {
    let file = |ino, display: &[u8], bytes: &str| Opened {
        key: FileKey { dev: 1, ino },
        bytes: bytes.as_bytes().to_vec(),
        trust: Trust::Executable,
        display: display.to_vec(),
    };
    let roots = vec![
        file(0, b"(built-in)", BUILTIN_TOML),
        file(1, name.as_bytes(), text),
    ];
    report(roots, &mut NoFiles, [0, 3, 0], Mode::Dark)
}

fn compiled(name: &str, text: &str) -> CompiledConfig {
    let r = read(name, text);
    r.snapshot
        .unwrap_or_else(|| panic!("{name}: {:?}", r.diagnostics))
}

/// The snapshot bytes without provenance: every origin keeps its trust and
/// loses its file and byte ranges.
fn without_provenance(mut c: CompiledConfig) -> Vec<u8> {
    let blank = |o: &mut Origin| {
        o.source = SourceId(0);
        o.key_span = Span::default();
        o.span = Span::default();
    };
    for unit in &mut c.exec_units {
        unit.origins.iter_mut().for_each(|(_, o)| blank(o));
        for r in unit.approved_by.iter_mut().chain(unit.shown_at.iter_mut()) {
            r.origin.as_mut().map(blank);
        }
    }
    encode_compiled(&c).unwrap()
}

fn prompt(c: &CompiledConfig, width: u16) -> bingsu_core::render::RenderedPrompt {
    let i = |id| BUILTIN.iter().position(|x| x.id == id).unwrap();
    let v = |id: &str, text: &[u8], set: &[(&str, FieldValue)]| {
        let s = segment(id).unwrap();
        let mut f = vec![Field::ABSENT; s.fields.len()];
        for (n, x) in set {
            f[s.field_index(n).unwrap()] = Field::known(x.clone());
        }
        Some(Value::new(text, f))
    };
    let mut values = vec![None; BUILTIN.len()];
    let mut facts = vec![None; BUILTIN.len()];
    values[i("char")] = v("char", b"", &[("failed", FieldValue::Bool(true))]);
    values[i("dir")] = v("dir", b"", &[]);
    let steps: [&[u8]; 2] = [b"Works", b"AiScream"];
    facts[i("dir")] = Some(PathFacts::new(Anchor::Home, &steps, None, &[]));
    values[i("status")] = v("status", b"1", &[("code", FieldValue::Int(1))]);
    let setup = c.setup();
    let inputs = Inputs {
        catalog: BUILTIN,
        values: &values,
        facts: &facts,
        setup: &setup,
    };
    let target = Target {
        shell: Shell::Zsh,
        depth: ColorDepth::Ansi256,
        options: Options {
            width,
            profile: c.profile,
            icons: c.icons,
            use_last_column: c.use_last_column,
        },
    };
    render_prompt(&c.theme(), &inputs, &target, &mut NoopRecorder)
}

const TOML: &str = r##"version = 1
icons = "ascii"
[colors]
mode = "dark"
override = { "git.dirty" = "#ff8800", "path" = "214" }
knobs = { hue = 250, accent_l = 0.74, accent_c = 0.1 }
[layout]
use_last_column = false
[layout.line1]
left = ["dir", "git", "custom/hi"]
right = ["status", "custom/run"]
[layout.line2]
left = ["char"]
[layout.when.narrow]
max_cols = 60
order = 2
[layout.when.narrow.line1]
left = ["dir", "char"]
[width]
ambiguous = 2
[segment.dir]
shorten = ["repo", "depth"]
[segment.duration]
min = "3s"
[segment."custom/hi"]
kind = "text"
text = "hi"
[segment."custom/run"]
kind = "command"
command = ["date", "+%H"]
timeout = "150ms"
cache = "20s"
env_allow = ["LANG"]
"##;

const JSON: &str = r##"{
  "$schema": "https://example.com/bingsu/config-v1.json",
  "version": 1,
  "icons": "ascii",
  "colors": {
    "mode": "dark",
    "override": {"git.dirty": "#ff8800", "path": "214"},
    "knobs": {"hue": 250, "accent_l": 0.74, "accent_c": 0.1}
  },
  "layout": {
    "use_last_column": false,
    "line1": {"left": ["dir", "git", "custom/hi"], "right": ["status", "custom/run"]},
    "line2": {"left": ["char"]},
    "when": {"narrow": {"max_cols": 60, "order": 2, "line1": {"left": ["dir", "char"]}}}
  },
  "width": {"ambiguous": 2},
  "segment": {
    "dir": {"shorten": ["repo", "depth"]},
    "duration": {"min": "3s"},
    "custom/hi": {"kind": "text", "text": "hi"},
    "custom/run": {"kind": "command", "command": ["date", "+%H"], "timeout": "150ms",
                   "cache": "20s", "env_allow": ["LANG"]}
  }
}"##;

// 이것을 실패시키는 것: JSON 파서가 키·값 하나를 잃거나 형을 바꾸는 것(예: 마지막 키를 빠뜨림, 정수를 실수로),
// 형식을 이름이 아닌 다른 것으로 고르는 것, 출처 필드 밖의 바이트가 형식에 따라 달라지는 것.
#[test]
fn toml_and_json_give_the_same_snapshot_and_prompt() {
    let toml = compiled("/c/config.toml", TOML);
    let json = compiled("/c/config.json", JSON);
    assert!(
        !toml.exec_units.is_empty(),
        "the fixture must carry provenance"
    );
    assert_eq!(
        without_provenance(toml.clone()),
        without_provenance(json.clone())
    );
    for width in [100, 50] {
        assert_eq!(prompt(&toml, width), prompt(&json, width), "width {width}");
    }
    // A different value is seen: the comparison is not blind.
    let other = compiled("/c/config.json", &JSON.replace("\"3s\"", "\"4s\""));
    assert_ne!(without_provenance(json), without_provenance(other));
}

// 이것을 실패시키는 것: `.json` 이름의 파일을 TOML로 읽는 것(E101), 그 반대, JSON 오류를 E101로 내는 것.
#[test]
fn the_file_name_picks_the_reader() {
    let codes = |name: &str, text: &str| -> Vec<String> {
        read(name, text)
            .diagnostics
            .iter()
            .map(|d| d.code.to_string())
            .collect()
    };
    assert_eq!(codes("/c/config.json", JSON), codes("/c/config.toml", TOML));
    let as_toml = codes("/c/config.toml", JSON);
    assert!(
        !as_toml.is_empty() && as_toml.iter().all(|c| c == "E101"),
        "{as_toml:?}"
    );
    assert_eq!(codes("/c/config.json", TOML), ["E106"]);
    assert_eq!(codes("/c/config.json", "{\"a\": 1, \"a\": 2}"), ["E106"]);
}

mod cross_format {
    use bingsu_core::config::tree::{Format, Table, Value, parse_as};
    use proptest::prelude::*;
    use std::collections::BTreeMap;

    #[derive(Clone, Debug)]
    enum V {
        Str(String),
        Int(i64),
        Float(f64),
        Bool(bool),
        Array(Vec<V>),
        Table(BTreeMap<String, V>),
    }

    fn text() -> impl Strategy<Value = String> {
        // Quotes, backslashes, controls (DEL too), dots, spaces and non-ASCII.
        prop::collection::vec(
            prop_oneof![
                prop::sample::select(vec![
                    'a', 'z', '.', ' ', '"', '\\', '/', '\u{0}', '\u{1f}', '\u{7f}', 'é', '빙',
                    '😀'
                ]),
                any::<char>(),
            ],
            0..8,
        )
        .prop_map(|c| c.into_iter().collect())
    }

    fn value() -> impl Strategy<Value = V> {
        let leaf = prop_oneof![
            text().prop_map(V::Str),
            any::<i64>().prop_map(V::Int),
            any::<f64>()
                .prop_filter("finite", |x| x.is_finite())
                .prop_map(V::Float),
            any::<bool>().prop_map(V::Bool),
        ];
        leaf.prop_recursive(4, 48, 6, |inner| {
            prop_oneof![
                prop::collection::vec(inner.clone(), 0..5).prop_map(V::Array),
                prop::collection::btree_map(text(), inner, 0..5).prop_map(V::Table),
            ]
        })
    }

    /// Every character outside printable ASCII as `\uXXXX` (pairs above the
    /// BMP for JSON, `\UXXXXXXXX` for TOML), so both writers stay simple.
    fn quote(s: &str, json: bool) -> String {
        let mut out = String::from("\"");
        for c in s.chars() {
            match c {
                '"' => out.push_str("\\\""),
                '\\' => out.push_str("\\\\"),
                ' '..='~' => out.push(c),
                c if (c as u32) < 0x10000 => out.push_str(&format!("\\u{:04x}", c as u32)),
                c if json => {
                    let mut units = [0u16; 2];
                    for u in c.encode_utf16(&mut units) {
                        out.push_str(&format!("\\u{:04x}", u));
                    }
                }
                c => out.push_str(&format!("\\U{:08x}", c as u32)),
            }
        }
        out.push('"');
        out
    }

    fn write(v: &V, json: bool) -> String {
        match v {
            V::Str(s) => quote(s, json),
            V::Int(n) => n.to_string(),
            V::Float(x) => format!("{x:?}"),
            V::Bool(b) => b.to_string(),
            V::Array(items) => {
                let items: Vec<String> = items.iter().map(|i| write(i, json)).collect();
                format!("[{}]", items.join(", "))
            }
            V::Table(t) => {
                let sep = if json { ": " } else { " = " };
                let items: Vec<String> = t
                    .iter()
                    .map(|(k, v)| format!("{}{sep}{}", quote(k, json), write(v, json)))
                    .collect();
                format!("{{{}}}", items.join(", "))
            }
        }
    }

    fn shape(t: &Table) -> BTreeMap<String, String> {
        fn value(v: &Value) -> String {
            match v {
                Value::Str(s) => format!("s{s:?}"),
                Value::Int(n) => format!("i{n}"),
                Value::Float(x) => format!("f{:?}", x.to_bits()),
                Value::Bool(b) => format!("b{b}"),
                Value::DateTime(d) => format!("d{d}"),
                Value::Array(a) => {
                    let items: Vec<String> = a.iter().map(|n| value(&n.value)).collect();
                    format!("[{}]", items.join(","))
                }
                Value::Table(t) => format!("{:?}", shape(t)),
            }
        }
        t.entries
            .iter()
            .map(|e| (e.key.clone(), value(&e.node.value)))
            .collect()
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(512))]
        // 같은 트리를 두 형식으로 쓴 두 파일은 span을 빼면 같은 트리로 읽힌다.
        // 이것을 실패시키는 것: JSON 이스케이프·서로게이트 해석, 정수·실수 구분, 키 디코드, 빈 배열·표 처리 중
        // 하나라도 TOML과 다르게 하는 것.
        #[test]
        fn a_tree_reads_the_same_in_both_formats(top in prop::collection::btree_map(text(), value(), 0..6)) {
            let mut toml = String::new();
            for (k, v) in &top {
                toml.push_str(&format!("{} = {}\n", quote(k, false), write(v, false)));
            }
            let json = write(&V::Table(top), true);
            let from_toml = parse_as(Format::Toml, toml.as_bytes());
            let from_json = parse_as(Format::Json, json.as_bytes());
            prop_assert!(from_toml.is_ok(), "{toml}\n{from_toml:?}");
            prop_assert!(from_json.is_ok(), "{json}\n{from_json:?}");
            prop_assert_eq!(shape(&from_toml.unwrap()), shape(&from_json.unwrap()));
        }
    }
}

// 맨 위 `$schema` 문자열은 두 형식 모두 모델에 넣지 않고, 맨 위가 아니거나 문자열이 아니면 오류다(같은 결과).
// 이것을 실패시키는 것: 한 형식에서만 받는 것, 문자열 `$schema`를 남겨 E201이 나는 것, 숫자를 받는 것, 안쪽 표의
// `$schema`까지 지우는 것.
#[test]
fn a_top_schema_string_is_for_editors_in_both_formats() {
    let codes = |name: &str, text: &str| -> Vec<String> {
        read(name, text)
            .diagnostics
            .iter()
            .map(|d| d.code.to_string())
            .collect()
    };
    for (toml, json, want) in [
        (
            "\"$schema\" = \"https://x/config-v1.json\"\n",
            "{\"$schema\": \"https://x/config-v1.json\"}",
            vec![],
        ),
        ("\"$schema\" = 1\n", "{\"$schema\": 1}", vec!["E202"]),
        (
            "[colors]\n\"$schema\" = \"x\"\n",
            "{\"colors\": {\"$schema\": \"x\"}}",
            vec!["E201"],
        ),
    ] {
        let from_toml = codes("/c/config.toml", toml);
        assert_eq!(from_toml, want, "{toml:?}");
        assert_eq!(codes("/c/config.json", json), from_toml, "{json:?}");
    }
    let plain = compiled("/c/config.toml", "");
    let with = compiled(
        "/c/config.toml",
        "\"$schema\" = \"https://x/config-v1.json\"\n",
    );
    assert_eq!(without_provenance(plain), without_provenance(with));
}
