//! YAML config files (`conf.d/*.yaml` and `*.yml`, and an `extends` or
//! `bingsu config use` path ending in either) read into the tree TOML and
//! JSON files make, so merging, key checks, trust and provenance are shared.
//! Core checks the tree again (`tree::check_parsed`) before it is used.
//!
//! yaml-rust2's parser reports anchors and aliases as events and never
//! expands an alias here: the first anchor ends the read before anything is
//! copied. Its events carry where they start, not where they end: a scalar's
//! span is that one point, a mapping's or list's runs to where its end event
//! starts.
//! Refused as YAML features bingsu does not read (E108): anchors, aliases
//! (also one whose anchor is not defined), tags, a second document and a key
//! that is a mapping or a list. Refused as errors (E107): the grammar, a key
//! written twice in one mapping, `null`, a top value that is not a mapping.
//! Nesting deeper than `NESTING_MAX` and integers outside i64 take the
//! errors TOML and JSON use.
//!
//! Scalars follow the YAML 1.2 core schema. A plain scalar is a boolean
//! (`true`, `True`, `TRUE`, and the same for false), an integer (decimal,
//! `0o` octal, `0x` hexadecimal), a float (decimal with a point or an
//! exponent, `.inf`, `.nan`), `null` (`~`, `null`, nothing) or else a
//! string; `yes` and `on` are strings. A quoted or block scalar is a string.
//! A key is the text of its scalar. An empty file, comments only, or a
//! document that is only null (a bare `---`) is an empty table, as an empty
//! TOML file is.

use bingsu_core::config::tree::{
    Entry, NESTING_MAX, Node, Span, SyntaxError, SyntaxErrorKind, Table, Value,
};
use std::collections::BTreeMap;
use yaml_rust2::parser::{Event, Parser};
use yaml_rust2::scanner::{Marker, ScanError, TScalarStyle};

/// Byte offsets of the parser's positions. The parser counts lines, and
/// columns in characters (its running index counts a block scalar's lines in
/// bytes, so it is not used). A cursor moves along one line in either
/// direction and jumps to a line's start through `lines`, so a file costs
/// steps in proportion to its length, however the events move about.
struct Offsets<'a> {
    text: &'a str,
    /// Where each line starts (after `\n`, `\r\n` or a lone `\r`).
    lines: Vec<usize>,
    line: usize,
    col: usize,
    byte: usize,
    /// Characters moved over, for `positions_cost_steps_in_proportion_to_the_text`.
    steps: usize,
}

impl<'a> Offsets<'a> {
    fn new(text: &'a str) -> Self {
        let b = text.as_bytes();
        let mut lines = vec![0];
        for (i, &c) in b.iter().enumerate() {
            if c == b'\n' || (c == b'\r' && b.get(i + 1) != Some(&b'\n')) {
                lines.push(i + 1);
            }
        }
        Self {
            text,
            lines,
            line: 0,
            col: 0,
            byte: 0,
            steps: 0,
        }
    }

    /// The byte of character `col` on line `line` (both from 0), clamped to
    /// the end of that line.
    fn byte_at(&mut self, line: usize, col: usize) -> u32 {
        let Some(&start) = self.lines.get(line) else {
            return self.text.len() as u32;
        };
        // 이것을 실패시키는 것: 다른 줄로 갈 때 그 줄 처음으로 옮기지 않는 것, 뒤로 가는 위치에서 되돌아가지 않는 것.
        if line != self.line {
            (self.line, self.col, self.byte) = (line, 0, start);
        }
        while self.col < col {
            match self.text[self.byte..].chars().next() {
                Some(c) if c != '\n' && c != '\r' => {
                    self.byte += c.len_utf8();
                    self.col += 1;
                    self.steps += 1;
                }
                _ => break,
            }
        }
        while self.col > col {
            let c = self.text[..self.byte].chars().next_back().unwrap_or('\0');
            self.byte -= c.len_utf8();
            self.col -= 1;
            self.steps += 1;
        }
        self.byte as u32
    }

    fn byte(&mut self, m: &Marker) -> u32 {
        self.byte_at(m.line().saturating_sub(1), m.col())
    }

    /// The point where an event starts.
    fn start(&mut self, m: &Marker) -> Span {
        let at = self.byte(m);
        Span { start: at, end: at }
    }

    /// One character at `m` (none at the end of the text).
    fn point(&mut self, m: &Marker) -> Span {
        let start = self.byte(m);
        let width = self.text[start as usize..]
            .chars()
            .next()
            .map_or(0, char::len_utf8);
        Span {
            start,
            end: start + width as u32,
        }
    }
}

enum Open {
    Map {
        table: Table,
        /// Each key's line, for a key written again.
        keys: BTreeMap<String, usize>,
        key: Option<(String, Span)>,
        start: u32,
    },
    Seq {
        items: Vec<Node>,
        start: u32,
    },
}

fn error(span: Span, kind: SyntaxErrorKind) -> Vec<SyntaxError> {
    vec![SyntaxError { span, kind }]
}

fn unsupported(feature: &str, span: Span) -> Vec<SyntaxError> {
    error(span, SyntaxErrorKind::YamlUnsupported(feature.into()))
}

fn syntax(message: impl Into<String>, span: Span) -> Vec<SyntaxError> {
    error(span, SyntaxErrorKind::Yaml(message.into()))
}

/// The parser's own error. Its wording is matched for the two cases that
/// have a code of their own; `scan_errors_keep_their_codes` pins it.
fn scan_error(e: &ScanError, at: &mut Offsets<'_>) -> Vec<SyntaxError> {
    let span = at.point(e.marker());
    // 이것을 실패시키는 것: 정의 없는 alias를 문법 오류(E107)로 두는 것, 파서의 깊이 한도를 TooDeep으로 바꾸지 않는 것.
    if e.info().contains("unknown anchor") {
        unsupported("alias", span)
    } else if e.info().contains("recursion limit exceeded") {
        error(span, SyntaxErrorKind::TooDeep)
    } else {
        syntax(e.info(), span)
    }
}

/// The text of a YAML file as a config tree, or why not.
pub fn parse(text: &str) -> Result<Table, Vec<SyntaxError>> {
    parse_with(text, &mut Offsets::new(text))
}

fn parse_with(text: &str, at: &mut Offsets<'_>) -> Result<Table, Vec<SyntaxError>> {
    // The parser reads a NUL as the end of the text and would drop the rest
    // silently; YAML does not allow one anyway.
    // 이것을 실패시키는 것: NUL 뒤를 버리고 앞부분만 읽는 것.
    if let Some(i) = text.find('\0') {
        let at = i as u32;
        return Err(syntax(
            "a NUL character is not allowed",
            Span {
                start: at,
                end: at + 1,
            },
        ));
    }
    let mut parser = Parser::new_from_str(text);
    let mut stack: Vec<Open> = Vec::new();
    let mut root: Option<Table> = None;
    let mut documents = 0;
    loop {
        let (event, mark) = parser.next_token().map_err(|e| scan_error(&e, at))?;
        let span = at.start(&mark);
        // Errors point at the event's first character; the tree keeps the point.
        let point = at.point(&mark);
        let line = mark.line();
        let awaiting_key = matches!(stack.last(), Some(Open::Map { key: None, .. }));
        let node = match event {
            Event::StreamEnd => break,
            Event::Nothing | Event::StreamStart | Event::DocumentEnd => continue,
            Event::DocumentStart => {
                documents += 1;
                // 이것을 실패시키는 것: 두 번째 문서를 받아들이는 것(뒤 문서가 앞 문서를 덮음).
                if documents > 1 {
                    return Err(unsupported("second document", point));
                }
                continue;
            }
            // An alias needs an anchor, refused where it is defined; one with no
            // anchor is the parser's "unknown anchor" error. Kept for any other.
            Event::Alias(_) => return Err(unsupported("alias", point)),
            // 이것을 실패시키는 것: anchor가 달린 노드를 받아들이는 것(alias 거부만으로는 정의를 막지 못함).
            Event::Scalar(_, _, anchor, _)
            | Event::SequenceStart(anchor, _)
            | Event::MappingStart(anchor, _)
                if anchor != 0 =>
            {
                return Err(unsupported("anchor", point));
            }
            // 이것을 실패시키는 것: 태그를 지나치는 것(`!!str 1`이 문자열인지 정수인지 읽는 쪽이 정함).
            Event::Scalar(_, _, _, Some(_))
            | Event::SequenceStart(_, Some(_))
            | Event::MappingStart(_, Some(_)) => return Err(unsupported("tag", point)),
            Event::MappingStart(..) | Event::SequenceStart(..) if awaiting_key => {
                return Err(unsupported("key that is a mapping or a list", point));
            }
            // A value inside the top mapping is at depth 1 (`stack` holds the
            // top mapping), as for TOML and JSON.
            // 이것을 실패시키는 것: 깊이를 하나 어긋나게 세는 것(32단이 거부되거나 33단이 받아들여짐).
            Event::MappingStart(..) | Event::SequenceStart(..)
                if stack.len() > NESTING_MAX as usize =>
            {
                return Err(error(point, SyntaxErrorKind::TooDeep));
            }
            Event::MappingStart(..) => {
                stack.push(Open::Map {
                    table: Table::default(),
                    keys: BTreeMap::new(),
                    key: None,
                    start: span.start,
                });
                continue;
            }
            Event::SequenceStart(..) => {
                stack.push(Open::Seq {
                    items: Vec::new(),
                    start: span.start,
                });
                continue;
            }
            Event::MappingEnd => match stack.pop() {
                Some(Open::Map {
                    table,
                    key: None,
                    start,
                    ..
                }) => Node {
                    value: Value::Table(table),
                    span: Span {
                        start,
                        end: span.end.max(start),
                    },
                },
                _ => return Err(syntax("a mapping ends where none is open", point)),
            },
            Event::SequenceEnd => match stack.pop() {
                Some(Open::Seq { items, start }) => Node {
                    value: Value::Array(items),
                    span: Span {
                        start,
                        end: span.end.max(start),
                    },
                },
                _ => return Err(syntax("a list ends where none is open", point)),
            },
            Event::Scalar(v, _, _, None) if awaiting_key => {
                let Some(Open::Map { keys, key, .. }) = stack.last_mut() else {
                    unreachable!("awaiting_key holds an open mapping")
                };
                // 이것을 실패시키는 것: 한 mapping에서 같은 키를 두 번 받아들이는 것(뒤 값이 조용히 앞 값을 덮음).
                if let Some(first) = keys.get(v.as_str()) {
                    return Err(syntax(
                        format!("duplicate key `{v}` (first written at line {first})"),
                        point,
                    ));
                }
                keys.insert(v.clone(), line);
                *key = Some((v, span));
                continue;
            }
            Event::Scalar(v, style, _, None) => {
                let value = if style == TScalarStyle::Plain {
                    plain(&v, point)?
                } else {
                    Some(Value::Str(v))
                };
                match (value, stack.is_empty()) {
                    (Some(value), _) => Node { value, span },
                    // A document that is only null reads as an empty file.
                    (None, true) => {
                        root.get_or_insert_with(Table::default);
                        continue;
                    }
                    (None, false) => {
                        return Err(syntax("`null` is not a setting value", point));
                    }
                }
            }
        };
        match stack.last_mut() {
            None => match node.value {
                Value::Table(t) => root = Some(t),
                _ => return Err(syntax("the top of the file must be a mapping", node.span)),
            },
            Some(Open::Seq { items, .. }) => items.push(node),
            Some(Open::Map { table, key, .. }) => {
                let Some((key, key_span)) = key.take() else {
                    unreachable!("a value of a mapping follows its key")
                };
                table.entries.push(Entry {
                    key,
                    key_span,
                    node,
                });
            }
        }
    }
    Ok(root.unwrap_or_default())
}

/// A plain scalar under the YAML 1.2 core schema; None for null.
fn plain(v: &str, span: Span) -> Result<Option<Value>, Vec<SyntaxError>> {
    Ok(Some(match v {
        "" | "~" | "null" | "Null" | "NULL" => return Ok(None),
        "true" | "True" | "TRUE" => Value::Bool(true),
        "false" | "False" | "FALSE" => Value::Bool(false),
        ".inf" | ".Inf" | ".INF" | "+.inf" | "+.Inf" | "+.INF" => Value::Float(f64::INFINITY),
        "-.inf" | "-.Inf" | "-.INF" => Value::Float(f64::NEG_INFINITY),
        ".nan" | ".NaN" | ".NAN" => Value::Float(f64::NAN),
        _ => match integer(v) {
            Some(Ok(n)) => Value::Int(n),
            Some(Err(())) => return Err(error(span, SyntaxErrorKind::IntegerRange)),
            None if is_float(v) => match v.parse::<f64>() {
                Ok(f) => Value::Float(f),
                Err(_) => Value::Str(v.into()),
            },
            None => Value::Str(v.into()),
        },
    }))
}

/// An integer of the core schema: None when `v` is not one, Err when it is
/// one outside i64.
fn integer(v: &str) -> Option<Result<i64, ()>> {
    let digits = |s: &str, radix: u32| !s.is_empty() && s.chars().all(|c| c.is_digit(radix));
    // 이것을 실패시키는 것: 부호 없는 `0o`·`0x`를 10진으로 읽는 것, 범위 밖 정수를 문자열로 두는 것.
    let (body, radix) = if let Some(octal) = v.strip_prefix("0o") {
        (octal, 8)
    } else if let Some(hex) = v.strip_prefix("0x") {
        (hex, 16)
    } else {
        (v.strip_prefix(['-', '+']).unwrap_or(v), 10)
    };
    if !digits(body, radix) {
        return None;
    }
    let parsed = if radix == 10 {
        v.parse::<i64>()
    } else {
        i64::from_str_radix(body, radix)
    };
    Some(parsed.map_err(|_| ()))
}

/// The core schema's float form: `[-+]?(\.[0-9]+|[0-9]+(\.[0-9]*)?)([eE][-+]?[0-9]+)?`.
/// Rust's own parser also takes `inf`, `NaN` and `infinity`, which are
/// strings here.
fn is_float(v: &str) -> bool {
    let v = v.strip_prefix(['-', '+']).unwrap_or(v);
    let (mantissa, exponent) = match v.find(['e', 'E']) {
        Some(i) => (&v[..i], Some(&v[i + 1..])),
        None => (v, None),
    };
    let digits = |s: &str| s.chars().all(|c| c.is_ascii_digit());
    let mantissa_ok = match mantissa.split_once('.') {
        Some((whole, part)) => {
            digits(whole) && digits(part) && !(whole.is_empty() && part.is_empty())
        }
        None => !mantissa.is_empty() && digits(mantissa),
    };
    let exponent_ok = exponent.is_none_or(|e| {
        let e = e.strip_prefix(['-', '+']).unwrap_or(e);
        !e.is_empty() && digits(e)
    });
    mantissa_ok && exponent_ok
}

#[cfg(test)]
mod tests {
    use super::*;
    use bingsu_core::color::palette::Mode;
    use bingsu_core::color::sgr::ColorDepth;
    use bingsu_core::config::compile::{BUILTIN_TOML, CompiledConfig};
    use bingsu_core::config::merge::Origin;
    use bingsu_core::config::report::{ConfigReport, report};
    use bingsu_core::config::source::{ExtendsRef, FileKey, OpenError, Opened, Resolver, Trust};
    use bingsu_core::config::tree::check_parsed;
    use bingsu_core::diag::SourceId;
    use bingsu_core::diag_codes as codes;
    use bingsu_core::field::{BUILTIN, Field, FieldValue, Value as Shown, segment};
    use bingsu_core::layout::{Inputs, Options};
    use bingsu_core::recorder::NoopRecorder;
    use bingsu_core::render::{RenderedPrompt, Target, render_prompt};
    use bingsu_core::shell_word::Shell;
    use bingsu_core::shorten::{Anchor, PathFacts};
    use bingsu_core::snapshot_codec::encode_compiled;

    /// The reader `config_load` gives core, without files.
    struct Reader;
    impl Resolver for Reader {
        fn open(&mut self, _: &Opened, _: &ExtendsRef) -> Result<Opened, OpenError> {
            panic!("the fixtures have no extends");
        }
        fn parse_yaml(&mut self, text: &str) -> Result<Table, Vec<SyntaxError>> {
            parse(text)
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
        report(roots, &mut Reader, [0, 3, 0], Mode::Dark)
    }

    fn compiled(name: &str, text: &str) -> CompiledConfig {
        let r = read(name, text);
        r.snapshot
            .unwrap_or_else(|| panic!("{name}: {:?}", r.diagnostics))
    }

    /// The snapshot bytes without provenance, as the TOML and JSON
    /// comparison in bingsu-core-tests (config_json.rs) leaves it out.
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

    fn prompt(c: &CompiledConfig, width: u16) -> RenderedPrompt {
        let i = |id| BUILTIN.iter().position(|x| x.id == id).unwrap();
        let v = |id: &str, text: &[u8], set: &[(&str, FieldValue)]| {
            let s = segment(id).unwrap();
            let mut f = vec![Field::ABSENT; s.fields.len()];
            for (n, x) in set {
                f[s.field_index(n).unwrap()] = Field::known(x.clone());
            }
            Some(Shown::new(text, f))
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

    /// The fixture of bingsu-core-tests' config_json.rs, in TOML.
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

    /// The same settings in YAML: block and flow mappings and lists, plain,
    /// quoted and block scalars.
    const YAML: &str = r##"# settings
$schema: https://example.com/bingsu/config-v1.json
version: 1
icons: ascii
colors:
  mode: dark
  override: {"git.dirty": "#ff8800", path: "214"}
  knobs: {hue: 250, accent_l: 0.74, accent_c: 0.1}
layout:
  use_last_column: false
  line1:
    left: [dir, git, custom/hi]
    right:
      - status
      - custom/run
  line2: {left: [char]}
  when:
    narrow:
      max_cols: 60
      order: 2
      line1:
        left: [dir, char]
width:
  ambiguous: 2
segment:
  dir:
    shorten: [repo, depth]
  duration:
    min: 3s
  custom/hi:
    kind: text
    text: |-
      hi
  custom/run:
    kind: 'command'
    command: [date, "+%H"]
    timeout: 150ms
    cache: 20s
    env_allow: [LANG]
"##;

    // 이것을 실패시키는 것: YAML 읽기가 키·값 하나를 잃거나 형을 바꾸는 것(예: 정수를 실수로, 따옴표 문자열을 수로),
    // 형식을 이름이 아닌 다른 것으로 고르는 것, 출처 필드 밖의 바이트가 형식에 따라 달라지는 것.
    #[test]
    fn toml_and_yaml_give_the_same_snapshot_and_prompt() {
        let toml = compiled("/c/config.toml", TOML);
        assert!(
            !toml.exec_units.is_empty(),
            "the fixture must carry provenance"
        );
        for name in ["/c/conf.d/a.yaml", "/c/conf.d/a.yml"] {
            let yaml = compiled(name, YAML);
            assert_eq!(
                without_provenance(toml.clone()),
                without_provenance(yaml.clone()),
                "{name}"
            );
            for width in [100, 50] {
                assert_eq!(
                    prompt(&toml, width),
                    prompt(&yaml, width),
                    "{name} width {width}"
                );
            }
        }
        // A different value is seen: the comparison is not blind.
        let other = compiled("/c/a.yaml", &YAML.replace("min: 3s", "min: 4s"));
        assert_ne!(
            without_provenance(compiled("/c/a.yaml", YAML)),
            without_provenance(other)
        );
    }

    fn codes_of(r: &ConfigReport) -> Vec<(String, Vec<String>)> {
        r.diagnostics
            .iter()
            .map(|d| {
                let args = d.args.iter().map(|a| a.value.to_string()).collect();
                (d.code.to_string(), args)
            })
            .collect()
    }

    // 이것을 실패시키는 것: YAML 오류를 E107·E108이 아닌 코드로 내는 것, 읽는 쪽 없이 YAML을 TOML로 읽는 것.
    #[test]
    fn yaml_problems_reach_the_report_with_their_codes() {
        let r = read("/c/a.yaml", "a: &x 1\nb: *x\n");
        assert_eq!(
            codes_of(&r),
            [(
                codes::YAML_UNSUPPORTED.to_string(),
                vec![String::from("anchor")]
            )]
        );
        let r = read("/c/a.yml", "a: [1\n");
        assert_eq!(codes_of(&r)[0].0, codes::YAML_SYNTAX.to_string());
        assert!(r.snapshot.is_none());
    }

    fn refused(text: &str) -> SyntaxError {
        let mut e = parse(text).expect_err(text);
        assert_eq!(e.len(), 1, "{text}");
        e.remove(0)
    }

    fn unsupported_kind(text: &str) -> String {
        match refused(text).kind {
            SyntaxErrorKind::YamlUnsupported(f) => f,
            other => panic!("{text}: {other:?}"),
        }
    }

    // 이것을 실패시키는 것: anchor·alias·merge 키·확장 폭탄·정의 없는 alias·태그·두 번째 문서·mapping 키 가운데 하나를
    // 받아들이거나 다른 이름으로 내는 것. 폭탄은 펼치지 않고 첫 anchor에서 멈춘다.
    #[test]
    fn features_bingsu_does_not_read_are_refused() {
        let mut bomb = String::from("a: &a [\"lol\", \"lol\", \"lol\"]\n");
        for (p, c) in "abcdefgh".chars().zip("bcdefghi".chars()) {
            bomb.push_str(&format!(
                "{c}: &{c} [*{p}, *{p}, *{p}, *{p}, *{p}, *{p}, *{p}, *{p}, *{p}]\n"
            ));
        }
        for (text, feature) in [
            ("base: &b\n  kind: text\n", "anchor"),
            ("a: &x 1\nb: *x\n", "anchor"),
            ("base: &b {kind: text}\nseg:\n  <<: *b\n", "anchor"),
            (bomb.as_str(), "anchor"),
            ("a: *nope\n", "alias"),
            ("a: !!str 1\n", "tag"),
            ("a: !custom x\n", "tag"),
            ("!!map {a: 1}\n", "tag"),
            ("a: !!seq []\n", "tag"),
            ("---\na: 1\n---\nb: 2\n", "second document"),
            ("? {a: 1}\n: x\n", "key that is a mapping or a list"),
            ("[a, b]: x\n", "key that is a mapping or a list"),
        ] {
            assert_eq!(unsupported_kind(text), feature, "{text}");
        }
    }

    fn syntax_message(text: &str) -> String {
        match refused(text).kind {
            SyntaxErrorKind::Yaml(m) => m,
            other => panic!("{text}: {other:?}"),
        }
    }

    // 이것을 실패시키는 것: 겹치는 키를 받아들이는 것, null을 빈 값이나 문자열로 읽는 것, 맨 위가 mapping이 아닌
    // 문서를 받아들이는 것, 파서의 문법 오류를 지나치는 것.
    #[test]
    fn errors_name_what_is_wrong() {
        assert_eq!(
            syntax_message("a: 1\nb: 2\na: 3\n"),
            "duplicate key `a` (first written at line 1)"
        );
        assert_eq!(
            syntax_message("x:\n  a: 1\n  a: 1\n"),
            "duplicate key `a` (first written at line 2)"
        );
        for null in [
            "a: ~\n",
            "a: null\n",
            "a: Null\n",
            "a:\n",
            "a: NULL\n",
            "a: [1, ~]\n",
        ] {
            assert_eq!(
                syntax_message(null),
                "`null` is not a setting value",
                "{null}"
            );
        }
        for top in ["- a\n- b\n", "hello\n", "\"a\"\n", "1\n"] {
            assert_eq!(
                syntax_message(top),
                "the top of the file must be a mapping",
                "{top}"
            );
        }
        assert!(!syntax_message("a: [1\n").is_empty());
        assert!(!syntax_message("a: b: c\n").is_empty());
        // A NUL ends the text for the parser; nothing after it is dropped.
        let nul = "colors: {mode: dark}\n\0colors: {mode: light}\n";
        let e = refused(nul);
        assert_eq!(
            e.kind,
            SyntaxErrorKind::Yaml("a NUL character is not allowed".into())
        );
        assert_eq!(&nul[e.span.start as usize..e.span.end as usize], "\0");
        // The same key in two mappings is two keys.
        assert!(parse("x: {a: 1}\ny: {a: 1}\n").is_ok());
    }

    // 이것을 실패시키는 것: 파서 문구가 바뀌어 정의 없는 alias나 깊이 한도가 다른 코드로 가는 것을 놓치는 것.
    #[test]
    fn scan_errors_keep_their_codes() {
        assert_eq!(unsupported_kind("a: *nope\n"), "alias");
        let deep = format!("a: {}{}\n", "[".repeat(10_000), "]".repeat(10_000));
        assert_eq!(refused(&deep).kind, SyntaxErrorKind::TooDeep);
    }

    /// `depth` nested lists under the top key `a` (the list itself is depth 1).
    fn nested(depth: usize, flow: bool) -> String {
        if flow {
            return format!("a: {}{}\n", "[".repeat(depth), "]".repeat(depth));
        }
        let mut s = String::from("a:\n");
        for i in 1..depth {
            s.push_str(&"  ".repeat(i));
            s.push_str("- \n");
        }
        s.push_str(&"  ".repeat(depth));
        s.push_str("- 1\n");
        s
    }

    // 깊이는 TOML·JSON과 같이 센다(맨 위의 값이 1, 32까지). 이것을 실패시키는 것: 하나 어긋나게 세는 것, list나
    // mapping 한쪽만 세는 것.
    #[test]
    fn nesting_stops_where_toml_and_json_stop() {
        for depth in [32usize, 33] {
            let yaml = format!("a: {}1{}\n", "{b: ".repeat(depth), "}".repeat(depth));
            let toml = format!("a = {}1{}\n", "{b = ".repeat(depth), "}".repeat(depth));
            let got = parse(&yaml);
            assert_eq!(
                got.is_ok(),
                depth <= NESTING_MAX as usize,
                "mappings {depth}"
            );
            assert_eq!(
                got.is_ok(),
                bingsu_core::config::tree::parse(toml.as_bytes()).is_ok(),
                "{depth}"
            );
        }
        for flow in [true, false] {
            for depth in [31usize, 32, 33, 34] {
                let text = nested(depth, flow);
                let got = parse(&text);
                let toml = bingsu_core::config::tree::parse(
                    format!("a = {}{}\n", "[".repeat(depth), "]".repeat(depth)).as_bytes(),
                );
                assert_eq!(got.is_ok(), depth <= NESTING_MAX as usize, "{flow} {depth}");
                assert_eq!(got.is_ok(), toml.is_ok(), "{flow} {depth}");
                if let Err(e) = got {
                    assert_eq!(e[0].kind, SyntaxErrorKind::TooDeep, "{flow} {depth}");
                }
            }
        }
    }

    fn value(text: &str) -> Value {
        let t = parse(&format!("v: {text}\n")).unwrap_or_else(|e| panic!("{text}: {e:?}"));
        t.entries[0].node.value.clone()
    }

    // YAML 1.2 core schema. 이것을 실패시키는 것: `yes`·`on`을 불리언으로, `inf`·`NaN`·`1_000`을 수로, `0o`·`0x`를
    // 10진이나 문자열로, 따옴표나 블록 스칼라를 수로 읽는 것, 범위 밖 정수를 문자열로 두는 것.
    #[test]
    fn scalars_follow_the_core_schema() {
        for (text, want) in [
            ("true", Value::Bool(true)),
            ("True", Value::Bool(true)),
            ("FALSE", Value::Bool(false)),
            ("yes", Value::Str("yes".into())),
            ("on", Value::Str("on".into())),
            ("42", Value::Int(42)),
            ("-7", Value::Int(-7)),
            ("+7", Value::Int(7)),
            ("007", Value::Int(7)),
            ("0o17", Value::Int(15)),
            ("0x1F", Value::Int(31)),
            ("0x", Value::Str("0x".into())),
            ("0o8", Value::Str("0o8".into())),
            ("-0x1", Value::Str("-0x1".into())),
            ("1_000", Value::Str("1_000".into())),
            ("9223372036854775807", Value::Int(i64::MAX)),
            ("1.5", Value::Float(1.5)),
            ("-.5", Value::Float(-0.5)),
            ("5.", Value::Float(5.0)),
            ("1e3", Value::Float(1000.0)),
            ("2.5E-1", Value::Float(0.25)),
            (".inf", Value::Float(f64::INFINITY)),
            ("-.Inf", Value::Float(f64::NEG_INFINITY)),
            ("inf", Value::Str("inf".into())),
            ("NaN", Value::Str("NaN".into())),
            ("infinity", Value::Str("infinity".into())),
            (".", Value::Str(".".into())),
            ("1e", Value::Str("1e".into())),
            ("e5", Value::Str("e5".into())),
            ("1.2.3", Value::Str("1.2.3".into())),
            ("'42'", Value::Str("42".into())),
            ("\"true\"", Value::Str("true".into())),
            ("''", Value::Str(String::new())),
            ("|-\n  7", Value::Str("7".into())),
            ("hi there", Value::Str("hi there".into())),
        ] {
            assert_eq!(value(text), want, "{text}");
        }
        assert!(matches!(value(".NaN"), Value::Float(f) if f.is_nan()));
        for big in [
            "9223372036854775808",
            "-9223372036854775809",
            "0x8000000000000000",
        ] {
            assert_eq!(
                refused(&format!("v: {big}\n")).kind,
                SyntaxErrorKind::IntegerRange,
                "{big}"
            );
        }
    }

    // 이것을 실패시키는 것: 빈 파일, 주석뿐인 파일, null 하나뿐인 문서를 오류로 내는 것(빈 TOML 파일은 빈 표다).
    #[test]
    fn an_empty_document_is_an_empty_table() {
        for text in [
            "",
            "# only a comment\n",
            "---\n",
            "--- ~\n",
            "---\n...\n",
            "null\n",
        ] {
            assert_eq!(parse(text), Ok(Table::default()), "{text:?}");
        }
    }

    // 이것을 실패시키는 것: 글자 수 위치를 바이트로 바꾸지 않는 것, 뒤로 가는 위치에서 다시 세지 않는 것.
    #[test]
    fn positions_are_byte_offsets() {
        // Events give where they start: each span is that point, in bytes.
        let shown = "가나: \"다\"\nk: [1, x]\n";
        let t = parse(shown).unwrap();
        let at = |s: Span| (s.start == s.end).then(|| &shown[s.start as usize..]);
        let (name, k) = (&t.entries[0], &t.entries[1]);
        assert_eq!(at(name.key_span), Some(shown));
        assert!(at(name.node.span).unwrap().starts_with("\"다\""));
        assert!(at(k.key_span).unwrap().starts_with("k: "));
        let Value::Array(items) = &k.node.value else {
            panic!("{k:?}")
        };
        assert!(at(items[1].span).unwrap().starts_with("x]"));
        // A list runs from its start to where its end starts.
        let list = &shown[k.node.span.start as usize..k.node.span.end as usize];
        assert!(list.starts_with("[1, x"), "{list:?}");
        // An error after multibyte text points at the `~` itself.
        let text = "가나: \"다\"\nb: [1, ~]\n";
        let err = refused(text);
        assert_eq!(&text[err.span.start as usize..err.span.end as usize], "~");
        // A block scalar of multibyte text does not move what follows it
        // (the parser's own running index counts its lines in bytes).
        let block = format!("a: |\n  {}\nb: ~\n", "가".repeat(32));
        let err = refused(&block);
        assert_eq!(&block[err.span.start as usize..err.span.end as usize], "~");
        // Lines and characters to bytes, in either direction on a line.
        let mut at = Offsets::new("가a\n나b\r\nc\rd");
        assert_eq!(at.byte_at(0, 2), 4);
        assert_eq!(at.byte_at(0, 1), 3);
        assert_eq!(at.byte_at(1, 1), 8);
        assert_eq!(at.byte_at(0, 0), 0);
        assert_eq!(at.byte_at(0, 99), 4, "the end of the line");
        assert_eq!(at.byte_at(2, 0), 11, "after \\r\\n");
        assert_eq!(at.byte_at(3, 0), 13, "after a lone \\r");
        assert_eq!(at.byte_at(9, 0), 14, "past the last line");
    }

    // 위치를 바이트로 바꾸는 데 드는 걸음은 글 길이에 비례한다. 이것을 실패시키는 것: 뒤로 가는 위치마다 처음부터
    // 다시 세는 것(블록 mapping이 많으면 n²).
    #[test]
    fn positions_cost_steps_in_proportion_to_the_text() {
        let text: String = (0..16_000).map(|i| format!("k{i:05}:\n  v: 1\n")).collect();
        let mut at = Offsets::new(&text);
        let t = parse_with(&text, &mut at).unwrap();
        assert_eq!(t.entries.len(), 16_000);
        assert!(
            at.steps <= 2 * text.len(),
            "{} steps for {} bytes",
            at.steps,
            text.len()
        );
    }

    // 읽은 트리와 오류의 위치는 core의 다시 검사를 늘 지난다.
    #[test]
    fn what_the_reader_returns_passes_the_core_check() {
        for text in [
            YAML,
            "가나: \"다\"\nk: 1\n",
            "a: [1\n",
            "가: *nope\n",
            "가나: ~\n",
        ] {
            let got = parse(text);
            assert_eq!(check_parsed(text, got.clone()), got, "{text}");
        }
    }
}
