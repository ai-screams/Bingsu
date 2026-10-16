//! A config file as an owned tree with byte spans (spec section 2 "설정
//! 파서와 국소 편집": diagnostics and provenance carry a stable position,
//! file and byte range). The `toml` crate parses (no_std, `parse` feature);
//! the rest of the config model sees only this tree, so the
//! parser can change behind it.
use alloc::borrow::{Cow, ToOwned};
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use toml::de::{DeTable, DeValue};
use toml_parser::lexer::TokenKind;
use toml_parser::parser::{Event, EventKind, RecursionGuard};

/// Per file (spec section 2 "`extends` 규칙": 256 KB per file).
pub const FILE_BYTES_MAX: usize = 256 * 1024;

/// Nesting of tables and arrays, counted together: a header `[a.b]` is two
/// levels, a dotted key `x.y = …` one per dot, each `[` or `{` of a value
/// one more. The parser caps each of these alone (80), not their sum, and
/// the sum is what the parser, this tree and every walk over it recurse on.
/// A hand-written config needs about five.
pub const NESTING_MAX: u32 = 32;

/// A byte range in one file, `start <= end`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Default)]
pub struct Span {
    pub start: u32,
    pub end: u32,
}

impl Span {
    fn of(r: core::ops::Range<usize>) -> Self {
        // FILE_BYTES_MAX keeps every offset far below u32::MAX.
        Self {
            start: r.start as u32,
            end: r.end as u32,
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum Value {
    Str(String),
    Int(i64),
    Float(f64),
    Bool(bool),
    /// A TOML date-time, as written (the model has no date-time key yet).
    DateTime(String),
    Array(Vec<Node>),
    Table(Table),
}

impl Value {
    /// The type name a diagnostic shows.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Str(_) => "string",
            Self::Int(_) => "integer",
            Self::Float(_) => "float",
            Self::Bool(_) => "boolean",
            Self::DateTime(_) => "date-time",
            Self::Array(_) => "array",
            Self::Table(_) => "table",
        }
    }
}

/// A value and where it is written. For a table opened by a header
/// (`[a.b]`), the span is the header; for a table only implied by a longer
/// key, it is that key.
#[derive(Clone, Debug, PartialEq)]
pub struct Node {
    pub value: Value,
    pub span: Span,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Entry {
    pub key: String,
    pub key_span: Span,
    pub node: Node,
}

/// Keys in file order (where each key is first written), unique. The
/// parser's map sorts keys; diagnostics and edits follow the file.
#[derive(Clone, Debug, PartialEq, Default)]
pub struct Table {
    pub entries: Vec<Entry>,
}

impl Table {
    pub fn get(&self, key: &str) -> Option<&Entry> {
        self.entries.iter().find(|e| e.key == key)
    }
}

/// Why a file did not parse, with where.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SyntaxError {
    pub span: Span,
    pub kind: SyntaxErrorKind,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SyntaxErrorKind {
    /// Over FILE_BYTES_MAX; the span is the first byte past the limit.
    TooLarge,
    /// Not UTF-8; the span is the first bad byte.
    NotUtf8,
    /// The parser's message, as it gave it.
    Toml(String),
    /// An integer outside i64.
    IntegerRange,
    /// A float the decimal parser refused.
    FloatSyntax,
    /// Nested deeper than `NESTING_MAX`; the span is where it went over.
    TooDeep,
}

/// `depth` is the nesting of `v` itself (a value at the top is 1). Past
/// `NESTING_MAX` the value is not copied and `TooDeep` is reported once:
/// this count is over the parser's own tree, so it holds whatever the text
/// scan does not represent (notably array-of-tables element nodes).
fn node(
    v: &toml::Spanned<DeValue<'_>>,
    text: &str,
    errors: &mut Vec<SyntaxError>,
    too_deep_reported: &mut bool,
    first_keys: &BTreeMap<usize, Span>,
    depth: u32,
) -> Node {
    let span = Span::of(v.span());
    let nested = matches!(v.get_ref(), DeValue::Array(_) | DeValue::Table(_));
    if nested && depth > NESTING_MAX {
        if !*too_deep_reported {
            *too_deep_reported = true;
            errors.push(SyntaxError {
                span,
                kind: SyntaxErrorKind::TooDeep,
            });
        }
        return Node {
            value: Value::Table(Table::default()),
            span,
        };
    }
    let value = match v.get_ref() {
        DeValue::String(s) => Value::Str(s.as_ref().to_owned()),
        DeValue::Integer(i) => match i64::from_str_radix(i.as_str(), i.radix()) {
            Ok(n) => Value::Int(n),
            Err(_) => {
                errors.push(SyntaxError {
                    span,
                    kind: SyntaxErrorKind::IntegerRange,
                });
                Value::Int(0)
            }
        },
        DeValue::Float(f) => match f.as_str().parse::<f64>() {
            Ok(x) => Value::Float(x),
            Err(_) => {
                errors.push(SyntaxError {
                    span,
                    kind: SyntaxErrorKind::FloatSyntax,
                });
                Value::Float(0.0)
            }
        },
        DeValue::Boolean(b) => Value::Bool(*b),
        DeValue::Datetime(_) => Value::DateTime(text[v.span()].to_owned()),
        DeValue::Array(a) => Value::Array(
            a.iter()
                .map(|e| node(e, text, errors, too_deep_reported, first_keys, depth + 1))
                .collect(),
        ),
        DeValue::Table(t) => {
            Value::Table(table(t, text, errors, too_deep_reported, first_keys, depth))
        }
    };
    Node { value, span }
}

fn table(
    t: &DeTable<'_>,
    text: &str,
    errors: &mut Vec<SyntaxError>,
    too_deep_reported: &mut bool,
    first_keys: &BTreeMap<usize, Span>,
    depth: u32,
) -> Table {
    let mut entries: Vec<Entry> = t
        .iter()
        .map(|(k, v)| Entry {
            key: k.get_ref().as_ref().to_owned(),
            key_span: first_keys
                .get(&k.span().start)
                .copied()
                .unwrap_or_else(|| Span::of(k.span())),
            node: node(v, text, errors, too_deep_reported, first_keys, depth + 1),
        })
        .collect();
    entries.sort_by_key(|e| e.key_span.start);
    Table { entries }
}

/// Inspect the same recovered events that build `DeTable`, without building
/// recursive values. The event parser's guard bounds its own call stack;
/// our combined count additionally includes dotted keys and table headers.
/// A malformed key/value separator therefore cannot hide an opening brace.
#[derive(Default)]
struct Scan {
    too_deep: Option<usize>,
    header_depth: u32,
    key_dots: u32,
    depths: Vec<u32>,
    in_header: bool,
    header: Vec<Event>,
    headers: Vec<Vec<Event>>,
}

impl Scan {
    fn depth(&self) -> u32 {
        self.depths.last().copied().unwrap_or(self.header_depth) + self.key_dots
    }

    fn event(&mut self, event: Event) {
        match event.kind() {
            EventKind::StdTableOpen | EventKind::ArrayTableOpen => {
                self.header_depth = 1;
                self.key_dots = 0;
                self.in_header = true;
                self.header.clear();
            }
            EventKind::StdTableClose | EventKind::ArrayTableClose => {
                self.header_depth += self.key_dots;
                self.key_dots = 0;
                self.in_header = false;
                if self.too_deep.is_none() {
                    self.headers.push(core::mem::take(&mut self.header));
                }
            }
            EventKind::SimpleKey if self.in_header && self.too_deep.is_none() => {
                self.header.push(event);
            }
            EventKind::KeySep => self.key_dots += 1,
            EventKind::InlineTableOpen | EventKind::ArrayOpen => {
                self.depths.push(self.depth() + 1);
                self.key_dots = 0;
            }
            EventKind::InlineTableClose | EventKind::ArrayClose => {
                self.depths.pop();
                self.key_dots = 0;
            }
            EventKind::Scalar | EventKind::ValueSep => self.key_dots = 0,
            EventKind::Newline if self.depths.is_empty() && !self.in_header => {
                self.key_dots = 0;
            }
            _ => {}
        }
        if self.too_deep.is_none() && self.depth() > NESTING_MAX {
            self.too_deep = Some(event.span().start());
        }
    }
}

fn scan(text: &str) -> Scan {
    let tokens = toml_parser::Source::new(text).lex().into_vec();
    let mut scan = Scan::default();
    // Bound the event parser before calling it too. Recovery can emit a close
    // without an open; its event guard alone must not be trusted to measure
    // the actual call stack. The lexer never recurses and hides punctuation
    // inside strings/comments. Mismatched closers cannot subtract depth.
    let mut delimiters = Vec::new();
    for token in &tokens {
        match token.kind() {
            TokenKind::LeftSquareBracket | TokenKind::LeftCurlyBracket => {
                delimiters.push(token.kind());
                if delimiters.len() > NESTING_MAX as usize {
                    scan.too_deep = Some(token.span().start());
                    return scan;
                }
            }
            TokenKind::RightSquareBracket
                if delimiters.last() == Some(&TokenKind::LeftSquareBracket) =>
            {
                delimiters.pop();
            }
            TokenKind::RightCurlyBracket
                if delimiters.last() == Some(&TokenKind::LeftCurlyBracket) =>
            {
                delimiters.pop();
            }
            _ => {}
        }
    }
    let mut receive = |event| scan.event(event);
    let mut guard = RecursionGuard::new(&mut receive, NESTING_MAX);
    toml_parser::parser::parse_document(&tokens, &mut guard, &mut ());
    scan
}

#[cfg(test)]
fn too_deep(text: &str) -> Option<usize> {
    scan(text).too_deep
}

/// Preserve the first spelling of every header path before a later explicit
/// parent can replace its key span. Resolve each path in the finished tree:
/// a parser key's offset identifies that particular entry, including entries
/// in different elements of an array of tables. No textual key matching or
/// global name-only map is used (quoted/escaped keys can name the same path).
fn first_key_spans(doc: &DeTable<'_>, text: &str, headers: &[Vec<Event>]) -> BTreeMap<usize, Span> {
    let source = toml_parser::Source::new(text);
    let mut first = BTreeMap::new();
    for header in headers {
        let mut table = doc;
        for event in header {
            let mut decoded = Cow::Borrowed("");
            source
                .get(*event)
                .expect("event span")
                .decode_key(&mut decoded, &mut ());
            let Some((key, value)) = table.get_key_value(decoded.as_ref()) else {
                break; // Invalid paths cannot produce a successful tree.
            };
            let span = event.span();
            first
                .entry(key.span().start)
                .or_insert_with(|| Span::of(key.span()).min(Span::of(span.start()..span.end())));
            table = match value.get_ref() {
                DeValue::Table(t) => t,
                DeValue::Array(a) => {
                    // A header belongs to the latest element opened before it.
                    let end = a.partition_point(|v| v.span().start <= span.start());
                    let Some(DeValue::Table(t)) = end.checked_sub(1).map(|i| a[i].get_ref()) else {
                        break;
                    };
                    t
                }
                _ => break,
            };
        }
    }
    first
}

/// Never run the parser tree's recursive drop glue, even for a rejected tree.
/// Move children onto a work list before dropping their now-empty container.
fn drop_parser_tree(doc: DeTable<'_>) {
    let mut pending = alloc::vec![DeValue::Table(doc)];
    while let Some(value) = pending.pop() {
        match value {
            DeValue::Table(t) => pending.extend(t.into_iter().map(|(_, v)| v.into_inner())),
            DeValue::Array(a) => pending.extend(a.into_iter().map(|v| v.into_inner())),
            _ => {}
        }
    }
}

/// Parses one file. Every error the parser recovers from is reported, in
/// byte order; any error means no tree. Nesting is capped twice: a text
/// event scan bounds recursion before constructing parser values, and the
/// copy counts actual nodes (including each array-of-tables element) so the
/// tree and every walk over it stay within `NESTING_MAX`. The parser tree is
/// then dismantled iteratively, including when the file has errors.
pub fn parse(bytes: &[u8]) -> Result<Table, Vec<SyntaxError>> {
    parse_inner(bytes, true)
}

fn parse_inner(bytes: &[u8], check_depth: bool) -> Result<Table, Vec<SyntaxError>> {
    if bytes.len() > FILE_BYTES_MAX {
        let at = FILE_BYTES_MAX as u32;
        return Err(alloc::vec![SyntaxError {
            span: Span { start: at, end: at },
            kind: SyntaxErrorKind::TooLarge,
        }]);
    }
    let text = core::str::from_utf8(bytes).map_err(|e| {
        let at = e.valid_up_to() as u32;
        alloc::vec![SyntaxError {
            span: Span {
                start: at,
                end: at + 1,
            },
            kind: SyntaxErrorKind::NotUtf8,
        }]
    })?;
    let scanned = scan(text);
    if let Some(at) = scanned.too_deep.filter(|_| check_depth) {
        let at = at as u32;
        return Err(alloc::vec![SyntaxError {
            span: Span {
                start: at,
                end: (at + 1).min(bytes.len() as u32)
            },
            kind: SyntaxErrorKind::TooDeep,
        }]);
    }
    let (doc, parse_errors) = DeTable::parse_recoverable(text);
    let mut errors: Vec<SyntaxError> = parse_errors
        .iter()
        .map(|e| SyntaxError {
            span: e.span().map(Span::of).unwrap_or_default(),
            kind: SyntaxErrorKind::Toml(e.message().to_owned()),
        })
        .collect();
    let first_keys = first_key_spans(doc.get_ref(), text, &scanned.headers);
    let mut too_deep_reported = false;
    let tree = table(
        doc.get_ref(),
        text,
        &mut errors,
        &mut too_deep_reported,
        &first_keys,
        0,
    );
    drop_parser_tree(doc.into_inner());
    if errors.is_empty() {
        Ok(tree)
    } else {
        errors.sort_by_key(|e| e.span);
        Err(errors)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn sp(src: &str, needle: &str) -> Span {
        let at = src.find(needle).expect("needle") as u32;
        Span {
            start: at,
            end: at + needle.len() as u32,
        }
    }

    // 이것을 실패시키는 것: 키·값·표 머리의 바이트 범위를 잘못 옮기는 것(진단과 출처가 틀린 줄을 가리킴).
    #[test]
    fn spans_point_at_the_written_text() {
        let src = "version = 1 # c\n[colors]\nmode = \"auto\"\n[segment.\"custom/kube\"]\nkind = \"command\"\n";
        let t = parse(src.as_bytes()).unwrap();
        let v = t.get("version").unwrap();
        assert_eq!(
            (v.key_span, v.node.span),
            (sp(src, "version"), sp(src, "1"))
        );
        assert_eq!(v.node.value, Value::Int(1));
        let colors = t.get("colors").unwrap();
        assert_eq!(colors.node.span, sp(src, "[colors]"));
        let Value::Table(c) = &colors.node.value else {
            panic!()
        };
        assert_eq!(c.get("mode").unwrap().node.span, sp(src, "\"auto\""));
        let Value::Table(seg) = &t.get("segment").unwrap().node.value else {
            panic!()
        };
        let kube = seg.get("custom/kube").unwrap();
        assert_eq!(kube.key_span, sp(src, "\"custom/kube\""));
        assert_eq!(kube.node.span, sp(src, "[segment.\"custom/kube\"]"));
    }

    // 이것을 실패시키는 것: 복구한 오류를 하나만 내거나, 오류가 있는데 트리를 내는 것, 정수 범위·크기·UTF-8 검사를 빠뜨리는 것.
    #[test]
    fn errors_are_all_reported_with_where() {
        let e = parse(b"a = \"x\nb = 1\nc = [\n").unwrap_err();
        assert_eq!(e.len(), 2, "{e:?}");
        assert!(e.windows(2).all(|w| w[0].span <= w[1].span));
        let e = parse(b"a = 1\na = 2\n").unwrap_err();
        assert_eq!(e[0].span, Span { start: 6, end: 7 });
        let e = parse(b"n = 99999999999999999999\n").unwrap_err();
        assert_eq!(e[0].kind, SyntaxErrorKind::IntegerRange);
        let e = parse(b"a = \"\xff\"\n").unwrap_err();
        assert_eq!(
            (e[0].kind.clone(), e[0].span.start),
            (SyntaxErrorKind::NotUtf8, 5)
        );
        let big = vec![b'#'; FILE_BYTES_MAX + 1];
        assert_eq!(parse(&big).unwrap_err()[0].kind, SyntaxErrorKind::TooLarge);
        assert!(parse(&vec![b'#'; FILE_BYTES_MAX]).is_ok());
    }

    // 이것을 실패시키는 것: 파서의 정렬된 순서(키 이름순)를 그대로 두는 것.
    #[test]
    fn entries_follow_the_file() {
        let t = parse(b"zeta = 1\nalpha = 2\n[mid]\nb = 1\na = 2\n").unwrap();
        let keys = |t: &Table| t.entries.iter().map(|e| e.key.clone()).collect::<Vec<_>>();
        assert_eq!(keys(&t), ["zeta", "alpha", "mid"]);
        let Value::Table(mid) = &t.get("mid").unwrap().node.value else {
            panic!()
        };
        assert_eq!(keys(mid), ["b", "a"]);
    }

    // 이것을 실패시키는 것: 나중에 명시한 부모의 span으로 첫 위치와 순서를 덮어쓰는 것.
    #[test]
    fn implicit_parents_keep_the_first_key_span() {
        let src = "[a.b]\nx=1\n[c]\nx=2\n[a]\nx=3\n";
        let t = parse(src.as_bytes()).unwrap();
        assert_eq!(
            t.entries.iter().map(|e| e.key.as_str()).collect::<Vec<_>>(),
            ["a", "c"]
        );
        assert_eq!(t.get("a").unwrap().key_span, Span { start: 1, end: 2 });
        assert_eq!(t.get("a").unwrap().node.span, sp(src, "[a]"));

        let src = "a.b=1\n[z]\nx=2\n[a.c]\nx=3\n";
        let t = parse(src.as_bytes()).unwrap();
        assert_eq!(t.entries[0].key, "a");
        assert_eq!(t.entries[0].key_span, Span { start: 0, end: 1 });

        // Decode equivalent quoted spellings, preserve nested parents, and keep
        // the two array elements' identical paths separate.
        let src = "[[items]]\n[items.'a.b'.child]\nx=1\n[items.c]\nx=2\n[items.\"a\\u002Eb\"]\nx=3\n\
                   [[items]]\n[items.c]\nx=4\n[items.\"a.b\".child]\nx=5\n[items.'a.b']\nx=6\n";
        let t = parse(src.as_bytes()).unwrap();
        let Value::Array(items) = &t.get("items").unwrap().node.value else {
            panic!()
        };
        for (i, expected) in [["a.b", "c"], ["c", "a.b"]].iter().enumerate() {
            let Value::Table(t) = &items[i].value else {
                panic!()
            };
            assert_eq!(
                t.entries.iter().map(|e| e.key.as_str()).collect::<Vec<_>>(),
                *expected
            );
            let first = if i == 0 { "'a.b'" } else { "\"a.b\"" };
            assert_eq!(t.get("a.b").unwrap().key_span, sp(src, first));
        }
    }

    // 이것을 실패시키는 것: 원본 트리를 재귀 drop으로 해제하는 것(거부한 트리도 포함).
    #[test]
    fn parser_tree_drop_does_not_recurse() {
        let mut value = DeValue::Boolean(true);
        for i in 0..20_000 {
            let child = toml::Spanned::new(0..0, value);
            value = if i % 2 == 0 {
                DeValue::Array(core::iter::once(child).collect())
            } else {
                let mut t = DeTable::new();
                t.insert(toml::Spanned::new(0..0, Cow::Borrowed("a")), child);
                DeValue::Table(t)
            };
        }
        let mut doc = DeTable::new();
        doc.insert(
            toml::Spanned::new(0..0, Cow::Borrowed("root")),
            toml::Spanned::new(0..0, value),
        );
        drop_parser_tree(doc);
    }

    fn kind_of(src: &str) -> Option<SyntaxErrorKind> {
        parse(src.as_bytes()).err().map(|e| e[0].kind.clone())
    }

    // 깊은 중첩은 스택을 넘기지 않고 오류다. 표 머리·점 키·배열·인라인 표의 깊이를 합쳐 센다
    // (파서는 장치마다 따로 80까지라, 합치면 수천 단이 되어 스택이 넘쳤다).
    // 이것을 실패시키는 것: 합친 깊이를 세지 않는 것, 따옴표 안의 점·괄호나 값의 소수점을 깊이로 세는 것,
    // 따옴표 키의 점을 세지 않는 것(우회), 32를 하나 어긋나게 세는 것.
    #[test]
    fn deep_nesting_is_an_error_not_a_crash() {
        // Each case holds for the scan alone and for the whole parse.
        let deep = |src: &str| {
            assert!(too_deep(src).is_some(), "scan: {src:.60}");
            assert_eq!(kind_of(src), Some(SyntaxErrorKind::TooDeep), "{src:.60}");
        };
        let shallow = |src: &str| {
            assert!(too_deep(src).is_none(), "scan: {src:.60}");
            assert!(parse(src.as_bytes()).is_ok(), "{src:.60}");
        };
        let arrays = |n: usize| alloc::format!("a = {}{}\n", "[".repeat(n), "]".repeat(n));
        shallow(&arrays(32));
        deep(&arrays(33));
        // 31 dots in the header = 32 levels; one more value level is 33.
        let header = alloc::format!("[{}]\n", ["a"; 32].join("."));
        shallow(&alloc::format!("{header}k = 1\n"));
        deep(&alloc::format!("{header}k = []\n"));
        // Header, dotted key and inline tables add up.
        let twelve = ["a"; 12].join("."); // 12 + 12 + 12 levels
        let mixed = alloc::format!("[{twelve}]\n{twelve} = {{ {twelve} = {{ x = 1 }} }}\n");
        deep(&mixed);
        let (h, k1, k2) = (
            ["a"; 10].join("."),
            ["b"; 10].join("."),
            ["c"; 11].join("."),
        );
        let at_limit = alloc::format!("[{h}]\n{k1} = {{ {k2} = {{ x = [1] }} }}\n");
        shallow(&at_limit);
        // Quoted parts: dots inside quotes are not levels, dots between them are.
        let quoted = alloc::format!("[{}]\nk = []\n", ["\"a\""; 32].join("."));
        deep(&quoted);
        let src = "x = \"[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[\"\n\"a.b.c\" = 1\nf = [1.5, 2.5] # [[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[\n";
        shallow(src);
        // A quoted header part with many dots is one level.
        let one = alloc::format!("[\"{}\"]\nk = 1\n", ["a"; 40].join("."));
        shallow(&one);
        // The parser's own caps stay behind ours.
        assert!(parse(arrays(100_000).as_bytes()).is_err());
        let dotted = alloc::format!("{} = 1\n", ["a"; 2000].join("."));
        deep(&dotted);
    }

    // 깊이는 파서가 만든 트리 노드로 센다(글 훑기가 파서와 다르게 읽어도 막힘).
    // 이것을 실패시키는 것: 트리로 옮길 때 깊이를 세지 않는 것, 다중 줄 문자열 끝의 덧붙은 따옴표를
    // 훑기가 새 문자열의 시작으로 읽는 것(그 줄의 괄호를 세지 않게 됨).
    #[test]
    fn depth_is_counted_on_the_parsed_tree() {
        let arrays = |n: usize| alloc::format!("a = {}{}\n", "[".repeat(n), "]".repeat(n));
        // The scan off: the parser accepts 40 (its cap is 80); the tree does not.
        assert!(parse_inner(arrays(32).as_bytes(), false).is_ok());
        assert_eq!(
            parse_inner(arrays(40).as_bytes(), false).unwrap_err()[0].kind,
            SyntaxErrorKind::TooDeep
        );
        let deep = alloc::format!(
            "{}{}",
            "{ a = ".repeat(33),
            "1".to_owned() + &" }".repeat(33)
        );
        for q in [
            "\"\"\"q\"\"\"\"",
            "\"\"\"q\"\"\"\"\"",
            "\'\'\'q\'\'\'\'",
            "\'\'\'q\'\'\'\'\'",
        ] {
            let src = alloc::format!("x = [ {q}, {deep} ]\n");
            assert_eq!(kind_of(&src), Some(SyntaxErrorKind::TooDeep), "{q}");
            // The scan alone sees it too, so the parser never recurses that deep.
            assert!(too_deep(&src).is_some(), "scan: {q}");
        }
    }

    // 이것을 실패시키는 것: 배열·인라인 표·점 키·표 배열을 다른 모양으로 옮기는 것.
    #[test]
    fn shapes_survive() {
        let src = "a.b = 1\nl = [1, \"x\", true]\ni = { k = 2.5 }\n[[x]]\ny = 2\n[[x]]\ny = 3\n";
        let t = parse(src.as_bytes()).unwrap();
        let Value::Table(a) = &t.get("a").unwrap().node.value else {
            panic!()
        };
        assert_eq!(a.get("b").unwrap().node.value, Value::Int(1));
        let Value::Array(l) = &t.get("l").unwrap().node.value else {
            panic!()
        };
        assert_eq!(
            l.iter().map(|n| n.value.kind()).collect::<Vec<_>>(),
            ["integer", "string", "boolean"]
        );
        let Value::Table(i) = &t.get("i").unwrap().node.value else {
            panic!()
        };
        assert_eq!(i.get("k").unwrap().node.value, Value::Float(2.5));
        let Value::Array(x) = &t.get("x").unwrap().node.value else {
            panic!()
        };
        assert_eq!(x.len(), 2);
        let second = src.rfind("[[x]]").unwrap() as u32;
        assert_eq!(
            x[1].span,
            Span {
                start: second,
                end: second + 5
            }
        );
    }
    // 이것을 실패시키는 것: 닫히지 않은 문자열의 마지막 역슬래시 뒤 바이트를 읽어 패닉하는 것.
    #[test]
    fn unfinished_escape_is_a_syntax_error() {
        for src in ["x = \"\\", "\"\\", "x = [\"\\", "x = \"\"\"\\", "[\"\\"] {
            let errors = parse(src.as_bytes()).unwrap_err();
            assert!(
                errors
                    .iter()
                    .any(|e| matches!(e.kind, SyntaxErrorKind::Toml(_))),
                "{src:?}: {errors:?}"
            );
            assert!(
                errors
                    .iter()
                    .all(|e| e.span.start <= e.span.end && e.span.end as usize <= src.len())
            );
        }
    }

    // 이것을 실패시키는 것: 날짜·시각을 다시 출력해 원본의 소문자·공백·소수 초를 바꾸는 것.
    #[test]
    fn datetime_keeps_the_written_spelling() {
        for spelling in [
            "1979-05-27t07:32:00z",
            "1979-05-27 07:32:00.1200",
            "07:32:00.000",
            "1979-05-27",
        ] {
            let src = alloc::format!("when = {spelling} # keep\n");
            let t = parse(src.as_bytes()).unwrap();
            let value = &t.get("when").unwrap().node;
            assert_eq!(value.value, Value::DateTime(spelling.to_owned()));
            assert_eq!(value.span, sp(&src, spelling));
            assert_eq!(value.value.kind(), "date-time");
        }
    }
}
