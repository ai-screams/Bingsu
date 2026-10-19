//! Local edits of one config file (spec section 2 "설정 파서와 국소 편집"):
//! change only around the changed key and keep comments, order and the way
//! the rest is written. The replacement value uses the caller's TOML spelling,
//! including its quotes. These functions support local value edits; `config
//! use` saves a selection record instead of editing a config file.
//!
//! An edit is a splice of byte ranges from the spanned tree (S1): set
//! replaces a value's range, insert adds one line after the table's last
//! key line (or a new table at the end), remove takes out the key's lines.
//! Every result is parsed again and must hold the change; otherwise the
//! edit is refused and the file is left as it was.
use crate::config::tree::{self, Node, Span, Table, Value};
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write as _;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EditError {
    /// The file does not parse now.
    Syntax,
    /// The path goes through a value that is not a table, or an array.
    NotATable { at: usize },
    /// A new key in an inline table (`a = { b = 1 }`) or in a table made by
    /// dotted keys, or a key removed from either: not edited in place (the
    /// caller explains). A key that is there is set in place.
    Unsupported,
    /// `remove` of a key that is not there.
    Missing,
    /// The new value text is not one TOML value.
    BadValue,
    /// The result did not parse back to the change (a bug guard).
    Check,
}

/// A TOML basic string for `s` (quotes, backslashes and control characters
/// escaped).
pub fn string(s: &str) -> String {
    let mut out = String::from("\"");
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 || c == '\u{7f}' => {
                let _ = write!(out, "\\u{:04X}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// A key as written in TOML: bare when it can be, quoted otherwise.
pub fn key(k: &str) -> String {
    let bare = !k.is_empty()
        && k.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-');
    if bare { String::from(k) } else { string(k) }
}

fn line_start(b: &[u8], at: usize) -> usize {
    b[..at]
        .iter()
        .rposition(|&c| c == b'\n')
        .map_or(0, |i| i + 1)
}

fn line_end(b: &[u8], at: usize) -> usize {
    b[at..]
        .iter()
        .position(|&c| c == b'\n')
        .map_or(b.len(), |i| at + i + 1)
}

fn is_header(b: &[u8], n: &Node) -> bool {
    b.get(n.span.start as usize) == Some(&b'[')
}

fn is_inline(b: &[u8], n: &Node) -> bool {
    b.get(n.span.start as usize) == Some(&b'{')
}

/// Walks the parent path, returning its table, node and whether any
/// ancestor is an inline table.
fn parent<'t>(
    bytes: &[u8],
    root: &'t Table,
    path: &[&str],
) -> Result<(&'t Table, Option<&'t Node>, bool), EditError> {
    let mut t = root;
    let mut node = None;
    let mut inside_inline = false;
    for (i, k) in path.iter().enumerate() {
        match t.get(k) {
            None => return Err(EditError::Missing),
            Some(e) => match &e.node.value {
                Value::Table(inner) => {
                    t = inner;
                    node = Some(&e.node);
                    inside_inline |= is_inline(bytes, &e.node);
                }
                _ => return Err(EditError::NotATable { at: i }),
            },
        }
    }
    Ok((t, node, inside_inline))
}

/// The value `text` is, when it is exactly one value: nothing after it, no
/// comment, no line break (a trailing `# …` would comment out what follows
/// the value on its line).
fn one_value(text: &str) -> Result<Value, EditError> {
    let probe = alloc::format!("v = {text}\n");
    let t = tree::parse(probe.as_bytes()).map_err(|_| EditError::BadValue)?;
    match t.entries.as_slice() {
        [e] if e.key == "v"
            && e.node.span
                == (Span {
                    start: 4,
                    end: 4 + text.len() as u32,
                }) =>
        {
            Ok(e.node.value.clone())
        }
        _ => Err(EditError::BadValue),
    }
}

/// Equal values, spans aside.
fn same(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Array(x), Value::Array(y)) => {
            x.len() == y.len() && x.iter().zip(y).all(|(p, q)| same(&p.value, &q.value))
        }
        (Value::Table(x), Value::Table(y)) => {
            x.entries.len() == y.entries.len()
                && x.entries.iter().all(|e| {
                    y.get(&e.key)
                        .is_some_and(|f| same(&e.node.value, &f.node.value))
                })
        }
        (Value::Float(x), Value::Float(y)) => x == y || (x.is_nan() && y.is_nan()),
        _ => a == b,
    }
}

/// Everything in `a` and `b` is the same except at `path` (a table missing
/// on one side counts as empty).
fn same_except(a: &Table, b: &Table, path: &[&str]) -> bool {
    let empty = Table::default();
    let keys = a.entries.iter().chain(&b.entries).map(|e| e.key.as_str());
    for k in keys {
        let (x, y) = (
            a.get(k).map(|e| &e.node.value),
            b.get(k).map(|e| &e.node.value),
        );
        match path {
            [p] if *p == k => continue,
            [p, rest @ ..] if *p == k => {
                fn t<'v>(v: Option<&'v Value>, empty: &'v Table) -> Option<&'v Table> {
                    match v {
                        Some(Value::Table(t)) => Some(t),
                        None => Some(empty),
                        _ => None,
                    }
                }
                match (t(x, &empty), t(y, &empty)) {
                    (Some(x), Some(y)) if same_except(x, y, rest) => continue,
                    _ => return false,
                }
            }
            _ => match (x, y) {
                (Some(x), Some(y)) if same(x, y) => {}
                _ => return false,
            },
        }
    }
    true
}

/// The guard every edit ends with: `out` parses, holds the change (`want`
/// is the value now at `path`, or `None` for gone), and nothing else in the
/// file changed meaning.
fn verify(
    before: &Table,
    out: &[u8],
    path: &[&str],
    want: Option<&Value>,
) -> Result<(), EditError> {
    let back = tree::parse(out).map_err(|_| EditError::Check)?;
    let ok = match (value_at(&back, path), want) {
        (Some(v), Some(w)) => same(v, w),
        (None, None) => true,
        _ => false,
    };
    if ok && same_except(before, &back, path) {
        Ok(())
    } else {
        Err(EditError::Check)
    }
}

fn splice(b: &[u8], at: Span, with: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(b.len() + with.len());
    out.extend_from_slice(&b[..at.start as usize]);
    out.extend_from_slice(with);
    out.extend_from_slice(&b[at.end as usize..]);
    out
}

fn value_at<'t>(t: &'t Table, path: &[&str]) -> Option<&'t Value> {
    let (last, first) = path.split_last()?;
    let mut t = t;
    for k in first {
        match &t.get(k)?.node.value {
            Value::Table(inner) => t = inner,
            _ => return None,
        }
    }
    Some(&t.get(last)?.node.value)
}

/// Sets `path` to `value` (TOML text of one value, e.g. `string("dark")`).
pub fn set(bytes: &[u8], path: &[&str], value: &str) -> Result<Vec<u8>, EditError> {
    let want = one_value(value)?;
    let root = tree::parse(bytes).map_err(|_| EditError::Syntax)?;
    let (last, table_path) = path.split_last().ok_or(EditError::Missing)?;
    let out = match parent(bytes, &root, table_path) {
        Ok((t, table_node, _)) => match t.get(last) {
            Some(e) => {
                if matches!(e.node.value, Value::Table(_)) && !is_inline(bytes, &e.node) {
                    return Err(EditError::NotATable { at: path.len() - 1 });
                }
                // The key is written on its own line in this table, or as the
                // last part of a dotted key: either way its value range is one
                // splice.
                splice(bytes, e.node.span, value.as_bytes())
            }
            // A table not opened by a header: made by dotted keys (`a.b = 1`),
            // where a new line would land in the enclosing table, or inline
            // (`a = { b = 1 }`), where it would not be inside the braces.
            None if table_node.is_some_and(|n| !is_header(bytes, n)) => {
                return Err(EditError::Unsupported);
            }
            None => {
                // After the table's last key line that is not itself a table.
                let after = t
                    .entries
                    .iter()
                    .filter(|e| {
                        !matches!(e.node.value, Value::Table(_)) || is_inline(bytes, &e.node)
                    })
                    .map(|e| e.node.span.end as usize)
                    .max();
                let at = match (after, table_node) {
                    (Some(end), _) => line_end(bytes, end),
                    (None, Some(n)) => line_end(bytes, n.span.end as usize),
                    (None, None) => 0,
                };
                let mut line = String::new();
                if at > 0 && bytes[at - 1] != b'\n' {
                    line.push('\n');
                }
                let _ = writeln!(line, "{} = {value}", key(last));
                splice(
                    bytes,
                    Span {
                        start: at as u32,
                        end: at as u32,
                    },
                    line.as_bytes(),
                )
            }
        },
        Err(EditError::Missing) => {
            // A new table at the end of the file.
            let mut add = String::new();
            if !bytes.is_empty() && !bytes.ends_with(b"\n") {
                add.push('\n');
            }
            if !bytes.is_empty() {
                add.push('\n');
            }
            add.push('[');
            for (i, k) in table_path.iter().enumerate() {
                if i > 0 {
                    add.push('.');
                }
                add.push_str(&key(k));
            }
            let _ = writeln!(add, "]\n{} = {value}", key(last));
            let end = bytes.len() as u32;
            splice(bytes, Span { start: end, end }, add.as_bytes())
        }
        Err(e) => return Err(e),
    };
    verify(&root, &out, path, Some(&want))?;
    Ok(out)
}

/// Removes `path` and its line (with a comment on the same line). Keys
/// that share a line with others, or sit in an inline table, are refused.
pub fn remove(bytes: &[u8], path: &[&str]) -> Result<Vec<u8>, EditError> {
    let root = tree::parse(bytes).map_err(|_| EditError::Syntax)?;
    let (last, table_path) = path.split_last().ok_or(EditError::Missing)?;
    let (t, _, inside_inline) = parent(bytes, &root, table_path)?;
    let e = t.get(last).ok_or(EditError::Missing)?;
    // Even on a line of its own, a key inside braces is not a key line
    // of a header table. This also covers dotted keys nested in braces.
    if inside_inline {
        return Err(EditError::Unsupported);
    }
    if matches!(e.node.value, Value::Table(_)) && !is_inline(bytes, &e.node) {
        return Err(EditError::Unsupported);
    }
    let start = line_start(bytes, e.key_span.start as usize);
    let end = line_end(bytes, e.node.span.end as usize);
    let before = &bytes[start..e.key_span.start as usize];
    let after = core::str::from_utf8(&bytes[e.node.span.end as usize..end])
        .map_err(|_| EditError::Check)?;
    let rest = after.trim_start_matches([' ', '\t']);
    let alone = before.iter().all(|&c| c == b' ' || c == b'\t')
        && (rest.is_empty()
            || rest.starts_with('\n')
            || rest.starts_with("\r\n")
            || rest.starts_with('#'));
    // A dotted key (`a.b = 1`) starts before this key's span on the line.
    if !alone {
        return Err(EditError::Unsupported);
    }
    let out = splice(
        bytes,
        Span {
            start: start as u32,
            end: end as u32,
        },
        b"",
    );
    verify(&root, &out, path, None)?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    const FILE: &str = "# my prompt\nversion = 1\n\n[colors]\n# I like it dark\nmode = 'auto'   # was light\nflavor = \"a\"\n\n[layout.line1]\nleft = [\"dir\",   \"git\"]\n";

    fn s(b: &[u8]) -> &str {
        core::str::from_utf8(b).unwrap()
    }

    // 이것을 실패시키는 것: 바뀐 값 밖의 바이트(주석·따옴표 모양·빈 줄·배열의 공백·순서)를 바꾸는 것.
    #[test]
    fn set_replaces_only_the_value() {
        let out = set(FILE.as_bytes(), &["colors", "mode"], &string("dark")).unwrap();
        assert_eq!(s(&out), FILE.replace("'auto'", "\"dark\""));
        let out = set(FILE.as_bytes(), &["layout", "line1", "left"], "[\"char\"]").unwrap();
        assert_eq!(s(&out), FILE.replace("[\"dir\",   \"git\"]", "[\"char\"]"));
    }

    // 이것을 실패시키는 것: 새 키를 표 밖(다음 표 아래)이나 파일 끝에 넣는 것, 없는 표를 만들지 않는 것.
    #[test]
    fn insert_goes_after_the_last_key_of_its_table() {
        let out = set(FILE.as_bytes(), &["colors", "knobs_note"], "1");
        assert!(out.is_ok());
        let out = set(FILE.as_bytes(), &["icons"], &string("nerd")).unwrap();
        assert_eq!(
            s(&out),
            FILE.replace("version = 1\n", "version = 1\nicons = \"nerd\"\n")
        );
        let out = set(
            FILE.as_bytes(),
            &["colors", "roles"],
            "{ path = \"accent.blue\" }",
        )
        .unwrap();
        assert_eq!(
            s(&out),
            FILE.replace(
                "flavor = \"a\"\n",
                "flavor = \"a\"\nroles = { path = \"accent.blue\" }\n"
            )
        );
        let out = set(
            FILE.as_bytes(),
            &["segment", "custom/kube", "kind"],
            &string("command"),
        )
        .unwrap();
        assert_eq!(
            s(&out),
            alloc::format!("{FILE}\n[segment.\"custom/kube\"]\nkind = \"command\"\n")
        );
        let out = set(b"", &["width", "ambiguous"], "2").unwrap();
        assert_eq!(s(&out), "[width]\nambiguous = 2\n");
        // A table opened only by its sub-table header gets the key under that header.
        let out = set(FILE.as_bytes(), &["layout", "line1", "right"], "[]").unwrap();
        assert_eq!(s(&out), alloc::format!("{FILE}right = []\n"));
    }

    // 이것을 실패시키는 것: 키 줄을 지우며 이웃 줄·주석 줄을 함께 지우거나, 한 줄의 다른 키까지 지우는 것.
    #[test]
    fn remove_takes_out_the_key_line_only() {
        let out = remove(FILE.as_bytes(), &["colors", "mode"]).unwrap();
        assert_eq!(s(&out), FILE.replace("mode = 'auto'   # was light\n", ""));
        assert_eq!(
            remove(b"a = { b = 1, c = 2 }\n", &["a", "b"]),
            Err(EditError::Unsupported)
        );
        assert_eq!(
            remove(FILE.as_bytes(), &["colors", "nope"]),
            Err(EditError::Missing)
        );
        assert_eq!(
            remove(b"x.y = 1\n", &["x", "y"]),
            Err(EditError::Unsupported)
        );
    }

    // 이것을 실패시키는 것: 인라인 표 값을 키 줄로 보지 않아 새 키를 그 앞에 넣는 것, 인라인 표 키를 지우지 못하거나
    // 머리로 연 표를 통째로 지우는 것.
    #[test]
    fn inline_table_values_are_key_lines() {
        let out = set(b"[c]\nx = { a = 1 }\n", &["c", "y"], "2").unwrap();
        assert_eq!(s(&out), "[c]\nx = { a = 1 }\ny = 2\n");
        assert_eq!(
            remove(b"a = { b = 1 }\nc = 2\n", &["a"]),
            Ok(b"c = 2\n".to_vec())
        );
        assert_eq!(remove(b"[t]\nk = 1\n", &["t"]), Err(EditError::Unsupported));
    }

    // 이것을 실패시키는 것: 인라인 표 안에 끼워 넣거나, 값이 아닌 글(두 값, 주석으로 끝남)을 받거나,
    // 문법 오류 파일을 고치는 것.
    #[test]
    fn refusals() {
        assert_eq!(
            set(b"a = { b = 1 }\n", &["a", "c"], "2"),
            Err(EditError::Unsupported)
        );
        // A key already in an inline table is set in place.
        assert_eq!(
            set(b"a = { b = 1 } # c\n", &["a", "b"], "2"),
            Ok(b"a = { b = 2 } # c\n".to_vec())
        );
        assert_eq!(
            set(FILE.as_bytes(), &["colors", "mode"], "1 2"),
            Err(EditError::BadValue)
        );
        assert_eq!(
            set(FILE.as_bytes(), &["colors", "mode"], "\"x\" # y\nz = 1"),
            Err(EditError::BadValue)
        );
        assert_eq!(set(b"a = [\n", &["a"], "1"), Err(EditError::Syntax));
        assert_eq!(
            set(FILE.as_bytes(), &["version", "x"], "1"),
            Err(EditError::NotATable { at: 0 })
        );
    }

    // 이것을 실패시키는 것: 결과를 다시 읽어 확인하지 않는 것(틀린 이어 붙이기를 그대로 돌려줌),
    // 점 키로만 생긴 표에 줄을 더해 바깥 표의 키가 되게 하는 것.
    #[test]
    fn every_edit_is_read_back() {
        let one = Value::Int(1);
        assert_eq!(
            verify(&Table::default(), b"a = 1\n", &["a"], Some(&one)),
            Ok(())
        );
        assert_eq!(
            verify(&Table::default(), b"a = 2\n", &["a"], Some(&one)),
            Err(EditError::Check)
        );
        assert_eq!(
            verify(&Table::default(), b"c = 1\n", &["a", "c"], Some(&one)),
            Err(EditError::Check)
        );
        assert_eq!(
            verify(&Table::default(), b"a = 1\n", &["a"], None),
            Err(EditError::Check)
        );
        assert_eq!(
            verify(&Table::default(), b"a = [\n", &["a"], None),
            Err(EditError::Check)
        );
        assert_eq!(
            set(b"a.b = 1\n", &["a", "c"], "2"),
            Err(EditError::Unsupported)
        );
        // Arrays and tables compare item by item, spans aside.
        let arr = Value::Array(vec![Node {
            value: Value::Int(1),
            span: Span::default(),
        }]);
        assert_eq!(
            verify(&Table::default(), b"a = [1]\n", &["a"], Some(&arr)),
            Ok(())
        );
        assert_eq!(
            verify(&Table::default(), b"a = [1, 2]\n", &["a"], Some(&arr)),
            Err(EditError::Check)
        );
        let tbl = one_value("{ b = 1 }").unwrap();
        assert_eq!(
            verify(&Table::default(), b"a = { b = 1 }\n", &["a"], Some(&tbl)),
            Ok(())
        );
        assert_eq!(
            verify(
                &Table::default(),
                b"a = { b = 1, c = 2 }\n",
                &["a"],
                Some(&tbl)
            ),
            Err(EditError::Check)
        );
        assert_eq!(
            verify(&Table::default(), b"a = { b = 2 }\n", &["a"], Some(&tbl)),
            Err(EditError::Check)
        );
    }

    // 이것을 실패시키는 것: 값 글 뒤의 주석이 같은 줄의 이웃 키를 주석으로 만들게 두는 것,
    // 바꾼 경로 밖의 키가 사라진 결과를 받는 것.
    #[test]
    fn neighbours_survive_an_edit() {
        let src = b"a = {\n  b = 1, c = 2,\n}\n";
        assert_eq!(set(src, &["a", "b"], "3 # x"), Err(EditError::BadValue));
        assert_eq!(set(src, &["a", "b"], "3\n"), Err(EditError::BadValue));
        assert_eq!(
            set(src, &["a", "b"], "3"),
            Ok(b"a = {\n  b = 3, c = 2,\n}\n".to_vec())
        );
        let before = tree::parse(b"a = 1\nb = 2\n").unwrap();
        assert_eq!(
            verify(&before, b"a = 5\n", &["a"], Some(&Value::Int(5))),
            Err(EditError::Check)
        );
        assert_eq!(
            verify(&before, b"a = 5\nb = 2\n", &["a"], Some(&Value::Int(5))),
            Ok(())
        );
    }

    // 이것을 실패시키는 것: 따옴표·역슬래시·제어 문자를 그대로 넣어 값이 깨지거나 다른 키가 생기는 것.
    #[test]
    fn strings_and_keys_are_quoted() {
        let nasty = "a\"b\\c\nd = 1\u{1}";
        let out = set(b"", &["colors", "roles", "git.dirty"], &string(nasty)).unwrap();
        let t = tree::parse(&out).unwrap();
        assert_eq!(
            value_at(&t, &["colors", "roles", "git.dirty"]),
            Some(&Value::Str(nasty.into()))
        );
        for text in ["\t\r\u{7f}", "한글🙂", "", "# x"] {
            let out = set(b"", &[text], &string(text)).unwrap();
            let t = tree::parse(&out).unwrap();
            assert_eq!(value_at(&t, &[text]), Some(&Value::Str(text.into())));
        }
        assert_eq!(string("\t"), "\"\\t\"");
        assert_eq!(key("dir"), "dir");
        assert_eq!(key("custom/kube"), "\"custom/kube\"");
        assert_eq!(vec![key("")], vec![String::from("\"\"")]);
    }

    // 이것을 실패시키는 것: 값인 인라인 표까지 머리로 연 표처럼 취급하여 교체를 거부하는 것.
    #[test]
    fn inline_tables_can_be_replaced_as_values() {
        let src = b"a = { b = 1 } # keep\n[t]\nx = 2\n";
        assert_eq!(
            set(src, &["a"], "{ c = 3 }"),
            Ok(b"a = { c = 3 } # keep\n[t]\nx = 2\n".to_vec())
        );
        assert_eq!(
            set(src, &["a"], "4"),
            Ok(b"a = 4 # keep\n[t]\nx = 2\n".to_vec())
        );
        assert_eq!(set(src, &["t"], "4"), Err(EditError::NotATable { at: 0 }));
    }

    // 이것을 실패시키는 것: 여러 줄 인라인 표에서 혼자 쓴 키를 지우거나 중첩된 인라인 조상을 놓치는 것.
    #[test]
    fn inline_children_cannot_be_removed_even_on_their_own_line() {
        for src in [
            "a = {\n b = 1\n}\n",
            "a = {\n b.c = 1\n}\n",
            "[t]\na = { b = {\n c = 1\n} }\n",
        ] {
            let path: &[&str] = if src.starts_with("[t]") {
                &["t", "a", "b", "c"]
            } else if src.contains("b.c") {
                &["a", "b", "c"]
            } else {
                &["a", "b"]
            };
            assert_eq!(
                remove(src.as_bytes(), path),
                Err(EditError::Unsupported),
                "{src}"
            );
        }
    }

    // 이것을 실패시키는 것: NaN의 자기 비교가 거짓인 탓에 유효한 편집이나 무관한 키의 편집을 거부하는 것.
    #[test]
    fn nan_values_survive_verification() {
        for nan in ["nan", "+nan", "-nan"] {
            let src = alloc::format!("n = {nan}\na = 1\n");
            assert_eq!(
                set(src.as_bytes(), &["a"], "2"),
                Ok(src.replace("a = 1", "a = 2").into_bytes())
            );
            assert_eq!(
                set(b"n = 1\n", &["n"], nan),
                Ok(alloc::format!("n = {nan}\n").into_bytes())
            );
            assert_eq!(
                remove(src.as_bytes(), &["a"]),
                Ok(alloc::format!("n = {nan}\n").into_bytes())
            );
        }
    }

    // 이것을 실패시키는 것: 파일 끝 개행이 없거나 빈 표일 때 새 키를 기존 줄과 붙이거나 다른 표에 넣는 것.
    #[test]
    fn inserts_handle_empty_tables_and_missing_final_newlines() {
        for (src, path, expected) in [
            ("", &["x"][..], "x = 2\n"),
            ("[t]\nx=1\n", &["y"], "y = 2\n[t]\nx=1\n"),
            (
                "# keep\n[t] # header\n[u]\nx=1\n",
                &["t", "x"],
                "# keep\n[t] # header\nx = 2\n[u]\nx=1\n",
            ),
            ("[t]", &["t", "x"], "[t]\nx = 2\n"),
            ("[t]\nx=1", &["t", "y"], "[t]\nx=1\ny = 2\n"),
            ("x=1", &["new", "y"], "x=1\n\n[new]\ny = 2\n"),
            (
                "x=1\r\n[t]\r\ny=1\r\n",
                &["z"],
                "x=1\r\nz = 2\n[t]\r\ny=1\r\n",
            ),
        ] {
            assert_eq!(
                set(src.as_bytes(), path, "2"),
                Ok(expected.as_bytes().to_vec()),
                "{src}"
            );
        }
        let src = b"[a.b]\nx=1\n[c]\nx=2\n[a]\nx=3\n";
        assert_eq!(
            set(src, &["a", "y"], "2"),
            Ok(b"[a.b]\nx=1\n[c]\nx=2\n[a]\nx=3\ny = 2\n".to_vec())
        );
    }

    // 이것을 실패시키는 것: 값의 앞뒤 공백·개행·주석 또는 추가 대입문을 값 하나로 받아들이는 것.
    #[test]
    fn values_must_fill_the_entire_argument() {
        for bad in [
            "",
            " 1",
            "1 ",
            "1\t",
            "1\n",
            "1\r\n",
            "1 # note",
            "1\nx=2",
            "1\n[t]\nx=2",
        ] {
            assert_eq!(
                set(b"a=0\n", &["a"], bad),
                Err(EditError::BadValue),
                "{bad:?}"
            );
        }
        assert_eq!(
            set(b"a=0\n", &["a"], "[\n1, # inside\n2\n]"),
            Ok(b"a=[\n1, # inside\n2\n]\n".to_vec())
        );
    }

    // 이것을 실패시키는 것: 경로 밖의 중첩 값 변경·추가·삭제나 스칼라 조상으로 바뀐 결과를 확인에서 놓치는 것.
    #[test]
    fn verification_preserves_nested_neighbours() {
        let before = tree::parse(b"[a]\nb=1\nc={ d=[2, 3] }\n").unwrap();
        for bad in [
            "[a]\nb=4\nc={ d=[2, 5] }\n",
            "[a]\nb=4\nc={ d=[2, 3], e=5 }\n",
            "[a]\nb=4\n",
            "[a]\nb=4\nc={ d=[2, 3] }\nx=5\n",
        ] {
            assert_eq!(
                verify(&before, bad.as_bytes(), &["a", "b"], Some(&Value::Int(4))),
                Err(EditError::Check)
            );
        }
        let floats = tree::parse(b"a=1\nf=2.0\n").unwrap();
        assert_eq!(
            verify(&floats, b"a=2\nf=3.0\n", &["a"], Some(&Value::Int(2))),
            Err(EditError::Check)
        );
        assert_eq!(
            verify(&floats, b"a=2\nf=2.0\n", &["a"], Some(&Value::Int(2))),
            Ok(())
        );
        let before = tree::parse(b"a=1\n").unwrap();
        assert_eq!(
            verify(&before, b"[a]\nb=2\n", &["a", "b"], Some(&Value::Int(2))),
            Err(EditError::Check)
        );
        assert_eq!(
            verify(
                &Table::default(),
                b"[a]\nb=2\n",
                &["a", "b"],
                Some(&Value::Int(2))
            ),
            Ok(())
        );
    }

    // 이것을 실패시키는 것: 빈 경로·배열 경유·존재하지 않는 삭제·깨진 원본에 잘못된 오류를 돌려주는 것.
    #[test]
    fn path_and_source_errors_are_stable() {
        assert_eq!(set(b"", &[], "1"), Err(EditError::Missing));
        assert_eq!(remove(b"", &[]), Err(EditError::Missing));
        assert_eq!(remove(b"", &["x", "y"]), Err(EditError::Missing));
        assert_eq!(remove(b"a=[\n", &["a"]), Err(EditError::Syntax));
        assert_eq!(
            set(b"a=[]\n", &["a", "b"], "1"),
            Err(EditError::NotATable { at: 0 })
        );
        assert_eq!(
            remove(b"a=1\n", &["a", "b"]),
            Err(EditError::NotATable { at: 0 })
        );
        assert_eq!(set(b"a.b=1\n", &["a", "b"], "2"), Ok(b"a.b=2\n".to_vec()));
        assert_eq!(
            remove(b"# keep\r\n x = 1 # gone\r\ny=2", &["x"]),
            Ok(b"# keep\r\ny=2".to_vec())
        );
        assert_eq!(remove(b"x=1", &["x"]), Ok(vec![]));
        assert_eq!(remove(b"a.b=1\n", &["a"]), Err(EditError::Unsupported));
    }
    // 이것을 실패시키는 것: set이 결과 확인을 생략하여 파일 크기나 합친 깊이 상한을 넘는 결과를 반환하는 것.
    #[test]
    fn edits_recheck_file_size_and_combined_depth() {
        let mut src = String::from("x=1\n#");
        src.extend(core::iter::repeat_n(' ', tree::FILE_BYTES_MAX - src.len()));
        assert!(tree::parse(src.as_bytes()).is_ok());
        assert_eq!(set(src.as_bytes(), &["x"], "22"), Err(EditError::Check));
        let path = ["a"; tree::NESTING_MAX as usize];
        let src = alloc::format!("[{}]\nx=1\n", path.join("."));
        let mut full_path = path.to_vec();
        full_path.push("x");
        assert_eq!(set(src.as_bytes(), &full_path, "[]"), Err(EditError::Check));
    }
}
