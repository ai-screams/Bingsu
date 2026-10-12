//! Template syntax (spec section 3 "템플릿 문법"; ABNF in the M2 plan).
//! Only `{` and `}` are special. Every construct is inside braces, so a new
//! helper never changes how an existing theme parses (decision 10).
use alloc::string::String;
use alloc::vec::Vec;

/// Byte range in the template source. Kept in the syntax tree and in the
/// compiled template's side table, never in render nodes (spec section 3
/// "출처").
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Span {
    pub start: u32,
    pub end: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Plain,
    Block,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Syntax {
    /// Literal text, escapes already decoded.
    Text(String),
    /// `{seg}` or `{seg:block}`.
    Segment { id: String, mode: Mode },
    /// `{seg.field}`.
    Field { segment: String, field: String },
    /// `{@name}` or `{@name:arg,arg}`; `group`, `style` and `end` are blocks.
    Helper { name: String, args: Vec<String> },
    /// `{@group}` … `{@end}`.
    Group(Vec<(Syntax, Span)>),
    /// `{@style:…}` … `{@end}`.
    Style {
        args: Vec<String>,
        body: Vec<(Syntax, Span)>,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SyntaxErrorKind {
    TooLong,
    ControlChar,
    StrayClose,
    Unclosed,
    BadName,
    BadArg,
    StrayEnd,
    UnclosedBlock,
    TooDeep,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SyntaxError {
    pub kind: SyntaxErrorKind,
    pub span: Span,
}

/// Template source cap in bytes, and the block nesting cap.
pub const MAX_TEMPLATE_BYTES: usize = 4096;
pub const MAX_DEPTH: usize = 8;

fn span(start: usize, end: usize) -> Span {
    // Both are below MAX_TEMPLATE_BYTES, so they fit in u32.
    Span {
        start: start as u32,
        end: end as u32,
    }
}

fn is_id_part(s: &str) -> bool {
    let mut b = s.bytes();
    b.next().is_some_and(|c| c.is_ascii_lowercase())
        && b.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_' || c == b'-')
}

/// `seg-id = id-part [ "/" id-part ]` (provisional; M3 fixes the id ABNF).
fn is_segment_id(s: &str) -> bool {
    match s.split_once('/') {
        Some((a, b)) => is_id_part(a) && is_id_part(b),
        None => is_id_part(s),
    }
}

fn is_field_name(s: &str) -> bool {
    let mut b = s.bytes();
    b.next().is_some_and(|c| c.is_ascii_lowercase())
        && b.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_')
}

fn is_helper_name(s: &str) -> bool {
    let mut b = s.bytes();
    b.next().is_some_and(|c| c.is_ascii_lowercase())
        && b.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
}

fn is_arg(s: &str) -> bool {
    !s.is_empty()
        && s.bytes().all(|c| {
            c.is_ascii_lowercase()
                || c.is_ascii_digit()
                || matches!(c, b'_' | b'-' | b'.' | b'=' | b'#' | b'/')
        })
}

fn body(inner: &str, sp: Span) -> Result<Syntax, SyntaxError> {
    let bad = |kind| SyntaxError { kind, span: sp };
    if let Some(h) = inner.strip_prefix('@') {
        let (name, args) = match h.split_once(':') {
            Some((n, a)) => (n, a.split(',').map(String::from).collect::<Vec<_>>()),
            None => (h, Vec::new()),
        };
        if !is_helper_name(name) {
            return Err(bad(SyntaxErrorKind::BadName));
        }
        if args.iter().any(|a| !is_arg(a)) {
            return Err(bad(SyntaxErrorKind::BadArg));
        }
        return Ok(Syntax::Helper {
            name: name.into(),
            args,
        });
    }
    let (path, mode) = match inner.split_once(':') {
        Some((p, "block")) => (p, Some(Mode::Block)),
        Some((p, "plain")) => (p, Some(Mode::Plain)),
        Some(_) => return Err(bad(SyntaxErrorKind::BadArg)),
        None => (inner, None),
    };
    match path.rsplit_once('.') {
        Some((seg, field)) if mode.is_none() && is_segment_id(seg) && is_field_name(field) => {
            Ok(Syntax::Field {
                segment: seg.into(),
                field: field.into(),
            })
        }
        None if is_segment_id(path) => Ok(Syntax::Segment {
            id: path.into(),
            mode: mode.unwrap_or(Mode::Plain),
        }),
        _ => Err(bad(SyntaxErrorKind::BadName)),
    }
}

/// Parses `src` into a tree with spans. Blocks (`@group`, `@style`) are
/// matched with `@end` here; helper names and arguments are checked by the
/// compiler (src/template/compile.rs), which knows the closed helper list.
pub fn parse(src: &str) -> Result<Vec<(Syntax, Span)>, SyntaxError> {
    if src.len() > MAX_TEMPLATE_BYTES {
        return Err(SyntaxError {
            kind: SyntaxErrorKind::TooLong,
            span: span(0, 0),
        });
    }
    if let Some((i, c)) = src
        .char_indices()
        .find(|&(_, c)| crate::sanitize::is_removed(c))
    {
        return Err(SyntaxError {
            kind: SyntaxErrorKind::ControlChar,
            span: span(i, i + c.len_utf8()),
        });
    }
    // Stack of open blocks: (items so far, opening helper and its span).
    type Open = (Vec<(Syntax, Span)>, Option<(Syntax, Span)>);
    let mut stack: Vec<Open> = alloc::vec![(Vec::new(), None)];
    let b = src.as_bytes();
    let mut i = 0;
    let mut text = String::new();
    let mut text_start = 0;
    let flush = |text: &mut String, start: usize, end: usize, items: &mut Vec<(Syntax, Span)>| {
        if !text.is_empty() {
            items.push((Syntax::Text(core::mem::take(text)), span(start, end)));
        }
    };
    while i < b.len() {
        match b[i] {
            b'{' if b.get(i + 1) == Some(&b'{') => {
                if text.is_empty() {
                    text_start = i;
                }
                text.push('{');
                i += 2;
            }
            b'}' if b.get(i + 1) == Some(&b'}') => {
                if text.is_empty() {
                    text_start = i;
                }
                text.push('}');
                i += 2;
            }
            b'}' => {
                return Err(SyntaxError {
                    kind: SyntaxErrorKind::StrayClose,
                    span: span(i, i + 1),
                });
            }
            b'{' => {
                let Some(len) = src[i + 1..]
                    .find(['{', '}'])
                    .filter(|&n| b[i + 1 + n] == b'}')
                else {
                    return Err(SyntaxError {
                        kind: SyntaxErrorKind::Unclosed,
                        span: span(i, b.len()),
                    });
                };
                let sp = span(i, i + len + 2);
                let node = body(&src[i + 1..i + 1 + len], sp)?;
                let top = stack.len() - 1;
                flush(&mut text, text_start, i, &mut stack[top].0);
                match node {
                    Syntax::Helper { ref name, .. } if name == "group" || name == "style" => {
                        if stack.len() > MAX_DEPTH {
                            return Err(SyntaxError {
                                kind: SyntaxErrorKind::TooDeep,
                                span: sp,
                            });
                        }
                        stack.push((Vec::new(), Some((node, sp))));
                    }
                    Syntax::Helper { ref name, ref args } if name == "end" => {
                        if !args.is_empty() {
                            return Err(SyntaxError {
                                kind: SyntaxErrorKind::BadArg,
                                span: sp,
                            });
                        }
                        let Some((items, Some((open, osp)))) =
                            (stack.len() > 1).then(|| stack.pop()).flatten()
                        else {
                            return Err(SyntaxError {
                                kind: SyntaxErrorKind::StrayEnd,
                                span: sp,
                            });
                        };
                        let whole = Span {
                            start: osp.start,
                            end: sp.end,
                        };
                        let block = match open {
                            Syntax::Helper { name, args } if name == "group" => {
                                if !args.is_empty() {
                                    return Err(SyntaxError {
                                        kind: SyntaxErrorKind::BadArg,
                                        span: osp,
                                    });
                                }
                                Syntax::Group(items)
                            }
                            Syntax::Helper { args, .. } => Syntax::Style { args, body: items },
                            _ => unreachable!("only group and style open blocks"),
                        };
                        let top = stack.len() - 1;
                        stack[top].0.push((block, whole));
                    }
                    other => stack[top].0.push((other, sp)),
                }
                i += len + 2;
            }
            _ => {
                if text.is_empty() {
                    text_start = i;
                }
                let ch_len = src[i..].chars().next().map_or(1, char::len_utf8);
                text.push_str(&src[i..i + ch_len]);
                i += ch_len;
            }
        }
    }
    let top = stack.len() - 1;
    flush(&mut text, text_start, b.len(), &mut stack[top].0);
    if stack.len() > 1 {
        let (_, open) = stack.pop().expect("len > 1");
        let osp = open.map_or(span(0, 0), |(_, s)| s);
        return Err(SyntaxError {
            kind: SyntaxErrorKind::UnclosedBlock,
            span: osp,
        });
    }
    Ok(stack.pop().expect("root").0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use SyntaxErrorKind::*;

    fn kinds(src: &str) -> Vec<Syntax> {
        parse(src).unwrap().into_iter().map(|(n, _)| n).collect()
    }
    fn err(src: &str) -> (SyntaxErrorKind, u32, u32) {
        let e = parse(src).unwrap_err();
        (e.kind, e.span.start, e.span.end)
    }

    // 이것을 실패시키는 것: `{{`·`}}`를 글자로 풀지 않거나 다른 글자를 특수로 보는 것.
    #[test]
    fn escapes_and_plain_text() {
        assert_eq!(
            kinds("a{{b}}c (venv) [x] $y %z !w"),
            [Syntax::Text("a{b}c (venv) [x] $y %z !w".into())]
        );
        assert_eq!(
            kinds("{{{dir}}}"),
            [
                Syntax::Text("{".into()),
                Syntax::Segment {
                    id: "dir".into(),
                    mode: Mode::Plain
                },
                Syntax::Text("}".into()),
            ]
        );
    }

    // 이것을 실패시키는 것: 세그먼트·필드·모드·도우미 인자를 잘못 나누는 것.
    #[test]
    fn references_and_helpers() {
        assert_eq!(
            kinds("{git:block}{git.ahead}{custom/kube}{@sep:triangle}{@fill}"),
            [
                Syntax::Segment {
                    id: "git".into(),
                    mode: Mode::Block
                },
                Syntax::Field {
                    segment: "git".into(),
                    field: "ahead".into()
                },
                Syntax::Segment {
                    id: "custom/kube".into(),
                    mode: Mode::Plain
                },
                Syntax::Helper {
                    name: "sep".into(),
                    args: alloc::vec!["triangle".into()]
                },
                Syntax::Helper {
                    name: "fill".into(),
                    args: Vec::new()
                },
            ]
        );
    }

    // 이것을 실패시키는 것: 블록을 짝짓지 못하거나 span이 여는 곳부터 `{@end}`까지가 아닌 것.
    #[test]
    fn blocks_nest_with_spans() {
        let tree =
            parse("{@group}on {@style:fg=git.branch,bold}{git.branch}{@end}{@end}!").unwrap();
        assert_eq!(tree.len(), 2);
        let (Syntax::Group(items), sp) = &tree[0] else {
            panic!()
        };
        assert_eq!((sp.start, sp.end), (0, 62));
        assert!(
            matches!(&items[1].0, Syntax::Style { args, body } if args.len() == 2 && body.len() == 1)
        );
    }

    // 이것을 실패시키는 것: 오류 종류나 위치가 틀리는 것(진단이 엉뚱한 칸을 가리킴).
    #[test]
    fn errors_with_spans() {
        assert_eq!(err("ab}c"), (StrayClose, 2, 3));
        assert_eq!(err("a{dir"), (Unclosed, 1, 5));
        assert_eq!(err("a{d{ir}"), (Unclosed, 1, 7));
        assert_eq!(err("{Dir}"), (BadName, 0, 5));
        assert_eq!(err("{git.Ahead}"), (BadName, 0, 11));
        assert_eq!(err("{git.ahead:block}"), (BadName, 0, 17));
        assert_eq!(err("{dir:bold}"), (BadArg, 0, 10));
        assert_eq!(err("{@sep:Tri}"), (BadArg, 0, 10));
        assert_eq!(err("{@end}"), (StrayEnd, 0, 6));
        assert_eq!(err("x{@group}a"), (UnclosedBlock, 1, 9));
        assert_eq!(err("{@group:x}a{dir}{@end}"), (BadArg, 0, 10));
        assert_eq!(err("a\x1bb"), (ControlChar, 1, 2));
        // A multi-byte format character: the span covers all its bytes.
        assert_eq!(err("a\u{202E}b"), (ControlChar, 1, 4));
        let deep = "{@group}".repeat(9) + "{dir}" + &"{@end}".repeat(9);
        assert_eq!(err(&deep).0, TooDeep);
        let long = "a".repeat(MAX_TEMPLATE_BYTES + 1);
        assert_eq!(err(&long).0, TooLong);
    }

    // Limits are inclusive: 8 nested blocks and 4096 bytes parse.
    // 이것을 실패시키는 것: `>`를 `>=`로 바꾸거나 `stack.len() > MAX_DEPTH`를 `>=`로 바꾸는 것.
    #[test]
    fn limits_are_inclusive() {
        let ok = "{@group}".repeat(MAX_DEPTH) + "{dir}" + &"{@end}".repeat(MAX_DEPTH);
        assert!(parse(&ok).is_ok());
        assert!(parse(&"a".repeat(MAX_TEMPLATE_BYTES)).is_ok());
    }

    // Hostile input: every prefix of tricky strings returns Ok or Err, never panics
    // (multi-byte characters next to braces, lone braces, unterminated blocks).
    // 이것을 실패시키는 것: 바이트 인덱스가 글자 경계를 넘는 슬라이스(`src[i..i + 1]` 같은 것).
    #[test]
    fn hostile_input_never_panics() {
        let src =
            "{{}}{@group}한{dir}é{@style:bold}{git.branch}😀{@end}}{{{@end}{:}{.}{@}{@:}{a.b.c}{/}";
        for (i, _) in src.char_indices().chain(core::iter::once((src.len(), ' '))) {
            let _ = parse(&src[..i]);
        }
        let _ = parse(&"{".repeat(MAX_TEMPLATE_BYTES));
        let _ = parse(&"{@group}".repeat(MAX_TEMPLATE_BYTES / 8));
        let _ = parse(&"{}".repeat(MAX_TEMPLATE_BYTES / 2));
    }
}
