//! Template tree to render nodes (spec section 3 "템플릿 중간 표현"). The
//! helper list is closed: an unknown helper is an error, so a later helper
//! never changes an existing theme. Source spans go to a side table
//! (`CompiledLine::origin`), not into the nodes.
use super::syntax::{Mode, Span, Syntax, SyntaxErrorKind, parse};
use crate::color::palette::token_index;
use crate::color::sgr::{BOLD, DIM, ITALIC, UNDERLINE};
use crate::field::SegmentDecl;
use crate::icons;
use alloc::string::String;
use alloc::vec::Vec;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Shape {
    Triangle,
    Round,
    Slant,
    Flat,
}

impl Shape {
    fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "triangle" => Self::Triangle,
            "round" => Self::Round,
            "slant" => Self::Slant,
            "flat" => Self::Flat,
            _ => return None,
        })
    }
    /// Icon name for a separator pointing right (left side) or left.
    pub fn icon(self, right: bool) -> &'static str {
        match (self, right) {
            (Self::Triangle, true) => "sep.triangle.r",
            (Self::Triangle, false) => "sep.triangle.l",
            (Self::Round, true) => "sep.round.r",
            (Self::Round, false) => "sep.round.l",
            (Self::Slant, true) => "sep.slant.r",
            (Self::Slant, false) => "sep.slant.l",
            (Self::Flat, _) => "sep.flat",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FillKind {
    Space,
    Dot,
    Line,
}

impl FillKind {
    pub fn icon(self) -> &'static str {
        match self {
            Self::Space => "fill.space",
            Self::Dot => "fill.dot",
            Self::Line => "fill.line",
        }
    }
}

/// `{@style:…}`: token indices into TOKENS and SGR attribute bits.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct StyleSpec {
    pub fg: Option<u16>,
    pub bg: Option<u16>,
    pub attrs: u8,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Node {
    Text(String),
    Segment {
        seg: u16,
        mode: Mode,
    },
    Field {
        seg: u16,
        field: u16,
    },
    /// Separator colored from the visible blocks around it.
    Sep(Shape),
    Head(Shape),
    Tail(Shape),
    /// Splits the line: left of it is the left part, right of it the right
    /// part. On an upper line the gap is filled with this glyph; on the input
    /// line the right part becomes the right prompt.
    Fill(FillKind),
    /// Index into `icons::ICONS`.
    Icon(u16),
    Style(StyleSpec),
    StyleEnd,
    /// Conditional group: `len` nodes follow up to and including GroupEnd.
    Group {
        len: u32,
    },
    GroupEnd,
}

/// One compiled template line. The fields are private: `compile` is the
/// only way to make a non-empty line, so every `Node::Text` passed the
/// template checks (no control or format character).
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct CompiledLine {
    nodes: Vec<Node>,
    /// `origin[i]` is the source span of `nodes[i]`. Read by diagnostics and
    /// the decision log, never by layout.
    origin: Vec<Span>,
    fill: Option<usize>,
}

impl CompiledLine {
    pub fn nodes(&self) -> &[Node] {
        &self.nodes
    }
    pub fn origin(&self) -> &[Span] {
        &self.origin
    }
    /// Index of the `Fill` node, if the line has one.
    pub fn fill(&self) -> Option<usize> {
        self.fill
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CompileErrorKind {
    Syntax(SyntaxErrorKind),
    UnknownSegment,
    UnknownField,
    UnknownHelper,
    BadHelperArg,
    UnknownToken,
    UnknownIcon,
    TwoFills,
    GroupWithoutReference,
    TooManyLines,
    NewlineInBlock,
    /// The catalog is not sorted by id (fields by name) or has more entries
    /// than a `u16` index holds.
    BadCatalog,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CompileError {
    pub kind: CompileErrorKind,
    pub span: Span,
}

/// Most lines a template may have (spec section 2: `line1` and `line2`).
pub const MAX_LINES: usize = 2;

struct Ctx<'a> {
    catalog: &'a [SegmentDecl],
    lines: Vec<CompiledLine>,
}

fn err(kind: CompileErrorKind, span: Span) -> CompileError {
    CompileError { kind, span }
}

fn seg_index(catalog: &[SegmentDecl], id: &str) -> Option<usize> {
    catalog.binary_search_by(|d| d.id.cmp(id)).ok()
}

/// Narrows a catalog position to the `u16` a node stores; no silent wrap.
fn index16(i: usize, sp: Span) -> Result<u16, CompileError> {
    u16::try_from(i).map_err(|_| err(CompileErrorKind::BadCatalog, sp))
}

/// Lookups are binary searches, so ids and field names must be strictly
/// ascending. The catalog is outside input (M3 installs declarations).
fn catalog_sorted(catalog: &[SegmentDecl]) -> bool {
    catalog.windows(2).all(|w| w[0].id < w[1].id)
        && catalog
            .iter()
            .all(|d| d.fields.windows(2).all(|w| w[0].name < w[1].name))
}

fn one_arg(args: &[String], sp: Span) -> Result<&str, CompileError> {
    match args {
        [a] => Ok(a),
        _ => Err(err(CompileErrorKind::BadHelperArg, sp)),
    }
}

fn style_spec(args: &[String], sp: Span) -> Result<StyleSpec, CompileError> {
    let mut s = StyleSpec::default();
    if args.is_empty() {
        return Err(err(CompileErrorKind::BadHelperArg, sp));
    }
    for a in args {
        let bit = match a.as_str() {
            "bold" => BOLD,
            "dim" => DIM,
            "italic" => ITALIC,
            "underline" => UNDERLINE,
            _ => 0,
        };
        if bit != 0 {
            if s.attrs & bit != 0 {
                return Err(err(CompileErrorKind::BadHelperArg, sp));
            }
            s.attrs |= bit;
            continue;
        }
        let (slot, name) = match a.split_once('=') {
            Some(("fg", n)) => (&mut s.fg, n),
            Some(("bg", n)) => (&mut s.bg, n),
            _ => return Err(err(CompileErrorKind::BadHelperArg, sp)),
        };
        let i = token_index(name).ok_or(err(CompileErrorKind::UnknownToken, sp))?;
        if slot.replace(i as u16).is_some() {
            return Err(err(CompileErrorKind::BadHelperArg, sp));
        }
    }
    Ok(s)
}

/// Appends `items` to the current line. Returns whether any segment or
/// field reference was emitted (for the group rule).
fn emit(cx: &mut Ctx<'_>, items: Vec<(Syntax, Span)>, depth: usize) -> Result<bool, CompileError> {
    let mut referenced = false;
    for (node, sp) in items {
        let n = match node {
            Syntax::Text(t) => Node::Text(t),
            Syntax::Segment { id, mode } => {
                let seg =
                    seg_index(cx.catalog, &id).ok_or(err(CompileErrorKind::UnknownSegment, sp))?;
                referenced = true;
                Node::Segment {
                    seg: index16(seg, sp)?,
                    mode,
                }
            }
            Syntax::Field { segment, field } => {
                let seg = seg_index(cx.catalog, &segment)
                    .ok_or(err(CompileErrorKind::UnknownSegment, sp))?;
                let f = cx.catalog[seg]
                    .field_index(&field)
                    .ok_or(err(CompileErrorKind::UnknownField, sp))?;
                referenced = true;
                Node::Field {
                    seg: index16(seg, sp)?,
                    field: index16(f, sp)?,
                }
            }
            Syntax::Group(body) => {
                let line = cx.lines.len() - 1;
                let at = cx.lines[line].nodes.len();
                push(cx, Node::Group { len: 0 }, sp);
                if !emit(cx, body, depth + 1)? {
                    return Err(err(CompileErrorKind::GroupWithoutReference, sp));
                }
                if cx.lines.len() - 1 != line {
                    return Err(err(CompileErrorKind::NewlineInBlock, sp));
                }
                push(cx, Node::GroupEnd, sp);
                let len = cx.lines[line].nodes.len() - at - 1;
                cx.lines[line].nodes[at] = Node::Group { len: len as u32 };
                referenced = true;
                continue;
            }
            Syntax::Style { args, body } => {
                let spec = style_spec(&args, sp)?;
                let line = cx.lines.len() - 1;
                push(cx, Node::Style(spec), sp);
                referenced |= emit(cx, body, depth + 1)?;
                if cx.lines.len() - 1 != line {
                    return Err(err(CompileErrorKind::NewlineInBlock, sp));
                }
                push(cx, Node::StyleEnd, sp);
                continue;
            }
            Syntax::Helper { name, args } => match name.as_str() {
                "sep" | "head" | "tail" => {
                    let shape = Shape::parse(one_arg(&args, sp)?)
                        .ok_or(err(CompileErrorKind::BadHelperArg, sp))?;
                    match name.as_str() {
                        "sep" => Node::Sep(shape),
                        "head" => Node::Head(shape),
                        _ => Node::Tail(shape),
                    }
                }
                "fill" => {
                    let kind = match args.as_slice() {
                        [] => FillKind::Space,
                        [a] if a == "space" => FillKind::Space,
                        [a] if a == "dot" => FillKind::Dot,
                        [a] if a == "line" => FillKind::Line,
                        _ => return Err(err(CompileErrorKind::BadHelperArg, sp)),
                    };
                    if depth > 0 {
                        return Err(err(CompileErrorKind::BadHelperArg, sp));
                    }
                    let line = cx.lines.len() - 1;
                    if cx.lines[line].fill.is_some() {
                        return Err(err(CompileErrorKind::TwoFills, sp));
                    }
                    cx.lines[line].fill = Some(cx.lines[line].nodes.len());
                    Node::Fill(kind)
                }
                "icon" => {
                    let name = one_arg(&args, sp)?;
                    let i = icons::ICONS
                        .binary_search_by(|ic| ic.name().cmp(name))
                        .map_err(|_| err(CompileErrorKind::UnknownIcon, sp))?;
                    Node::Icon(i as u16)
                }
                "nl" => {
                    if !args.is_empty() {
                        return Err(err(CompileErrorKind::BadHelperArg, sp));
                    }
                    if depth > 0 {
                        return Err(err(CompileErrorKind::NewlineInBlock, sp));
                    }
                    if cx.lines.len() == MAX_LINES {
                        return Err(err(CompileErrorKind::TooManyLines, sp));
                    }
                    cx.lines.push(CompiledLine::default());
                    continue;
                }
                _ => return Err(err(CompileErrorKind::UnknownHelper, sp)),
            },
        };
        push(cx, n, sp);
    }
    Ok(referenced)
}

fn push(cx: &mut Ctx<'_>, n: Node, sp: Span) {
    let line = cx.lines.last_mut().expect("at least one line");
    line.nodes.push(n);
    line.origin.push(sp);
}

/// Compiles `src` against the segment catalog (sorted by id), one
/// CompiledLine per template line.
pub fn compile(src: &str, catalog: &[SegmentDecl]) -> Result<Vec<CompiledLine>, CompileError> {
    if !catalog_sorted(catalog) {
        return Err(err(CompileErrorKind::BadCatalog, Span { start: 0, end: 0 }));
    }
    let tree = parse(src).map_err(|e| err(CompileErrorKind::Syntax(e.kind), e.span))?;
    let mut cx = Ctx {
        catalog,
        lines: alloc::vec![CompiledLine::default()],
    };
    emit(&mut cx, tree, 0)?;
    Ok(cx.lines)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::BUILTIN;
    use crate::template::syntax::MAX_TEMPLATE_BYTES;
    use CompileErrorKind::*;

    fn kind(src: &str) -> CompileErrorKind {
        compile(src, BUILTIN).unwrap_err().kind
    }

    // 이것을 실패시키는 것: 세그먼트·필드 색인, 도우미 노드, 채움 위치, 줄 나누기가 틀리는 것.
    #[test]
    fn compiles_a_two_line_template() {
        let lines = compile("{@head:round}{dir:block}{@sep:triangle}{git:block}{@tail:triangle}{@fill:line}{time}{@nl}{char}", BUILTIN).unwrap();
        assert_eq!(lines.len(), 2);
        let dir = BUILTIN.iter().position(|d| d.id == "dir").unwrap() as u16;
        assert_eq!(lines[0].nodes[0], Node::Head(Shape::Round));
        assert_eq!(
            lines[0].nodes[1],
            Node::Segment {
                seg: dir,
                mode: Mode::Block
            }
        );
        assert_eq!(lines[0].fill, Some(5));
        assert_eq!(lines[0].nodes[5], Node::Fill(FillKind::Line));
        assert_eq!(lines[0].origin.len(), lines[0].nodes.len());
        assert_eq!(lines[1].nodes.len(), 1);
    }

    // 이것을 실패시키는 것: 묶음 길이(len)가 GroupEnd까지를 세지 않는 것.
    #[test]
    fn group_len_and_style() {
        let lines = compile(
            "{@group}on {@style:fg=git.branch,bold}{git.branch}{@end}{@end}",
            BUILTIN,
        )
        .unwrap();
        let n = &lines[0].nodes;
        assert_eq!(n[0], Node::Group { len: 5 });
        assert_eq!(n[5], Node::GroupEnd);
        let Node::Style(s) = n[2] else { panic!() };
        assert_eq!((s.fg.is_some(), s.bg, s.attrs), (true, None, BOLD));
    }

    // 이것을 실패시키는 것: 닫힌 도우미 목록·인자·참조 검사 중 하나가 빠지는 것.
    #[test]
    fn errors() {
        assert_eq!(kind("{nope}"), UnknownSegment);
        assert_eq!(kind("{git.nope}"), UnknownField);
        assert_eq!(kind("{@sparkle}"), UnknownHelper);
        assert_eq!(kind("{@sep}"), BadHelperArg);
        assert_eq!(kind("{@sep:hexagon}"), BadHelperArg);
        assert_eq!(kind("{@fill}{@fill}"), TwoFills);
        assert_eq!(kind("{@group}{@fill}{dir}{@end}"), BadHelperArg);
        assert_eq!(kind("{@group}hi{@end}"), GroupWithoutReference);
        assert_eq!(kind("{@style:fg=nope}x{@end}"), UnknownToken);
        assert_eq!(kind("{@style:fg=path,fg=path}x{@end}"), BadHelperArg);
        assert_eq!(kind("{@style:blink}x{@end}"), BadHelperArg);
        assert_eq!(kind("{@icon:nope}"), UnknownIcon);
        assert_eq!(kind("a{@nl}b{@nl}c"), TooManyLines);
        assert_eq!(kind("{@group}{dir}{@nl}{@end}"), NewlineInBlock);
        assert_eq!(kind("{dir"), Syntax(SyntaxErrorKind::Unclosed));
    }

    // 이것을 실패시키는 것: 속성 중복 검사, 빈 style 인자 검사, `@nl` 오류 위치(depth 검사), style 안의 `@nl`·`@fill` 검사,
    // `@nl` 인자 검사 중 하나를 지우는 것.
    #[test]
    fn style_and_newline_edges() {
        assert_eq!(kind("{@style:bold,bold}{dir}{@end}"), BadHelperArg);
        assert_eq!(kind("{@style:bg=path,bg=path}{dir}{@end}"), BadHelperArg);
        assert_eq!(kind("{@style:fg=path,bold,bold}{dir}{@end}"), BadHelperArg);
        assert_eq!(kind("{@style:bold}{dir}{@nl}{@end}"), NewlineInBlock);
        assert_eq!(kind("{@style:bold}{@fill}{@end}"), BadHelperArg);
        assert_eq!(kind("{@nl:x}"), BadHelperArg);
        assert_eq!(kind("{@style}{dir}{@end}"), BadHelperArg);
        // The error points at the `{@nl}` itself, not at the enclosing block.
        let e = compile("{@group}{dir}{@nl}{@end}", BUILTIN).unwrap_err();
        assert_eq!((e.span.start, e.span.end), (13, 18));
        assert_eq!(kind("{@end}"), Syntax(SyntaxErrorKind::StrayEnd));
        let ok = compile(
            "{@style:fg=path,bg=path,bold,dim,italic,underline}{dir}{@end}",
            BUILTIN,
        )
        .unwrap();
        let Node::Style(s) = ok[0].nodes[0] else {
            panic!()
        };
        assert_eq!(s.attrs, BOLD | DIM | ITALIC | UNDERLINE);
    }

    // 이것을 실패시키는 것: `origin`을 `nodes`와 어긋나게 쌓는 것(Group·Style 시작·끝 표식 포함).
    #[test]
    fn origin_is_parallel_and_points_at_source() {
        let src = "ab{@group}{dir}{@end}";
        let line = &compile(src, BUILTIN).unwrap()[0];
        assert_eq!(line.nodes().len(), line.origin().len());
        assert_eq!((line.origin()[0].start, line.origin()[0].end), (0, 2));
        // Group, its body and GroupEnd all carry the block's whole span.
        assert_eq!((line.origin()[1].start, line.origin()[1].end), (2, 21));
        assert_eq!(line.fill(), None);
    }

    // Worst-case inputs compile or fail cleanly (nesting is capped by the parser).
    // 이것을 실패시키는 것: 재귀 깊이나 크기에 상한이 없어 스택·메모리를 쓰는 것.
    #[test]
    fn hostile_input_stays_bounded() {
        let deep = "{@group}".repeat(8) + "{dir}" + &"{@end}".repeat(8);
        assert!(compile(&deep, BUILTIN).is_ok());
        let deeper = "{@style:bold}".repeat(9) + "{dir}" + &"{@end}".repeat(9);
        assert_eq!(kind(&deeper), Syntax(SyntaxErrorKind::TooDeep));
        let wide = "{dir}".repeat(MAX_TEMPLATE_BYTES / 5);
        assert!(compile(&wide, BUILTIN).is_ok());
        assert_eq!(
            kind(&"x".repeat(MAX_TEMPLATE_BYTES + 1)),
            Syntax(SyntaxErrorKind::TooLong)
        );
    }

    // 이것을 실패시키는 것: 인덱스를 `as u16`으로 자르는 것(65536이 0이 됨).
    #[test]
    fn index16_stops_at_the_u16_edge() {
        let sp = Span { start: 0, end: 0 };
        assert_eq!(index16(65535, sp), Ok(65535));
        assert_eq!(index16(65536, sp).unwrap_err().kind, BadCatalog);
    }

    // 이것을 실패시키는 것: compile 진입의 카탈로그 정렬 검사(필드 순서·id 순서·중복 id).
    #[test]
    fn unsorted_catalog_is_an_error_not_a_wrong_lookup() {
        use crate::field::{FieldDecl, FieldType, SegmentDecl};
        const ZA: &[FieldDecl] = &[
            FieldDecl {
                name: "z",
                ty: FieldType::Bool,
            },
            FieldDecl {
                name: "a",
                ty: FieldType::Bool,
            },
        ];
        const AZ: &[FieldDecl] = &[
            FieldDecl {
                name: "a",
                ty: FieldType::Bool,
            },
            FieldDecl {
                name: "z",
                ty: FieldType::Bool,
            },
        ];
        let d = |id, fields| SegmentDecl {
            id,
            role: "path",
            fields,
        };
        let bad_fields = [d("x", ZA)];
        assert_eq!(compile("{x.a}", &bad_fields).unwrap_err().kind, BadCatalog);
        let bad_ids = [d("y", AZ), d("x", AZ)];
        assert_eq!(compile("{x.a}", &bad_ids).unwrap_err().kind, BadCatalog);
        let dup_ids = [d("x", AZ), d("x", AZ)];
        assert_eq!(compile("{x.a}", &dup_ids).unwrap_err().kind, BadCatalog);
        let good = [d("x", AZ), d("y", AZ)];
        assert!(compile("{y.z}", &good).is_ok());
    }
}
