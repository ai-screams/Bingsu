//! The three style levels: the preset is the base, option keys sit on top, and
//! a template replaces both (`config check` reports the ignored levels from
//! M3). Presets and options only produce template text: the renderer knows
//! templates alone.
//!
//! A run of blocks (one side of a line) has an outer end at the screen edge,
//! joints between its blocks and an inner end facing the middle; the right
//! side mirrors the left. `style.outer_end`, `style.separator` and
//! `style.inner_end` choose the three, `style.gap` a blank cell between
//! blocks that have ends of their own.
use crate::ident::{IdError, parse_segment_id};
use crate::template::compile::{FillKind, Shape};
use crate::template::syntax::MAX_TEMPLATE_BYTES;
use alloc::string::String;
use alloc::vec::Vec;

/// How a segment's text is drawn.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Body {
    /// On a colored block (`{id:block}`), with the end shapes.
    Block,
    /// Plain text without a background; no end shapes.
    Plain,
    /// Plain text inside a literal `[` and `]` (preset `bracket`): one
    /// ASCII cell each, so every icon set draws it the same. Both sides of
    /// the fill draw them, whatever the end keys say.
    Bracket,
}

/// The shape at one end of a block: `{@head:…}` before it, `{@tail:…}`
/// after it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cap {
    None,
    Shape(Shape),
}

/// How neighboring blocks meet ("가운데 이음").
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Joining {
    /// A separator glyph between blocks.
    Attached,
    /// Blocks touch with no glyph.
    Adjacent,
    /// Every block has its own outer and inner end; `gap` puts one blank
    /// cell between them.
    Capped,
}

/// Option keys (option combination). `None` = not set at this
/// level. The keys are `style.outer_end`, `style.inner_end`,
/// `style.separator` (which sets `separator` and `joining`), `style.gap`,
/// `layout.fill` and `layout.frame`; `body` comes from the preset alone.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct StyleOptions {
    pub body: Option<Body>,
    pub separator: Option<Shape>,
    /// The end at the screen edge: the left end of a left run, the right
    /// end of a right run.
    pub outer_end: Option<Cap>,
    /// The end facing the middle of the line (the fill, the input).
    pub inner_end: Option<Cap>,
    pub joining: Option<Joining>,
    pub gap: Option<bool>,
    pub fill: Option<FillKind>,
    pub frame: Option<bool>,
}

impl StyleOptions {
    /// `self` on top of `base`, key by key.
    pub fn over(self, base: Self) -> Self {
        Self {
            body: self.body.or(base.body),
            separator: self.separator.or(base.separator),
            outer_end: self.outer_end.or(base.outer_end),
            inner_end: self.inner_end.or(base.inner_end),
            joining: self.joining.or(base.joining),
            gap: self.gap.or(base.gap),
            fill: self.fill.or(base.fill),
            frame: self.frame.or(base.frame),
        }
    }
    fn is_empty(&self) -> bool {
        *self == Self::default()
    }
}

#[derive(Debug)]
pub struct Preset {
    pub name: &'static str,
    /// Every key set.
    pub options: StyleOptions,
}

/// A preset's options; no built-in preset turns the gap on.
const fn options(
    body: Body,
    separator: Shape,
    outer_end: Cap,
    inner_end: Cap,
    joining: Joining,
) -> StyleOptions {
    StyleOptions {
        body: Some(body),
        separator: Some(separator),
        outer_end: Some(outer_end),
        inner_end: Some(inner_end),
        joining: Some(joining),
        gap: Some(false),
        fill: Some(FillKind::Space),
        frame: Some(false),
    }
}

const fn preset_of(name: &'static str, options: StyleOptions) -> Preset {
    Preset { name, options }
}

/// The eight first-release presets (the style playground's seven, then `capsule`):
/// each is a combination of the option keys, no renderer code of its own.
/// None puts a blank cell between blocks (`gap`): `pill` and `diamond`
/// repeat their ends on every block, the blocks touching, `block` draws
/// touching blocks without ends, `bracket` touching `[…]`. A separator shape
/// under `Adjacent` or `Capped` is not drawn.
pub const PRESETS: &[Preset] = &[
    preset_of(
        "lean",
        options(
            Body::Plain,
            Shape::Flat,
            Cap::None,
            Cap::None,
            Joining::Attached,
        ),
    ),
    preset_of(
        "triangle",
        options(
            Body::Block,
            Shape::Triangle,
            Cap::None,
            Cap::Shape(Shape::Triangle),
            Joining::Attached,
        ),
    ),
    preset_of(
        "pill",
        options(
            Body::Block,
            Shape::Round,
            Cap::Shape(Shape::Round),
            Cap::Shape(Shape::Round),
            Joining::Capped,
        ),
    ),
    preset_of(
        "capsule",
        options(
            Body::Block,
            Shape::Triangle,
            Cap::Shape(Shape::Round),
            Cap::Shape(Shape::Round),
            Joining::Attached,
        ),
    ),
    preset_of(
        "slant",
        options(
            Body::Block,
            Shape::Slant,
            Cap::None,
            Cap::Shape(Shape::Slant),
            Joining::Attached,
        ),
    ),
    preset_of(
        "diamond",
        options(
            Body::Block,
            Shape::Triangle,
            Cap::Shape(Shape::Triangle),
            Cap::Shape(Shape::Triangle),
            Joining::Capped,
        ),
    ),
    preset_of(
        "block",
        options(
            Body::Block,
            Shape::Flat,
            Cap::None,
            Cap::None,
            Joining::Adjacent,
        ),
    ),
    preset_of(
        "bracket",
        options(
            Body::Bracket,
            Shape::Flat,
            Cap::None,
            Cap::None,
            Joining::Capped,
        ),
    ),
];

pub fn preset(name: &str) -> Option<&'static Preset> {
    PRESETS.iter().find(|p| p.name == name)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StyleError {
    /// The generated template is longer than `MAX_TEMPLATE_BYTES`.
    TooLong,
    /// A layout entry is not a segment id (`crate::ident`): checked before
    /// it is joined into template text, where `}` or `{@` would be syntax.
    SegmentId {
        /// Zero-based line number.
        line: usize,
        /// Zero-based index across the left side followed by the right side.
        index: usize,
        error: IdError,
    },
}

/// One line of `[layout.lineN]`: segment ids left and right.
#[derive(Clone, Copy, Debug)]
pub struct LineLayout<'a> {
    pub left: &'a [&'a str],
    pub right: &'a [&'a str],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StyleNotice {
    /// A template is set, so the preset (and the options, when `options`
    /// is true) are not used.
    TemplateReplaces { options: bool },
}

fn shape_name(s: Shape) -> &'static str {
    match s {
        Shape::Triangle => "triangle",
        Shape::Round => "round",
        Shape::Slant => "slant",
        Shape::Flat => "flat",
    }
}

fn fill_name(f: FillKind) -> &'static str {
    match f {
        FillKind::Space => "space",
        FillKind::Dot => "dot",
        FillKind::Line => "line",
    }
}

fn cap(out: &mut String, which: &str, c: Cap) {
    if let Cap::Shape(s) = c {
        out.push_str("{@");
        out.push_str(which);
        out.push(':');
        out.push_str(shape_name(s));
        out.push('}');
    }
}

/// One side of a line (a run of blocks). The right side mirrors the left:
/// its inner end comes first (as `{@head:…}`) and its outer end, at the
/// screen edge, last (as `{@tail:…}`).
fn run(out: &mut String, ids: &[&str], o: &StyleOptions, right: bool) {
    let body = o.body.unwrap_or(Body::Plain);
    let block = body == Body::Block;
    let (outer, inner) = (
        o.outer_end.unwrap_or(Cap::None),
        o.inner_end.unwrap_or(Cap::None),
    );
    let (head, tail) = if right {
        (inner, outer)
    } else {
        (outer, inner)
    };
    let joining = o.joining.unwrap_or(Joining::Capped);
    let gap = o.gap == Some(true);
    let capped = joining == Joining::Capped;
    // Blocks with ends of their own: each block, its ends and its gap go in
    // one group, so a segment without a value takes them along. A gap sits
    // on the side away from the screen edge (after a left block, before a
    // right one): when the last segment of a run is empty, a stray space
    // then lands next to the fill, not on the last cell.
    let grouped = block && capped && ids.len() > 1;
    let spaced = grouped && gap;
    for (i, id) in ids.iter().enumerate() {
        let first = i == 0;
        let last = i + 1 == ids.len();
        if !first {
            match (block, joining) {
                (true, Joining::Attached) => {
                    out.push_str("{@sep:");
                    out.push_str(shape_name(o.separator.unwrap_or(Shape::Flat)));
                    out.push('}');
                }
                // Touching blocks, or a gap that rides in the group below.
                (true, Joining::Adjacent | Joining::Capped) => {}
                // Without a background a glyph separator is one blank cell,
                // and touching segments get one only with a gap.
                (false, Joining::Attached) => out.push_str("{@sep:flat}"),
                (false, Joining::Adjacent | Joining::Capped) => {
                    if gap {
                        out.push_str("{@sep:flat}");
                    }
                }
            }
        }
        if grouped {
            out.push_str("{@group}");
            if spaced && right && !first {
                out.push(' ');
            }
        }
        if block && (first || capped) {
            cap(out, "head", head);
        }
        // A group drops the brackets with a segment that has no value. The
        // input marker `char` stays bare: it is not a fact about the shell.
        let bracket = body == Body::Bracket && *id != "char";
        if bracket {
            out.push_str("{@group}[");
        }
        out.push('{');
        out.push_str(id);
        if block {
            out.push_str(":block");
        }
        out.push('}');
        if bracket {
            out.push_str("]{@end}");
        }
        if block && (last || capped) {
            cap(out, "tail", tail);
        }
        if grouped {
            if spaced && !right && !last {
                out.push(' ');
            }
            out.push_str("{@end}");
        }
    }
}

/// Template text from preset and options for `lines`.
pub fn generate(
    preset: &Preset,
    options: &StyleOptions,
    lines: &[LineLayout<'_>],
) -> Result<String, StyleError> {
    for (n, line) in lines.iter().enumerate() {
        for (index, id) in line.left.iter().chain(line.right).enumerate() {
            if let Err(error) = parse_segment_id(id) {
                return Err(StyleError::SegmentId {
                    line: n,
                    index,
                    error,
                });
            }
        }
    }
    let o = options.over(preset.options);
    let mut out = String::new();
    for (n, line) in lines.iter().enumerate() {
        if n > 0 {
            out.push_str("{@nl}");
        }
        if o.frame == Some(true) && lines.len() > 1 {
            out.push_str(if n == 0 {
                "{@icon:frame.top}"
            } else {
                "{@icon:frame.bottom}"
            });
        }
        run(&mut out, line.left, &o, false);
        if !line.right.is_empty() {
            out.push_str("{@fill:");
            out.push_str(fill_name(o.fill.unwrap_or(FillKind::Space)));
            out.push('}');
            run(&mut out, line.right, &o, true);
        }
    }
    // The compiler refuses longer sources; fail here with a clear cause.
    if out.len() > MAX_TEMPLATE_BYTES {
        return Err(StyleError::TooLong);
    }
    Ok(out)
}

/// The template the renderer uses, and notices for `config check`.
pub fn resolve(
    preset: &Preset,
    options: &StyleOptions,
    template: Option<&str>,
    lines: &[LineLayout<'_>],
) -> Result<(String, Vec<StyleNotice>), StyleError> {
    match template {
        Some(t) => Ok((
            t.into(),
            alloc::vec![StyleNotice::TemplateReplaces {
                options: !options.is_empty()
            }],
        )),
        None => Ok((generate(preset, options, lines)?, Vec::new())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::BUILTIN;
    use crate::template::compile::compile;

    const TWO: [LineLayout<'static>; 2] = [
        LineLayout {
            left: &["dir", "git"],
            right: &["status", "time"],
        },
        LineLayout {
            left: &["char"],
            right: &[],
        },
    ];

    // 이것을 실패시키는 것: 레이아웃 id를 검증하지 않고 템플릿 글에 잇는 것(`}`·`{@`가 구문이 됨),
    // 또는 둘째 줄·양쪽 배열을 빠뜨리거나 오류 위치를 잘못 보고하는 것.
    #[test]
    fn layout_ids_are_checked_before_they_join_the_template() {
        let left = LineLayout {
            left: &["time}{@nl"],
            right: &[],
        };
        let right = LineLayout {
            left: &["dir"],
            right: &["time}{@nl"],
        };
        for (line, index, bad) in [
            (0, 0, [left, TWO[1]]),
            (0, 1, [right, TWO[1]]),
            (1, 0, [TWO[0], left]),
            (1, 1, [TWO[0], right]),
        ] {
            for p in PRESETS {
                let e = generate(p, &StyleOptions::default(), &bad).unwrap_err();
                assert_eq!(
                    e,
                    StyleError::SegmentId {
                        line,
                        index,
                        error: crate::ident::IdError::BadByte { at: 4 },
                    }
                );
            }
        }
    }

    // 이것을 실패시키는 것: 프리셋이 만든 템플릿이 바뀌는 것(머리·꼬리·구분자·채움 자리).
    #[test]
    fn presets_generate_templates() {
        let tri = generate(preset("triangle").unwrap(), &StyleOptions::default(), &TWO).unwrap();
        assert_eq!(
            tri,
            "{dir:block}{@sep:triangle}{git:block}{@tail:triangle}{@fill:space}{@head:triangle}{status:block}{@sep:triangle}{time:block}{@nl}{char:block}{@tail:triangle}"
        );
        let lean = generate(preset("lean").unwrap(), &StyleOptions::default(), &TWO).unwrap();
        assert_eq!(
            lean,
            "{dir}{@sep:flat}{git}{@fill:space}{status}{@sep:flat}{time}{@nl}{char}"
        );
        for t in [tri, lean] {
            assert!(compile(&t, BUILTIN).is_ok(), "{t}");
        }
    }

    // No preset has a gap: `pill` and `diamond` repeat their ends on every block and the blocks
    // touch, `block` draws touching blocks without ends, `bracket` touching `[…]`.
    // 이것을 실패시키는 것: 새 프리셋 다섯과 `capsule`의 끝·구분자·이음이 바뀌는 것(`capsule`이 `Capped`로 가거나
    // 바깥 끝이 `None`이 되는 것, 오른쪽 둘째 블록 앞뒤 포함), `bracket`이 `char`를 감싸거나
    // 괄호를 그룹 밖에 두는 것(값 없는 세그먼트에 `[]`가 남음), 프리셋 이름 목록(`config` 키 enum)과 표가 갈라지는 것,
    // 네 프리셋 하나를 빈칸 모양으로 되돌리는 것, `block`에 끝칸을 남기는 것.
    #[test]
    fn first_release_presets() {
        let g = |n| generate(preset(n).unwrap(), &StyleOptions::default(), &TWO).unwrap();
        assert_eq!(
            g("pill"),
            "{@group}{@head:round}{dir:block}{@tail:round}{@end}{@group}{@head:round}{git:block}{@tail:round}{@end}{@fill:space}{@group}{@head:round}{status:block}{@tail:round}{@end}{@group}{@head:round}{time:block}{@tail:round}{@end}{@nl}{@head:round}{char:block}{@tail:round}"
        );
        assert_eq!(
            g("slant"),
            "{dir:block}{@sep:slant}{git:block}{@tail:slant}{@fill:space}{@head:slant}{status:block}{@sep:slant}{time:block}{@nl}{char:block}{@tail:slant}"
        );
        // `capsule`: TWO has two blocks on each side. Round caps sit only on the outer ends of a side
        // (head before the first block, tail after the last); between blocks the triangle separator.
        assert_eq!(
            g("capsule"),
            "{@head:round}{dir:block}{@sep:triangle}{git:block}{@tail:round}{@fill:space}{@head:round}{status:block}{@sep:triangle}{time:block}{@tail:round}{@nl}{@head:round}{char:block}{@tail:round}"
        );
        assert_eq!(g("diamond"), g("pill").replace("round", "triangle"));
        assert_eq!(
            g("block"),
            "{dir:block}{git:block}{@fill:space}{status:block}{time:block}{@nl}{char:block}"
        );
        assert_eq!(
            g("bracket"),
            "{@group}[{dir}]{@end}{@group}[{git}]{@end}{@fill:space}{@group}[{status}]{@end}{@group}[{time}]{@end}{@nl}{char}"
        );
        let names: Vec<&str> = PRESETS.iter().map(|p| p.name).collect();
        assert_eq!(
            names,
            [
                "lean", "triangle", "pill", "capsule", "slant", "diamond", "block", "bracket"
            ]
        );
        for n in names {
            assert!(compile(&g(n), BUILTIN).is_ok(), "{n}");
        }
    }

    // A gap between blocks with ends of their own is an option: the four presets draw their gapped
    // shapes with `gap = true` (and `block` with flat ends and `caps`). The gap rides in each
    // block's group, after a left block and before a right one.
    // 이것을 실패시키는 것: `Capped` + 빈칸의 빈칸을 그룹 밖으로 옮기는 것, 오른쪽 줄에서 빈칸을 블록 뒤에 두는 것,
    // 배경 없는 몸체의 빈칸을 빼는 것.
    #[test]
    fn gapped_shapes_come_from_the_options() {
        let g = |n, o: StyleOptions| generate(preset(n).unwrap(), &o, &TWO).unwrap();
        let gap = StyleOptions {
            gap: Some(true),
            ..StyleOptions::default()
        };
        let pill = "{@group}{@head:round}{dir:block}{@tail:round} {@end}{@group}{@head:round}{git:block}{@tail:round}{@end}{@fill:space}{@group}{@head:round}{status:block}{@tail:round}{@end}{@group} {@head:round}{time:block}{@tail:round}{@end}{@nl}{@head:round}{char:block}{@tail:round}";
        assert_eq!(g("pill", gap), pill);
        assert_eq!(g("diamond", gap), pill.replace("round", "triangle"));
        let flat = Some(Cap::Shape(Shape::Flat));
        let block = StyleOptions {
            outer_end: flat,
            inner_end: flat,
            joining: Some(Joining::Capped),
            ..gap
        };
        assert_eq!(g("block", block), pill.replace("round", "flat"));
        assert_eq!(
            g("bracket", gap),
            "{@group}[{dir}]{@end}{@sep:flat}{@group}[{git}]{@end}{@fill:space}{@group}[{status}]{@end}{@sep:flat}{@group}[{time}]{@end}{@nl}{char}"
        );
    }

    // 이것을 실패시키는 것: 옵션이 프리셋 위에 얹히지 않거나(키별), 템플릿이 있는데 프리셋·옵션을 쓰는 것.
    #[test]
    fn priority_rule() {
        let o = StyleOptions {
            separator: Some(Shape::Round),
            frame: Some(true),
            ..StyleOptions::default()
        };
        let (t, n) = resolve(preset("triangle").unwrap(), &o, None, &TWO).unwrap();
        assert!(t.starts_with("{@icon:frame.top}{dir:block}{@sep:round}"));
        assert!(t.contains("{@nl}{@icon:frame.bottom}{char:block}"));
        assert!(n.is_empty());
        let (t, n) = resolve(preset("triangle").unwrap(), &o, Some("{dir}"), &TWO).unwrap();
        assert_eq!(
            (t.as_str(), n.as_slice()),
            (
                "{dir}",
                &[StyleNotice::TemplateReplaces { options: true }][..]
            )
        );
        let (_, n) = resolve(
            preset("lean").unwrap(),
            &StyleOptions::default(),
            Some("{dir}"),
            &TWO,
        )
        .unwrap();
        assert_eq!(n, [StyleNotice::TemplateReplaces { options: false }]);
    }

    // 이것을 실패시키는 것: Capped에서 블록마다 끝을 두지 않는 것, 빈칸을 세그먼트 그룹 밖에 두는 것.
    #[test]
    fn capped_blocks_get_ends_and_the_gap() {
        let o = StyleOptions {
            body: Some(Body::Block),
            joining: Some(Joining::Capped),
            gap: Some(true),
            outer_end: Some(Cap::Shape(Shape::Round)),
            inner_end: Some(Cap::Shape(Shape::Round)),
            ..StyleOptions::default()
        };
        let t = generate(
            preset("lean").unwrap(),
            &o,
            &[LineLayout {
                left: &["dir", "git"],
                right: &[],
            }],
        )
        .unwrap();
        assert_eq!(
            t,
            "{@group}{@head:round}{dir:block}{@tail:round} {@end}{@group}{@head:round}{git:block}{@tail:round}{@end}"
        );
    }

    // 이것을 실패시키는 것: Adjacent에서 구분자·공백을 넣는 것, 블록 아닌 Attached에서 공백을 빼는 것,
    // 단일 줄에 테두리를 붙이는 것, 채움 옵션을 무시하는 것, `over`가 키별로 합치지 않는 것.
    #[test]
    fn joining_frame_fill_and_over() {
        let one = [LineLayout {
            left: &["dir", "git"],
            right: &["time"],
        }];
        let adj = StyleOptions {
            joining: Some(Joining::Adjacent),
            body: Some(Body::Block),
            ..StyleOptions::default()
        };
        assert_eq!(
            generate(preset("lean").unwrap(), &adj, &one).unwrap(),
            "{dir:block}{git:block}{@fill:space}{time:block}"
        );
        let plain = StyleOptions {
            joining: Some(Joining::Attached),
            fill: Some(FillKind::Dot),
            frame: Some(true),
            ..StyleOptions::default()
        };
        assert_eq!(
            generate(preset("lean").unwrap(), &plain, &one).unwrap(),
            "{dir}{@sep:flat}{git}{@fill:dot}{time}"
        );
        let base = StyleOptions {
            frame: Some(true),
            fill: Some(FillKind::Line),
            ..StyleOptions::default()
        };
        let top = StyleOptions {
            separator: Some(Shape::Round),
            ..StyleOptions::default()
        };
        let m = top.over(base);
        assert_eq!(
            (m.separator, m.fill, m.frame),
            (Some(Shape::Round), Some(FillKind::Line), Some(true))
        );
        // Every field, each from the side that sets it.
        let all = preset("pill").unwrap().options;
        assert_eq!(StyleOptions::default().over(all), all);
        assert_eq!(all.over(StyleOptions::default()), all);
        let lean = preset("lean").unwrap().options;
        assert_eq!(all.over(lean), all);
        assert_eq!(lean.over(all), lean);
    }

    // The generated text must stay within the compiler's source cap. With the
    // lean preset a left run costs 16 bytes per `dir` (5 + a flat separator)
    // and 17 per `time`, minus eleven for the last separator.
    // 이것을 실패시키는 것: `>`를 `>=`로 바꾸는 것(정확히 4096바이트가 거부됨), 상한을 하나 늘리거나
    // 검사를 빼는 것(4097바이트가 통과함), `resolve`가 오류를 삼키는 것.
    #[test]
    fn generated_template_respects_the_source_cap() {
        let lean = preset("lean").unwrap();
        let none = StyleOptions::default();
        let fit = |ids: &[&str]| {
            let line = [LineLayout {
                left: ids,
                right: &[],
            }];
            generate(lean, &none, &line)
        };
        let mut exact: Vec<&str> = alloc::vec!["dir"; 245];
        exact.extend(["time"; 11]);
        let t = fit(&exact).unwrap();
        assert_eq!(t.len(), MAX_TEMPLATE_BYTES);
        assert!(compile(&t, BUILTIN).is_ok());
        let t = fit(&alloc::vec!["dir"; 256]).unwrap();
        assert_eq!(t.len(), MAX_TEMPLATE_BYTES - 11);
        assert!(compile(&t, BUILTIN).is_ok());
        let mut over = exact.clone();
        over[0] = "time";
        assert_eq!(fit(&over), Err(StyleError::TooLong));
        let line = [LineLayout {
            left: &over,
            right: &[],
        }];
        assert_eq!(resolve(lean, &none, None, &line), Err(StyleError::TooLong));
        // A user template is passed through; the compiler enforces its own cap.
        assert!(resolve(lean, &none, Some("{dir}"), &line).is_ok());
    }

    /// The default layout's lines (`default_theme::LINES`).
    const EIGHT: [LineLayout<'static>; 2] = [
        LineLayout {
            left: &["host", "dir", "git"],
            right: &["status", "duration", "jobs", "venv", "time"],
        },
        LineLayout {
            left: &["char"],
            right: &[],
        },
    ];

    // Templates of approved shapes (the four presets without gaps, and three mixes of
    // outer end, joint and inner end), copied from the setup wizard's captures.
    const NEW_PILL: &str = "{@group}{@head:round}{host:block}{@tail:round}{@end}{@group}{@head:round}{dir:block}{@tail:round}{@end}{@group}{@head:round}{git:block}{@tail:round}{@end}{@fill:space}{@group}{@head:round}{status:block}{@tail:round}{@end}{@group}{@head:round}{duration:block}{@tail:round}{@end}{@group}{@head:round}{jobs:block}{@tail:round}{@end}{@group}{@head:round}{venv:block}{@tail:round}{@end}{@group}{@head:round}{time:block}{@tail:round}{@end}{@nl}{@head:round}{char:block}{@tail:round}";
    const NEW_DIAMOND: &str = "{@group}{@head:triangle}{host:block}{@tail:triangle}{@end}{@group}{@head:triangle}{dir:block}{@tail:triangle}{@end}{@group}{@head:triangle}{git:block}{@tail:triangle}{@end}{@fill:space}{@group}{@head:triangle}{status:block}{@tail:triangle}{@end}{@group}{@head:triangle}{duration:block}{@tail:triangle}{@end}{@group}{@head:triangle}{jobs:block}{@tail:triangle}{@end}{@group}{@head:triangle}{venv:block}{@tail:triangle}{@end}{@group}{@head:triangle}{time:block}{@tail:triangle}{@end}{@nl}{@head:triangle}{char:block}{@tail:triangle}";
    const NEW_BLOCK: &str = "{host:block}{dir:block}{git:block}{@fill:space}{status:block}{duration:block}{jobs:block}{venv:block}{time:block}{@nl}{char:block}";
    const NEW_BRACKET: &str = "{@group}[{host}]{@end}{@group}[{dir}]{@end}{@group}[{git}]{@end}{@fill:space}{@group}[{status}]{@end}{@group}[{duration}]{@end}{@group}[{jobs}]{@end}{@group}[{venv}]{@end}{@group}[{time}]{@end}{@nl}{char}";
    const ROUND_SLANT_TRIANGLE: &str = "{@head:round}{host:block}{@sep:slant}{dir:block}{@sep:slant}{git:block}{@tail:triangle}{@fill:space}{@head:triangle}{status:block}{@sep:slant}{duration:block}{@sep:slant}{jobs:block}{@sep:slant}{venv:block}{@sep:slant}{time:block}{@tail:round}{@nl}{@head:round}{char:block}{@tail:triangle}";
    const SLANT_ROUND_SLANT: &str = "{@head:slant}{host:block}{@sep:round}{dir:block}{@sep:round}{git:block}{@tail:slant}{@fill:space}{@head:slant}{status:block}{@sep:round}{duration:block}{@sep:round}{jobs:block}{@sep:round}{venv:block}{@sep:round}{time:block}{@tail:slant}{@nl}{@head:slant}{char:block}{@tail:slant}";
    const FLAT_NONE_TRIANGLE: &str = "{@head:flat}{host:block}{dir:block}{git:block}{@tail:triangle}{@fill:space}{@head:triangle}{status:block}{duration:block}{jobs:block}{venv:block}{time:block}{@tail:flat}{@nl}{@head:flat}{char:block}{@tail:triangle}";

    fn end(s: Shape) -> Option<Cap> {
        Some(Cap::Shape(s))
    }

    /// What `style.separator = "<shape>"` sets.
    fn joint(s: Shape) -> StyleOptions {
        StyleOptions {
            separator: Some(s),
            joining: Some(Joining::Attached),
            ..StyleOptions::default()
        }
    }

    // The approved shapes: the four presets as they are, and three mixes of outer end, joint and
    // inner end from the option keys laid over a preset.
    // 이것을 실패시키는 것: 네 프리셋 하나를 빈칸 모양으로 되돌리는 것, Capped의 블록마다 그룹을 빼는 것(pill·diamond),
    // 오른쪽 줄에서 바깥 끝과 안쪽 끝을 바꿔 쓰지 않는 것(둥글게·사선·삼각형), 끝 `flat`을 그리지 않는 것.
    #[test]
    fn approved_shapes_come_from_presets_and_option_keys() {
        let g = |p: &str, o: StyleOptions| generate(preset(p).unwrap(), &o, &EIGHT).unwrap();
        let none = StyleOptions::default();
        assert_eq!(g("pill", none), NEW_PILL);
        assert_eq!(g("diamond", none), NEW_DIAMOND);
        assert_eq!(g("block", none), NEW_BLOCK);
        assert_eq!(g("bracket", none), NEW_BRACKET);
        let mix = |outer, sep: StyleOptions, inner| StyleOptions {
            outer_end: outer,
            inner_end: inner,
            ..sep
        };
        let round = end(Shape::Round);
        let slant = end(Shape::Slant);
        let triangle = end(Shape::Triangle);
        assert_eq!(
            g("triangle", mix(round, joint(Shape::Slant), triangle)),
            ROUND_SLANT_TRIANGLE
        );
        assert_eq!(
            g("triangle", mix(slant, joint(Shape::Round), slant)),
            SLANT_ROUND_SLANT
        );
        let adjacent = StyleOptions {
            joining: Some(Joining::Adjacent),
            ..StyleOptions::default()
        };
        assert_eq!(
            g("triangle", mix(end(Shape::Flat), adjacent, triangle)),
            FLAT_NONE_TRIANGLE
        );
        for t in [NEW_PILL, NEW_DIAMOND, NEW_BLOCK, NEW_BRACKET] {
            assert!(compile(t, BUILTIN).is_ok(), "{t}");
        }
    }

    // On blocks a gap goes only between blocks with ends of their own (`caps`): with a
    // separator glyph or `none` it changes nothing. Without a background it is the one
    // blank cell between touching segments.
    // 이것을 실패시키는 것: `Adjacent`(`none`)에도 빈칸을 넣는 것(블록 몸체에서 템플릿이 달라짐), 글리프
    // 구분자에 빈칸을 더하는 것, 배경 없는 몸체에서 `none`·`caps`의 빈칸을 빼는 것.
    #[test]
    fn a_gap_needs_blocks_with_ends_of_their_own() {
        let ends = [
            (Cap::None, Cap::None),
            (Cap::Shape(Shape::Round), Cap::Shape(Shape::Round)),
            (Cap::Shape(Shape::Flat), Cap::Shape(Shape::Triangle)),
        ];
        let joinings = [Joining::Adjacent, Joining::Attached];
        for p in PRESETS
            .iter()
            .filter(|p| p.options.body == Some(Body::Block))
        {
            for (outer, inner) in ends {
                for joining in joinings {
                    let o = |gap| StyleOptions {
                        outer_end: Some(outer),
                        inner_end: Some(inner),
                        joining: Some(joining),
                        gap: Some(gap),
                        ..StyleOptions::default()
                    };
                    assert_eq!(
                        generate(p, &o(true), &EIGHT),
                        generate(p, &o(false), &EIGHT),
                        "{} {outer:?} {joining:?} {inner:?}",
                        p.name
                    );
                }
            }
        }
        let lean = preset("lean").unwrap();
        let o = |joining, gap| StyleOptions {
            joining: Some(joining),
            gap: Some(gap),
            ..StyleOptions::default()
        };
        let one = [LineLayout {
            left: &["dir", "git"],
            right: &[],
        }];
        let g = |o: StyleOptions| generate(lean, &o, &one).unwrap();
        for joining in [Joining::Adjacent, Joining::Capped] {
            assert_eq!(g(o(joining, false)), "{dir}{git}");
            assert_eq!(g(o(joining, true)), "{dir}{@sep:flat}{git}");
        }
        assert_eq!(g(o(Joining::Attached, false)), "{dir}{@sep:flat}{git}");
        assert_eq!(g(o(Joining::Attached, true)), "{dir}{@sep:flat}{git}");
    }

    // Brackets belong to the body: both sides of the fill keep them, and end keys change
    // nothing on them.
    // 이것을 실패시키는 것: 괄호를 거울로 바꾼 끝(왼쪽 줄은 바깥 끝, 오른쪽 줄은 안쪽 끝)에서 다시 정하는 것
    // (한쪽 끝만 바꾸면 한쪽 줄에서 괄호가 사라짐).
    #[test]
    fn end_keys_leave_both_sides_of_bracket_bracketed() {
        let b = preset("bracket").unwrap();
        let base = generate(b, &StyleOptions::default(), &TWO).unwrap();
        let round = end(Shape::Round);
        for (outer_end, inner_end) in [(round, None), (None, round), (round, round)] {
            let o = StyleOptions {
                outer_end,
                inner_end,
                ..StyleOptions::default()
            };
            assert_eq!(generate(b, &o, &TWO).unwrap(), base, "{o:?}");
        }
        assert!(
            base.contains("[{dir}]") && base.contains("[{time}]"),
            "{base}"
        );
    }

    // `Preset::options` says every key is set: the engine's fallbacks never draw a preset.
    // 이것을 실패시키는 것: 프리셋 하나가 키 하나를 비워 두는 것(그 모양을 `run`의 기본값이 정함).
    #[test]
    fn every_preset_sets_every_key() {
        for p in PRESETS {
            let o = p.options;
            assert!(
                o.body.is_some()
                    && o.separator.is_some()
                    && o.outer_end.is_some()
                    && o.inner_end.is_some()
                    && o.joining.is_some()
                    && o.gap.is_some()
                    && o.fill.is_some()
                    && o.frame.is_some(),
                "{}",
                p.name
            );
        }
    }

    // A template replaces every option, so writing any one of them next to it is noted.
    // 이것을 실패시키는 것: `is_empty`가 새 필드(끝, 빈칸, 몸체, 이음) 하나를 빼고 보는 것(그 키만 쓰고 템플릿을
    // 쓰면 N501의 options가 거짓이 됨).
    #[test]
    fn a_template_notes_each_option_it_replaces() {
        let d = StyleOptions::default;
        let one_each = [
            StyleOptions {
                body: Some(Body::Block),
                ..d()
            },
            StyleOptions {
                separator: Some(Shape::Round),
                ..d()
            },
            StyleOptions {
                outer_end: Some(Cap::None),
                ..d()
            },
            StyleOptions {
                inner_end: Some(Cap::None),
                ..d()
            },
            StyleOptions {
                joining: Some(Joining::Capped),
                ..d()
            },
            StyleOptions {
                gap: Some(false),
                ..d()
            },
            StyleOptions {
                fill: Some(FillKind::Dot),
                ..d()
            },
            StyleOptions {
                frame: Some(false),
                ..d()
            },
        ];
        for o in one_each {
            let (_, n) = resolve(preset("lean").unwrap(), &o, Some("{dir}"), &TWO).unwrap();
            assert_eq!(
                n,
                [StyleNotice::TemplateReplaces { options: true }],
                "{o:?}"
            );
        }
    }
}
