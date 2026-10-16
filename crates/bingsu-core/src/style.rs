//! The three style levels (ADR-0022, spec section 2 "스타일 세 단계의
//! 우선순위", M2 rule): the preset is the base, option keys sit on top, and
//! a template replaces both (`config check` reports the ignored levels from
//! M3). Presets and options only produce template text: the renderer knows
//! templates alone.
use crate::ident::{IdError, parse_segment_id};
use crate::template::compile::{FillKind, Shape};
use crate::template::syntax::MAX_TEMPLATE_BYTES;
use alloc::string::String;
use alloc::vec::Vec;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cap {
    None,
    Shape(Shape),
}

/// How neighboring blocks meet (ADR-0022 "블록 연결").
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Joining {
    /// A separator glyph between blocks.
    Attached,
    /// Blocks touch with no glyph.
    Adjacent,
    /// Every block has its own head and tail, one space apart.
    Spaced,
}

/// Option keys (ADR-0022 option combination). `None` = not set at this
/// level. Key names are fixed in M3.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct StyleOptions {
    pub background: Option<bool>,
    pub separator: Option<Shape>,
    pub head: Option<Cap>,
    pub tail: Option<Cap>,
    pub joining: Option<Joining>,
    pub fill: Option<FillKind>,
    pub frame: Option<bool>,
}

impl StyleOptions {
    /// `self` on top of `base`, key by key.
    pub fn over(self, base: Self) -> Self {
        Self {
            background: self.background.or(base.background),
            separator: self.separator.or(base.separator),
            head: self.head.or(base.head),
            tail: self.tail.or(base.tail),
            joining: self.joining.or(base.joining),
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

/// Test fixtures for M2. The seven first-release presets are M7.
pub const PRESETS: &[Preset] = &[
    Preset {
        name: "lean",
        options: StyleOptions {
            background: Some(false),
            separator: Some(Shape::Flat),
            head: Some(Cap::None),
            tail: Some(Cap::None),
            joining: Some(Joining::Spaced),
            fill: Some(FillKind::Space),
            frame: Some(false),
        },
    },
    Preset {
        name: "triangle",
        options: StyleOptions {
            background: Some(true),
            separator: Some(Shape::Triangle),
            head: Some(Cap::None),
            tail: Some(Cap::Shape(Shape::Triangle)),
            joining: Some(Joining::Attached),
            fill: Some(FillKind::Space),
            frame: Some(false),
        },
    },
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

/// One side of a line. The right side mirrors the left: its outer cap
/// (the preset's tail) comes first, and nothing closes at the screen edge.
fn run(out: &mut String, ids: &[&str], o: &StyleOptions, right: bool) {
    let block = o.background == Some(true);
    let (head, tail) = (o.head.unwrap_or(Cap::None), o.tail.unwrap_or(Cap::None));
    let (head, tail) = if right { (tail, head) } else { (head, tail) };
    let joining = o.joining.unwrap_or(Joining::Spaced);
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
                (_, Joining::Adjacent) => {}
                (false, Joining::Spaced | Joining::Attached) => out.push_str("{@sep:flat}"),
                (true, Joining::Spaced) => out.push(' '),
            }
        }
        if block && (first || joining == Joining::Spaced) {
            cap(out, "head", head);
        }
        out.push('{');
        out.push_str(id);
        if block {
            out.push_str(":block");
        }
        out.push('}');
        if block && (last || joining == Joining::Spaced) {
            cap(out, "tail", tail);
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

    // 이것을 실패시키는 것: Spaced에서 블록마다 머리·꼬리를 두지 않는 것.
    #[test]
    fn spaced_blocks_get_caps() {
        let o = StyleOptions {
            background: Some(true),
            joining: Some(Joining::Spaced),
            head: Some(Cap::Shape(Shape::Round)),
            tail: Some(Cap::Shape(Shape::Round)),
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
            "{@head:round}{dir:block}{@tail:round} {@head:round}{git:block}{@tail:round}"
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
            background: Some(true),
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
}
