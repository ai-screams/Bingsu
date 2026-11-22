//! The eight setting rows of the editor: their values in screen order, the
//! config key each writes, how a source's value reads back as one of them,
//! and what a preset gives the four part rows. Every value comes from these
//! fixed lists, so nothing a user typed can reach a file.
use crate::config::starter::Icons;
use crate::config::tree::{Table, Value};
use crate::icons::{IconSet, lookup};
use crate::style::{Body, Cap, Joining, StyleOptions, preset};
use crate::template::compile::Shape;
use alloc::vec::Vec;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Row {
    Style,
    Outer,
    Joint,
    Inner,
    Gap,
    Icons,
    Colors,
    Lines,
}

/// The preset names in screen order: `style::PRESETS` order (test
/// `rows_follow_the_core_tables`).
pub const STYLES: [&str; 8] = [
    "lean", "triangle", "pill", "capsule", "slant", "diamond", "block", "bracket",
];
/// `style.outer_end` and `style.inner_end`.
pub const ENDS: [&str; 5] = ["none", "triangle", "round", "slant", "flat"];
/// `style.separator`: a shape is a separator glyph, `none` touching blocks,
/// `caps` blocks with ends of their own.
pub const JOINTS: [&str; 6] = ["triangle", "round", "slant", "flat", "none", "caps"];
pub const GAPS: [&str; 2] = ["off", "on"];
/// The icon sets `setup` writes (`starter::Icons::ALL`, the four of
/// `icons::IconSet`), in that order.
pub const ICONS: [&str; 4] = {
    let a = Icons::ALL;
    [a[0].word(), a[1].word(), a[2].word(), a[3].word()]
};
pub const MODES: [&str; 3] = ["auto", "dark", "light"];
pub const LINES: [&str; 2] = ["2 lines", "1 line"];

/// The segments of the one line `1 line` writes, and of the upper line the
/// built-in layout draws (`config::compile::BUILTIN_TOML`), which `2 lines`
/// writes back over an inherited single line.
pub const ONE_LINE: [&str; 4] = ["host", "dir", "git", "char"];
pub const UPPER_LINE: [&str; 3] = ["host", "dir", "git"];

impl Row {
    pub const ALL: [Row; 8] = [
        Row::Style,
        Row::Outer,
        Row::Joint,
        Row::Inner,
        Row::Gap,
        Row::Icons,
        Row::Colors,
        Row::Lines,
    ];
    /// The five rows that shape the blocks.
    pub const SHAPE: [Row; 5] = [Row::Style, Row::Outer, Row::Joint, Row::Inner, Row::Gap];
    /// The rows a template (`style.template`) replaces: the shape rows and
    /// the layout lines it draws in place of.
    pub const TEMPLATED: [Row; 6] = [
        Row::Style,
        Row::Outer,
        Row::Joint,
        Row::Inner,
        Row::Gap,
        Row::Lines,
    ];

    pub const fn index(self) -> usize {
        self as usize
    }

    pub const fn name(self) -> &'static str {
        match self {
            Row::Style => "style",
            Row::Outer => "outer",
            Row::Joint => "joint",
            Row::Inner => "inner",
            Row::Gap => "gap",
            Row::Icons => "icons",
            Row::Colors => "colors",
            Row::Lines => "lines",
        }
    }

    /// The letter that steps the row forward (the upper case steps back).
    pub const fn key(self) -> u8 {
        match self {
            Row::Style => b's',
            Row::Outer => b'o',
            Row::Joint => b'j',
            Row::Inner => b'n',
            Row::Gap => b'g',
            Row::Icons => b'i',
            Row::Colors => b'c',
            Row::Lines => b'l',
        }
    }

    pub fn by_key(c: u8) -> Option<Row> {
        Row::ALL.into_iter().find(|r| r.key() == c)
    }

    /// The values, as the screen shows them.
    pub const fn values(self) -> &'static [&'static str] {
        match self {
            Row::Style => &STYLES,
            Row::Outer | Row::Inner => &ENDS,
            Row::Joint => &JOINTS,
            Row::Gap => &GAPS,
            Row::Icons => &ICONS,
            Row::Colors => &MODES,
            Row::Lines => &LINES,
        }
    }

    /// The config keys the row writes, as dotted paths.
    pub const fn keys(self) -> &'static [&'static str] {
        match self {
            Row::Style => &["style.preset"],
            Row::Outer => &["style.outer_end"],
            Row::Joint => &["style.separator"],
            Row::Inner => &["style.inner_end"],
            Row::Gap => &["style.gap"],
            Row::Icons => &["icons"],
            Row::Colors => &["colors.mode"],
            Row::Lines => &["layout.line1.left", "layout.line2.enabled"],
        }
    }

    /// What one source says for this row: its value of the row's key, when
    /// it is one of the row's values. Any other value is no opinion, as
    /// compile leaves a name it does not know unset (`style_options`).
    pub fn read(self, t: &Table) -> Option<u8> {
        let text = |path: &[&str]| match at(t, path) {
            Some(Value::Str(s)) => Some(s.as_str()),
            _ => None,
        };
        let boolean = |path: &[&str]| match at(t, path) {
            Some(Value::Bool(b)) => Some(*b),
            _ => None,
        };
        let find = |list: &[&str], v: Option<&str>| {
            let v = v?;
            list.iter().position(|x| *x == v).map(|i| i as u8)
        };
        match self {
            Row::Style => find(&STYLES, text(&["style", "preset"])),
            Row::Outer => find(&ENDS, text(&["style", "outer_end"])),
            Row::Joint => find(&JOINTS, text(&["style", "separator"])),
            Row::Inner => find(&ENDS, text(&["style", "inner_end"])),
            Row::Gap => Some(u8::from(boolean(&["style", "gap"])?)),
            Row::Icons => find(&ICONS, text(&["icons"])),
            Row::Colors => find(&MODES, text(&["colors", "mode"])),
            // Only `enabled` tells: `1 line` turns the input line off.
            Row::Lines => boolean(&["layout", "line2", "enabled"]).map(|on| u8::from(!on)),
        }
    }

    /// What a source's own text gives key number `key` of the row
    /// (`keys()`), as the screen may show it: a string quoted and sanitized
    /// (`starter::shown`), `true`/`false`, a list of strings. For "now" in a
    /// change, also when it is not one of the row's values.
    pub fn raw(self, t: &Table, key: usize) -> Option<alloc::string::String> {
        let path = *self.keys().get(key)?;
        let path: Vec<&str> = path.split('.').collect();
        let shown = |v: &Value| match v {
            Value::Str(s) => crate::config::starter::shown(s),
            Value::Bool(b) => alloc::format!("{b}"),
            _ => alloc::string::String::from("(not a string)"),
        };
        match at(t, &path)? {
            Value::Array(items) => {
                let items: Vec<_> = items.iter().map(|n| shown(&n.value)).collect();
                Some(alloc::format!("[{}]", items.join(", ")))
            }
            v => Some(shown(v)),
        }
    }
}

fn at<'a>(t: &'a Table, path: &[&str]) -> Option<&'a Value> {
    let (last, parents) = path.split_last()?;
    let mut table = t;
    for key in parents {
        match &table.get(key)?.node.value {
            Value::Table(inner) => table = inner,
            _ => return None,
        }
    }
    Some(&table.get(last)?.node.value)
}

fn shape_name(s: Shape) -> &'static str {
    match s {
        Shape::Triangle => "triangle",
        Shape::Round => "round",
        Shape::Slant => "slant",
        Shape::Flat => "flat",
    }
}

fn position(list: &[&str], name: &str) -> u8 {
    list.iter().position(|x| *x == name).unwrap_or(0) as u8
}

/// What preset `style` (an index of `STYLES`) gives part row `row`, when no
/// source writes the row's key. Not a part row: 0.
pub fn preset_part(row: Row, style: u8) -> u8 {
    let Some(p) = STYLES.get(usize::from(style)).and_then(|n| preset(n)) else {
        return 0;
    };
    let o = p.options;
    let end = |c: Option<Cap>| match c {
        Some(Cap::Shape(s)) => position(&ENDS, shape_name(s)),
        _ => 0,
    };
    match row {
        Row::Outer => end(o.outer_end),
        Row::Inner => end(o.inner_end),
        Row::Joint => match o.joining {
            Some(Joining::Adjacent) => position(&JOINTS, "none"),
            Some(Joining::Capped) => position(&JOINTS, "caps"),
            _ => position(&JOINTS, shape_name(o.separator.unwrap_or(Shape::Flat))),
        },
        Row::Gap => u8::from(o.gap == Some(true)),
        _ => 0,
    }
}

/// The style options of the five shape values (indexes of `STYLES`,
/// `ENDS`, `JOINTS`, `ENDS`, `GAPS`) laid over their preset, as compile
/// lays the written keys over it (`config::compile::style_options`).
pub fn options(style: u8, outer: u8, joint: u8, inner: u8, gap: u8) -> StyleOptions {
    let shape = |name: &str| match name {
        "triangle" => Some(Shape::Triangle),
        "round" => Some(Shape::Round),
        "slant" => Some(Shape::Slant),
        "flat" => Some(Shape::Flat),
        _ => None,
    };
    let cap = |i: u8| {
        let name = ENDS.get(usize::from(i)).copied().unwrap_or("none");
        Some(shape(name).map_or(Cap::None, Cap::Shape))
    };
    let joint_name = JOINTS.get(usize::from(joint)).copied().unwrap_or("flat");
    let (separator, joining) = match joint_name {
        "none" => (None, Some(Joining::Adjacent)),
        "caps" => (None, Some(Joining::Capped)),
        n => (shape(n), Some(Joining::Attached)),
    };
    let written = StyleOptions {
        separator,
        joining,
        outer_end: cap(outer),
        inner_end: cap(inner),
        gap: Some(gap == 1),
        ..StyleOptions::default()
    };
    match STYLES.get(usize::from(style)).and_then(|n| preset(n)) {
        Some(p) => written.over(p.options),
        None => written,
    }
}

/// Why a shape row changes nothing under `o` (see `options`), as the screen
/// says it; `None` when it does change something.
pub fn no_effect(row: Row, o: &StyleOptions, joint: u8) -> Option<&'static str> {
    let block = o.body == Some(Body::Block);
    match row {
        Row::Outer | Row::Inner if !block => Some("no ends without a background"),
        Row::Joint
            if !block
                && JOINTS
                    .get(usize::from(joint))
                    .is_some_and(|n| !matches!(*n, "none" | "caps")) =>
        {
            Some("one blank cell")
        }
        Row::Gap if !crate::style::gap_applies(o) => Some(if block {
            "only with caps"
        } else {
            "only with none or caps"
        }),
        _ => None,
    }
}

/// Whether icon set `icons` (an index of `ICONS`) draws the triangle, round
/// and slant separators as one glyph, from the icon table.
pub fn shapes_look_alike(icons: u8) -> bool {
    let Some(set) = ICONS
        .get(usize::from(icons))
        .and_then(|n| IconSet::parse(n))
    else {
        return false;
    };
    ["l", "r"].iter().all(|side| {
        let glyph = |s: &str| lookup(&alloc::format!("sep.{s}.{side}")).map(|i| i.glyph(set));
        let t = glyph("triangle");
        t.is_some() && t == glyph("round") && t == glyph("slant")
    })
}

/// The preset a new file starts from with icon set `icons` (an index of
/// `ICONS`) until the user touches a shape row: the one `setup` writes for
/// it without the editor (`starter::Icons::preset`).
pub fn icons_preset(icons: u8) -> u8 {
    let set = Icons::ALL
        .get(usize::from(icons))
        .copied()
        .unwrap_or(Icons::Nerd);
    position(&STYLES, set.preset())
}
