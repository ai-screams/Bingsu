//! Line assembly and the seven overflow steps (spec section 3 "한 줄 조립과
//! 넘칠 때", "마지막 칸은 비운다"). left + fill + right = target width; when a
//! line overflows the steps apply in order and stop as soon as it fits, so a
//! line never overflows at any width from 0 up.
//!
//! Cost: values, path text, fields and glyphs are read and measured once per
//! line. Each fit check then walks the line's nodes once with no allocation
//! (O(M) for M nodes) and the steps make at most a few checks per segment, so
//! a line costs O(N·M) for N distinct segments (N is at most the catalog
//! size). The only allocations after setup are the shortener's own results
//! and the output runs, each at its exact size.
use crate::bands::{Band, select};
use crate::color::palette::token_index;
use crate::color::sgr::{Color, DIM, Style};
use crate::field::{FieldValue, SegmentDecl, Value};
use crate::icons::{self, IconSet};
use crate::shorten::{Keep, Method, PathFacts, Piece, Source, shorten};
use crate::template::compile::{CompiledLine, FillKind, Node, Shape};
use crate::template::syntax::{MAX_DEPTH, Mode};
use crate::width::{WidthProfile, ellipsis, fit_prefix, fit_suffix, str_width};
use alloc::string::String;
use alloc::vec::Vec;
use core::cmp::Reverse;
use unicode_segmentation::UnicodeSegmentation;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum When {
    /// Shorten only when the line overflows (default).
    Needed,
    /// Always use the first method.
    Always,
}

#[derive(Clone, Copy, Debug)]
pub struct SegmentSetup<'a> {
    /// Higher stays longer (steps 2 and 5).
    pub priority: u16,
    /// Never hidden by steps 2, 3 and 5 (`dir`, `char`).
    pub required: bool,
    pub methods: &'a [Method],
    pub when: When,
}

/// A segment with no setup entry (an `Inputs::setup` shorter than the
/// catalog): lowest priority, optional, never shortened.
const NO_SETUP: SegmentSetup<'static> = SegmentSetup {
    priority: 0,
    required: false,
    methods: &[],
    when: When::Needed,
};

/// Per catalog entry (same index as `catalog`). A slice shorter than the
/// catalog leaves the missing entries without a value, path or setup.
#[derive(Clone, Copy, Debug)]
pub struct Inputs<'a> {
    pub catalog: &'a [SegmentDecl],
    /// None: the segment sent no value and is hidden.
    pub values: &'a [Option<Value>],
    pub facts: &'a [Option<PathFacts>],
    pub setup: &'a [SegmentSetup<'a>],
}

#[derive(Clone, Copy, Debug)]
pub struct Options {
    /// The shell's width in cells; 0 = unknown.
    pub width: u16,
    pub profile: WidthProfile,
    pub icons: IconSet,
    /// `layout.use_last_column`; default false leaves the last cell empty.
    pub use_last_column: bool,
}

/// Target width: none at 0, 1 at 1, `width - 1` from 2 unless the last
/// column is used.
pub fn target(o: &Options) -> u32 {
    match o.width {
        0 => 0,
        1 => 1,
        w if o.use_last_column => u32::from(w),
        w => u32::from(w) - 1,
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Run {
    pub text: String,
    pub style: Style,
}

#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct LaidLine {
    pub left: Vec<Run>,
    /// Empty on upper lines (their right part is in `left`, after the fill).
    pub right: Vec<Run>,
    /// Step 7 reached: an upper line is then dropped.
    pub minimal: bool,
}

/// Cells of `runs` printed one after another, measured on the joined text
/// as a terminal reads it: a run that starts with U+FE0F or a ZWJ can widen
/// the grapheme that the run before it ends with.
pub fn runs_width(runs: &[Run], p: WidthProfile) -> u32 {
    match runs {
        [] => 0,
        [r] => str_width(&r.text, p),
        _ => {
            let joined: String = runs.iter().map(|r| r.text.as_str()).collect();
            str_width(&joined, p)
        }
    }
}

/// 1 when `s` starts with a grapheme that joins the one before it (it
/// starts with an extending character) and holds U+FE0F or a ZWJ. Joined,
/// that can turn a 1-cell base before it (`#`, a text-style pictograph such
/// as `▶`) into a 2-cell emoji; joining never widens anything by more than
/// that one cell. Counting the cell keeps every measured width at or above
/// what the terminal draws, wherever the text ends up next to other text.
fn join_risk(s: &str) -> u32 {
    let Some(g) = s.graphemes(true).next() else {
        return 0;
    };
    let Some(c) = g.chars().next() else {
        return 0;
    };
    if !g.contains(['\u{FE0F}', '\u{200D}']) {
        return 0;
    }
    // `A` then `c` is one grapheme exactly when `c` extends any base.
    let mut buf = [0u8; 5];
    buf[0] = b'A';
    let n = c.encode_utf8(&mut buf[1..]).len();
    let joins =
        core::str::from_utf8(&buf[..=n]).is_ok_and(|ab| ab.graphemes(true).nth(1).is_none());
    u32::from(joins)
}

/// Width of a piece of text in the measure: its cells plus the join risk.
fn measured(s: &str, p: WidthProfile) -> u32 {
    str_width(s, p).saturating_add(join_risk(s))
}

/// Sum that stops at `u32::MAX`: a template can repeat a 16-million-cell
/// path many times, and a wrapped sum would pass the fit check.
fn total(widths: impl Iterator<Item = u32>) -> u32 {
    widths.fold(0, u32::saturating_add)
}

fn tok(name: &str) -> u16 {
    token_index(name)
        .and_then(|i| u16::try_from(i).ok())
        .unwrap_or(0)
}

fn icon_glyph(name: &str, o: &Options) -> icons::Resolved {
    icons::lookup(name).map_or(
        icons::Resolved {
            text: "",
            width: 0,
            fell_back_to: None,
        },
        |ic| icons::resolve(ic, o.icons, o.profile),
    )
}

fn bool_field(decl: &SegmentDecl, v: &Value, name: &str) -> bool {
    decl.field_index(name)
        .and_then(|i| v.fields.get(i))
        .is_some_and(|f| f.value == FieldValue::Bool(true))
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum SepKind {
    Sep,
    Head,
    Tail,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Content,
    Sep(SepKind, Shape),
}

/// Where an item's text lives (no copy until the runs are written).
#[derive(Clone, Copy)]
enum Src {
    /// A template `Text` node, by node index.
    Text(usize),
    /// A field, as a byte range of `Lay::fields`.
    Field(usize, usize),
    /// An icon or a separator glyph.
    Glyph(&'static str),
    /// A segment's text before any shortening.
    Base(usize),
    /// Piece `.1` of segment `.0`'s shortened text.
    Cut(usize, usize),
}

/// One drawn thing in a line side. Separators keep their place until
/// cleanup decides on them; content is never dropped by cleanup.
#[derive(Clone, Copy)]
struct Item {
    kind: Kind,
    /// Head only: a block follows before the next head or tail.
    head_ok: bool,
    /// Block padding: one space before and after the segment's text.
    pad_l: bool,
    pad_r: bool,
    /// Measured cells, padding included.
    width: u32,
    /// Token of the block this content draws on.
    block: Option<u16>,
    style: Style,
    src: Src,
}

/// A shortened piece and its measured width.
struct Cut {
    piece: Piece,
    width: u32,
}

/// A segment's text before shortening.
enum Base {
    /// `Value::text`.
    Value,
    /// Path text (`PathFacts::display`).
    Owned(String),
    /// The `char` glyph.
    Glyph(&'static str),
}

/// Per catalog entry, for one line.
struct Slot {
    /// Has a value (and an index within `Inputs::values`).
    present: bool,
    hidden: bool,
    /// Appears in this line as a segment.
    in_line: bool,
    /// Step 4 cannot cut it further.
    exhausted: bool,
    base: Base,
    base_w: u32,
    short: Option<Vec<Cut>>,
    /// Color token of its text (plain) or background (block).
    role: u16,
    /// Segment nodes for it in this line, for the item capacity.
    nodes: u32,
}

/// A segment of this line in order of first appearance.
#[derive(Clone, Copy)]
struct Seg {
    seg: usize,
    right: bool,
    pos: u32,
}

/// Measured facts of a template node, read once per line.
#[derive(Clone, Copy, Default)]
struct Info {
    width: u32,
    /// Field: byte range in `Lay::fields`.
    a: usize,
    b: usize,
    /// Field: not empty for a conditional group.
    filled: bool,
    /// Icon glyph.
    glyph: &'static str,
}

/// Separator glyphs and widths: `[shape][pointing right]`.
type SepTable = [[(&'static str, u32); 2]; 4];

fn shape_ix(s: Shape) -> usize {
    match s {
        Shape::Triangle => 0,
        Shape::Round => 1,
        Shape::Slant => 2,
        Shape::Flat => 3,
    }
}

/// Reused buffers of the fit checks. Each is allocated at a size that the
/// walk cannot exceed, so no check grows a buffer.
struct Bufs {
    left: Vec<Item>,
    right: Vec<Item>,
    /// `refs[k]`: visible segment and field references in `nodes[..k]`.
    refs: Vec<u32>,
    styles: Vec<Style>,
}

/// One line being laid out.
struct Lay<'l, 'i> {
    nodes: &'l [Node],
    inp: &'l Inputs<'i>,
    o: &'l Options,
    info: Vec<Info>,
    fields: String,
    slots: Vec<Slot>,
    segs: Vec<Seg>,
    seps: SepTable,
    block_text: u16,
    char_seg: Option<usize>,
    /// Step 6: no blocks, separators, heads or tails.
    plain: bool,
}

impl<'l, 'i> Lay<'l, 'i> {
    fn new(line: &'l CompiledLine, inp: &'l Inputs<'i>, o: &'l Options) -> Self {
        let p = o.profile;
        let nodes = line.nodes();
        let cat = inp.catalog;
        let char_seg = cat.iter().position(|d| d.id == "char");
        let mut slots: Vec<Slot> = Vec::with_capacity(cat.len());
        for (i, d) in cat.iter().enumerate() {
            slots.push(Slot {
                present: matches!(inp.values.get(i), Some(Some(_))),
                hidden: false,
                in_line: false,
                exhausted: false,
                base: Base::Glyph(""),
                base_w: 0,
                short: None,
                role: tok(d.role),
                nodes: 0,
            });
        }
        // Segment order, and the exact size of the field text.
        let mut segs: Vec<Seg> = Vec::with_capacity(cat.len());
        let mut field_bytes = 0usize;
        let mut right = false;
        for (k, n) in nodes.iter().enumerate() {
            match *n {
                Node::Fill(_) => right = true,
                Node::Segment { seg, .. } => {
                    let s = usize::from(seg);
                    if let Some(slot) = slots.get_mut(s) {
                        slot.nodes += 1;
                        if !slot.in_line {
                            slot.in_line = true;
                            segs.push(Seg {
                                seg: s,
                                right,
                                pos: u32::try_from(k).unwrap_or(u32::MAX),
                            });
                        }
                    }
                }
                Node::Field { seg, field } => {
                    // Every drawn form is at most 24 bytes but text.
                    field_bytes += match field_of(inp, usize::from(seg), usize::from(field)) {
                        Some(FieldValue::Text(t)) => t.as_str().len(),
                        _ => 24,
                    };
                }
                _ => {}
            }
        }
        // Base text of each segment in the line.
        for g in &segs {
            let s = g.seg;
            let Some(Some(v)) = inp.values.get(s) else {
                continue;
            };
            let decl = &cat[s];
            let slot = &mut slots[s];
            if Some(s) == char_seg {
                let failed = bool_field(decl, v, "failed");
                let name = if bool_field(decl, v, "vicmd") {
                    "char.vicmd"
                } else if failed {
                    "char.err"
                } else {
                    "char.ok"
                };
                slot.base = Base::Glyph(icon_glyph(name, o).text);
                if failed {
                    // Failure changes both the color and the glyph (spec
                    // section 4 "필수 세그먼트").
                    slot.role = tok("prompt.err");
                }
            } else if let Some(Some(f)) = inp.facts.get(s) {
                slot.base = Base::Owned(f.display());
            } else {
                slot.base = Base::Value;
            }
            slot.base_w = measured(base_text(slot, v), p);
        }
        // Node widths and field text, once.
        let mut fields = String::with_capacity(field_bytes);
        let mut info: Vec<Info> = Vec::with_capacity(nodes.len());
        for n in nodes {
            let mut x = Info::default();
            match *n {
                Node::Text(ref t) => x.width = measured(t, p),
                Node::Icon(i) => {
                    // `compile` stores only indices into ICONS.
                    let r = icons::ICONS
                        .get(usize::from(i))
                        .map(|ic| icons::resolve(ic, o.icons, p));
                    x.glyph = r.map_or("", |r| r.text);
                    x.width = measured(x.glyph, p);
                }
                Node::Field { seg, field } => {
                    if let Some(f) = inp
                        .values
                        .get(usize::from(seg))
                        .and_then(Option::as_ref)
                        .and_then(|v| v.fields.get(usize::from(field)))
                    {
                        x.a = fields.len();
                        f.write_to(&mut fields);
                        x.b = fields.len();
                        x.filled = !f.is_empty_for_group();
                        x.width = measured(&fields[x.a..x.b], p);
                    }
                }
                _ => {}
            }
            info.push(x);
        }
        let mut seps: SepTable = [[("", 0); 2]; 4];
        for shape in [Shape::Triangle, Shape::Round, Shape::Slant, Shape::Flat] {
            for (d, right) in [false, true].into_iter().enumerate() {
                let r = icon_glyph(shape.icon(right), o);
                seps[shape_ix(shape)][d] = (r.text, u32::from(r.width));
            }
        }
        Self {
            nodes,
            inp,
            o,
            info,
            fields,
            slots,
            segs,
            seps,
            block_text: tok("block.text"),
            char_seg,
            plain: false,
        }
    }

    fn setup(&self, s: usize) -> SegmentSetup<'i> {
        self.inp.setup.get(s).copied().unwrap_or(NO_SETUP)
    }

    fn visible(&self, s: usize) -> bool {
        self.slots.get(s).is_some_and(|x| x.present && !x.hidden)
    }

    fn value(&self, s: usize) -> Option<&'i Value> {
        self.inp.values.get(s).and_then(Option::as_ref)
    }

    fn base_str(&self, s: usize) -> &str {
        match self.value(s) {
            Some(v) => base_text(&self.slots[s], v),
            None => "",
        }
    }

    /// Measured width of segment `s`'s text (padding excluded).
    fn seg_width(&self, s: usize) -> u32 {
        let slot = &self.slots[s];
        match &slot.short {
            Some(c) => total(c.iter().map(|c| c.width)),
            None => slot.base_w,
        }
    }

    fn source(&self, s: usize) -> Source<'_> {
        match self.inp.facts.get(s) {
            Some(Some(f)) => Source::Path(f),
            _ => Source::Text(self.base_str(s)),
        }
    }

    fn set_short(&mut self, s: usize, pieces: Vec<Piece>) {
        let p = self.o.profile;
        let cuts: Vec<Cut> = pieces
            .into_iter()
            .map(|piece| {
                let width = measured(&piece.text, p);
                Cut { piece, width }
            })
            .collect();
        self.slots[s].short = Some(cuts);
    }

    /// Most items one walk can make: one per node, plus one per extra
    /// shortened piece of every segment node.
    fn item_bound(&self) -> usize {
        let extra: usize = self
            .slots
            .iter()
            .filter_map(|x| {
                x.short
                    .as_ref()
                    .map(|c| c.len().saturating_sub(1) * x.nodes as usize)
            })
            .sum();
        self.nodes.len() + extra
    }

    fn new_bufs(&self) -> Bufs {
        Bufs {
            left: Vec::new(),
            right: Vec::new(),
            refs: Vec::with_capacity(self.nodes.len() + 1),
            styles: Vec::with_capacity(MAX_DEPTH + 1),
        }
    }

    /// Items of both sides for the current state, cleaned up.
    fn walk(&self, b: &mut Bufs) {
        let Bufs {
            left,
            right,
            refs,
            styles,
        } = b;
        let bound = self.item_bound();
        for side in [&mut *left, &mut *right] {
            side.clear();
            if side.capacity() < bound {
                *side = Vec::with_capacity(bound);
            }
        }
        refs.clear();
        let mut acc = 0u32;
        refs.push(0);
        for (k, n) in self.nodes.iter().enumerate() {
            acc += u32::from(match *n {
                Node::Segment { seg, .. } => self.visible(usize::from(seg)),
                Node::Field { seg, .. } => self.visible(usize::from(seg)) && self.info[k].filled,
                _ => false,
            });
            refs.push(acc);
        }
        styles.clear();
        let mut on_right = false;
        let mut k = 0;
        while k < self.nodes.len() {
            let side: &mut Vec<Item> = if on_right { &mut *right } else { &mut *left };
            let plain_style = with(styles, Style::default());
            let content = |width, src| Item {
                kind: Kind::Content,
                head_ok: false,
                pad_l: false,
                pad_r: false,
                width,
                block: None,
                style: plain_style,
                src,
            };
            match &self.nodes[k] {
                Node::Group { len } => {
                    // A group spans `len` nodes after it (`compile`); `end`
                    // is at most nodes.len(), so both reads are in `refs`.
                    let end = (k + 1).saturating_add(*len as usize).min(self.nodes.len());
                    if refs[end] == refs[k + 1] {
                        k = end;
                        continue;
                    }
                }
                Node::GroupEnd => {}
                Node::Style(spec) => {
                    let parent = styles.last().copied().unwrap_or_default();
                    styles.push(Style {
                        fg: spec.fg.map_or(parent.fg, Color::Text),
                        bg: spec.bg.map_or(parent.bg, Color::Block),
                        attrs: parent.attrs | spec.attrs,
                    });
                }
                Node::StyleEnd => {
                    styles.pop();
                }
                Node::Text(_) => side.push(content(self.info[k].width, Src::Text(k))),
                Node::Icon(_) => {
                    side.push(content(self.info[k].width, Src::Glyph(self.info[k].glyph)))
                }
                Node::Field { seg, .. } => {
                    if self.visible(usize::from(*seg)) {
                        let x = self.info[k];
                        side.push(content(x.width, Src::Field(x.a, x.b)));
                    }
                }
                Node::Segment { seg, mode } => {
                    let s = usize::from(*seg);
                    if self.visible(s) {
                        self.push_segment(side, styles, s, *mode == Mode::Block && !self.plain);
                    }
                }
                Node::Sep(shape) | Node::Head(shape) | Node::Tail(shape) => {
                    if !self.plain {
                        let kind = match self.nodes[k] {
                            Node::Sep(_) => SepKind::Sep,
                            Node::Head(_) => SepKind::Head,
                            _ => SepKind::Tail,
                        };
                        // Left side separators point right, right side ones
                        // left; a head points left and a tail right.
                        let to_right = match kind {
                            SepKind::Sep => !on_right,
                            SepKind::Head => false,
                            SepKind::Tail => true,
                        };
                        let (glyph, width) = self.seps[shape_ix(*shape)][usize::from(to_right)];
                        side.push(Item {
                            kind: Kind::Sep(kind, *shape),
                            width,
                            ..content(width, Src::Glyph(glyph))
                        });
                    }
                }
                Node::Fill(_) => on_right = true,
            }
            k += 1;
        }
        clean(left);
        clean(right);
    }

    fn push_segment(&self, side: &mut Vec<Item>, styles: &[Style], s: usize, block: bool) {
        let slot = &self.slots[s];
        let base = if block {
            Style {
                fg: Color::Text(self.block_text),
                bg: Color::Block(slot.role),
                attrs: 0,
            }
        } else {
            Style {
                fg: Color::Text(slot.role),
                bg: Color::Default,
                attrs: 0,
            }
        };
        let style = with(styles, base);
        let pad = u32::from(block);
        let item = |width: u32, style, src, first: bool, last: bool| Item {
            kind: Kind::Content,
            head_ok: false,
            pad_l: block && first,
            pad_r: block && last,
            width: width.saturating_add(if first { pad } else { 0 } + if last { pad } else { 0 }),
            block: block.then_some(slot.role),
            style,
            src,
        };
        match &slot.short {
            None => side.push(item(slot.base_w, style, Src::Base(s), true, true)),
            Some(cuts) => {
                let n = cuts.len();
                for (j, c) in cuts.iter().enumerate() {
                    let st = if c.piece.shortened {
                        Style {
                            attrs: style.attrs | DIM,
                            ..style
                        }
                    } else {
                        style
                    };
                    side.push(item(c.width, st, Src::Cut(s, j), j == 0, j + 1 == n));
                }
            }
        }
    }

    /// Measured width of the line in its current state.
    fn measure(&self, b: &mut Bufs) -> u32 {
        self.walk(b);
        total(b.left.iter().chain(&b.right).map(|x| x.width))
    }

    fn text(&self, it: &Item) -> &str {
        match it.src {
            Src::Text(k) => match &self.nodes[k] {
                Node::Text(t) => t,
                _ => "",
            },
            Src::Field(a, b) => &self.fields[a..b],
            Src::Glyph(g) => g,
            Src::Base(s) => self.base_str(s),
            Src::Cut(s, j) => self.slots[s]
                .short
                .as_ref()
                .map_or("", |c| c[j].piece.text.as_str()),
        }
    }

    /// Bytes of an item's text, padding included.
    fn bytes(&self, it: &Item) -> usize {
        self.text(it).len() + usize::from(it.pad_l) + usize::from(it.pad_r)
    }

    /// Writes the runs of cleaned items `items` to `out`, merging neighbors
    /// of one style; empty items are skipped (`run_count` counts the same).
    fn write_runs(&self, items: &[Item], right_side: bool, out: &mut Sink<'_>) {
        let mut i = 0;
        while i < items.len() {
            let style = item_style(items, i, right_side);
            if self.bytes(&items[i]) == 0 {
                i += 1;
                continue;
            }
            // One run: this item and the following ones of the same style.
            let mut end = i + 1;
            let mut len = self.bytes(&items[i]);
            while end < items.len()
                && (self.bytes(&items[end]) == 0 || item_style(items, end, right_side) == style)
            {
                len += self.bytes(&items[end]);
                end += 1;
            }
            let text = out.start(style, len);
            for it in &items[i..end] {
                if it.pad_l {
                    text.push(' ');
                }
                text.push_str(self.text(it));
                if it.pad_r {
                    text.push(' ');
                }
            }
            i = end;
        }
    }

    fn run_count(&self, items: &[Item], right_side: bool) -> usize {
        let mut n = 0;
        let mut last: Option<Style> = None;
        for (i, it) in items.iter().enumerate() {
            if self.bytes(it) == 0 {
                continue;
            }
            let style = item_style(items, i, right_side);
            if last != Some(style) {
                n += 1;
                last = Some(style);
            }
        }
        n
    }
}

fn field_of<'a>(inp: &Inputs<'a>, seg: usize, field: usize) -> Option<&'a FieldValue> {
    inp.values
        .get(seg)
        .and_then(Option::as_ref)
        .and_then(|v| v.fields.get(field))
        .map(|f| &f.value)
}

fn base_text<'a>(slot: &'a Slot, v: &'a Value) -> &'a str {
    match &slot.base {
        Base::Value => v.text(),
        Base::Owned(s) => s,
        Base::Glyph(g) => g,
    }
}

/// `base` under the innermost `{@style}`: its colors and attributes win.
fn with(spec_stack: &[Style], mut s: Style) -> Style {
    if let Some(top) = spec_stack.last() {
        if top.fg != Color::Default {
            s.fg = top.fg;
        }
        if top.bg != Color::Default {
            s.bg = top.bg;
        }
        s.attrs |= top.attrs;
    }
    s
}

/// Separator cleanup (spec section 3 "템플릿 중간 표현"): a head needs a
/// block after it before the next head or tail, a separator with no content
/// before it goes, a separator right after a head goes, and separators with
/// no content between them become one (a tail among them wins). Linear: one
/// pass from the end marks the heads, one pass from the start compacts.
fn clean(items: &mut Vec<Item>) {
    let mut block_ahead = false;
    for it in items.iter_mut().rev() {
        match it.kind {
            Kind::Content => block_ahead |= it.block.is_some(),
            Kind::Sep(SepKind::Head, _) => {
                it.head_ok = block_ahead;
                block_ahead = false;
            }
            Kind::Sep(SepKind::Tail, _) => block_ahead = false,
            Kind::Sep(SepKind::Sep, _) => {}
        }
    }
    let mut w = 0usize;
    let mut any_content = false;
    for r in 0..items.len() {
        let it = items[r];
        let keep = match it.kind {
            Kind::Content => {
                any_content = true;
                true
            }
            Kind::Sep(SepKind::Head, _) => it.head_ok,
            Kind::Sep(kind, _) => {
                if !any_content {
                    false
                } else {
                    match w.checked_sub(1).map(|l| items[l].kind) {
                        Some(Kind::Sep(SepKind::Head, _)) => false,
                        Some(Kind::Sep(..)) => {
                            if kind == SepKind::Tail {
                                // The run becomes this tail, glyph included.
                                items[w - 1] = it;
                            }
                            false
                        }
                        _ => true,
                    }
                }
            }
        };
        if keep {
            items[w] = it;
            w += 1;
        }
    }
    items.truncate(w);
}

/// Style of cleaned item `i`. Separators take the colors of the blocks
/// next to them (design brief interlock rule): a left side separator `▶`
/// has the block before as text color and the block after as background, a
/// right side `◀` the reverse; a head takes the block after, a tail the
/// block before, on the default background; `flat` is a space on the
/// neighboring block's background.
fn item_style(items: &[Item], i: usize, right_side: bool) -> Style {
    let it = items[i];
    let Kind::Sep(kind, shape) = it.kind else {
        return it.style;
    };
    let block_at = |j: Option<usize>| match j.and_then(|j| items.get(j)) {
        Some(Item {
            kind: Kind::Content,
            block: Some(b),
            ..
        }) => Some(Color::Block(*b)),
        _ => None,
    };
    let (prev, next) = (block_at(i.checked_sub(1)), block_at(Some(i + 1)));
    let (fg, bg) = match kind {
        SepKind::Head => (next, None),
        SepKind::Tail => (prev, None),
        SepKind::Sep if right_side => (next, prev),
        SepKind::Sep => (prev, next),
    };
    let (fg, bg) = if shape == Shape::Flat {
        (None, next.or(prev))
    } else {
        (fg, bg)
    };
    Style {
        fg: fg.unwrap_or_default(),
        bg: bg.unwrap_or_default(),
        attrs: 0,
    }
}

/// `src` (pieces and their "shortened" marks) cut to at most `cut` cells
/// with an ellipsis that fits the profile, keeping the start or the end.
/// Pieces stay whole where they fit, so earlier dim marks stay; a cut piece
/// is cut between graphemes.
fn truncate<T>(
    src: &[T],
    get: impl Fn(&T) -> (&str, bool),
    cut: u32,
    keep: Keep,
    p: WidthProfile,
) -> Vec<Cut> {
    let e = ellipsis(p, cut);
    let room = cut.saturating_sub(str_width(e, p));
    // Whole pieces kept from the kept end, then the one cut inside.
    let mut used = 0u32;
    let mut whole = 0usize;
    let mut part: Option<(usize, usize)> = None;
    let order: &mut dyn Iterator<Item = (usize, &T)> = match keep {
        Keep::End => &mut src.iter().enumerate().rev(),
        Keep::Start => &mut src.iter().enumerate(),
    };
    for (i, t) in order {
        let (text, _) = get(t);
        let w = str_width(text, p);
        if used.saturating_add(w) <= room {
            used += w;
            whole += 1;
            continue;
        }
        let at = match keep {
            Keep::End => fit_suffix(text, room - used, p).0,
            Keep::Start => fit_prefix(text, room - used, p).0,
        };
        part = Some((i, at));
        break;
    }
    let mut out: Vec<Cut> = Vec::with_capacity(whole + 2);
    let mut add = |text: &str, shortened: bool| {
        if !text.is_empty() {
            out.push(Cut {
                width: measured(text, p),
                piece: Piece {
                    text: text.into(),
                    shortened,
                },
            });
        }
    };
    match keep {
        Keep::End => {
            add(e, true);
            if let Some((i, at)) = part {
                let (text, sh) = get(&src[i]);
                add(&text[at..], sh);
            }
            for t in &src[src.len() - whole..] {
                let (text, sh) = get(t);
                add(text, sh);
            }
        }
        Keep::Start => {
            for t in &src[..whole] {
                let (text, sh) = get(t);
                add(text, sh);
            }
            if let Some((i, at)) = part {
                let (text, sh) = get(&src[i]);
                add(&text[..at], sh);
            }
            add(e, true);
        }
    }
    out
}

/// Output runs written in place: an existing run's String is reused when
/// it has room and otherwise allocated at its exact size, so writing never
/// grows a String or a Vec.
struct Sink<'a> {
    runs: &'a mut Vec<Run>,
    n: usize,
}

impl<'a> Sink<'a> {
    fn new(runs: &'a mut Vec<Run>, count: usize) -> Self {
        if runs.capacity() < count {
            *runs = Vec::with_capacity(count);
        }
        runs.truncate(count);
        Self { runs, n: 0 }
    }

    fn start(&mut self, style: Style, bytes: usize) -> &mut String {
        if self.n < self.runs.len() {
            let r = &mut self.runs[self.n];
            r.style = style;
            r.text.clear();
            if r.text.capacity() < bytes {
                r.text = String::with_capacity(bytes);
            }
        } else {
            self.runs.push(Run {
                text: String::with_capacity(bytes),
                style,
            });
        }
        self.n += 1;
        &mut self.runs[self.n - 1].text
    }

    fn finish(self) {
        self.runs.truncate(self.n);
    }
}

fn one_run(runs: &mut Vec<Run>, text: &str, style: Style) {
    let mut sink = Sink::new(runs, 1);
    sink.start(style, text.len()).push_str(text);
    sink.finish();
}

fn clear_line(out: &mut LaidLine, minimal: bool) {
    out.left.clear();
    out.right.clear();
    out.minimal = minimal;
}

/// Lays out one line. `upper` lines get the fill and lose step 7's output.
pub fn layout_line(line: &CompiledLine, upper: bool, inp: &Inputs<'_>, o: &Options) -> LaidLine {
    let mut out = LaidLine::default();
    layout_line_into(line, upper, inp, o, &mut out);
    out
}

/// `layout_line` into `out`, reusing its run buffers.
pub fn layout_line_into(
    line: &CompiledLine,
    upper: bool,
    inp: &Inputs<'_>,
    o: &Options,
    out: &mut LaidLine,
) {
    let target = target(o);
    let p = o.profile;
    if o.width == 1 {
        // Spec section 3 table: width 1 is one ASCII `>`.
        clear_line(out, true);
        if !upper {
            one_run(&mut out.left, ">", Style::default());
        }
        return;
    }
    if target == 0 {
        clear_line(out, true);
        return;
    }
    let mut lay = Lay::new(line, inp, o);
    let mut b = lay.new_bufs();
    for i in 0..lay.segs.len() {
        let g = lay.segs[i];
        let su = lay.setup(g.seg);
        if su.when == When::Always && lay.visible(g.seg) {
            if let Some(first) = su.methods.get(..1) {
                if let Some((res, _, _)) = shorten(lay.source(g.seg), first, u32::MAX, p) {
                    lay.set_short(g.seg, res.pieces);
                }
            }
        }
    }
    let mut over = lay.measure(&mut b).saturating_sub(target);
    'steps: {
        if over == 0 {
            break 'steps;
        }
        // Step 1: left before right (the path before right-side information,
        // user decision 2026-10-02), each to "its width - overflow".
        for right in [false, true] {
            for i in 0..lay.segs.len() {
                let g = lay.segs[i];
                let su = lay.setup(g.seg);
                if g.right != right || su.methods.is_empty() || !lay.visible(g.seg) {
                    continue;
                }
                let budget = lay.seg_width(g.seg).saturating_sub(over);
                if let Some((res, _, _)) = shorten(lay.source(g.seg), su.methods, budget, p) {
                    lay.set_short(g.seg, res.pieces);
                }
                over = lay.measure(&mut b).saturating_sub(target);
                if over == 0 {
                    break 'steps;
                }
            }
        }
        // Steps 2 and 3: right side, lowest priority (then rightmost) first;
        // hiding the last one is step 3.
        for (_, _, s) in by_priority(&lay, true) {
            if lay.visible(s) {
                lay.slots[s].hidden = true;
                over = lay.measure(&mut b).saturating_sub(target);
                if over == 0 {
                    break 'steps;
                }
            }
        }
        // Step 4: cut left values by the overflow, widest first (leftmost on
        // a tie), down to the ellipsis. A one-cell value (the `char` glyph)
        // cannot get narrower, so it is only ever marked exhausted.
        loop {
            let pick = lay
                .segs
                .iter()
                .filter(|g| !g.right && lay.visible(g.seg) && !lay.slots[g.seg].exhausted)
                .max_by_key(|g| (lay.seg_width(g.seg), Reverse(g.pos)));
            let Some(&g) = pick else { break };
            let s = g.seg;
            let w = lay.seg_width(s);
            let keep = if matches!(inp.facts.get(s), Some(Some(_))) {
                Keep::End
            } else {
                Keep::Start
            };
            let cut = w.saturating_sub(over).max(1);
            let cuts = match &lay.slots[s].short {
                Some(c) => truncate(
                    c,
                    |c| (c.piece.text.as_str(), c.piece.shortened),
                    cut,
                    keep,
                    p,
                ),
                None => truncate(&[lay.base_str(s)], |t| (*t, false), cut, keep, p),
            };
            if total(cuts.iter().map(|c| c.width)) >= w {
                lay.slots[s].exhausted = true;
                continue;
            }
            lay.slots[s].short = Some(cuts);
            over = lay.measure(&mut b).saturating_sub(target);
            if over == 0 {
                break 'steps;
            }
        }
        // Step 5: optional left segments, lowest priority (then rightmost)
        // first.
        for (_, _, s) in by_priority(&lay, false) {
            if lay.visible(s) {
                lay.slots[s].hidden = true;
                over = lay.measure(&mut b).saturating_sub(target);
                if over == 0 {
                    break 'steps;
                }
            }
        }
        // Step 6: plain text, no backgrounds, separators, heads or tails.
        lay.plain = true;
        over = lay.measure(&mut b).saturating_sub(target);
        if over == 0 {
            break 'steps;
        }
        // Step 7.
        return minimal(&lay, upper, target, out);
    }
    // Every way out of the steps follows a check, so `b` holds the items of
    // the final state.
    out.minimal = false;
    let width = |items: &[Item]| total(items.iter().map(|x| x.width));
    let (nl, nr) = (lay.run_count(&b.left, false), lay.run_count(&b.right, true));
    if upper {
        let gap = target.saturating_sub(width(&b.left) + width(&b.right));
        let fill = (nr > 0 && gap > 0).then(|| {
            let kind = line.fill().and_then(|i| match line.nodes().get(i) {
                Some(Node::Fill(f)) => Some(*f),
                _ => None,
            });
            let kind = kind.unwrap_or(FillKind::Space);
            // Fill glyphs are one-cell icons, so `gap` glyphs fill `gap`
            // cells (test `fill_glyphs_are_one_cell`).
            let style = if kind == FillKind::Space {
                Style::default()
            } else {
                Style {
                    fg: Color::Text(tok("muted")),
                    ..Style::default()
                }
            };
            (icon_glyph(kind.icon(), o).text, style)
        });
        let mut sink = Sink::new(&mut out.left, nl + usize::from(fill.is_some()) + nr);
        lay.write_runs(&b.left, false, &mut sink);
        if let Some((glyph, style)) = fill {
            let text = sink.start(style, glyph.len() * gap as usize);
            for _ in 0..gap {
                text.push_str(glyph);
            }
        }
        lay.write_runs(&b.right, true, &mut sink);
        sink.finish();
        out.right.clear();
    } else {
        let mut sink = Sink::new(&mut out.left, nl);
        lay.write_runs(&b.left, false, &mut sink);
        sink.finish();
        let mut sink = Sink::new(&mut out.right, nr);
        lay.write_runs(&b.right, true, &mut sink);
        sink.finish();
    }
}

/// Optional segments of one side as `(priority, Reverse(position), seg)`,
/// lowest priority first and the rightmost first on a tie.
fn by_priority(lay: &Lay<'_, '_>, right: bool) -> Vec<(u16, Reverse<u32>, usize)> {
    let mut v: Vec<(u16, Reverse<u32>, usize)> = Vec::with_capacity(lay.segs.len());
    for g in &lay.segs {
        let su = lay.setup(g.seg);
        if g.right == right && !su.required {
            v.push((su.priority, Reverse(g.pos), g.seg));
        }
    }
    v.sort_unstable();
    v
}

/// Step 7: `char` and a space, then `char` alone, then ASCII `>`, then
/// nothing. An upper line collapses to nothing.
fn minimal(lay: &Lay<'_, '_>, upper: bool, target: u32, out: &mut LaidLine) {
    clear_line(out, true);
    if upper {
        return;
    }
    let ch = lay
        .char_seg
        .filter(|&c| lay.slots[c].in_line && lay.slots[c].present);
    let (glyph, style) = match ch {
        Some(c) => {
            let failed = lay
                .value(c)
                .is_some_and(|v| bool_field(&lay.inp.catalog[c], v, "failed"));
            let role = if failed { "prompt.err" } else { "prompt.ok" };
            (
                lay.base_str(c),
                Style {
                    fg: Color::Text(tok(role)),
                    ..Style::default()
                },
            )
        }
        None => (">", Style::default()),
    };
    let gw = measured(glyph, lay.o.profile);
    // The `char` glyph is a one-cell icon and the target is at least 1
    // here, so the spec's later fallbacks (ASCII `>`, then nothing) are
    // reached only as the `>` drawn when the line has no `char`. A glyph
    // that fits in neither form would draw nothing.
    let choices = [(glyph, " ", gw + 1), (glyph, "", gw)];
    let Some(&(a, b, _)) = choices.iter().find(|c| c.2 <= target) else {
        return;
    };
    let mut sink = Sink::new(&mut out.left, 1);
    let t = sink.start(style, a.len() + b.len());
    t.push_str(a);
    t.push_str(b);
    sink.finish();
}

/// Picks the band for the shell's width and lays out every line of it.
/// `variants[0]` is the default layout, `variants[i + 1]` band `i`.
pub fn layout(
    variants: &[Vec<CompiledLine>],
    bands: &[Band],
    band_order: &[usize],
    inp: &Inputs<'_>,
    o: &Options,
) -> Vec<LaidLine> {
    let mut out = Vec::new();
    layout_into(variants, bands, band_order, inp, o, &mut out);
    out
}

/// `layout` into `out`, reusing its lines and run buffers. A band order
/// with an index outside `bands`, or a band with no variant, falls back to
/// the default layout; no variants at all give no lines.
pub fn layout_into(
    variants: &[Vec<CompiledLine>],
    bands: &[Band],
    band_order: &[usize],
    inp: &Inputs<'_>,
    o: &Options,
    out: &mut Vec<LaidLine>,
) {
    let band = if band_order.iter().all(|&i| i < bands.len()) {
        select(band_order, bands, o.width)
    } else {
        None
    };
    let lines = band
        .and_then(|b| variants.get(b + 1))
        .or(variants.first())
        .map_or(&[][..], Vec::as_slice);
    if out.capacity() < lines.len() {
        *out = Vec::with_capacity(lines.len());
    }
    out.truncate(lines.len());
    while out.len() < lines.len() {
        out.push(LaidLine::default());
    }
    let last = lines.len().saturating_sub(1);
    for (n, (l, dst)) in lines.iter().zip(out.iter_mut()).enumerate() {
        layout_line_into(l, n < last, inp, o, dst);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::{BUILTIN, Field, FieldValue, segment};
    use crate::shorten::Anchor;
    use crate::style::{LineLayout, StyleOptions, generate, preset};
    use crate::template::compile::compile;
    use alloc::vec;

    pub(crate) struct Fixture {
        pub values: Vec<Option<Value>>,
        pub facts: Vec<Option<PathFacts>>,
        pub setup: Vec<SegmentSetup<'static>>,
    }

    const PATH_METHODS: &[Method] = &[Method::Repo, Method::Abbrev(1), Method::Depth(1)];
    const BRANCH_METHODS: &[Method] = &[Method::Truncate {
        max: 24,
        keep: Keep::Start,
    }];

    fn idx(id: &str) -> usize {
        BUILTIN.iter().position(|d| d.id == id).unwrap()
    }

    fn value(id: &str, text: &str, set: &[(&str, FieldValue)]) -> Option<Value> {
        let d = segment(id).unwrap();
        let mut fields = vec![Field::ABSENT; d.fields.len()];
        for (name, v) in set {
            fields[d.field_index(name).unwrap()] = Field::known(v.clone());
        }
        Some(Value::new(text.as_bytes(), fields))
    }

    pub(crate) fn fixture(steps: &[&str], branch: &str) -> Fixture {
        let mut values = vec![None; BUILTIN.len()];
        let mut facts = vec![None; BUILTIN.len()];
        let mut setup = vec![
            SegmentSetup {
                priority: 10,
                required: false,
                methods: &[],
                when: When::Needed
            };
            BUILTIN.len()
        ];
        values[idx("char")] = value("char", "", &[]);
        values[idx("dir")] = value("dir", "", &[]);
        let raw: Vec<&[u8]> = steps.iter().map(|s| s.as_bytes()).collect();
        facts[idx("dir")] = Some(PathFacts::new(Anchor::Home, &raw, Some(2), &[]));
        values[idx("git")] = value(
            "git",
            branch,
            &[(
                "ahead",
                FieldValue::Count {
                    n: 2,
                    saturated: false,
                },
            )],
        );
        values[idx("status")] = value("status", "1", &[("code", FieldValue::Int(1))]);
        values[idx("time")] = value("time", "12:34", &[]);
        setup[idx("char")].required = true;
        setup[idx("dir")] = SegmentSetup {
            priority: 100,
            required: true,
            methods: PATH_METHODS,
            when: When::Needed,
        };
        setup[idx("git")].methods = BRANCH_METHODS;
        setup[idx("time")].priority = 1;
        Fixture {
            values,
            facts,
            setup,
        }
    }

    impl Fixture {
        pub(crate) fn inputs(&self) -> Inputs<'_> {
            Inputs {
                catalog: BUILTIN,
                values: &self.values,
                facts: &self.facts,
                setup: &self.setup,
            }
        }
    }

    pub(crate) fn opts(width: u16) -> Options {
        Options {
            width,
            profile: WidthProfile::DEFAULT,
            icons: IconSet::Nerd,
            use_last_column: false,
        }
    }

    pub(crate) fn two_lines(preset_name: &str) -> Vec<CompiledLine> {
        let t = generate(
            preset(preset_name).unwrap(),
            &StyleOptions::default(),
            &[
                LineLayout {
                    left: &["dir", "git"],
                    right: &["status", "time"],
                },
                LineLayout {
                    left: &["char"],
                    right: &[],
                },
            ],
        )
        .unwrap();
        compile(&t, BUILTIN).unwrap()
    }

    fn text(runs: &[Run]) -> String {
        runs.iter().map(|r| r.text.as_str()).collect()
    }

    fn lay(lines: &[CompiledLine], f: &Fixture, o: &Options) -> Vec<LaidLine> {
        layout(&[lines.to_vec()], &[], &[], &f.inputs(), o)
    }

    /// Every line's joined width is within the target.
    fn assert_fits(out: &[LaidLine], o: &Options, what: &str) {
        for l in out {
            let lw = runs_width(&l.left, o.profile) + runs_width(&l.right, o.profile);
            assert!(
                lw <= target(o),
                "{what} w={}: {lw} > {} {l:?}",
                o.width,
                target(o)
            );
        }
    }

    // 이것을 실패시키는 것: 첫 줄이 목표 폭(셸 폭 − 1)과 다르게 끝나는 것(오른쪽 끝 정렬, 마지막 칸 비움).
    // `target`의 `w - 1`을 `w`로 바꾸면 80칸에서 실패한다(변이 E3).
    #[test]
    fn upper_line_ends_on_the_second_to_last_cell() {
        let f = fixture(&["Works", "AiScream", "themes"], "main");
        for name in ["lean", "triangle"] {
            let out = lay(&two_lines(name), &f, &opts(80));
            assert_eq!(
                runs_width(&out[0].left, WidthProfile::DEFAULT),
                79,
                "{name}"
            );
            assert!(
                text(&out[0].left).ends_with("12:34 ") || text(&out[0].left).ends_with("12:34"),
                "{name}"
            );
            let mut lc = opts(80);
            lc.use_last_column = true;
            assert_eq!(
                runs_width(
                    &lay(&two_lines(name), &f, &lc)[0].left,
                    WidthProfile::DEFAULT
                ),
                80,
                "{name}"
            );
        }
    }

    // 이것을 실패시키는 것: 0–200 어느 폭·어느 프로필에서든 줄이 목표 폭을 넘는 것(스펙 7절 1층).
    // 경계가 실제로 닿는지(최소 프롬프트, `…`, amb=2의 `.`, 목표 폭에 꼭 맞는 줄) 센다.
    #[test]
    fn never_overflows_any_width() {
        let long = "x".repeat(300);
        let cases = [
            fixture(
                &["Works", "AiScream", "themes", "src", "render"],
                "feature/very-long-branch-name",
            ),
            fixture(
                &[
                    "프로젝트",
                    "\u{1112}\u{1161}\u{11AB}\u{1100}\u{1173}\u{11AF}",
                    long.as_str(),
                ],
                "\u{1F3F3}\u{FE0F}\u{200D}\u{1F308}-\u{2026}",
            ),
        ];
        let (mut minimal, mut ell, mut dot, mut tight) = (0, 0, 0, 0);
        for f in &cases {
            for name in ["lean", "triangle"] {
                let lines = two_lines(name);
                for amb in [1, 2] {
                    for w in 0..=200u16 {
                        let o = Options {
                            profile: WidthProfile::new(amb, 2).unwrap(),
                            ..opts(w)
                        };
                        let out = lay(&lines, f, &o);
                        assert_fits(&out, &o, name);
                        for l in &out {
                            assert!(
                                l.left.iter().chain(&l.right).all(|r| !r.text.is_empty()),
                                "{name} w={w} {l:?}"
                            );
                            let t = text(&l.left);
                            minimal += usize::from(l.minimal && w >= 2);
                            ell += usize::from(amb == 1 && t.contains('\u{2026}'));
                            dot += usize::from(amb == 2 && t.contains('.'));
                            tight +=
                                usize::from(w >= 2 && runs_width(&l.left, o.profile) == target(&o));
                        }
                    }
                }
            }
        }
        assert!(
            minimal > 0 && ell > 0 && dot > 0 && tight > 0,
            "{minimal} {ell} {dot} {tight}"
        );
    }

    // 이것을 실패시키는 것: 폭 0·1·2·3 규칙(빈 문자열, `>`, `char`+공백) 중 하나가 틀리는 것.
    #[test]
    fn tiny_widths() {
        let f = fixture(&["Works"], "main");
        let lines = two_lines("triangle");
        let input = |w| text(&lay(&lines, &f, &opts(w)).pop().unwrap().left);
        assert_eq!(input(0), "");
        assert_eq!(input(1), ">");
        assert_eq!(input(2), "\u{276F}");
        // Width 3 (target 2): step 6 already fits the plain `❯`.
        assert_eq!(input(3), "\u{276F}");
        assert!(lay(&lines, &f, &opts(1))[0].minimal);
        assert_eq!(text(&lay(&lines, &f, &opts(3))[0].left), "\u{2026}");
    }

    // 이것을 실패시키는 것: 값이 없는 세그먼트의 구분자가 남거나 겹치는 것, 꼬리가 사라지는 것.
    #[test]
    fn separator_cleanup() {
        let mut f = fixture(&["Works"], "main");
        f.values[idx("git")] = None;
        f.values[idx("status")] = None;
        let out = lay(&two_lines("triangle"), &f, &opts(80));
        let t = text(&out[0].left);
        assert_eq!(t.matches('\u{E0B0}').count(), 1, "{t:?}");
        assert!(t.starts_with(" ~/Works \u{E0B0}"), "{t:?}");
        assert_eq!(t.matches('\u{E0B2}').count(), 1, "{t:?}");
    }

    // 이것을 실패시키는 것: ambiguous=2에서 채움 `─`(2칸)를 그대로 쓰거나 남은 칸을 못 채우는 것.
    #[test]
    fn fill_under_ambiguous_two() {
        let f = fixture(&["Works"], "main");
        let t = "{dir}{@fill:line}{time}{@nl}{char}";
        let lines = compile(t, BUILTIN).unwrap();
        let o = Options {
            profile: WidthProfile::new(2, 2).unwrap(),
            ..opts(41)
        };
        let out = lay(&lines, &f, &o);
        let s = text(&out[0].left);
        assert!(!s.contains('\u{2500}') && s.contains("----"), "{s:?}");
        assert_eq!(runs_width(&out[0].left, o.profile), 40);
    }

    // 이것을 실패시키는 것: 4단계의 동점을 줄 위치가 아니라 카탈로그 순서로 고르는 것(`git`이 카탈로그에서 `time`보다 앞),
    // 또는 자른 조각을 흐리게(DIM) 그리지 않는 것.
    #[test]
    fn step4_cuts_the_leftmost_of_equal_widths() {
        let mut f = fixture(&["Works"], "main");
        f.values[idx("time")] = value("time", "aaaaaa", &[]);
        f.values[idx("git")] = value("git", "bbbbbb", &[]);
        f.setup[idx("git")].methods = &[];
        let lines = compile("{time} {git}{@nl}{char}", BUILTIN).unwrap();
        let out = lay(&lines, &f, &opts(11));
        assert_eq!(text(&out[0].left), "aa\u{2026} bbbbbb");
        let cut = out[0]
            .left
            .iter()
            .find(|r| r.text.contains('\u{2026}'))
            .unwrap();
        assert_ne!(cut.style.attrs & DIM, 0, "{cut:?}");
    }

    // 이것을 실패시키는 것: 조각마다 잰 폭만 믿는 것. `#` 뒤에 U+FE0F로 시작하는 값이 오면 터미널은 둘을
    // 2칸 이모지 하나로 읽으므로, 이어 붙인 폭이 목표 폭을 넘는다(`join_risk`가 0을 돌려주면 폭 5에서 실패).
    #[test]
    fn a_joining_value_never_widens_the_line() {
        let mut f = fixture(&["Works"], "main");
        f.values[idx("git")] = value("git", "\u{FE0F}abc", &[]);
        f.setup[idx("git")].methods = &[];
        let lines = compile("#{git}{@nl}{char}", BUILTIN).unwrap();
        for w in 0..=12 {
            assert_fits(&lay(&lines, &f, &opts(w)), &opts(w), "joined");
        }
        assert_eq!(join_risk("\u{FE0F}abc"), 1);
        assert_eq!(join_risk("\u{0301}\u{200D}x"), 1);
        assert_eq!(join_risk("\u{1F3F3}\u{FE0F}"), 0);
        assert_eq!(join_risk("abc"), 0);
    }

    // 이것을 실패시키는 것: 공개 필드로 만든 어긋난 입력에서 색인 패닉이 나는 것. `values`·`facts`·`setup`이
    // 카탈로그보다 짧은 것, 다른 카탈로그로 컴파일한 줄, 선언보다 필드가 적은 값, 범위 밖 band 순서, 빈 variants.
    #[test]
    fn ragged_inputs_do_not_panic() {
        let lines = compile(
            "{@group}{git.ahead}{@end}{dir:block}{@sep:round}{git:block}{venv}{@fill:dot}{time}{@nl}{char}",
            BUILTIN,
        )
        .unwrap();
        let values = vec![
            Some(Value::new(b"x", Vec::new())),
            None,
            Some(Value::new(b"y", Vec::new())),
            Some(Value::new(b"main", Vec::new())),
        ];
        let facts = vec![None];
        // Shortened segments read `facts` past its end.
        let setup = [SegmentSetup {
            priority: 1,
            required: false,
            methods: BRANCH_METHODS,
            when: When::Always,
        }; 4];
        for catalog in [BUILTIN, &BUILTIN[..3]] {
            let inp = Inputs {
                catalog,
                values: &values,
                facts: &facts,
                setup: &setup,
            };
            for w in 0..=40 {
                let o = opts(w);
                assert_fits(
                    &layout(core::slice::from_ref(&lines), &[], &[], &inp, &o),
                    &o,
                    "ragged",
                );
                assert_fits(
                    &layout(
                        core::slice::from_ref(&lines),
                        &[Band {
                            min_cols: None,
                            max_cols: None,
                            order: None,
                        }],
                        &[3],
                        &inp,
                        &o,
                    ),
                    &o,
                    "band",
                );
                // Band 0 has no variant: the default layout is used.
                let out = layout(
                    core::slice::from_ref(&lines),
                    &[Band {
                        min_cols: None,
                        max_cols: None,
                        order: None,
                    }],
                    &[0],
                    &inp,
                    &o,
                );
                assert_eq!(out.len(), 2);
                assert_fits(&out, &o, "variant");
                assert!(layout(&[], &[], &[], &inp, &o).is_empty());
            }
        }
    }

    // 이것을 실패시키는 것: 채움 글리프가 어떤 세트·프로필에서 1칸이 아닌 것(채움은 `gap`개를 이어 붙이므로 칸 수가 어긋난다).
    #[test]
    fn fill_glyphs_are_one_cell() {
        for kind in [FillKind::Space, FillKind::Dot, FillKind::Line] {
            for set in [
                IconSet::Nerd,
                IconSet::Light,
                IconSet::Unicode,
                IconSet::Ascii,
            ] {
                for (a, e) in [(1, 1), (1, 2), (2, 1), (2, 2)] {
                    let o = Options {
                        profile: WidthProfile::new(a, e).unwrap(),
                        icons: set,
                        ..opts(80)
                    };
                    let g = icon_glyph(kind.icon(), &o);
                    assert_eq!(
                        (g.width, str_width(g.text, o.profile)),
                        (1, 1),
                        "{kind:?} {set:?} {a} {e}"
                    );
                }
            }
        }
    }

    fn one(t: &str, f: &Fixture, w: u16) -> Vec<LaidLine> {
        lay(&compile(t, BUILTIN).unwrap(), f, &opts(w))
    }

    // 이것을 실패시키는 것: 구분자가 꼬리로 합쳐질 때 종류만 꼬리로 바꾸고 글리프는 구분자의 것을 남기는 것,
    // 블록이 하나도 남지 않은 머리를 남기는 것, 앞 내용 없는 구분자나 머리 바로 뒤 구분자를 남기는 것.
    #[test]
    fn merged_separator_draws_the_tail() {
        let mut f = fixture(&["Works"], "main");
        f.values[idx("git")] = None;
        let t = "{dir:block}{@tail:triangle} {@head:round}{git:block}{@sep:triangle}{status:block}{@nl}{char}";
        let s = text(&one(t, &f, 80)[0].left);
        assert_eq!(s, " ~/Works \u{E0B0} \u{E0B6} 1 ", "{s:?}");
        let mut f = fixture(&["Works"], "main");
        f.values[idx("time")] = None;
        let t = "{dir}{@fill}{@head:triangle}{status:block}{@sep:triangle}{time:block}{@tail:round}{@nl}{char}";
        let s = text(&one(t, &f, 80)[0].left);
        assert!(s.ends_with(" 1 \u{E0B4}"), "{s:?}");
        assert_eq!(s.matches('\u{E0B2}').count(), 1, "{s:?}");
        // Nothing visible on the right: the head goes too.
        f.values[idx("status")] = None;
        let s = text(&one(t, &f, 80)[0].left);
        assert!(!s.contains('\u{E0B2}') && !s.contains('\u{E0B4}'), "{s:?}");
        // A separator with nothing before it goes.
        f.values[idx("git")] = None;
        let s = text(&one("{git:block}{@sep:triangle}{dir:block}{@nl}{char}", &f, 80)[0].left);
        assert_eq!(s, " ~/Works ", "{s:?}");
    }

    // 이것을 실패시키는 것: 왼쪽 구분자의 글자색·배경을 앞뒤 블록과 바꿔 칠하는 것.
    #[test]
    fn left_separator_takes_the_blocks_around_it() {
        let f = fixture(&["Works"], "main");
        let out = lay(&two_lines("triangle"), &f, &opts(80));
        let sep = out[0].left.iter().find(|r| r.text == "\u{E0B0}").unwrap();
        assert_eq!(sep.style.fg, Color::Block(tok("path")));
        assert_eq!(sep.style.bg, Color::Block(tok("git.branch")));
    }

    // 이것을 실패시키는 것: 조건 묶음의 보임 판정(안의 필드가 비면 숨김)이 틀리는 것.
    #[test]
    fn group_hides_with_its_references() {
        let mut f = fixture(&["Works"], "main");
        let t = "{dir}{@group} +{git.ahead}{@end}{@nl}{char}";
        assert_eq!(text(&one(t, &f, 80)[0].left), "~/Works +2");
        f.values[idx("git")] = value(
            "git",
            "main",
            &[(
                "ahead",
                FieldValue::Count {
                    n: 0,
                    saturated: false,
                },
            )],
        );
        assert_eq!(text(&one(t, &f, 80)[0].left), "~/Works");
        f.values[idx("git")] = None;
        assert_eq!(text(&one(t, &f, 80)[0].left), "~/Works");
    }

    // 이것을 실패시키는 것: 1단계에서 오른쪽 값을 왼쪽 경로보다 먼저 줄이는 것(사용자 결정 2026-10-02).
    #[test]
    fn step1_shortens_left_before_right() {
        let mut f = fixture(
            &["Works", "AiScream", "themes"],
            "feature/very-long-branch-name",
        );
        f.setup[idx("dir")].methods = &[Method::Repo];
        let t = "{dir}{@fill}{git}{@nl}{char}";
        // 23 + 29 = 52 cells; "themes" saves 17, the branch cut to 24 saves 5.
        let s = text(&one(t, &f, 48)[0].left);
        assert!(
            s.starts_with("themes ") && s.ends_with("feature/very-long-branch-name"),
            "{s:?}"
        );
    }

    // 이것을 실패시키는 것: 2단계가 우선순위 높은 것부터 숨기거나, 동점에서 왼쪽 것을 먼저 숨기는 것.
    #[test]
    fn step2_hides_low_priority_then_rightmost() {
        let mut f = fixture(&["Works"], "main");
        f.values[idx("status")] = value("status", "E", &[]);
        let t = "{dir}{@fill}{status} {time}{@nl}{char}";
        // "~/Works" 7 + "E 12:34" 7: target 13 drops one right segment.
        let shown = |f: &Fixture| {
            let s = text(&one(t, f, 14)[0].left);
            (s.contains('E'), s.contains("12:34"))
        };
        assert_eq!(shown(&f), (true, false));
        f.setup[idx("time")].priority = 50;
        assert_eq!(shown(&f), (false, true));
        f.setup[idx("time")].priority = 10;
        assert_eq!(shown(&f), (true, false));
    }

    // 이것을 실패시키는 것: 실패한 `char`의 색이나 기호 중 하나만 바뀌는 것, vi 명령 모드 기호를 쓰지 않는 것.
    #[test]
    fn char_failure_changes_glyph_and_color() {
        let mut f = fixture(&["Works"], "main");
        f.values[idx("char")] = value("char", "", &[("failed", FieldValue::Bool(true))]);
        let out = one("{dir}{@nl}{char}", &f, 80);
        assert_eq!(out[1].left[0].text, "\u{2717}");
        assert_eq!(out[1].left[0].style.fg, Color::Text(tok("prompt.err")));
        f.values[idx("char")] = value("char", "", &[("vicmd", FieldValue::Bool(true))]);
        let out = one("{dir}{@nl}{char}", &f, 80);
        assert_eq!(out[1].left[0].text, "\u{276E}");
        assert_eq!(out[1].left[0].style.fg, Color::Text(tok("prompt.ok")));
    }

    // 이것을 실패시키는 것: `when = always`의 첫 방식을 넘치지 않을 때 적용하지 않는 것.
    #[test]
    fn always_shortens_even_when_it_fits() {
        let mut f = fixture(&["Works", "AiScream", "themes"], "main");
        f.setup[idx("dir")].when = When::Always;
        assert_eq!(text(&one("{dir}{@nl}{char}", &f, 80)[0].left), "themes");
    }

    // 이것을 실패시키는 것: 4단계가 경로의 앞을 남기는 것(경로는 끝, 다른 값은 앞을 남긴다),
    // `char` 없는 줄의 7단계가 `>`+공백이 아닌 것.
    #[test]
    fn step4_keeps_the_end_of_a_path() {
        let f = fixture(&["folder"], "main");
        assert_eq!(text(&one("{dir}{@nl}{char}", &f, 5)[0].left), "\u{2026}der");
        assert_eq!(text(&one("abc{dir}", &f, 3)[0].left), "> ");
    }

    // 이것을 실패시키는 것: 4단계가 이미 줄인 조각을 이어 붙여 다시 자르면서 흐림 표시를 잃는 것.
    #[test]
    fn step4_keeps_dim_marks_of_whole_pieces() {
        let mut f = fixture(&["Works", "AiScream", "themes"], "main");
        f.setup[idx("dir")].methods = &[Method::Abbrev(1)];
        let out = one("{dir}{@nl}{char}", &f, 10);
        assert_eq!(text(&out[0].left), "\u{2026}A/themes");
        assert_eq!(out[0].left[0].text, "\u{2026}A");
        assert_ne!(out[0].left[0].style.attrs & DIM, 0);
        assert_eq!(out[0].left[1].style.attrs & DIM, 0);
    }

    // 이것을 실패시키는 것: `layout_into`가 이미 있는 줄·run 버퍼를 다시 쓰지 않고 새로 잡는 것.
    #[test]
    fn layout_into_reuses_buffers() {
        let f = fixture(&["Works"], "main");
        let lines = [two_lines("triangle")];
        let mut out = Vec::new();
        layout_into(&lines, &[], &[], &f.inputs(), &opts(80), &mut out);
        let before = (
            out.as_ptr(),
            out[0].left.as_ptr(),
            out[0].left[0].text.as_ptr(),
        );
        layout_into(&lines, &[], &[], &f.inputs(), &opts(80), &mut out);
        assert_eq!(
            before,
            (
                out.as_ptr(),
                out[0].left.as_ptr(),
                out[0].left[0].text.as_ptr()
            )
        );
    }
}
