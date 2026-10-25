//! Line assembly and the seven overflow steps (spec section 3 "한 줄 조립과
//! 넘칠 때", "마지막 칸은 비운다"). left + fill + right = target width; when a
//! line overflows the steps apply in order and stop as soon as it fits, so a
//! line never overflows at any width from 0 up.
//!
//! Widths are those of the joined text, as a terminal reads it (a `#` then
//! U+FE0F is one 2-cell keycap emoji). Each drawn item is measured once.
//! Where no border between items may join (`may_join`, decided on the two
//! code points at the border) the widths add up; a side with a border that
//! may join is measured on its joined text instead.
//!
//! Bounds. A segment's text is read, shortened and measured once per line,
//! however often the template repeats it. One check walks the line's M
//! nodes once and makes at most one item per node, into buffers allocated
//! once per line at the size of each side; the steps make O(N) checks for
//! N segment references (one per segment and side of the fill, so at most
//! twice the catalog size). Two caps keep the overflow steps finite for any
//! input: a shortened text has at most `SEG_PIECES_MAX` pieces (a method
//! with more is skipped, like an invalid one), and a line with more than
//! `LINE_BYTES_MAX` bytes of text does not fit, so the steps go on, down to
//! the minimal prompt if need be. Before it runs, a shortening method sure
//! to break those caps is skipped (`too_big`), only the first
//! `METHODS_MAX` methods run, and a path over `PATH_BYTES_MAX` is never
//! read. The largest inputs the limits allow (`shorten::MAX_STEPS` folders
//! drawn 819 times, folder names of 3 KB, a fill 65535 columns wide) peak
//! under 1 MB (test `the_largest_inputs_stay_small`).
use crate::bands::{Band, select};
use crate::color::palette::token_index;
use crate::color::sgr::{Color, DIM, Style};
use crate::field::{FieldValue, SegmentDecl, Value};
use crate::icons::{self, IconSet};
use crate::recorder::{HideReason, Recorder, Step};
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
    /// Never hidden by steps 2 and 5 (`dir`, `char`); step 3 hides the
    /// whole right side regardless.
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

/// Most pieces a shortened text may have. A method whose result has more
/// (`abbrev` or `unique` on a path deeper than 511 steps) is skipped like an
/// invalid result; step 4 adds at most one piece to a text it cuts.
pub const SEG_PIECES_MAX: usize = 1024;

/// Most bytes of text one laid line may hold, fill included. A line over it
/// does not fit, whatever its width, so the overflow steps go on; the
/// minimal prompt is a few bytes. Two lines and their SGR stay well inside
/// a record (`record::RECORD_MAX_BYTES`, 64 KiB).
pub const LINE_BYTES_MAX: usize = 16 * 1024;

/// Most methods of a segment's chain that run, in order; the rest are
/// ignored (there are six kinds, so a real chain is shorter).
pub const METHODS_MAX: usize = 8;

/// Most bytes of path text layout reads. Every path method checks its
/// result against the whole path text, and drawing it unshortened needs it
/// too, so a longer path is never read: it is drawn as a lone dim ellipsis
/// and step 4 can only keep that. A path of `shorten::MAX_STEPS` ordinary
/// folder names (about 50 KiB) stays under it.
pub const PATH_BYTES_MAX: usize = 64 * 1024;

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
/// as a terminal reads it.
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

/// Byte length of the first grapheme of `s`.
fn head_len(s: &str) -> usize {
    s.graphemes(true).next().map_or(0, |s| s.len())
}

/// Byte offset where the last grapheme of `s` starts.
fn tail_at(s: &str) -> usize {
    s.grapheme_indices(true).next_back().map_or(0, |(i, _)| i)
}

/// `buf` cleared and at least `n` bytes long, allocated anew (never grown)
/// when it is shorter.
fn scratch(buf: &mut String, n: usize) {
    buf.clear();
    if buf.capacity() < n {
        *buf = String::with_capacity(n);
    }
}

/// Do `x` then `y` make one grapheme on their own?
fn pair_joins(x: char, y: char) -> bool {
    let mut buf = [0u8; 8];
    let n = x.encode_utf8(&mut buf).len();
    let m = y.encode_utf8(&mut buf[n..]).len();
    core::str::from_utf8(&buf[..n + m]).is_ok_and(|s| s.graphemes(true).nth(1).is_none())
}

/// Can a grapheme ending in `a` join one starting with `b`? When false,
/// any `t` ending in `a` and `h` starting with `b` measure w(t) + w(h).
/// Below U+0300 no code point joins anything (CR and LF never reach a
/// line). Otherwise the pair decides, except for two rules that look
/// further back, an emoji ZWJ sequence (GB11) and an Indic conjunct (GB9c):
/// both need an `a` that extends any base (a ZWJ, a linker, another mark),
/// as `A` then `a` tells. A "may" that does not join only costs a
/// measurement. A search over every code point on either side of the
/// border found no width change where this says no (report E3, round 1).
fn may_join(a: char, b: char) -> bool {
    if u32::from(a) < 0x300 && u32::from(b) < 0x300 {
        return false;
    }
    if pair_joins(a, b) {
        return true;
    }
    pair_joins('A', a)
}

/// Cells gained (or lost) where `t`, the last grapheme drawn, meets `h`, the
/// first one after it: w(t + h) − w(t) − w(h); zero when they stay two
/// graphemes.
fn join_delta(t: &str, h: &str, buf: &mut String, p: WidthProfile) -> i64 {
    let (Some(a), Some(b)) = (t.chars().next_back(), h.chars().next()) else {
        return 0;
    };
    if !may_join(a, b) {
        return 0;
    }
    measure_join(t, h, buf, p)
}

fn measure_join(t: &str, h: &str, buf: &mut String, p: WidthProfile) -> i64 {
    scratch(buf, t.len() + h.len());
    buf.push_str(t);
    buf.push_str(h);
    let (wj, wt, wh) = (str_width(buf, p), str_width(t, p), str_width(h, p));
    i64::from(wj) - i64::from(wt) - i64::from(wh)
}

/// `may_join` for the few code point pairs a line repeats at its borders
/// (a separator glyph and a padding space), remembered per line.
struct PairMemo([(char, char, bool); 32]);

impl PairMemo {
    fn may_join(&mut self, a: char, b: char) -> bool {
        // Multiplicative hashing: a pair and its reverse (space then glyph,
        // glyph then space) land in different slots.
        let h = (u32::from(a).wrapping_mul(0x9E37_79B9) ^ u32::from(b)).wrapping_mul(0x85EB_CA6B);
        let slot = &mut self.0[(h >> 27) as usize];
        if slot.0 != a || slot.1 != b {
            *slot = (a, b, may_join(a, b));
        }
        slot.2
    }
}

/// Adds a signed join delta to a width (never below 0).
fn add(w: u32, d: i64) -> u32 {
    u32::try_from((i64::from(w) + d).max(0)).unwrap_or(u32::MAX)
}

/// A segment's text measured alone and padded for a block.
#[derive(Clone, Copy, Default)]
struct TextM {
    width: u32,
    /// Width of `" " + text + " "`.
    padded: u32,
    /// First grapheme's length and last grapheme's start.
    head: usize,
    tail: usize,
}

fn text_m(t: &str, buf: &mut String, p: WidthProfile) -> TextM {
    let width = str_width(t, p);
    let (head, tail) = (head_len(t), tail_at(t));
    let dh = join_delta(" ", &t[..head], buf, p);
    let dt = join_delta(&t[tail..], " ", buf, p);
    TextM {
        width,
        padded: add(width.saturating_add(2), dh + dt),
        head,
        tail,
    }
}

fn tok(name: &str) -> u16 {
    token_index(name)
        .and_then(|i| u16::try_from(i).ok())
        .unwrap_or(0)
}

/// A segment role's token; a name that is not a token (a declaration from
/// outside) gets the default color rather than an arbitrary token.
fn role_tok(name: &str) -> Option<u16> {
    token_index(name).and_then(|i| u16::try_from(i).ok())
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
    /// A field node, by node index (its text is in `Lay::fields`).
    Field(usize),
    /// An icon or a separator glyph.
    Glyph(&'static str),
    /// Segment `.0`'s current text, padded for a block when `.1`.
    Seg(usize, bool),
}

/// One drawn thing in a line side: one per template node at most. Content
/// with no text is never made, so it never counts as content.
#[derive(Clone, Copy)]
struct Item {
    kind: Kind,
    /// Head and separator: a block follows before the next head or tail,
    /// or a flat separator has plain content on both sides (see `clean`).
    ok: bool,
    /// Cells of its text alone.
    width: u32,
    bytes: u32,
    /// Background of the block this content draws on (`Color::Default`
    /// for a role that names no token).
    block: Option<Color>,
    style: Style,
    src: Src,
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

/// A shortened text: the pieces joined, and where each ends.
struct Short {
    text: String,
    /// End byte of each piece and whether it was shortened (drawn dim).
    ends: Vec<(usize, bool)>,
}

/// Per catalog entry, for one line.
struct Slot {
    /// Has a value (and an index within `Inputs::values`).
    present: bool,
    /// Hidden on the left side, on the right side.
    hidden: [bool; 2],
    /// Appears in this line as a segment (not only as fields).
    in_line: bool,
    /// Step 4 cannot cut it further.
    exhausted: bool,
    base: Base,
    short: Option<Short>,
    m: TextM,
    /// Color token of its text (plain) or background (block); None for a
    /// role that names no token, drawn in the default color.
    role: Option<u16>,
    /// Its step entry on each side, if it is referenced there.
    entry: [Option<usize>; 2],
}

/// A segment referenced on one side of the fill (by a segment or a field
/// node), at its first reference there. A segment on both sides has two.
#[derive(Clone, Copy)]
struct Entry {
    seg: usize,
    right: bool,
    pos: u32,
    /// A segment node (not only fields) on this side: steps 1 and 4 apply.
    text: bool,
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
    /// Text or field: first grapheme's length, last grapheme's start.
    head: usize,
    tail: usize,
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

/// Buffers of the fit checks, allocated once per line at the most a walk
/// can need: one item per node of each side.
struct Bufs {
    left: Vec<Item>,
    right: Vec<Item>,
    /// `refs[k]`: visible segment and field references in `nodes[..k]`.
    refs: Vec<u32>,
    styles: Vec<Style>,
    /// Joined edge graphemes being measured.
    join: String,
    pairs: PairMemo,
}

/// A check's result.
#[derive(Clone, Copy, Default)]
struct Fit {
    /// Cells of the left and right side, each joined within itself.
    l: u32,
    r: u32,
    /// Cells of the whole line (upper lines: left and right touching).
    cells: u32,
    bytes: usize,
}

/// One line being laid out.
struct Lay<'l, 'i> {
    nodes: &'l [Node],
    inp: &'l Inputs<'i>,
    o: &'l Options,
    upper: bool,
    target: u32,
    /// Index of the fill node.
    fill: Option<usize>,
    /// Its glyph (one cell, test `fill_glyphs_are_one_cell`) and kind.
    fill_glyph: &'static str,
    fill_kind: FillKind,
    info: Vec<Info>,
    fields: String,
    slots: Vec<Slot>,
    entries: Vec<Entry>,
    seps: SepTable,
    block_text: u16,
    char_seg: Option<usize>,
    /// Step 6: no backgrounds, heads, tails or non-flat separators.
    plain: bool,
}

impl<'l, 'i> Lay<'l, 'i> {
    fn new(
        line: &'l CompiledLine,
        upper: bool,
        inp: &'l Inputs<'i>,
        o: &'l Options,
        join: &mut String,
    ) -> Self {
        let p = o.profile;
        let nodes = line.nodes();
        let fill = line.fill();
        let fill_kind = fill
            .and_then(|i| match nodes.get(i) {
                Some(Node::Fill(f)) => Some(*f),
                _ => None,
            })
            .unwrap_or(FillKind::Space);
        let cat = inp.catalog;
        let char_seg = cat.iter().position(|d| d.id == "char");
        let mut slots: Vec<Slot> = Vec::with_capacity(cat.len());
        for (i, d) in cat.iter().enumerate() {
            slots.push(Slot {
                present: matches!(inp.values.get(i), Some(Some(_))),
                hidden: [false; 2],
                in_line: false,
                exhausted: false,
                base: Base::Glyph(""),
                short: None,
                m: TextM::default(),
                role: role_tok(d.role),
                entry: [None; 2],
            });
        }
        // Step entries, and the exact size of the field text.
        let mut entries: Vec<Entry> = Vec::with_capacity(nodes.len().min(2 * cat.len()));
        let mut field_bytes = 0usize;
        for (k, n) in nodes.iter().enumerate() {
            let right = fill.is_some_and(|f| k > f);
            let (seg, text) = match *n {
                Node::Segment { seg, .. } => (usize::from(seg), true),
                Node::Field { seg, field } => {
                    // Every drawn form is at most 24 bytes but text.
                    field_bytes += match field_of(inp, usize::from(seg), usize::from(field)) {
                        Some(FieldValue::Text(t)) => t.as_str().len(),
                        _ => 24,
                    };
                    (usize::from(seg), false)
                }
                _ => continue,
            };
            let Some(slot) = slots.get_mut(seg) else {
                continue;
            };
            slot.in_line |= text;
            let side = usize::from(right);
            match slot.entry[side] {
                Some(e) => entries[e].text |= text,
                None => {
                    slot.entry[side] = Some(entries.len());
                    entries.push(Entry {
                        seg,
                        right,
                        pos: u32::try_from(k).unwrap_or(u32::MAX),
                        text,
                    });
                }
            }
        }
        // Base text of each segment drawn in the line, measured once.
        for (s, slot) in slots.iter_mut().enumerate() {
            let Some(Some(v)) = inp.values.get(s) else {
                continue;
            };
            if !slot.in_line {
                continue;
            }
            let decl = &cat[s];
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
                    slot.role = role_tok("prompt.err");
                }
            } else if let Some(Some(f)) = inp.facts.get(s) {
                if f.display_len() > PATH_BYTES_MAX {
                    let e = ellipsis(p, 1);
                    let mut short = Short {
                        text: e.into(),
                        ends: alloc::vec![(e.len(), true)],
                    };
                    if f.readonly() == Some(true) {
                        let prefix = alloc::format!("{} ", icons::readonly_marker(o.icons, p));
                        short.text.insert_str(0, &prefix);
                        short.ends[0].0 += prefix.len();
                        short.ends.insert(0, (prefix.len(), false));
                    }
                    slot.m = text_m(&short.text, join, p);
                    slot.short = Some(short);
                    continue;
                }
                let mut text = f.display();
                if f.readonly() == Some(true) {
                    text.insert(0, ' ');
                    text.insert_str(0, icons::readonly_marker(o.icons, p));
                }
                slot.base = Base::Owned(text);
            } else {
                slot.base = Base::Value;
            }
            slot.m = text_m(base_text(slot, v), join, p);
        }
        // Node widths and field text, once.
        let mut fields = String::with_capacity(field_bytes);
        let mut info: Vec<Info> = Vec::with_capacity(nodes.len());
        for n in nodes {
            let mut x = Info::default();
            match *n {
                Node::Text(ref t) => {
                    x.width = str_width(t, p);
                    (x.head, x.tail) = (head_len(t), tail_at(t));
                }
                Node::Icon(i) => {
                    // `compile` stores only indices into ICONS.
                    let r = icons::ICONS
                        .get(usize::from(i))
                        .map(|ic| icons::resolve(ic, o.icons, p));
                    x.glyph = r.map_or("", |r| r.text);
                    x.width = str_width(x.glyph, p);
                }
                Node::Field { seg, field } => {
                    if let Some(f) = inp
                        .values
                        .get(usize::from(seg))
                        .and_then(|v| v.as_ref())
                        .and_then(|v| v.fields.get(usize::from(field)))
                    {
                        x.a = fields.len();
                        f.write_to(&mut fields);
                        x.b = fields.len();
                        x.filled = !f.is_empty_for_group();
                        let t = &fields[x.a..x.b];
                        x.width = str_width(t, p);
                        (x.head, x.tail) = (head_len(t), tail_at(t));
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
            upper,
            target: target(o),
            fill,
            fill_glyph: icon_glyph(fill_kind.icon(), o).text,
            fill_kind,
            info,
            fields,
            slots,
            entries,
            seps,
            block_text: tok("block.text"),
            char_seg,
            plain: false,
        }
    }

    fn new_bufs(&self, join: String) -> Bufs {
        let left = self.fill.unwrap_or(self.nodes.len());
        Bufs {
            left: Vec::with_capacity(left),
            right: Vec::with_capacity(self.nodes.len() - left),
            refs: Vec::with_capacity(self.nodes.len() + 1),
            styles: Vec::with_capacity(MAX_DEPTH + 1),
            join,
            // NUL never reaches a line, so the empty slots never match.
            pairs: PairMemo([('\0', '\0', false); 32]),
        }
    }

    fn setup(&self, s: usize) -> SegmentSetup<'i> {
        self.inp.setup.get(s).copied().unwrap_or(NO_SETUP)
    }

    fn visible(&self, s: usize, right: bool) -> bool {
        self.slots
            .get(s)
            .is_some_and(|x| x.present && !x.hidden[usize::from(right)])
    }

    fn value(&self, s: usize) -> Option<&'i Value> {
        self.inp.values.get(s).and_then(|v| v.as_ref())
    }

    fn base_str(&self, s: usize) -> &str {
        match self.value(s) {
            Some(v) => base_text(&self.slots[s], v),
            None => "",
        }
    }

    /// Segment `s`'s current text (shortened or not).
    fn seg_text(&self, s: usize) -> &str {
        match &self.slots[s].short {
            Some(sh) => &sh.text,
            None => self.base_str(s),
        }
    }

    fn source(&self, s: usize) -> Source<'_> {
        match self.inp.facts.get(s) {
            Some(Some(f)) => Source::Path(f),
            _ => Source::Text(self.base_str(s)),
        }
    }

    fn readonly_prefix(&self, s: usize) -> Option<String> {
        let facts = self.inp.facts.get(s)?.as_ref()?;
        if facts.readonly() != Some(true) {
            return None;
        }
        let mut prefix = String::from(icons::readonly_marker(self.o.icons, self.o.profile));
        prefix.push(' ');
        Some(prefix)
    }

    /// The methods' first result that fits `budget`, else the narrowest, as
    /// `shorten` picks, over the first `METHODS_MAX` methods. A method sure
    /// to give more than `SEG_PIECES_MAX` pieces or `LINE_BYTES_MAX` bytes
    /// is not run (`too_big`); a result over the piece cap is dropped too.
    /// A path over `PATH_BYTES_MAX` is not shortened at all. The method
    /// picked is recorded for line `n`.
    fn shorten_capped<R: Recorder>(
        &self,
        s: usize,
        methods: &[Method],
        budget: u32,
        n: usize,
        rec: &mut R,
    ) -> Option<Vec<Piece>> {
        if matches!(self.inp.facts.get(s), Some(Some(f)) if f.display_len() > PATH_BYTES_MAX) {
            return None;
        }
        let prefix = self.readonly_prefix(s);
        let prefix_width = prefix
            .as_deref()
            .map_or(0, |t| str_width(t, self.o.profile));
        let budget = budget.saturating_sub(prefix_width);
        let mut best: Option<(Vec<Piece>, u32)> = None;
        let mut best_at = 0;
        for (at, m) in methods.iter().take(METHODS_MAX).enumerate() {
            if too_big(*m, self.source(s)) {
                continue;
            }
            let Some((mut res, _, w)) = shorten(
                self.source(s),
                core::slice::from_ref(m),
                budget,
                self.o.profile,
            ) else {
                continue;
            };
            if let Some(prefix) = &prefix {
                res.pieces.insert(
                    0,
                    Piece {
                        text: prefix.clone(),
                        shortened: false,
                    },
                );
            }
            if res.pieces.len() > SEG_PIECES_MAX {
                continue;
            }
            if w <= budget {
                if R::ENABLED {
                    rec.shortened(n, s, at);
                }
                return Some(res.pieces);
            }
            if best.as_ref().is_none_or(|b| w < b.1) {
                if R::ENABLED {
                    best_at = at;
                }
                best = Some((res.pieces, w));
            }
        }
        let (pieces, _) = best?;
        if R::ENABLED {
            rec.shortened(n, s, best_at);
        }
        Some(pieces)
    }

    /// Segment `s`'s current text as pieces (one, unshortened, before any
    /// shortening).
    fn pieces(&self, s: usize) -> Vec<(&str, bool)> {
        match &self.slots[s].short {
            Some(sh) => {
                let mut start = 0;
                sh.ends
                    .iter()
                    .map(|&(end, d)| {
                        let piece = (&sh.text[start..end], d);
                        start = end;
                        piece
                    })
                    .collect()
            }
            None => alloc::vec![(self.base_str(s), false)],
        }
    }

    fn put_short(&mut self, s: usize, short: Short, join: &mut String) {
        self.slots[s].m = text_m(&short.text, join, self.o.profile);
        self.slots[s].short = Some(short);
    }

    /// Items of both sides for the current state, cleaned up.
    fn walk(&self, b: &mut Bufs) {
        let Bufs {
            left,
            right,
            refs,
            styles,
            ..
        } = b;
        left.clear();
        right.clear();
        refs.clear();
        let mut acc = 0u32;
        refs.push(0);
        for (k, n) in self.nodes.iter().enumerate() {
            let on_right = self.fill.is_some_and(|f| k > f);
            acc += u32::from(match *n {
                Node::Segment { seg, .. } => {
                    let s = usize::from(seg);
                    // Empty displays cannot keep a group's literals visible.
                    // Direct fields keep their own group semantics below.
                    self.visible(s, on_right) && self.slots[s].m.head != 0
                }
                Node::Field { seg, .. } => {
                    self.visible(usize::from(seg), on_right) && self.info[k].filled
                }
                _ => false,
            });
            refs.push(acc);
        }
        styles.clear();
        let mut on_right = false;
        let mut k = 0;
        while k < self.nodes.len() {
            // Pushes stay within capacity: one item per node of this side.
            let side: &mut Vec<Item> = if on_right { &mut *right } else { &mut *left };
            let plain_style = self.unblock(with(styles, Style::default()));
            let content = |width, bytes: usize, src| Item {
                kind: Kind::Content,
                ok: false,
                width,
                bytes: u32::try_from(bytes).unwrap_or(u32::MAX),
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
                Node::Text(t) => side.push(content(self.info[k].width, t.len(), Src::Text(k))),
                Node::Icon(_) => {
                    let g = self.info[k].glyph;
                    if !g.is_empty() {
                        side.push(content(self.info[k].width, g.len(), Src::Glyph(g)));
                    }
                }
                Node::Field { seg, .. } => {
                    let x = self.info[k];
                    if self.visible(usize::from(*seg), on_right) && x.b > x.a {
                        side.push(content(x.width, x.b - x.a, Src::Field(k)));
                    }
                }
                Node::Segment { seg, mode } => {
                    let s = usize::from(*seg);
                    if self.visible(s, on_right) {
                        self.push_segment(side, styles, s, *mode == Mode::Block && !self.plain);
                    }
                }
                Node::Sep(shape) | Node::Head(shape) | Node::Tail(shape) => {
                    if !self.plain || matches!(self.nodes[k], Node::Sep(Shape::Flat)) {
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
                            ..content(width, glyph.len(), Src::Glyph(glyph))
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

    /// Records the conditional groups of the final state that vanished
    /// because fields of visible segments in them are empty (`refs` from the
    /// last walk). Each segment once per group; nested groups go with the
    /// outer one.
    fn record_empty_groups<R: Recorder>(&self, n: usize, refs: &[u32], r: &mut R) {
        let mut k = 0;
        while k < self.nodes.len() {
            let Node::Group { len } = self.nodes[k] else {
                k += 1;
                continue;
            };
            let end = (k + 1).saturating_add(len as usize).min(self.nodes.len());
            if refs[end] != refs[k + 1] {
                k += 1;
                continue;
            }
            let right = self.fill.is_some_and(|f| k > f);
            for j in k + 1..end {
                let Node::Field { seg, .. } = self.nodes[j] else {
                    continue;
                };
                let s = usize::from(seg);
                let again = self.nodes[k + 1..j]
                    .iter()
                    .any(|x| matches!(*x, Node::Field { seg: o, .. } if o == seg));
                if self.visible(s, right) && !again {
                    r.hidden(n, s, HideReason::EmptyGroup);
                }
            }
            k = end;
        }
    }

    /// Step 6 draws no background at all, a `{@style:bg=…}` one included;
    /// text color and attributes stay (ruling C, 2026-10-13).
    fn unblock(&self, mut s: Style) -> Style {
        if self.plain {
            s.bg = Color::Default;
        }
        s
    }

    fn push_segment(&self, side: &mut Vec<Item>, styles: &[Style], s: usize, block: bool) {
        let slot = &self.slots[s];
        // Empty displays (for example, an unborn clean repository) must not
        // create a padded block that keeps adjacent separators visible. This
        // applies to every segment; non-empty displays and direct fields remain
        // unchanged, including a directly referenced exact zero.
        if slot.m.head == 0 {
            return;
        }
        let base = if block {
            Style {
                fg: slot
                    .role
                    .map_or(Color::Text(self.block_text), Color::OnBlock),
                bg: slot.role.map_or(Color::Default, Color::Block),
                attrs: 0,
            }
        } else {
            Style {
                fg: slot.role.map_or(Color::Default, Color::Text),
                bg: Color::Default,
                attrs: 0,
            }
        };
        let bytes = self.seg_text(s).len() + 2 * usize::from(block);
        if bytes == 0 {
            return;
        }
        side.push(Item {
            kind: Kind::Content,
            ok: false,
            width: if block { slot.m.padded } else { slot.m.width },
            bytes: u32::try_from(bytes).unwrap_or(u32::MAX),
            block: block.then(|| slot.role.map_or(Color::Default, Color::Block)),
            style: self.unblock(with(styles, base)),
            src: Src::Seg(s, block),
        });
    }

    fn text(&self, it: &Item) -> &str {
        match it.src {
            Src::Text(k) => match &self.nodes[k] {
                Node::Text(t) => t,
                _ => "",
            },
            Src::Field(k) => &self.fields[self.info[k].a..self.info[k].b],
            Src::Glyph(g) => g,
            Src::Seg(s, _) => self.seg_text(s),
        }
    }

    /// First and last grapheme of an item's drawn text. A block's edges are
    /// its padding spaces: a grapheme the space joins with only extends it
    /// (a mark after it, a prepended letter before it), which changes no
    /// width at the item's border beyond what `TextM::padded` counts.
    fn edges(&self, it: &Item) -> (&str, &str) {
        let t = self.text(it);
        let (head, tail) = match it.src {
            Src::Text(k) | Src::Field(k) => (self.info[k].head, self.info[k].tail),
            Src::Glyph(g) => (head_len(g), tail_at(g)),
            Src::Seg(_, true) => return (" ", " "),
            Src::Seg(s, false) => (self.slots[s].m.head, self.slots[s].m.tail),
        };
        (&t[..head], &t[tail..])
    }

    /// Sum of the items' widths, and whether any border between them may
    /// join (then the sum is not their drawn width).
    fn sum_and_joins(&self, items: &[Item], pairs: &mut PairMemo) -> (u32, bool) {
        let mut w = 0u32;
        let mut joins = false;
        for (i, it) in items.iter().enumerate() {
            w = w.saturating_add(it.width);
            if let Some(prev) = i.checked_sub(1).map(|j| &items[j]) {
                joins |= self.may_join_at(prev, it, pairs);
            }
        }
        (w, joins)
    }

    fn may_join_at(&self, a: &Item, c: &Item, pairs: &mut PairMemo) -> bool {
        match (self.last_char(a), self.first_char(c)) {
            (Some(x), Some(y)) => pairs.may_join(x, y),
            _ => false,
        }
    }

    /// Drawn width of items in a row, measured on their joined text.
    fn joined_width<'a>(
        &self,
        items: impl Iterator<Item = &'a Item> + Clone,
        join: &mut String,
    ) -> u32 {
        scratch(join, items.clone().map(|x| x.bytes as usize).sum());
        for it in items {
            let pad = if matches!(it.src, Src::Seg(_, true)) {
                " "
            } else {
                ""
            };
            join.push_str(pad);
            join.push_str(self.text(it));
            join.push_str(pad);
        }
        str_width(join, self.o.profile)
    }

    fn first_char(&self, it: &Item) -> Option<char> {
        match it.src {
            Src::Seg(_, true) => Some(' '),
            _ => self.text(it).chars().next(),
        }
    }

    fn last_char(&self, it: &Item) -> Option<char> {
        match it.src {
            Src::Seg(_, true) => Some(' '),
            _ => self.text(it).chars().next_back(),
        }
    }

    /// Walks the current state and measures it.
    fn check(&self, b: &mut Bufs) -> Fit {
        self.walk(b);
        let bytes: usize = b
            .left
            .iter()
            .chain(&b.right)
            .map(|x| x.bytes as usize)
            .sum();
        if bytes > LINE_BYTES_MAX {
            // Does not fit whatever the width. The cells are summed without
            // measuring joins over the oversized text, so step 4 sees the
            // cell overflow (often none) rather than a made-up one.
            let cells = b
                .left
                .iter()
                .chain(&b.right)
                .fold(0u32, |w, x| w.saturating_add(x.width));
            return Fit {
                l: 0,
                r: 0,
                cells,
                bytes,
            };
        }
        // Where no border may join, the widths add up; where one may, the
        // side (or, on an upper line whose sides touch there, the whole
        // line) is measured on its joined text, at most LINE_BYTES_MAX.
        let (wl, jl) = self.sum_and_joins(&b.left, &mut b.pairs);
        let (wr, jr) = self.sum_and_joins(&b.right, &mut b.pairs);
        let l = if jl {
            self.joined_width(b.left.iter(), &mut b.join)
        } else {
            wl
        };
        let r = if jr {
            self.joined_width(b.right.iter(), &mut b.join)
        } else {
            wr
        };
        let touch = match (self.upper, b.left.last(), b.right.first()) {
            (true, Some(a), Some(c)) => self.may_join_at(a, c, &mut b.pairs),
            _ => false,
        };
        let cells = if touch {
            self.joined_width(b.left.iter().chain(&b.right), &mut b.join)
        } else {
            l.saturating_add(r)
        };
        // The fill's glyphs are text too (`{@fill:line}` at 65535 columns
        // would be about 192 KiB).
        let bytes = bytes.saturating_add(
            self.fill_count(&b.left, &b.right, l, r, &mut b.join)
                .saturating_mul(self.fill_glyph.len()),
        );
        Fit { l, r, cells, bytes }
    }

    /// Glyphs an upper line's fill draws between cleaned sides `left` and
    /// `right` measuring `l` and `r` cells: what is left of the target once
    /// the joins at both ends of the fill are counted. None without a right
    /// side, and none when the sides already reach the target.
    fn fill_count(
        &self,
        left: &[Item],
        right: &[Item],
        l: u32,
        r: u32,
        join: &mut String,
    ) -> usize {
        let Some(c) = right.first().filter(|_| self.upper) else {
            return 0;
        };
        let (g, p) = (self.fill_glyph, self.o.profile);
        let d1 = left
            .last()
            .map_or(0, |a| join_delta(self.edges(a).1, g, join, p));
        let d2 = join_delta(g, self.edges(c).0, join, p);
        usize::try_from(i64::from(self.target) - i64::from(l) - i64::from(r) - d1 - d2).unwrap_or(0)
    }

    fn fits(&self, f: &Fit) -> bool {
        f.cells <= self.target && f.bytes <= LINE_BYTES_MAX
    }

    /// Number of pieces item `it` is drawn in.
    fn parts(&self, it: &Item) -> usize {
        match it.src {
            Src::Seg(s, _) => self.slots[s].short.as_ref().map_or(1, |sh| sh.ends.len()),
            _ => 1,
        }
    }

    /// Piece `j` of item `items[i]`: style and text as (before, text, after).
    fn part(&self, items: &[Item], i: usize, j: usize, right_side: bool) -> (Style, [&str; 3]) {
        let it = &items[i];
        match it.src {
            Src::Seg(s, padded) => {
                let t = self.seg_text(s);
                let (start, end, sh) = match &self.slots[s].short {
                    Some(short) => {
                        let start = j.checked_sub(1).map_or(0, |p| short.ends[p].0);
                        (start, short.ends[j].0, short.ends[j].1)
                    }
                    None => (0, t.len(), false),
                };
                let last = j + 1 == self.parts(it);
                let style = if sh {
                    Style {
                        attrs: it.style.attrs | DIM,
                        ..it.style
                    }
                } else {
                    it.style
                };
                let pad = |on| if padded && on { " " } else { "" };
                (style, [pad(j == 0), &t[start..end], pad(last)])
            }
            _ => (item_style(items, i, right_side), ["", self.text(it), ""]),
        }
    }

    /// The first non-empty piece at or after piece `j` of item `i`.
    fn next_part(
        &self,
        items: &[Item],
        mut i: usize,
        mut j: usize,
        right_side: bool,
    ) -> Option<(usize, usize)> {
        while i < items.len() {
            if j >= self.parts(&items[i]) {
                (i, j) = (i + 1, 0);
                continue;
            }
            if self
                .part(items, i, j, right_side)
                .1
                .iter()
                .any(|x| !x.is_empty())
            {
                return Some((i, j));
            }
            j += 1;
        }
        None
    }

    /// Writes the runs of cleaned items to `out` (or only counts them when
    /// `out` is None): neighbors of one style merge, and each run's String
    /// is opened at its exact size. Returns the run count.
    fn runs(&self, items: &[Item], right_side: bool, mut out: Option<&mut Sink<'_>>) -> usize {
        let mut n = 0;
        let mut at = self.next_part(items, 0, 0, right_side);
        while let Some((i, j)) = at {
            let style = self.part(items, i, j, right_side).0;
            // The run ends at the first piece of another style.
            let (mut len, mut end) = (0usize, Some((i, j)));
            while let Some((a, c)) = end {
                let (st, t) = self.part(items, a, c, right_side);
                if st != style {
                    break;
                }
                len += t.iter().map(|x| x.len()).sum::<usize>();
                end = self.next_part(items, a, c + 1, right_side);
            }
            if let Some(sink) = out.as_deref_mut() {
                let text = sink.start(style, len);
                let mut q = Some((i, j));
                while q != end {
                    let Some((a, c)) = q else { break };
                    for x in self.part(items, a, c, right_side).1 {
                        text.push_str(x);
                    }
                    q = self.next_part(items, a, c + 1, right_side);
                }
            }
            n += 1;
            at = end;
        }
        n
    }
}

/// Is method `m` on `src` sure to give a result over `SEG_PIECES_MAX`
/// pieces or `LINE_BYTES_MAX` bytes? Piece counts are lower bounds known
/// from the step count alone: a path method draws `/` and a name for each
/// step it keeps (`depth n` keeps n of them after an ellipsis). `none`
/// gives the whole text.
fn too_big(m: Method, src: Source<'_>) -> bool {
    let (pieces, bytes) = match (m, src) {
        (Method::None, Source::Path(f)) => (1, f.display_len()),
        (Method::None, Source::Text(t)) => (1, t.len()),
        (Method::Depth(n), Source::Path(f)) => {
            let n = usize::from(n.max(1));
            (
                if f.steps() > n {
                    1 + 2 * n
                } else {
                    2 * f.steps()
                },
                0,
            )
        }
        (Method::Abbrev(_) | Method::Unique, Source::Path(f)) => (2 * f.steps(), 0),
        _ => (0, 0),
    };
    pieces > SEG_PIECES_MAX || bytes > LINE_BYTES_MAX
}

fn field_of<'a>(inp: &Inputs<'a>, seg: usize, field: usize) -> Option<&'a FieldValue> {
    inp.values
        .get(seg)
        .and_then(|v| v.as_ref())
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

/// Separator cleanup (spec section 3 "템플릿 중간 표현"): a head or a
/// separator needs a block after it before the next head or tail, a tail
/// needs a block before it since the last head or tail (rulings A and B,
/// 2026-10-13), a separator with no content before it goes, a separator
/// right after a head goes, and separators with no content between them
/// become one (the first stays). A flat separator additionally acts as a
/// plain gap when the nearest content on each side, without crossing a
/// head or tail, is non-block content. This includes the background-removal
/// fallback; otherwise flat separators keep the block-ahead rule above.
/// Linear, without allocation: mark plain content behind, check content
/// ahead in reverse, then compact from the start.
fn clean(items: &mut Vec<Item>) {
    let mut plain_behind = false;
    for it in items.iter_mut() {
        match it.kind {
            Kind::Content => plain_behind = it.block.is_none(),
            Kind::Sep(SepKind::Head | SepKind::Tail, _) => plain_behind = false,
            Kind::Sep(SepKind::Sep, _) => it.ok = plain_behind,
        }
    }
    let mut block_ahead = false;
    let mut content_ahead = false;
    for it in items.iter_mut().rev() {
        match it.kind {
            Kind::Content => {
                block_ahead |= it.block.is_some();
                content_ahead = true;
            }
            Kind::Sep(SepKind::Head, _) => {
                it.ok = block_ahead;
                block_ahead = false;
                content_ahead = false;
            }
            Kind::Sep(SepKind::Tail, _) => {
                block_ahead = false;
                content_ahead = false;
            }
            Kind::Sep(SepKind::Sep, Shape::Flat) => {
                // With no block ahead, any content ahead is plain.
                it.ok = block_ahead || (it.ok && content_ahead);
            }
            Kind::Sep(SepKind::Sep, _) => it.ok = block_ahead,
        }
    }
    let mut w = 0usize;
    let mut any_content = false;
    let mut block_behind = false;
    for r in 0..items.len() {
        let it = items[r];
        let keep = match it.kind {
            Kind::Content => {
                any_content = true;
                block_behind |= it.block.is_some();
                true
            }
            Kind::Sep(SepKind::Head, _) => {
                block_behind = false;
                it.ok
            }
            Kind::Sep(kind, _) => {
                let behind = block_behind;
                if kind == SepKind::Tail {
                    block_behind = false;
                }
                if !any_content
                    || (kind == SepKind::Sep && !it.ok)
                    || (kind == SepKind::Tail && !behind)
                {
                    false
                } else {
                    // A separator right after a head, a separator or a tail
                    // goes. A tail never follows a kept separator or tail: a
                    // kept separator has a block before the next tail, and a
                    // tail resets the block seen (rulings A and B).
                    !matches!(w.checked_sub(1).map(|l| items[l].kind), Some(Kind::Sep(..)))
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
        }) => Some(*b),
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

fn short_of<'a>(pieces: impl Iterator<Item = (&'a str, bool)> + Clone) -> Short {
    let mut text = String::with_capacity(pieces.clone().map(|x| x.0.len()).sum());
    let mut ends = Vec::with_capacity(pieces.clone().count());
    for (t, sh) in pieces {
        text.push_str(t);
        ends.push((text.len(), sh));
    }
    Short { text, ends }
}

/// `src` (pieces and their "shortened" marks) cut to at most `cut` cells
/// with an ellipsis that fits the profile, keeping the start or the end.
/// Pieces stay whole where they fit, so earlier dim marks stay; a cut piece
/// is cut between graphemes. The result has at most one piece more.
fn truncate(src: &[(&str, bool)], cut: u32, keep: Keep, p: WidthProfile) -> Short {
    let e = ellipsis(p, cut);
    let room = cut.saturating_sub(str_width(e, p));
    // Whole pieces kept from the kept end, then the one cut inside.
    let mut used = 0u32;
    let mut whole = 0usize;
    let mut part: Option<(usize, usize)> = None;
    let order: &mut dyn Iterator<Item = (usize, &(&str, bool))> = match keep {
        Keep::End => &mut src.iter().enumerate().rev(),
        Keep::Start => &mut src.iter().enumerate(),
    };
    for (i, &(text, _)) in order {
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
    let cut_piece = part.map(|(i, at)| {
        let (t, sh) = src[i];
        (
            if keep == Keep::End {
                &t[at..]
            } else {
                &t[..at]
            },
            sh,
        )
    });
    let mark = [(e, true)];
    let kept = if keep == Keep::End {
        &src[src.len() - whole..]
    } else {
        &src[..whole]
    };
    let pieces = match keep {
        Keep::End => mark
            .iter()
            .copied()
            .chain(cut_piece)
            .chain(kept.iter().copied())
            .filter(|x| !x.0.is_empty()),
        Keep::Start => {
            return short_of(
                kept.iter()
                    .copied()
                    .chain(cut_piece)
                    .chain(mark.iter().copied())
                    .filter(|x| !x.0.is_empty()),
            );
        }
    };
    short_of(pieces)
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

/// Lays out line `n`. `upper` lines get the fill and lose step 7's output.
/// Decisions go to `r` (`NoopRecorder` records nothing, at no cost).
pub fn layout_line<R: Recorder>(
    n: usize,
    line: &CompiledLine,
    upper: bool,
    inp: &Inputs<'_>,
    o: &Options,
    r: &mut R,
) -> LaidLine {
    let mut out = LaidLine::default();
    layout_line_into(n, line, upper, inp, o, r, &mut out);
    out
}

/// `layout_line` into `out`, reusing its run buffers.
pub fn layout_line_into<R: Recorder>(
    n: usize,
    line: &CompiledLine,
    upper: bool,
    inp: &Inputs<'_>,
    o: &Options,
    r: &mut R,
    out: &mut LaidLine,
) {
    let target = target(o);
    let p = o.profile;
    if o.width <= 1 && R::ENABLED {
        record_tiny(n, line, inp, r);
    }
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
    // Join measuring rarely needs more than a few graphemes; a longer pair
    // gets a new buffer of its size (`scratch`).
    let mut join = String::with_capacity(64);
    let mut lay = Lay::new(line, upper, inp, o, &mut join);
    let mut b = lay.new_bufs(join);
    if R::ENABLED {
        for (s, slot) in lay.slots.iter().enumerate() {
            if slot.entry.iter().any(|v| v.is_some()) && !slot.present {
                r.hidden(n, s, HideReason::NoValue);
            }
        }
    }
    // `when = always`: the first method, once per segment however often
    // the line draws it.
    for s in 0..lay.slots.len() {
        let su = lay.setup(s);
        if su.when == When::Always && lay.slots[s].in_line {
            if let Some(first) = su.methods.get(..1) {
                if let Some(pieces) = lay.shorten_capped(s, first, u32::MAX, n, r) {
                    let short = short_of(pieces.iter().map(|x| (x.text.as_str(), x.shortened)));
                    lay.put_short(s, short, &mut b.join);
                }
            }
        }
    }
    let mut fit = lay.check(&mut b);
    'steps: {
        if lay.fits(&fit) {
            break 'steps;
        }
        if R::ENABLED {
            r.step(n, Step::ShortenNames);
        }
        // Step 1: left before right (the path before right-side information,
        // user decision 2026-10-02), each to "its width - overflow". A
        // segment on both sides is shortened again from its original text
        // with the same methods, which gives the same result.
        for right in [false, true] {
            for i in 0..lay.entries.len() {
                let e = lay.entries[i];
                let su = lay.setup(e.seg);
                // `!e.text` is a performance-only shortcut that no output
                // or record can show: a segment referenced only by fields
                // has no text built, so shortening it gives an empty result
                // that validation drops. A segment drawn on both sides is
                // shortened once, from its left entry.
                let left_done =
                    right && lay.slots[e.seg].entry[0].is_some_and(|l| lay.entries[l].text);
                if e.right != right
                    || !e.text
                    || left_done
                    || su.methods.is_empty()
                    || !lay.visible(e.seg, right)
                {
                    continue;
                }
                let over = fit.cells.saturating_sub(target);
                let budget = lay.slots[e.seg].m.width.saturating_sub(over);
                if let Some(pieces) = lay.shorten_capped(e.seg, su.methods, budget, n, r) {
                    let short = short_of(pieces.iter().map(|x| (x.text.as_str(), x.shortened)));
                    lay.put_short(e.seg, short, &mut b.join);
                }
                fit = lay.check(&mut b);
                if lay.fits(&fit) {
                    break 'steps;
                }
            }
        }
        // Step 2: optional right references, lowest priority (then
        // rightmost) first.
        if R::ENABLED {
            r.step(n, Step::HideRightByPriority);
        }
        for (_, _, s) in by_priority(&lay, true) {
            if lay.visible(s, true) {
                lay.slots[s].hidden[1] = true;
                if R::ENABLED {
                    r.hidden(n, s, HideReason::Priority);
                }
                fit = lay.check(&mut b);
                if lay.fits(&fit) {
                    break 'steps;
                }
            }
        }
        // Step 3: the whole right side, `required` included (ruling E,
        // 2026-10-13: `required` only stops the hiding by choice).
        if R::ENABLED {
            r.step(n, Step::HideRight);
        }
        for i in 0..lay.entries.len() {
            let e = lay.entries[i];
            if e.right {
                if R::ENABLED && lay.visible(e.seg, true) {
                    r.hidden(n, e.seg, HideReason::RightHidden);
                }
                lay.slots[e.seg].hidden[1] = true;
            }
        }
        fit = lay.check(&mut b);
        if lay.fits(&fit) {
            break 'steps;
        }
        // Step 4: cut left texts by the overflow, widest first (leftmost on
        // a tie), down to the ellipsis. A one-cell text (the `char` glyph)
        // cannot get narrower, so it is only ever marked exhausted; so is
        // any text when the line is over `LINE_BYTES_MAX` but not too wide.
        if R::ENABLED {
            r.step(n, Step::TruncateLeft);
        }
        loop {
            let pick = lay
                .entries
                .iter()
                .filter(|e| !e.right && lay.visible(e.seg, false) && !lay.slots[e.seg].exhausted)
                .max_by_key(|e| (lay.slots[e.seg].m.width, Reverse(e.pos)));
            let Some(&e) = pick else { break };
            let s = e.seg;
            let w = lay.slots[s].m.width;
            let keep = if matches!(inp.facts.get(s), Some(Some(_))) {
                Keep::End
            } else {
                Keep::Start
            };
            let cut = w.saturating_sub(fit.cells.saturating_sub(target)).max(1);
            let short = if let Some(prefix) = lay.readonly_prefix(s) {
                // The marker is decoration, never a path component or a
                // partially truncated token. Reserve it even in step four.
                let mut pieces = lay.pieces(s);
                let first = pieces.first_mut().expect("visible path piece");
                first.0 = first.0.strip_prefix(&prefix).expect("readonly prefix");
                let path = truncate(
                    &pieces,
                    cut.saturating_sub(str_width(&prefix, p)).max(1),
                    keep,
                    p,
                );
                let mut short = Short {
                    text: prefix.clone(),
                    ends: alloc::vec![(prefix.len(), false)],
                };
                short.text.push_str(&path.text);
                short.ends.extend(
                    path.ends
                        .into_iter()
                        .map(|(end, dim)| (end + prefix.len(), dim)),
                );
                short
            } else {
                truncate(&lay.pieces(s), cut, keep, p)
            };
            if str_width(&short.text, p) >= w {
                lay.slots[s].exhausted = true;
                continue;
            }
            lay.put_short(s, short, &mut b.join);
            fit = lay.check(&mut b);
            if lay.fits(&fit) {
                break 'steps;
            }
        }
        // Step 5: optional left references, lowest priority (then
        // rightmost) first.
        if R::ENABLED {
            r.step(n, Step::HideLeftOptional);
        }
        for (_, _, s) in by_priority(&lay, false) {
            if lay.visible(s, false) {
                lay.slots[s].hidden[0] = true;
                if R::ENABLED {
                    r.hidden(n, s, HideReason::LeftOptional);
                }
                fit = lay.check(&mut b);
                if lay.fits(&fit) {
                    break 'steps;
                }
            }
        }
        // Step 6: plain text, no backgrounds, heads, tails or non-flat separators.
        if R::ENABLED {
            r.step(n, Step::DropDecoration);
        }
        lay.plain = true;
        fit = lay.check(&mut b);
        if lay.fits(&fit) {
            break 'steps;
        }
        // Step 7.
        if R::ENABLED {
            r.step(n, Step::Minimal);
        }
        return minimal(n, &lay, upper, target, r, out);
    }
    // Every way out of the steps follows a check, so `b` holds the items of
    // the final state and `fit` its measure.
    if R::ENABLED {
        lay.record_empty_groups(n, &b.refs, r);
    }
    out.minimal = false;
    let (nl, nr) = (
        lay.runs(&b.left, false, None),
        lay.runs(&b.right, true, None),
    );
    if upper {
        // left + fill + right = target: the fill takes what is left once
        // the joins at both of its ends are counted, and is left out when
        // that is no cell (the sides then touch, as `check` measured).
        let n = lay.fill_count(&b.left, &b.right, fit.l, fit.r, &mut b.join);
        let fill = (n > 0).then(|| {
            let style = if lay.fill_kind == FillKind::Space {
                Style::default()
            } else {
                Style {
                    fg: Color::Text(tok("muted")),
                    ..Style::default()
                }
            };
            (lay.fill_glyph, n, style)
        });
        let mut sink = Sink::new(&mut out.left, nl + usize::from(fill.is_some()) + nr);
        lay.runs(&b.left, false, Some(&mut sink));
        if let Some((glyph, n, style)) = fill {
            let text = sink.start(style, glyph.len() * n);
            for _ in 0..n {
                text.push_str(glyph);
            }
        }
        lay.runs(&b.right, true, Some(&mut sink));
        sink.finish();
        out.right.clear();
    } else {
        let mut sink = Sink::new(&mut out.left, nl);
        lay.runs(&b.left, false, Some(&mut sink));
        sink.finish();
        let mut sink = Sink::new(&mut out.right, nr);
        lay.runs(&b.right, true, Some(&mut sink));
        sink.finish();
    }
}

/// Step 7 at widths 0 and 1, which return before the line is measured:
/// the step, and every segment the line references (its value missing, or
/// dropped like at step 7; the prompt character is kept on the input line
/// and, as at step 7, never recorded).
fn record_tiny<R: Recorder>(n: usize, line: &CompiledLine, inp: &Inputs<'_>, r: &mut R) {
    r.step(n, Step::Minimal);
    let char_seg = inp.catalog.iter().position(|d| d.id == "char");
    let mut seen = alloc::vec![false; inp.catalog.len()];
    for node in line.nodes() {
        let (Node::Segment { seg, .. } | Node::Field { seg, .. }) = *node else {
            continue;
        };
        let s = usize::from(seg);
        if s >= seen.len() || seen[s] || Some(s) == char_seg {
            continue;
        }
        seen[s] = true;
        let reason = if matches!(inp.values.get(s), Some(Some(_))) {
            HideReason::Minimal
        } else {
            HideReason::NoValue
        };
        r.hidden(n, s, reason);
    }
}

/// Optional references of one side as `(priority, Reverse(position), seg)`,
/// lowest priority first and the rightmost first on a tie.
fn by_priority(lay: &Lay<'_, '_>, right: bool) -> Vec<(u16, Reverse<u32>, usize)> {
    let mut v: Vec<(u16, Reverse<u32>, usize)> = Vec::with_capacity(lay.entries.len());
    for e in &lay.entries {
        let su = lay.setup(e.seg);
        if e.right == right && !su.required {
            v.push((su.priority, Reverse(e.pos), e.seg));
        }
    }
    v.sort_unstable();
    v
}

/// Step 7: `char` and a space, then `char` alone, then ASCII `>`, then
/// nothing. An upper line collapses to nothing.
fn minimal<R: Recorder>(
    n: usize,
    lay: &Lay<'_, '_>,
    upper: bool,
    target: u32,
    r: &mut R,
    out: &mut LaidLine,
) {
    clear_line(out, true);
    if R::ENABLED {
        // Everything still drawn but the prompt character goes.
        for (s, slot) in lay.slots.iter().enumerate() {
            // Still drawn: visible on a side that references it.
            let drawn = (0..2).any(|side| slot.entry[side].is_some() && lay.visible(s, side == 1));
            if Some(s) != lay.char_seg && drawn {
                r.hidden(n, s, HideReason::Minimal);
            }
        }
    }
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
    let gw = str_width(glyph, lay.o.profile);
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
pub fn layout<R: Recorder>(
    variants: &[Vec<CompiledLine>],
    bands: &[Band],
    band_order: &[usize],
    inp: &Inputs<'_>,
    o: &Options,
    r: &mut R,
) -> Vec<LaidLine> {
    let mut out = Vec::new();
    layout_into(variants, bands, band_order, inp, o, r, &mut out);
    out
}

/// `layout` into `out`, reusing its lines and run buffers. A band with no
/// variant falls back to the default layout; no variants at all give no
/// lines.
pub fn layout_into<R: Recorder>(
    variants: &[Vec<CompiledLine>],
    bands: &[Band],
    band_order: &[usize],
    inp: &Inputs<'_>,
    o: &Options,
    r: &mut R,
    out: &mut Vec<LaidLine>,
) {
    let band = select(band_order, bands, o.width);
    if R::ENABLED {
        r.begin();
        r.band(band);
    }
    let lines = band
        .and_then(|b| variants.get(b + 1))
        .or(variants.first())
        .map_or(&[][..], |v| v.as_slice());
    if out.capacity() < lines.len() {
        *out = Vec::with_capacity(lines.len());
    }
    out.truncate(lines.len());
    while out.len() < lines.len() {
        out.push(LaidLine::default());
    }
    let last = lines.len().saturating_sub(1);
    for (n, (l, dst)) in lines.iter().zip(out.iter_mut()).enumerate() {
        layout_line_into(n, l, n < last, inp, o, r, dst);
    }
}
#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::field::{BUILTIN, Field, FieldValue, segment};
    use crate::recorder::{DecisionLog, HideReason, NoopRecorder, Step};
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
        layout(
            &[lines.to_vec()],
            &[],
            &[],
            &f.inputs(),
            o,
            &mut NoopRecorder,
        )
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
                            minimal += usize::from(l.minimal);
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

    // 이것을 실패시키는 것: lean의 빈 host·git·duration 앞뒤에 공백이 남거나 빈 값 때문에 경로를 일찍 줄이는 것.
    #[test]
    fn lean_gaps_follow_visible_segments() {
        let template = generate(
            preset("lean").unwrap(),
            &StyleOptions::default(),
            &[
                LineLayout {
                    left: &["host", "dir", "git"],
                    right: &[],
                },
                LineLayout {
                    left: &["duration", "char"],
                    right: &[],
                },
            ],
        )
        .unwrap();
        let lines = compile(&template, BUILTIN).unwrap();
        for mask in 0..8 {
            let mut f = fixture(&["Works"], "main");
            f.values[idx("host")] = (mask & 1 != 0).then(|| value("host", "host", &[]).unwrap());
            f.values[idx("git")] = (mask & 2 != 0).then(|| value("git", "main", &[]).unwrap());
            f.values[idx("duration")] =
                (mask & 4 != 0).then(|| value("duration", "3s", &[]).unwrap());
            let out = lay(&lines, &f, &opts(80));
            let upper = [
                if mask & 1 != 0 { "host" } else { "" },
                "~/Works",
                if mask & 2 != 0 { "main" } else { "" },
            ]
            .into_iter()
            .filter(|s| !s.is_empty())
            .collect::<Vec<_>>()
            .join(" ");
            assert_eq!(text(&out[0].left), upper, "mask {mask}");
            assert_eq!(
                text(&out[1].left),
                if mask & 4 != 0 { "3s ❯" } else { "❯" },
                "mask {mask}"
            );
            if mask == 0 {
                assert_eq!(text(&lay(&lines, &f, &opts(8))[0].left), "~/Works");
            }
        }
        // Each side cleans its own leading, duplicate and trailing gaps.
        let mut f = fixture(&["Works"], "main");
        f.values[idx("status")] = None;
        let out = one(
            "{dir}{@fill}{status}{@sep:flat}{time}{@sep:flat}{host}{@nl}{char}",
            &f,
            80,
        );
        assert!(text(&out[0].left).ends_with("12:34"));
        assert_eq!(
            text(&out[0].left).trim_end().len(),
            text(&out[0].left).len()
        );
    }

    // 이것을 실패시키는 것: 배경 제거 단계에서 flat 공백까지 지워 이웃 세그먼트를 붙이는 것.
    #[test]
    fn flat_gaps_survive_background_removal() {
        let f = fixture(&["Works"], "main");
        let out = one("{char:block}{@sep:flat}{char:block}{@nl}{char}", &f, 4);
        assert_eq!(text(&out[0].left), "❯ ❯");
    }

    // 이것을 실패시키는 것: 뒤의 리터럴만 보고 기존 블록 구분자를 남기거나,
    // 가장 가까운 콘텐츠 대신 앞의 다른 plain 콘텐츠로 간격을 판단하는 것.
    #[test]
    fn flat_block_separators_keep_the_block_ahead_rule() {
        let mut f = fixture(&["Works"], "main");
        let template = "{dir:block}{@sep:flat}{git:block} x{@nl}{char}";
        assert_eq!(text(&one(template, &f, 80)[0].left), " ~/Works   main  x");
        f.values[idx("git")] = None;
        assert_eq!(text(&one(template, &f, 80)[0].left), " ~/Works  x");
        for (template, expected) in [
            ("p{dir:block}{@sep:flat} x{@nl}{char}", "p ~/Works  x"),
            ("{dir:block}p{@sep:flat}x{@nl}{char}", " ~/Works p x"),
            (
                "{dir}{@sep:flat}x{time:block}{@nl}{char}",
                "~/Works x 12:34 ",
            ),
            (
                "{dir:block}{@sep:flat}x{time:block}{@nl}{char}",
                " ~/Works  x 12:34 ",
            ),
        ] {
            assert_eq!(text(&one(template, &f, 80)[0].left), expected, "{template}");
        }
    }

    // 이것을 실패시키는 것: flat 간격이 head/tail 경계를 넘어 콘텐츠를 찾는 것.
    #[test]
    fn flat_plain_gaps_respect_heads_and_tails() {
        let f = fixture(&["Works"], "main");
        for boundary in ["{@head:flat}", "{@tail:flat}"] {
            for template in [
                alloc::format!("{{dir}}{boundary}{{@sep:flat}}x{{@nl}}{{char}}"),
                alloc::format!("{{dir}}{{@sep:flat}}{boundary}x{{@nl}}{{char}}"),
            ] {
                assert_eq!(
                    text(&one(&template, &f, 80)[0].left),
                    "~/Worksx",
                    "{template}"
                );
            }
        }
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
    // 2칸 이모지 하나로 읽고, `emoji = 1`에서 `⌚` 뒤에 U+FE0E가 오면 2칸 글자 꼴로 읽으므로, 이어 붙인 폭이
    // 목표 폭을 넘는다(`join_risk`가 0을 돌려주거나 U+FE0E를 빼면 실패).
    #[test]
    fn a_joining_value_never_widens_the_line() {
        let mut f = fixture(&["Works"], "main");
        f.setup[idx("git")].methods = &[];
        for (t, v, emoji) in [
            ("#{git}{@nl}{char}", "\u{FE0F}abc", 2),
            ("\u{231A}{git}{@nl}{char}", "\u{FE0E}abc", 1),
        ] {
            f.values[idx("git")] = value("git", v, &[]);
            let lines = compile(t, BUILTIN).unwrap();
            for w in 0..=12 {
                let o = Options {
                    profile: WidthProfile::new(1, emoji).unwrap(),
                    ..opts(w)
                };
                assert_fits(&lay(&lines, &f, &o), &o, t);
            }
        }
        let mut buf = String::new();
        let d = |t, h, e| join_delta(t, h, &mut String::new(), WidthProfile::new(1, e).unwrap());
        assert_eq!(d("#", "\u{FE0F}", 2), 1);
        assert_eq!(d("\u{231A}", "\u{FE0E}", 1), 1);
        assert_eq!(d("a", "\u{FE0F}", 2), 0);
        assert_eq!(d("\u{1F468}", "\u{200D}", 2), 0);
        assert_eq!(d("e", "\u{0301}", 2), 0);
        assert_eq!(join_delta("a", "b", &mut buf, WidthProfile::DEFAULT), 0);
        // Below U+0300 the measure is skipped and the buffer stays unused.
        assert_eq!(buf.capacity(), 0);
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
                // A recording log reads the same ragged inputs.
                let _ = layout(
                    core::slice::from_ref(&lines),
                    &[],
                    &[],
                    &inp,
                    &o,
                    &mut DecisionLog::default(),
                );
                assert_fits(
                    &layout(
                        core::slice::from_ref(&lines),
                        &[],
                        &[],
                        &inp,
                        &o,
                        &mut NoopRecorder,
                    ),
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
                        &mut NoopRecorder,
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
                    &mut NoopRecorder,
                );
                assert_eq!(out.len(), 2);
                assert_fits(&out, &o, "variant");
                assert!(layout(&[], &[], &[], &inp, &o, &mut NoopRecorder).is_empty());
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

    // 이것을 실패시키는 것: 숨은 블록 뒤 꼬리를 앞 구분자의 글리프로 그리는 것, 블록이 하나도 남지 않은 머리를
    // 남기는 것, 앞 내용 없는 구분자나 머리 바로 뒤 구분자를 남기는 것, 숨은 블록 양쪽의 구분자를 둘 다 남기는 것.
    #[test]
    fn merged_separator_draws_the_tail() {
        let mut f = fixture(&["Works"], "main");
        f.values[idx("git")] = None;
        let t = "{dir:block}{@sep:triangle}{git:block}{@sep:triangle}{status:block}{@nl}{char}";
        assert_eq!(text(&one(t, &f, 80)[0].left), " ~/Works \u{E0B0} 1 ");
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
        layout_into(
            &lines,
            &[],
            &[],
            &f.inputs(),
            &opts(80),
            &mut NoopRecorder,
            &mut out,
        );
        let before = (
            out.as_ptr(),
            out[0].left.as_ptr(),
            out[0].left[0].text.as_ptr(),
        );
        layout_into(
            &lines,
            &[],
            &[],
            &f.inputs(),
            &opts(80),
            &mut NoopRecorder,
            &mut out,
        );
        assert_eq!(
            before,
            (
                out.as_ptr(),
                out[0].left.as_ptr(),
                out[0].left[0].text.as_ptr()
            )
        );
    }

    // 판정 A(2026-10-13). 이것을 실패시키는 것: 뒤에 블록이 없는 구분자를 남기는 것(구분자의 `ok` 판정을 끄면 실패).
    #[test]
    fn ruling_a_drops_a_separator_with_no_block_after() {
        let mut f = fixture(&["Works"], "main");
        f.values[idx("time")] = None;
        let t = "{dir}{@fill}{@head:triangle}{status:block}{@sep:triangle}{time:block}{@nl}{char}";
        let s = text(&one(t, &f, 80)[0].left);
        assert!(s.ends_with("\u{E0B2} 1 "), "{s:?}");
        assert_eq!(s.matches('\u{E0B2}').count(), 1, "{s:?}");
    }

    // 판정 B(2026-10-13). 이것을 실패시키는 것: 앞에 블록이 없는 구역의 꼬리를 남기는 것, 머리가 구역을
    // 새로 열지 않아 그 앞 블록을 꼬리의 블록으로 세는 것.
    #[test]
    fn ruling_b_drops_a_tail_with_no_block_before() {
        let mut f = fixture(&["Works"], "main");
        f.values[idx("git")] = None;
        let t = "{@head:triangle}{dir:block}{@tail:triangle} {@head:triangle}{git:block}{@tail:triangle}{@nl}{char}";
        assert_eq!(text(&one(t, &f, 80)[0].left), "\u{E0B2} ~/Works \u{E0B0} ");
        let t = "{dir:block}{@head:round}{git:block}{@tail:triangle}{@nl}{char}";
        assert_eq!(text(&one(t, &f, 80)[0].left), " ~/Works ");
    }

    // 이것을 실패시키는 것: 역할이 있는 블록 글자를 `block.text` 하나로 그리는 것(해석기가 블록마다 고른
    // 글자색 `OnBlock`을 쓰지 않음, 2026-10-13).
    #[test]
    fn role_block_text_is_picked_per_block() {
        let f = fixture(&["Works"], "main");
        let out = one("{dir:block}{@nl}{char}", &f, 80);
        let r = out[0]
            .left
            .iter()
            .find(|r| r.text.contains("Works"))
            .unwrap();
        assert_eq!(
            r.style,
            Style {
                fg: Color::OnBlock(tok("path")),
                bg: Color::Block(tok("path")),
                attrs: 0
            }
        );
    }

    // 판정(2026-10-13, 대비 구현 중). 이것을 실패시키는 것: 단계 6이 배경을 빼고도 블록 글자색
    // `OnBlock`을 남기는 것(단계 6에서 `push_segment`에 블록으로 넘기는 것). light `fg` 블록(time)의
    // 글자는 밝은 색으로 골라져 있어, 남으면 밝은 터미널 바탕 위에서 보이지 않는다. 단계 6에서는 역할의
    // 일반 글자색이어야 한다. 폭 3은 블록(" … ")이 들어가지 않아 단계 6까지 간다.
    #[test]
    fn plain_step_uses_the_role_text_color() {
        use crate::color::math::contrast_milli;
        use crate::color::palette::{Knobs, Mode, PaletteInput, resolve_palette};
        let mut f = fixture(&["Works"], "main");
        f.setup[idx("time")].required = true;
        let t = "{time:block}{@nl}{char}";
        let first = |w| one(t, &f, w)[0].left[0].style;
        assert_eq!(first(80).fg, Color::OnBlock(tok("fg")));
        let plain = first(3);
        assert_eq!(plain.bg, Color::Default);
        assert_eq!(plain.fg, Color::Text(tok("fg")));
        let p = resolve_palette(&PaletteInput {
            mode: Mode::Light,
            knobs: Knobs::default(),
            overrides: &[],
            roles: &[],
        })
        .unwrap();
        let fg = p.get("fg").unwrap();
        assert!(contrast_milli(fg.fg, p.background) >= 4_500);
        assert_eq!(fg.on_block, p.background, "the color step 6 must not keep");
    }

    // 판정 C(2026-10-13). 이것을 실패시키는 것: 단계 6에서 사용자 `{@style:bg=…}` 배경을 남기거나,
    // 글자색·속성까지 지우는 것.
    #[test]
    fn ruling_c_plain_step_drops_user_backgrounds() {
        let f = fixture(&["Works"], "main");
        let t = "{@style:bg=path,fg=git.branch,bold}abcdefgh{@end}{dir:block}{@nl}{char}";
        let run = |w| {
            one(t, &f, w)[0]
                .left
                .iter()
                .find(|r| r.text.starts_with("abc"))
                .unwrap()
                .style
        };
        let wide = run(80);
        assert_eq!(wide.bg, Color::Block(tok("path")));
        // "abcdefgh" + " … " is 11 cells; target 10 needs step 6.
        let plain = run(11);
        assert_eq!(
            plain,
            Style {
                fg: Color::Text(tok("git.branch")),
                bg: Color::Default,
                attrs: crate::color::sgr::BOLD
            }
        );
    }

    // 판정 D(2026-10-13). 이것을 실패시키는 것: token이 아닌 역할을 색 0번으로 그리는 것.
    #[test]
    fn ruling_d_unknown_role_is_the_default_color() {
        const CAT: &[SegmentDecl] = &[SegmentDecl {
            id: "x",
            role: "no.such.role",
            fields: &[],
        }];
        let lines = compile("{x:block} {x}", CAT).unwrap();
        let values = vec![Some(Value::new(b"v", Vec::new()))];
        let inp = Inputs {
            catalog: CAT,
            values: &values,
            facts: &[],
            setup: &[],
        };
        let out = layout(
            core::slice::from_ref(&lines),
            &[],
            &[],
            &inp,
            &opts(80),
            &mut NoopRecorder,
        );
        let styles: Vec<Style> = out[0].left.iter().map(|r| r.style).collect();
        assert_eq!(
            styles[0],
            Style {
                fg: Color::Text(tok("block.text")),
                bg: Color::Default,
                attrs: 0
            }
        );
        assert_eq!(styles.last().unwrap().fg, Color::Default);
    }

    // 판정 E(2026-10-13). 이것을 실패시키는 것: 단계 3이 `required`인 오른쪽 세그먼트를 남기는 것.
    #[test]
    fn ruling_e_step3_hides_required_right_segments() {
        let mut f = fixture(&["Works"], "main");
        f.setup[idx("time")].required = true;
        // "~/Works" 7 + "12:34" 5 = 12 cells, target 11.
        assert_eq!(
            text(&one("{dir}{@fill}{time}{@nl}{char}", &f, 12)[0].left),
            "~/Works"
        );
    }

    // 리뷰 #2. 이것을 실패시키는 것: 필드만 참조하는 세그먼트를 단계 대상에서 빼는 것, 같은 세그먼트를 첫 출현 쪽으로만
    // 분류해 단계 3이 오른쪽 출현을 남기는 것.
    #[test]
    fn steps_see_fields_and_both_sides() {
        let f = fixture(&["Works"], "main");
        let out = one("abcdefg{@fill}{git.ahead}{@nl}{char}", &f, 8);
        assert_eq!(
            (text(&out[0].left).as_str(), out[0].minimal),
            ("abcdefg", false)
        );
        let out = one("{time}{@fill}{time}{@nl}{char}", &f, 10);
        assert_eq!(
            (text(&out[0].left).as_str(), out[0].minimal),
            ("12:34", false)
        );
    }

    // 리뷰 #3. 이것을 실패시키는 것: 앞 grapheme을 보지 않고 결합 가능 접미사마다 칸을 더하는 것(`a`+U+FE0F는 1칸으로
    // 남으므로, 윗줄이 목표 폭보다 짧게 끝난다), 또는 결합으로 넓어지는 칸을 세지 않는 것(`#`+U+FE0F).
    #[test]
    fn joins_count_exactly() {
        let mut f = fixture(&["Works"], "main");
        f.setup[idx("git")].methods = &[];
        for (t, v, emoji) in [
            ("a{git}{@fill}{time}{@nl}{char}", "\u{FE0F}b", 2),
            ("#{git}{@fill}{time}{@nl}{char}", "\u{FE0F}b", 2),
            ("\u{231A}{git}{@fill}{time}{@nl}{char}", "\u{FE0E}b", 1),
            // A prepended mark takes the block's trailing pad into its
            // grapheme; a spacing mark joins the fill space before it.
            ("{git:block}{@fill}{time}{@nl}{char}", "\u{0D4E}", 2),
            ("{dir}{@fill}{git}{@nl}{char}", "\u{0903}b", 2),
            // A spacing mark joins the block's leading pad; a prepended
            // letter takes in the first fill glyph.
            ("{git:block}{@fill}{time}{@nl}{char}", "\u{0903}b", 2),
            ("{git}{@fill}{time}{@nl}{char}", "a\u{0D4E}", 2),
            // Joins that reach past the first grapheme: a ZWJ sequence takes
            // in the emoji after it, a virama joins the next consonant.
            (
                "~ \u{231A}{git}{@fill}{time}{@nl}{char}",
                "\u{FE0E}\u{200D}\u{1F600}",
                1,
            ),
            (
                "\u{0915}\u{094D}{git}{@fill}{time}{@nl}{char}",
                "\u{0937}x",
                2,
            ),
            (
                "\u{1F468}\u{200D}{git}{@fill}{time}{@nl}{char}",
                "\u{1F469}x",
                2,
            ),
            // A join inside the right side.
            ("{dir}{@fill}#{git}{@nl}{char}", "\u{FE0F}b", 2),
        ] {
            f.values[idx("git")] = value("git", v, &[]);
            let o = Options {
                profile: WidthProfile::new(1, emoji).unwrap(),
                ..opts(80)
            };
            assert_eq!(
                runs_width(
                    &lay(&compile(t, BUILTIN).unwrap(), &f, &o)[0].left,
                    o.profile
                ),
                79,
                "{t}"
            );
        }
        // With no room for a fill, the two sides touch: `#` and U+FE0F join.
        f.values[idx("git")] = value("git", "\u{FE0F}b", &[]);
        let lines = compile("#{@fill}{git}{@nl}{char}", BUILTIN).unwrap();
        for w in 0..=10 {
            assert_fits(&lay(&lines, &f, &opts(w)), &opts(w), "touch");
        }
    }

    // 리뷰 #4. 이것을 실패시키는 것: 빈 필드를 내용으로 세어 줄 맨 앞 구분자를 남기거나, 자동색의 이전 블록을 놓치는 것.
    #[test]
    fn empty_fields_are_not_content() {
        let mut f = fixture(&["Works"], "main");
        // An icon with no glyph in the set and a plain segment with no text
        // draw nothing either.
        let o = Options {
            icons: IconSet::Unicode,
            ..opts(80)
        };
        let lines = compile(
            "{@icon:git.branch}{@sep:triangle}{dir:block}{@nl}{char}",
            BUILTIN,
        )
        .unwrap();
        assert_eq!(text(&lay(&lines, &f, &o)[0].left), " ~/Works ");
        f.values[idx("venv")] = value("venv", "", &[]);
        let out = one("{venv}{@sep:triangle}{dir:block}{@nl}{char}", &f, 80);
        assert_eq!(text(&out[0].left), " ~/Works ");
        let out = one(
            "{status.signal}{@sep:triangle}{dir:block}{@nl}{char}",
            &f,
            80,
        );
        assert_eq!(text(&out[0].left), " ~/Works ");
        let out = one(
            "{dir:block}{status.signal}{@sep:triangle}{status:block}{@nl}{char}",
            &f,
            80,
        );
        let sep = out[0].left.iter().find(|r| r.text == "\u{E0B0}").unwrap();
        assert_eq!(
            (sep.style.fg, sep.style.bg),
            (Color::Block(tok("path")), Color::Block(tok("status")))
        );
    }

    // 이것을 실패시키는 것: `SEG_PIECES_MAX`보다 조각이 많은 줄이기 결과를 받는 것(600단계 경로의 `abbrev`가 미리
    // 걸러지지 않거나, 저장소 루트에 따라 조각 수가 정해지는 `repo` 결과가 실행 뒤에 버려지지 않는 것).
    #[test]
    fn results_over_the_piece_cap_are_skipped() {
        let names: Vec<String> = (0..600).map(|n| alloc::format!("folder-{n:03}")).collect();
        let raw: Vec<&[u8]> = names.iter().map(|s| s.as_bytes()).collect();
        let mut f = fixture(&["Works"], "main");
        f.facts[idx("dir")] = Some(PathFacts::new(Anchor::Home, &raw, None, &[]));
        f.setup[idx("dir")].methods = &[Method::Abbrev(1)];
        let s = text(&one("{dir}{@nl}{char}", &f, 40)[0].left);
        assert!(s.ends_with("/folder-599") && !s.contains("f/f/"), "{s:?}");
        // `repo`'s piece count depends on the repository root, so it runs and
        // its result (1,199 pieces) is dropped afterwards. At 6,600 columns
        // that result (6,599 cells) would fit where the whole path (6,601)
        // does not; dropped, the path is cut instead.
        f.facts[idx("dir")] = Some(PathFacts::new(Anchor::Home, &raw, Some(0), &[]));
        f.setup[idx("dir")].methods = &[Method::Repo];
        let s = text(&one("{dir}{@nl}{char}", &f, 6600)[0].left);
        assert!(
            s.starts_with('\u{2026}') && s.ends_with("/folder-599"),
            "{}",
            &s[..20]
        );
    }

    // 이것을 실패시키는 것: 폭은 맞아도 `LINE_BYTES_MAX`를 넘는 줄을 맞는 것으로 보는 것.
    #[test]
    fn a_line_over_the_byte_cap_does_not_fit() {
        let mut f = fixture(&["Works"], "main");
        let heavy = alloc::format!("e{}", "\u{0301}".repeat(4000));
        f.values[idx("git")] = value("git", &heavy, &[]);
        f.setup[idx("git")].methods = &[];
        let out = one("{git}{git}{git}{dir}{@nl}{char}", &f, 80);
        let bytes: usize = out[0].left.iter().map(|r| r.text.len()).sum();
        assert!(
            bytes <= LINE_BYTES_MAX && text(&out[0].left).starts_with('~'),
            "{bytes} {:?}",
            text(&out[0].left)
        );
    }

    // 이것을 실패시키는 것: 방식 사슬을 `METHODS_MAX`(8) 너머까지 돌리는 것(아홉째 `depth 1`이 `…/themes`를 만든다).
    #[test]
    fn only_the_first_methods_run() {
        const NINE: &[Method] = &[
            Method::None,
            Method::None,
            Method::None,
            Method::None,
            Method::None,
            Method::None,
            Method::None,
            Method::None,
            Method::Depth(1),
        ];
        let mut f = fixture(&["Works", "AiScream", "themes"], "main");
        f.setup[idx("dir")].methods = NINE;
        let s = text(&one("{dir}{@nl}{char}", &f, 15)[0].left);
        assert!(
            s.ends_with("Scream/themes") && s.starts_with('\u{2026}'),
            "{s:?}"
        );
        f.setup[idx("dir")].methods = &NINE[1..];
        assert_eq!(
            text(&one("{dir}{@nl}{char}", &f, 15)[0].left),
            "\u{2026}/themes"
        );
    }

    // 이것을 실패시키는 것: `PATH_BYTES_MAX`를 넘는 경로를 읽어 그리거나 줄이는 것(흐린 생략 기호 하나로 그린다).
    #[test]
    fn a_path_too_long_to_read_is_an_ellipsis() {
        let name = alloc::format!("e{}", "\u{0301}".repeat(300));
        let raw: Vec<&[u8]> = (0..120).map(|_| name.as_bytes()).collect();
        let mut f = fixture(&["Works"], "main");
        f.facts[idx("dir")] = Some(PathFacts::new(Anchor::Home, &raw, None, &[]));
        assert!(f.facts[idx("dir")].as_ref().unwrap().display_len() > PATH_BYTES_MAX);
        let out = one("{dir}{@nl}{char}", &f, 80);
        assert_eq!(text(&out[0].left), "\u{2026}");
        assert_ne!(out[0].left[0].style.attrs & DIM, 0);
    }

    // 이것을 실패시키는 것: 채움 글리프 바이트를 `LINE_BYTES_MAX`에 넣지 않거나 글리프당 1바이트로 세는 것(폭 6000의 `─`는
    // 약 18 KB, 1바이트로 세면 약 6 KB), 채움이
    // 없는 입력 줄에서도 채움 바이트를 세는 것.
    #[test]
    fn fill_bytes_count_toward_the_byte_cap() {
        let f = fixture(&["Works"], "main");
        let out = one("{dir}{@fill:line}{time}{@nl}{char}", &f, u16::MAX);
        let bytes: usize = out[0].left.iter().map(|r| r.text.len()).sum();
        assert!(bytes <= LINE_BYTES_MAX, "{bytes}");
        let out = one("{dir}{@fill:line}{time}{@nl}{char}", &f, 5000);
        assert!(text(&out[0].left).ends_with("12:34"));
        // At 6000 columns about 5,980 fill cells are 3 bytes each (about
        // 18 KiB, over the cap) but would be under it at 1 byte each: the
        // right side goes and the line stays within the cap.
        let out = one("{dir}{@fill:line}{time}{@nl}{char}", &f, 6000);
        let bytes: usize = out[0].left.iter().map(|r| r.text.len()).sum();
        assert!(
            bytes <= LINE_BYTES_MAX && !text(&out[0].left).contains("12:34"),
            "{bytes}"
        );
        // An input line draws no fill: its right side is the right prompt.
        let out = one("{dir}{@fill:line}{time}", &f, u16::MAX);
        assert_eq!(text(&out[0].right), "12:34");
    }

    fn logged(t: &str, f: &Fixture, w: u16) -> (Vec<LaidLine>, DecisionLog) {
        let mut log = DecisionLog::default();
        let out = layout(
            &[compile(t, BUILTIN).unwrap()],
            &[],
            &[],
            &f.inputs(),
            &opts(w),
            &mut log,
        );
        (out, log)
    }

    // 이것을 실패시키는 것: 맞는 방식의 번호를 0으로 기록하는 것, 기록하는 단계·줄인 방식·숨긴 이유가 실제 단계와 어긋나는 것(경로를 오른쪽보다 먼저 줄이고,
    // 그다음 우선순위 낮은 `time`을 숨긴다), `DecisionLog::step`이 기록하지 않는 것.
    #[test]
    fn steps_in_order() {
        let f = fixture(&["Works", "AiScream", "themes", "src", "render"], "main");
        let t = "{dir} {git}{@fill}{status} {time}{@nl}{char}";
        let (out, log) = logged(t, &f, 40);
        assert!(
            text(&out[0].left).starts_with("themes/src/render"),
            "{out:?}"
        );
        assert_eq!(log.steps, vec![(0, Step::ShortenNames)]);
        assert_eq!(log.shortened, vec![(0, idx("dir"), 0)]);
        // The first method does not fit, the second does: index 1.
        let mut g = fixture(&["Works", "AiScream", "themes", "src", "render"], "main");
        g.setup[idx("dir")].methods = &[
            Method::Truncate {
                max: 60,
                keep: Keep::End,
            },
            Method::Repo,
        ];
        assert_eq!(logged(t, &g, 40).1.shortened, vec![(0, idx("dir"), 1)]);
        let (_, log) = logged(t, &f, 16);
        assert_eq!(
            log.steps[..2],
            [(0, Step::ShortenNames), (0, Step::HideRightByPriority)]
        );
        assert_eq!(
            log.hidden.first(),
            Some(&(0, idx("time"), HideReason::Priority))
        );
        assert_eq!(log.band, None);
    }

    // 이것을 실패시키는 것: 단계와 숨김(값 없음, 2·3·5·7단계)이 기록되지 않거나, 다른 이유로·두 번·줄에 없는 세그먼트까지
    // 기록되는 것, 맞는 방식이 없을 때 고른 방식 번호가 틀리는 것, 7단계가 `char`를 숨긴 것으로 기록하는 것.
    #[test]
    fn every_step_and_reason_is_recorded() {
        let mut f = fixture(&["Works"], "main");
        f.values[idx("venv")] = None;
        // Present but not in the line: never recorded.
        f.values[idx("host")] = value("host", "me@host", &[]);
        f.setup[idx("time")].required = true;
        // Literal text cannot be cut, so the line ends at step 7.
        let t = "{venv}abcd{dir} {git}{@fill}{status} {time}{@nl}{char}";
        let (out, log) = logged(t, &f, 4);
        assert!(out[0].minimal);
        let steps: Vec<Step> = log.steps.iter().map(|s| s.1).collect();
        use HideReason::{LeftOptional, NoValue, Priority, RightHidden};
        use Step::*;
        assert_eq!(
            steps,
            [
                ShortenNames,
                HideRightByPriority,
                HideRight,
                TruncateLeft,
                HideLeftOptional,
                DropDecoration,
                Minimal
            ]
        );
        // No method fits 3 cells: the narrowest, `abbrev 1` (index 1; `repo`
        // does not apply), is recorded; then the branch's `truncate`.
        assert_eq!(log.shortened, vec![(0, idx("dir"), 1), (0, idx("git"), 0)]);
        let line0: Vec<(usize, HideReason)> = log
            .hidden
            .iter()
            .filter(|h| h.0 == 0)
            .map(|h| (h.1, h.2))
            .collect();
        // Once each, in order: no value, step 2, step 3, step 5, step 7.
        assert_eq!(
            line0,
            [
                (idx("venv"), NoValue),
                (idx("status"), Priority),
                (idx("time"), RightHidden),
                (idx("git"), LeftOptional),
                (idx("dir"), HideReason::Minimal)
            ]
        );
        // The input line keeps `char` and records nothing.
        assert!(!log.hidden.iter().any(|h| h.0 == 1));
        // An input line at step 7 keeps `char`: only `dir` is recorded.
        let (out, log) = logged("abcd{dir}{char}", &f, 3);
        assert!(out[0].minimal);
        assert_eq!(log.hidden, [(0, idx("dir"), HideReason::Minimal)]);
    }

    // 이것을 실패시키는 것: 고른 폭 구간을 기록하지 않는 것.
    #[test]
    fn the_band_is_recorded() {
        let f = fixture(&["Works"], "main");
        let lines = compile("{dir}{@nl}{char}", BUILTIN).unwrap();
        let band = Band {
            min_cols: None,
            max_cols: Some(60),
            order: None,
        };
        let mut log = DecisionLog::default();
        layout(
            &[lines.clone(), lines],
            &[band],
            &[0],
            &f.inputs(),
            &opts(40),
            &mut log,
        );
        assert_eq!(log.band, Some(0));
    }

    // 이것을 실패시키는 것: 기록기를 켜면 결과가 바뀌는 것(결정 기록은 관찰만 한다).
    #[test]
    fn recorder_does_not_change_output() {
        let f = fixture(
            &["Works", "AiScream", "themes", "src", "render"],
            "feature/very-long-branch-name",
        );
        for name in ["lean", "triangle"] {
            let lines = two_lines(name);
            for w in 0..=120u16 {
                let a = layout(
                    core::slice::from_ref(&lines),
                    &[],
                    &[],
                    &f.inputs(),
                    &opts(w),
                    &mut NoopRecorder,
                );
                let b = layout(
                    core::slice::from_ref(&lines),
                    &[],
                    &[],
                    &f.inputs(),
                    &opts(w),
                    &mut DecisionLog::default(),
                );
                assert_eq!(a, b, "{name} {w}");
            }
        }
    }

    // 리뷰 #1. 이것을 실패시키는 것: 비어서 사라진 조건 묶음을 기록하지 않는 것, 한 묶음의 같은 세그먼트를 두 번
    // 기록하는 것, 값이 없어서(NoValue) 또는 오른쪽에서 숨어서(Priority) 사라진 묶음까지 EmptyGroup으로 기록하는 것.
    #[test]
    fn empty_groups_are_recorded() {
        let mut f = fixture(&["Works"], "main");
        let t = "{dir}{@group} +{git.ahead}/{git.behind}{@end}{@nl}{char}";
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
        let (out, log) = logged(t, &f, 80);
        assert_eq!(text(&out[0].left), "~/Works");
        assert_eq!(log.hidden, [(0, idx("git"), HideReason::EmptyGroup)]);
        f.values[idx("git")] = value(
            "git",
            "main",
            &[(
                "ahead",
                FieldValue::Count {
                    n: 2,
                    saturated: false,
                },
            )],
        );
        assert!(logged(t, &f, 80).1.hidden.is_empty());
        f.values[idx("git")] = None;
        assert_eq!(
            logged(t, &f, 80).1.hidden,
            [(0, idx("git"), HideReason::NoValue)]
        );
        // On the right, step 2 hides git's group: "main" + "+2 12:34" is 12
        // cells, target 11. Still drawn on the left, it is no empty group.
        f.values[idx("git")] = value(
            "git",
            "main",
            &[(
                "ahead",
                FieldValue::Count {
                    n: 2,
                    saturated: false,
                },
            )],
        );
        f.setup[idx("git")].priority = 0;
        let (out, log) = logged(
            "{git}{@fill}{@group}+{git.ahead}{@end} {time}{@nl}{char}",
            &f,
            12,
        );
        assert!(text(&out[0].left).ends_with(" 12:34"), "{out:?}");
        assert_eq!(log.hidden, [(0, idx("git"), HideReason::Priority)]);
    }

    // 리뷰 #2. 이것을 실패시키는 것: fill 양쪽에 있는 세그먼트를 단계 1이 쪽마다 줄여 같은 기록을 두 번 남기는 것.
    #[test]
    fn a_segment_on_both_sides_is_shortened_once() {
        let f = fixture(&["Works", "AiScream", "themes"], "main");
        let (out, log) = logged("{dir}{@fill}{dir}{@nl}{char}", &f, 30);
        assert_eq!(log.shortened, [(0, idx("dir"), 0)]);
        // Both occurrences draw the one shortened text.
        assert_eq!(text(&out[0].left).matches("themes").count(), 2, "{out:?}");
        // Still too wide after the left entry: the right entry is skipped,
        // not shortened (and recorded) again.
        let (_, log) = logged("{dir}{@fill}{dir}{@nl}{char}", &f, 12);
        assert_eq!(log.shortened, [(0, idx("dir"), 0)]);
        // Referenced only by a field on the left, the segment is shortened
        // from its right entry.
        let (out, log) = logged("{dir.in_repo}x{@fill}{dir}{@nl}{char}", &f, 12);
        assert_eq!(log.shortened, [(0, idx("dir"), 0)]);
        assert!(text(&out[0].left).ends_with("themes"), "{out:?}");
    }

    // 리뷰 #3. 이것을 실패시키는 것: 폭 0·1의 최소 프롬프트가 단계 7과 숨긴 세그먼트를 기록하지 않는 것.
    #[test]
    fn tiny_widths_are_recorded() {
        let mut f = fixture(&["Works"], "main");
        f.values[idx("venv")] = None;
        for w in [0, 1] {
            // `dir` twice: recorded once.
            let (out, log) = logged("{venv}{dir} {git} {dir}{@nl}{char}", &f, w);
            assert!(out.iter().all(|l| l.minimal));
            assert_eq!(log.steps, [(0, Step::Minimal), (1, Step::Minimal)], "{w}");
            assert_eq!(
                log.hidden,
                [
                    (0, idx("venv"), HideReason::NoValue),
                    (0, idx("dir"), HideReason::Minimal),
                    (0, idx("git"), HideReason::Minimal)
                ],
                "{w}"
            );
        }
    }

    // 리뷰 #5. 이것을 실패시키는 것: `layout`이 기록기를 비우지 않고 이어 쌓는 것.
    #[test]
    fn each_layout_starts_a_new_log() {
        let f = fixture(&["Works", "AiScream", "themes", "src", "render"], "main");
        let lines = [two_lines("triangle")];
        let mut log = DecisionLog::default();
        layout(&lines, &[], &[], &f.inputs(), &opts(30), &mut log);
        let once = log.clone();
        assert!(!once.steps.is_empty());
        layout(&lines, &[], &[], &f.inputs(), &opts(30), &mut log);
        assert_eq!(log, once);
    }
}
