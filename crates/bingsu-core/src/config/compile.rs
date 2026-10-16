//! Compiling a checked, merged config into what the renderer and the
//! snapshot use (spec section 2 "합치는 순서": merge → check → style →
//! template). Compiling happens once per config change (the refresh
//! helper), never per prompt. `CompiledConfig` is owned and comparable:
//! the snapshot (Task N1) encodes it and must decode to an equal value.
//!
//! The built-in theme enters the merge as the first source (`BUILTIN_TOML`),
//! so a user file changes only what it writes and the rest stays the
//! built-in value (rule 3). Keys absent from every source take the key
//! table's default.
//!
//! Execution (spec section 2 "민감 키 원칙"; a layout array is an execution
//! key for the command segments it names): the units that run are the
//! commands a trusted source put in a layout, and that are still on a line
//! that is drawn. `trusted` is the merge of the executable sources alone,
//! `m` the merge of all of them: a shape-only file can hide a command (take
//! it out of a drawn line, turn the line off) but cannot turn one on (add it,
//! turn a line on). Running is M6; this step records each unit with its
//! whole policy and why one does not run.
use crate::bands::{Band, MAX_BANDS, order_bands};
use crate::color::notation::{ColorSpec, parse_color};
use crate::color::palette::{Knobs, Mode, PaletteInput, ResolvedPalette, resolve_palette};
use crate::config::check::parse_duration_ms;
use crate::config::keys;
use crate::config::merge::{KeyClass, MEntry, MNode, MTable, MValue, Merged, Origin};
use crate::config::source::Trust;
use crate::config::tree::Value;
use crate::default_theme::{DIR_METHODS, SETUP};
use crate::diag::{Diagnostic, Place};
use crate::diag_codes as codes;
use crate::diag_widths::{WidthRun, width_table};
use crate::field::BUILTIN;
use crate::icons::IconSet;
use crate::layout::{SegmentSetup, When};
use crate::render::Theme;
use crate::shorten::Method;
use crate::style::{Joining, LineLayout, StyleOptions, generate, preset};
use crate::template::compile::{CompiledLine, FillKind, Node, Shape, compile as compile_template};
use crate::template::syntax::{Span as TSpan, Syntax, parse as parse_template};
use crate::width::WidthProfile;
use alloc::collections::{BTreeMap, BTreeSet};
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

/// The built-in theme as a config source (the same values as
/// `default_theme`, the narrow band its `NARROW_TEMPLATE`; the test
/// `builtin_source_draws_the_default_theme` keeps them equal).
pub const BUILTIN_TOML: &str = r#"icons = "unicode"
[style]
preset = "triangle"
[layout.line1]
left = ["host", "dir", "git"]
right = ["status", "duration", "jobs", "venv", "time"]
[layout.line2]
left = ["char"]
[layout.when.narrow]
max_cols = 59
[layout.when.narrow.style]
template = "{@group}{host} {@end}{dir}{@group} {git}{@end}{@nl}{@group}{duration} {@end}{char}"
[segment.dir]
shorten = ["repo", "abbrev", "depth"]
"#;

/// What a unit runs. Tagged, so the snapshot format (N1) carries both
/// kinds from the start; M6 fills the language keys and runs both.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExecPolicy {
    Command {
        argv: Vec<String>,
        cwd: Option<String>,
        env_allow: Vec<String>,
        shell: Option<String>,
        unsafe_shell: bool,
    },
    /// A user-defined language version. Its keys (interpreter, version
    /// command, files that mark the language) come with M6; the fields are
    /// here so the format does not change then.
    Language {
        interpreter: Option<String>,
        version_argv: Vec<String>,
        detect_files: Vec<String>,
    },
}

/// Why a unit does not run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NotRun {
    /// `enabled = false` from a trusted file.
    Disabled,
    /// No drawn line of a trusted layout names it.
    NotInTrustedLayout,
    /// An execution key of it comes from a file that failed the safety
    /// check (owner, permissions).
    UnsafeFile { key: String },
}

/// One user segment that runs something, with its whole policy, where each
/// key came from, and the layout references that let it run.
#[derive(Clone, Debug, PartialEq)]
pub struct ExecUnit {
    pub id: String,
    pub policy: ExecPolicy,
    pub timeout_ms: Option<u64>,
    pub cache_ms: Option<u64>,
    /// Each execution key written for it and its origin.
    pub origins: Vec<(String, Origin)>,
    /// Where a trusted layout draws it (what allows it to run).
    pub approved_by: Vec<LayoutRef>,
    /// Where the full config draws it (what is on screen).
    pub shown_at: Vec<LayoutRef>,
    /// `None`: it runs.
    pub not_run: Option<NotRun>,
}

/// Per `field::BUILTIN` index: priority, required, shorten methods, when.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Setup {
    pub priority: u16,
    pub required: bool,
    pub methods: Vec<Method>,
    pub when: When,
}

#[derive(Clone, Debug, PartialEq)]
pub struct CompiledConfig {
    pub variants: Vec<Vec<CompiledLine>>,
    pub bands: Vec<Band>,
    pub band_names: Vec<String>,
    pub band_order: Vec<usize>,
    pub transient: CompiledLine,
    pub vi: CompiledLine,
    /// Dark display slot; an explicit color mode makes both slots equal.
    pub palette: ResolvedPalette,
    pub light_palette: ResolvedPalette,
    pub setup: Vec<Setup>,
    /// Bit i: `field::BUILTIN[i]` is drawn in some layout and not turned
    /// off, so the collector gathers it.
    pub collect_mask: u32,
    pub icons: IconSet,
    pub profile: WidthProfile,
    pub use_last_column: bool,
    pub duration_min_ms: u64,
    pub exec_units: Vec<ExecUnit>,
    pub widths: Vec<WidthRun>,
}

impl CompiledConfig {
    pub fn theme(&self) -> Theme<'_> {
        self.theme_for(Mode::Dark)
    }
    pub fn theme_for(&self, display_mode: Mode) -> Theme<'_> {
        Theme {
            variants: &self.variants,
            bands: &self.bands,
            band_order: &self.band_order,
            transient: &self.transient,
            vi: &self.vi,
            palette: match display_mode {
                Mode::Dark => &self.palette,
                Mode::Light => &self.light_palette,
            },
        }
    }
    pub fn setup(&self) -> Vec<SegmentSetup<'_>> {
        self.setup
            .iter()
            .map(|s| SegmentSetup {
                priority: s.priority,
                required: s.required,
                methods: &s.methods,
                when: s.when,
            })
            .collect()
    }
}

fn get<'a>(t: &'a MTable, path: &[&str]) -> Option<&'a MNode> {
    t.at(path)
}

fn s<'a>(t: &'a MTable, path: &[&str]) -> Option<&'a str> {
    match get(t, path).map(|n| &n.value) {
        Some(MValue::Scalar(Value::Str(v))) => Some(v),
        _ => None,
    }
}

fn int(t: &MTable, path: &[&str]) -> Option<i64> {
    match get(t, path).map(|n| &n.value) {
        Some(MValue::Scalar(Value::Int(v))) => Some(*v),
        _ => None,
    }
}

fn float(t: &MTable, path: &[&str]) -> Option<f64> {
    match get(t, path).map(|n| &n.value) {
        Some(MValue::Scalar(Value::Float(v))) => Some(*v),
        Some(MValue::Scalar(Value::Int(v))) => Some(*v as f64),
        _ => None,
    }
}

fn boolean(t: &MTable, path: &[&str]) -> Option<bool> {
    match get(t, path).map(|n| &n.value) {
        Some(MValue::Scalar(Value::Bool(v))) => Some(*v),
        _ => None,
    }
}

fn strings(n: &MNode) -> Vec<String> {
    match &n.value {
        MValue::Array(a) => a
            .iter()
            .filter_map(|i| match &i.value {
                Value::Str(s) => Some(s.clone()),
                _ => None,
            })
            .collect(),
        _ => Vec::new(),
    }
}

fn entries<'a>(t: &'a MTable, path: &[&str]) -> &'a [MEntry] {
    match get(t, path).map(|n| &n.value) {
        Some(MValue::Table(t)) => &t.entries,
        _ => &[],
    }
}

/// The table's default for `path` as a string (`"auto"` → `auto`).
fn default_str(path: &str) -> &'static str {
    keys::KEYS
        .iter()
        .find(|k| k.path == path)
        .and_then(|k| k.default)
        .map_or("", |d| d.trim_matches('"'))
}

fn at(n: &MNode) -> Place {
    Place::Source {
        id: n.origin.source,
        span: n.origin.span,
    }
}

fn place_of(t: &MTable, path: &[&str]) -> Place {
    get(t, path).map_or(Place::Builtin, at)
}

/// One line of one layout table, over the line it inherits: each side and
/// `enabled` keep the node they came from.
#[derive(Clone, Default)]
struct Line {
    left: Vec<String>,
    right: Vec<String>,
    enabled: bool,
    /// The nodes behind this line (its own and the ones it inherits), for
    /// blame.
    nodes: Vec<MNode>,
    /// This layout table writes the line itself (not only inherits it).
    written: bool,
    left_origin: Option<Origin>,
    right_origin: Option<Origin>,
}

fn line(t: Option<&MNode>, base: &Line) -> Line {
    let mut l = base.clone();
    l.written = false;
    if let Some(MNode {
        value: MValue::Table(t),
        ..
    }) = t
    {
        if let Some(n) = t.get("left") {
            l.left = strings(n);
            l.left_origin = Some(n.origin);
            l.nodes.push(n.clone());
            l.written = true;
        }
        if let Some(n) = t.get("right") {
            l.right = strings(n);
            l.right_origin = Some(n.origin);
            l.nodes.push(n.clone());
            l.written = true;
        }
        if let Some(n) = t.get("enabled") {
            if let MValue::Scalar(Value::Bool(b)) = &n.value {
                l.enabled = *b;
            }
            l.nodes.push(n.clone());
            l.written = true;
        }
    }
    l
}

fn lines(t: &MTable, base: &[Line; 2]) -> [Line; 2] {
    [
        line(t.get("line1"), &base[0]),
        line(t.get("line2"), &base[1]),
    ]
}

/// One layout: the default (`name` None) or a band, its lines over the
/// default lines, and its table.
struct Layout {
    name: Option<String>,
    lines: [Line; 2],
    table: Option<MTable>,
    /// The template in effect (the band's own, else the default's).
    template: Option<MNode>,
}

fn layouts(r: &MTable) -> Vec<Layout> {
    let empty = Line {
        enabled: true,
        ..Line::default()
    };
    let layout = match get(r, &["layout"]).map(|n| &n.value) {
        Some(MValue::Table(t)) => t.clone(),
        _ => MTable::default(),
    };
    let base = lines(&layout, &[empty.clone(), empty]);
    let base_template = get(r, &["style", "template"]).cloned();
    let mut out = vec![Layout {
        name: None,
        lines: base.clone(),
        table: None,
        template: base_template.clone(),
    }];
    for b in entries(&layout, &["when"]) {
        if let MValue::Table(bt) = &b.node.value {
            let template = get(bt, &["style", "template"])
                .cloned()
                .or_else(|| base_template.clone());
            out.push(Layout {
                name: Some(b.key.clone()),
                lines: lines(bt, &base),
                table: Some(bt.clone()),
                template,
            });
        }
    }
    out
}

/// Which side of a layout line.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Side {
    Left,
    Right,
}

/// Where a segment id is drawn: the layout (`band` None is the default),
/// line 1 or 2 (0: named by a template, which replaces the lines), the
/// side, and the array or template that put it there.
#[derive(Clone, Debug, PartialEq)]
pub struct LayoutRef {
    pub band: Option<String>,
    pub line: u8,
    pub side: Side,
    pub origin: Option<Origin>,
}

/// Every segment id a template names, inside groups and styles too. A
/// template that does not parse names none (the compile reports it).
pub(crate) fn template_ids(text: &str) -> Vec<String> {
    fn walk(items: &[(Syntax, TSpan)], out: &mut Vec<String>) {
        for (syn, _) in items {
            match syn {
                Syntax::Segment { id, .. } | Syntax::Field { segment: id, .. } => {
                    out.push(id.clone());
                }
                Syntax::Group(body) | Syntax::Style { body, .. } => walk(body, out),
                _ => {}
            }
        }
    }
    let mut out = Vec::new();
    if let Ok(t) = parse_template(text) {
        walk(&t, &mut out);
    }
    out
}

/// `text` without custom references (drawn from M6) or disabled built-ins:
/// each is cut out, and so is a group left without a reference (a
/// group needs one to compile). A template that does not parse is kept as
/// it is, so the compile reports it.
fn without_hidden(text: &str, off: &BTreeSet<&str>) -> String {
    fn cuts(items: &[(Syntax, TSpan)], off: &BTreeSet<&str>, out: &mut Vec<TSpan>) -> bool {
        let mut kept = false;
        for (syn, sp) in items {
            match syn {
                Syntax::Segment { id, .. } | Syntax::Field { segment: id, .. } => {
                    if id.starts_with("custom/") || off.contains(id.as_str()) {
                        out.push(*sp);
                    } else {
                        kept = true;
                    }
                }
                Syntax::Group(body) => {
                    let mut inner = Vec::new();
                    if cuts(body, off, &mut inner) || inner.is_empty() {
                        out.extend(inner);
                        kept = true;
                    } else {
                        out.push(*sp);
                    }
                }
                Syntax::Style { body, .. } => kept |= cuts(body, off, out),
                _ => {}
            }
        }
        kept
    }
    let Ok(tree) = parse_template(text) else {
        return String::from(text);
    };
    let mut gone = Vec::new();
    cuts(&tree, off, &mut gone);
    gone.sort_by_key(|sp| sp.start);
    let mut out = String::with_capacity(text.len());
    let mut at = 0;
    for sp in gone {
        out.push_str(&text[at..sp.start as usize]);
        at = sp.end as usize;
    }
    out.push_str(&text[at..]);
    out
}

/// Whether `[segment."<id>"]` is declared.
fn declared(r: &MTable, id: &str) -> bool {
    matches!(
        get(r, &["segment", id]).map(|n| &n.value),
        Some(MValue::Table(_))
    )
}

/// Every id on a drawn line, with where.
fn drawn(r: &MTable) -> BTreeMap<String, Vec<LayoutRef>> {
    let mut out: BTreeMap<String, Vec<LayoutRef>> = BTreeMap::new();
    for lay in layouts(r) {
        if let Some(t) = &lay.template {
            // A template replaces the lines: what it names is what is drawn.
            if let MValue::Scalar(Value::Str(text)) = &t.value {
                for id in template_ids(text) {
                    out.entry(id).or_default().push(LayoutRef {
                        band: lay.name.clone(),
                        line: 0,
                        side: Side::Left,
                        origin: Some(t.origin),
                    });
                }
            }
            continue;
        }
        for (n, l) in lay.lines.iter().enumerate().filter(|(_, l)| l.enabled) {
            for (side, ids, origin) in [
                (Side::Left, &l.left, l.left_origin),
                (Side::Right, &l.right, l.right_origin),
            ] {
                for id in ids {
                    out.entry(id.clone()).or_default().push(LayoutRef {
                        band: lay.name.clone(),
                        line: n as u8 + 1,
                        side,
                        origin,
                    });
                }
            }
        }
    }
    out
}

/// The place to blame for a problem these nodes caused together: a
/// shape-only one if there is one (so rule 5 drops that file and not the
/// user's), else the one from the latest source.
fn blame(nodes: &[&MNode]) -> Place {
    let pick = nodes
        .iter()
        .filter(|n| n.origin.trust == Trust::ShapeOnly)
        .max_by_key(|n| n.origin.source)
        .or_else(|| nodes.iter().max_by_key(|n| n.origin.source));
    pick.map_or(Place::Builtin, |n| at(n))
}

/// Expanded input budget: a segment reference costs 64 units plus its
/// bytes; template text costs its byte length. Count inherited values even
/// when overridden: `layouts` clones them before applying the override.
/// This allows thousands of ordinary layouts, while preventing a large
/// base line/template from being multiplied by thousands of bands.
const MAX_LAYOUT_WORK: usize = 4 * 1024 * 1024;

fn check_band_count(r: &MTable) -> Result<(), Vec<Diagnostic>> {
    let bands = entries(r, &["layout", "when"]);
    if bands.len() > MAX_BANDS {
        return Err(vec![bad(
            blame(&bands.iter().map(|b| &b.node).collect::<Vec<_>>()),
            "layout.when",
            &alloc::format!("{} bands", bands.len()),
            &alloc::format!("at most {MAX_BANDS} bands"),
        )]);
    }
    Ok(())
}

fn check_layout_budget(r: &MTable) -> Result<(), Vec<Diagnostic>> {
    check_band_count(r)?;
    // The checked layout contains scalar options, segment-id arrays and
    // tables. Retain every charged origin, including inherited values and
    // the band declarations that multiply them, for rule-5 isolation.
    fn weight<'a>(n: &'a MNode, nodes: &mut Vec<&'a MNode>) -> (usize, usize) {
        nodes.push(n);
        match &n.value {
            // Three bytes is the shortest template reference. Counting
            // other string options this way is a conservative upper bound.
            MValue::Scalar(Value::Str(s)) => (s.len(), s.len() / 3),
            MValue::Array(a) => (
                a.iter().fold(0usize, |sum, n| {
                    sum.saturating_add(
                        64 + match &n.value {
                            Value::Str(s) => s.len(),
                            _ => 0,
                        },
                    )
                }),
                a.len(),
            ),
            MValue::Table(t) => t.entries.iter().fold((0usize, 0usize), |(work, refs), e| {
                let (w, r) = weight(&e.node, nodes);
                (
                    work.saturating_add(e.key.len()).saturating_add(w),
                    refs.saturating_add(r),
                )
            }),
            _ => (1, 0),
        }
    }
    let mut nodes = Vec::new();
    let (base, base_refs) = [
        get(r, &["layout", "line1"]),
        get(r, &["layout", "line2"]),
        get(r, &["style", "template"]),
    ]
    .into_iter()
    .flatten()
    .fold((0usize, 0usize), |(work, refs), n| {
        let (w, r) = weight(n, &mut nodes);
        (work.saturating_add(w), refs.saturating_add(r))
    });
    let mut work = base;
    for b in entries(r, &["layout", "when"]) {
        let (own, own_refs) = weight(&b.node, &mut nodes);
        // LayoutRef copies the band name for every drawn reference.
        let name_work = base_refs
            .saturating_add(own_refs)
            .saturating_mul(b.key.len());
        work = work
            .saturating_add(base)
            .saturating_add(own)
            .saturating_add(name_work);
    }
    if work > MAX_LAYOUT_WORK {
        return Err(vec![bad(
            blame(&nodes),
            "layout",
            &alloc::format!("{work} expanded layout work units"),
            &alloc::format!("at most {MAX_LAYOUT_WORK} expanded layout work units"),
        )]);
    }
    Ok(())
}

/// The bands of a merged config, ordered, and the width table. Kept apart
/// from the snapshot compile so `config check` shows the table even when
/// another key has an error.
pub struct Bands {
    pub bands: Vec<Band>,
    pub names: Vec<String>,
    pub order: Vec<usize>,
    pub widths: Vec<WidthRun>,
    pub notes: Vec<Diagnostic>,
}

pub fn bands_of(m: &Merged) -> Result<Bands, Vec<Diagnostic>> {
    let r = &m.root;
    check_band_count(r)?;
    let mut bands = Vec::new();
    let mut names = Vec::new();
    let mut nodes: Vec<Vec<MNode>> = Vec::new();
    for b in entries(r, &["layout", "when"]) {
        let MValue::Table(bt) = &b.node.value else {
            continue;
        };
        let n = |k: &str| int(bt, &[k]);
        bands.push(Band {
            min_cols: n("min_cols").map(|v| v as u16),
            max_cols: n("max_cols").map(|v| v as u16),
            order: n("order").map(|v| v as i32),
        });
        names.push(b.key.clone());
        let mut v = vec![b.node.clone()];
        v.extend(
            ["min_cols", "max_cols", "order"]
                .iter()
                .filter_map(|k| bt.get(k).cloned()),
        );
        nodes.push(v);
    }
    let order = order_bands(&bands).map_err(|e| {
        use crate::bands::BandError;
        let involved: Vec<usize> = match e {
            BandError::Empty(i) => vec![i],
            BandError::NeedsOrder(i, j) | BandError::SameOrder(i, j) => vec![i, j],
            _ => (0..bands.len()).collect(),
        };
        let all: Vec<&MNode> = involved.iter().flat_map(|&i| nodes[i].iter()).collect();
        vec![bad(
            blame(&all),
            "layout.when",
            "bands the order rule cannot compare",
            "`order` on overlapping bands",
        )]
    })?;
    let places: Vec<Place> = nodes
        .iter()
        .map(|v| blame(&v.iter().collect::<Vec<_>>()))
        .collect();
    let (widths, notes) = width_table(&order, &bands, &names, &places);
    Ok(Bands {
        bands,
        names,
        order,
        widths,
        notes,
    })
}

fn method(name: &str) -> Method {
    match name {
        "repo" => Method::Repo,
        "abbrev" => Method::Abbrev(1),
        "depth" => Method::Depth(1),
        "unique" => Method::Unique,
        _ => Method::None,
    }
}

fn bad(place: Place, key: &str, found: &str, expected: &str) -> Diagnostic {
    Diagnostic::new(codes::BAD_VALUE, place)
        .arg("key", key)
        .arg("found", found)
        .arg("expected", expected)
}

fn palette(r: &MTable, mode: Mode) -> Result<ResolvedPalette, Vec<Diagnostic>> {
    let knobs = Knobs {
        hue: float(r, &["colors", "knobs", "hue"]),
        accent_l: float(r, &["colors", "knobs", "accent_l"]),
        accent_c: float(r, &["colors", "knobs", "accent_c"]),
    };
    let mut overrides: Vec<(&str, ColorSpec)> = Vec::new();
    let mut roles: Vec<(&str, &str)> = Vec::new();
    let mut errors = Vec::new();
    // Each row alone first, so an error points at the row that caused it.
    for e in entries(r, &["colors", "override"]) {
        if let MValue::Scalar(Value::Str(v)) = &e.node.value {
            if let Ok(c) = parse_color(v) {
                let one = [(e.key.as_str(), c)];
                let input = PaletteInput {
                    mode,
                    knobs,
                    overrides: &one,
                    roles: &[],
                };
                match resolve_palette(&input) {
                    Ok(_) => overrides.push((e.key.as_str(), c)),
                    Err(_) => errors.push(bad(
                        at(&e.node),
                        "colors.override",
                        &e.key,
                        "a palette color or token name",
                    )),
                }
            }
        }
    }
    for e in entries(r, &["colors", "roles"]) {
        if let MValue::Scalar(Value::Str(v)) = &e.node.value {
            let one = [(e.key.as_str(), v.as_str())];
            let input = PaletteInput {
                mode,
                knobs,
                overrides: &[],
                roles: &one,
            };
            match resolve_palette(&input) {
                Ok(_) => roles.push((e.key.as_str(), v.as_str())),
                Err(_) => errors.push(bad(
                    at(&e.node),
                    "colors.roles",
                    v,
                    "a token name and a palette color name",
                )),
            }
        }
    }
    if !errors.is_empty() {
        return Err(errors);
    }
    resolve_palette(&PaletteInput {
        mode,
        knobs,
        overrides: &overrides,
        roles: &roles,
    })
    .map_err(|_| {
        vec![bad(
            place_of(r, &["colors"]),
            "colors",
            "",
            "a palette that resolves",
        )]
    })
}

/// Compiles `m` (already checked without errors) with `trusted`, the merge
/// of the executable sources alone. Both display palettes are retained;
/// `auto` remains in the interface for existing callers (S-11). Returns the config
/// and its warnings and notes; errors carry the place of the key that
/// caused them.
pub fn compile(
    m: &Merged,
    trusted: &Merged,
    _auto: Mode,
) -> Result<(CompiledConfig, Vec<Diagnostic>), Vec<Diagnostic>> {
    // Check both views before `layouts`/`drawn` can multiply inherited data.
    check_layout_budget(&trusted.root)?;
    check_layout_budget(&m.root)?;
    let r = &m.root;
    let mut notes = Vec::new();
    let (mode, light_mode) = match s(r, &["colors", "mode"]).unwrap_or(default_str("colors.mode")) {
        "dark" => (Mode::Dark, Mode::Dark),
        "light" => (Mode::Light, Mode::Light),
        _ => (Mode::Dark, Mode::Light),
    };
    let palette = palette(r, mode)?;
    let light_palette = if mode == light_mode {
        palette.clone()
    } else {
        self::palette(r, light_mode)?
    };
    let options = StyleOptions {
        separator: s(r, &["style", "separator"]).and_then(|v| match v {
            "triangle" => Some(Shape::Triangle),
            "round" => Some(Shape::Round),
            "slant" => Some(Shape::Slant),
            "flat" => Some(Shape::Flat),
            _ => None,
        }),
        fill: s(r, &["layout", "fill"]).and_then(|v| match v {
            "space" => Some(FillKind::Space),
            "dot" => Some(FillKind::Dot),
            "line" => Some(FillKind::Line),
            _ => None,
        }),
        frame: s(r, &["layout", "frame"]).map(|v| v == "line"),
        ..StyleOptions::default()
    };
    // Built-in segments turned off. `enabled` is an execution key: a
    // shape-only file cannot set it (dropped at the merge), and one from a
    // file that failed the safety check turns the segment off (W405).
    let mut off: BTreeSet<&str> = BTreeSet::new();
    for d in BUILTIN {
        if let Some(n) = get(r, &["segment", d.id, "enabled"]) {
            if n.origin.trust == Trust::Unsafe {
                notes.push(
                    Diagnostic::new(codes::NOT_RUN_UNSAFE_FILE, at(n))
                        .arg("id", d.id)
                        .arg("key", "enabled")
                        .arg("reason", "the file failed the owner and permission check"),
                );
                off.insert(d.id);
            } else if n.value == MValue::Scalar(Value::Bool(false)) {
                off.insert(d.id);
            }
        }
    }
    let base_preset = s(r, &["style", "preset"]).unwrap_or(default_str("style.preset"));
    let banded = bands_of(m)?;
    notes.extend(banded.notes.iter().cloned());
    let mut variants = Vec::new();
    let mut mask = 0u32;
    for lay in layouts(r) {
        let bt = lay.table.as_ref();
        let preset_node = bt
            .and_then(|bt| get(bt, &["style", "preset"]))
            .or_else(|| get(r, &["style", "preset"]));
        let p = bt
            .and_then(|bt| s(bt, &["style", "preset"]))
            .unwrap_or(base_preset);
        // A template replaces preset and options (spec section 2 "스타일 세
        // 단계"); a band's own template wins over the default's.
        let template = lay.template.as_ref();
        // User segments are drawn from M6; built-ins turned off are not drawn.
        let keep = |ids: &[String]| -> Vec<String> {
            ids.iter()
                .filter(|id| !id.contains('/') && !off.contains(id.as_str()))
                .cloned()
                .collect()
        };
        let owned: Vec<(Vec<String>, Vec<String>)> = lay
            .lines
            .iter()
            .filter(|l| l.enabled)
            .map(|l| (keep(&l.left), keep(&l.right)))
            .collect();
        let refs: Vec<(Vec<&str>, Vec<&str>)> = owned
            .iter()
            .map(|(a, b)| {
                (
                    a.iter().map(String::as_str).collect(),
                    b.iter().map(String::as_str).collect(),
                )
            })
            .collect();
        let layout_lines: Vec<LineLayout<'_>> = refs
            .iter()
            .map(|(a, b)| LineLayout { left: a, right: b })
            .collect();
        let mut involved: Vec<&MNode> = lay.lines.iter().flat_map(|l| l.nodes.iter()).collect();
        involved.extend(preset_node);
        involved.extend(template);
        // Explicit templates replace these options; only generated layouts
        // depend on their origins (including template-size failures).
        if template.is_none() {
            if layout_lines.len() > 1 {
                involved.extend(get(r, &["layout", "frame"]));
            }
            if layout_lines.iter().any(|l| !l.right.is_empty()) {
                involved.extend(get(r, &["layout", "fill"]));
            }
            if let Some(pr) = preset(p) {
                let effective = options.over(pr.options);
                if effective.background == Some(true)
                    && effective.joining == Some(Joining::Attached)
                    && layout_lines
                        .iter()
                        .any(|l| l.left.len() > 1 || l.right.len() > 1)
                {
                    involved.extend(get(r, &["style", "separator"]));
                }
            }
        }
        let where_ = blame(&involved);
        let text = match template.map(|n| &n.value) {
            Some(MValue::Scalar(Value::Str(t))) => {
                // Lines or options written next to a template are not used:
                // say so, never drop them in silence.
                if options != StyleOptions::default() || lay.lines.iter().any(|l| l.written) {
                    notes.push(Diagnostic::new(codes::TEMPLATE_REPLACES_STYLE, where_));
                }
                // `custom/…` is drawn from M6 (N502 when declared, W408 when
                // not): only that reference goes, the rest compiles.
                without_hidden(t, &off)
            }
            _ => {
                let pr =
                    preset(p).ok_or_else(|| vec![bad(where_, "style.preset", p, "a preset")])?;
                generate(pr, &options, &layout_lines)
                    .map_err(|_| vec![bad(where_, "layout", "", "a layout that fits a template")])?
            }
        };
        let compiled = compile_template(&text, BUILTIN)
            .map_err(|_| vec![bad(where_, "layout", "", "a layout that compiles")])?;
        // A theme may change how the prompt looks, never erase it: a
        // shape-only template that draws none of the required segments
        // (`char`, `dir`) is an error placed in that file, so rule 5 drops
        // it and the trusted layout stays.
        if let Some(t) = template.filter(|t| t.origin.trust == Trust::ShapeOnly) {
            let needed: Vec<usize> = SETUP
                .iter()
                .filter(|(id, _, required)| *required && !off.contains(id))
                .filter_map(|(id, _, _)| BUILTIN.iter().position(|d| d.id == *id))
                .collect();
            // Fields may be absent; booleans such as char.failed never
            // print text. Only the segment itself guarantees an anchor.
            let draws = |i: usize| {
                compiled.iter().any(|l| {
                    l.nodes()
                        .iter()
                        .any(|n| matches!(n, Node::Segment { seg, .. } if usize::from(*seg) == i))
                })
            };
            if !needed.is_empty() && !needed.iter().any(|&i| draws(i)) {
                return Err(vec![bad(
                    at(t),
                    "style.template",
                    "",
                    "a template that draws char or dir",
                )]);
            }
        }
        for (i, d) in BUILTIN.iter().enumerate() {
            let uses = |l: &CompiledLine| {
                l.nodes().iter().any(|n| matches!(n, Node::Segment { seg, .. } | Node::Field { seg, .. } if usize::from(*seg) == i))
            };
            if compiled.iter().any(uses) && !off.contains(d.id) {
                mask |= 1 << i;
            }
        }
        variants.push(compiled);
    }
    for (id, refs) in drawn(r) {
        if id.starts_with("custom/") && declared(r, &id) {
            let place = refs
                .first()
                .and_then(|r| r.origin)
                .map_or(Place::Builtin, |o| Place::Source {
                    id: o.source,
                    span: o.span,
                });
            notes.push(Diagnostic::new(codes::CUSTOM_DRAWN_LATER, place).arg("id", id));
        }
    }
    let Bands {
        bands,
        names: band_names,
        order: band_order,
        widths,
        ..
    } = banded;
    let one = |src: &str| compile_template(src, BUILTIN).map(|mut v| v.remove(0));
    let transient = one("{char}").map_err(|_| Vec::new())?;
    let vi = one("{char}").map_err(|_| Vec::new())?;
    let dir_methods: Vec<Method> = match get(r, &["segment", "dir", "shorten"]) {
        Some(n) => strings(n).iter().map(|x| method(x)).collect(),
        None => DIR_METHODS.to_vec(),
    };
    let dir_when = match s(r, &["segment", "dir", "when"]) {
        Some("always") => When::Always,
        _ => When::Needed,
    };
    let mut setup = vec![
        Setup {
            priority: 0,
            required: false,
            methods: Vec::new(),
            when: When::Needed
        };
        BUILTIN.len()
    ];
    for (id, priority, required) in SETUP {
        if let Some(i) = BUILTIN.iter().position(|d| d.id == id) {
            setup[i].priority = priority;
            setup[i].required = required;
            if id == "dir" {
                setup[i].methods = dir_methods.clone();
                setup[i].when = dir_when;
            }
        }
    }
    let exec_units = exec_units(r, &trusted.root, &mut notes);
    let profile = WidthProfile::new(
        int(r, &["width", "ambiguous"]).unwrap_or(1) as u8,
        int(r, &["width", "emoji"]).unwrap_or(2) as u8,
    )
    .unwrap_or(WidthProfile::DEFAULT);
    let icons = IconSet::parse(s(r, &["icons"]).unwrap_or(default_str("icons")))
        .unwrap_or(IconSet::Unicode);
    let duration_min_ms = s(r, &["segment", "duration", "min"])
        .and_then(parse_duration_ms)
        .or_else(|| parse_duration_ms(default_str("segment.duration.min")))
        .unwrap_or(2000);
    Ok((
        CompiledConfig {
            variants,
            bands,
            band_names,
            band_order,
            transient,
            vi,
            palette,
            light_palette,
            setup,
            collect_mask: mask,
            icons,
            profile,
            use_last_column: boolean(r, &["layout", "use_last_column"]).unwrap_or(false),
            duration_min_ms,
            exec_units,
            widths,
        },
        notes,
    ))
}

fn exec_units(r: &MTable, trusted: &MTable, notes: &mut Vec<Diagnostic>) -> Vec<ExecUnit> {
    // A unit runs when a trusted layout draws it and it is still drawn.
    let (approved, shown) = (drawn(trusted), drawn(r));
    let mut out = Vec::new();
    for e in entries(r, &["segment"]) {
        let MValue::Table(t) = &e.node.value else {
            continue;
        };
        let str_of = |k: &str| match t.get(k).map(|n| &n.value) {
            Some(MValue::Scalar(Value::Str(v))) => Some(v.clone()),
            _ => None,
        };
        let list = |k: &str| t.get(k).map(strings).unwrap_or_default();
        let policy = match str_of("kind").as_deref() {
            Some("command") => ExecPolicy::Command {
                argv: list("command"),
                cwd: str_of("cwd"),
                env_allow: list("env_allow"),
                shell: str_of("shell"),
                unsafe_shell: boolean(t, &["unsafe_shell"]) == Some(true),
            },
            Some("language") => ExecPolicy::Language {
                interpreter: None,
                version_argv: Vec::new(),
                detect_files: Vec::new(),
            },
            _ => continue,
        };
        let place = at(&e.node);
        let origins: Vec<(String, Origin)> = t
            .entries
            .iter()
            .filter(|k| keys::classify(&["segment", &e.key, &k.key]) == KeyClass::Exec)
            .map(|k| (k.key.clone(), k.node.origin))
            .collect();
        let approved_by = approved.get(&e.key).cloned().unwrap_or_default();
        let shown_at = shown.get(&e.key).cloned().unwrap_or_default();
        let not_run = if let Some((k, origin)) =
            origins.iter().find(|(_, o)| o.trust == Trust::Unsafe)
        {
            notes.push(
                Diagnostic::new(
                    codes::NOT_RUN_UNSAFE_FILE,
                    Place::Source {
                        id: origin.source,
                        span: origin.span,
                    },
                )
                .arg("id", e.key.clone())
                .arg("key", k.clone())
                .arg("reason", "the file failed the owner and permission check"),
            );
            Some(NotRun::UnsafeFile { key: k.clone() })
        } else if boolean(t, &["enabled"]) == Some(false) {
            Some(NotRun::Disabled)
        } else if approved_by.is_empty() || shown_at.is_empty() {
            notes.push(
                Diagnostic::new(codes::NOT_RUN_UNTRUSTED_LAYOUT, place).arg("id", e.key.clone()),
            );
            Some(NotRun::NotInTrustedLayout)
        } else {
            None
        };
        out.push(ExecUnit {
            id: e.key.clone(),
            policy,
            timeout_ms: str_of("timeout").as_deref().and_then(parse_duration_ms),
            cache_ms: str_of("cache").as_deref().and_then(parse_duration_ms),
            origins,
            approved_by,
            shown_at,
            not_run,
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::color::sgr::ColorDepth;
    use crate::config::report::tests::{codes_of, read};
    use crate::default_theme::DefaultTheme;
    use crate::field::{Field, FieldValue, Value as FValue, segment};
    use crate::layout::{Inputs, Options};
    use crate::recorder::NoopRecorder;
    use crate::render::{RenderedPrompt, Target, render_prompt};
    use crate::shell_word::Shell;
    use crate::shorten::{Anchor, PathFacts};

    fn compiled(user: &str) -> CompiledConfig {
        let r = read(user, &[]);
        let codes = codes_of(&r);
        r.snapshot.unwrap_or_else(|| panic!("{codes:?}"))
    }

    fn draw(
        theme: Theme<'_>,
        setup: &[SegmentSetup<'_>],
        icons: IconSet,
        width: u16,
    ) -> RenderedPrompt {
        let i = |id| BUILTIN.iter().position(|s| s.id == id).unwrap();
        let mut values = vec![None; BUILTIN.len()];
        let mut facts = vec![None; BUILTIN.len()];
        let ch = segment("char").unwrap();
        values[i("char")] = Some(FValue::new(b"", vec![Field::ABSENT; ch.fields.len()]));
        let dir = segment("dir").unwrap();
        values[i("dir")] = Some(FValue::new(b"", vec![Field::ABSENT; dir.fields.len()]));
        let steps: [&[u8]; 2] = [b"Works", b"bingsu"];
        facts[i("dir")] = Some(PathFacts::new(Anchor::Home, &steps, None, &[]));
        let du = segment("duration").unwrap();
        values[i("duration")] = Some(FValue::new(
            b"3.0s",
            vec![Field::known(FieldValue::Duration { ms: 3000 }); du.fields.len()],
        ));
        let inputs = Inputs {
            catalog: BUILTIN,
            values: &values,
            facts: &facts,
            setup,
        };
        let t = Target {
            shell: Shell::Zsh,
            depth: ColorDepth::Ansi256,
            options: Options {
                width,
                profile: WidthProfile::DEFAULT,
                icons,
                use_last_column: false,
            },
        };
        render_prompt(&theme, &inputs, &t, &mut NoopRecorder)
    }

    // 이것을 실패시키는 것: 내장 원본(BUILTIN_TOML)과 Part V의 default_theme이 다른 프롬프트를 그리는 것
    // (설정이 없는 사용자의 프롬프트가 바뀜).
    #[test]
    fn builtin_source_draws_the_default_theme() {
        let r = read("", &[]);
        assert!(r.diagnostics.is_empty(), "{:?}", codes_of(&r));
        let c = r.snapshot.unwrap();
        let d = DefaultTheme::new(Mode::Dark).unwrap();
        for w in [120, 59, 40] {
            assert_eq!(
                draw(c.theme(), &c.setup(), c.icons, w),
                draw(d.theme(), d.setup(), crate::default_theme::ICONS, w),
                "width {w}"
            );
        }
        assert_eq!(
            (c.icons, c.profile, c.duration_min_ms),
            (IconSet::Unicode, WidthProfile::DEFAULT, 2000)
        );
    }

    // 이것을 실패시키는 것: 사용자 파일의 값(아이콘·폭·한쪽 배열)을 쓰지 않거나, 쓰지 않은 부분까지 내장 값을 버리는 것.
    #[test]
    fn user_keys_change_only_what_they_write() {
        let c = compiled(
            "icons = \"nerd\"\n[width]\nambiguous = 2\n[layout.line1]\nright = []\n[segment.duration]\nmin = \"500ms\"\n",
        );
        assert_eq!(
            (c.icons, c.profile.ambiguous(), c.duration_min_ms),
            (IconSet::Nerd, 2, 500)
        );
        let d = compiled("");
        let a = draw(c.theme(), &c.setup(), IconSet::Unicode, 120);
        let b = draw(d.theme(), &d.setup(), IconSet::Unicode, 120);
        assert_ne!(a.upper, b.upper);
        assert_eq!(a.left, b.left);
        assert!(String::from_utf8_lossy(&a.upper).contains("bingsu"));
    }

    // 이것을 실패시키는 것: auto 팔레트를 도우미의 화면 모드 하나로 고정하거나 명시 모드를 무시하는 것.
    #[test]
    fn both_display_palettes_survive_compilation() {
        let c = compiled("");
        assert_ne!(c.palette, c.light_palette);
        for mode in [Mode::Dark, Mode::Light] {
            let d = DefaultTheme::new(mode).unwrap();
            assert_eq!(c.theme_for(mode).palette, d.theme().palette);
        }
        let m = crate::config::check::tests::merged_with("", &[]);
        assert_eq!(compile(&m, &m, Mode::Dark), compile(&m, &m, Mode::Light));
        for (text, palette) in [("dark", &c.palette), ("light", &c.light_palette)] {
            let fixed = compiled(&alloc::format!("[colors]\nmode = '{text}'\n"));
            assert_eq!(&fixed.palette, palette);
            assert_eq!(&fixed.light_palette, palette);
        }
    }

    // 이것을 실패시키는 것: 템플릿에서 꺼진 내장 참조·빈 그룹을 남기거나 플러그인 참조까지 조용히 버리는 것.
    #[test]
    fn templates_omit_disabled_builtins_and_reject_unknown_plugins() {
        let c = compiled(
            "[segment.git]\nenabled = false\n[style]\ntemplate = '{dir}{@group}<{git}>{@end}{@nl}{char}'\n",
        );
        let git = BUILTIN.iter().position(|d| d.id == "git").unwrap();
        for lines in &c.variants {
            assert!(lines.iter().flat_map(|l| l.nodes()).all(|n| !matches!(n,
                Node::Segment { seg, .. } | Node::Field { seg, .. } if usize::from(*seg) == git)));
        }
        assert_eq!(
            c.variants[0],
            compiled("[style]\ntemplate = '{dir}{@nl}{char}'\n").variants[0]
        );
        assert!(
            read("[style]\ntemplate = '{dir}{acme/unknown}'\n", &[])
                .snapshot
                .is_none()
        );
    }

    /// Every shape key, a file that sets it away from the built-in value.
    const EFFECTS: &[(&str, &str)] = &[
        ("colors.knobs.accent_c", "[colors.knobs]\naccent_c = 0.2\n"),
        ("colors.knobs.accent_l", "[colors.knobs]\naccent_l = 0.5\n"),
        ("colors.knobs.hue", "[colors.knobs]\nhue = 100\n"),
        ("colors.mode", "[colors]\nmode = \"light\"\n"),
        (
            "colors.override.*",
            "[colors.override]\n\"git.dirty\" = \"#ff0000\"\n",
        ),
        ("colors.roles.*", "[colors.roles]\npath = \"accent.red\"\n"),
        ("icons", "icons = \"nerd\"\n"),
        ("layout.fill", "[layout]\nfill = \"dot\"\n"),
        ("layout.frame", "[layout]\nframe = \"line\"\n"),
        ("layout.line1.enabled", "[layout.line1]\nenabled = false\n"),
        ("layout.line1.left", "[layout.line1]\nleft = [\"dir\"]\n"),
        ("layout.line1.right", "[layout.line1]\nright = []\n"),
        ("layout.line2.enabled", "[layout.line2]\nenabled = false\n"),
        (
            "layout.line2.left",
            "[layout.line2]\nleft = [\"dir\", \"char\"]\n",
        ),
        ("layout.line2.right", "[layout.line2]\nright = [\"time\"]\n"),
        (
            "layout.use_last_column",
            "[layout]\nuse_last_column = true\n",
        ),
        (
            "layout.when.*.line1.enabled",
            "[layout.when.wide.line1]\nenabled = false\n",
        ),
        (
            "layout.when.*.line1.left",
            "[layout.when.wide.line1]\nleft = [\"dir\"]\n",
        ),
        (
            "layout.when.*.line1.right",
            "[layout.when.wide.line1]\nright = [\"time\"]\n",
        ),
        (
            "layout.when.*.line2.enabled",
            "[layout.when.wide.line2]\nenabled = false\n",
        ),
        (
            "layout.when.*.line2.left",
            "[layout.when.wide.line2]\nleft = [\"duration\", \"char\"]\n",
        ),
        (
            "layout.when.*.line2.right",
            "[layout.when.wide.line2]\nright = [\"time\"]\n",
        ),
        (
            "layout.when.*.max_cols",
            "[layout.when.narrow]\nmax_cols = 40\n",
        ),
        (
            "layout.when.*.min_cols",
            "[layout.when.narrow]\nmin_cols = 10\n",
        ),
        ("layout.when.*.order", "[layout.when.narrow]\norder = 1\n"),
        (
            "layout.when.*.style.preset",
            "[layout.when.wide.style]\npreset = \"lean\"\n",
        ),
        (
            "segment.dir.shorten",
            "[segment.dir]\nshorten = [\"depth\"]\n",
        ),
        ("segment.dir.when", "[segment.dir]\nwhen = \"always\"\n"),
        ("segment.duration.min", "[segment.duration]\nmin = \"5s\"\n"),
        ("style.preset", "[style]\npreset = \"lean\"\n"),
        ("style.separator", "[style]\nseparator = \"round\"\n"),
        ("width.ambiguous", "[width]\nambiguous = 2\n"),
        ("width.emoji", "[width]\nemoji = 1\n"),
        (
            "style.template",
            "[style]\ntemplate = \"{dir}{@nl}{char}\"\n",
        ),
        (
            "layout.when.*.style.template",
            "[layout.when.wide.style]\ntemplate = \"{dir}{@nl}{char}\"\n",
        ),
    ];
    /// Shape keys that cannot change the output yet, and why.
    const NO_EFFECT: [(&str, &str); 4] = [
        (
            "theme",
            "one built-in theme: the only accepted value is the default",
        ),
        (
            "colors.flavor",
            "one flavor: the only accepted value is the default",
        ),
        (
            "segment.*.text",
            "user segments are drawn from M6; N502 says so",
        ),
        ("layout.transient", "planned for M4 and M5; N503 says so"),
    ];

    // 받아 놓고 쓰지 않는 키는 조용한 무시다(스펙 6절 규칙 5가 가장 나쁘다고 한 실패).
    // 이것을 실패시키는 것: 모양 키를 검사만 하고 컴파일에 잇지 않는 것, 새 모양 키를 이 표에 더하지 않는 것.
    #[test]
    fn every_shape_key_changes_the_compiled_config() {
        use crate::config::keys::{KEYS, Ty};
        let base = compiled("");
        for k in KEYS
            .iter()
            .filter(|k| k.class == KeyClass::Shape && k.ty != Ty::Table)
        {
            let effect = EFFECTS.iter().find(|(p, _)| *p == k.path);
            let none = NO_EFFECT.iter().find(|(p, _)| *p == k.path);
            match (effect, none) {
                (Some((_, src)), None) => {
                    // Band keys are tried on a band of their own, against the
                    // same band without the key.
                    let wide = "[layout.when.wide]\nmin_cols = 100\n";
                    let (with, without) = if src.contains("layout.when.wide") {
                        (alloc::format!("{wide}{src}"), compiled(wide))
                    } else {
                        (String::from(*src), base.clone())
                    };
                    assert!(compiled(&with) != without, "{} has no effect", k.path);
                }
                (None, Some(_)) => {}
                _ => panic!("{} must be in exactly one of EFFECTS and NO_EFFECT", k.path),
            }
        }
        // A planned key is accepted with a notice, not an error.
        let r = read("[layout]\ntransient = \"char\"\n", &[]);
        assert!(r.snapshot.is_some());
        assert_eq!(codes_of(&r), [codes::KEY_PLANNED]);
    }

    // 이것을 실패시키는 것: 실행 정책 필드(cwd·env_allow·timeout·cache·shell)와 키별 출처를 snapshot에서 버리는 것.
    #[test]
    fn exec_units_keep_their_whole_policy() {
        let c = compiled(
            "[segment.\"custom/k\"]\nkind = \"command\"\ncommand = [\"k\", \"x\"]\ncwd = \"/w\"\nenv_allow = [\"KUBECONFIG\"]\ntimeout = \"200ms\"\ncache = \"30s\"\n[layout.line1]\nleft = [\"custom/k\"]\n",
        );
        let u = &c.exec_units[0];
        let want = ExecPolicy::Command {
            argv: vec![String::from("k"), String::from("x")],
            cwd: Some(String::from("/w")),
            env_allow: vec![String::from("KUBECONFIG")],
            shell: None,
            unsafe_shell: false,
        };
        assert_eq!(
            (&u.policy, u.timeout_ms, u.cache_ms, &u.not_run),
            (&want, Some(200), Some(30_000), &None)
        );
        // The trusted reference that lets it run, and where it shows.
        let r = &u.approved_by[0];
        assert_eq!((r.band.as_deref(), r.line, r.side), (None, 1, Side::Left));
        assert_eq!(r.origin.map(|o| o.source), Some(crate::diag::SourceId(1)));
        assert_eq!(u.approved_by, u.shown_at);
        let keys: Vec<&str> = u.origins.iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(
            keys,
            ["kind", "command", "cwd", "env_allow", "timeout", "cache"]
        );
        let c = compiled(
            "[segment.\"custom/l\"]\nkind = \"language\"\n[layout.line1]\nleft = [\"custom/l\"]\n",
        );
        assert!(matches!(
            c.exec_units[0].policy,
            ExecPolicy::Language { .. }
        ));
    }

    // 이것을 실패시키는 것: 안전 검사에 실패한 파일의 실행 키로 명령을 켜는 것(이름은 알려야 함).
    #[test]
    fn unsafe_file_commands_do_not_run() {
        let seg = "[segment.\"custom/k\"]\nkind = \"command\"\ncommand = [\"k\"]\n";
        let r = read(
            "extends = [\"unsafe-mine\"]\n[layout.line1]\nleft = [\"custom/k\"]\n",
            &[("unsafe-mine", seg)],
        );
        let c = r.snapshot.unwrap();
        assert_eq!(
            c.exec_units[0].not_run,
            Some(NotRun::UnsafeFile {
                key: String::from("kind")
            })
        );
        assert!(
            r.diagnostics
                .iter()
                .any(|d| d.code == codes::NOT_RUN_UNSAFE_FILE)
        );
    }

    // 템플릿은 프리셋·옵션·줄을 대신한다. 템플릿 옆에 쓴 줄은 쓰이지 않으니 알림 N501로 알린다.
    // 이것을 실패시키는 것: 템플릿을 무시하는 것, 템플릿 옆의 줄을 말없이 버리는 것.
    #[test]
    fn a_template_replaces_lines_and_says_so() {
        let c = compiled("[style]\ntemplate = \"{dir}{@nl}{char}\"\n");
        assert_ne!(c.variants[0], compiled("").variants[0]);
        let r = read(
            "[style]\ntemplate = \"{dir}{@nl}{char}\"\n[layout.line1]\nleft = [\"git\"]\n",
            &[],
        );
        assert!(
            codes_of(&r).contains(&codes::TEMPLATE_REPLACES_STYLE),
            "{:?}",
            codes_of(&r)
        );
    }

    // 이것을 실패시키는 것: 꺼진 내장 세그먼트를 그리거나 수집 mask에 남기는 것, 그려지는 세그먼트를 mask에서 빠뜨리는 것.
    #[test]
    fn collect_mask_follows_drawn_and_enabled_segments() {
        let bit = |id| 1u32 << BUILTIN.iter().position(|d| d.id == id).unwrap();
        let c = compiled("");
        assert_ne!(c.collect_mask & bit("git"), 0);
        let c = compiled("[segment.git]\nenabled = false\n");
        assert_eq!(c.collect_mask & bit("git"), 0);
        assert_ne!(c.variants, compiled("").variants, "git is not drawn");
        let git = BUILTIN.iter().position(|d| d.id == "git").unwrap();
        assert!(
            c.variants
                .iter()
                .flatten()
                .flat_map(|l| l.nodes())
                .all(|n| !matches!(n,
            Node::Segment { seg, .. } | Node::Field { seg, .. } if usize::from(*seg) == git))
        );
        let c = compiled(
            "[layout.line1]\nleft = [\"dir\"]\nright = []\n[layout.when.narrow.style]\ntemplate = \"{dir}{@nl}{char}\"\n",
        );
        assert_eq!(c.collect_mask & bit("git"), 0);
    }

    // 이것을 실패시키는 것: 팔레트·구간 오류를 내장 위치로 알리는 것(사용자 파일의 그 키를 가리켜야 함).
    #[test]
    fn derived_errors_point_at_the_key() {
        let src = "[colors.roles]\npath = \"accent.nope\"\n";
        let r = read(src, &[]);
        let d = r
            .diagnostics
            .iter()
            .find(|d| d.code == codes::BAD_VALUE)
            .unwrap();
        let Place::Source { id, span } = d.at else {
            panic!("{:?}", d.at)
        };
        assert_eq!(
            (id, span.start as usize),
            (
                crate::diag::SourceId(1),
                src.find("\"accent.nope\"").unwrap()
            )
        );
        let src = "[layout.when.a]\nmin_cols = 1\nmax_cols = 70\n";
        let r = read(src, &[]);
        let d = r
            .diagnostics
            .iter()
            .find(|d| d.code == codes::BAD_VALUE)
            .unwrap();
        assert!(
            matches!(
                d.at,
                Place::Source {
                    id: crate::diag::SourceId(1),
                    ..
                }
            ),
            "{:?}",
            d.at
        );
    }
}
