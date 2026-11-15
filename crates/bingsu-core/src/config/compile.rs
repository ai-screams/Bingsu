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
use crate::diag::{Diagnostic, Place, SourceId};
use crate::diag_codes as codes;
use crate::diag_widths::{WidthRun, width_table};
use crate::field::BUILTIN;
use crate::icons::IconSet;
use crate::layout::{SegmentSetup, When};
use crate::render::Theme;
use crate::shorten::Method;
use crate::style::{Joining, LineLayout, StyleOptions, generate, preset};
use crate::template::compile::{CompiledLine, FillKind, Node, Shape, compile_builtin};
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
    /// A user-defined language version: `interpreter`, its `version`
    /// arguments and the `detect_files` that mark the language's project
    /// (`language_form` checks them), with the folder it runs in and the
    /// variables it receives as a command's.
    Language {
        interpreter: Option<String>,
        version_argv: Vec<String>,
        detect_files: Vec<String>,
        cwd: Option<String>,
        env_allow: Vec<String>,
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
    /// A reference names a band index the config does not have.
    UnknownBand,
    /// `shell` without `unsafe_shell = true` (an error, E211).
    ShellNotAllowed,
    /// `match` does not compile or passes the size limit (E203, decided by
    /// the CLI's `bingsu-match`, never by core).
    MatchInvalid,
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
    /// A command segment's `match`: the helper applies it to the first line
    /// before publishing, the prompt compares its digest
    /// (`command::wire::pattern_digest`). Not in the policy digest, so a
    /// change of `match` alone runs nothing again.
    pub pattern: Option<String>,
}

/// Most user segments a config draws, text and command together (the
/// snapshot carries each one).
pub const MAX_CUSTOM_TEXT: usize = 256;
/// Command and language segments one config may draw: those a trusted
/// layout draws at some width and that may run (32 units, the
/// command response's `CONFIG_ENTRIES_MAX`, which holds only units that run). A
/// declared segment no layout draws is not counted.
pub const MAX_EXEC_UNITS: usize = 32;

/// A user `custom/…` segment a layout draws. Its segment number is
/// `field::BUILTIN.len()` plus its place in `CompiledConfig::custom`, which
/// is sorted by id; the one field is `value` (`field::CUSTOM_TEXT`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CustomSegment {
    pub id: String,
    pub kind: CustomKind,
}

/// What a user segment shows.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CustomKind {
    /// `kind = "text"`: its text, cut to the field's cells.
    Text(String),
    /// `kind = "command"`: the unit's value from the command response; a
    /// segment with no value draws nothing.
    Command,
    /// `kind = "env"`: the value of this variable in the prompt's own
    /// environment, cut like text; unset or empty draws nothing.
    Env(String),
    /// `kind = "language"`: the unit's version from the command response,
    /// as a command's value; a segment with no value draws nothing.
    Language,
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
    /// Disabled-aware upper bound over all layout references, including bands
    /// hidden by priority. Collection intersects it with the selected variant
    /// and the adapter's fixed worker catalog; it is not execution authority.
    /// Dir references need readonly/repo facts even without unique shortening.
    pub collect_mask: u32,
    pub icons: IconSet,
    pub profile: WidthProfile,
    pub use_last_column: bool,
    pub duration_min_ms: u64,
    pub exec_units: Vec<ExecUnit>,
    /// Drawn text segments, sorted by id.
    pub custom: Vec<CustomSegment>,
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
    /// The same per-segment setup the prompt front lays out with.
    pub fn setup(&self) -> Vec<SegmentSetup<'_>> {
        crate::layout_view::LayoutView::shared(self).segment_setup()
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

fn optional_duration(text: Option<&str>) -> Option<u64> {
    match text {
        Some(text) => parse_duration_ms(text),
        None => None,
    }
}

fn place_of(t: &MTable, path: &[&str]) -> Place {
    match get(t, path) {
        Some(n) => at(n),
        None => Place::Builtin,
    }
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

/// The bands of `when` (the `layout.when` table) that are on: a band with
/// `enabled = false` is left out of the band choice, the width table and the
/// compiled variants, so its widths go to the next band that fits them and
/// only then to the default layout (the first band that fits wins,
/// `bands::select`). `layouts` and
/// `bands_of` both walk bands through this, which keeps a band's index the
/// same in both. The band count limit and the layout budget still count
/// every band written, off or not.
///
/// `off` comes from `off_bands`, once per compile.
fn live_bands<'a>(when: &'a [MEntry], off: &'a BTreeSet<&str>) -> impl Iterator<Item = &'a MEntry> {
    when.iter().filter(move |b| !off.contains(b.key.as_str()))
}

/// The names of the bands turned off: `enabled = false` read from
/// `trusted`, the merge of the trusted sources alone (as `approved` does for
/// layouts), because `enabled` is an execution key. A shape-only file's value
/// is already dropped at the merge (W401), and one from a file that failed
/// the safety check (Unsafe) neither turns a band off nor turns back on a
/// band a trusted file turned off. One pass over the trusted bands, so a
/// compile reads it once and every band choice looks a name up in the set.
pub fn off_bands(trusted: &MTable) -> BTreeSet<&str> {
    // 이것을 실패시키는 것: `enabled = false`인 구간을 남기는 것(내장 narrow를 끌 수 없음), `enabled` 없는
    // 구간이나 `true`인 구간을 빼는 것, 전체 병합의 값을 읽는 것(안전 검사에 실패한 파일이 구간을 끄거나
    // 신뢰 파일이 끈 구간을 다시 켬).
    entries(trusted, &["layout", "when"])
        .iter()
        .filter(|b| {
            matches!(&b.node.value, MValue::Table(bt)
                if bt.get("enabled").is_some_and(|n| n.value == MValue::Scalar(Value::Bool(false))))
        })
        .map(|b| b.key.as_str())
        .collect()
}

fn layouts(r: &MTable, off: &BTreeSet<&str>) -> Vec<Layout> {
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
    for b in live_bands(entries(&layout, &["when"]), off) {
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

/// Where a segment id is drawn: the layout (`band` None is the default, else
/// the index into `CompiledConfig::bands`), line 1 or 2 (0: named by a
/// template, which replaces the lines), the side, and the array or template
/// that put it there.
#[derive(Clone, Debug, PartialEq)]
pub struct LayoutRef {
    pub band: Option<u16>,
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

/// `text` without custom references other than the drawn user segments
/// `texts`, and without disabled built-ins:
/// each is cut out, and so is a group left without a reference (a
/// group needs one to compile). A template that does not parse is kept as
/// it is, so the compile reports it.
fn without_hidden(text: &str, off: &BTreeSet<&str>, texts: &[&str]) -> String {
    fn cuts(
        items: &[(Syntax, TSpan)],
        off: &BTreeSet<&str>,
        texts: &[&str],
        out: &mut Vec<TSpan>,
    ) -> bool {
        let mut kept = false;
        for (syn, sp) in items {
            match syn {
                Syntax::Segment { id, .. } | Syntax::Field { segment: id, .. } => {
                    if (id.starts_with("custom/") && !texts.contains(&id.as_str()))
                        || off.contains(id.as_str())
                    {
                        out.push(*sp);
                    } else {
                        kept = true;
                    }
                }
                Syntax::Group(body) => {
                    let mut inner = Vec::new();
                    if cuts(body, off, texts, &mut inner) || inner.is_empty() {
                        out.extend(inner);
                        kept = true;
                    } else {
                        out.push(*sp);
                    }
                }
                Syntax::Style { body, .. } => kept |= cuts(body, off, texts, out),
                _ => {}
            }
        }
        kept
    }
    let Ok(tree) = parse_template(text) else {
        return String::from(text);
    };
    let mut gone = Vec::new();
    cuts(&tree, off, texts, &mut gone);
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

/// The built-in theme is the first source of every read (module comment).
const BUILTIN_SOURCE: SourceId = SourceId(0);

/// Widths `from..=to` as the width table of `config check` writes them.
fn width_span(from: u16, to: u16) -> String {
    if to == u16::MAX {
        alloc::format!("{from}+")
    } else if from == to {
        alloc::format!("{from}")
    } else {
        alloc::format!("{from}-{to}")
    }
}

/// N504: a band's own template draws in place of the lines the band takes
/// from `[layout]`. Said only for lines a file wrote that is neither the
/// built-in theme nor the file of the template (a file that writes both
/// chose it); lines the band writes itself are N501's case. `None` when no
/// such line is replaced or no width draws the band.
fn band_replaces_lines(lay: &Layout, own: &MNode, widths: &[WidthRun]) -> Option<Diagnostic> {
    let name = lay.name.as_ref()?;
    let mut lines = Vec::new();
    let mut first = None;
    for (i, l) in lay.lines.iter().enumerate() {
        // 이것을 실패시키는 것: 구간이 직접 쓴 줄에도 내는 것(N501과 겹침).
        if l.written {
            continue;
        }
        // 이것을 실패시키는 것: 내장 테마가 쓴 줄에 내는 것(설정 없는 사용자에게도 노트), 템플릿과 같은 파일이
        // 쓴 줄에 내는 것, 사용자 파일이 쓴 줄을 놓치는 것.
        let by_user = l
            .nodes
            .iter()
            .find(|n| n.origin.source != BUILTIN_SOURCE && n.origin.source != own.origin.source);
        if let Some(n) = by_user {
            first.get_or_insert(n);
            lines.push(alloc::format!("layout.line{}", i + 1));
        }
    }
    let first = first?;
    let spans: Vec<String> = widths
        .iter()
        .filter(|w| w.band.as_deref() == Some(name.as_str()))
        .map(|w| width_span(w.from, w.to))
        .collect();
    // 이것을 실패시키는 것: 어느 폭에서도 골라지지 않는 구간(W407)에 내는 것.
    if spans.is_empty() {
        return None;
    }
    Some(
        Diagnostic::new(codes::BAND_TEMPLATE_REPLACES_LINES, at(first))
            .arg("band", name.clone())
            .arg("widths", spans.join(", "))
            .arg("lines", lines.join(" and ")),
    )
}

/// The index of a band name; a name `names` lacks gets `names.len()`, which
/// `layout_verdict` treats as unknown.
fn band_index(names: &[String], name: &Option<String>) -> Option<u16> {
    name.as_ref()
        .map(|n| names.iter().position(|x| x == n).unwrap_or(names.len()) as u16)
}

/// Every id on a drawn line, with where. Bands are indexed by `names`.
fn drawn(r: &MTable, off: &BTreeSet<&str>, names: &[String]) -> BTreeMap<String, Vec<LayoutRef>> {
    let mut out: BTreeMap<String, Vec<LayoutRef>> = BTreeMap::new();
    for lay in layouts(r, off) {
        let band = band_index(names, &lay.name);
        if let Some(t) = &lay.template {
            // A template replaces the lines: what it names is what is drawn.
            if let MValue::Scalar(Value::Str(text)) = &t.value {
                for id in template_ids(text) {
                    out.entry(id).or_default().push(LayoutRef {
                        band,
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
                        band,
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

/// `off` names the bands turned off (`off_bands`).
pub fn bands_of(m: &Merged, off: &BTreeSet<&str>) -> Result<Bands, Vec<Diagnostic>> {
    let r = &m.root;
    check_band_count(r)?;
    let mut bands = Vec::new();
    let mut names = Vec::new();
    let mut nodes: Vec<Vec<MNode>> = Vec::new();
    for b in live_bands(entries(r, &["layout", "when"]), off) {
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
/// `auto` remains in the interface for existing callers. Returns the config
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
    // `off` above is the built-in segments turned off; these are the bands.
    let bands_off = off_bands(&trusted.root);
    let banded = bands_of(m, &bands_off)?;
    notes.extend(banded.notes.iter().cloned());
    let profile = WidthProfile::new(
        int(r, &["width", "ambiguous"]).unwrap_or(1) as u8,
        int(r, &["width", "emoji"]).unwrap_or(2) as u8,
    )
    .unwrap_or(WidthProfile::DEFAULT);
    let shown_bands = selectable(&banded.order, &banded.bands);
    // What a trusted layout can draw is judged on the trusted merge alone: a
    // shape-only source may re-order or resize bands, but must not make a band
    // reachable that the trusted sources never reach. A trusted merge whose
    // bands fail to order approves nothing.
    let approved_bands = bands_of(trusted, &bands_off).map_or_else(
        |_| BTreeSet::new(),
        |t| {
            let full = &banded.names;
            crate::bands::selection_table(&t.order, &t.bands)
                .into_iter()
                .filter_map(|(_, _, b)| match b {
                    None => Some(None),
                    Some(i) => full
                        .iter()
                        .position(|n| *n == t.names[i])
                        .map(|j| Some(j as u16)),
                })
                .collect()
        },
    );
    let reach = Reach {
        approved: approved_bands,
        shown: shown_bands,
    };
    // Without a declared user segment of a drawn kind nothing is looked up,
    // so the usual config compiles exactly as it did before user segments.
    let custom = if declares_custom(r) {
        custom_segments(
            r,
            &drawn(r, &bands_off, &banded.names),
            &drawn(&trusted.root, &bands_off, &banded.names),
            banded.names.len(),
            &reach,
            profile,
            &mut notes,
        )?
    } else {
        Vec::new()
    };
    let texts: Vec<&str> = custom.iter().map(|c| c.id.as_str()).collect();
    let mut variants = Vec::new();
    let mut mask = 0u32;
    for lay in layouts(r, &bands_off) {
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
        // Command and language segments are drawn from M6, text segments now;
        // built-ins turned off are not drawn.
        let keep = |ids: &[String]| -> Vec<String> {
            ids.iter()
                .filter(|id| {
                    (!id.contains('/') || texts.contains(&id.as_str()))
                        && !off.contains(id.as_str())
                })
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
                    a.iter().map(|s| s.as_str()).collect(),
                    b.iter().map(|s| s.as_str()).collect(),
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
                // A band's own template also draws in place of the lines it
                // takes from `[layout]`: never in silence either.
                // 이것을 실패시키는 것: 구간이 물려받은 기본 템플릿(자기 것 아님)에 내는 것(N501이 기본 레이아웃에서 이미 알림).
                if let Some(own) = bt.and_then(|bt| get(bt, &["style", "template"])) {
                    notes.extend(band_replaces_lines(&lay, own, &banded.widths));
                }
                // A `custom/…` reference that is not drawn (turned off, or
                // undeclared, which W408 names) goes alone; the rest compiles.
                without_hidden(t, &off, &texts)
            }
            _ => {
                let pr =
                    preset(p).ok_or_else(|| vec![bad(where_, "style.preset", p, "a preset")])?;
                generate(pr, &options, &layout_lines)
                    .map_err(|_| vec![bad(where_, "layout", "", "a layout that fits a template")])?
            }
        };
        let compiled = compile_builtin(&text, &texts)
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
        let referenced = crate::collection::selection::references(&compiled);
        for (i, d) in BUILTIN.iter().enumerate() {
            if referenced & (1 << i) != 0 && !off.contains(d.id) {
                mask |= 1 << i;
            }
        }
        variants.push(compiled);
    }
    let Bands {
        bands,
        names: band_names,
        order: band_order,
        widths,
        ..
    } = banded;
    let one = |src: &str| compile_builtin(src, &[]).map(|mut v| v.remove(0));
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
    let exec_units = exec_units(
        r,
        &trusted.root,
        &bands_off,
        &band_names,
        &reach,
        &mut notes,
    )?;
    let icons = IconSet::parse(s(r, &["icons"]).unwrap_or(default_str("icons")))
        .unwrap_or(IconSet::Unicode);
    let duration_min_ms = optional_duration(s(r, &["segment", "duration", "min"]))
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
            custom,
            widths,
        },
        notes,
    ))
}

/// The layouts a width can choose, for the trusted merge (what approves a
/// unit) and for the full merge (what is on screen).
pub(crate) struct Reach {
    approved: BTreeSet<Option<u16>>,
    shown: BTreeSet<Option<u16>>,
}

/// The layouts a width can choose: `None` is the default layout, `Some(i)` band `i`.
fn selectable(order: &[usize], bands: &[Band]) -> BTreeSet<Option<u16>> {
    crate::bands::selection_table(order, bands)
        .into_iter()
        .map(|(_, _, b)| b.map(|i| i as u16))
        .collect()
}

/// Whether a unit with these references may run, judged on layout alone.
/// Every kind of unit goes through this one function. A reference counts only
/// where a width can choose that layout, since no other line is ever drawn.
pub(crate) fn layout_verdict(
    approved_by: &[LayoutRef],
    shown_at: &[LayoutRef],
    band_count: usize,
    reach: &Reach,
) -> Option<NotRun> {
    let refs = || approved_by.iter().chain(shown_at);
    if refs().any(|r| r.band.is_some_and(|b| usize::from(b) >= band_count)) {
        return Some(NotRun::UnknownBand);
    }
    let live =
        |v: &[LayoutRef], set: &BTreeSet<Option<u16>>| v.iter().any(|r| set.contains(&r.band));
    (!live(approved_by, &reach.approved) || !live(shown_at, &reach.shown))
        .then_some(NotRun::NotInTrustedLayout)
}

/// The user segment kinds a layout draws.
const DRAWN_KINDS: [&str; 4] = ["text", "command", "env", "language"];

/// Whether any `custom/…` segment is declared with a drawn kind.
fn declares_custom(r: &MTable) -> bool {
    entries(r, &["segment"]).iter().any(|e| {
        e.key.starts_with("custom/")
            && matches!(&e.node.value, MValue::Table(t)
                if s(t, &["kind"]).is_some_and(|k| DRAWN_KINDS.contains(&k)))
    })
}

/// The `kind = "text"`, `"command"` and `"env"` segments some layout draws,
/// sorted by id. A segment turned off (`enabled = false`, or from a file
/// that failed the safety check) is not drawn; a missing `text` shows
/// nothing. A command segment carries no value here: the prompt fills it
/// from the command response, and draws nothing without one. An env segment
/// carries the name of its variable, which the prompt reads from its own
/// environment; like a command it shows only where a trusted layout draws
/// it (`layout_verdict`, `trusted` the references of the trusted merge), so
/// a repository's config cannot put the user's variables on screen.
fn custom_segments(
    r: &MTable,
    drawn: &BTreeMap<String, Vec<LayoutRef>>,
    trusted: &BTreeMap<String, Vec<LayoutRef>>,
    band_count: usize,
    reach: &Reach,
    profile: WidthProfile,
    notes: &mut Vec<Diagnostic>,
) -> Result<Vec<CustomSegment>, Vec<Diagnostic>> {
    let mut out: Vec<CustomSegment> = Vec::new();
    for e in entries(r, &["segment"]) {
        let MValue::Table(t) = &e.node.value else {
            continue;
        };
        let Some(kind) = s(t, &["kind"]).filter(|k| DRAWN_KINDS.contains(k)) else {
            continue;
        };
        if !e.key.starts_with("custom/") || !drawn.contains_key(&e.key) {
            continue;
        }
        // `kind` and `enabled` are execution keys: one written by a file
        // that failed the safety check keeps the segment from being drawn.
        if unsafe_exec_key(&e.key, &exec_origins(&e.key, t), notes).is_some()
            || boolean(t, &["enabled"]) == Some(false)
        {
            continue;
        }
        if kind == "env" {
            let approved_by = trusted.get(&e.key).map_or(&[][..], |v| v.as_slice());
            let shown_at = drawn.get(&e.key).map_or(&[][..], |v| v.as_slice());
            if layout_verdict(approved_by, shown_at, band_count, reach).is_some() {
                notes.push(
                    Diagnostic::new(codes::NOT_RUN_UNTRUSTED_LAYOUT, at(&e.node))
                        .arg("id", e.key.clone()),
                );
                continue;
            }
        }
        out.push(CustomSegment {
            id: e.key.clone(),
            kind: if kind == "command" {
                CustomKind::Command
            } else if kind == "language" {
                CustomKind::Language
            } else if kind == "env" {
                // Checked as a variable name (`check::env_name`) before compile.
                CustomKind::Env(s(t, &["env"]).unwrap_or_default().into())
            } else {
                // Cut here, to the cells the field shows, so the stored text
                // is what the front draws and always fits the codec's byte
                // cap (`Clean` keeps at most `CUSTOM_TEXT_CELLS * 4` bytes).
                CustomKind::Text(
                    crate::field::Clean::new(
                        s(t, &["text"]).unwrap_or_default().as_bytes(),
                        crate::field::CUSTOM_TEXT_CELLS,
                        profile,
                    )
                    .as_str()
                    .into(),
                )
            },
        });
    }
    out.sort_by(|a, b| a.id.cmp(&b.id));
    out.dedup_by(|a, b| a.id == b.id);
    if out.len() > MAX_CUSTOM_TEXT {
        return Err(vec![bad(
            place_of(r, &["segment"]),
            "segment",
            &alloc::format!("{}", out.len()),
            "at most 256 drawn text, command and env segments",
        )]);
    }
    Ok(out)
}

/// Each execution key written for a segment and its origin.
fn exec_origins(id: &str, t: &MTable) -> Vec<(String, Origin)> {
    t.entries
        .iter()
        .filter(|k| keys::classify(&["segment", id, &k.key]) == KeyClass::Exec)
        .map(|k| (k.key.clone(), k.node.origin))
        .collect()
}

/// The first execution key written by a file that failed the safety check,
/// with the W405 note that says the segment is not used for it. Every kind
/// of segment, drawn text included, goes through this one judgement.
fn unsafe_exec_key(
    id: &str,
    origins: &[(String, Origin)],
    notes: &mut Vec<Diagnostic>,
) -> Option<String> {
    let (k, origin) = origins.iter().find(|(_, o)| o.trust == Trust::Unsafe)?;
    notes.push(
        Diagnostic::new(
            codes::NOT_RUN_UNSAFE_FILE,
            Place::Source {
                id: origin.source,
                span: origin.span,
            },
        )
        .arg("id", id)
        .arg("key", k.clone())
        .arg("reason", "the file failed the owner and permission check"),
    );
    Some(k.clone())
}

/// The placeholder this version replaces (`{branch}` and others come with
/// the facts they need).
const PLACEHOLDER: &str = "{dir}";

/// `env_allow` names that can be variable names and that a command may
/// receive, and the warning for `cwd = "untrusted-current"`: the same for a
/// command and a language segment.
fn env_and_cwd_form(id: &str, t: &MTable, notes: &mut Vec<Diagnostic>) {
    let item = |n: &MNode, span| Place::Source {
        id: n.origin.source,
        span,
    };
    if let Some(
        n @ MNode {
            value: MValue::Array(names),
            ..
        },
    ) = t.get("env_allow")
    {
        for w in names {
            if let Value::Str(v) = &w.value {
                if v.is_empty() || v.contains(['=', '\0']) {
                    notes.push(bad(
                        item(n, w.span),
                        "env_allow",
                        &alloc::format!("\"{v}\""),
                        "a variable name: not empty, without `=` or NUL",
                    ));
                } else if crate::command::grant::forbidden(v.as_bytes()) {
                    notes.push(bad(
                        item(n, w.span),
                        "env_allow",
                        &alloc::format!("\"{v}\""),
                        "a name a command may receive: loader, language and shell startup settings never pass",
                    ));
                }
            }
        }
    }
    if let Some(c) = t
        .get("cwd")
        .filter(|c| matches!(&c.value, MValue::Scalar(Value::Str(v)) if v == "untrusted-current"))
    {
        notes.push(Diagnostic::new(codes::CWD_UNTRUSTED_CURRENT, at(c)).arg("id", id));
    }
}

/// A language segment's shape (D3c rulings): `detect_files`, one to
/// `collection::language::NAMES_MAX` file names, each one path component
/// the worker can look for (`collection::language::name_ok`), none given
/// twice; `interpreter`, a word without NUL; `version`, words without NUL.
/// Problems are errors in `notes`.
fn language_form(id: &str, seg: &MNode, t: &MTable, notes: &mut Vec<Diagnostic>) {
    // Fails without it: language_keys_are_checked (a forbidden env_allow
    // name, the untrusted-current warning).
    env_and_cwd_form(id, t, notes);
    use crate::collection::language::{NAMES_MAX, name_ok};
    let item = |n: &MNode, span| Place::Source {
        id: n.origin.source,
        span,
    };
    match t.get("detect_files") {
        None => notes.push(bad(
            at(seg),
            "detect_files",
            "nothing",
            "the file names that mark this language's project",
        )),
        Some(
            n @ MNode {
                value: MValue::Array(names),
                ..
            },
        ) => {
            // Fails without it: language_keys_are_checked (empty, 17 names).
            if names.is_empty() || names.len() > NAMES_MAX {
                notes.push(bad(
                    at(n),
                    "detect_files",
                    &alloc::format!("{} names", names.len()),
                    "1 to 16 file names",
                ));
            }
            let mut seen: Vec<&str> = Vec::new();
            for w in names {
                let Value::Str(v) = &w.value else { continue };
                // Fails without it: language_keys_are_checked (a path, `..`,
                // a name given twice).
                if !name_ok(v.as_bytes()) {
                    notes.push(bad(
                        item(n, w.span),
                        "detect_files",
                        &alloc::format!("\"{v}\""),
                        "one file name: not empty, no `/` or NUL, not `.` or `..`, at most 255 bytes",
                    ));
                } else if seen.contains(&v.as_str()) {
                    notes.push(bad(
                        item(n, w.span),
                        "detect_files",
                        &alloc::format!("\"{v}\""),
                        "each name once",
                    ));
                }
                seen.push(v);
            }
        }
        Some(_) => {}
    }
    match t.get("interpreter") {
        None => notes.push(bad(
            at(seg),
            "interpreter",
            "nothing",
            "the program that prints the version",
        )),
        // Fails without it: language_keys_are_checked (an empty word, NUL).
        Some(
            n @ MNode {
                value: MValue::Scalar(Value::Str(v)),
                ..
            },
        ) if v.is_empty() || v.contains('\0') => notes.push(bad(
            at(n),
            "interpreter",
            &alloc::format!("\"{v}\""),
            "a program name or absolute path, not empty, without NUL",
        )),
        Some(_) => {}
    }
    if let Some(
        n @ MNode {
            value: MValue::Array(words),
            ..
        },
    ) = t.get("version")
    {
        for w in words {
            // Fails without it: language_keys_are_checked (NUL in an argument).
            if matches!(&w.value, Value::Str(v) if v.contains('\0')) {
                notes.push(bad(
                    item(n, w.span),
                    "version",
                    "an argument with NUL",
                    "arguments without NUL",
                ));
            }
        }
    }
}

/// The form rules of one `kind = "command"` segment (spec section 3 "사용자
/// 명령 실행 모델"): `command` or `shell`, never both; `shell` only with
/// `unsafe_shell = true`; one of the two, with at least one word; a placeholder only as one whole `command` element
/// and never in `shell`; `env_allow` names that can be variable names.
/// Problems are errors and warnings in `notes`; `true` when `shell` lacks its
/// explicit allowance, so the unit never runs.
fn command_form(id: &str, seg: &MNode, t: &MTable, notes: &mut Vec<Diagnostic>) -> bool {
    let shell = t.get("shell");
    let allow = t.get("unsafe_shell");
    let allowed = boolean(t, &["unsafe_shell"]) == Some(true);
    let item = |n: &MNode, span| Place::Source {
        id: n.origin.source,
        span,
    };
    let conflict = |n: &MNode, problem: &'static str| {
        Diagnostic::new(codes::COMMAND_FORM_CONFLICT, at(n))
            .arg("id", id)
            .arg("problem", problem)
    };
    let mid = |p: Place, place: &'static str| {
        Diagnostic::new(codes::PLACEHOLDER_NOT_WHOLE, p)
            .arg("id", id)
            .arg("placeholder", PLACEHOLDER)
            .arg("place", place)
    };
    if let (Some(sh), Some(_)) = (shell, t.get("command")) {
        notes.push(conflict(sh, "`command` and `shell` are both set"));
    }
    match (t.get("command"), shell) {
        (None, None) => notes.push(conflict(seg, "neither `command` nor `shell` is set")),
        (
            Some(
                c @ MNode {
                    value: MValue::Array(words),
                    ..
                },
            ),
            None,
        ) if words.is_empty() => notes.push(conflict(c, "`command` is empty")),
        _ => {}
    }
    if let (None, Some(a), true) = (shell, allow, allowed) {
        notes.push(conflict(a, "`unsafe_shell = true` is set without `shell`"));
    }
    if let Some(sh) = shell {
        if allowed {
            notes.push(Diagnostic::new(codes::UNSAFE_SHELL_USED, at(sh)).arg("id", id));
        } else {
            notes.push(Diagnostic::new(codes::SHELL_NOT_ALLOWED, at(sh)).arg("id", id));
        }
        if matches!(&sh.value, MValue::Scalar(Value::Str(v)) if v.contains(PLACEHOLDER)) {
            notes.push(mid(at(sh), "in `shell` text"));
        }
    }
    if let Some(
        n @ MNode {
            value: MValue::Array(words),
            ..
        },
    ) = t.get("command")
    {
        for w in words {
            if let Value::Str(v) = &w.value {
                if v != PLACEHOLDER && v.contains(PLACEHOLDER) {
                    notes.push(mid(item(n, w.span), "inside a longer element"));
                }
            }
        }
    }
    env_and_cwd_form(id, t, notes);
    shell.is_some() && !allowed
}

fn exec_units(
    r: &MTable,
    trusted: &MTable,
    off: &BTreeSet<&str>,
    names: &[String],
    reach: &Reach,
    notes: &mut Vec<Diagnostic>,
) -> Result<Vec<ExecUnit>, Vec<Diagnostic>> {
    // A unit runs when a trusted layout draws it and it is still drawn.
    let (approved, shown) = (drawn(trusted, off, names), drawn(r, off, names));
    let mut out = Vec::new();
    for e in entries(r, &["segment"]) {
        let MValue::Table(t) = &e.node.value else {
            continue;
        };
        let str_of = |k: &str| match t.get(k).map(|n| &n.value) {
            Some(MValue::Scalar(Value::Str(v))) => Some(v.clone()),
            _ => None,
        };
        let list = |k: &str| match t.get(k) {
            Some(n) => strings(n),
            None => Vec::new(),
        };
        let policy = match str_of("kind").as_deref() {
            Some("command") => ExecPolicy::Command {
                argv: list("command"),
                cwd: str_of("cwd"),
                env_allow: list("env_allow"),
                shell: str_of("shell"),
                unsafe_shell: boolean(t, &["unsafe_shell"]) == Some(true),
            },
            Some("language") => ExecPolicy::Language {
                interpreter: str_of("interpreter"),
                version_argv: list("version"),
                detect_files: list("detect_files"),
                cwd: str_of("cwd"),
                env_allow: list("env_allow"),
            },
            _ => continue,
        };
        let place = at(&e.node);
        let origins = exec_origins(&e.key, t);
        let approved_by = approved.get(&e.key).cloned().unwrap_or_default();
        let shown_at = shown.get(&e.key).cloned().unwrap_or_default();
        // Only a command segment needs `command` or `shell`; a language
        // segment cannot hold them (E206).
        if matches!(&policy, ExecPolicy::Language { .. }) {
            language_form(&e.key, &e.node, t, notes);
        }
        let not_run = if matches!(&policy, ExecPolicy::Command { .. })
            && command_form(&e.key, &e.node, t, notes)
        {
            Some(NotRun::ShellNotAllowed)
        } else if let Some(k) = unsafe_exec_key(&e.key, &origins, notes) {
            Some(NotRun::UnsafeFile { key: k })
        } else if boolean(t, &["enabled"]) == Some(false) {
            Some(NotRun::Disabled)
        } else if let why @ Some(_) = layout_verdict(&approved_by, &shown_at, names.len(), reach) {
            notes.push(
                Diagnostic::new(codes::NOT_RUN_UNTRUSTED_LAYOUT, place).arg("id", e.key.clone()),
            );
            why
        } else {
            None
        };
        // `match` is a command key (keys.rs): a language segment that writes
        // it fails the check (E206) before it compiles.
        let pattern = str_of("match");
        out.push(ExecUnit {
            id: e.key.clone(),
            policy,
            timeout_ms: optional_duration(str_of("timeout").as_deref()),
            cache_ms: optional_duration(str_of("cache").as_deref()),
            origins,
            approved_by,
            shown_at,
            not_run,
            pattern,
        });
    }
    // Only units that may run count: drawn by a trusted layout at some
    // width (a field reference such as `{custom/x.value}` draws it too), not
    // turned off, and of a kind that runs. The prompt's display and the
    // helper's round decide with the same function (`plan::runnable`).
    // Fails without it: at_most_32_drawn_exec_units.
    let drawn = out
        .iter()
        .filter(|u| crate::command::plan::runnable(u).is_some())
        .count();
    if drawn > MAX_EXEC_UNITS {
        return Err(vec![bad(
            place_of(r, &["segment"]),
            "segment",
            &alloc::format!("{drawn} drawn"),
            "at most 32 drawn command and language segments",
        )]);
    }
    Ok(out)
}

#[cfg(test)]
mod tests;
