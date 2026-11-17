//! The bands and layouts of a merged config: reading each layout table over
//! the one it inherits, checking the band count and the layout work budget,
//! ordering the bands and building their width table, and the references a
//! layout makes to segments. Split from `compile` so that file keeps the
//! step that turns these into a `CompiledConfig`.
use super::values::{at, bad, entries, get, int, strings};
use crate::bands::{Band, MAX_BANDS, order_bands};
use crate::config::merge::{MEntry, MNode, MTable, MValue, Merged, Origin};
use crate::config::source::Trust;
use crate::config::tree::Value;
use crate::diag::{Diagnostic, Place, SourceId};
use crate::diag_codes as codes;
use crate::diag_widths::{WidthRun, width_table};
use crate::template::syntax::{Span as TSpan, Syntax, parse as parse_template};
use alloc::collections::{BTreeMap, BTreeSet};
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

/// One line of one layout table, over the line it inherits: each side and
/// `enabled` keep the node they came from.
#[derive(Clone, Default)]
pub(super) struct Line {
    pub(super) left: Vec<String>,
    pub(super) right: Vec<String>,
    pub(super) enabled: bool,
    /// The nodes behind this line (its own and the ones it inherits), for
    /// blame.
    pub(super) nodes: Vec<MNode>,
    /// This layout table writes the line itself (not only inherits it).
    pub(super) written: bool,
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
pub(super) struct Layout {
    name: Option<String>,
    pub(super) lines: [Line; 2],
    pub(super) table: Option<MTable>,
    /// The template in effect (the band's own, else the default's).
    pub(super) template: Option<MNode>,
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

pub(super) fn layouts(r: &MTable, off: &BTreeSet<&str>) -> Vec<Layout> {
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
pub(super) fn without_hidden(text: &str, off: &BTreeSet<&str>, texts: &[&str]) -> String {
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
pub(super) fn band_replaces_lines(
    lay: &Layout,
    own: &MNode,
    widths: &[WidthRun],
) -> Option<Diagnostic> {
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
/// `exec_units::layout_verdict` treats as unknown.
fn band_index(names: &[String], name: &Option<String>) -> Option<u16> {
    name.as_ref()
        .map(|n| names.iter().position(|x| x == n).unwrap_or(names.len()) as u16)
}

/// Every id on a drawn line, with where. Bands are indexed by `names`.
pub(super) fn drawn(
    r: &MTable,
    off: &BTreeSet<&str>,
    names: &[String],
) -> BTreeMap<String, Vec<LayoutRef>> {
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
pub(super) fn blame(nodes: &[&MNode]) -> Place {
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

pub(super) fn check_layout_budget(r: &MTable) -> Result<(), Vec<Diagnostic>> {
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

/// The layouts a width can choose: `None` is the default layout, `Some(i)` band `i`.
pub(super) fn selectable(order: &[usize], bands: &[Band]) -> BTreeSet<Option<u16>> {
    crate::bands::selection_table(order, bands)
        .into_iter()
        .map(|(_, _, b)| b.map(|i| i as u16))
        .collect()
}
