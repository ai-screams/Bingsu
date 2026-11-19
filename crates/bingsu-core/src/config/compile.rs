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
pub use super::exec_units::{
    CustomKind, CustomSegment, ExecPolicy, ExecUnit, MAX_CUSTOM_TEXT, MAX_EXEC_UNITS, NotRun,
};
use super::exec_units::{Reach, custom_segments, declares_custom, exec_units};
pub use super::layouts::{Bands, LayoutRef, Side, bands_of, off_bands};
use super::layouts::{
    Layout, band_replaces_lines, blame, check_layout_budget, drawn, layouts, selectable,
    without_hidden,
};
use super::values::{
    at, bad, boolean, default_str, entries, float, get, int, optional_duration, parse_duration_ms,
    place_of, s, strings,
};
use crate::bands::Band;
use crate::color::notation::{ColorSpec, parse_color};
use crate::color::palette::{Knobs, Mode, PaletteInput, ResolvedPalette, resolve_palette};
use crate::config::merge::{MNode, MTable, MValue, Merged};
use crate::config::source::Trust;
use crate::config::tree::Value;
use crate::default_theme::{DIR_METHODS, SETUP};
use crate::diag::Diagnostic;
use crate::diag_codes as codes;
use crate::diag_widths::WidthRun;
use crate::field::BUILTIN;
use crate::icons::IconSet;
use crate::layout::{SegmentSetup, When};
use crate::render::Theme;
use crate::shorten::Method;
use crate::style::{Body, Cap, Joining, LineLayout, StyleOptions, generate, preset};
use crate::template::compile::{CompiledLine, FillKind, Node, Shape, compile_builtin};
use crate::width::WidthProfile;
use alloc::collections::BTreeSet;
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

fn method(name: &str) -> Method {
    match name {
        "repo" => Method::Repo,
        "abbrev" => Method::Abbrev(1),
        "depth" => Method::Depth(1),
        "unique" => Method::Unique,
        _ => Method::None,
    }
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

fn shape(v: &str) -> Option<Shape> {
    match v {
        "triangle" => Some(Shape::Triangle),
        "round" => Some(Shape::Round),
        "slant" => Some(Shape::Slant),
        "flat" => Some(Shape::Flat),
        _ => None,
    }
}

/// An end shape: a written `none` is a value that covers the preset's end.
fn end_shape(v: Option<&str>) -> Option<Cap> {
    match v? {
        "none" => Some(Cap::None),
        v => shape(v).map(Cap::Shape),
    }
}

/// The style options the config writes: the ends, the joint between
/// blocks (`style.separator`: a shape is a separator glyph, `none` touching
/// blocks, `caps` blocks with ends of their own), the gap, fill and frame. A
/// value that is not one of the names stays unset (the check reports it).
fn style_options(r: &MTable) -> StyleOptions {
    let (separator, joining) = match s(r, &["style", "separator"]) {
        Some("none") => (None, Some(Joining::Adjacent)),
        Some("caps") => (None, Some(Joining::Capped)),
        Some(v) => match shape(v) {
            Some(sh) => (Some(sh), Some(Joining::Attached)),
            None => (None, None),
        },
        None => (None, None),
    };
    StyleOptions {
        separator,
        joining,
        outer_end: end_shape(s(r, &["style", "outer_end"])),
        inner_end: end_shape(s(r, &["style", "inner_end"])),
        gap: boolean(r, &["style", "gap"]),
        fill: s(r, &["layout", "fill"]).and_then(|v| match v {
            "space" => Some(FillKind::Space),
            "dot" => Some(FillKind::Dot),
            "line" => Some(FillKind::Line),
            _ => None,
        }),
        frame: s(r, &["layout", "frame"]).map(|v| v == "line"),
        ..StyleOptions::default()
    }
}

/// The built-in segments turned off. `enabled` is an execution key: a
/// shape-only file cannot set it (dropped at the merge), and one from a
/// file that failed the safety check turns the segment off, which is
/// reported on `notes` (W405) as the keys are read.
fn builtin_off<'a>(r: &MTable, notes: &mut Vec<Diagnostic>) -> BTreeSet<&'a str> {
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
    off
}

/// What a layout can draw is judged on the trusted merge alone: a shape-only
/// source may re-order or resize bands, but must not make a band reachable
/// that the trusted sources never reach. A trusted merge whose bands fail to
/// order approves nothing. `full_names` are the band names of the full merge
/// (the indices the compiled bands use).
fn approved_bands(
    trusted: &Merged,
    bands_off: &BTreeSet<&str>,
    full_names: &[String],
) -> BTreeSet<Option<u16>> {
    bands_of(trusted, bands_off).map_or_else(
        |_| BTreeSet::new(),
        |t| {
            let full = full_names;
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
    )
}

/// The compiled setup of every built-in segment, in `BUILTIN` order: its
/// priority, whether it is required and, for `dir`, the shortening methods
/// and when they apply.
fn builtin_setup(r: &MTable) -> Vec<Setup> {
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
    setup
}

/// What every layout variant is compiled against: the merged root and the
/// values derived from it once, read only.
struct VariantContext<'a> {
    r: &'a MTable,
    options: &'a StyleOptions,
    off: &'a BTreeSet<&'a str>,
    texts: &'a [&'a str],
    base_preset: &'a str,
    widths: &'a [WidthRun],
}

/// The ids each enabled line of `lay` draws, left and right. Command and
/// language segments are drawn from M6, text segments now; built-ins turned
/// off, and a `custom/…` id that is not drawn, are left out.
fn drawn_lines(
    lay: &Layout,
    texts: &[&str],
    off: &BTreeSet<&str>,
) -> Vec<(Vec<String>, Vec<String>)> {
    let keep = |ids: &[String]| -> Vec<String> {
        ids.iter()
            .filter(|id| {
                (!id.contains('/') || texts.contains(&id.as_str())) && !off.contains(id.as_str())
            })
            .cloned()
            .collect()
    };
    lay.lines
        .iter()
        .filter(|l| l.enabled)
        .map(|l| (keep(&l.left), keep(&l.right)))
        .collect()
}

/// A theme may change how the prompt looks, never erase it: a shape-only
/// template that draws none of the required segments (`char`, `dir`) is an
/// error placed in that file, so rule 5 drops it and the trusted layout
/// stays. `off` are the built-ins turned off, which are not required.
fn draws_required_segment(
    compiled: &[CompiledLine],
    template: &MNode,
    off: &BTreeSet<&str>,
) -> Result<(), Vec<Diagnostic>> {
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
            at(template),
            "style.template",
            "",
            "a template that draws char or dir",
        )]);
    }
    Ok(())
}

/// One layout variant (the default layout, or a band's) compiled: its
/// template or generated lines, the required-segment check, and the built-in
/// segments it references added to `mask`. Notes go on `notes` in the order
/// they are found.
fn compile_variant(
    lay: &Layout,
    cx: &VariantContext<'_>,
    notes: &mut Vec<Diagnostic>,
    mask: &mut u32,
) -> Result<Vec<CompiledLine>, Vec<Diagnostic>> {
    let VariantContext {
        r,
        options,
        off,
        texts,
        base_preset,
        widths,
    } = *cx;
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
    let owned = drawn_lines(lay, texts, off);
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
            // The keys whose value can change this generated template (a
            // shape-only file that set one is then blamed for a template
            // that does not fit, not the user's file). The separator keeps
            // its earlier guard for lines of two or more blocks; the other
            // keys have none, since two lines of one block a side stay far
            // under the length cap.
            let o = options.over(pr.options);
            let block = o.body == Some(Body::Block);
            if block {
                involved.extend(get(r, &["style", "outer_end"]));
                involved.extend(get(r, &["style", "inner_end"]));
            }
            if (block || o.gap != Some(true))
                && layout_lines
                    .iter()
                    .any(|l| l.left.len() > 1 || l.right.len() > 1)
            {
                involved.extend(get(r, &["style", "separator"]));
            }
            let gapped = match o.joining {
                Some(Joining::Capped) => true,
                Some(Joining::Adjacent) => !block,
                _ => false,
            };
            if gapped {
                involved.extend(get(r, &["style", "gap"]));
            }
        }
    }
    let where_ = blame(&involved);
    let text = match template.map(|n| &n.value) {
        Some(MValue::Scalar(Value::Str(t))) => {
            // Lines or options written next to a template are not used:
            // say so, never drop them in silence.
            if *options != StyleOptions::default() || lay.lines.iter().any(|l| l.written) {
                notes.push(Diagnostic::new(codes::TEMPLATE_REPLACES_STYLE, where_));
            }
            // A band's own template also draws in place of the lines it
            // takes from `[layout]`: never in silence either.
            // 이것을 실패시키는 것: 구간이 물려받은 기본 템플릿(자기 것 아님)에 내는 것(N501이 기본 레이아웃에서 이미 알림).
            if let Some(own) = bt.and_then(|bt| get(bt, &["style", "template"])) {
                notes.extend(band_replaces_lines(lay, own, widths));
            }
            // A `custom/…` reference that is not drawn (turned off, or
            // undeclared, which W408 names) goes alone; the rest compiles.
            without_hidden(t, off, texts)
        }
        _ => {
            let pr = preset(p).ok_or_else(|| vec![bad(where_, "style.preset", p, "a preset")])?;
            generate(pr, options, &layout_lines)
                .map_err(|_| vec![bad(where_, "layout", "", "a layout that fits a template")])?
        }
    };
    let compiled = compile_builtin(&text, texts)
        .map_err(|_| vec![bad(where_, "layout", "", "a layout that compiles")])?;
    if let Some(t) = template.filter(|t| t.origin.trust == Trust::ShapeOnly) {
        draws_required_segment(&compiled, t, off)?;
    }
    let referenced = crate::collection::selection::references(&compiled);
    for (i, d) in BUILTIN.iter().enumerate() {
        if referenced & (1 << i) != 0 && !off.contains(d.id) {
            *mask |= 1 << i;
        }
    }
    Ok(compiled)
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
    let options = style_options(r);
    // Built-in segments turned off; the W405 notes come before the band notes.
    let off = builtin_off(r, &mut notes);
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
    let approved = approved_bands(trusted, &bands_off, &banded.names);
    let reach = Reach::new(approved, shown_bands);
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
    let cx = VariantContext {
        r,
        options: &options,
        off: &off,
        texts: &texts,
        base_preset,
        widths: &banded.widths,
    };
    for lay in layouts(r, &bands_off) {
        variants.push(compile_variant(&lay, &cx, &mut notes, &mut mask)?);
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
    let setup = builtin_setup(r);
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

#[cfg(test)]
mod tests;
