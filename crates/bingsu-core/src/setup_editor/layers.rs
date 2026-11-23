//! What the sources say for each row, seen from the target file (the one the
//! editor makes or shows the changes for). Sources merge in apply order and
//! later wins (`config::merge`); the order is the built-in theme, the
//! target's own `extends` (each file comes after what it extends), the
//! target, then `conf.d/*` and `config.local.*` (`config::source`, the
//! CLI's `config_load`). So the sources before the target in that order
//! give the value the target inherits, and the ones after it can cover what
//! the target writes.
use super::rows::Row;
use crate::config::source::Found;
use crate::config::tree::{Table, Value};
use crate::default_theme::NARROW_TEMPLATE;
use crate::diag::SourceId;
use crate::diag_widths::WidthRun;
use alloc::string::String;
use alloc::vec::Vec;

/// One row as the sources give it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Layer {
    /// The value the sources before the target give the row: that of the
    /// last of them that sets its value key (`Row::value_key`), `None`
    /// when none sets it or that value is not one of the row's (`config
    /// check` refuses it, whatever came before).
    pub earlier: Option<u8>,
    /// What the target itself writes.
    pub written: Option<u8>,
    /// The target's own text for each of the row's keys (`Row::keys`),
    /// shown (quoted, sanitized): also a value the row does not know.
    pub written_raw: [Option<String>; 2],
    /// The value the last source after the target that sets the value key
    /// gives, and its place in `Layers::names`; `None` also when that
    /// value is not one of the row's (`later_keys` still names it).
    pub later: Option<(u8, usize)>,
    /// For each of the row's keys, the last source after the target that
    /// sets it, whatever the value: it covers what the target writes there.
    pub later_keys: [Option<usize>; 2],
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Layers {
    pub rows: [Layer; 8],
    /// The last applied source that sets `style.template`, by its index in
    /// `names`: the template replaces the preset and the shape keys.
    pub template: Option<usize>,
    /// The display name of each applied source, in apply order (`later` and
    /// `template` name one by its place), as the loader gave it: not
    /// sanitized, the screen does that.
    pub names: Vec<Vec<u8>>,
}

fn has_template(t: &Table) -> bool {
    match t.get("style").map(|e| &e.node.value) {
        Some(Value::Table(style)) => style.get("template").is_some(),
        _ => false,
    }
}

impl Layers {
    /// The layers for the target `target`, from a load's catalog `files`
    /// (`SourceId(i)` is `files[i]`) and apply `order` (`LoadReport` and
    /// `report::ConfigReport` both have them). A target that is not applied
    /// (left out of the order) writes nothing, and every applied source
    /// counts as earlier.
    pub fn from_sources(files: &[Found], order: &[SourceId], target: SourceId) -> Self {
        let mut out = Self::default();
        let at = order.iter().position(|id| *id == target);
        let split = at.unwrap_or(order.len());
        for (k, id) in order.iter().enumerate() {
            let found = files.get(id.0 as usize);
            out.names
                .push(found.map(|f| f.opened.display.clone()).unwrap_or_default());
            let Some(found) = found else {
                continue;
            };
            let tree = &found.tree;
            if has_template(tree) {
                out.template = Some(k);
            }
            for row in Row::ALL {
                let layer = &mut out.rows[row.index()];
                if k == split {
                    layer.written_raw = [row.raw(tree, 0), row.raw(tree, 1)];
                }
                if k > split {
                    for (i, slot) in layer.later_keys.iter_mut().enumerate() {
                        if row.has(tree, i) {
                            *slot = Some(k);
                        }
                    }
                }
                // The last source that sets the value key decides, also with
                // a value outside the list.
                if !row.has(tree, row.value_key()) {
                    continue;
                }
                let v = row.read(tree);
                match k.cmp(&split) {
                    core::cmp::Ordering::Less => layer.earlier = v,
                    core::cmp::Ordering::Equal => layer.written = v,
                    core::cmp::Ordering::Greater => layer.later = v.map(|v| (v, k)),
                }
            }
        }
        out
    }
}

/// The value at `path` in `t`, when the tables on the way are there.
fn value_at<'a>(t: &'a Table, path: &[&str]) -> Option<&'a Value> {
    let (last, tables) = path.split_last()?;
    let mut t = t;
    for key in tables {
        match t.get(key).map(|e| &e.node.value) {
            Some(Value::Table(inner)) => t = inner,
            _ => return None,
        }
    }
    t.get(last).map(|e| &e.node.value)
}

/// The text at `path` in `t`, when it is one.
fn text_at<'a>(t: &'a Table, path: &[&str]) -> Option<&'a str> {
    match value_at(t, path)? {
        Value::Str(s) => Some(s.as_str()),
        _ => None,
    }
}

/// The text the settings compose to at `path`: that of the last applied
/// source in `order` that sets it (later wins, `config::merge`). `None`
/// when no applied source sets it, or the last one sets something else
/// (`config check` refuses that).
pub fn composed_text<'a>(files: &'a [Found], order: &[SourceId], path: &[&str]) -> Option<&'a str> {
    let value = order
        .iter()
        .rev()
        .filter_map(|id| files.get(id.0 as usize))
        .find_map(|f| value_at(&f.tree, path))?;
    match value {
        Value::Str(s) => Some(s.as_str()),
        _ => None,
    }
}

/// Whether a preview `width` cells wide draws the `narrow` band with the
/// built-in template, from a load's catalog `files`, apply `order` and the
/// compiled band of each width (`CompiledConfig::widths`): the shape rows
/// then change nothing on screen, and `View::narrow` says so. A band of
/// that name with a template a source wrote draws that template.
pub fn builtin_narrow(
    files: &[Found],
    order: &[SourceId],
    widths: &[WidthRun],
    width: u16,
) -> bool {
    // The runs cover the widths in order from 0.
    let band = widths
        .iter()
        .find(|r| width <= r.to)
        .and_then(|r| r.band.as_deref());
    if band != Some("narrow") {
        return false;
    }
    let template = order
        .iter()
        .rev()
        .filter_map(|id| files.get(id.0 as usize))
        .find_map(|f| text_at(&f.tree, &["layout", "when", "narrow", "style", "template"]));
    template == Some(NARROW_TEMPLATE)
}
