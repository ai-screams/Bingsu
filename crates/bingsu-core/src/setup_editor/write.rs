//! What saving writes for a new file, and for an
//! existing file the lines to change in it, which the editor only shows.
//! Every value comes from the rows' fixed lists; the file text is ASCII.
use super::model::{Model, Target};
use super::rows::{self, Row};
use crate::config::edit::{self, EditError};
use crate::config::starter::SCHEMA_URL;
use crate::config::tree::Format;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

/// A key and its value as TOML writes it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyValue {
    /// Dotted path: `style.outer_end`.
    pub key: &'static str,
    /// `"round"`, `true`, `["host", "dir", "git", "char"]`.
    pub value: String,
}

fn list(items: &[&str]) -> String {
    let quoted: Vec<String> = items.iter().map(|s| format!("\"{s}\"")).collect();
    format!("[{}]", quoted.join(", "))
}

/// The keys and values row `row` writes when its value is `v`.
fn key_values(row: Row, v: u8) -> Vec<KeyValue> {
    let label = row.values()[usize::from(v)];
    let one = |value: String| {
        alloc::vec![KeyValue {
            key: row.keys()[0],
            value,
        }]
    };
    match row {
        Row::Gap => one((v == 1).to_string()),
        Row::Lines => {
            let one_line = v == 1;
            alloc::vec![
                KeyValue {
                    key: "layout.line1.left",
                    value: list(if one_line {
                        &rows::ONE_LINE
                    } else {
                        &rows::UPPER_LINE
                    }),
                },
                KeyValue {
                    key: "layout.line2.enabled",
                    value: (!one_line).to_string(),
                },
            ]
        }
        _ => one(format!("\"{label}\"")),
    }
}

/// The keys saving writes: for a new file `style.preset` always (the value
/// the file gives, never one a later file covers), then the
/// rows the file writes. Empty for an existing file, which is not written.
pub fn written_keys(m: &Model) -> Vec<KeyValue> {
    if m.target() != Target::New {
        return Vec::new();
    }
    let mut out = Vec::new();
    for row in Row::ALL {
        let v = match (row, m.written(row)) {
            (Row::Style, w) => w.unwrap_or_else(|| m.chosen(Row::Style)),
            (_, Some(v)) => v,
            (_, None) => continue,
        };
        out.extend(key_values(row, v));
    }
    out
}

/// One comment line for each key the file writes.
fn comment(key: &str) -> &'static str {
    match key {
        "icons" => {
            "# \"nerd\" draws Nerd Font glyphs, \"light\" only its block separators;\n\
             # \"unicode\" needs no special font, \"ascii\" draws ASCII only."
        }
        "style.preset" => "# See `bingsu list presets --preview`.",
        "style.outer_end" => "# The end of each run of blocks at the edge of the screen.",
        "style.separator" => "# The joint between two blocks.",
        "style.inner_end" => "# The end of each run of blocks that faces the middle.",
        "style.gap" => "# One blank cell between blocks that have ends of their own.",
        "colors.mode" => "# \"auto\" follows the terminal; \"dark\" or \"light\" fixes it.",
        _ => "",
    }
}

/// The text of the new settings file, or `None` for an existing target:
/// the editor never writes a file that is there.
pub fn new_file_text(m: &Model) -> Option<String> {
    if m.target() != Target::New {
        return None;
    }
    let mut keys = written_keys(m);
    // Keys outside a table first: after a `[table]` line they would be
    // read as that table's.
    keys.sort_by_key(|kv| kv.key.contains('.'));
    let mut out = format!(
        "#:schema {SCHEMA_URL}\n\
         # bingsu settings. Every line is optional: delete one to get the default.\n\
         # Check this file with `bingsu config check`; `bingsu list` shows the names.\n"
    );
    let mut table = "";
    for kv in &keys {
        let (t, name) = kv.key.rsplit_once('.').unwrap_or(("", kv.key));
        if t != table || t.is_empty() {
            out.push('\n');
        }
        if t != table {
            if t == "layout.line1" {
                out.push_str(if kv.value.contains("char") {
                    "# These two pin the segments; delete both to follow the built-in lines.\n"
                } else {
                    "# These two pin the segments; delete both to follow the lines your other files set.\n"
                });
            }
            out.push_str(&format!("[{t}]\n"));
            table = t;
        }
        let c = comment(kv.key);
        if !c.is_empty() {
            out.push_str(c);
            out.push('\n');
        }
        out.push_str(&format!("{name} = {}\n", kv.value));
    }
    Some(out)
}

/// One key to change in an existing file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Change {
    pub key: &'static str,
    /// The file's value now, shown (quoted, sanitized), or `not set`.
    pub now: String,
    /// The value to set, as TOML writes it (`"round"`, `true`); `None`:
    /// delete the file's key.
    pub value: Option<String>,
    /// The value picked, or `not set` when the file's own value goes.
    pub chosen: String,
    /// What to do in the file: the line to put in under its table (TOML),
    /// or the key path and value (JSON, YAML), or what to delete.
    pub line: String,
    /// The later source that sets this key too, by its place in
    /// `Layers::names`.
    pub covered_by: Option<usize>,
}

/// The keys to change in an existing file to get what the editor shows:
/// every row that differs from what the file wrote, by the keys the file
/// has (a delete) or gets (a set). Empty for a new file.
pub fn changes(m: &Model) -> Vec<Change> {
    let Target::Existing(format) = m.target() else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for row in Row::ALL {
        if !m.marked(row) {
            continue;
        }
        let raw = &m.layers().rows[row.index()].written_raw;
        let set = m.written(row).map(|v| key_values(row, v));
        for (i, key) in row.keys().iter().enumerate() {
            let value = |kv: &Option<Vec<KeyValue>>| kv.as_ref().map(|k| k[i].value.clone());
            // Without a value to set, only a key the file really has can be
            // deleted. (A row that keeps its keys is not marked.)
            if set.is_none() && raw[i].is_none() {
                continue;
            }
            // The file's own text for the key, also a value the row does not
            // know.
            let shown_now = raw[i].clone().unwrap_or_else(|| "not set".into());
            let (table, name) = key.rsplit_once('.').unwrap_or(("", key));
            let line = match (value(&set), format) {
                (Some(v), Format::Toml) if table.is_empty() => format!("{name} = {v}"),
                (Some(v), Format::Toml) => format!("under [{table}]: {name} = {v}"),
                (Some(v), _) => format!("{key}: {v}"),
                (None, Format::Toml) if table.is_empty() => format!("delete {name}"),
                (None, Format::Toml) => format!("delete {name} under [{table}]"),
                (None, _) => format!("delete {key}"),
            };
            out.push(Change {
                key,
                value: value(&set),
                now: shown_now,
                chosen: value(&set).unwrap_or_else(|| "not set".into()),
                line,
                covered_by: m.covered_key(row, i),
            });
        }
    }
    out
}

/// The existing TOML file `original` with every change of `changes(m)`
/// made in place (`config::edit`: the rest of the file, its comments and
/// order kept): the bytes the preview loads in the file's place. A change
/// the local edit refuses (an inline or dotted table, a shape it does not
/// edit) refuses the whole candidate.
pub fn candidate_toml(m: &Model, original: &[u8]) -> Result<Vec<u8>, EditError> {
    let mut bytes = original.to_vec();
    for c in changes(m) {
        let path: Vec<&str> = c.key.split('.').collect();
        bytes = match &c.value {
            Some(v) => edit::set(&bytes, &path, v)?,
            None => edit::remove(&bytes, &path)?,
        };
    }
    Ok(bytes)
}
