//! One preview line per built-in preset for `bingsu list presets --preview`
//! (plan D2). It draws the default theme's upper line with the preset
//! through the same renderer as the prompt. Nothing is collected: the folder
//! is the caller's, every other value is a fixed sample.
use crate::color::palette::Mode;
use crate::color::sgr::ColorDepth;
use crate::default_theme::{DefaultTheme, DefaultThemeError};
use crate::emit::emit;
use crate::field::{BUILTIN, Field, FieldValue, Value, segment};
use crate::icons::IconSet;
use crate::layout::{Inputs, Options, layout};
use crate::recorder::NoopRecorder;
use crate::shell_values::path_facts;
use crate::shell_word::Shell;
use crate::width::WidthProfile;
use alloc::vec;
use alloc::vec::Vec;

/// Narrower than the default theme's `narrow` band (59), every preset
/// would draw the same lean line.
pub const MIN_WIDTH: u16 = 60;

#[derive(Clone, Copy, Debug)]
pub struct PreviewInput<'a> {
    pub pwd: &'a [u8],
    pub home: Option<&'a [u8]>,
    pub width: u16,
    pub icons: IconSet,
    /// `None`: plain text, no escapes.
    pub depth: Option<ColorDepth>,
}

fn sample(id: &str, text: &[u8], set: &[(&str, FieldValue)]) -> Option<Value> {
    let d = segment(id)?;
    let mut f = vec![Field::ABSENT; d.fields.len()];
    for (name, v) in set {
        if let Some(k) = d.field_index(name) {
            f[k] = Field::known(v.clone());
        }
    }
    Some(Value::new(text, f))
}

/// The upper line of the default two-line layout with `preset`, without a
/// newline; empty when the width leaves no upper line.
pub fn preview_line(preset: &str, i: &PreviewInput<'_>) -> Result<Vec<u8>, DefaultThemeError> {
    let theme = DefaultTheme::with_preset(Mode::Dark, preset)?;
    let at = |id: &str| BUILTIN.iter().position(|d| d.id == id);
    let mut values = vec![None; BUILTIN.len()];
    let mut facts = vec![None; BUILTIN.len()];
    let mut put = |id: &str, v: Option<Value>| {
        if let Some(k) = at(id) {
            values[k] = v;
        }
    };
    put("char", sample("char", b"", &[]));
    // The folder shows through its facts, which sanitize the names.
    put("dir", sample("dir", b"", &[]));
    if let Some(k) = at("dir") {
        facts[k] = Some(path_facts(i.pwd, i.home));
    }
    put("git", sample("git", b"main", &[]));
    put(
        "duration",
        sample(
            "duration",
            b"2.3s",
            &[("ms", FieldValue::Duration { ms: 2300 })],
        ),
    );
    put("time", sample("time", b"12:34", &[]));
    let inputs = Inputs {
        catalog: BUILTIN,
        values: &values,
        facts: &facts,
        setup: theme.setup(),
    };
    let t = theme.theme();
    let o = Options {
        width: i.width.max(MIN_WIDTH),
        profile: WidthProfile::DEFAULT,
        icons: i.icons,
        use_last_column: false,
    };
    let lines = layout(
        t.variants,
        t.bands,
        t.band_order,
        &inputs,
        &o,
        &mut NoopRecorder,
    );
    // Two lines: the upper one is first. One line is the input line alone.
    let upper = match lines.as_slice() {
        [u, _] => &u.left,
        _ => return Ok(Vec::new()),
    };
    let mut out = Vec::new();
    match i.depth {
        // `Shell::Fish` writes bare escapes, with no prompt-width markers.
        Some(d) => emit(Shell::Fish, upper, t.palette, d, &mut out),
        None => {
            for r in upper {
                out.extend_from_slice(r.text.as_bytes());
            }
        }
    }
    Ok(out)
}
