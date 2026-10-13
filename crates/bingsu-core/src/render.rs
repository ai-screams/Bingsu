//! One render: every line of the layout, the transient prompt and the vi
//! symbols, written for one shell (spec section 1 "호출은 한 번"). The
//! mapping to record fields is `to_b1_fields`.
use crate::bands::Band;
use crate::color::palette::ResolvedPalette;
use crate::color::sgr::ColorDepth;
use crate::emit::{emit, readline_mode_string};
use crate::field::{Field, FieldValue, Value};
use crate::layout::{Inputs, Options, Run, layout, layout_line};
use crate::recorder::{NoopRecorder, Recorder};
use crate::shell_word::Shell;
use crate::template::compile::CompiledLine;
use alloc::vec;
use alloc::vec::Vec;

#[derive(Clone, Copy, Debug)]
pub struct Theme<'a> {
    /// `variants[0]` default layout, `variants[i + 1]` band `i`.
    pub variants: &'a [Vec<CompiledLine>],
    pub bands: &'a [Band],
    pub band_order: &'a [usize],
    /// One line; its left part becomes the transient left, its right part
    /// the transient right.
    pub transient: &'a CompiledLine,
    /// The line drawn for the vi symbols (usually `{char}`), once with the
    /// `char` segment's `vicmd` field false and once true.
    pub vi: &'a CompiledLine,
    pub palette: &'a ResolvedPalette,
}

#[derive(Clone, Copy, Debug)]
pub struct Target {
    pub shell: Shell,
    pub depth: ColorDepth,
    pub options: Options,
}

/// Field bytes for one shell. `upper` is the line above the input line,
/// empty for a one-line layout or when step 7 dropped it. bash's vi fields
/// are readline strings (`emit::readline_mode_string`), quotes included.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RenderedPrompt {
    pub upper: Vec<u8>,
    pub left: Vec<u8>,
    pub right: Vec<u8>,
    pub transient_left: Vec<u8>,
    pub transient_right: Vec<u8>,
    pub vi_insert: Vec<u8>,
    pub vi_command: Vec<u8>,
}

/// Room for the text and about one SGR per run, so a field is usually
/// written without growing.
fn capacity(runs: &[Run]) -> usize {
    runs.iter().map(|r| r.text.len() + 48).sum::<usize>() + 16
}

fn field(t: &Target, p: &ResolvedPalette, runs: &[Run]) -> Vec<u8> {
    let mut v = Vec::with_capacity(capacity(runs));
    emit(t.shell, runs, p, t.depth, &mut v);
    v
}

/// The vi line with `char`'s `vicmd` field set to `vicmd`. Only the `char`
/// value is copied: the line draws nothing else that changes with it.
fn vi_symbol(theme: &Theme<'_>, inp: &Inputs<'_>, t: &Target, vicmd: bool) -> Vec<u8> {
    let Some(ci) = inp.catalog.iter().position(|d| d.id == "char") else {
        return Vec::new();
    };
    let mut values: Vec<Option<Value>> = vec![None; inp.values.len()];
    if let Some(v) = inp.values.get(ci).cloned().flatten() {
        let mut v = v;
        if let Some(f) = inp.catalog[ci]
            .field_index("vicmd")
            .and_then(|k| v.fields.get_mut(k))
        {
            *f = Field::known(FieldValue::Bool(vicmd));
        }
        values[ci] = Some(v);
    }
    let vi_inp = Inputs {
        values: &values,
        ..*inp
    };
    let line = layout_line(0, theme.vi, false, &vi_inp, &t.options, &mut NoopRecorder);
    if t.shell == Shell::Bash {
        let mut s = Vec::with_capacity(capacity(&line.left) + 32);
        readline_mode_string(&line.left, theme.palette, t.depth, &mut s);
        s
    } else {
        field(t, theme.palette, &line.left)
    }
}

/// Lays out the prompt and writes every display field for `t.shell`.
/// Decisions of the main layout go to `r`; the transient and vi lines are
/// laid out with `NoopRecorder`.
pub fn render_prompt<R: Recorder>(
    theme: &Theme<'_>,
    inp: &Inputs<'_>,
    t: &Target,
    r: &mut R,
) -> RenderedPrompt {
    let lines = layout(
        theme.variants,
        theme.bands,
        theme.band_order,
        inp,
        &t.options,
        r,
    );
    let p = theme.palette;
    // At most two lines (template::compile::MAX_LINES): the last is the
    // input line, one before it the upper line. A dropped upper line has
    // no runs, and no runs give an empty field.
    let (input, upper) = match lines.split_last() {
        Some((l, u)) => (Some(l), u.last()),
        None => (None, None),
    };
    let tr = layout_line(
        0,
        theme.transient,
        false,
        inp,
        &t.options,
        &mut NoopRecorder,
    );
    RenderedPrompt {
        upper: upper.map(|l| field(t, p, &l.left)).unwrap_or_default(),
        left: input.map(|l| field(t, p, &l.left)).unwrap_or_default(),
        right: input.map(|l| field(t, p, &l.right)).unwrap_or_default(),
        transient_left: field(t, p, &tr.left),
        transient_right: field(t, p, &tr.right),
        vi_insert: vi_symbol(theme, inp, t, false),
        vi_command: vi_symbol(theme, inp, t, true),
    }
}

/// The seven B1 display fields (record change plan 12: `upper` is the
/// seventh).
pub fn to_b1_fields(r: &RenderedPrompt) -> crate::record::Fields<'_> {
    crate::record::Fields {
        left: &r.left,
        right: &r.right,
        transient_left: &r.transient_left,
        transient_right: &r.transient_right,
        vi_insert: &r.vi_insert,
        vi_command: &r.vi_command,
        upper: &r.upper,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::color::palette::{Knobs, Mode, PaletteInput, resolve_palette};
    use crate::field::BUILTIN;
    use crate::layout::tests::{fixture, opts};
    use crate::template::compile::compile;

    fn draw(shell: Shell, template: &str, width: u16) -> RenderedPrompt {
        let f = fixture(&["Works"], "main");
        let pal = resolve_palette(&PaletteInput {
            mode: Mode::Dark,
            knobs: Knobs::default(),
            overrides: &[],
            roles: &[],
        })
        .unwrap();
        let lines = compile(template, BUILTIN).unwrap();
        let ch = compile("{char}", BUILTIN).unwrap().remove(0);
        let theme = Theme {
            variants: core::slice::from_ref(&lines),
            bands: &[],
            band_order: &[],
            transient: &ch,
            vi: &ch,
            palette: &pal,
        };
        let t = Target {
            shell,
            depth: ColorDepth::TrueColor,
            options: opts(width),
        };
        render_prompt(&theme, &f.inputs(), &t, &mut NoopRecorder)
    }

    // 이것을 실패시키는 것: 윗줄을 B1 필드에 싣지 않거나 다른 필드에 섞는 것.
    #[test]
    fn upper_line_goes_to_its_own_field() {
        let r = RenderedPrompt {
            left: b"x".to_vec(),
            upper: b"line 1".to_vec(),
            ..RenderedPrompt::default()
        };
        let f = to_b1_fields(&r);
        assert_eq!(
            (f.left, f.upper, f.right),
            (&b"x"[..], &b"line 1"[..], &b""[..])
        );
    }

    // 이것을 실패시키는 것: 윗줄이 없는 프롬프트(한 줄 템플릿, 단계 7이 윗줄을 버린 폭)에 윗줄 필드 바이트를
    // 쓰는 것. 비어 있지 않은 윗줄 필드는 hook이 줄바꿈을 붙여 빈 줄 하나를 더 그린다.
    #[test]
    fn no_upper_line_gives_an_empty_field() {
        for shell in [Shell::Zsh, Shell::Bash, Shell::Fish] {
            let one = draw(shell, "{dir} {git}", 80);
            assert!(one.upper.is_empty() && !one.left.is_empty(), "{shell:?}");
            let two = draw(shell, "{dir} {git}{@nl}{char}", 80);
            assert!(!two.upper.is_empty(), "{shell:?}");
            // Width 2: step 7 drops the upper line (it is laid out minimal,
            // with no runs) while the input line still shows `❯`.
            let f = fixture(&["Works"], "main");
            let lines = compile("{dir} {git}{@nl}{char}", BUILTIN).unwrap();
            let laid = layout(
                core::slice::from_ref(&lines),
                &[],
                &[],
                &f.inputs(),
                &opts(2),
                &mut NoopRecorder,
            );
            assert!(laid[0].minimal && !laid[1].minimal);
            let tiny = draw(shell, "{dir} {git}{@nl}{char}", 2);
            assert!(tiny.upper.is_empty() && !tiny.left.is_empty(), "{shell:?}");
        }
    }

    // 이것을 실패시키는 것: vi 입력·명령 기호를 같은 값으로 그리는 것(vicmd 필드를 바꾸지 않음), bash vi 필드를
    // readline 문자열로 바꾸지 않는 것.
    #[test]
    fn vi_symbols() {
        let z = draw(Shell::Zsh, "{char}", 80);
        assert_ne!(z.vi_insert, z.vi_command);
        assert!(String::from_utf8_lossy(&z.vi_command).contains('\u{276E}'));
        let b = draw(Shell::Bash, "{char}", 80);
        assert!(b.vi_insert.starts_with(b"\"") && b.vi_insert.ends_with(b"\""));
        assert!(!b.vi_command.iter().any(|&c| c < 0x20));
    }
}
