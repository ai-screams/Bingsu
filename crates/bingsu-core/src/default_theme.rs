//! The built-in default theme (ADR-0008: two lines, blocks, transient
//! `char`), used while there is no compiled config snapshot. The values
//! are provisional: the seven presets of the first release are M7. Built
//! from the same parts a config would give (preset, layout lines, band,
//! palette), so the snapshot path later renders through the same code.
use crate::bands::{Band, BandError, order_bands};
use crate::color::palette::{
    Knobs, Mode, PaletteError, PaletteInput, ResolvedPalette, resolve_palette,
};
use crate::field::BUILTIN;
use crate::icons::IconSet;
use crate::layout::{SegmentSetup, When};
use crate::render::Theme;
use crate::shorten::Method;
use crate::style::{LineLayout, StyleError, StyleOptions, generate, preset};
use crate::template::compile::{CompileError, CompiledLine, compile};
use alloc::vec;
use alloc::vec::Vec;

/// Line 1: blocks left and right; line 2: the input line. A segment with
/// no value is hidden, so ids the front end cannot fill yet cost nothing.
/// The icon set the built-in default draws with until settings can choose
/// one (decision P20, 2026-10-14): `unicode` needs no Nerd Font or
/// Powerline font, so a fresh install shows no boxes. Settings (Part S) and
/// the setup wizard bring back the spec's choice (`nerd`, ADR-0008 powerline
/// separators) with a "can you see these?" check.
pub const ICONS: IconSet = IconSet::Unicode;

pub const LINES: [LineLayout<'static>; 2] = [
    LineLayout {
        left: &["host", "dir", "git"],
        right: &["status", "duration", "jobs", "venv", "time"],
    },
    LineLayout {
        left: &["char"],
        right: &[],
    },
];

/// The `narrow` band (spec section 2 "폭 구간별 레이아웃", width under 60,
/// the spec's example): the right side is dropped and `duration` moves
/// beside `char`, drawn lean (`NARROW_TEMPLATE`).
pub const NARROW: Band = Band {
    min_cols: None,
    max_cols: Some(59),
    order: None,
};
/// Written as a template with each literal gap grouped with the optional
/// segment beside it, so both disappear together. `dir` and `char` are
/// required and anchor the two lines. Generated `lean` layouts instead use
/// flat separators, cleaned up between visible plain segments.
pub const NARROW_TEMPLATE: &str =
    "{@group}{host} {@end}{dir}{@group} {git}{@end}{@nl}{@group}{duration} {@end}{char}";

pub(crate) const DIR_METHODS: &[Method] = &[Method::Repo, Method::Abbrev(1), Method::Depth(1)];

/// (segment id, priority, required). Higher priority stays longer.
pub(crate) const SETUP: [(&str, u16, bool); 9] = [
    ("char", 1000, true),
    ("dir", 900, true),
    ("git", 800, false),
    ("status", 700, false),
    ("duration", 600, false),
    ("jobs", 500, false),
    ("host", 400, false),
    ("venv", 300, false),
    ("time", 100, false),
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DefaultThemeError {
    UnknownPreset,
    Style(StyleError),
    Compile(CompileError),
    Bands(BandError),
    Palette(PaletteError),
}

/// Owns everything `render::Theme` borrows.
#[derive(Clone, Debug)]
pub struct DefaultTheme {
    variants: Vec<Vec<CompiledLine>>,
    bands: [Band; 1],
    band_order: Vec<usize>,
    transient: CompiledLine,
    vi: CompiledLine,
    palette: ResolvedPalette,
    setup: Vec<SegmentSetup<'static>>,
}

fn lines(preset_name: &str, l: &[LineLayout<'_>]) -> Result<Vec<CompiledLine>, DefaultThemeError> {
    let p = preset(preset_name).ok_or(DefaultThemeError::UnknownPreset)?;
    let t = match generate(p, &StyleOptions::default(), l) {
        Ok(t) => t,
        Err(error) => return Err(DefaultThemeError::Style(error)),
    };
    compile_all(&t)
}

fn compile_all(src: &str) -> Result<Vec<CompiledLine>, DefaultThemeError> {
    match compile(src, BUILTIN) {
        Ok(lines) => Ok(lines),
        Err(error) => Err(DefaultThemeError::Compile(error)),
    }
}

fn one_line(src: &str) -> Result<CompiledLine, DefaultThemeError> {
    let mut v = compile_all(src)?;
    Ok(v.remove(0))
}

impl DefaultTheme {
    pub fn new(mode: Mode) -> Result<Self, DefaultThemeError> {
        let bands = [NARROW];
        let band_order = match order_bands(&bands) {
            Ok(order) => order,
            Err(error) => return Err(DefaultThemeError::Bands(error)),
        };
        let palette = match resolve_palette(&PaletteInput {
            mode,
            knobs: Knobs::default(),
            overrides: &[],
            roles: &[],
        }) {
            Ok(palette) => palette,
            Err(error) => return Err(DefaultThemeError::Palette(error)),
        };
        let mut setup = vec![
            SegmentSetup {
                priority: 0,
                required: false,
                methods: &[],
                when: When::Needed,
            };
            BUILTIN.len()
        ];
        for (id, priority, required) in SETUP {
            if let Some(i) = BUILTIN.iter().position(|d| d.id == id) {
                setup[i].priority = priority;
                setup[i].required = required;
                if id == "dir" {
                    setup[i].methods = DIR_METHODS;
                }
            }
        }
        Ok(Self {
            variants: vec![lines("triangle", &LINES)?, compile_all(NARROW_TEMPLATE)?],
            bands,
            band_order,
            transient: one_line("{char}")?,
            vi: one_line("{char}")?,
            palette,
            setup,
        })
    }

    pub fn theme(&self) -> Theme<'_> {
        Theme {
            variants: &self.variants,
            bands: &self.bands,
            band_order: &self.band_order,
            transient: &self.transient,
            vi: &self.vi,
            palette: &self.palette,
        }
    }

    /// Per `field::BUILTIN` entry, same index.
    pub fn setup(&self) -> &[SegmentSetup<'static>] {
        &self.setup
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::color::sgr::ColorDepth;
    use crate::field::{Field, FieldValue, Value, segment};
    use crate::layout::{Inputs, Options};
    use crate::recorder::NoopRecorder;
    use crate::render::{Target, render_prompt};
    use crate::shell_word::Shell;
    use crate::shorten::{Anchor, PathFacts};
    use crate::width::WidthProfile;
    use alloc::string::String;

    fn draw(shell: Shell, width: u16) -> crate::render::RenderedPrompt {
        draw_with(shell, width, true)
    }

    fn draw_with(shell: Shell, width: u16, duration: bool) -> crate::render::RenderedPrompt {
        let d = DefaultTheme::new(Mode::Dark).unwrap();
        let i = |id| BUILTIN.iter().position(|s| s.id == id).unwrap();
        let mut values = vec![None; BUILTIN.len()];
        let mut facts = vec![None; BUILTIN.len()];
        let ch = segment("char").unwrap();
        values[i("char")] = Some(Value::new(b"", vec![Field::ABSENT; ch.fields.len()]));
        let dir = segment("dir").unwrap();
        values[i("dir")] = Some(Value::new(b"", vec![Field::ABSENT; dir.fields.len()]));
        let steps: [&[u8]; 2] = [b"Works", b"bingsu"];
        facts[i("dir")] = Some(PathFacts::new(Anchor::Home, &steps, None, &[]));
        let du = segment("duration").unwrap();
        if duration {
            values[i("duration")] = Some(Value::new(
                b"3.0s",
                vec![Field::known(FieldValue::Duration { ms: 3000 }); du.fields.len()],
            ));
        }
        let inputs = Inputs {
            catalog: BUILTIN,
            values: &values,
            facts: &facts,
            setup: d.setup(),
        };
        let t = Target {
            shell,
            depth: ColorDepth::Ansi256,
            options: Options {
                width,
                profile: WidthProfile::DEFAULT,
                icons: ICONS,
                use_last_column: false,
            },
        };
        render_prompt(&d.theme(), &inputs, &t, &mut NoopRecorder)
    }

    // 이것을 실패시키는 것: 기본 테마의 프리셋 이름·레이아웃 id·구간이 컴파일되지 않는 것(오타 하나도), 두 모드 중 하나만 되는 것,
    // SETUP의 id 오타(조용히 무시돼 우선순위가 0이 됨).
    #[test]
    fn default_theme_builds() {
        for mode in [Mode::Dark, Mode::Light] {
            let d = DefaultTheme::new(mode).unwrap();
            assert_eq!(d.theme().variants.len(), 2);
            assert_eq!(d.setup().len(), BUILTIN.len());
        }
        for (id, _, _) in SETUP {
            assert!(segment(id).is_some(), "{id}");
        }
    }

    // 이것을 실패시키는 것: 기본 레이아웃을 1줄로 바꾸는 것(윗줄 필드가 빔), `char`를 입력 줄에서 빼는 것.
    #[test]
    fn wide_is_two_lines_with_char_on_the_input_line() {
        for shell in [Shell::Zsh, Shell::Bash, Shell::Fish] {
            let r = draw(shell, 100);
            assert!(!r.upper.is_empty(), "{shell:?}");
            assert!(
                String::from_utf8_lossy(&r.upper).contains("bingsu"),
                "{shell:?}"
            );
            assert!(
                String::from_utf8_lossy(&r.left).contains('\u{276F}'),
                "{shell:?}"
            );
        }
    }

    // 이것을 실패시키는 것: narrow 구간을 빼거나 경계를 바꾸는 것(59칸에서 duration이 입력 줄로 내려오지 않음).
    #[test]
    fn narrow_band_moves_duration_beside_char() {
        let wide = draw(Shell::Fish, 60);
        let narrow = draw(Shell::Fish, 59);
        assert!(String::from_utf8_lossy(&wide.upper).contains("3.0s"));
        assert!(String::from_utf8_lossy(&narrow.left).contains("3.0s"));
        assert!(!String::from_utf8_lossy(&narrow.upper).contains("3.0s"));
    }

    // 이것을 실패시키는 것: narrow 템플릿의 간격을 리터럴 공백으로 되돌리는 것(`lean` 생성기처럼).
    // 값 없는 duration이 입력 줄을 한 칸 들여쓰거나, 값 없는 host·git이 윗줄 앞뒤에 공백을 남긴다.
    #[test]
    fn narrow_gaps_vanish_with_their_segment() {
        for shell in [Shell::Zsh, Shell::Bash, Shell::Fish] {
            let r = draw_with(shell, 59, false);
            let strip = |b: &[u8]| {
                // Drop SGR runs and the shell's invisible-span markers.
                let t = String::from_utf8_lossy(b).into_owned();
                let mut out = String::new();
                let mut esc = false;
                for c in t.chars() {
                    match (esc, c) {
                        (false, '\u{1b}') => esc = true,
                        (true, 'm') => esc = false,
                        (false, c) => out.push(c),
                        _ => {}
                    }
                }
                out.replace("%{", "")
                    .replace("%}", "")
                    .replace(['\u{1}', '\u{2}'], "")
            };
            let left = strip(&r.left);
            assert_eq!(left, "\u{276F}", "{shell:?} input line indented: {left:?}");
            let upper = strip(&r.upper);
            assert_eq!(
                upper,
                upper.trim(),
                "{shell:?} stray space on line 1: {upper:?}"
            );
        }
    }

    // 이것을 실패시키는 것: dir을 required에서 빼는 것(좁은 폭에서 경로가 사라짐), char의 우선순위를 dir보다 낮추는 것.
    #[test]
    fn dir_and_char_are_required() {
        let d = DefaultTheme::new(Mode::Dark).unwrap();
        let s = |id| d.setup()[BUILTIN.iter().position(|x| x.id == id).unwrap()];
        assert!(s("dir").required && s("char").required);
        assert!(s("char").priority > s("dir").priority);
        assert!(!s("dir").methods.is_empty());
    }
}
