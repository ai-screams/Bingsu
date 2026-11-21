//! Every line of a compiled config as runs, for a screen that keeps its own
//! cell grid and writes only the cells that change (the setup editor).
//!
//! The lines are what the prompt front draws for the same config and width:
//! the variant `LayoutView::lines_at` picks, the palette of the display mode,
//! the config's segment setup, width profile and `use_last_column`, laid out
//! by `layout::layout` (`front::render_selected_inner` and `select_theme`
//! make the same choices). The values are samples made by the prompt's own
//! value code: `shell_values::collect_with_duration_min` from an envelope,
//! `format_git` from typed git fields, the collected folder facts, and text
//! segments made as the front makes them. Nothing runs and nothing is read:
//! command, env and language segments have no value, as in the prompt
//! before their first answer.
//!
//! # The run type
//!
//! A line has a left and a right `PreviewSide`. A side is its text after
//! emit's last filter, cut into runs; each `PreviewRun` has:
//!
//! - `text`: what the terminal shows, never a removed character;
//! - `cells`: the cells of the grapheme clusters that start in this run;
//! - `style`: the token style the prompt's `emit` writes for it;
//! - `paint`: that style resolved at the preview's depth and mode.
//!
//! The runs are the layout's runs one to one, so writing them back through
//! `emit` gives the prompt's bytes (test `preview_lines::runs_are_the_prompt`).
//! A grid compares and writes `paint`, not `style`: dark and light share
//! token styles, so only the paint changes on a mode or depth switch.
//!
//! Cells are counted on the side's joined text, as layout measures it and a
//! terminal reads it: a combining mark at the start of a run joins the cell
//! before it, and two regional indicators split over two runs are one flag
//! of 2 cells, given to the first run. The cells of a side's runs add up to
//! `PreviewSide::width`, which is `layout::runs_width` of the layout's runs.
//! `PreviewSide::cells` walks the side one cluster at a time for a grid.
use crate::collection::path_facts::{PathFactInput, PathQuery};
use crate::collection::{DIR_SEGMENT, git};
use crate::color::palette::{Mode, ResolvedPalette};
use crate::color::sgr::{ColorDepth, Paint, Style, paint};
use crate::envelope::Envelope;
use crate::field::{BUILTIN, CUSTOM_TEXT, CUSTOM_TEXT_CELLS, Field, FieldType, FieldValue};
use crate::field::{SegmentDecl, Value};
use crate::icons::IconSet;
use crate::layout::{Inputs, LaidLine, Options, PATH_BYTES_MAX, Run, layout, target};
use crate::layout_view::{LayoutView, Shared, custom_text};
use crate::recorder::NoopRecorder;
use crate::sanitize::is_removed;
use crate::shell_values::{Collected, collect_with_duration_min, format_git};
use crate::width::{WidthProfile, grapheme_width};
use alloc::borrow::Cow;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use unicode_segmentation::{GraphemeIndices, UnicodeSegmentation};

/// The sample command's duration (`2.1s`). A config whose
/// `segment.duration.min` is longer hides it, as the prompt would.
pub const SAMPLE_DURATION_MS: u64 = 2100;
/// The sample background job count.
pub const SAMPLE_JOBS: u32 = 1;
/// The sample branch; the sample repository also has one modified and one
/// untracked file.
pub const SAMPLE_BRANCH: &[u8] = b"main";

/// The values that come from the machine; every other value is a sample.
#[derive(Clone, Copy, Debug)]
pub struct Sample<'a> {
    /// The folder as the shell shows it. Not absolute or longer than
    /// `layout::PATH_BYTES_MAX`: no folder, as the prompt's envelope reads it.
    pub pwd: &'a [u8],
    pub home: Option<&'a [u8]>,
    /// The host name; `None` or empty: no `host` value.
    pub host: Option<&'a [u8]>,
}

/// What one preview draws with.
#[derive(Clone, Copy, Debug)]
pub struct Request<'a> {
    /// The palette's mode. For `colors.mode = "auto"` the prompt asks
    /// `envelope::display_mode`; an explicit mode compiles one palette for both.
    pub mode: Mode,
    /// Separator, fill and git glyphs. The prompt draws the config's own
    /// `icons` (`Shared::icons`); another set shows the config in it.
    pub icons: IconSet,
    pub depth: ColorDepth,
    /// Terminal width in cells, as the prompt gets it (0: unknown).
    pub width: u16,
    pub sample: Sample<'a>,
}

/// One line of the prompt. The left side starts on the first cell; the
/// right side starts on `right_at` and ends on the last cell the line may
/// use (`layout::target`: the terminal's last column stays empty unless
/// `layout.use_last_column`). An upper line keeps the layout's form: its
/// fill and right part are in `left`, which spans the target when the line
/// has a fill (the built-in `narrow` band's has none), and `right` is empty.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreviewLine {
    pub left: PreviewSide,
    pub right: PreviewSide,
    pub right_at: u32,
}

/// One side of a line: its text and the runs that cut it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreviewSide {
    text: String,
    spans: Vec<Span>,
    profile: WidthProfile,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Span {
    /// Byte offset in `text` where the run ends; it starts where the one
    /// before ended.
    end: usize,
    cells: u32,
    style: Style,
    paint: Paint,
}

/// One run of a side (see the module notes).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PreviewRun<'a> {
    pub text: &'a str,
    pub cells: u32,
    pub style: Style,
    pub paint: Paint,
}

/// One drawn cluster of a side, from `PreviewSide::cells`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PreviewCell<'a> {
    /// Cell from the side's start.
    pub at: u32,
    /// One grapheme cluster. A code point of no cells (a combining mark, a
    /// variation selector) is always part of the cluster before it, so it
    /// draws on that cell, whichever run it came in.
    pub text: &'a str,
    /// 1 or 2; a 2-cell cluster's second cell is its continuation. 0 only
    /// for a cluster at the side's start that has no base (a mark first):
    /// the terminal puts it on the cell before the side.
    pub width: u8,
    /// The paint of the run the cluster starts in.
    pub paint: Paint,
}

impl PreviewSide {
    fn new(runs: &[Run], p: &ResolvedPalette, depth: ColorDepth, profile: WidthProfile) -> Self {
        let mut text = String::with_capacity(runs.iter().map(|r| r.text.len()).sum());
        let mut spans = Vec::with_capacity(runs.len());
        for r in runs {
            // emit's last filter (`emit::text`), so the text is what is shown.
            text.extend(r.text.chars().filter(|&c| !is_removed(c)));
            spans.push(Span {
                end: text.len(),
                cells: 0,
                style: r.style,
                paint: paint(r.style, p, depth),
            });
        }
        let mut side = Self {
            text,
            spans,
            profile,
        };
        let mut k = 0;
        for (i, g) in side.text.grapheme_indices(true) {
            k = run_at(&side.spans, k, i);
            side.spans[k].cells += u32::from(side.cluster_width(g));
        }
        side
    }

    /// `str_width`'s cells of one cluster: private use is 1 cell, as there.
    fn cluster_width(&self, g: &str) -> u8 {
        grapheme_width(g, self.profile, |_| None).0
    }

    /// The side's text, as the terminal shows it.
    pub fn text(&self) -> &str {
        &self.text
    }

    /// Cells of the whole side.
    pub fn width(&self) -> u32 {
        self.spans.iter().map(|s| s.cells).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.spans.is_empty()
    }

    /// The runs, in order.
    pub fn runs(&self) -> impl ExactSizeIterator<Item = PreviewRun<'_>> + '_ {
        let mut start = 0;
        self.spans.iter().map(move |s| {
            let run = PreviewRun {
                text: &self.text[start..s.end],
                cells: s.cells,
                style: s.style,
                paint: s.paint,
            };
            start = s.end;
            run
        })
    }

    /// The side one drawn cluster at a time, for a cell grid.
    pub fn cells(&self) -> PreviewCells<'_> {
        PreviewCells {
            side: self,
            clusters: self.text.grapheme_indices(true),
            span: 0,
            at: 0,
        }
    }
}

/// The run holding byte `i` (inside the text), searched from run `k` on.
/// Runs whose text the filter emptied end where the next starts, so they
/// hold no byte; the last run ends at the text's end.
fn run_at(spans: &[Span], mut k: usize, i: usize) -> usize {
    while spans[k].end <= i {
        k += 1;
    }
    k
}

/// `PreviewSide::cells`.
pub struct PreviewCells<'a> {
    side: &'a PreviewSide,
    clusters: GraphemeIndices<'a>,
    span: usize,
    at: u32,
}

impl<'a> Iterator for PreviewCells<'a> {
    type Item = PreviewCell<'a>;

    fn next(&mut self) -> Option<PreviewCell<'a>> {
        let (i, g) = self.clusters.next()?;
        let width = self.side.cluster_width(g);
        self.span = run_at(&self.side.spans, self.span, i);
        let cell = PreviewCell {
            at: self.at,
            text: g,
            width,
            paint: self.side.spans[self.span].paint,
        };
        self.at += u32::from(width);
        Some(cell)
    }
}

/// Every line `config` draws at `r.width`: the upper line when the prompt
/// would show one (two-line layout, not dropped by the last overflow step),
/// then the input line. Empty only when the config has no lines there.
pub fn lines<L: LayoutView>(config: &L, r: &Request<'_>) -> Vec<PreviewLine> {
    let shared = config.shared();
    let theme = shared.theme(config.lines_at(r.width), r.mode);
    let setup = shared.segment_setup();
    let options = Options {
        width: r.width,
        profile: shared.profile,
        icons: r.icons,
        use_last_column: shared.use_last_column,
    };
    let (catalog, values) = sample_values(&shared, &options, &r.sample);
    let inputs = Inputs {
        catalog: &catalog,
        values: &values.values,
        facts: &values.facts,
        setup: &setup,
    };
    let laid = layout(
        theme.variants,
        theme.bands,
        theme.band_order,
        &inputs,
        &options,
        &mut NoopRecorder,
    );
    let end = target(&options);
    let line = |l: &LaidLine| {
        let side = |runs: &[Run]| PreviewSide::new(runs, theme.palette, r.depth, options.profile);
        let (left, right) = (side(&l.left), side(&l.right));
        PreviewLine {
            right_at: end.saturating_sub(right.width()),
            left,
            right,
        }
    };
    // As `render::render_prompt`: the last line is the input line, the one
    // before it the upper line, which the shells print only when its field
    // is not empty (no runs, no bytes).
    let Some((input, upper)) = laid.split_last() else {
        return Vec::new();
    };
    upper
        .last()
        .filter(|u| !u.left.is_empty())
        .map(line)
        .into_iter()
        .chain([line(input)])
        .collect()
}

/// The values of every catalog entry the front would draw, with the
/// catalog itself (the built-ins, then one text declaration per user
/// segment, as `front::render_selected_inner` extends it).
fn sample_values(
    shared: &Shared<'_>,
    o: &Options,
    s: &Sample<'_>,
) -> (Cow<'static, [SegmentDecl]>, Collected) {
    // The envelope's own rules for `--pwd` and `--host` (`pwd_or_unknown`,
    // `display_or_unknown`); an empty host draws nothing either way.
    let e = Envelope {
        pwd: (s.pwd.first() == Some(&b'/') && s.pwd.len() <= PATH_BYTES_MAX)
            .then(|| s.pwd.to_vec()),
        home: s.home.map(<[u8]>::to_vec),
        host: s
            .host
            .filter(|h| h.len() <= PATH_BYTES_MAX)
            .map(<[u8]>::to_vec),
        status: Some(0),
        duration_ms: Some(SAMPLE_DURATION_MS),
        jobs: Some(SAMPLE_JOBS),
        ..Envelope::default()
    };
    let mut c = collect_with_duration_min(&e, shared.duration_min_ms);
    if let Some(pwd) = e.pwd.as_deref() {
        sample_folder(&mut c, pwd, e.home.as_deref());
    }
    if let Some(slot) = c.values.get_mut(usize::from(git::SEGMENT)) {
        *slot = Some(format_git(&sample_git(), o.icons, o.profile));
    }
    if shared.custom.is_empty() {
        return (Cow::Borrowed(BUILTIN), c);
    }
    let catalog = BUILTIN
        .iter()
        .copied()
        .chain(shared.custom.iter().map(|_| CUSTOM_TEXT))
        .collect();
    for t in shared.custom {
        c.values
            .push(custom_text(t).map(|text| text_value(text, o.profile)));
        c.facts.push(None);
    }
    (Cow::Owned(catalog), c)
}

/// A text segment's value: its field and its text. Compile has cut the
/// stored text to the field's cells under the config's profile
/// (`config::exec_units`), so the cut here keeps it whole and the value is
/// what `front::text_value` makes of it; test
/// `preview_lines::config_keys_reach_the_preview` draws a text that compile
/// cuts and compares it with the front.
fn text_value(text: &str, profile: WidthProfile) -> Value {
    let f = Field::text(text.as_bytes(), CUSTOM_TEXT_CELLS, profile);
    Value::new(text.as_bytes(), vec![f])
}

/// What one collection round reports for a folder inside a repository that
/// is not read-only, merged as `collection::merge` merges it: the two
/// observed `dir` fields and the facts made from the same input. The
/// repository's root is not known, so `repo` shortening has nothing to cut
/// at.
fn sample_folder(c: &mut Collected, pwd: &[u8], home: Option<&[u8]>) {
    let observed = PathFactInput {
        in_repo: Some(true),
        readonly: Some(false),
        ..PathFactInput::default()
    };
    let dir = usize::from(DIR_SEGMENT);
    // The query is made from the same folder, so its checks pass; were one
    // to fail, the folder keeps the envelope's facts.
    let Ok(facts) = observed.to_path_facts(pwd, PathQuery::for_path(pwd, home, false)) else {
        return;
    };
    let decl = &BUILTIN[dir];
    if let Some(Some(v)) = c.values.get_mut(dir) {
        for (name, b) in [("in_repo", true), ("readonly", false)] {
            if let Some(i) = decl.field_index(name) {
                v.fields[i] = Field::known(FieldValue::Bool(b));
            }
        }
    }
    if let Some(slot) = c.facts.get_mut(dir) {
        *slot = Some(facts);
    }
}

/// The sample repository as typed git fields, before `format_git`: branch
/// `SAMPLE_BRANCH`, one modified and one untracked file, every other count
/// zero (hidden), a finished, unfiltered status.
fn sample_git() -> Value {
    let decl = &BUILTIN[usize::from(git::SEGMENT)];
    let mut fields = vec![Field::ABSENT; decl.fields.len()];
    for (d, f) in decl.fields.iter().zip(fields.iter_mut()) {
        *f = match (d.name, d.ty) {
            ("branch", FieldType::Text { max_cells }) => {
                Field::text(SAMPLE_BRANCH, max_cells, WidthProfile::DEFAULT)
            }
            ("stage", FieldType::Text { max_cells }) => {
                Field::text(b"D", max_cells, WidthProfile::DEFAULT)
            }
            ("detached" | "filtered" | "no_repo" | "partial", _) => {
                Field::known(FieldValue::Bool(false))
            }
            (name, FieldType::Count) => Field::known(FieldValue::Count {
                n: u32::from(matches!(name, "modified" | "untracked")),
                saturated: false,
            }),
            _ => Field::ABSENT,
        };
    }
    Value::new(b"", fields)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::color::palette::{Knobs, PaletteInput, resolve_palette, token_index};
    use crate::color::sgr::Color;
    use crate::layout::runs_width;

    fn pal() -> ResolvedPalette {
        resolve_palette(&PaletteInput {
            mode: Mode::Dark,
            knobs: Knobs::default(),
            overrides: &[],
            roles: &[],
        })
        .unwrap()
    }
    fn style(token: &str) -> Style {
        Style {
            fg: Color::Text(token_index(token).unwrap() as u16),
            ..Style::default()
        }
    }
    fn runs(parts: &[(&str, &str)]) -> Vec<Run> {
        parts
            .iter()
            .map(|(t, tok)| Run {
                text: String::from(*t),
                style: style(tok),
            })
            .collect()
    }
    fn side(parts: &[(&str, &str)]) -> PreviewSide {
        PreviewSide::new(
            &runs(parts),
            &pal(),
            ColorDepth::TrueColor,
            WidthProfile::DEFAULT,
        )
    }
    fn cells(s: &PreviewSide) -> Vec<(u32, &str, u8, Paint)> {
        s.cells()
            .map(|c| (c.at, c.text, c.width, c.paint))
            .collect()
    }
    fn run_cells(s: &PreviewSide) -> Vec<u32> {
        s.runs().map(|r| r.cells).collect()
    }

    // 이것을 실패시키는 것: run마다 따로 폭을 세는 것(둘로 나뉜 지역 표시 문자 쌍이 2+2칸이 된다), 결합 문자가
    // 앞 run의 칸에 붙지 않는 것(그 칸의 글자와 paint), 넓은 글자 뒤 칸 위치가 1만 느는 것, run 칸의 합이
    // layout이 세는 폭(`runs_width`, 이어 붙인 글자)과 다른 것.
    #[test]
    fn cells_are_counted_on_the_joined_text() {
        let flag = [("\u{1F1F0}", "path"), ("\u{1F1F7}", "muted")];
        let s = side(&flag);
        assert_eq!(run_cells(&s), [2, 0]);
        assert_eq!(s.width(), runs_width(&runs(&flag), WidthProfile::DEFAULT));
        let red = s.runs().next().unwrap().paint;
        assert_eq!(cells(&s), [(0, "\u{1F1F0}\u{1F1F7}", 2, red)]);

        let mark = [("e", "path"), ("\u{301}x", "muted")];
        let s = side(&mark);
        let p: Vec<Paint> = s.runs().map(|r| r.paint).collect();
        assert_ne!(p[0], p[1]);
        assert_eq!(run_cells(&s), [1, 1]);
        assert_eq!(cells(&s), [(0, "e\u{301}", 1, p[0]), (1, "x", 1, p[1])]);

        let wide = [("\u{6F22}a", "path")];
        let s = side(&wide);
        assert_eq!(run_cells(&s), [3]);
        assert_eq!(cells(&s), [(0, "\u{6F22}", 2, p[0]), (2, "a", 1, p[0])]);
        for parts in [&flag[..], &mark, &wide] {
            assert_eq!(
                side(parts).width(),
                runs_width(&runs(parts), WidthProfile::DEFAULT),
                "{parts:?}"
            );
        }
    }

    // 이것을 실패시키는 것: 옆 쪽 맨 앞의 바탕 없는 표지를 뒤 글자에 붙이거나 칸 위치를 1 늘리는 것.
    // 폭 0 칸은 이것 하나뿐이다(`no_cell_code_point_stands_alone`).
    #[test]
    fn a_leading_mark_has_no_cell() {
        let s = side(&[("\u{301}a", "path")]);
        let p = s.runs().next().unwrap().paint;
        assert_eq!(cells(&s), [(0, "\u{301}", 0, p), (0, "a", 1, p)]);
        assert_eq!(s.width(), 1);
    }

    // 이것을 실패시키는 것: 홀로는 폭 0인 code point가 앞 글자와 다른 cluster가 되는 것(그러면 쪽 가운데에
    // 폭 0 칸이 생겨 `PreviewCell::width`의 약속이 깨진다). 정제 뒤 남는 모든 code point를 `a`, `漢`, 빈칸 뒤에
    // 둔다. 표가 바뀌어 U+1160(앞 글자와 cluster가 갈리는 한글 중성 채움)이 폭 0이 되면 실패한다.
    #[test]
    fn no_cell_code_point_stands_alone() {
        let mut checked = 0;
        for c in (0..=0x10_FFFFu32).filter_map(char::from_u32) {
            let mut one = [0u8; 4];
            let one = c.encode_utf8(&mut one);
            if is_removed(c) || grapheme_width(one, WidthProfile::DEFAULT, |_| None).0 != 0 {
                continue;
            }
            for base in ['a', '\u{6F22}', ' '] {
                let mut s = String::new();
                s.push(base);
                s.push(c);
                assert_eq!(
                    s.graphemes(true).count(),
                    1,
                    "U+{:04X} after {base:?}",
                    u32::from(c)
                );
            }
            checked += 1;
        }
        assert!(checked > 1000, "{checked}");
    }

    // 이것을 실패시키는 것: emit의 마지막 거름(정제 대상 글자 지우기)을 run 글자에 하지 않는 것. 위쪽 입구를
    // 우회한 RLO·ZWSP·SOH·ESC가 와도 편집판이 터미널에 그대로 쓰는 글자에 남지 않아야 한다. 다 지워진 run도
    // 자리(스타일)를 지켜 emit과 run 경계가 같다.
    #[test]
    fn removed_characters_never_reach_a_run() {
        let s = side(&[
            ("a\u{202E}b\u{200B}c\u{1}d\x1b[31me%", "path"),
            ("\u{202E}", "muted"),
            ("z", "fg"),
        ]);
        assert_eq!(s.text(), "abcd[31me%z");
        let texts: Vec<&str> = s.runs().map(|r| r.text).collect();
        assert_eq!(texts, ["abcd[31me%", "", "z"]);
        assert_eq!(run_cells(&s), [10, 0, 1]);
        assert_eq!(cells(&s).last().map(|c| (c.0, c.1)), Some((10, "z")));
    }
}
