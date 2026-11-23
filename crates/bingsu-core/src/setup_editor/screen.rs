//! The editor's screen as a grid of cells, from the model and the preview
//! lines. Writing the grid to the terminal is not here; the shaved-ice
//! bowl's frames come from `crate::opening`, and [`put_band`] copies one
//! into rows 1-7 where [`bowl_shown`] says the main screen has them.
//!
//! Sizes: 80 columns or more list every value of a row; 60-79 show the
//! picked one (`< triangle >  2/8`); below 24 rows or 60 columns the bowl's
//! rows go and blank lines are dropped first; below 40x16 the "too small"
//! screen, and below 12x3 nothing.
//!
//! Text: what bingsu writes here is ASCII. Text from outside (the path, the
//! names of other settings files) goes through `sanitize` and is cut by
//! cells, its cut end an ASCII `...`; a path is cut in the middle. The last
//! column stays empty, as the prompt leaves it.
use super::model::{Model, Screen, Target};
use super::rows::{self, Row};
use super::write::{changes, written_keys};
use crate::color::math::{Srgb8, nearest_256};
use crate::color::palette::{Mode, ResolvedPalette, named_color};
use crate::color::sgr::{BOLD, ColorDepth, Ink, Paint, REVERSE, write_paint};
use crate::preview::PreviewLine;
use crate::width::{WidthProfile, fit_prefix, fit_suffix, grapheme_width, str_width};
use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use unicode_segmentation::UnicodeSegmentation;

/// The smallest screen the editor draws on.
pub const MIN_COLS: u16 = 40;
pub const MIN_ROWS: u16 = 16;
/// Below this the "too small" screen draws nothing.
const BLANK_COLS: u16 = 12;
const BLANK_ROWS: u16 = 3;
/// The rows the bowl takes, at 24 rows and 60 columns or more.
pub const BOWL_ROWS: u16 = 7;
/// Where the values of a setting row start.
const VALUES_AT: u16 = 15;
/// The largest grid. A window size comes from the terminal driver, which
/// any process of the user can set (0 to 65535 each way), so it is bounded
/// before the cells are made; a larger screen is drawn in its top left
/// corner, the rest left as it was cleared.
pub const MAX_COLS: u16 = 512;
pub const MAX_ROWS: u16 = 256;

pub fn too_small(cols: u16, rows: u16) -> bool {
    cols < MIN_COLS || rows < MIN_ROWS
}

/// The first of the bowl's rows (under the title).
pub const BOWL_TOP: u16 = 1;

/// Whether the main screen's layout keeps the bowl's rows at this size
/// (24 rows and 60 columns or more).
/// 이것을 실패시키는 것: 그릇 자리 조건을 배치와 따로 두는 것(그릇이 다른 줄 위에 그려짐;
/// the_band_goes_only_where_the_layout_keeps_the_bowl).
const fn bowl_fits(cols: u16, rows: u16) -> bool {
    rows >= 24 && cols >= 60
}

/// Whether a frame drawn now (`draw(m, v)`) has the bowl's rows: the main
/// screen, at a size that keeps them. The keys and save screens use those
/// rows for their own text.
pub fn bowl_shown(m: &Model, cols: u16, rows: u16) -> bool {
    let (cols, rows) = (cols.min(MAX_COLS), rows.min(MAX_ROWS));
    m.screen() == Screen::Main && !too_small(cols, rows) && bowl_fits(cols, rows)
}

/// Copies the opening's `band` into the grid's rows `BOWL_TOP`.. (the
/// caller draws it `cols - 1` wide: the last column stays empty). A cell
/// with an ink takes its glyph in that color, mapped as the editor's own
/// colors are (`ink`), or in the default color with `mono` (`NO_COLOR`);
/// the background stays the screen's. An empty cell is left as the screen
/// has it. Through `Grid::set`, like every other cell: a glyph that is a
/// control is not put, and nothing goes past the grid or onto its last
/// column.
/// 이것을 실패시키는 것: 칸을 직접 써서 set을 건너뛰는 것(제어 글자가 칸에 들어감; a_band_cell_goes_through_the_one_writer),
/// 색 깊이를 편집판 글과 다르게 옮기는 것(Ansi16에 256색; the_band_goes_only_where_the_layout_keeps_the_bowl).
pub fn put_band(g: &mut Grid, band: &crate::opening::Band, depth: ColorDepth, mono: bool) {
    let end = g.cols.saturating_sub(1);
    for y in 0..crate::opening::ROWS {
        let gy = BOWL_TOP + y;
        if gy >= g.rows {
            break;
        }
        for (x, c) in (0..end).zip(band.row(y)) {
            let Some(color) = c.ink else { continue };
            let fg = if mono {
                Ink::Default
            } else {
                ink(Some(color), depth)
            };
            let paint = Paint {
                fg,
                ..g.cell(x, gy).paint
            };
            let mut glyph = [0u8; 4];
            let text = char::from(c.ch).encode_utf8(&mut glyph);
            let w = grapheme_width(text, WidthProfile::DEFAULT, |_| None).0;
            g.set(u32::from(x), gy, text, w, paint, u32::from(end));
        }
    }
}

/// One cell: one grapheme cluster and its paint. A cell covered by the
/// 2-cell cluster on its left has empty text.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Cell {
    pub text: String,
    pub paint: Paint,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Grid {
    cols: u16,
    rows: u16,
    cells: Vec<Cell>,
}

impl Grid {
    fn new(cols: u16, rows: u16, paint: Paint) -> Self {
        let blank = Cell {
            text: String::from(" "),
            paint,
        };
        Self {
            cols,
            rows,
            cells: vec![blank; usize::from(cols) * usize::from(rows)],
        }
    }
    pub fn cols(&self) -> u16 {
        self.cols
    }
    pub fn rows(&self) -> u16 {
        self.rows
    }
    pub fn cell(&self, x: u16, y: u16) -> &Cell {
        &self.cells[usize::from(y) * usize::from(self.cols) + usize::from(x)]
    }
    fn cell_mut(&mut self, x: u16, y: u16) -> &mut Cell {
        &mut self.cells[usize::from(y) * usize::from(self.cols) + usize::from(x)]
    }
    /// The text of row `y`, the cells covered by a 2-cell cluster left out.
    pub fn row_text(&self, y: u16) -> String {
        (0..self.cols)
            .map(|x| self.cell(x, y).text.as_str())
            .collect()
    }

    /// Puts `text` (sanitized already, or bingsu's own) at `x` on row `y`,
    /// no further than column `end` (exclusive); returns where it ended. A
    /// 2-cell cluster that would cross `end` is not put.
    /// Puts one cluster of `width` cells at `x` on row `y`; a 2-cell
    /// cluster also covers the cell after it. Puts nothing, and says so, for
    /// a cluster of no cells (a mark with no base, which a terminal would
    /// put on the cell before) or one that does not end by column `end`
    /// (exclusive) inside the row.
    fn set(&mut self, x: u32, y: u16, text: &str, width: u8, paint: Paint, end: u32) -> bool {
        let w = u32::from(width);
        let fits = x
            .checked_add(w)
            .is_some_and(|e| e <= end.min(u32::from(self.cols)));
        // The one writer of cells: a control, bidi or invisible character
        // never reaches a frame, whatever the caller forgot to clean.
        // A closure: the purity gate refuses a function item passed on.
        let removed = text
            .chars()
            .filter(|&c| crate::sanitize::is_removed(c))
            .count()
            > 0;
        if w == 0 || !fits || y >= self.rows || removed {
            return false;
        }
        let x = x as u16;
        *self.cell_mut(x, y) = Cell {
            text: String::from(text),
            paint,
        };
        if w == 2 {
            *self.cell_mut(x + 1, y) = Cell {
                text: String::new(),
                paint,
            };
        }
        true
    }

    /// Puts `text` (sanitized already, or bingsu's own) at `x` on row `y`,
    /// no further than column `end` (exclusive); returns where it ended. A
    /// 2-cell cluster that would cross `end` is not put.
    fn put(&mut self, x: u16, y: u16, text: &str, paint: Paint, end: u16) -> u16 {
        let mut at = x;
        for g in text.graphemes(true) {
            let w = grapheme_width(g, WidthProfile::DEFAULT, |_| None).0;
            if at + u16::from(w) > end {
                break;
            }
            if self.set(u32::from(at), y, g, w, paint, u32::from(end)) {
                at += u16::from(w);
            }
        }
        at
    }
}

/// Cursor to column `x`, row `y` (0-based).
fn move_to(x: u16, y: u16, out: &mut Vec<u8>) {
    out.extend_from_slice(format!("\x1b[{};{}H", u32::from(y) + 1, u32::from(x) + 1).as_bytes());
}

/// The bytes that turn the screen `prev` showed into `next`: cursor moves,
/// SGR, erase to the line's end and the cells' text, no other escape (no
/// string, no mode). `None`, or a grid of another size: the whole screen,
/// first cleared. Otherwise only the cells that changed, from the first one
/// of each run, and a paint only where it changes. The last column gets
/// no glyph (one there leaves the cursor waiting to wrap, and on the last
/// row a terminal can scroll): its paint comes from erasing from it to the
/// line's end in that paint (the terminal's background-color erase). Each
/// frame sets its first paint whole, so it needs nothing of the terminal's
/// state.
pub fn frame(prev: Option<&Grid>, next: &Grid, out: &mut Vec<u8>) {
    let (cols, rows) = (next.cols, next.rows);
    if cols == 0 || rows == 0 {
        return;
    }
    let last = cols - 1;
    let prev = prev.filter(|p| p.cols == cols && p.rows == rows);
    if prev.is_none() {
        write_paint(next.cell(last, 0).paint, out);
        out.extend_from_slice(b"\x1b[2J");
    }
    let mut paint = None;
    for y in 0..rows {
        // Where the cursor is after the last cell written on this row.
        let mut at = None;
        for x in 0..last {
            let cell = next.cell(x, y);
            // A cell a 2-cell cluster covers comes with that cluster.
            if cell.text.is_empty() {
                continue;
            }
            let wide = x + 1 < last && next.cell(x + 1, y).text.is_empty();
            if prev.is_some_and(|p| p.cell(x, y) == cell) {
                continue;
            }
            if at != Some(x) {
                move_to(x, y, out);
            }
            if paint != Some(cell.paint) {
                write_paint(cell.paint, out);
                paint = Some(cell.paint);
            }
            out.extend_from_slice(cell.text.as_bytes());
            at = Some(x + if wide { 2 } else { 1 });
        }
        let edge = next.cell(last, y).paint;
        if prev.is_none_or(|p| p.cell(last, y).paint != edge) {
            move_to(last, y, out);
            if paint != Some(edge) {
                write_paint(edge, out);
                paint = Some(edge);
            }
            out.extend_from_slice(b"\x1b[K");
        }
    }
}

/// `raw` as the screen may show it: control, bidi and invisible
/// characters taken out (`sanitize`).
pub fn clean(raw: &[u8]) -> String {
    crate::sanitize::sanitize(raw)
}

/// `s` in at most `max` cells: cut at its end with `...` when it is longer.
pub fn cut_end(s: &str, max: u16) -> String {
    let p = WidthProfile::DEFAULT;
    if str_width(s, p) <= u32::from(max) {
        return String::from(s);
    }
    let (n, _) = fit_prefix(s, u32::from(max.saturating_sub(3)), p);
    let dots = &"..."[..usize::from(max.min(3))];
    format!("{}{dots}", &s[..n])
}

/// `s` in at most `max` cells: cut in the middle with `...` (a path keeps
/// its start and its file name).
pub fn cut_middle(s: &str, max: u16) -> String {
    let p = WidthProfile::DEFAULT;
    if str_width(s, p) <= u32::from(max) || max < 5 {
        return cut_end(s, max);
    }
    let room = u32::from(max - 3);
    let tail_room = room / 2 + room % 2;
    let (from, tail_w) = fit_suffix(s, tail_room, p);
    let (to, _) = fit_prefix(s, room - tail_w, p);
    format!("{}...{}", &s[..to], &s[from..])
}

/// What the screen shows beside the model.
#[derive(Clone, Copy, Debug)]
pub struct View<'a> {
    pub cols: u16,
    pub rows: u16,
    /// The settings file the editor is for, as the loader names it.
    pub path: &'a [u8],
    /// `preview::lines` of the settings as the model has them, at `cols`
    /// bounded by `MAX_COLS`. The last column stays empty: a config with
    /// `layout.use_last_column` is laid out one column narrower, so its
    /// right side ends on the last cell drawn. Lines of another width (made
    /// before a resize) are cut there.
    pub lines: &'a [PreviewLine],
    /// The palette the preview drew with (its `background` is the mode's
    /// `neutral.base`, the preview's own background).
    pub palette: &'a ResolvedPalette,
    pub mode: Mode,
    pub depth: ColorDepth,
    /// Why the preview draws in `mode`, bingsu's own words: `dark`, or
    /// `auto: dark (no COLORFGBG)`.
    pub mode_note: &'a str,
    /// What the terminal said its background is (OSC 11), when it said.
    pub terminal: Option<Mode>,
    /// The width picks the built-in `narrow` band with its built-in
    /// template: the preview cannot show the shape rows.
    pub narrow: bool,
    /// `NO_COLOR`: bingsu's own text in the terminal's colors, the picked
    /// value reversed and bold; the preview keeps its colors.
    pub mono: bool,
    /// Why the preview does not follow the picks (`not updated for this
    /// file format`): it then shows the settings as they are.
    pub stale: Option<&'a str>,
}

/// The paints of bingsu's own text.
struct Ui {
    text: Paint,
    sub: Paint,
    title: Paint,
    pick: Paint,
    base: Ink,
}

fn ink(c: Option<Srgb8>, depth: ColorDepth) -> Ink {
    match (c, depth) {
        (Some(c), ColorDepth::TrueColor) => Ink::Rgb(c.r, c.g, c.b),
        (Some(c), ColorDepth::Ansi256) => Ink::Indexed(nearest_256(c)),
        _ => Ink::Default,
    }
}

/// The UI colors of `mode`, as names of the palette (text
/// `neutral.text` and `neutral.subtext` on `neutral.base`; a picked value
/// on the accent). A picked value that changes nothing has no box: it is
/// `[value]` in the subtext color, so it never looks stronger than an
/// effective pick, and the brackets mark it without color.
fn ui(mode: Mode, depth: ColorDepth, mono: bool) -> Ui {
    if mono {
        let text = Paint::default();
        return Ui {
            text,
            sub: text,
            title: Paint {
                attrs: BOLD,
                ..text
            },
            pick: Paint {
                attrs: BOLD | REVERSE,
                ..text
            },
            base: Ink::Default,
        };
    }
    let c = |name: &str, read: bool| ink(named_color(name, mode, read), depth);
    let base = c("neutral.base", false);
    let text = Paint {
        fg: c("neutral.text", true),
        bg: base,
        attrs: 0,
    };
    Ui {
        text,
        sub: Paint {
            fg: c("neutral.subtext", true),
            ..text
        },
        title: Paint {
            attrs: BOLD,
            ..text
        },
        pick: Paint {
            fg: c("neutral.ink", false),
            bg: c("accent.blue", false),
            attrs: BOLD,
        },
        base,
    }
}

/// The keys line at full width, and the one that fits 40 columns.
const KEYS_LONG: &str = "s o j n g i c l change  arrows move  ? keys  u undo  enter save  q quit";
const KEYS_SHORT: &str = "? keys  enter save  q quit";
const ICONS_HINT: &str = "Boxes or blanks above? Press i for unicode.";
/// The narrow note, shown only under 60 columns: the longer form where it
/// fits (from 50 columns).
const NARROW_LONG: &str = "narrow layout under 60 columns; widen to compare";
const NARROW_SHORT: &str = "narrow layout under 60 columns";

/// The lines of the main screen, top down.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Line {
    Title,
    Bowl,
    Blank,
    Label,
    Preview(usize),
    Hint,
    Setting(Row),
    Status,
    Keys,
}

/// The screen for `m` and `v`, at most `MAX_COLS` by `MAX_ROWS` cells.
pub fn draw(m: &Model, v: &View<'_>) -> Grid {
    let v = &View {
        cols: v.cols.min(MAX_COLS),
        rows: v.rows.min(MAX_ROWS),
        ..*v
    };
    let u = ui(v.mode, v.depth, v.mono);
    let mut g = Grid::new(
        v.cols,
        v.rows,
        Paint {
            bg: u.base,
            ..Paint::default()
        },
    );
    if too_small(v.cols, v.rows) {
        too_small_screen(&mut g, v, &u);
        return g;
    }
    match m.screen() {
        Screen::Main => main_screen(&mut g, m, v, &u),
        Screen::Keys => keys_screen(&mut g, &u),
        Screen::Save { .. } => save_screen(&mut g, m, v, &u),
    }
    g
}

fn too_small_screen(g: &mut Grid, v: &View<'_>, u: &Ui) {
    if v.cols < BLANK_COLS || v.rows < BLANK_ROWS {
        return;
    }
    let lines = [
        String::from("bingsu setup"),
        format!("Too small: {MIN_COLS}x{MIN_ROWS} or more needed."),
        format!("Now {}x{}; q quits.", v.cols, v.rows),
    ];
    // Each line cut where the screen ends.
    let end = v.cols - 1;
    for (y, line) in lines.iter().enumerate().take(usize::from(v.rows)) {
        g.put(1, y as u16, line, u.text, end);
    }
}

fn main_screen(g: &mut Grid, m: &Model, v: &View<'_>, u: &Ui) {
    let bowl = bowl_fits(v.cols, v.rows);
    let mut plan = vec![Line::Title];
    if bowl {
        plan.extend([Line::Bowl; BOWL_ROWS as usize]);
    } else {
        plan.push(Line::Blank);
    }
    plan.push(Line::Label);
    // Two preview rows at full size, so the rows below do not move when
    // the prompt changes between one line and two.
    let previews = if bowl { 2 } else { v.lines.len().clamp(1, 2) };
    for i in 0..previews {
        plan.push(Line::Preview(i));
    }
    plan.push(Line::Hint);
    for row in Row::ALL {
        plan.push(Line::Setting(row));
    }
    plan.extend([Line::Blank, Line::Status, Line::Blank, Line::Keys]);
    // Blank lines go first when the rows run out.
    // Without them every line fits `MIN_ROWS`: title, label, two preview
    // rows, the hint, eight rows, status and keys are 15.
    while plan.len() > usize::from(v.rows) {
        let Some(i) = plan.iter().position(|l| *l == Line::Blank) else {
            break;
        };
        plan.remove(i);
    }
    let end = v.cols - 1;
    for (y, line) in plan.iter().enumerate() {
        let y = y as u16;
        match *line {
            Line::Title => title(g, m, v, u, y),
            Line::Bowl | Line::Blank => {}
            Line::Label => {
                let text = format!(
                    "preview  {} columns, {}, {}",
                    v.cols,
                    v.mode_note,
                    v.stale.unwrap_or("sample values")
                );
                g.put(1, y, &cut_end(&text, end - 1), u.sub, end);
            }
            Line::Preview(i) => preview(g, v, u, y, i),
            Line::Hint => {
                let text = if v.narrow {
                    if str_width(NARROW_LONG, WidthProfile::DEFAULT) <= u32::from(end - 1) {
                        NARROW_LONG
                    } else {
                        NARROW_SHORT
                    }
                } else if m.icons_hint() && m.effective(Row::Icons) < 2 {
                    ICONS_HINT
                } else {
                    ""
                };
                g.put(1, y, &cut_end(text, end - 1), u.sub, end);
            }
            Line::Setting(row) => setting(g, m, v, u, y, row),
            Line::Status => {
                g.put(1, y, &cut_end(&status(m), end - 1), u.text, end);
            }
            Line::Keys => {
                let keys = if str_width(KEYS_LONG, WidthProfile::DEFAULT) <= u32::from(end - 1) {
                    KEYS_LONG
                } else {
                    KEYS_SHORT
                };
                g.put(1, y, keys, u.sub, end);
            }
        }
    }
}

fn state_word(m: &Model) -> &'static str {
    match (m.read_only(), m.target()) {
        (true, _) => "read only",
        (false, Target::New) => "new file",
        (false, Target::Existing(_)) => "exists: not changed",
    }
}

fn title(g: &mut Grid, m: &Model, v: &View<'_>, u: &Ui, y: u16) {
    let end = v.cols - 1;
    let name = "bingsu setup";
    let x = g.put(1, y, name, u.title, end);
    let state = state_word(m);
    // The path and its state end on the last column the screen uses.
    let room = end.saturating_sub(x + 2 + 2 + state.len() as u16);
    let path = cut_middle(&clean(v.path), room);
    let right = format!("{path}  {state}");
    let w = str_width(&right, WidthProfile::DEFAULT) as u16;
    g.put(end.saturating_sub(w), y, &right, u.text, end);
}

fn preview(g: &mut Grid, v: &View<'_>, u: &Ui, y: u16, i: usize) {
    let base = ink(Some(v.palette.background), v.depth);
    let blank = Paint { bg: base, ..u.text };
    for x in 0..v.cols {
        *g.cell_mut(x, y) = Cell {
            text: String::from(" "),
            paint: blank,
        };
    }
    let Some(line) = v.lines.get(i) else {
        return;
    };
    // The last column stays empty here too, also for lines laid out at an
    // older, wider width (before a resize).
    let end = u32::from(v.cols.saturating_sub(1));
    for (side, from) in [(&line.left, 0u32), (&line.right, line.right_at)] {
        for c in side.cells() {
            let mut paint = c.paint;
            if paint.bg == Ink::Default {
                paint.bg = base;
            }
            // `right_at` is a public field: a position past `u32` is off
            // the grid.
            if let Some(x) = from.checked_add(c.at) {
                g.set(x, y, c.text, c.width, paint, end);
            }
        }
    }
}

/// The note at the end of a setting row, and whether the picked value
/// changes nothing (then drawn as `[value]`).
fn row_note(m: &Model, v: &View<'_>, row: Row) -> (String, bool) {
    let name = |i: usize| clean(m.layers().names.get(i).map_or(&[][..], |n| n.as_slice()));
    if Row::TEMPLATED.contains(&row) {
        if let Some(t) = m.layers().template {
            return (format!("a template in {} replaces these", name(t)), true);
        }
    }
    if let Some(n) = m.covered_by(row) {
        return (format!("overridden by {}", name(n)), true);
    }
    if Row::SHAPE.contains(&row) {
        if let Some(why) = rows::no_effect(row, &m.options(), m.effective(Row::Joint)) {
            return (String::from(why), true);
        }
    }
    if matches!(row, Row::Outer | Row::Joint | Row::Inner)
        && rows::shapes_look_alike(m.effective(Row::Icons))
    {
        return (String::from("3 shapes look alike here"), false);
    }
    if row == Row::Colors && m.effective(Row::Colors) == 0 {
        if let Some(t) = v.terminal.filter(|t| *t != v.mode) {
            let w = rows::MODES[if t == Mode::Light { 2 } else { 1 }];
            return (format!("the terminal looks {w}; pick {w}"), false);
        }
    }
    (String::new(), false)
}

fn setting(g: &mut Grid, m: &Model, v: &View<'_>, u: &Ui, y: u16, row: Row) {
    let end = v.cols - 1;
    let cursor = if m.row() == row && m.screen() == Screen::Main {
        ">"
    } else {
        " "
    };
    let mark = if m.marked(row) { "*" } else { " " };
    let head = format!("{cursor}{mark} {} {}", row.key() as char, row.name());
    g.put(0, y, &head, u.text, end);
    let (note, idle) = row_note(m, v, row);
    let picked = usize::from(m.chosen(row));
    // A pick that changes nothing: `[value]` in the subtext color, the
    // brackets in the spaces around it (the row keeps its width).
    let pick = if idle { u.sub } else { u.pick };
    let values = row.values();
    let mut x = VALUES_AT;
    if v.cols >= 80 {
        for (i, value) in values.iter().enumerate() {
            if i > 0 {
                let gap = if idle && i == picked + 1 { " " } else { "  " };
                x = g.put(x, y, gap, u.text, end);
            }
            if idle && i == picked {
                g.put(x - 1, y, "[", u.sub, end);
            }
            x = g.put(x, y, value, if i == picked { pick } else { u.text }, end);
            if idle && i == picked {
                x = g.put(x, y, "]", u.sub, end);
            }
        }
    } else {
        let (open, close) = if idle { ("<[", "]>") } else { ("< ", " >") };
        x = g.put(x, y, open, u.text, end);
        x = g.put(x, y, values[picked], pick, end);
        x = g.put(x, y, close, u.text, end);
        let count = format!("  {}/{}", picked + 1, values.len());
        x = g.put(x, y, &count, u.sub, end);
    }
    let room = end.saturating_sub(x + 2);
    g.put(x + 2, y, &cut_end(&note, room), u.sub, end);
}

/// The status line: the message of the last key, else what saving would
/// write (or change) and what a later file covers.
fn status(m: &Model) -> String {
    if let Some(n) = m.note() {
        return String::from(n.text());
    }
    let keys: Vec<&str> = match m.target() {
        Target::New => written_keys(m).iter().map(|k| k.key).collect(),
        Target::Existing(_) => changes(m).iter().map(|c| c.key).collect(),
    };
    let verb = match m.target() {
        Target::New => "writes",
        Target::Existing(_) => "changes",
    };
    let summary = match keys.len() {
        0 => String::from("no changes"),
        1 => format!("{verb} 1 key: {}", keys[0]),
        n => format!("{verb} {n} keys: {}", keys.join(", ")),
    };
    // A key this file writes that a later file covers does not show in the
    // preview: that comes first, so a long name cuts the list, not it.
    match Row::ALL
        .into_iter()
        .filter(|r| m.marked(*r))
        .flat_map(|r| (0..r.keys().len()).map(move |i| (r, i)))
        .find_map(|(r, i)| m.covered_key(r, i).map(|n| (r.keys()[i], n)))
    {
        Some((key, n)) => {
            let name = clean(m.layers().names.get(n).map_or(&[][..], |x| x.as_slice()));
            format!("{key} covered by {name}; {summary}")
        }
        None => summary,
    }
}

/// The list of every key (`?`).
const KEY_LINES: [&str; 13] = [
    "Keys",
    "",
    "s o j n g i c l    change that row (upper case: back)",
    "up down, tab       move between the rows",
    "left right, space  change the value",
    "1-9                pick a value",
    "backspace          remove this file's value",
    "u                  undo the last change (again: redo)",
    "r                  back to the start",
    "enter              save",
    "q                  quit",
    "ctrl-l             draw again",
    "esc                close this list",
];

fn keys_screen(g: &mut Grid, u: &Ui) {
    let end = g.cols() - 1;
    for (y, line) in KEY_LINES.iter().enumerate().take(usize::from(g.rows())) {
        let paint = if y == 0 { u.title } else { u.text };
        g.put(1, y as u16, &cut_end(line, end - 1), paint, end);
    }
}

/// The save screen's line about a template, when one replaces rows this
/// file writes (or changes): those keys draw nothing.
fn template_line(m: &Model, writes: impl Fn(Row) -> bool) -> Option<(String, bool)> {
    let t = m.layers().template?;
    if !Row::TEMPLATED.into_iter().any(writes) {
        return None;
    }
    let name = clean(m.layers().names.get(t).map_or(&[][..], |n| n.as_slice()));
    Some((
        format!("A template in {name} draws in place of the style and line keys."),
        false,
    ))
}

/// What the save screen says of an existing settings file `path` (as the
/// loader names it), line by line from its title: nothing is written, and
/// each key to change with its value now and the one chosen, the line to
/// put in or take out, and a later file that sets it too. The CLI prints
/// the same lines once the editor is left. Every text from outside
/// (values, names, the path) is cleaned.
pub fn existing_report(m: &Model, path: &[u8]) -> Vec<String> {
    let name = |i: usize| clean(m.layers().names.get(i).map_or(&[][..], |n| n.as_slice()));
    let path = clean(path);
    let file = path.rsplit('/').next().unwrap_or("");
    let mut lines = vec![
        format!("{file} is already there; bingsu does not change it."),
        String::new(),
    ];
    let c = changes(m);
    if c.is_empty() {
        lines.push(String::from("It already has the choices you made."));
    }
    lines.extend(template_line(m, |r| m.marked(r)).map(|(l, _)| l));
    for ch in c {
        lines.push(format!(
            "{}: {} now, {} chosen",
            ch.key,
            clean(ch.now.as_bytes()),
            ch.chosen
        ));
        lines.push(format!("  {}", ch.line));
        if let Some(n) = ch.covered_by {
            // Only the fact: whether that file can be edited (a package's
            // theme reached through `extends`) is not known here.
            lines.push(format!("  {} sets this too, and wins.", name(n)));
        }
    }
    lines
}

fn save_screen(g: &mut Grid, m: &Model, v: &View<'_>, u: &Ui) {
    let end = v.cols - 1;
    let path = clean(v.path);
    let name = |i: usize| clean(m.layers().names.get(i).map_or(&[][..], |n| n.as_slice()));
    let mut lines: Vec<(String, bool)> = Vec::new();
    let footer = match m.target() {
        Target::New => {
            lines.push((format!("Write {}?", cut_middle(&path, end - 8)), true));
            lines.push((String::new(), false));
            let keys = written_keys(m);
            for kv in &keys {
                lines.push((format!("  {} = {}", kv.key, kv.value), false));
            }
            // Per key: a later file may set one key of a row and not the
            // other (`layout.line1.left` alone).
            for kv in &keys {
                let covered = Row::ALL.into_iter().find_map(|r| {
                    let i = r.keys().iter().position(|k| *k == kv.key)?;
                    m.covered_key(r, i)
                });
                if let Some(n) = covered {
                    lines.push((format!("{} sets {} too, and wins.", name(n), kv.key), false));
                }
            }
            lines.extend(template_line(m, |r| m.marked(r)));
            let parts = [Row::Outer, Row::Joint, Row::Inner, Row::Gap];
            if parts.iter().any(|r| m.written(*r).is_some()) {
                lines.push((
                    String::from(
                        "Under 60 columns the built-in narrow layout draws instead of these style keys.",
                    ),
                    false,
                ));
            }
            if m.written(Row::Lines) == Some(1) {
                lines.push((
                    String::from("1 line: under 60 columns the built-in narrow layout still draws two lines."),
                    false,
                ));
            }
            if m.read_only() {
                "The folder cannot be written.  esc back  q quit"
            } else {
                "enter write  esc back  q quit"
            }
        }
        Target::Existing(_) => {
            let mut report = existing_report(m, v.path).into_iter();
            if let Some(head) = report.next() {
                lines.push((head, true));
            }
            lines.extend(report.map(|l| (l, false)));
            "enter print and quit  esc back"
        }
    };
    let last = v.rows - 1;
    for (y, (line, bold)) in lines.iter().enumerate() {
        let y = y as u16;
        if y + 1 >= last {
            g.put(1, y, "...", u.sub, end);
            break;
        }
        g.put(
            1,
            y,
            &cut_end(line, end - 1),
            if *bold { u.title } else { u.text },
            end,
        );
    }
    g.put(1, last, &cut_end(footer, end - 1), u.sub, end);
}

#[cfg(test)]
mod tests {
    use super::*;

    // A band cell whose glyph is a control (U+0085 from byte 0x85) is not
    // put; a plain one is. 이것을 실패시키는 것: put_band가 set을 건너뛰고 칸을 직접 쓰는 것.
    #[test]
    fn a_band_cell_goes_through_the_one_writer() {
        use crate::opening::{Band, Cell as BandCell, ROWS};
        let ink = Some(Srgb8 {
            r: 200,
            g: 200,
            b: 200,
        });
        let mut cells = vec![BandCell::EMPTY; 4 * usize::from(ROWS)];
        cells[0] = BandCell { ch: 0x85, ink };
        cells[1] = BandCell { ch: b'x', ink };
        let band = Band::from_cells(4, cells);
        let mut g = Grid::new(5, 9, Paint::default());
        put_band(&mut g, &band, ColorDepth::TrueColor, false);
        assert_eq!(g.cell(0, BOWL_TOP).text, " ");
        assert_eq!(g.cell(1, BOWL_TOP).text, "x");
    }

    // 이것을 실패시키는 것: 칸이 없는 cluster(바탕 없는 결합 표지)를 제 칸에 두는 것(그 칸의 폭이 0이 되어 줄이
    // 한 칸 모자란다), 줄 끝을 넘는 2칸 글자를 두는 것(다음 줄 첫 칸에 쓰인다), 격자 밖 줄에 쓰는 것.
    #[test]
    fn a_cell_takes_only_clusters_that_fit() {
        let p = Paint::default();
        let mut g = Grid::new(4, 2, p);
        assert!(!g.set(0, 0, "\u{301}", 0, p, 4));
        assert_eq!(g.row_text(0), "    ");
        assert!(!g.set(3, 0, "\u{6f22}", 2, p, 4));
        assert_eq!(
            (g.row_text(0), g.row_text(1)),
            ("    ".into(), "    ".into())
        );
        assert!(g.set(2, 0, "\u{6f22}", 2, p, 4));
        assert_eq!(g.row_text(0), "  \u{6f22}");
        assert_eq!(g.cell(3, 0).text, "");
        assert!(!g.set(0, 2, "x", 1, p, 4));
        assert!(!g.set(3, 1, "x", 1, p, 3));
        // An end past the row is the row's end.
        assert!(!g.set(4, 1, "x", 1, p, 9));
        assert_eq!(g.put(0, 1, "\u{301}ab", p, 4), 2);
        assert_eq!(g.row_text(1), "ab  ");
    }

    // 이것을 실패시키는 것: 칸 쓰기가 제어 글자(ESC, BEL, 8비트 CSI)나 bidi 표지(U+202E)를 칸에 두는 것(호출하는 쪽이
    // 정제를 빠뜨려도 프레임에 들어가지 않아야 한다).
    #[test]
    fn a_cell_never_takes_a_removed_character() {
        let p = Paint::default();
        let mut g = Grid::new(6, 1, p);
        for bad in ["\u{1b}", "\u{7}", "\u{202e}", "\u{9b}", "a\u{1b}"] {
            assert!(!g.set(0, 0, bad, 1, p, 6), "{bad:?}");
        }
        assert_eq!(g.put(0, 0, "a\u{1b}[2Jb\u{202e}c", p, 6), 6);
        assert_eq!(g.row_text(0), "a[2Jbc");
    }
}
