//! `bingsu setup`'s one-screen editor on the terminal: the full-screen
//! session, the key reader, the frame writer, the editor model and its
//! grid, and the preview loaded from the start's reading of the settings
//! (`setup_sources`). Also what the editor takes from this machine once at
//! the start to draw the preview the way the prompt would: the folder as
//! the shell shows it and the color mode with bingsu's words for why.
//!
//! One thread, no child, no file: the loop waits on the session only, and a
//! key's preview loads from memory. The session is dropped before the
//! caller writes, checks or publishes anything (the deadline's watchdog is
//! a thread and ends the process without putting the terminal back).
use super::frame_writer::{Flushed, FrameWriter};
use super::keys::KeyInput;
use super::setup_sources::Sources;
use super::tty::Tty;
use super::tty::session::{Event, Session};
use bingsu_core::color::osc11::{REPLY_MAX, find_reply, is_light, parse_osc11};
use bingsu_core::color::palette::{Knobs, Mode, PaletteInput, ResolvedPalette, resolve_palette};
use bingsu_core::color::sgr::ColorDepth;
use bingsu_core::config::report;
use bingsu_core::config::source::Catalog;
use bingsu_core::config::starter::{Choices, Icons as StarterIcons, Mode as StarterMode};
use bingsu_core::config::tree::Format;
use bingsu_core::diag::{Severity, render_human};
use bingsu_core::envelope::{colorfgbg_mode, display_mode};
use bingsu_core::opening::{Bowl, Inks, Opening};
use bingsu_core::preview::{PreviewLine, Request, Sample, lines};
use bingsu_core::setup_editor::layers::{Layers, builtin_narrow, composed_text};
use bingsu_core::setup_editor::model::{Effect, Given, Input, Model, Target};
use bingsu_core::setup_editor::rows::{MODES, Row};
use bingsu_core::setup_editor::screen::{
    Grid, MAX_COLS, View, bowl_shown, draw, existing_report, frame, put_band, too_small,
};
use bingsu_core::setup_editor::write::{candidate_toml, changes, new_file_text};
use std::ffi::OsStr;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// How long the start waits for the terminal's background color, and how
/// long it then drops what comes late (`tty::REPLY_TIMEOUT`,
/// `tty::LATE_REPLY_DRAIN`, as the line questions).
const REPLY_WAIT: Duration = Duration::from_millis(200);
const LATE_DRAIN: Duration = Duration::from_millis(50);
const QUERY: &[u8] = b"\x1b]11;?\x1b\\";

/// How the editor ended. The session is gone by then.
pub(crate) enum Ended {
    /// `q`, or Esc twice: nothing written.
    Quit,
    /// Ctrl-C.
    Cancelled,
    /// Enter on the save screen: write this text, made from these choices.
    Write { text: String, choices: Choices },
    /// Enter on an existing file's save screen: what to change in it, line
    /// by line (`screen::existing_report`), and whether anything is to
    /// change; nothing is written.
    Report { lines: Vec<String>, changes: bool },
    /// The terminal went away, took no output, or could not be taken:
    /// nothing written, and why.
    Lost(String),
    /// An existing file the settings do not apply as they are (another
    /// file, or the file itself, fails to load): no editor, since there is
    /// nothing to compare against; the reader's first problem, rendered and
    /// cleaned.
    NotLoaded(String),
}

/// What the editor draws with, decided before it starts.
pub(crate) struct Start<'a> {
    pub sources: &'a Sources,
    /// The settings file as the loader names it.
    pub path: &'a [u8],
    pub folder: &'a [u8],
    pub home: &'a [u8],
    pub host: Option<&'a [u8]>,
    pub colorfgbg: Option<&'a OsStr>,
    pub depth: ColorDepth,
    /// `NO_COLOR`.
    pub mono: bool,
    /// `--no-motion`: the opening's end frame from the start.
    pub still: bool,
    /// The folder is not one only the user can change: nothing is saved.
    pub read_only: bool,
    pub given: Given,
    /// A new file, or the existing one (`Sources::existing`).
    pub target: Target,
}

/// The preview of one state at one width.
struct Preview {
    /// What the settings file's bytes came from (the new file's text, or
    /// the changes to an existing one).
    text: String,
    /// Why the preview does not follow the picks.
    stale: Option<&'static str>,
    cols: u16,
    lines: Vec<PreviewLine>,
    palette: ResolvedPalette,
    mode: Mode,
    note: String,
    narrow: bool,
}

impl Preview {
    /// The settings with the model's file at a window `cols` wide, loaded
    /// from the start's reading (no file is opened). Settings that do not
    /// compile (another file has an error) show no preview, on the
    /// default colors of the mode. `None`: those colors could not be made.
    ///
    /// The color mode is what those settings compose to, as the prompt
    /// draws them: a later file (`config.local`) can cover the pick, and a
    /// file the preview does not follow keeps its own.
    fn new(s: &Start<'_>, m: &Model, cols: u16) -> Option<Self> {
        let (text, bytes, stale) = file_bytes(s, m);
        // The mode given here is not used by the report.
        let r = report::from_loaded(s.sources.load(&bytes), Mode::Dark);
        let word = composed_text(&r.files, &r.order, &["colors", "mode"]).unwrap_or("auto");
        let (mode, note) = preview_mode(word, s.colorfgbg);
        let Some(c) = &r.snapshot else {
            let palette = resolve_palette(&PaletteInput {
                mode,
                knobs: Knobs::default(),
                overrides: &[],
                roles: &[],
            })
            .ok()?;
            return Some(Self {
                text,
                stale,
                cols,
                lines: Vec::new(),
                palette,
                mode,
                note,
                narrow: false,
            });
        };
        // The last column stays empty: a config that uses it is laid out
        // one column narrower.
        let width = cols.min(MAX_COLS) - u16::from(c.use_last_column && cols > 0);
        let lines = lines(
            c,
            &Request {
                mode,
                icons: c.icons,
                depth: s.depth,
                width,
                sample: Sample {
                    pwd: s.folder,
                    home: Some(s.home),
                    host: s.host,
                },
            },
        );
        Some(Self {
            text,
            stale,
            cols,
            lines,
            palette: match mode {
                Mode::Dark => c.palette.clone(),
                Mode::Light => c.light_palette.clone(),
            },
            mode,
            note,
            narrow: builtin_narrow(&r.files, &r.order, &c.widths, width),
        })
    }
}

/// The settings file's bytes for the model's state, what they came from
/// (the preview is made again only when that changes), and why they do not
/// follow the picks. A new file: its text. An existing TOML file: the
/// changes made in place (`config::edit`); one whose shape that does not
/// edit, and a JSON or YAML file, stay as they are.
fn file_bytes(s: &Start<'_>, m: &Model) -> (String, Vec<u8>, Option<&'static str>) {
    let key = file_key(s, m);
    match s.target {
        Target::New => {
            let bytes = key.clone().into_bytes();
            (key, bytes, None)
        }
        Target::Existing(format) => {
            let original = s.sources.original();
            match format {
                Format::Toml => match candidate_toml(m, original) {
                    Ok(bytes) => (key, bytes, None),
                    Err(_) => (key, original.to_vec(), Some(NOT_EDITED)),
                },
                _ => (key, original.to_vec(), Some(NOT_UPDATED)),
            }
        }
    }
}

/// What the settings file's bytes come from, cheap to make for every
/// frame: the new file's text, or the changes to the existing one.
fn file_key(s: &Start<'_>, m: &Model) -> String {
    match s.target {
        Target::New => new_file_text(m).unwrap_or_default(),
        Target::Existing(_) => format!("{:?}", changes(m)),
    }
}

// Short enough for the preview's label at 80 columns.
const NOT_UPDATED: &str = "not updated for this format";
const NOT_EDITED: &str = "not updated for this layout";

/// The shaved-ice opening in rows 1-7 of the main screen (`bowl_shown`),
/// as `bingsu_core::opening` describes: the bowl is made the first time it
/// is shown, a frame goes in whenever the screen is drawn, and the next one
/// is due one `FRAME` after the last one drawn or missed. With no bowl rows
/// on the screen, or once the end frame was drawn, no frame is due.
struct Band {
    /// When the editor began: the opening's clock counts from here.
    origin: Instant,
    opening: Opening,
    bowl: Option<Bowl>,
    /// The inks, and the mode they were made for (`None`: none yet).
    inks: Inks,
    inks_mode: Option<Mode>,
    /// When a frame was last drawn or missed, into the opening.
    last: Option<Duration>,
    /// The last screen drawn had the bowl's rows.
    shown: bool,
}

impl Band {
    /// `still`: `--no-motion` or a set `NO_COLOR` (the end frame at once).
    fn new(origin: Instant, still: bool) -> Self {
        Self {
            origin,
            opening: if still {
                Opening::still()
            } else {
                Opening::new(Duration::ZERO)
            },
            bowl: None,
            inks: Inks::of(Mode::Dark),
            inks_mode: None,
            last: None,
            shown: false,
        }
    }

    fn since(&self, now: Instant) -> Duration {
        now.saturating_duration_since(self.origin)
    }

    /// When the next frame of the band is due; `None`: no timer (the bowl
    /// is not on the screen, the end frame was drawn, or no frame was
    /// drawn yet: the first comes with the first screen).
    /// 이것을 실패시키는 것: 그릇이 화면에 없을 때도 기한을 두는 것(작은 창에서 30번씩 깨어남;
    /// a_band_off_the_screen_asks_for_no_frame).
    fn next(&self) -> Option<Instant> {
        if !self.shown {
            return None;
        }
        let at = self.opening.next(self.last?)?;
        self.origin.checked_add(at)
    }

    /// A frame is built at `now`: the time into the opening it shows, and
    /// the frame counted as drawn; `None` when it has no bowl rows
    /// (`shown` false).
    fn take(&mut self, shown: bool, now: Instant) -> Option<Duration> {
        self.shown = shown;
        if !shown {
            return None;
        }
        let t = self.since(now);
        let at = self.opening.at(t);
        self.opening.drawn(t);
        self.last = Some(t);
        Some(at)
    }

    /// A frame is built at `now`: when `shown` (the frame has the bowl's
    /// rows), the band of `now` goes into `grid` in `mode`'s inks.
    fn draw(
        &mut self,
        grid: &mut Grid,
        shown: bool,
        mode: Mode,
        how: (ColorDepth, bool),
        now: Instant,
    ) {
        let Some(at) = self.take(shown, now) else {
            return;
        };
        let bowl = self.bowl.get_or_insert_with(Bowl::new);
        // New inks when the mode changed: the colors row repaints the bowl,
        // it does not move it.
        // 이것을 실패시키는 것: 모드가 바뀌어도 그릇의 잉크를 다시 만들지 않는 것(the_bowl_takes_the_colors_of_the_mode).
        if self.inks_mode != Some(mode) {
            self.inks = Inks::of(mode);
            self.inks_mode = Some(mode);
        }
        let band = bowl.draw(at, grid.cols().saturating_sub(1), &self.inks);
        put_band(grid, &band, how.0, how.1);
    }

    /// A frame came due at `now` while the writer still held the last one.
    /// 이것을 실패시키는 것: 놓친 시각을 기록하지 않는 것(지난 기한이 남아 기다림이 곧바로 끝나기를 되풀이함;
    /// a_missed_frame_moves_the_next_one_on).
    fn missed(&mut self, now: Instant) {
        self.opening.missed();
        self.last = Some(self.since(now));
    }

    /// A key, or a resume after a stop: the end frame from now on.
    fn skip(&mut self) {
        self.opening.skip();
    }
}

/// Asks the terminal for its background once, right after the session
/// began: `REPLY_WAIT` for the answer, then `LATE_DRAIN` of dropping what
/// comes. What else comes meanwhile is dropped too. `Err`: the session
/// must end (a signal, a hang-up).
fn ask_background(session: &mut Session<'_>) -> Result<Option<Mode>, Ended> {
    let until = Instant::now() + REPLY_WAIT;
    let mut sent = 0;
    while sent < QUERY.len() {
        match session.write_some(&QUERY[sent..]) {
            Ok(0) if Instant::now() >= until => return Ok(None),
            Ok(n) => sent += n,
            Err(_) => return Err(Ended::Lost(String::from("the terminal went away"))),
        }
        if sent < QUERY.len() {
            match session.wait(true, Some(until)) {
                Event::Signal(_) | Event::Hangup => return Err(gone()),
                Event::Timeout => return Ok(None),
                _ => {}
            }
        }
    }
    let mut got: Vec<u8> = Vec::new();
    let mut until = until;
    let mut answer = None;
    loop {
        match session.wait(false, Some(until)) {
            // Ctrl-C while the terminal is asked cancels, as on the line
            // questions; a reply never holds the byte.
            Event::Input(b) if b.contains(&0x03) => return Err(Ended::Cancelled),
            Event::Input(b) if answer.is_none() && got.len() < REPLY_MAX * 4 => {
                got.extend_from_slice(b);
                if let Some(reply) = find_reply(&got) {
                    answer = Some(
                        parse_osc11(reply)
                            .map(|c| if is_light(c) { Mode::Light } else { Mode::Dark }),
                    );
                    break;
                }
            }
            Event::Signal(_) | Event::Hangup => return Err(gone()),
            Event::Timeout if answer.is_none() && until < Instant::now() + LATE_DRAIN => {
                // Silent: what comes for a moment more is a late answer.
                until = Instant::now() + LATE_DRAIN;
                answer = Some(None);
            }
            Event::Timeout => break,
            _ => {}
        }
    }
    Ok(answer.flatten())
}

/// The first error of a load (else its first diagnostic), as `config
/// check` shows it; its texts are cleaned (`diag::render_human`).
fn first_problem(r: &report::ConfigReport) -> String {
    let d = r
        .diagnostics
        .iter()
        .find(|d| d.severity() == Severity::Error)
        .or(r.diagnostics.first());
    d.map_or_else(
        || String::from("the settings did not load"),
        |d| render_human(d, &Catalog(&r.files)),
    )
}

fn gone() -> Ended {
    Ended::Lost(String::from("the terminal went away"))
}

/// The editor, from its first frame to the end. Nothing is written here.
pub(crate) fn edit(tty: &Tty, s: &Start<'_>) -> Ended {
    let start = s.sources.load(s.sources.original());
    let r = report::from_loaded(start, Mode::Dark);
    let target = s.sources.target(&r.files);
    // An existing file's values are known only from a load that applies
    // it: a failed one keeps no order, and the file would seem to set
    // nothing.
    // 이것을 실패시키는 것: 불러오지 못한 설정에서 편집판을 여는 것(이미 있는 값을 "not set now"로 보임;
    // test_settings_that_do_not_load_show_nothing_to_compare).
    if matches!(s.target, Target::Existing(_)) && !target.is_some_and(|t| r.order.contains(&t)) {
        return Ended::NotLoaded(first_problem(&r));
    }
    let layers = match target {
        Some(t) => Layers::from_sources(&r.files, &r.order, t),
        None => Layers::default(),
    };
    let mut m = Model::new(layers, s.target, s.given);
    m.set_read_only(s.read_only);
    let mut session = match tty.full_screen() {
        Ok(session) => session,
        Err(e) => {
            return Ended::Lost(format!(
                "the terminal could not be used for the editor ({e}); run bingsu setup --plain"
            ));
        }
    };
    let terminal = match ask_background(&mut session) {
        Ok(t) => t,
        Err(end) => return end,
    };
    let origin = Instant::now();
    let mut keys = KeyInput::new(origin);
    let mut writer = FrameWriter::new();
    let mut read: u64 = 0;
    let size = session.size();
    // Raw TIOCGWINSZ values: `draw` bounds them before it makes the grid,
    // and the preview is laid out at most `MAX_COLS` wide.
    let (mut cols, mut rows) = (size.cols, size.rows);
    let mut shown: Option<Grid> = None;
    let mut band = Band::new(origin, s.still || s.mono);
    let Some(mut preview) = Preview::new(s, &m, cols) else {
        return Ended::Lost(String::from("the default colors could not be made"));
    };
    writer.request();
    loop {
        m.set_too_small(too_small(cols, rows));
        if writer.wants_frame() {
            let text = file_key(s, &m);
            if text != preview.text || cols != preview.cols {
                match Preview::new(s, &m, cols) {
                    Some(p) => preview = p,
                    None => {
                        return Ended::Lost(String::from("the default colors could not be made"));
                    }
                }
            }
            let mut grid = draw(
                &m,
                &View {
                    cols,
                    rows,
                    path: s.path,
                    lines: &preview.lines,
                    palette: &preview.palette,
                    mode: preview.mode,
                    depth: s.depth,
                    mode_note: &preview.note,
                    terminal,
                    narrow: preview.narrow,
                    mono: s.mono,
                    stale: preview.stale,
                },
            );
            band.draw(
                &mut grid,
                bowl_shown(&m, cols, rows),
                preview.mode,
                (s.depth, s.mono),
                Instant::now(),
            );
            let mut bytes = Vec::new();
            frame(shown.as_ref(), &grid, &mut bytes);
            if writer.begin(&bytes, Instant::now()).is_err() {
                return Ended::Lost(String::from("a frame was too large"));
            }
            shown = Some(grid);
        }
        match writer.flush(&mut session, Instant::now()) {
            Flushed::Gone(e) => {
                return Ended::Lost(format!("the terminal went away ({e})"));
            }
            // Decided only on a timeout, which never comes while the session
            // is in the background: after a stop (`suspend` returns once the
            // process goes on, before `Resumed`) the frame is pending with
            // no progress, and `Resumed` drops it first.
            Flushed::Done | Flushed::Pending | Flushed::Stalled => {}
        }
        let until = [keys.deadline(), writer.deadline(), band.next()]
            .into_iter()
            .flatten()
            .min();
        let pressed = match session.wait(writer.wants_write(), until) {
            Event::Input(bytes) => {
                read += 1;
                keys.feed(bytes, Instant::now())
            }
            Event::Writable => continue,
            Event::Resized(size) => {
                (cols, rows) = (size.cols, size.rows);
                writer.request();
                continue;
            }
            Event::Resumed(size) => {
                (cols, rows) = (size.cols, size.rows);
                keys.reset();
                writer.discard();
                shown = None;
                // A stop in the middle of the opening comes back to its
                // end frame.
                // 이것을 실패시키는 것: 재개 뒤에도 여는 그림을 이어 가는 것(the_opening_ends_after_a_stop).
                band.skip();
                continue;
            }
            // A signal: dropping the session puts the terminal back and
            // ends the process with it, so the caller never goes on.
            Event::Signal(_) | Event::Hangup => return gone(),
            Event::Timeout => {
                let now = Instant::now();
                if writer.stalled(now) {
                    return Ended::Lost(String::from("the terminal took no output for 2 s"));
                }
                if band.next().is_some_and(|due| due <= now) {
                    if writer.idle() {
                        writer.request();
                    } else {
                        band.missed(now);
                    }
                }
                read += 1;
                keys.tick(now)
            }
        };
        if !pressed.is_empty() {
            band.skip();
        }
        for &key in pressed.as_slice() {
            match m.handle(Input { key, read }) {
                Effect::None => {}
                Effect::Draw => writer.request(),
                Effect::Redraw => {
                    shown = None;
                    writer.request();
                }
                Effect::Quit => return Ended::Quit,
                Effect::Cancel => return Ended::Cancelled,
                Effect::Suspend => session.suspend(),
                Effect::Write => {
                    let icons = StarterIcons::ALL[usize::from(m.chosen(Row::Icons))];
                    let mode = StarterMode::parse(MODES[usize::from(m.chosen(Row::Colors))])
                        .unwrap_or(StarterMode::Auto);
                    return Ended::Write {
                        text: new_file_text(&m).unwrap_or_default(),
                        choices: Choices { icons, mode },
                    };
                }
                Effect::Report => {
                    return Ended::Report {
                        lines: existing_report(&m, s.path),
                        changes: !changes(&m).is_empty(),
                    };
                }
            }
        }
    }
}

/// The folder the preview shows: `$PWD`, the folder as the shell shows it
/// (links kept), when it is absolute and is the folder `cwd` is (same
/// device and inode); else `cwd`.
pub(crate) fn sample_folder(pwd: Option<&OsStr>, cwd: &Path) -> PathBuf {
    let same = |p: &Path| {
        let (Ok(a), Ok(b)) = (std::fs::metadata(p), std::fs::metadata(cwd)) else {
            return false;
        };
        (a.dev(), a.ino()) == (b.dev(), b.ino())
    };
    match pwd.map(Path::new) {
        Some(p) if p.is_absolute() && same(p) => p.to_path_buf(),
        _ => cwd.to_path_buf(),
    }
}

/// The mode the preview draws in for the colors row's `word` (`auto`,
/// `dark` or `light`), and why in bingsu's words. `auto` reads
/// `COLORFGBG` as the prompt does (`envelope::display_mode`).
pub(crate) fn preview_mode(word: &str, colorfgbg: Option<&OsStr>) -> (Mode, String) {
    let name = |m: Mode| match m {
        Mode::Dark => "dark",
        Mode::Light => "light",
    };
    match word {
        "dark" => (Mode::Dark, String::from("dark")),
        "light" => (Mode::Light, String::from("light")),
        _ => {
            let seen = colorfgbg.and_then(|v| colorfgbg_mode(v.as_encoded_bytes()));
            let mode = display_mode(seen);
            let why = if seen.is_some() {
                "COLORFGBG"
            } else {
                "no COLORFGBG"
            };
            (mode, format!("auto: {} ({why})", name(mode)))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bingsu_core::opening::{FRAME, LENGTH};

    // 이것을 실패시키는 것: 그릇이 화면에 없을 때도 기한을 두는 것(작은 창이나 다른 화면에서 1초에 30번 깨어남), 첫
    // 화면 전에 기한을 두는 것.
    #[test]
    fn a_band_off_the_screen_asks_for_no_frame() {
        let origin = Instant::now();
        let mut b = Band::new(origin, false);
        assert_eq!(b.next(), None, "before the first screen");
        assert_eq!(b.take(false, origin), None);
        assert_eq!(b.next(), None, "no bowl rows");
        let at = origin + Duration::from_millis(100);
        assert_eq!(b.take(true, at), Some(Duration::from_millis(100)));
        assert_eq!(b.next(), Some(at + FRAME));
        assert_eq!(b.take(false, at + FRAME), None);
        assert_eq!(b.next(), None, "the rows went");
    }

    // 이것을 실패시키는 것: 놓친 시각을 기록하지 않는 것(지난 기한이 남아 기다림이 곧바로 끝나기를 되풀이함), 열 번
    // 놓쳐도 끝 프레임으로 가지 않는 것.
    #[test]
    fn a_missed_frame_moves_the_next_one_on() {
        let origin = Instant::now();
        let mut b = Band::new(origin, false);
        b.take(true, origin);
        let mut now = origin;
        for _ in 0..9 {
            now += FRAME;
            b.missed(now);
            assert_eq!(b.next(), Some(now + FRAME));
        }
        now += FRAME;
        b.missed(now);
        // The tenth: the end frame comes next, and after it no timer.
        assert_eq!(b.take(true, now + FRAME), Some(LENGTH));
        assert_eq!(b.next(), None);
    }

    // 이것을 실패시키는 것: --no-motion이나 NO_COLOR에서 움직이는 것, 키나 재개 뒤에도 이어 가는 것, 끝 프레임 뒤에도
    // 기한을 두는 것(끝난 뒤 30 fps로 깨어남).
    #[test]
    fn a_still_or_skipped_opening_draws_its_end_frame_once() {
        let origin = Instant::now();
        let mut still = Band::new(origin, true);
        assert_eq!(still.take(true, origin), Some(LENGTH));
        assert_eq!(still.next(), None);
        let mut b = Band::new(origin, false);
        let at = origin + Duration::from_millis(500);
        assert_eq!(b.take(true, at), Some(Duration::from_millis(500)));
        assert!(b.next().is_some());
        b.skip();
        assert_eq!(b.take(true, at + FRAME), Some(LENGTH));
        assert_eq!(b.next(), None);
        // Its own end: a frame at `LENGTH` or later is the last.
        let mut run = Band::new(origin, false);
        assert_eq!(run.take(true, origin + LENGTH), Some(LENGTH));
        assert_eq!(run.next(), None);
    }

    // 이것을 실패시키는 것: 링크로 들어온 같은 폴더의 $PWD 대신 물리 경로를 보이는 것, 다른 폴더를 가리키는 $PWD나
    // 상대 경로, 없는 경로의 $PWD를 믿는 것.
    #[test]
    fn the_shell_folder_is_shown_when_it_is_this_folder() {
        let d = std::env::temp_dir().join(format!("bingsu-sf-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        let real = d.join("real");
        let other = d.join("other");
        std::fs::create_dir_all(&real).unwrap();
        std::fs::create_dir_all(&other).unwrap();
        let link = d.join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let cwd = std::fs::canonicalize(&real).unwrap();
        let pick = |p: &Path| sample_folder(Some(p.as_os_str()), &cwd);
        assert_eq!(pick(&link), link);
        assert_eq!(pick(&other), cwd);
        // Relative, even when it leads here from the process's folder.
        let here = std::env::current_dir().unwrap();
        let mut relative = PathBuf::new();
        for _ in here.components().skip(1) {
            relative.push("..");
        }
        relative.push(link.strip_prefix("/").unwrap());
        assert!(std::fs::metadata(&relative).is_ok());
        assert_eq!(pick(&relative), cwd);
        assert_eq!(pick(&d.join("gone")), cwd);
        assert_eq!(sample_folder(None, &cwd), cwd);
        let _ = std::fs::remove_dir_all(&d);
    }

    // 이것을 실패시키는 것: 한 번 읽은 바이트의 두 Enter(`\r\r`, LNM 터미널의 `\r\n`)를 저장 확인으로 받는 것.
    // 읽기 경계를 시험이 정한다: 키 해석기의 `feed` 한 번이 한 읽기다.
    #[test]
    fn two_enters_of_one_read_do_not_confirm_the_save() {
        use bingsu_core::setup_editor::layers::Layers;
        use bingsu_core::setup_editor::model::{Effect, Given, Input, Model, Screen, Target};
        let t = Instant::now();
        let mut keys = KeyInput::new(t);
        let mut m = Model::new(Layers::default(), Target::New, Given::default());
        let effects = |m: &mut Model, bytes: &[u8], read: u64, keys: &mut KeyInput| {
            keys.feed(bytes, t)
                .as_slice()
                .iter()
                .map(|&key| m.handle(Input { key, read }))
                .collect::<Vec<_>>()
        };
        for one in [&b"\r\r"[..], b"\r\n"] {
            let mut s = m.clone();
            let got = effects(&mut s, one, 1, &mut keys);
            assert!(!got.contains(&Effect::Write), "{one:?}: {got:?}");
            assert!(matches!(s.screen(), Screen::Save { .. }));
            assert_eq!(effects(&mut s, b"\r", 2, &mut keys), [Effect::Write]);
        }
        let got = effects(&mut m, b"\r", 1, &mut keys);
        assert!(!got.contains(&Effect::Write));
    }

    // 이것을 실패시키는 것: auto에서 COLORFGBG를 보지 않는 것, 읽을 수 없는 값을 근거로 적는 것, 정한 모드에 COLORFGBG를
    // 적용하는 것.
    #[test]
    fn the_mode_and_its_reason() {
        fn fgbg(s: &str) -> Option<&OsStr> {
            Some(OsStr::new(s))
        }
        assert_eq!(
            preview_mode("auto", None),
            (Mode::Dark, String::from("auto: dark (no COLORFGBG)"))
        );
        assert_eq!(
            preview_mode("auto", fgbg("0;15")),
            (Mode::Light, String::from("auto: light (COLORFGBG)"))
        );
        assert_eq!(
            preview_mode("auto", fgbg("x")),
            (Mode::Dark, String::from("auto: dark (no COLORFGBG)"))
        );
        assert_eq!(
            preview_mode("dark", fgbg("0;15")),
            (Mode::Dark, String::from("dark"))
        );
        assert_eq!(
            preview_mode("light", None),
            (Mode::Light, String::from("light"))
        );
    }
}
