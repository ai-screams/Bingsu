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
use super::frame_writer::{Flushed, FrameWriter, Sink};
use super::keys::KeyInput;
use super::setup_sources::Sources;
use super::tty::Tty;
use super::tty::session::{Event, Session};
use bingsu_core::color::osc11::{REPLY_MAX, find_reply, is_light, parse_osc11};
use bingsu_core::color::palette::{Knobs, Mode, PaletteInput, ResolvedPalette, resolve_palette};
use bingsu_core::color::sgr::ColorDepth;
use bingsu_core::config::report;
use bingsu_core::config::starter::{Choices, Icons as StarterIcons, Mode as StarterMode};
use bingsu_core::envelope::{colorfgbg_mode, display_mode};
use bingsu_core::preview::{PreviewLine, Request, Sample, lines};
use bingsu_core::setup_editor::layers::{Layers, builtin_narrow};
use bingsu_core::setup_editor::model::{Effect, Given, Input, Model, Target};
use bingsu_core::setup_editor::rows::{MODES, Row};
use bingsu_core::setup_editor::screen::{Grid, MAX_COLS, View, draw, frame, too_small};
use bingsu_core::setup_editor::write::new_file_text;
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
    /// The terminal went away, took no output, or could not be taken:
    /// nothing written, and why.
    Lost(String),
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
    /// The folder is not one only the user can change: nothing is saved.
    pub read_only: bool,
    pub given: Given,
}

/// The frames go to the session.
struct Term<'s, 't>(&'s mut Session<'t>);

impl Sink for Term<'_, '_> {
    fn write_some(&mut self, rest: &[u8]) -> std::io::Result<usize> {
        self.0.write_some(rest)
    }
    fn mark_synced(&mut self, on: bool) {
        self.0.mark_synced(on);
    }
}

/// The preview of one state at one width.
struct Preview {
    text: String,
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
    fn new(s: &Start<'_>, m: &Model, cols: u16) -> Option<Self> {
        let text = new_file_text(m).unwrap_or_default();
        let word = MODES[usize::from(m.chosen(Row::Colors))];
        let (mode, note) = preview_mode(word, s.colorfgbg);
        let r = report::from_loaded(s.sources.load(text.as_bytes()), mode);
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

fn gone() -> Ended {
    Ended::Lost(String::from("the terminal went away"))
}

/// The editor, from its first frame to the end. Nothing is written here.
pub(crate) fn edit(tty: &Tty, s: &Start<'_>) -> Ended {
    let start = s.sources.load(b"");
    let r = report::from_loaded(start, Mode::Dark);
    let layers = match s.sources.target(&r.files) {
        Some(t) => Layers::from_sources(&r.files, &r.order, t),
        None => Layers::default(),
    };
    let mut m = Model::new(layers, Target::New, s.given);
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
    let Some(mut preview) = Preview::new(s, &m, cols) else {
        return Ended::Lost(String::from("the default colors could not be made"));
    };
    writer.request();
    loop {
        m.set_too_small(too_small(cols, rows));
        if writer.wants_frame() {
            let text = new_file_text(&m).unwrap_or_default();
            if text != preview.text || cols != preview.cols {
                match Preview::new(s, &m, cols) {
                    Some(p) => preview = p,
                    None => {
                        return Ended::Lost(String::from("the default colors could not be made"));
                    }
                }
            }
            let grid = draw(
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
                },
            );
            let mut bytes = Vec::new();
            frame(shown.as_ref(), &grid, &mut bytes);
            if writer.begin(&bytes, Instant::now()).is_err() {
                return Ended::Lost(String::from("a frame was too large"));
            }
            shown = Some(grid);
        }
        match writer.flush(&mut Term(&mut session), Instant::now()) {
            Flushed::Gone(_) => return gone(),
            Flushed::Stalled => {
                return Ended::Lost(String::from("the terminal took no output for 2 s"));
            }
            Flushed::Done | Flushed::Pending => {}
        }
        let until = match (keys.deadline(), writer.deadline()) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        };
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
                read += 1;
                keys.tick(now)
            }
        };
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
                // An existing file has no save here.
                Effect::Report => {}
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
