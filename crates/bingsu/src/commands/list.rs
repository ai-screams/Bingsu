//! `bingsu list <what>`: the rows of `bingsu_core::listing`, one per line.
//! Nothing is read from the settings, nothing is written, and no command or
//! collector process starts.
//! `presets --preview` draws each preset once with the caller's folder
//! (`bingsu_core::preview`).
use super::{init::trusted_env::TrustedEnv, sys};
use bingsu_core::color::sgr::ColorDepth;
use bingsu_core::icons::IconSet;
use bingsu_core::listing::{What, rows};
use bingsu_core::preview::{PreviewInput, preview_line};
use bingsu_core::style::PRESETS;
use std::ffi::{OsStr, OsString};
use std::io::IsTerminal;
use std::os::unix::ffi::OsStrExt;
use std::process::ExitCode;

/// The longest preset name (`triangle`) and one space.
const NAME_COLUMN: u16 = 9;

const USAGE: &str = "usage: bingsu list <presets [--preview [--icons nerd|light|unicode|ascii]]|segments|flavors|roles|shorteners|icons>";

fn emit(text: &str) -> ExitCode {
    match sys::write_fd(1, text.as_bytes()) {
        sys::WriteOutcome::Done => ExitCode::SUCCESS,
        sys::WriteOutcome::Failed => ExitCode::from(1),
    }
}

fn lines(rows: &[String]) -> String {
    rows.iter().map(|r| format!("{r}\n")).collect()
}

/// Escapes only on a terminal, and not when `NO_COLOR` is set.
fn depth(colorterm: Option<&OsStr>, no_color: bool) -> Option<ColorDepth> {
    if no_color || !std::io::stdout().is_terminal() {
        return None;
    }
    let truecolor = colorterm.is_some_and(|v| matches!(v.as_bytes(), b"truecolor" | b"24bit"));
    Some(if truecolor {
        ColorDepth::TrueColor
    } else {
        ColorDepth::Ansi256
    })
}

fn preview(icons: IconSet) -> ExitCode {
    let Ok(cwd) = std::env::current_dir() else {
        eprintln!("bingsu: the current folder cannot be read");
        return ExitCode::from(super::ctx::EXIT_FAILED);
    };
    let home = TrustedEnv::capture().home;
    let (columns, colorterm, no_color) = TrustedEnv::terminal();
    // The rule `bingsu explain` follows: COLUMNS, else the terminal, else 80.
    // 이것을 실패시키는 것: COLUMNS만 읽는 것(셸은 COLUMNS를 넘기지 않아 터미널에서도 80), COLUMNS=0을 폭으로 받는 것.
    let (width, _) = super::out_width::stdout_width(None, columns.as_deref());
    // The name column is `NAME_COLUMN` cells, so the line still fits.
    let width = width.saturating_sub(NAME_COLUMN);
    let input = PreviewInput {
        pwd: cwd.as_os_str().as_bytes(),
        home: home.as_deref().map(OsStr::as_bytes),
        width,
        icons,
        depth: depth(colorterm.as_deref(), no_color),
    };
    let mut out = Vec::new();
    for p in PRESETS {
        let Ok(line) = preview_line(p.name, &input) else {
            eprintln!("bingsu: preset {} cannot be drawn", p.name);
            return ExitCode::from(super::ctx::EXIT_FAILED);
        };
        out.extend_from_slice(format!("{:<1$}", p.name, usize::from(NAME_COLUMN)).as_bytes());
        out.extend_from_slice(&line);
        out.push(b'\n');
    }
    emit(&String::from_utf8_lossy(&out))
}

pub fn run(args: &[OsString]) -> ExitCode {
    let words: Vec<Option<&str>> = args.iter().map(|a| a.to_str()).collect();
    match words.as_slice() {
        [Some("presets"), Some("--preview")] => preview(bingsu_core::default_theme::ICONS),
        [
            Some("presets"),
            Some("--preview"),
            Some("--icons"),
            Some(set),
        ] => match IconSet::parse(set) {
            Some(icons) => preview(icons),
            None => usage(),
        },
        [Some(w)] => match What::parse(w) {
            Some(what) => emit(&lines(&rows(what))),
            None => usage(),
        },
        _ => usage(),
    }
}

fn usage() -> ExitCode {
    eprintln!("{USAGE}");
    ExitCode::from(super::ctx::EXIT_USAGE)
}
