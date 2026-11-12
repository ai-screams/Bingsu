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
    let width = columns
        .as_deref()
        .and_then(OsStr::to_str)
        .and_then(|v| v.parse().ok())
        .unwrap_or(80u16);
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
