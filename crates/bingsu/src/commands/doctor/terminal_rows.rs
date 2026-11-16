//! The two terminal rows, `terminal-width` and `terminal-background`: each asks
//! the terminal (the `run_*` functions) and hands the answer to a pure `judge_*`
//! function.
use super::*;

// ---- terminal -------------------------------------------------------------------

/// Exit code of a run ended by Ctrl-C (128 + SIGINT).
pub(super) const EXIT_CANCELLED: u8 = 130;

fn terminal_settings(c: &Ctx) -> Option<TerminalSettings> {
    *c.terminal.settings.get_or_init(|| {
        let i = inspect_config(&c.user, &c.env).ok()?;
        let snap = i.report.snapshot?;
        // An explicit `colors.mode` makes both palettes the same one.
        Some(TerminalSettings {
            profile: snap.profile,
            auto: snap.palette != snap.light_palette,
        })
    })
}

/// The row for a run that asks no terminal: a Ctrl-C ended an earlier
/// question, or standard output is not a terminal and `--terminal` is not
/// given.
fn no_question(c: &Ctx) -> Option<Finding> {
    let skipped = |text: &str| finding(Status::Skipped, text, None);
    if c.terminal.cancelled.get() {
        return Some(skipped("stopped"));
    }
    (!c.terminal.measure).then(|| {
        skipped(
            "standard output is not a terminal; `--terminal` asks the controlling terminal anyway",
        )
    })
}

/// Runs `measure` on the controlling terminal in raw mode, or gives the row
/// that says why there is none. The terminal is back in its mode when this
/// returns; each row asks on a guard of its own.
pub(super) fn with_terminal<T>(
    c: &Ctx,
    measure: impl FnOnce(&mut dyn Terminal) -> T,
) -> Result<T, Finding> {
    if let Some(f) = no_question(c) {
        return Err(f);
    }
    let skipped = |text: &str| finding(Status::Skipped, text, None);
    let Some(tty) = (c.terminal.open)() else {
        return Err(skipped(
            "there is no terminal to ask (none is attached, or this is not its foreground job)",
        ));
    };
    let Ok(mut guard) = tty.raw_terminal() else {
        return Err(finding(
            Status::Unknown,
            "the terminal could not be put in the mode the questions need",
            None,
        ));
    };
    Ok(measure(&mut *guard))
}

fn why_text(why: Why) -> &'static str {
    match why {
        Why::Silent => "the terminal did not answer in time",
        Why::Garbled => "the terminal answered with something that is not a cursor position",
        Why::Moved => "the cursor left the line while measuring",
    }
}

fn mismatch_text(m: &Mismatch) -> String {
    match *m {
        Mismatch::AmbiguousWidth {
            measured,
            configured,
        } => format!(
            "ambiguous-width characters take {measured} cell(s), the settings say {configured}"
        ),
        Mismatch::AmbiguousMixed => {
            "ambiguous-width characters do not all take the same number of cells".into()
        }
        Mismatch::EmojiWidth {
            measured,
            configured,
        } => format!("emoji take {measured} cell(s), the settings say {configured}"),
        Mismatch::EmojiCells { cells, expected } => {
            format!("a plain emoji takes {cells} cell(s), bingsu counts {expected}")
        }
        Mismatch::Vs16Differs { plain, vs16 } => {
            format!("an emoji made by U+FE0F takes {vs16} cell(s), a plain one {plain}")
        }
        Mismatch::ZwjCells { cells, expected } => {
            format!("a joined emoji takes {cells} cell(s), bingsu counts {expected}")
        }
        Mismatch::FlagCells { cells, expected } => {
            format!("a flag takes {cells} cell(s), bingsu counts {expected}")
        }
        Mismatch::CombiningCells { cells } => {
            format!("a letter with a combining mark takes {cells} cell(s), bingsu counts 1")
        }
        Mismatch::NerdCells { cells } => {
            format!("an icon takes {cells} cell(s), bingsu counts 1")
        }
    }
}

pub(super) fn judge_width(outcome: &WidthOutcome, profile: WidthProfile, tmux: bool) -> Finding {
    let cells = match outcome {
        WidthOutcome::Measured(cells) => cells,
        WidthOutcome::TooNarrow(c) => {
            return finding(
                Status::Skipped,
                format!(
                    "the terminal is {c} columns wide; the measurement needs {} or more",
                    width::MIN_COLUMNS
                ),
                None,
            );
        }
        WidthOutcome::NoAnswer(why) => return finding(Status::Unknown, why_text(*why), None),
        WidthOutcome::Cancelled => return finding(Status::Skipped, "stopped", None),
        WidthOutcome::Failed => {
            return finding(
                Status::Unknown,
                "the terminal could not be written to",
                None,
            );
        }
    };
    let recommended = width::recommended(cells);
    let details = Some(Details::Width {
        cells: *cells,
        recommended,
        inside_tmux: tmux,
    });
    let via = if tmux {
        " (inside tmux, which answers for its own pane)"
    } else {
        ""
    };
    let mut f = if !width::reliable(cells) {
        finding(
            Status::Unknown,
            format!(
                "the control characters moved the cursor by {} and {} cell(s), not 1 and 2, so the measurement is not trusted{via}",
                cells[0], cells[1]
            ),
            None,
        )
    } else {
        let bad = width::mismatches(cells, profile);
        if bad.is_empty() {
            finding(
                Status::Ok,
                format!(
                    "{} probe characters moved the cursor as the settings say (ambiguous {}, emoji {}){via}",
                    PROBES.len(),
                    profile.ambiguous(),
                    profile.emoji()
                ),
                None,
            )
        } else {
            let list: Vec<String> = bad.iter().map(mismatch_text).collect();
            let set = match (recommended.ambiguous, recommended.emoji) {
                (Some(a), Some(e)) => {
                    format!("; this terminal fits `width.ambiguous = {a}` and `width.emoji = {e}`")
                }
                (Some(a), None) => format!("; this terminal fits `width.ambiguous = {a}`"),
                (None, Some(e)) => format!("; this terminal fits `width.emoji = {e}`"),
                (None, None) => String::new(),
            };
            finding(
                Status::Warn,
                format!("{}{set}{via}", list.join("; ")),
                Some(codes::TERMINAL_WIDTH_DIFFERS),
            )
        }
    };
    f.details = details;
    f
}

pub(super) fn mode_word(m: Mode) -> &'static str {
    match m {
        Mode::Dark => "dark",
        Mode::Light => "light",
    }
}

pub(super) fn judge_background(
    outcome: &BackgroundOutcome,
    prompt: Mode,
    hint_set: bool,
) -> Finding {
    let terminal = match outcome {
        BackgroundOutcome::Dark => Mode::Dark,
        BackgroundOutcome::Light => Mode::Light,
        BackgroundOutcome::NoAnswer(why) => {
            return finding(Status::Unknown, why_text(*why), None);
        }
        BackgroundOutcome::Cancelled => return finding(Status::Skipped, "stopped", None),
        BackgroundOutcome::Failed => {
            return finding(
                Status::Unknown,
                "the terminal could not be written to",
                None,
            );
        }
    };
    let hint = if hint_set {
        "from COLORFGBG"
    } else {
        "COLORFGBG is not set"
    };
    let mut f = if terminal == prompt {
        finding(
            Status::Ok,
            format!(
                "the terminal is {} and the prompt draws for {} ({hint})",
                mode_word(terminal),
                mode_word(prompt)
            ),
            None,
        )
    } else {
        finding(
            Status::Warn,
            format!(
                "the terminal is {} but the prompt draws for {} ({hint})",
                mode_word(terminal),
                mode_word(prompt)
            ),
            Some(codes::TERMINAL_BACKGROUND_DIFFERS),
        )
    };
    f.details = Some(Details::Background { terminal, prompt });
    f
}

pub(super) fn run_terminal_width(c: &Ctx) -> Finding {
    if let Some(f) = no_question(c) {
        return f;
    }
    let Some(settings) = terminal_settings(c) else {
        return finding(
            Status::Unknown,
            "the settings could not be read, so there is nothing to compare with",
            None,
        );
    };
    let outcome = match with_terminal(c, |t| terminal::measure_widths(t)) {
        Ok(o) => o,
        Err(f) => return f,
    };
    if outcome == WidthOutcome::Cancelled {
        c.terminal.cancelled.set(true);
    }
    judge_width(&outcome, settings.profile, c.terminal.tmux)
}

/// The brightness hint the prompt gets: what the shell's last prompt call
/// carried when it handed its evidence (a variable that was never exported
/// is not in the environment, but the hook passes it), else the environment's.
pub(super) fn colorfgbg_hint(evidence: &Given, env: Option<&OsStr>) -> Option<Mode> {
    doctor_evidence::envelope_colorfgbg(evidence)
        .or_else(|| env.and_then(|v| colorfgbg_mode(v.as_bytes())))
}

pub(super) fn run_terminal_background(c: &Ctx) -> Finding {
    let Some(settings) = terminal_settings(c) else {
        return finding(
            Status::Unknown,
            "the settings could not be read, so there is nothing to compare with",
            None,
        );
    };
    if !settings.auto {
        return finding(
            Status::Skipped,
            "`colors.mode` is not auto, so the prompt does not guess the background",
            None,
        );
    }
    let outcome = match with_terminal(c, |t| terminal::measure_background(t)) {
        Ok(o) => o,
        Err(f) => return f,
    };
    if outcome == BackgroundOutcome::Cancelled {
        c.terminal.cancelled.set(true);
    }
    // The prompt draws by what its envelope carries: the same two functions.
    let hint = colorfgbg_hint(&c.evidence, c.terminal.colorfgbg.as_deref());
    judge_background(&outcome, display_mode(hint), hint.is_some())
}
