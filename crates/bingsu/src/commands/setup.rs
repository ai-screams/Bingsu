//! `bingsu setup`: a first settings file, from two questions at most (icons,
//! background color) asked on the terminal (`/dev/tty`). The file is made
//! only when there is none: a temporary file in the settings folder
//! (`O_EXCL`, 0600), its data and the folder flushed, then `linkat`, which
//! cannot replace a name another process made in the meantime. When the
//! settings file is there, as `config.toml` or as `config.json` (one place,
//! and both names together are refused when settings are read), nothing is
//! written and only the differences from the starter are shown. The shell startup file is never edited: the line to
//! add is the only thing printed on stdout.
//!
//! Exit codes: 0 done (written, or already there), 1 refused or failed,
//! 2 usage, 130 cancelled.
use super::{
    clock::SystemClock,
    config_inspect::{self, Opening, Selection, open_loader},
    config_load::name_present,
    ctx::{self, Applied, EXIT_FAILED, EXIT_USAGE, User},
    group_policy::SystemGroups,
    init::{roots, trusted_env::TrustedEnv},
    messages::{MsgId, en},
    reload,
    runtime_root::{self, Chain, RootError},
    setup_screen::{self, Ended},
    setup_sources::{NewFile, Sources, Tape},
    sys,
    tty::{Answer, Tty},
};
use bingsu_core::color::osc11::{is_light, parse_osc11};
use bingsu_core::color::sgr::ColorDepth;
use bingsu_core::config::compile::BUILTIN_TOML;
use bingsu_core::config::source::Trust;
use bingsu_core::config::starter::{Choices, Icons, Mode, differences, starter};
use bingsu_core::fs_trust::Last;
use bingsu_core::icons::{IconSet, lookup};
use bingsu_core::setup_editor::model::Given;
use bingsu_core::setup_editor::screen::too_small;
use std::ffi::{OsStr, OsString};
use std::io::Read;
use std::os::fd::{AsFd, AsRawFd};
use std::path::Path;
use std::process::ExitCode;

const USAGE: &str = "usage: bingsu setup [--yes] [--plain] [--icons nerd|light|unicode|ascii] [--mode auto|dark|light]";
const FILE: &str = "config.toml";
/// The names of the one place `setup` writes: the file it makes, and the
/// JSON name that stands in the same place.
const NAMES: [&str; 2] = [FILE, "config.json"];
const CANCELLED: u8 = 130;

#[derive(Debug, Default, PartialEq, Eq)]
struct Args {
    yes: bool,
    /// The line questions even where the editor could be drawn.
    plain: bool,
    icons: Option<Icons>,
    mode: Option<Mode>,
}

fn parse(args: &[OsString]) -> Result<Args, String> {
    let mut out = Args::default();
    let mut it = args.iter().map(|a| a.to_str());
    while let Some(word) = it.next() {
        match word {
            Some("--yes") => out.yes = true,
            Some("--plain") => out.plain = true,
            Some("--icons") => {
                let v = it.next().flatten().and_then(Icons::parse);
                out.icons = Some(v.ok_or("--icons takes nerd, light, unicode or ascii")?);
            }
            Some("--mode") => {
                let v = it.next().flatten().and_then(Mode::parse);
                out.mode = Some(v.ok_or("--mode takes auto, dark or light")?);
            }
            _ => return Err(USAGE.to_owned()),
        }
    }
    Ok(out)
}

/// Without a terminal there is no one to ask: all three arguments must be
/// there (the defaults are never chosen silently, and `OSC 11` cannot be
/// asked). Names what is missing.
fn complete(a: &Args) -> Result<Choices, String> {
    let mut missing = Vec::new();
    if !a.yes {
        missing.push("--yes");
    }
    if a.icons.is_none() {
        missing.push("--icons");
    }
    if a.mode.is_none() {
        missing.push("--mode");
    }
    match (a.icons, a.mode) {
        (Some(icons), Some(mode)) if a.yes => Ok(Choices { icons, mode }),
        _ => Err(format!(
            "bingsu setup: there is no terminal to ask, so it needs {} too\n{USAGE}",
            missing.join(", ")
        )),
    }
}

/// How the choices are made when there is a terminal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Way {
    /// All three given: nothing is asked.
    Given,
    /// The line questions: asked for, or a terminal the editor cannot draw
    /// on (no name, `dumb`, smaller than the editor, or of unknown size).
    Lines,
    /// The one-screen editor.
    Editor,
}

fn way(a: &Args, term: Option<&OsStr>, size: Option<(u16, u16)>) -> Way {
    if a.yes && a.icons.is_some() && a.mode.is_some() {
        return Way::Given;
    }
    let named = term.is_some_and(|t| !t.is_empty() && t != "dumb");
    let fits = size.is_some_and(|(cols, rows)| !too_small(cols, rows));
    if a.plain || !named || !fits {
        Way::Lines
    } else {
        Way::Editor
    }
}

fn yes(answer: Option<String>, default: bool) -> Option<bool> {
    match answer?.as_str() {
        "" => Some(default),
        "y" | "yes" => Some(true),
        "n" | "no" => Some(false),
        _ => Some(default),
    }
}

/// Question one: can the user see Nerd Font glyphs? `None`: cancelled.
fn ask_icons(tty: &Tty) -> Option<Icons> {
    let sample: String = ["sep.triangle.r", "readonly", "char.ok"]
        .iter()
        .filter_map(|n| lookup(n))
        .map(|i| format!("  {}", i.glyph(IconSet::Nerd)))
        .collect();
    tty.say(&format!(
        "These should look like three small symbols, not boxes or blanks:\n{sample}\nCan you see them? [Y/n] "
    ));
    Some(if yes(tty.line(), true)? {
        Icons::Nerd
    } else {
        Icons::Unicode
    })
}

/// Question two: the color mode. The terminal is asked for its background
/// first; a missing or unreadable answer leaves the question open.
fn ask_mode(tty: &Tty) -> Option<Mode> {
    let detected = match tty.ask_background() {
        Ok(Answer::Reply(b)) => {
            parse_osc11(&b).map(|c| if is_light(c) { Mode::Light } else { Mode::Dark })
        }
        Ok(Answer::Cancelled) => return None,
        Ok(Answer::Silent) | Err(_) => None,
    };
    let (default, note) = match detected {
        Some(m) => (m, format!(" (the terminal looks {})", m.word())),
        None => (Mode::Auto, " (the terminal did not say)".to_owned()),
    };
    tty.say(&format!(
        "Color mode{note}: [a]uto, [d]ark or [l]ight? [{}] ",
        &default.word()[..1]
    ));
    Some(match tty.line()?.as_str() {
        "a" | "auto" => Mode::Auto,
        "d" | "dark" => Mode::Dark,
        "l" | "light" => Mode::Light,
        _ => default,
    })
}

/// The line that starts bingsu in the shell named by `$SHELL`, or all three.
fn startup_lines(shell: Option<&OsStr>) -> String {
    use std::os::unix::ffi::OsStrExt;
    let base = shell.map(|s| s.as_bytes().rsplit(|&b| b == b'/').next().unwrap_or(b""));
    let line = |name: &str| match name {
        "fish" => "bingsu init fish | source".to_owned(),
        n => format!("eval \"$(bingsu init {n})\""),
    };
    match base {
        Some(b"zsh") => line("zsh") + "\n",
        Some(b"bash") => line("bash") + "\n",
        Some(b"fish") => line("fish") + "\n",
        _ => ["zsh", "bash", "fish"]
            .iter()
            .map(|n| format!("# {n}\n{}\n", line(n)))
            .collect(),
    }
}

#[derive(Debug, PartialEq, Eq)]
enum Created {
    Wrote,
    /// The file is there, but the folder could not be flushed: the name may
    /// not survive a crash.
    Unflushed,
    /// `config.toml` appeared between the check and the link.
    Exists,
}

fn unique_name() -> OsString {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.subsec_nanos());
    format!(".{FILE}.setup-{}-{nanos}", std::process::id()).into()
}

/// `fsync` of the folder `chain` ends in. Opened again by its name with
/// `O_RDONLY | O_DIRECTORY`: on Linux a folder kept open as a search-only
/// (`O_PATH`) descriptor, as `open_chain` keeps it, cannot be synced
/// (EBADF). The folder found must be the one in the chain.
fn sync_folder(chain: &Chain, dir: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let folder = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(dir)?;
    let (a, b) = (folder.metadata()?, chain.last().metadata()?);
    if (a.dev(), a.ino()) != (b.dev(), b.ino()) {
        return Err(std::io::Error::other("the settings folder changed"));
    }
    folder.sync_all()
}

/// Temporary file, data flushed, `linkat`, then the folder flushed. An error
/// means no file was made.
fn create(chain: &Chain, dir_path: &Path, text: &str) -> std::io::Result<Created> {
    let dir = chain.last();
    let tmp = unique_name();
    let file = sys::create_file_at(dir.as_fd(), &tmp, 0o600)?;
    let made = (|| {
        if sys::write_fd(file.as_raw_fd(), text.as_bytes()) != sys::WriteOutcome::Done {
            return Err(std::io::Error::other("write"));
        }
        file.sync_all()?;
        match sys::link_at(dir.as_fd(), &tmp, OsStr::new(FILE)) {
            Ok(()) => Ok(Created::Wrote),
            Err(e) if e.raw_os_error() == Some(libc::EEXIST) => Ok(Created::Exists),
            Err(e) => Err(e),
        }
    })();
    let _ = sys::unlink_at(dir.as_fd(), &tmp);
    let made = made?;
    if made == Created::Wrote && sync_folder(chain, dir_path).is_err() {
        return Ok(Created::Unflushed);
    }
    Ok(made)
}

/// The settings file already in the place, under either of its names
/// (`config.toml` first), with its bytes (capped). `Ok(None)` when there is
/// none; an error when something is there that is not a plain file.
/// 이것을 실패시키는 것: `config.json`을 보지 않는 것(그 곁에 `config.toml`을 만들어 다음 읽기가 E308로 멈춤).
fn existing(chain: &Chain) -> std::io::Result<Option<(&'static str, Vec<u8>)>> {
    let cap = bingsu_core::config::tree::FILE_BYTES_MAX as u64;
    for name in NAMES {
        match sys::open_data_at_nofollow(chain.last().as_fd(), OsStr::new(name)) {
            Ok(f) => {
                let mut bytes = Vec::new();
                f.take(cap + 1).read_to_end(&mut bytes)?;
                return Ok(Some((name, bytes)));
            }
            Err(e) if e.raw_os_error() == Some(libc::ENOENT) => {}
            Err(e) => return Err(e),
        }
    }
    Ok(None)
}

/// Says that the settings file `path` is there and nothing was written,
/// and how its `bytes` (when they could be read) differ from the choices.
fn report_existing(path: &Path, bytes: Option<&[u8]>, c: Choices) {
    use std::os::unix::ffi::OsStrExt;
    eprintln!(
        "bingsu: {} is already there, so nothing was written.",
        ctx::show(path)
    );
    let format = bingsu_core::config::tree::format_of(path.as_os_str().as_bytes());
    match bytes {
        Some(b) if b.len() <= bingsu_core::config::tree::FILE_BYTES_MAX => {
            match differences(format, b, c) {
                Some(d) if d.is_empty() => eprintln!("It already has the choices you made."),
                Some(d) => {
                    eprintln!("It differs from your choices here:");
                    for line in d {
                        eprintln!("  {line}");
                    }
                    eprintln!(
                        "Edit it yourself to change them; `bingsu config check` checks the result."
                    );
                }
                None => eprintln!("It does not parse; `bingsu config check` says where."),
            }
        }
        _ => eprintln!("It could not be read to compare."),
    }
}

/// `report_existing` for what `existing` found in `dir`; a read error is
/// named after the file `setup` would have written.
fn report_found(dir: &Path, found: std::io::Result<Option<(&'static str, Vec<u8>)>>, c: Choices) {
    match found {
        Ok(Some((name, b))) => report_existing(&dir.join(name), Some(&b), c),
        _ => report_existing(&dir.join(FILE), None, c),
    }
}

fn refuse(what: &str) -> ExitCode {
    eprintln!("bingsu setup: {what}");
    ctx::code(EXIT_FAILED)
}

/// The roots `init` pinned in the shell that ran `setup`, re-checked now;
/// `None` before `init` (then the folders come from the environment,
/// without the warning other commands give: that is the usual time to run
/// `setup`).
fn pinned(user: &User, runs_here: bool) -> Result<Option<roots::Roots>, (String, u8)> {
    if runs_here {
        ctx::pinned_roots(user)
    } else {
        Ok(None)
    }
}

/// One reading of every settings source, as the reader makes it now.
fn read_sources(user: &User, env: &TrustedEnv, runs_here: bool) -> Result<(Opening, Tape), String> {
    let mut opening =
        open_loader(user, env, pinned(user, runs_here).map_err(|(t, _)| t)?).map_err(|(t, _)| t)?;
    let roots = opening.loader.roots(BUILTIN_TOML.as_bytes());
    let (tape, _) = Tape::read(roots, &mut opening.loader, ctx::version());
    Ok((opening, tape))
}

/// What a failed second reading says: nothing was written, and the keys
/// the file would have had, so they can be chosen again.
fn changed_words(text: &str) -> String {
    let mut out = String::from(
        "bingsu: settings changed while you edited; nothing written.\nThese are the keys it would have written:\n",
    );
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        out.push_str("  ");
        out.push_str(&bingsu_core::sanitize::sanitize(line.as_bytes()));
        out.push('\n');
    }
    out
}

/// What `setup` says after publishing the settings with its new file.
fn applied_words(a: &Applied) -> String {
    match a {
        Applied::Published { left_out, .. } => {
            let mut text = String::from("bingsu: applied; the next prompt shows it\n");
            for p in left_out {
                text.push_str(&format!(
                    "bingsu: left out, nothing in it runs: {}\n",
                    ctx::show(p)
                ));
            }
            text
        }
        Applied::Invalid => NOT_APPLIED.to_owned(),
        Applied::Busy => String::from(
            "bingsu: saved; another refresh is running, so the next prompt picks it up\n",
        ),
        other => match reload::report(other, "applied") {
            Ok(text) => text,
            Err((text, _)) => format!("{text}\n"),
        },
    }
}

const NOT_APPLIED: &str = "bingsu: not applied; the prompt keeps the last valid settings\n";
const LOADS_LATER: &str = "bingsu: the new look shows once your shell loads bingsu\n";
const DOCTOR: &str = "Line ends look off? `bingsu doctor` checks the character widths.";

/// After the file is written: the same check as `config check` (its output
/// only when the settings are not valid), then, in a shell that already
/// runs bingsu, the same publication as `reload`, under the commands'
/// deadline. Says what came of it; the file stays either way.
fn apply_written(exe: &OsStr, user: &User, env: &TrustedEnv, runs_here: bool) {
    // A reading earlier in this process may have left the refused latch.
    let _ = super::io_meter::take_refused();
    let started = ctx::start();
    let deadline = match ctx::arm_deadline_ending(
        ctx::COMMAND_LIMIT,
        format!("{}\n", en(MsgId::DeadlineReached)),
        0,
    ) {
        Ok(d) => d,
        Err(_) => {
            eprintln!(
                "bingsu: the deadline watchdog could not start, so the file was not checked or applied; run: bingsu reload"
            );
            return;
        }
    };
    deadline.selection_saved();
    let valid = match pinned(user, runs_here)
        .and_then(|p| config_inspect::check_report_with(user, env, p))
    {
        Ok((_, 0)) => true,
        Ok((shown, _)) => {
            eprint!("{shown}");
            false
        }
        Err((text, _)) => {
            eprintln!("{text}");
            false
        }
    };
    if !runs_here {
        eprint!("{}", if valid { LOADS_LATER } else { NOT_APPLIED });
        return;
    }
    let (Some(started), Ok(Some(roots))) = (started, ctx::pinned_roots(user)) else {
        eprintln!("{}", en(MsgId::ReloadIncomplete));
        return;
    };
    let applied = ctx::apply(Path::new(exe), &roots, user, started, &mut SystemClock);
    eprint!("{}", applied_words(&applied));
}

pub fn run(exe: &OsStr, args: &[OsString]) -> ExitCode {
    let args = match parse(args) {
        Ok(a) => a,
        Err(text) => {
            eprintln!("{text}");
            return ctx::code(EXIT_USAGE);
        }
    };
    let tty = Tty::open();
    // No terminal: everything must be given, and nothing is asked.
    let given = if tty.is_none() {
        match complete(&args) {
            Ok(c) => Some(c),
            Err(text) => {
                eprintln!("{text}");
                return ctx::code(EXIT_USAGE);
            }
        }
    } else {
        None
    };
    let Some(user) = User::current() else {
        return refuse("the account or its home folder cannot be read");
    };
    let env = TrustedEnv::capture();
    // `init` pinned roots in this shell (or the one that started it).
    let runs_here = TrustedEnv::pinned_roots().is_some();
    let written = match pinned(&user, runs_here) {
        Ok(Some(roots::Roots {
            config: Some(pin), ..
        })) => pin.written,
        Ok(_) => roots::config_candidate(&env, &user.pw.home),
        Err((text, _)) => {
            eprintln!("{text}");
            return ctx::code(EXIT_FAILED);
        }
    };
    let Some(dir) = roots::canonical_lenient(&written) else {
        return refuse("the settings folder cannot be placed (a `..` in its path?)");
    };
    let mut groups = SystemGroups::new(&user.pw.name);
    let (chain, mine) = match runtime_root::open_chain(&dir) {
        Ok(chain) => {
            let local = sys::fd_is_local(chain.last().as_raw_fd());
            let mine = bingsu_core::fs_trust::walk_verdict(
                &chain.facts,
                user.me,
                Last::Mine,
                local,
                &mut groups,
            )
            .is_ok();
            (Some(chain), mine)
        }
        Err(RootError::Open { errno, .. }) if errno == libc::ENOENT => (None, true),
        Err(_) => return refuse(&format!("{} cannot be used", ctx::show(&dir))),
    };
    let not_mine = || {
        refuse(&format!(
            "{} is not a folder only you can change; fix that first",
            ctx::show(&dir)
        ))
    };
    // The settings as the reader reads them now, before anything is asked.
    let (opening, start) = match read_sources(&user, &env, runs_here) {
        Ok(r) => r,
        // The reader leaves out a settings folder others can change.
        Err(_) if !mine => return not_mine(),
        Err(text) => {
            eprintln!("{text}");
            return ctx::code(EXIT_FAILED);
        }
    };
    // With a `config use` record the reader reads the chosen file in the
    // place of the folder's own: that is the settings file.
    let chosen = match &opening.selection {
        Selection::Incomplete => {
            return refuse(
                "the settings choice could not be read, so nothing was written. Run: bingsu config path",
            );
        }
        Selection::Chosen(r) if !name_present(&r.path) => {
            eprintln!(
                "bingsu: your chosen settings file {} is missing; run bingsu config use again",
                ctx::show(&r.path)
            );
            return ctx::code(EXIT_FAILED);
        }
        Selection::Chosen(r) => Some(r.path.clone()),
        Selection::None | Selection::Unusable(_) => None,
    };

    let way = match &tty {
        None => Way::Given,
        Some(t) => way(
            &args,
            TrustedEnv::term().as_deref(),
            t.size().map(|s| (s.cols, s.rows)),
        ),
    };
    if let Some(file) = chosen {
        use std::os::unix::ffi::OsStrExt;
        let choices = match choose(tty.as_ref(), given, &args) {
            Ok(c) => c,
            Err(code) => return code,
        };
        let bytes = start.root_bytes(file.as_os_str().as_bytes());
        report_existing(&file, bytes, choices);
        return finish(runs_here);
    }
    let path = dir.join(FILE);

    if refuses_folder(mine, way) {
        return not_mine();
    }
    if let Some(chain) = &chain {
        match existing(chain) {
            Ok(None) => {}
            other => {
                let choices = match choose(tty.as_ref(), given, &args) {
                    Ok(c) => c,
                    Err(code) => return code,
                };
                report_found(&dir, other, choices);
                return finish(runs_here);
            }
        }
    }
    let file = NewFile {
        display: opening
            .root
            .join(FILE)
            .into_os_string()
            .into_encoded_bytes(),
        trust: if opening.shape_only {
            Trust::ShapeOnly
        } else {
            Trust::Executable
        },
    };
    drop(opening);
    let sources = Sources::new(start, file, ctx::version());

    // The choices: the editor, the line questions, or all given.
    let (text, choices) = match (&tty, way) {
        (Some(t), Way::Editor) => {
            let (_, colorterm, no_color) = TrustedEnv::terminal();
            let truecolor = colorterm
                .as_deref()
                .is_some_and(|v| matches!(v.as_encoded_bytes(), b"truecolor" | b"24bit"));
            let here = std::env::current_dir().unwrap_or_default();
            let folder = setup_screen::sample_folder(TrustedEnv::pwd().as_deref(), &here);
            let host = sys::host_name();
            let colorfgbg = TrustedEnv::terminal_hints().0;
            let start = setup_screen::Start {
                sources: &sources,
                path: &sources.file().display,
                folder: folder.as_os_str().as_encoded_bytes(),
                home: user.pw.home.as_os_str().as_encoded_bytes(),
                host: host.as_deref(),
                colorfgbg: colorfgbg.as_deref(),
                depth: if truecolor {
                    ColorDepth::TrueColor
                } else {
                    ColorDepth::Ansi256
                },
                mono: no_color,
                read_only: !mine,
                given: Given {
                    icons: args.icons,
                    mode: args.mode,
                },
            };
            match setup_screen::edit(t, &start) {
                Ended::Write { text, choices } => (text, choices),
                Ended::Quit => {
                    eprintln!("bingsu: nothing written.");
                    return finish(runs_here);
                }
                Ended::Cancelled => return cancelled(),
                Ended::Lost(why) => {
                    return refuse(&format!("{why}; nothing was written"));
                }
            }
        }
        _ => {
            let choices = match choose(tty.as_ref(), given, &args) {
                Ok(c) => c,
                Err(code) => return code,
            };
            // Ask before the first write, unless told to go ahead.
            if !args.yes
                && let Some(t) = &tty
            {
                t.say(&format!("Write {}? [Y/n] ", ctx::show(&path)));
                match yes(t.line(), true) {
                    Some(true) => {}
                    Some(false) => {
                        eprintln!("bingsu: nothing written.");
                        return finish(runs_here);
                    }
                    None => return cancelled(),
                }
            }
            (starter(choices), choices)
        }
    };
    // Anything but all three choices with `--yes` asked on a terminal (no
    // terminal needs all three).
    let asked = way != Way::Given;

    // The settings read again: what the choices were made against must
    // still be what the reader reads.
    match read_sources(&user, &env, runs_here) {
        Ok((_, now)) if sources.unchanged(&now) => {}
        Ok(_) => {
            eprint!("{}", changed_words(&text));
            return ctx::code(EXIT_FAILED);
        }
        Err(why) => {
            eprintln!("{why}");
            return refuse("the settings could not be read again, so nothing was written");
        }
    }
    let chain = match chain {
        Some(c) => c,
        None => match runtime_root::ensure_root(&dir, user.me, &mut groups, Last::Mine) {
            Ok(c) => c,
            Err(_) => return refuse(&format!("{} cannot be made", ctx::show(&dir))),
        },
    };
    // From the temporary file to its removal nothing ends the process: a
    // Ctrl-C or a TERM then comes after.
    let held = sys::hold_signals();
    let made = create(&chain, &dir, &text);
    drop(held);
    match made {
        Ok(Created::Wrote) => eprintln!("bingsu: wrote {}", ctx::show(&path)),
        Ok(Created::Unflushed) => eprintln!(
            "bingsu: wrote {}, but the folder could not be flushed; it may not survive a crash",
            ctx::show(&path)
        ),
        Ok(Created::Exists) => {
            report_found(&dir, existing(&chain), choices);
            return finish(runs_here);
        }
        Err(_) => return refuse(&format!("{} could not be written", ctx::show(&path))),
    }
    // The startup line goes out first: the deadline below may end the
    // process.
    let code = finish(runs_here);
    apply_written(exe, &user, &env, runs_here);
    if asked {
        eprintln!("{DOCTOR}");
    }
    code
}

/// A settings folder setup may not write (`mine` false) is refused, except
/// by the editor: it shows a folder the reader reads (its owner or members
/// could not all be confirmed) read-only.
fn refuses_folder(mine: bool, way: Way) -> bool {
    !mine && way != Way::Editor
}

/// The two choices: all given, or the line questions for what is not.
fn choose(tty: Option<&Tty>, given: Option<Choices>, args: &Args) -> Result<Choices, ExitCode> {
    match (tty, given) {
        (_, Some(c)) => Ok(c),
        (Some(t), None) => {
            let icons = match args.icons {
                Some(i) => i,
                None => ask_icons(t).ok_or_else(cancelled)?,
            };
            let mode = match args.mode {
                Some(m) => m,
                None => ask_mode(t).ok_or_else(cancelled)?,
            };
            Ok(Choices { icons, mode })
        }
        (None, None) => Err(ctx::code(EXIT_USAGE)),
    }
}

fn cancelled() -> ExitCode {
    eprintln!("bingsu: cancelled, nothing written.");
    ExitCode::from(CANCELLED)
}

/// What the startup line is for: a shell `init` already ran in (or its
/// parent) has the roots it pinned.
fn startup_note(runs_here: bool) -> &'static str {
    if runs_here {
        "bingsu already runs in this shell or the shell that started it; this line is only for a new setup:"
    } else {
        "Add this to your shell's startup file to start bingsu:"
    }
}

/// The startup line on stdout, and a word on stderr about what it is.
fn finish(runs_here: bool) -> ExitCode {
    let shell = TrustedEnv::login_shell();
    eprintln!("{}", startup_note(runs_here));
    if ctx::print(&startup_lines(shell.as_deref())) {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;

    fn args(words: &[&str]) -> Vec<OsString> {
        words.iter().map(OsString::from).collect()
    }

    // 이것을 실패시키는 것: 인자 값 검사를 빼는 것(모르는 아이콘·모드·남는 단어를 받음), 값 없는 `--icons`를
    // 받는 것, 아이콘 낱말 넷 중 하나를 받지 않거나 다른 집합으로 읽는 것, 거부 문구가 받는 낱말을 다 말하지
    // 않는 것.
    #[test]
    fn arguments_are_read_strictly() {
        for icons in Icons::ALL {
            let a = parse(&args(&["--icons", icons.word()])).unwrap();
            assert_eq!(a.icons, Some(icons));
        }
        let e = parse(&args(&["--icons", "emoji"])).unwrap_err();
        assert_eq!(e, "--icons takes nerd, light, unicode or ascii");
        let words = Icons::ALL.map(Icons::word).join("|");
        assert!(USAGE.contains(&format!("[--icons {words}]")), "{USAGE}");
        let a = parse(&args(&["--yes", "--icons", "nerd", "--mode", "light"])).unwrap();
        assert_eq!(
            a,
            Args {
                yes: true,
                plain: false,
                icons: Some(Icons::Nerd),
                mode: Some(Mode::Light)
            }
        );
        assert!(parse(&args(&["--plain"])).unwrap().plain);
        for bad in [
            &["--icons", "emoji"][..],
            &["--icons", "Light"],
            &["--icons", "ASCII"],
            &["--icons", ""],
            &["--icons"],
            &["--yes", "--icons=light"],
            &["--mode", "dim"],
            &["--mode"],
            &["extra"],
            &["--yes", "--icons=nerd"],
        ] {
            assert!(parse(&args(bad)).is_err(), "{bad:?}");
        }
    }

    // 이것을 실패시키는 것: `--plain`, 이름 없는 TERM, 빈 TERM, `dumb`, 편집판보다 작은 창(가로 또는 세로), 크기를 모르는
    // 창 가운데 하나라도 편집판으로 보내는 것, 세 값과 `--yes`가 다 있는데 묻는 것, 셋 중 하나가 빠졌는데 묻지 않는 것.
    #[test]
    fn plain_terminals_get_the_line_questions() {
        let a = |w: &[&str]| parse(&args(w)).unwrap();
        let fit = Some((80, 24));
        let xterm = Some(OsStr::new("xterm-256color"));
        assert_eq!(way(&a(&[]), xterm, fit), Way::Editor);
        assert_eq!(way(&a(&["--icons", "nerd"]), xterm, fit), Way::Editor);
        assert_eq!(way(&a(&["--yes"]), xterm, Some((40, 16))), Way::Editor);
        assert_eq!(way(&a(&["--plain"]), xterm, fit), Way::Lines);
        for term in [None, Some(OsStr::new("")), Some(OsStr::new("dumb"))] {
            assert_eq!(way(&a(&[]), term, fit), Way::Lines, "{term:?}");
        }
        for size in [None, Some((39, 24)), Some((80, 15)), Some((0, 0))] {
            assert_eq!(way(&a(&[]), xterm, size), Way::Lines, "{size:?}");
        }
        let all = ["--yes", "--icons", "ascii", "--mode", "dark"];
        assert_eq!(way(&a(&all), xterm, fit), Way::Given);
        assert_eq!(way(&a(&all), None, None), Way::Given);
        assert_eq!(way(&a(&all[..3]), xterm, fit), Way::Editor);
        assert_eq!(way(&a(&all[1..]), xterm, fit), Way::Editor);
        assert_eq!(
            way(&a(&["--yes", "--mode", "dark"]), xterm, fit),
            Way::Editor
        );
        assert!(USAGE.contains(" [--plain] "), "{USAGE}");
    }

    // 이것을 실패시키는 것: 터미널 없이 기본값을 조용히 고르는 것, 빠진 인자를 이름으로 알리지 않는 것,
    // `--yes` 없이 쓰기로 넘어가는 것.
    #[test]
    fn without_a_terminal_all_three_must_be_given() {
        let all = Args {
            yes: true,
            icons: Some(Icons::Unicode),
            mode: Some(Mode::Auto),
            ..Args::default()
        };
        assert_eq!(
            complete(&all),
            Ok(Choices {
                icons: Icons::Unicode,
                mode: Mode::Auto
            })
        );
        let e = complete(&Args::default()).unwrap_err();
        assert!(e.contains("--yes, --icons, --mode"), "{e}");
        let e = complete(&Args {
            icons: Some(Icons::Nerd),
            ..Args::default()
        })
        .unwrap_err();
        assert!(
            e.contains("--yes, --mode") && !e.contains("--icons,"),
            "{e}"
        );
        let e = complete(&Args { yes: false, ..all }).unwrap_err();
        assert!(e.contains("needs --yes too"), "{e}");
    }

    // 이것을 실패시키는 것: 기본 답을 바꾸는 것(빈 줄은 예), 모르는 글자를 아니오로 치는 것, 입력 끝(Ctrl-D)을
    // 답으로 치는 것.
    #[test]
    fn answers_default_to_the_first_choice() {
        assert_eq!(yes(Some(String::new()), true), Some(true));
        assert_eq!(yes(Some("y".into()), false), Some(true));
        assert_eq!(yes(Some("n".into()), true), Some(false));
        assert_eq!(yes(Some("what".into()), true), Some(true));
        assert_eq!(yes(None, true), None);
    }

    // 이것을 실패시키는 것: 다시 읽기가 달라졌을 때 "nothing written"을 빼는 것, 주석·빈 줄을 키로 내는 것, 키의
    // 제어 바이트를 그대로 내는 것.
    #[test]
    fn a_changed_reading_says_what_it_would_have_written() {
        let w =
            changed_words("#:schema x\n# a note\n\n[style]\npreset = \"pill\"\nx = \"\x1b[2J\"\n");
        assert_eq!(
            w,
            "bingsu: settings changed while you edited; nothing written.\nThese are the keys it would have written:\n  [style]\n  preset = \"pill\"\n  x = \"[2J\"\n"
        );
    }

    // 이것을 실패시키는 것: 발행의 끝마다 문구를 바꾸는 것(바쁨을 실패로, 유효하지 않음을 적용으로), 빠진 파일을
    // 알리지 않거나 그 경로의 제어 바이트를 그대로 내는 것, 그대로인 설정에 reload의 문구를 쓰지 않는 것.
    #[test]
    fn every_publication_ending_has_its_words() {
        let published = Applied::Published {
            generation: 3,
            left_out: vec![std::path::PathBuf::from("/c/x\u{1b}.toml")],
        };
        assert_eq!(
            applied_words(&published),
            "bingsu: applied; the next prompt shows it\nbingsu: left out, nothing in it runs: /c/x.toml\n"
        );
        assert_eq!(
            applied_words(&Applied::Unchanged { generation: 3 }),
            "bingsu: applied; the settings did not change (generation 3)\n"
        );
        assert_eq!(
            applied_words(&Applied::Invalid),
            "bingsu: not applied; the prompt keeps the last valid settings\n"
        );
        assert_eq!(
            applied_words(&Applied::Busy),
            "bingsu: saved; another refresh is running, so the next prompt picks it up\n"
        );
        for (a, m) in [
            (Applied::Incomplete, MsgId::ReloadIncomplete),
            (Applied::OverCap, MsgId::ReloadOverCap),
            (
                Applied::Unavailable(MsgId::NoRuntimeRoot),
                MsgId::NoRuntimeRoot,
            ),
        ] {
            assert_eq!(applied_words(&a), format!("{}\n", en(m)));
        }
    }

    // 이것을 실패시키는 것: 쓸 수 없는 폴더를 편집판에서도 거부하는 것(읽기 전용으로 보여야 함), 다른 길에서 받아
    // 쓰는 것, 쓸 수 있는 폴더를 거부하는 것.
    #[test]
    fn only_the_editor_shows_a_folder_it_may_not_write() {
        assert!(!refuses_folder(false, Way::Editor));
        assert!(refuses_folder(false, Way::Lines));
        assert!(refuses_folder(false, Way::Given));
        assert!(!refuses_folder(true, Way::Lines));
    }

    // 이것을 실패시키는 것: init이 고정한 값이 있는 셸과 없는 셸의 안내를 바꾸는 것.
    #[test]
    fn the_startup_note_says_whether_bingsu_runs_here() {
        assert_eq!(
            startup_note(true),
            "bingsu already runs in this shell or the shell that started it; this line is only for a new setup:"
        );
        assert_eq!(
            startup_note(false),
            "Add this to your shell's startup file to start bingsu:"
        );
    }

    // 이것을 실패시키는 것: 셸 이름 → 시작 줄 대응(fish만 다른 형식), 모르는 셸에서 한 줄만 내는 것.
    #[test]
    fn the_startup_line_follows_the_shell() {
        let line = |s: &str| startup_lines(Some(OsStr::new(s)));
        assert_eq!(line("/bin/zsh"), "eval \"$(bingsu init zsh)\"\n");
        assert_eq!(line("/usr/bin/bash"), "eval \"$(bingsu init bash)\"\n");
        assert_eq!(
            line("/opt/homebrew/bin/fish"),
            "bingsu init fish | source\n"
        );
        for unknown in [Some(OsStr::new("/bin/tcsh")), None] {
            let all = startup_lines(unknown);
            assert!(
                all.contains("# zsh\n") && all.contains("# fish\n") && all.contains("init bash")
            );
        }
    }

    fn scratch(tag: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("bingsu-setup-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o700)).unwrap();
        // `open_chain` follows no link, and `/var` is one on macOS.
        p.canonicalize().unwrap()
    }

    // 이것을 실패시키는 것: 이름 넣기를 `renameat`으로 바꾸는 것(먼저 만들어진 파일을 덮어씀: 검사와 생성 사이
    // 경쟁), 만든 파일의 권한이 0600이 아닌 것, 임시 파일을 남기는 것, 이름을 넣은 뒤 폴더 flush 실패를 "쓰지
    // 못함"(오류)이나 "썼음"으로 알리는 것, 남의 파일이 있을 때 폴더를 flush하는 것. 폴더에 `fsync`하지 않는
    // 것은 시험할 수 없어 제외.
    #[test]
    fn a_file_that_appeared_first_is_never_replaced() {
        let dir = scratch("race");
        let chain = runtime_root::open_chain(&dir).unwrap();
        // The fixture makes the file after the caller's check, before the link.
        std::fs::write(dir.join(FILE), b"theirs\n").unwrap();
        let got = create(&chain, &dir, "ours\n").unwrap();
        assert_eq!(got, Created::Exists);
        // Someone else's file is not flushed: a folder that would fail it
        // changes nothing.
        let other = scratch("race-other");
        assert_eq!(create(&chain, &other, "ours\n").unwrap(), Created::Exists);
        assert_eq!(std::fs::read(dir.join(FILE)).unwrap(), b"theirs\n");
        let names: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(names, [OsString::from(FILE)], "a temporary file was left");
        // Without a rival the file is made, private, and no temporary stays.
        std::fs::remove_file(dir.join(FILE)).unwrap();
        assert_eq!(create(&chain, &dir, "ours\n").unwrap(), Created::Wrote);
        let meta = std::fs::metadata(dir.join(FILE)).unwrap();
        assert_eq!(meta.permissions().mode() & 0o7777, 0o600);
        assert_eq!(std::fs::read(dir.join(FILE)).unwrap(), b"ours\n");
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 1);
        // The folder named is not the one written in, so its flush fails
        // after the link: the file is there and says so.
        std::fs::remove_file(dir.join(FILE)).unwrap();
        assert_eq!(
            create(&chain, &other, "ours\n").unwrap(),
            Created::Unflushed
        );
        assert_eq!(std::fs::read(dir.join(FILE)).unwrap(), b"ours\n");
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&other);
    }

    // 이것을 실패시키는 것: 파일이 없을 때 `None`이 아닌 것, 링크를 따라가 읽는 것(`O_NOFOLLOW`),
    // 파일이 있는데 있다고 알리지 않는 것.
    #[test]
    fn existing_is_none_only_when_there_is_no_file() {
        let dir = scratch("exists");
        let chain = runtime_root::open_chain(&dir).unwrap();
        assert!(matches!(existing(&chain), Ok(None)));
        std::fs::write(dir.join(FILE), b"icons = \"nerd\"\n").unwrap();
        assert_eq!(
            existing(&chain).unwrap().unwrap(),
            (FILE, b"icons = \"nerd\"\n".to_vec())
        );
        std::fs::remove_file(dir.join(FILE)).unwrap();
        std::os::unix::fs::symlink("/etc/hosts", dir.join(FILE)).unwrap();
        assert!(existing(&chain).is_err(), "a link is not read");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
