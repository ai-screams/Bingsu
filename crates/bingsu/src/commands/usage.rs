//! The usage line and the `-h`/`--help` text of every user-facing command,
//! from one table (`COMMANDS`). A wrong use prints the command's usage line
//! on stderr and exits 2, as before; `-h` or `--help` as the only word after
//! a command (or after a `config` subcommand, or alone) prints its help on
//! stdout and exits 0. The help is ASCII and fits 80 columns.
//!
//! `prompt` is listed but has no help here: `bingsu prompt` never reaches
//! this module (the prompt adapter takes it first) and its words are the
//! shell hook's. `--version` takes no argument. Internal entry points are not
//! listed.
use std::ffi::OsString;
use std::process::ExitCode;

/// One option or operand: its words as the usage line writes them, and what
/// it does.
pub(super) struct Opt {
    pub words: &'static str,
    pub what: &'static str,
}

/// One command: its name, what follows the name in its usage line, what it
/// does, its subcommands (the usage line is then `<sub|sub ...>`), its
/// options, and whether `-h`/`--help` after it prints this entry's help
/// (the subjects of `list` are words of one command line, not commands).
pub(super) struct Cmd {
    pub name: &'static str,
    pub args: &'static str,
    pub what: &'static str,
    pub subs: &'static [Cmd],
    pub opts: &'static [Opt],
    pub help: bool,
}

const FORMAT: Opt = Opt {
    words: "--format json|text",
    what: "the output format (text by default)",
};

const fn cmd(
    name: &'static str,
    args: &'static str,
    what: &'static str,
    opts: &'static [Opt],
) -> Cmd {
    Cmd {
        name,
        args,
        what,
        subs: &[],
        opts,
        help: true,
    }
}

const CONFIG_SUBS: &[Cmd] = &[
    cmd(
        "check",
        "[--explain] [--format json|text]",
        "read the settings and report what is wrong; write nothing",
        &[
            Opt {
                words: "--explain",
                what: "also show what the settings run (commands, executables)",
            },
            FORMAT,
        ],
    ),
    cmd(
        "edit",
        "",
        "open the settings in $VISUAL or $EDITOR, then apply them",
        &[],
    ),
    cmd(
        "path",
        "",
        "list the settings files that apply, in order",
        &[],
    ),
    cmd(
        "schema",
        "[--theme]",
        "print the JSON Schema of a settings file",
        &[Opt {
            words: "--theme",
            what: "the schema of a theme file instead",
        }],
    ),
    cmd(
        "use",
        "PATH",
        "use the file at PATH as the settings file, and apply it",
        &[Opt {
            words: "PATH",
            what: "the settings file to use",
        }],
    ),
];

/// A word of `list` that names what to list: no help of its own.
const fn subject(name: &'static str, args: &'static str, what: &'static str) -> Cmd {
    Cmd {
        name,
        args,
        what,
        subs: &[],
        opts: &[],
        help: false,
    }
}

const LIST_SUBS: &[Cmd] = &[
    subject(
        "presets",
        "[--preview [--icons nerd|light|unicode|ascii]]",
        "the style presets",
    ),
    subject("segments", "", "the segments a layout can show"),
    subject("flavors", "", "the color flavors"),
    subject("roles", "", "the color roles of the segments"),
    subject("shorteners", "", "the ways a long path is shortened"),
    subject("icons", "", "the icon sets"),
];

/// Every command, in the order of the top-level usage line.
pub(super) const COMMANDS: &[Cmd] = &[
    Cmd {
        name: "config",
        args: "",
        what: "check, list, edit or choose the settings files",
        subs: CONFIG_SUBS,
        opts: &[],
        help: true,
    },
    cmd(
        "doctor",
        "[--format json|text] [--terminal] [--evidence-stdin]",
        "check the installation and the shell setup; change nothing",
        &[
            FORMAT,
            Opt {
                words: "--terminal",
                what: "ask the terminal even when stdout is not one",
            },
            Opt {
                words: "--evidence-stdin",
                what: "read the shell's facts on stdin (from bingsu_doctor)",
            },
        ],
    ),
    cmd(
        "explain",
        "[SEGMENT] [--width N] [--config FILE] [--format json|text]",
        "say in words what the prompt decides at one width",
        &[
            Opt {
                words: "SEGMENT",
                what: "only this segment",
            },
            Opt {
                words: "--width N",
                what: "the width in columns (else COLUMNS, the terminal's or 80)",
            },
            Opt {
                words: "--config FILE",
                what: "read this one file instead of the settings",
            },
            FORMAT,
        ],
    ),
    cmd(
        "help",
        "<code>   (a code such as E201, W404 or N501)",
        "explain a diagnostic code",
        &[Opt {
            words: "<code>",
            what: "a code such as E201, W404 or N501",
        }],
    ),
    cmd(
        "init",
        "zsh|bash|fish",
        "print the hook that connects bingsu to the shell",
        &[Opt {
            words: "zsh|bash|fish",
            what: "the shell; setup prints the line for its startup file",
        }],
    ),
    Cmd {
        name: "list",
        args: "",
        what: "list what the settings can name",
        subs: LIST_SUBS,
        opts: &[
            Opt {
                words: "--preview",
                what: "with presets: draw each preset in this folder",
            },
            Opt {
                words: "--icons nerd|light|unicode|ascii",
                what: "with --preview: the icon set to draw with",
            },
        ],
        help: true,
    },
    Cmd {
        name: "prompt",
        args: "",
        what: "draw the prompt; the shell hook runs it",
        subs: &[],
        opts: &[],
        help: false,
    },
    cmd(
        "reload",
        "",
        "read the settings again and apply them now",
        &[],
    ),
    cmd(
        "setup",
        "[--yes] [--plain] [--no-motion] [--icons nerd|light|unicode|ascii] [--mode auto|dark|light]",
        "make a first settings file, asking on the terminal",
        &[
            Opt {
                words: "--yes",
                what: "with --icons and --mode: write without asking",
            },
            Opt {
                words: "--plain",
                what: "ask line by line instead of the one-screen editor",
            },
            Opt {
                words: "--no-motion",
                what: "draw the opening still (no animation)",
            },
            Opt {
                words: "--icons nerd|light|unicode|ascii",
                what: "the icon set",
            },
            Opt {
                words: "--mode auto|dark|light",
                what: "the color mode",
            },
        ],
    ),
    Cmd {
        name: "--version",
        args: "",
        what: "print this build; check bingsu-prompt and bingsu-collect",
        subs: &[],
        opts: &[],
        help: false,
    },
];

const HELP_WORDS: [&str; 2] = ["-h", "--help"];
const WIDTH: usize = 80;
/// Where the description of an option starts.
const COLUMN: usize = 22;

/// The command at `path` (`["config", "use"]`); `None` for an unknown one.
pub(super) fn find(path: &[&str]) -> Option<&'static Cmd> {
    let (first, rest) = path.split_first()?;
    let mut c = COMMANDS.iter().find(|c| c.name == *first)?;
    for word in rest {
        c = c.subs.iter().find(|s| s.name == *word)?;
    }
    Some(c)
}

/// What follows `bingsu` and the command's names in its usage line.
fn synopsis(c: &Cmd) -> String {
    if c.subs.is_empty() {
        return c.args.to_owned();
    }
    let subs: Vec<String> = c.subs.iter().map(|s| joined(s.name, s.args)).collect();
    format!("<{}>", subs.join("|"))
}

fn joined(name: &str, args: &str) -> String {
    if args.is_empty() {
        name.to_owned()
    } else {
        format!("{name} {args}")
    }
}

/// The usage line of the command at `path` (the top level when empty), as
/// a wrong use prints it.
pub(super) fn line(path: &[&str]) -> String {
    if path.is_empty() {
        let names: Vec<&str> = COMMANDS.iter().map(|c| c.name).collect();
        return format!("usage: bingsu <{}> ...", names.join("|"));
    }
    let found = find(path);
    debug_assert!(found.is_some(), "no usage line for {path:?}");
    let Some(c) = found else {
        return line(&[]);
    };
    let name = path.join(" ");
    format!("usage: bingsu {}", joined(&name, &synopsis(c)))
}

/// `usage: bingsu NAME ARGS` as a wrong use prints it when it fits `WIDTH`;
/// otherwise it breaks between the bracketed groups of `args`, and a
/// continued line starts under the first group.
fn wrapped(name: &str, args: &str, out: &mut String) {
    let head = format!("usage: bingsu {name}");
    let full = format!("usage: bingsu {}", joined(name, args));
    if full.len() <= WIDTH {
        out.push_str(&full);
        out.push('\n');
        return;
    }
    let mut groups: Vec<String> = Vec::new();
    let mut depth = 0i32;
    let mut cur = String::new();
    for ch in args.chars() {
        match ch {
            '[' | '<' | '(' => depth += 1,
            ']' | '>' | ')' => depth -= 1,
            _ => {}
        }
        if ch == ' ' && depth == 0 {
            groups.push(std::mem::take(&mut cur));
        } else {
            cur.push(ch);
        }
    }
    groups.push(cur);
    let indent = " ".repeat(head.len());
    let mut row = head;
    for g in groups {
        if row.len() + 1 + g.len() > WIDTH {
            out.push_str(&row);
            out.push('\n');
            row.clone_from(&indent);
        }
        row.push(' ');
        row.push_str(&g);
    }
    out.push_str(&row);
    out.push('\n');
}

/// `  WORDS   WHAT`, the description at `COLUMN`, or on the next line when
/// the words reach it.
fn item(words: &str, what: &str, out: &mut String) {
    let lead = format!("  {words}");
    if lead.len() + 1 < COLUMN {
        out.push_str(&format!("{lead:<COLUMN$}{what}\n"));
    } else {
        out.push_str(&format!("{lead}\n{:COLUMN$}{what}\n", ""));
    }
}

/// The help of the command at `path` (the top level when empty).
pub(super) fn text(path: &[&str]) -> String {
    let mut out = String::new();
    let Some(c) = find(path) else {
        out.push_str("bingsu: a prompt engine and terminal theme for zsh, bash and fish\n\n");
        out.push_str("usage: bingsu <command> ...\n\ncommands:\n");
        for c in COMMANDS {
            item(c.name, c.what, &mut out);
        }
        out.push_str("\noptions:\n");
        item("-h, --help", "print this help", &mut out);
        out.push_str(
            "\nbingsu <command> --help shows the arguments of a command.\n\
             bingsu help <code> explains a diagnostic code such as E201.\n",
        );
        return out;
    };
    let name = path.join(" ");
    out.push_str(&format!("bingsu {name}: {}\n\n", c.what));
    if c.subs.is_empty() {
        wrapped(&name, c.args, &mut out);
    } else {
        for s in c.subs {
            wrapped(&joined(&name, s.name), s.args, &mut out);
        }
        out.push_str("\ncommands:\n");
        for s in c.subs {
            item(s.name, s.what, &mut out);
        }
    }
    out.push_str("\noptions:\n");
    for o in c.opts {
        item(o.words, o.what, &mut out);
    }
    item("-h, --help", "print this help", &mut out);
    if c.subs.iter().any(|s| s.help) {
        out.push_str(&format!(
            "\nbingsu {name} <command> --help shows the arguments of a command.\n"
        ));
    }
    out
}

/// The help `args` ask for, when they do: `-h` or `--help` as the only word
/// at the top level, after a command, or after a subcommand that has a help
/// (those of `config`). `None` otherwise, and for an entry without help.
pub(super) fn asked(args: &[OsString]) -> Option<String> {
    let words: Vec<&str> = args.iter().map(|a| a.to_str()).collect::<Option<_>>()?;
    let (last, path) = words.split_last()?;
    if !HELP_WORDS.contains(last) {
        return None;
    }
    if path.is_empty() {
        return Some(text(&[]));
    }
    find(path)?.help.then(|| text(path))
}

/// Prints `help` on stdout: exit 0, or 1 when stdout takes no output.
pub(super) fn print(help: &str) -> ExitCode {
    if write_stdout(help.as_bytes()) {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}

#[cfg(unix)]
pub(super) fn write_stdout(bytes: &[u8]) -> bool {
    matches!(
        super::sys::write_fd(1, bytes),
        super::sys::WriteOutcome::Done
    )
}

// Windows has no `sys` module; a plain write is enough for a help text.
#[cfg(not(unix))]
#[allow(clippy::disallowed_methods, reason = "no sys::write_fd outside unix")]
pub(super) fn write_stdout(bytes: &[u8]) -> bool {
    use std::io::Write as _;
    std::io::stdout().write_all(bytes).is_ok()
}

#[cfg(test)]
mod tests;
