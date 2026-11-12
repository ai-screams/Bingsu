//! `bingsu setup`: a first settings file, from two questions at most (icons,
//! background color) asked on the terminal (`/dev/tty`). The file is made
//! only when there is none: a temporary file in the settings folder
//! (`O_EXCL`, 0600), its data and the folder flushed, then `linkat`, which
//! cannot replace a name another process made in the meantime. When
//! `config.toml` is there, nothing is written and only the differences from
//! the starter are shown. The shell startup file is never edited: the line to
//! add is the only thing printed on stdout.
//!
//! Exit codes: 0 done (written, or already there), 1 refused or failed,
//! 2 usage, 130 cancelled.
use super::{
    ctx::{self, EXIT_FAILED, EXIT_USAGE, User},
    group_policy::SystemGroups,
    init::{roots, trusted_env::TrustedEnv},
    runtime_root::{self, Chain, RootError},
    sys,
    tty::{Reply, Tty},
};
use bingsu_core::color::osc11::{is_light, parse_osc11};
use bingsu_core::config::starter::{Choices, Icons, Mode, differences, starter};
use bingsu_core::fs_trust::Last;
use bingsu_core::icons::{IconSet, lookup};
use std::ffi::{OsStr, OsString};
use std::io::Read;
use std::os::fd::{AsFd, AsRawFd};
use std::path::Path;
use std::process::ExitCode;

const USAGE: &str = "usage: bingsu setup [--yes] [--icons nerd|unicode] [--mode auto|dark|light]";
const FILE: &str = "config.toml";
const CANCELLED: u8 = 130;

#[derive(Debug, Default, PartialEq, Eq)]
struct Args {
    yes: bool,
    icons: Option<Icons>,
    mode: Option<Mode>,
}

fn parse(args: &[OsString]) -> Result<Args, String> {
    let mut out = Args::default();
    let mut it = args.iter().map(|a| a.to_str());
    while let Some(word) = it.next() {
        match word {
            Some("--yes") => out.yes = true,
            Some("--icons") => {
                let v = it.next().flatten().and_then(Icons::parse);
                out.icons = Some(v.ok_or("--icons takes nerd or unicode")?);
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
        Ok(Reply::Bytes(b)) => {
            parse_osc11(&b).map(|c| if is_light(c) { Mode::Light } else { Mode::Dark })
        }
        Ok(Reply::Cancelled) => return None,
        Ok(Reply::Silent) | Err(_) => None,
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

enum Created {
    Wrote,
    /// `config.toml` appeared between the check and the link.
    Exists,
}

fn unique_name() -> OsString {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.subsec_nanos());
    format!(".{FILE}.setup-{}-{nanos}", std::process::id()).into()
}

/// Temporary file, data and folder flushed, then `linkat`.
fn create(chain: &Chain, text: &str) -> std::io::Result<Created> {
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
    dir.sync_all()?;
    Ok(made)
}

/// The bytes of `config.toml` (capped), `Ok(None)` when there is none, an
/// error when something is there that is not a plain file.
fn existing(chain: &Chain) -> std::io::Result<Option<Vec<u8>>> {
    let cap = bingsu_core::config::tree::FILE_BYTES_MAX as u64;
    match sys::open_data_at_nofollow(chain.last().as_fd(), OsStr::new(FILE)) {
        Ok(f) => {
            let mut bytes = Vec::new();
            f.take(cap + 1).read_to_end(&mut bytes)?;
            Ok(Some(bytes))
        }
        Err(e) if e.raw_os_error() == Some(libc::ENOENT) => Ok(None),
        Err(e) => Err(e),
    }
}

fn report_existing(path: &Path, bytes: std::io::Result<Option<Vec<u8>>>, c: Choices) {
    let shown = ctx::show(path);
    eprintln!("bingsu: {shown} is already there, so nothing was written.");
    match bytes {
        Ok(Some(b)) if b.len() <= bingsu_core::config::tree::FILE_BYTES_MAX => {
            match differences(&b, c) {
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
                None => eprintln!("It does not parse as TOML; `bingsu config check` says where."),
            }
        }
        _ => eprintln!("It could not be read to compare."),
    }
}

fn refuse(what: &str) -> ExitCode {
    eprintln!("bingsu setup: {what}");
    ctx::code(EXIT_FAILED)
}

pub fn run(args: &[OsString]) -> ExitCode {
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
    // Before `init` there is nothing pinned, and that is the usual time to run
    // `setup`: the folder then comes from the environment without a warning.
    let written = if TrustedEnv::pinned_roots().is_some() {
        match ctx::pinned_roots(&user) {
            Ok(Some(roots::Roots {
                config: Some(pin), ..
            })) => pin.written,
            Ok(_) => roots::config_candidate(&TrustedEnv::capture(), &user.pw.home),
            Err((text, code)) => {
                eprintln!("{text}");
                return ctx::code(code);
            }
        }
    } else {
        roots::config_candidate(&TrustedEnv::capture(), &user.pw.home)
    };
    let Some(dir) = roots::canonical_lenient(&written) else {
        return refuse("the settings folder cannot be placed (a `..` in its path?)");
    };

    // Choices: asked on the terminal, or all given.
    let choices = match (&tty, given) {
        (_, Some(c)) => c,
        (Some(t), None) => {
            let icons = match args.icons {
                Some(i) => i,
                None => match ask_icons(t) {
                    Some(i) => i,
                    None => return cancelled(),
                },
            };
            let mode = match args.mode {
                Some(m) => m,
                None => match ask_mode(t) {
                    Some(m) => m,
                    None => return cancelled(),
                },
            };
            Choices { icons, mode }
        }
        (None, None) => return ctx::code(EXIT_USAGE),
    };
    let path = dir.join(FILE);

    let mut groups = SystemGroups::new(&user.pw.name);
    let chain = match runtime_root::open_chain(&dir) {
        Ok(chain) => {
            let local = sys::fd_is_local(chain.last().as_raw_fd());
            if bingsu_core::fs_trust::walk_verdict(
                &chain.facts,
                user.me,
                Last::Mine,
                local,
                &mut groups,
            )
            .is_err()
            {
                return refuse(&format!(
                    "{} is not a folder only you can change; fix that first",
                    ctx::show(&dir)
                ));
            }
            Some(chain)
        }
        Err(RootError::Open { errno, .. }) if errno == libc::ENOENT => None,
        Err(_) => return refuse(&format!("{} cannot be used", ctx::show(&dir))),
    };
    if let Some(chain) = &chain {
        match existing(chain) {
            Ok(None) => {}
            other => {
                report_existing(&path, other, choices);
                return finish();
            }
        }
    }

    // Ask before the first write, unless told to go ahead.
    if !args.yes
        && let Some(t) = &tty
    {
        t.say(&format!("Write {}? [Y/n] ", ctx::show(&path)));
        match yes(t.line(), true) {
            Some(true) => {}
            Some(false) => {
                eprintln!("bingsu: nothing written.");
                return finish();
            }
            None => return cancelled(),
        }
    }
    let chain = match chain {
        Some(c) => c,
        None => match runtime_root::ensure_root(&dir, user.me, &mut groups, Last::Mine) {
            Ok(c) => c,
            Err(_) => return refuse(&format!("{} cannot be made", ctx::show(&dir))),
        },
    };
    match create(&chain, &starter(choices)) {
        Ok(Created::Wrote) => eprintln!("bingsu: wrote {}", ctx::show(&path)),
        Ok(Created::Exists) => report_existing(&path, existing(&chain), choices),
        Err(_) => return refuse(&format!("{} could not be written", ctx::show(&path))),
    }
    finish()
}

fn cancelled() -> ExitCode {
    eprintln!("bingsu: cancelled, nothing written.");
    ExitCode::from(CANCELLED)
}

/// The startup line on stdout, and a word on stderr about what it is.
fn finish() -> ExitCode {
    let shell = TrustedEnv::login_shell();
    eprintln!("Add this to your shell's startup file to start bingsu:");
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
    // 받는 것.
    #[test]
    fn arguments_are_read_strictly() {
        let a = parse(&args(&["--yes", "--icons", "nerd", "--mode", "light"])).unwrap();
        assert_eq!(
            a,
            Args {
                yes: true,
                icons: Some(Icons::Nerd),
                mode: Some(Mode::Light)
            }
        );
        for bad in [
            &["--icons", "emoji"][..],
            &["--icons"],
            &["--mode", "dim"],
            &["--mode"],
            &["extra"],
            &["--yes", "--icons=nerd"],
        ] {
            assert!(parse(&args(bad)).is_err(), "{bad:?}");
        }
    }

    // 이것을 실패시키는 것: 터미널 없이 기본값을 조용히 고르는 것, 빠진 인자를 이름으로 알리지 않는 것,
    // `--yes` 없이 쓰기로 넘어가는 것.
    #[test]
    fn without_a_terminal_all_three_must_be_given() {
        let all = Args {
            yes: true,
            icons: Some(Icons::Unicode),
            mode: Some(Mode::Auto),
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
    // 경쟁), 만든 파일의 권한이 0600이 아닌 것, 임시 파일을 남기는 것, 폴더에 `fsync`하지 않는 것은
    // 시험할 수 없어 제외.
    #[test]
    fn a_file_that_appeared_first_is_never_replaced() {
        let dir = scratch("race");
        let chain = runtime_root::open_chain(&dir).unwrap();
        // The fixture makes the file after the caller's check, before the link.
        std::fs::write(dir.join(FILE), b"theirs\n").unwrap();
        let got = create(&chain, "ours\n").unwrap();
        assert!(matches!(got, Created::Exists));
        assert_eq!(std::fs::read(dir.join(FILE)).unwrap(), b"theirs\n");
        let names: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(names, [OsString::from(FILE)], "a temporary file was left");
        // Without a rival the file is made, private, and no temporary stays.
        std::fs::remove_file(dir.join(FILE)).unwrap();
        assert!(matches!(create(&chain, "ours\n").unwrap(), Created::Wrote));
        let meta = std::fs::metadata(dir.join(FILE)).unwrap();
        assert_eq!(meta.permissions().mode() & 0o7777, 0o600);
        assert_eq!(std::fs::read(dir.join(FILE)).unwrap(), b"ours\n");
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    // 이것을 실패시키는 것: 파일이 없을 때 `None`이 아닌 것, 링크를 따라가 읽는 것(`O_NOFOLLOW`),
    // 파일이 있는데 있다고 알리지 않는 것.
    #[test]
    fn existing_is_none_only_when_there_is_no_file() {
        let dir = scratch("exists");
        let chain = runtime_root::open_chain(&dir).unwrap();
        assert!(matches!(existing(&chain), Ok(None)));
        std::fs::write(dir.join(FILE), b"icons = \"nerd\"\n").unwrap();
        assert_eq!(existing(&chain).unwrap().unwrap(), b"icons = \"nerd\"\n");
        std::fs::remove_file(dir.join(FILE)).unwrap();
        std::os::unix::fs::symlink("/etc/hosts", dir.join(FILE)).unwrap();
        assert!(existing(&chain).is_err(), "a link is not read");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
