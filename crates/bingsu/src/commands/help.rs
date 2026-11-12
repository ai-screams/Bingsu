//! `bingsu help <code>`: the long explanation of one diagnostic code
//! (`bingsu_core::diag_help`). Reads nothing and writes only to stdout; an
//! unknown code or a missing argument is a usage error.
use bingsu_core::diag_help::{parse_code, render};
use std::ffi::OsString;
use std::process::ExitCode;

const USAGE: &str = "usage: bingsu help <code>   (a code such as E201, W404 or N501)";
const EXIT_USAGE: u8 = 2;

pub fn run(args: &[OsString]) -> ExitCode {
    let [word] = args else {
        eprintln!("{USAGE}");
        return ExitCode::from(EXIT_USAGE);
    };
    let Some(text) = word.to_str().and_then(parse_code).and_then(render) else {
        eprintln!(
            "bingsu help: unknown code `{}`",
            word.to_string_lossy().escape_debug()
        );
        eprintln!("{USAGE}");
        return ExitCode::from(EXIT_USAGE);
    };
    if write_stdout(text.as_bytes()) {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}

#[cfg(unix)]
fn write_stdout(bytes: &[u8]) -> bool {
    matches!(
        super::sys::write_fd(1, bytes),
        super::sys::WriteOutcome::Done
    )
}

// Windows has no `sys` module; a plain write is enough for a help text.
#[cfg(not(unix))]
#[allow(clippy::disallowed_methods, reason = "no sys::write_fd outside unix")]
fn write_stdout(bytes: &[u8]) -> bool {
    use std::io::Write as _;
    std::io::stdout().write_all(bytes).is_ok()
}

#[cfg(test)]
mod tests {
    use bingsu_core::diag_help::COMMANDS;

    fn source(text: &str) -> String {
        text.replace("\r\n", "\n")
    }

    // 이것을 실패시키는 것: COMMANDS에 CLI가 모르는 명령이나 하위 명령을 적는 것(진단 도움말이 없는 명령을 안내한다).
    #[test]
    fn every_command_a_hint_may_name_is_dispatched() {
        let top = source(include_str!("mod.rs"));
        let config = source(include_str!("config.rs"));
        for cmd in COMMANDS {
            let words: Vec<&str> = cmd.split(' ').collect();
            assert_eq!(words[0], "bingsu", "{cmd}");
            assert!(top.contains(&format!("Some(\"{}\")", words[1])), "{cmd}");
            if words[1] == "config" {
                assert!(config.contains(&format!("\"{}\"", words[2])), "{cmd}");
                if let Some(flag) = words.get(3) {
                    assert!(config.contains(&format!("\"{flag}\"")), "{cmd}");
                }
            }
        }
    }
}
