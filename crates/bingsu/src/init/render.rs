//! Fills script templates with shell-encoded words. Single pass: inserted
//! values are never rescanned, so a path containing "@CONFIG_ROOT@" stays
//! literal.
use crate::messages::{MsgId, en};
use bingsu_core::record::RecordVersion;
use bingsu_core::root_arg::{
    CONFIG_ROOT_PREFIX, LOG_ROOT_PREFIX, RUNTIME_ROOT_PREFIX, STATE_ROOT_PREFIX,
};
use bingsu_core::shell_word::{Shell, encode_word};
use bingsu_core::status::Status;

pub struct ScriptInputs<'a> {
    pub shell: Shell,
    pub exe: &'a [u8],
    pub runtime_root: Option<(u64, u64, &'a [u8])>,
    /// `None`: the path could not be confirmed; the word is left out.
    pub config_root: Option<&'a [u8]>,
    pub state_root: Option<&'a [u8]>,
    pub log_root: Option<&'a [u8]>,
    pub session_hex: &'a [u8; 32],
}

const ZSH: [&str; 2] = [
    include_str!("../shell/zsh/reader.zsh"),
    include_str!("../shell/zsh/hooks.zsh"),
];
const BASH: [&str; 2] = [
    include_str!("../shell/bash/reader.bash"),
    include_str!("../shell/bash/hooks.bash"),
];
const FISH: [&str; 2] = [
    include_str!("../shell/fish/reader.fish"),
    include_str!("../shell/fish/hooks.fish"),
];

// bash < 5.1: the init process cannot know the parent shell's version, so
// the script checks it and prints a fixed line instead of installing.
const BASH_PRELUDE: &str = "if (( BASH_VERSINFO[0] * 100 + BASH_VERSINFO[1] >= 501 )); then\n";
const BASH_EPILOGUE: &str = "else\n  printf '%s\\n' @MSG_BASH_TOO_OLD@ >&2\nfi\n";

fn prefixed(shell: Shell, prefix: &[u8], value: &[u8], out: &mut Vec<u8>) {
    let mut w = prefix.to_vec();
    w.extend_from_slice(value);
    encode_word(shell, &w, out);
}

fn emit(inp: &ScriptInputs<'_>, name: &[u8], out: &mut Vec<u8>) -> bool {
    let sh = inp.shell;
    match name {
        b"BIN" => encode_word(sh, inp.exe, out),
        b"RECORD" => encode_word(sh, RecordVersion::B1.as_str().as_bytes(), out),
        b"SESSION" => encode_word(sh, inp.session_hex, out),
        b"RUNTIME_ROOT" => {
            if let Some((dev, ino, path)) = inp.runtime_root {
                let mut v = format!("{dev}:{ino}:").into_bytes();
                v.extend_from_slice(path);
                prefixed(sh, RUNTIME_ROOT_PREFIX, &v, out);
            }
        }
        b"CONFIG_ROOT" => {
            if let Some(v) = inp.config_root {
                prefixed(sh, CONFIG_ROOT_PREFIX, v, out);
            }
        }
        b"STATE_ROOT" => {
            if let Some(v) = inp.state_root {
                prefixed(sh, STATE_ROOT_PREFIX, v, out);
            }
        }
        b"LOG_ROOT" => {
            if let Some(v) = inp.log_root {
                prefixed(sh, LOG_ROOT_PREFIX, v, out);
            }
        }
        b"MSG_BASH_TOO_OLD" => encode_word(sh, en(MsgId::BashTooOld).as_bytes(), out),
        b"MSG_LATE_HOOK_ZSH" => encode_word(sh, en(MsgId::LateHookZsh).as_bytes(), out),
        b"MSG_LATE_HOOK_BASH" => encode_word(sh, en(MsgId::LateHookBash).as_bytes(), out),
        b"KNOWN_CODES" => {
            for (n, s) in Status::KNOWN_NON_OK.iter().enumerate() {
                if n > 0 {
                    out.push(b' ');
                }
                let mut b = Vec::new();
                s.write_to(&mut b);
                encode_word(sh, &b, out);
            }
        }
        _ => return false,
    }
    true
}

fn substitute(inp: &ScriptInputs<'_>, tpl: &[u8], out: &mut Vec<u8>) {
    let mut i = 0;
    while i < tpl.len() {
        if tpl[i] == b'@' {
            if let Some(len) = tpl[i + 1..].iter().position(|&b| b == b'@') {
                let name = &tpl[i + 1..i + 1 + len];
                let is_marker =
                    !name.is_empty() && name.iter().all(|&b| b.is_ascii_uppercase() || b == b'_');
                if is_marker && emit(inp, name, out) {
                    i += len + 2;
                    continue;
                }
            }
        }
        out.push(tpl[i]);
        i += 1;
    }
}

pub fn render(inp: &ScriptInputs<'_>, out: &mut Vec<u8>) {
    let parts = match inp.shell {
        Shell::Zsh => ZSH,
        Shell::Bash => BASH,
        Shell::Fish => FISH,
    };
    if inp.shell == Shell::Bash {
        out.extend_from_slice(BASH_PRELUDE.as_bytes());
    }
    for t in parts {
        substitute(inp, t.as_bytes(), out);
        out.push(b'\n');
    }
    if inp.shell == Shell::Bash {
        substitute(inp, BASH_EPILOGUE.as_bytes(), out);
    }
}
