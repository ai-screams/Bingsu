//! Fills script templates with shell-encoded words. Single pass: inserted
//! values are never rescanned, so a path containing "@CONFIG_ROOT@" stays
//! literal.
use crate::commands::messages::{MsgId, en};
use bingsu_core::record::RecordVersion;
use bingsu_core::root_arg::{
    CONFIG_ROOT_PREFIX, CONFIG_ROOT_SHAPE_ONLY, CONFIG_ROOT_WRITTEN_PREFIX, HOME_PREFIX,
    LOG_ROOT_PREFIX, RUNTIME_ROOT_PREFIX, STATE_ROOT_PREFIX,
};
use bingsu_core::shell_word::{Shell, encode_word};
use bingsu_core::status::Status;

pub struct ScriptInputs<'a> {
    pub shell: Shell,
    pub exe: &'a [u8],
    pub runtime_groups: &'a [bingsu_core::fs_trust::GroupPin],
    pub runtime_root: Option<(u64, u64, &'a [u8])>,
    /// `(canonical, written, shape_only)`. `None`: the path could not be
    /// confirmed; the words are left out. `shape_only` adds
    /// `--config-root-shape-only` after them.
    pub config_root: Option<(&'a [u8], &'a [u8], bool)>,
    pub state_root: Option<&'a [u8]>,
    pub log_root: Option<&'a [u8]>,
    pub session_hex: &'a [u8; 32],
    /// `pw_dir` from getpwuid, for the `~` of the dir segment.
    pub home: &'a [u8],
}

const ZSH: [&str; 2] = [
    include_str!("../../shell/zsh/reader.zsh"),
    include_str!("../../shell/zsh/hooks.zsh"),
];
const BASH: [&str; 2] = [
    include_str!("../../shell/bash/reader.bash"),
    include_str!("../../shell/bash/hooks.bash"),
];
const FISH: [&str; 2] = [
    include_str!("../../shell/fish/reader.fish"),
    include_str!("../../shell/fish/hooks.fish"),
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
        b"RUNTIME_GROUPS" => {
            if inp.runtime_root.is_some() {
                prefixed(
                    sh,
                    b"--runtime-groups=",
                    bingsu_core::helper::encode_groups(inp.runtime_groups).as_bytes(),
                    out,
                );
            }
        }
        b"CONFIG_ROOT" => {
            if let Some((canonical, written, shape_only)) = inp.config_root {
                prefixed(sh, CONFIG_ROOT_PREFIX, canonical, out);
                out.push(b' ');
                prefixed(sh, CONFIG_ROOT_WRITTEN_PREFIX, written, out);
                if shape_only {
                    out.push(b' ');
                    encode_word(sh, CONFIG_ROOT_SHAPE_ONLY, out);
                }
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
        b"HOME" => prefixed(sh, HOME_PREFIX, inp.home, out),
        b"MSG_BASH_TOO_OLD" => encode_word(sh, en(MsgId::BashTooOld).as_bytes(), out),
        b"MSG_LATE_HOOK_ZSH" => encode_word(sh, en(MsgId::LateHookZsh).as_bytes(), out),
        b"MSG_LATE_HOOK_BASH" => encode_word(sh, en(MsgId::LateHookBash).as_bytes(), out),
        b"MSG_NO_SANDBOX" => encode_word(sh, en(MsgId::NoSandbox).as_bytes(), out),
        b"STATUS_SANDBOX" => {
            let mut b = Vec::new();
            Status::DEGRADED_SANDBOX.write_to(&mut b);
            encode_word(sh, &b, out);
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use bingsu_core::layout::PATH_BYTES_MAX;

    fn script(shell: Shell, home: &[u8]) -> Vec<u8> {
        script_with(shell, home, Some((b"/c", b"/original/c", false)))
    }

    fn script_with(
        shell: Shell,
        home: &[u8],
        config_root: Option<(&[u8], &[u8], bool)>,
    ) -> Vec<u8> {
        let mut out = Vec::new();
        render(
            &ScriptInputs {
                shell,
                exe: b"/bin/bingsu",
                runtime_groups: &[],
                runtime_root: Some((1, 2, b"/r")),
                config_root,
                state_root: Some(b"/s"),
                log_root: Some(b"/l"),
                session_hex: &[b'0'; 32],
                home,
            },
            &mut out,
        );
        out
    }

    fn count(hay: &[u8], needle: &[u8]) -> usize {
        hay.windows(needle.len()).filter(|w| *w == needle).count()
    }

    // 이것을 실패시키는 것: 홈을 `prefixed`(셸 단어 인코딩) 없이 그대로 잇는 것, `@HOME@`을 남기는 것.
    // 이 인코딩의 셸 왕복은 test_init_words.py가 같은 함수(뿌리 단어)로 고정한다.
    #[test]
    fn home_is_one_encoded_word() {
        let home = b"/h/it's \"q\" $(x) `y` a\nb\\c -d";
        for shell in [Shell::Zsh, Shell::Bash, Shell::Fish] {
            let s = script(shell, home);
            let mut want = Vec::new();
            prefixed(shell, HOME_PREFIX, home, &mut want);
            assert_eq!(count(&s, &want), 1, "{shell:?}");
            assert_eq!(count(&s, b"@HOME@"), 0, "{shell:?}");
        }
    }

    // 이것을 실패시키는 것: 셸 인용된 작성 경로 또는 정규 경로를 전달하지 않는 것.
    #[test]
    fn config_root_handoff_keeps_both_paths() {
        for shell in [Shell::Zsh, Shell::Bash, Shell::Fish] {
            let s = script(shell, b"/home");
            for (prefix, path) in [
                (CONFIG_ROOT_PREFIX, &b"/c"[..]),
                (CONFIG_ROOT_WRITTEN_PREFIX, &b"/original/c"[..]),
            ] {
                let mut word = Vec::new();
                prefixed(shell, prefix, path, &mut word);
                assert_eq!(count(&s, &word), 1, "{shell:?}");
            }
        }
    }

    // 모양 전용 뿌리는 두 뿌리 단어와 표식 한 단어를 함께 넘기고, 보통 뿌리·버린 뿌리에는 표식이 없다.
    // 이것을 실패시키는 것: 표식을 빼는 것, 보통 뿌리에도 붙이는 것, 뿌리 없이 표식만 남기는 것.
    #[test]
    fn shape_only_root_adds_one_mark_word() {
        for shell in [Shell::Zsh, Shell::Bash, Shell::Fish] {
            let mut mark = Vec::new();
            encode_word(shell, CONFIG_ROOT_SHAPE_ONLY, &mut mark);
            let marked = script_with(shell, b"/h", Some((b"/c", b"/original/c", true)));
            assert_eq!(count(&marked, &mark), 1, "{shell:?}");
            let mut root = Vec::new();
            prefixed(shell, CONFIG_ROOT_PREFIX, b"/c", &mut root);
            assert_eq!(count(&marked, &root), 1, "{shell:?}");
            assert_eq!(count(&script(shell, b"/h"), &mark), 0, "{shell:?}");
            assert_eq!(
                count(&script_with(shell, b"/h", None), &mark),
                0,
                "{shell:?}"
            );
            assert_eq!(
                count(&script_with(shell, b"/h", None), &root),
                0,
                "{shell:?}"
            );
        }
    }

    // 이것을 실패시키는 것: 어느 셸이든 hook의 `$PWD` 상한(바이트)을 봉투의 PATH_BYTES_MAX와 다르게 두는 것.
    #[test]
    fn hook_pwd_cap_is_the_envelope_cap() {
        for (shell, cap) in [
            (
                Shell::Zsh,
                format!("${{#_bingsu_pwd}} <= {PATH_BYTES_MAX} ))"),
            ),
            (Shell::Bash, format!("(( _bingsu_n <= {PATH_BYTES_MAX} ))")),
            (
                Shell::Fish,
                format!("(_bingsu_bytes $PWD) -gt {PATH_BYTES_MAX}"),
            ),
        ] {
            let s = script(shell, b"/h");
            assert_eq!(
                count(&s, cap.as_bytes()),
                // bash shares the byte counter across pwd, host, venv and COLORFGBG.
                if shell == Shell::Bash { 4 } else { 1 },
                "{shell:?}"
            );
        }
    }
}
