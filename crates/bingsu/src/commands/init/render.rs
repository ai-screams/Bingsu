//! Fills script templates with shell-encoded words. Single pass: inserted
//! values are never rescanned, so a path containing "@CONFIG_ROOT@" stays
//! literal.
use crate::commands::messages::{MsgId, en};
use bingsu_core::record::RecordVersion;
use bingsu_core::root_arg::{
    CONFIG_ROOT_PREFIX, CONFIG_ROOT_SHAPE_ONLY, CONFIG_ROOT_WRITTEN_PREFIX, HELPER_EXE_PREFIX,
    HOME_PREFIX, LOG_ROOT_PREFIX, RUNTIME_ROOT_PREFIX, STATE_ROOT_PREFIX,
};
use bingsu_core::shell_word::{Shell, encode_word};
use bingsu_core::status::Status;

pub struct ScriptInputs<'a> {
    pub shell: Shell,
    pub exe: &'a [u8],
    /// The verified `bingsu-prompt` beside `exe`. `None`: the hook calls
    /// `exe prompt`, the slower entry that also links every other command.
    pub prompt_exe: Option<&'a [u8]>,
    pub collector_exe: Option<&'a [u8]>,
    pub runtime_groups: &'a [bingsu_core::fs_trust::GroupPin],
    pub runtime_root: Option<(u64, u64, &'a [u8])>,
    /// `(canonical, written, shape_only)`. `None`: the path could not be
    /// confirmed; the words are left out. `shape_only` adds
    /// `--config-root-shape-only` after them.
    pub config_root: Option<(&'a [u8], &'a [u8], bool)>,
    pub state_root: Option<&'a [u8]>,
    pub log_root: Option<&'a [u8]>,
    /// The pinned roots for the user's commands (`pinned::encode`); `None`
    /// clears any value an earlier init exported.
    pub roots_var: Option<&'a [u8]>,
    pub session_hex: &'a [u8; 32],
    /// `pw_dir` from getpwuid, for the `~` of the dir segment.
    pub home: &'a [u8],
    /// Validated init-time HOME/XDG_CONFIG_HOME or an invalid-input marker,
    /// independent of display home.
    /// Always emitted, including empty values, to distinguish legacy hooks.
    pub git_global_home: &'a [u8],
    pub git_global_xdg: &'a [u8],
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

/// Each known non-ok status with its fixed line.
const NOTICES: [(&[u8], Status, MsgId); 12] = [
    (b"BAD_ARGS", Status::ERROR_BAD_ARGS, MsgId::NoticeBadArgs),
    (b"INTERNAL", Status::ERROR_INTERNAL, MsgId::NoticeInternal),
    (
        b"RUNTIME_ROOT",
        Status::DEGRADED_RUNTIME_ROOT,
        MsgId::NoticeRuntimeRoot,
    ),
    (
        b"OVERSIZE",
        Status::DEGRADED_OVERSIZE,
        MsgId::NoticeOversize,
    ),
    (
        b"TRUST_UNVERIFIED",
        Status::DEGRADED_TRUST_UNVERIFIED,
        MsgId::NoticeTrustUnverified,
    ),
    (
        b"TRUST_EXPIRED",
        Status::DEGRADED_TRUST_EXPIRED,
        MsgId::NoticeTrustExpired,
    ),
    (
        b"TRUST_INVALID",
        Status::DEGRADED_TRUST_INVALID,
        MsgId::TrustInvalid,
    ),
    (
        b"TRUST_MISMATCH",
        Status::DEGRADED_TRUST_MISMATCH,
        MsgId::TrustMismatch,
    ),
    (
        b"TRUST_CLOCK",
        Status::DEGRADED_TRUST_CLOCK,
        MsgId::TrustClock,
    ),
    (b"SANDBOX", Status::DEGRADED_SANDBOX, MsgId::NoSandbox),
    (
        b"CONFIG_LAST_GOOD",
        Status::ERROR_CONFIG_LAST_GOOD,
        MsgId::NoticeConfigLastGood,
    ),
    (
        b"CONFIG_DEFAULT",
        Status::ERROR_CONFIG_DEFAULT,
        MsgId::NoticeConfigDefault,
    ),
];

// zsh expands the user's aliases when it parses a function body, and it parses
// all of `eval "$(bingsu init zsh)"` before running any of it, so an option set
// in the script is too late. The script is one quoted word instead, parsed by
// an eval that runs with aliases off. Every word here is quoted, because a
// global alias matches any unquoted word. Inside this function new globals
// are meant.
const ZSH_PRELUDE: &str = "() {\n  \\builtin \\setopt \\local_options \\no_aliases \\no_warn_create_global \\no_csh_junkie_quotes\n  \\builtin \\eval ";
const ZSH_EPILOGUE: &str = "\n}\n";

/// One `$'…'` word on one line: CSH_JUNKIE_QUOTES refuses a newline inside
/// plain quotes before anything in the script can turn the option off. For
/// the words in the body, which can hold a newline, the prelude turns it off.
fn zsh_ansi_word(text: &[u8], out: &mut Vec<u8>) {
    out.extend_from_slice(b"$'");
    for &b in text {
        match b {
            b'\\' => out.extend_from_slice(b"\\\\"),
            b'\'' => out.extend_from_slice(b"\\'"),
            b'\n' => out.extend_from_slice(b"\\n"),
            _ => out.push(b),
        }
    }
    out.push(b'\'');
}

fn prefixed(shell: Shell, prefix: &[u8], value: &[u8], out: &mut Vec<u8>) {
    let mut w = prefix.to_vec();
    w.extend_from_slice(value);
    encode_word(shell, &w, out);
}

fn emit(inp: &ScriptInputs<'_>, name: &[u8], out: &mut Vec<u8>) -> bool {
    let sh = inp.shell;
    match name {
        b"PROMPT_BIN" => encode_word(sh, inp.prompt_exe.unwrap_or(inp.exe), out),
        // The helper is `exe`, the path init pins, in either case. No one
        // checks that file when the prompt runs: whoever can edit the hook
        // can already run anything in the shell (as with argv0).
        b"HELPER_EXE" => prefixed(sh, HELPER_EXE_PREFIX, inp.exe, out),
        b"COLLECTOR_EXE" => {
            if let Some(exe) = inp.collector_exe {
                prefixed(sh, b"--collector-exe=", exe, out);
            }
        }
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
        b"GIT_GLOBAL_HOME" => prefixed(sh, b"--git-global-home=", inp.git_global_home, out),
        b"GIT_GLOBAL_XDG" => prefixed(sh, b"--git-global-xdg=", inp.git_global_xdg, out),
        b"MSG_BASH_TOO_OLD" => encode_word(sh, en(MsgId::BashTooOld).as_bytes(), out),
        b"MSG_LATE_HOOK_ZSH" => encode_word(sh, en(MsgId::LateHookZsh).as_bytes(), out),
        b"MSG_LATE_HOOK_BASH" => encode_word(sh, en(MsgId::LateHookBash).as_bytes(), out),
        b"MSG_NO_SANDBOX" => encode_word(sh, en(MsgId::NoSandbox).as_bytes(), out),
        b"MSG_NOTICE_GENERIC" => encode_word(sh, en(MsgId::NoticeGeneric).as_bytes(), out),
        b"MSG_NO_RECORD" => encode_word(sh, en(MsgId::NoRecord).as_bytes(), out),
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
        _ => return emit_notice(sh, name, out),
    }
    true
}

/// `@STATUS_<NAME>@` and `@MSG_NOTICE_<NAME>@`: the constants of the hooks'
/// notice chain.
fn emit_notice(sh: Shell, name: &[u8], out: &mut Vec<u8>) -> bool {
    let row = |suffix: &[u8]| NOTICES.iter().find(|(n, _, _)| *n == suffix);
    if let Some((_, status, _)) = name.strip_prefix(b"STATUS_").and_then(row) {
        let mut b = Vec::new();
        status.write_to(&mut b);
        encode_word(sh, &b, out);
        return true;
    }
    if let Some((_, _, id)) = name.strip_prefix(b"MSG_NOTICE_").and_then(row) {
        encode_word(sh, en(*id).as_bytes(), out);
        return true;
    }
    false
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
    if inp.shell == Shell::Zsh {
        let mut body = Vec::new();
        render_parts(inp, ZSH, &mut body);
        out.extend_from_slice(ZSH_PRELUDE.as_bytes());
        zsh_ansi_word(&body, out);
        out.extend_from_slice(ZSH_EPILOGUE.as_bytes());
        return;
    }
    let parts = if inp.shell == Shell::Bash { BASH } else { FISH };
    if inp.shell == Shell::Bash {
        out.extend_from_slice(BASH_PRELUDE.as_bytes());
    }
    render_parts(inp, parts, out);
    if inp.shell == Shell::Bash {
        substitute(inp, BASH_EPILOGUE.as_bytes(), out);
    }
}

fn render_parts(inp: &ScriptInputs<'_>, parts: [&str; 2], out: &mut Vec<u8>) {
    for t in parts {
        substitute(inp, t.as_bytes(), out);
        out.push(b'\n');
    }
    export_roots(inp, out);
}

/// One exported variable the commands read; a re-init replaces or clears it.
fn export_roots(inp: &ScriptInputs<'_>, out: &mut Vec<u8>) {
    let fish = inp.shell == Shell::Fish;
    match inp.roots_var {
        Some(v) => {
            out.extend_from_slice(if fish {
                b"set -gx BINGSU_ROOTS ".as_slice()
            } else {
                b"export BINGSU_ROOTS=".as_slice()
            });
            encode_word(inp.shell, v, out);
        }
        None => out.extend_from_slice(if fish {
            b"set -e BINGSU_ROOTS".as_slice()
        } else {
            b"unset BINGSU_ROOTS".as_slice()
        }),
    }
    out.push(b'\n');
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
        script_text(&inputs(shell, home, config_root), &mut out);
        out
    }

    fn inputs<'a>(
        shell: Shell,
        home: &'a [u8],
        config_root: Option<(&'a [u8], &'a [u8], bool)>,
    ) -> ScriptInputs<'a> {
        ScriptInputs {
            shell,
            exe: b"/bin/bingsu",
            prompt_exe: Some(b"/bin/bingsu-prompt"),
            collector_exe: Some(b"/bin/bingsu-collect"),
            runtime_groups: &[],
            runtime_root: Some((1, 2, b"/r")),
            config_root,
            state_root: Some(b"/s"),
            log_root: Some(b"/l"),
            roots_var: Some(b"5:a\nb'c"),
            session_hex: &[b'0'; 32],
            home,
            git_global_home: home,
            git_global_xdg: b"/xdg",
        }
    }

    fn sample(shell: Shell) -> ScriptInputs<'static> {
        inputs(shell, b"/h", Some((b"/c", b"/original/c", false)))
    }

    /// The text these tests read; zsh's output wraps it in one quoted word.
    fn script_text(inp: &ScriptInputs<'_>, out: &mut Vec<u8>) {
        if inp.shell == Shell::Zsh {
            render_parts(inp, ZSH, out);
        } else {
            render(inp, out);
        }
    }

    // 이것을 실패시키는 것: 본문을 줄바꿈이 든 따옴표로 내는 것(CSH_JUNKIE_QUOTES에서 파싱 실패), 치환이 빠진 본문을 내는 것.
    #[test]
    fn zsh_body_is_one_line_word() {
        let mut text = Vec::new();
        script_text(&sample(Shell::Zsh), &mut text);
        let mut word = Vec::new();
        zsh_ansi_word(&text, &mut word);
        assert_eq!(count(&word, b"\n"), 0);
        let mut out = Vec::new();
        render(&sample(Shell::Zsh), &mut out);
        assert_eq!(
            out,
            [ZSH_PRELUDE.as_bytes(), &word, ZSH_EPILOGUE.as_bytes()].concat()
        );
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

    // 이것을 실패시키는 것: 확인한 bingsu-prompt 대신 bingsu를 부르는 것, 형제가 없을 때
    // `bingsu prompt`로 돌아가지 않는 것, helper 단어를 빼거나 형제 경로로 쓰는 것, helper 단어를 프롬프트 호출 줄 밖에서
    // `bingsu_doctor` 함수 본문 말고 다른 곳에 더하거나 함수에서 두 번 쓰는 것(위치까지 센다).
    #[test]
    fn prompt_call_uses_the_verified_sibling_and_names_the_helper() {
        for shell in [Shell::Zsh, Shell::Bash, Shell::Fish] {
            for prompt_exe in [Some(b"/opt/bingsu-prompt".as_slice()), None] {
                let mut inp = sample(shell);
                inp.prompt_exe = prompt_exe;
                let mut s = Vec::new();
                script_text(&inp, &mut s);
                let mut call = Vec::new();
                encode_word(shell, prompt_exe.unwrap_or(b"/bin/bingsu"), &mut call);
                call.extend_from_slice(b" prompt ");
                assert_eq!(count(&s, &call), 1, "{shell:?} {prompt_exe:?}");
                let mut cli = Vec::new();
                encode_word(shell, b"/bin/bingsu", &mut cli);
                cli.extend_from_slice(b" prompt ");
                let want = usize::from(prompt_exe.is_none());
                assert_eq!(count(&s, &cli), want, "{shell:?} {prompt_exe:?}");
                let mut helper = Vec::new();
                prefixed(shell, HELPER_EXE_PREFIX, b"/bin/bingsu", &mut helper);
                // Where the word stands is fixed: once on the prompt call
                // line and, in zsh only, once in the body of `bingsu_doctor`
                // (the shell function that hands doctor its evidence); nowhere else.
                let text = String::from_utf8_lossy(&s).into_owned();
                let helper_text = String::from_utf8_lossy(&helper).into_owned();
                let (body_start, body_end) = match text.find("\nbingsu_doctor() {") {
                    Some(i) => (i, i + text[i..].find("\n}\n").expect("function end")),
                    None => (0, 0),
                };
                let in_body = text[body_start..body_end].matches(&helper_text).count();
                let in_call = text
                    .lines()
                    .filter(|l| l.contains(&helper_text) && l.contains(" prompt "))
                    .count();
                assert_eq!(in_call, 1, "{shell:?} {prompt_exe:?}");
                assert_eq!(in_body, usize::from(shell == Shell::Zsh), "{shell:?}");
                assert_eq!(
                    count(&s, &helper),
                    in_call + in_body,
                    "{shell:?} {prompt_exe:?}: the word stands only on the prompt call and in the doctor function"
                );
                assert_eq!(count(&s, HELPER_EXE_PREFIX), in_call + in_body, "{shell:?}");
            }
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

    // 고정 뿌리는 셸마다 한 번 내보내고(셸 단어 하나), 없으면 이전 init의 값을 지운다.
    // 이것을 실패시키는 것: 내보내기 줄을 빼거나 두 번 내는 것, 값을 셸 단어로 인코딩하지 않는 것, 뿌리가 없을 때 옛 값을 남기는 것.
    #[test]
    fn roots_variable_is_exported_once_or_cleared() {
        for shell in [Shell::Zsh, Shell::Bash, Shell::Fish] {
            let s = script(shell, b"/h");
            let mut want = if shell == Shell::Fish {
                b"set -gx BINGSU_ROOTS ".to_vec()
            } else {
                b"export BINGSU_ROOTS=".to_vec()
            };
            encode_word(shell, b"5:a\nb'c", &mut want);
            assert_eq!(count(&s, &want), 1, "{shell:?}");
            assert_eq!(count(&s, b"BINGSU_ROOTS"), 1, "{shell:?}");
            let mut out = Vec::new();
            script_text(
                &ScriptInputs {
                    shell,
                    exe: b"/bin/bingsu",
                    prompt_exe: None,
                    collector_exe: Some(b"/bin/bingsu-collect"),
                    runtime_groups: &[],
                    runtime_root: None,
                    config_root: None,
                    state_root: None,
                    log_root: None,
                    roots_var: None,
                    session_hex: &[b'0'; 32],
                    home: b"/h",
                    git_global_home: b"",
                    git_global_xdg: b"",
                },
                &mut out,
            );
            let clear: &[u8] = if shell == Shell::Fish {
                b"set -e BINGSU_ROOTS\n"
            } else {
                b"unset BINGSU_ROOTS\n"
            };
            assert_eq!(count(&out, clear), 1, "{shell:?}");
            assert_eq!(count(&out, b"BINGSU_ROOTS"), 1, "{shell:?}");
        }
    }

    // 이것을 실패시키는 것: 아는 상태를 표에서 빼거나 다른 상태에 묶는 것, 사슬에서 가지를 빼거나 다른 문구를 고르는 것.
    #[test]
    fn notice_chain_has_one_branch_per_known_status() {
        assert_eq!(NOTICES.len(), Status::KNOWN_NON_OK.len());
        let hooks = include_str!("../../shell/zsh/hooks.zsh");
        for (row, known) in NOTICES.iter().zip(Status::KNOWN_NON_OK) {
            assert_eq!(row.1, *known);
            let name = core::str::from_utf8(row.0).unwrap();
            let branch = format!(
                "elif [[ $_bingsu_note == @STATUS_{name}@ ]]; then print -u2 -r -- @MSG_NOTICE_{name}@\n"
            );
            assert_eq!(hooks.matches(&branch).count(), 1, "{name}");
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
