//! The long explanation of every diagnostic code, for `bingsu help <code>`.
//! The short frame of `diag` (`what`, `why`, `fix` of `diag_codes`) names
//! this place on one line; here each code gets three fields: what happened,
//! why bingsu treats it that way, and how to fix it. The texts are fixed (no
//! arguments), because `help` runs without a file.
//!
//! A `fix` field names the commands and config keys it refers to in
//! backticks (`bingsu config check`, `segment.<id>.command`). The registry
//! test in this file checks every such name against `COMMANDS` and the key
//! tables, so a renamed key or command fails the build instead of leaving a
//! stale hint.
use crate::diag::DiagCode;
use crate::diag_codes::{self as c, CODES, CodeStatus};
use alloc::string::String;
use core::fmt::Write as _;

/// The long explanation of one code.
#[derive(Debug)]
pub struct Help {
    pub code: DiagCode,
    /// What happened.
    pub what: &'static str,
    /// Why bingsu treats it that way.
    pub why: &'static str,
    /// How to fix it; names the commands and keys it refers to in backticks.
    pub fix: &'static str,
}

/// The commands a `fix` field may name, in the form a user types them
/// (a trailing argument such as `<path>` is left out). The CLI crate checks
/// that its dispatch knows every one.
pub const COMMANDS: &[&str] = &[
    "bingsu config check",
    "bingsu config check --explain",
    "bingsu config path",
    "bingsu config schema",
    "bingsu config schema --theme",
    "bingsu config use",
    "bingsu help",
    "bingsu init",
    "bingsu reload",
];

const fn h(code: DiagCode, what: &'static str, why: &'static str, fix: &'static str) -> Help {
    Help {
        code,
        what,
        why,
        fix,
    }
}

/// Every code, by number; the same order and set as `diag_codes::CODES`.
pub const HELP: &[Help] = &[
    h(
        c::TOML_SYNTAX,
        "The file is not valid TOML, so bingsu could not read it.\nThe place points at the first character the parser could not accept.",
        "Nothing in a file is used until the whole file parses. A half-read file could apply some settings and drop others without telling you.",
        "Fix the text at the place shown (a missing quote, bracket or `=` is the usual cause).\nThen run `bingsu config check` to read the file again.",
    ),
    h(
        c::FILE_TOO_LARGE,
        "The file is larger than 256 KiB.",
        "Every config file is capped at 256 KiB so that reading settings stays fast and bounded, even for a file someone else wrote.",
        "Remove unused parts, or move part of the settings into a second file and list it in `extends`.\nThen run `bingsu config check`.",
    ),
    h(
        c::NOT_UTF8,
        "The file contains bytes that are not valid UTF-8.",
        "Config files are UTF-8 text. Reading other encodings by guessing could change what a key or a value says.",
        "Save the file as UTF-8 in your editor, then run `bingsu config check`.",
    ),
    h(
        c::INTEGER_RANGE,
        "A whole number in the file is outside the 64-bit signed range (about 9.2 quintillion up or down).",
        "TOML integers are 64-bit signed. A larger number cannot be stored without changing its value.",
        "Write a smaller number. Most keys accept far smaller ranges; `bingsu config schema` lists the range of each key.",
    ),
    h(
        c::NESTING_TOO_DEEP,
        "Tables or arrays are nested more than 32 levels deep.",
        "The depth is capped so that reading a file can never run out of stack, whoever wrote the file.",
        "Flatten the structure. The config keys are at most a handful of levels deep; `bingsu config schema` shows the shape.",
    ),
    h(
        c::UNKNOWN_KEY,
        "A key in the file is not a bingsu key.",
        "Unknown keys are errors, so a typo such as `colr` never passes silently and leaves you wondering why nothing changed.",
        "Check the spelling against `bingsu config schema`. When a close key exists, the message suggests it.\nA key inside a user segment is written as `segment.<id>.command`, `segment.<id>.text` and so on.",
    ),
    h(
        c::WRONG_TYPE,
        "A key has a value of the wrong type, for example a number where a string is expected.",
        "Each key has exactly one type, so bingsu never has to guess what `\"5\"` or `5` means.",
        "Write a value of the expected type. `bingsu config schema` shows the type of each key.\nFor example `segment.<id>.timeout` takes a duration string such as \"200ms\".",
    ),
    h(
        c::BAD_VALUE,
        "A key has the right type but a value outside what the key accepts.",
        "Keys with a closed list of values (a preset, a shape, a mode) or a range (a cell count) reject anything else, so a typo cannot change behavior unnoticed.",
        "Use one of the accepted values listed in the message. For example `style.preset` takes a preset name and `width.ambiguous` takes 1 or 2.",
    ),
    h(
        c::BAD_SEGMENT_ID,
        "A segment name is not a valid id.",
        "An id is one part (a built-in segment) or two parts joined by one `/` (your own: `custom/<name>`).\nEach part is 1 to 32 bytes, starts with a lowercase letter a-z, holds only a-z, 0-9, `_` and `-`, and does not end in `_` or `-`.\nThe whole id is at most 65 bytes. The namespaces `bingsu`, `topping` and `file` are reserved, and so are the prefixes `topping:` and `file:`.\nThe limits keep ids safe to use in tables, layouts and file names.",
        "Rename the segment to fit these rules, in `layout.line1.left` and in its table `segment.<id>`. For example `custom/1foo`, `custom/foo-` and a 33-byte name are all refused.\nThen run `bingsu config check`.",
    ),
    h(
        c::UNKNOWN_SEGMENT,
        "A layout line names a segment that does not exist.",
        "A name without a slash is a built-in segment. Your own segments are named `custom/<name>`, so that a new built-in segment can never take the name of one of yours.",
        "Check the spelling of the name in `layout.line1.left` or `layout.line1.right`.\nFor a segment of your own, define the table `segment.<id>` with a `segment.<id>.kind`.",
    ),
    h(
        c::KEY_NOT_FOR_KIND,
        "A segment sets a key that does not apply to its kind.\nFor example `segment.<id>.command` on a segment of kind `text`.",
        "Keys are checked against the declared `kind`, so a key that would do nothing is reported instead of being ignored.",
        "Remove the key, or change `segment.<id>.kind` to a kind that uses it. `bingsu config schema` lists which kinds each key applies to.",
    ),
    h(
        c::THEME_FORBIDDEN_KEY,
        "A theme file sets a key that only a user config may set.",
        "A theme is shared with other people and never runs commands. Keys that run something or reach the environment are accepted only from your own config.",
        "Move the key into your own config file (`bingsu config path` shows where it is).\nFor a command segment, that means `segment.<id>.command`.",
    ),
    h(
        c::BAD_LAYOUT_LINE,
        "A table under `layout` is not an allowed line.\nEither its name is not `line1` or `line2`, or `layout.line2` is written without `layout.line1`.",
        "Lines are `line1` and `line2`, with no gaps: no other name can be drawn, and a second line needs a first. (A width band may write only its `line2`; it inherits the default `line1`.)",
        "Rename the table to `layout.line1` or `layout.line2`.\nIf you wrote only `layout.line2`, add `layout.line1` too, or move its segments to `layout.line1`.",
    ),
    h(
        c::SEGMENT_NEEDS_KIND,
        "A segment of your own has no `kind`.",
        "bingsu has to know whether the segment shows text, runs a command, shows an environment variable or reports a language before it can check its other keys.",
        "Add `segment.<id>.kind` with one of command, text, env or language.",
    ),
    h(
        c::CONTROL_IN_TEXT,
        "A text value contains a control, bidirectional or invisible character.",
        "Such characters can move the cursor, hide text or reorder what you read. A prompt never draws them, so a value that holds one is rejected.",
        "Remove the character. If you pasted the text, retype it. For the text of a segment the key is `segment.<id>.text`.",
    ),
    h(
        c::SHELL_NOT_ALLOWED,
        "A segment sets `shell` without `unsafe_shell = true`, so it does not run.",
        "Shell text runs whatever it says, with the shell's quoting rules. Running it only when you ask for it explicitly keeps a copied config from running a command you did not read.",
        "Write the command as an array in `segment.<id>.command`, for example `command = [\"tool\", \"arg\"]`.\nOr set `segment.<id>.unsafe_shell` to true if you need shell syntax.",
    ),
    h(
        c::COMMAND_FORM_CONFLICT,
        "A command segment does not give exactly one usable form. One of these is the case:\n`command` and `shell` are both set; neither is set; `command` is an empty array; or `unsafe_shell = true` is set without `shell`.",
        "The two forms run in different ways (no shell, or a shell), so bingsu will not choose one when both or neither are given, and a command with no word has nothing to run.",
        "Keep one form and make it complete: `segment.<id>.command` as an array with at least one word, or `segment.<id>.shell` together with `segment.<id>.unsafe_shell` set to true.\nDo not set `segment.<id>.unsafe_shell` without `segment.<id>.shell`.",
    ),
    h(
        c::PLACEHOLDER_NOT_WHOLE,
        "The placeholder `{dir}` is not a whole element of `command`, or sits inside shell text.",
        "The placeholder is replaced only as one whole element of the `command` array, and its value reaches the program as one argument that is never split or joined to other text.\nThis does not make the value safe for a program that reads its argument as code. With `command = [\"/bin/sh\", \"-c\", \"{dir}\"]` the shell reads the folder name as code, so a folder name with `$(...)` in it would run.",
        "Make the placeholder an element of its own in `segment.<id>.command`.\nFor example [\"tool\", \"{dir}\"] and not \"--dir={dir}\".\nDo not pass it to a shell or to another program that evaluates its argument as code (such as `sh -c` or `python -c`).",
    ),
    h(
        c::EXTENDS_CYCLE,
        "Files listed in `extends` lead back to a file already being read.",
        "A cycle has no first file, so there is no order in which to apply them.",
        "Remove one of the entries of `extends` on the path. `bingsu config check` prints the chain.",
    ),
    h(
        c::EXTENDS_TOO_DEEP,
        "The chain of `extends` is more than 8 files deep.",
        "The depth is capped so that reading settings stays bounded, however the files were written.",
        "Flatten the chain: list the files directly in one `extends`, or merge some of them.",
    ),
    h(
        c::EXTENDS_TOO_MANY,
        "The `extends` entries reach more than 32 distinct files.",
        "At most 32 files are read in one load, so a config cannot make every prompt read hundreds of files.",
        "Merge some files, then run `bingsu config check`. The `extends` list of each file shows what it pulls in.",
    ),
    h(
        c::EXTENDS_TOO_BIG,
        "The files reached by `extends` are larger than 1 MiB together.",
        "All files of one load are capped at 1 MiB together, in addition to the 256 KiB cap of each file.",
        "Remove files you do not use from `extends`, or cut unused settings.",
    ),
    h(
        c::EXTENDS_BAD_PATH,
        "An `extends` entry cannot be used, for example a URL or a path that cannot be read.",
        "Only local files are read, so an entry must name a file on this machine.",
        "Point the entry in `extends` at a local file, for example `~/dotfiles/bingsu-team.toml`, then run `bingsu config check`.",
    ),
    h(
        c::REQUIRES_NEWER,
        "The file asks for a newer bingsu than the one running.",
        "`requires` says which version a file was written for. Reading it with an older bingsu could ignore or misread keys it does not know.",
        "Upgrade bingsu, or lower `requires` if the file does not need the newer version.\nCheck your version with your package manager; `bingsu config check` tells you when a file needs more.",
    ),
    h(
        c::VERSION_UNKNOWN,
        "The `version` of the file is a number this bingsu does not know.",
        "This bingsu reads config format version 1. Another number means the file was written for a different format.",
        "Set `version` to 1, or upgrade bingsu if the file comes from a newer version.",
    ),
    h(
        c::ROOTS_NO_LONGER_MATCH,
        "A folder that `init` pinned in this shell is not the same folder now: the runtime folder was removed and made again, or a pinned folder is no longer safe.",
        "bingsu does not trust a folder again just because a folder with the same name exists. The prompt shows a notice until the shell pins the new one.",
        "Run `bingsu init` again in this shell, or open a new shell.",
    ),
    h(
        c::SETTINGS_INVALID,
        "Reading the settings finds an error, so no new settings are published.",
        "An error is never applied half way. The prompt keeps drawing with the last settings that checked out.",
        "Run `bingsu config check`, fix what it reports, then `bingsu reload`.",
    ),
    h(
        c::EXEC_KEY_IGNORED,
        "A key that runs something or reaches the environment is set in a shape-only file, so it is dropped.",
        "A shape-only file is read for colors and layout only; it may change how the prompt looks but never what runs.\nThemes, `extends` files outside your config folder, and every file in a config folder that `bingsu init` marked shape-only are shape-only.\nA file in your config folder whose own folder fails the safety check is a different case (W405).",
        "Put the key in your own config file in the config folder (`bingsu config path` shows where it is).\nRun `bingsu config check` for the details.",
    ),
    h(
        c::ENV_SEGMENT_IGNORED,
        "A segment of kind `env` is defined in a file that is trusted for colors and layout only, so it is ignored.",
        "Showing an environment variable can show a secret. Only your own config may decide which variable is shown.",
        "Define the segment in your own config with `segment.<id>.kind` and `segment.<id>.env`.",
    ),
    h(
        c::SEGMENT_DROPPED,
        "A segment is ignored because its `kind` comes from a file that is trusted for colors and layout only.",
        "The kind decides whether the segment runs a command or reads the environment, so it cannot be taken from a shape-only file.",
        "Define the segment in your own config, with `segment.<id>.kind` set there.",
    ),
    h(
        c::NOT_RUN_UNTRUSTED_LAYOUT,
        "A segment that runs a command or reads the environment (a command, env or language segment) is declared but not turned on.",
        "It runs only when a layout from a trusted file draws it, and that layout is still the one drawn after all files are merged, at a width some band can choose. One of these fails:\nno layout line names it; only a theme or another shape-only file names it; a shape-only file overrides the trusted layout so it no longer draws the segment; or the line is in a band that no width can choose.",
        "Name the segment in a layout line of your own config, for example `layout.line1.left`, or in a band line such as `layout.when.<name>.line1.left`.\nIf another file overrides the layout, set the layout in your own config. If the line is in a band, check `layout.when.<name>.min_cols`, `layout.when.<name>.max_cols` and `layout.when.<name>.order`.",
    ),
    h(
        c::NOT_RUN_UNSAFE_FILE,
        "A segment does not run because the file that sets one of its execution keys failed the safety check.",
        "A file or folder that another user can change could be edited to run something else. The check looks at the file and each folder above it: each must be owned by you or by root and must not be writable by anyone else.\nGroup write counts only when the group has no member besides you and root, and an access list entry that grants write fails the check.",
        "Find the file and folder the message names, then remove the extra write access from it, for example `chmod go-w`. Do not change the owner of system folders such as `/` or `/home`: root ownership is accepted there.\nRun `bingsu config check` for the exact reason.",
    ),
    h(
        c::SHAPE_FILE_DROPPED,
        "A shape-only file did not pass the checks, so it is left out of this load. The other files are still used.",
        "A file that is trusted for colors and layout only is dropped alone when it is broken, so one bad theme does not stop your whole prompt.",
        "Fix the file named in the message, or remove it from `extends`. Then run `bingsu config check`.",
    ),
    h(
        c::BAND_NEVER_CHOSEN,
        "A width band is never chosen: another band wins at every width this one covers.",
        "Bands are picked by width and then by `order`. A band that always loses does nothing, which is usually a mistake in its range.",
        "Change `layout.when.<name>.min_cols`, `layout.when.<name>.max_cols` or `layout.when.<name>.order`, or remove the band.",
    ),
    h(
        c::CUSTOM_UNDECLARED,
        "A layout names a segment of your own that no file declares, so it is not drawn.",
        "A theme may have removed the segment, or the name has a typo. Drawing nothing would hide the mistake, so it is reported.",
        "Declare the segment as the table `segment.<id>` with `segment.<id>.kind`, or take it out of `layout.line1.left` and the other layout keys.",
    ),
    h(
        c::UNSAFE_SHELL_USED,
        "A segment runs its `shell` text through a shell.",
        "Shell text can run anything it says, and nothing in it is quoted for you. This is allowed because you set `unsafe_shell = true`, and bingsu tells you so each time.",
        "Prefer `segment.<id>.command` as an array. Keep `segment.<id>.unsafe_shell` only where you need pipes, globs or other shell syntax.",
    ),
    h(
        c::CWD_UNTRUSTED_CURRENT,
        "A segment runs its command inside the current folder.",
        "Files in a folder you did not write, such as a cloned repository, can change what a command does (a local script with the same name, a config file the tool reads).",
        "Set `segment.<id>.cwd` to \"neutral\" (an empty private folder) and pass the folder as an element of `segment.<id>.command` if the command needs it.",
    ),
    h(
        c::ENV_SHEBANG,
        "A program that a segment would run is refused. The message gives the reason, which is one of these:\na script whose first line starts with `#!/usr/bin/env`, or names a relative interpreter, or is longer than 256 bytes, or holds a NUL byte, or names an interpreter that is setuid, setgid or has file capabilities;\nor the program itself is setuid, setgid or has file capabilities (a compiled program has no first line to fix).",
        "`#!/usr/bin/env python3` does name an absolute path, but `env` then looks `python3` up in `PATH`, which a folder you work in can influence, so it is refused. A set-id program or a file with capabilities runs with rights that bingsu will not hand to a prompt segment.",
        "For a script, write the absolute path of the interpreter on its first line, for example `#!/usr/bin/python3`, and keep that line under 256 bytes. Or run the interpreter itself from `segment.<id>.command`.\nFor a set-id program, use a different program in `segment.<id>.command`.",
    ),
    h(
        c::EXE_FOLDER_CHANGEABLE,
        "A folder on the way to the bingsu executable, or the file itself, can be changed by another user.\nThe check follows every symbolic link and every folder above the file.",
        "The prompt runs whatever file is at that path when a prompt starts. If another user can write there, they can make the prompt run their code as you.\nA folder that only you or root can write is fine; a folder shared with a group is fine when the group has no member besides you and root.",
        "Install bingsu under a folder that only you or root can change (a package manager folder owned by root is the usual choice), then run `bingsu init` again in your shell setup.",
    ),
    h(
        c::PATH_BINGSU_DIFFERS,
        "The `bingsu` that your shell finds on `PATH` is a different file from the executable that is running now.",
        "The hook that `init` wrote calls the path it pinned, not whatever `PATH` finds. After an install or an upgrade the two can differ, and then commands you type and the prompt come from different builds.",
        "Run `bingsu init` again from the bingsu you want to use, then open a new shell, or put that bingsu first on `PATH`.",
    ),
    h(
        c::NO_PINNED_ROOTS,
        "This shell has no pinned folders: `init` has not run in it.",
        "`init` pins the settings, state and runtime folders into the shell so that your commands act on the folders the prompt reads, even if `XDG_*` variables change later. Without the pin, commands read the current environment instead, which can differ.",
        "Add `bingsu init` for your shell to the end of your shell setup file and open a new shell.",
    ),
    h(
        c::SIBLING_UNVERIFIED,
        "`bingsu-collect` or `bingsu-prompt` next to the `bingsu` executable is missing, is not from this build, or sits in a folder that fails the safety check.",
        "The three executables must come from one build and live in one folder. Without a verified `bingsu-collect` no git or folder facts are collected. Without `bingsu-prompt` the hook calls `bingsu prompt`, which works but starts a larger program.",
        "Install the three executables from one build into one folder, then run `bingsu init` again.",
    ),
    h(
        c::NO_KERNEL_SECCOMP,
        "The kernel answers that it has no seccomp support.",
        "The prompt installs a system call filter around itself. Without kernel support the prompt still draws, and the filter is the only thing missing.",
        "Nothing in your settings changes this. Run a kernel built with seccomp; `bingsu config check` is not affected.",
    ),
    h(
        c::TEMPLATE_REPLACES_STYLE,
        "A `template` is set together with a preset or style options, and the template wins.",
        "A template takes precedence over the style keys, so the keys next to it have no effect.",
        "Remove the unused style keys, or remove `style.template`.",
    ),
    h(
        c::CUSTOM_DRAWN_LATER,
        "Deprecated since 0.0.0: bingsu no longer reports this note.\nIt used to say that a segment of your own was not drawn yet.",
        "Every kind of segment of your own is drawn now, so no segment is left waiting for a later version.",
        "Nothing to do. Run `bingsu config check` to see the notes that bingsu reports today.",
    ),
    h(
        c::KEY_PLANNED,
        "A key is accepted but has no effect yet.",
        "The key is read from a later milestone on. Until then it is accepted and left out, so a config written for the future does not fail today.",
        "Keep the key, or remove it. `bingsu config schema` marks which keys are planned.",
    ),
];

/// Parse a code as typed: a letter `E`, `W` or `N` (either case) and
/// three digits.
pub fn parse_code(text: &str) -> Option<DiagCode> {
    let b = text.as_bytes();
    if b.len() != 4 || !b[1..].iter().all(|d| d.is_ascii_digit()) {
        return None;
    }
    let number =
        u16::from(b[1] - b'0') * 100 + u16::from(b[2] - b'0') * 10 + u16::from(b[3] - b'0');
    let severity = match b[0].to_ascii_uppercase() {
        b'E' => crate::diag::Severity::Error,
        b'W' => crate::diag::Severity::Warning,
        b'N' => crate::diag::Severity::Note,
        _ => return None,
    };
    let code = DiagCode::new(severity, number);
    CODES.iter().any(|i| i.code == code).then_some(code)
}

/// The explanation of `code`, when it has one.
pub fn help(code: DiagCode) -> Option<&'static Help> {
    HELP.iter().find(|x| x.code == code)
}

fn field(out: &mut String, title: &str, text: &str) {
    out.push('\n');
    out.push_str(title);
    out.push('\n');
    for line in text.lines() {
        out.push_str("  ");
        out.push_str(line);
        out.push('\n');
    }
}

/// The text `bingsu help <code>` prints: the code and its severity, then the
/// three fields. A deprecated code says so on the first line.
pub fn render(code: DiagCode) -> Option<String> {
    let x = help(code)?;
    let info = code.info()?;
    let severity = match code.severity {
        crate::diag::Severity::Error => "error",
        crate::diag::Severity::Warning => "warning",
        crate::diag::Severity::Note => "note",
    };
    let mut out = String::new();
    let _ = write!(out, "{code} ({severity}");
    if let CodeStatus::Deprecated { since } = info.status {
        let _ = write!(out, ", deprecated since {since}");
    }
    out.push_str(")\n");
    field(&mut out, "What happened", x.what);
    field(&mut out, "Why", x.why);
    field(&mut out, "How to fix", x.fix);
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::keys;
    use crate::config::schema::META;

    /// The names a `fix` text puts in backticks: a command (`bingsu …`) or
    /// a dotted key. Anything with a space or a quote is an example value and
    /// is not a name.
    fn names(fix: &str) -> alloc::vec::Vec<&str> {
        fix.split('`')
            .skip(1)
            .step_by(2)
            .filter(|s| s.starts_with("bingsu ") || is_key(s))
            .collect()
    }

    fn is_key(s: &str) -> bool {
        !s.is_empty()
            && s.bytes().all(|b| {
                b.is_ascii_lowercase()
                    || matches!(b, b'_' | b'.' | b'<' | b'>' | b'-' | b'0'..=b'9')
            })
    }

    fn key_exists(name: &str) -> bool {
        if META.iter().any(|m| m.path == name) {
            return true;
        }
        // `<id>` stands for a name the user chooses, as `*` does in the table.
        let mut parts: alloc::vec::Vec<&str> = alloc::vec::Vec::new();
        for p in name.split('.') {
            parts.push(if p.starts_with('<') { "x" } else { p });
        }
        keys::lookup(&parts).is_some()
    }

    fn command_exists(name: &str) -> bool {
        // A trailing `<argument>` word is not part of the command.
        let words: alloc::vec::Vec<&str> =
            name.split(' ').filter(|w| !w.starts_with('<')).collect();
        COMMANDS.contains(&words.join(" ").as_str())
    }

    // 이것을 실패시키는 것: CODES에 코드를 더하고 HELP에 빠뜨리는 것(또는 순서·집합이 달라지는 것),
    // 세 칸 중 하나를 비우는 것, `fix` 칸에서 명령이나 설정 키를 가리키는 이름을 없애는 것,
    // 없는 키(`segment.<id>.comand`)나 없는 명령을 적는 것. 변이는 PR 본문 표에 있다.
    #[test]
    fn every_code_has_three_fields_and_its_fix_names_real_things() {
        assert_eq!(HELP.len(), CODES.len());
        for (x, info) in HELP.iter().zip(CODES) {
            assert_eq!(x.code, info.code, "same order as the registry");
            for (label, text) in [("what", x.what), ("why", x.why), ("fix", x.fix)] {
                assert!(!text.trim().is_empty(), "{} has no {label}", x.code);
            }
            let found = names(x.fix);
            assert!(!found.is_empty(), "{}: fix names no command or key", x.code);
            for n in found {
                let ok = if n.starts_with("bingsu ") {
                    command_exists(n)
                } else {
                    key_exists(n)
                };
                assert!(ok, "{}: `{n}` is not a command or a config key", x.code);
            }
            assert!(
                !x.fix.contains("doctor"),
                "{}: no doctor command yet",
                x.code
            );
        }
    }

    // 이것을 실패시키는 것: 대소문자 구분, 자릿수 검사, 레지스트리에 없는 번호를 받는 것.
    #[test]
    fn codes_parse_as_typed() {
        assert_eq!(parse_code("E201"), Some(c::UNKNOWN_KEY));
        assert_eq!(parse_code("e201"), Some(c::UNKNOWN_KEY));
        assert_eq!(parse_code("W411"), Some(c::ENV_SHEBANG));
        assert_eq!(parse_code("N503"), Some(c::KEY_PLANNED));
        for bad in [
            "", "E20", "E2011", "X201", "E999", "B101", "201", "E2a1", "E２01",
        ] {
            assert_eq!(parse_code(bad), None, "{bad}");
        }
    }

    // 이것을 실패시키는 것: 비활성 코드의 표시를 지우는 것.
    #[test]
    fn a_deprecated_code_says_so() {
        let text = render(c::CUSTOM_DRAWN_LATER).unwrap();
        assert!(
            text.starts_with("N502 (note, deprecated since 0.0.0)\n"),
            "{text}"
        );
    }

    // 이것을 실패시키는 것: 도움말 문구에 제어 문자나 ESC를 넣는 것(터미널로 그대로 나간다).
    #[test]
    fn texts_are_plain() {
        for x in HELP {
            for t in [x.what, x.why, x.fix] {
                assert!(
                    t.chars().all(|ch| ch == '\n' || !ch.is_control()),
                    "{}",
                    x.code
                );
            }
        }
    }
}
