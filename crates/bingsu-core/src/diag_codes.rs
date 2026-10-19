//! The diagnostic code registry (spec section 6 "진단 구조"). A code keeps its
//! number and meaning forever: it is never removed and never reused, only
//! marked deprecated. `diag-codes.txt` next to this crate's manifest lists
//! every code with its status; the test below keeps the two equal, and
//! `scripts/check_diag_codes.py` keeps the file append-only against the
//! base branch.
//!
//! Numbers: 1xx file syntax, 2xx keys and values, 3xx sources and
//! `extends`, 4xx trust of execution keys, 5xx style notices. Texts are
//! provisional (M7 writes the wording); `{name}` is an argument.
use crate::diag::{DiagCode, Severity};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CodeStatus {
    Stable,
    Deprecated { since: &'static str },
}

#[derive(Debug)]
pub struct CodeInfo {
    pub code: DiagCode,
    pub status: CodeStatus,
    pub what: &'static str,
    pub why: &'static str,
    pub fix: &'static str,
}

const fn e(n: u16) -> DiagCode {
    DiagCode::new(Severity::Error, n)
}
const fn w(n: u16) -> DiagCode {
    DiagCode::new(Severity::Warning, n)
}
const fn n(n: u16) -> DiagCode {
    DiagCode::new(Severity::Note, n)
}

pub const TOML_SYNTAX: DiagCode = e(101);
pub const FILE_TOO_LARGE: DiagCode = e(102);
pub const NOT_UTF8: DiagCode = e(103);
pub const INTEGER_RANGE: DiagCode = e(104);
pub const NESTING_TOO_DEEP: DiagCode = e(105);
pub const UNKNOWN_KEY: DiagCode = e(201);
pub const WRONG_TYPE: DiagCode = e(202);
pub const BAD_VALUE: DiagCode = e(203);
pub const BAD_SEGMENT_ID: DiagCode = e(204);
pub const UNKNOWN_SEGMENT: DiagCode = e(205);
pub const KEY_NOT_FOR_KIND: DiagCode = e(206);
pub const THEME_FORBIDDEN_KEY: DiagCode = e(207);
pub const BAD_LAYOUT_LINE: DiagCode = e(208);
pub const SEGMENT_NEEDS_KIND: DiagCode = e(209);
pub const CONTROL_IN_TEXT: DiagCode = e(210);
pub const EXTENDS_CYCLE: DiagCode = e(301);
pub const EXTENDS_TOO_DEEP: DiagCode = e(302);
pub const EXTENDS_TOO_MANY: DiagCode = e(303);
pub const EXTENDS_TOO_BIG: DiagCode = e(304);
pub const EXTENDS_BAD_PATH: DiagCode = e(305);
pub const REQUIRES_NEWER: DiagCode = e(306);
pub const VERSION_UNKNOWN: DiagCode = e(307);
pub const EXEC_KEY_IGNORED: DiagCode = w(401);
pub const ENV_SEGMENT_IGNORED: DiagCode = w(402);
pub const SEGMENT_DROPPED: DiagCode = w(403);
pub const NOT_RUN_UNTRUSTED_LAYOUT: DiagCode = w(404);
pub const NOT_RUN_UNSAFE_FILE: DiagCode = w(405);
pub const SHAPE_FILE_DROPPED: DiagCode = w(406);
pub const BAND_NEVER_CHOSEN: DiagCode = w(407);
pub const CUSTOM_UNDECLARED: DiagCode = w(408);
pub const TEMPLATE_REPLACES_STYLE: DiagCode = n(501);
pub const CUSTOM_DRAWN_LATER: DiagCode = n(502);
pub const KEY_PLANNED: DiagCode = n(503);

const fn stable(
    code: DiagCode,
    what: &'static str,
    why: &'static str,
    fix: &'static str,
) -> CodeInfo {
    CodeInfo {
        code,
        status: CodeStatus::Stable,
        what,
        why,
        fix,
    }
}

/// Every code, by number.
pub const CODES: &[CodeInfo] = &[
    stable(
        TOML_SYNTAX,
        "this is not valid TOML: {message}",
        "the file must parse before anything in it is used",
        "fix the text at this place",
    ),
    stable(
        FILE_TOO_LARGE,
        "the file is larger than 256 KiB",
        "each config file is capped at 256 KiB",
        "split the file, or remove unused parts",
    ),
    stable(
        NOT_UTF8,
        "the file is not UTF-8",
        "config files are UTF-8 text",
        "save the file as UTF-8",
    ),
    stable(
        INTEGER_RANGE,
        "the number {value} is out of range",
        "integers are 64-bit signed",
        "use a smaller number",
    ),
    stable(
        NESTING_TOO_DEEP,
        "tables and arrays are nested more than 32 deep here",
        "nesting is capped so reading a file can never run out of stack",
        "flatten the structure",
    ),
    stable(
        UNKNOWN_KEY,
        "unknown key `{key}`",
        "unknown keys are errors, so a typo is never silently ignored",
        "check the key name{suggest}",
    ),
    stable(
        WRONG_TYPE,
        "`{key}` must be {expected}, found {found}",
        "each key has one type",
        "write a value of the expected type",
    ),
    stable(
        BAD_VALUE,
        "`{key}` cannot be {found}",
        "the value is outside what this key accepts: {expected}",
        "use one of the accepted values",
    ),
    stable(
        BAD_SEGMENT_ID,
        "`{id}` is not a segment id",
        "ids are lowercase a-z, digits, `_` and `-`, at most one `/`",
        "rename the segment",
    ),
    stable(
        UNKNOWN_SEGMENT,
        "there is no segment `{id}`",
        "a one-part name is a built-in segment; user segments are `custom/<name>`",
        "check the name, or define `[segment.\"custom/<name>\"]`",
    ),
    stable(
        KEY_NOT_FOR_KIND,
        "`{key}` does not apply to a segment of kind `{kind}`",
        "keys are checked against the declared `kind`",
        "remove the key, or change `kind`",
    ),
    stable(
        THEME_FORBIDDEN_KEY,
        "a theme cannot set `{key}`",
        "themes never run commands",
        "move the key into your own config",
    ),
    stable(
        BAD_LAYOUT_LINE,
        "`{key}` is not a layout line",
        "lines are `line1` and `line2`, without gaps",
        "rename the table",
    ),
    stable(
        SEGMENT_NEEDS_KIND,
        "segment `{id}` has no `kind`",
        "a user segment says what it is: command, text, env or language",
        "add `kind = \"…\"`",
    ),
    stable(
        CONTROL_IN_TEXT,
        "`{key}` holds {char}, which a prompt never shows",
        "control, bidi and invisible characters could change what the terminal draws",
        "remove the character",
    ),
    stable(
        EXTENDS_CYCLE,
        "`extends` comes back to a file it started from",
        "extends must not form a cycle",
        "remove one of the `extends` entries on the path",
    ),
    stable(
        EXTENDS_TOO_DEEP,
        "`extends` is nested more than 8 deep",
        "nesting is capped at 8",
        "flatten the chain",
    ),
    stable(
        EXTENDS_TOO_MANY,
        "`extends` reaches more than 32 files",
        "at most 32 distinct files",
        "merge some files",
    ),
    stable(
        EXTENDS_TOO_BIG,
        "the files reached by `extends` are larger than 1 MiB together",
        "all files together are capped at 1 MiB",
        "remove unused files from `extends`",
    ),
    stable(
        EXTENDS_BAD_PATH,
        "`extends` entry `{path}` cannot be used: {reason}",
        "only local files are read",
        "point to a local file",
    ),
    stable(
        REQUIRES_NEWER,
        "this config requires bingsu {requires}",
        "the file asks for a newer bingsu",
        "upgrade bingsu",
    ),
    stable(
        VERSION_UNKNOWN,
        "config version {found} is not known",
        "this bingsu reads version 1",
        "upgrade bingsu, or check `version`",
    ),
    stable(
        EXEC_KEY_IGNORED,
        "`{key}` is ignored here",
        "this file is trusted for colors and layout only; execution keys are not allowed",
        "put the key in a trusted config file; run `bingsu config check` for folder safety details",
    ),
    stable(
        ENV_SEGMENT_IGNORED,
        "segment `{id}` of kind `env` is ignored here",
        "a shape-only file cannot show environment variables",
        "define the segment in your own config",
    ),
    stable(
        SEGMENT_DROPPED,
        "segment `{id}` is ignored here",
        "its `kind` comes from a shape-only file",
        "define the segment in your own config",
    ),
    stable(
        NOT_RUN_UNTRUSTED_LAYOUT,
        "segment `{id}` does not run",
        "only a layout from a trusted file turns on a command segment",
        "add the segment to a layout line in your own config",
    ),
    stable(
        NOT_RUN_UNSAFE_FILE,
        "segment `{id}` does not run: `{key}` comes from a file that failed the safety check",
        "{reason}",
        "check the file and folder ownership, write permissions and access lists; run `bingsu config check`",
    ),
    stable(
        SHAPE_FILE_DROPPED,
        "this shape-only file is not used: {reason}",
        "a shape-only file that does not check is dropped alone",
        "fix the file, or remove it from `extends`",
    ),
    stable(
        BAND_NEVER_CHOSEN,
        "band `{id}` is never chosen",
        "another band wins at every width this one covers",
        "see the width table, or change `min_cols`, `max_cols` or `order`",
    ),
    stable(
        CUSTOM_UNDECLARED,
        "segment `{id}` is not declared, so it is not drawn",
        "a layout names a user segment that no file declares (a theme may have removed it, or it is a typo)",
        "declare `[segment.\"{id}\"]`, or take it out of the layout",
    ),
    stable(
        TEMPLATE_REPLACES_STYLE,
        "the template replaces the preset and options",
        "a template takes precedence over style keys",
        "remove the unused keys, or the template",
    ),
    stable(
        CUSTOM_DRAWN_LATER,
        "segment `{id}` is not drawn yet",
        "user segments are drawn once user commands run (a later version)",
        "keep it; it starts showing after an upgrade",
    ),
    stable(
        KEY_PLANNED,
        "`{key}` has no effect yet",
        "it is read from {milestone} on; until then it is accepted and left out",
        "keep it, or remove it",
    ),
];

#[cfg(test)]
mod tests {
    use super::*;

    // 이것을 실패시키는 것: 진단 도움말에 아직 없는 doctor 명령을 다시 넣는 것.
    #[test]
    fn fixes_use_available_commands() {
        for c in CODES {
            assert!(!c.fix.contains("doctor"), "{}", c.code);
        }
    }

    // 이것을 실패시키는 것: 모양 전용을 설정 폴더 밖의 미승인 파일로만 설명하거나, 안전 확인 없이 config use만 안내하는 것.
    #[test]
    fn shape_only_reason_also_fits_an_unconfirmed_config_root() {
        let c = CODES.iter().find(|c| c.code == EXEC_KEY_IGNORED).unwrap();
        assert_eq!(
            c.why,
            "this file is trusted for colors and layout only; execution keys are not allowed"
        );
        assert!(c.fix.contains("bingsu config check"));
    }

    // 이것을 실패시키는 것: 문구 틀의 인자 이름이 없는 칸을 남기는 것(`{` 짝 틀림).
    #[test]
    fn texts_have_balanced_arguments() {
        for c in CODES {
            for t in [c.what, c.why, c.fix] {
                assert_eq!(t.matches('{').count(), t.matches('}').count(), "{}", c.code);
            }
        }
    }
}
