//! User segments and the units they run: which `custom/…` segments a layout
//! draws, their kind-specific forms (text, command, env, language), and the
//! execution units with the policy and the reason one does not run, and the
//! unit types themselves. A new segment kind is compiled here and needs its
//! keys in `keys.rs`; a kind that runs something (an execution unit) also
//! needs its line in `explain.rs`.
use super::layouts::{LayoutRef, drawn};
use super::values::{at, bad, boolean, entries, optional_duration, place_of, s, strings};
use crate::config::keys;
use crate::config::merge::{KeyClass, MNode, MTable, MValue, Origin};
use crate::config::source::Trust;
use crate::config::tree::Value;
use crate::diag::{Diagnostic, Place};
use crate::diag_codes as codes;
use crate::width::WidthProfile;
use alloc::collections::{BTreeMap, BTreeSet};
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

/// What a unit runs. Tagged, so the snapshot format (N1) carries both
/// kinds from the start; M6 fills the language keys and runs both.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExecPolicy {
    Command {
        argv: Vec<String>,
        cwd: Option<String>,
        env_allow: Vec<String>,
        shell: Option<String>,
        unsafe_shell: bool,
    },
    /// A user-defined language version: `interpreter`, its `version`
    /// arguments and the `detect_files` that mark the language's project
    /// (`language_form` checks them), with the folder it runs in and the
    /// variables it receives as a command's.
    Language {
        interpreter: Option<String>,
        version_argv: Vec<String>,
        detect_files: Vec<String>,
        cwd: Option<String>,
        env_allow: Vec<String>,
    },
}

/// Why a unit does not run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NotRun {
    /// `enabled = false` from a trusted file.
    Disabled,
    /// No drawn line of a trusted layout names it.
    NotInTrustedLayout,
    /// An execution key of it comes from a file that failed the safety
    /// check (owner, permissions).
    UnsafeFile { key: String },
    /// A reference names a band index the config does not have.
    UnknownBand,
    /// `shell` without `unsafe_shell = true` (an error, E211).
    ShellNotAllowed,
    /// `match` does not compile or passes the size limit (E203, decided by
    /// the CLI's `bingsu-match`, never by core).
    MatchInvalid,
}

/// One user segment that runs something, with its whole policy, where each
/// key came from, and the layout references that let it run.
#[derive(Clone, Debug, PartialEq)]
pub struct ExecUnit {
    pub id: String,
    pub policy: ExecPolicy,
    pub timeout_ms: Option<u64>,
    pub cache_ms: Option<u64>,
    /// Each execution key written for it and its origin.
    pub origins: Vec<(String, Origin)>,
    /// Where a trusted layout draws it (what allows it to run).
    pub approved_by: Vec<LayoutRef>,
    /// Where the full config draws it (what is on screen).
    pub shown_at: Vec<LayoutRef>,
    /// `None`: it runs.
    pub not_run: Option<NotRun>,
    /// A command segment's `match`: the helper applies it to the first line
    /// before publishing, the prompt compares its digest
    /// (`command::wire::pattern_digest`). Not in the policy digest, so a
    /// change of `match` alone runs nothing again.
    pub pattern: Option<String>,
}

/// Most user segments a config draws, text and command together (the
/// snapshot carries each one).
pub const MAX_CUSTOM_TEXT: usize = 256;

/// Command and language segments one config may draw: those a trusted
/// layout draws at some width and that may run (32 units, the
/// command response's `CONFIG_ENTRIES_MAX`, which holds only units that run). A
/// declared segment no layout draws is not counted.
pub const MAX_EXEC_UNITS: usize = 32;

/// A user `custom/…` segment a layout draws. Its segment number is
/// `field::BUILTIN.len()` plus its place in `CompiledConfig::custom`, which
/// is sorted by id; the one field is `value` (`field::CUSTOM_TEXT`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CustomSegment {
    pub id: String,
    pub kind: CustomKind,
}

/// What a user segment shows.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CustomKind {
    /// `kind = "text"`: its text, cut to the field's cells.
    Text(String),
    /// `kind = "command"`: the unit's value from the command response; a
    /// segment with no value draws nothing.
    Command,
    /// `kind = "env"`: the value of this variable in the prompt's own
    /// environment, cut like text; unset or empty draws nothing.
    Env(String),
    /// `kind = "language"`: the unit's version from the command response,
    /// as a command's value; a segment with no value draws nothing.
    Language,
}

/// The layouts a width can choose, for the trusted merge (what approves a
/// unit) and for the full merge (what is on screen).
pub(crate) struct Reach {
    approved: BTreeSet<Option<u16>>,
    shown: BTreeSet<Option<u16>>,
}

impl Reach {
    pub(super) fn new(approved: BTreeSet<Option<u16>>, shown: BTreeSet<Option<u16>>) -> Self {
        Self { approved, shown }
    }
}

/// Whether a unit with these references may run, judged on layout alone.
/// Every kind of unit goes through this one function. A reference counts only
/// where a width can choose that layout, since no other line is ever drawn.
pub(crate) fn layout_verdict(
    approved_by: &[LayoutRef],
    shown_at: &[LayoutRef],
    band_count: usize,
    reach: &Reach,
) -> Option<NotRun> {
    let refs = || approved_by.iter().chain(shown_at);
    if refs().any(|r| r.band.is_some_and(|b| usize::from(b) >= band_count)) {
        return Some(NotRun::UnknownBand);
    }
    let live =
        |v: &[LayoutRef], set: &BTreeSet<Option<u16>>| v.iter().any(|r| set.contains(&r.band));
    (!live(approved_by, &reach.approved) || !live(shown_at, &reach.shown))
        .then_some(NotRun::NotInTrustedLayout)
}

/// The user segment kinds a layout draws.
const DRAWN_KINDS: [&str; 4] = ["text", "command", "env", "language"];

/// Whether any `custom/…` segment is declared with a drawn kind.
pub(super) fn declares_custom(r: &MTable) -> bool {
    entries(r, &["segment"]).iter().any(|e| {
        e.key.starts_with("custom/")
            && matches!(&e.node.value, MValue::Table(t)
                if s(t, &["kind"]).is_some_and(|k| DRAWN_KINDS.contains(&k)))
    })
}

/// The `kind = "text"`, `"command"` and `"env"` segments some layout draws,
/// sorted by id. A segment turned off (`enabled = false`, or from a file
/// that failed the safety check) is not drawn; a missing `text` shows
/// nothing. A command segment carries no value here: the prompt fills it
/// from the command response, and draws nothing without one. An env segment
/// carries the name of its variable, which the prompt reads from its own
/// environment; like a command it shows only where a trusted layout draws
/// it (`layout_verdict`, `trusted` the references of the trusted merge), so
/// a repository's config cannot put the user's variables on screen.
pub(super) fn custom_segments(
    r: &MTable,
    drawn: &BTreeMap<String, Vec<LayoutRef>>,
    trusted: &BTreeMap<String, Vec<LayoutRef>>,
    band_count: usize,
    reach: &Reach,
    profile: WidthProfile,
    notes: &mut Vec<Diagnostic>,
) -> Result<Vec<CustomSegment>, Vec<Diagnostic>> {
    let mut out: Vec<CustomSegment> = Vec::new();
    for e in entries(r, &["segment"]) {
        let MValue::Table(t) = &e.node.value else {
            continue;
        };
        let Some(kind) = s(t, &["kind"]).filter(|k| DRAWN_KINDS.contains(k)) else {
            continue;
        };
        if !e.key.starts_with("custom/") || !drawn.contains_key(&e.key) {
            continue;
        }
        // `kind` and `enabled` are execution keys: one written by a file
        // that failed the safety check keeps the segment from being drawn.
        if unsafe_exec_key(&e.key, &exec_origins(&e.key, t), notes).is_some()
            || boolean(t, &["enabled"]) == Some(false)
        {
            continue;
        }
        if kind == "env" {
            let approved_by = trusted.get(&e.key).map_or(&[][..], |v| v.as_slice());
            let shown_at = drawn.get(&e.key).map_or(&[][..], |v| v.as_slice());
            if layout_verdict(approved_by, shown_at, band_count, reach).is_some() {
                notes.push(
                    Diagnostic::new(codes::NOT_RUN_UNTRUSTED_LAYOUT, at(&e.node))
                        .arg("id", e.key.clone()),
                );
                continue;
            }
        }
        out.push(CustomSegment {
            id: e.key.clone(),
            kind: if kind == "command" {
                CustomKind::Command
            } else if kind == "language" {
                CustomKind::Language
            } else if kind == "env" {
                // Checked as a variable name (`check::env_name`) before compile.
                CustomKind::Env(s(t, &["env"]).unwrap_or_default().into())
            } else {
                // Cut here, to the cells the field shows, so the stored text
                // is what the front draws and always fits the codec's byte
                // cap (`Clean` keeps at most `CUSTOM_TEXT_CELLS * 4` bytes).
                CustomKind::Text(
                    crate::field::Clean::new(
                        s(t, &["text"]).unwrap_or_default().as_bytes(),
                        crate::field::CUSTOM_TEXT_CELLS,
                        profile,
                    )
                    .as_str()
                    .into(),
                )
            },
        });
    }
    out.sort_by(|a, b| a.id.cmp(&b.id));
    out.dedup_by(|a, b| a.id == b.id);
    if out.len() > MAX_CUSTOM_TEXT {
        return Err(vec![bad(
            place_of(r, &["segment"]),
            "segment",
            &alloc::format!("{}", out.len()),
            "at most 256 drawn text, command and env segments",
        )]);
    }
    Ok(out)
}

/// Each execution key written for a segment and its origin.
fn exec_origins(id: &str, t: &MTable) -> Vec<(String, Origin)> {
    t.entries
        .iter()
        .filter(|k| keys::classify(&["segment", id, &k.key]) == KeyClass::Exec)
        .map(|k| (k.key.clone(), k.node.origin))
        .collect()
}

/// The first execution key written by a file that failed the safety check,
/// with the W405 note that says the segment is not used for it. Every kind
/// of segment, drawn text included, goes through this one judgement.
fn unsafe_exec_key(
    id: &str,
    origins: &[(String, Origin)],
    notes: &mut Vec<Diagnostic>,
) -> Option<String> {
    let (k, origin) = origins.iter().find(|(_, o)| o.trust == Trust::Unsafe)?;
    notes.push(
        Diagnostic::new(
            codes::NOT_RUN_UNSAFE_FILE,
            Place::Source {
                id: origin.source,
                span: origin.span,
            },
        )
        .arg("id", id)
        .arg("key", k.clone())
        .arg("reason", "the file failed the owner and permission check"),
    );
    Some(k.clone())
}

/// The placeholder this version replaces (`{branch}` and others come with
/// the facts they need).
const PLACEHOLDER: &str = "{dir}";

/// `env_allow` names that can be variable names and that a command may
/// receive, and the warning for `cwd = "untrusted-current"`: the same for a
/// command and a language segment.
fn env_and_cwd_form(id: &str, t: &MTable, notes: &mut Vec<Diagnostic>) {
    let item = |n: &MNode, span| Place::Source {
        id: n.origin.source,
        span,
    };
    if let Some(
        n @ MNode {
            value: MValue::Array(names),
            ..
        },
    ) = t.get("env_allow")
    {
        for w in names {
            if let Value::Str(v) = &w.value {
                if v.is_empty() || v.contains(['=', '\0']) {
                    notes.push(bad(
                        item(n, w.span),
                        "env_allow",
                        &alloc::format!("\"{v}\""),
                        "a variable name: not empty, without `=` or NUL",
                    ));
                } else if crate::command::grant::forbidden(v.as_bytes()) {
                    notes.push(bad(
                        item(n, w.span),
                        "env_allow",
                        &alloc::format!("\"{v}\""),
                        "a name a command may receive: loader, language and shell startup settings never pass",
                    ));
                }
            }
        }
    }
    if let Some(c) = t
        .get("cwd")
        .filter(|c| matches!(&c.value, MValue::Scalar(Value::Str(v)) if v == "untrusted-current"))
    {
        notes.push(Diagnostic::new(codes::CWD_UNTRUSTED_CURRENT, at(c)).arg("id", id));
    }
}

/// A language segment's shape (D3c rulings): `detect_files`, one to
/// `collection::language::NAMES_MAX` file names, each one path component
/// the worker can look for (`collection::language::name_ok`), none given
/// twice; `interpreter`, a word without NUL; `version`, words without NUL.
/// Problems are errors in `notes`.
fn language_form(id: &str, seg: &MNode, t: &MTable, notes: &mut Vec<Diagnostic>) {
    // Fails without it: language_keys_are_checked (a forbidden env_allow
    // name, the untrusted-current warning).
    env_and_cwd_form(id, t, notes);
    use crate::collection::language::{NAMES_MAX, name_ok};
    let item = |n: &MNode, span| Place::Source {
        id: n.origin.source,
        span,
    };
    match t.get("detect_files") {
        None => notes.push(bad(
            at(seg),
            "detect_files",
            "nothing",
            "the file names that mark this language's project",
        )),
        Some(
            n @ MNode {
                value: MValue::Array(names),
                ..
            },
        ) => {
            // Fails without it: language_keys_are_checked (empty, 17 names).
            if names.is_empty() || names.len() > NAMES_MAX {
                notes.push(bad(
                    at(n),
                    "detect_files",
                    &alloc::format!("{} names", names.len()),
                    "1 to 16 file names",
                ));
            }
            let mut seen: Vec<&str> = Vec::new();
            for w in names {
                let Value::Str(v) = &w.value else { continue };
                // Fails without it: language_keys_are_checked (a path, `..`,
                // a name given twice).
                if !name_ok(v.as_bytes()) {
                    notes.push(bad(
                        item(n, w.span),
                        "detect_files",
                        &alloc::format!("\"{v}\""),
                        "one file name: not empty, no `/` or NUL, not `.` or `..`, at most 255 bytes",
                    ));
                } else if seen.contains(&v.as_str()) {
                    notes.push(bad(
                        item(n, w.span),
                        "detect_files",
                        &alloc::format!("\"{v}\""),
                        "each name once",
                    ));
                }
                seen.push(v);
            }
        }
        Some(_) => {}
    }
    match t.get("interpreter") {
        None => notes.push(bad(
            at(seg),
            "interpreter",
            "nothing",
            "the program that prints the version",
        )),
        // Fails without it: language_keys_are_checked (an empty word, NUL).
        Some(
            n @ MNode {
                value: MValue::Scalar(Value::Str(v)),
                ..
            },
        ) if v.is_empty() || v.contains('\0') => notes.push(bad(
            at(n),
            "interpreter",
            &alloc::format!("\"{v}\""),
            "a program name or absolute path, not empty, without NUL",
        )),
        Some(_) => {}
    }
    if let Some(
        n @ MNode {
            value: MValue::Array(words),
            ..
        },
    ) = t.get("version")
    {
        for w in words {
            // Fails without it: language_keys_are_checked (NUL in an argument).
            if matches!(&w.value, Value::Str(v) if v.contains('\0')) {
                notes.push(bad(
                    item(n, w.span),
                    "version",
                    "an argument with NUL",
                    "arguments without NUL",
                ));
            }
        }
    }
}

/// The form rules of one `kind = "command"` segment (spec section 3 "사용자
/// 명령 실행 모델"): `command` or `shell`, never both; `shell` only with
/// `unsafe_shell = true`; one of the two, with at least one word; a placeholder only as one whole `command` element
/// and never in `shell`; `env_allow` names that can be variable names.
/// Problems are errors and warnings in `notes`; `true` when `shell` lacks its
/// explicit allowance, so the unit never runs.
fn command_form(id: &str, seg: &MNode, t: &MTable, notes: &mut Vec<Diagnostic>) -> bool {
    let shell = t.get("shell");
    let allow = t.get("unsafe_shell");
    let allowed = boolean(t, &["unsafe_shell"]) == Some(true);
    let item = |n: &MNode, span| Place::Source {
        id: n.origin.source,
        span,
    };
    let conflict = |n: &MNode, problem: &'static str| {
        Diagnostic::new(codes::COMMAND_FORM_CONFLICT, at(n))
            .arg("id", id)
            .arg("problem", problem)
    };
    let mid = |p: Place, place: &'static str| {
        Diagnostic::new(codes::PLACEHOLDER_NOT_WHOLE, p)
            .arg("id", id)
            .arg("placeholder", PLACEHOLDER)
            .arg("place", place)
    };
    if let (Some(sh), Some(_)) = (shell, t.get("command")) {
        notes.push(conflict(sh, "`command` and `shell` are both set"));
    }
    match (t.get("command"), shell) {
        (None, None) => notes.push(conflict(seg, "neither `command` nor `shell` is set")),
        (
            Some(
                c @ MNode {
                    value: MValue::Array(words),
                    ..
                },
            ),
            None,
        ) if words.is_empty() => notes.push(conflict(c, "`command` is empty")),
        _ => {}
    }
    if let (None, Some(a), true) = (shell, allow, allowed) {
        notes.push(conflict(a, "`unsafe_shell = true` is set without `shell`"));
    }
    if let Some(sh) = shell {
        if allowed {
            notes.push(Diagnostic::new(codes::UNSAFE_SHELL_USED, at(sh)).arg("id", id));
        } else {
            notes.push(Diagnostic::new(codes::SHELL_NOT_ALLOWED, at(sh)).arg("id", id));
        }
        if matches!(&sh.value, MValue::Scalar(Value::Str(v)) if v.contains(PLACEHOLDER)) {
            notes.push(mid(at(sh), "in `shell` text"));
        }
    }
    if let Some(
        n @ MNode {
            value: MValue::Array(words),
            ..
        },
    ) = t.get("command")
    {
        for w in words {
            if let Value::Str(v) = &w.value {
                if v != PLACEHOLDER && v.contains(PLACEHOLDER) {
                    notes.push(mid(item(n, w.span), "inside a longer element"));
                }
            }
        }
    }
    env_and_cwd_form(id, t, notes);
    shell.is_some() && !allowed
}

pub(super) fn exec_units(
    r: &MTable,
    trusted: &MTable,
    off: &BTreeSet<&str>,
    names: &[String],
    reach: &Reach,
    notes: &mut Vec<Diagnostic>,
) -> Result<Vec<ExecUnit>, Vec<Diagnostic>> {
    // A unit runs when a trusted layout draws it and it is still drawn.
    let (approved, shown) = (drawn(trusted, off, names), drawn(r, off, names));
    let mut out = Vec::new();
    for e in entries(r, &["segment"]) {
        let MValue::Table(t) = &e.node.value else {
            continue;
        };
        let str_of = |k: &str| match t.get(k).map(|n| &n.value) {
            Some(MValue::Scalar(Value::Str(v))) => Some(v.clone()),
            _ => None,
        };
        let list = |k: &str| match t.get(k) {
            Some(n) => strings(n),
            None => Vec::new(),
        };
        let policy = match str_of("kind").as_deref() {
            Some("command") => ExecPolicy::Command {
                argv: list("command"),
                cwd: str_of("cwd"),
                env_allow: list("env_allow"),
                shell: str_of("shell"),
                unsafe_shell: boolean(t, &["unsafe_shell"]) == Some(true),
            },
            Some("language") => ExecPolicy::Language {
                interpreter: str_of("interpreter"),
                version_argv: list("version"),
                detect_files: list("detect_files"),
                cwd: str_of("cwd"),
                env_allow: list("env_allow"),
            },
            _ => continue,
        };
        let place = at(&e.node);
        let origins = exec_origins(&e.key, t);
        let approved_by = approved.get(&e.key).cloned().unwrap_or_default();
        let shown_at = shown.get(&e.key).cloned().unwrap_or_default();
        // Only a command segment needs `command` or `shell`; a language
        // segment cannot hold them (E206).
        if matches!(&policy, ExecPolicy::Language { .. }) {
            language_form(&e.key, &e.node, t, notes);
        }
        let not_run = if matches!(&policy, ExecPolicy::Command { .. })
            && command_form(&e.key, &e.node, t, notes)
        {
            Some(NotRun::ShellNotAllowed)
        } else if let Some(k) = unsafe_exec_key(&e.key, &origins, notes) {
            Some(NotRun::UnsafeFile { key: k })
        } else if boolean(t, &["enabled"]) == Some(false) {
            Some(NotRun::Disabled)
        } else if let why @ Some(_) = layout_verdict(&approved_by, &shown_at, names.len(), reach) {
            notes.push(
                Diagnostic::new(codes::NOT_RUN_UNTRUSTED_LAYOUT, place).arg("id", e.key.clone()),
            );
            why
        } else {
            None
        };
        // `match` is a command key (keys.rs): a language segment that writes
        // it fails the check (E206) before it compiles.
        let pattern = str_of("match");
        out.push(ExecUnit {
            id: e.key.clone(),
            policy,
            timeout_ms: optional_duration(str_of("timeout").as_deref()),
            cache_ms: optional_duration(str_of("cache").as_deref()),
            origins,
            approved_by,
            shown_at,
            not_run,
            pattern,
        });
    }
    // Only units that may run count: drawn by a trusted layout at some
    // width (a field reference such as `{custom/x.value}` draws it too), not
    // turned off, and of a kind that runs. The prompt's display and the
    // helper's round decide with the same function (`plan::runnable`).
    // Fails without it: at_most_32_drawn_exec_units.
    let drawn = out
        .iter()
        .filter(|u| crate::command::plan::runnable(u).is_some())
        .count();
    if drawn > MAX_EXEC_UNITS {
        return Err(vec![bad(
            place_of(r, &["segment"]),
            "segment",
            &alloc::format!("{drawn} drawn"),
            "at most 32 drawn command and language segments",
        )]);
    }
    Ok(out)
}
