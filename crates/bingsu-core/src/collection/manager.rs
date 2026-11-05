//! Version manager resolvers (plan D2, spec section 4 "language versions",
//! row "read before running"; user decision U-12 R2: rustup and pyenv).
//!
//! When the language's command on the sanitized `PATH` is the shim of a
//! manager bingsu understands, the version can be read from the repository's
//! selection file instead of running anything, but only when every source of
//! precedence the manager has is known and the named version is installed.
//! Anything unknown turns the fast path off and the version command runs
//! (D3). This module is the pure part: the helper gathers the facts (the
//! shell environment, the manager's settings file, one install check) and
//! these rules decide. Nothing here touches a file.
use super::language::{lines, trim};
use alloc::vec::Vec;

/// The managers with a resolver (U-12 R2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Manager {
    Rustup,
    Pyenv,
}

impl Manager {
    /// The environment variable that overrides every selection file.
    pub const fn override_variable(self) -> &'static [u8] {
        match self {
            Self::Rustup => b"RUSTUP_TOOLCHAIN",
            Self::Pyenv => b"PYENV_VERSION",
        }
    }
}

/// The repository's selection for this manager, as language detection found
/// it (the helper maps the detection result here).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Selection<'a> {
    /// No selection file in the repository (ruling Q2 for D2: the folders
    /// above the repository root are not read).
    Absent,
    /// The nearest file exists but has no usable value (over its cap, not
    /// grammar-checked, malformed).
    Unusable,
    /// `rust-toolchain.toml` names a `path` toolchain (ruling Q4 for D2).
    Path,
    /// A grammar-checked name.
    Value(&'a [u8]),
}

/// Why a language's version is not shown at all.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Hidden {
    /// `rust-toolchain.toml` names a `path` toolchain: neither read nor run.
    ToolchainPath,
}

/// What to do with one language whose command is a known manager's shim.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Decision {
    /// Show this version without running anything.
    Fast(Vec<u8>),
    /// Run the version command (D3); with the toolchain name to select when
    /// one is known.
    Run(Option<Vec<u8>>),
    /// Show nothing; one diagnostic.
    Hidden(Hidden),
}

/// rustup's settings file, as far as the resolver needs it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Settings {
    /// Missing, unreadable or in a form these rules do not parse.
    Unknown,
    Known {
        /// `default_host_triple`, when the file names one (ruling Q5).
        host: Option<Vec<u8>>,
        /// A directory override (`rustup override set`) covers the shell's
        /// folder: it outranks every selection file.
        overridden: bool,
    },
}

/// The facts the helper gathered for one language.
#[derive(Clone, Copy, Debug)]
pub struct Facts<'a> {
    pub manager: Manager,
    /// Whether the manager's override variable is set in the shell
    /// environment; `None` when the environment did not reach the helper.
    pub override_set: Option<bool>,
    pub selection: Selection<'a>,
    /// rustup only; ignored for pyenv.
    pub settings: &'a Settings,
    /// rustup only: the target triple bingsu was built for, used when the
    /// settings name no `default_host_triple` (rustup leaves the key out
    /// when the host is its own; ruling Q8 for D2). A wrong guess only
    /// misses the install check, which then runs the command.
    pub build_host: &'a [u8],
}

/// The decision before the install check, or the folder to check.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Plan {
    Done(Decision),
    /// Open this one name below the manager's install folder (no-follow,
    /// a directory); then [`installed`] decides.
    Check {
        folder: Vec<u8>,
        name: Vec<u8>,
    },
}

/// The first half of the decision: everything that needs no file.
pub fn plan(f: &Facts<'_>) -> Plan {
    // An environment that did not arrive may hold the override.
    // Fails without it: decision_table (env unknown → run).
    let Some(override_set) = f.override_set else {
        return Plan::Done(Decision::Run(None));
    };
    // Fails without it: decision_table (override set → run).
    if override_set {
        return Plan::Done(Decision::Run(None));
    }
    if f.manager == Manager::Rustup {
        match f.settings {
            // Fails without it: decision_table (settings unknown → run).
            Settings::Unknown => return Plan::Done(Decision::Run(None)),
            // Fails without it: decision_table (override → run).
            Settings::Known {
                overridden: true, ..
            } => return Plan::Done(Decision::Run(None)),
            Settings::Known { .. } => {}
        }
    }
    let name = match f.selection {
        Selection::Absent | Selection::Unusable => {
            return Plan::Done(Decision::Run(None));
        }
        // Fails without it: decision_table (path → hidden).
        Selection::Path => return Plan::Done(Decision::Hidden(Hidden::ToolchainPath)),
        Selection::Value(name) => name,
    };
    match f.manager {
        Manager::Pyenv => {
            // pyenv's `system` is the Python outside pyenv, not a version.
            // Fails without it: decision_table (system → run).
            if name == b"system" {
                return Plan::Done(Decision::Run(None));
            }
            Plan::Check {
                folder: b"versions".to_vec(),
                name: name.to_vec(),
            }
        }
        Manager::Rustup => {
            let host = match f.settings {
                Settings::Known {
                    host: Some(host), ..
                } => host.as_slice(),
                // Fails without it: decision_table (no key → the build's
                // triple is checked).
                _ => f.build_host,
            };
            Plan::Check {
                folder: b"toolchains".to_vec(),
                name: [name, b"-", host].concat(),
            }
        }
    }
}

/// The second half: the install check's answer for the planned name.
/// `selected` is the selection's value.
pub fn installed(selected: &[u8], present: bool) -> Decision {
    // Fails without it: decision_table (missing install → run).
    if present && concrete(selected) {
        Decision::Fast(selected.to_vec())
    } else {
        Decision::Run(Some(selected.to_vec()))
    }
}

/// A name that is itself the version shown: `major.minor.patch`, digits
/// only. A channel (`stable`), a shortened name (`1.80`, `3.12`) or a
/// distribution (`pypy3.10-7.3.15`) is not a version until it runs.
pub fn concrete(name: &[u8]) -> bool {
    let mut parts = 0;
    // Fails without the count: concrete_names (`1.80` is not concrete).
    for part in name.split(|b| *b == b'.') {
        if part.is_empty() || !part.iter().all(|b| b.is_ascii_digit()) {
            return false;
        }
        parts += 1;
    }
    parts == 3
}

/// rustup's `settings.toml` (written by rustup itself): `bare = value` lines
/// at the top, and `"<folder>" = "<toolchain>"` lines under `[overrides]`.
/// An override covers its folder and every folder below it. Any other form
/// (another table, an escape in a quoted key, a value spread over lines) is
/// [`Settings::Unknown`].
pub fn rustup_settings(bytes: &[u8], cwd: &[u8]) -> Settings {
    match parse_settings(bytes, cwd) {
        Some(settings) => settings,
        None => Settings::Unknown,
    }
}

fn parse_settings(bytes: &[u8], cwd: &[u8]) -> Option<Settings> {
    let mut host = None;
    let mut overridden = false;
    let mut in_overrides = false;
    for l in lines(bytes) {
        if l.is_empty() || l.starts_with(b"#") {
            continue;
        }
        if l.starts_with(b"[") {
            // Fails without it: settings_forms (another table → unknown).
            if l != b"[overrides]" {
                return None;
            }
            in_overrides = true;
            continue;
        }
        let eq = l.iter().position(|b| *b == b'=')?;
        let (key, value) = (trim(&l[..eq]), trim(&l[eq + 1..]));
        if in_overrides {
            let folder = quoted(key)?;
            quoted(value)?;
            // Fails without it: settings_forms (an override above the
            // shell's folder covers it).
            if covers(folder, cwd) {
                overridden = true;
            }
            continue;
        }
        // Fails without it: settings_forms (a quoted top-level key → unknown).
        if key.is_empty()
            || !key
                .iter()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
        {
            return None;
        }
        // A value spread over lines would hide the next line's meaning.
        // Fails without it: settings_forms (open array → unknown).
        if (value.starts_with(b"[") && !value.ends_with(b"]"))
            || value.starts_with(b"\"\"\"")
            || value.starts_with(b"'''")
        {
            return None;
        }
        if key == b"default_host_triple" {
            host = Some(quoted(value)?.to_vec());
        }
    }
    Some(Settings::Known { host, overridden })
}

/// A basic string without escapes: its contents.
fn quoted(s: &[u8]) -> Option<&[u8]> {
    let inner = s.strip_prefix(b"\"")?.strip_suffix(b"\"")?;
    // Fails without it: settings_forms (escaped key → unknown).
    if inner.iter().any(|b| matches!(b, b'"' | b'\\')) {
        return None;
    }
    Some(inner)
}

/// `folder` is `cwd` or one of its parents, compared by whole components.
fn covers(folder: &[u8], cwd: &[u8]) -> bool {
    let folder = folder.strip_suffix(b"/").unwrap_or(folder);
    // Fails without the boundary: settings_forms (`/w/re` does not cover
    // `/w/repo`).
    cwd == folder || (cwd.starts_with(folder) && cwd[folder.len()] == b'/')
}
