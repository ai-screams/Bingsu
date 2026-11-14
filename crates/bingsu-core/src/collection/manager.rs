//! Version manager resolvers for rustup and pyenv.
//!
//! When the language's command on the sanitized `PATH` is the shim of a
//! manager bingsu understands, the version can be read from the repository's
//! selection file instead of running anything, but only when every source of
//! precedence the manager has is known and the named version is installed.
//! Anything unknown turns the fast path off and the version command runs
//! (D3). This module is the pure part: the helper gathers the facts (the
//! shell environment, the manager's settings file, one install check) and
//! these rules decide. Nothing here touches a file.
use super::language::{lines, trim, version_ok};
use alloc::vec::Vec;

/// The managers with a resolver.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Manager {
    Rustup,
    Pyenv,
}

impl Manager {
    /// Shell variables that change this manager's choice beyond what the
    /// rules model: the override itself and, for pyenv, where the search for
    /// `.python-version` starts (`PYENV_DIR`) and where hooks that may change
    /// the version name are found (`PYENV_HOOK_PATH`); see the pyenv README's
    /// environment variable table (https://github.com/pyenv/pyenv#environment-variables).
    /// Any of them set turns the fast path off.
    pub const fn precedence_variables(self) -> &'static [&'static [u8]] {
        match self {
            Self::Rustup => &[b"RUSTUP_TOOLCHAIN"],
            Self::Pyenv => &[b"PYENV_VERSION", b"PYENV_DIR", b"PYENV_HOOK_PATH"],
        }
    }
}

/// The repository's selection for this manager, as language detection found
/// it (the helper maps the detection result here).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Selection<'a> {
    /// No selection file in the repository (the folders
    /// above the repository root are not read).
    Absent,
    /// The nearest file exists but has no usable value (over its cap, not
    /// grammar-checked, malformed).
    Unusable,
    /// `rust-toolchain.toml` names a `path` toolchain.
    Path,
    /// A grammar-checked name.
    Value(&'a [u8]),
}

/// Why a language's version is not shown at all.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Hidden {
    /// `rust-toolchain.toml` names a `path` toolchain: neither read nor run.
    ToolchainPath,
    /// The manager's folders failed the trust rule, or a name in them is a
    /// link or not what it should be: neither read nor run.
    Untrusted,
}

/// The install check's answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Install {
    Present,
    /// Nothing by that name.
    Absent,
    /// A folder on the way fails the trust rule, or the name is a link or
    /// of the wrong kind.
    Untrusted,
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
        /// `default_host_triple`, when the file names one.
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
    /// Whether any of the manager's [`Manager::precedence_variables`] is set
    /// in the shell environment; `None` when the environment did not reach
    /// the helper whole.
    pub override_set: Option<bool>,
    pub selection: Selection<'a>,
    /// rustup only; ignored for pyenv.
    pub settings: &'a Settings,
    /// rustup only: the target triple bingsu was built for, used when the
    /// settings name no `default_host_triple` (rustup leaves the key out
    /// when the host is its own). A wrong guess only
    /// misses the install check, which then runs the command.
    pub build_host: &'a [u8],
}

/// The decision before the install check, or the folder to check.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Plan {
    Done(Decision),
    /// Open `<value>` (pyenv) or `<value>-<host>` (rustup) below `folder`
    /// in the manager's install folder (no-follow, a directory); then
    /// [`installed`] decides on `value`. Both parts passed the version
    /// grammar, so the name has no `/` and no `..`.
    Check {
        folder: Vec<u8>,
        value: Vec<u8>,
        host: Option<Vec<u8>>,
    },
}

/// What can be decided before any of the manager's files is read, in this
/// order: a path toolchain is hidden whatever else holds; an environment
/// that did not arrive, a precedence variable set, or no usable selection
/// runs the command. `None`: the files decide.
pub fn early(override_set: Option<bool>, selection: Selection<'_>) -> Option<Decision> {
    // Fails without the order: decision_table (path with no environment).
    if selection == Selection::Path {
        return Some(Decision::Hidden(Hidden::ToolchainPath));
    }
    // An environment that did not arrive may hold the override.
    // Fails without it: decision_table (env unknown → run).
    let Some(override_set) = override_set else {
        return Some(Decision::Run(None));
    };
    // Fails without it: decision_table (override set → run).
    if override_set {
        return Some(Decision::Run(None));
    }
    match selection {
        Selection::Absent | Selection::Unusable => Some(Decision::Run(None)),
        Selection::Path | Selection::Value(_) => None,
    }
}

/// The first half of the decision: [`early`], then the settings.
pub fn plan(f: &Facts<'_>) -> Plan {
    if let Some(decision) = early(f.override_set, f.selection) {
        return Plan::Done(decision);
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
    let Selection::Value(name) = f.selection else {
        // `early` answered every other selection.
        return Plan::Done(Decision::Run(None));
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
                value: name.to_vec(),
                host: None,
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
                value: name.to_vec(),
                host: Some(host.to_vec()),
            }
        }
    }
}

/// The second half: the install check's answer for the planned name.
/// `selected` is the selection's value. A folder that fails the trust rule
/// hides the value (it is neither shown nor run); a missing one runs the
/// command, which reports what is there.
pub fn installed(selected: &[u8], install: Install) -> Decision {
    match install {
        // Fails without it: install_check_decides_the_fast_path (untrusted
        // → hidden, not run).
        Install::Untrusted => Decision::Hidden(Hidden::Untrusted),
        // Fails without it: install_check_decides_the_fast_path (missing
        // install → run).
        Install::Present if concrete(selected) => Decision::Fast(selected.to_vec()),
        Install::Present | Install::Absent => Decision::Run(Some(selected.to_vec())),
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
            // A toolchain name rustup would use must pass the version
            // grammar (no path-shaped name from this file).
            // Fails without it: settings_forms (a path override value).
            if !version_ok(quoted(value)?) {
                return None;
            }
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
        // Only the value shapes rustup writes at the top: a basic string, a
        // boolean, an integer. An inline table (`overrides = { … }`, which
        // would hide overrides), an array, a multi-line string or anything
        // else is a form these rules do not read.
        // Fails without it: settings_forms (inline table, array, multi-line).
        if quoted(value).is_none() && !plain_scalar(value) {
            return None;
        }
        // Names this file gives (the host, the default toolchain) pass the
        // version grammar too; host tuples fit its 32 bytes. rustup 1.29
        // writes `default_host_tuple` and reads `default_host_triple` as an
        // alias; both at once is a duplicate field rustup itself refuses
        // (rustup 1.29.2: "could not parse settings file").
        // Fails without it: settings_forms (a host or default with `/`, the
        // tuple key, both keys).
        if matches!(
            key,
            b"default_host_tuple" | b"default_host_triple" | b"default_toolchain"
        ) {
            let name = quoted(value)?;
            if !version_ok(name) {
                return None;
            }
            if key != b"default_toolchain" {
                if host.is_some() {
                    return None;
                }
                host = Some(name.to_vec());
            }
        }
    }
    Some(Settings::Known { host, overridden })
}

/// `true`, `false` or a decimal integer.
fn plain_scalar(value: &[u8]) -> bool {
    value == b"true"
        || value == b"false"
        || (!value.is_empty() && value.iter().all(|b| b.is_ascii_digit()))
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
