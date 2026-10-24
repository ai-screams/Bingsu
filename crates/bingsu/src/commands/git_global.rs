//! Trusted helper input only. Never consult the repository or spawn Git.
//! Keep this independent of gix: the prompt's dependency graph stays fixed.
use super::sys;
use bingsu_core::collection::wire::{GLOBAL_EXCLUDES_MAX, Request};
use std::{
    ffi::OsStr,
    io::Read,
    os::unix::{ffi::OsStrExt, fs::OpenOptionsExt},
    path::{Component, Path, PathBuf},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Reason {
    Loaded,
    Missing,
    Unreadable,
    UnsafePath,
    Special,
    ForeignOwner,
    TooLarge,
    Changed,
    InvalidConfig,
    ConditionalConfig,
    IncludeDepth,
    ConfigBudget,
    UnsupportedPath,
    RequestBudget,
}
impl Reason {
    pub(crate) fn known(self) -> bool {
        matches!(self, Self::Loaded | Self::Missing)
    }

    pub(crate) fn log_level(self) -> bingsu_core::envelope::LogLevel {
        if self == Self::Loaded {
            bingsu_core::envelope::LogLevel::DebugLog
        } else {
            bingsu_core::envelope::LogLevel::Info
        }
    }

    pub(crate) fn message(self) -> &'static str {
        match self {
            Self::Loaded => "global excludes: loaded",
            Self::Missing => "global excludes: missing; using empty input",
            Self::Unreadable => "global excludes: unreadable; using empty input",
            Self::UnsafePath => "global excludes: unsafe path; using empty input",
            Self::Special => "global excludes: source is not a regular file; using empty input",
            Self::ForeignOwner => {
                "global excludes: source owner is neither the effective user nor root; using empty input"
            }
            Self::TooLarge => "global excludes: file exceeds 64 KiB; using empty input",
            Self::Changed => "global excludes: file changed; using empty input",
            Self::InvalidConfig => "global excludes: invalid global config; using empty input",
            Self::ConditionalConfig => {
                "global excludes: unevaluated includeIf changes core.excludesFile; using empty input"
            }
            Self::IncludeDepth => {
                "global excludes: config includes exceed depth 10; using empty input"
            }
            Self::ConfigBudget => {
                "global excludes: config sources exceed 256 KiB total; using empty input"
            }
            Self::UnsupportedPath => {
                "global excludes: unsupported path expansion; using empty input"
            }
            Self::RequestBudget => "global excludes: request budget; using empty input",
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Input {
    pub bytes: Vec<u8>,
    pub reason: Reason,
}

/// The shell passes init-pinned locations because the helper is spawned with
/// an empty environment. Old hooks omit both fields and retain their pinned
/// --home; an explicitly empty init-time HOME is not silently replaced.
pub(crate) fn attach(request: &mut Request, e: &bingsu_core::envelope::Envelope) -> Reason {
    if request.binding.mask & (1 << bingsu_core::collection::git::SEGMENT) == 0 {
        return Reason::Missing;
    }
    let input = load(
        e.git_global_home.as_deref().or(e.home.as_deref()),
        e.git_global_xdg.as_deref(),
    );
    request.global_excludes_known = input.reason.known();
    request.global_excludes = input.bytes;
    // Long binding paths still collect normally; never truncate patterns.
    if request.encode_body().is_err() {
        request.global_excludes.clear();
        request.global_excludes_known = false;
        Reason::RequestBudget
    } else {
        input.reason
    }
}

pub(crate) fn load(home: Option<&[u8]>, xdg: Option<&[u8]>) -> Input {
    match resolve(home, xdg).and_then(|path| read(&path)) {
        Ok(bytes) => Input {
            bytes,
            reason: Reason::Loaded,
        },
        Err(reason) => Input {
            bytes: Vec::new(),
            reason,
        },
    }
}

fn absolute(bytes: &[u8]) -> Result<PathBuf, Reason> {
    let path = Path::new(OsStr::from_bytes(bytes));
    if bytes.len() > 65_536
        || bytes.contains(&0)
        || !path.is_absolute()
        || path.components().any(|c| matches!(c, Component::ParentDir))
    {
        return Err(Reason::UnsafePath);
    }
    Ok(path.to_path_buf())
}

fn resolve(home: Option<&[u8]>, xdg: Option<&[u8]>) -> Result<PathBuf, Reason> {
    let home = home.filter(|v| !v.is_empty()).map(absolute).transpose()?;
    let xdg = xdg
        .filter(|v| !v.is_empty())
        .map(absolute)
        .transpose()?
        .or_else(|| home.as_ref().map(|p| p.join(".config")));
    let mut result = Config::default();
    let mut failed_source = None;
    let mut remaining = CONFIG_TOTAL_MAX;
    // Git reads both global files, with ~/.gitconfig taking precedence. A bad
    // source must not hide an answer supplied by the other global config.
    for path in [
        xdg.as_ref().map(|p| p.join("git/config")),
        home.as_ref().map(|p| p.join(".gitconfig")),
    ]
    .into_iter()
    .flatten()
    {
        match config(&path, home.as_deref(), 0, &mut remaining) {
            Ok(next) => result.append(next),
            Err(Reason::Missing) => {}
            Err(reason) => failed_source = Some(reason),
        }
    }
    if let Some(reason) = result.error {
        return Err(reason);
    }
    if result.selected.is_none()
        && let Some(reason) = failed_source
    {
        return Err(reason);
    }
    let chosen = match result.selected {
        Some(value) => excludes_path(&value, home.as_deref()),
        None => xdg.map(|p| p.join("git/ignore")).ok_or(Reason::Missing),
    };
    // The request carries cwd, not the discovered gitdir. Neither gitdir:
    // nor gitdir/i: can be evaluated from cwd (nested and linked worktrees).
    // Do not discover/read repository metadata here. Compare all possible
    // includeIf outcomes to the final unconditional result instead.
    for alternative in result.conditional {
        if excludes_path(&alternative, home.as_deref()) != chosen {
            return Err(Reason::ConditionalConfig);
        }
    }
    chosen
}

fn excludes_path(value: &[u8], home: Option<&Path>) -> Result<PathBuf, Reason> {
    if value.is_empty() {
        return Err(Reason::Missing);
    }
    if let Some(suffix) = value.strip_prefix(b"~/") {
        let home = home.ok_or(Reason::UnsupportedPath)?;
        // Concatenate like Git: ~// must not discard HOME.
        let mut path = home.as_os_str().as_bytes().to_vec();
        path.push(b'/');
        path.extend_from_slice(suffix);
        return absolute(&path);
    }
    // Relative excludes paths depend on repository setup. ~user and Git's
    // installation prefix likewise have no authority in this protocol.
    if !value.starts_with(b"/") {
        return Err(Reason::UnsupportedPath);
    }
    absolute(value)
}

const CONFIG_TOTAL_MAX: usize = 262_144;
const INCLUDE_DEPTH_MAX: usize = 10;

#[derive(Default)]
struct Config {
    selected: Option<Vec<u8>>,
    conditional: Vec<Vec<u8>>,
    error: Option<Reason>,
}
impl Config {
    fn append(&mut self, next: Self) {
        if next.selected.is_some() {
            self.selected = next.selected;
            // A later unconditional assignment overrides earlier includes,
            // including uncertainty. Source order is Git's insertion order.
            self.conditional.clear();
            self.error = None;
        }
        self.conditional.extend(next.conditional);
        self.error = next.error.or(self.error);
    }
}

fn config(
    path: &Path,
    home: Option<&Path>,
    depth: usize,
    remaining: &mut usize,
) -> Result<Config, Reason> {
    if depth > INCLUDE_DEPTH_MAX {
        return Err(Reason::IncludeDepth);
    }
    let bytes =
        read_bounded(path, (*remaining).min(GLOBAL_EXCLUDES_MAX), |_| {}).map_err(|reason| {
            if reason == Reason::TooLarge && *remaining < GLOBAL_EXCLUDES_MAX {
                Reason::ConfigBudget
            } else {
                reason
            }
        })?;
    *remaining -= bytes.len();
    let mut result = Config::default();
    parse_config(&bytes, |entry| {
        match entry {
            Entry::Excludes(value) => result.append(Config {
                selected: Some(value),
                ..Default::default()
            }),
            Entry::Include { value, conditional } => {
                let target = if value.starts_with(b"/") || value.starts_with(b"~") {
                    excludes_path(&value, home)
                } else if value.is_empty() {
                    Err(Reason::Missing)
                } else {
                    // Include paths, unlike excludes paths, are relative to
                    // the including file. The kernel resolves links and .. .
                    Ok(path
                        .parent()
                        .ok_or(Reason::UnsafePath)?
                        .join(OsStr::from_bytes(&value)))
                };
                match target.and_then(|target| config(&target, home, depth + 1, remaining)) {
                    Ok(mut included) => {
                        if conditional {
                            // No excludes assignment means this include is
                            // irrelevant, even if its condition is unknown.
                            result.conditional.extend(included.selected.take());
                            result.conditional.extend(included.conditional);
                            result.error = included.error.or(result.error);
                        } else {
                            result.append(included);
                        }
                    }
                    Err(Reason::Missing) => {}
                    Err(reason) => result.error = Some(reason),
                }
            }
        }
        Ok(())
    })?;
    Ok(result)
}

fn io_reason(error: std::io::Error) -> Reason {
    match error.raw_os_error() {
        Some(libc::ENOENT) => Reason::Missing,
        Some(libc::ELOOP | libc::ENOTDIR) => Reason::UnsafePath,
        _ => Reason::Unreadable,
    }
}

/// User-authorized global sources follow normal symlinks, including HOME's
/// ancestors and Nix store links. Repository reads retain their own no-follow
/// rules. Only the opened regular file's owner and same-fd evidence matter.
fn read(path: &Path) -> Result<Vec<u8>, Reason> {
    read_bounded(path, GLOBAL_EXCLUDES_MAX, |_| {})
}

#[cfg(test)]
fn read_with(path: &Path, after_read: impl FnOnce(&std::fs::File)) -> Result<Vec<u8>, Reason> {
    read_bounded(path, GLOBAL_EXCLUDES_MAX, after_read)
}

#[allow(unsafe_code)]
fn effective_uid() -> u32 {
    // SAFETY: geteuid has no preconditions and cannot fail.
    unsafe { libc::geteuid() }
}

fn read_bounded(
    path: &Path,
    cap: usize,
    after_read: impl FnOnce(&std::fs::File),
) -> Result<Vec<u8>, Reason> {
    if !path.is_absolute() || path.as_os_str().as_bytes().len() > 65_536 {
        return Err(Reason::UnsafePath);
    }
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_NOCTTY | libc::O_CLOEXEC)
        .open(path)
        .map_err(io_reason)?;
    let before = sys::file_stamp(&file).map_err(io_reason)?;
    check_metadata(&before, effective_uid(), cap)?;
    let mut bytes = Vec::new();
    (&mut file)
        .take(cap as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(io_reason)?;
    after_read(&file);
    if bytes.len() > cap {
        return Err(Reason::TooLarge);
    }
    if sys::file_stamp(&file).map_err(io_reason)? != before || bytes.len() as u64 != before.size {
        return Err(Reason::Changed);
    }
    Ok(bytes)
}

fn check_metadata(before: &sys::Stamp, uid: u32, cap: usize) -> Result<(), Reason> {
    if before.mode & 0o170000 != 0o100000 {
        return Err(Reason::Special);
    }
    if before.uid != uid && before.uid != 0 {
        return Err(Reason::ForeignOwner);
    }
    // Check size before allocating, then cap+1 detects growth on this fd.
    if before.size > cap as u64 {
        return Err(Reason::TooLarge);
    }
    Ok(())
}

#[derive(Debug, PartialEq, Eq)]
enum Entry {
    Excludes(Vec<u8>),
    Include { value: Vec<u8>, conditional: bool },
}

/// Bounded Git config lexer. Only excludes and include targets escape the
/// parser; all other keys are irrelevant to global ignore selection.
fn parse_config(
    bytes: &[u8],
    mut emit: impl FnMut(Entry) -> Result<(), Reason>,
) -> Result<(), Reason> {
    if bytes.contains(&0) {
        return Err(Reason::InvalidConfig);
    }
    let bytes = bytes.strip_prefix(b"\xef\xbb\xbf").unwrap_or(bytes);
    let mut section = Vec::new();
    let mut core = false;
    let mut subsection = false;
    let mut at = 0;
    while at < bytes.len() {
        while at < bytes.len() && bytes[at].is_ascii_whitespace() {
            at += 1;
        }
        if at == bytes.len() {
            break;
        }
        if matches!(bytes[at], b'#' | b';') {
            while at < bytes.len() && bytes[at] != b'\n' {
                at += 1;
            }
            continue;
        }
        if bytes[at] == b'[' {
            at += 1;
            let start = at;
            while at < bytes.len()
                && (bytes[at].is_ascii_alphanumeric() || matches!(bytes[at], b'-' | b'.'))
            {
                at += 1;
            }
            if start == at {
                return Err(Reason::InvalidConfig);
            }
            section = bytes[start..at].to_ascii_lowercase();
            while at < bytes.len() && matches!(bytes[at], b' ' | b'\t') {
                at += 1;
            }
            subsection = bytes.get(at) == Some(&b'"');
            if subsection {
                at += 1;
                while at < bytes.len() && bytes[at] != b'"' {
                    if bytes[at] == b'\\' {
                        at += 1;
                    }
                    if at == bytes.len() || bytes[at] == b'\n' {
                        return Err(Reason::InvalidConfig);
                    }
                    at += 1;
                }
                if bytes.get(at) != Some(&b'"') {
                    return Err(Reason::InvalidConfig);
                }
                at += 1;
                while at < bytes.len() && matches!(bytes[at], b' ' | b'\t') {
                    at += 1;
                }
            }
            if bytes.get(at) != Some(&b']') {
                return Err(Reason::InvalidConfig);
            }
            at += 1;
            core = section == b"core" && !subsection;
            continue;
        }
        let start = at;
        if section.is_empty() || !bytes[at].is_ascii_alphabetic() {
            return Err(Reason::InvalidConfig);
        }
        while at < bytes.len() && (bytes[at].is_ascii_alphanumeric() || bytes[at] == b'-') {
            at += 1;
        }
        let key = &bytes[start..at];
        while at < bytes.len() && matches!(bytes[at], b' ' | b'\t' | b'\r') {
            at += 1;
        }
        let explicit = bytes.get(at) == Some(&b'=');
        if explicit {
            at += 1;
        } else if at < bytes.len() && !matches!(bytes[at], b'\n' | b'#' | b';') {
            return Err(Reason::InvalidConfig);
        }
        let value = value(bytes, &mut at)?;
        if core && key.eq_ignore_ascii_case(b"excludesfile") {
            if !explicit {
                return Err(Reason::InvalidConfig);
            }
            emit(Entry::Excludes(value))?;
        } else if key.eq_ignore_ascii_case(b"path")
            && ((section == b"include" && !subsection)
                || (section == b"includeif" && subsection)
                || section.starts_with(b"includeif."))
        {
            if !explicit {
                return Err(Reason::InvalidConfig);
            }
            emit(Entry::Include {
                value,
                conditional: section != b"include",
            })?;
        }
    }
    Ok(())
}

fn value(bytes: &[u8], at: &mut usize) -> Result<Vec<u8>, Reason> {
    let mut out = Vec::new();
    let mut quoted = false;
    let mut keep = 0;
    while *at < bytes.len() {
        let b = bytes[*at];
        *at += 1;
        match b {
            b'\n' => break,
            b'"' => {
                quoted = !quoted;
            }
            b'#' | b';' if !quoted => {
                while *at < bytes.len() && bytes[*at] != b'\n' {
                    *at += 1;
                }
                break;
            }
            b'\\' => {
                let next = *bytes.get(*at).ok_or(Reason::InvalidConfig)?;
                *at += 1;
                if next == b'\n' {
                    continue;
                }
                if next == b'\r' && bytes.get(*at) == Some(&b'\n') {
                    *at += 1;
                    continue;
                }
                out.push(match next {
                    b'n' => b'\n',
                    b't' => b'\t',
                    b'b' => 8,
                    b'\\' | b'"' => next,
                    _ => return Err(Reason::InvalidConfig),
                });
                keep = out.len();
            }
            b if b.is_ascii_whitespace() && !quoted => {
                if !out.is_empty() {
                    out.push(b);
                }
            }
            _ => {
                out.push(b);
                keep = out.len();
            }
        }
    }
    if quoted {
        return Err(Reason::InvalidConfig);
    }
    out.truncate(keep);
    Ok(out)
}

#[cfg(test)]
#[allow(unsafe_code)]
mod tests;
