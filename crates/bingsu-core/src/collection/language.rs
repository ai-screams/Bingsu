//! Language detection inputs and results (spec section 4 "language versions"
//! rows detection and version selection files; plan D1). The worker reads the
//! marker and version selection files under its read confinement; this module
//! holds the pure parts: the fixed built-in table, the request's query
//! limits, the version string grammar, the per-format extraction and the wire
//! encoding of both sides. Nothing here touches a file.
use super::wire::{ProtocolError, Reader, add_budget, put_bytes};
use alloc::vec::Vec;

/// Languages one request may ask about.
pub const LANGUAGES_MAX: usize = 16;
/// Marker files and version selection files per language, each.
pub const NAMES_MAX: usize = 16;
/// One file name (a single path component).
pub const NAME_MAX: usize = 255;
/// A language id (a built-in name or a user segment id).
pub const ID_MAX: usize = 64;
/// Folders looked at: the shell's folder and up to this many above it, never
/// past the repository root. It equals the discovery's own bound, so a
/// repository found is always within reach (C2 ruling Q2 for D1).
pub const DETECT_LEVELS: usize = 32;
/// The version string grammar's length bound (spec line 935).
pub const VERSION_MAX: usize = 32;
/// The largest version selection file read (C2 ruling Q4 for D1); `go.mod`
/// may hold a long module list before its `toolchain` line.
pub const FILE_MAX: u64 = 4_096;
pub const GO_MOD_MAX: u64 = 16_384;

/// How a version selection file names its version.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Format {
    /// The first line that is not empty and not a `#` comment
    /// (`.nvmrc`, `.node-version`, `.python-version`, plain `rust-toolchain`).
    Line,
    /// asdf/mise `.tool-versions`: the first version on the line of this tool.
    ToolVersions(Vec<u8>),
    /// `rust-toolchain.toml`: `channel = "…"` in `[toolchain]`.
    RustToolchainToml,
    /// `go.mod`: `toolchain go<version>`, else the `go` directive's version.
    GoMod,
}

impl Format {
    pub fn cap(&self) -> u64 {
        if *self == Self::GoMod {
            GO_MOD_MAX
        } else {
            FILE_MAX
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VersionFile {
    pub name: Vec<u8>,
    pub format: Format,
}

/// What one language asks the worker to look for. Built-in languages carry
/// their version files; a user-defined language has markers only (its
/// version comes from its own command).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LanguageQuery {
    pub id: Vec<u8>,
    pub markers: Vec<Vec<u8>>,
    pub version_files: Vec<VersionFile>,
}

/// The version found for a language, if any version selection file was.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Version {
    /// No version selection file at any level looked at.
    None,
    /// The nearest file (`file` in the query, `level` folders above the
    /// shell's) held no string that passes the grammar.
    Refused {
        file: u8,
        level: u8,
        digest: [u8; 16],
    },
    /// The nearest file's version string, grammar-checked.
    Found {
        file: u8,
        level: u8,
        digest: [u8; 16],
        value: Vec<u8>,
    },
}

/// One language's answer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LanguageResult {
    /// The query's language this answers.
    pub index: u8,
    /// The nearest marker found: its index in the query and its level.
    pub marker: Option<(u8, u8)>,
    pub version: Version,
}

const fn line(name: &'static [u8]) -> (&'static [u8], u8, &'static [u8]) {
    (name, 0, b"")
}
const fn tool(tool: &'static [u8]) -> (&'static [u8], u8, &'static [u8]) {
    (b".tool-versions", 1, tool)
}

/// One built-in language: its id, markers and version files (name, format
/// tag, `.tool-versions` tool name). Within a level the files are tried in
/// this order; the precedence between version managers is D2's.
pub struct Builtin {
    pub id: &'static [u8],
    pub markers: &'static [&'static [u8]],
    pub files: &'static [(&'static [u8], u8, &'static [u8])],
}

/// The four built-in languages (spec section 4: Node, Python, Rust, Go).
/// D3 opens the segments that request them.
pub const BUILTIN: [Builtin; 4] = [
    Builtin {
        id: b"node",
        markers: &[b"package.json"],
        files: &[line(b".nvmrc"), line(b".node-version"), tool(b"nodejs")],
    },
    Builtin {
        id: b"python",
        markers: &[
            b"pyproject.toml",
            b"setup.py",
            b"setup.cfg",
            b"requirements.txt",
        ],
        files: &[line(b".python-version"), tool(b"python")],
    },
    Builtin {
        id: b"rust",
        markers: &[b"Cargo.toml"],
        files: &[
            (b"rust-toolchain.toml", 2, b""),
            line(b"rust-toolchain"),
            tool(b"rust"),
        ],
    },
    Builtin {
        id: b"go",
        markers: &[b"go.mod"],
        files: &[(b"go.mod", 3, b""), tool(b"golang")],
    },
];

impl Builtin {
    pub fn query(&self) -> LanguageQuery {
        LanguageQuery {
            id: self.id.to_vec(),
            markers: self.markers.iter().map(|m| m.to_vec()).collect(),
            version_files: self
                .files
                .iter()
                .map(|(name, tag, tool)| VersionFile {
                    name: name.to_vec(),
                    format: format_from(*tag, tool).expect("fixed table"),
                })
                .collect(),
        }
    }
}

fn format_from(tag: u8, tool: &[u8]) -> Result<Format, ProtocolError> {
    Ok(match tag {
        0 => Format::Line,
        1 => Format::ToolVersions(tool.to_vec()),
        2 => Format::RustToolchainToml,
        3 => Format::GoMod,
        _ => return Err(ProtocolError::Schema),
    })
}

fn format_tag(format: &Format) -> u8 {
    match format {
        Format::Line => 0,
        Format::ToolVersions(_) => 1,
        Format::RustToolchainToml => 2,
        Format::GoMod => 3,
    }
}

/// One path component: 1–255 bytes, no `/`, no NUL, not `.` or `..`.
pub fn name_ok(name: &[u8]) -> bool {
    (1..=NAME_MAX).contains(&name.len())
        && !name.contains(&b'/')
        && !name.contains(&0)
        && name != b"."
        && name != b".."
}

/// The version string grammar (spec line 935): `[0-9A-Za-z._+-]`, 1–32
/// bytes, no `..`, and starting with `[0-9A-Za-z]`, so no value reads as an
/// option, a hidden name or a bare `.` (security review M1 for D1, which
/// replaces the earlier "not starting with `-`"). Control characters and
/// `/` are outside the set.
pub fn version_ok(value: &[u8]) -> bool {
    (1..=VERSION_MAX).contains(&value.len())
        && value[0].is_ascii_alphanumeric()
        && value
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'+' | b'-'))
        && !value.windows(2).any(|w| w == b"..")
}

/// What a file says before the grammar: no candidate, a malformed one, or
/// the candidate bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Candidate<'a> {
    Absent,
    Malformed,
    Value(&'a [u8]),
}

fn lines(bytes: &[u8]) -> impl Iterator<Item = &[u8]> {
    bytes
        .split(|b| *b == b'\n')
        .map(|l| trim(l.strip_suffix(b"\r").unwrap_or(l)))
}

fn trim(mut s: &[u8]) -> &[u8] {
    while let [b' ' | b'\t', rest @ ..] = s {
        s = rest;
    }
    while let [rest @ .., b' ' | b'\t'] = s {
        s = rest;
    }
    s
}

/// The candidate version in `bytes` read from a file of `format`.
pub fn extract<'a>(format: &Format, bytes: &'a [u8]) -> Candidate<'a> {
    match format {
        Format::Line => match lines(bytes).find(|l| !l.is_empty() && !l.starts_with(b"#")) {
            Some(l) => Candidate::Value(l),
            None => Candidate::Absent,
        },
        Format::ToolVersions(tool) => {
            for l in lines(bytes) {
                let l = l.split(|b| *b == b'#').next().unwrap_or(l);
                let mut words = l
                    .split(|b| *b == b' ' || *b == b'\t')
                    .filter(|w| !w.is_empty());
                if words.next() == Some(tool.as_slice()) {
                    return match words.next() {
                        Some(v) => Candidate::Value(v),
                        None => Candidate::Malformed,
                    };
                }
            }
            Candidate::Absent
        }
        Format::RustToolchainToml => rust_toolchain_toml(bytes),
        Format::GoMod => go_mod(bytes),
    }
}

/// `channel = "<value>"` in the `[toolchain]` table. The file is read as a
/// small TOML subset, line by line, aware of strings and brackets:
/// comments (also after a table header), single-line basic and literal
/// strings, multi-line strings (three `"` or three `'`) and values spread
/// over lines (arrays, inline tables), whose contents are never read as
/// tables or keys. Anything else that could set the channel is malformed
/// rather than guessed at: quoted or dotted keys, a quoted table name,
/// `toolchain` set at the top level, a channel that is not a basic string
/// without escapes, a string or bracket left open.
fn rust_toolchain_toml(bytes: &[u8]) -> Candidate<'_> {
    match toml_channel(bytes) {
        Some(candidate) => candidate,
        None => Candidate::Malformed,
    }
}

/// What the string- and bracket-aware scan carries from one line to the next.
#[derive(Default)]
struct TomlScan {
    /// Inside a multi-line string closed by three of this quote.
    multi: Option<u8>,
    /// Open `[` and `{` of a value spread over lines.
    depth: u8,
}

impl TomlScan {
    /// One line's bytes (a value, or a whole continuation line); `None` when
    /// a single-line string does not close or brackets do not balance.
    fn scan(&mut self, line: &[u8]) -> Option<()> {
        let mut i = 0;
        while i < line.len() {
            if let Some(q) = self.multi {
                if line[i] == b'\\' && q == b'"' {
                    i += 2;
                } else if line[i..].starts_with(&[q; 3]) {
                    self.multi = None;
                    i += 3;
                } else {
                    i += 1;
                }
                continue;
            }
            match line[i] {
                b'#' => return Some(()),
                q @ (b'"' | b'\'') if line[i..].starts_with(&[q; 3]) => {
                    self.multi = Some(q);
                    i += 3;
                }
                q @ (b'"' | b'\'') => i += string_end(&line[i + 1..], q)? + 2,
                b'[' | b'{' => {
                    self.depth = self.depth.checked_add(1)?;
                    i += 1;
                }
                b']' | b'}' => {
                    self.depth = self.depth.checked_sub(1)?;
                    i += 1;
                }
                _ => i += 1,
            }
        }
        Some(())
    }
}

/// Where a single-line string's closing quote is in `rest` (after the
/// opening one); a basic string's `\` escapes the next byte.
fn string_end(rest: &[u8], quote: u8) -> Option<usize> {
    let mut i = 0;
    while i < rest.len() {
        match rest[i] {
            b'\\' if quote == b'"' => i += 2,
            b if b == quote => return Some(i),
            _ => i += 1,
        }
    }
    None
}

/// A bare key, possibly dotted with no spaces: `a`, `a-b_c`, `a.b`.
fn bare_key(key: &[u8]) -> bool {
    key.split(|b| *b == b'.').all(|k| {
        !k.is_empty()
            && k.iter()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
    })
}

fn comment_or_end(rest: &[u8]) -> bool {
    let rest = trim(rest);
    rest.is_empty() || rest.starts_with(b"#")
}

/// `None` is malformed (unsupported syntax).
fn toml_channel(bytes: &[u8]) -> Option<Candidate<'_>> {
    let mut scan = TomlScan::default();
    // None at the top level; then whether the current table is `[toolchain]`.
    let mut table = None;
    for l in lines(bytes) {
        if scan.multi.is_some() || scan.depth > 0 {
            scan.scan(l)?;
            continue;
        }
        if l.is_empty() || l.starts_with(b"#") {
            continue;
        }
        if let Some(header) = l.strip_prefix(b"[") {
            let (header, close): (&[u8], &[u8]) = match header.strip_prefix(b"[") {
                Some(array) => (array, b"]]"),
                None => (header, b"]"),
            };
            let end = header.windows(close.len()).position(|w| w == close)?;
            let name = trim(&header[..end]);
            if !bare_key(name) || !comment_or_end(&header[end + close.len()..]) {
                return None;
            }
            table = Some(name == b"toolchain" && close == b"]");
            continue;
        }
        let eq = l.iter().position(|b| *b == b'=')?;
        let (key, value) = (trim(&l[..eq]), trim(&l[eq + 1..]));
        if !bare_key(key) {
            return None;
        }
        match table {
            None if key == b"toolchain" || key.starts_with(b"toolchain.") => return None,
            Some(true) if key.starts_with(b"channel.") => return None,
            Some(true) if key == b"channel" => {
                let quoted = value.strip_prefix(b"\"")?;
                let end = quoted.iter().position(|b| *b == b'"')?;
                let value = &quoted[..end];
                if value.contains(&b'\\') || !comment_or_end(&quoted[end + 1..]) {
                    return None;
                }
                return Some(Candidate::Value(value));
            }
            _ => {}
        }
        scan.scan(value)?;
    }
    if scan.multi.is_none() && scan.depth == 0 {
        Some(Candidate::Absent)
    } else {
        None
    }
}

/// `toolchain go<version>`; without it the `go` directive's version (C2
/// ruling Q5 for D1: the Go 1.21+ meaning of a missing toolchain line).
fn go_mod(bytes: &[u8]) -> Candidate<'_> {
    let mut go = Candidate::Absent;
    for l in lines(bytes) {
        let l = trim(match l.windows(2).position(|w| w == b"//") {
            Some(at) => &l[..at],
            None => l,
        });
        let mut words = l
            .split(|b| *b == b' ' || *b == b'\t')
            .filter(|w| !w.is_empty());
        match (words.next(), words.next(), words.next()) {
            (Some(b"toolchain"), Some(v), None) => {
                return match v.strip_prefix(b"go") {
                    Some(v) => Candidate::Value(v),
                    None => Candidate::Malformed,
                };
            }
            (Some(b"toolchain"), _, _) => return Candidate::Malformed,
            (Some(b"go"), Some(v), None) if go == Candidate::Absent => go = Candidate::Value(v),
            _ => {}
        }
    }
    go
}

/// The version answer for one read file: `Found` only when the candidate
/// passes the grammar.
pub fn version(format: &Format, bytes: &[u8], file: u8, level: u8) -> Version {
    let d = super::cwd_hash::sha256(bytes);
    let mut digest = [0; 16];
    digest.copy_from_slice(&d[..16]);
    match extract(format, bytes) {
        Candidate::Value(v) if version_ok(v) => Version::Found {
            file,
            level,
            digest,
            value: v.to_vec(),
        },
        _ => Version::Refused {
            file,
            level,
            digest,
        },
    }
}

impl LanguageQuery {
    pub(crate) fn validate(&self) -> Result<(), ProtocolError> {
        if !(1..=ID_MAX).contains(&self.id.len())
            || self.id.contains(&0)
            || self.markers.len() > NAMES_MAX
            || self.version_files.len() > NAMES_MAX
            || !self.markers.iter().all(|m| name_ok(m))
            || !self.version_files.iter().all(|f| {
                name_ok(&f.name)
                    && match &f.format {
                        Format::ToolVersions(tool) => name_ok(tool) && tool.len() <= ID_MAX,
                        _ => true,
                    }
            })
        {
            return Err(ProtocolError::Schema);
        }
        Ok(())
    }

    fn encoded_len(&self) -> usize {
        // id, marker count, names, file count, (name, tag, tool) each.
        4 + self.id.len()
            + 1
            + self.markers.iter().map(|m| 4 + m.len()).sum::<usize>()
            + 1
            + self
                .version_files
                .iter()
                .map(|f| {
                    4 + f.name.len()
                        + 1
                        + match &f.format {
                            Format::ToolVersions(t) => 4 + t.len(),
                            _ => 0,
                        }
                })
                .sum::<usize>()
    }

    fn put(&self, out: &mut Vec<u8>) {
        put_bytes(out, &self.id);
        out.push(self.markers.len() as u8);
        for m in &self.markers {
            put_bytes(out, m);
        }
        out.push(self.version_files.len() as u8);
        for f in &self.version_files {
            put_bytes(out, &f.name);
            out.push(format_tag(&f.format));
            if let Format::ToolVersions(t) = &f.format {
                put_bytes(out, t);
            }
        }
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, ProtocolError> {
        let id = r.bytes(ID_MAX, ProtocolError::Schema)?.to_vec();
        let n = usize::from(r.u8()?);
        if n > NAMES_MAX {
            return Err(ProtocolError::Schema);
        }
        let mut markers = Vec::with_capacity(n);
        for _ in 0..n {
            markers.push(r.bytes(NAME_MAX, ProtocolError::Schema)?.to_vec());
        }
        let n = usize::from(r.u8()?);
        if n > NAMES_MAX {
            return Err(ProtocolError::Schema);
        }
        let mut version_files = Vec::with_capacity(n);
        for _ in 0..n {
            let name = r.bytes(NAME_MAX, ProtocolError::Schema)?.to_vec();
            let tag = r.u8()?;
            let tool = if tag == 1 {
                r.bytes(ID_MAX, ProtocolError::Schema)?
            } else {
                b""
            };
            version_files.push(VersionFile {
                name,
                format: format_from(tag, tool)?,
            });
        }
        let query = Self {
            id,
            markers,
            version_files,
        };
        query.validate()?;
        Ok(query)
    }
}

/// The user-defined languages that may run (no `not_run` reason) with
/// `detect_files`, as queries: markers only, at most `LANGUAGES_MAX`, in
/// the config's unit order. A name that is not one path component is left
/// out with its language (`config check` reports it).
pub fn user_queries(units: &[crate::config::compile::ExecUnit]) -> Vec<LanguageQuery> {
    use crate::config::compile::ExecPolicy;
    units
        .iter()
        .filter(|u| u.not_run.is_none())
        .filter_map(|u| match &u.policy {
            ExecPolicy::Language { detect_files, .. } if !detect_files.is_empty() => {
                Some(LanguageQuery {
                    id: u.id.as_bytes().to_vec(),
                    markers: detect_files.iter().map(|f| f.as_bytes().to_vec()).collect(),
                    version_files: Vec::new(),
                })
            }
            _ => None,
        })
        // Fails without it: user_queries_leave_out_bad_names.
        .filter(|q| q.validate().is_ok())
        .take(LANGUAGES_MAX)
        .collect()
}

/// A request's queries: count, then each.
pub(crate) fn queries_len(queries: &[LanguageQuery]) -> Result<usize, ProtocolError> {
    if queries.len() > LANGUAGES_MAX {
        return Err(ProtocolError::Budget);
    }
    let mut n = 1;
    for q in queries {
        q.validate()?;
        n = add_budget(n, q.encoded_len(), super::wire::STREAM_MAX)?;
    }
    Ok(n)
}

pub(crate) fn put_queries(out: &mut Vec<u8>, queries: &[LanguageQuery]) {
    out.push(queries.len() as u8);
    for q in queries {
        q.put(out);
    }
}

pub(crate) fn read_queries(r: &mut Reader<'_>) -> Result<Vec<LanguageQuery>, ProtocolError> {
    let n = usize::from(r.u8()?);
    if n > LANGUAGES_MAX {
        return Err(ProtocolError::Budget);
    }
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        out.push(LanguageQuery::read(r)?);
    }
    Ok(out)
}

impl LanguageResult {
    /// The result fits `queries`: its language, marker and file indices
    /// exist, levels are within `DETECT_LEVELS`, a found value passes the
    /// grammar. The receiver checks this; the worker's word is not enough.
    pub(crate) fn check(&self, queries: &[LanguageQuery]) -> Result<(), ProtocolError> {
        let q = queries
            .get(usize::from(self.index))
            .ok_or(ProtocolError::Schema)?;
        let level_ok = |level: u8| usize::from(level) <= DETECT_LEVELS;
        if let Some((marker, level)) = self.marker
            && (usize::from(marker) >= q.markers.len() || !level_ok(level))
        {
            return Err(ProtocolError::Schema);
        }
        let file_ok =
            |file: u8, level: u8| usize::from(file) < q.version_files.len() && level_ok(level);
        let ok = match &self.version {
            Version::None => true,
            Version::Refused { file, level, .. } => file_ok(*file, *level),
            Version::Found {
                file, level, value, ..
            } => file_ok(*file, *level) && version_ok(value),
        };
        if ok {
            Ok(())
        } else {
            Err(ProtocolError::Schema)
        }
    }

    pub fn encoded_len(&self) -> usize {
        1 + 3
            + match &self.version {
                Version::None => 1,
                Version::Refused { .. } => 1 + 2 + 16,
                Version::Found { value, .. } => 1 + 2 + 16 + 4 + value.len(),
            }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.encoded_len());
        self.put(&mut out);
        out
    }

    pub(crate) fn put(&self, out: &mut Vec<u8>) {
        out.push(self.index);
        match self.marker {
            Some((m, level)) => out.extend_from_slice(&[1, m, level]),
            None => out.extend_from_slice(&[0, 0, 0]),
        }
        match &self.version {
            Version::None => out.push(0),
            Version::Refused {
                file,
                level,
                digest,
            } => {
                out.extend_from_slice(&[1, *file, *level]);
                out.extend_from_slice(digest);
            }
            Version::Found {
                file,
                level,
                digest,
                value,
            } => {
                out.extend_from_slice(&[2, *file, *level]);
                out.extend_from_slice(digest);
                put_bytes(out, value);
            }
        }
    }

    pub(crate) fn read(r: &mut Reader<'_>) -> Result<Self, ProtocolError> {
        let index = r.u8()?;
        let [present, m, level] = r.array::<3>()?;
        let marker = match present {
            0 if m == 0 && level == 0 => None,
            1 => Some((m, level)),
            _ => return Err(ProtocolError::Schema),
        };
        let version = match r.u8()? {
            0 => Version::None,
            1 => {
                let [file, level] = r.array::<2>()?;
                Version::Refused {
                    file,
                    level,
                    digest: r.array()?,
                }
            }
            2 => {
                let [file, level] = r.array::<2>()?;
                let digest = r.array()?;
                let value = r.bytes(VERSION_MAX, ProtocolError::Schema)?.to_vec();
                Version::Found {
                    file,
                    level,
                    digest,
                    value,
                }
            }
            _ => return Err(ProtocolError::Schema),
        };
        Ok(Self {
            index,
            marker,
            version,
        })
    }
}
