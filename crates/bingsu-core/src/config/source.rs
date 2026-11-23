//! Config sources and the `extends` graph. Core orders the graph; the caller
//! (the CLI) opens files. The exchange is one call per edge: core parses a
//! file and asks the caller's `Resolver` for each `extends` entry, left to
//! right; the caller resolves the path against the declaring file's folder,
//! opens it, checks it and answers with the bytes, a stable file identity
//! and the file's trust. Core never reads a file itself.
//!
//! Order: depth first, left first; each file after its own `extends`
//! (later wins). A file reached again is applied once, where it was first
//! met (diamond). Limits: depth 8, 32 distinct files, 1 MiB together, 256
//! KiB each (`tree::FILE_BYTES_MAX`); a cycle is an error.
//!
//! Taint: a file that is not trusted for execution keys is shape-only, and
//! so is everything reached through it. The walk has two phases so that a
//! shape-only file can never move, fail or crowd out a trusted one:
//!
//! 1. Trusted walk: only files trusted for execution keys are followed.
//!    Trusted files get their place, depth and budget from trusted paths
//!    alone. A file that is not trusted is a leaf here.
//! 2. Each such leaf, in apply order, is followed on its own. What it
//!    reaches first is shape-only and goes just before it. Registered
//!    shape-only leaves are still walked; execution origins keep their
//!    phase-1 positions. If anything in that subgraph goes wrong
//!    (a cycle, depth, the budget left over, a file that does not parse),
//!    the subgraph is dropped alone with a warning (rule 5) and its budget
//!    is given back.
//!
//! A problem in a trusted file rejects the whole load (the caller keeps the
//! last good snapshot). Every file met is in the report's
//! catalog, whether applied, dropped or failed, so a diagnostic's place can
//! always be shown.
use crate::config::tree::{self, Span, SyntaxErrorKind, Table, Value};
use crate::diag::{DiagCode, Diagnostic, Place, SourceId};
use crate::diag_codes as codes;
use alloc::string::String;
use alloc::vec::Vec;

pub const EXTENDS_DEPTH_MAX: usize = 8;
pub const DISTINCT_FILES_MAX: usize = 32;
pub const TOTAL_BYTES_MAX: usize = 1024 * 1024;

/// What the caller knows of a file: `(st_dev, st_ino)` of the opened file.
/// Two entries with the same key are the same file.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct FileKey {
    pub dev: u64,
    pub ino: u64,
}

/// Whether a file may give execution keys (the CLI decides).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Trust {
    /// Under the config root or approved with `config use`, and it passed
    /// the file safety check.
    Executable,
    /// Anything else: may change how the prompt looks, not what runs.
    ShapeOnly,
    /// Would be executable, but failed the safety check: its execution keys
    /// are kept so the segment can be named, and the segment does not run.
    Unsafe,
}

/// One opened file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Opened {
    pub key: FileKey,
    pub bytes: Vec<u8>,
    pub trust: Trust,
    /// The path to show (sanitized when shown).
    pub display: Vec<u8>,
}

/// One entry of a file's `extends` array.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExtendsRef {
    pub text: String,
    pub span: Span,
}

/// Why the caller could not use an `extends` entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpenError {
    pub reason: String,
    /// The trust the path would have had (the caller knows it from where
    /// the path points, before opening): a missing or unusable shape-only
    /// file is dropped alone, a missing trusted file fails the load.
    pub trust: Trust,
}

/// A root before it is read: what the caller learns from `fstat` (key,
/// size) and from where the file is (trust). Core decides the budget on
/// this and asks for the bytes only when the root fits.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RootMeta {
    pub key: FileKey,
    pub size: usize,
    pub trust: Trust,
    pub display: Vec<u8>,
}

/// One root: already in memory (the built-in source) or still on disk.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Root {
    Read(Opened),
    File(RootMeta),
    /// One place holds two files in different formats (`config.toml` and
    /// `config.json`): neither is read, and the read fails (E308) whatever
    /// trust the place has. `other` is the second path.
    TwoFormats {
        meta: RootMeta,
        other: Vec<u8>,
    },
}

impl From<Opened> for Root {
    fn from(o: Opened) -> Self {
        Root::Read(o)
    }
}

impl From<RootMeta> for Root {
    fn from(m: RootMeta) -> Self {
        Root::File(m)
    }
}

impl Root {
    fn meta(&self) -> (FileKey, usize, Trust) {
        match self {
            Root::Read(o) => (o.key, o.bytes.len(), o.trust),
            Root::File(m) | Root::TwoFormats { meta: m, .. } => (m.key, m.size, m.trust),
        }
    }

    /// The catalog entry of a root that is never read.
    fn unread(self) -> Opened {
        match self {
            Root::Read(o) => Opened {
                bytes: Vec::new(),
                ..o
            },
            Root::File(m) | Root::TwoFormats { meta: m, .. } => Opened {
                key: m.key,
                bytes: Vec::new(),
                trust: m.trust,
                display: m.display,
            },
        }
    }
}

pub trait Resolver {
    /// Completes the preceding successful read before the next open. None
    /// excludes it; Some carries trust after taint. Known aliases retain
    /// the catalog's trust so they cannot discard execution evidence.
    /// In-memory roots may also be adopted without a pending read.
    fn adopt(&mut self, _key: FileKey, _trust: Option<Trust>) {}

    /// Resolves `r` (written in file `from`) and opens it.
    fn open(&mut self, from: &Opened, r: &ExtendsRef) -> Result<Opened, OpenError>;

    /// Reads root `r`. Called only for a root that fits the budget.
    fn open_root(&mut self, r: &RootMeta) -> Result<Opened, OpenError> {
        Err(OpenError {
            reason: String::from("this resolver reads no roots"),
            trust: r.trust,
        })
    }

    /// Parses the text of a YAML file (`tree::Format::Yaml`), already within
    /// the size limit and UTF-8. Core keeps no YAML parser; the reader that
    /// opens files supplies one, and core checks what it returns
    /// (`tree::check_parsed`) before the tree is used.
    fn parse_yaml(&mut self, _text: &str) -> Result<Table, Vec<tree::SyntaxError>> {
        tree::parse_as(tree::Format::Yaml, &[])
    }
}

/// What became of a file met in the walk.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    Applied,
    /// A shape-only file or subgraph left out (rule 5), with a warning.
    Dropped,
    /// A trusted file with a problem: the load fails.
    Failed,
}

/// One file met in the walk. `SourceId(i)` is its index in the catalog.
#[derive(Clone, Debug)]
pub struct Found {
    pub id: SourceId,
    pub opened: Opened,
    /// Trust after taint. An explicit `Unsafe` origin retains its execution
    /// keys even when shape-only aliases also reach it.
    pub trust: Trust,
    /// The file's keys, without `extends`, `version` and `requires`
    /// (empty when the file did not parse).
    pub tree: Table,
    /// The `extends` chain of the path that placed it, outermost first.
    pub via: Vec<SourceId>,
    pub status: Status,
}

/// A load that can be used: every file met, the apply order of the ones
/// applied, and the warnings (dropped shape-only files).
#[derive(Debug, Default)]
pub struct LoadReport {
    pub files: Vec<Found>,
    pub order: Vec<SourceId>,
    pub warnings: Vec<Diagnostic>,
}

/// A load that cannot be used: a trusted file has a problem. The catalog
/// is still there for the diagnostics.
#[derive(Debug, Default)]
pub struct LoadError {
    pub files: Vec<Found>,
    pub errors: Vec<Diagnostic>,
    pub warnings: Vec<Diagnostic>,
}

impl LoadReport {
    pub fn get(&self, id: SourceId) -> Option<&Found> {
        self.files.get(id.0 as usize)
    }
}

/// Shows diagnostics against a catalog (`diag::render_human`).
pub struct Catalog<'a>(pub &'a [Found]);

impl crate::diag::SourceView for Catalog<'_> {
    fn display(&self, id: SourceId) -> &[u8] {
        self.0
            .get(id.0 as usize)
            .map_or(b"?", |f| &f.opened.display)
    }
    fn bytes(&self, id: SourceId) -> &[u8] {
        self.0.get(id.0 as usize).map_or(b"", |f| &f.opened.bytes)
    }
}

/// `requires = ">=MAJOR.MINOR[.PATCH]"`, the only form accepted.
pub fn parse_requires(s: &str) -> Option<[u32; 3]> {
    let v = s.strip_prefix(">=")?;
    let mut out = [0u32; 3];
    let mut n = 0;
    for part in v.split('.') {
        if n == 3 || part.is_empty() || !part.bytes().all(|b| b.is_ascii_digit()) || part.len() > 9
        {
            return None;
        }
        out[n] = part.parse().ok()?;
        n += 1;
    }
    (n >= 2).then_some(out)
}

/// A bingsu version as `requires` compares it: `MAJOR.MINOR.PATCH` and
/// whether a pre-release label follows (`0.1.0-rc.1`). SemVer puts a
/// pre-release below the release with the same numbers; build metadata
/// (`+...`) takes no part. No ordering is derived: the field order would put
/// a release below its own pre-release.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Version {
    pub numbers: [u32; 3],
    pub pre_release: bool,
}

impl Version {
    /// `text` as Cargo writes a package version. A part that is missing or
    /// is not a number reads as 0.
    pub fn parse(text: &str) -> Version {
        // Build metadata may hold `-` (`1.0.0+build-5`): cut it off first.
        // 이것을 실패시키는 것: `+` 뒤를 자르지 않는 것(`1.0.0+build-5`가 pre-release가 됨).
        let text = text.split_once('+').map_or(text, |(v, _)| v);
        let (numbers, pre_release) = match text.split_once('-') {
            Some((numbers, _)) => (numbers, true),
            None => (text, false),
        };
        let mut parts = numbers.split('.').map(|n| n.parse().unwrap_or(0));
        let mut next = || parts.next().unwrap_or(0);
        Version {
            numbers: [next(), next(), next()],
            pre_release,
        }
    }

    /// Whether this version meets `requires = ">=want"`: higher numbers, or
    /// the same numbers without a pre-release label.
    pub fn meets(self, want: [u32; 3]) -> bool {
        self.numbers > want || (self.numbers == want && !self.pre_release)
    }
}

/// A release: tests and fixed inputs give the numbers alone.
impl From<[u32; 3]> for Version {
    fn from(numbers: [u32; 3]) -> Version {
        Version {
            numbers,
            pre_release: false,
        }
    }
}

fn syntax_diag(id: SourceId, e: &tree::SyntaxError) -> Diagnostic {
    let at = Place::Source { id, span: e.span };
    match &e.kind {
        SyntaxErrorKind::TooLarge => Diagnostic::new(codes::FILE_TOO_LARGE, at),
        SyntaxErrorKind::NotUtf8 => Diagnostic::new(codes::NOT_UTF8, at),
        SyntaxErrorKind::TooDeep => Diagnostic::new(codes::NESTING_TOO_DEEP, at),
        SyntaxErrorKind::IntegerRange => Diagnostic::new(codes::INTEGER_RANGE, at).arg("value", ""),
        SyntaxErrorKind::FloatSyntax => {
            Diagnostic::new(codes::TOML_SYNTAX, at).arg("message", "bad float")
        }
        SyntaxErrorKind::Toml(m) => {
            Diagnostic::new(codes::TOML_SYNTAX, at).arg("message", m.clone())
        }
        SyntaxErrorKind::Json(m) => {
            Diagnostic::new(codes::JSON_SYNTAX, at).arg("message", m.clone())
        }
        SyntaxErrorKind::Yaml(m) => {
            Diagnostic::new(codes::YAML_SYNTAX, at).arg("message", m.clone())
        }
        SyntaxErrorKind::YamlUnsupported(f) => {
            Diagnostic::new(codes::YAML_UNSUPPORTED, at).arg("feature", f.clone())
        }
    }
}

/// A file's meta keys, taken out of its tree.
struct Meta {
    extends: Vec<ExtendsRef>,
    errors: Vec<Diagnostic>,
}

fn take_meta(id: SourceId, t: &mut Table, version: Version) -> Meta {
    let mut m = Meta {
        extends: Vec::new(),
        errors: Vec::new(),
    };
    let mut keep = Vec::with_capacity(t.entries.len());
    for e in core::mem::take(&mut t.entries) {
        let at = Place::Source {
            id,
            span: e.node.span,
        };
        match e.key.as_str() {
            "extends" => match &e.node.value {
                Value::Array(items) => {
                    for n in items {
                        match &n.value {
                            Value::Str(s) => m.extends.push(ExtendsRef {
                                text: s.clone(),
                                span: n.span,
                            }),
                            v => m.errors.push(
                                Diagnostic::new(
                                    codes::WRONG_TYPE,
                                    Place::Source { id, span: n.span },
                                )
                                .arg("key", "extends")
                                .arg("expected", "a string")
                                .arg("found", v.kind()),
                            ),
                        }
                    }
                }
                v => m.errors.push(
                    Diagnostic::new(codes::WRONG_TYPE, at)
                        .arg("key", "extends")
                        .arg("expected", "an array of strings")
                        .arg("found", v.kind()),
                ),
            },
            "version" => match e.node.value {
                Value::Int(1) => {}
                Value::Int(n) => m.errors.push(
                    Diagnostic::new(codes::VERSION_UNKNOWN, at).arg("found", alloc::format!("{n}")),
                ),
                ref v => m.errors.push(
                    Diagnostic::new(codes::WRONG_TYPE, at)
                        .arg("key", "version")
                        .arg("expected", "an integer")
                        .arg("found", v.kind()),
                ),
            },
            "requires" => match &e.node.value {
                Value::Str(s) => match parse_requires(s) {
                    Some(want) if !version.meets(want) => m.errors.push(
                        Diagnostic::new(codes::REQUIRES_NEWER, at).arg("requires", s.clone()),
                    ),
                    Some(_) => {}
                    None => m.errors.push(
                        Diagnostic::new(codes::BAD_VALUE, at)
                            .arg("key", "requires")
                            .arg("found", s.clone())
                            .arg("expected", "\">=MAJOR.MINOR\""),
                    ),
                },
                v => m.errors.push(
                    Diagnostic::new(codes::WRONG_TYPE, at)
                        .arg("key", "requires")
                        .arg("expected", "a string")
                        .arg("found", v.kind()),
                ),
            },
            // For editors only, in both formats: a string is left out, any
            // other value is an error. Below the top it is an unknown key.
            // 이것을 실패시키는 것: 문자열 `$schema`를 모델에 남기는 것(E201), 문자열이 아닌 값을 받는 것.
            "$schema" => {
                if !matches!(e.node.value, Value::Str(_)) {
                    m.errors.push(
                        Diagnostic::new(codes::WRONG_TYPE, at)
                            .arg("key", "$schema")
                            .arg("expected", "a string")
                            .arg("found", e.node.value.kind()),
                    );
                }
            }
            _ => keep.push(e),
        }
    }
    t.entries = keep;
    m
}

/// A file as the walk met it.
struct Node {
    found: Found,
    extends: Vec<ExtendsRef>,
    /// Problems of the file itself and of its `extends` entries.
    problems: Vec<Diagnostic>,
    /// Phase-2 traversal is separate from phase-1 catalog registration.
    walked: bool,
}

#[derive(Clone, Copy, Default)]
struct Budget {
    files: usize,
    bytes: usize,
}

struct Walk<'r> {
    resolver: &'r mut dyn Resolver,
    version: Version,
    nodes: Vec<Node>,
    stack: Vec<usize>,
    used: Budget,
    /// Shape-only leaves dropped in phase 1 (could not be opened or were
    /// too deep), with why.
    warnings: Vec<Diagnostic>,
}

impl Walk<'_> {
    fn known(&self, key: FileKey) -> Option<usize> {
        self.nodes.iter().position(|n| n.found.opened.key == key)
    }

    /// Executable paths retain the rule that a trusted file is placed by its trusted path alone. Without one, an
    /// explicit unsafe origin must preserve the execution-blocking keys
    /// that a shape-only alias would discard.
    fn replaces_origin(&self, i: usize, trust: Trust) -> bool {
        matches!(
            (self.nodes[i].found.trust, trust),
            (Trust::ShapeOnly, Trust::Unsafe | Trust::Executable)
                | (Trust::Unsafe, Trust::Executable)
        )
    }

    /// A stronger execution origin replaces an untrusted leaf in the same
    /// catalog slot. Its order, bytes, spans and chain come from that path.
    fn put(&mut self, node: Node) {
        let i = node.found.id.0 as usize;
        if i == self.nodes.len() {
            self.nodes.push(node);
        } else {
            self.nodes[i] = node;
        }
    }

    fn adopted_trust(&self, i: usize) -> Option<Trust> {
        let f = &self.nodes[i].found;
        (f.status == Status::Applied).then_some(f.trust)
    }

    fn open(&mut self, opened: Opened, via: &[SourceId], tainted: bool) -> usize {
        let i = self.known(opened.key).unwrap_or(self.nodes.len());
        let id = SourceId(i as u32);
        let mut problems = Vec::new();
        let parsed = match tree::format_of(&opened.display) {
            // 이것을 실패시키는 것: 읽는 쪽이 돌려준 YAML 트리를 core가 다시 검사하지 않는 것.
            tree::Format::Yaml => tree::checked_text(&opened.bytes).and_then(|text| {
                let parsed = self.resolver.parse_yaml(text);
                tree::check_parsed(text, parsed)
            }),
            format => tree::parse_as(format, &opened.bytes),
        };
        let mut tree = match parsed {
            Ok(t) => t,
            Err(es) => {
                problems.extend(es.iter().map(|e| syntax_diag(id, e)));
                Table::default()
            }
        };
        let meta = take_meta(id, &mut tree, self.version);
        problems.extend(meta.errors);
        for d in &mut problems {
            d.via = via.to_vec();
        }
        let trust = if tainted {
            Trust::ShapeOnly
        } else {
            opened.trust
        };
        self.resolver.adopt(opened.key, Some(trust));
        self.put(Node {
            found: Found {
                id,
                opened,
                trust,
                tree,
                via: via.to_vec(),
                status: Status::Applied,
            },
            extends: meta.extends,
            problems,
            walked: false,
        });
        i
    }

    /// The problem of a new edge under `limit` (files and bytes in use).
    fn edge_problem(&self, child: &Opened, depth: usize, limit: Budget) -> Option<Diagnostic> {
        budget_problem(child.bytes.len(), depth, limit)
    }

    /// Retain an excluded candidate's identity for diagnostics, without
    /// parsing it, keeping its bytes or retaining execution evidence.
    fn reject(&mut self, opened: Opened, via: &[SourceId], tainted: bool) {
        self.resolver.adopt(opened.key, None);
        let i = self.known(opened.key).unwrap_or(self.nodes.len());
        let trust = if tainted {
            Trust::ShapeOnly
        } else {
            opened.trust
        };
        self.put(Node {
            found: Found {
                id: SourceId(i as u32),
                opened: Opened {
                    bytes: Vec::new(),
                    ..opened
                },
                trust,
                tree: Table::default(),
                via: via.to_vec(),
                status: if trust == Trust::Executable {
                    Status::Failed
                } else {
                    Status::Dropped
                },
            },
            extends: Vec::new(),
            problems: Vec::new(),
            walked: false,
        });
    }

    /// A root that is not read: in the catalog (so its place can be shown),
    /// never parsed, never applied. A trusted one fails the load with `d`;
    /// any other is left out with a warning.
    fn unread_root(&mut self, r: Root, mut d: Diagnostic) {
        let opened = r.unread();
        let i = self.known(opened.key).unwrap_or(self.nodes.len());
        let trust = opened.trust;
        d.at = Place::Source {
            id: SourceId(i as u32),
            span: Span::default(),
        };
        let mut problems = Vec::new();
        let status = if trust == Trust::Executable {
            problems.push(d);
            Status::Applied
        } else {
            self.warnings.push(dropped(SourceId(i as u32), &[], d.code));
            self.warnings.push(d);
            Status::Dropped
        };
        self.put(Node {
            found: Found {
                id: SourceId(i as u32),
                opened,
                trust,
                tree: Table::default(),
                via: Vec::new(),
                status,
            },
            extends: Vec::new(),
            problems,
            walked: false,
        });
    }
}

/// The budget problem of a new file of `len` bytes at `depth` under
/// `limit` (files and bytes in use), if any.
fn budget_problem(len: usize, depth: usize, limit: Budget) -> Option<Diagnostic> {
    let code = if depth > EXTENDS_DEPTH_MAX {
        codes::EXTENDS_TOO_DEEP
    } else if limit.files >= DISTINCT_FILES_MAX {
        codes::EXTENDS_TOO_MANY
    } else if len > TOTAL_BYTES_MAX.saturating_sub(limit.bytes) {
        codes::EXTENDS_TOO_BIG
    } else {
        return None;
    };
    Some(Diagnostic::new(code, Place::Builtin))
}

impl Walk<'_> {
    /// Phase 1 from node `i`: follow trusted files only.
    fn trusted(&mut self, i: usize, order: &mut Vec<usize>) {
        let n = &self.nodes[i];
        if n.found.trust == Trust::Executable && n.problems.is_empty() {
            self.stack.push(i);
            let mut via = n.found.via.clone();
            via.push(n.found.id);
            for r in self.nodes[i].extends.clone() {
                let at = Place::Source {
                    id: SourceId(i as u32),
                    span: r.span,
                };
                let child = match self.resolver.open(&self.nodes[i].found.opened, &r) {
                    Ok(c) => c,
                    Err(e) => {
                        let d = Diagnostic::new(codes::EXTENDS_BAD_PATH, at)
                            .arg("path", r.text.clone())
                            .arg("reason", e.reason);
                        if e.trust == Trust::Executable {
                            self.problem(i, d);
                        } else {
                            self.drop_leaf(i, at, d);
                        }
                        continue;
                    }
                };
                if let Some(k) = self.known(child.key) {
                    if !self.replaces_origin(k, child.trust) {
                        self.resolver.adopt(child.key, self.adopted_trust(k));
                        if child.trust == Trust::Executable && self.stack.contains(&k) {
                            self.problem(i, Diagnostic::new(codes::EXTENDS_CYCLE, at));
                        }
                        continue; // diamond: keep the first trusted place
                    }
                    // An alias cannot claim a stronger origin's place,
                    // provenance or depth (P-S2 and unsafe execution keys).
                    order.retain(|&placed| placed != k);
                }
                let exec = child.trust == Trust::Executable;
                // Checked against what trusted files spent. A leaf that is not
                // trusted is not charged here (phase 2 charges it); if it
                // already does not fit, or is too deep, only it is dropped.
                let limit = self.used;
                if let Some(mut d) = self.edge_problem(&child, via.len(), limit) {
                    self.reject(child, &via, false);
                    d.at = at;
                    if exec {
                        self.problem(i, d);
                    } else {
                        self.drop_leaf(i, at, d);
                    }
                    continue;
                }
                if exec {
                    self.used.files += 1;
                    self.used.bytes += child.bytes.len();
                }
                let k = self.open(child, &via, false);
                // A file not trusted is a leaf here; phase 2 follows it.
                self.trusted(k, order);
            }
            self.stack.pop();
        }
        order.push(i);
    }

    /// A shape-only `extends` entry of node `i` that cannot be used: left
    /// out with a warning, `i` is not at fault.
    fn drop_leaf(&mut self, i: usize, at: Place, mut d: Diagnostic) {
        let via = self.nodes[i].found.via.clone();
        let mut warn = Diagnostic::new(codes::SHAPE_FILE_DROPPED, at)
            .arg("reason", alloc::format!("{}", d.code));
        warn.via = via.clone();
        d.via = via;
        self.warnings.push(warn);
        self.warnings.push(d);
    }

    fn problem(&mut self, i: usize, mut d: Diagnostic) {
        d.via = self.nodes[i].found.via.clone();
        self.nodes[i].problems.push(d);
    }

    /// Phase 2 below node `i`: everything new is shape-only. Returns the
    /// first problem met, if any; `order` gets the new files in apply order.
    fn shaped(
        &mut self,
        i: usize,
        order: &mut Vec<usize>,
        spent: &mut Budget,
        visited: &mut Vec<usize>,
    ) -> Option<Diagnostic> {
        self.nodes[i].walked = true;
        visited.push(i);
        if let Some(d) = self.nodes[i].problems.first() {
            return Some(d.clone());
        }
        self.stack.push(i);
        let mut via = self.nodes[i].found.via.clone();
        via.push(SourceId(i as u32));
        let mut first = None;
        for r in self.nodes[i].extends.clone() {
            let at = Place::Source {
                id: SourceId(i as u32),
                span: r.span,
            };
            let child = match self.resolver.open(&self.nodes[i].found.opened, &r) {
                Ok(c) => c,
                Err(e) => {
                    let mut d = Diagnostic::new(codes::EXTENDS_BAD_PATH, at)
                        .arg("path", r.text.clone())
                        .arg("reason", e.reason);
                    d.via = self.nodes[i].found.via.clone();
                    first.get_or_insert(d);
                    break;
                }
            };
            if let Some(k) = self.known(child.key) {
                if self.stack.contains(&k) {
                    self.resolver.adopt(child.key, self.adopted_trust(k));
                    let mut d = Diagnostic::new(codes::EXTENDS_CYCLE, at);
                    d.via = self.nodes[i].found.via.clone();
                    first.get_or_insert(d);
                    break;
                }
                if self.nodes[k].found.trust != Trust::ShapeOnly
                    || self.nodes[k].walked
                    || self.nodes[k].found.status == Status::Dropped
                {
                    self.resolver.adopt(child.key, self.adopted_trust(k));
                    continue;
                }
                // Registration is not traversal: walk this shape-only
                // identity here, with this path's depth and provenance.
            }
            let limit = Budget {
                files: self.used.files + spent.files,
                bytes: self.used.bytes + spent.bytes,
            };
            if let Some(mut d) = self.edge_problem(&child, via.len(), limit) {
                self.reject(child, &via, true);
                d.at = at;
                d.via = self.nodes[i].found.via.clone();
                first.get_or_insert(d);
                break;
            }
            spent.files += 1;
            spent.bytes += child.bytes.len();
            let k = self.open(child, &via, true);
            if let Some(d) = self.shaped(k, order, spent, visited) {
                first.get_or_insert(d);
                break;
            }
            order.push(k);
        }
        self.stack.pop();
        first
    }
}

/// Loads `roots` in order (built-in, global config, `conf.d` by name,
/// local), following `extends`. `version` is this bingsu's version, for
/// `requires` (numbers alone are a release).
pub fn load<R: Into<Root>, V: Into<Version>>(
    roots: Vec<R>,
    resolver: &mut dyn Resolver,
    version: V,
) -> Result<LoadReport, LoadError> {
    load_as(roots, resolver, version.into())
}

fn load_as<R: Into<Root>>(
    roots: Vec<R>,
    resolver: &mut dyn Resolver,
    version: Version,
) -> Result<LoadReport, LoadError> {
    let mut w = Walk {
        resolver,
        version,
        nodes: Vec::new(),
        stack: Vec::new(),
        used: Budget::default(),
        warnings: Vec::new(),
    };
    let mut order = Vec::new();
    // Untrusted roots provisionally reserve space until phase 2 charges
    // their subgraphs. A replacement origin removes the old reservation.
    let mut root_leaves = Vec::new();
    for r in roots {
        add_root(&mut w, r.into(), &mut order, &mut root_leaves);
    }
    // Phase 2: each file that is not trusted, on its own.
    let mut warnings = core::mem::take(&mut w.warnings);
    let full = shape_leaves(&mut w, &order, &mut warnings);
    let errors = classify(&mut w.nodes, &mut warnings);
    let order: Vec<SourceId> = full
        .into_iter()
        .filter(|&i| w.nodes[i].found.status == Status::Applied)
        .map(|i| SourceId(i as u32))
        .collect();
    let files: Vec<Found> = w.nodes.into_iter().map(|n| n.found).collect();
    if errors.is_empty() {
        Ok(LoadReport {
            files,
            order,
            warnings,
        })
    } else {
        Err(LoadError {
            files,
            errors,
            warnings,
        })
    }
}

/// Phase 1 for one root: whether it replaces a root already met, the budget
/// on its size, two formats at one place, opening it, the budget on its
/// actual bytes, then the trusted walk from it.
fn add_root(w: &mut Walk<'_>, r: Root, order: &mut Vec<usize>, root_leaves: &mut Vec<usize>) {
    let (key, size, trust) = r.meta();
    if let Some(k) = w.known(key) {
        if !w.replaces_origin(k, trust) {
            return;
        }
        order.retain(|&placed| placed != k);
        root_leaves.retain(|&leaf| leaf != k);
    }
    // Promoted roots no longer consume the provisional shape budget.
    let leaves = root_leaves
        .iter()
        .fold(Budget::default(), |mut b, &i: &usize| {
            let f = &w.nodes[i].found;
            if f.trust != Trust::Executable {
                b.files += 1;
                b.bytes += f.opened.bytes.len();
            }
            b
        });
    // Roots (`conf.d` too) spend the same budget, decided on the size
    // before the root is read or parsed: a trusted root over it fails
    // the load, any other root over it is left out unread (W406).
    let exec = trust == Trust::Executable;
    let limit = if exec {
        w.used
    } else {
        Budget {
            files: w.used.files + leaves.files,
            bytes: w.used.bytes + leaves.bytes,
        }
    };
    if let Some(d) = budget_problem(size, 0, limit) {
        w.unread_root(r, d);
        return;
    }
    let r = match r {
        // Always an error, whatever trust the files would have had: a
        // shape-only or unsafe place must not drop one of two files and
        // publish what is left.
        // 이것을 실패시키는 것: 공존을 그 자리의 신뢰로 판정하는 것(모양 전용·안전하지 않은 두 파일이면
        // 경고로 내려가 새 스냅샷이 발행됨).
        Root::TwoFormats { meta, other } => {
            let d = Diagnostic::new(codes::TWO_FORMATS, Place::Builtin)
                .arg("path", String::from_utf8_lossy(&meta.display).into_owned())
                .arg("other", String::from_utf8_lossy(&other).into_owned());
            let meta = RootMeta {
                trust: Trust::Executable,
                ..meta
            };
            w.unread_root(Root::File(meta), d);
            return;
        }
        Root::Read(o) => o,
        Root::File(m) => match w.resolver.open_root(&m) {
            Ok(o) => o,
            Err(e) => {
                let d = Diagnostic::new(codes::EXTENDS_BAD_PATH, Place::Builtin)
                    .arg("path", String::from_utf8_lossy(&m.display).into_owned())
                    .arg("reason", e.reason);
                w.unread_root(Root::File(m), d);
                return;
            }
        },
    };
    // Recheck actual bytes before parsing for every trust grade. A root
    // that grew beyond its budget must not fail an unrelated trusted root.
    if let Some(d) = budget_problem(r.bytes.len(), 0, limit) {
        w.resolver.adopt(r.key, None);
        w.unread_root(Root::Read(r), d);
        return;
    }
    if exec {
        w.used.files += 1;
        w.used.bytes += r.bytes.len();
    }
    let i = w.open(r, &[], false);
    if !exec {
        root_leaves.push(i);
    }
    w.trusted(i, order);
}

/// Phase 2 over the apply order: each file that is not trusted gets its own
/// walk; returns the order with the subgraphs that were kept.
fn shape_leaves(w: &mut Walk<'_>, order: &[usize], warnings: &mut Vec<Diagnostic>) -> Vec<usize> {
    let mut full = Vec::with_capacity(order.len());
    for &i in order {
        if w.nodes[i].walked || w.nodes[i].found.status == Status::Dropped {
            continue;
        }
        if w.nodes[i].found.trust != Trust::Executable && w.nodes[i].problems.is_empty() {
            shape_leaf(w, i, &mut full, warnings);
        }
        full.push(i);
    }
    full
}

/// One leaf that is not trusted: its subgraph is kept and charged to the
/// budget, or the files walked under it are dropped with a warning and the
/// budget they would have spent comes back. The leaf goes with them, unless
/// it is an unsafe leaf within the budget: that one stays and pays for itself.
fn shape_leaf(w: &mut Walk<'_>, i: usize, full: &mut Vec<usize>, warnings: &mut Vec<Diagnostic>) {
    let mut sub = Vec::new();
    let mut visited = Vec::new();
    // The leaf itself is the first thing its subgraph spends.
    let mut spent = Budget {
        files: 1,
        bytes: w.nodes[i].found.opened.bytes.len(),
    };
    let over =
        w.used.files + 1 > DISTINCT_FILES_MAX || w.used.bytes + spent.bytes > TOTAL_BYTES_MAX;
    let outcome = if over {
        let code = if w.used.files + 1 > DISTINCT_FILES_MAX {
            codes::EXTENDS_TOO_MANY
        } else {
            codes::EXTENDS_TOO_BIG
        };
        let at = Place::Source {
            id: SourceId(i as u32),
            span: Span::default(),
        };
        let mut d = Diagnostic::new(code, at);
        d.via = w.nodes[i].found.via.clone();
        Some(d)
    } else {
        w.shaped(i, &mut sub, &mut spent, &mut visited)
    };
    match outcome {
        None => {
            w.used.files += spent.files;
            w.used.bytes += spent.bytes;
            full.extend(sub);
        }
        Some(d) => {
            // Drop every shape-only node walked here, including
            // leaves registered in phase 1. Unsafe keeps its own keys.
            for k in visited {
                if k != i {
                    w.nodes[k].found.status = Status::Dropped;
                }
            }
            let id = SourceId(i as u32);
            if over || w.nodes[i].found.trust == Trust::ShapeOnly {
                w.nodes[i].found.status = Status::Dropped;
            } else {
                // Unsafe keeps its own keys after a bad descendant,
                // so the retained leaf still spends one file and its bytes.
                w.used.files += 1;
                w.used.bytes += w.nodes[i].found.opened.bytes.len();
            }
            warnings.push(dropped(id, &w.nodes[i].found.via, d.code));
            warnings.push(d);
        }
    }
}

/// Phase 3: a problem in a shape-only file drops it with a warning; a problem
/// in any other file fails the load. Returns the errors.
fn classify(nodes: &mut [Node], warnings: &mut Vec<Diagnostic>) -> Vec<Diagnostic> {
    let mut errors = Vec::new();
    for n in nodes {
        if n.problems.is_empty() || n.found.status == Status::Dropped {
            continue;
        }
        if n.found.trust == Trust::ShapeOnly {
            n.found.status = Status::Dropped;
            warnings.push(dropped(n.found.id, &n.found.via, n.problems[0].code));
            warnings.append(&mut n.problems);
        } else {
            n.found.status = Status::Failed;
            errors.append(&mut n.problems);
        }
    }
    errors
}

/// The W406 warning at file `id`: the file, or the files under it, are left
/// out because of a problem with code `reason`; `via` is the `extends` chain
/// that brought `id` in.
fn dropped(id: SourceId, via: &[SourceId], reason: DiagCode) -> Diagnostic {
    let mut warn = Diagnostic::new(
        codes::SHAPE_FILE_DROPPED,
        Place::Source {
            id,
            span: Span::default(),
        },
    )
    .arg("reason", alloc::format!("{}", reason));
    warn.via = via.to_vec();
    warn
}

#[cfg(test)]
pub(crate) mod tests;
