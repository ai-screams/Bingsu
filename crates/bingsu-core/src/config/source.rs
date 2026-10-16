//! Config sources and the `extends` graph (spec section 2 "합치는 순서",
//! "`extends` 규칙", "키별 출처 검증"). Core orders the graph; the caller
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
//!    alone (spec change S-7). A file that is not trusted is a leaf here.
//! 2. Each such leaf, in apply order, is followed on its own. What it
//!    reaches first is shape-only and goes just before it. A file already
//!    placed stays where it is. If anything in that subgraph goes wrong
//!    (a cycle, depth, the budget left over, a file that does not parse),
//!    the subgraph is dropped alone with a warning (rule 5) and its budget
//!    is given back.
//!
//! A problem in a trusted file rejects the whole load (the caller keeps the
//! last good snapshot, spec section 6). Every file met is in the report's
//! catalog, whether applied, dropped or failed, so a diagnostic's place can
//! always be shown.
use crate::config::tree::{self, Span, SyntaxErrorKind, Table, Value};
use crate::diag::{Diagnostic, Place, SourceId};
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

/// Whether a file may give execution keys (the CLI decides, Task R3).
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
#[derive(Clone, Debug)]
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
#[derive(Clone, Debug)]
pub struct RootMeta {
    pub key: FileKey,
    pub size: usize,
    pub trust: Trust,
    pub display: Vec<u8>,
}

/// One root: already in memory (the built-in source) or still on disk.
#[derive(Clone, Debug)]
pub enum Root {
    Read(Opened),
    File(RootMeta),
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
            Root::File(m) => (m.key, m.size, m.trust),
        }
    }

    /// The catalog entry of a root that is never read.
    fn unread(self) -> Opened {
        match self {
            Root::Read(o) => Opened {
                bytes: Vec::new(),
                ..o
            },
            Root::File(m) => Opened {
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
    /// Trust after taint: `ShapeOnly` when no trusted path reached it.
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
    }
}

/// A file's meta keys, taken out of its tree.
struct Meta {
    extends: Vec<ExtendsRef>,
    errors: Vec<Diagnostic>,
}

fn take_meta(id: SourceId, t: &mut Table, version: [u32; 3]) -> Meta {
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
                    Some(want) if want > version => m.errors.push(
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
}

#[derive(Clone, Copy, Default)]
struct Budget {
    files: usize,
    bytes: usize,
}

struct Walk<'r> {
    resolver: &'r mut dyn Resolver,
    version: [u32; 3],
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

    /// A stronger trusted path replaces an untrusted leaf in the same
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
        let mut tree = match tree::parse(&opened.bytes) {
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
            let warn = Diagnostic::new(codes::SHAPE_FILE_DROPPED, d.at)
                .arg("reason", alloc::format!("{}", d.code));
            self.warnings.push(warn);
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
                    if child.trust != Trust::Executable
                        || self.nodes[k].found.trust == Trust::Executable
                    {
                        self.resolver.adopt(child.key, self.adopted_trust(k));
                        if child.trust == Trust::Executable && self.stack.contains(&k) {
                            self.problem(i, Diagnostic::new(codes::EXTENDS_CYCLE, at));
                        }
                        continue; // diamond: keep the first trusted place
                    }
                    // A shape-only/unsafe alias cannot claim the place or
                    // depth of a later trusted path to this identity (P-S2).
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
    ) -> Option<Diagnostic> {
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
                    first.get_or_insert(
                        Diagnostic::new(codes::EXTENDS_BAD_PATH, at)
                            .arg("path", r.text.clone())
                            .arg("reason", e.reason),
                    );
                    continue;
                }
            };
            if let Some(k) = self.known(child.key) {
                self.resolver.adopt(child.key, self.adopted_trust(k));
                if self.stack.contains(&k) {
                    first.get_or_insert(Diagnostic::new(codes::EXTENDS_CYCLE, at));
                }
                continue;
            }
            let limit = Budget {
                files: self.used.files + spent.files,
                bytes: self.used.bytes + spent.bytes,
            };
            if let Some(mut d) = self.edge_problem(&child, via.len(), limit) {
                self.reject(child, &via, true);
                d.at = at;
                first.get_or_insert(d);
                continue;
            }
            spent.files += 1;
            spent.bytes += child.bytes.len();
            let k = self.open(child, &via, true);
            if let Some(d) = self.nodes[k].problems.first() {
                first.get_or_insert(d.clone());
            } else if let Some(d) = self.shaped(k, order, spent) {
                first.get_or_insert(d);
            }
            order.push(k);
        }
        self.stack.pop();
        first
    }
}

/// Loads `roots` in order (built-in, global config, `conf.d` by name,
/// local), following `extends`. `version` is this bingsu's version, for
/// `requires`.
pub fn load<R: Into<Root>>(
    roots: Vec<R>,
    resolver: &mut dyn Resolver,
    version: [u32; 3],
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
    // their subgraphs. A later trusted alias removes that reservation.
    let mut root_leaves = Vec::new();
    for r in roots {
        let r: Root = r.into();
        let (key, size, trust) = r.meta();
        if let Some(k) = w.known(key) {
            if trust != Trust::Executable || w.nodes[k].found.trust == Trust::Executable {
                continue;
            }
            order.retain(|&placed| placed != k);
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
            continue;
        }
        let r = match r {
            Root::Read(o) => o,
            Root::File(m) => match w.resolver.open_root(&m) {
                Ok(o) => o,
                Err(e) => {
                    let d = Diagnostic::new(codes::EXTENDS_BAD_PATH, Place::Builtin)
                        .arg("path", String::from_utf8_lossy(&m.display).into_owned())
                        .arg("reason", e.reason);
                    w.unread_root(Root::File(m), d);
                    continue;
                }
            },
        };
        // Recheck actual bytes before parsing for every trust grade. A root
        // that grew beyond its budget must not fail an unrelated trusted root.
        if let Some(d) = budget_problem(r.bytes.len(), 0, limit) {
            w.resolver.adopt(r.key, None);
            w.unread_root(Root::Read(r), d);
            continue;
        }
        if exec {
            w.used.files += 1;
            w.used.bytes += r.bytes.len();
        }
        let i = w.open(r, &[], false);
        if !exec {
            root_leaves.push(i);
        }
        w.trusted(i, &mut order);
    }
    // Phase 2: each file that is not trusted, on its own.
    let mut warnings = core::mem::take(&mut w.warnings);
    let mut full = Vec::with_capacity(order.len());
    for &i in &order {
        if w.nodes[i].found.trust != Trust::Executable && w.nodes[i].problems.is_empty() {
            let before = w.nodes.len();
            let mut sub = Vec::new();
            // The leaf itself is the first thing its subgraph spends.
            let mut spent = Budget {
                files: 1,
                bytes: w.nodes[i].found.opened.bytes.len(),
            };
            let over = w.used.files + 1 > DISTINCT_FILES_MAX
                || w.used.bytes + spent.bytes > TOTAL_BYTES_MAX;
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
                Some(Diagnostic::new(code, at))
            } else {
                w.shaped(i, &mut sub, &mut spent)
            };
            match outcome {
                None => {
                    w.used.files += spent.files;
                    w.used.bytes += spent.bytes;
                    full.extend(sub);
                }
                Some(d) => {
                    // Drop what this subgraph added; a shape-only file goes
                    // with it, an unsafe one keeps its own keys.
                    for k in before..w.nodes.len() {
                        w.nodes[k].found.status = Status::Dropped;
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
                    let mut warn = Diagnostic::new(
                        codes::SHAPE_FILE_DROPPED,
                        Place::Source {
                            id,
                            span: Span::default(),
                        },
                    )
                    .arg("reason", alloc::format!("{}", d.code));
                    warn.via = w.nodes[i].found.via.clone();
                    warnings.push(warn);
                    warnings.push(d);
                }
            }
        }
        full.push(i);
    }
    let mut errors = Vec::new();
    for n in &mut w.nodes {
        if n.problems.is_empty() || n.found.status == Status::Dropped {
            continue;
        }
        if n.found.trust == Trust::ShapeOnly {
            n.found.status = Status::Dropped;
            let mut warn = Diagnostic::new(
                codes::SHAPE_FILE_DROPPED,
                Place::Source {
                    id: n.found.id,
                    span: Span::default(),
                },
            )
            .arg("reason", alloc::format!("{}", n.problems[0].code));
            warn.via = n.found.via.clone();
            warnings.push(warn);
            warnings.append(&mut n.problems);
        } else {
            n.found.status = Status::Failed;
            errors.append(&mut n.problems);
        }
    }
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

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::diag::DiagCode;
    use alloc::borrow::ToOwned;
    use alloc::collections::BTreeMap;
    use alloc::vec;

    /// Files by name; `extends` entries are names. Trust: names starting
    /// with `shape-` are shape-only, `unsafe-` unsafe.
    #[derive(Default)]
    pub(crate) struct Files(pub BTreeMap<&'static str, String>);

    pub(crate) fn opened(name: &str, text: &str, key: u64) -> Opened {
        let trust = if name.starts_with("shape-") {
            Trust::ShapeOnly
        } else if name.starts_with("unsafe-") {
            Trust::Unsafe
        } else {
            Trust::Executable
        };
        Opened {
            key: FileKey { dev: 1, ino: key },
            bytes: text.as_bytes().to_vec(),
            trust,
            display: name.as_bytes().to_vec(),
        }
    }

    impl Resolver for Files {
        fn open(&mut self, _: &Opened, r: &ExtendsRef) -> Result<Opened, OpenError> {
            let (i, (name, text)) = self
                .0
                .iter()
                .enumerate()
                .find(|(_, (n, _))| **n == r.text)
                .ok_or(OpenError {
                    reason: "no such file".to_owned(),
                    trust: opened(&r.text, "", 0).trust,
                })?;
            Ok(opened(name, text, 100 + i as u64))
        }
    }

    pub(crate) fn files(list: &[(&'static str, &str)]) -> Files {
        Files(list.iter().map(|(n, t)| (*n, String::from(*t))).collect())
    }

    fn name(f: &Found) -> String {
        String::from_utf8(f.opened.display.clone()).unwrap()
    }

    fn order(g: &LoadReport) -> Vec<String> {
        g.order.iter().map(|id| name(g.get(*id).unwrap())).collect()
    }

    fn trust_of(g: &LoadReport, n: &str) -> Trust {
        g.files
            .iter()
            .find(|f| f.opened.display == n.as_bytes())
            .unwrap()
            .trust
    }

    fn codes_of(e: &[Diagnostic]) -> Vec<DiagCode> {
        e.iter().map(|d| d.code).collect()
    }

    fn leak(s: String) -> &'static str {
        alloc::boxed::Box::leak(s.into_boxed_str())
    }

    const V: [u32; 3] = [0, 3, 0];

    // 이것을 실패시키는 것: 자기보다 extends를 뒤에 적용하거나(앞이 이김), 오른쪽부터 걷거나,
    // 다이아몬드에서 같은 파일을 두 번 적용하는 것.
    #[test]
    fn depth_first_left_first_and_diamond_once() {
        let mut f = files(&[
            ("a", "extends = [\"c\"]\nx = 1\n"),
            ("b", "extends = [\"c\"]\nx = 2\n"),
            ("c", "x = 3\n"),
        ]);
        let g = load(
            vec![opened("root", "extends = [\"a\", \"b\"]\n", 1)],
            &mut f,
            V,
        )
        .unwrap();
        assert_eq!(order(&g), ["c", "a", "b", "root"]);
        assert!(g.files.iter().all(|s| s.tree.get("extends").is_none()));
        let c = g.files.iter().find(|f| f.opened.display == b"c").unwrap();
        assert_eq!(c.via, [SourceId(0), SourceId(1)]);
    }

    // 이것을 실패시키는 것: 순환을 끝없이 따라가거나 오류로 내지 않는 것.
    #[test]
    fn a_cycle_is_an_error() {
        let mut f = files(&[("a", "extends = [\"b\"]\n"), ("b", "extends = [\"a\"]\n")]);
        let e = load(vec![opened("root", "extends = [\"a\"]\n", 1)], &mut f, V).unwrap_err();
        assert_eq!(codes_of(&e.errors), [codes::EXTENDS_CYCLE]);
        assert_eq!(e.files.len(), 3, "the catalog keeps every file met");
    }

    fn chain(n: usize, prefix: &str) -> Files {
        let names: Vec<&'static str> = (0..n)
            .map(|i| leak(alloc::format!("{prefix}{i}")))
            .collect();
        let mut list = Vec::new();
        for i in 0..n {
            let text = if i + 1 < n {
                alloc::format!("extends = [\"{}\"]\n", names[i + 1])
            } else {
                String::new()
            };
            list.push((names[i], text));
        }
        Files(list.into_iter().collect())
    }

    // 이것을 실패시키는 것: 깊이 8·고유 32·합계 1 MiB 경계를 하나씩 어긋나게 세는 것.
    #[test]
    fn limits_are_exact() {
        let mut f = chain(8, "f");
        assert!(load(vec![opened("root", "extends = [\"f0\"]\n", 1)], &mut f, V).is_ok());
        let mut f = chain(9, "f");
        let e = load(vec![opened("root", "extends = [\"f0\"]\n", 1)], &mut f, V).unwrap_err();
        assert_eq!(codes_of(&e.errors), [codes::EXTENDS_TOO_DEEP]);
        let fan = |n: usize| {
            let names: Vec<String> = (0..n).map(|i| alloc::format!("\"g{i}\"")).collect();
            let list: Vec<(&'static str, String)> = (0..n)
                .map(|i| (leak(alloc::format!("g{i}")), String::new()))
                .collect();
            (
                alloc::format!("extends = [{}]\n", names.join(", ")),
                Files(list.into_iter().collect()),
            )
        };
        let (root, mut f) = fan(31);
        assert_eq!(
            load(vec![opened("root", &root, 1)], &mut f, V)
                .unwrap()
                .order
                .len(),
            32
        );
        let (root, mut f) = fan(32);
        let e = load(vec![opened("root", &root, 1)], &mut f, V).unwrap_err();
        assert_eq!(codes_of(&e.errors), [codes::EXTENDS_TOO_MANY]);
        let big = |n| alloc::format!("{}\n", "#".repeat(n));
        let quarter = 256 * 1024;
        let head = "extends = [\"h0\", \"h1\", \"h2\"]\n";
        let root = alloc::format!("{head}{}", "#".repeat(quarter - head.len()));
        let mut f = files(&[
            ("h0", &big(quarter - 1)),
            ("h1", &big(quarter - 1)),
            ("h2", &big(quarter - 1)),
        ]);
        assert!(load(vec![opened("root", &root, 1)], &mut f, V).is_ok());
        let mut f = files(&[
            ("h0", &big(quarter - 1)),
            ("h1", &big(quarter - 1)),
            ("h2", &big(quarter)),
        ]);
        let e = load(vec![opened("root", &root, 1)], &mut f, V).unwrap_err();
        assert_eq!(codes_of(&e.errors), [codes::EXTENDS_TOO_BIG]);
    }

    // 이것을 실패시키는 것: 모양 전용 파일 아래의 파일을 깨끗하다고 보거나(오염 전이 없음),
    // 깨끗한 경로로도 닿은 파일을 오염된 채로 두는 것(P-S2), Unsafe 파일 아래를 깨끗하다고 보는 것.
    #[test]
    fn taint_flows_down_shape_only_edges() {
        let mut f = files(&[
            ("shape-team", "extends = [\"mine\"]\n"),
            ("mine", "x = 1\n"),
            ("other", "extends = [\"deep\"]\ny = 1\n"),
            ("deep", "z = 1\n"),
            ("shape-repo", "extends = [\"other\"]\n"),
            ("unsafe-x", "extends = [\"deep\"]\n"),
        ]);
        let g = load(
            vec![opened("root", "extends = [\"shape-team\"]\n", 1)],
            &mut f,
            V,
        )
        .unwrap();
        assert_eq!(order(&g), ["mine", "shape-team", "root"]);
        assert_eq!(
            (trust_of(&g, "mine"), trust_of(&g, "shape-team")),
            (Trust::ShapeOnly, Trust::ShapeOnly)
        );
        for list in ["\"shape-repo\", \"other\"", "\"other\", \"shape-repo\""] {
            let g = load(
                vec![opened("root", &alloc::format!("extends = [{list}]\n"), 1)],
                &mut f,
                V,
            )
            .unwrap();
            assert_eq!(
                (trust_of(&g, "other"), trust_of(&g, "deep")),
                (Trust::Executable, Trust::Executable),
                "{list}"
            );
        }
        let g = load(
            vec![opened("root", "extends = [\"unsafe-x\"]\n", 1)],
            &mut f,
            V,
        )
        .unwrap();
        assert_eq!(
            (trust_of(&g, "deep"), trust_of(&g, "unsafe-x")),
            (Trust::ShapeOnly, Trust::Unsafe)
        );
    }

    // 스펙 개정 S-7: 신뢰 파일의 적용 자리는 신뢰 경로만으로 정한다.
    // 이것을 실패시키는 것: 모양 전용 파일이 신뢰 파일을 먼저 가리켜 그 자리를 앞당기는 것(뒤가 이기는 순서가 바뀜).
    #[test]
    fn trusted_files_keep_their_trusted_place() {
        let mut f = files(&[
            ("a", "x = 1\n"),
            ("f", "x = 2\n"),
            ("shape-t", "extends = [\"f\"]\ny = 1\n"),
        ]);
        let g = load(
            vec![opened("root", "extends = [\"shape-t\", \"a\", \"f\"]\n", 1)],
            &mut f,
            V,
        )
        .unwrap();
        assert_eq!(order(&g), ["shape-t", "a", "f", "root"]);
    }

    // 이것을 실패시키는 것: 모양 전용 하위 그래프가 예산·깊이·순환·문법으로 신뢰 파일을 실패시키는 것,
    // 실패한 하위 그래프를 통째로 버리지 않는 것, 버린 예산을 돌려주지 않는 것.
    #[test]
    fn a_shape_only_subgraph_that_goes_wrong_is_dropped_alone() {
        // Count: shape-t reaches 31 files; `mine` (trusted) still fits.
        let fans: Vec<String> = (0..31).map(|i| alloc::format!("\"s{i}\"")).collect();
        let mut list: Vec<(&'static str, String)> = (0..31)
            .map(|i| (leak(alloc::format!("s{i}")), String::new()))
            .collect();
        list.push((
            "shape-t",
            alloc::format!("extends = [{}]\n", fans.join(", ")),
        ));
        list.push(("mine", String::from("m = 1\n")));
        let mut f = Files(list.into_iter().collect());
        let g = load(
            vec![opened("root", "extends = [\"shape-t\", \"mine\"]\n", 1)],
            &mut f,
            V,
        )
        .unwrap();
        assert_eq!(
            order(&g),
            ["root", "mine"]
                .iter()
                .rev()
                .map(|s| String::from(*s))
                .collect::<Vec<_>>()
        );
        assert_eq!(codes_of(&g.warnings)[0], codes::SHAPE_FILE_DROPPED);
        // Depth: shape-t reaching `mine` first does not make mine's chain deeper.
        let mut f = chain(7, "c");
        f.0.insert("mine", String::from("extends = [\"c0\"]\n"));
        f.0.insert("shape-t", String::from("extends = [\"mine\"]\n"));
        let g = load(
            vec![opened("root", "extends = [\"shape-t\", \"mine\"]\n", 1)],
            &mut f,
            V,
        )
        .unwrap();
        assert_eq!(trust_of(&g, "c6"), Trust::Executable);
        // Cycle and syntax below a shape-only file: dropped, root fine.
        let mut f = files(&[
            ("shape-a", "extends = [\"shape-b\"]\n"),
            ("shape-b", "extends = [\"shape-a\"]\n"),
            ("shape-x", "extends = [\"bad\"]\n"),
            ("bad", "x = [\n"),
        ]);
        let g = load(
            vec![opened("root", "extends = [\"shape-a\", \"shape-x\"]\n", 1)],
            &mut f,
            V,
        )
        .unwrap();
        assert_eq!(order(&g), ["root"]);
        let w = codes_of(&g.warnings);
        assert!(
            w.contains(&codes::EXTENDS_CYCLE) && w.contains(&codes::TOML_SYNTAX),
            "{w:?}"
        );
        // Bytes: a dropped subgraph gives its budget back to the next one.
        let quarter = 256 * 1024 - 1;
        let big = alloc::format!("{}\n", "#".repeat(quarter));
        // 256 KiB: fits only if the dropped 768 KiB were given back.
        let mid = alloc::format!("{}\n", "#".repeat(256 * 1024 - 1));
        let mut f = files(&[
            ("shape-big", "extends = [\"x1\", \"x2\", \"x3\", \"x4\"]\n"),
            ("x1", &big),
            ("x2", &big),
            ("x3", &big),
            ("x4", &big),
            ("shape-small", "extends = [\"y\"]\n"),
            ("y", &mid),
        ]);
        let g = load(
            vec![opened(
                "root",
                "extends = [\"shape-big\", \"shape-small\"]\n",
                1,
            )],
            &mut f,
            V,
        )
        .unwrap();
        assert_eq!(order(&g), ["y", "shape-small", "root"]);
        // The shape-only file itself is counted: 32 trusted files leave no
        // room for it, and only it is dropped.
        let names: Vec<String> = (0..31).map(|i| alloc::format!("\"g{i}\"")).collect();
        let mut list: Vec<(&'static str, String)> = (0..31)
            .map(|i| (leak(alloc::format!("g{i}")), String::new()))
            .collect();
        list.push(("shape-z", String::from("z = 1\n")));
        let mut f = Files(list.into_iter().collect());
        // Before the trusted fan it waits for phase 2; after it, phase 1
        // already knows that only this leaf exceeds the file budget.
        for root in [
            alloc::format!("extends = [\"shape-z\", {}]\n", names.join(", ")),
            alloc::format!("extends = [{}, \"shape-z\"]\n", names.join(", ")),
        ] {
            let g = load(vec![opened("root", &root, 1)], &mut f, V).unwrap();
            assert_eq!(g.order.len(), 32);
            assert_eq!(
                codes_of(&g.warnings),
                [codes::SHAPE_FILE_DROPPED, codes::EXTENDS_TOO_MANY]
            );
        }
    }

    // 이것을 실패시키는 것: 모양 전용 잎을 열지 못하거나 너무 클 때 그것을 가리킨 신뢰 파일의 문제로 보는 것
    // (저장소가 테마 파일을 지우거나 키우는 것만으로 사용자 설정 전체가 거부됨).
    #[test]
    fn a_shape_only_leaf_that_cannot_be_used_is_dropped_alone() {
        let huge = alloc::format!("{}\n", "#".repeat(1024 * 1024 + 10));
        let mut f = files(&[("shape-big", &huge)]);
        for root in [
            "extends = [\"shape-big\"]\n",
            "extends = [\"shape-gone\"]\n",
        ] {
            let g = load(vec![opened("root", root, 1)], &mut f, V).unwrap();
            assert_eq!(order(&g), ["root"], "{root}");
            assert_eq!(
                codes_of(&g.warnings)[0],
                codes::SHAPE_FILE_DROPPED,
                "{root}"
            );
        }
        // A trusted file that is missing still fails the load.
        let e = load(vec![opened("root", "extends = [\"gone\"]\n", 1)], &mut f, V).unwrap_err();
        assert_eq!(codes_of(&e.errors), [codes::EXTENDS_BAD_PATH]);
    }

    // 이것을 실패시키는 것: 뿌리(`conf.d`)를 예산 밖에 두는 것. 신뢰 뿌리는 읽기를 실패시키고,
    // 모양 전용 뿌리는 그것만 빠진다.
    #[test]
    fn roots_spend_the_same_budget() {
        let mut f = files(&[]);
        let roots = |n: u64| (0..n).map(|i| opened("r", "", i + 1)).collect::<Vec<_>>();
        assert_eq!(load(roots(32), &mut f, V).unwrap().order.len(), 32);
        let e = load(roots(33), &mut f, V).unwrap_err();
        assert_eq!(codes_of(&e.errors), [codes::EXTENDS_TOO_MANY]);
        let mut r = roots(32);
        r.push(opened("shape-root", "", 99));
        let g = load(r, &mut f, V).unwrap();
        assert_eq!(
            (g.order.len(), codes_of(&g.warnings)[0]),
            (32, codes::SHAPE_FILE_DROPPED)
        );
    }

    /// Roots on disk: counts what core asked to read.
    struct Disk {
        read: Vec<u64>,
        /// Bytes each read returns (a file can grow after `fstat`).
        pad: usize,
    }

    impl Resolver for Disk {
        fn open(&mut self, _: &Opened, _: &ExtendsRef) -> Result<Opened, OpenError> {
            unreachable!("the roots here have no extends")
        }
        fn open_root(&mut self, r: &RootMeta) -> Result<Opened, OpenError> {
            self.read.push(r.key.ino);
            let name = String::from_utf8(r.display.clone()).unwrap();
            let mut o = opened(&name, "", r.key.ino);
            o.bytes = vec![b'#'; self.pad];
            Ok(o)
        }
    }

    fn on_disk(name: &str, size: usize, ino: u64) -> Root {
        let o = opened(name, "", ino);
        Root::File(RootMeta {
            key: o.key,
            size,
            trust: o.trust,
            display: o.display,
        })
    }

    // 초과 뿌리는 읽지도 파싱하지도 않는다. 크기만 보고 판정하고, 모양 전용·unsafe 뿌리는 적용 순서에서 빠진다(W406).
    // 이것을 실패시키는 것: 뿌리를 연 뒤 예산을 보는 것, 초과한 unsafe 뿌리를 적용하는 것, 읽은 바이트를 다시 세지 않는 것.
    #[test]
    fn roots_over_the_budget_are_not_parsed() {
        let mut roots: Vec<Root> = (0..32).map(|i| on_disk("r", 0, i + 1)).collect();
        roots.push(on_disk("unsafe-root", 0, 90));
        roots.push(on_disk("shape-root", 0, 91));
        // Already in memory and not TOML: parsed, it would give a syntax error.
        roots.push(opened("unsafe-mem", "= = =", 92).into());
        let mut disk = Disk {
            read: Vec::new(),
            pad: 0,
        };
        let g = load(roots, &mut disk, V).unwrap();
        assert_eq!(disk.read, (1..=32).collect::<Vec<u64>>());
        assert_eq!(g.order.len(), 32);
        assert!(order(&g).iter().all(|n| n == "r"));
        for n in ["unsafe-root", "shape-root", "unsafe-mem"] {
            let f = g
                .files
                .iter()
                .find(|f| f.opened.display == n.as_bytes())
                .unwrap();
            assert_eq!(
                (f.status, f.opened.bytes.len()),
                (Status::Dropped, 0),
                "{n}"
            );
        }
        let c = codes_of(&g.warnings);
        assert_eq!(
            c.iter()
                .filter(|c| **c == codes::SHAPE_FILE_DROPPED)
                .count(),
            3
        );
        assert!(
            c.iter()
                .all(|c| *c == codes::SHAPE_FILE_DROPPED || *c == codes::EXTENDS_TOO_MANY)
        );
        // The size first seen decides: one big root is not read either.
        let mut disk = Disk {
            read: Vec::new(),
            pad: 0,
        };
        let g = load(
            vec![on_disk("shape-big", TOTAL_BYTES_MAX + 1, 7)],
            &mut disk,
            V,
        )
        .unwrap();
        assert!(disk.read.is_empty() && g.order.is_empty());
        assert!(codes_of(&g.warnings).contains(&codes::EXTENDS_TOO_BIG));
        // The bytes read count, not the size first seen: a trusted root that
        // grew past the budget fails the load.
        let mut disk = Disk {
            read: Vec::new(),
            pad: TOTAL_BYTES_MAX + 1,
        };
        let e = load(vec![on_disk("r", 1, 8)], &mut disk, V).unwrap_err();
        assert!(codes_of(&e.errors).contains(&codes::EXTENDS_TOO_BIG));
    }

    // 이것을 실패시키는 것: 첫 잘못된 extends에서 멈춰 나머지 오류를 숨기는 것.
    #[test]
    fn every_bad_edge_is_reported() {
        let mut f = files(&[]);
        let e = load(
            vec![opened("root", "extends = [\"nope1\", \"nope2\"]\n", 1)],
            &mut f,
            V,
        )
        .unwrap_err();
        assert_eq!(
            codes_of(&e.errors),
            [codes::EXTENDS_BAD_PATH, codes::EXTENDS_BAD_PATH]
        );
    }

    // 이것을 실패시키는 것: 신뢰 파일의 requires·문법 오류를 경고로 낮추는 것.
    #[test]
    fn trusted_problems_fail_the_load() {
        let mut f = files(&[]);
        let e = load(vec![opened("root", "requires = \">=0.4\"\n", 1)], &mut f, V).unwrap_err();
        assert_eq!(codes_of(&e.errors), [codes::REQUIRES_NEWER]);
        assert!(
            load(
                vec![opened("root", "requires = \">=0.3\"\nversion = 1\n", 1)],
                &mut f,
                V
            )
            .is_ok()
        );
        let mut f = files(&[("shape-t", "requires = \">=9.0\"\n")]);
        let g = load(
            vec![opened("root", "extends = [\"shape-t\"]\n", 1)],
            &mut f,
            V,
        )
        .unwrap();
        assert_eq!(
            codes_of(&g.warnings),
            [codes::SHAPE_FILE_DROPPED, codes::REQUIRES_NEWER]
        );
    }

    // 이것을 실패시키는 것: `>=` 밖의 형식을 받거나 부분이 하나뿐인 버전을 받는 것.
    #[test]
    fn requires_grammar() {
        assert_eq!(parse_requires(">=0.3"), Some([0, 3, 0]));
        assert_eq!(parse_requires(">=1.2.3"), Some([1, 2, 3]));
        assert_eq!(parse_requires(">=999999999.0"), Some([999999999, 0, 0]));
        for bad in [
            "0.3",
            ">=0",
            ">=0.3.1.2",
            ">= 0.3",
            ">=0.x",
            ">=0..3",
            "^0.3",
            ">=1000000000.0",
        ] {
            assert_eq!(parse_requires(bad), None, "{bad}");
        }
    }

    // 이것을 실패시키는 것: 파일 크기 덧셈을 넘치게 하거나, 커진 비신뢰 뿌리를 파싱해 전체를 실패시키는 것.
    #[test]
    fn oversized_metadata_and_growing_untrusted_roots_are_isolated() {
        for name in ["shape-root", "unsafe-root"] {
            let mut disk = Disk {
                read: Vec::new(),
                pad: TOTAL_BYTES_MAX + 1,
            };
            let g = load(vec![on_disk(name, 1, 7)], &mut disk, V).unwrap();
            assert_eq!(disk.read, [7]);
            assert!(g.order.is_empty());
            assert_eq!(g.files[0].status, Status::Dropped);
            assert_eq!(
                codes_of(&g.warnings),
                [codes::SHAPE_FILE_DROPPED, codes::EXTENDS_TOO_BIG]
            );
        }
        let mut disk = Disk {
            read: Vec::new(),
            pad: 0,
        };
        let g = load(
            vec![
                Root::Read(opened("r", "x = 1", 1)),
                on_disk("shape-huge", usize::MAX, 7),
            ],
            &mut disk,
            V,
        )
        .unwrap();
        assert!(disk.read.is_empty());
        assert_eq!(order(&g), ["r"]);
        assert!(codes_of(&g.warnings).contains(&codes::EXTENDS_TOO_BIG));
    }

    // 이것을 실패시키는 것: 하위 그래프가 실패한 Unsafe 잎을 무료로 남기거나, 잎 자체가 초과해도 남기는 것.
    #[test]
    fn retained_unsafe_leaves_still_spend_their_budget() {
        let mut roots = vec![
            opened("unsafe-a", "extends = [\"gone\"]", 90),
            opened("unsafe-b", "extends = [\"gone\"]", 91),
        ];
        roots.extend((0..31).map(|i| opened("r", "", i + 1)));
        let g = load(roots, &mut files(&[]), V).unwrap();
        assert_eq!(g.order.len(), 32);
        assert_eq!(g.files[0].status, Status::Applied);
        assert_eq!(g.files[1].status, Status::Dropped);
        assert_eq!(g.files[0].trust, Trust::Unsafe);

        let mut big = String::from("extends = [\"gone\"]\n#");
        big.push_str(&"#".repeat(tree::FILE_BYTES_MAX - big.len()));
        let mut roots = vec![opened("unsafe-a", &big, 90), opened("shape-b", "x = 1", 91)];
        roots.extend((0..3).map(|i| opened("r", &"#".repeat(tree::FILE_BYTES_MAX), i + 1)));
        let g = load(roots, &mut files(&[]), V).unwrap();
        assert_eq!(order(&g), ["unsafe-a", "r", "r", "r"]);
        assert!(codes_of(&g.warnings).contains(&codes::EXTENDS_TOO_BIG));
    }

    /// Checks that each resolver read is completed before another begins.
    struct Session {
        files: Files,
        root_bytes: Vec<u8>,
        pending: Option<FileKey>,
        adopted: Vec<(FileKey, Option<Trust>)>,
    }

    impl Resolver for Session {
        fn open(&mut self, from: &Opened, r: &ExtendsRef) -> Result<Opened, OpenError> {
            assert!(self.pending.is_none(), "the preceding read was not adopted");
            let mut o = self.files.open(from, r)?;
            if matches!(r.text.as_str(), "alias" | "shape-alias" | "unsafe-alias") {
                o.key = self
                    .files
                    .open(
                        from,
                        &ExtendsRef {
                            text: "clean".into(),
                            span: r.span,
                        },
                    )?
                    .key;
            }
            self.pending = Some(o.key);
            Ok(o)
        }
        fn open_root(&mut self, r: &RootMeta) -> Result<Opened, OpenError> {
            assert!(self.pending.is_none());
            self.pending = Some(r.key);
            Ok(Opened {
                key: r.key,
                bytes: self.root_bytes.clone(),
                trust: r.trust,
                display: r.display.clone(),
            })
        }
        fn adopt(&mut self, key: FileKey, trust: Option<Trust>) {
            if let Some(pending) = self.pending.take() {
                assert_eq!(pending, key);
                self.adopted.push((key, trust));
            }
        }
    }

    // 이것을 실패시키는 것: 채택 응답 누락, 별칭의 중복 적용, 오염된 자식의 실행 채택, 제외 후보의 실행 증거 보유.
    #[test]
    fn resolver_adoption_preserves_effective_trust_and_aliases() {
        let huge = "#".repeat(TOTAL_BYTES_MAX + 1);
        let mut session = Session {
            files: files(&[
                ("shape-t", "extends = ['clean', 'tainted', 'big2']"),
                ("clean", "x = 1"),
                ("alias", "x = 1"),
                ("tainted", "x = 2"),
                ("shape-big", &huge),
                ("big2", &huge),
            ]),
            root_bytes: b"extends = ['shape-t', 'clean', 'alias', 'shape-big']".to_vec(),
            pending: None,
            adopted: Vec::new(),
        };
        let g = load(vec![on_disk("root", 100, 1)], &mut session, V).unwrap();
        assert!(session.pending.is_none());
        assert_eq!(order(&g), ["clean", "root"]);
        let key = |name: &[u8]| {
            g.files
                .iter()
                .find(|f| f.opened.display == name)
                .unwrap()
                .opened
                .key
        };
        assert_eq!(
            session.adopted,
            [
                (FileKey { dev: 1, ino: 1 }, Some(Trust::Executable)),
                (key(b"shape-t"), Some(Trust::ShapeOnly)),
                (key(b"clean"), Some(Trust::Executable)),
                (key(b"clean"), Some(Trust::Executable)),
                (key(b"shape-big"), None),
                (key(b"clean"), Some(Trust::Executable)),
                (key(b"tainted"), Some(Trust::ShapeOnly)),
                (key(b"big2"), None),
            ]
        );
        assert_eq!(trust_of(&g, "big2"), Trust::ShapeOnly);
        session.adopted.clear();
        session.root_bytes = huge.into_bytes();
        let g = load(vec![on_disk("shape-root", 1, 1)], &mut session, V).unwrap();
        assert!(session.pending.is_none() && g.order.is_empty());
        assert_eq!(session.adopted, [(FileKey { dev: 1, ino: 1 }, None)]);
    }

    // 이것을 실패시키는 것: 거절 후보의 정체를 잃거나 큰 바이트를 보유하거나, 별칭을 경로 이름만으로 비교하는 것.
    #[test]
    fn catalog_keeps_rejected_sources_and_uses_device_and_inode() {
        use crate::diag::SourceView;
        let huge = "#".repeat(TOTAL_BYTES_MAX + 1);
        let g = load(
            vec![opened("root", "extends = ['shape-big']", 1)],
            &mut files(&[("shape-big", &huge)]),
            V,
        )
        .unwrap();
        assert_eq!(g.files.len(), 2);
        assert_eq!(g.files[1].status, Status::Dropped);
        assert_eq!(g.files[1].via, [SourceId(0)]);
        let catalog = Catalog(&g.files);
        assert_eq!(catalog.display(SourceId(1)), b"shape-big");
        assert!(catalog.bytes(SourceId(1)).is_empty());
        assert_eq!(catalog.display(SourceId(999)), b"?");
        assert_eq!(catalog.bytes(SourceId(999)), b"");
        let e = load(
            vec![opened("root", "extends = ['big']", 1)],
            &mut files(&[("big", &huge)]),
            V,
        )
        .unwrap_err();
        assert_eq!(e.files[1].status, Status::Failed);

        let a = opened("a", "x = 1", 1);
        let mut b = a.clone();
        b.key.dev = 2;
        b.display = b"b".to_vec();
        let g = load(vec![a.clone(), a, b], &mut files(&[]), V).unwrap();
        assert_eq!(order(&g), ["a", "b"]);
    }

    // 이것을 실패시키는 것: 잘못된 메타 키를 받아들이거나, 격리된 원본의 진단 범위·경유 경로를 잃는 것.
    #[test]
    fn metadata_errors_keep_their_source_and_span() {
        for (text, code) in [
            ("extends = 1", codes::WRONG_TYPE),
            ("extends = [1]", codes::WRONG_TYPE),
            ("version = 2", codes::VERSION_UNKNOWN),
            ("version = false", codes::WRONG_TYPE),
            ("requires = 1", codes::WRONG_TYPE),
            ("requires = '^1.0'", codes::BAD_VALUE),
            ("x = [", codes::TOML_SYNTAX),
        ] {
            let g = load(
                vec![opened("root", "extends = ['shape-bad']", 1)],
                &mut files(&[("shape-bad", text)]),
                V,
            )
            .unwrap();
            assert_eq!(order(&g), ["root"]);
            assert_eq!(
                codes_of(&g.warnings),
                [codes::SHAPE_FILE_DROPPED, code],
                "{text}"
            );
            let d = &g.warnings[1];
            assert_eq!(d.via, [SourceId(0)]);
            let Place::Source { id, span } = d.at else {
                panic!()
            };
            assert_eq!(id, SourceId(1));
            assert!(span.start > 0 && span.start <= span.end && span.end as usize <= text.len());
            let e = load(vec![opened("unsafe-bad", text, 1)], &mut files(&[]), V).unwrap_err();
            assert_eq!(codes_of(&e.errors), [code]);
        }
    }

    // 이것을 실패시키는 것: 앞서 버린 파일을 뒤 모양 전용 경로에서 다시 살리는 것.
    #[test]
    fn a_dropped_shared_descendant_stays_dropped() {
        let mut f = files(&[
            ("shape-a", "extends = ['shared', 'gone']"),
            ("shape-b", "extends = ['shared']"),
            ("shared", "x = 1"),
        ]);
        let g = load(
            vec![opened("root", "extends = ['shape-a', 'shape-b']", 1)],
            &mut f,
            V,
        )
        .unwrap();
        assert_eq!(order(&g), ["shape-b", "root"]);
        assert_eq!(
            g.files
                .iter()
                .find(|f| f.opened.display == b"shared")
                .unwrap()
                .status,
            Status::Dropped
        );
    }

    // 이것을 실패시키는 것: 파서 오류 종류를 다른 안정 코드로 바꾸거나 원래 바이트 범위를 잃는 것.
    #[test]
    fn syntax_diagnostics_keep_codes_and_ranges() {
        let span = Span { start: 4, end: 7 };
        for (kind, code) in [
            (SyntaxErrorKind::TooLarge, codes::FILE_TOO_LARGE),
            (SyntaxErrorKind::NotUtf8, codes::NOT_UTF8),
            (SyntaxErrorKind::TooDeep, codes::NESTING_TOO_DEEP),
            (SyntaxErrorKind::IntegerRange, codes::INTEGER_RANGE),
            (SyntaxErrorKind::FloatSyntax, codes::TOML_SYNTAX),
            (
                SyntaxErrorKind::Toml("bad syntax".into()),
                codes::TOML_SYNTAX,
            ),
        ] {
            let d = syntax_diag(SourceId(2), &tree::SyntaxError { span, kind });
            assert_eq!(d.code, code);
            assert_eq!(
                d.at,
                Place::Source {
                    id: SourceId(2),
                    span
                }
            );
        }
    }

    // 이것을 실패시키는 것: 읽지 못한 비신뢰 뿌리로 전체를 실패시키거나, 신뢰 뿌리의 읽기 실패를 숨기는 것.
    #[test]
    fn unread_root_errors_are_trust_scoped() {
        for name in ["shape-root", "unsafe-root"] {
            let g = load(vec![on_disk(name, 0, 1)], &mut files(&[]), V).unwrap();
            assert!(g.order.is_empty());
            assert_eq!(g.files[0].status, Status::Dropped);
            assert!(g.files[0].opened.bytes.is_empty());
            assert_eq!(
                codes_of(&g.warnings),
                [codes::SHAPE_FILE_DROPPED, codes::EXTENDS_BAD_PATH]
            );
        }
        let e = load(vec![on_disk("root", 0, 1)], &mut files(&[]), V).unwrap_err();
        assert_eq!(e.files[0].status, Status::Failed);
        assert_eq!(codes_of(&e.errors), [codes::EXTENDS_BAD_PATH]);
        assert!(e.warnings.is_empty());
    }

    // 이것을 실패시키는 것: 비신뢰 별칭을 먼저 본 정체를 신뢰 경로에서도 건너뛰어 신뢰·자리·하위 그래프를 잃는 것.
    #[test]
    fn a_trusted_alias_promotes_identity_at_its_trusted_place() {
        for alias in ["shape-alias", "unsafe-alias"] {
            let mut session = Session {
                files: files(&[
                    (alias, "extends = ['child']"),
                    ("clean", "extends = ['child']"),
                    ("child", "x = 1"),
                    ("middle", "x = 2"),
                ]),
                root_bytes: alloc::format!("extends = ['{alias}', 'middle', 'clean']").into_bytes(),
                pending: None,
                adopted: Vec::new(),
            };
            let g = load(vec![on_disk("root", 100, 1)], &mut session, V).unwrap();
            assert_eq!(order(&g), ["middle", "child", "clean", "root"]);
            assert_eq!(g.files.len(), 4);
            assert!(g.files.iter().all(|f| f.trust == Trust::Executable));
            assert_eq!(g.files[1].via, [SourceId(0)]);
            assert_eq!(session.adopted.last().unwrap().1, Some(Trust::Executable));
            assert!(session.pending.is_none());
        }
    }

    // 이것을 실패시키는 것: 먼저 본 모양 전용 뿌리가 같은 정체의 신뢰 뿌리를 가리거나, 승격한 뿌리를 비신뢰 예산에 이중 계산하는 것.
    #[test]
    fn trusted_root_aliases_replace_the_shape_place_and_budget() {
        let mut roots = vec![
            opened("shape-alias", "x = 1", 1),
            opened("middle", "x = 2", 2),
        ];
        roots.push(opened("clean", "x = 1", 1));
        roots.extend((3..32).map(|i| opened("r", "", i)));
        roots.push(opened("shape-last", "", 32));
        let g = load(roots, &mut files(&[]), V).unwrap();
        assert_eq!(&order(&g)[..2], ["middle", "clean"]);
        assert_eq!(g.order.len(), 32);
        assert_eq!(g.files.len(), 32);
        assert_eq!(g.files[0].trust, Trust::Executable);
        assert!(g.warnings.is_empty());
    }

    // 이것을 실패시키는 것: 깊이 때문에 버린 별칭으로 더 얕은 신뢰 경로까지 버리는 것.
    #[test]
    fn rejected_aliases_do_not_hide_a_later_trusted_path() {
        let mut session = Session {
            files: chain(8, "f"),
            root_bytes: b"extends = ['f0', 'clean']".to_vec(),
            pending: None,
            adopted: Vec::new(),
        };
        session
            .files
            .0
            .insert("f7", "extends = ['shape-alias']".into());
        session.files.0.insert("shape-alias", "x = 1".into());
        session.files.0.insert("clean", "x = 1".into());
        let g = load(vec![on_disk("root", 100, 1)], &mut session, V).unwrap();
        assert_eq!(trust_of(&g, "clean"), Trust::Executable);
        assert_eq!(g.order.len(), 10);
        assert_eq!(g.files.len(), 10);
        assert!(session.adopted.iter().any(|(_, trust)| trust.is_none()));
        let clean = g
            .files
            .iter()
            .find(|f| f.opened.display == b"clean")
            .unwrap();
        assert_eq!(clean.via, [SourceId(0)]);
    }

    // 이것을 실패시키는 것: 비신뢰 별칭이 신뢰 조상의 정체를 가리킨다고 신뢰 그래프의 순환으로 처리하는 것.
    #[test]
    fn a_shape_alias_cannot_create_a_trusted_cycle() {
        let mut session = Session {
            files: files(&[("clean", ""), ("shape-alias", "extends = ['shape-alias']")]),
            root_bytes: b"extends = ['shape-alias']".to_vec(),
            pending: None,
            adopted: Vec::new(),
        };
        // 'clean' is the first entry (key 100), the root's same identity.
        let g = load(vec![on_disk("root", 100, 100)], &mut session, V).unwrap();
        assert_eq!(order(&g), ["root"]);
        assert!(g.warnings.is_empty());
        assert_eq!(session.adopted.len(), 2);
        assert!(
            session
                .adopted
                .iter()
                .all(|(_, t)| *t == Some(Trust::Executable))
        );
    }

    // 이것을 실패시키는 것: 예산으로 거절한 정체를 재방문할 때 Some(Executable)로 채택해 실행 증거를 보유하는 것.
    #[test]
    fn rejected_aliases_are_never_adopted_for_execution() {
        let huge = "#".repeat(TOTAL_BYTES_MAX + 1);
        for text in ["extends = ['big', 'big']", "extends = ['shape-t']"] {
            let mut session = Session {
                files: files(&[("big", &huge), ("shape-t", "extends = ['big', 'big']")]),
                root_bytes: text.as_bytes().to_vec(),
                pending: None,
                adopted: Vec::new(),
            };
            let _ = load(vec![on_disk("root", 100, 1)], &mut session, V);
            assert!(session.pending.is_none());
            let big: Vec<_> = session
                .adopted
                .iter()
                .filter(|(k, _)| k.ino == 100)
                .collect();
            assert_eq!(big.len(), 2);
            assert!(big.iter().all(|(_, trust)| trust.is_none()));
        }
    }
}
