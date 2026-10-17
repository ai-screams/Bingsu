//! The CLI side of reading config (spec section 2 "합치는 순서", `extends`
//! path and safety rows; Task R3). Core walks the `extends` graph and
//! returns the S3a source graph; this module finds the roots,
//! resolves and opens each `extends` entry, checks every file and decides
//! its trust:
//!
//! - `Executable`: the file is under the config root `init` pinned, or it
//!   is at the canonical path recorded by `config use`, and it
//!   passes the safety check (owned by the user, nobody else can write it
//!   or a folder above it; group write follows `group_policy`). A changed
//!   identity at that same path is renewed only after the full check.
//! - `Unsafe`: such a file that fails the check. Its execution keys are kept
//!   so the segment can be named, and nothing it configures runs (core W405).
//! - `ShapeOnly`: every other file, checked or not (spec: other `extends`
//!   are shape-only whatever the check says), and every file under a root
//!   init marked shape-only (`ConfigRootPin::shape_only`).
//!
//! Root discovery probes metadata without retaining its descriptors. The
//! read plan deduplicates FileKey; core then admits roots under its trusted
//! and shape-only budgets. Each admitted source is opened again, compared
//! to the plan, and read from the same descriptor that supplied its facts.
//! Core reports adoption before the next open. Only adopted execution sources
//! retain descriptors; shape-only or excluded candidates close immediately.
//! Loader retains execution source, root, parent, link, listing and approval evidence until
//! N2 calls verified immediately before publication.
use super::evidence::{Encoder, EvidenceExport};
use crate::commands::group_policy::SystemGroups;
use crate::commands::runtime_root::{Chain, open_chain};
use crate::commands::source_path::Resolved;
use crate::commands::sys;
use crate::commands::trust_record::{Record, RecordEvidence};
use bingsu_core::config::source::{
    ExtendsRef, FileKey, Found, OpenError, Opened, Resolver, Root, RootMeta, Status, Trust,
};
use bingsu_core::config::tree::FILE_BYTES_MAX;
use bingsu_core::fs_trust::{GroupOracle, Refusal};
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::io::{Read, Seek};
use std::os::fd::AsFd;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};

/// The built-in source's key: no file has inode 0.
pub const BUILTIN_KEY: FileKey = FileKey { dev: 0, ino: 0 };

/// What `init` pinned and who the user is.
pub struct Places {
    /// Canonical and written roots with checked parent/link/target evidence.
    pub config_root: crate::commands::init::roots::ConfigRootPin,
    /// The home folder from `getpwuid` (`--home`), for `~/` in `extends`.
    pub home: PathBuf,
    pub me: u32,
    pub user: Vec<u8>,
}

/// Why a file that could give execution keys did not (for `config check`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Untrusted {
    /// The safety check refused it (`Unsafe`).
    Unsafe(Refusal),
}

/// What the refresh helper may publish after this read (ruling P-R4, spec
/// section 4 "표식을 새로 쓰는 조건" as amended): the files left out were
/// checked to the end, so the rest is verified and its execution units get
/// a marker; the files left out are warned about.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Verified {
    /// Publish the snapshot and a marker for its execution set. `left_out`:
    /// files dropped (rule 5) or not trusted to run (`Unsafe`), to warn.
    Publish { left_out: Vec<PathBuf> },
    /// A trusted file failed: confirmed, so an invalid marker (spec 4).
    Invalid,
    /// The source set was not read to the end (a `conf.d` listing failed):
    /// no new marker; the old one ages out after T.
    Incomplete,
}

/// One file opened and judged.
struct Checked {
    evidence: Resolved,
    key: FileKey,
    size: usize,
    trust: Trust,
    canonical: PathBuf,
    written: PathBuf,
}

/// Independent resource guard, not the 32-file semantic budget. Hitting
/// this marks the session incomplete; it never invents a FileKey.
pub const SESSION_FDS_MAX: usize = 4096;

struct Planned {
    written: PathBuf,
    canonical: PathBuf,
    trust: Trust,
}

struct Listing {
    chain: Chain,
    path_evidence: Vec<u8>,
    file: std::fs::File,
    names: Vec<OsString>,
}

fn config_names(file: &std::fs::File) -> std::io::Result<Vec<OsString>> {
    let mut names: Vec<_> = sys::directory_names(file.as_fd())?
        .into_iter()
        .filter(|n| n.as_bytes().ends_with(b".toml") && !n.as_bytes().starts_with(b"."))
        .collect();
    names.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
    Ok(names)
}

/// Opens and judges files for one config read.
pub struct Loader {
    places: Places,
    record: Option<Record>,
    /// Metadata-only read plan, keyed by identity. Core owns file budgets.
    plan: BTreeMap<FileKey, Planned>,
    /// The latest read awaits core's adoption decision (at most one).
    pending: Option<Checked>,
    /// Executable sources adopted by core, retained through publication.
    held: BTreeMap<FileKey, Checked>,
    pub(super) record_evidence: Option<RecordEvidence>,
    fds: usize,
    fd_cap: usize,
    listing: Option<Listing>,
    /// Roots passed unread, by their stand-in key: why they were not opened.
    unread: BTreeMap<FileKey, OpenError>,
    /// Why each file that could have been trusted was not.
    pub untrusted: Vec<(FileKey, PathBuf, Untrusted)>,
    pub remedies: Vec<String>,
    /// The `config use` file's new identity, when another file now stands
    /// at the recorded path and it passed the whole safety check (ruling
    /// P-R3c, spec change S-10). The caller writes it back with
    /// `trust_record::write`.
    pub renew: Option<Record>,
    /// False when the source set could not be listed to the end.
    complete: bool,
    observed: BTreeMap<PathBuf, Vec<u8>>,
    absent: BTreeMap<PathBuf, (PathBuf, Vec<u8>)>,
    edges: Vec<(FileKey, ExtendsRef, PathBuf)>,
}

fn open_error(reason: impl Into<String>, trust: Trust) -> OpenError {
    OpenError {
        reason: reason.into(),
        trust,
    }
}

fn errno_text(e: &std::io::Error) -> String {
    e.raw_os_error()
        .map_or_else(|| e.to_string(), |n| format!("errno {n}"))
}

impl Loader {
    pub fn new(places: Places) -> Self {
        let mut loader = Self {
            record: None,
            held: BTreeMap::new(),
            plan: BTreeMap::new(),
            record_evidence: None,
            fds: places.config_root.evidence.fd_count(),
            places,
            pending: None,
            fd_cap: SESSION_FDS_MAX,
            listing: None,
            unread: BTreeMap::new(),
            untrusted: Vec::new(),
            remedies: Vec::new(),
            renew: None,
            complete: true,
            observed: BTreeMap::new(),
            absent: BTreeMap::new(),
            edges: Vec::new(),
        };
        if loader.places.config_root.evidence.canonical != loader.places.config_root.path {
            let missing = loader.places.config_root.path.clone();
            loader.observe_absence(&missing);
        }
        loader
    }

    /// The only production interface for an approved external config.
    pub fn with_record(places: Places, evidence: RecordEvidence) -> Self {
        let mut loader = Self::new(places);
        loader.record = Some(evidence.record.clone());
        loader.fds += evidence.fd_count();
        loader.record_evidence = Some(evidence);
        loader
    }

    /// N2 calls this immediately before publishing, while Loader still owns
    /// every original fd. Changed evidence means no new marker. A fresh
    /// oracle checks memberships again; cached per-walk answers do not leak.
    pub fn revalidate(&self) -> Result<(), String> {
        self.revalidate_with(&mut SystemGroups::new(&self.places.user))
    }

    fn revalidate_with(&self, groups: &mut dyn GroupOracle) -> Result<(), String> {
        if !self.complete {
            return Err("incomplete session".into());
        }
        for (path, before) in &self.observed {
            let now = Resolved::open(path, self.places.me, groups).map_err(|e| e.to_string())?;
            if now.evidence_export().map_err(|e| e.to_string())? != *before {
                return Err("source observation changed".into());
            }
        }
        for (path, (prefix, before)) in &self.absent {
            if !std::fs::symlink_metadata(path)
                .is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound)
            {
                return Err("absence changed".into());
            }
            let now =
                Resolved::open_dir(prefix, self.places.me, groups).map_err(|e| e.to_string())?;
            if now.evidence_export().map_err(|e| e.to_string())? != *before {
                return Err("absence parent changed".into());
            }
        }
        if let Some(listing) = &self.listing {
            let now = Resolved::open_dir(
                &self.places.config_root.path.join("conf.d"),
                self.places.me,
                groups,
            )
            .map_err(|e| e.to_string())?;
            if now.evidence_export().map_err(|e| e.to_string())? != listing.path_evidence {
                return Err("conf.d path changed".into());
            }
            listing.chain.revalidate().map_err(|e| e.to_string())?;
            if config_names(&listing.file).map_err(|e| e.to_string())? != listing.names {
                return Err("conf.d names changed".into());
            }
        }
        let root = &self.places.config_root;
        // A shape-only root grants nothing to run; it must still show no
        // refusal other than `Undecided`, and its evidence must not change.
        if root.shape_only {
            root.evidence
                .revalidate_assuming_decided(self.places.me, groups)
        } else {
            root.evidence.revalidate(self.places.me, groups)
        }
        .map_err(|e| format!("config root: {e}"))?;
        if let Some(record) = &self.record_evidence {
            record
                .revalidate(self.places.me, groups)
                .map_err(|e| format!("record: {e:?}"))?;
        } else if self.record.is_some() {
            return Err("approval has no descriptor evidence".into());
        }
        for c in self.held.values().filter(|c| c.trust == Trust::Executable) {
            c.evidence
                .revalidate(self.places.me, groups)
                .map_err(|e| e.to_string())?;
        }
        Ok(())
    }

    fn observe_absence(&mut self, path: &Path) {
        let mut prefix = path.parent();
        while let Some(parent) = prefix {
            match Resolved::open_dir(
                parent,
                self.places.me,
                &mut SystemGroups::new(&self.places.user),
            ) {
                Ok(e) => {
                    match e.evidence_export() {
                        Ok(bytes) => {
                            self.absent
                                .insert(path.to_path_buf(), (parent.to_path_buf(), bytes));
                        }
                        Err(_) => self.complete = false,
                    }
                    return;
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => prefix = parent.parent(),
                Err(_) => break,
            }
        }
        self.complete = false;
    }

    /// Comparison data comes from this session, never from a second stat-only
    /// summary. Shape-only observations are exported before their fds close.
    pub fn evidence_export(
        &self,
        files: &[Found],
        state: &Path,
        version: [u32; 3],
        selection: &[u8],
    ) -> std::io::Result<EvidenceExport> {
        let mut e = Encoder::new();
        e.path(&self.places.config_root.path);
        e.path(state);
        e.path(&self.places.config_root.written);
        e.path(&self.places.home);
        e.byte(u8::from(self.places.config_root.shape_only));
        for n in version {
            e.num(n.into());
        }
        e.blob(selection);
        let context_end = e.len();
        e.catalog(files);
        let catalog_end = e.len();
        e.count(self.edges.len());
        for (from, reference, path) in &self.edges {
            e.num(from.dev);
            e.num(from.ino);
            e.blob(reference.text.as_bytes());
            e.num(reference.span.start.into());
            e.num(reference.span.end.into());
            e.path(path);
        }
        let edges_end = e.len();
        e.count(self.observed.len());
        for (p, b) in &self.observed {
            e.path(p);
            e.blob(b);
        }
        let observations_end = e.len();
        e.count(self.absent.len());
        for (p, (prefix, b)) in &self.absent {
            e.path(p);
            e.path(prefix);
            e.blob(b);
        }
        let absent_end = e.len();
        e.blob(&self.places.config_root.evidence.evidence_export()?);
        e.count(self.held.len());
        for (key, c) in &self.held {
            e.num(key.dev);
            e.num(key.ino);
            e.blob(&c.evidence.evidence_export()?);
        }
        let held_end = e.len();
        e.byte(u8::from(self.listing.is_some()));
        if let Some(l) = &self.listing {
            e.chain(&l.chain);
            e.blob(&l.path_evidence);
            e.count(l.names.len());
            for n in &l.names {
                e.blob(n.as_bytes());
            }
        }
        e.byte(u8::from(self.complete));
        let listing_end = e.len();
        e.byte(u8::from(self.record_evidence.is_some()));
        if let Some(r) = &self.record_evidence {
            r.export(&mut e);
        }
        Ok(EvidenceExport {
            comparison: e.finish()?,
            context_end,
            catalog_end,
            edges_end,
            observations_end,
            absent_end,
            held_end,
            listing_end,
        })
    }

    /// Where a canonical path may give execution keys: under the config
    /// root, or the `config use` file (its identity is compared after the
    /// file is open).
    /// Under a shape-only root nothing is a trusted place, the `config use`
    /// file included when it lies under that root.
    fn trusted_place(&self, canonical: &Path) -> bool {
        let root = &self.places.config_root;
        let under_root = canonical.starts_with(&root.path);
        (under_root && !root.shape_only)
            || (self.record.as_ref().is_some_and(|r| r.path == canonical)
                && !(under_root && root.shape_only))
    }

    /// Candidate place only; this never grants execution trust on its own.
    /// Resolved checks every parent chain, link owner and folder target.
    fn linked_from_root(&self, written: &Path) -> bool {
        !self.places.config_root.shape_only
            && written.starts_with(&self.places.config_root.path)
            && !written
                .components()
                .any(|c| matches!(c, std::path::Component::ParentDir))
    }

    /// Unresolved errors have a separate, conservative place verdict.
    /// Resolve the longest existing prefix before classifying a missing
    /// suffix; never pass `/config/../themes/missing` to trusted_place.
    fn unresolved_place(&self, written: &Path) -> Trust {
        let mut prefix = written.to_path_buf();
        let mut suffix = Vec::new();
        loop {
            if let Ok(mut resolved) = std::fs::canonicalize(&prefix) {
                for part in suffix.iter().rev() {
                    resolved.push(part);
                }
                let mut normalized = PathBuf::new();
                for c in resolved.components() {
                    match c {
                        std::path::Component::ParentDir => {
                            normalized.pop();
                        }
                        std::path::Component::CurDir => {}
                        other => normalized.push(other.as_os_str()),
                    }
                }
                return if self.trusted_place(&normalized) || self.linked_from_root(written) {
                    Trust::Executable
                } else {
                    Trust::ShapeOnly
                };
            }
            let Some(name) = prefix.file_name().map(|n| n.to_os_string()) else {
                return Trust::ShapeOnly;
            };
            suffix.push(name);
            if !prefix.pop() {
                return Trust::ShapeOnly;
            }
        }
    }

    fn check(&mut self, written: &Path) -> Result<Checked, OpenError> {
        let guess = self.unresolved_place(written);
        let mut groups = SystemGroups::new(&self.places.user);
        let evidence = Resolved::open(written, self.places.me, &mut groups).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                self.observe_absence(written);
            } else {
                self.complete = false;
            }
            open_error(errno_text(&e), guess)
        })?;
        match evidence.evidence_export() {
            Ok(bytes) => {
                if self.observed.get(written).is_some_and(|old| old != &bytes) {
                    self.complete = false;
                }
                self.observed.entry(written.to_path_buf()).or_insert(bytes);
            }
            Err(_) => self.complete = false,
        }
        let canonical = evidence.canonical.clone();
        let key = FileKey {
            dev: evidence.stamp.dev,
            ino: evidence.stamp.ino,
        };
        let place = self.trusted_place(&canonical) || self.linked_from_root(written);
        let trust = if !place {
            Trust::ShapeOnly
        } else if let Some(r) = evidence.refusal {
            if matches!(r, Refusal::Undecided { .. }) {
                self.remedies
                    .push(crate::commands::group_policy::undecided_remedy(
                        evidence.blocked_path.as_deref().unwrap_or(&canonical),
                    ));
            }
            self.untrusted
                .push((key, canonical.clone(), Untrusted::Unsafe(r)));
            Trust::Unsafe
        } else {
            Trust::Executable
        };
        Ok(Checked {
            key,
            size: usize::try_from(evidence.stamp.size).unwrap_or(usize::MAX),
            trust,
            canonical,
            written: written.to_path_buf(),
            evidence,
        })
    }

    fn read_candidate(&mut self, mut c: Checked) -> Result<Opened, OpenError> {
        let mut bytes = Vec::new();
        c.evidence
            .file
            .rewind()
            .and_then(|()| {
                c.evidence
                    .file
                    .by_ref()
                    .take(FILE_BYTES_MAX as u64 + 1)
                    .read_to_end(&mut bytes)
            })
            .map_err(|e| {
                self.complete = false;
                open_error(errno_text(&e), c.trust)
            })?;
        if c.trust == Trust::Executable {
            let mut groups = SystemGroups::new(&self.places.user);
            c.evidence
                .revalidate(self.places.me, &mut groups)
                .map_err(|e| {
                    self.complete = false;
                    open_error(e.to_string(), c.trust)
                })?;
            if let Some(r) = self.record.as_ref().filter(|r| r.path == c.canonical)
                && (r.dev, r.ino) != (c.key.dev, c.key.ino)
            {
                self.renew = Some(Record {
                    dev: c.key.dev,
                    ino: c.key.ino,
                    path: c.canonical.clone(),
                });
            }
        }
        let opened = Opened {
            key: c.key,
            bytes,
            trust: c.trust,
            display: c.canonical.as_os_str().as_bytes().to_vec(),
        };
        self.pending = Some(c);
        Ok(opened)
    }

    /// Built-in, config.toml (or the recorded path), sorted conf.d names,
    /// config.local.toml. All candidates are probed one at a time and
    /// deduplicated by FileKey; core owns the semantic file/byte budgets.
    /// S3b/N2 supplies the compiled-in default TOML; R3 does not define it.
    /// Probe fds close before the next candidate. After reading, adopt
    /// retains only execution evidence, bounded by SESSION_FDS_MAX.
    pub fn roots(&mut self, builtin: &[u8]) -> Vec<Root> {
        let mut out = vec![Root::Read(Opened {
            key: BUILTIN_KEY,
            bytes: builtin.to_vec(),
            trust: Trust::Executable,
            display: b"(built-in)".to_vec(),
        })];
        let root = self.places.config_root.path.clone();
        let mut paths = Vec::new();
        match &self.record {
            Some(r) => paths.push(r.path.clone()),
            None => paths.push(root.join("config.toml")),
        }
        let listed = (|| -> std::io::Result<Listing> {
            let evidence = Resolved::open_dir(
                &root.join("conf.d"),
                self.places.me,
                &mut SystemGroups::new(&self.places.user),
            )?;
            let path_evidence = evidence.evidence_export()?;
            let canonical = evidence.canonical;
            let chain =
                open_chain(&canonical).map_err(|e| std::io::Error::other(format!("{e:?}")))?;
            let file = sys::open_dir_at_nofollow(chain.last().as_fd(), std::ffi::OsStr::new("."))?;
            let names = config_names(&file)?;
            Ok(Listing {
                chain,
                path_evidence,
                file,
                names,
            })
        })();
        match listed {
            Ok(listing) => {
                paths.extend(listing.names.iter().map(|n| root.join("conf.d").join(n)));
                self.fds += listing.chain.fds.len() + 1;
                self.listing = Some(listing);
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                self.observe_absence(&root.join("conf.d"));
            }
            Err(_) => {
                self.complete = false;
            }
        }
        paths.push(root.join("config.local.toml"));
        for p in paths {
            let selected = self.record.as_ref().is_some_and(|r| r.path == p);
            let optional =
                !selected && (p == root.join("config.toml") || p == root.join("config.local.toml"));
            if optional
                && std::fs::symlink_metadata(&p)
                    .is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound)
            {
                self.observe_absence(&p);
                continue;
            }
            match self.check(&p) {
                Ok(c) => {
                    let plan = Planned {
                        written: c.written.clone(),
                        canonical: c.canonical.clone(),
                        trust: c.trust,
                    };
                    // Deduplicate identities before core sees the read plan.
                    // If an unsafe alias came first, a later safe alias can
                    // supply execution trust without changing apply order.
                    if let Some(old) = self.plan.get_mut(&c.key) {
                        if old.trust != Trust::Executable && c.trust == Trust::Executable {
                            *old = plan;
                            for root in &mut out {
                                if let Root::File(m) = root
                                    && m.key == c.key
                                {
                                    m.trust = c.trust;
                                    m.display = c.canonical.as_os_str().as_bytes().to_vec();
                                }
                            }
                        }
                        continue;
                    }
                    out.push(Root::File(RootMeta {
                        key: c.key,
                        size: c.size,
                        trust: c.trust,
                        display: c.canonical.as_os_str().as_bytes().to_vec(),
                    }));
                    self.plan.insert(c.key, plan);
                    // All probe descriptors close here. Part S's adoption
                    // decision later selects execution evidence to retain.
                }
                Err(e) => self.pass_unread(&mut out, &p, e),
            }
        }
        out
    }

    /// Passes a root core will not get bytes for, under a stand-in key no
    /// file has (`dev` all ones), keeping why.
    fn pass_unread(&mut self, out: &mut Vec<Root>, p: &Path, e: OpenError) {
        let key = FileKey {
            dev: u64::MAX,
            ino: out.len() as u64,
        };
        out.push(Root::File(RootMeta {
            key,
            size: 0,
            trust: e.trust,
            display: p.as_os_str().as_bytes().to_vec(),
        }));
        self.unread.insert(key, e);
    }

    /// The spelling the read plan used for a file (`config path` shows it
    /// next to the canonical path when the two differ).
    pub fn written_path(&self, key: FileKey) -> Option<&Path> {
        self.plan.get(&key).map(|p| p.written.as_path())
    }

    /// N2 passes the final catalog and whether S3b produced a snapshot.
    /// This boundary deliberately uses only S3a types. Call immediately
    /// before publication, retaining this loader throughout compilation.
    pub fn verified(&self, files: &[Found], compiled: bool) -> Verified {
        if !self.complete {
            return Verified::Incomplete;
        }
        if !compiled {
            return Verified::Invalid;
        }
        if self.revalidate().is_err() {
            return Verified::Incomplete;
        }
        let left_out = files
            .iter()
            .filter(|f| f.status == Status::Dropped || f.trust == Trust::Unsafe)
            .map(|f| PathBuf::from(OsString::from_vec(f.opened.display.clone())))
            .collect();
        Verified::Publish { left_out }
    }

    /// The path an `extends` entry names, before canonicalization.
    fn resolve(&self, from: &Opened, text: &str) -> Result<PathBuf, &'static str> {
        if text.contains("://") {
            return Err("only local files");
        }
        if text.starts_with('$') {
            return Err("environment variables are not expanded");
        }
        if let Some(rest) = text.strip_prefix("~/") {
            return Ok(self.places.home.join(rest));
        }
        if text.starts_with('~') {
            return Err("only ~/ (the user's own home) is supported");
        }
        let p = Path::new(text);
        if p.is_absolute() {
            return Ok(p.to_path_buf());
        }
        let from = PathBuf::from(OsString::from_vec(from.display.clone()));
        match from.parent() {
            Some(dir) if from.is_absolute() => Ok(dir.join(p)),
            _ => Err("a relative path in a file without a folder"),
        }
    }
}

impl Resolver for Loader {
    fn adopt(&mut self, key: FileKey, trust: Option<Trust>) {
        let Some(c) = self.pending.take() else { return };
        assert_eq!(
            c.key, key,
            "adoption must immediately follow the matching read"
        );
        // Shape-only bytes (including tainted safe paths) carry no execution
        // authority. Excluded sources close here, before the next edge opens.
        if trust != Some(Trust::Executable) {
            return;
        }
        let count = c.evidence.fd_count();
        let previous = self
            .held
            .get(&c.key)
            .map_or(0, |old| old.evidence.fd_count());
        if self.fds - previous + count > self.fd_cap {
            self.complete = false;
            return;
        }
        // Preserve stronger evidence when an alias is visited through a less
        // trusted path. Its bytes still came from the same identity.
        if !self
            .held
            .get(&c.key)
            .is_some_and(|old| old.trust == Trust::Executable && c.trust != Trust::Executable)
        {
            self.fds = self.fds - previous + count;
            self.held.insert(c.key, c);
        }
    }

    fn open(&mut self, from: &Opened, r: &ExtendsRef) -> Result<Opened, OpenError> {
        let lexical = self.resolve(from, &r.text);
        let path = lexical.map_err(|why| open_error(why, Trust::ShapeOnly))?;
        self.edges.push((from.key, r.clone(), path.clone()));
        let c = self.check(&path)?;
        self.read_candidate(c)
    }

    fn open_root(&mut self, m: &RootMeta) -> Result<Opened, OpenError> {
        if let Some(e) = self.unread.remove(&m.key) {
            return Err(e);
        }
        let p = self
            .plan
            .get(&m.key)
            .ok_or_else(|| open_error("not in read plan", m.trust))?;
        let (written, canonical, trust) = (p.written.clone(), p.canonical.clone(), p.trust);
        let c = self.check(&written).inspect_err(|_| {
            self.complete = false;
        })?;
        if c.key != m.key || c.canonical != canonical || c.trust != trust {
            self.complete = false;
            return Err(open_error("source changed since read plan", m.trust));
        }
        self.read_candidate(c)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bingsu_core::config::source::{Found, load};
    use bingsu_core::diag::{Diagnostic, SourceId};

    // Tests exercise S3a graph loading only. S3b must separately verify
    // compiled execution units and pass its actual snapshot outcome.
    struct GraphResult {
        files: Vec<Found>,
        order: Vec<SourceId>,
        diagnostics: Vec<Diagnostic>,
        succeeded: bool,
    }

    fn read_graph(roots: Vec<Root>, loader: &mut Loader) -> GraphResult {
        match load(roots, loader, [0, 3, 0]) {
            Ok(r) => GraphResult {
                files: r.files,
                order: r.order,
                diagnostics: r.warnings,
                succeeded: true,
            },
            Err(mut e) => {
                e.errors.extend(e.warnings);
                GraphResult {
                    files: e.files,
                    order: Vec::new(),
                    diagnostics: e.errors,
                    succeeded: false,
                }
            }
        }
    }
    use bingsu_core::config::source::Status;
    use bingsu_core::diag_codes as codes;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    struct Fx {
        base: PathBuf,
        root: PathBuf,
        home: PathBuf,
    }

    impl Fx {
        fn new(tag: &str) -> Self {
            let d = std::env::temp_dir().join(format!("bingsu-cl-{tag}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&d);
            std::fs::create_dir_all(&d).unwrap();
            let base = std::fs::canonicalize(&d).unwrap();
            std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o700)).unwrap();
            let root = base.join("config");
            let home = base.join("home");
            std::fs::create_dir_all(root.join("conf.d")).unwrap();
            std::fs::create_dir_all(&home).unwrap();
            Self { base, root, home }
        }

        fn put(&self, p: &Path, text: &str) -> PathBuf {
            std::fs::write(p, text).unwrap();
            std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o644)).unwrap();
            p.to_path_buf()
        }

        fn loader(&self, record: Option<Record>) -> Loader {
            let me = sys::current_uid();
            let mut loader = Loader::new(Places {
                config_root: crate::commands::init::roots::ConfigRootPin::check(
                    &self.root,
                    me,
                    &mut SystemGroups::new(&sys::passwd_entry(me).unwrap().name),
                )
                .unwrap(),
                home: self.home.clone(),
                me,
                user: sys::passwd_entry(me).unwrap().name,
            });
            loader.record = record;
            loader
        }

        /// The root at 0775 with group members the system could not
        /// confirm: init keeps it as a shape-only root (R3 I-1).
        /// Group members unknown for the root folder only.
        fn root_unknown(&self) -> UnknownAt {
            let md = std::fs::metadata(&self.root).unwrap();
            UnknownAt(md.dev(), md.ino())
        }

        fn shape_only_loader(&self, record: Option<Record>) -> Loader {
            std::fs::set_permissions(&self.root, std::fs::Permissions::from_mode(0o775)).unwrap();
            let me = sys::current_uid();
            let pin = crate::commands::init::roots::ConfigRootPin::check(
                &self.root,
                me,
                &mut self.root_unknown(),
            )
            .unwrap();
            assert!(pin.shape_only);
            let mut loader = Loader::new(Places {
                config_root: pin,
                home: self.home.clone(),
                me,
                user: sys::passwd_entry(me).unwrap().name,
            });
            loader.record = record;
            loader
        }

        fn read(&self, record: Option<Record>) -> (GraphResult, Loader) {
            let mut l = self.loader(record);
            let roots = l.roots(b"");
            let r = read_graph(roots, &mut l);
            (r, l)
        }
    }

    struct UnknownAt(u64, u64);
    impl GroupOracle for UnknownAt {
        fn group_write(
            &mut self,
            at: &bingsu_core::fs_trust::Facts,
        ) -> bingsu_core::fs_trust::Group {
            if (at.dev, at.ino) == (self.0, self.1) {
                bingsu_core::fs_trust::Group::Unknown
            } else {
                bingsu_core::fs_trust::Group::HasOthers
            }
        }
    }

    impl Drop for Fx {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.base);
        }
    }

    fn trust_of(r: &GraphResult, end: &str) -> Option<(Trust, Status)> {
        r.files
            .iter()
            .find(|f| f.opened.display.ends_with(end.as_bytes()))
            .map(|f| (f.trust, f.status))
    }

    fn codes_of(r: &GraphResult) -> Vec<bingsu_core::diag::DiagCode> {
        r.diagnostics.iter().map(|d| d.code).collect()
    }

    const CMD: &str = "[segment.\"custom/k\"]\nkind = \"command\"\ncommand = [\"k\"]\n[layout.line1]\nleft = [\"custom/k\", \"dir\"]\n";

    // 합치는 순서와 신뢰: 내장 → config.toml → conf.d 이름순 → config.local.toml, 뿌리 아래 안전한 파일은 Executable,
    // 남이 쓸 수 있으면 Unsafe(그 명령은 실행 안 함), 뿌리 밖 extends는 ShapeOnly.
    // 이것을 실패시키는 것: conf.d 순서를 바꾸는 것, 안전 검사를 빼거나 뿌리 밖 파일에 실행 신뢰를 주는 것.
    #[test]
    fn roots_in_order_with_their_trust() {
        let fx = Fx::new("order");
        fx.put(
            &fx.root.join("config.toml"),
            "extends = [\"~/theme.toml\"]\n",
        );
        fx.put(&fx.root.join("conf.d/b.toml"), "");
        fx.put(&fx.root.join("conf.d/a.toml"), CMD);
        fx.put(&fx.root.join("conf.d/.hidden.toml"), "");
        fx.put(&fx.root.join("config.local.toml"), "");
        fx.put(&fx.home.join("theme.toml"), "[colors]\nmode = \"dark\"\n");
        let (r, l) = fx.read(None);
        let order: Vec<String> = r
            .order
            .iter()
            .map(|id| String::from_utf8_lossy(&r.files[id.0 as usize].opened.display).into_owned())
            .collect();
        let tails: Vec<&str> = order
            .iter()
            .map(|p| p.rsplit('/').next().unwrap())
            .collect();
        assert_eq!(
            tails,
            [
                "(built-in)",
                "theme.toml",
                "config.toml",
                "a.toml",
                "b.toml",
                "config.local.toml"
            ]
        );
        assert_eq!(
            trust_of(&r, "theme.toml"),
            Some((Trust::ShapeOnly, Status::Applied))
        );
        assert_eq!(
            trust_of(&r, "a.toml"),
            Some((Trust::Executable, Status::Applied))
        );
        assert!(l.untrusted.is_empty());
        // The same file writable by others: kept, named, not run.
        std::fs::set_permissions(
            fx.root.join("conf.d/a.toml"),
            std::fs::Permissions::from_mode(0o646),
        )
        .unwrap();
        let (r, l) = fx.read(None);
        assert_eq!(
            trust_of(&r, "a.toml"),
            Some((Trust::Unsafe, Status::Applied))
        );
        assert!(matches!(l.untrusted[0].2, Untrusted::Unsafe(Refusal::Last)));
    }

    // 파일은 한 번 연다: fstat한 fd에서 읽으므로 확인 뒤 바꿔치기한 파일은 읽히지 않는다.
    // 이것을 실패시키는 것: 읽기 계획과 다른 정체를 열고도 바이트를 읽는 것.
    #[test]
    fn a_root_replaced_after_the_check_is_not_read() {
        let fx = Fx::new("swap");
        fx.put(&fx.root.join("config.toml"), "[colors]\nmode = \"dark\"\n");
        let mut l = fx.loader(None);
        let roots = l.roots(b"");
        let swapped = fx.base.join("evil.toml");
        fx.put(&swapped, CMD);
        std::fs::rename(&swapped, fx.root.join("config.toml")).unwrap();
        let r = read_graph(roots, &mut l);
        let f = r
            .files
            .iter()
            .find(|f| f.opened.display.ends_with(b"config.toml"))
            .unwrap();
        assert!(f.opened.bytes.is_empty());
        assert!(!r.succeeded);
        assert_eq!(l.verified(&r.files, r.succeeded), Verified::Incomplete);
    }

    // extends 경로: 상대 경로는 선언한 파일의 폴더 기준, `~/`는 getpwuid 홈, URL·`$`·`~user`는 거부.
    // 신뢰 경로의 파일이 없으면 읽기 실패, 모양 전용 경로의 파일이 없으면 그것만 빠진다(W406).
    // 이것을 실패시키는 것: 상대 경로를 현재 폴더 기준으로 푸는 것, 환경 변수를 펼치는 것, 없는 파일의 신뢰를 잘못 정하는 것.
    #[test]
    fn extends_paths_resolve_from_the_declaring_file() {
        let fx = Fx::new("extends");
        std::fs::create_dir_all(fx.root.join("parts")).unwrap();
        fx.put(
            &fx.root.join("config.toml"),
            "extends = [\"parts/a.toml\"]\n",
        );
        fx.put(&fx.root.join("parts/a.toml"), "extends = [\"b.toml\"]\n");
        fx.put(&fx.root.join("parts/b.toml"), CMD);
        let (r, _) = fx.read(None);
        assert_eq!(
            trust_of(&r, "parts/b.toml"),
            Some((Trust::Executable, Status::Applied))
        );
        for (bad, why) in [
            ("https://x/t.toml", "only local files"),
            ("$HOME/t.toml", "environment variables are not expanded"),
            ("~root/t.toml", "only ~/"),
        ] {
            fx.put(
                &fx.root.join("config.toml"),
                &format!("extends = [\"{bad}\"]\n"),
            );
            let (r, _) = fx.read(None);
            assert!(r.succeeded, "{bad}: {:?}", codes_of(&r));
            let d = r
                .diagnostics
                .iter()
                .find(|d| d.code == codes::EXTENDS_BAD_PATH)
                .unwrap();
            let reason = d.args.iter().find(|a| a.name == "reason").unwrap();
            assert!(reason.value.starts_with(why), "{bad}: {}", reason.value);
        }
        fx.put(
            &fx.root.join("config.toml"),
            "extends = [\"parts/none.toml\"]\n",
        );
        let (r, _) = fx.read(None);
        assert!(!r.succeeded);
        fx.put(
            &fx.root.join("config.toml"),
            "extends = [\"~/none.toml\"]\n",
        );
        let (r, _) = fx.read(None);
        assert!(r.succeeded);
        assert!(codes_of(&r).contains(&codes::SHAPE_FILE_DROPPED));
    }

    // 큰 conf.d는 메타데이터 계획만 만들고 fd를 보유하지 않는다. Part S가 고유 파일 예산을 정한다.
    // 이것을 실패시키는 것: 모든 뿌리를 열어 fd를 쥐는 것, 열지 못한 이유를 일반 문구로 바꾸는 것.
    #[test]
    fn a_large_conf_d_opens_only_up_to_the_limit() {
        let fx = Fx::new("many");
        for i in 0..300 {
            fx.put(&fx.root.join(format!("conf.d/{i:03}.toml")), "");
        }
        let mut l = fx.loader(None);
        let roots = l.roots(b"");
        assert_eq!(roots.len(), 301);
        assert!(l.held.is_empty());
        assert_eq!(l.plan.len(), 300);
        let r = read_graph(roots, &mut l);
        assert!(!r.succeeded);
        assert!(
            codes_of(&r).contains(&codes::EXTENDS_TOO_MANY),
            "{:?}",
            codes_of(&r)
        );
        // A root that is there but is not a regular file keeps its reason.
        let fx = Fx::new("fifo");
        std::fs::create_dir(fx.root.join("config.toml")).unwrap();
        let (r, _) = fx.read(None);
        let d = r
            .diagnostics
            .iter()
            .find(|d| d.code == codes::EXTENDS_BAD_PATH);
        let reasons: Vec<String> = r
            .diagnostics
            .iter()
            .flat_map(|d| d.args.iter().map(|a| a.value.clone()))
            .collect();
        assert!(
            reasons.iter().any(|v| v.contains("not a regular file")),
            "{d:?} {reasons:?}"
        );
    }

    // 모양 전용 뿌리(사용자 결정 2026-10-17, R3 I-1): 그 아래 파일은 모두 ShapeOnly다. 색은 적용되고, 명령 세그먼트는
    // 다른 모양 전용 원본과 같은 진단(W405 계열)으로 막히며 실행 단위가 없다. S3b 보고 경로로 확인한다.
    // 이것을 실패시키는 것: trusted_place·linked_from_root에서 모양 전용 상한을 빼는 것(뿌리 아래 파일이 Executable 또는
    // Unsafe가 됨), 발행 전 재확인에서 모양 전용 뿌리를 보통 뿌리처럼 다시 검사하는 것.
    #[test]
    fn a_shape_only_root_applies_colors_and_runs_nothing() {
        use bingsu_core::color::palette::Mode;
        use bingsu_core::config::compile::BUILTIN_TOML;
        use bingsu_core::config::report::report;
        let fx = Fx::new("shape-root");
        fx.put(
            &fx.root.join("config.toml"),
            &format!("{CMD}[colors]\nmode = \"light\"\n"),
        );
        fx.put(&fx.root.join("conf.d/a.toml"), CMD);
        // A link in the root to a file outside it (`linked_from_root`).
        let linked = fx.put(&fx.home.join("linked.toml"), CMD);
        std::os::unix::fs::symlink(&linked, fx.root.join("conf.d/b.toml")).unwrap();
        let mut l = fx.shape_only_loader(None);
        let roots = l.roots(BUILTIN_TOML.as_bytes());
        let r = report(roots, &mut l, [0, 3, 0], Mode::Dark);
        for end in ["/config.toml", "/a.toml", "/linked.toml"] {
            let f = r
                .files
                .iter()
                .find(|f| f.opened.display.ends_with(end.as_bytes()))
                .unwrap();
            assert_eq!(
                (f.trust, f.status),
                (Trust::ShapeOnly, Status::Applied),
                "{end}"
            );
        }
        let snap = r.snapshot.as_ref().expect("shape keys still compile");
        assert_eq!(snap.palette, snap.light_palette, "colors.mode applied");
        assert!(snap.exec_units.is_empty(), "{:?}", snap.exec_units);
        let codes: Vec<_> = r.diagnostics.iter().map(|d| d.code).collect();
        assert!(codes.contains(&codes::EXEC_KEY_IGNORED), "{codes:?}");
        assert!(l.untrusted.is_empty());
        // Publication rechecks the root with undecided facts read as
        // decided; a plain recheck would refuse it on every read. Read and
        // recheck use the same system oracle, so the result does not depend
        // on how this machine answers group lookups.
        assert_eq!(l.revalidate(), Ok(()));
        // A real change between read and publish still blocks.
        // 이것을 실패시키는 것: 발행 전 재확인이 observed 비교를 건너뛰는 것.
        fx.put(&fx.root.join("conf.d/a.toml"), &format!("{CMD}# changed\n"));
        assert_eq!(
            l.revalidate(),
            Err("source observation changed".to_string())
        );
    }

    // `config use` 기록도 모양 전용 뿌리 아래 파일의 신뢰를 올리지 못한다. 뿌리 밖 기록 파일은 그대로 실행 신뢰를 얻는다.
    // 이것을 실패시키는 것: trusted_place의 기록 분기에서 모양 전용 상한을 빼는 것.
    #[test]
    fn approval_cannot_lift_a_file_under_a_shape_only_root() {
        let fx = Fx::new("shape-root-use");
        let inside = fx.put(&fx.root.join("config.toml"), CMD);
        let md = std::fs::metadata(&inside).unwrap();
        let rec = Record {
            dev: md.dev(),
            ino: md.ino(),
            path: inside.clone(),
        };
        let mut l = fx.shape_only_loader(Some(rec));
        let roots = l.roots(b"");
        let r = read_graph(roots, &mut l);
        assert_eq!(
            trust_of(&r, "/config.toml"),
            Some((Trust::ShapeOnly, Status::Applied))
        );
        let outside = fx.put(&fx.home.join("work.toml"), CMD);
        let md = std::fs::metadata(&outside).unwrap();
        let rec = Record {
            dev: md.dev(),
            ino: md.ino(),
            path: outside,
        };
        let mut l = fx.shape_only_loader(Some(rec));
        let roots = l.roots(b"");
        let r = read_graph(roots, &mut l);
        assert_eq!(
            trust_of(&r, "work.toml"),
            Some((Trust::Executable, Status::Applied))
        );
    }

    // config use 기록: 기록한 파일이 config.toml 자리를 대신하고 실행 키를 준다. 같은 정규 경로에 새 파일이 오면
    // (편집기의 새 파일 저장) 전체 안전 검사를 다시 통과할 때 승계하고 새 정체를 돌려준다(P-R3c, S-10).
    // 검사에 실패하면 승계하지 않는다.
    // 이것을 실패시키는 것: 기록 밖 파일에 실행 신뢰를 주는 것, 새 정체를 돌려주지 않는 것(다음 회차에도 다시 검사),
    // 안전하지 않은 새 파일을 승계하는 것.
    #[test]
    fn the_config_use_record_trusts_that_file_only() {
        let fx = Fx::new("use");
        let chosen = fx.put(&fx.home.join("work.toml"), CMD);
        fx.put(&fx.root.join("config.toml"), "");
        let md = std::fs::metadata(&chosen).unwrap();
        let rec = Record {
            dev: md.dev(),
            ino: md.ino(),
            path: chosen.clone(),
        };
        let (r, l) = fx.read(Some(rec.clone()));
        assert_eq!(
            trust_of(&r, "work.toml"),
            Some((Trust::Executable, Status::Applied))
        );
        assert_eq!(trust_of(&r, "/config.toml"), None);
        assert_eq!(l.renew, None);
        // A new file at the same path (old one kept aside so the inode differs).
        std::fs::rename(&chosen, fx.home.join("old.toml")).unwrap();
        fx.put(&chosen, CMD);
        let new = std::fs::metadata(&chosen).unwrap();
        let (r, l) = fx.read(Some(rec.clone()));
        assert_eq!(
            trust_of(&r, "work.toml"),
            Some((Trust::Executable, Status::Applied))
        );
        assert_eq!(
            l.renew,
            Some(Record {
                dev: new.dev(),
                ino: new.ino(),
                path: chosen.clone(),
            })
        );
        // The new file is writable by others: not taken over.
        std::fs::set_permissions(&chosen, std::fs::Permissions::from_mode(0o646)).unwrap();
        let (r, l) = fx.read(Some(rec));
        assert_eq!(
            trust_of(&r, "work.toml"),
            Some((Trust::Unsafe, Status::Applied))
        );
        assert_eq!(l.renew, None);
        // Another file elsewhere is not trusted.
        let other = fx.put(&fx.home.join("other.toml"), CMD);
        fx.put(
            &fx.root.join("config.toml"),
            &format!("extends = [\"{}\"]\n", other.display()),
        );
        let (r, _) = fx.read(None);
        assert_eq!(
            trust_of(&r, "other.toml"),
            Some((Trust::ShapeOnly, Status::Applied))
        );
    }

    // 표식(P-R4): 빠진 파일(규칙 5)이나 Unsafe 파일이 있어도 나머지를 끝까지 검증했으면 발행하고 그 파일을 경고 목록에
    // 둔다. 신뢰 파일의 실패는 무효 표식, 목록을 끝까지 못 읽었으면 새 표식 없음.
    // 이것을 실패시키는 것: 빠진·Unsafe 파일 때문에 발행을 막는 것, 경고 목록에서 빼는 것, 신뢰 실패를 발행으로 보는 것,
    // conf.d 목록 실패를 무시하는 것.
    #[test]
    fn what_may_be_published_after_a_read() {
        let fx = Fx::new("verified");
        fx.put(&fx.root.join("config.toml"), "extends = [\"~/t.toml\"]\n");
        fx.put(&fx.home.join("t.toml"), "extends = 5\n");
        fx.put(&fx.root.join("conf.d/a.toml"), CMD);
        std::fs::set_permissions(
            fx.root.join("conf.d/a.toml"),
            std::fs::Permissions::from_mode(0o646),
        )
        .unwrap();
        let (r, l) = fx.read(None);
        match l.verified(&r.files, r.succeeded) {
            Verified::Publish { left_out } => {
                let names: Vec<String> = left_out
                    .iter()
                    .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
                    .collect();
                assert_eq!(names, ["t.toml", "a.toml"]);
            }
            other => panic!("{other:?}"),
        }
        fx.put(&fx.root.join("config.toml"), "extends = 5\n");
        let (r, l) = fx.read(None);
        assert_eq!(l.verified(&r.files, r.succeeded), Verified::Invalid);
        std::fs::set_permissions(
            fx.root.join("conf.d"),
            std::fs::Permissions::from_mode(0o000),
        )
        .unwrap();
        let (r, l) = fx.read(None);
        std::fs::set_permissions(
            fx.root.join("conf.d"),
            std::fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        assert_eq!(l.verified(&r.files, r.succeeded), Verified::Incomplete);
    }

    // 판정 P-R3b(S-9): 뿌리 안의 symlink는 링크가 있는 자리로 신뢰한다. 대상은 같은 안전 검사를 거친다.
    // 적힌 경로의 `..`로 뿌리를 벗어난 파일은 뿌리 안이 아니다.
    // 이것을 실패시키는 것: 정규 경로로만 판단하는 것(stow 사용자의 명령이 꺼짐), 대상의 안전 검사를 건너뛰는 것,
    // `..`가 든 적힌 경로를 뿌리 안으로 보는 것.
    #[test]
    fn a_symlink_in_the_root_is_trusted_where_it_is() {
        let fx = Fx::new("link");
        let real = fx.put(&fx.home.join("dot.toml"), CMD);
        std::os::unix::fs::symlink(&real, fx.root.join("config.toml")).unwrap();
        let (r, _) = fx.read(None);
        assert_eq!(
            trust_of(&r, "dot.toml"),
            Some((Trust::Executable, Status::Applied))
        );
        // The target is still checked: writable by others, it is not run.
        std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o646)).unwrap();
        let (r, _) = fx.read(None);
        assert_eq!(
            trust_of(&r, "dot.toml"),
            Some((Trust::Unsafe, Status::Applied))
        );
        std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o644)).unwrap();
        // Reached through `extends`, the same.
        std::fs::remove_file(fx.root.join("config.toml")).unwrap();
        std::os::unix::fs::symlink(&real, fx.root.join("link.toml")).unwrap();
        fx.put(&fx.root.join("config.toml"), "extends = [\"link.toml\"]\n");
        let (r, _) = fx.read(None);
        assert_eq!(
            trust_of(&r, "dot.toml"),
            Some((Trust::Executable, Status::Applied))
        );
        // A `..` out of the root is not under it.
        fx.put(&fx.home.join("out.toml"), CMD);
        fx.put(
            &fx.root.join("config.toml"),
            "extends = [\"../home/out.toml\"]\n",
        );
        let (r, _) = fx.read(None);
        assert_eq!(
            trust_of(&r, "out.toml"),
            Some((Trust::ShapeOnly, Status::Applied))
        );
    }
    // 이것을 실패시키는 것: 링크 위치의 전체 부모 사슬 검사를 생략하는 것.
    #[test]
    fn unsafe_link_parent_never_grants_execution() {
        let fx = Fx::new("bad-link-parent");
        let payload = fx.put(&fx.home.join("payload.toml"), CMD);
        std::os::unix::fs::symlink(payload, fx.root.join("conf.d/zz.toml")).unwrap();
        std::fs::set_permissions(
            fx.root.join("conf.d"),
            std::fs::Permissions::from_mode(0o777),
        )
        .unwrap();
        let (r, _) = fx.read(None);
        assert_eq!(
            trust_of(&r, "payload.toml"),
            Some((Trust::Unsafe, Status::Applied))
        );
    }

    fn resolved_config(
        fx: &Fx,
        config_home: &Path,
    ) -> Option<crate::commands::init::roots::ConfigRootPin> {
        let env = crate::commands::init::trusted_env::TrustedEnv {
            path: None,
            xdg_config_home: Some(config_home.as_os_str().to_owned()),
            xdg_runtime_dir: Some(fx.base.join("run").into_os_string()),
            xdg_state_home: Some(fx.base.join("state").into_os_string()),
            xdg_cache_home: None,
        };
        crate::commands::init::roots::resolve(
            &env,
            &fx.home,
            &sys::passwd_entry(sys::current_uid()).unwrap().name,
        )
        .config
    }

    fn read_pinned(
        fx: &Fx,
        config_root: crate::commands::init::roots::ConfigRootPin,
    ) -> (GraphResult, Loader) {
        let me = sys::current_uid();
        let mut l = Loader::new(Places {
            config_root,
            home: fx.home.clone(),
            me,
            user: sys::passwd_entry(me).unwrap().name,
        });
        let roots = l.roots(b"");
        let r = read_graph(roots, &mut l);
        (r, l)
    }

    // init부터 도우미까지 stow 뿌리의 작성 경로와 링크 증거를 유지해야 한다.
    // 이것을 실패시키는 것: stow 대상이나 원래 뿌리 링크의 보유 증거를 재검사하지 않는 것.
    #[test]
    fn stow_folder_links_require_safe_target_chains() {
        let fx = Fx::new("folder-links");
        let target = fx.home.join("pieces");
        std::fs::create_dir(&target).unwrap();
        fx.put(&target.join("a.toml"), CMD);
        std::fs::remove_dir(fx.root.join("conf.d")).unwrap();
        std::os::unix::fs::symlink(&target, fx.root.join("conf.d")).unwrap();
        let config_home = fx.home.join(".config");
        std::fs::create_dir(&config_home).unwrap();
        std::os::unix::fs::symlink(&fx.root, config_home.join("bingsu")).unwrap();
        let read = || read_pinned(&fx, resolved_config(&fx, &config_home).unwrap());
        let (r, l) = read();
        assert_eq!(
            trust_of(&r, "a.toml"),
            Some((Trust::Executable, Status::Applied))
        );
        assert!(matches!(
            l.verified(&r.files, r.succeeded),
            Verified::Publish { .. }
        ));
        assert_eq!(l.places.config_root.path, fx.root);
        assert_eq!(l.places.config_root.written, config_home.join("bingsu"));
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o777)).unwrap();
        assert_eq!(
            trust_of(&read().0, "a.toml"),
            Some((Trust::Unsafe, Status::Applied))
        );
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o755)).unwrap();
        let moved = fx.home.join("dotfiles");
        std::fs::rename(&fx.root, &moved).unwrap();
        std::os::unix::fs::symlink(&moved, &fx.root).unwrap();
        let (r, l) = read();
        assert_eq!(
            trust_of(&r, "a.toml"),
            Some((Trust::Executable, Status::Applied))
        );
        assert!(matches!(
            l.verified(&r.files, r.succeeded),
            Verified::Publish { .. }
        ));
        // The original root link must still be checked at publication.
        std::fs::remove_file(config_home.join("bingsu")).unwrap();
        std::os::unix::fs::symlink(&target, config_home.join("bingsu")).unwrap();
        assert_eq!(l.verified(&r.files, r.succeeded), Verified::Incomplete);
        let me = sys::current_uid();
        assert!(
            crate::commands::init::roots::ConfigRootPin::reopen(
                &l.places.config_root.written,
                &l.places.config_root.path,
                false,
                me,
                &mut SystemGroups::new(&sys::passwd_entry(me).unwrap().name),
            )
            .is_err()
        );
    }

    // 피해자 소유 저장소여도 남이 쓸 수 있는 .config의 뿌리 링크는 승인 근거가 아니다.
    // 링크 소유자가 본인인 경우에도 부모 검사만으로 막아야 한다.
    // 이것을 실패시키는 것: 작성 경로를 먼저 정규화하여 링크 부모의 위험을 숨기는 것.
    #[test]
    fn planted_root_link_is_rejected_before_pinning() {
        let fx = Fx::new("planted-root");
        fx.put(&fx.root.join("config.toml"), CMD);
        let config_home = fx.home.join(".config");
        std::fs::create_dir(&config_home).unwrap();
        std::os::unix::fs::symlink(&fx.root, config_home.join("bingsu")).unwrap();
        std::fs::set_permissions(&config_home, std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(resolved_config(&fx, &config_home).is_none());
        std::fs::set_permissions(&config_home, std::fs::Permissions::from_mode(0o755)).unwrap();
        let (r, l) = read_pinned(&fx, resolved_config(&fx, &config_home).unwrap());
        assert!(matches!(
            l.verified(&r.files, r.succeeded),
            Verified::Publish { .. }
        ));
        // A safe link location cannot bless a writable target chain either.
        std::fs::set_permissions(&fx.root, std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(resolved_config(&fx, &config_home).is_none());
    }

    // 파일 수가 실제 세션 fd 상한보다 많아도 버린 테마는 실행 증거를 밀어내지 못한다.
    // 이것을 실패시키는 것: 제외·오염된 원본의 fd를 계속 보유하는 것.
    #[test]
    fn discarded_theme_sources_release_fds_before_the_next_edge() {
        let fx = Fx::new("theme-fd-fanout");
        let refs: Vec<_> = (0..SESSION_FDS_MAX + 1)
            .map(|i| {
                let name = format!("theme-{i}.toml");
                fx.put(&fx.home.join(&name), "");
                format!("\"{name}\"")
            })
            .collect();
        fx.put(
            &fx.home.join("theme.toml"),
            &format!("extends = [{}]\n", refs.join(",")),
        );
        fx.put(
            &fx.root.join("config.toml"),
            "extends = [\"~/theme.toml\"]\n",
        );
        fx.put(&fx.root.join("config.local.toml"), CMD);
        let (r, l) = fx.read(None);
        assert_eq!(
            trust_of(&r, "theme.toml"),
            Some((Trust::ShapeOnly, Status::Dropped))
        );
        assert!(codes_of(&r).contains(&codes::EXTENDS_TOO_MANY));
        assert!(matches!(
            l.verified(&r.files, r.succeeded),
            Verified::Publish { .. }
        ));
        assert!(l.pending.is_none());
        assert_eq!(
            l.held.len(),
            2,
            "only the two adopted execution sources retain fds"
        );
        let listing = l.listing.as_ref().unwrap();
        assert_eq!(
            l.fds,
            l.places.config_root.evidence.fd_count()
                + listing.chain.fds.len()
                + 1
                + l.held
                    .values()
                    .map(|c| c.evidence.fd_count())
                    .sum::<usize>()
        );
        // The same bound must hold when many safe config paths are reached
        // only through a shape-only theme (effective trust after taint).
        let refs: Vec<_> = (0..100)
            .map(|i| {
                let name = format!("tainted-{i}.toml");
                fx.put(&fx.root.join(&name), "");
                format!("\"{}\"", fx.root.join(name).display())
            })
            .collect();
        fx.put(
            &fx.home.join("theme.toml"),
            &format!("extends = [{}]\n", refs.join(",")),
        );
        let (r, l) = fx.read(None);
        assert!(matches!(
            l.verified(&r.files, r.succeeded),
            Verified::Publish { .. }
        ));
        assert_eq!(l.held.len(), 2);
    }

    // 이것을 실패시키는 것: 사용자 링크에 다른 uid 또는 root 소유를 허용하는 것.
    #[test]
    fn a_link_owner_must_be_the_user_even_when_root() {
        assert!(crate::commands::source_path::link_owner_is_mine(501, 501));
        assert!(!crate::commands::source_path::link_owner_is_mine(502, 501));
        assert!(!crate::commands::source_path::link_owner_is_mine(0, 501));
    }

    // 이것을 실패시키는 것: 미해석 외부 상대 경로를 뿌리 안으로 분류하는 것.
    #[test]
    fn missing_relative_external_theme_does_not_reject_config() {
        let fx = Fx::new("missing-theme");
        fx.put(
            &fx.root.join("config.toml"),
            "extends = [\"../home/missing.toml\"]\n",
        );
        let (r, _) = fx.read(None);
        assert!(r.succeeded);
        assert!(codes_of(&r).contains(&codes::SHAPE_FILE_DROPPED));
        fx.put(
            &fx.root.join("config.toml"),
            "extends = [\"missing.toml\"]\n",
        );
        assert!(!fx.read(None).0.succeeded);
    }

    // 이것을 실패시키는 것: 같은 FileKey 별칭을 중복 계획하거나 Unsafe가 신뢰 예산을 차지하는 것.
    #[test]
    fn aliases_and_unsafe_roots_do_not_consume_trusted_budget() {
        let fx = Fx::new("read-plan");
        let shared = fx.put(&fx.root.join("conf.d/000.toml"), "");
        for i in 1..40 {
            std::fs::hard_link(&shared, fx.root.join(format!("conf.d/{i:03}.toml"))).unwrap();
        }
        fx.put(&fx.root.join("config.local.toml"), CMD);
        let mut planned = fx.loader(None);
        assert_eq!(planned.roots(b"").len(), 3);
        let (r, l) = fx.read(None);
        assert!(r.succeeded);
        assert_eq!(l.plan.len(), 2);
        assert_eq!(l.held.len(), 2);
        for i in 0..40 {
            let p = fx.root.join(format!("conf.d/{i:03}.toml"));
            std::fs::remove_file(&p).unwrap();
            fx.put(&p, "");
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o666)).unwrap();
        }
        let (r, _) = fx.read(None);
        assert!(r.succeeded);
    }

    // 이것을 실패시키는 것: fd 상한을 무시하거나 의미상 파일 예산 오류로 바꾸는 것.
    #[test]
    fn descriptor_cap_is_incomplete_not_a_file_budget_error() {
        let fx = Fx::new("fd-cap");
        fx.put(&fx.root.join("config.toml"), CMD);
        let mut l = fx.loader(None);
        l.fd_cap = 1;
        let roots = l.roots(b"");
        assert!(l.held.is_empty());
        let r = read_graph(roots, &mut l);
        assert_eq!(l.verified(&r.files, r.succeeded), Verified::Incomplete);
        assert!(!codes_of(&r).contains(&codes::EXTENDS_TOO_MANY));
    }

    // 이것을 실패시키는 것: 발행 전에 원본 fd와 부모 이름 연결의 변경을 검사하지 않는 것.
    #[test]
    fn session_keeps_fds_and_rechecks_source_and_parent_names() {
        for change in ["mode", "content", "parent", "replace"] {
            let fx = Fx::new(change);
            let path = fx.put(&fx.root.join("config.toml"), CMD);
            let (r, l) = fx.read(None);
            assert!(matches!(
                l.verified(&r.files, r.succeeded),
                Verified::Publish { .. }
            ));
            assert_eq!(l.held.len(), 1);
            match change {
                "mode" => {
                    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).unwrap()
                }
                "content" => std::fs::write(&path, "icons = \"unicode\"\n").unwrap(),
                "parent" => {
                    std::fs::rename(&fx.root, fx.base.join("old-config")).unwrap();
                    std::fs::create_dir(&fx.root).unwrap();
                }
                _ => {
                    std::fs::rename(&path, fx.home.join("old.toml")).unwrap();
                    fx.put(&path, CMD);
                }
            }
            assert!(l.revalidate().is_err(), "{change}");
            assert_eq!(l.verified(&r.files, r.succeeded), Verified::Incomplete);
        }
    }

    // 이것을 실패시키는 것: 승인 기록의 원래 fd·이름 연결을 발행 전에 재검사하지 않는 것.
    #[test]
    fn session_keeps_record_descriptor_until_publication() {
        let fx = Fx::new("record-session");
        let path = fx.put(&fx.home.join("approved.toml"), CMD);
        let m = std::fs::metadata(&path).unwrap();
        let record = Record {
            dev: m.dev(),
            ino: m.ino(),
            path,
        };
        let mut groups = bingsu_core::fs_trust::RefuseGroupWrite;
        crate::commands::trust_record::write(&fx.home, sys::current_uid(), &mut groups, &record)
            .unwrap();
        let evidence =
            crate::commands::trust_record::read_session(&fx.home, sys::current_uid(), &mut groups)
                .unwrap();
        let places = fx.loader(None).places;
        let mut l = Loader::with_record(places, evidence);
        let roots = l.roots(b"");
        let r = read_graph(roots, &mut l);
        assert!(matches!(
            l.verified(&r.files, r.succeeded),
            Verified::Publish { .. }
        ));
        let at = fx.home.join(crate::commands::trust_record::RECORD_NAME);
        std::fs::rename(&at, fx.home.join("old-record")).unwrap();
        crate::commands::trust_record::write(&fx.home, sys::current_uid(), &mut groups, &record)
            .unwrap();
        assert_eq!(l.verified(&r.files, r.succeeded), Verified::Incomplete);
    }

    // 이것을 실패시키는 것: 다른 사용자가 심은 링크나 공유 폴더를 실행 원본으로 신뢰하는 것.
    /// Invoked explicitly by the Linux two-user harness; never a skipped
    /// default test masquerading as a container result.
    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires fixtures owned by two distinct container users"]
    #[expect(
        clippy::disallowed_methods,
        reason = "explicit container fixture paths, not runtime configuration"
    )]
    fn two_user_link_attacks() {
        let root = PathBuf::from(std::env::var_os("PARTR_CONFIG").expect("two-user fixture"));
        let home = PathBuf::from(std::env::var_os("PARTR_HOME").expect("two-user fixture"));
        let me = sys::current_uid();
        assert_ne!(me, 0);
        let mut l = Loader::new(Places {
            config_root: crate::commands::init::roots::ConfigRootPin::check(
                &root,
                me,
                &mut SystemGroups::new(&sys::passwd_entry(me).unwrap().name),
            )
            .unwrap(),
            home,
            me,
            user: sys::passwd_entry(me).unwrap().name,
        });
        let roots = l.roots(b"");
        let r = read_graph(roots, &mut l);
        assert_eq!(
            trust_of(&r, "payload.toml"),
            Some((Trust::Unsafe, Status::Applied))
        );
    }
    // 이것을 실패시키는 것: conf.d 목록 변경을 검사하지 않는 것.
    #[test]
    fn session_rechecks_directory_listing() {
        let fx = Fx::new("listing-evidence");
        fx.put(&fx.root.join("config.toml"), CMD);
        let (r, l) = fx.read(None);
        assert!(matches!(
            l.verified(&r.files, r.succeeded),
            Verified::Publish { .. }
        ));
        fx.put(&fx.root.join("conf.d/new.toml"), "");
        assert_eq!(l.verified(&r.files, r.succeeded), Verified::Incomplete);
    }

    // 이것을 실패시키는 것: S3b가 전달한 내장 원본을 버리거나 바꾸는 것.
    #[test]
    fn builtin_bytes_are_supplied_by_the_caller() {
        let fx = Fx::new("builtin");
        let mut l = fx.loader(None);
        let roots = l.roots(b"version = 1\n");
        let Root::Read(builtin) = &roots[0] else {
            panic!()
        };
        assert_eq!(builtin.bytes, b"version = 1\n");
        assert_eq!(builtin.key, BUILTIN_KEY);
        assert_eq!(builtin.trust, Trust::Executable);
    }

    // 이것을 실패시키는 것: 계획 뒤 사라지거나 신뢰·정규 경로가 달라진 뿌리를 읽는 것.
    #[test]
    fn planned_roots_must_keep_path_trust_and_presence() {
        for change in ["missing", "trust", "canonical"] {
            let fx = Fx::new(&format!("planned-{change}"));
            let at = fx.put(&fx.root.join("config.toml"), "");
            let mut l = fx.loader(None);
            let roots = l.roots(b"");
            match change {
                "missing" => std::fs::remove_file(&at).unwrap(),
                "trust" => {
                    std::fs::set_permissions(&at, std::fs::Permissions::from_mode(0o666)).unwrap()
                }
                _ => {
                    let alias = fx.home.join("same-inode.toml");
                    std::fs::hard_link(&at, &alias).unwrap();
                    std::fs::remove_file(&at).unwrap();
                    std::os::unix::fs::symlink(&alias, &at).unwrap();
                }
            }
            let r = read_graph(roots, &mut l);
            assert!(!r.succeeded, "{change}");
            assert_eq!(
                l.verified(&r.files, r.succeeded),
                Verified::Incomplete,
                "{change}"
            );
            assert!(r.files.iter().all(|f| f.opened.bytes.is_empty()));
        }
    }

    // 이것을 실패시키는 것: 같은 fd를 읽지 못했거나 읽는 동안 바뀌었는데 완료된 회차로 보는 것.
    #[test]
    fn candidate_read_failures_are_incomplete() {
        for change in ["content", "read"] {
            let fx = Fx::new(&format!("candidate-{change}"));
            let at = fx.put(&fx.root.join("config.toml"), "");
            let mut l = fx.loader(None);
            let mut c = l.check(&at).unwrap();
            if change == "content" {
                std::fs::write(&at, "version = 1\n").unwrap();
            } else {
                c.evidence.file = std::fs::File::open(&fx.root).unwrap();
            }
            assert!(l.read_candidate(c).is_err());
            assert_eq!(l.verified(&[], false), Verified::Incomplete, "{change}");
        }
    }

    // 이것을 실패시키는 것: config use가 conf.d·local까지 대체하거나 선택 파일의 부재를 숨기는 것.
    #[test]
    fn selected_config_keeps_overlays_and_missing_selection_is_an_error() {
        let fx = Fx::new("selected-overlays");
        let chosen = fx.put(&fx.home.join("chosen.toml"), "");
        fx.put(&fx.root.join("config.toml"), "");
        fx.put(&fx.root.join("conf.d/a.toml"), "");
        fx.put(&fx.root.join("config.local.toml"), "");
        let md = std::fs::metadata(&chosen).unwrap();
        let record = Record {
            dev: md.dev(),
            ino: md.ino(),
            path: chosen.clone(),
        };
        let (r, _) = fx.read(Some(record.clone()));
        let names: Vec<_> = r
            .order
            .iter()
            .map(|id| {
                Path::new(std::ffi::OsStr::from_bytes(
                    &r.files[id.0 as usize].opened.display,
                ))
                .file_name()
                .unwrap()
                .to_string_lossy()
                .into_owned()
            })
            .collect();
        assert_eq!(
            names,
            ["(built-in)", "chosen.toml", "a.toml", "config.local.toml"]
        );
        std::fs::remove_file(chosen).unwrap();
        let (r, l) = fx.read(Some(record));
        assert!(!r.succeeded);
        assert!(codes_of(&r).contains(&codes::EXTENDS_BAD_PATH));
        assert_eq!(l.verified(&r.files, r.succeeded), Verified::Invalid);
    }

    // 이것을 실패시키는 것: 승인 경로가 다른 정규 대상으로 향해도 실행 신뢰를 승계하는 것.
    #[test]
    fn approval_does_not_follow_a_retargeted_link() {
        let fx = Fx::new("approval-retarget");
        let at = fx.put(&fx.home.join("chosen.toml"), "");
        let md = std::fs::metadata(&at).unwrap();
        let record = Record {
            dev: md.dev(),
            ino: md.ino(),
            path: at.clone(),
        };
        let target = fx.put(&fx.home.join("other.toml"), "");
        std::fs::remove_file(&at).unwrap();
        std::os::unix::fs::symlink(target, at).unwrap();
        let (r, l) = fx.read(Some(record));
        assert_eq!(
            trust_of(&r, "other.toml"),
            Some((Trust::ShapeOnly, Status::Applied))
        );
        assert!(l.renew.is_none());
        assert!(l.held.is_empty());
    }

    // 이것을 실패시키는 것: 안전한 별칭의 증거를 채택하지 않거나 처음 적용 순서를 옮기는 것.
    #[test]
    fn safe_alias_keeps_the_first_root_position() {
        let fx = Fx::new("safe-alias");
        let target = fx.put(&fx.home.join("target.toml"), "");
        std::os::unix::fs::symlink(&target, fx.root.join("config.toml")).unwrap();
        fx.put(&fx.root.join("conf.d/a.toml"), "");
        std::fs::hard_link(&target, fx.root.join("conf.d/b.toml")).unwrap();
        std::fs::set_permissions(&fx.home, std::fs::Permissions::from_mode(0o777)).unwrap();
        let (r, l) = fx.read(None);
        assert!(r.succeeded);
        let names: Vec<_> = r
            .order
            .iter()
            .map(|id| r.files[id.0 as usize].opened.display.clone())
            .collect();
        assert!(names[1].ends_with(b"b.toml"));
        assert!(names[2].ends_with(b"a.toml"));
        assert_eq!(
            trust_of(&r, "b.toml"),
            Some((Trust::Executable, Status::Applied))
        );
        assert!(matches!(
            l.verified(&r.files, true),
            Verified::Publish { .. }
        ));
    }
}
