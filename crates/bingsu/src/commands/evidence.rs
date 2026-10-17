//! Canonical comparison bytes, never authority. Descriptors remain in Loader.
//! Lengths and integers are little endian; paths remain raw Unix bytes.
use super::{runtime_root::Chain, sys::Stamp};
use bingsu_core::{
    config::{
        report::ConfigReport,
        source::{Found, Status, Trust},
    },
    diag::{Diagnostic, Place},
    fs_trust::{AclFacts, Facts, Refusal},
    snapshot::{self, META_MAX},
};
use std::os::unix::ffi::OsStrExt;
use std::{io, path::Path};

pub struct Encoder {
    bytes: Vec<u8>,
    failed: bool,
}
impl Encoder {
    pub fn new() -> Self {
        Self {
            bytes: Vec::new(),
            failed: false,
        }
    }
    pub fn len(&self) -> usize {
        self.bytes.len()
    }
    pub fn raw(&mut self, bytes: &[u8]) {
        if self.failed
            || self
                .bytes
                .len()
                .checked_add(bytes.len())
                .is_none_or(|n| n > META_MAX - 20)
            || self.bytes.try_reserve(bytes.len()).is_err()
        {
            self.failed = true;
            return;
        }
        self.bytes.extend_from_slice(bytes);
    }
    pub fn num(&mut self, n: u64) {
        self.raw(&n.to_le_bytes());
    }
    pub fn count(&mut self, n: usize) {
        self.num(n as u64);
    }
    pub fn byte(&mut self, b: u8) {
        self.raw(&[b]);
    }
    pub fn blob(&mut self, b: &[u8]) {
        self.count(b.len());
        self.raw(b);
    }
    pub fn path(&mut self, p: &Path) {
        self.blob(p.as_os_str().as_bytes());
    }
    pub fn finish(self) -> io::Result<Vec<u8>> {
        if self.failed {
            Err(io::Error::other("evidence capacity"))
        } else {
            Ok(self.bytes)
        }
    }
    pub fn facts(&mut self, f: Facts) {
        self.num(f.dev);
        self.num(f.ino);
        self.num(f.uid.into());
        self.num(f.gid.into());
        self.num(f.mode.into());
        self.byte(match f.acl {
            AclFacts::None => 0,
            AclFacts::DenyOnly => 1,
            AclFacts::AllowsWrite => 2,
            AclFacts::Unknown => 3,
            AclFacts::PosixExtended => 4,
        });
        self.byte(match f.ownership {
            None => 0,
            Some(false) => 1,
            Some(true) => 2,
        });
    }
    pub fn stamp(&mut self, s: &Stamp) {
        self.num(s.dev);
        self.num(s.ino);
        self.num(s.uid.into());
        self.num(s.gid.into());
        self.num(s.mode.into());
        // Directory entry timestamps change for unrelated files. Name bindings
        // and conf.d's complete listing are encoded separately.
        if s.mode & 0o170000 != 0o040000 {
            self.num(s.size);
            for (seconds, nanos) in [s.mtime, s.ctime] {
                self.raw(&seconds.to_le_bytes());
                match u32::try_from(nanos) {
                    Ok(nanos) => self.raw(&nanos.to_le_bytes()),
                    Err(_) => self.failed = true,
                }
            }
        }
    }
    pub fn refusal(&mut self, r: Option<Refusal>) {
        let (tag, at) = match r {
            None => (0, 0),
            Some(Refusal::Undecided { at }) => (1, at),
            Some(Refusal::Ancestor { at }) => (2, at),
            Some(Refusal::StickyNext { at }) => (3, at),
            Some(Refusal::Last) => (4, 0),
            Some(Refusal::NotLocal) => (5, 0),
        };
        self.byte(tag);
        self.count(at);
    }
    pub fn chain(&mut self, c: &Chain) {
        self.count(c.facts.len());
        for f in &c.facts {
            self.facts(*f);
        }
        self.count(c.names.len());
        for n in &c.names {
            self.blob(n.as_bytes());
        }
    }
    pub fn catalog(&mut self, files: &[Found]) {
        let mut sorted: Vec<_> = files.iter().collect();
        sorted.sort_by(|a, b| {
            a.opened
                .display
                .cmp(&b.opened.display)
                .then(a.id.cmp(&b.id))
        });
        self.count(sorted.len());
        for f in sorted {
            self.num(f.id.0.into());
            self.blob(&f.opened.display);
            self.num(f.opened.key.dev);
            self.num(f.opened.key.ino);
            self.byte(trust(f.trust));
            self.byte(trust(f.opened.trust));
            self.byte(match f.status {
                Status::Applied => 0,
                Status::Dropped => 1,
                Status::Failed => 2,
            });
            self.raw(&snapshot::crc32c(&[&f.opened.bytes]));
            // Equality is never inferred from a CRC, even for shape-only data.
            self.blob(&f.opened.bytes);
            self.count(f.via.len());
            for id in &f.via {
                self.num(id.0.into());
            }
        }
    }
    pub fn diagnostics(&mut self, ds: &[Diagnostic]) {
        self.count(ds.len());
        for d in ds {
            self.byte(d.code.letter() as u8);
            self.num(d.code.number.into());
            match d.at {
                Place::Builtin => self.byte(0),
                Place::Source { id, span } => {
                    self.byte(1);
                    self.num(id.0.into());
                    self.num(span.start.into());
                    self.num(span.end.into());
                }
                Place::Foreign { file, span } => {
                    self.byte(2);
                    self.num(file.into());
                    self.num(span.start.into());
                    self.num(span.end.into());
                }
            }
            self.count(d.args.len());
            for a in &d.args {
                self.blob(a.name.as_bytes());
                self.blob(a.value.as_bytes());
            }
            self.count(d.via.len());
            for id in &d.via {
                self.num(id.0.into());
            }
        }
    }
}
fn trust(t: Trust) -> u8 {
    match t {
        Trust::Executable => 0,
        Trust::ShapeOnly => 1,
        Trust::Unsafe => 2,
    }
}

#[derive(Default)]
pub struct EvidenceExport {
    pub comparison: Vec<u8>,
    pub context_end: usize,
    pub catalog_end: usize,
    pub edges_end: usize,
    pub observations_end: usize,
    pub absent_end: usize,
    pub held_end: usize,
    pub listing_end: usize,
}
impl EvidenceExport {
    pub fn metadata(&self, report: &ConfigReport) -> io::Result<Vec<u8>> {
        let mut e = Encoder::new();
        e.raw(b"BNGEVD02");
        // Payload order: context, catalog, apply order, reference edges,
        // absence, exclusions, adopted evidence, listing, approval, origins,
        // stable diagnostics. A length-delimited comparison trailer lets the
        // next session skip compilation without trusting cached verdicts.
        let c = &self.comparison;
        e.raw(&c[..self.context_end]);
        e.catalog(&report.files);
        e.raw(&c[self.edges_end..self.observations_end]);
        e.count(report.order.len());
        for id in &report.order {
            e.num(id.0.into());
        }
        e.raw(&c[self.catalog_end..self.edges_end]);
        e.raw(&c[self.observations_end..self.absent_end]);
        let excluded: Vec<_> = report
            .files
            .iter()
            .filter(|f| f.status == Status::Dropped || f.trust == Trust::Unsafe)
            .cloned()
            .collect();
        e.catalog(&excluded);
        e.raw(&c[self.absent_end..self.held_end]);
        e.raw(&c[self.held_end..self.listing_end]);
        e.raw(&c[self.listing_end..]);
        if let Some(c) = &report.snapshot {
            e.count(c.exec_units.len());
            for u in &c.exec_units {
                e.blob(u.id.as_bytes());
                e.count(u.origins.len());
                for (key, o) in &u.origins {
                    e.blob(key.as_bytes());
                    e.num(o.source.0.into());
                    e.byte(trust(o.trust));
                    e.num(o.key_span.start.into());
                    e.num(o.key_span.end.into());
                    e.num(o.span.start.into());
                    e.num(o.span.end.into());
                }
            }
        } else {
            e.count(0);
        }
        e.diagnostics(&report.diagnostics);
        e.raw(&self.comparison);
        e.count(self.comparison.len());
        snapshot::encode_metadata(&e.finish()?).map_err(|_| io::Error::other("metadata capacity"))
    }
    pub fn matches(&self, metadata: &[u8]) -> bool {
        Self::comparison_in(metadata) == Some(self.comparison.as_slice())
    }
    pub fn comparison_in(metadata: &[u8]) -> Option<&[u8]> {
        let p = snapshot::decode_metadata(metadata).ok()?;
        if p.get(..8) != Some(b"BNGEVD02") {
            return None;
        }
        let end = p.len().checked_sub(8)?;
        let n = usize::try_from(u64::from_le_bytes(p.get(end..)?.try_into().ok()?)).ok()?;
        let start = end.checked_sub(n).filter(|start| *start >= 8)?;
        p.get(start..end)
    }
}
