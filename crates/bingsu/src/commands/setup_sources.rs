//! The settings `bingsu setup`'s editor previews, read from disk once.
//!
//! The editor reads every source at the start through the real loader
//! (`config_load::Loader`: the `config use` record, trust per source,
//! `extends`, the I/O meter and every limit) and keeps each answer the loader
//! gave on a tape. A preview loads the settings again from that tape, with
//! the file `setup` would make as one more root, in memory, in the place of
//! `config.toml`: right after the built-in source. Core's `load` decides the
//! merge order, the budgets and the trust from the same roots it saw at the
//! start, so the preview is what the reader will apply once the file is
//! there. No file is opened, and nothing runs: a preview is a load and a
//! compile, never a refresh, a collector or a publication.
//!
//! Before the file is written, `Tape::read` again with a fresh loader gives
//! the tape the reader sees now; when it differs from the start's tape, the
//! preview no longer says what the file will do, and nothing is written.
use super::config_load::Loader;
use super::config_yaml;
use super::init::roots::canonical_lenient;
use bingsu_core::config::source::{
    ExtendsRef, FileKey, Found, LoadError, LoadReport, OpenError, Opened, Resolver, Root, RootMeta,
    Trust, Version, load,
};
use bingsu_core::config::tree::{SyntaxError, Table};
use bingsu_core::diag::SourceId;
use std::ffi::OsString;
use std::os::unix::ffi::OsStringExt;
use std::path::{Path, PathBuf};

/// One answer of the loader at the start, in call order.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Call {
    Root(FileKey, Result<Opened, OpenError>),
    Edge {
        from: FileKey,
        text: String,
        /// Where the entry led, canonical as far as it exists: an entry
        /// that names the file setup makes reaches it once it is there.
        to: Option<PathBuf>,
        got: Result<Opened, OpenError>,
    },
}

/// What one reading of the settings saw: the roots and every answer the
/// loader gave.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Tape {
    roots: Vec<Root>,
    calls: Vec<Call>,
}

/// Passes every call to the loader and keeps its answer.
struct Recorder<'a> {
    inner: &'a mut Loader,
    calls: Vec<Call>,
}

impl Resolver for Recorder<'_> {
    fn adopt(&mut self, key: FileKey, trust: Option<Trust>) {
        self.inner.adopt(key, trust);
    }

    fn open(&mut self, from: &Opened, r: &ExtendsRef) -> Result<Opened, OpenError> {
        let to = self
            .inner
            .resolve_ref(from, &r.text)
            .and_then(|p| canonical_lenient(&p));
        let got = self.inner.open(from, r);
        self.calls.push(Call::Edge {
            from: from.key,
            text: r.text.clone(),
            to,
            got: got.clone(),
        });
        got
    }

    fn open_root(&mut self, m: &RootMeta) -> Result<Opened, OpenError> {
        let got = self.inner.open_root(m);
        self.calls.push(Call::Root(m.key, got.clone()));
        got
    }

    fn parse_yaml(&mut self, text: &str) -> Result<Table, Vec<SyntaxError>> {
        self.inner.parse_yaml(text)
    }
}

impl Tape {
    /// The bytes the reading got for the root it names `display`, when it
    /// read them.
    pub(crate) fn root_bytes(&self, display: &[u8]) -> Option<&[u8]> {
        let key = self.roots.iter().find_map(|r| match r {
            Root::File(m) if m.display == display => Some(m.key),
            _ => None,
        })?;
        self.calls.iter().find_map(|c| match c {
            Call::Root(k, Ok(o)) if *k == key => Some(o.bytes.as_slice()),
            _ => None,
        })
    }

    /// Loads `roots` through `loader` and keeps what it answered. The
    /// report is the start's own reading, without the new file.
    pub(crate) fn read(
        roots: Vec<Root>,
        loader: &mut Loader,
        version: Version,
    ) -> (Self, Result<LoadReport, LoadError>) {
        let mut recorder = Recorder {
            inner: loader,
            calls: Vec::new(),
        };
        let loaded = load(roots.clone(), &mut recorder, version);
        let calls = recorder.calls;
        (Self { roots, calls }, loaded)
    }
}

/// Answers from the tape, in the order they were given; a call the start
/// did not make (none can come while the new file has no `extends`) is
/// refused like a file that cannot be read.
struct Replay<'a> {
    calls: &'a [Call],
    used: Vec<bool>,
    /// The new file and its path: an `extends` entry that led there opens
    /// it, as it will once the file is written.
    target: Option<(&'a Path, &'a Opened)>,
}

impl<'a> Replay<'a> {
    /// The first unused answer that fits, else the last one that fits.
    fn take(&mut self, fits: impl Fn(&Call) -> bool) -> Option<&'a Call> {
        let mut last = None;
        for (i, c) in self.calls.iter().enumerate() {
            if !fits(c) {
                continue;
            }
            if !self.used[i] {
                self.used[i] = true;
                return Some(c);
            }
            last = Some(c);
        }
        last
    }
}

fn not_read(trust: Trust) -> OpenError {
    OpenError {
        reason: String::from("not read when setup started"),
        trust,
    }
}

impl Resolver for Replay<'_> {
    fn open(&mut self, from: &Opened, r: &ExtendsRef) -> Result<Opened, OpenError> {
        let edge = self.take(
            |c| matches!(c, Call::Edge { from: f, text, .. } if *f == from.key && *text == r.text),
        );
        match (edge, self.target) {
            (Some(Call::Edge { to: Some(to), .. }), Some((path, file))) if to == path => {
                Ok(file.clone())
            }
            (Some(Call::Edge { got, .. }), _) => got.clone(),
            _ => Err(not_read(Trust::ShapeOnly)),
        }
    }

    fn open_root(&mut self, m: &RootMeta) -> Result<Opened, OpenError> {
        match self.take(|c| matches!(c, Call::Root(k, _) if *k == m.key)) {
            Some(Call::Root(_, got)) => got.clone(),
            _ => Err(not_read(m.trust)),
        }
    }

    fn parse_yaml(&mut self, text: &str) -> Result<Table, Vec<SyntaxError>> {
        config_yaml::parse(text)
    }
}

/// The file `setup` would make, as the reader will name and trust it.
#[derive(Clone, Debug)]
pub(crate) struct NewFile {
    pub display: Vec<u8>,
    pub trust: Trust,
}

/// The new file's key while it has no inode. No file has inode 0 (the
/// built-in source's `config_load::BUILTIN_KEY` is `0, 0`), and the
/// loader's stand-ins for roots it does not read have `dev` all ones. The
/// key lives only in a preview's catalog: the loader never sees it, so no
/// trust or evidence is kept under it from one reading to the next.
pub(crate) const NEW_FILE_KEY: FileKey = FileKey { dev: 1, ino: 0 };

/// The start's tape and the file to add to it.
pub(crate) struct Sources {
    tape: Tape,
    file: NewFile,
    version: Version,
}

impl Sources {
    pub(crate) fn new(tape: Tape, file: NewFile, version: Version) -> Self {
        Self {
            tape,
            file,
            version,
        }
    }

    /// The settings with `bytes` as the new file, loaded from the tape. The
    /// file stands where the reader puts the settings folder's own file:
    /// `Loader::roots` gives the built-in source, then that place
    /// (`config.toml` or `config.json`), then `conf.d` and `config.local`.
    pub(crate) fn load(&self, bytes: &[u8]) -> Result<LoadReport, LoadError> {
        let file = Opened {
            key: NEW_FILE_KEY,
            bytes: bytes.to_vec(),
            trust: self.file.trust,
            display: self.file.display.clone(),
        };
        let path = PathBuf::from(OsString::from_vec(self.file.display.clone()));
        let mut roots = self.tape.roots.clone();
        let at = 1.min(roots.len());
        roots.insert(at, Root::Read(file.clone()));
        let mut replay = Replay {
            calls: &self.tape.calls,
            used: vec![false; self.tape.calls.len()],
            target: Some((&path, &file)),
        };
        load(roots, &mut replay, self.version)
    }

    /// The file setup would make.
    pub(crate) fn file(&self) -> &NewFile {
        &self.file
    }

    /// The new file's place in a catalog `load` returned.
    pub(crate) fn target(&self, files: &[Found]) -> Option<SourceId> {
        files
            .iter()
            .find(|f| f.opened.key == NEW_FILE_KEY)
            .map(|f| f.id)
    }

    /// Whether `now`, a reading made later, saw the same sources.
    pub(crate) fn unchanged(&self, now: &Tape) -> bool {
        self.tape == *now
    }
}

#[cfg(test)]
mod tests;
