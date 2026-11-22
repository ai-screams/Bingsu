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
use super::config_yaml;
use bingsu_core::config::source::{
    ExtendsRef, FileKey, Found, LoadError, LoadReport, OpenError, Opened, Resolver, Root, RootMeta,
    Trust, Version, load,
};
use bingsu_core::config::tree::{SyntaxError, Table};
use bingsu_core::diag::SourceId;

/// One answer of the loader at the start, in call order.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Call {
    Root(FileKey, Result<Opened, OpenError>),
    Edge {
        from: FileKey,
        text: String,
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
    inner: &'a mut dyn Resolver,
    calls: Vec<Call>,
}

impl Resolver for Recorder<'_> {
    fn adopt(&mut self, key: FileKey, trust: Option<Trust>) {
        self.inner.adopt(key, trust);
    }

    fn open(&mut self, from: &Opened, r: &ExtendsRef) -> Result<Opened, OpenError> {
        let got = self.inner.open(from, r);
        self.calls.push(Call::Edge {
            from: from.key,
            text: r.text.clone(),
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
    /// Loads `roots` through `loader` and keeps what it answered. The
    /// report is the start's own reading, without the new file.
    pub(crate) fn read(
        roots: Vec<Root>,
        loader: &mut dyn Resolver,
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
}

impl Replay<'_> {
    /// The first unused answer that fits, else the last one that fits.
    fn take(&mut self, fits: impl Fn(&Call) -> bool) -> Option<&Call> {
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
        match self.take(
            |c| matches!(c, Call::Edge { from: f, text, .. } if *f == from.key && *text == r.text),
        ) {
            Some(Call::Edge { got, .. }) => got.clone(),
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

/// The start's tape and the file to add to it.
pub(crate) struct Sources {
    tape: Tape,
    file: NewFile,
    /// A key no source of the tape has: the new file has no inode yet.
    key: FileKey,
    version: Version,
}

impl Sources {
    pub(crate) fn new(tape: Tape, file: NewFile, version: Version) -> Self {
        // A root read has its root's key (the loader checks it), and every
        // `extends` starts from a file already met.
        let taken = |k: FileKey| {
            tape.roots.iter().any(|r| root_key(r) == k)
                || tape
                    .calls
                    .iter()
                    .any(|c| matches!(c, Call::Edge { got: Ok(o), .. } if o.key == k))
        };
        let mut key = FileKey { dev: 0, ino: 1 };
        while taken(key) {
            key.ino += 1;
        }
        Self {
            tape,
            file,
            key,
            version,
        }
    }

    /// The settings with `bytes` as the new file, loaded from the tape.
    pub(crate) fn load(&self, bytes: &[u8]) -> Result<LoadReport, LoadError> {
        let mut roots = self.tape.roots.clone();
        let at = 1.min(roots.len());
        roots.insert(
            at,
            Root::Read(Opened {
                key: self.key,
                bytes: bytes.to_vec(),
                trust: self.file.trust,
                display: self.file.display.clone(),
            }),
        );
        let mut replay = Replay {
            calls: &self.tape.calls,
            used: vec![false; self.tape.calls.len()],
        };
        load(roots, &mut replay, self.version)
    }

    /// The new file's place in a catalog `load` returned.
    pub(crate) fn target(&self, files: &[Found]) -> Option<SourceId> {
        files
            .iter()
            .find(|f| f.opened.key == self.key)
            .map(|f| f.id)
    }

    /// Whether `now`, a reading made later, saw the same sources.
    pub(crate) fn unchanged(&self, now: &Tape) -> bool {
        self.tape == *now
    }
}

fn root_key(r: &Root) -> FileKey {
    match r {
        Root::Read(o) => o.key,
        Root::File(m) | Root::TwoFormats { meta: m, .. } => m.key,
    }
}

#[cfg(test)]
mod tests;
