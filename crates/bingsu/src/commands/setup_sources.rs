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
use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
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

/// What one reading of the settings saw: the roots, every answer the
/// loader gave, and whether it read everything it met.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Tape {
    roots: Vec<Root>,
    calls: Vec<Call>,
    /// `Loader::read_whole` after the reading: a source dropped for a file
    /// or folder that could not be read can still leave an apply order.
    complete: bool,
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
    /// The settings place's root, the file `place` (right after the
    /// built-in source, named by its canonical path once checked, by
    /// `place` when the check failed): its key and name, and why the reading
    /// could not use it (`None`: read). `None` when the reading found no
    /// such file there (it went, or another root comes first).
    pub(crate) fn settings_root(&self, place: &Path) -> Option<(FileKey, &[u8], Option<&str>)> {
        let Some(Root::File(m)) = self.roots.get(1) else {
            return None;
        };
        // A root checked is named by its canonical path, one whose check
        // failed by the path the reader tried (in the pinned folder, itself
        // canonical).
        let display = Path::new(OsStr::from_bytes(&m.display));
        if display != place && canonical_lenient(place).as_deref() != Some(display) {
            return None;
        }
        let why = self.calls.iter().find_map(|c| match c {
            Call::Root(k, got) if *k == m.key => {
                Some(got.as_ref().err().map(|e| e.reason.as_str()))
            }
            _ => None,
        });
        // A root the reading never asked for (over its budget) is unread too.
        Some((m.key, &m.display, why.unwrap_or(Some("not read"))))
    }

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
        let complete = loader.read_whole();
        (
            Self {
                roots,
                calls,
                complete,
            },
            loaded,
        )
    }

    /// Whether the reading read everything it met.
    pub(crate) fn complete(&self) -> bool {
        self.complete
    }
}

/// Answers from the tape, in the order they were given; a call the start
/// did not make (none can come while the new file has no `extends`) is
/// refused like a file that cannot be read.
struct Replay<'a> {
    calls: &'a [Call],
    used: Vec<bool>,
    target: Option<Swap<'a>>,
}

/// The settings file's bytes in the preview.
#[derive(Clone, Copy)]
enum Swap<'a> {
    /// The new file and its path: an `extends` entry that led there opens
    /// it, as it will once the file is written.
    New { path: &'a Path, file: &'a Opened },
    /// The existing file's key and the bytes in its place: an `extends`
    /// entry that opened it gets them, with the trust of that answer.
    ///
    /// The loader does not reach that today: core keeps a file's first
    /// place when it meets the file again, and gives the place to a later
    /// answer only when that one has stronger trust, which the loader has
    /// not given an alias (a link through a folder others can change and a
    /// hard link from a trusted folder both read with the root's trust).
    /// It stays because such an alias would otherwise draw the start's
    /// bytes in the preview; `every_answer_that_opened_the_settings_file_
    /// gets_the_changed_bytes` makes that case from a recorded reading.
    Existing { key: FileKey, bytes: &'a [u8] },
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
            (Some(Call::Edge { to: Some(to), .. }), Some(Swap::New { path, file }))
                if to == path =>
            {
                Ok(file.clone())
            }
            (Some(Call::Edge { got: Ok(o), .. }), Some(Swap::Existing { key, bytes }))
                if o.key == key =>
            {
                Ok(Opened {
                    bytes: bytes.to_vec(),
                    ..o.clone()
                })
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

/// The settings file the editor is for.
enum Place {
    New(NewFile),
    /// A root the start read, as the loader answered it.
    Existing(Opened),
}

/// The start's tape and the settings file whose bytes a preview sets.
pub(crate) struct Sources {
    tape: Tape,
    place: Place,
    version: Version,
}

impl Sources {
    pub(crate) fn new(tape: Tape, file: NewFile, version: Version) -> Self {
        Self {
            tape,
            place: Place::New(file),
            version,
        }
    }

    /// The sources for the existing root `key`; `None` when the start
    /// could not read it (the loader's reason is then the tape's).
    pub(crate) fn existing(tape: Tape, key: FileKey, version: Version) -> Option<Self> {
        let read = tape.calls.iter().find_map(|c| match c {
            Call::Root(k, Ok(o)) if *k == key => Some(o.clone()),
            _ => None,
        })?;
        Some(Self {
            tape,
            place: Place::Existing(read),
            version,
        })
    }

    /// The existing file's bytes as the start read them (empty for a new
    /// file).
    pub(crate) fn original(&self) -> &[u8] {
        match &self.place {
            Place::New(_) => &[],
            Place::Existing(o) => &o.bytes,
        }
    }

    /// The settings with `bytes` as the new file, loaded from the tape. The
    /// file stands where the reader puts the settings folder's own file:
    /// `Loader::roots` gives the built-in source, then that place
    /// (`config.toml` or `config.json`), then `conf.d` and `config.local`.
    /// An existing file's bytes are swapped in its own place: its root,
    /// read whole into the catalog with the trust and name the loader gave
    /// it, and every `extends` answer that opened it.
    pub(crate) fn load(&self, bytes: &[u8]) -> Result<LoadReport, LoadError> {
        let mut replay = Replay {
            calls: &self.tape.calls,
            used: vec![false; self.tape.calls.len()],
            target: None,
        };
        match &self.place {
            Place::New(new) => {
                let file = Opened {
                    key: NEW_FILE_KEY,
                    bytes: bytes.to_vec(),
                    trust: new.trust,
                    display: new.display.clone(),
                };
                let path = PathBuf::from(OsString::from_vec(new.display.clone()));
                let mut roots = self.tape.roots.clone();
                let at = 1.min(roots.len());
                roots.insert(at, Root::Read(file.clone()));
                replay.target = Some(Swap::New {
                    path: &path,
                    file: &file,
                });
                load(roots, &mut replay, self.version)
            }
            Place::Existing(read) => {
                let roots: Vec<Root> = self
                    .tape
                    .roots
                    .iter()
                    .map(|r| match r {
                        Root::File(m) if m.key == read.key => Root::Read(Opened {
                            bytes: bytes.to_vec(),
                            ..read.clone()
                        }),
                        other => other.clone(),
                    })
                    .collect();
                replay.target = Some(Swap::Existing {
                    key: read.key,
                    bytes,
                });
                load(roots, &mut replay, self.version)
            }
        }
    }

    /// The settings file's place in a catalog `load` returned.
    pub(crate) fn target(&self, files: &[Found]) -> Option<SourceId> {
        let key = match &self.place {
            Place::New(_) => NEW_FILE_KEY,
            Place::Existing(o) => o.key,
        };
        files.iter().find(|f| f.opened.key == key).map(|f| f.id)
    }

    /// Whether the start read everything it met (`Tape::complete`).
    pub(crate) fn complete(&self) -> bool {
        self.tape.complete
    }

    /// Whether `now`, a reading made later, saw the same sources.
    pub(crate) fn unchanged(&self, now: &Tape) -> bool {
        self.tape == *now
    }
}

#[cfg(test)]
mod tests;
