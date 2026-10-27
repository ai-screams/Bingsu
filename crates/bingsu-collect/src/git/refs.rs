//! Bounded loose refs and an in-memory packed-refs snapshot. No ref store.
use super::io::{RepoIo, RepoPath, RootId};
use crate::{
    meter::{Meter, ObjectAllocation},
    safe_read::{ReadError, same_worktree_stat},
};
use bingsu_core::collection::budget::{Axis, REF_BYTES, REF_ENTRIES, SMALL_FILE_BYTES};
use gix_ref::bstr::ByteSlice;
use std::{cell::RefCell, rc::Rc};

pub type ObjectId = gix_index::hash::ObjectId;
const INVALID: ReadError = ReadError::Io(libc::EINVAL);
// At most 40 reads (39 symbolic hops followed by an object).
pub const SYMREF_LIMIT: usize = 40;
/// The release PARSER_ALLOCATION is derived from.
pub const GIX_REF_VERSION: &str = "0.68.0";
// gix-ref 0.68.0 Buffer::from_bytes on N <= REF_BYTES input bytes copies them
// (N). Without a sorted header it collects at most REF_ENTRIES references (the
// axis is charged before; a power of two, so the doubling Vec stops there and
// its growth stays under the later peak), sorts them with scratch of the same size (freed
// before the next step), then writes them back in order into a Vec that
// doubles: at its last growth the old buffer is under N and the new one under
// 2N. The peak is therefore under N + 3N + REF_ENTRIES * size_of(Reference),
// 1,245,184 B with 48-byte references; the worst measured shape (2,049
// unsorted refs, a 1,994 B first name) peaked at 1,244,856 B. Rounded up to
// 5 * 256 KiB.
pub const PARSER_ALLOCATION: usize = REF_BYTES as usize * 5;
// 이것을 실패시키는 것: PARSER_ALLOCATION을 4 * REF_BYTES로 줄이는 것(빌드가 멈춘다).
const _: () = assert!(
    4 * REF_BYTES as usize
        + REF_ENTRIES as usize * std::mem::size_of::<gix_ref::packed::Reference<'static>>()
        <= PARSER_ALLOCATION
);

#[derive(Debug, PartialEq, Eq)]
pub enum Target {
    Object(ObjectId),
    Symbolic(Vec<u8>),
}

pub struct Refs {
    packed: Option<gix_ref::packed::Buffer>,
    source: Source,
    _allocation: Option<ObjectAllocation>,
}

/// What packed-refs was when the snapshot was taken.
enum Source {
    Missing,
    File(libc::stat),
    /// Parsed from bytes without a file (fuzz, unit tests): never current.
    Unrecorded,
}

type LoadedRefs = Result<Rc<Refs>, ReadError>;

/// One lazy packed-refs parse per request, shared by preflight and B/C/D.
/// Cloning the immutable result releases the cell before loose-ref I/O.
#[derive(Default)]
pub struct RefSnapshot {
    refs: RefCell<Option<LoadedRefs>>,
}

impl RefSnapshot {
    pub fn load(&self, io: &RepoIo<'_>) -> LoadedRefs {
        self.get_or_load(io, || Refs::load(io))
    }

    pub(super) fn load_with_config(
        &self,
        io: &RepoIo<'_>,
        config: &super::config::Config,
    ) -> LoadedRefs {
        self.get_or_load(io, || Refs::load_with_config(io, config))
    }

    fn get_or_load(
        &self,
        io: &RepoIo<'_>,
        load: impl FnOnce() -> Result<Refs, ReadError>,
    ) -> LoadedRefs {
        io.metered(|meter| meter.check())?;
        if let Some(loaded) = self.refs.borrow().as_ref() {
            return loaded.clone();
        }
        // No snapshot borrow spans I/O. Deadline belongs to this stage only;
        // real reads/parsed entries stay charged even when a later stage retries.
        let loaded = load().map(Rc::new);
        if !matches!(loaded, Err(ReadError::Deadline)) {
            *self.refs.borrow_mut() = Some(loaded.clone());
        }
        loaded
    }
}

impl Refs {
    pub fn load(io: &RepoIo<'_>) -> Result<Self, ReadError> {
        let config = super::config::Config::load(io)?;
        Self::load_with_config(io, &config)
    }

    pub(super) fn load_with_config(
        io: &RepoIo<'_>,
        config: &super::config::Config,
    ) -> Result<Self, ReadError> {
        config.ensure_supported(io)?;
        let (bytes, metadata) = match io.read_ref_stat(packed_path(), REF_BYTES) {
            Ok(read) => read,
            Err(ReadError::Missing) => {
                return Ok(Self {
                    packed: None,
                    source: Source::Missing,
                    _allocation: None,
                });
            }
            Err(error) => return Err(error),
        };
        let mut refs = io.metered(|meter| Self::parse(&bytes, meter))?;
        refs.source = Source::File(metadata);
        Ok(refs)
    }

    pub(crate) fn parse(bytes: &[u8], meter: &mut Meter) -> Result<Self, ReadError> {
        if bytes.len() > REF_BYTES as usize {
            return Err(ReadError::Limit);
        }
        let mut allocation = meter.object_allocation();
        allocation.reserve(PARSER_ALLOCATION, meter)?;
        // Validate and charge BEFORE Buffer's optional unsorted-input sort.
        let iter =
            gix_ref::packed::Iter::new(bytes, gix_index::hash::Kind::Sha1).map_err(|_| INVALID)?;
        for entry in iter {
            meter.charge_axis(Axis::RefEntries, 1)?;
            let entry = entry.map_err(|_| INVALID)?;
            validate_name(entry.name.as_bstr())?;
        }
        meter.event("before_packed_parse");
        let packed = gix_ref::packed::Buffer::from_bytes(bytes, gix_index::hash::Kind::Sha1)
            .map_err(|_| INVALID)?;
        // A hostile "sorted" header is not evidence of ordering/uniqueness.
        let mut previous = None;
        for entry in packed.iter().map_err(|_| INVALID)? {
            meter.check()?;
            let entry = entry.map_err(|_| INVALID)?;
            let name = entry.name.as_bstr();
            if previous.is_some_and(|old| old >= name) {
                return Err(INVALID);
            }
            previous = Some(name);
        }
        Ok(Self {
            packed: Some(packed),
            source: Source::Unrecorded,
            _allocation: Some(allocation),
        })
    }

    /// Packed refs only. C5 preflight checks loose refs/replace separately.
    pub fn contains_replace(&self) -> bool {
        self.packed.as_ref().is_some_and(|packed| {
            packed.iter().expect("validated buffer").any(|entry| {
                entry
                    .expect("validated entry")
                    .name
                    .as_bstr()
                    .starts_with(b"refs/replace/")
            })
        })
    }

    /// Loose first, then the request snapshot. A loose miss answered from the
    /// snapshot is trusted only while packed-refs is still the file the
    /// snapshot read: packing after the snapshot moves a loose ref into a
    /// packed-refs it never saw, which is `Changed`, never absence or an old id.
    pub fn resolve(&self, io: &RepoIo<'_>, name: &[u8]) -> Result<Option<ObjectId>, ReadError> {
        validate_name(name)?;
        let mut scratch = io.metered(|meter| {
            let mut scratch = meter.path_allocation();
            scratch.reserve(
                name.len() + SYMREF_LIMIT * std::mem::size_of::<Vec<u8>>(),
                meter,
            )?;
            Ok(scratch)
        })?;
        let mut seen = Vec::new();
        let mut current = name.to_vec();
        for _ in 0..SYMREF_LIMIT {
            validate_name(&current)?;
            if seen.contains(&current) {
                return Err(ReadError::Symlink);
            }
            io.metered(|meter| {
                meter.charge_axis(Axis::RefEntries, 1)?;
                scratch.reserve(current.len(), meter)
            })?;
            // HEAD and per-worktree namespaces live in gitdir. Never interpret
            // main-worktree/worktrees pseudo paths or repository-supplied roots.
            let root = ref_root(&current);
            match io.read_ref(RepoPath::new(root, &current), SMALL_FILE_BYTES) {
                Ok(bytes) => match parse_loose(&bytes)? {
                    Target::Object(id) => return Ok(Some(id)),
                    Target::Symbolic(next) => {
                        seen.push(current);
                        current = next;
                    }
                },
                Err(ReadError::Missing) => {
                    let found = self.find_packed(io, &current, root)?;
                    // After the loose miss: git packs by renaming packed-refs
                    // into place before it deletes loose refs, so an unchanged
                    // file now proves the miss and the snapshot agree.
                    if root == RootId::CommonDir {
                        self.ensure_current(io)?;
                    }
                    return Ok(found);
                }
                Err(error) => return Err(error),
            }
        }
        Err(ReadError::Limit)
    }

    /// A fresh same-path open and fstat, compared with the snapshot's fd stat.
    fn ensure_current(&self, io: &RepoIo<'_>) -> Result<(), ReadError> {
        let same = match (&self.source, io.metadata(packed_path())) {
            (Source::Missing, Err(ReadError::Missing)) => true,
            (Source::File(then), Ok(now)) => same_worktree_stat(then, &now),
            (_, Err(error)) if error != ReadError::Missing => return Err(error),
            _ => false,
        };
        if same {
            Ok(())
        } else {
            Err(ReadError::Changed)
        }
    }

    fn find_packed(
        &self,
        io: &RepoIo<'_>,
        name: &[u8],
        root: RootId,
    ) -> Result<Option<ObjectId>, ReadError> {
        if root == RootId::GitDir {
            return Ok(None);
        }
        io.metered(|meter| {
            if let Some(packed) = &self.packed {
                for entry in packed.iter().map_err(|_| INVALID)? {
                    meter.check()?;
                    let entry = entry.map_err(|_| INVALID)?;
                    if entry.name.as_bstr() == name {
                        return Ok(Some(entry.target()));
                    }
                }
            }
            Ok(None)
        })
    }
}

fn packed_path() -> RepoPath {
    RepoPath::new(RootId::CommonDir, b"packed-refs")
}

fn ref_root(name: &[u8]) -> RootId {
    if name == b"HEAD"
        || [
            b"refs/bisect/".as_slice(),
            b"refs/worktree/",
            b"refs/rewritten/",
        ]
        .iter()
        .any(|prefix| name.starts_with(prefix))
    {
        RootId::GitDir
    } else {
        RootId::CommonDir
    }
}

fn validate_name(name: &[u8]) -> Result<(), ReadError> {
    if name.len() > SMALL_FILE_BYTES as usize || (name != b"HEAD" && !name.starts_with(b"refs/")) {
        return Err(INVALID);
    }
    gix_index::validate::reference::name(name.as_bstr()).map_err(|_| INVALID)?;
    Ok(())
}

pub fn parse_loose(bytes: &[u8]) -> Result<Target, ReadError> {
    if bytes.len() > SMALL_FILE_BYTES as usize {
        return Err(ReadError::Limit);
    }
    let line = bytes.strip_suffix(b"\n").unwrap_or(bytes);
    let line = line.strip_suffix(b"\r").unwrap_or(line);
    if let Some(name) = line.strip_prefix(b"ref: ") {
        validate_name(name)?;
        Ok(Target::Symbolic(name.to_vec()))
    } else if line.len() == 40 {
        ObjectId::from_hex(line)
            .map(Target::Object)
            .map_err(|_| INVALID)
    } else {
        Err(INVALID)
    }
}
