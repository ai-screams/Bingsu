//! Bounded loose refs and an in-memory packed-refs snapshot. No ref store.
use super::io::{RepoIo, RepoPath, RootId};
use crate::{meter::Meter, safe_read::ReadError};
use bingsu_core::collection::budget::{Axis, REF_BYTES, SMALL_FILE_BYTES};
use gix_ref::bstr::ByteSlice;

pub type ObjectId = gix_index::hash::ObjectId;
const INVALID: ReadError = ReadError::Io(libc::EINVAL);
// At most 40 reads (39 symbolic hops followed by an object).
pub const SYMREF_LIMIT: usize = 40;
// gix-ref 0.68.0: counted peak 1,139,975 B (4.35 * 256 KiB), including
// unsorted entries, sort scratch and overlapping serialized Vec growth.
// Round up to 5 * 256 KiB; the allocator corpus guards this pinned envelope.
pub const PARSER_ALLOCATION: usize = REF_BYTES as usize * 5;

#[derive(Debug, PartialEq, Eq)]
pub enum Target {
    Object(ObjectId),
    Symbolic(Vec<u8>),
}

pub struct Refs {
    packed: Option<gix_ref::packed::Buffer>,
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
        let bytes = match io.read_ref(RepoPath::new(RootId::CommonDir, b"packed-refs"), REF_BYTES) {
            Ok(bytes) => bytes,
            Err(ReadError::Missing) => return Ok(Self { packed: None }),
            Err(error) => return Err(error),
        };
        io.metered(|meter| Self::parse(&bytes, meter))
    }

    pub(crate) fn parse(bytes: &[u8], meter: &mut Meter) -> Result<Self, ReadError> {
        if bytes.len() > REF_BYTES as usize {
            return Err(ReadError::Limit);
        }
        meter.allocation(PARSER_ALLOCATION)?;
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

    pub fn resolve(&self, io: &RepoIo<'_>, name: &[u8]) -> Result<Option<ObjectId>, ReadError> {
        validate_name(name)?;
        io.metered(|meter| meter.allocation(name.len()))?;
        let mut seen = Vec::new();
        let mut current = name.to_vec();
        for _ in 0..SYMREF_LIMIT {
            validate_name(&current)?;
            if seen.contains(&current) {
                return Err(ReadError::Symlink);
            }
            io.metered(|meter| {
                meter.charge_axis(Axis::RefEntries, 1)?;
                meter.allocation(current.len())
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
                Err(ReadError::Missing) => return self.find_packed(io, &current, root),
                Err(error) => return Err(error),
            }
        }
        Err(ReadError::Limit)
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
