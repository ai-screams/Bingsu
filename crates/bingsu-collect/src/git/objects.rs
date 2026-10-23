//! Read-only SHA-1 object access. No alternates, replacement refs, commit-graph,
//! path-opening gix constructors, or ambient repository state exists here.
use super::{ReadMap, RepoIo, RepoPath, RootId, UNSUPPORTED, index::checksum};
use crate::{meter::Meter, safe_read::ReadError};
use bingsu_core::collection::budget::{self, Axis};
use gix_error::ErrorExt;
use gix_index::hash::{self, ObjectId, oid};
use gix_object::{Data, Kind};
use gix_pack::data::{Entry, entry::Header};
use std::{cell::RefCell, path::PathBuf};

const INVALID: ReadError = ReadError::Io(libc::EINVAL);
pub const DELTA_DEPTH: usize = 64;
// Measured by the counting allocator, including zlib's deferred window and
// gix's SmallVec delta chain (old + new allocation during growth) and errors.
pub const DECODER_OVERHEAD: usize = 131_072;
pub const PARSER_OVERHEAD: usize = 16_384;
// The object cap includes the decoder, not just the caller's output buffer.
pub const OBJECT_BUFFER: usize = budget::OBJECT_ALLOC as usize - DECODER_OVERHEAD;

pub(crate) struct Pack {
    name: Vec<u8>,
    index: gix_pack::index::File<ReadMap>,
    data: ReadMap,
}

/// One adapter per repository, sharing the same B/C meter. Initialization does
/// no I/O. Immutable pack snapshots are retained after the first loose miss.
pub struct SafeObjectDb<'a> {
    io: &'a RepoIo<'a>,
    packs: RefCell<Option<Result<Vec<Pack>, ReadError>>>,
}
impl<'a> SafeObjectDb<'a> {
    pub fn new(io: &'a RepoIo<'a>) -> Self {
        Self {
            io,
            packs: RefCell::new(None),
        }
    }

    pub fn find<'b>(
        &self,
        id: &oid,
        buffer: &'b mut Vec<u8>,
    ) -> Result<Option<Data<'b>>, ReadError> {
        self.io.metered(|meter| meter.check())?;
        // A previous object's capacity must not overlap the next loose input.
        // Drop it before safe-read allocates its compressed snapshot.
        *buffer = Vec::new();
        // SHA-256 repositories are rejected by preflight; don't reinterpret IDs.
        if id.kind() != hash::Kind::Sha1 {
            return Err(UNSUPPORTED);
        }
        // Reuse the packed snapshot without reopening paths after initialization.
        if self.packs.borrow().is_none() {
            let mut hex = [0u8; 40];
            id.write_hex_to(&mut hex.as_mut_slice())
                .map_err(|_| INVALID)?;
            let mut relative = [0u8; 49];
            relative[..8].copy_from_slice(b"objects/");
            relative[8..10].copy_from_slice(&hex[..2]);
            relative[10] = b'/';
            relative[11..].copy_from_slice(&hex[2..]);
            match self.io.read_sized(
                RepoPath::new(RootId::CommonDir, &relative),
                (OBJECT_BUFFER - 1) as u64,
                None,
            ) {
                Ok(bytes) => {
                    return self
                        .io
                        .metered(|meter| loose(&bytes, id, buffer, meter))
                        .map(Some);
                }
                Err(ReadError::Missing) => {}
                Err(error) => return Err(error),
            }
            *self.packs.borrow_mut() = Some(self.load_packs());
        }
        let packs = self.packs.borrow();
        let packs = packs
            .as_ref()
            .expect("initialized")
            .as_ref()
            .map_err(|e| *e)?;
        for pack in packs {
            if let Some(position) = pack.index.lookup(id) {
                let offset = pack.index.pack_offset_at_index(position);
                return self
                    .io
                    .metered(|meter| decode(&pack.data, &pack.index, offset, id, buffer, meter))
                    .map(Some);
            }
        }
        // A packed miss can still be loose, including objects added after pack
        // initialization. It never causes a pack refresh or alternates lookup.
        let relative = format!("objects/{}/{}", &id.to_string()[..2], &id.to_string()[2..]);
        match self.io.read_sized(
            RepoPath::new(RootId::CommonDir, relative.as_bytes()),
            (OBJECT_BUFFER - 1) as u64,
            None,
        ) {
            Ok(bytes) => self
                .io
                .metered(|meter| loose(&bytes, id, buffer, meter))
                .map(Some),
            Err(ReadError::Missing) => Ok(None),
            Err(error) => Err(error),
        }
    }

    fn load_packs(&self) -> Result<Vec<Pack>, ReadError> {
        self.io.metered(|meter| {
            if meter.budget.used(Axis::Packs) == budget::PACKS {
                return Err(ReadError::Limit);
            }
            meter.allocation(PARSER_OVERHEAD)
        })?;
        let listing = match self
            .io
            .list(RepoPath::new(RootId::CommonDir, b"objects/pack"), 4096)
        {
            Ok(listing) => listing,
            Err(ReadError::Missing) => return Ok(Vec::new()),
            Err(error) => return Err(error),
        };
        if !listing.complete {
            return self.io.metered(|_| Err(ReadError::Limit));
        }
        let count = listing
            .names
            .iter()
            .filter(|n| pack_name(n, b".pack"))
            .count();
        self.io
            .metered(|meter| meter.charge_axis(Axis::Packs, count as u64))?;
        let mut packs = Vec::with_capacity(count);
        for mut name in listing.names.into_iter().filter(|n| pack_name(n, b".pack")) {
            let data = self.io.map(pack_path(&name), budget::PACK_BYTES)?;
            self.io.metered(|meter| {
                meter.check()?;
                checksum(&data)
            })?;
            name.truncate(45);
            name.extend_from_slice(b".idx");
            let bytes = self.io.map(pack_path(&name), budget::PACK_BYTES)?;
            let pack = self
                .io
                .metered(|meter| Pack::from_bytes(name, data, bytes, meter))?;
            packs.push(pack);
        }
        // MIDX is optional; a corrupt or unsupported one must be Partial, never
        // silently treated as empty. Names never become paths without validation.
        match self
            .io
            .map(pack_path(b"multi-pack-index"), budget::PACK_BYTES)
        {
            Ok(bytes) => self
                .io
                .metered(|meter| validate_midx(bytes, &packs, meter))?,
            Err(ReadError::Missing) => {}
            Err(error) => return Err(error),
        }
        Ok(packs)
    }

    pub fn head_tree(&self, head: &oid) -> Result<ObjectId, ReadError> {
        let mut buffer = Vec::new();
        let data = self.find(head, &mut buffer)?.ok_or(ReadError::Missing)?;
        self.io.metered(|meter| {
            meter.allocation(PARSER_OVERHEAD)?;
            if data.kind != Kind::Commit {
                return Err(INVALID);
            }
            gix_object::CommitRefIter::from_bytes(data.data, hash::Kind::Sha1)
                .tree_id()
                .map_err(|_| INVALID)
        })
    }

    /// A borrowed tree iterator; D1a charges full joined paths before retaining
    /// derived entries. Here even entries that D1a excludes consume the budget.
    pub fn tree<'b>(
        &self,
        id: &oid,
        buffer: &'b mut Vec<u8>,
    ) -> Result<gix_object::TreeRefIter<'b>, ReadError> {
        let data = self.find(id, buffer)?.ok_or(ReadError::Missing)?;
        self.io.metered(|meter| {
            meter.allocation(PARSER_OVERHEAD)?;
            if data.kind != Kind::Tree {
                return Err(INVALID);
            }
            for entry in gix_object::TreeRefIter::from_bytes(data.data, hash::Kind::Sha1) {
                meter.charge_axis(Axis::IndexEntries, 1)?;
                let entry = entry.map_err(|_| INVALID)?;
                let name: &[u8] = entry.filename.as_ref();
                if name.is_empty() || name == b"." || name == b".." || name.contains(&b'/') {
                    return Err(INVALID);
                }
                meter.charge_axis(Axis::IndexBytes, name.len() as u64)?;
            }
            Ok(gix_object::TreeRefIter::from_bytes(
                data.data,
                hash::Kind::Sha1,
            ))
        })
    }
}
impl gix_object::Find for SafeObjectDb<'_> {
    fn try_find<'b>(
        &self,
        id: &oid,
        buffer: &'b mut Vec<u8>,
    ) -> gix_error::ExnResult<Option<Data<'b>>> {
        self.find(id, buffer)
            .map_err(|error| ObjectError(error).raise_erased())
    }
}
#[derive(Debug)]
pub struct ObjectError(pub ReadError);
impl std::fmt::Display for ObjectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "safe object read: {:?}", self.0)
    }
}
impl std::error::Error for ObjectError {}

fn pack_name(name: &[u8], suffix: &[u8]) -> bool {
    name.len() == 45 + suffix.len()
        && name.starts_with(b"pack-")
        && name.ends_with(suffix)
        && name[5..45]
            .iter()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}
fn pack_path(name: &[u8]) -> RepoPath {
    let mut path = b"objects/pack/".to_vec();
    path.extend_from_slice(name);
    RepoPath::new(RootId::CommonDir, &path)
}
fn reserve(buffer: &mut Vec<u8>, size: usize, meter: &mut Meter) -> Result<(), ReadError> {
    if size > OBJECT_BUFFER {
        return Err(ReadError::Limit);
    }
    // Replace a too-small Vec, avoiding unbounded growth and retaining the
    // caller's previous buffer only until the exact reservation has succeeded.
    if buffer.capacity() < size {
        meter.allocation(size)?;
        *buffer = Vec::new();
        buffer
            .try_reserve_exact(size)
            .map_err(|_| ReadError::Limit)?;
    }
    buffer.clear();
    Ok(())
}
fn verify(id: &oid, kind: Kind, buffer: &[u8]) -> Result<(), ReadError> {
    if gix_object::compute_hash(hash::Kind::Sha1, kind, buffer)
        .map_err(|_| INVALID)?
        .as_ref()
        != id
    {
        return Err(INVALID);
    }
    Ok(())
}

pub(crate) fn loose<'b>(
    bytes: &[u8],
    id: &oid,
    buffer: &'b mut Vec<u8>,
    meter: &mut Meter,
) -> Result<Data<'b>, ReadError> {
    // Reserve room for safe-read's cap+1 allocation before constructing zlib.
    if bytes.len() >= OBJECT_BUFFER {
        return Err(ReadError::Limit);
    }
    // Direct bytes-parser callers obey the same live-capacity bound as Find.
    *buffer = Vec::new();
    meter.allocation(DECODER_OVERHEAD)?;
    let mut inflate = gix_zlib::Inflate::default();
    let mut header = [0u8; 64];
    // The first probe is bounded even for a zip bomb, and its duplicated output
    // is charged independently of the full second inflate.
    meter.charge_axis(Axis::DecompressedBytes, header.len() as u64)?;
    let (_, _, out) = inflate.once(bytes, &mut header).map_err(|_| INVALID)?;
    let end = header[..out].iter().position(|b| *b == 0).ok_or(INVALID)?;
    let split = header[..end]
        .iter()
        .position(|b| *b == b' ')
        .ok_or(INVALID)?;
    let kind = match &header[..split] {
        b"blob" => Kind::Blob,
        b"tree" => Kind::Tree,
        b"commit" => Kind::Commit,
        b"tag" => Kind::Tag,
        _ => return Err(INVALID),
    };
    let digits = &header[split + 1..end];
    if digits.is_empty() || (digits.len() > 1 && digits[0] == b'0') {
        return Err(INVALID);
    }
    let mut size = 0usize;
    for byte in digits {
        if !byte.is_ascii_digit() {
            return Err(INVALID);
        }
        size = size
            .checked_mul(10)
            .and_then(|n| n.checked_add((byte - b'0') as usize))
            .ok_or(ReadError::Limit)?;
    }
    let total = size.checked_add(end + 1).ok_or(ReadError::Limit)?;
    // The loose snapshot is live throughout inflate: include it alongside the
    // decoder and output in the per-object allocation cap, before reserving.
    if bytes
        .len()
        .checked_add(total)
        .and_then(|n| n.checked_add(1)) // safe-read's cap+1 probe allocation
        .ok_or(ReadError::Limit)?
        > OBJECT_BUFFER
    {
        return Err(ReadError::Limit);
    }
    meter.charge_axis(Axis::DecompressedBytes, total as u64)?;
    reserve(buffer, total, meter)?;
    buffer.resize(total, 0);
    inflate.reset();
    let (status, consumed, produced) = inflate.once(bytes, buffer).map_err(|_| INVALID)?;
    if status != gix_zlib::Status::StreamEnd || consumed != bytes.len() || produced != total {
        return Err(INVALID);
    }
    buffer.copy_within(end + 1.., 0);
    buffer.truncate(size);
    verify(id, kind, buffer)?;
    Ok(Data {
        kind,
        object_hash: hash::Kind::Sha1,
        data: buffer,
    })
}

fn checked_entry(
    file: &gix_pack::data::File<&[u8]>,
    data: &[u8],
    offset: u64,
) -> Result<Entry, ReadError> {
    if offset < 12 || offset >= data.len().saturating_sub(20) as u64 {
        return Err(INVALID);
    }
    file.entry(offset).map_err(|_| INVALID)
}

pub(crate) fn decode<'b>(
    data: &[u8],
    index: &gix_pack::index::File<impl gix_pack::FileData>,
    offset: u64,
    id: &oid,
    buffer: &'b mut Vec<u8>,
    meter: &mut Meter,
) -> Result<Data<'b>, ReadError> {
    // Do not retain a caller capacity larger than this object's reservation.
    *buffer = Vec::new();
    meter.allocation(DECODER_OVERHEAD)?;
    let file = gix_pack::data::File::from_data(data, PathBuf::new(), hash::Kind::Sha1)
        .map_err(|_| INVALID)?
        .with_alloc_limit_bytes(Some(OBJECT_BUFFER));
    let first = checked_entry(&file, data, offset)?;
    let mut cursor = first.clone();
    let mut offsets = [0u64; DELTA_DEPTH];
    let mut depth = 0usize;
    let mut delta_bytes = 0usize;
    let mut largest = 0usize;
    let mut inflate = gix_zlib::Inflate::default();
    loop {
        meter.check()?;
        let size = usize::try_from(cursor.decompressed_size).map_err(|_| ReadError::Limit)?;
        if size > budget::OBJECT_ALLOC as usize {
            return Err(ReadError::Limit);
        }
        meter.charge_axis(Axis::DecompressedBytes, size as u64)?;
        if !cursor.header.is_delta() {
            largest = largest.max(size);
            break;
        }
        if depth == DELTA_DEPTH || offsets[..depth].contains(&cursor.pack_offset()) {
            return Err(ReadError::Limit);
        }
        offsets[depth] = cursor.pack_offset();
        depth += 1;
        delta_bytes = delta_bytes.checked_add(size).ok_or(ReadError::Limit)?;
        if delta_bytes > budget::OBJECT_ALLOC as usize {
            return Err(ReadError::Limit);
        }
        let mut prefix = [0u8; 20];
        meter.charge_axis(Axis::DecompressedBytes, prefix.len() as u64)?;
        inflate.reset();
        let (_, _, n) = inflate
            .once(&data[cursor.data_offset as usize..], &mut prefix)
            .map_err(|_| INVALID)?;
        let (base, used) = delta_size(&prefix[..n]).map_err(|_| INVALID)?;
        let (result, _) = delta_size(&prefix[used..n]).map_err(|_| INVALID)?;
        largest = largest.max(usize::try_from(base.max(result)).map_err(|_| ReadError::Limit)?);
        let next = match cursor.header {
            Header::OfsDelta { base_distance } => cursor
                .checked_base_pack_offset(base_distance)
                .ok_or(INVALID)?,
            Header::RefDelta { base_id } => index
                .lookup(base_id)
                .map(|n| index.pack_offset_at_index(n))
                .ok_or(UNSUPPORTED)?,
            _ => unreachable!(),
        };
        cursor = checked_entry(&file, data, next)?;
    }
    let capacity = if depth == 0 {
        largest
    } else {
        largest
            .checked_mul(2)
            .and_then(|n| n.checked_add(delta_bytes))
            .ok_or(ReadError::Limit)?
    };
    reserve(buffer, capacity, meter)?;
    // Every in-pack base has already been walked, charged and bounded above.
    // A thin pack with an external base is unsupported (Partial); it must never
    // trigger a recursive path lookup, alternate, or unmetered allocation.
    let resolve = |base: &oid, _: &mut Vec<u8>| {
        let position = index.lookup(base)?;
        let entry = checked_entry(&file, data, index.pack_offset_at_index(position)).ok()?;
        Some(gix_pack::data::decode::entry::ResolvedBase::InPack(entry))
    };
    let outcome = file
        .decode_entry(
            first,
            buffer,
            &mut inflate,
            &resolve,
            &mut gix_pack::cache::Never,
        )
        .map_err(|_| INVALID)?;
    verify(id, outcome.kind, buffer)?;
    Ok(Data {
        kind: outcome.kind,
        object_hash: hash::Kind::Sha1,
        data: buffer,
    })
}

fn u32_at(bytes: &[u8], offset: usize) -> Result<u32, ReadError> {
    Ok(u32::from_be_bytes(
        bytes
            .get(offset..offset + 4)
            .ok_or(INVALID)?
            .try_into()
            .map_err(|_| INVALID)?,
    ))
}
pub(crate) fn validate_midx(
    bytes: ReadMap,
    packs: &[Pack],
    meter: &mut Meter,
) -> Result<(), ReadError> {
    checksum(&bytes)?;
    if bytes.len() < 12 || bytes[5] != 1 || bytes[7] != 0 {
        return Err(UNSUPPORTED);
    }
    let count = u32_at(&bytes, 8)? as usize;
    if count > budget::PACKS as usize {
        return Err(ReadError::Limit);
    }
    // Bound all constructor allocations: <=255 chunk descriptors, <=8 paths,
    // names bounded by input bytes. Reject large-offset chunks before accessors
    // whose LOFF indirection is unchecked; our <=8 MiB packs cannot need LOFF.
    for n in 0..usize::from(bytes[6]) {
        let at = 12 + n * 12;
        if bytes.get(at..at + 4).ok_or(INVALID)? == b"LOFF" {
            return Err(UNSUPPORTED);
        }
    }
    let reservation = bytes
        .len()
        .checked_add(PARSER_OVERHEAD)
        .ok_or(ReadError::Limit)?;
    meter.allocation(reservation)?;
    let midx = gix_pack::multi_index::File::from_data(bytes, PathBuf::new(), Some(reservation))
        .map_err(|_| INVALID)?;
    if midx.num_indices() as usize > packs.len() {
        return Err(INVALID);
    }
    for name in midx.index_names() {
        let name = name.as_os_str().as_encoded_bytes();
        if !pack_name(name, b".idx") || !packs.iter().any(|p| p.name == name) {
            return Err(INVALID);
        }
    }
    for n in 0..midx.num_objects() {
        meter.check()?;
        let id = midx.oid_at_index(n);
        if n > 0 && midx.oid_at_index(n - 1) >= id {
            return Err(INVALID);
        }
        if midx.lookup(id) != Some(n) {
            return Err(INVALID);
        }
        let (pack, offset) = midx.pack_id_and_pack_offset_at_index(n);
        let name = midx
            .index_names()
            .get(pack as usize)
            .ok_or(INVALID)?
            .as_os_str()
            .as_encoded_bytes();
        let pack = packs.iter().find(|p| p.name == name).ok_or(INVALID)?;
        if pack
            .index
            .lookup(id)
            .map(|n| pack.index.pack_offset_at_index(n))
            != Some(offset)
        {
            return Err(INVALID);
        }
    }
    Ok(())
}

// Size framing only; gix remains responsible for delta validation/application.
fn delta_size(bytes: &[u8]) -> Result<(u64, usize), ReadError> {
    let mut size = 0u64;
    for (n, byte) in bytes.iter().take(10).enumerate() {
        if n == 9 && *byte > 1 {
            return Err(INVALID);
        }
        size |= u64::from(byte & 127) << (n * 7);
        if byte & 128 == 0 {
            return Ok((size, n + 1));
        }
    }
    Err(INVALID)
}

impl Pack {
    pub(crate) fn from_bytes(
        name: Vec<u8>,
        data: ReadMap,
        bytes: ReadMap,
        meter: &mut Meter,
    ) -> Result<Self, ReadError> {
        meter.allocation(PARSER_OVERHEAD)?;
        checksum(&data)?;
        checksum(&bytes)?;
        let index = gix_pack::index::File::from_data(bytes, PathBuf::new(), hash::Kind::Sha1)
            .map_err(|_| INVALID)?;
        let file = gix_pack::data::File::from_data(&data[..], PathBuf::new(), hash::Kind::Sha1)
            .map_err(|_| INVALID)?;
        if index.pack_checksum() != file.checksum() || index.num_objects() != file.num_objects() {
            return Err(INVALID);
        }
        for n in 0..index.num_objects() {
            meter.check()?;
            if n > 0 && index.oid_at_index(n - 1) >= index.oid_at_index(n) {
                return Err(INVALID);
            }
            if index.lookup(index.oid_at_index(n)) != Some(n) {
                return Err(INVALID);
            }
            checked_entry(&file, &data, index.pack_offset_at_index(n))?;
        }
        Ok(Self { name, data, index })
    }
}
