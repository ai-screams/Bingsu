//! Byte builders for the in-memory corpus: zlib, SHA-1 trailers, pack v2,
//! pack index v2, multi-pack-index v1 and index v2. Test input only; the
//! collector never writes these formats. Shared by fuzz/collector and the
//! stable seed replay, so a seed means the same bytes in both.
use std::io::Write;

pub type Oid = [u8; 20];

pub fn sha1(bytes: &[u8]) -> Oid {
    let mut digest = gix_index::hash::hasher(gix_index::hash::Kind::Sha1);
    digest.update(bytes);
    let id = digest.try_finalize().expect("sha1 of test bytes");
    id.as_slice().try_into().expect("sha1 width")
}

/// A git object id: SHA-1 of "<kind> <len>\0<body>".
pub fn object_id(kind: &str, body: &[u8]) -> Oid {
    sha1(&loose_raw(kind, body))
}

pub fn loose_raw(kind: &str, body: &[u8]) -> Vec<u8> {
    let mut raw = format!("{kind} {}\0", body.len()).into_bytes();
    raw.extend_from_slice(body);
    raw
}

pub fn deflate(bytes: &[u8]) -> Vec<u8> {
    let mut writer =
        gix_zlib::stream::deflate::Write::new(Vec::new(), gix_zlib::Compression::DEFAULT);
    writer.write_all(bytes).expect("in-memory deflate");
    writer.flush().expect("in-memory deflate");
    writer.into_inner()
}

/// Replace (or append) the trailing SHA-1 of everything before it.
pub fn seal(mut bytes: Vec<u8>) -> Vec<u8> {
    let digest = sha1(&bytes);
    bytes.extend_from_slice(&digest);
    bytes
}

pub fn reseal(bytes: &mut [u8]) {
    if let Some(end) = bytes.len().checked_sub(20) {
        let digest = sha1(&bytes[..end]);
        bytes[end..].copy_from_slice(&digest);
    }
}

pub enum PackEntry {
    Base {
        kind: u8,
        body: Vec<u8>,
    },
    /// Base is the entry this many entries earlier (always backwards).
    OfsDelta {
        back: usize,
        delta: Vec<u8>,
    },
    RefDelta {
        base: Oid,
        delta: Vec<u8>,
    },
}

/// Header byte: type in bits 4-6, size as little-endian 4 + 7*n bits.
fn entry_header(kind: u8, mut size: usize) -> Vec<u8> {
    let mut out = vec![(kind << 4) | (size & 15) as u8];
    size >>= 4;
    while size != 0 {
        *out.last_mut().expect("header byte") |= 0x80;
        out.push((size & 0x7f) as u8);
        size >>= 7;
    }
    out
}

/// OFS_DELTA's big-endian, offset-by-one base distance encoding.
fn ofs_distance(mut distance: u64) -> Vec<u8> {
    let mut out = vec![(distance & 0x7f) as u8];
    distance >>= 7;
    while distance != 0 {
        distance -= 1;
        out.push(0x80 | (distance & 0x7f) as u8);
        distance >>= 7;
    }
    out.reverse();
    out
}

pub fn varint(mut value: u64) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let byte = (value & 0x7f) as u8;
        value >>= 7;
        if value == 0 {
            out.push(byte);
            return out;
        }
        out.push(byte | 0x80);
    }
}

/// A delta that copies `base_len` bytes from offset 0, then inserts `insert`.
pub fn copy_insert_delta(base_len: usize, insert: &[u8]) -> Vec<u8> {
    assert!(base_len > 0 && base_len < 0x10000 && insert.len() < 128);
    let mut delta = varint(base_len as u64);
    delta.extend(varint((base_len + insert.len()) as u64));
    delta.extend([
        0x80 | 0x10 | 0x20,
        (base_len & 0xff) as u8,
        (base_len >> 8) as u8,
    ]);
    if !insert.is_empty() {
        delta.push(insert.len() as u8);
        delta.extend_from_slice(insert);
    }
    delta
}

pub struct Pack {
    pub data: Vec<u8>,
    pub offsets: Vec<u64>,
}

pub fn pack(entries: &[PackEntry]) -> Pack {
    let mut data = b"PACK".to_vec();
    data.extend(2u32.to_be_bytes());
    data.extend((entries.len() as u32).to_be_bytes());
    let mut offsets = Vec::new();
    for entry in entries {
        let offset = data.len() as u64;
        match entry {
            PackEntry::Base { kind, body } => {
                data.extend(entry_header(*kind, body.len()));
                data.extend(deflate(body));
            }
            PackEntry::OfsDelta { back, delta } => {
                let base = offsets[offsets.len() - back];
                data.extend(entry_header(6, delta.len()));
                data.extend(ofs_distance(offset - base));
                data.extend(deflate(delta));
            }
            PackEntry::RefDelta { base, delta } => {
                data.extend(entry_header(7, delta.len()));
                data.extend_from_slice(base);
                data.extend(deflate(delta));
            }
        }
        offsets.push(offset);
    }
    Pack {
        data: seal(data),
        offsets,
    }
}

/// Pack index v2 for (oid, offset) pairs; ids need not hash their entries.
pub fn pack_index(objects: &[(Oid, u64)], pack: &[u8]) -> Vec<u8> {
    let mut sorted = objects.to_vec();
    sorted.sort();
    let mut out = vec![0xff, b't', b'O', b'c'];
    out.extend(2u32.to_be_bytes());
    for byte in 0..=255u8 {
        let count = sorted.iter().filter(|(id, _)| id[0] <= byte).count() as u32;
        out.extend(count.to_be_bytes());
    }
    for (id, _) in &sorted {
        out.extend_from_slice(id);
    }
    for _ in &sorted {
        out.extend(0u32.to_be_bytes());
    }
    for (_, offset) in &sorted {
        out.extend((*offset as u32).to_be_bytes());
    }
    out.extend_from_slice(&pack[pack.len() - 20..]);
    seal(out)
}

/// The name the collector accepts for an index file in objects/pack.
pub fn pack_name(pack: &[u8]) -> Vec<u8> {
    let mut name = b"pack-".to_vec();
    for byte in &pack[pack.len() - 20..] {
        name.extend(format!("{byte:02x}").bytes());
    }
    name.extend(b".idx");
    name
}

pub struct MidxParts {
    pub packs: u32,
    pub names: Vec<Vec<u8>>,
    pub objects: Vec<(Oid, u32, u32)>,
    pub extra_chunk: Option<([u8; 4], Vec<u8>)>,
}

pub fn midx(parts: &MidxParts) -> Vec<u8> {
    let mut sorted = parts.objects.clone();
    sorted.sort();
    let mut pnam = Vec::new();
    for name in &parts.names {
        pnam.extend_from_slice(name);
        pnam.push(0);
    }
    while pnam.len() % 4 != 0 {
        pnam.push(0);
    }
    let mut oidf = Vec::new();
    for byte in 0..=255u8 {
        let count = sorted.iter().filter(|(id, ..)| id[0] <= byte).count() as u32;
        oidf.extend(count.to_be_bytes());
    }
    let oidl: Vec<u8> = sorted.iter().flat_map(|(id, ..)| id.to_vec()).collect();
    let ooff: Vec<u8> = sorted
        .iter()
        .flat_map(|(_, pack, offset)| [pack.to_be_bytes(), offset.to_be_bytes()].concat())
        .collect();
    let mut chunks: Vec<([u8; 4], Vec<u8>)> = vec![
        (*b"PNAM", pnam),
        (*b"OIDF", oidf),
        (*b"OIDL", oidl),
        (*b"OOFF", ooff),
    ];
    if let Some(extra) = &parts.extra_chunk {
        chunks.push(extra.clone());
    }
    let mut out = b"MIDX".to_vec();
    out.extend([1, 1, chunks.len() as u8, 0]);
    out.extend(parts.packs.to_be_bytes());
    let mut offset = (out.len() + 12 * (chunks.len() + 1)) as u64;
    for (id, body) in &chunks {
        out.extend_from_slice(id);
        out.extend(offset.to_be_bytes());
        offset += body.len() as u64;
    }
    out.extend([0; 4]);
    out.extend(offset.to_be_bytes());
    for (_, body) in &chunks {
        out.extend_from_slice(body);
    }
    seal(out)
}

pub struct IndexEntry {
    pub path: Vec<u8>,
    pub id: Oid,
    pub mode: u32,
    pub stage: u16,
}

/// Index v2 (or v3 header) with optional raw extensions, sealed.
pub fn index(version: u32, entries: &[IndexEntry], extensions: &[([u8; 4], Vec<u8>)]) -> Vec<u8> {
    let mut out = b"DIRC".to_vec();
    out.extend(version.to_be_bytes());
    out.extend((entries.len() as u32).to_be_bytes());
    for entry in entries {
        let start = out.len();
        out.extend([0u8; 24]);
        out.extend(entry.mode.to_be_bytes());
        out.extend([0u8; 12]);
        out.extend_from_slice(&entry.id);
        let length = entry.path.len().min(0xfff) as u16;
        out.extend(((entry.stage << 12) | length).to_be_bytes());
        out.extend_from_slice(&entry.path);
        out.push(0);
        while (out.len() - start) % 8 != 0 {
            out.push(0);
        }
    }
    for (signature, body) in extensions {
        out.extend_from_slice(signature);
        out.extend((body.len() as u32).to_be_bytes());
        out.extend_from_slice(body);
    }
    seal(out)
}

/// The empty tree, as Git names it.
pub const EMPTY_TREE: &str = "4b825dc642cb6eb9a060e54bf8d69288fbee4904";

pub fn commit_body(tree: &str, parents: &[String], message: &[u8]) -> Vec<u8> {
    let mut body = format!("tree {tree}\n").into_bytes();
    for parent in parents {
        body.extend(format!("parent {parent}\n").bytes());
    }
    body.extend(
        b"author A <a@example.invalid> 0 +0000\ncommitter A <a@example.invalid> 0 +0000\n\n",
    );
    body.extend_from_slice(message);
    body
}

pub fn hex(id: &Oid) -> String {
    id.iter().map(|b| format!("{b:02x}")).collect()
}
