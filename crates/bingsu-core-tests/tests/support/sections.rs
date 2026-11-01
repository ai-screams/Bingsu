//! Hand-built compiled sections and whole files with their checksums resealed:
//! what anyone able to write the file can produce (CRCs detect damage only).
#![allow(dead_code, reason = "each test binary uses part of this file")]
use bingsu_core::{
    snapshot::{HEADER, PREFIX, crc32c},
    snapshot_codec::{HEAD, section_sum},
};

pub const P: usize = HEADER + PREFIX;
const ENTRY: usize = 16;

pub fn le32(b: &[u8], at: usize) -> usize {
    u32::from_le_bytes(b[at..at + 4].try_into().unwrap()) as usize
}
pub fn put32(b: &mut [u8], at: usize, v: usize) {
    b[at..at + 4].copy_from_slice(&(v as u32).to_le_bytes());
}

/// Where the sections of an encoded compiled section are.
pub struct Sections {
    pub common: usize,
    pub index: usize,
    pub count: usize,
    /// End of INDEX, where the first variant starts.
    pub front: usize,
    pub names: usize,
}
impl Sections {
    pub fn of(c: &[u8]) -> Self {
        let common = le32(c, 12);
        let count = le32(c, 16);
        let index = HEAD + common;
        let last = index + (count - 1) * ENTRY;
        Self {
            common,
            index,
            count,
            front: index + count * ENTRY,
            names: le32(c, last) + le32(c, last + 4),
        }
    }
    pub fn variant<'a>(&self, c: &'a [u8], i: usize) -> &'a [u8] {
        let e = self.index + i * ENTRY;
        &c[le32(c, e)..le32(c, e) + le32(c, e + 4)]
    }
}

/// The name block of `names`.
pub fn names_block(names: &[&str]) -> Vec<u8> {
    let mut b = (names.len() as u32).to_le_bytes().to_vec();
    for n in names {
        b.extend((n.len() as u32).to_le_bytes());
        b.extend(n.as_bytes());
    }
    b
}

/// A compiled section from `head`'s first 12 bytes and COMMON (its name
/// length and CRC replaced to match `names`), variants and names, with an
/// index that tiles them.
pub fn assemble(head: &[u8], common: &[u8], variants: &[Vec<u8>], names: &[u8]) -> Vec<u8> {
    let mut c = head[..12].to_vec();
    c.extend((common.len() as u32).to_le_bytes());
    c.extend((variants.len() as u32).to_le_bytes());
    c.extend(common);
    let end = c.len();
    put32(&mut c, end - 8, names.len());
    c[end - 4..end].copy_from_slice(&section_sum(names));
    let mut offset = end + variants.len() * ENTRY;
    for v in variants {
        c.extend((offset as u32).to_le_bytes());
        c.extend((v.len() as u32).to_le_bytes());
        c.extend(section_sum(v));
        c.extend([0; 4]);
        offset += v.len();
    }
    for v in variants {
        c.extend(v);
    }
    c.extend(names);
    c
}

/// Recompute the frame checksum over the front part the compiled section names.
/// A front part that runs past the file falls back to `fallback` bytes.
pub fn resign(b: &mut [u8], fallback: usize) {
    let front = le32(b, P + 16)
        .checked_mul(ENTRY)
        .and_then(|index| index.checked_add(le32(b, P + 12)))
        .and_then(|n| n.checked_add(HEAD))
        .filter(|n| n.checked_add(P).is_some_and(|end| end <= b.len()))
        .unwrap_or(fallback);
    let sum = crc32c(&[b"bingsu-snapshot-v3\0", &b[..160], &b[P..P + front]]);
    b[160..164].copy_from_slice(&sum);
}

/// `wire` with its compiled section replaced, lengths and checksum resealed.
pub fn reframe(wire: &[u8], compiled: &[u8]) -> Vec<u8> {
    let c = le32(wire, 76);
    let mut out = wire[..P].to_vec();
    out.extend_from_slice(compiled);
    out.extend_from_slice(&wire[P + c..]);
    put32(&mut out, 76, compiled.len());
    put32(&mut out, 60, PREFIX + compiled.len());
    resign(&mut out, compiled.len());
    out
}
