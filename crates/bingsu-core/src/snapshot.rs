//! Version 2 snapshot frames, context addresses and execution eligibility.
//! Checksums detect damage; checked runtime descriptors establish trust.
use crate::{
    config::compile::{CompiledConfig, ExecUnit},
    layout_view::FrontConfig,
    snapshot_codec::{self, Error},
};
use alloc::vec::Vec;
pub const T_NS: u64 = 60_000_000_000;
pub const HEADER: usize = 64;
pub const PREFIX: usize = 128;
pub const MARKER: usize = 208;
pub const COMPILED_MAX: usize = 16 * 1024 * 1024;
pub const META_MAX: usize = 8 * 1024 * 1024;
/// Reflected Castagnoli polynomial.
const POLY: u32 = 0x82f6_3b78;
/// Slicing-by-8 tables: `TABLES[0]` is the byte table; `TABLES[k][i]` is the
/// CRC of byte `i` followed by `k` zero bytes. Evaluated at compile time.
const TABLES: [[u32; 256]; 8] = tables();
const fn tables() -> [[u32; 256]; 8] {
    let mut t = [[0u32; 256]; 8];
    let mut i = 0;
    while i < 256 {
        let mut c = i as u32;
        let mut bit = 0;
        while bit < 8 {
            c = (c >> 1) ^ (POLY & 0u32.wrapping_sub(c & 1));
            bit += 1;
        }
        t[0][i] = c;
        i += 1;
    }
    let mut k = 1;
    while k < 8 {
        let mut i = 0;
        while i < 256 {
            let prev = t[k - 1][i];
            t[k][i] = (prev >> 8) ^ t[0][(prev & 0xff) as usize];
            i += 1;
        }
        k += 1;
    }
    t
}
/// CRC-32C (Castagnoli), reflected polynomial, init/xorout all ones.
/// Damage detection only: runtime permissions and checked fds enforce trust.
/// The wire stores the u32 in little-endian order; parts are concatenated.
pub fn crc32c(parts: &[&[u8]]) -> [u8; 4] {
    let t = &TABLES;
    let mut crc = u32::MAX;
    for part in parts {
        // Eight bytes per step; the state carries across part boundaries.
        let mut chunks = part.chunks_exact(8);
        for c in &mut chunks {
            let lo = crc ^ u32::from_le_bytes([c[0], c[1], c[2], c[3]]);
            let hi = u32::from_le_bytes([c[4], c[5], c[6], c[7]]);
            crc = t[7][usize::from(lo as u8)]
                ^ t[6][usize::from((lo >> 8) as u8)]
                ^ t[5][usize::from((lo >> 16) as u8)]
                ^ t[4][usize::from((lo >> 24) as u8)]
                ^ t[3][usize::from(hi as u8)]
                ^ t[2][usize::from((hi >> 8) as u8)]
                ^ t[1][usize::from((hi >> 16) as u8)]
                ^ t[0][usize::from((hi >> 24) as u8)];
        }
        for byte in chunks.remainder() {
            crc = (crc >> 8) ^ t[0][usize::from(crc as u8 ^ *byte)];
        }
    }
    (!crc).to_le_bytes()
}
/// Exact, reversible context addressing; a CRC must never select a store.
/// Inputs are init's canonical config AND state roots. Never use CRC as a path.
pub fn context_components(
    canonical: &[u8],
    state: &[u8],
) -> Result<Vec<alloc::string::String>, Error> {
    validate_context(canonical, state)?;
    let mut names = Vec::new();
    names
        .try_reserve_exact(4 + canonical.len().div_ceil(60) + state.len().div_ceil(60))
        .map_err(|_| Error::Limit)?;
    names.push(string(b"contexts-v2")?);
    for (label, root) in [
        (b"config".as_slice(), canonical),
        (b"state".as_slice(), state),
    ] {
        names.push(string(label)?);
        for chunk in root.chunks(60) {
            let mut name = alloc::string::String::new();
            name.try_reserve_exact(chunk.len() * 2)
                .map_err(|_| Error::Limit)?;
            for byte in chunk {
                name.push(char::from(b"0123456789abcdef"[usize::from(byte >> 4)]));
                name.push(char::from(b"0123456789abcdef"[usize::from(byte & 15)]));
            }
            names.push(name);
        }
    }
    names.push(string(b"store")?);
    Ok(names)
}
fn string(b: &[u8]) -> Result<alloc::string::String, Error> {
    let mut s = alloc::string::String::new();
    s.try_reserve_exact(b.len()).map_err(|_| Error::Limit)?;
    s.push_str(core::str::from_utf8(b).map_err(|_| Error::Utf8)?);
    Ok(s)
}
// Bound the address's heap usage, not the user's filesystem spelling to PATH_MAX.
// At most 16 MiB input becomes 32 MiB hex plus < 7 MiB Vec/String bookkeeping.
fn validate_context(canonical: &[u8], state: &[u8]) -> Result<(), Error> {
    if canonical
        .len()
        .checked_add(state.len())
        .is_none_or(|n| n > COMPILED_MAX)
    {
        return Err(Error::Limit);
    }
    validate_root(canonical)?;
    validate_root(state)
}
fn validate_root(root: &[u8]) -> Result<(), Error> {
    crate::root_arg::parse_abs_path(root).map_err(|_| Error::Tag)?;
    if root.contains(&0)
        || (root != b"/"
            && root[1..]
                .split(|b| *b == b'/')
                .any(|p| p.is_empty() || p == b"." || p == b".."))
    {
        return Err(Error::Tag);
    }
    Ok(())
}
pub fn context_crc(canonical: &[u8], state: &[u8]) -> Result<[u8; 4], Error> {
    validate_context(canonical, state)?;
    let c = u32::try_from(canonical.len())
        .map_err(|_| Error::Limit)?
        .to_le_bytes();
    let s = u32::try_from(state.len())
        .map_err(|_| Error::Limit)?
        .to_le_bytes();
    Ok(crc32c(&[b"bingsu-context-v3\0", &c, canonical, &s, state]))
}
/// Input must be the complete canonical evidence export, not just source contents.
pub fn source_crc(evidence: &[u8]) -> [u8; 4] {
    crc32c(&[b"bingsu-sources-v2\0", evidence])
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Identity {
    pub boot: [u8; 16],
    pub epoch: [u8; 16],
    pub context: [u8; 4],
    pub generation: u64,
    pub source: [u8; 4],
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Clock {
    pub kind: u8,
    pub domain: [u8; 16],
    pub resume: u64,
    pub boot: [u8; 16],
    pub now: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Marker {
    pub id: Identity,
    pub seq: u64,
    pub verified_at: u64,
    pub kind: u8,
    pub domain: [u8; 16],
    pub resume: u64,
    pub invalid: bool,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    Missing,
    Invalid,
    Pair,
    Boot,
    Clock,
    Resume,
    Future,
    Expired,
}
fn n<const N: usize>(b: &[u8], at: usize) -> Result<[u8; N], Error> {
    b.get(at..at.checked_add(N).ok_or(Error::Limit)?)
        .ok_or(Error::Short)?
        .try_into()
        .map_err(|_| Error::Short)
}
fn u64at(b: &[u8], at: usize) -> Result<u64, Error> {
    Ok(u64::from_le_bytes(n(b, at)?))
}
fn u32at(b: &[u8], at: usize) -> Result<u32, Error> {
    Ok(u32::from_le_bytes(n(b, at)?))
}
fn set(b: &mut [u8], at: usize, v: &[u8]) {
    b[at..at + v.len()].copy_from_slice(v)
}
impl Marker {
    pub fn encode(self) -> [u8; MARKER] {
        let mut b = [0; MARKER];
        set(&mut b, 0, b"BNGMRK02");
        set(&mut b, 8, &2u16.to_le_bytes());
        set(&mut b, 10, &(MARKER as u16).to_le_bytes());
        b[12] = if self.invalid { 2 } else { 1 };
        b[13] = self.kind;
        set(&mut b, 16, &self.id.generation.to_le_bytes());
        set(&mut b, 24, &self.seq.to_le_bytes());
        set(&mut b, 32, &self.verified_at.to_le_bytes());
        set(&mut b, 40, &self.resume.to_le_bytes());
        set(&mut b, 48, &self.id.boot);
        set(&mut b, 64, &self.id.epoch);
        set(&mut b, 80, &self.id.source);
        set(&mut b, 112, &self.id.context);
        set(&mut b, 144, &self.domain);
        let sum = crc32c(&[b"bingsu-marker-v2\0", &b[..176]]);
        set(&mut b, 176, &sum);
        b
    }
    pub fn decode(b: &[u8]) -> Result<Self, Error> {
        if b.len() != MARKER {
            return Err(Error::Short);
        }
        if &b[..8] != b"BNGMRK02"
            || b[8..12] != [2, 0, 208, 0]
            || ![1, 2].contains(&b[12])
            || ![1, 2].contains(&b[13])
            || b[14..16] != [0, 0]
            || b[84..112] != [0; 28]
            || b[116..144] != [0; 28]
            || b[160..176] != [0; 16]
            || b[180..208] != [0; 28]
        {
            return Err(Error::Tag);
        }
        if crc32c(&[b"bingsu-marker-v2\0", &b[..176]]) != b[176..180] {
            return Err(Error::Shape);
        }
        Ok(Self {
            id: Identity {
                generation: u64at(b, 16)?,
                boot: n(b, 48)?,
                epoch: n(b, 64)?,
                source: n(b, 80)?,
                context: n(b, 112)?,
            },
            seq: u64at(b, 24)?,
            verified_at: u64at(b, 32)?,
            resume: u64at(b, 40)?,
            kind: b[13],
            domain: n(b, 144)?,
            invalid: b[12] == 2,
        })
    }
}
/// `context` is derived from the current shell's canonical config/state roots,
/// independently of the selected file and marker. A matching foreign pair is not
/// an authorization for this shell (the exact address is checked by the reader).
pub fn eligible(
    selected: Identity,
    m: Option<Marker>,
    now: Clock,
    context: [u8; 4],
) -> Result<u64, Refusal> {
    let m = m.ok_or(Refusal::Missing)?;
    if m.invalid {
        return Err(Refusal::Invalid);
    }
    if m.id != selected || selected.context != context {
        return Err(Refusal::Pair);
    }
    if now.boot == [0; 16] || now.boot != selected.boot {
        return Err(Refusal::Boot);
    }
    if ![1, 2].contains(&now.kind) || now.kind != m.kind || now.domain != m.domain {
        return Err(Refusal::Clock);
    }
    if now.resume != m.resume {
        return Err(Refusal::Resume);
    }
    if now.now < m.verified_at {
        return Err(Refusal::Future);
    }
    let end = m.verified_at.checked_add(T_NS).ok_or(Refusal::Expired)?;
    if now.now >= end {
        return Err(Refusal::Expired);
    }
    Ok(end)
}
pub fn same_boot(id: Identity, boot: Option<[u8; 16]>, context: [u8; 4]) -> bool {
    id.boot != [0; 16] && boot == Some(id.boot) && context == id.context
}
/// The front never receives source metadata. Clock fields belong to the selected
/// compiled section, including when that section came from last-good.
#[derive(Debug, PartialEq)]
pub struct FrontSnapshot {
    pub id: Identity,
    pub clock_kind: u8,
    pub resume: u64,
    /// Only the variant selected at the envelope's width (K63).
    pub config: FrontConfig,
}
impl FrontSnapshot {
    pub fn eligible(
        &self,
        marker: Option<Marker>,
        now: Clock,
        context: [u8; 4],
    ) -> Result<u64, Refusal> {
        // Invalid and pair failures take precedence over clock failures.
        let result = eligible(self.id, marker, now, context);
        if matches!(
            result,
            Err(Refusal::Missing | Refusal::Invalid | Refusal::Pair | Refusal::Boot)
        ) {
            return result;
        }
        if self.clock_kind != now.kind {
            return Err(Refusal::Clock);
        }
        if self.resume != now.resume {
            return Err(Refusal::Resume);
        }
        result
    }
}

/// Maximum single read, independent of attacker-controlled wire lengths.
pub const READ_CHUNK: usize = 16 * 1024;

/// Sequential front decoder: header, prefix, then only the compiled section.
/// Construct only after the descriptor's owner/mode/type/link/ACL/size checks.
/// No body allocation is approved until BOTH fixed parts and file size agree.
pub struct FrontDecoder {
    bytes: Vec<u8>,
    file_len: usize,
    end: usize,
}
impl FrontDecoder {
    pub fn new(file_len: u64) -> Result<Self, Error> {
        let file_len = usize::try_from(file_len).map_err(|_| Error::Limit)?;
        if !(HEADER + PREFIX..=HEADER + PREFIX + COMPILED_MAX + META_MAX).contains(&file_len) {
            return Err(Error::Limit);
        }
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(HEADER + PREFIX)
            .map_err(|_| Error::Limit)?;
        Ok(Self {
            bytes,
            file_len,
            end: HEADER,
        })
    }
    /// Zero means complete. Short reads are accepted; EOF before zero is failure.
    pub fn read_len(&self) -> usize {
        self.end.saturating_sub(self.bytes.len()).min(READ_CHUNK)
    }
    pub fn push(&mut self, bytes: &[u8]) -> Result<(), Error> {
        if bytes.is_empty() || bytes.len() > self.read_len() {
            return Err(Error::Short);
        }
        self.bytes.extend_from_slice(bytes);
        if self.bytes.len() != self.end {
            return Ok(());
        }
        if self.end == HEADER {
            header(&self.bytes)?;
            self.end = HEADER + PREFIX;
        } else if self.end == HEADER + PREFIX {
            let (c, m) = lengths(&self.bytes)?;
            if self.file_len != HEADER + PREFIX + c + m {
                return Err(Error::Shape);
            }
            self.bytes.try_reserve_exact(c).map_err(|_| Error::Limit)?;
            self.end += c;
        }
        Ok(())
    }
    /// The envelope gives the width before any read, so the decode ends by
    /// materializing only the variant selected at `width`. Another width
    /// (a later prompt) selects again from its own read of the same bytes.
    pub fn finish_for(self, width: u16) -> Result<FrontSnapshot, Error> {
        if self.read_len() != 0 {
            return Err(Error::Short);
        }
        Snapshot::decode_front(&self.bytes, self.file_len, width)
    }
}

fn header(b: &[u8]) -> Result<(), Error> {
    if b.len() < HEADER {
        return Err(Error::Short);
    }
    if &b[..8] != b"BNGSNP02"
        || b[8..12] != [2, 0, 64, 0]
        || b[12] > 1
        || b[13..16] != [0; 3]
        || b[28..56] != [0; 28]
    {
        return Err(Error::Tag);
    }
    let c = usize::try_from(u32at(b, 60)?).map_err(|_| Error::Limit)?;
    if !(PREFIX..=PREFIX + COMPILED_MAX).contains(&c) {
        return Err(Error::Limit);
    }
    Ok(())
}
#[derive(Debug, PartialEq)]
pub struct Snapshot {
    pub id: Identity,
    pub config: CompiledConfig,
    pub metadata: Vec<u8>,
}
impl Snapshot {
    pub fn encode(&self, clock_kind: u8, resume: u64) -> Result<Vec<u8>, Error> {
        let c = snapshot_codec::encode_compiled(&self.config)?;
        if self.metadata.len() > META_MAX || ![1, 2].contains(&clock_kind) {
            return Err(Error::Limit);
        }
        decode_metadata(&self.metadata)?;
        let len = HEADER + PREFIX + c.len() + self.metadata.len();
        let mut out = Vec::new();
        out.try_reserve_exact(len).map_err(|_| Error::Limit)?;
        out.resize(HEADER + PREFIX, 0);
        set(&mut out, 0, b"BNGSNP02");
        set(&mut out, 8, &2u16.to_le_bytes());
        set(&mut out, 10, &64u16.to_le_bytes());
        out[12] = u8::from(self.config.exec_units.iter().any(|u| u.not_run.is_none()));
        set(&mut out, 16, &self.id.generation.to_le_bytes());
        set(&mut out, 24, &self.id.source);
        set(&mut out, 56, &self.config.collect_mask.to_le_bytes());
        set(&mut out, 60, &((PREFIX + c.len()) as u32).to_le_bytes());
        let p = &mut out[HEADER..];
        set(p, 0, b"BNGCMP02");
        set(p, 8, &2u16.to_le_bytes());
        set(p, 10, &128u16.to_le_bytes());
        set(p, 12, &(c.len() as u32).to_le_bytes());
        set(p, 16, &(self.metadata.len() as u32).to_le_bytes());
        p[20] = clock_kind;
        set(p, 24, &self.id.boot);
        set(p, 40, &self.id.epoch);
        set(p, 56, &self.id.context);
        set(p, 88, &resume.to_le_bytes());
        let sum = crc32c(&[b"bingsu-snapshot-v2\0", &out[..160], &c]);
        set(&mut out, 160, &sum);
        out.extend_from_slice(&c);
        out.extend_from_slice(&self.metadata);
        Ok(out)
    }
    /// Helper-only read. The front decoder deliberately never reads metadata.
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let (c, m) = lengths(bytes)?;
        let end = HEADER + PREFIX + c;
        if bytes.len() != end + m {
            return Err(Error::Shape);
        }
        let frame = Frame::check(&bytes[..end], bytes.len())?;
        let config = snapshot_codec::decode_compiled(frame.compiled)?;
        frame.matches(config.collect_mask, &config.exec_units)?;
        let mut out = Self {
            id: frame.id()?,
            config,
            metadata: Vec::new(),
        };
        decode_metadata(&bytes[end..])?;
        out.metadata
            .try_reserve_exact(m)
            .map_err(|_| Error::Limit)?;
        out.metadata.extend_from_slice(&bytes[end..]);
        Ok(out)
    }
    /// The front's read: header, prefix and compiled section (never the
    /// metadata), with only the variant selected at `width` materialized.
    /// Rejects exactly what the helper's whole decode of the section rejects.
    pub fn decode_front(bytes: &[u8], file_len: usize, width: u16) -> Result<FrontSnapshot, Error> {
        let frame = Frame::check(bytes, file_len)?;
        let layout = snapshot_codec::scan_compiled(frame.compiled)?;
        frame.matches(layout.collect_mask(), layout.exec_units())?;
        Ok(FrontSnapshot {
            id: frame.id()?,
            clock_kind: bytes[84],
            resume: u64at(bytes, 152)?,
            config: layout.select(width)?,
        })
    }
}
/// Header, prefix and CRC of a snapshot cut at the end of its compiled section.
struct Frame<'a> {
    bytes: &'a [u8],
    compiled: &'a [u8],
}
impl<'a> Frame<'a> {
    fn check(bytes: &'a [u8], file_len: usize) -> Result<Self, Error> {
        let (c_len, m_len) = lengths(bytes)?;
        if file_len != HEADER + PREFIX + c_len + m_len || bytes.len() != HEADER + PREFIX + c_len {
            return Err(Error::Shape);
        }
        let c = &bytes[HEADER + PREFIX..];
        if crc32c(&[b"bingsu-snapshot-v2\0", &bytes[..160], c]) != bytes[160..164] {
            return Err(Error::Shape);
        }
        Ok(Self { bytes, compiled: c })
    }
    /// The header's copies of the collect mask and the runnable-unit flag.
    fn matches(&self, collect_mask: u32, exec_units: &[ExecUnit]) -> Result<(), Error> {
        if collect_mask != u32at(self.bytes, 56)?
            || u8::from(exec_units.iter().any(|u| u.not_run.is_none())) != self.bytes[12]
        {
            return Err(Error::Shape);
        }
        Ok(())
    }
    fn id(&self) -> Result<Identity, Error> {
        let b = self.bytes;
        Ok(Identity {
            generation: u64at(b, 16)?,
            source: n(b, 24)?,
            boot: n(b, 88)?,
            epoch: n(b, 104)?,
            context: n(b, 120)?,
        })
    }
}
pub fn lengths(b: &[u8]) -> Result<(usize, usize), Error> {
    header(b)?;
    if b.len() < HEADER + PREFIX {
        return Err(Error::Short);
    }
    if &b[..8] != b"BNGSNP02"
        || b[8..12] != [2, 0, 64, 0]
        || b[12] > 1
        || b[13..16] != [0; 3]
        || &b[64..72] != b"BNGCMP02"
        || b[72..76] != [2, 0, 128, 0]
        || ![1, 2].contains(&b[84])
        || b[85..88] != [0; 3]
        || b[28..56] != [0; 28]
        || b[124..152] != [0; 28]
        || b[164..192] != [0; 28]
    {
        return Err(Error::Tag);
    }
    let c = usize::try_from(u32at(b, 76)?).map_err(|_| Error::Limit)?;
    let m = usize::try_from(u32at(b, 80)?).map_err(|_| Error::Limit)?;
    if c > COMPILED_MAX
        || m > META_MAX
        || usize::try_from(u32at(b, 60)?).map_err(|_| Error::Limit)? != PREFIX + c
    {
        return Err(Error::Limit);
    }
    Ok((c, m))
}

/// A sequence is reserved under snapshot.lock before any publication. An unreadable
/// sequence requires a new random epoch and full verification in the caller.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Sequence {
    pub boot: [u8; 16],
    pub epoch: [u8; 16],
    pub generation: u64,
    pub verified: u64,
}
impl Sequence {
    pub fn reserve(self, changed: bool) -> Result<Self, Error> {
        Ok(Self {
            generation: if changed {
                self.generation.checked_add(1).ok_or(Error::Limit)?
            } else {
                self.generation
            },
            verified: self.verified.checked_add(1).ok_or(Error::Limit)?,
            ..self
        })
    }
    pub fn encode(self) -> [u8; 96] {
        let mut b = [0; 96];
        set(&mut b, 0, b"BNGSEQ02");
        set(&mut b, 8, &[2, 0, 96, 0]);
        set(&mut b, 16, &self.boot);
        set(&mut b, 32, &self.epoch);
        set(&mut b, 48, &self.generation.to_le_bytes());
        set(&mut b, 56, &self.verified.to_le_bytes());
        let sum = crc32c(&[b"bingsu-sequence-v2\0", &b[..64]]);
        set(&mut b, 64, &sum);
        b
    }
    pub fn decode(b: &[u8]) -> Result<Self, Error> {
        if b.len() != 96 {
            return Err(Error::Short);
        }
        if &b[..8] != b"BNGSEQ02"
            || b[8..12] != [2, 0, 96, 0]
            || b[12..16] != [0; 4]
            || b[68..96] != [0; 28]
        {
            return Err(Error::Tag);
        }
        if crc32c(&[b"bingsu-sequence-v2\0", &b[..64]]) != b[64..68] {
            return Err(Error::Shape);
        }
        Ok(Self {
            boot: n(b, 16)?,
            epoch: n(b, 32)?,
            generation: u64at(b, 48)?,
            verified: u64at(b, 56)?,
        })
    }
}
/// Envelope only. N2 supplies canonical EvidenceExport fields in the specified
/// order from retained descriptors; an opaque payload is never proof of trust.
pub fn encode_metadata(payload: &[u8]) -> Result<Vec<u8>, Error> {
    let len = payload
        .len()
        .checked_add(20)
        .filter(|n| *n <= META_MAX)
        .ok_or(Error::Limit)?;
    let mut b = Vec::new();
    b.try_reserve_exact(len).map_err(|_| Error::Limit)?;
    b.extend_from_slice(b"BNGTRS02\x02\0\0\0");
    b.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    b.extend_from_slice(payload);
    let sum = crc32c(&[b"bingsu-trust-v2\0", &b]);
    b.extend_from_slice(&sum);
    Ok(b)
}
pub fn decode_metadata(b: &[u8]) -> Result<&[u8], Error> {
    if b.len() < 20 {
        return Err(Error::Short);
    }
    if b.len() > META_MAX {
        return Err(Error::Limit);
    }
    if &b[..8] != b"BNGTRS02" || b[8..12] != [2, 0, 0, 0] {
        return Err(Error::Tag);
    }
    let len = usize::try_from(u32at(b, 12)?).map_err(|_| Error::Limit)?;
    if len != b.len() - 20 {
        return Err(Error::Shape);
    }
    if crc32c(&[b"bingsu-trust-v2\0", &b[..b.len() - 4]]) != b[b.len() - 4..] {
        return Err(Error::Shape);
    }
    Ok(&b[16..b.len() - 4])
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClockError {
    Boot,
    Domain,
    Time,
}
/// DI boundary. Implemented by the OS adapter; core never reads a clock itself.
pub trait ClockSource {
    fn observe(&mut self) -> Result<Clock, ClockError>;
}
/// `proc_verified` covers both the current process directory and its ns directory.
/// `missing` means ENOENT for time, time_for_children and timens_offsets respectively.
pub fn namespace_domain(
    handle: Option<(u64, u64)>,
    proc_verified: bool,
    missing: [bool; 3],
) -> Result<[u8; 16], ClockError> {
    if !proc_verified {
        return Err(ClockError::Domain);
    }
    let mut out = [0; 16];
    if let Some((dev, ino)) = handle {
        if dev == 0 || ino == 0 {
            return Err(ClockError::Domain);
        }
        out[..8].copy_from_slice(&dev.to_le_bytes());
        out[8..].copy_from_slice(&ino.to_le_bytes());
    } else if missing != [true; 3] {
        return Err(ClockError::Domain);
    }
    Ok(out)
}
/// X-30 timebase conversion; intermediates must not overflow on Intel ratios.
pub fn ticks_to_ns(ticks: u64, numerator: u32, denominator: u32) -> Result<u64, ClockError> {
    if numerator == 0 || denominator == 0 {
        return Err(ClockError::Time);
    }
    let ns = u128::from(ticks)
        .checked_mul(u128::from(numerator))
        .ok_or(ClockError::Time)?
        / u128::from(denominator);
    u64::try_from(ns).map_err(|_| ClockError::Time)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    Publish,
    Invalid,
    Incomplete,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    Keep,
    Invalidate { seq: u64 },
    Refresh { generation: u64, seq: u64 },
    Replace { generation: u64, seq: u64 },
}
pub fn decide(
    outcome: Outcome,
    changed: bool,
    g: u64,
    seq: u64,
    start: u64,
    now: u64,
    work_end: u64,
) -> Action {
    if now < start || now >= work_end || start.checked_add(T_NS).is_none_or(|e| now >= e) {
        return Action::Keep;
    }
    let Some(next_seq) = seq.checked_add(1) else {
        return Action::Keep;
    };
    match outcome {
        Outcome::Invalid => Action::Invalidate { seq: next_seq },
        Outcome::Publish if changed => match g.checked_add(1) {
            Some(generation) => Action::Replace {
                generation,
                seq: next_seq,
            },
            None => Action::Keep,
        },
        Outcome::Publish => Action::Refresh {
            generation: g,
            seq: next_seq,
        },
        Outcome::Incomplete => Action::Keep,
    }
}

#[cfg(test)]
mod tests;
