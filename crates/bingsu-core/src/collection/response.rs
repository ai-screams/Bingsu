//! Complete immutable records, including logically partial collection results.
use super::wire::{
    self, Binding, BuildId, EndReason, ProtocolError, Reader, RequestId, STREAM_MAX, Schema, Update,
};
use crate::{
    field::{self, SegmentDecl},
    snapshot::{self, Clock},
};
use alloc::vec::Vec;

pub const HEADER: usize = 64;
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Completed {
    pub request_id: RequestId,
    pub binding: Binding,
    pub completed_at_ns: u64,
    pub reason: EndReason,
    pub updates: Vec<Update>,
}
/// File header plus request id, binding, completion clock, reason and count.
pub(crate) fn base_len(binding: &Binding) -> Result<usize, ProtocolError> {
    wire::add_budget(HEADER + 32 + 8 + 1 + 2, binding.encoded_len()?, STREAM_MAX)
}
impl Completed {
    pub fn encode(&self) -> Result<Vec<u8>, ProtocolError> {
        self.encode_with_catalog(field::BUILTIN)
    }
    pub fn encode_with_catalog(&self, catalog: &[SegmentDecl]) -> Result<Vec<u8>, ProtocolError> {
        let schema = Schema::new(catalog)?;
        if self.updates.len() > wire::SEGMENTS_MAX {
            return Err(ProtocolError::Budget);
        }
        let mut len = base_len(&self.binding)?;
        let mut seen = 0u32;
        for update in &self.updates {
            let n = wire::update_len(update, &schema, self.binding.mask)?;
            let bit = 1u32 << update.segment;
            if seen & bit != 0 {
                return Err(ProtocolError::Duplicate);
            }
            seen |= bit;
            len = wire::add_budget(len, n, STREAM_MAX)?;
        }
        let mut out = Vec::with_capacity(len);
        out.resize(HEADER, 0);
        out.extend_from_slice(&self.request_id.0);
        out.extend_from_slice(&self.binding.build_id.0);
        self.binding.put_identity(&mut out);
        self.binding.put_paths(&mut out);
        out.extend_from_slice(&self.completed_at_ns.to_le_bytes());
        out.push(self.reason.tag());
        out.extend_from_slice(&(self.updates.len() as u16).to_le_bytes());
        for update in &self.updates {
            wire::put_update(&mut out, update);
        }
        let mut out = wire::checked_encoding(out, len)?;
        out[..8].copy_from_slice(b"BNGRES02");
        out[8..10].copy_from_slice(&2u16.to_le_bytes());
        out[10..12].copy_from_slice(&(HEADER as u16).to_le_bytes());
        out[12..16].copy_from_slice(&((len - HEADER) as u32).to_le_bytes());
        let crc = snapshot::crc32c(&[&out[HEADER..]]);
        out[16..20].copy_from_slice(&crc);
        Ok(out)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, ProtocolError> {
        Self::decode_with_catalog(bytes, field::BUILTIN)
    }
    pub fn decode_with_catalog(
        bytes: &[u8],
        catalog: &[SegmentDecl],
    ) -> Result<Self, ProtocolError> {
        let total = declared_len(bytes)?;
        if bytes.len() < total {
            return Err(ProtocolError::Truncated);
        }
        if bytes.len() != total {
            return Err(ProtocolError::Schema);
        }
        if snapshot::crc32c(&[&bytes[HEADER..]]) != bytes[16..20] {
            return Err(ProtocolError::Checksum);
        }
        let schema = Schema::new(catalog)?;
        let mut r = Reader::new(&bytes[HEADER..]);
        let request_id = RequestId(r.array()?);
        let mut binding = Binding::read_identity(BuildId(r.array()?), &mut r)?;
        binding.read_paths(&mut r)?;
        let completed_at_ns = r.u64()?;
        let reason = EndReason::from_tag(r.u8()?)?;
        let count = usize::from(r.u16()?);
        if count > wire::SEGMENTS_MAX {
            return Err(ProtocolError::Budget);
        }
        let mut updates = Vec::with_capacity(count);
        let mut seen = 0u32;
        let mut len = base_len(&binding)?;
        for _ in 0..count {
            // Stored text is already sanitized. Invalid raw UTF-8 can expand
            // beyond the wire's 4096-byte input cap; preserve that bounded result.
            let update = wire::read_update(
                &mut r,
                &schema,
                binding.mask,
                usize::from(field::VALUE_MAX_CELLS) * 4,
            )?;
            let bit = 1u32 << update.segment;
            if seen & bit != 0 {
                return Err(ProtocolError::Duplicate);
            }
            seen |= bit;
            len = wire::add_budget(
                len,
                wire::update_len(&update, &schema, binding.mask)?,
                STREAM_MAX,
            )?;
            updates.push(update);
        }
        r.end()?;
        Ok(Self {
            request_id,
            binding,
            completed_at_ns,
            reason,
            updates,
        })
    }
    pub fn eligible(&self, expected: &Binding, entry: Clock) -> bool {
        self.binding.validate().is_ok()
            && self.binding.matches(expected)
            && entry.boot == self.binding.snapshot.boot
            && entry.kind == self.binding.clock_kind
            && entry.domain == self.binding.domain
            && entry.resume == self.binding.resume
            && self
                .completed_at_ns
                .checked_add(1)
                .is_some_and(|after| after <= entry.now)
    }
}
/// Inspect just the header before allocating or reading the bounded body.
pub fn declared_len(bytes: &[u8]) -> Result<usize, ProtocolError> {
    if bytes.len() < HEADER {
        return Err(ProtocolError::Truncated);
    }
    let body = u32::from_le_bytes(bytes[12..16].try_into().unwrap()) as usize;
    let total = wire::add_budget(HEADER, body, STREAM_MAX)?;
    if bytes.len() > STREAM_MAX {
        return Err(ProtocolError::Budget);
    }
    if &bytes[..8] != b"BNGRES02" {
        return Err(ProtocolError::Magic);
    }
    if bytes[8..10] != 2u16.to_le_bytes() {
        return Err(ProtocolError::Version);
    }
    if bytes[10..12] != (HEADER as u16).to_le_bytes() || bytes[20..HEADER].iter().any(|b| *b != 0) {
        return Err(ProtocolError::Schema);
    }
    Ok(total)
}
