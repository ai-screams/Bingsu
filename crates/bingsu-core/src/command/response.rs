//! The command response (spec section 4 "cache"; U-16 K1, U-6 S1): one file
//! per config context and cwd that holds the last result of each command
//! unit. It is the cache too: a unit whose entry still matches its policy and
//! original environment, within its cache time, does not run again. Several
//! sessions of one context and cwd share the file, so a publication merges
//! only the entries its own round ran. Types and pure decisions only.
use super::{
    Error,
    wire::{Outcome, Reason},
};
use crate::{
    collection::wire::BuildId,
    handoff::Origin,
    snapshot::{self, Clock},
};
use alloc::{string::String, vec::Vec};

const MAGIC: &[u8; 8] = b"BNGCMD01";
const VERSION: u16 = 1;
pub const HEADER: usize = 64;
/// Entries in one response (U-9d: 32 units).
pub const ENTRIES_MAX: usize = 32;
/// A value or a raw first line, in bytes (U-9c).
pub const VALUE_MAX: usize = 4_096;
/// A unit id, in bytes.
pub const ID_MAX: usize = 256;
/// The longest config, state or cwd path.
pub const PATH_MAX: usize = 65_536;
/// The whole file: the header, a binding of three longest paths, and 32
/// entries of longest id, value and raw line.
pub const RESPONSE_MAX: usize =
    HEADER + BINDING_FIXED + 3 * (4 + PATH_MAX) + 1 + ENTRIES_MAX * ENTRY_MAX;
/// How long a failed or timed-out result stands (spec: 10 s failure cache).
pub const FAILURE_NS: u64 = 10_000_000_000;

const BINDING_FIXED: usize = 32 + 16 + 16 + 4 + 1 + 16 + 8;
const ENTRY_FIXED: usize = 2 + 1 + 32 * 3 + 8 + 8 + 1 + 4 + 4;
const ENTRY_MAX: usize = ENTRY_FIXED + ID_MAX + 2 * VALUE_MAX;

/// What a response is bound to: the build, the boot and its clock domain, the
/// exact config and state roots and the raw cwd. Not the snapshot generation:
/// a unit whose policy is unchanged keeps its value across config edits.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Binding {
    pub build_id: BuildId,
    pub boot: [u8; 16],
    pub epoch: [u8; 16],
    pub context: [u8; 4],
    pub clock_kind: u8,
    pub domain: [u8; 16],
    pub resume: u64,
    pub config: Vec<u8>,
    pub state: Vec<u8>,
    pub cwd: Vec<u8>,
}

impl Binding {
    fn validate(&self) -> Result<(), Error> {
        for p in [&self.config, &self.state, &self.cwd] {
            if p.len() > PATH_MAX || p.first() != Some(&b'/') || p.contains(&0) {
                return Err(Error::Utf8);
            }
        }
        if !matches!(self.clock_kind, 1 | 2)
            || snapshot::context_crc(&self.config, &self.state).map_err(|_| Error::Flags)?
                != self.context
        {
            return Err(Error::Flags);
        }
        Ok(())
    }
}

/// How a unit's last run ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    /// Exited 0; the value is shown.
    Ok,
    /// Any other end (nonzero exit, timeout, refusal, spawn failure): no
    /// value, kept for `FAILURE_NS` so the unit does not run again at once.
    Failed,
}

/// One unit's last result.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub origin: Origin,
    pub id: String,
    /// `wire::policy_digest` of the unit that ran.
    pub policy: [u8; 32],
    /// [`super::plan::env_digest`] of the environment it ran with.
    pub environment: [u8; 32],
    /// Digest of the `match` pattern the value was cut with; zero without one.
    pub pattern: [u8; 32],
    /// When it was last tried (the round's grant), for round robin.
    pub attempted_at: u64,
    /// When its result came back.
    pub completed_at: u64,
    pub status: Status,
    /// What is shown: the raw line, cut by `match` when there is one.
    pub value: String,
    /// The sanitized first line of stdout, at most 4 KB.
    pub raw: String,
}

impl Entry {
    /// The cache: a hit when the unit's policy and original environment are
    /// the ones it ran with, and its result still stands at `now` (`cache_ns`
    /// after a success, `FAILURE_NS` after a failure). A hit runs nothing.
    pub fn hit(&self, policy: &[u8; 32], environment: &[u8; 32], now: u64, cache_ns: u64) -> bool {
        let stands = match self.status {
            Status::Ok => cache_ns,
            Status::Failed => FAILURE_NS,
        };
        self.policy == *policy
            && self.environment == *environment
            && self.completed_at <= now
            && self.completed_at.saturating_add(stands) > now
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Response {
    pub binding: Binding,
    pub entries: Vec<Entry>,
}

impl Response {
    /// The entry of `origin`/`id`, if any.
    pub fn entry(&self, origin: Origin, id: &str) -> Option<&Entry> {
        self.entries
            .iter()
            .find(|e| e.origin == origin && e.id == id)
    }

    /// Whether this response may be used at `entry` under `expected`: the
    /// same binding and the same clock (boot, kind, domain, resume).
    pub fn eligible(&self, expected: &Binding, entry: Clock) -> bool {
        self.binding == *expected
            && entry.boot == self.binding.boot
            && entry.kind == self.binding.clock_kind
            && entry.domain == self.binding.domain
            && entry.resume == self.binding.resume
    }

    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        self.binding.validate()?;
        check_entries(&self.entries, Raw::Checked)?;
        let mut out = alloc::vec![0; HEADER];
        let b = &self.binding;
        out.extend_from_slice(&b.build_id.0);
        out.extend_from_slice(&b.boot);
        out.extend_from_slice(&b.epoch);
        out.extend_from_slice(&b.context);
        out.push(b.clock_kind);
        out.extend_from_slice(&b.domain);
        out.extend_from_slice(&b.resume.to_le_bytes());
        for p in [&b.config, &b.state, &b.cwd] {
            put_bytes(&mut out, p);
        }
        out.push(self.entries.len() as u8);
        for e in &self.entries {
            out.extend_from_slice(&(e.id.len() as u16).to_le_bytes());
            out.extend_from_slice(e.id.as_bytes());
            out.push(e.origin.tag());
            out.extend_from_slice(&e.policy);
            out.extend_from_slice(&e.environment);
            out.extend_from_slice(&e.pattern);
            out.extend_from_slice(&e.attempted_at.to_le_bytes());
            out.extend_from_slice(&e.completed_at.to_le_bytes());
            out.push(match e.status {
                Status::Ok => 0,
                Status::Failed => 1,
            });
            put_bytes(&mut out, e.value.as_bytes());
            put_bytes(&mut out, e.raw.as_bytes());
        }
        // Within RESPONSE_MAX: every part was bounded above.
        out[..8].copy_from_slice(MAGIC);
        out[8..10].copy_from_slice(&VERSION.to_le_bytes());
        out[10..12].copy_from_slice(&(HEADER as u16).to_le_bytes());
        let body = (out.len() - HEADER) as u32;
        out[12..16].copy_from_slice(&body.to_le_bytes());
        let crc = snapshot::crc32c(&[&out[HEADER..]]);
        out[16..20].copy_from_slice(&crc);
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        Self::decode_with(bytes, Raw::Checked)
    }

    /// The prompt's decode: every check of [`Response::decode`] except the
    /// characters of `raw`, which the prompt never draws (its length, UTF-8
    /// and the empty raw line of a failure still are checked), and every
    /// `raw` comes back empty. The helper reads with `decode`, so a file
    /// that fails it is never merged or used for the cache.
    pub fn decode_shown(bytes: &[u8]) -> Result<Self, Error> {
        Self::decode_with(bytes, Raw::Unchecked)
    }

    fn decode_with(bytes: &[u8], raw_text: Raw) -> Result<Self, Error> {
        let total = declared_len(bytes)?;
        if bytes.len() != total {
            return Err(if bytes.len() < total {
                Error::Short
            } else {
                Error::Trailing
            });
        }
        if snapshot::crc32c(&[&bytes[HEADER..]]) != bytes[16..20] {
            return Err(Error::Checksum);
        }
        let mut r = Reader(&bytes[HEADER..]);
        let binding = Binding {
            build_id: BuildId(r.array()?),
            boot: r.array()?,
            epoch: r.array()?,
            context: r.array()?,
            clock_kind: r.u8()?,
            domain: r.array()?,
            resume: r.u64()?,
            config: r.bytes()?.to_vec(),
            state: r.bytes()?.to_vec(),
            cwd: r.bytes()?.to_vec(),
        };
        binding.validate()?;
        // At most 255; check_entries holds the real cap after the loop.
        let count = usize::from(r.u8()?);
        let mut entries = Vec::with_capacity(count);
        for _ in 0..count {
            let id_len = usize::from(r.u16()?);
            let id = text(r.take(id_len)?)?;
            let origin = Origin::from_tag(r.u8()?).map_err(|_| Error::Kind)?;
            let policy = r.array()?;
            let environment = r.array()?;
            let pattern = r.array()?;
            let attempted_at = r.u64()?;
            let completed_at = r.u64()?;
            let status = match r.u8()? {
                0 => Status::Ok,
                1 => Status::Failed,
                _ => return Err(Error::Kind),
            };
            let value = text(r.bytes()?)?;
            let raw = match raw_text {
                Raw::Checked => text(r.bytes()?)?,
                // The prompt never draws the raw line: it gets the same
                // length, UTF-8 and failure checks, then is left out, so no
                // unchecked character reaches the prompt's memory.
                Raw::Unchecked => {
                    let bytes = r.bytes()?;
                    core::str::from_utf8(bytes).map_err(|_| Error::Utf8)?;
                    if bytes.len() > VALUE_MAX {
                        return Err(Error::Limit);
                    }
                    if status == Status::Failed && !bytes.is_empty() {
                        return Err(Error::Flags);
                    }
                    String::new()
                }
            };
            entries.push(Entry {
                origin,
                id,
                policy,
                environment,
                pattern,
                attempted_at,
                completed_at,
                status,
                value,
                raw,
            });
        }
        if !r.0.is_empty() {
            return Err(Error::Trailing);
        }
        check_entries(&entries, raw_text)?;
        Ok(Self { binding, entries })
    }
}

/// The file length a header declares, checked before the body is read.
pub fn declared_len(bytes: &[u8]) -> Result<usize, Error> {
    if bytes.len() < HEADER {
        return Err(Error::Short);
    }
    if &bytes[..8] != MAGIC {
        return Err(Error::Magic);
    }
    if bytes[8..10] != VERSION.to_le_bytes() {
        return Err(Error::Version);
    }
    if bytes[10..12] != (HEADER as u16).to_le_bytes() || bytes[20..HEADER].iter().any(|&b| b != 0) {
        return Err(Error::Flags);
    }
    let body = u32::from_le_bytes(bytes[12..16].try_into().unwrap()) as usize;
    let total = HEADER.checked_add(body).ok_or(Error::Length)?;
    if total > RESPONSE_MAX {
        return Err(Error::Length);
    }
    Ok(total)
}

/// Whether `check_entries` checks the characters of `raw`.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Raw {
    Checked,
    Unchecked,
}

fn check_entries(entries: &[Entry], raw_text: Raw) -> Result<(), Error> {
    if entries.len() > ENTRIES_MAX {
        return Err(Error::Limit);
    }
    for (i, e) in entries.iter().enumerate() {
        if e.id.is_empty()
            || e.id.len() > ID_MAX
            || e.value.len() > VALUE_MAX
            || e.raw.len() > VALUE_MAX
            || e.attempted_at > e.completed_at
        {
            return Err(Error::Limit);
        }
        // The front reads values straight to the terminal (C4b): only
        // sanitized text, as `first_line` makes it. A failure has no value.
        let clean = |t: &str| t.chars().all(|c| !crate::sanitize::is_removed(c));
        if !clean(&e.value) || (raw_text == Raw::Checked && !clean(&e.raw)) {
            return Err(Error::Utf8);
        }
        if e.status == Status::Failed && !(e.value.is_empty() && e.raw.is_empty()) {
            return Err(Error::Flags);
        }
        if entries[..i]
            .iter()
            .any(|o| o.origin == e.origin && o.id == e.id)
        {
            return Err(Error::Flags);
        }
    }
    Ok(())
}

/// Lengths are checked once, by `check_entries`, after the whole decode.
fn text(bytes: &[u8]) -> Result<String, Error> {
    String::from_utf8(bytes.to_vec()).map_err(|_| Error::Utf8)
}

fn put_bytes(out: &mut Vec<u8>, b: &[u8]) {
    out.extend_from_slice(&(b.len() as u32).to_le_bytes());
    out.extend_from_slice(b);
}

struct Reader<'a>(&'a [u8]);
impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        if self.0.len() < n {
            return Err(Error::Short);
        }
        let (head, rest) = self.0.split_at(n);
        self.0 = rest;
        Ok(head)
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        Ok(self.take(N)?.try_into().unwrap())
    }
    fn u8(&mut self) -> Result<u8, Error> {
        Ok(self.array::<1>()?[0])
    }
    fn u16(&mut self) -> Result<u16, Error> {
        Ok(u16::from_le_bytes(self.array()?))
    }
    fn u64(&mut self) -> Result<u64, Error> {
        Ok(u64::from_le_bytes(self.array()?))
    }
    fn bytes(&mut self) -> Result<&'a [u8], Error> {
        let n = u32::from_le_bytes(self.array()?) as usize;
        self.take(n)
    }
}

/// The response after this round: `current` when it is bound to `binding`
/// (else nothing), with each of `mine` put in place of the entry of the same
/// unit when it completed later. Entries of other units, and their attempt
/// times, stay. Past `ENTRIES_MAX`, the entries tried longest ago that this
/// round did not write go first.
pub fn merge(current: Option<&Response>, binding: &Binding, mine: &[Entry]) -> Response {
    let mut entries: Vec<Entry> = match current {
        Some(c) if c.binding == *binding => c.entries.clone(),
        _ => Vec::new(),
    };
    for m in mine {
        match entries
            .iter_mut()
            .find(|e| e.origin == m.origin && e.id == m.id)
        {
            Some(e) if m.completed_at > e.completed_at => *e = m.clone(),
            Some(_) => {}
            None => entries.push(m.clone()),
        }
    }
    while entries.len() > ENTRIES_MAX {
        let ours = |e: &Entry| mine.iter().any(|m| m.origin == e.origin && m.id == e.id);
        let Some(oldest) = entries
            .iter()
            .enumerate()
            .filter(|(_, e)| !ours(e))
            .min_by_key(|(_, e)| e.attempted_at)
            .map(|(i, _)| i)
        else {
            entries.truncate(ENTRIES_MAX);
            break;
        };
        entries.remove(oldest);
    }
    Response {
        binding: binding.clone(),
        entries,
    }
}

/// What a unit shows: the first line of its stdout, sanitized by the
/// section 3 rules (a CR before the line end is a control character it
/// drops), at most `VALUE_MAX` bytes.
pub fn first_line(stdout: &[u8]) -> String {
    let line = stdout.split(|&b| b == b'\n').next().unwrap_or_default();
    let mut value = crate::sanitize::sanitize(line);
    let mut end = value.len().min(VALUE_MAX);
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    value.truncate(end);
    value
}

/// The entry a unit's result leaves, or `None` when it did not run (the
/// supervisor refused it: the next round tries it again). Exit 0 is a
/// value; any other end is a failure, kept for `FAILURE_NS`.
pub fn entry_for(
    id: String,
    policy: [u8; 32],
    environment: [u8; 32],
    attempted_at: u64,
    o: &Outcome,
) -> Option<Entry> {
    let ok = match o.reason {
        Reason::Exited(status) => status == 0,
        Reason::Timeout | Reason::SpawnFailed => false,
        Reason::Refused(_) => return None,
    };
    let raw = if ok {
        first_line(&o.stdout)
    } else {
        String::new()
    };
    // The value the prompt draws: the part of the first line it reads to
    // cut it to a user segment's cells (m6-P1), so the response it decodes
    // carries at most 272 bytes a unit instead of 4 KB. The raw line stays
    // whole for `match`.
    let value = crate::field::Clean::read_prefix(&raw, crate::field::CUSTOM_TEXT_CELLS).into();
    Some(Entry {
        origin: o.origin,
        id,
        policy,
        environment,
        pattern: [0; 32],
        attempted_at: attempted_at.min(o.ended_at),
        completed_at: o.ended_at,
        status: if ok { Status::Ok } else { Status::Failed },
        value,
        raw,
    })
}

#[cfg(test)]
mod tests;
