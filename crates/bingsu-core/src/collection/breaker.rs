//! Pure session-local stage A backoff. Only codec-verified progress may be observed.
use super::{
    cwd_hash::sha256,
    wire::{EndReason, Progress},
};
use crate::snapshot::{Clock, crc32c};
use alloc::vec::Vec;

pub const MAX_BYTES: usize = 262_144;
pub const MAX_KEYS: usize = 64;
pub const BLOCK_NS: u64 = 300_000_000_000;
/// A crashed helper cannot own a probe beyond the existing two-second lifetime.
pub const LEASE_NS: u64 = 2_000_000_000;
const HEADER: usize = 72;
const ENTRY: usize = 79;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Key {
    Cwd(Vec<u8>),
    Device(u64),
}
impl Key {
    /// Lexical normalization only; never resolves a link or invents a device.
    /// `..` is rejected because collapsing it across symlinks is not sound.
    pub fn cwd(pwd: &[u8]) -> Result<Self, Error> {
        if pwd.first() != Some(&b'/') || pwd.len() > 65_536 || pwd.contains(&0) {
            return Err(Error::Invalid);
        }
        let mut out = Vec::new();
        for part in pwd.split(|b| *b == b'/') {
            if part == b".." {
                return Err(Error::Invalid);
            }
            if part.is_empty() || part == b"." {
                continue;
            }
            out.push(b'/');
            out.extend_from_slice(part);
        }
        if out.is_empty() {
            out.push(b'/');
        }
        Ok(Self::Cwd(out))
    }
    fn bytes(&self) -> Vec<u8> {
        match self {
            Self::Cwd(cwd) => cwd.clone(),
            Self::Device(dev) => dev.to_le_bytes().to_vec(),
        }
    }
    fn digest(&self) -> [u8; 32] {
        sha256(&self.bytes())
    }
    fn valid(&self) -> bool {
        match self {
            Self::Cwd(cwd) => Self::cwd(cwd).as_ref() == Ok(self),
            Self::Device(_) => true,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Admission {
    Allowed,
    Probe,
    Blocked,
    Disabled,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Invalid,
    Domain,
    Sequence,
    Capacity,
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct Entry {
    key: Key,
    digest: [u8; 32],
    device: Option<u64>,
    failures: u8,
    blocked_until: u64,
    lease_until: u64,
    sequence: u64,
    used: u64,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Breaker {
    clock: Clock,
    sequence: Option<u64>,
    entries: Vec<Entry>,
}
impl Breaker {
    pub fn new(now: Clock) -> Self {
        Self {
            clock: now,
            sequence: None,
            entries: Vec::new(),
        }
    }
    pub fn used(&self) -> Clock {
        self.clock
    }
    pub fn live(&self, now: Clock) -> bool {
        self.clock.boot == now.boot
            && self.entries.iter().any(|e| {
                e.lease_until != 0 && (self.domain(now).is_err() || e.lease_until > now.now)
            })
    }
    fn domain(&self, now: Clock) -> Result<(), Error> {
        if !matches!(now.kind, 1 | 2)
            || now.boot != self.clock.boot
            || now.kind != self.clock.kind
            || now.domain != self.clock.domain
            || now.resume != self.clock.resume
            || now.now < self.clock.now
        {
            Err(Error::Domain)
        } else {
            Ok(())
        }
    }
    fn index(&self, key: &Key) -> Option<usize> {
        let digest = key.digest();
        self.entries
            .iter()
            .position(|e| e.digest == digest && e.key == *key)
    }
    fn effective(&self, key: &Key) -> Key {
        match self.index(key).and_then(|i| self.entries[i].device) {
            Some(device) if self.index(&Key::Device(device)).is_some() => Key::Device(device),
            _ => key.clone(),
        }
    }
    pub fn admit(&self, key: &Key, now: Clock) -> Admission {
        if !key.valid() || self.domain(now).is_err() {
            return Admission::Disabled;
        }
        let Some(i) = self.index(&self.effective(key)) else {
            return Admission::Allowed;
        };
        let e = &self.entries[i];
        if e.failures < 3 {
            Admission::Allowed
        } else if now.now < e.lease_until || now.now < e.blocked_until {
            Admission::Blocked
        } else {
            Admission::Probe
        }
    }
    /// A rejected sequence cannot reserve a lease, so it must not bypass an
    /// existing collector or start an untracked half-open probe.
    pub fn admit_after_sequence_rejection(&self, key: &Key, now: Clock) -> Admission {
        match self.admit(key, now) {
            Admission::Allowed
                if self
                    .index(&self.effective(key))
                    .is_some_and(|i| now.now < self.entries[i].lease_until) =>
            {
                Admission::Blocked
            }
            Admission::Probe => Admission::Blocked,
            admission => admission,
        }
    }
    fn insert(&mut self, key: Key, now: Clock, protected: &[Key]) -> Result<usize, Error> {
        if let Some(i) = self.index(&key) {
            return Ok(i);
        }
        let size = ENTRY + key.bytes().len();
        while self.entries.len() >= MAX_KEYS || self.len().saturating_add(size) > MAX_BYTES {
            let i = self
                .entries
                .iter()
                .enumerate()
                .filter(|(_, e)| e.lease_until <= now.now && !protected.contains(&e.key))
                .min_by_key(|(_, e)| (e.used, e.sequence))
                .map(|(i, _)| i)
                .ok_or(Error::Capacity)?;
            self.entries.remove(i);
        }
        self.entries.push(Entry {
            digest: key.digest(),
            key,
            device: None,
            failures: 0,
            blocked_until: 0,
            lease_until: 0,
            sequence: 0,
            used: now.now,
        });
        Ok(self.entries.len() - 1)
    }
    /// Must be saved under the session lock BEFORE a probe can be spawned.
    pub fn reserve(&mut self, key: &Key, sequence: u64, now: Clock) -> Result<Admission, Error> {
        self.domain(now)?;
        if !key.valid() {
            return Err(Error::Invalid);
        }
        if self.sequence.is_some_and(|last| sequence <= last) {
            return Err(Error::Sequence);
        }
        let admission = self.admit(key, now);
        if admission == Admission::Blocked {
            return Ok(admission);
        }
        let mut next = self.clone();
        let effective = next.effective(key);
        for k in [key.clone(), effective.clone()] {
            let i = next.insert(k, now, &[key.clone(), effective.clone()])?;
            next.entries[i].sequence = sequence;
            next.entries[i].used = now.now;
            next.entries[i].lease_until = now.now.checked_add(LEASE_NS).ok_or(Error::Invalid)?;
            // Pessimistic half-open: losing the result must not turn the
            // two-second helper lease into a two-second retry interval.
            if admission == Admission::Probe && next.entries[i].failures == 3 {
                next.entries[i].blocked_until =
                    now.now.checked_add(BLOCK_NS).ok_or(Error::Invalid)?;
            }
        }
        next.sequence = Some(sequence);
        next.clock = now;
        *self = next;
        Ok(admission)
    }
    /// Hidden/initial Progress do not prove A. Non-deadline failures are neutral;
    /// verified A (even followed by Deadline) and Complete break the streak.
    pub fn observe(
        &mut self,
        key: Key,
        sequence: u64,
        progress: Progress,
        reason: EndReason,
        now: Clock,
    ) -> Result<(), Error> {
        self.domain(now)?;
        if !key.valid() {
            return Err(Error::Invalid);
        }
        let reserved = self.index(&key).is_some_and(|i| {
            let e = &self.entries[i];
            e.sequence == sequence && e.lease_until != 0
        });
        if self
            .sequence
            .is_some_and(|last| sequence < last || (sequence == last && !reserved))
        {
            return Err(Error::Sequence);
        }
        let mut next = self.clone();
        let old = next.effective(&key);
        let effective = match progress.device {
            Some(device) => Key::Device(device),
            None => old.clone(),
        };
        let protected = [key.clone(), effective.clone()];
        next.insert(key.clone(), now, &protected)?;
        let target_was_missing = next.index(&effective).is_none();
        let prior = next.index(&old).map(|i| next.entries[i].clone());
        let target = next.insert(effective.clone(), now, &protected)?;
        // Only the first observed device can inherit failures collected before
        // device discovery. A changed, previously observed device is independent.
        if let (true, Some(prior)) = (target_was_missing && old == key, prior) {
            next.entries[target].failures = prior.failures;
            next.entries[target].blocked_until = prior.blocked_until;
        }
        let e = &mut next.entries[target];
        if progress.stage_a_complete || reason == EndReason::Complete {
            e.failures = 0;
            e.blocked_until = 0;
        } else if reason == EndReason::Deadline {
            e.failures = e.failures.saturating_add(1).min(3);
            if e.failures == 3 {
                e.blocked_until = now.now.checked_add(BLOCK_NS).ok_or(Error::Invalid)?;
            }
        }
        for k in &protected {
            let i = next.index(k).ok_or(Error::Invalid)?;
            next.entries[i].lease_until = 0;
            next.entries[i].sequence = sequence;
            next.entries[i].used = now.now;
        }
        if let (Some(device), Key::Cwd(_)) = (progress.device, &key) {
            let i = next.index(&key).ok_or(Error::Invalid)?;
            next.entries[i].device = Some(device);
        }
        next.clock = now;
        next.sequence = Some(sequence);
        *self = next;
        Ok(())
    }
    fn len(&self) -> usize {
        HEADER
            + self
                .entries
                .iter()
                .map(|e| ENTRY + e.key.bytes().len())
                .sum::<usize>()
    }
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        if self.len() > MAX_BYTES || self.entries.len() > MAX_KEYS {
            return Err(Error::Capacity);
        }
        let mut out = b"BNGBRK01\0\0\0\0".to_vec();
        out.extend_from_slice(&self.clock.boot);
        out.push(self.clock.kind);
        out.extend_from_slice(&self.clock.domain);
        for n in [
            self.clock.resume,
            self.clock.now,
            self.sequence.unwrap_or(0),
        ] {
            out.extend_from_slice(&n.to_le_bytes());
        }
        out.push(u8::from(self.sequence.is_some()));
        out.extend_from_slice(&(self.entries.len() as u16).to_le_bytes());
        for e in &self.entries {
            out.push(u8::from(matches!(e.key, Key::Device(_))));
            let bytes = e.key.bytes();
            out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
            out.extend_from_slice(&bytes);
            out.extend_from_slice(&e.digest);
            out.push(u8::from(e.device.is_some()));
            out.extend_from_slice(&e.device.unwrap_or(0).to_le_bytes());
            out.push(e.failures);
            for n in [e.blocked_until, e.lease_until, e.sequence, e.used] {
                out.extend_from_slice(&n.to_le_bytes());
            }
        }
        debug_assert_eq!(out.len(), self.len());
        let crc = crc32c(&[&out[12..]]);
        out[8..12].copy_from_slice(&crc);
        Ok(out)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() < HEADER
            || bytes.len() > MAX_BYTES
            || &bytes[..8] != b"BNGBRK01"
            || crc32c(&[&bytes[12..]]) != bytes[8..12]
        {
            return Err(Error::Invalid);
        }
        let mut r = Reader(&bytes[12..]);
        let boot = r.take(16)?.try_into().unwrap();
        let kind = r.take(1)?[0];
        let domain = r.take(16)?.try_into().unwrap();
        let clock = Clock {
            boot,
            kind,
            domain,
            resume: r.u64()?,
            now: r.u64()?,
        };
        let sequence = r.u64()?;
        let present = r.flag()?;
        if !present && sequence != 0 || !matches!(kind, 1 | 2) {
            return Err(Error::Invalid);
        }
        let count = u16::from_le_bytes(r.take(2)?.try_into().unwrap()) as usize;
        if count > MAX_KEYS {
            return Err(Error::Capacity);
        }
        let mut out = Self {
            clock,
            sequence: present.then_some(sequence),
            entries: Vec::new(),
        };
        for _ in 0..count {
            let device_key = r.flag()?;
            let len = u32::from_le_bytes(r.take(4)?.try_into().unwrap()) as usize;
            if len > 65_536 {
                return Err(Error::Invalid);
            }
            let raw = r.take(len)?;
            let key = if device_key {
                Key::Device(u64::from_le_bytes(
                    raw.try_into().map_err(|_| Error::Invalid)?,
                ))
            } else {
                Key::Cwd(raw.to_vec())
            };
            let digest = r.take(32)?.try_into().unwrap();
            let alias = r.flag()?;
            let device = r.u64()?;
            let failures = r.take(1)?[0];
            let entry = Entry {
                key,
                digest,
                device: alias.then_some(device),
                failures,
                blocked_until: r.u64()?,
                lease_until: r.u64()?,
                sequence: r.u64()?,
                used: r.u64()?,
            };
            if !entry.key.valid()
                || entry.digest != entry.key.digest()
                || out.index(&entry.key).is_some()
                || (!alias && device != 0)
                || (alias && device_key)
                || failures > 3
                || (failures < 3 && entry.blocked_until != 0)
                || entry.used > clock.now
                || !present
                || entry.sequence > sequence
                || entry.lease_until > clock.now.saturating_add(LEASE_NS)
                || entry.blocked_until > clock.now.saturating_add(BLOCK_NS)
            {
                return Err(Error::Invalid);
            }
            out.entries.push(entry);
        }
        if !r.0.is_empty() {
            return Err(Error::Invalid);
        }
        Ok(out)
    }
}
struct Reader<'a>(&'a [u8]);
impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        let head = self.0.get(..n).ok_or(Error::Invalid)?;
        self.0 = &self.0[n..];
        Ok(head)
    }
    fn u64(&mut self) -> Result<u64, Error> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }
    fn flag(&mut self) -> Result<bool, Error> {
        match self.take(1)?[0] {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(Error::Invalid),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::{format, vec};
    fn clock(n: u64) -> Clock {
        Clock {
            boot: [1; 16],
            kind: 1,
            domain: [2; 16],
            resume: 0,
            now: n,
        }
    }
    fn cwd() -> Key {
        Key::cwd(b"/repo").unwrap()
    }
    fn fail(b: &mut Breaker, seq: u64) {
        b.observe(
            cwd(),
            seq,
            Progress::default(),
            EndReason::Deadline,
            clock(seq),
        )
        .unwrap();
    }
    #[test]
    fn three_missing_a_deadlines_block_for_five_minutes() {
        let mut b = Breaker::new(clock(0));
        for seq in 1..=3 {
            fail(&mut b, seq);
            assert_eq!(
                b.admit(&cwd(), clock(seq)),
                if seq == 3 {
                    Admission::Blocked
                } else {
                    Admission::Allowed
                }
            );
        }
        assert_eq!(
            b.admit(&cwd(), clock(3 + 300_000_000_000 - 1)),
            Admission::Blocked
        );
        assert_eq!(
            b.admit(&cwd(), clock(3 + 300_000_000_000)),
            Admission::Probe
        );
        let now = clock(3 + 300_000_000_000);
        assert_eq!(b.reserve(&cwd(), 4, now), Ok(Admission::Probe));
        b.observe(cwd(), 4, Progress::default(), EndReason::Deadline, now)
            .unwrap();
        assert_eq!(
            b.admit(&cwd(), clock(now.now + 300_000_000_000 - 1)),
            Admission::Blocked
        );
    }
    #[test]
    fn healthy_device_lease_allows_another_cwd_and_is_overwritten() {
        // Mutation: checking leases before failures starves /b while /a runs.
        let a = Key::cwd(b"/a").unwrap();
        let other = Key::cwd(b"/b").unwrap();
        for failures in 0..3 {
            let mut b = Breaker::new(clock(0));
            for (seq, key) in [(1, a.clone()), (2, other.clone())] {
                b.observe(
                    key,
                    seq,
                    Progress {
                        stage_a_complete: true,
                        device: Some(42),
                    },
                    EndReason::Complete,
                    clock(seq),
                )
                .unwrap();
            }
            for seq in 3..3 + failures {
                b.observe(
                    a.clone(),
                    seq,
                    Progress::default(),
                    EndReason::Deadline,
                    clock(seq),
                )
                .unwrap();
            }
            assert_eq!(b.reserve(&a, 100, clock(100)), Ok(Admission::Allowed));
            assert_eq!(b.admit(&other, clock(101)), Admission::Allowed);
            assert_eq!(b.reserve(&other, 101, clock(101)), Ok(Admission::Allowed));
            // Mutation: skipping lease replacement loses the latest reservation.
            for key in [&other, &Key::Device(42)] {
                let entry = &b.entries[b.index(key).unwrap()];
                assert_eq!(entry.sequence, 101);
                assert_eq!(entry.lease_until, 101 + LEASE_NS);
            }
        }
    }
    #[test]
    fn sequence_rejection_with_live_device_lease_is_blocked() {
        // Mutation: using normal admission for Sequence bypasses the device lease.
        let a = Key::cwd(b"/a").unwrap();
        let other = Key::cwd(b"/b").unwrap();
        let mut b = Breaker::new(clock(0));
        for (seq, key) in [(1, a.clone()), (2, other.clone())] {
            b.observe(
                key,
                seq,
                Progress {
                    stage_a_complete: true,
                    device: Some(42),
                },
                EndReason::Complete,
                clock(seq),
            )
            .unwrap();
        }
        assert_eq!(b.reserve(&a, 100, clock(100)), Ok(Admission::Allowed));
        let saved = b.clone();
        assert_eq!(b.reserve(&other, 1, clock(101)), Err(Error::Sequence));
        assert_eq!(b.admit(&other, clock(101)), Admission::Allowed);
        assert_eq!(
            b.admit_after_sequence_rejection(&other, clock(101)),
            Admission::Blocked
        );
        assert_eq!(
            b.admit_after_sequence_rejection(&other, clock(100 + LEASE_NS)),
            Admission::Allowed
        );
        assert_eq!(b, saved);
    }
    #[test]
    fn blocked_key_with_live_probe_lease_is_blocked() {
        // Mutation: ignoring a blocked key's lease permits a second probe.
        let mut b = Breaker::new(clock(0));
        for seq in 1..=3 {
            fail(&mut b, seq);
        }
        let now = clock(BLOCK_NS + 3);
        assert_eq!(b.reserve(&cwd(), 4, now), Ok(Admission::Probe));
        // Isolate the lease guard from the independent pessimistic cooldown.
        let i = b.index(&cwd()).unwrap();
        b.entries[i].blocked_until = now.now;
        let mut b = Breaker::decode(&b.encode().unwrap()).unwrap();
        assert_eq!(b.reserve(&cwd(), 5, now), Ok(Admission::Blocked));
        assert_eq!(
            b.admit(&cwd(), clock(now.now + LEASE_NS - 1)),
            Admission::Blocked
        );
        assert_eq!(b.admit(&cwd(), clock(now.now + LEASE_NS)), Admission::Probe);
    }
    #[test]
    fn half_open_probe_is_single_and_ordered() {
        let mut b = Breaker::new(clock(0));
        for seq in 1..=3 {
            fail(&mut b, seq);
        }
        let now = clock(BLOCK_NS + 3);
        // Mutation: a rejected sequence must not run an untracked probe.
        assert_eq!(b.admit(&cwd(), now), Admission::Probe);
        assert_eq!(
            b.admit_after_sequence_rejection(&cwd(), now),
            Admission::Blocked
        );
        assert_eq!(b.reserve(&cwd(), 4, now), Ok(Admission::Probe));
        let mut b = Breaker::decode(&b.encode().unwrap()).unwrap();
        assert_eq!(b.reserve(&cwd(), 5, now), Ok(Admission::Blocked));
        assert_eq!(b.reserve(&cwd(), 4, now), Err(Error::Sequence));
        assert_eq!(
            b.admit(&cwd(), clock(now.now + LEASE_NS - 1)),
            Admission::Blocked
        );
        // Mutation: omitting the block renewal permits another probe at +2s.
        assert_eq!(
            b.admit(&cwd(), clock(now.now + LEASE_NS)),
            Admission::Blocked
        );
        assert_eq!(
            b.admit(&cwd(), clock(now.now + BLOCK_NS - 1)),
            Admission::Blocked
        );
        assert_eq!(b.admit(&cwd(), clock(now.now + BLOCK_NS)), Admission::Probe);
        b.observe(
            cwd(),
            4,
            Progress {
                stage_a_complete: true,
                device: None,
            },
            EndReason::Deadline,
            now,
        )
        .unwrap();
        assert_eq!(b.admit(&cwd(), now), Admission::Allowed);
        let saved = b.clone();
        assert_eq!(
            b.observe(cwd(), 4, Progress::default(), EndReason::Deadline, now),
            Err(Error::Sequence)
        );
        assert_eq!(b, saved);
    }
    #[test]
    fn partial_b_d_never_trip_breaker() {
        for reason in [
            EndReason::Complete,
            EndReason::Deadline,
            EndReason::WorkerExit,
            EndReason::Protocol,
            EndReason::Resource,
        ] {
            let mut b = Breaker::new(clock(0));
            fail(&mut b, 1);
            fail(&mut b, 2);
            b.observe(
                cwd(),
                3,
                Progress {
                    stage_a_complete: true,
                    device: Some(10),
                },
                reason,
                clock(3),
            )
            .unwrap();
            b.observe(
                cwd(),
                4,
                Progress {
                    stage_a_complete: false,
                    device: Some(10),
                },
                EndReason::Deadline,
                clock(4),
            )
            .unwrap();
            assert_eq!(b.admit(&cwd(), clock(4)), Admission::Allowed);
            assert_eq!(b.entries[b.index(&Key::Device(10)).unwrap()].failures, 1);
        }
        let mut b = Breaker::new(clock(0));
        fail(&mut b, 1);
        fail(&mut b, 2);
        b.observe(cwd(), 3, Progress::default(), EndReason::Complete, clock(3))
            .unwrap();
        fail(&mut b, 4);
        assert_eq!(b.entries[0].failures, 1);
        for reason in [
            EndReason::Protocol,
            EndReason::Resource,
            EndReason::WorkerExit,
        ] {
            b.observe(cwd(), 5, Progress::default(), reason, clock(5))
                .unwrap();
            assert_eq!(b.entries[0].failures, 1);
            b = Breaker::decode(&b.encode().unwrap()).unwrap();
            b.sequence = Some(4);
        }
    }
    #[test]
    fn devices_alias_only_after_observation_and_do_not_share_failures() {
        let a = Key::cwd(b"/a").unwrap();
        let bkey = Key::cwd(b"/b").unwrap();
        let other = Key::cwd(b"/other").unwrap();
        let mut b = Breaker::new(clock(0));
        for (seq, key, dev) in [
            (1, a.clone(), 10),
            (2, bkey.clone(), 10),
            (3, other.clone(), 20),
            (4, a.clone(), 10),
        ] {
            b.observe(
                key,
                seq,
                Progress {
                    stage_a_complete: false,
                    device: Some(dev),
                },
                EndReason::Deadline,
                clock(seq),
            )
            .unwrap();
        }
        assert_eq!(b.admit(&a, clock(4)), Admission::Blocked);
        assert_eq!(b.admit(&bkey, clock(4)), Admission::Blocked);
        assert_eq!(b.admit(&other, clock(4)), Admission::Allowed);
        assert_eq!(
            b.admit(&Key::cwd(b"/unobserved").unwrap(), clock(4)),
            Admission::Allowed
        );
        b.observe(
            a.clone(),
            5,
            Progress {
                stage_a_complete: false,
                device: Some(30),
            },
            EndReason::Deadline,
            clock(5),
        )
        .unwrap();
        assert_eq!(b.admit(&a, clock(5)), Admission::Allowed);
        assert_eq!(b.entries[b.index(&Key::Device(30)).unwrap()].failures, 1);
    }
    #[test]
    fn clock_domain_and_sequence_reversal_are_transactional() {
        let mut b = Breaker::new(clock(10));
        b.reserve(&cwd(), 10, clock(10)).unwrap();
        let saved = b.clone();
        for now in [
            clock(9),
            Clock {
                boot: [3; 16],
                ..clock(10)
            },
            Clock {
                kind: 2,
                ..clock(10)
            },
            Clock {
                domain: [3; 16],
                ..clock(10)
            },
            Clock {
                resume: 1,
                ..clock(10)
            },
        ] {
            assert_eq!(b.admit(&cwd(), now), Admission::Disabled);
            assert_eq!(b.reserve(&cwd(), 11, now), Err(Error::Domain));
            assert_eq!(
                b.observe(cwd(), 10, Progress::default(), EndReason::Complete, now),
                Err(Error::Domain)
            );
            assert_eq!(b, saved);
        }
        assert_eq!(
            b.observe(
                cwd(),
                9,
                Progress::default(),
                EndReason::Complete,
                clock(10)
            ),
            Err(Error::Sequence)
        );
        b.reserve(&Key::Device(20), 11, clock(11)).unwrap();
        assert_eq!(
            b.observe(
                cwd(),
                10,
                Progress::default(),
                EndReason::Complete,
                clock(11)
            ),
            Err(Error::Sequence)
        );
    }
    #[test]
    fn bounded_lru_preserves_live_keys_and_checks_hash_and_original() {
        let mut b = Breaker::new(clock(0));
        for i in 0..64 {
            b.observe(
                Key::Device(i),
                i,
                Progress::default(),
                EndReason::Complete,
                clock(i),
            )
            .unwrap();
        }
        b.reserve(&Key::Device(0), 64, clock(64)).unwrap();
        b.observe(
            Key::Device(64),
            65,
            Progress::default(),
            EndReason::Complete,
            clock(65),
        )
        .unwrap();
        assert_eq!(b.entries.len(), 64);
        assert!(b.index(&Key::Device(0)).is_some());
        assert_eq!(b.index(&Key::Device(1)), None);
        // A digest collision alone never selects a key.
        b.entries[0].digest = Key::Device(999).digest();
        assert_eq!(b.index(&Key::Device(999)), None);
        assert_eq!(Breaker::decode(&b.encode().unwrap()), Err(Error::Invalid));
        let mut b = Breaker::new(clock(0));
        for i in 0..64 {
            b.reserve(&Key::Device(i), i, clock(0)).unwrap();
        }
        let saved = b.clone();
        assert_eq!(
            b.reserve(&Key::Device(64), 64, clock(0)),
            Err(Error::Capacity)
        );
        assert_eq!(b, saved);
        let mut b = Breaker::new(clock(0));
        for i in 0..20 {
            let mut path = format!("/{i}/").into_bytes();
            path.resize(65_536, b'a');
            b.observe(
                Key::cwd(&path).unwrap(),
                i,
                Progress::default(),
                EndReason::Complete,
                clock(i),
            )
            .unwrap();
            let bytes = b.encode().unwrap();
            assert!(bytes.len() <= MAX_BYTES);
            assert_eq!(Breaker::decode(&bytes), Ok(b.clone()));
        }
        assert_eq!(b.entries.len(), 3);
        let raw = b.encode().unwrap();
        for n in 0..raw.len().min(200) {
            assert_eq!(Breaker::decode(&raw[..n]), Err(Error::Invalid));
        }
        assert_eq!(
            Breaker::decode(&vec![0; MAX_BYTES + 1]),
            Err(Error::Invalid)
        );
    }
    #[test]
    fn pwd_normalization_is_pure_and_conservative() {
        assert_eq!(Key::cwd(b"//a/./b///"), Key::cwd(b"/a/b"));
        assert_eq!(Key::cwd(b"/"), Ok(Key::Cwd(vec![b'/'])));
        for bad in [b"a".as_slice(), b"/a/../b", b"/a\0b"] {
            assert_eq!(Key::cwd(bad), Err(Error::Invalid));
        }
    }
    #[test]
    fn persisted_codec_rejects_noncanonical_and_inconsistent_records() {
        let mut b = Breaker::new(clock(10));
        b.reserve(&cwd(), 1, clock(10)).unwrap();
        let check = |mut bytes: Vec<u8>, error| {
            let crc = crc32c(&[&bytes[12..]]);
            bytes[8..12].copy_from_slice(&crc);
            assert_eq!(Breaker::decode(&bytes), Err(error));
        };
        let bytes = b.encode().unwrap();
        // Header magic, clock kind, sequence-present and entry key/alias flags.
        for index in [0, 28, 69, 72, 114] {
            let mut altered = bytes.clone();
            altered[index] = 9;
            check(altered, Error::Invalid);
        }
        let mut bad_crc = bytes.clone();
        bad_crc[8] ^= 1;
        assert_eq!(Breaker::decode(&bad_crc), Err(Error::Invalid));
        let mut oversized_key = bytes.clone();
        oversized_key[73..77].copy_from_slice(&65_537u32.to_le_bytes());
        check(oversized_key, Error::Invalid);
        let mut count = bytes.clone();
        count[70..72].copy_from_slice(&65u16.to_le_bytes());
        check(count, Error::Capacity);
        let mut trailing = bytes.clone();
        trailing.push(0);
        check(trailing, Error::Invalid);
        let mut duplicate = b.clone();
        duplicate.entries.push(duplicate.entries[0].clone());
        assert_eq!(
            Breaker::decode(&duplicate.encode().unwrap()),
            Err(Error::Invalid)
        );
        for invalid in 0..11 {
            let mut changed = b.clone();
            let entry = &mut changed.entries[0];
            match invalid {
                0 => {
                    entry.key = Key::Cwd(b"relative".to_vec());
                    entry.digest = entry.key.digest();
                }
                1 => entry.failures = 4,
                2 => entry.blocked_until = 1,
                3 => entry.used = 11,
                4 => entry.sequence = 2,
                5 => entry.lease_until = 10 + 2_000_000_001,
                6 => {
                    entry.failures = 3;
                    entry.blocked_until = 10 + 300_000_000_001;
                }
                7 => {
                    entry.key = Key::Device(1);
                    entry.digest = entry.key.digest();
                    entry.device = Some(1);
                }
                8 => changed.sequence = None,
                9 => {
                    let mut bytes = bytes.clone();
                    bytes[115] = 1;
                    check(bytes, Error::Invalid);
                    continue;
                }
                _ => {
                    entry.digest[0] ^= 1;
                }
            }
            assert_eq!(
                Breaker::decode(&changed.encode().unwrap()),
                Err(Error::Invalid),
                "case {invalid}"
            );
        }
    }
}
