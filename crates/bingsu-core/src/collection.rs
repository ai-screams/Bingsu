//! Legacy helper request and bounded collector protocol.
//! Bounded, read-only fixed collector request. Never a configured command.
use crate::{
    snapshot::{self, Clock, Identity},
    snapshot_codec::Error,
};
pub mod cwd_hash;
pub mod response;
pub mod wire;

use alloc::{string::String, vec::Vec};
pub const REQUEST_MAX: usize = 108 + 3 * crate::layout::PATH_BYTES_MAX;
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    pub id: Identity,
    pub kind: u8,
    pub domain: [u8; 16],
    pub resume: u64,
    pub config: Vec<u8>,
    pub state: Vec<u8>,
    pub cwd: Vec<u8>,
    pub mask: u32,
}
pub fn worker_mask(mask: u32) -> u32 {
    crate::field::BUILTIN
        .iter()
        .position(|s| s.id == "git")
        .map_or(0, |i| mask & (1 << i))
}
impl Request {
    pub fn new(
        id: Identity,
        clock: Clock,
        config: &[u8],
        state: &[u8],
        cwd: &[u8],
        mask: u32,
    ) -> Result<Option<Self>, Error> {
        let request = Self {
            id,
            kind: clock.kind,
            domain: clock.domain,
            resume: clock.resume,
            config: config.to_vec(),
            state: state.to_vec(),
            cwd: cwd.to_vec(),
            mask: worker_mask(mask),
        };
        if request.mask == 0 {
            return Ok(None);
        }
        request.validate()?;
        if clock.boot != id.boot {
            return Err(Error::Tag);
        }
        Ok(Some(request))
    }
    fn validate(&self) -> Result<(), Error> {
        for path in [&self.config, &self.state, &self.cwd] {
            if path.first() != Some(&b'/')
                || path.len() > crate::layout::PATH_BYTES_MAX
                || path.contains(&0)
            {
                return Err(Error::Tag);
            }
        }
        if ![1, 2].contains(&self.kind)
            || self.mask == 0
            || worker_mask(self.mask) != self.mask
            || snapshot::context_crc(&self.config, &self.state)? != self.id.context
        {
            return Err(Error::Tag);
        }
        Ok(())
    }
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        self.validate()?;
        let mut b = alloc::vec![0;104];
        b[..8].copy_from_slice(b"BNGCOL01");
        b[8] = self.kind;
        b[16..32].copy_from_slice(&self.id.boot);
        b[32..48].copy_from_slice(&self.id.epoch);
        b[48..56].copy_from_slice(&self.id.generation.to_le_bytes());
        b[56..60].copy_from_slice(&self.id.source);
        b[60..64].copy_from_slice(&self.id.context);
        b[64..80].copy_from_slice(&self.domain);
        b[80..88].copy_from_slice(&self.resume.to_le_bytes());
        b[88..92].copy_from_slice(&self.mask.to_le_bytes());
        for (n, path) in [&self.config, &self.state, &self.cwd].iter().enumerate() {
            b[92 + n * 4..96 + n * 4].copy_from_slice(&(path.len() as u32).to_le_bytes());
            b.extend_from_slice(path);
        }
        b.extend_from_slice(&snapshot::crc32c(&[b"bingsu-collection-v1\0", &b]));
        Ok(b)
    }
    pub fn decode(b: &[u8]) -> Result<Self, Error> {
        if b.len() < 108 || b.len() > REQUEST_MAX {
            return Err(Error::Short);
        }
        let end = b.len() - 4;
        if &b[..8] != b"BNGCOL01"
            || b[9..16] != [0; 7]
            || snapshot::crc32c(&[b"bingsu-collection-v1\0", &b[..end]]) != b[end..]
        {
            return Err(Error::Tag);
        }
        let u32_at = |at| u32::from_le_bytes(b[at..at + 4].try_into().unwrap());
        let u64_at = |at| u64::from_le_bytes(b[at..at + 8].try_into().unwrap());
        let mut at: usize = 104;
        let mut path = |n: usize| -> Result<Vec<u8>, Error> {
            let len = u32_at(92 + n * 4) as usize;
            let next = at.checked_add(len).ok_or(Error::Short)?;
            if len > crate::layout::PATH_BYTES_MAX || next > end {
                return Err(Error::Short);
            }
            let p = b[at..next].to_vec();
            at = next;
            Ok(p)
        };
        let r = Self {
            id: Identity {
                boot: b[16..32].try_into().unwrap(),
                epoch: b[32..48].try_into().unwrap(),
                generation: u64_at(48),
                source: b[56..60].try_into().unwrap(),
                context: b[60..64].try_into().unwrap(),
            },
            kind: b[8],
            domain: b[64..80].try_into().unwrap(),
            resume: u64_at(80),
            mask: u32_at(88),
            config: path(0)?,
            state: path(1)?,
            cwd: path(2)?,
        };
        if at != end {
            return Err(Error::Tag);
        }
        r.validate()?;
        Ok(r)
    }
    pub fn accepts(&self, actual: &Self, completed_at: u64, prompt_started: u64) -> bool {
        self == actual && completed_at < prompt_started
    }
    pub fn components(&self) -> Vec<String> {
        let mut out = alloc::vec![String::from("collections-v1")];
        for chunk in self.cwd.chunks(60) {
            let mut name = String::new();
            for b in chunk {
                name.push(char::from(b"0123456789abcdef"[(b >> 4) as usize]));
                name.push(char::from(b"0123456789abcdef"[(b & 15) as usize]));
            }
            out.push(name);
        }
        out.push(String::from("store"));
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // 이것을 실패시키는 것: 내장 git 선택·정체/시각·길이·CRC 검사를 제거하는 것.
    #[test]
    fn fixed_collection_wire_and_eligibility() {
        let clock = Clock {
            kind: 1,
            boot: [1; 16],
            domain: [2; 16],
            resume: 0,
            now: 10,
        };
        let id = Identity {
            boot: clock.boot,
            epoch: [3; 16],
            generation: 1,
            source: [4; 4],
            context: snapshot::context_crc(b"/c", b"/s").unwrap(),
        };
        let r = Request::new(id, clock, b"/c", b"/s", b"/r", u32::MAX)
            .unwrap()
            .unwrap();
        assert_eq!(
            r.mask,
            1 << crate::field::BUILTIN
                .iter()
                .position(|s| s.id == "git")
                .unwrap()
        );
        assert!(
            Request::new(id, clock, b"/c", b"/s", b"/r", !r.mask)
                .unwrap()
                .is_none()
        );
        assert!(Request::new(id, clock, b"/wrong", b"/s", b"/r", r.mask).is_err());
        assert!(Request::new(id, clock, b"/c", b"/s", b"relative", r.mask).is_err());
        let mut wrong_clock = clock;
        wrong_clock.boot[0] ^= 1;
        assert!(Request::new(id, wrong_clock, b"/c", b"/s", b"/r", r.mask).is_err());
        for bad_cwd in [b"".as_slice(), b"/x\0y"] {
            assert!(Request::new(id, clock, b"/c", b"/s", bad_cwd, r.mask).is_err());
        }
        for field in 0..3 {
            let mut bad = r.clone();
            match field {
                0 => bad.kind = 3,
                1 => bad.mask = 0,
                _ => bad.mask = u32::MAX,
            };
            assert!(bad.encode().is_err());
        }
        let bytes = r.encode().unwrap();
        assert_eq!(Request::decode(&bytes).unwrap(), r);
        for i in 0..bytes.len() {
            let mut b = bytes.clone();
            b[i] ^= 0x80;
            assert!(Request::decode(&b).is_err(), "{i}");
        }
        // Recompute CRC to exercise structural checks independently of damage detection.
        for at in [0usize, 8, 9, 92, 96, 100] {
            let mut bad = bytes.clone();
            bad[at] ^= 0x80;
            let end = bad.len() - 4;
            let sum = snapshot::crc32c(&[b"bingsu-collection-v1\0", &bad[..end]]);
            bad[end..].copy_from_slice(&sum);
            assert!(Request::decode(&bad).is_err(), "structural {at}");
        }
        assert!(Request::decode(&bytes[..107]).is_err());
        let mut trailing = bytes[..bytes.len() - 4].to_vec();
        trailing.push(0);
        trailing.extend_from_slice(&snapshot::crc32c(&[b"bingsu-collection-v1\0", &trailing]));
        assert!(Request::decode(&trailing).is_err());
        assert!(r.accepts(&r, 9, 10));
        assert!(!r.accepts(&r, 10, 10));
        let mut other = r.clone();
        other.id.epoch[0] ^= 1;
        assert!(!r.accepts(&other, 9, 10));
        let mut other = r.clone();
        other.cwd.push(b'x');
        assert_ne!(r.components(), other.components());
        let mut huge = r.clone();
        huge.cwd = alloc::vec![b'/';crate::layout::PATH_BYTES_MAX+1];
        assert!(huge.encode().is_err());
        huge.cwd.pop();
        assert!(huge.encode().is_ok());
    }
}
