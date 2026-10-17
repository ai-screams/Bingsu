//! Fixed relay permit. Recheck with a fresh clock immediately before execution.
use crate::{
    snapshot::{Clock, crc32c},
    snapshot_codec::Error,
};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Permit {
    pub kind: u8,
    pub deadline: u64,
    pub boot: [u8; 16],
    pub resume: u64,
    pub domain: [u8; 16],
}
impl Permit {
    pub fn encode(self) -> [u8; 96] {
        let mut b = [0; 96];
        b[..8].copy_from_slice(b"BNGEXC02");
        b[8] = 2;
        b[10] = 96;
        b[12] = self.kind;
        b[16..24].copy_from_slice(&self.deadline.to_le_bytes());
        b[24..40].copy_from_slice(&self.boot);
        b[40..48].copy_from_slice(&self.resume.to_le_bytes());
        b[48..64].copy_from_slice(&self.domain);
        let h = crc32c(&[b"bingsu-exec-v2\0", &b[..64]]);
        b[64..68].copy_from_slice(&h);
        b
    }
    pub fn decode(b: &[u8]) -> Result<Self, Error> {
        if b.len() != 96 {
            return Err(Error::Short);
        }
        if &b[..8] != b"BNGEXC02"
            || b[8..12] != [2, 0, 96, 0]
            || ![1, 2].contains(&b[12])
            || b[13..16] != [0, 0, 0]
            || crc32c(&[b"bingsu-exec-v2\0", &b[..64]]) != b[64..68]
            || b[68..96] != [0; 28]
        {
            return Err(Error::Tag);
        }
        Ok(Self {
            kind: b[12],
            deadline: u64::from_le_bytes(b[16..24].try_into().map_err(|_| Error::Short)?),
            boot: b[24..40].try_into().map_err(|_| Error::Short)?,
            resume: u64::from_le_bytes(b[40..48].try_into().map_err(|_| Error::Short)?),
            domain: b[48..64].try_into().map_err(|_| Error::Short)?,
        })
    }
    pub fn allows(self, now: Clock) -> bool {
        self.kind == now.kind
            && self.boot == now.boot
            && self.resume == now.resume
            && self.domain == now.domain
            && now.now < self.deadline
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // 이것을 실패시키는 것: 중계의 fresh clock 비교 또는 버전·정체 비교 하나를 제거한다.
    #[test]
    fn relay_checks_fresh_clock() {
        let p = Permit {
            kind: 1,
            deadline: 100,
            boot: [1; 16],
            resume: 0,
            domain: [2; 16],
        };
        let c = Clock {
            kind: 1,
            now: 99,
            boot: p.boot,
            resume: 0,
            domain: p.domain,
        };
        assert_eq!(Permit::decode(&p.encode()), Ok(p));
        assert!(p.allows(c));
        let mut x = c;
        x.now = 100;
        assert!(!p.allows(x));
        let mut x = c;
        x.boot[0] ^= 1;
        assert!(!p.allows(x));
        let mut x = c;
        x.kind = 2;
        assert!(!p.allows(x));
        let mut x = c;
        x.resume = 1;
        assert!(!p.allows(x));
        let mut x = c;
        x.domain[0] ^= 1;
        assert!(!p.allows(x));
        for i in 0..96 {
            let mut b = p.encode();
            b[i] ^= 0x80;
            assert!(Permit::decode(&b).is_err())
        }
    }
}
