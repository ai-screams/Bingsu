use crate::other::Make;
pub fn m(v: &[u8]) -> usize { v.iter().copied().map(Make).count() }
