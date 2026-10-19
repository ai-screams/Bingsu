pub struct W(pub u8);
pub fn m(v: &[u8]) -> usize { v.iter().copied().map(W).count() }
