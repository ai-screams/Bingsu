#![cfg(any(test, x))]
pub fn probe(a: &[u8]) { let _ = a.as_ptr(); }
