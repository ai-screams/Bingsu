#![cfg(test)]
#![no_std]
#![forbid(unsafe_code)]
pub fn probe(a: &[u8]) { let _ = a.as_ptr(); }
