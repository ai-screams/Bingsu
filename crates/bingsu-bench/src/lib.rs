//! Measurement code for M1 (spec section 9, M1 row). Not shipped.
#![deny(unsafe_code)]

#[cfg(unix)]
#[allow(unsafe_code)]
pub mod sys;
