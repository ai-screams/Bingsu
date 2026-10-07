//! Measurement code for M1 (spec section 9, M1 row). Not shipped.
#![deny(unsafe_code)]

pub mod cgroup_rule;
pub mod report;
pub mod rounds;
pub mod stats;

/// Read buffer size of the file-reading rows and of the synthetic program
/// (spec section 9 M1 row (7): an implementation constant, recorded in the
/// results).
pub const BUF: usize = 4096;

#[cfg(unix)]
#[allow(unsafe_code)]
pub mod sys;
