//! Measurement code for M1. Not shipped.
#![deny(unsafe_code)]

pub mod cgroup_rule;
pub mod report;
pub mod rounds;
pub mod stats;

/// Read buffer size of the file-reading rows and of the synthetic program
/// (an implementation constant, recorded in the results).
pub const BUF: usize = 4096;

#[cfg(unix)]
#[allow(unsafe_code)]
pub mod sys;

pub mod collector_stub;
