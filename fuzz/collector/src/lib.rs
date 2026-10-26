//! Fuzz harness library: the collector's parser modules, compiled here with
//! cfg(collector_fuzz), plus the shared entries, formats and seed corpus.
#![cfg(unix)]
#![allow(dead_code, unsafe_code)]
#[path = "../../../crates/bingsu-collect/src/git/mod.rs"]
mod git;
#[cfg(target_os = "linux")]
#[path = "../../../crates/bingsu-collect/src/landlock.rs"]
mod landlock;
#[path = "../../../crates/bingsu-collect/src/meter.rs"]
mod meter;
#[path = "../../../crates/bingsu-collect/src/safe_read/mod.rs"]
mod safe_read;
#[path = "../../../crates/bingsu-collect/src/update_sink.rs"]
mod update_sink;

#[path = "../../../crates/bingsu-collect/tests/support/allocation.rs"]
mod allocation;
pub mod entries;
pub mod formats;
pub mod seeds;

use entries::Target;
use std::time::Duration;

/// One libFuzzer input: the shared entry plus the shared oracles. A panic,
/// an exceeded oracle or a sanitizer report is a finding; nothing is caught.
pub fn fuzz_one(target: Target, data: &[u8]) {
    let mut prepared = entries::prepare(target, data);
    let (outcome, counts) = allocation::measure(|| entries::execute(&mut prepared));
    entries::assert_bounded(&outcome, counts.peak, data.len(), Duration::from_secs(1));
}
