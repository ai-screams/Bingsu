//! Dedicated entry; the helper links only the identity library.
//! The worker owns its bounded UpdateSink, including in startup test targets.
#![deny(unsafe_code)]
#[cfg(target_os = "linux")]
// The other ABI and row metadata are exercised by tests/filter.rs.
#[allow(dead_code, unsafe_code)]
mod filter;
// C2 compiles the bytes-only git boundary; C5/E4 connect collection later.
#[cfg(unix)]
#[allow(dead_code)]
mod git;
#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
mod landlock;
#[cfg(unix)]
#[allow(unsafe_code)]
mod limits;
// B1 compiles the capability layer without activating product collection.
#[cfg(unix)]
#[allow(dead_code)]
mod meter;
#[cfg(unix)]
#[allow(dead_code, unsafe_code)]
mod safe_read;
#[cfg(unix)]
#[allow(unsafe_code)]
mod sys;
mod worker;
#[cfg(unix)]
use bingsu_identity::build_id;

#[used]
static ROLE_TAG: [u8; 49] = bingsu_identity::role_tag(bingsu_identity::COLLECTOR_ROLE);

fn main() {
    std::hint::black_box(&ROLE_TAG);
    std::process::exit(worker::run());
}
