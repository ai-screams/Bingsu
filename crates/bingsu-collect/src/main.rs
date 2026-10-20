//! Dedicated entry; the helper links only the identity library.
#![deny(unsafe_code)]
#[cfg(target_os = "linux")]
// The other ABI and row metadata are exercised by tests/filter.rs.
#[allow(dead_code, unsafe_code)]
mod filter;
#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
mod landlock;
#[cfg(unix)]
#[allow(unsafe_code)]
mod limits;
#[cfg(unix)]
#[allow(unsafe_code)]
mod sys;
mod worker;
#[cfg(unix)]
use bingsu_collect::build_id;

#[used]
static ROLE_TAG: [u8; 49] = bingsu_collect::role_tag(bingsu_collect::COLLECTOR_ROLE);

fn main() {
    std::hint::black_box(&ROLE_TAG);
    std::process::exit(worker::run());
}
