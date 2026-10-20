//! Dedicated entry; the helper links only the identity library.
#![deny(unsafe_code)]
#[cfg(unix)]
#[allow(unsafe_code)]
mod limits;
#[cfg(unix)]
#[allow(unsafe_code)]
mod sys;
mod worker;
#[cfg(unix)]
use bingsu_collect::build_id;

fn main() {
    std::process::exit(worker::run());
}
