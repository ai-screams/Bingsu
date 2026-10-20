//! Shared sibling identity only. Worker OS code belongs to the dedicated binary.
#![no_std]
#![deny(unsafe_code)]

// The helper still links only identity code. Linux probes use the exact same
// policy builder and installer as the dedicated worker, without a feature flag.
#[cfg(any(target_os = "linux", test))]
extern crate std;
#[cfg(any(target_os = "linux", test))]
#[allow(unsafe_code)]
pub mod filter;
#[cfg(any(target_os = "linux", test))]
#[allow(unsafe_code)]
pub mod landlock;

include!(concat!(env!("OUT_DIR"), "/build_id.rs"));

pub const ROLE_MARKER: [u8; 16] = *b"BNGROLE-ID02\0\0\0\0";
pub const COLLECTOR_ROLE: u8 = 1;
pub const BINGSU_ROLE: u8 = 2;

/// Only each binary's entry embeds its own role, bound to this build identity.
pub const fn role_tag(role: u8) -> [u8; 49] {
    let mut tag = [0; 49];
    let mut i = 0;
    while i < 16 {
        tag[i] = ROLE_MARKER[i];
        i += 1;
    }
    tag[16] = role;
    i = 0;
    while i < 32 {
        tag[17 + i] = BUILD_ID.0[i];
        i += 1;
    }
    tag
}

/// Reference the whole manifest tag so deployment checks can inspect both files.
pub fn build_id() -> bingsu_core::collection::wire::BuildId {
    let tag = manifest_tag();
    bingsu_core::collection::wire::BuildId(tag[16..].try_into().unwrap())
}

/// Fixed tag plus digest for installation checks of both sibling binaries.
pub fn manifest_tag() -> &'static [u8; 48] {
    core::hint::black_box(&BUILD_MANIFEST_TAG)
}
