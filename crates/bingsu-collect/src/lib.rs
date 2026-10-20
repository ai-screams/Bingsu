//! Shared sibling identity only. Worker OS code belongs to the dedicated binary.
#![no_std]
#![deny(unsafe_code)]

include!(concat!(env!("OUT_DIR"), "/build_id.rs"));

/// Reference the whole manifest tag so deployment checks can inspect both files.
pub fn build_id() -> bingsu_core::collection::wire::BuildId {
    let tag = manifest_tag();
    bingsu_core::collection::wire::BuildId(tag[16..].try_into().unwrap())
}

/// Fixed tag plus digest for installation checks of both sibling binaries.
pub fn manifest_tag() -> &'static [u8; 48] {
    core::hint::black_box(&BUILD_MANIFEST_TAG)
}
