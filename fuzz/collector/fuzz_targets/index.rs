#![no_main]
use bingsu_collector_fuzz::{entries::Target, fuzz_one};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| fuzz_one(Target::Index, data));
