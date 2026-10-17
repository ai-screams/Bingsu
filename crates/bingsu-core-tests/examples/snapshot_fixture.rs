//! Native: write fixture to stdout. wasm32-unknown-unknown: call snapshot_fixture,
//! then read length (low 32 bits) bytes at pointer (high 32 bits) in exported memory.
#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
fn main() {
    use std::io::Write;
    std::io::stdout()
        .write_all(&bingsu_core_tests::snapshot_fixture::bytes())
        .unwrap();
}
#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
fn main() {}
#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
#[unsafe(no_mangle)]
pub extern "C" fn snapshot_fixture() -> u64 {
    let b = Box::leak(bingsu_core_tests::snapshot_fixture::bytes().into_boxed_slice());
    ((b.as_ptr() as u64) << 32) | b.len() as u64
}
