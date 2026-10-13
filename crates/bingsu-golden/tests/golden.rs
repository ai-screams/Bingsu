//! Native half of the determinism golden: the probe's stdout equals the
//! committed tests/golden/render/render.tsv byte for byte. A missing file
//! fails. What makes it fail: one flipped byte in the file, a deleted file,
//! or `+ 0.5` changed to `+ 0.49` in the 8-bit rounding of color::math.
//! CI repeats the comparison under wasmtime (wasm32-wasip1).
use std::process::Command;

#[test]
fn native_output_matches_committed_golden() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/golden/render/render.tsv");
    let want = std::fs::read(&path).unwrap_or_else(|e| {
        panic!(
            "{}: {e} (cargo run -q -p bingsu-golden --release > it)",
            path.display()
        )
    });
    let out = Command::new(env!("CARGO_BIN_EXE_bingsu-golden"))
        .output()
        .expect("run bingsu-golden");
    assert!(out.status.success(), "bingsu-golden failed");
    let first = out
        .stdout
        .split(|&b| b == b'\n')
        .zip(want.split(|&b| b == b'\n'))
        .position(|(a, b)| a != b);
    assert!(
        out.stdout == want,
        "output differs from {} (first differing line index: {first:?}, lengths {} vs {})",
        path.display(),
        out.stdout.len(),
        want.len()
    );
}
