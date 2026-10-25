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
    // Keep coverage even if both the generator and golden are regenerated after
    // accidentally deleting a matrix axis. Every cell has seven rendered fields.
    let text = std::str::from_utf8(&out.stdout).unwrap();
    let rows: Vec<_> = text
        .lines()
        .filter(|line| line.starts_with("git "))
        .collect();
    assert_eq!(rows.len(), 43 * 3 * 2 * 3 * 7);
    for case in [
        "no-repo",
        "unborn",
        "unborn-pending",
        "detached",
        "rebase",
        "merge",
        "cherry-pick",
        "revert",
        "bisect",
        "counts",
        "pending",
        "saturated",
        "filtered",
        "clean",
        "partial",
        "filtered-pending",
        "filtered-zero",
        "filtered-unknown-count",
        "filtered-unknown-zero",
        "readonly-unknown",
        "readonly-false",
        "readonly-true",
        "cmdsub",
        "osc_title",
        "bidi_override",
        "bad_utf8",
    ] {
        for icons in ["ascii", "unicode", "nerd"] {
            for amb in [1, 2] {
                for shell in ["zsh", "bash", "fish"] {
                    for width in [0, 1, 2, 3, 59, 60, 120] {
                        let key = format!("git {case} {icons} {amb} {shell} {width}\t");
                        let row = rows
                            .iter()
                            .find(|r| r.starts_with(&key))
                            .expect("git golden matrix cell");
                        assert_eq!(row.split_once('\t').unwrap().1.split(' ').count(), 8);
                    }
                }
            }
        }
    }
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
