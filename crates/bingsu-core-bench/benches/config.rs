//! Instruction counts of reading one config file into the spanned tree
//! (M3a S1, spec section 2 "설정 파서와 국소 편집": the parser is chosen by
//! WASM size and speed). Its own bench target, like every group.
use bingsu_core::config::tree::{SyntaxError, Table, parse};
use gungraun::prelude::*;
use std::hint::black_box;

/// A config of about `bytes` bytes: the spec's example file, then custom
/// segments with comments, strings, arrays and numbers until the size.
fn config(bytes: u32) -> Vec<u8> {
    let mut s = String::from(
        "version = 1\nrequires = \">=0.3\"\ntheme = \"bingsu-default\"\n\n[colors]\nflavor = \"a\"\n\
         mode = \"auto\"\nknobs = { hue = 280, accent_l = 0.76, accent_c = 0.12 }\n\n\
         [layout.line1]\nleft = [\"dir\", \"git\"]\nright = [\"status\", \"duration\"]\n\n",
    );
    let mut i = 0;
    while s.len() < bytes as usize {
        s.push_str(&format!(
            "# segment {i}: a comment line written by hand\n[segment.\"custom/seg-{i}\"]\n\
             kind = \"command\"\ncommand = [\"kubectl\", \"config\", \"current-context\"]\n\
             timeout = \"200ms\"\ncache = \"30s\"\nenabled = true\nmin = 2.5\n\n"
        ));
        i += 1;
    }
    s.into_bytes()
}

// Behind `#[inline(never)]`: inlined into the wrapper, Callgrind on aarch64
// undercounts the work (crates/bingsu-core-bench, every group does this).
#[inline(never)]
fn read(bytes: &[u8]) -> Result<Table, Vec<SyntaxError>> {
    parse(bytes)
}

#[library_benchmark]
#[bench::kib4(args = [4096], setup = config)]
#[bench::kib64(args = [65536], setup = config)]
fn config_parse(input: Vec<u8>) -> (Vec<u8>, Result<Table, Vec<SyntaxError>>) {
    let t = black_box(read(black_box(&input)));
    // Returned, so the tree is freed outside the counted code.
    (input, t)
}

library_benchmark_group!(name = config, benchmarks = [config_parse]);

// Keep the generated main at top level so the benchmark actually runs.
main!(library_benchmark_groups = config);
