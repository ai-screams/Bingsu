//! Instruction counts of parsing and the complete config read pipeline.
use bingsu_core::color::palette::Mode;
use bingsu_core::config::compile::BUILTIN_TOML;
use bingsu_core::config::report::{ConfigReport, report};
use bingsu_core::config::source::{ExtendsRef, FileKey, OpenError, Opened, Resolver, Trust};
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

fn opened(bytes: Vec<u8>, ino: u64) -> Opened {
    Opened {
        key: FileKey { dev: 1, ino },
        bytes,
        trust: Trust::Executable,
        display: b"f".to_vec(),
    }
}

/// `extends` entries `p0`, `p1`, … answered with `parts`.
struct Parts(Vec<Vec<u8>>);
impl Resolver for Parts {
    fn open(&mut self, _: &Opened, r: &ExtendsRef) -> Result<Opened, OpenError> {
        let i: usize = r.text[1..].parse().map_err(|_| OpenError {
            reason: String::new(),
            trust: Trust::Executable,
        })?;
        Ok(opened(self.0[i].clone(), 10 + i as u64))
    }
}

/// The whole read at the size caps: one file of 256 KiB, or a root that
/// extends three more files of 256 KiB (1 MiB in all).
fn graph(files: u32) -> (Vec<Opened>, Parts) {
    // Keep the parser-only fixture unchanged; the full read uses only
    // valid keys so it reaches compilation, then pads with a comment.
    let part = |_| {
        String::from_utf8(config(250 * 1024))
            .unwrap()
            .replace("min = 2.5\n", "")
            .into_bytes()
    };
    let extends: Vec<String> = (0..files - 1).map(|i| format!("\"p{i}\"")).collect();
    let mut root = format!("extends = [{}]\n", extends.join(", ")).into_bytes();
    if files == 1 {
        root.clear();
    }
    root.extend(part(0));
    let pad = |b: &mut Vec<u8>, size| {
        b.push(b'#');
        b.resize(size - 1, b' ');
        b.push(b'\n');
    };
    let mut parts = Parts((0..files - 1).map(part).collect());
    for p in &mut parts.0 {
        pad(p, 256 * 1024);
    }
    let root_size = 256 * 1024 - if files == 1 { 0 } else { BUILTIN_TOML.len() };
    pad(&mut root, root_size);
    (
        vec![opened(BUILTIN_TOML.as_bytes().to_vec(), 0), opened(root, 1)],
        parts,
    )
}

#[inline(never)]
fn read_all(roots: Vec<Opened>, parts: &mut Parts) -> ConfigReport {
    report(roots, parts, [0, 3, 0], Mode::Dark)
}

#[library_benchmark]
#[bench::kib256(args = [1], setup = graph)]
#[bench::mib1(args = [4], setup = graph)]
fn config_read(input: (Vec<Opened>, Parts)) -> (Parts, ConfigReport) {
    let (roots, mut parts) = input;
    let r = black_box(read_all(black_box(roots), &mut parts));
    assert!(
        r.snapshot.is_some(),
        "the full-read benchmark must reach compilation"
    );
    (parts, r)
}

library_benchmark_group!(name = config, benchmarks = [config_parse, config_read]);

// main! defines `fn main` itself: wrapped in a fn of ours the bench would
// build, exit 0 and measure nothing.
main!(library_benchmark_groups = config);
