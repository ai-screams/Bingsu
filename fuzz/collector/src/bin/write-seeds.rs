//! Writes the fixed seed corpus as libFuzzer start corpora:
//! <out>/<target>/<name>. Seeds above seeds::CORPUS_MAX stay replay-only.
use bingsu_collector_fuzz::seeds;
use std::{fs, path::PathBuf};

fn main() {
    let out = PathBuf::from(
        std::env::args_os()
            .nth(1)
            .expect("usage: write-seeds <dir>"),
    );
    let mut written = 0;
    for seed in seeds::all() {
        if seed.data.len() > seeds::CORPUS_MAX {
            continue;
        }
        let dir = out.join(seed.target.name());
        fs::create_dir_all(&dir).expect("corpus directory");
        fs::write(dir.join(seed.name), &seed.data).expect("seed file");
        written += 1;
    }
    println!("wrote {written} seeds");
}
