fn main() {
    // Declares the name only; nothing here or in [features] enables it. The
    // independent fuzz/collector crate sets it for its own copy of the parser
    // modules, so neither a product build nor --all-features can reach them.
    println!("cargo:rustc-check-cfg=cfg(collector_fuzz)");
}
