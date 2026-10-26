fn main() {
    // The only place collector_fuzz is set: this crate's own compilation of
    // the collector's modules. No product crate depends on this crate.
    println!("cargo:rustc-check-cfg=cfg(collector_fuzz)");
    println!("cargo:rustc-cfg=collector_fuzz");
}
