use std::{env, path::PathBuf, process::Command};
fn main() {
    println!("cargo:rerun-if-changed=../x16-write-denial.c");
    println!("cargo:rerun-if-env-changed=CC");
    println!("cargo:rerun-if-env-changed=AR");
    if env::var("CARGO_CFG_TARGET_OS").unwrap() != "linux" { return; }
    let out = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    let object = out.join("x16.o");
    assert!(Command::new(env::var("CC").unwrap_or_else(|_| "cc".into()))
        .args(["-std=c11", "-Wall", "-Wextra", "-Werror", "-c", "../x16-write-denial.c", "-o"])
        .arg(&object).status().unwrap().success());
    let archive = out.join("libcollector_x16.a");
    assert!(Command::new(env::var("AR").unwrap_or_else(|_| "ar".into()))
        .arg("crs").arg(&archive).arg(&object).status().unwrap().success());
    println!("cargo:rustc-link-search=native={}",out.display());
    println!("cargo:rustc-link-lib=static=collector_x16");
}
