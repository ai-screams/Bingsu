//! CLI rule canary (not a workspace member). One tagged line per entry of
//! crates/bingsu/clippy.toml; scripts/check_core_purity.py requires a
//! clippy diagnostic naming exactly that path on exactly that line.
#![allow(dead_code, unused_must_use, unused_variables, unreachable_code, clippy::all)]
#![warn(clippy::disallowed_methods, clippy::disallowed_types, clippy::disallowed_macros)]

pub fn c0() { let _ = std::env::var("X"); } // CANARY: std::env::var
pub fn c1() { let _ = std::env::var_os("X"); } // CANARY: std::env::var_os
pub fn c2() { let _ = std::env::vars(); } // CANARY: std::env::vars
pub fn c3() { let _ = std::env::vars_os(); } // CANARY: std::env::vars_os
pub fn c4() { let _ = std::env::home_dir(); } // CANARY: std::env::home_dir
pub fn c5() { std::process::exit(0); } // CANARY: std::process::exit
pub fn c6() { use std::io::Write; let _ = std::io::stderr().write_all(b"x"); } // CANARY: std::io::Write::write_all
