//! The builtin version probes' fixed profiles (spec section 4 "language
//! versions", profile rows; plan D3). The supervisor builds a probe's argv and
//! environment from this table alone; the grant only names the profile, the
//! resolved executable and, for Rust, the toolchain the helper's resolver
//! chose (a grammar-checked name). Nothing from the shell reaches a probe.
use crate::collection::language::version_ok;
use alloc::vec::Vec;

/// Profile ids, one per builtin language (the grant's `Probe::profile`).
pub const NODE: u8 = 1;
pub const PYTHON: u8 = 2;
pub const RUST: u8 = 3;
pub const GO: u8 = 4;

/// How long a probe may run, in nanoseconds.
pub const TIMEOUT: u64 = 200_000_000;

/// One profile: the arguments after the executable's name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Profile {
    pub args: &'static [&'static [u8]],
    pub timeout: u64,
}

/// The profile of `id`; `None` for an unknown id (the probe is refused).
pub const fn profile(id: u8) -> Option<Profile> {
    let args: &'static [&'static [u8]] = match id {
        // An empty environment: NODE_OPTIONS and the rest never reach it.
        NODE => &[b"--version"],
        // `-I` drops the environment, user site and current folder; `-S`
        // skips `site`, so no `.pth` or `sitecustomize` runs (spec, X-12).
        PYTHON => &[b"-I", b"-S", b"--version"],
        RUST => &[b"--version"],
        GO => &[b"version"],
        _ => return None,
    };
    Some(Profile {
        args,
        timeout: TIMEOUT,
    })
}

/// The probe's whole environment as `NAME=VALUE\0` entries: fixed names, and
/// for Rust the toolchain the resolver chose. `home` is the folder `HOME`
/// points at (the neutral folder the probe runs in). `None` when the
/// toolchain is not a grammar-checked name or is given to another profile.
pub fn environment(id: u8, toolchain: Option<&[u8]>, home: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let mut put = |name: &[u8], value: &[u8]| {
        out.extend_from_slice(name);
        out.push(b'=');
        out.extend_from_slice(value);
        out.push(0);
    };
    match (id, toolchain) {
        (NODE | PYTHON, None) => {}
        (RUST, toolchain) => {
            put(b"HOME", home);
            // rustup never downloads a toolchain for a probe (X-18).
            put(b"RUSTUP_AUTO_INSTALL", b"0");
            if let Some(name) = toolchain {
                // Fails without it: profiles_build_fixed_environments (a
                // path-shaped toolchain).
                if !version_ok(name) {
                    return None;
                }
                put(b"RUSTUP_TOOLCHAIN", name);
            }
        }
        // `go.mod`'s `toolchain` line never makes `go` download (X-18).
        (GO, None) => {
            put(b"HOME", home);
            put(b"GOTOOLCHAIN", b"local");
        }
        // Fails without it: profiles_build_fixed_environments (a toolchain
        // given to another profile).
        _ => return None,
    }
    Some(out)
}
