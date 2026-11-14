//! The builtin version probes' fixed profiles. The supervisor builds a probe's argv and
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
        // `HOME` too, so a startup file under the user's home is never read
        // (D3a security review S-M1).
        (NODE | PYTHON, None) => put(b"HOME", home),
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

/// The version a probe printed, from the sanitized first line of its stdout:
/// `Python 3.11.2`, `v18.20.4`, `rustc 1.98.1 (… …)`, `go version go1.19.8
/// linux/arm64`. Only a token that passes the version grammar and begins
/// with a digit is a version; anything else is no value.
pub fn version(id: u8, line: &str) -> Option<&str> {
    let mut words = line.split(' ');
    let token = match id {
        // Fails without each prefix: probe_output_yields_the_version.
        NODE => words.next()?.strip_prefix('v')?,
        PYTHON => words.nth(1).filter(|_| line.starts_with("Python "))?,
        RUST => words.nth(1).filter(|_| line.starts_with("rustc "))?,
        GO => words
            .nth(2)
            .filter(|_| line.starts_with("go version "))?
            .strip_prefix("go")?,
        _ => return None,
    };
    // Fails without it: probe_output_yields_the_version (`vtrue`, a
    // `/`-name).
    (token.as_bytes().first().is_some_and(|b| b.is_ascii_digit()) && version_ok(token.as_bytes()))
        .then_some(token)
}

/// The version a user-defined language's version command printed: the first word of the sanitized first line that,
/// after one
/// leading `v` is taken off, begins with a digit and passes the version
/// grammar. `deno 2.1.4 (stable)` gives `2.1.4`, `v20.1.0` gives `20.1.0`;
/// a line with no such word gives no value.
pub fn any_version(line: &str) -> Option<&str> {
    line.split(' ')
        .map(|w| w.strip_prefix('v').unwrap_or(w))
        .find(|w| {
            w.as_bytes().first().is_some_and(|b| b.is_ascii_digit()) && version_ok(w.as_bytes())
        })
}

/// The digest a builtin entry is bound to (spec "cache"): the profile, how
/// the value was decided (`kind`, the helper's) and each part that decided
/// it, each with its length, so no two lists collide.
pub fn digest(id: u8, kind: u8, parts: &[&[u8]]) -> [u8; 32] {
    let mut b = Vec::new();
    b.extend_from_slice(b"bingsu-builtin-policy-v1\0");
    b.push(id);
    b.push(kind);
    b.extend_from_slice(&(parts.len() as u64).to_le_bytes());
    for p in parts {
        b.extend_from_slice(&(p.len() as u64).to_le_bytes());
        b.extend_from_slice(p);
    }
    crate::collection::cwd_hash::sha256(&b)
}

#[cfg(test)]
mod tests {
    use super::*;

    // 사용자 정의 language의 버전 토큰: 첫 줄의 단어 중 앞의 v 하나를 뗀 뒤 숫자로 시작하고 버전 문법을
    // 통과하는 첫 단어다. 이것을 실패시키는 것: v를 떼지 않는 것, 숫자 시작 검사를 지우는 것(`deno`가 값이 됨),
    // 문법 검사를 지우는 것, 첫 단어만 보는 것.
    #[test]
    fn any_version_takes_the_first_version_word() {
        for (line, want) in [
            (
                "deno 2.1.4 (stable, release, aarch64-apple-darwin)",
                Some("2.1.4"),
            ),
            ("v20.1.0", Some("20.1.0")),
            ("zig v 0.13.0", Some("0.13.0")),
            ("bun 1.1.0/x", None),
            (
                "ruby 3.3.0p0 (2023-12-25 revision 5124f9ac75)",
                Some("3.3.0p0"),
            ),
            ("no version here", None),
            ("", None),
        ] {
            assert_eq!(any_version(line), want, "{line:?}");
        }
    }
}
