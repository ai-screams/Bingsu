//! The roots init pinned, handed to the user's own commands (`reload`,
//! `config check|path|use`) in one exported variable, so they act on the
//! folders the prompt reads even when `XDG_*` changed after init (direnv).
//! The value is the hook's own root words (the ones `bingsu prompt` gets),
//! each as `<byte length>:<word>`; the lengths are the only framing, so no
//! byte of a path can end a word early. Decoding applies the checks of the
//! prompt words (`core::helper::validate`) and the runtime root's identity
//! check; anything else is rejected whole.
use super::{
    prime,
    roots::{ConfigRootPin, Roots, RuntimeRootPin},
};
use crate::commands::{group_policy::SystemGroups, runtime_root};
use bingsu_core::root_arg::parse_decimal;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

pub const VAR: &str = "BINGSU_ROOTS";

/// `None` when a root the commands need (runtime, config, state) is not pinned.
pub fn encode(roots: &Roots, home: &Path) -> Option<Vec<u8>> {
    let words = prime::helper_words(roots, home)?;
    let mut out = Vec::new();
    for w in &words {
        out.extend_from_slice(w.len().to_string().as_bytes());
        out.push(b':');
        out.extend_from_slice(w);
    }
    Some(out)
}

fn unframe(mut v: &[u8]) -> Option<Vec<&[u8]>> {
    let mut words = Vec::new();
    while !v.is_empty() {
        let colon = v.iter().position(|&b| b == b':')?;
        let len = usize::try_from(parse_decimal(&v[..colon])?).ok()?;
        let rest = &v[colon + 1..];
        if len == 0 || len > rest.len() {
            return None;
        }
        words.push(&rest[..len]);
        v = &rest[len..];
    }
    (!words.is_empty() && words.len() <= 16).then_some(words)
}

/// The pinned roots, re-checked now; `None` for a missing, garbled, forged
/// or no longer matching value.
/// `Roots.log` and `RuntimeRootPin.group_ok` are copied from the environment,
/// not verified evidence. Any later consumer must re-check the log root and
/// group policy before using them (including before writing logs).
pub fn decode(var: &[u8], me: u32, user: &[u8], home: &Path) -> Option<Roots> {
    let raw = unframe(var)?;
    if raw
        .iter()
        .any(|word| matches!(*word, b"--redraw" | b"--width"))
    {
        return None;
    }
    let words = bingsu_core::helper::words(&raw).ok()?;
    // The prompt path drops words it does not know; a pinned value that
    // holds any is not what init wrote.
    if words.len() != raw.len() + 6 {
        return None;
    }
    let e = bingsu_core::helper::validate(&words).ok()?;
    let path = |b: &[u8]| PathBuf::from(std::ffi::OsStr::from_bytes(b));
    if path(e.home.as_deref()?) != home {
        return None;
    }
    let r = e.runtime_root.as_ref()?;
    let pin = runtime_root::Pinned {
        dev: r.dev,
        ino: r.ino,
        path: path(&r.path),
    };
    runtime_root::open_runtime_root(&pin, me, &mut SystemGroups::new(user)).ok()?;
    let config = ConfigRootPin::reopen(
        &path(e.config_root_written.as_deref()?),
        &path(e.config_root.as_deref()?),
        e.config_root_shape_only,
        me,
        &mut SystemGroups::new(user),
    )
    .ok()?;
    Some(Roots {
        runtime: Some(RuntimeRootPin {
            dev: pin.dev,
            ino: pin.ino,
            path: pin.path,
            group_ok: e.runtime_groups,
        }),
        config: Some(config),
        state: Some(path(e.state_root.as_deref()?)),
        log: e.log_root.as_deref().map(path),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // 이것을 실패시키는 것: pinned roots에서 prompt 전용 --redraw/--width를 받는 것.
    #[test]
    fn pinned_roots_reject_prompt_flags() {
        use crate::commands::sys;
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        struct Cleanup(PathBuf);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                std::fs::remove_dir(&self.0).unwrap();
            }
        }
        let base = std::env::temp_dir().join(format!("bingsu-pinned-flags-{}", std::process::id()));
        std::fs::create_dir(&base).unwrap();
        let _cleanup = Cleanup(base.clone());
        std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o700)).unwrap();
        let base = std::fs::canonicalize(base).unwrap();
        let md = std::fs::metadata(&base).unwrap();
        let me = sys::current_uid();
        let user = sys::passwd_entry(me).unwrap().name;
        let roots = Roots {
            runtime: Some(RuntimeRootPin {
                dev: md.dev(),
                ino: md.ino(),
                path: base.clone(),
                group_ok: Vec::new(),
            }),
            config: Some(ConfigRootPin::check(&base, me, &mut SystemGroups::new(&user)).unwrap()),
            state: Some(base.join("state")),
            log: None,
        };
        let valid = encode(&roots, &base).unwrap();
        assert!(decode(&valid, me, &user, &base).is_some());
        for extra in [b"8:--redraw".as_slice(), b"7:--width2:80", b"7:--width"] {
            let mut forged = valid.clone();
            forged.extend_from_slice(extra);
            assert!(decode(&forged, me, &user, &base).is_none(), "{extra:?}");
        }
    }

    // 이것을 실패시키는 것: 길이를 무시하고 구분자로 자르는 것(경로 속 ':'·줄바꿈이 낱말을 끊음), 길이 0·넘치는 길이·앞 0·남는 바이트를 받는 것.
    #[test]
    fn framing_is_by_length_only() {
        let hostile: &[u8] = b"--state-root=/a:3:b\n--home=/x";
        let mut v = format!("{}:", hostile.len()).into_bytes();
        v.extend_from_slice(hostile);
        v.extend_from_slice(b"2:ab");
        assert_eq!(unframe(&v).unwrap(), [hostile, b"ab"]);
        for bad in [
            &b""[..],
            b"0:",
            b"3:ab",
            b"03:abc",
            b"x:abc",
            b"3abc",
            b"2:abX",
            b"2:ab9",
        ] {
            assert!(unframe(bad).is_none(), "{bad:?}");
        }
    }
}
