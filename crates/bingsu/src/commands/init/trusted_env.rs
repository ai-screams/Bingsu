//! The one function in this crate that reads the environment. Only `init`
//! and the user's own commands (`reload`, `config check|path|use`) call it:
//! they run at a trusted moment, `init` pins what it finds into the hook
//! (spec section 4 "runtime root" 1 and 7, F-01), and the commands find the
//! same folders for the same user. The prompt path never reads the
//! environment (crates/bingsu/clippy.toml).
use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::OsStrExt;

pub struct TrustedEnv {
    pub path: Option<OsString>,
    pub home: Option<OsString>,
    pub xdg_runtime_dir: Option<OsString>,
    pub xdg_config_home: Option<OsString>,
    pub xdg_state_home: Option<OsString>,
    pub xdg_cache_home: Option<OsString>,
}

impl TrustedEnv {
    #[expect(
        clippy::disallowed_methods,
        reason = "init pins roots at a trusted moment (spec 4, runtime root 1 and 7)"
    )]
    pub fn capture() -> Self {
        Self {
            path: std::env::var_os("PATH"),
            home: std::env::var_os("HOME"),
            xdg_runtime_dir: std::env::var_os("XDG_RUNTIME_DIR"),
            xdg_config_home: std::env::var_os("XDG_CONFIG_HOME"),
            xdg_state_home: std::env::var_os("XDG_STATE_HOME"),
            xdg_cache_home: std::env::var_os("XDG_CACHE_HOME"),
        }
    }

    /// Pin Git's locations at the same trusted moment as the roots. Keep the
    /// written bytes (including symlinks); the helper checks each opened file.
    /// Empty/unset values are explicit empty words, not the legacy fallback.
    /// Invalid values use a non-path marker: the helper rejects it as unknown
    /// before I/O. Empty would incorrectly claim that Git has no global rules.
    pub fn git_global_paths(
        &self,
        mut notice: impl FnMut(&'static str, &'static str),
    ) -> (&[u8], &[u8]) {
        fn checked<'a>(
            name: &'static str,
            value: Option<&'a OsStr>,
            notice: &mut impl FnMut(&'static str, &'static str),
        ) -> &'a [u8] {
            let bytes = value.map_or(b"".as_slice(), OsStrExt::as_bytes);
            let reason = if bytes.len() > bingsu_core::layout::PATH_BYTES_MAX {
                Some("exceeds 65536 bytes")
            } else if bytes.contains(&0) {
                Some("contains NUL")
            } else if !bytes.is_empty() && !bytes.starts_with(b"/") {
                Some("is not an absolute path")
            } else {
                None
            };
            if let Some(reason) = reason {
                // Optional collection inputs must never prevent prompt setup.
                notice(name, reason);
                b"!invalid".as_slice()
            } else {
                bytes
            }
        }
        (
            checked("HOME", self.home.as_deref(), &mut notice),
            checked(
                "XDG_CONFIG_HOME",
                self.xdg_config_home.as_deref(),
                &mut notice,
            ),
        )
    }

    /// The roots variable the init script exported (see `pinned`).
    #[expect(
        clippy::disallowed_methods,
        reason = "the user's commands read the roots init exported"
    )]
    pub fn pinned_roots() -> Option<OsString> {
        std::env::var_os(super::pinned::VAR)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Mutations: preserve invalid bytes, reject the exact cap, omit/duplicate
    // a notice, name the wrong variable/reason, or swap the two locations.
    #[test]
    fn git_global_pins_validate_both_paths_before_rendering() {
        let mut env = TrustedEnv {
            path: None,
            home: None,
            xdg_runtime_dir: None,
            xdg_config_home: None,
            xdg_state_home: None,
            xdg_cache_home: None,
        };
        for value in [None, Some(OsString::new())] {
            env.home = value.clone();
            env.xdg_config_home = value;
            assert_eq!(
                env.git_global_paths(|_, _| panic!("unexpected notice")),
                (b"".as_slice(), b"".as_slice())
            );
        }
        let max = bingsu_core::layout::PATH_BYTES_MAX;
        for name in ["HOME", "XDG_CONFIG_HOME"] {
            for (value, reason) in [
                (b"relative".to_vec(), Some("is not an absolute path")),
                (b"~/.config".to_vec(), Some("is not an absolute path")),
                (b"/nul\0path".to_vec(), Some("contains NUL")),
                (b"/home ' $(literal)\n\xff".to_vec(), None),
            ]
            .into_iter()
            .chain([max - 1, max, max + 1, 70_000].map(|length| {
                let mut value = vec![b'x'; length];
                value[0] = b'/';
                (value, (length > max).then_some("exceeds 65536 bytes"))
            })) {
                env.home = Some(OsString::from("/home"));
                env.xdg_config_home = Some(OsString::from("/xdg"));
                let slot = if name == "HOME" {
                    &mut env.home
                } else {
                    &mut env.xdg_config_home
                };
                *slot = Some(OsStr::from_bytes(&value).to_owned());
                let mut notices = Vec::new();
                let pins = env.git_global_paths(|name, reason| notices.push((name, reason)));
                let expected = if reason.is_some() {
                    b"!invalid".as_slice()
                } else {
                    &value
                };
                assert_eq!(
                    pins,
                    if name == "HOME" {
                        (expected, b"/xdg".as_slice())
                    } else {
                        (b"/home".as_slice(), expected)
                    }
                );
                assert_eq!(
                    notices,
                    reason.map(|r| (name, r)).into_iter().collect::<Vec<_>>()
                );
            }
        }
        env.home = Some(OsString::from("relative"));
        env.xdg_config_home = Some(OsString::from("~/.config"));
        let mut notices = Vec::new();
        assert_eq!(
            env.git_global_paths(|n, r| notices.push((n, r))),
            (b"!invalid".as_slice(), b"!invalid".as_slice())
        );
        assert_eq!(
            notices,
            [
                ("HOME", "is not an absolute path"),
                ("XDG_CONFIG_HOME", "is not an absolute path")
            ]
        );
    }
}
