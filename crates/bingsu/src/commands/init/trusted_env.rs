//! The one function in this crate that reads the environment. Only `init`
//! calls it: init runs at a trusted moment and pins what it finds into the
//! hook (spec section 4 "runtime root" 1 and 7, F-01). The prompt path
//! never reads the environment (crates/bingsu/clippy.toml).
use std::ffi::OsString;

pub struct TrustedEnv {
    pub path: Option<OsString>,
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
            xdg_runtime_dir: std::env::var_os("XDG_RUNTIME_DIR"),
            xdg_config_home: std::env::var_os("XDG_CONFIG_HOME"),
            xdg_state_home: std::env::var_os("XDG_STATE_HOME"),
            xdg_cache_home: std::env::var_os("XDG_CACHE_HOME"),
        }
    }
}
