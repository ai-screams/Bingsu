//! A private home for the user commands (`reload`, `config …`, `init`):
//! settings, runtime, state and cache folders under CARGO_TARGET_TMPDIR (not
//! /tmp, so no world-writable ancestor makes the roots untrusted), and the
//! binary run with an empty environment plus exactly those four XDG values.
//! Shared by `#[path]`; not a test target itself.
#![allow(dead_code)] // each test binary uses its own subset

use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

pub struct Env {
    pub base: PathBuf,
}

pub fn chmod(p: &Path, mode: u32) {
    std::fs::set_permissions(p, std::fs::Permissions::from_mode(mode)).unwrap();
}

impl Env {
    /// `config/bingsu` exists (0700); runtime, state and cache are left to
    /// the commands, as on a fresh machine.
    pub fn new(suite: &str, tag: &str) -> Self {
        let base = Path::new(env!("CARGO_TARGET_TMPDIR")).join(suite).join(tag);
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        chmod(&base, 0o755);
        let env = Self {
            base: std::fs::canonicalize(&base).unwrap(),
        };
        std::fs::create_dir_all(env.config_dir()).unwrap();
        chmod(&env.base.join("cfg"), 0o700);
        chmod(&env.config_dir(), 0o700);
        env
    }

    pub fn config_dir(&self) -> PathBuf {
        self.base.join("cfg/bingsu")
    }

    pub fn state_dir(&self) -> PathBuf {
        self.base.join("state/bingsu")
    }

    /// Writes a file (0600) below the base, making its folders (0700).
    pub fn put(&self, rel: &str, text: &str) -> PathBuf {
        let p = self.base.join(rel);
        let parent = p.parent().unwrap();
        if !parent.exists() {
            std::fs::create_dir_all(parent).unwrap();
            chmod(parent, 0o700);
        }
        let _ = std::fs::remove_file(&p);
        std::fs::write(&p, text).unwrap();
        chmod(&p, 0o600);
        p
    }

    pub fn put_config(&self, rel: &str, text: &str) -> PathBuf {
        self.put(&format!("cfg/bingsu/{rel}"), text)
    }

    pub fn cmd(&self, args: &[&str]) -> Command {
        let mut c = Command::new(env!("CARGO_BIN_EXE_bingsu"));
        c.args(args)
            .current_dir(&self.base)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("XDG_RUNTIME_DIR", self.base.join("run"))
            .env("XDG_CONFIG_HOME", self.base.join("cfg"))
            .env("XDG_STATE_HOME", self.base.join("state"))
            .env("XDG_CACHE_HOME", self.base.join("cache"));
        c
    }

    pub fn run(&self, args: &[&str]) -> Output {
        self.cmd(args).output().unwrap()
    }

    /// The one context folder (it holds `snapshot.lock`) below the runtime root.
    pub fn context_dir(&self) -> PathBuf {
        fn find(dir: &Path) -> Option<PathBuf> {
            for e in std::fs::read_dir(dir).ok()? {
                let p = e.ok()?.path();
                if p.file_name().is_some_and(|n| n == "snapshot.lock") {
                    return p.parent().map(Path::to_path_buf);
                }
                if p.is_dir()
                    && let Some(found) = find(&p)
                {
                    return Some(found);
                }
            }
            None
        }
        find(&self.base.join("run")).expect("a context folder")
    }

    /// Every file and folder below the base with what a write would change:
    /// kind, mode, size, inode, modification time (ns) and link target.
    pub fn tree(&self) -> Vec<String> {
        fn walk(dir: &Path, base: &Path, out: &mut Vec<String>) {
            let mut names: Vec<_> = std::fs::read_dir(dir)
                .unwrap()
                .map(|e| e.unwrap().path())
                .collect();
            names.sort();
            for p in names {
                let md = std::fs::symlink_metadata(&p).unwrap();
                out.push(format!(
                    "{} {:o} {} {} {}.{}",
                    p.strip_prefix(base).unwrap().display(),
                    md.mode(),
                    md.len(),
                    md.ino(),
                    md.mtime(),
                    md.mtime_nsec()
                ));
                if md.is_dir() {
                    walk(&p, base, out);
                }
            }
        }
        let mut out = Vec::new();
        walk(&self.base, &self.base, &mut out);
        out
    }
}

pub fn text(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

/// The one-line notice the commands print when no pinned roots came from an
/// init in this shell (the tests run without one unless they say so).
pub const FALLBACK_NOTICE: &str = "bingsu: the folders were found from the environment now";

/// stderr without that notice.
pub fn quiet(stderr: &[u8]) -> String {
    text(stderr)
        .lines()
        .filter(|l| !l.starts_with(FALLBACK_NOTICE))
        .map(|l| format!("{l}\n"))
        .collect()
}

fn account_home() -> PathBuf {
    use std::os::unix::ffi::OsStrExt;
    // SAFETY: getuid has no preconditions.
    let uid = unsafe { libc::getuid() };
    // SAFETY: getpwuid returns null or a pointer to a static passwd that stays valid until the next lookup.
    let pw = unsafe { libc::getpwuid(uid) };
    assert!(!pw.is_null());
    // SAFETY: pw is non-null, so reading its pw_dir field is valid.
    let raw = unsafe { (*pw).pw_dir };
    // SAFETY: pw_dir is a NUL-terminated string that outlives this call.
    let dir = unsafe { std::ffi::CStr::from_ptr(raw) };
    let home = dir.to_bytes().to_vec();
    PathBuf::from(std::ffi::OsStr::from_bytes(&home))
}

pub fn frame(words: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::new();
    for w in words {
        out.extend_from_slice(format!("{}:", w.len()).as_bytes());
        out.extend_from_slice(w);
    }
    out
}

impl Env {
    /// The root words init would hand the hook for this home (the runtime
    /// root is made, 0700, as init does).
    pub fn pinned_words(&self) -> Vec<Vec<u8>> {
        use std::os::unix::ffi::OsStrExt;
        let run = self.base.join("run/bingsu");
        std::fs::create_dir_all(&run).unwrap();
        chmod(&self.base.join("run"), 0o700);
        chmod(&run, 0o700);
        let md = std::fs::metadata(&run).unwrap();
        let w = |prefix: &str, p: &[u8]| [prefix.as_bytes(), p].concat();
        vec![
            w(
                "--runtime-root=",
                format!("{}:{}:{}", md.dev(), md.ino(), run.display()).as_bytes(),
            ),
            b"--runtime-groups=1".to_vec(),
            w("--config-root=", self.config_dir().as_os_str().as_bytes()),
            w(
                "--config-root-written=",
                self.config_dir().as_os_str().as_bytes(),
            ),
            w("--state-root=", self.state_dir().as_os_str().as_bytes()),
            w("--home=", account_home().as_os_str().as_bytes()),
        ]
    }

    /// A command that has the variable and XDG values that point elsewhere.
    pub fn cmd_pinned(&self, args: &[&str], var: &[u8]) -> Command {
        use std::os::unix::ffi::OsStrExt;
        let elsewhere = self.base.join("elsewhere");
        let mut c = self.cmd(args);
        c.env("BINGSU_ROOTS", std::ffi::OsStr::from_bytes(var))
            .env("XDG_RUNTIME_DIR", elsewhere.join("run"))
            .env("XDG_CONFIG_HOME", elsewhere.join("cfg"))
            .env("XDG_STATE_HOME", elsewhere.join("state"))
            .env("XDG_CACHE_HOME", elsewhere.join("cache"));
        c
    }
}
