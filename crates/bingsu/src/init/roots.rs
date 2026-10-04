//! Roots pinned by init (spec section 4 "runtime root"). M1 creates the
//! runtime folder and pins (st_dev, st_ino); ancestor rules, ownership and
//! the local-filesystem check are M3a.
use super::trusted_env::TrustedEnv;
use std::ffi::OsString;
use std::os::unix::fs::{DirBuilderExt, MetadataExt};
use std::path::{Path, PathBuf};

pub struct RuntimeRootPin {
    pub dev: u64,
    pub ino: u64,
    pub path: PathBuf,
}

pub struct Roots {
    pub runtime: Option<RuntimeRootPin>,
    pub config: PathBuf,
    pub state: PathBuf,
    pub log: PathBuf,
}

fn abs(v: &Option<OsString>) -> Option<PathBuf> {
    v.as_ref().map(PathBuf::from).filter(|p| p.is_absolute())
}

pub fn runtime_candidate(env: &TrustedEnv, home: &Path) -> PathBuf {
    match abs(&env.xdg_runtime_dir) {
        Some(d) => d.join("bingsu"),
        None => abs(&env.xdg_cache_home)
            .unwrap_or_else(|| home.join(".cache"))
            .join("bingsu")
            .join("run"),
    }
}

/// Creates the folder (0700) if missing. A concurrent creator is fine:
/// recursive creation treats an existing directory as success.
pub fn pin(candidate: &Path) -> std::io::Result<RuntimeRootPin> {
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(candidate)?;
    let path = std::fs::canonicalize(candidate)?;
    let md = std::fs::metadata(&path)?;
    if !md.is_dir() {
        return Err(std::io::Error::other("runtime root is not a directory"));
    }
    Ok(RuntimeRootPin {
        dev: md.dev(),
        ino: md.ino(),
        path,
    })
}

/// Canonical form of a path that may not exist yet: canonicalize the deepest
/// existing ancestor and append the remaining names unchanged.
pub fn canonical_lenient(p: &Path) -> PathBuf {
    let mut rest = Vec::new();
    let mut cur = p;
    loop {
        if let Ok(c) = std::fs::canonicalize(cur) {
            return rest
                .iter()
                .rev()
                .fold(c, |acc: PathBuf, n: &&std::ffi::OsStr| acc.join(n));
        }
        match (cur.parent(), cur.file_name()) {
            (Some(parent), Some(name)) => {
                rest.push(name);
                cur = parent;
            }
            _ => return p.to_path_buf(),
        }
    }
}

pub fn resolve(env: &TrustedEnv, home: &Path) -> Roots {
    let state = canonical_lenient(
        &abs(&env.xdg_state_home)
            .unwrap_or_else(|| home.join(".local").join("state"))
            .join("bingsu"),
    );
    Roots {
        runtime: pin(&runtime_candidate(env, home)).ok(),
        config: canonical_lenient(
            &abs(&env.xdg_config_home)
                .unwrap_or_else(|| home.join(".config"))
                .join("bingsu"),
        ),
        log: canonical_lenient(&state.join("log")),
        state,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(rt: Option<&str>, cache: Option<&str>) -> TrustedEnv {
        TrustedEnv {
            path: None,
            xdg_runtime_dir: rt.map(OsString::from),
            xdg_config_home: None,
            xdg_state_home: None,
            xdg_cache_home: cache.map(OsString::from),
        }
    }

    // 이것을 실패시키는 것: 없는 이름을 버리거나, 있는 상위 폴더의 symlink를 풀지 않는 것.
    #[test]
    fn canonical_lenient_resolves_existing_part_only() {
        let base = std::env::temp_dir().join(format!("bingsu-lenient-{}", std::process::id()));
        let real = base.join("real");
        std::fs::create_dir_all(&real).unwrap();
        let link = base.join("link");
        let _ = std::fs::remove_file(&link);
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let got = canonical_lenient(&link.join("bingsu").join("log"));
        assert_eq!(
            got,
            std::fs::canonicalize(&real)
                .unwrap()
                .join("bingsu")
                .join("log")
        );
        std::fs::remove_dir_all(&base).unwrap();
    }

    // 이것을 실패시키는 것: 로그 뿌리를 정규화한 상태 뿌리에 이름만 붙이는 것(이미 있는 `log`가
    // symlink면 실제로 쓰는 곳은 다른 폴더다).
    #[test]
    fn log_root_resolves_symlinked_log_dir() {
        let base = std::env::temp_dir().join(format!("bingsu-logroot-{}", std::process::id()));
        let elsewhere = base.join("elsewhere");
        let state = base.join("state").join("bingsu");
        std::fs::create_dir_all(&elsewhere).unwrap();
        std::fs::create_dir_all(&state).unwrap();
        std::os::unix::fs::symlink(&elsewhere, state.join("log")).unwrap();
        let e = TrustedEnv {
            xdg_state_home: Some(base.join("state").into_os_string()),
            ..env(None, None)
        };
        let roots = resolve(&e, &base.join("home"));
        assert_eq!(roots.log, std::fs::canonicalize(&elsewhere).unwrap());
        assert_eq!(roots.state, std::fs::canonicalize(&state).unwrap());
        std::fs::remove_dir_all(&base).unwrap();
    }

    // 이것을 실패시키는 것: 후보 순서를 바꾸거나 상대 경로를 받아 주는 것.
    #[test]
    fn candidate_order() {
        let h = Path::new("/home/u");
        assert_eq!(
            runtime_candidate(&env(Some("/run/user/1"), Some("/c")), h),
            Path::new("/run/user/1/bingsu")
        );
        assert_eq!(
            runtime_candidate(&env(None, Some("/c")), h),
            Path::new("/c/bingsu/run")
        );
        assert_eq!(
            runtime_candidate(&env(Some("rel"), None), h),
            Path::new("/home/u/.cache/bingsu/run")
        );
        assert_eq!(
            runtime_candidate(&env(None, Some("rel")), h),
            Path::new("/home/u/.cache/bingsu/run")
        );
    }
}
