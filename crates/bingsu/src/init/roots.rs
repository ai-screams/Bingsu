//! Roots pinned by init (spec section 4 "runtime root"). M1 creates the
//! runtime folder and pins (st_dev, st_ino); ancestor rules, ownership and
//! the local-filesystem check are M3a.
use super::trusted_env::TrustedEnv;
use std::ffi::OsString;
use std::os::unix::fs::{DirBuilderExt, MetadataExt};
use std::path::{Component, Path, PathBuf};

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

/// Creates the folder if missing (a concurrent creator is fine: recursive
/// creation treats an existing directory as success), then opens it without
/// following a symlink and, through that descriptor, checks the owner, sets
/// the mode to exactly 0700 (the creation mode is masked by umask, and an
/// existing folder may be looser) and checks that it is on a local file
/// system. Any failure means no runtime root. The last folder must belong
/// to the current user (spec section 4 "runtime root"; ancestor rules are
/// M3a).
pub fn pin(candidate: &Path) -> std::io::Result<RuntimeRootPin> {
    pin_for(candidate, crate::sys::current_uid())
}

fn pin_for(candidate: &Path, uid: u32) -> std::io::Result<RuntimeRootPin> {
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(candidate)?;
    let path = std::fs::canonicalize(candidate)?;
    let dir = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(&path)?;
    if dir.metadata()?.uid() != uid {
        return Err(std::io::Error::other(
            "runtime root is owned by another user",
        ));
    }
    if crate::sys::fd_is_local(dir.as_raw_fd()) != Some(true) {
        return Err(std::io::Error::other(
            "runtime root is not on a local file system",
        ));
    }
    dir.set_permissions(std::fs::Permissions::from_mode(0o700))?;
    // O_DIRECTORY made it a directory; fchmod succeeded, so the mode is 0700.
    let md = dir.metadata()?;
    Ok(RuntimeRootPin {
        dev: md.dev(),
        ino: md.ino(),
        path,
    })
}

/// Canonical form of a path that may not exist yet: canonicalize the
/// longest existing prefix, then add the remaining names with "." dropped
/// and ".." taking off the previous name (lexically: those names do not
/// exist, so no symlink can sit there). If that brings back a name that
/// does exist (`a/missing/../link`), the result is canonicalized again the
/// same way; the second pass has no "..", so it ends.
pub fn canonical_lenient(p: &Path) -> PathBuf {
    let once = |p: &Path| -> PathBuf {
        let comps: Vec<Component<'_>> = p.components().collect();
        for k in (1..=comps.len()).rev() {
            let prefix: PathBuf = comps[..k].iter().collect();
            if let Ok(mut out) = std::fs::canonicalize(&prefix) {
                for c in &comps[k..] {
                    match c {
                        Component::Normal(n) => out.push(n),
                        Component::ParentDir => {
                            out.pop();
                        }
                        _ => {}
                    }
                }
                return out;
            }
        }
        p.to_path_buf()
    };
    let first = once(p);
    if first == p { first } else { once(&first) }
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

    fn scratch(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("bingsu-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    // 이것을 실패시키는 것: 없는 상위 폴더 뒤의 `..`를 풀지 않거나(`missing/..`가 그대로 박힘),
    // `..`로 되돌아온 이미 있는 symlink를 풀지 않는 것.
    #[test]
    fn canonical_lenient_folds_dotdot_after_missing_names() {
        let base = scratch("lenient-dotdot");
        let real = base.join("real");
        std::fs::create_dir_all(&real).unwrap();
        std::os::unix::fs::symlink(&real, base.join("link")).unwrap();
        let canon = std::fs::canonicalize(&base).unwrap();
        assert_eq!(
            canonical_lenient(&base.join("missing/../cfgx")),
            canon.join("cfgx")
        );
        assert_eq!(
            canonical_lenient(&base.join("missing/./x/../../link/b")),
            canon.join("real/b")
        );
        std::fs::remove_dir_all(&base).unwrap();
    }

    // 이것을 실패시키는 것: 소유자 검사를 빼는 것, 0700으로 맞추지 않는 것(umask 0177이면 0600이 됨).
    #[test]
    fn pin_checks_owner_and_forces_0700() {
        use std::os::unix::fs::PermissionsExt;
        let base = scratch("pin");
        let me = crate::sys::current_uid();
        let loose = base.join("loose");
        std::fs::create_dir_all(&loose).unwrap();
        std::fs::set_permissions(&loose, std::fs::Permissions::from_mode(0o755)).unwrap();
        let got = pin_for(&loose, me).unwrap();
        assert_eq!(std::fs::metadata(&got.path).unwrap().mode() & 0o7777, 0o700);
        assert!(pin_for(&base.join("other"), me.wrapping_add(1)).is_err());
        std::fs::remove_dir_all(&base).unwrap();
    }

    // /home is an autofs mount point owned by root. With uid 0 the owner
    // check passes, so the refusal must come from the file-system check
    // (without it, fchmod would fail with a permission error instead).
    // 이것을 실패시키는 것: 런타임 폴더의 로컬 파일 시스템 검사를 빼는 것.
    #[cfg(target_os = "macos")]
    #[test]
    fn pin_refuses_non_local_file_system() {
        let mount = std::process::Command::new("/sbin/mount").output().unwrap();
        if !String::from_utf8_lossy(&mount.stdout).contains(" on /System/Volumes/Data/home (autofs")
        {
            eprintln!("skip: /System/Volumes/Data/home is not an autofs mount here");
            return;
        }
        let err = pin_for(Path::new("/home"), 0).err().expect("must refuse");
        assert!(err.to_string().contains("local file system"), "{err}");
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
