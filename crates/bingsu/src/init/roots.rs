//! Roots pinned by init (spec section 4 "runtime root"). M1 creates the
//! runtime folder and pins (st_dev, st_ino); ancestor rules, ownership and
//! the local-filesystem check are M3a.
use super::trusted_env::TrustedEnv;
use std::ffi::OsString;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};

pub struct RuntimeRootPin {
    pub dev: u64,
    pub ino: u64,
    pub path: PathBuf,
}

/// `None` for config, state or log: the path could not be confirmed (see
/// `canonical_lenient`); init then leaves that word out and warns.
pub struct Roots {
    pub runtime: Option<RuntimeRootPin>,
    pub config: Option<PathBuf>,
    pub state: Option<PathBuf>,
    pub log: Option<PathBuf>,
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

/// Pins the runtime folder (spec section 4 "runtime root"; ancestor rules
/// are M3a). The parent's existing part is canonicalized and opened; every
/// missing folder below it, and the last folder, is created with `mkdirat`
/// and opened with `openat(O_NOFOLLOW)` relative to the folder above, so a
/// symlink in their place is refused, never followed. Through each
/// descriptor the owner must be the current user and the mode becomes
/// exactly 0700 (the creation mode is masked by umask, and an existing
/// last folder may be looser); the last folder must also be on a local file
/// system, checked before its mode is touched. `dev` and `ino` come from
/// the last descriptor; `path` is the canonical parent plus the names
/// opened. Any failure means no runtime root.
pub fn pin(candidate: &Path) -> std::io::Result<RuntimeRootPin> {
    pin_for(candidate, crate::sys::current_uid())
}

fn pin_for(candidate: &Path, uid: u32) -> std::io::Result<RuntimeRootPin> {
    use std::os::fd::{AsFd, AsRawFd};
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let bad = |what: &str| std::io::Error::other(format!("runtime root: {what}"));
    let (Some(parent), Some(last)) = (candidate.parent(), candidate.file_name()) else {
        return Err(bad("no folder name"));
    };
    let comps: Vec<Component<'_>> = parent.components().collect();
    let (mut path, missing) = (1..=comps.len())
        .rev()
        .find_map(|k| {
            let prefix: PathBuf = comps[..k].iter().collect();
            std::fs::canonicalize(prefix).ok().map(|c| (c, &comps[k..]))
        })
        .ok_or_else(|| bad("no existing parent"))?;
    let mut dir = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY)
        .open(&path)?;
    let owned_child = |dir: &std::fs::File, name: &std::ffi::OsStr| {
        crate::sys::mkdir_at(dir.as_fd(), name, 0o700)?;
        let child = crate::sys::open_dir_at_nofollow(dir.as_fd(), name)?;
        if child.metadata()?.uid() != uid {
            return Err(bad("owned by another user"));
        }
        Ok(child)
    };
    for c in missing {
        let Component::Normal(name) = c else {
            return Err(bad("unexpected path component"));
        };
        let child = owned_child(&dir, name)?;
        child.set_permissions(std::fs::Permissions::from_mode(0o700))?;
        path.push(name);
        dir = child;
    }
    let root = owned_child(&dir, last)?;
    if crate::sys::fd_is_local(root.as_raw_fd()) != Some(true) {
        return Err(bad("not on a local file system"));
    }
    root.set_permissions(std::fs::Permissions::from_mode(0o700))?;
    let md = root.metadata()?;
    path.push(last);
    Ok(RuntimeRootPin {
        dev: md.dev(),
        ino: md.ino(),
        path,
    })
}

/// Canonical form of a path that may not exist yet: canonicalize the
/// longest existing prefix and append the remaining names. Those names do
/// not exist now, but by the time they do any of them may be a symlink, so
/// a ".." among them cannot be resolved ahead of the kernel: such a path
/// gives `None` (not pinned, warned) rather than a guess.
pub fn canonical_lenient(p: &Path) -> Option<PathBuf> {
    let comps: Vec<Component<'_>> = p.components().collect();
    for k in (1..=comps.len()).rev() {
        let prefix: PathBuf = comps[..k].iter().collect();
        if let Ok(mut out) = std::fs::canonicalize(&prefix) {
            for c in &comps[k..] {
                match c {
                    Component::Normal(n) => out.push(n),
                    Component::CurDir => {}
                    _ => return None,
                }
            }
            return Some(out);
        }
    }
    None
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
        log: state
            .as_ref()
            .and_then(|s| canonical_lenient(&s.join("log"))),
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
        let got = canonical_lenient(&link.join("bingsu").join("log")).unwrap();
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
        assert_eq!(roots.log, Some(std::fs::canonicalize(&elsewhere).unwrap()));
        assert_eq!(roots.state, Some(std::fs::canonicalize(&state).unwrap()));
        std::fs::remove_dir_all(&base).unwrap();
    }

    fn scratch(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("bingsu-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    // A ".." after a missing name: `missing` may later be created as a
    // symlink, so the kernel's answer is unknown now. Without ".." the
    // missing names are kept as they are (control row).
    // 이것을 실패시키는 것: 없는 구간의 `..`를 어휘적으로 접어 추측한 경로를 박는 것.
    #[test]
    fn canonical_lenient_refuses_dotdot_after_missing_names() {
        let base = scratch("lenient-dotdot");
        std::fs::create_dir_all(base.join("deep/a/b")).unwrap();
        std::os::unix::fs::symlink(base.join("deep/a/b"), base.join("lnk")).unwrap();
        let canon = std::fs::canonicalize(&base).unwrap();
        assert_eq!(canonical_lenient(&base.join("missing/../lnk/../x")), None);
        assert_eq!(canonical_lenient(&base.join("missing/../cfgx")), None);
        assert_eq!(
            canonical_lenient(&base.join("missing/x")),
            Some(canon.join("missing/x"))
        );
        assert_eq!(
            canonical_lenient(&base.join("lnk/../x")),
            Some(canon.join("deep/a/x"))
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

    // /System/Volumes/Data/home is an autofs mount point owned by root. With uid 0 the owner
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
        let err = pin_for(Path::new("/System/Volumes/Data/home"), 0)
            .err()
            .expect("must refuse");
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
