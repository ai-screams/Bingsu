//! Roots pinned by init (spec section 4 "runtime root"): create missing
//! folders and secure the final folder, then judge the retained no-follow
//! chain with the same rules as the helper (including local file system).
use super::trusted_env::TrustedEnv;
use crate::commands::{
    group_policy::{Recording, SystemGroups},
    runtime_root, sys,
};
use bingsu_core::fs_trust::{GroupOracle, GroupPin};
use std::ffi::OsString;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};

pub struct RuntimeRootPin {
    pub dev: u64,
    pub ino: u64,
    pub path: PathBuf,
    /// Ancestors whose group write was cleared by this walk (P-R1/S-8).
    /// N4 carries these pins to the front end, which never asks the system.
    #[cfg_attr(not(test), expect(dead_code, reason = "N4 hook hand-off"))]
    pub group_ok: Vec<GroupPin>,
}

/// `None`: the path could not be confirmed; config also requires the
/// written path's trust evidence. Init omits that root word and warns.
pub struct Roots {
    pub runtime: Option<RuntimeRootPin>,
    pub config: Option<ConfigRootPin>,
    pub state: Option<PathBuf>,
    pub log: Option<PathBuf>,
}

/// Config trust is a checked written path, never a canonical path alone.
/// The helper receives both paths and calls `reopen`; descriptors are kept
/// in-process through Loader::verified, not serialized into a shell word.
pub struct ConfigRootPin {
    pub path: PathBuf,
    pub written: PathBuf,
    pub evidence: crate::commands::source_path::Resolved,
}

impl ConfigRootPin {
    pub fn check(
        written: &Path,
        me: u32,
        groups: &mut dyn bingsu_core::fs_trust::GroupOracle,
    ) -> std::io::Result<Self> {
        let mut prefix = written.to_path_buf();
        let mut missing = Vec::new();
        loop {
            match crate::commands::source_path::Resolved::open_dir(&prefix, me, groups) {
                Ok(evidence) => {
                    if evidence.refusal.is_some() {
                        return Err(std::io::Error::other("untrusted config root path"));
                    }
                    evidence.revalidate(me, groups)?;
                    let mut path = evidence.canonical.clone();
                    path.extend(missing.iter().rev());
                    return Ok(Self {
                        path,
                        written: written.to_path_buf(),
                        evidence,
                    });
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    // A dangling link is not a missing name. Never erase it
                    // from the checked prefix, or simplify a missing `..`.
                    if std::fs::symlink_metadata(&prefix).is_ok() {
                        return Err(e);
                    }
                    match prefix.components().next_back() {
                        Some(Component::Normal(name)) => missing.push(name.to_os_string()),
                        _ => return Err(e),
                    }
                    prefix.pop();
                }
                Err(e) => return Err(e),
            }
        }
    }

    /// N2 rebuilds the trust evidence from the original spelling and must
    /// compare the result with init's canonical pin before loading sources.
    #[cfg_attr(not(test), expect(dead_code, reason = "Part N2 hand-off"))]
    pub fn reopen(
        written: &Path,
        canonical: &Path,
        me: u32,
        groups: &mut dyn bingsu_core::fs_trust::GroupOracle,
    ) -> std::io::Result<Self> {
        let pin = Self::check(written, me, groups)?;
        if pin.path != canonical {
            return Err(std::io::Error::other("config root target changed"));
        }
        Ok(pin)
    }
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

/// Pins the runtime folder (spec section 4 "runtime root"). The parent's
/// existing part is canonicalized and opened by a no-follow walk from "/"
/// (`runtime_root::open_chain`); every
/// missing folder below it, and the last folder, is created with `mkdirat`
/// and opened with `openat(O_NOFOLLOW)` relative to the folder above, so a
/// symlink in their place is refused, never followed. Through each
/// descriptor the owner must be the current user and the mode becomes
/// exactly 0700 (the creation mode is masked by umask, and an existing
/// last folder may be looser); the last folder must also be on a local file
/// system, checked before its mode is touched. `dev` and `ino` come from
/// the last descriptor; `path` is the canonical parent plus the names
/// opened. Any failure means no runtime root, and the folders this call
/// created are removed again.
pub fn pin(candidate: &Path, user: &[u8]) -> std::io::Result<RuntimeRootPin> {
    pin_for(candidate, sys::current_uid(), &mut SystemGroups::new(user))
}

fn pin_for(
    candidate: &Path,
    uid: u32,
    groups: &mut dyn GroupOracle,
) -> std::io::Result<RuntimeRootPin> {
    use std::os::fd::{AsFd, AsRawFd};
    use std::os::unix::fs::PermissionsExt;
    let bad = |what: &str| std::io::Error::other(format!("runtime root: {what}"));
    let (Some(parent), Some(last)) = (candidate.parent(), candidate.file_name()) else {
        return Err(bad("no folder name"));
    };
    let comps: Vec<Component<'_>> = parent.components().collect();
    let (base, missing) = (1..=comps.len())
        .rev()
        .find_map(|k| {
            let prefix: PathBuf = comps[..k].iter().collect();
            std::fs::canonicalize(prefix).ok().map(|c| (c, &comps[k..]))
        })
        .ok_or_else(|| bad("no existing parent"))?;
    // Every name to create must be a plain name, checked before creating
    // anything (`miss/../r4` would otherwise leave `miss` behind).
    let names: Vec<&std::ffi::OsStr> = missing
        .iter()
        .map(|c| match c {
            Component::Normal(n) => Ok(*n),
            _ => Err(bad("unexpected path component")),
        })
        .collect::<std::io::Result<_>>()?;
    // Keep the existing prefix and every created child's descriptors until
    // the same chain is judged and its parent/name connections rechecked.
    // `created` lists (holding descriptor index, name) for rollback.
    let mut chain = runtime_root::open_chain(&base).map_err(|e| bad(&format!("{e:?}")))?;
    let mut groups = Recording::new(groups);
    let mut created: Vec<(usize, std::ffi::OsString)> = Vec::new();
    let result = (|| {
        let mut owned_child = |chain: &[std::fs::File], name: &std::ffi::OsStr| {
            let holder = chain.len() - 1;
            if sys::mkdir_at(chain[holder].as_fd(), name, 0o700)? {
                created.push((holder, name.to_os_string()));
            }
            let child = sys::open_dir_at_nofollow(chain[holder].as_fd(), name)?;
            if child.metadata()?.uid() != uid {
                return Err(bad("owned by another user"));
            }
            Ok(child)
        };
        for name in &names {
            let child = owned_child(&chain.fds, name)?;
            child.set_permissions(std::fs::Permissions::from_mode(0o700))?;
            chain.facts.push(sys::fd_facts(child.as_fd())?);
            chain.names.push(name.to_os_string());
            chain.fds.push(child);
        }
        let root = owned_child(&chain.fds, last)?;
        if sys::fd_is_local(root.as_raw_fd()) != Some(true) {
            return Err(bad("not on a local file system"));
        }
        root.set_permissions(std::fs::Permissions::from_mode(0o700))?;
        chain.facts.push(sys::fd_facts(root.as_fd())?);
        chain.names.push(last.to_os_string());
        chain.fds.push(root);
        runtime_root::judge(&chain, uid, &mut groups).map_err(|e| bad(&format!("{e:?}")))?;
        chain.revalidate()?;
        Ok(())
    })();
    match result {
        Ok(()) => {}
        Err(e) => {
            // Undo what this call made, deepest first. Folders that already
            // existed are not touched; a folder another process filled in
            // the meantime is not empty and stays.
            for (holder, name) in created.iter().rev() {
                let _ = sys::remove_dir_at(chain.fds[*holder].as_fd(), name);
            }
            return Err(e);
        }
    };
    let md = chain.last().metadata()?;
    let mut path = base;
    path.extend(&names);
    path.push(last);
    Ok(RuntimeRootPin {
        dev: md.dev(),
        ino: md.ino(),
        path,
        group_ok: groups.cleared,
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

pub fn resolve(env: &TrustedEnv, home: &Path, user: &[u8]) -> Roots {
    let state = canonical_lenient(
        &abs(&env.xdg_state_home)
            .unwrap_or_else(|| home.join(".local").join("state"))
            .join("bingsu"),
    );
    Roots {
        runtime: pin(&runtime_candidate(env, home), user).ok(),
        config: ConfigRootPin::check(
            &abs(&env.xdg_config_home)
                .unwrap_or_else(|| home.join(".config"))
                .join("bingsu"),
            sys::current_uid(),
            &mut SystemGroups::new(user),
        )
        .ok(),
        log: state
            .as_ref()
            .and_then(|s| canonical_lenient(&s.join("log"))),
        state,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bingsu_core::fs_trust::RefuseGroupWrite;

    fn env(rt: Option<&str>, cache: Option<&str>) -> TrustedEnv {
        TrustedEnv {
            path: None,
            xdg_runtime_dir: rt.map(OsString::from),
            xdg_config_home: None,
            xdg_state_home: None,
            xdg_cache_home: cache.map(OsString::from),
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    // 이것을 실패시키는 것: 다른 사용자가 심은 설정 뿌리 링크를 정규화만 하고 승인하는 것.
    #[ignore = "requires an eve-owned root link in victim's config home"]
    fn two_user_planted_config_root() {
        let me = crate::commands::sys::current_uid();
        assert_ne!(me, 0);
        let pw = crate::commands::sys::passwd_entry(me).unwrap();
        assert_eq!(pw.name, b"victim");
        let e = env(None, None);
        assert!(resolve(&e, &pw.home, &pw.name).config.is_none());
    }

    // 실제 root 소유 접두 링크도 원래 이름의 증거를 남기고 init을 통과해야 한다.
    #[cfg(target_os = "macos")]
    // 이것을 실패시키는 것: root가 보호하는 조상 링크도 사용자 링크로 판정해 거부하는 것.
    #[test]
    fn root_owned_ancestor_link_is_accepted() {
        let link = Path::new("/tmp");
        let md = std::fs::symlink_metadata(link).unwrap();
        assert!(md.file_type().is_symlink());
        assert_eq!(md.uid(), 0);
        assert_ne!(crate::commands::sys::current_uid(), 0);
        let base = link.join(format!("bingsu-root-ancestor-{}", std::process::id()));
        std::fs::create_dir_all(base.join("config/bingsu")).unwrap();
        let pw = crate::commands::sys::passwd_entry(crate::commands::sys::current_uid()).unwrap();
        let e = TrustedEnv {
            xdg_config_home: Some(base.join("config").into_os_string()),
            xdg_runtime_dir: Some(base.join("run").into_os_string()),
            ..env(None, None)
        };
        let pin = resolve(&e, &base, &pw.name)
            .config
            .expect("a protected root-owned ancestor must not discard the config root");
        assert_eq!(pin.written, base.join("config/bingsu"));
        assert_eq!(pin.path, std::fs::canonicalize(&pin.written).unwrap());
        assert!(pin.evidence.retains_link(link));
        assert!(
            ConfigRootPin::reopen(
                &pin.written,
                &pin.path,
                crate::commands::sys::current_uid(),
                &mut bingsu_core::fs_trust::RefuseGroupWrite,
            )
            .is_ok()
        );
        std::fs::remove_dir_all(base).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    // 이것을 실패시키는 것: root가 보호하는 접두 링크를 거부하거나 그 증거를 잃는 것.
    #[ignore = "requires the root-owned /srv/partr-home ancestor link from Linux case F"]
    fn root_owned_ancestor_link_is_accepted() {
        let me = crate::commands::sys::current_uid();
        assert_ne!(me, 0);
        let pw = crate::commands::sys::passwd_entry(me).unwrap();
        assert_eq!(pw.name, b"victim");
        let link = Path::new("/srv/partr-home");
        let md = std::fs::symlink_metadata(link).unwrap();
        assert!(md.file_type().is_symlink());
        assert_eq!(md.uid(), 0);
        let home = link.join("victim");
        let pin = resolve(&env(None, None), &home, &pw.name)
            .config
            .expect("a protected root-owned ancestor must not discard the config root");
        assert_eq!(pin.written, home.join(".config/bingsu"));
        assert_eq!(pin.path, std::fs::canonicalize(&pin.written).unwrap());
        assert!(pin.evidence.retains_link(link));
        pin.evidence
            .revalidate(me, &mut bingsu_core::fs_trust::RefuseGroupWrite)
            .unwrap();
    }

    // 본인 소유 링크여도 남이 바꿀 수 있는 부모는 C1 검사에서 거부해야 한다.
    // 이것을 실패시키는 것: 사용자 설정 뿌리 링크의 부모 검사를 우회하는 것.
    #[test]
    fn user_planted_config_root_link_is_rejected() {
        use std::os::unix::fs::PermissionsExt;
        let base = std::fs::canonicalize(scratch("user-root-link")).unwrap();
        let config_home = base.join("config");
        let target = base.join("repo");
        std::fs::create_dir(&config_home).unwrap();
        std::fs::create_dir(&target).unwrap();
        let link = config_home.join("bingsu");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let me = crate::commands::sys::current_uid();
        let pw = crate::commands::sys::passwd_entry(me).unwrap();
        assert_eq!(std::fs::symlink_metadata(&link).unwrap().uid(), me);
        let e = TrustedEnv {
            xdg_config_home: Some(config_home.clone().into_os_string()),
            xdg_runtime_dir: Some(base.join("run").into_os_string()),
            ..env(None, None)
        };
        std::fs::set_permissions(&config_home, std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(resolve(&e, &base, &pw.name).config.is_none());
        std::fs::set_permissions(&config_home, std::fs::Permissions::from_mode(0o755)).unwrap();
        let pin = resolve(&e, &base, &pw.name).config.unwrap();
        assert_eq!(pin.path, target);
        assert!(pin.evidence.retains_link(&link));
        std::fs::set_permissions(&config_home, std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(
            pin.evidence
                .revalidate(me, &mut bingsu_core::fs_trust::RefuseGroupWrite)
                .is_err()
        );
        std::fs::remove_dir_all(base).unwrap();
    }

    // 이것을 실패시키는 것: 없는 뿌리의 안전한 접두 증거를 잃거나 끊어진 링크·미해석 ..를 허용하는 것.
    #[test]
    fn config_pin_keeps_checked_prefix_for_missing_roots() {
        let base = std::fs::canonicalize(scratch("missing-config")).unwrap();
        let written = base.join("missing/bingsu");
        let me = crate::commands::sys::current_uid();
        let mut groups = bingsu_core::fs_trust::RefuseGroupWrite;
        let pin = ConfigRootPin::check(&written, me, &mut groups).unwrap();
        assert_eq!(pin.path, written);
        assert_eq!(pin.evidence.canonical, base);
        std::fs::create_dir_all(&written).unwrap();
        assert!(ConfigRootPin::reopen(&pin.written, &pin.path, me, &mut groups).is_ok());
        std::fs::remove_dir(&written).unwrap();
        std::os::unix::fs::symlink(base.join("absent"), &written).unwrap();
        assert!(ConfigRootPin::check(&written, me, &mut groups).is_err());
        assert!(ConfigRootPin::check(&base.join("absent/../elsewhere"), me, &mut groups).is_err());
        std::fs::remove_dir_all(base).unwrap();
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
        let roots = resolve(&e, &base.join("home"), b"unused");
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
        let me = sys::current_uid();
        let loose = base.join("loose");
        std::fs::create_dir_all(&loose).unwrap();
        std::fs::set_permissions(&loose, std::fs::Permissions::from_mode(0o755)).unwrap();
        let got = pin_for(&loose, me, &mut RefuseGroupWrite).unwrap();
        assert_eq!(std::fs::metadata(&got.path).unwrap().mode() & 0o7777, 0o700);
        assert!(
            pin_for(
                &base.join("other"),
                me.wrapping_add(1),
                &mut RefuseGroupWrite
            )
            .is_err()
        );
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
            eprintln!(
                "skipped: an autofs mount on /System/Volumes/Data/home not present on this host"
            );
            return;
        }
        let err = pin_for(
            Path::new("/System/Volumes/Data/home"),
            0,
            &mut RefuseGroupWrite,
        )
        .err()
        .expect("must refuse");
        assert!(err.to_string().contains("local file system"), "{err}");
    }

    // The walk must refuse a symlink anywhere in the path: after
    // canonicalization there is none, so one found now was swapped in.
    // 이것을 실패시키는 것: 걷기에서 O_NOFOLLOW를 빼는 것(symlink를 따라감).
    #[test]
    fn canonical_walk_refuses_symlinked_component() {
        let base = std::fs::canonicalize(scratch("walk")).unwrap();
        std::fs::create_dir_all(base.join("real_a/b")).unwrap();
        std::os::unix::fs::symlink(base.join("real_a"), base.join("a")).unwrap();
        assert!(runtime_root::open_chain(&base.join("real_a/b")).is_ok());
        assert!(runtime_root::open_chain(&base.join("a/b")).is_err());
        std::fs::remove_dir_all(&base).unwrap();
    }

    // A failure after creating folders removes them again; folders that
    // already existed stay.
    // 이것을 실패시키는 것: 실패 때 만든 폴더를 되돌리지 않는 것.
    #[test]
    fn failed_pin_removes_the_folders_it_created() {
        let base = scratch("rollback");
        let me = sys::current_uid();
        assert!(
            pin_for(
                &base.join("x/y/bingsu"),
                me.wrapping_add(1),
                &mut RefuseGroupWrite
            )
            .is_err()
        );
        assert!(!base.join("x").exists());
        assert!(base.exists());
        assert!(pin_for(&base.join("x/y/bingsu"), me, &mut RefuseGroupWrite).is_ok());
        assert!(base.join("x/y/bingsu").is_dir());
        std::fs::remove_dir_all(&base).unwrap();
    }

    // Two missing folders are made (`n1`, `n2`), then the last `mkdirat`
    // fails on a name longer than NAME_MAX (255 on Linux and macOS). Undoing
    // must go deepest first: removing `n1` while `n2` is still inside fails
    // with ENOTEMPTY and leaves `n1` behind.
    // 이것을 실패시키는 것: rollback에서 `.rev()`를 빼는 것(`n1`이 남는다).
    #[test]
    fn failed_pin_removes_created_folders_deepest_first() {
        let base = scratch("rollback-order");
        let me = sys::current_uid();
        let too_long = "x".repeat(256);
        let err = pin_for(
            &base.join("n1/n2").join(&too_long),
            me,
            &mut RefuseGroupWrite,
        )
        .err()
        .expect("a 256-byte name must fail");
        assert_eq!(err.raw_os_error(), Some(libc::ENAMETOOLONG), "{err}");
        assert!(!base.join("n1/n2").exists());
        assert!(!base.join("n1").exists());
        assert!(base.exists());
        std::fs::remove_dir_all(&base).unwrap();
    }

    // An ancestor with search (x) but no read (r) permission, like a shared
    // host's `/home` at 0711, must not stop the walk. Not meaningful as
    // root, which ignores the mode.
    // 이것을 실패시키는 것: 걷기 fd를 O_RDONLY로 여는 것(0111 조상에서 EACCES).
    #[test]
    fn pin_walks_through_search_only_ancestor() {
        use std::os::unix::fs::PermissionsExt;
        let base = scratch("search-only");
        let me = sys::current_uid();
        let lk = base.join("lk");
        std::fs::create_dir_all(lk.join("run")).unwrap();
        std::fs::set_permissions(lk.join("run"), std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::set_permissions(&lk, std::fs::Permissions::from_mode(0o111)).unwrap();
        let got = pin_for(&lk.join("run"), me, &mut RefuseGroupWrite);
        std::fs::set_permissions(&lk, std::fs::Permissions::from_mode(0o700)).unwrap();
        let got = got.expect("x-only ancestor must not lose the runtime root");
        assert_eq!(got.path, std::fs::canonicalize(lk.join("run")).unwrap());
        std::fs::remove_dir_all(&base).unwrap();
    }

    // init도 상위 폴더 규칙을 건다(스펙 4절 "런타임 뿌리" 2): 그룹 쓰기 상위 폴더는 판정 P-R1의 oracle이 정한다.
    // 이것을 실패시키는 것: init의 pin이 기존 상위 폴더를 보지 않는 것, 거부 뒤 만든 폴더를 남기는 것,
    // 승인한 조상을 기록하지 않는 것, 앞단이 dev·ino·gid·mode가 다른 그룹 pin을 받는 것.
    #[test]
    fn pin_applies_rule_2_to_existing_ancestors() {
        use std::os::unix::fs::PermissionsExt;
        let base = scratch("gw-ancestor");
        let me = sys::current_uid();
        let gw = base.join("gw");
        std::fs::create_dir_all(&gw).unwrap();
        std::fs::set_permissions(&gw, std::fs::Permissions::from_mode(0o775)).unwrap();
        let got = pin_for(
            &gw.join("bingsu"),
            me,
            &mut bingsu_core::fs_trust::RefuseGroupWrite,
        );
        assert!(got.is_err());
        assert!(!gw.join("bingsu").exists());
        struct Cleared;
        impl bingsu_core::fs_trust::GroupOracle for Cleared {
            fn group_write(
                &mut self,
                _: &bingsu_core::fs_trust::Facts,
            ) -> bingsu_core::fs_trust::Group {
                bingsu_core::fs_trust::Group::OnlyRootAndUser
            }
        }
        // init clears it and pins it for the front end (P-R1, S-8).
        let pin = pin_for(&gw.join("bingsu"), me, &mut Cleared).unwrap();
        let gw_md = std::fs::metadata(&gw).unwrap();
        assert_eq!(
            pin.group_ok
                .iter()
                .map(|p| (p.dev, p.ino, p.gid, p.mode))
                .collect::<Vec<_>>(),
            [(gw_md.dev(), gw_md.ino(), gw_md.gid(), gw_md.mode())]
        );
        let root = runtime_root::Pinned {
            dev: pin.dev,
            ino: pin.ino,
            path: pin.path,
        };
        use bingsu_core::fs_trust::PinnedGroupWrite;
        assert!(
            runtime_root::open_runtime_root(&root, me, &mut PinnedGroupWrite(&pin.group_ok))
                .is_ok()
        );
        assert!(runtime_root::open_runtime_root(&root, me, &mut PinnedGroupWrite(&[])).is_err());
        let ok = pin.group_ok[0];
        for wrong in [
            GroupPin {
                dev: ok.dev.wrapping_add(1),
                ..ok
            },
            GroupPin {
                ino: ok.ino.wrapping_add(1),
                ..ok
            },
            GroupPin {
                gid: ok.gid.wrapping_add(1),
                ..ok
            },
            GroupPin {
                mode: ok.mode ^ 0o100,
                ..ok
            },
        ] {
            assert!(
                runtime_root::open_runtime_root(&root, me, &mut PinnedGroupWrite(&[wrong]))
                    .is_err()
            );
        }
        std::fs::remove_dir_all(&base).unwrap();
    }

    // 이것을 실패시키는 것: 그룹 조회 뒤 pin을 반환하기 전에 같은 fd·부모 이름을 재확인하지 않는 것.
    #[test]
    fn pin_rechecks_the_chain_after_group_queries() {
        use bingsu_core::fs_trust::{Facts, Group};
        use std::os::unix::fs::PermissionsExt;
        struct ReplaceParent(PathBuf);
        impl GroupOracle for ReplaceParent {
            fn group_write(&mut self, _: &Facts) -> Group {
                std::fs::rename(&self.0, self.0.with_file_name("moved")).unwrap();
                std::fs::create_dir(&self.0).unwrap();
                Group::OnlyRootAndUser
            }
        }
        let base = scratch("pin-recheck");
        let parent = base.join("group");
        std::fs::create_dir(&parent).unwrap();
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o775)).unwrap();
        let result = pin_for(
            &parent.join("new/run"),
            sys::current_uid(),
            &mut ReplaceParent(parent.clone()),
        );
        assert!(result.is_err());
        assert!(!base.join("moved/new").exists());
        assert!(parent.is_dir());
        std::fs::remove_dir_all(base).unwrap();
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
