//! Roots pinned by init (spec section 4 "runtime root"): create missing
//! folders and secure the final folder, then judge the retained no-follow
//! chain with the same rules as the helper (including local file system).
use super::trusted_env::TrustedEnv;
use crate::commands::{
    group_policy::{Recording, SystemGroups},
    runtime_root, sys,
};
use bingsu_core::fs_trust::{GroupOracle, GroupPin, Refusal};
use std::ffi::OsString;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};

pub struct RuntimeRootPin {
    pub dev: u64,
    pub ino: u64,
    pub path: PathBuf,
    /// Ancestors whose group write was cleared by this walk (P-R1/S-8).
    /// N4 carries these pins to the front end, which never asks the system.
    pub group_ok: Vec<GroupPin>,
}

/// `None`: the path could not be confirmed; config also requires the
/// written path's trust evidence. Init omits that root word and warns.
/// After environment decoding, `log` and `runtime.group_ok` are untrusted
/// environment claims: re-check the log path and group policy before any use.
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
    /// Trust ceiling for every file under the root (user decision
    /// 2026-10-17, R3 I-1). `true`: the only refusals in the root's chain
    /// are `Undecided` (group members, ACL or ownership enforcement could
    /// not be confirmed), so the root is kept for colors and layout but
    /// nothing under it is `Executable`, the `config use` record included.
    /// Any other refusal (another user's link, a folder others can write)
    /// still drops the root.
    pub shape_only: bool,
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
                    // `refusal` is the first refusal only; an `Undecided`
                    // one can hide a later `Ancestor` or `Last`, so the
                    // whole chain is judged again with undecidable facts
                    // read as decided.
                    let shape_only = match evidence.refusal {
                        None => {
                            evidence.revalidate(me, groups)?;
                            false
                        }
                        Some(Refusal::Undecided { .. }) => {
                            evidence.revalidate_assuming_decided(me, groups)?;
                            true
                        }
                        Some(_) => {
                            return Err(std::io::Error::other("untrusted config root path"));
                        }
                    };
                    let mut path = evidence.canonical.clone();
                    path.extend(missing.iter().rev());
                    return Ok(Self {
                        path,
                        written: written.to_path_buf(),
                        evidence,
                        shape_only,
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
    /// `shape_only`: init's `--config-root-shape-only` mark. It can only
    /// lower trust: a root init marked stays shape-only even when its chain
    /// is clean now, and a root that turned undecidable since becomes
    /// shape-only here.
    pub fn reopen(
        written: &Path,
        canonical: &Path,
        shape_only: bool,
        me: u32,
        groups: &mut dyn bingsu_core::fs_trust::GroupOracle,
    ) -> std::io::Result<Self> {
        let mut pin = Self::check(written, me, groups)?;
        if pin.path != canonical {
            return Err(std::io::Error::other("config root target changed"));
        }
        pin.shape_only |= shape_only;
        Ok(pin)
    }

    /// Init's stderr lines for a shape-only root: what happens, then the
    /// cause at the first undecided folder.
    pub fn shape_only_notice(&self) -> Option<[String; 2]> {
        use crate::commands::messages::{MsgId, en};
        if !self.shape_only {
            return None;
        }
        let at = self.evidence.blocked_path.as_deref().unwrap_or(&self.path);
        Some([
            en(MsgId::ShapeOnlyConfigRoot).to_owned(),
            format!(
                "bingsu: {}",
                undecided_cause(at, self.evidence.facts_at(at).as_ref())
            ),
        ])
    }
}

/// Why `at` could not be decided, in `entry_verdict`'s order, with
/// `chmod g-w` where group write is the cause (unconfirmed members, or a
/// POSIX ACL mask that allows group write). The path is shell-quoted and
/// the resulting display text is sanitized; hook arguments keep the original bytes.
fn undecided_cause(at: &Path, facts: Option<&bingsu_core::fs_trust::Facts>) -> String {
    use bingsu_core::fs_trust::AclFacts;
    let mut q = Vec::new();
    bingsu_core::shell_word::encode_word(
        bingsu_core::shell_word::Shell::Bash,
        at.as_os_str().as_encoded_bytes(),
        &mut q,
    );
    let quoted = String::from_utf8_lossy(&q);
    let cause = match facts {
        Some(f) if f.ownership != Some(true) => {
            format!("could not confirm that the volume holding {quoted} enforces file ownership")
        }
        Some(f) if f.acl == AclFacts::Unknown => {
            format!("could not read the access list of {quoted}")
        }
        Some(f) if f.mode & 0o020 != 0 => crate::commands::group_policy::undecided_remedy(at),
        _ => format!("could not confirm who can change {quoted}"),
    };
    bingsu_core::sanitize::sanitize(cause.as_bytes())
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
    let mut path = base;
    path.extend(&names);
    path.push(last);
    let mut groups = Recording::new(groups);
    let chain = runtime_root::create_private(&path, uid, &mut groups)?;
    let md = chain.last().metadata()?;
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

/// The written config root before any check (`$XDG_CONFIG_HOME/bingsu`).
pub fn config_candidate(env: &TrustedEnv, home: &Path) -> PathBuf {
    abs(&env.xdg_config_home)
        .unwrap_or_else(|| home.join(".config"))
        .join("bingsu")
}

/// The canonical state root, which may not exist yet.
pub fn state_root(env: &TrustedEnv, home: &Path) -> Option<PathBuf> {
    canonical_lenient(
        &abs(&env.xdg_state_home)
            .unwrap_or_else(|| home.join(".local").join("state"))
            .join("bingsu"),
    )
}

pub fn resolve(env: &TrustedEnv, home: &Path, user: &[u8]) -> Roots {
    let state = state_root(env, home);
    Roots {
        runtime: pin(&runtime_candidate(env, home), user).ok(),
        config: ConfigRootPin::check(
            &config_candidate(env, home),
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
        private_dirs(base.join("config/bingsu")).unwrap();
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
                false,
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
        private_dirs(&written).unwrap();
        assert!(ConfigRootPin::reopen(&pin.written, &pin.path, false, me, &mut groups).is_ok());
        std::fs::remove_dir(&written).unwrap();
        std::os::unix::fs::symlink(base.join("absent"), &written).unwrap();
        assert!(ConfigRootPin::check(&written, me, &mut groups).is_err());
        assert!(ConfigRootPin::check(&base.join("absent/../elsewhere"), me, &mut groups).is_err());
        std::fs::remove_dir_all(base).unwrap();
    }

    /// Group members unknown for the listed folders only; any other group
    /// write is another user's.
    struct UnknownAt(Vec<(u64, u64)>);
    impl GroupOracle for UnknownAt {
        fn group_write(
            &mut self,
            at: &bingsu_core::fs_trust::Facts,
        ) -> bingsu_core::fs_trust::Group {
            if self.0.contains(&(at.dev, at.ino)) {
                bingsu_core::fs_trust::Group::Unknown
            } else {
                bingsu_core::fs_trust::Group::HasOthers
            }
        }
    }

    fn unknown_at(paths: &[&Path]) -> UnknownAt {
        UnknownAt(
            paths
                .iter()
                .map(|p| {
                    let md = std::fs::metadata(p).unwrap();
                    (md.dev(), md.ino())
                })
                .collect(),
        )
    }

    fn mode(p: &Path, m: u32) {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(m)).unwrap();
    }

    // 사용자 결정(2026-10-17, R3 I-1): 그룹 구성원을 확정하지 못한 뿌리(Undecided)는 모양 전용으로 남기고,
    // 남이 쓸 수 있는 것으로 확정된 뿌리(Last)와 조상(Ancestor)은 지금처럼 버린다.
    // 이것을 실패시키는 것: Undecided 뿌리를 버리는 것(모양 전용 분기 삭제), Last·Ancestor 거부를 모양 전용으로
    // 받아 주는 것(`Some(_)` 분기를 모양 전용으로 바꾸기).
    #[test]
    fn undecided_root_is_kept_shape_only_and_others_are_dropped() {
        let base = std::fs::canonicalize(scratch("shape-only-root")).unwrap();
        let root = base.join("cfg/bingsu");
        private_dirs(&root).unwrap();
        let me = sys::current_uid();
        mode(&root, 0o775);
        let pin = ConfigRootPin::check(&root, me, &mut unknown_at(&[&root])).unwrap();
        assert!(pin.shape_only);
        assert_eq!(pin.path, root);
        let clean = ConfigRootPin::check(&root, me, &mut unknown_at(&[])).err();
        assert!(clean.is_some(), "group write by others is Last, dropped");
        mode(&root, 0o777);
        assert!(ConfigRootPin::check(&root, me, &mut unknown_at(&[&root])).is_err());
        mode(&root, 0o755);
        let full = ConfigRootPin::check(&root, me, &mut unknown_at(&[])).unwrap();
        assert!(!full.shape_only);
        mode(&base.join("cfg"), 0o777);
        assert!(ConfigRootPin::check(&root, me, &mut unknown_at(&[&root])).is_err());
        mode(&base.join("cfg"), 0o755);
        std::fs::remove_dir_all(base).unwrap();
    }

    // Resolved는 첫 거부만 남긴다. 조상이 Undecided여도 그 아래 뿌리를 남이 쓸 수 있으면(0777) 버려야 한다.
    // 이것을 실패시키는 것: 첫 거부의 종류만 보고 모양 전용으로 정하는 것
    // (`revalidate_assuming_decided` 대신 검사 없이 통과시키기).
    #[test]
    fn undecided_ancestor_does_not_hide_a_writable_root() {
        let base = std::fs::canonicalize(scratch("shape-only-mask")).unwrap();
        let home = base.join("cfg");
        let root = home.join("bingsu");
        private_dirs(&root).unwrap();
        let me = sys::current_uid();
        mode(&home, 0o775);
        mode(&root, 0o755);
        let pin = ConfigRootPin::check(&root, me, &mut unknown_at(&[&home])).unwrap();
        assert!(pin.shape_only);
        assert!(matches!(
            pin.evidence.refusal,
            Some(Refusal::Undecided { .. })
        ));
        mode(&root, 0o777);
        let r =
            crate::commands::source_path::Resolved::open_dir(&root, me, &mut unknown_at(&[&home]))
                .unwrap();
        assert!(
            matches!(r.refusal, Some(Refusal::Undecided { .. })),
            "masked"
        );
        assert!(ConfigRootPin::check(&root, me, &mut unknown_at(&[&home])).is_err());
        mode(&home, 0o755);
        std::fs::remove_dir_all(base).unwrap();
    }

    // 표식은 신뢰를 낮추기만 한다: init이 표시한 뿌리는 지금 깨끗해도 모양 전용, 지금 판정 불가면 표식이 없어도 모양 전용.
    // 이것을 실패시키는 것: reopen에서 표식을 버리는 것(`|=` 줄 삭제), 표식으로 덮어써 신뢰를 올리는 것(`=`).
    #[test]
    fn reopen_mark_only_lowers_trust() {
        let base = std::fs::canonicalize(scratch("shape-only-reopen")).unwrap();
        let root = base.join("bingsu");
        private_dirs(&root).unwrap();
        let me = sys::current_uid();
        mode(&root, 0o755);
        let marked = ConfigRootPin::reopen(&root, &root, true, me, &mut unknown_at(&[])).unwrap();
        assert!(marked.shape_only);
        mode(&root, 0o775);
        let now =
            ConfigRootPin::reopen(&root, &root, false, me, &mut unknown_at(&[&root])).unwrap();
        assert!(now.shape_only);
        std::fs::remove_dir_all(base).unwrap();
    }

    // 이것을 실패시키는 것: 원인 표시의 정제를 빼서 경로의 제어 문자가 터미널에 도달하는 것.
    #[test]
    fn shape_only_cause_sanitizes_every_path_branch() {
        use bingsu_core::fs_trust::{AclFacts, Facts};
        use std::os::unix::ffi::OsStrExt;
        let at = Path::new(std::ffi::OsStr::from_bytes(
            b"/h/a'\x1b\n\r\t\x7f\xc2\x9b\xe2\x80\xae\xff b",
        ));
        let facts = Facts {
            dev: 1,
            ino: 2,
            uid: 501,
            gid: 20,
            mode: 0o040775,
            acl: AclFacts::None,
            ownership: Some(true),
        };
        for f in [
            None,
            Some(facts),
            Some(Facts {
                ownership: None,
                ..facts
            }),
            Some(Facts {
                acl: AclFacts::Unknown,
                ..facts
            }),
            Some(Facts {
                mode: 0o040755,
                ..facts
            }),
        ] {
            let cause = undecided_cause(at, f.as_ref());
            assert!(
                !cause.chars().any(|c| c.is_control() || c == '\u{202e}'),
                "{cause:?}"
            );
            assert!(cause.contains("/h/a"), "{cause:?}");
            assert!(cause.contains("\u{fffd} b'"), "{cause:?}");
        }
    }

    // init 안내: 고정 문구 한 줄과 원인 한 줄. 그룹 쓰기가 원인일 때만 `chmod g-w`를 붙인다.
    // 이것을 실패시키는 것: 소유권·ACL 미확인에도 chmod g-w를 안내하는 것(분기 순서 바꾸기), 그룹 원인에서 빼는 것,
    // 모양 전용이 아닌 뿌리에도 안내하는 것.
    #[test]
    fn shape_only_notice_names_the_cause() {
        use bingsu_core::fs_trust::{AclFacts, Facts};
        let at = Path::new("/h/a b/.config");
        let f = Facts {
            dev: 1,
            ino: 2,
            uid: 501,
            gid: 20,
            mode: 0o040775,
            acl: AclFacts::None,
            ownership: Some(true),
        };
        assert_eq!(
            undecided_cause(at, Some(&f)),
            "group membership could not be confirmed; chmod g-w '/h/a b/.config'"
        );
        let posix = Facts {
            acl: AclFacts::PosixExtended,
            ..f
        };
        assert!(undecided_cause(at, Some(&posix)).contains("chmod g-w"));
        for odd in [
            Facts {
                ownership: None,
                ..f
            },
            Facts {
                acl: AclFacts::Unknown,
                ..f
            },
            Facts {
                mode: 0o040755,
                ..f
            },
        ] {
            let c = undecided_cause(at, Some(&odd));
            assert!(!c.contains("chmod"), "{c}");
            assert!(c.contains("'/h/a b/.config'"), "{c}");
        }
        assert!(undecided_cause(at, None).contains("'/h/a b/.config'"));

        let base = std::fs::canonicalize(scratch("shape-only-notice")).unwrap();
        let root = base.join("bingsu");
        private_dirs(&root).unwrap();
        let me = sys::current_uid();
        mode(&root, 0o775);
        let pin = ConfigRootPin::check(&root, me, &mut unknown_at(&[&root])).unwrap();
        let [what, why] = pin.shape_only_notice().unwrap();
        assert_eq!(
            what,
            crate::commands::messages::en(crate::commands::messages::MsgId::ShapeOnlyConfigRoot)
        );
        assert_eq!(
            why,
            format!(
                "bingsu: {}",
                crate::commands::group_policy::undecided_remedy(&root)
            )
        );
        mode(&root, 0o755);
        let full = ConfigRootPin::check(&root, me, &mut unknown_at(&[])).unwrap();
        assert!(full.shape_only_notice().is_none());
        std::fs::remove_dir_all(base).unwrap();
    }

    // 이것을 실패시키는 것: 없는 이름을 버리거나, 있는 상위 폴더의 symlink를 풀지 않는 것.
    #[test]
    fn canonical_lenient_resolves_existing_part_only() {
        let base = std::env::temp_dir().join(format!("bingsu-lenient-{}", std::process::id()));
        let real = base.join("real");
        private_dirs(&real).unwrap();
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
        private_dirs(&elsewhere).unwrap();
        private_dirs(&state).unwrap();
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

    // 이것을 실패시키는 것: 시험 폴더를 기본 mode로 만들어 umask 002에서 그룹 쓰기 조상을 남기는 것.
    fn private_dirs(path: impl AsRef<Path>) -> std::io::Result<()> {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(path)
    }

    fn scratch(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("bingsu-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        private_dirs(&d).unwrap();
        d
    }

    // A ".." after a missing name: `missing` may later be created as a
    // symlink, so the kernel's answer is unknown now. Without ".." the
    // missing names are kept as they are (control row).
    // 이것을 실패시키는 것: 없는 구간의 `..`를 어휘적으로 접어 추측한 경로를 박는 것.
    #[test]
    fn canonical_lenient_refuses_dotdot_after_missing_names() {
        let base = scratch("lenient-dotdot");
        private_dirs(base.join("deep/a/b")).unwrap();
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
        private_dirs(&loose).unwrap();
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
        private_dirs(base.join("real_a/b")).unwrap();
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
        private_dirs(lk.join("run")).unwrap();
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
        private_dirs(&gw).unwrap();
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
