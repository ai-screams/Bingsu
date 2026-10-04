//! Fixed executable path policy (spec section 5 "connection", decision 2;
//! spec section 2 safety row and decision 6 review for group write).
use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

/// Worse verdicts compare greater: Safe < Unknown < Tamperable.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Verdict {
    Safe,
    Unknown,
    Tamperable,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Group {
    OnlyRootAndUser,
    HasOthers,
    Unknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(
    all(not(target_os = "macos"), not(test)),
    expect(
        dead_code,
        reason = "only the macOS ACL reader yields DenyOnly and AllowsWrite"
    )
)]
pub enum AclFacts {
    None,
    DenyOnly,
    AllowsWrite,
    Unknown,
}

/// One extended ACL entry as read on macOS.
#[cfg(any(target_os = "macos", test))]
#[derive(Clone, Copy, Debug)]
pub enum AclEntry {
    /// `writes`: grants write, append, delete, delete-child, attribute,
    /// extended-attribute, security or ownership change.
    Allow {
        writes: bool,
    },
    Deny,
}

/// Folds the entries of one ACL. `Err` marks an ACL call that failed or an
/// entry of a kind we do not know; the ACL then counts as unread (fail
/// closed), unless an earlier entry already allowed writing.
#[cfg(any(target_os = "macos", test))]
pub fn fold_acl(entries: impl IntoIterator<Item = Result<AclEntry, ()>>) -> AclFacts {
    let mut facts = AclFacts::None;
    for e in entries {
        match e {
            Err(()) => return AclFacts::Unknown,
            Ok(AclEntry::Allow { writes: true }) => return AclFacts::AllowsWrite,
            Ok(AclEntry::Allow { writes: false }) => {}
            Ok(AclEntry::Deny) => facts = AclFacts::DenyOnly,
        }
    }
    facts
}

/// The executable must live on a local file system (spec section 4,
/// macOS executable row: not `MNT_LOCAL` is refused; init only warns).
pub fn local_verdict(local: Option<bool>) -> Verdict {
    match local {
        Some(true) => Verdict::Safe,
        Some(false) => Verdict::Tamperable,
        None => Verdict::Unknown,
    }
}

#[derive(Clone, Copy, Debug)]
pub struct EntryFacts {
    pub uid: u32,
    pub gid: u32,
    pub mode: u32,
    pub is_symlink: bool,
    pub acl: AclFacts,
}

/// The path the user ran, without resolving the last symlink: pinning the
/// canonical target breaks open shells when a package manager removes the
/// old version folder. A relative PATH entry (".", or an empty one) met
/// before the match gives `None`: the shell would have searched it relative
/// to its own working folder, which init cannot see, so the caller falls
/// back to the resolved executable and says so.
pub fn invocation_path(argv0: &OsStr, path_env: Option<&OsStr>, cwd: &Path) -> Option<PathBuf> {
    let p = Path::new(argv0);
    if argv0.as_bytes().contains(&b'/') {
        return Some(if p.is_absolute() {
            p.to_path_buf()
        } else {
            cwd.join(p)
        });
    }
    for d in std::env::split_paths(path_env?) {
        if !d.is_absolute() {
            return None;
        }
        let c = d.join(p);
        if std::fs::metadata(&c).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0) {
            return Some(c);
        }
    }
    None
}

/// Pure rule for one path entry (table in Task A7).
pub fn classify(e: &EntryFacts, uid: u32, group: &dyn Fn(u32) -> Group) -> Verdict {
    if e.uid != 0 && e.uid != uid {
        return Verdict::Tamperable;
    }
    let acl = match e.acl {
        AclFacts::AllowsWrite => Verdict::Tamperable,
        AclFacts::Unknown => Verdict::Unknown,
        AclFacts::None | AclFacts::DenyOnly => Verdict::Safe,
    };
    if e.is_symlink {
        return acl; // a symlink's own mode bits are not used
    }
    let mode = if e.mode & 0o002 != 0 {
        Verdict::Tamperable
    } else if e.mode & 0o020 != 0 {
        match group(e.gid) {
            Group::OnlyRootAndUser => Verdict::Safe,
            Group::HasOthers => Verdict::Tamperable,
            Group::Unknown => Verdict::Unknown,
        }
    } else {
        Verdict::Safe
    };
    mode.max(acl)
}

fn facts(p: &Path) -> Option<EntryFacts> {
    let m = std::fs::symlink_metadata(p).ok()?;
    Some(EntryFacts {
        uid: m.uid(),
        gid: m.gid(),
        mode: m.mode(),
        is_symlink: m.file_type().is_symlink(),
        acl: crate::sys::acl_facts(p),
    })
}

/// The same bound Linux uses for one path lookup (MAXSYMLINKS = 40).
const MAX_SYMLINK_HOPS: usize = 40;

/// Every entry the kernel passes through to reach `exe`, resolving it one
/// name at a time: "/", each folder entered, each symlink on the way (any
/// hop of a chain, in any component) and the final file. Each symlink and
/// each target sits in a folder that is itself on the list, so this covers
/// "the symlink, its target and every ancestor folder" (spec section 4)
/// for every hop. `None` if a name cannot be inspected, a link cannot be
/// read, the path is relative, or the chain exceeds `MAX_SYMLINK_HOPS`.
/// The second value is the resolved final file.
fn resolution_entries(exe: &Path) -> Option<(Vec<PathBuf>, PathBuf)> {
    use std::path::Component;
    if !exe.is_absolute() {
        return None;
    }
    let root = PathBuf::from("/");
    let mut seen = vec![root.clone()];
    let mut cur = root.clone();
    // Names still to resolve, last name first so `pop` takes the next one.
    let mut todo: Vec<std::ffi::OsString> = Vec::new();
    let push_front = |todo: &mut Vec<std::ffi::OsString>, p: &Path| {
        let names: Vec<_> = p
            .components()
            .filter_map(|c| match c {
                Component::Normal(n) => Some(n.to_os_string()),
                Component::ParentDir => Some("..".into()),
                _ => None,
            })
            .collect();
        todo.extend(names.into_iter().rev());
    };
    push_front(&mut todo, exe);
    let mut hops = 0;
    while let Some(name) = todo.pop() {
        if name == ".." {
            // `cur` is always a resolved folder, so its lexical parent is
            // the physical parent.
            cur.pop();
            continue;
        }
        let next = cur.join(&name);
        let md = std::fs::symlink_metadata(&next).ok()?;
        if !seen.contains(&next) {
            seen.push(next.clone());
        }
        if md.file_type().is_symlink() {
            hops += 1;
            if hops > MAX_SYMLINK_HOPS {
                return None;
            }
            let target = std::fs::read_link(&next).ok()?;
            if target.is_absolute() {
                cur = root.clone();
            }
            push_front(&mut todo, &target);
        } else {
            cur = next;
        }
    }
    Some((seen, cur))
}

/// Worst verdict over every entry on the way to the executable: the path
/// as run, each symlink hop and its target, and every folder above any of
/// them, plus the final file's file system. Anything that cannot be
/// inspected is `Unknown` (fail closed).
///
/// The checks go by path (`symlink_metadata`, `acl_get_link_np`), not by an
/// open descriptor, so a change between this check and a later run is not
/// caught. init only warns; checking by descriptor and running what was
/// checked belongs to the command paths of M3 and M6.
pub fn check_path(exe: &Path, uid: u32, user: &[u8]) -> Verdict {
    let Some((paths, target)) = resolution_entries(exe) else {
        return Verdict::Unknown;
    };
    // One verdict per gid for the whole walk: Homebrew paths cross several
    // group-writable folders of the same group (`bin`, `Cellar`).
    // The account list is read once, and only if some folder is group
    // writable.
    let cache = std::cell::RefCell::new(std::collections::HashMap::<u32, Group>::new());
    let users = std::cell::OnceCell::new();
    let group = |gid: u32| {
        *cache.borrow_mut().entry(gid).or_insert_with(|| {
            let users = users.get_or_init(crate::sys::local_users);
            crate::sys::group_membership(gid, user, users.as_deref())
        })
    };
    paths
        .iter()
        .map(|p| facts(p).map_or(Verdict::Unknown, |f| classify(&f, uid, &group)))
        .chain([local_verdict(crate::sys::fs_is_local(&target))])
        .max()
        .unwrap_or(Verdict::Unknown)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ME: u32 = 501;

    // 이것을 실패시키는 것: ACL 호출 오류나 모르는 항목을 "항목 없음"으로 읽는 것(fail-open).
    #[test]
    fn acl_errors_are_unknown() {
        use AclEntry::{Allow, Deny};
        let rows: &[(&[Result<AclEntry, ()>], AclFacts)] = &[
            (&[], AclFacts::None),
            (&[Ok(Deny)], AclFacts::DenyOnly),
            (&[Ok(Allow { writes: false })], AclFacts::None),
            (
                &[Ok(Deny), Ok(Allow { writes: true })],
                AclFacts::AllowsWrite,
            ),
            (&[Err(())], AclFacts::Unknown),
            (&[Ok(Deny), Err(())], AclFacts::Unknown),
            (&[Ok(Allow { writes: false }), Err(())], AclFacts::Unknown),
        ];
        for (entries, want) in rows {
            assert_eq!(fold_acl(entries.iter().copied()), *want, "{entries:?}");
        }
    }

    // 이것을 실패시키는 것: 로컬이 아닌 파일 시스템이나 statfs 실패를 안전으로 보는 것.
    #[test]
    fn non_local_file_system_is_not_safe() {
        assert_eq!(local_verdict(Some(true)), Verdict::Safe);
        assert_eq!(local_verdict(Some(false)), Verdict::Tamperable);
        assert_eq!(local_verdict(None), Verdict::Unknown);
    }

    // /home -> /System/Volumes/Data/home is an autofs mount point: owned by
    // root, no write bits, no ACL, so only the file system makes it unsafe.
    // 이것을 실패시키는 것: check_path가 최종 대상의 파일 시스템을 보지 않는 것.
    #[cfg(target_os = "macos")]
    #[test]
    fn final_target_on_non_local_file_system_is_tamperable() {
        let mount = std::process::Command::new("/sbin/mount").output().unwrap();
        if !String::from_utf8_lossy(&mount.stdout).contains(" on /System/Volumes/Data/home (autofs")
        {
            eprintln!("skip: /System/Volumes/Data/home is not an autofs mount here");
            return;
        }
        let me = crate::sys::current_uid();
        let name = crate::sys::passwd_entry(me).unwrap().name;
        assert_eq!(
            check_path(Path::new("/home"), me, &name),
            Verdict::Tamperable
        );
    }

    // 이것을 실패시키는 것: 없는 그룹을 "구성원 없음"으로 보는 것.
    #[test]
    fn missing_group_is_unknown() {
        let users = crate::sys::local_users();
        assert_eq!(
            crate::sys::group_membership(u32::MAX - 7, b"nobody-here", users.as_deref()),
            Group::Unknown
        );
    }

    // init only passes absolute paths; a relative one would be walked from
    // "/" and check the wrong entries.
    // 이것을 실패시키는 것: 상대 경로 가드를 빼는 것.
    #[test]
    fn relative_path_cannot_be_inspected() {
        assert_eq!(resolution_entries(Path::new("usr/bin")), None);
        assert!(resolution_entries(Path::new("/usr/bin")).is_some());
    }

    fn e(uid: u32, mode: u32, is_symlink: bool, acl: AclFacts) -> EntryFacts {
        EntryFacts {
            uid,
            gid: 80,
            mode,
            is_symlink,
            acl,
        }
    }

    // One row per rule in the Task A7 table. 이것을 실패시키는 것: 표의 어느 한 행이라도 다르게 판정하는 것.
    #[test]
    fn rule_table() {
        use AclFacts as A;
        use Group as G;
        use Verdict as V;
        let rows: &[(EntryFacts, G, V, &str)] = &[
            (
                e(ME, 0o755, false, A::None),
                G::Unknown,
                V::Safe,
                "own, no write bits",
            ),
            (
                e(0, 0o755, false, A::None),
                G::Unknown,
                V::Safe,
                "root-owned",
            ),
            (
                e(502, 0o755, false, A::None),
                G::OnlyRootAndUser,
                V::Tamperable,
                "other owner",
            ),
            (
                e(ME, 0o757, false, A::None),
                G::OnlyRootAndUser,
                V::Tamperable,
                "other-writable",
            ),
            (
                e(ME, 0o775, false, A::None),
                G::OnlyRootAndUser,
                V::Safe,
                "group-writable, members root+user",
            ),
            (
                e(ME, 0o775, false, A::None),
                G::HasOthers,
                V::Tamperable,
                "group-writable, other member",
            ),
            (
                e(ME, 0o775, false, A::None),
                G::Unknown,
                V::Unknown,
                "group-writable, membership unknown",
            ),
            (
                e(ME, 0o777, true, A::None),
                G::HasOthers,
                V::Safe,
                "symlink: mode bits ignored",
            ),
            (
                e(502, 0o755, true, A::None),
                G::OnlyRootAndUser,
                V::Tamperable,
                "symlink owned by other",
            ),
            (
                e(ME, 0o755, false, A::AllowsWrite),
                G::OnlyRootAndUser,
                V::Tamperable,
                "ACL allows write",
            ),
            (
                e(ME, 0o755, false, A::DenyOnly),
                G::OnlyRootAndUser,
                V::Safe,
                "ACL deny entries only",
            ),
            (
                e(ME, 0o755, false, A::Unknown),
                G::OnlyRootAndUser,
                V::Unknown,
                "ACL unreadable",
            ),
            (
                e(ME, 0o775, false, A::Unknown),
                G::HasOthers,
                V::Tamperable,
                "worst of two wins",
            ),
        ];
        for (f, g, want, why) in rows {
            let g = *g;
            assert_eq!(classify(f, ME, &|_| g), *want, "{why}");
        }
    }
}
