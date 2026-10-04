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
/// old version folder.
pub fn invocation_path(argv0: &OsStr, path_env: Option<&OsStr>, cwd: &Path) -> Option<PathBuf> {
    let p = Path::new(argv0);
    if argv0.as_bytes().contains(&b'/') {
        return Some(if p.is_absolute() {
            p.to_path_buf()
        } else {
            cwd.join(p)
        });
    }
    std::env::split_paths(path_env?)
        .filter(|d| d.is_absolute())
        .map(|d| d.join(p))
        .find(|c| {
            std::fs::metadata(c).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
        })
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

/// Worst verdict over the link, its canonical target and every ancestor of
/// both. Anything that cannot be inspected is `Unknown` (fail closed).
pub fn check_path(exe: &Path, uid: u32, user: &[u8]) -> Verdict {
    let mut paths: Vec<PathBuf> = exe.ancestors().map(Path::to_path_buf).collect();
    match std::fs::canonicalize(exe) {
        Ok(target) => paths.extend(target.ancestors().map(Path::to_path_buf)),
        Err(_) => return Verdict::Unknown,
    }
    let group = |gid: u32| crate::sys::group_membership(gid, user);
    paths
        .iter()
        .map(|p| facts(p).map_or(Verdict::Unknown, |f| classify(&f, uid, &group)))
        .max()
        .unwrap_or(Verdict::Unknown)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ME: u32 = 501;

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
