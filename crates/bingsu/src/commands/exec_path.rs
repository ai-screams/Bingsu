//! Sanitized `PATH` and executable lookup for user commands and builtin
//! probes (spec section 4, rows environment, executable lookup and native
//! executable). The rules are `bingsu_core::command::path` and
//! `bingsu_core::fs_trust`; this file walks the file system one name at a
//! time through held descriptors and hands them the facts.
//!
//! The helper resolves; the relay, which cannot ask the group database,
//! runs only the canonical path it is given, refuses any symlink on it and
//! accepts group write only for the pin found here (B2 ruling, design A).
//! Ancestor folders get no pin: the walk below found that only root, the
//! user or a cleared group can change them, so between this check and the
//! relay's exec nobody else can swap a name on the way.
use crate::commands::group_policy::Recording;
use crate::commands::sys;
use bingsu_core::command::path::{self as rule, Candidate, Name};
use bingsu_core::fs_trust::{GroupOracle, GroupPin, NextOwner, ancestor_verdict};
use std::collections::VecDeque;
use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::os::fd::AsFd;
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf};

/// The same bound Linux uses for one path lookup (MAXSYMLINKS).
const LINKS_MAX: usize = 40;
/// Folders held open at once by one walk.
const DEPTH_MAX: usize = 256;

/// The executable to run: its canonical path and, when it is group-writable,
/// the pin the relay compares against.
#[derive(Debug, PartialEq, Eq)]
pub struct Found {
    pub executable: PathBuf,
    pub pin: Option<GroupPin>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Miss {
    /// No such name on the way, or the lookup found no executable.
    Absent,
    /// A link, folder or file on the way someone else can change, or one
    /// the rules could not decide, or a name that cannot be looked up.
    Refused,
}

struct Folder {
    file: File,
    /// The duty this folder leaves for its next entry (sticky `/tmp`).
    next: NextOwner,
}

enum End {
    Folder,
    File { file: File, next: NextOwner },
}

/// `p`'s names in order: "/" restarts at the root, ".." steps back.
fn names(p: &Path) -> VecDeque<OsString> {
    p.components()
        .filter_map(|c| match c {
            Component::RootDir => Some(OsString::from("/")),
            Component::ParentDir => Some(OsString::from("..")),
            Component::Normal(n) => Some(n.to_os_string()),
            Component::CurDir | Component::Prefix(_) => None,
        })
        .collect()
}

fn miss(e: &std::io::Error) -> Miss {
    if e.kind() == std::io::ErrorKind::NotFound {
        Miss::Absent
    } else {
        Miss::Refused
    }
}

/// Walks absolute `path` from "/" one name at a time. Every folder entered
/// must pass the ancestor rule before any name inside it is trusted; a
/// symlink is followed only when root or `me` owns it (its folder passed
/// already); `..` steps back to the folder the walk came from. Returns the
/// canonical path and how it ended.
fn walk(
    path: &Path,
    me: u32,
    groups: &mut dyn GroupOracle,
    want_folder: bool,
) -> Result<(PathBuf, End), Miss> {
    if !path.is_absolute() {
        return Err(Miss::Refused);
    }
    let root = sys::open_dir_at_search_nofollow(None, OsStr::new("/")).map_err(|e| miss(&e))?;
    let facts = sys::fd_facts(root.as_fd()).map_err(|_| Miss::Refused)?;
    let next =
        ancestor_verdict(&facts, me, 0, NextOwner::Any, groups).map_err(|_| Miss::Refused)?;
    let mut stack = vec![Folder { file: root, next }];
    let mut canonical = PathBuf::from("/");
    let mut todo = names(path);
    let mut links = 0;
    while let Some(name) = todo.pop_front() {
        if name == "/" {
            stack.truncate(1);
            canonical = PathBuf::from("/");
            continue;
        }
        if name == ".." {
            if stack.len() > 1 {
                stack.pop();
                canonical.pop();
            }
            continue;
        }
        let top = stack.last().expect("root");
        let dir = top.file.as_fd();
        let stamp = sys::at_stamp(dir, &name).map_err(|e| miss(&e))?;
        let kind = stamp.mode & 0o170_000;
        if kind == 0o120_000 {
            links += 1;
            if links > LINKS_MAX || !rule::link_owner_ok(stamp.uid, me) {
                return Err(Miss::Refused);
            }
            let target = sys::read_link_at(dir, &name).map_err(|_| Miss::Refused)?;
            if sys::at_stamp(dir, &name).map_err(|_| Miss::Refused)? != stamp {
                return Err(Miss::Refused);
            }
            let mut expansion = names(&target);
            expansion.append(&mut todo);
            todo = expansion;
            continue;
        }
        let last = todo.is_empty();
        if last && !want_folder {
            if kind != 0o100_000 {
                // Not a regular file: the lookup moves on, like a shell.
                return Err(Miss::Absent);
            }
            let next = top.next;
            let file = open_target(dir, &name).map_err(|_| Miss::Refused)?;
            let now = sys::file_stamp(&file).map_err(|_| Miss::Refused)?;
            if (now.dev, now.ino) != (stamp.dev, stamp.ino) {
                return Err(Miss::Refused);
            }
            canonical.push(&name);
            return Ok((canonical, End::File { file, next }));
        }
        if kind != 0o040_000 || stack.len() >= DEPTH_MAX {
            return Err(if kind == 0o040_000 {
                Miss::Refused
            } else {
                Miss::Absent
            });
        }
        let file = sys::open_dir_at_search_nofollow(Some(dir), &name).map_err(|e| miss(&e))?;
        let facts = sys::fd_facts(file.as_fd()).map_err(|_| Miss::Refused)?;
        if (facts.dev, facts.ino) != (stamp.dev, stamp.ino) {
            return Err(Miss::Refused);
        }
        let next = ancestor_verdict(&facts, me, stack.len(), top.next, groups)
            .map_err(|_| Miss::Refused)?;
        stack.push(Folder { file, next });
        canonical.push(&name);
    }
    if want_folder {
        Ok((canonical, End::Folder))
    } else {
        Err(Miss::Absent)
    }
}

/// The final file for reading (the relay reads its first bytes), or, on
/// Linux, path-only when the user may only execute it.
fn open_target(dir: std::os::fd::BorrowedFd<'_>, name: &OsStr) -> std::io::Result<File> {
    match sys::open_file_at_nofollow(dir, name) {
        #[cfg(target_os = "linux")]
        Err(e) if e.raw_os_error() == Some(libc::EACCES) => sys::open_path_at_nofollow(dir, name),
        other => other,
    }
}

/// The canonical folders of `path_env` that commands may search, in order,
/// first occurrence only: absolute entries whose whole way passes the
/// ancestor rule and that are not inside `repo` (the canonical root of the
/// repository the shell is in).
pub fn sanitize(
    path_env: &[u8],
    repo: Option<&Path>,
    me: u32,
    groups: &mut dyn GroupOracle,
) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = Vec::new();
    for entry in rule::entries(path_env) {
        let walked = walk(Path::new(OsStr::from_bytes(entry)), me, groups, true);
        let Ok((canonical, _)) = walked else {
            continue;
        };
        let keep = rule::keep_folder(
            canonical.as_os_str().as_bytes(),
            repo.map(|r| r.as_os_str().as_bytes()),
            true,
        );
        if keep && !out.contains(&canonical) {
            out.push(canonical);
        }
    }
    out
}

/// The `PATH` value for the target's environment.
pub fn path_value(folders: &[PathBuf]) -> Vec<u8> {
    rule::sanitized(folders.iter().map(|f| f.as_os_str().as_bytes()))
}

/// Looks the command's first word up: an absolute path as given, a bare
/// name in `folders` (from `sanitize`). The first folder with an
/// executable regular file of that name decides; if that file fails the
/// rules nothing runs.
pub fn lookup(
    word: &[u8],
    folders: &[PathBuf],
    me: u32,
    groups: &mut dyn GroupOracle,
) -> Result<Found, Miss> {
    match rule::name(word) {
        Name::Refused => Err(Miss::Refused),
        Name::Absolute(p) => resolve(Path::new(OsStr::from_bytes(p)), me, groups),
        Name::Search(n) => {
            for folder in folders {
                match resolve(&folder.join(OsStr::from_bytes(n)), me, groups) {
                    Err(Miss::Absent) => continue,
                    other => return other,
                }
            }
            Err(Miss::Absent)
        }
    }
}

/// One executable path: walked, then judged with the group answers kept,
/// so a group-writable target carries the pin its group was cleared for.
pub fn resolve(path: &Path, me: u32, groups: &mut dyn GroupOracle) -> Result<Found, Miss> {
    let (executable, end) = walk(path, me, groups, false)?;
    let End::File { file, next } = end else {
        return Err(Miss::Absent);
    };
    let facts = sys::fd_facts(file.as_fd()).map_err(|_| Miss::Refused)?;
    let mut recording = Recording::new(groups);
    match rule::candidate(&facts, me, next, &mut recording) {
        Candidate::Run => Ok(Found {
            executable,
            pin: rule::target_pin(&facts, &recording.cleared),
        }),
        Candidate::Skip => Err(Miss::Absent),
        Candidate::Refuse => Err(Miss::Refused),
    }
}

/// `resolve` for the current user with the system's group answers, asked
/// afresh (one `SystemGroups` per call, like every other walk).
pub fn resolve_for_user(path: &Path) -> Result<Found, Miss> {
    let me = sys::current_uid();
    let user = sys::passwd_entry(me).ok_or(Miss::Refused)?;
    let mut groups = crate::commands::group_policy::SystemGroups::new(&user.name);
    resolve(path, me, &mut groups)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bingsu_core::fs_trust::{Facts, Group, RefuseGroupWrite};
    use std::os::unix::fs::{PermissionsExt, symlink};

    struct Clear;
    impl GroupOracle for Clear {
        fn group_write(&mut self, _: &Facts) -> Group {
            Group::OnlyRootAndUser
        }
    }

    fn me() -> u32 {
        sys::current_uid()
    }

    /// A fresh folder under the temporary folder, canonical (macOS `/var`
    /// is a root-owned link to `/private/var`).
    fn scratch(tag: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("bingsu-exec-path-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::canonicalize(&dir).unwrap()
    }

    /// Folders up to `p`, each 0755 whatever the umask (a 0002 umask makes
    /// them group-writable, which `RefuseGroupWrite` refuses).
    fn folders(p: &Path) {
        if p.is_dir() {
            return;
        }
        folders(p.parent().unwrap());
        std::fs::create_dir(p).unwrap();
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    fn exe(path: &Path, mode: u32) {
        folders(path.parent().unwrap());
        std::fs::copy(std::fs::canonicalize("/usr/bin/true").unwrap(), path).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    fn bytes(p: &Path) -> &[u8] {
        p.as_os_str().as_bytes()
    }

    // 이것을 실패시키는 것: sanitize에서 저장소 검사(keep_folder의 repo)를 지우는 것(저장소의 bin/env가
    // 뽑힘), 또는 entries의 상대·빈 항목 제외를 지우는 것.
    #[test]
    fn test_path_skips_repo_and_relative_entries() {
        let t = scratch("repo");
        let repo = t.join("repo");
        exe(&repo.join("bin/env"), 0o755);
        let mut path = bytes(&repo.join("bin")).to_vec();
        path.extend_from_slice(b":.::bin:/usr/bin");
        let folders = sanitize(&path, Some(&repo), me(), &mut RefuseGroupWrite);
        let found = lookup(b"env", &folders, me(), &mut RefuseGroupWrite).unwrap();
        assert_eq!(
            found.executable,
            std::fs::canonicalize("/usr/bin/env").unwrap()
        );
        assert!(
            folders
                .iter()
                .all(|f| f.is_absolute() && !f.starts_with(&repo)),
            "{folders:?}"
        );
        let usr_bin = std::fs::canonicalize("/usr/bin").unwrap();
        assert_eq!(path_value(&folders), bytes(&usr_bin));
        // Positive control: outside a repository the same folder stays and wins.
        let folders = sanitize(&path, None, me(), &mut RefuseGroupWrite);
        let found = lookup(b"env", &folders, me(), &mut RefuseGroupWrite).unwrap();
        assert_eq!(found.executable, repo.join("bin/env"));
        std::fs::remove_dir_all(&t).unwrap();
    }

    // 양성 대조(Homebrew 모양). 이것을 실패시키는 것: walk가 본인 소유 symlink까지 거부하는 것, 상대
    // 대상의 ".."를 링크가 있던 폴더 기준으로 풀지 않는 것.
    #[test]
    fn test_brew_cellar_symlink_resolved() {
        let t = scratch("brew");
        let real = t.join("Cellar/x/1/bin/x");
        exe(&real, 0o755);
        folders(&t.join("bin"));
        symlink("../Cellar/x/1/bin/x", t.join("bin/x")).unwrap();
        let folders = sanitize(bytes(&t.join("bin")), None, me(), &mut RefuseGroupWrite);
        let found = lookup(b"x", &folders, me(), &mut RefuseGroupWrite).unwrap();
        assert_eq!(
            found,
            Found {
                executable: real,
                pin: None
            }
        );
        std::fs::remove_dir_all(&t).unwrap();
    }

    // 다른 uid 소유 symlink는 root만 만들 수 있다(lchown). Linux 컨테이너에서 root로 --ignored로 돌린다.
    // 이것을 실패시키는 것: walk의 link_owner_ok 비교를 반전하거나 지우는 것.
    #[test]
    #[ignore = "needs root (lchown to another uid); run in the Linux container"]
    fn test_foreign_symlink_refused() {
        assert_eq!(me(), 0, "run as root");
        let t = scratch("foreign");
        let real = t.join("real/x");
        exe(&real, 0o755);
        let link = t.join("x");
        symlink(&real, &link).unwrap();
        // Positive control: a root-owned link resolves.
        assert_eq!(
            resolve(&link, 0, &mut RefuseGroupWrite).unwrap().executable,
            real
        );
        std::os::unix::fs::lchown(&link, Some(12345), Some(12345)).unwrap();
        assert_eq!(resolve(&link, 0, &mut RefuseGroupWrite), Err(Miss::Refused));
        std::fs::remove_dir_all(&t).unwrap();
    }

    // 이것을 실패시키는 것: walk의 폴더 ancestor_verdict를 지우는 것(남이 쓸 수 있는 폴더가 남음).
    #[test]
    fn folders_others_can_write_are_dropped() {
        let t = scratch("loose");
        let loose = t.join("loose");
        exe(&loose.join("x"), 0o755);
        std::fs::set_permissions(&loose, std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(sanitize(bytes(&loose), None, me(), &mut RefuseGroupWrite).is_empty());
        assert_eq!(
            resolve(&loose.join("x"), me(), &mut RefuseGroupWrite),
            Err(Miss::Refused)
        );
        std::fs::set_permissions(&loose, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(
            sanitize(bytes(&loose), None, me(), &mut RefuseGroupWrite),
            [loose]
        );
        std::fs::remove_dir_all(&t).unwrap();
    }

    // 이것을 실패시키는 것: lookup이 Refused에서 다음 폴더로 넘어가는 것(앞 폴더의 남이 쓸 수 있는 x 대신
    // 뒤 폴더의 x가 실행됨), 또는 실행 비트 없는 파일에서 멈추는 것.
    #[test]
    fn first_executable_decides() {
        let t = scratch("first");
        let (a, b) = (t.join("a"), t.join("b"));
        exe(&a.join("x"), 0o757);
        exe(&a.join("y"), 0o644);
        exe(&b.join("x"), 0o755);
        exe(&b.join("y"), 0o755);
        let folders = [a.clone(), b.clone()];
        assert_eq!(
            lookup(b"x", &folders, me(), &mut RefuseGroupWrite),
            Err(Miss::Refused)
        );
        assert_eq!(
            lookup(b"y", &folders, me(), &mut RefuseGroupWrite)
                .unwrap()
                .executable,
            b.join("y")
        );
        assert_eq!(
            lookup(b"z", &folders, me(), &mut RefuseGroupWrite),
            Err(Miss::Absent)
        );
        assert_eq!(
            lookup(b"a/x", &folders, me(), &mut RefuseGroupWrite),
            Err(Miss::Refused)
        );
        std::fs::remove_dir_all(&t).unwrap();
    }

    // 이것을 실패시키는 것: resolve가 Recording 없이 판정해 pin을 비우는 것, target_pin을 빼는 것,
    // 또는 그룹 쓰기 파일을 오라클 답 없이 받는 것.
    #[test]
    fn group_writable_target_gets_its_pin() {
        let t = scratch("pin");
        let x = t.join("x");
        exe(&x, 0o775);
        assert_eq!(resolve(&x, me(), &mut RefuseGroupWrite), Err(Miss::Refused));
        let found = resolve(&x, me(), &mut Clear).unwrap();
        let file = File::open(&x).unwrap();
        let facts = sys::fd_facts(file.as_fd()).unwrap();
        assert_eq!(found.pin, Some(GroupPin::of(&facts)));
        std::fs::remove_dir_all(&t).unwrap();
    }

    // 이것을 실패시키는 것: open_target의 O_PATH 재시도를 지우는 것. root는 읽기 권한을 무시하므로
    // root가 아닌 사용자로 돌려야 뜻이 있다.
    #[cfg(target_os = "linux")]
    #[test]
    fn execute_only_target_resolves() {
        let t = scratch("xonly");
        let x = t.join("x");
        exe(&x, 0o111);
        assert_eq!(
            resolve(&x, me(), &mut RefuseGroupWrite).unwrap().executable,
            x
        );
        std::fs::remove_dir_all(&t).unwrap();
    }
}
