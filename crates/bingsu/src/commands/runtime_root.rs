//! The runtime root walk (spec section 4 "runtime root" 2 and 4). The pinned
//! path is canonical, so it holds no symlink: it is opened from "/" one name
//! at a time with `openat(O_NOFOLLOW)` on search-only descriptors (a
//! symlink swapped in later fails the walk instead of redirecting it), each
//! descriptor is `fstat`ed (and on macOS its ACL read), rule 2 is applied
//! to the whole chain (`bingsu_core::fs_trust::walk_verdict`), and the last
//! folder's `(st_dev, st_ino)` must equal the pin.
//!
//! `init` pins with the same walk (`init::roots`), and the refresh helper
//! and the write child (Part N) open the root with `open_runtime_root`. The
//! prompt front end makes the same observations through its read plan
//! (Task N4) and applies the same core rule, so the three cannot disagree.
use crate::commands::sys;
use bingsu_core::fs_trust::{Facts, GroupOracle, Last, Refusal, walk_verdict};
use std::ffi::OsStr;
use std::fs::File;
use std::os::fd::{AsFd, AsRawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

/// What `init` pinned (`--runtime-root=<st_dev>:<st_ino>:<path>`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pinned {
    pub dev: u64,
    pub ino: u64,
    pub path: PathBuf,
}

#[derive(Debug, PartialEq, Eq)]
pub enum RootError {
    /// The path is not absolute or has `.`, `..` or empty names (not canonical).
    NotCanonical,
    /// `openat` or `fstat` failed at chain index `at` (0 is "/"): ELOOP or
    /// ENOTDIR for a symlink swapped in, ENOENT for a removed folder.
    Open { at: usize, errno: i32 },
    /// Rule 2 refused the chain.
    Refused(Refusal),
    /// The last folder is not the pinned one (remounted, or removed and
    /// made again).
    Moved { dev: u64, ino: u64 },
}

/// The open chain: `fds[0]` is "/", `fds[i]` is the i-th name; `facts[i]`
/// was read through `fds[i]`.
pub struct Chain {
    pub fds: Vec<File>,
    pub facts: Vec<Facts>,
    pub names: Vec<std::ffi::OsString>,
}

impl Chain {
    pub fn revalidate(&self) -> std::io::Result<()> {
        for (i, f) in self.fds.iter().enumerate() {
            if sys::fd_facts(f.as_fd())? != self.facts[i] {
                return Err(std::io::Error::other("chain facts changed"));
            }
            if i > 0 {
                let named = sys::at_stamp(self.fds[i - 1].as_fd(), &self.names[i - 1])?;
                if (named.dev, named.ino) != (self.facts[i].dev, self.facts[i].ino) {
                    return Err(std::io::Error::other("chain name changed"));
                }
            }
        }
        Ok(())
    }

    pub fn last(&self) -> &File {
        self.fds.last().expect("a chain holds at least /")
    }
}

/// The plain names of a canonical absolute path.
fn names(path: &Path) -> Result<Vec<&OsStr>, RootError> {
    // Components normalizes interior `.` and repeated separators; check the
    // spelling too, before any descriptor is opened.
    let bytes = path.as_os_str().as_bytes();
    if !path.is_absolute()
        || (bytes != b"/"
            && bytes[1..]
                .split(|b| *b == b'/')
                .any(|part| part.is_empty() || part == b"." || part == b".."))
    {
        return Err(RootError::NotCanonical);
    }
    if bytes == b"/" {
        return Ok(Vec::new());
    }
    Ok(bytes[1..]
        .split(|b| *b == b'/')
        .map(OsStr::from_bytes)
        .collect())
}

/// Opens `path` from "/" without following any symlink, reading the facts
/// of every folder on the way.
pub fn open_chain(path: &Path) -> Result<Chain, RootError> {
    let err = |at: usize| {
        move |e: std::io::Error| RootError::Open {
            at,
            errno: e.raw_os_error().unwrap_or(0),
        }
    };
    let names = names(path)?;
    let root = sys::open_dir_at_search_nofollow(None, OsStr::new("/")).map_err(err(0))?;
    let mut chain = Chain {
        facts: vec![sys::fd_facts(root.as_fd()).map_err(err(0))?],
        fds: vec![root],
        names: names.iter().map(|n| n.to_os_string()).collect(),
    };
    for (i, name) in names.iter().enumerate() {
        let next = sys::open_dir_at_search_nofollow(Some(chain.last().as_fd()), name)
            .map_err(err(i + 1))?;
        chain
            .facts
            .push(sys::fd_facts(next.as_fd()).map_err(err(i + 1))?);
        chain.fds.push(next);
    }
    Ok(chain)
}

/// Create a private root at an already-canonical spelling. Shared by R1
/// init and refresh/log writers: existing ancestors are judged before any
/// mutation; missing names are made 0700 through held no-follow descriptors.
/// The whole final chain is judged and revalidated; failures roll back only
/// folders made by this call. Never canonicalize a helper's pinned spelling.
pub fn create_private(
    path: &Path,
    uid: u32,
    groups: &mut dyn GroupOracle,
) -> std::io::Result<Chain> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let bad = |what: &str| std::io::Error::other(format!("private root: {what}"));
    let all = names(path).map_err(|e| bad(&format!("{e:?}")))?;
    let Some((last, parents)) = all.split_last() else {
        return Err(bad("no folder name"));
    };
    let mut prefix = path.parent().ok_or_else(|| bad("no parent"))?.to_path_buf();
    let mut chain = loop {
        match open_chain(&prefix) {
            Ok(chain) => break chain,
            Err(RootError::Open {
                errno: libc::ENOENT,
                ..
            }) => {
                if !prefix.pop() {
                    return Err(bad("no existing parent"));
                }
            }
            Err(e) => return Err(bad(&format!("{e:?}"))),
        }
    };
    let names = &parents[chain.names.len()..];
    // Keep the existing prefix and every created child's descriptors until
    // the same chain is judged and its parent/name connections rechecked.
    // `created` lists (holding descriptor index, name) for rollback.
    let mut next = bingsu_core::fs_trust::NextOwner::Any;
    for (at, facts) in chain.facts.iter().enumerate() {
        next = bingsu_core::fs_trust::ancestor_verdict(facts, uid, at, next, groups)
            .map_err(|e| bad(&format!("{e:?}")))?;
    }
    chain.revalidate()?;
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
        for name in names {
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
        judge(&chain, uid, groups).map_err(|e| bad(&format!("{e:?}")))?;
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
    Ok(chain)
}

/// A writer may create a missing pinned root, but an existing root must
/// already satisfy its caller's trust policy (`Mine` for state, `PrivateFolder`
/// for logs): do not repair its permissions or follow
/// a link planted since init. No configuration root is created here.
pub fn ensure_root(
    path: &Path,
    me: u32,
    groups: &mut dyn GroupOracle,
    last: Last,
) -> std::io::Result<Chain> {
    let bad = |e| std::io::Error::other(format!("private root: {e:?}"));
    match open_chain(path) {
        Ok(chain) => {
            walk_verdict(
                &chain.facts,
                me,
                last,
                sys::fd_is_local(chain.last().as_raw_fd()),
                groups,
            )
            .map_err(|e| bad(RootError::Refused(e)))?;
            chain.revalidate()?;
            Ok(chain)
        }
        Err(RootError::Open {
            errno: libc::ENOENT,
            ..
        }) => create_private(path, me, groups),
        Err(e) => Err(bad(e)),
    }
}

/// Rule 2 over an open chain whose last folder is a private root.
pub fn judge(chain: &Chain, me: u32, groups: &mut dyn GroupOracle) -> Result<(), RootError> {
    let local = sys::fd_is_local(chain.last().as_raw_fd());
    walk_verdict(&chain.facts, me, Last::PrivateFolder, local, groups).map_err(RootError::Refused)
}

/// Opens the pinned runtime root for the helper and the write child: the
/// walk, rule 2 and the pin. The descriptor is search-only (a base for
/// `openat`, `mkdirat`, `renameat`).
pub fn open_runtime_root(
    pin: &Pinned,
    me: u32,
    groups: &mut dyn GroupOracle,
) -> Result<File, RootError> {
    use std::os::unix::fs::MetadataExt;
    let chain = open_chain(&pin.path)?;
    judge(&chain, me, groups)?;
    chain.revalidate().map_err(|e| RootError::Open {
        at: chain.fds.len() - 1,
        errno: e.raw_os_error().unwrap_or(0),
    })?;
    let md = chain.last().metadata().map_err(|e| RootError::Open {
        at: chain.fds.len() - 1,
        errno: e.raw_os_error().unwrap_or(0),
    })?;
    if (md.dev(), md.ino()) != (pin.dev, pin.ino) {
        return Err(RootError::Moved {
            dev: md.dev(),
            ino: md.ino(),
        });
    }
    let mut chain = chain;
    Ok(chain.fds.pop().expect("a chain holds at least /"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use bingsu_core::fs_trust::RefuseGroupWrite;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    // 이것을 실패시키는 것: 시험 폴더를 기본 mode로 만들어 umask 002에서 그룹 쓰기 조상을 남기는 것.
    fn private_dirs(path: impl AsRef<Path>) -> std::io::Result<()> {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(path)
    }

    fn scratch(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("bingsu-rt-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        private_dirs(&d).unwrap();
        std::fs::canonicalize(&d).unwrap()
    }

    fn private(p: &Path) -> Pinned {
        private_dirs(p).unwrap();
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o700)).unwrap();
        let md = std::fs::metadata(p).unwrap();
        Pinned {
            dev: md.dev(),
            ino: md.ino(),
            path: p.to_path_buf(),
        }
    }

    // 이것을 실패시키는 것: judge 뒤 전체 chain 재확인을 생략하고 마지막 inode만 비교하는 것.
    #[test]
    fn runtime_open_rechecks_ancestors_after_judgement() {
        struct Change {
            parent: PathBuf,
            rename: bool,
            fired: bool,
        }
        impl GroupOracle for Change {
            fn group_write(&mut self, _: &Facts) -> bingsu_core::fs_trust::Group {
                if !self.fired {
                    self.fired = true;
                    if self.rename {
                        std::fs::rename(&self.parent, self.parent.with_extension("old")).unwrap();
                        std::fs::create_dir(&self.parent).unwrap();
                    } else {
                        std::fs::set_permissions(
                            &self.parent,
                            std::fs::Permissions::from_mode(0o777),
                        )
                        .unwrap();
                    }
                }
                bingsu_core::fs_trust::Group::OnlyRootAndUser
            }
        }
        for rename in [false, true] {
            let base = scratch(&format!("judge-race-{rename}"));
            std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o700)).unwrap();
            let parent = base.join("parent");
            let pin = private(&parent.join("run"));
            std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o775)).unwrap();
            let mut groups = Change {
                parent: parent.clone(),
                rename,
                fired: false,
            };
            assert!(open_runtime_root(&pin, sys::current_uid(), &mut groups).is_err());
            assert!(groups.fired);
            let last = if rename {
                parent.with_extension("old").join("run")
            } else {
                pin.path.clone()
            };
            let md = std::fs::metadata(last).unwrap();
            assert_eq!((md.dev(), md.ino()), (pin.dev, pin.ino));
            std::fs::remove_dir_all(base).unwrap();
        }
    }

    // 스펙 4절 "런타임 뿌리" 4·5: 고정값이 맞으면 열리고, 지웠다 다시 만들면 Moved, 0755면 규칙 위반,
    // 상위 이름이 symlink로 바뀌면 걷기가 실패한다(따라가지 않음), 상대·`..` 경로는 거부.
    // 이것을 실패시키는 것: (dev, ino) 비교를 빼는 것, 마지막 폴더 규칙을 빼는 것, O_NOFOLLOW를 빼는 것,
    // 정규 경로 검사를 빼는 것.
    #[test]
    fn the_pinned_root_opens_and_nothing_else() {
        let me = sys::current_uid();
        let base = scratch("pin");
        let pin = private(&base.join("a/bingsu"));
        let opened = open_runtime_root(&pin, me, &mut RefuseGroupWrite).unwrap();
        let md = opened.metadata().unwrap();
        assert_eq!((md.dev(), md.ino()), (pin.dev, pin.ino));
        for wrong in [
            Pinned {
                dev: pin.dev.wrapping_add(1),
                ..pin.clone()
            },
            Pinned {
                ino: pin.ino.wrapping_add(1),
                ..pin.clone()
            },
        ] {
            assert_eq!(
                open_runtime_root(&wrong, me, &mut RefuseGroupWrite).err(),
                Some(RootError::Moved {
                    dev: pin.dev,
                    ino: pin.ino
                })
            );
        }
        // Replaced by another folder at the same path. The old one is kept
        // aside until the new one exists: tmpfs and overlayfs hand a freed
        // inode number out again, so remove-then-make can get the same one
        // (seen in a Linux container). A pin cannot tell that case apart.
        std::fs::rename(&pin.path, base.join("old")).unwrap();
        let again = private(&pin.path);
        assert!(matches!(
            open_runtime_root(&pin, me, &mut RefuseGroupWrite),
            Err(RootError::Moved { .. })
        ));
        // Loose mode.
        std::fs::set_permissions(&again.path, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(
            open_runtime_root(&again, me, &mut RefuseGroupWrite).err(),
            Some(RootError::Refused(Refusal::Last))
        );
        std::fs::set_permissions(&again.path, std::fs::Permissions::from_mode(0o700)).unwrap();
        // An ancestor swapped for a symlink to the same folder.
        std::fs::rename(base.join("a"), base.join("real")).unwrap();
        std::os::unix::fs::symlink(base.join("real"), base.join("a")).unwrap();
        let at = names(&again.path).unwrap().len() - 1;
        match open_runtime_root(&again, me, &mut RefuseGroupWrite) {
            Err(RootError::Open { at: got, errno }) => {
                assert_eq!(got, at);
                assert!(errno == libc::ELOOP || errno == libc::ENOTDIR, "{errno}");
            }
            other => panic!("{other:?}"),
        }
        for bad in ["rel/bingsu", "/a/../b"] {
            let p = Pinned {
                path: PathBuf::from(bad),
                ..again.clone()
            };
            assert_eq!(
                open_runtime_root(&p, me, &mut RefuseGroupWrite).err(),
                Some(RootError::NotCanonical)
            );
        }
        std::fs::remove_dir_all(&base).unwrap();
    }

    // 이것을 실패시키는 것: components가 지우는 `.`·빈 이름을 받아들이거나 절대 경로 검사를 빼는 것.
    #[test]
    fn only_canonical_spellings_are_walked() {
        assert!(names(Path::new("/")).unwrap().is_empty());
        assert_eq!(names(Path::new("/a/b")).unwrap(), ["a", "b"]);
        for bad in ["", "relative", "/a/./b", "/a/../b", "/a//b", "/a/", "//a"] {
            assert_eq!(names(Path::new(bad)), Err(RootError::NotCanonical), "{bad}");
        }
        // Unix names need not be UTF-8.
        assert_eq!(
            names(Path::new(OsStr::from_bytes(b"/a/\xff"))).unwrap(),
            [OsStr::new("a"), OsStr::from_bytes(b"\xff")]
        );
    }

    // 이것을 실패시키는 것: 보유 fd의 권한 변화나 부모/이름의 교체를 재확인하지 않는 것,
    // fstatat에서 링크를 따라 원래 폴더를 본 것으로 인정하는 것.
    #[test]
    fn chain_revalidation_checks_facts_and_each_name_without_following() {
        let base = scratch("revalidate");
        let pin = private(&base.join("mid/run"));
        let chain = open_chain(&pin.path).unwrap();
        assert_eq!(chain.names.len() + 1, chain.fds.len());
        assert_eq!(chain.facts.len(), chain.fds.len());
        chain.revalidate().unwrap();
        let mid = base.join("mid");
        let saved_mode = std::fs::metadata(&mid).unwrap().permissions();
        std::fs::set_permissions(&mid, std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(chain.revalidate().is_err());
        std::fs::set_permissions(&mid, saved_mode).unwrap();
        chain.revalidate().unwrap();

        let old = base.join("old");
        std::fs::rename(&mid, &old).unwrap();
        // The fd remains open even while its original name is absent.
        assert!(chain.last().metadata().is_ok());
        assert!(chain.revalidate().is_err());
        std::fs::create_dir(&mid).unwrap();
        assert!(chain.revalidate().is_err());
        std::fs::remove_dir(&mid).unwrap();
        std::os::unix::fs::symlink(&old, &mid).unwrap();
        assert!(chain.revalidate().is_err());
        std::fs::remove_file(&mid).unwrap();
        std::fs::rename(&old, &mid).unwrap();
        chain.revalidate().unwrap();
        std::fs::remove_dir_all(&base).unwrap();
    }

    // 이것을 실패시키는 것: 마지막 fd의 로컬 관측을 Some(true)로 대신하는 것.
    #[test]
    fn judge_requires_locality_from_the_last_descriptor() {
        let base = scratch("locality");
        let pin = private(&base.join("run"));
        let mut chain = open_chain(&pin.path).unwrap();
        let me = sys::current_uid();
        judge(&chain, me, &mut RefuseGroupWrite).unwrap();
        // Keep safe folder facts, but supply a descriptor whose filesystem
        // cannot count as local (socketfs on Linux, failed query on macOS).
        // This isolates the locality observation from the pure mode rule.
        let (socket, _peer) = std::os::unix::net::UnixStream::pair().unwrap();
        let fd: std::os::fd::OwnedFd = socket.into();
        *chain.fds.last_mut().unwrap() = File::from(fd);
        assert_ne!(sys::fd_is_local(chain.last().as_raw_fd()), Some(true));
        assert_eq!(
            judge(&chain, me, &mut RefuseGroupWrite),
            Err(RootError::Refused(Refusal::NotLocal))
        );
        std::fs::remove_dir_all(base).unwrap();
    }

    // 상위 폴더 규칙은 걷기의 모든 폴더에 적용된다(그룹 쓰기, 다른 사용자 쓰기).
    // 이것을 실패시키는 것: 상위 폴더를 judge에 넘기지 않는 것(마지막 폴더만 보는 것).
    #[test]
    fn a_loose_ancestor_refuses_the_root() {
        let me = sys::current_uid();
        let base = scratch("ancestor");
        let pin = private(&base.join("mid/bingsu"));
        let mid = base.join("mid");
        for mode in [0o775, 0o757] {
            std::fs::set_permissions(&mid, std::fs::Permissions::from_mode(mode)).unwrap();
            let at = names(&mid).unwrap().len();
            assert_eq!(
                open_runtime_root(&pin, me, &mut RefuseGroupWrite).err(),
                Some(RootError::Refused(Refusal::Ancestor { at })),
                "{mode:o}"
            );
        }
        std::fs::remove_dir_all(&base).unwrap();
    }
}
