//! Descriptor-based path resolution and retained name/parent evidence.
//! Every symlink is read with readlinkat and bracketed by lstat-at; its
//! parent's whole chain and its own owner must pass before place trust is
//! granted. Root-owned ancestor links protected by root-only parent chains
//! use ancestor rules; user links (stow folding) also check the target folder.
use crate::commands::sys::{self, Stamp};
use bingsu_core::fs_trust::{
    Facts, GroupOracle, Last, NextOwner, Refusal, RefuseGroupWrite, ancestor_verdict, walk_verdict,
};
use std::collections::VecDeque;
use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io;
use std::os::fd::AsFd;
use std::path::{Component, Path, PathBuf};

pub const PATH_FDS_MAX: usize = 256;
const LINKS_MAX: usize = 40;

struct Node {
    file: File,
    facts: Facts,
    stamp: Stamp,
    path: PathBuf,
}

struct Edge {
    parent: usize,
    name: OsString,
    stamp: Stamp,
    link: Option<Link>,
}

struct Link {
    target: PathBuf,
    root_ancestor: bool,
}

struct Check {
    stack: Vec<usize>,
    root_ancestor: bool,
}

impl Check {
    fn verdict(
        &self,
        facts: &[Facts],
        me: u32,
        groups: &mut dyn GroupOracle,
    ) -> Result<(), Refusal> {
        if self.root_ancestor {
            root_link_parent_verdict(facts)
        } else {
            walk_verdict(facts, me, Last::Mine, Some(true), groups)
        }
    }
}

pub struct Resolved {
    nodes: Vec<Node>,
    edges: Vec<Edge>,
    checks: Vec<Check>,
    /// Final descriptor and its original facts survive all reads.
    pub file: File,
    pub stamp: Stamp,
    pub facts: Facts,
    pub canonical: PathBuf,
    pub refusal: Option<Refusal>,
    pub blocked_path: Option<PathBuf>,
}

#[derive(Clone)]
enum Step {
    Root,
    Name(OsString),
    Parent,
    FolderTarget,
}

fn steps(path: &Path) -> VecDeque<Step> {
    path.components()
        .filter_map(|c| match c {
            Component::RootDir => Some(Step::Root),
            Component::Normal(n) => Some(Step::Name(n.to_os_string())),
            Component::ParentDir => Some(Step::Parent),
            Component::CurDir => None,
            Component::Prefix(_) => None,
        })
        .collect()
}

fn chain_facts(nodes: &[Node], stack: &[usize]) -> Vec<Facts> {
    stack.iter().map(|&i| nodes[i].facts).collect()
}

pub fn link_owner_is_mine(owner: u32, me: u32) -> bool {
    owner == me
}

fn root_link_parent_verdict(facts: &[Facts]) -> Result<(), Refusal> {
    // This exception grants no user a choice of config root. Every parent
    // must protect the root-owned link from non-root replacement. Use the
    // ancestor rules with uid 0 and conservatively refuse all group write.
    let mut next = NextOwner::Any;
    for (at, f) in facts.iter().enumerate() {
        next = ancestor_verdict(f, 0, at, next, &mut RefuseGroupWrite)?;
    }
    // Any sticky-next duty is satisfied by the link's checked uid 0.
    Ok(())
}

fn folder_target_verdict(
    facts: &[Facts],
    me: u32,
    groups: &mut dyn GroupOracle,
) -> Result<(), Refusal> {
    walk_verdict(facts, me, Last::Mine, Some(true), groups)
}

fn directory_stamp_matches(now: &Stamp, before: &Stamp) -> bool {
    (now.dev, now.ino, now.uid, now.gid, now.mode)
        == (before.dev, before.ino, before.uid, before.gid, before.mode)
}

impl Resolved {
    pub fn open(path: &Path, me: u32, groups: &mut dyn GroupOracle) -> io::Result<Self> {
        Self::open_kind(path, me, groups, false)
    }

    pub fn open_dir(path: &Path, me: u32, groups: &mut dyn GroupOracle) -> io::Result<Self> {
        Self::open_kind(path, me, groups, true)
    }

    fn open_kind(
        path: &Path,
        me: u32,
        groups: &mut dyn GroupOracle,
        directory: bool,
    ) -> io::Result<Self> {
        if !path.is_absolute() {
            return Err(io::Error::other("not absolute"));
        }
        let root = sys::open_dir_at_search_nofollow(None, OsStr::new("/"))?;
        let mut nodes = vec![Node {
            facts: sys::fd_facts(root.as_fd())?,
            stamp: sys::file_stamp(&root)?,
            file: root,
            path: PathBuf::from("/"),
        }];
        let mut edges = Vec::new();
        let mut checks = Vec::new();
        let mut stack = vec![0];
        let mut canonical = PathBuf::from("/");
        let mut todo = steps(path);
        let mut links = 0;
        let mut refusal = None;
        let mut blocked_path = None;
        while let Some(step) = todo.pop_front() {
            match step {
                Step::Root => {
                    stack.truncate(1);
                    canonical = PathBuf::from("/");
                }
                Step::Parent => {
                    if stack.len() > 1 {
                        stack.pop();
                        canonical.pop();
                    }
                }
                Step::FolderTarget => {
                    let verdict = folder_target_verdict(&chain_facts(&nodes, &stack), me, groups);
                    if refusal.is_none()
                        && let Err(r) = verdict
                    {
                        let at = match r {
                            Refusal::Undecided { at }
                            | Refusal::Ancestor { at }
                            | Refusal::StickyNext { at } => at,
                            _ => stack.len() - 1,
                        };
                        blocked_path = Some(nodes[stack[at]].path.clone());
                        refusal = Some(r);
                    }
                    checks.push(Check {
                        stack: stack.clone(),
                        root_ancestor: false,
                    });
                }
                Step::Name(name) => {
                    let parent = *stack.last().expect("root");
                    let dir = nodes[parent].file.as_fd();
                    let before = sys::at_stamp(dir, &name)?;
                    if before.mode & 0o170000 == 0o120000 {
                        links += 1;
                        if links > LINKS_MAX {
                            return Err(io::Error::other("too many symlinks"));
                        }
                        let folder = todo
                            .iter()
                            .any(|s| matches!(s, Step::Name(_) | Step::Parent));
                        let root_ancestor = before.uid == 0 && me != 0 && folder;
                        let check = Check {
                            stack: stack.clone(),
                            root_ancestor,
                        };
                        let verdict = check.verdict(&chain_facts(&nodes, &stack), me, groups);
                        if refusal.is_none()
                            && let Err(r) = verdict
                        {
                            let at = match r {
                                Refusal::Undecided { at }
                                | Refusal::Ancestor { at }
                                | Refusal::StickyNext { at } => at,
                                _ => stack.len() - 1,
                            };
                            blocked_path = Some(nodes[stack[at]].path.clone());
                            refusal = Some(r);
                        }
                        checks.push(check);
                        if !root_ancestor && !link_owner_is_mine(before.uid, me) {
                            refusal = refusal.or(Some(Refusal::Last));
                        }
                        let target = sys::read_link_at(dir, &name)?;
                        if sys::at_stamp(dir, &name)? != before {
                            return Err(io::Error::other("link changed"));
                        }
                        edges.push(Edge {
                            parent,
                            name,
                            stamp: before,
                            link: Some(Link {
                                target: target.clone(),
                                root_ancestor,
                            }),
                        });
                        let mut expansion = steps(&target);
                        // A system prefix's target remains an ancestor in
                        // the continued walk, including sticky-next duties.
                        if folder && !root_ancestor {
                            expansion.push_back(Step::FolderTarget);
                        }
                        expansion.append(&mut todo);
                        todo = expansion;
                        continue;
                    }
                    let final_file = !todo
                        .iter()
                        .any(|s| matches!(s, Step::Name(_) | Step::Parent | Step::FolderTarget));
                    if final_file {
                        let kind = if directory { 0o040000 } else { 0o100000 };
                        if before.mode & 0o170000 != kind {
                            return Err(io::Error::other(if directory {
                                "not a directory"
                            } else {
                                "not a regular file"
                            }));
                        }
                        let file = if directory {
                            sys::open_dir_at_search_nofollow(Some(dir), &name)?
                        } else {
                            sys::open_file_at_nofollow(dir, &name)?
                        };
                        let stamp = sys::file_stamp(&file)?;
                        if stamp != before {
                            return Err(io::Error::other("file changed while opening"));
                        }
                        let facts = sys::fd_facts(file.as_fd())?;
                        let mut all = chain_facts(&nodes, &stack);
                        all.push(facts);
                        if refusal.is_none()
                            && let Err(r) = walk_verdict(&all, me, Last::Mine, Some(true), groups)
                        {
                            let at = match r {
                                Refusal::Undecided { at }
                                | Refusal::Ancestor { at }
                                | Refusal::StickyNext { at } => at,
                                _ => stack.len(),
                            };
                            blocked_path = Some(if at == stack.len() {
                                canonical.join(&name)
                            } else {
                                nodes[stack[at]].path.clone()
                            });
                            refusal = Some(r);
                        }
                        checks.push(Check {
                            stack,
                            root_ancestor: false,
                        });
                        canonical.push(&name);
                        edges.push(Edge {
                            parent,
                            name,
                            stamp: before,
                            link: None,
                        });
                        return Ok(Self {
                            nodes,
                            edges,
                            checks,
                            file,
                            stamp,
                            facts,
                            canonical,
                            refusal,
                            blocked_path,
                        });
                    }
                    if nodes.len() + 1 >= PATH_FDS_MAX {
                        return Err(io::Error::from_raw_os_error(libc::EMFILE));
                    }
                    let file = sys::open_dir_at_search_nofollow(Some(dir), &name)?;
                    let stamp = sys::file_stamp(&file)?;
                    if !directory_stamp_matches(&stamp, &before) {
                        return Err(io::Error::other("folder changed while opening"));
                    }
                    edges.push(Edge {
                        parent,
                        name: name.clone(),
                        stamp: before,
                        link: None,
                    });
                    stack.push(nodes.len());
                    nodes.push(Node {
                        facts: sys::fd_facts(file.as_fd())?,
                        stamp,
                        file,
                        path: canonical.join(&name),
                    });
                    canonical.push(name);
                }
            }
        }
        Err(io::Error::other("not a regular file"))
    }

    pub fn fd_count(&self) -> usize {
        self.nodes.len() + 1
    }

    #[cfg(test)]
    pub fn retains_link(&self, path: &Path) -> bool {
        self.edges
            .iter()
            .any(|e| e.link.is_some() && self.nodes[e.parent].path.join(&e.name) == path)
    }

    /// Immediately before N2 publishes: verify the SAME descriptors, every
    /// retained parent/name binding, link text, permission/ACL/mount facts,
    /// timestamps and a fresh group oracle. No reopened source substitutes
    /// for the source whose bytes were compiled.
    pub fn revalidate(&self, me: u32, groups: &mut dyn GroupOracle) -> io::Result<()> {
        for n in &self.nodes {
            let now = sys::file_stamp(&n.file)?;
            // Directory content times may change because unrelated entries
            // change. Each name we used is checked independently below.
            if !directory_stamp_matches(&now, &n.stamp) || sys::fd_facts(n.file.as_fd())? != n.facts
            {
                return Err(io::Error::other("ancestor evidence changed"));
            }
        }
        for e in &self.edges {
            let dir = self.nodes[e.parent].file.as_fd();
            let now = sys::at_stamp(dir, &e.name)?;
            let same = if e.stamp.mode & 0o170000 == 0o040000 {
                directory_stamp_matches(&now, &e.stamp)
            } else {
                now == e.stamp
            };
            if !same {
                return Err(io::Error::other("parent/name binding changed"));
            }
            if let Some(link) = &e.link
                && (sys::read_link_at(dir, &e.name)? != link.target
                    || if link.root_ancestor {
                        now.uid != 0
                    } else {
                        !link_owner_is_mine(now.uid, me)
                    })
            {
                return Err(io::Error::other("link evidence changed"));
            }
        }
        let now = sys::file_stamp(&self.file)?;
        let same = if self.stamp.mode & 0o170000 == 0o040000 {
            directory_stamp_matches(&now, &self.stamp)
        } else {
            now == self.stamp
        };
        if !same || sys::fd_facts(self.file.as_fd())? != self.facts {
            return Err(io::Error::other("source evidence changed"));
        }
        for (i, check) in self.checks.iter().enumerate() {
            let mut facts = chain_facts(&self.nodes, &check.stack);
            if i + 1 == self.checks.len() {
                facts.push(self.facts);
            }
            check
                .verdict(&facts, me, groups)
                .map_err(|e| io::Error::other(format!("trust changed: {e:?}")))?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bingsu_core::fs_trust::{AclFacts, RefuseGroupWrite};

    // 이것을 실패시키는 것: root 소유 접두 링크의 부모에 사용자 소유·공유 쓰기·쓰기 ACL·소유권 미확인을 허용하는 것.
    #[test]
    fn root_link_parents_must_be_protected_from_non_root() {
        let root = Facts {
            dev: 1,
            ino: 1,
            uid: 0,
            gid: 0,
            mode: 0o40755,
            acl: AclFacts::None,
            ownership: Some(true),
        };
        assert!(root_link_parent_verdict(&[root]).is_ok());
        for parent in [
            Facts { uid: 501, ..root },
            Facts {
                mode: 0o40777,
                ..root
            },
            Facts {
                mode: 0o40775,
                ..root
            },
            Facts {
                acl: AclFacts::AllowsWrite,
                ..root
            },
            Facts {
                ownership: None,
                ..root
            },
        ] {
            assert!(root_link_parent_verdict(&[root, parent]).is_err());
        }
        // A root-owned name in a root-owned sticky folder is root-protected.
        let sticky = Facts {
            mode: 0o41777,
            ..root
        };
        assert!(root_link_parent_verdict(&[root, sticky]).is_ok());
        // Sticky protection does not bless a user-controlled parent below it.
        assert!(root_link_parent_verdict(&[root, sticky, Facts { uid: 501, ..root }]).is_err());
    }

    // 이것을 실패시키는 것: 사용자 폴더 링크의 sticky 대상을 조상 예외로 허용하는 것.
    #[test]
    fn folder_target_is_not_just_a_sticky_ancestor() {
        let f = |uid, mode| Facts {
            dev: 1,
            ino: 1,
            uid,
            gid: 1,
            mode,
            acl: AclFacts::None,
            ownership: Some(true),
        };
        let chain = [f(0, 0o40755), f(0, 0o41777)];
        assert!(folder_target_verdict(&chain, 501, &mut RefuseGroupWrite).is_err());
        // The same sticky folder as an ancestor of my own file is safe.
        assert!(
            walk_verdict(
                &[chain[0], chain[1], f(501, 0o100644)],
                501,
                Last::Mine,
                Some(true),
                &mut RefuseGroupWrite
            )
            .is_ok()
        );
    }
    // 이것을 실패시키는 것: 폴더의 무관한 변경을 거부하거나 정체·권한 변경을 허용하는 것.
    #[test]
    fn directory_evidence_ignores_unrelated_child_timestamps() {
        let before = Stamp {
            dev: 1,
            ino: 2,
            uid: 501,
            gid: 20,
            mode: 0o40755,
            size: 32,
            ctime: (1, 2),
            mtime: (3, 4),
        };
        let mut now = before.clone();
        now.size += 1;
        now.ctime.1 += 1;
        now.mtime.1 += 1;
        assert!(directory_stamp_matches(&now, &before));
        now.ino += 1;
        assert!(!directory_stamp_matches(&now, &before));
        now.ino = before.ino;
        now.mode |= 0o002;
        assert!(!directory_stamp_matches(&now, &before));
    }

    // 이것을 실패시키는 것: 링크 40개·일시 fd 256개 경계를 없애거나 정상 경계까지 거부하는 것.
    #[test]
    fn resolution_caps_links_and_descriptors() {
        let base = std::env::temp_dir().join(format!("bingsu-path-caps-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        let base = std::fs::canonicalize(base).unwrap();
        let me = crate::commands::sys::current_uid();
        let file = base.join("file");
        std::fs::write(&file, "").unwrap();
        for i in (0..40).rev() {
            let target = if i == 39 {
                PathBuf::from("file")
            } else {
                PathBuf::from(format!("s{}", i + 1))
            };
            std::os::unix::fs::symlink(target, base.join(format!("s{i}"))).unwrap();
        }
        let resolved = Resolved::open(&base.join("s0"), me, &mut RefuseGroupWrite).unwrap();
        assert_eq!(resolved.canonical, file);
        assert!(resolved.refusal.is_none());
        resolved.revalidate(me, &mut RefuseGroupWrite).unwrap();
        std::os::unix::fs::symlink("s0", base.join("overflow")).unwrap();
        assert!(Resolved::open(&base.join("overflow"), me, &mut RefuseGroupWrite).is_err());
        let mut deep = base.clone();
        for _ in base.components().count()..255 {
            deep.push("d");
        }
        std::fs::create_dir_all(&deep).unwrap();
        std::fs::write(deep.join("file"), "").unwrap();
        let resolved = Resolved::open(&deep.join("file"), me, &mut RefuseGroupWrite).unwrap();
        assert_eq!(resolved.fd_count(), 256);
        std::fs::create_dir(deep.join("d")).unwrap();
        std::fs::write(deep.join("d/file"), "").unwrap();
        assert_eq!(
            Resolved::open(&deep.join("d/file"), me, &mut RefuseGroupWrite)
                .err()
                .unwrap()
                .raw_os_error(),
            Some(libc::EMFILE)
        );
        drop(resolved);
        std::fs::remove_dir_all(base).unwrap();
    }
}
