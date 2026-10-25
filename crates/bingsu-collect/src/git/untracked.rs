//! Depth-first, directory-at-a-time status. Raw listings supply BOTH tracked
//! observations and untracked candidates; ignored directories are pruned before
//! entry. Only comparison keys are normalized; I/O always uses observed bytes.
use super::{
    GuardedRepository,
    io::{
        RepoIo, RepoPath, RootId,
        policy::{PatternKind, Patterns, Policies},
        worktree::{self, Comparison},
    },
    status_tracked::StatusCounts,
};
use crate::{meter::PathAllocation, safe_read::ReadError};
use bingsu_core::field::{Field, FieldValue};
use gix_index::{
    State,
    entry::{Flags, Mode},
};
use std::borrow::Cow;

// One allowance per topmost index-free subtree, shared by all descendants.
// Kernel batches remain bounded/accounted separately. Root and directories
// containing index entries must finish their tracked comparisons.
const UNTRACKED_SUBTREE_FILES: u32 = 256;

fn count(n: u32) -> Field {
    Field::known(FieldValue::Count {
        n,
        saturated: false,
    })
}

pub(crate) fn untracked_status(
    repo: &GuardedRepository<'_>,
    index: &State,
    global_excludes: &[u8],
) -> Field {
    let mut counts = StatusCounts::default();
    if repo
        .io
        .account(|m| super::io::index::validate(index, m))
        .is_ok()
    {
        worktree_status_validated(repo, index, &mut counts, global_excludes);
    }
    counts.untracked
}

pub(crate) fn worktree_status(
    repo: &GuardedRepository<'_>,
    index: &super::io::index::ExpandedIndex,
    counts: &mut StatusCounts,
    global_excludes: &[u8],
) {
    worktree_status_validated(repo, index, counts, global_excludes);
}

fn worktree_status_validated(
    repo: &GuardedRepository<'_>,
    index: &State,
    counts: &mut StatusCounts,
    global_excludes: &[u8],
) {
    // Counts are provisional until all held directory edges are revalidated.
    let result = (|| {
        let policies = Policies::from_config(&repo.config)?;
        let mut walk = Walk::new(&repo.io, index, policies)?;
        walk.patterns.add_global(&repo.io, global_excludes)?;
        repo.io
            .with_worktree_stats(|| {
                walk.patterns.add(
                    &repo.io,
                    RepoPath::new(RootId::CommonDir, b"info/exclude"),
                    PatternKind::Ignore,
                )?;
                walk.patterns.add(
                    &repo.io,
                    RepoPath::new(RootId::CommonDir, b"info/attributes"),
                    PatternKind::Attributes,
                )?;
                if let Err(error) = walk.directory(b"", false, None) {
                    return if error == ReadError::Limit && walk.untracked != 0 {
                        Ok((
                            Field::known(FieldValue::Count {
                                n: walk.untracked,
                                saturated: true,
                            }),
                            false,
                        ))
                    } else {
                        Err(error)
                    };
                }
                walk.compare_unseen()?;
                Ok((
                    Field::known(FieldValue::Count {
                        n: walk.untracked,
                        saturated: walk.capped,
                    }),
                    true,
                ))
            })
            .map(|(n, complete)| {
                (
                    n,
                    complete,
                    walk.modified,
                    walk.filtered,
                    walk.modified_error,
                )
            })
            .inspect_err(|_| counts.filtered |= walk.filtered)
    })();
    if let Ok((untracked, complete, modified, filtered, error)) = result {
        counts.untracked = untracked;
        counts.filtered |= filtered;
        // A local untracked cap skips no index entries. Only a global walk
        // failure prevents publishing the completed tracked comparison.
        if complete && error.is_none() {
            counts.modified = count(modified);
        }
    }
}

fn eligible(entry: &gix_index::Entry) -> bool {
    entry.stage_raw() == 0
        && entry.mode != Mode::COMMIT
        && !entry.flags.contains(Flags::SKIP_WORKTREE)
}

struct Walk<'a, 'io> {
    io: &'a RepoIo<'io>,
    index: &'a State,
    policies: Policies,
    keys: Vec<(Cow<'a, [u8]>, usize)>,
    seen: Vec<bool>,
    patterns: Patterns,
    untracked: u32,
    capped: bool,
    modified: u32,
    filtered: bool,
    modified_error: Option<ReadError>,
    _allocation: PathAllocation,
}
impl<'a, 'io> Walk<'a, 'io> {
    fn new(io: &'a RepoIo<'io>, index: &'a State, policies: Policies) -> Result<Self, ReadError> {
        let allocation = io.account(|m| {
            if index.entries().iter().any(|e| e.mode.is_sparse()) {
                return Err(super::io::UNSUPPORTED);
            }
            let mut a = m.path_allocation();
            let key_bytes = index.entries().iter().try_fold(0usize, |bytes, entry| {
                let path = entry.path(index);
                let extra = if policies.names.precompose() && !path.is_ascii() {
                    path.len().checked_mul(33).ok_or(ReadError::Limit)?
                } else if policies.names.ignore_case && path.iter().any(u8::is_ascii_uppercase) {
                    path.len()
                } else {
                    0
                };
                bytes.checked_add(extra).ok_or(ReadError::Limit)
            })?;
            a.reserve(
                index.entries().len() * (std::mem::size_of::<(Cow<'_, [u8]>, usize)>() + 1)
                    + key_bytes,
                m,
            )?;
            Ok(a)
        })?;
        let mut keys = Vec::with_capacity(index.entries().len());
        let mut previous = None;
        for (i, entry) in index.entries().iter().enumerate() {
            let path = entry.path(index);
            if previous != Some(path) {
                keys.push((policies.names.key(path.as_ref()), i));
            }
            previous = Some(path);
        }
        keys.sort_unstable_by(|a, b| a.0.cmp(&b.0));
        if keys.windows(2).any(|p| p[0].0 == p[1].0) {
            return Err(ReadError::Changed);
        }
        Ok(Self {
            io,
            index,
            policies,
            keys,
            seen: vec![false; index.entries().len()],
            patterns: Patterns::default(),
            untracked: 0,
            capped: false,
            modified: 0,
            filtered: false,
            modified_error: None,
            _allocation: allocation,
        })
    }

    fn compare_unseen(&mut self) -> Result<(), ReadError> {
        for (i, entry) in self.index.entries().iter().enumerate() {
            if !self.seen[i] && eligible(entry) {
                self.io.account(|_| Ok(()))?;
                self.compare(i, entry.path(self.index).as_ref(), Err(ReadError::Missing))?;
            }
        }
        Ok(())
    }

    fn compare(
        &mut self,
        i: usize,
        raw: &[u8],
        metadata: Result<&libc::stat, ReadError>,
    ) -> Result<(), ReadError> {
        let entry = &self.index.entries()[i];
        if !eligible(entry) {
            return Ok(());
        }
        self.seen[i] = true;
        let conversion = self.patterns.conversion(self.io, raw, self.policies)?;
        let result = if entry.flags.contains(Flags::INTENT_TO_ADD) {
            Ok(Comparison::Exact { modified: true })
        } else {
            worktree::compare_observed(
                self.io,
                raw,
                entry,
                self.index,
                Policies {
                    conversion,
                    ..self.policies
                },
                metadata,
            )
        };
        match result {
            Ok(Comparison::Skipped) => {}
            Ok(Comparison::Exact { modified }) => self.modified += u32::from(modified),
            Ok(Comparison::Approximate { modified }) => {
                self.modified += u32::from(modified);
                self.filtered = true;
            }
            Err(error @ (ReadError::Limit | ReadError::Deadline)) => return Err(error),
            Err(error) => self.modified_error = Some(error),
        }
        Ok(())
    }

    fn reached_cap(&mut self, limit: Option<u32>) -> bool {
        let reached = limit.is_some_and(|limit| self.untracked >= limit);
        self.capped |= reached;
        reached
    }

    fn directory(
        &mut self,
        parent: &[u8],
        inherited_ignore: bool,
        subtree_limit: Option<u32>,
    ) -> Result<(), ReadError> {
        let mut batch = self.io.worktree_listing(parent, true)?;
        let mut scratch = self.io.account(|m| Ok(m.path_allocation()))?;
        self.io
            .account(|m| scratch.reserve((parent.len() + 4097) * 34, m))?;
        let mut path = Vec::with_capacity(parent.len() + 4097);
        path.extend_from_slice(parent);
        if !path.is_empty() {
            path.push(b'/');
        }
        let prefix = path.len();
        // The index keys are sorted. Search only this directory's descendants,
        // keeping the slash in the prefix so adjacent names cannot overlap.
        let prefix_key = self.policies.names.key(&path);
        // Retain this key while the path buffer and each child's key change.
        self.io.account(|m| scratch.reserve(prefix_key.len(), m))?;
        let prefix_key = prefix_key.into_owned();
        let candidates = directory_candidates(&self.keys, &prefix_key);
        // Validate the fixed marker from this batch's held directory fd, even
        // when .git is beyond the first batch. Junk markers are ordinary dirs;
        // valid repositories collapse before reading their local policies.
        if subtree_limit.is_some() && self.io.worktree_embedded_repository()? {
            self.untracked += 1;
            return Ok(());
        }
        for (name, kind) in [
            (b".gitignore".as_slice(), PatternKind::Ignore),
            (b".gitattributes", PatternKind::Attributes),
        ] {
            path.truncate(prefix);
            path.extend_from_slice(name);
            let metadata = if let Some(record) = batch
                .entries
                .iter()
                .find(|r| &batch.names[r.name.clone()] == name)
            {
                record.metadata
            } else {
                // Missing candidates do not consume pattern-file axes, even
                // when the last real pattern file exhausted an exact budget.
                self.io.worktree_metadata(&path)
            };
            match metadata {
                Ok(m) if m.st_mode & libc::S_IFMT == libc::S_IFREG => {}
                Ok(_) | Err(ReadError::Missing | ReadError::Special) => continue,
                Err(error) => return Err(error),
            }
            self.patterns.add_with_names(
                self.io,
                RepoPath::new(RootId::Worktree, &path),
                kind,
                self.policies.names,
            )?;
        }
        // Retain only comparison keys across batches to detect ambiguous names.
        // Full stat records live for one kernel batch, not the whole directory.
        let mut keys: Vec<std::ops::Range<usize>> = Vec::new();
        let mut key_bytes = Vec::new();
        // Keep the observed lower bound on Limit, but reject ambiguous keys
        // even when a later batch or descendant exhausts a budget.
        let result = (|| {
            loop {
                for record in &batch.entries {
                    if self.reached_cap(subtree_limit) {
                        return Ok(());
                    }
                    // Never inspect repository metadata or gitlink contents.
                    let name = &batch.names[record.name.clone()];
                    if name.eq_ignore_ascii_case(b".git") {
                        continue;
                    }
                    path.truncate(prefix);
                    path.extend_from_slice(name);
                    let key = self.policies.names.key(&path);
                    // One live deadline check covers key reservation and the
                    // comparison below. Any content I/O charges/checks again.
                    self.io.account(|m| {
                        super::io::reserve_scratch(&mut keys, 1, &mut scratch, m)?;
                        super::io::reserve_scratch(&mut key_bytes, key.len(), &mut scratch, m)
                    })?;
                    let start = key_bytes.len();
                    key_bytes.extend_from_slice(&key);
                    keys.push(start..key_bytes.len());
                    let exact = find_key(&self.keys, &prefix_key, candidates.clone(), &key);
                    if exact.is_some_and(|i| self.index.entries()[i].mode == Mode::COMMIT) {
                        continue;
                    }
                    let metadata = record.metadata.as_ref().map_err(|e| *e)?;
                    if metadata.st_dev != self.io.worktree_device() {
                        return Err(ReadError::Escape);
                    }
                    if let Some(i) = exact {
                        self.compare(i, &path, Ok(metadata))?;
                    }
                    let directory = metadata.st_mode & libc::S_IFMT == libc::S_IFDIR;
                    // Ignore rules affect untracked leaves and directory
                    // traversal, never an already compared tracked leaf.
                    let ignored = inherited_ignore
                        || ((directory || exact.is_none())
                            && self.patterns.ignored(
                                self.io,
                                &path,
                                directory,
                                self.policies.names,
                            )?);
                    if directory {
                        let mut child = key.into_owned();
                        child.push(b'/');
                        let start = self
                            .keys
                            .partition_point(|(p, _)| p.as_ref() < child.as_slice());
                        let tracked = self
                            .keys
                            .get(start)
                            .is_some_and(|(p, _)| p.starts_with(&child));
                        if !tracked && ignored {
                            continue;
                        }
                        let limit = if tracked {
                            None
                        } else {
                            // Absolute count at this subtree's boundary avoids
                            // resetting the allowance in nested directories.
                            subtree_limit.or(Some(self.untracked + UNTRACKED_SUBTREE_FILES))
                        };
                        self.directory(&path, ignored, limit)?;
                    } else if exact.is_none() && !ignored {
                        self.untracked += 1;
                    }
                }
                let more = batch.more;
                drop(batch);
                if !more {
                    break;
                }
                // EOF is not proven: even exactly cap files are a lower bound
                // here. Do not fetch another batch just to refine that bound.
                if self.reached_cap(subtree_limit) {
                    break;
                }
                batch = self.io.worktree_listing(parent, false)?;
            }
            Ok(())
        })();
        if ambiguous_keys(&mut keys, &key_bytes) {
            return Err(ReadError::Changed);
        }
        result
    }
}

fn directory_candidates(keys: &[(Cow<'_, [u8]>, usize)], prefix: &[u8]) -> std::ops::Range<usize> {
    let start = keys.partition_point(|(p, _)| p.as_ref() < prefix);
    let len = keys[start..].partition_point(|(p, _)| p.starts_with(prefix));
    start..start + len
}

fn find_key(
    keys: &[(Cow<'_, [u8]>, usize)],
    prefix: &[u8],
    candidates: std::ops::Range<usize>,
    key: &[u8],
) -> Option<usize> {
    // NFC precomposition falls back to raw bytes for an entire non-UTF-8
    // path. Its parent's normalized key need not be a prefix in that case.
    let candidates = if key.starts_with(prefix) {
        candidates
    } else {
        0..keys.len()
    };
    keys[candidates.clone()]
        .binary_search_by(|(p, _)| p.as_ref().cmp(key))
        .ok()
        .map(|i| keys[candidates.start + i].1)
}

fn ambiguous_keys(keys: &mut [std::ops::Range<usize>], bytes: &[u8]) -> bool {
    keys.sort_unstable_by(|a, b| bytes[a.clone()].cmp(&bytes[b.clone()]));
    keys.windows(2)
        .any(|p| bytes[p[0].clone()] == bytes[p[1].clone()])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn directory_key_search_falls_back_for_nonprefix_keys() {
        let keys = [
            (Cow::Borrowed(b"a/file".as_slice()), 7),
            (Cow::Borrowed(b"z/file".as_slice()), 9),
        ];
        let candidates = directory_candidates(&keys, b"z/");
        assert_eq!(candidates, 1..2);
        assert_eq!(
            find_key(&keys, b"z/", candidates.clone(), b"z/file"),
            Some(9)
        );
        assert_eq!(find_key(&keys, b"z/", candidates, b"a/file"), Some(7));
    }

    // No filesystem fixture: APFS rejects the non-UTF-8 child with EILSEQ.
    #[cfg(target_os = "macos")]
    #[test]
    fn nfd_parent_non_utf8_child_uses_full_key_search() {
        let names = super::super::io::policy::NamePolicy {
            precompose_unicode: true,
            ..Default::default()
        };
        for ignore_case in [false, true] {
            let names = super::super::io::policy::NamePolicy {
                ignore_case,
                ..names
            };
            let parent = b"e\xcc\x81/";
            let child = b"e\xcc\x81/\xffFile";
            let prefix = names.key(parent);
            let key = names.key(child);
            assert_eq!(prefix.as_ref(), "é/".as_bytes());
            assert!(!key.starts_with(&prefix));
            let mut keys = vec![
                (names.key(b"a/file"), 3),
                (names.key(child), 5),
                (names.key("é/other".as_bytes()), 8),
            ];
            keys.sort_unstable_by(|a, b| a.0.cmp(&b.0));
            let candidates = directory_candidates(&keys, &prefix);
            assert!(!keys[candidates.clone()].iter().any(|(p, _)| p == &key));
            assert_eq!(find_key(&keys, &prefix, candidates, &key), Some(5));
        }
    }

    #[test]
    fn unseen_entries_check_expired_deadline_before_comparison() {
        super::super::io::test_support::with_io(|io, meter, index, policies| {
            let mut walk = Walk::new(io, index, policies).unwrap();
            *meter.borrow_mut() = crate::meter::Meter::new(std::time::Instant::now());
            assert_eq!(walk.compare_unseen(), Err(ReadError::Deadline));
            assert_eq!(walk.modified, 0);
            assert!(walk.seen.iter().all(|seen| !seen));
        });
    }

    // Mutations: compare offsets instead of name bytes, omit sorting or accept
    // duplicates. Equal keys can live in different batches of one directory.
    #[test]
    fn ambiguous_names_compare_bytes_across_disjoint_ranges() {
        let names = b"dogcatdogcatalog";
        assert!(!super::ambiguous_keys(&mut [0..3, 3..6, 9..16], names));
        assert!(super::ambiguous_keys(&mut [0..3, 3..6, 6..9, 9..16], names));
        assert!(!super::ambiguous_keys(&mut [], names));
    }
}
