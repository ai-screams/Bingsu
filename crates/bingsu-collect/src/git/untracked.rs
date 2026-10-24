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

fn count(n: u32) -> Field {
    Field::known(FieldValue::Count {
        n,
        saturated: false,
    })
}

pub fn untracked_status(repo: &GuardedRepository<'_>, index: &State) -> Field {
    let mut counts = StatusCounts::default();
    worktree_status(repo, index, &mut counts);
    counts.untracked
}

pub(crate) fn worktree_status(
    repo: &GuardedRepository<'_>,
    index: &State,
    counts: &mut StatusCounts,
) {
    // Counts are provisional until all held directory edges are revalidated.
    let result = (|| {
        let policies = Policies::from_config(&repo.config)?;
        let mut walk = Walk::new(&repo.io, index, policies)?;
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
                let untracked = walk.directory(b"", false, false)?;
                for (i, entry) in index.entries().iter().enumerate() {
                    if !walk.seen[i] && eligible(entry) {
                        walk.compare(i, entry.path(index).as_ref(), Err(ReadError::Missing))?;
                    }
                }
                Ok(untracked)
            })
            .map(|n| (n, walk.modified, walk.filtered, walk.modified_error))
            .inspect_err(|_| counts.filtered |= walk.filtered)
    })();
    if let Ok((untracked, modified, filtered, error)) = result {
        counts.untracked = count(untracked);
        counts.filtered |= filtered;
        if error.is_none() {
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
    modified: u32,
    filtered: bool,
    modified_error: Option<ReadError>,
    _allocation: PathAllocation,
}
impl<'a, 'io> Walk<'a, 'io> {
    fn new(io: &'a RepoIo<'io>, index: &'a State, policies: Policies) -> Result<Self, ReadError> {
        let allocation = io.account(|m| {
            super::io::index::validate(index, m)?;
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
            modified: 0,
            filtered: false,
            modified_error: None,
            _allocation: allocation,
        })
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
            // A file replaced by a directory is deleted from the tracked view.
            let metadata = metadata.and_then(|m| {
                if m.st_mode & libc::S_IFMT == libc::S_IFDIR {
                    Err(ReadError::Missing)
                } else {
                    Ok(m)
                }
            });
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

    fn directory(
        &mut self,
        parent: &[u8],
        inherited_ignore: bool,
        collapse: bool,
    ) -> Result<u32, ReadError> {
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
        // Validate the fixed marker from this batch's held directory fd, even
        // when .git is beyond the first batch. Junk markers are ordinary dirs;
        // valid repositories collapse before reading their local policies.
        if collapse && self.io.worktree_embedded_repository()? {
            return Ok(1);
        }
        for (name, kind) in [
            (b".gitignore".as_slice(), PatternKind::Ignore),
            (b".gitattributes", PatternKind::Attributes),
        ] {
            path.truncate(prefix);
            path.extend_from_slice(name);
            let metadata = if let Some(record) = batch.entries.iter().find(|r| r.name == name) {
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
        let mut keys: Vec<Vec<u8>> = Vec::new();
        let mut untracked = 0;
        loop {
            for record in &batch.entries {
                self.io.account(|m| m.check())?;
                // Never inspect repository metadata or gitlink contents.
                if record.name.eq_ignore_ascii_case(b".git") {
                    continue;
                }
                path.truncate(prefix);
                path.extend_from_slice(&record.name);
                let key = self.policies.names.key(&path);
                self.io.account(|m| {
                    if keys.len() == keys.capacity() {
                        let extra = keys.capacity().max(16);
                        scratch.reserve(extra * std::mem::size_of::<Vec<u8>>(), m)?;
                        let mut growth = m.path_allocation();
                        growth.reserve(keys.capacity() * std::mem::size_of::<Vec<u8>>(), m)?;
                        keys.try_reserve_exact(extra)
                            .map_err(|_| ReadError::Limit)?;
                    }
                    scratch.reserve(key.len(), m)
                })?;
                keys.push(key.to_vec());
                let exact = self
                    .keys
                    .binary_search_by(|(p, _)| p.as_ref().cmp(key.as_ref()))
                    .ok()
                    .map(|i| self.keys[i].1);
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
                let ignored = inherited_ignore
                    || self
                        .patterns
                        .ignored(self.io, &path, directory, self.policies.names)?;
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
                    let n = self.directory(&path, ignored, !tracked)?;
                    untracked += if tracked { n } else { u32::from(n != 0) };
                } else if exact.is_none() && !ignored {
                    untracked += 1;
                }
                // --untracked-files=normal only needs proof of one visible
                // entry below an index-free directory, including descendants.
                if collapse && untracked != 0 {
                    return Ok(1);
                }
            }
            let more = batch.more;
            drop(batch);
            if !more {
                break;
            }
            batch = self.io.worktree_listing(parent, false)?;
        }
        keys.sort_unstable();
        if keys.windows(2).any(|p| p[0] == p[1]) {
            return Err(ReadError::Changed);
        }
        Ok(untracked)
    }
}
