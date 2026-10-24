//! Single-entry primitives. Stage aggregation, staged comparison and directory
//! walking belong to the callers; no index refresh/write is performed here.
use super::{
    RepoIo,
    policy::{ConversionPolicy, StatPolicy},
};
use crate::safe_read::ReadError;
use gix_index::{
    Entry, State,
    entry::{Flags, Mode, Stat, stat::Time},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Comparison {
    Skipped,
    Exact {
        modified: bool,
    },
    /// Caller projects filtered=true, partial=true even when modified=false.
    Approximate {
        modified: bool,
    },
}

/// Construct Git's truncated stat fields from safe fd-relative Unix metadata.
/// ctime is inode change time, never birth time. Values are comparisons only.
pub fn stat(metadata: &libc::stat) -> Stat {
    Stat {
        mtime: Time {
            secs: metadata.st_mtime as u32,
            nsecs: metadata.st_mtime_nsec as u32,
        },
        ctime: Time {
            secs: metadata.st_ctime as u32,
            nsecs: metadata.st_ctime_nsec as u32,
        },
        dev: metadata.st_dev as u32,
        ino: metadata.st_ino as u32,
        uid: metadata.st_uid,
        gid: metadata.st_gid,
        size: metadata.st_size as u32,
    }
}

pub fn compare(
    io: &RepoIo<'_>,
    relative: &[u8],
    entry: &Entry,
    index: &State,
    policy: StatPolicy,
    conversion: ConversionPolicy,
    filemode: bool,
) -> Result<Comparison, ReadError> {
    if entry.mode == Mode::COMMIT || entry.flags.contains(Flags::SKIP_WORKTREE) {
        return Ok(Comparison::Skipped);
    }
    // Sparse directories and tracked symlinks are explicitly unresolved here.
    // D1 must keep them Partial, never convert an unsupported kind to clean.
    if !matches!(entry.mode, Mode::FILE | Mode::FILE_EXECUTABLE) {
        return Err(super::UNSUPPORTED);
    }
    let observed = io.worktree_metadata(relative);
    compare_observed(
        io,
        relative,
        entry,
        index,
        super::policy::Policies {
            stat: policy,
            conversion,
            filemode,
            names: Default::default(),
        },
        observed.as_ref().map_err(|e| *e),
    )
}

/// Consume a validated batch observation without another stat or record copy.
/// The caller retains the original raw path for any subsequent safe hash.
pub fn compare_observed(
    io: &RepoIo<'_>,
    relative: &[u8],
    entry: &Entry,
    index: &State,
    policies: super::policy::Policies,
    observed: Result<&libc::stat, ReadError>,
) -> Result<Comparison, ReadError> {
    if entry.mode == Mode::COMMIT || entry.flags.contains(Flags::SKIP_WORKTREE) {
        return Ok(Comparison::Skipped);
    }
    if !matches!(entry.mode, Mode::FILE | Mode::FILE_EXECUTABLE) {
        return Err(super::UNSUPPORTED);
    }
    let metadata = match observed {
        Ok(stat) => stat,
        Err(ReadError::Missing) => return Ok(Comparison::Exact { modified: true }),
        Err(ReadError::Symlink) => return Ok(Comparison::Exact { modified: true }),
        Err(error) => return Err(error),
    };
    let super::policy::Policies {
        stat: policy,
        conversion,
        filemode,
        ..
    } = policies;
    if metadata.st_dev != io.worktree_device() {
        return Ok(Comparison::Exact { modified: true });
    }
    match metadata.st_mode & libc::S_IFMT {
        libc::S_IFREG => {}
        libc::S_IFLNK => return Ok(Comparison::Exact { modified: true }),
        _ => return Err(ReadError::Special),
    }
    let current = stat(metadata);
    let mode_changed =
        filemode && (metadata.st_mode & 0o100 != 0) != (entry.mode == Mode::FILE_EXECUTABLE);
    if conversion == ConversionPolicy::MetadataApproximation {
        // Deliberately size + full mtime only: ctime, inode churn and raw blob
        // differences say nothing reliable about the converted Git blob.
        return Ok(Comparison::Approximate {
            modified: mode_changed
                || current.size != entry.stat.size
                || current.mtime != entry.stat.mtime,
        });
    }
    if mode_changed {
        return Ok(Comparison::Exact { modified: true });
    }
    // Git can decide an empty blob from the full-width stat size alone, even
    // with racy timestamps or stale cached stat fields. Mode was checked above.
    if metadata.st_size == 0 && entry.id.is_empty_blob() {
        return Ok(Comparison::Exact { modified: false });
    }
    let options = policy.options();
    if entry.stat.size != 0
        && entry.stat.matches(&current, options)
        && !entry.stat.is_racy(index.timestamp(), options)
    {
        return Ok(Comparison::Exact { modified: false });
    }
    let id = io.worktree_hash(relative, metadata)?;
    Ok(Comparison::Exact {
        modified: id != entry.id,
    })
}

/// Metadata-only directory primitive for D1's sorted index groups. Names are
/// leaf bytes in raw index order. No hash/content I/O occurs in this callback;
/// defer such reads until this call succeeds. With a shared walk, observations
/// stay provisional until with_worktree_stats returns (edge revalidation).
/// Missing leaves are delivered at EOF. Any error invalidates the entire batch
/// and projects to Partial, including ambiguous policy keys and bulk limits.
#[allow(clippy::too_many_arguments)]
pub(crate) fn directory_stats(
    scan: &mut crate::safe_read::WorktreeStats,
    root: &crate::safe_read::Root,
    parent: &[u8],
    leaves: &[&[u8]],
    names: super::policy::NamePolicy,
    access: &crate::safe_read::Access,
    meter: &mut crate::meter::Meter,
    mut visitor: impl FnMut(usize, Result<&libc::stat, ReadError>) -> Result<(), ReadError>,
) -> Result<(), ReadError> {
    if (!parent.is_empty()
        && parent
            .split(|b| *b == b'/')
            .any(|p| p.is_empty() || p == b"." || p == b".."))
        || parent.contains(&0)
        || leaves.iter().any(|p| {
            p.is_empty() || *p == b"." || *p == b".." || p.contains(&b'/') || p.contains(&0)
        })
        || leaves.windows(2).any(|p| p[0] >= p[1])
    {
        return Err(ReadError::Escape);
    }
    if parent.len() > 65_536
        || leaves.len() > bingsu_core::collection::budget::INDEX_ENTRIES as usize
        || leaves.iter().any(|p| p.len() > 4096)
    {
        return Err(ReadError::Limit);
    }
    #[cfg(target_os = "macos")]
    {
        use std::borrow::Cow;
        // Default policy borrows the caller's sorted index directly. Only
        // transformed keys need a separate ordering; ordinary ASCII names do
        // not allocate per entry even when a name policy is enabled.
        let mut scratch = meter.object_allocation();
        let transformed = names.ignore_case || names.precompose_unicode;
        // ASCII folding is a byte comparator, not an owned lowercase name.
        // Only Unicode composition may require the bounded existing parser.
        let normalizer = super::policy::NamePolicy {
            ignore_case: false,
            precompose_unicode: names.precompose_unicode,
        };
        let mut keys: Vec<(Cow<'_, [u8]>, usize)> = Vec::new();
        if transformed {
            let bytes = leaves
                .iter()
                .filter(|p| names.precompose_unicode && !p.is_ascii())
                .try_fold(0usize, |sum, p| {
                    sum.checked_add(p.len()).ok_or(ReadError::Limit)
                })?;
            scratch.reserve(
                bytes
                    .checked_mul(33)
                    .and_then(|v| {
                        v.checked_add(leaves.len() * std::mem::size_of::<(Cow<'_, [u8]>, usize)>())
                    })
                    .ok_or(ReadError::Limit)?,
                meter,
            )?;
            keys.try_reserve_exact(leaves.len())
                .map_err(|_| ReadError::Limit)?;
            keys.extend(
                leaves
                    .iter()
                    .enumerate()
                    .map(|(i, p)| (normalizer.key(p), i)),
            );
            keys.sort_unstable_by(|a, b| compare_key(&a.0, &b.0, names.ignore_case));
            if keys
                .windows(2)
                .any(|p| compare_key(&p[0].0, &p[1].0, names.ignore_case).is_eq())
            {
                return Err(ReadError::Changed);
            }
        }
        scratch.reserve(leaves.len(), meter)?;
        let mut seen = Vec::new();
        seen.try_reserve_exact(leaves.len())
            .map_err(|_| ReadError::Limit)?;
        seen.resize(leaves.len(), false);
        // Bound the rare Unicode normalization scratch once for this directory.
        if names.precompose_unicode {
            scratch.reserve(4096 * 33, meter)?;
        }
        scan.directory(root, parent, access, meter, |raw, metadata| {
            let found = if transformed {
                let key = normalizer.key(raw);
                keys.binary_search_by(|p| compare_key(&p.0, &key, names.ignore_case))
                    .ok()
                    .map(|i| keys[i].1)
            } else {
                leaves.binary_search(&raw).ok()
            };
            let Some(i) = found else {
                return Ok(());
            };
            if seen[i] {
                return Err(ReadError::Changed);
            }
            seen[i] = true;
            visitor(i, metadata)
        })?;
        for (i, present) in seen.into_iter().enumerate() {
            if !present {
                visitor(i, Err(ReadError::Missing))?;
            }
        }
        Ok(())
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = names;
        let mut path = [0u8; 65_537];
        let prefix = parent.len() + usize::from(!parent.is_empty());
        path[..parent.len()].copy_from_slice(parent);
        if prefix != 0 {
            path[prefix - 1] = b'/';
        }
        for (i, leaf) in leaves.iter().enumerate() {
            let end = prefix
                .checked_add(leaf.len())
                .filter(|n| *n <= 65_536)
                .ok_or(ReadError::Limit)?;
            path[prefix..end].copy_from_slice(leaf);
            let metadata = scan.metadata(root, &path[..end], access, meter);
            match metadata {
                Err(error @ (ReadError::Limit | ReadError::Deadline)) => return Err(error),
                _ => visitor(i, metadata.as_ref().map_err(|e| *e))?,
            }
        }
        Ok(())
    }
}

#[cfg(target_os = "macos")]
fn compare_key(left: &[u8], right: &[u8], fold: bool) -> std::cmp::Ordering {
    if fold {
        left.iter()
            .map(u8::to_ascii_lowercase)
            .cmp(right.iter().map(u8::to_ascii_lowercase))
    } else {
        left.cmp(right)
    }
}
