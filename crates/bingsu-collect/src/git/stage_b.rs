//! One B budget and one worktree scan. D3 owns deadlines and cumulative A–D
//! publication; this module never resets the shared meter or enables collection.
use super::{GuardedRepository, io::index, status_tracked::StatusCounts, untracked};
use bingsu_core::{
    collection::git::StageResult,
    field::{Field, FieldValue},
};

pub fn stage_b(repo: &GuardedRepository<'_>) -> StageResult {
    let counts = status(repo);
    // The bool is provisional during the walk. Neither true nor false may
    // escape an incomplete/unvalidated scan; unseen entries can change it.
    let filtered = if [&counts.modified, &counts.untracked].iter().all(|f| {
        matches!(
            f.value,
            FieldValue::Count {
                saturated: false,
                ..
            }
        )
    }) {
        Field::known(FieldValue::Bool(counts.filtered))
    } else {
        Field::PENDING
    };
    let fields = [
        ("staged", counts.staged),
        ("modified", counts.modified),
        ("untracked", counts.untracked),
        ("conflicted", counts.conflicted),
        ("filtered", filtered),
    ];
    let partial = counts.filtered
        || fields[..4].iter().any(|(_, f)| {
            !matches!(
                f.value,
                FieldValue::Count {
                    saturated: false,
                    ..
                }
            )
        });
    super::stage_c::result(b"B", partial, &fields)
}

pub fn status(repo: &GuardedRepository<'_>) -> StatusCounts {
    let index = match index::load(&repo.io) {
        Ok(index) => index,
        Err(_) => return StatusCounts::default(),
    };
    let index = match index::expand_sparse(repo, index) {
        Ok(index) => index,
        Err(_) => return StatusCounts::default(),
    };
    let mut counts = super::status_tracked::index_status(repo, &index);
    untracked::worktree_status(repo, &index, &mut counts);
    counts
}
