//! One B budget and one worktree scan. D3 owns deadlines and cumulative A–D
//! publication; this module never resets the shared meter or enables collection.
use super::{GuardedRepository, io::index, status_tracked::StatusCounts, untracked};
use bingsu_core::{
    collection::git::StageResult,
    field::{Field, FieldValue},
};

/// D3 passes both global excludes fields from the decoded request, unchanged.
pub fn stage_b(
    repo: &GuardedRepository<'_>,
    global_excludes: &[u8],
    global_excludes_known: bool,
) -> StageResult {
    let mut counts = status(repo, global_excludes);
    // Still perform the shared scan, but missing rules can exclude any counted
    // path. The observed count is neither exact nor a proven lower bound.
    if !global_excludes_known {
        counts.untracked = Field::PENDING;
    }
    // Only a completed, validated modified comparison fixes this bool. A
    // local untracked cap skips no index entries, unlike a global walk limit.
    let complete = matches!(
        counts.modified.value,
        FieldValue::Count {
            saturated: false,
            ..
        }
    );
    // Preserve the conservative unknown-global-policy publication contract.
    let filtered = if complete && global_excludes_known {
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

pub(crate) fn status(repo: &GuardedRepository<'_>, global_excludes: &[u8]) -> StatusCounts {
    let index = match index::load_expanded(repo) {
        Ok(index) => index,
        Err(_) => return StatusCounts::default(),
    };
    let mut counts = super::status_tracked::index_status(repo, &index);
    untracked::worktree_status(repo, &index, &mut counts, global_excludes);
    counts
}
