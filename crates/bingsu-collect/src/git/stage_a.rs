//! HEAD identity without gix/config. Owners alone choose the read policy.
use super::discover::RepoRoots;
use crate::{
    meter::Meter,
    safe_read::{self, Access, ReadError, StageADirectory, StageAFile},
};
use bingsu_core::{
    collection::git::StageResult,
    field::{self, Field, FieldValue, Value},
    width::WidthProfile,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HeadPolicy {
    HeadOnly,
    OwnedMetadata,
}

pub fn stage_a(roots: &RepoRoots, policy: HeadPolicy, meter: &mut Meter) -> StageResult {
    // A caller cannot upgrade a foreign repository by passing OwnedMetadata.
    let policy = if roots.head_policy() == HeadPolicy::HeadOnly {
        HeadPolicy::HeadOnly
    } else {
        policy
    };
    meter.event("stage_a_head");
    let reduced = Access::stage_a_only();
    let access = if policy == HeadPolicy::HeadOnly {
        &reduced
    } else {
        &roots.access
    };
    let head = match safe_read::read_stage_a(&roots.gitdir, StageAFile::Head, access, meter) {
        Ok(head) => head,
        Err(_) => return StageResult::Hidden,
    };
    let mut value = Value::new(b"", vec![Field::PENDING; field::BUILTIN[3].fields.len()]);
    put(&mut value, "no_repo", Field::ABSENT);
    put(&mut value, "partial", Field::known(FieldValue::Bool(true)));
    put(&mut value, "stage", text(b"A", 1));
    put(&mut value, "branch", Field::ABSENT);
    put(&mut value, "commit", Field::ABSENT);
    let line = head.strip_suffix(b"\n").unwrap_or(&head);
    let line = line.strip_suffix(b"\r").unwrap_or(line);
    if let Some(name) = line.strip_prefix(b"ref: refs/heads/") {
        if !valid_branch(name) {
            return StageResult::Hidden;
        }
        put(
            &mut value,
            "detached",
            Field::known(FieldValue::Bool(false)),
        );
        // HEAD alone is enough for the branch identity in reduced/foreign mode.
        // In owned full mode, prove unborn with a missing loose ref AND missing
        // packed-refs. A packed snapshot is never read before the first Update.
        let unborn = policy == HeadPolicy::OwnedMetadata
            && roots.access.guarantee().is_some()
            && (roots.unborn.get() || unborn(roots, &line[5..], meter));
        if !unborn {
            put(&mut value, "branch", text(name, 256));
        }
    } else if line.len() == 40 && line.iter().all(u8::is_ascii_hexdigit) {
        put(&mut value, "detached", Field::known(FieldValue::Bool(true)));
        put(
            &mut value,
            "commit",
            text(&line[..12].to_ascii_lowercase(), 16),
        );
    } else {
        return StageResult::Hidden;
    }
    if policy == HeadPolicy::OwnedMetadata {
        let operation = operation(roots, meter);
        put(
            &mut value,
            "operation",
            match operation {
                Ok(Some(name)) => text(name, 16),
                Ok(None) => Field::ABSENT,
                Err(_) => Field::PENDING,
            },
        );
    }
    if meter.check().is_err() {
        StageResult::Hidden
    } else {
        StageResult::Partial(value)
    }
}

fn unborn(roots: &RepoRoots, name: &[u8], meter: &mut Meter) -> bool {
    meter.event("stage_a_ref_presence");
    if !matches!(
        safe_read::resolve_with(roots.common(), name, &roots.access, meter),
        Err(ReadError::Missing)
    ) {
        return false;
    }
    matches!(
        safe_read::resolve_with(roots.common(), b"packed-refs", &roots.access, meter),
        Err(ReadError::Missing)
    )
}

fn operation(roots: &RepoRoots, meter: &mut Meter) -> Result<Option<&'static [u8]>, ReadError> {
    meter.event("stage_a_operations");
    for directory in [StageADirectory::RebaseMerge, StageADirectory::RebaseApply] {
        match safe_read::directory_stage_a(&roots.gitdir, directory, &roots.access, meter) {
            Ok(_) => return Ok(Some(b"rebase")),
            Err(ReadError::Missing) => {}
            Err(error) => return Err(error),
        }
    }
    for (file, name) in [
        (StageAFile::MergeHead, b"merge".as_slice()),
        (StageAFile::CherryPickHead, b"cherry-pick"),
        (StageAFile::RevertHead, b"revert"),
        (StageAFile::BisectLog, b"bisect"),
    ] {
        match safe_read::read_stage_a(&roots.gitdir, file, &roots.access, meter) {
            Ok(_) => return Ok(Some(name)),
            Err(ReadError::Missing) => {}
            Err(error) => return Err(error),
        }
    }
    Ok(None)
}

fn valid_branch(name: &[u8]) -> bool {
    !name.is_empty()
        && !name.ends_with(b"/")
        && !name.ends_with(b".")
        && !name.windows(2).any(|p| matches!(p, b".." | b"@{" | b"//"))
        && !name
            .iter()
            .any(|b| *b <= b' ' || *b == 127 || b"~^:?*[\\".contains(b))
        && !name
            .split(|b| *b == b'/')
            .any(|p| p.is_empty() || p.starts_with(b".") || p.ends_with(b".lock"))
}

fn text(bytes: &[u8], cells: u16) -> Field {
    Field::text(bytes, cells, WidthProfile::DEFAULT)
}
fn put(value: &mut Value, name: &str, field: Field) {
    value.fields[field::BUILTIN[3]
        .field_index(name)
        .expect("fixed git field")] = field;
}
