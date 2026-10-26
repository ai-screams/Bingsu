//! Test fixtures for comparison loops that must check deadlines without I/O.
use super::*;

// No content authority: comparisons here must stop before any filesystem I/O.
pub fn with_io(
    run: impl FnOnce(&RepoIo<'_>, &RefCell<Meter>, &gix_index::State, policy::Policies),
) {
    use std::{
        os::unix::ffi::OsStrExt,
        time::{Duration, Instant},
    };
    let mut meter = Meter::new(Instant::now() + Duration::from_secs(30));
    let cwd = std::env::current_dir().unwrap();
    let root = safe_read::acquire(
        cwd.as_os_str().as_bytes(),
        safe_read::DiscoveryQuery::default(),
        &mut meter,
    )
    .unwrap()
    .unchecked_cwd_for_test();
    let access = Access::stage_a_only();
    let meter = RefCell::new(meter);
    let io = RepoIo::new(
        RepoRoots {
            worktree: &root,
            gitdir: &root,
            commondir: &root,
        },
        &access,
        &meter,
    );
    let mut index = gix_index::State::new(gix_index::hash::Kind::Sha1);
    for i in 0..8 {
        index.dangerously_push_entry(
            Default::default(),
            gix_index::hash::ObjectId::null(gix_index::hash::Kind::Sha1),
            gix_index::entry::Flags::INTENT_TO_ADD,
            gix_index::entry::Mode::FILE,
            format!("file{i}").as_bytes().into(),
        );
    }
    let policies = policy::Policies {
        stat: Default::default(),
        names: Default::default(),
        conversion: policy::ConversionPolicy::RawHash,
        filemode: true,
        symlinks: true,
    };
    run(&io, &meter, &index, policies);
}
