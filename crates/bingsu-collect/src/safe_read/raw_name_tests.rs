use super::*;
// A deleted slot, dot entries, files, links and unknown types all spend raw budget.
#[test]
fn raw_deleted_and_nonfolder_entries_count_before_filtering() {
    let mut m = Meter::new(std::time::Instant::now() + std::time::Duration::from_secs(60));
    let mut names = Names::new(Some(8192), &m);
    for (name, live) in [(b".".as_slice(), true), (b"..", true), (b"", false)] {
        assert!(names.entry(name, live, libc::DT_DIR, &mut m).unwrap());
    }
    for _ in 3..256 {
        assert!(
            names
                .entry(b"file-or-unknown", true, libc::DT_UNKNOWN, &mut m)
                .unwrap()
        );
    }
    assert_eq!(m.counts[Phase::Content as usize].raw_entries, 256);
    for kind in [libc::DT_REG, libc::DT_LNK, libc::DT_FIFO, libc::DT_SOCK] {
        assert!(names.entry(b"not-a-folder", true, kind, &mut m).unwrap());
    }
    assert_eq!(m.counts[Phase::Content as usize].raw_entries, 260);
    assert_eq!(names.finish(false).names.len(), 253);
    let mut names = Names::new(Some(8192), &m);
    assert_eq!(
        names.entry(b"bad/name", true, libc::DT_UNKNOWN, &mut m),
        Err(ReadError::Io(libc::EIO))
    );
}
