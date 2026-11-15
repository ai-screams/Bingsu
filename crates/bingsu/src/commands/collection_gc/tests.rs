//! The shared tail of the two evictions, on a real folder under a private
//! temporary root.
use super::{Catalog, Entry, GcReport, Victim, retire_store};
use crate::commands::{snapshot_store::StoreError, sys};
use bingsu_core::snapshot::Clock;
use std::{fs, fs::File, os::unix::fs::PermissionsExt, path::PathBuf};

fn clock() -> Clock {
    Clock {
        boot: [0; 16],
        kind: 0,
        domain: [0; 16],
        resume: 0,
        now: 0,
    }
}

struct Root(PathBuf);
impl Root {
    fn new(tag: &str) -> Self {
        let path =
            std::env::temp_dir().join(format!("bingsu-gc-retire-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).unwrap();
        Self(path)
    }
}
impl Drop for Root {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn entry(path: &[&str], bytes: u64) -> Entry {
    Entry {
        path: path.iter().map(|s| s.to_string()).collect(),
        cwd: vec![],
        dev: 0,
        ino: 0,
        bytes,
        reserved: false,
        used: clock(),
    }
}

// What each call below leaves behind. A catalog of three entries, the middle
// one retired.
fn retire_middle(tomb: &str, name: &str, path_len: usize) -> (Catalog, GcReport) {
    let root = Root::new(&format!("{name}-{path_len}"));
    let runtime = File::open(&root.0).unwrap();
    let parent_path = root.0.join("p");
    fs::create_dir(&parent_path).unwrap();
    fs::create_dir(parent_path.join(name)).unwrap();
    let parent = File::open(&parent_path).unwrap();
    let dir = File::open(parent_path.join(name)).unwrap();
    let mut catalog = Catalog::empty(&runtime).unwrap();
    let mut long: Vec<&str> = vec!["a"; path_len - 1];
    long.push(name);
    catalog.entries = vec![
        entry(&["x", "y", "first"], 10),
        entry(&long, 20),
        entry(&["x", "y", "last"], 30),
    ];
    catalog.stores = 3;
    catalog.nodes = 9;
    catalog.bytes = 60;
    let mut report = GcReport::default();
    retire_store(
        &mut catalog,
        1,
        &mut report,
        &Victim {
            parent: &parent,
            dir: &dir,
            name,
        },
        tomb,
        std::iter::empty(),
        sys::current_uid(),
    )
    .unwrap();
    assert!(!parent_path.join(name).exists() && !parent_path.join(tomb).exists());
    (catalog, report)
}

// 이것을 실패시키는 것: `catalog.next`를 지운 자리 다음(`index + 1`)이나 0으로 두는 것, 합계를 줄이지 않거나
// 줄이는 양을 `bytes`가 아닌 값으로 하는 것, 항목을 지우지 않는 것, 폴더를 세지 않는 것.
#[test]
fn retiring_one_store_takes_it_out_of_the_totals_and_points_at_its_successor() {
    for (name, tomb) in [("store", ".store.gc"), (".s.gc", ".s.gc")] {
        let (catalog, report) = retire_middle(tomb, name, 3);
        assert_eq!((catalog.stores, catalog.nodes, catalog.bytes), (2, 8, 40));
        assert_eq!(catalog.entries.len(), 2);
        assert_eq!(catalog.entries[1].path.last().unwrap(), "last");
        assert_eq!(catalog.next, 1);
        assert_eq!(report.removed_dirs, 1);
    }
}

// 이것을 실패시키는 것: 이름 바꾼 뒤 경로의 마지막 성분이 아닌 자리(`path[2]`나 `path[0]`)를 갱신하는 것, 이름을
// 바꾸지 않고 지우는 것. 폴더에 파일이 남아 제거가 실패하면 항목의 경로가 바뀐 채 남아 관찰된다. 길이 3(세션
// 폴더)과 긴 경로(저장소 폴더) 둘 다 마지막 성분만 바뀐다.
#[test]
fn the_rename_changes_only_the_last_component_of_the_entry_path() {
    for len in [3usize, 9] {
        let root = Root::new(&format!("path-{len}"));
        let runtime = File::open(&root.0).unwrap();
        let parent_path = root.0.join("p");
        fs::create_dir_all(parent_path.join("store")).unwrap();
        fs::write(parent_path.join("store").join("left-over"), b"x").unwrap();
        let parent = File::open(&parent_path).unwrap();
        let dir = File::open(parent_path.join("store")).unwrap();
        let mut catalog = Catalog::empty(&runtime).unwrap();
        let mut path: Vec<&str> = vec!["a"; len - 1];
        path.push("store");
        catalog.entries = vec![entry(&path, 5)];
        let mut report = GcReport::default();
        let failed = retire_store(
            &mut catalog,
            0,
            &mut report,
            &Victim {
                parent: &parent,
                dir: &dir,
                name: "store",
            },
            ".store.gc",
            std::iter::empty(),
            sys::current_uid(),
        );
        assert!(matches!(failed, Err(StoreError::Io(_))), "{failed:?}");
        let mut want: Vec<String> = vec!["a".into(); len - 1];
        want.push(".store.gc".into());
        assert_eq!(catalog.entries[0].path, want);
        assert!(parent_path.join(".store.gc").exists() && !parent_path.join("store").exists());
    }
}

// 이것을 실패시키는 것: 이미 있는 tombstone 이름 위로 이름을 바꾸는 것(`Busy` 검사를 지움).
#[test]
fn a_taken_tombstone_name_stops_the_retirement_before_any_rename() {
    let root = Root::new("busy");
    let runtime = File::open(&root.0).unwrap();
    let parent_path = root.0.join("p");
    fs::create_dir_all(parent_path.join("store")).unwrap();
    fs::create_dir(parent_path.join(".store.gc")).unwrap();
    let parent = File::open(&parent_path).unwrap();
    let dir = File::open(parent_path.join("store")).unwrap();
    let mut catalog = Catalog::empty(&runtime).unwrap();
    catalog.entries = vec![entry(&["a", "b", "store"], 5)];
    let mut report = GcReport::default();
    let busy = retire_store(
        &mut catalog,
        0,
        &mut report,
        &Victim {
            parent: &parent,
            dir: &dir,
            name: "store",
        },
        ".store.gc",
        std::iter::empty(),
        sys::current_uid(),
    );
    assert!(matches!(busy, Err(StoreError::Busy)));
    assert_eq!(catalog.entries[0].path, ["a", "b", "store"]);
    assert!(parent_path.join("store").exists());
}

// A folder holding a data file and the lock file, each with its own cap.
fn folder_with(tag: &str, files: &[(&str, &[u8])]) -> (Root, PathBuf, File, File, Catalog) {
    let root = Root::new(tag);
    let runtime = File::open(&root.0).unwrap();
    let parent_path = root.0.join("p");
    fs::create_dir_all(parent_path.join("store")).unwrap();
    for (name, bytes) in files {
        let path = parent_path.join("store").join(name);
        fs::write(&path, bytes).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    }
    let parent = File::open(&parent_path).unwrap();
    let dir = File::open(parent_path.join("store")).unwrap();
    let mut catalog = Catalog::empty(&runtime).unwrap();
    catalog.entries = vec![entry(&["a", "b", "store"], 5)];
    (root, parent_path, parent, dir, catalog)
}

// 이것을 실패시키는 것: 파일 제거 루프를 빼는 것(제거 수가 0이고 폴더가 남음), 파일별 상한을 무시하는 것.
#[test]
fn every_file_the_caller_names_goes_before_the_folder() {
    let (_root, parent_path, parent, dir, mut catalog) =
        folder_with("files", &[("data", b"abc"), ("lock", b"")]);
    let mut report = GcReport::default();
    retire_store(
        &mut catalog,
        0,
        &mut report,
        &Victim {
            parent: &parent,
            dir: &dir,
            name: "store",
        },
        ".store.gc",
        [("data", 10usize), ("lock", 0)].into_iter(),
        sys::current_uid(),
    )
    .unwrap();
    assert_eq!((report.removed_files, report.removed_dirs), (2, 1));
    assert!(!parent_path.join("store").exists() && !parent_path.join(".store.gc").exists());
}

// 이것을 실패시키는 것: 상한을 넘는 파일을 지우는 것, 반복자가 준 순서를 바꾸는 것(락 파일이 마지막이어야
// 앞 파일이 실패했을 때 락이 남는다), 실패한 뒤에도 계속 지우는 것.
#[test]
fn a_file_over_its_cap_stops_the_removal_and_leaves_the_lock_for_last() {
    let (_root, parent_path, parent, dir, mut catalog) =
        folder_with("cap", &[("data", b"abcdef"), ("lock", b"")]);
    let mut report = GcReport::default();
    let failed = retire_store(
        &mut catalog,
        0,
        &mut report,
        &Victim {
            parent: &parent,
            dir: &dir,
            name: "store",
        },
        ".store.gc",
        [("data", 3usize), ("lock", 0)].into_iter(),
        sys::current_uid(),
    );
    assert!(failed.is_err(), "{failed:?}");
    assert_eq!(report.removed_files, 0);
    assert!(parent_path.join(".store.gc/lock").exists());
    assert!(parent_path.join(".store.gc/data").exists());
    assert_eq!(catalog.entries.len(), 1);
}
