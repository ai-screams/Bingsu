//! C2 bytes boundary, outside the product entry (product collection stays off).
#![cfg(unix)]
#[allow(dead_code)]
#[path = "../src/git/mod.rs"]
mod git;
#[cfg(target_os = "linux")]
#[allow(dead_code)]
#[path = "../src/landlock.rs"]
mod landlock;
#[allow(dead_code)]
#[path = "../src/meter.rs"]
mod meter;
#[allow(dead_code)]
#[path = "../src/safe_read/mod.rs"]
mod safe_read;

use bingsu_core::collection::budget::{self, Axis};
use git::{
    config::Config,
    io::{RepoIo, RepoPath, RepoRoots, RootId},
    refs::{self, Refs, Target},
};
use meter::{Meter, Phase};
use safe_read::{Access, DiscoveryQuery, ReadCap, ReadError as E, Root};
use std::{
    cell::RefCell,
    fs,
    os::unix::{ffi::OsStrExt, fs::symlink},
    path::PathBuf,
    rc::Rc,
    time::{Duration, Instant},
};

const A: &str = "1111111111111111111111111111111111111111";
const B: &str = "2222222222222222222222222222222222222222";
const INVALID: E = E::Io(libc::EINVAL);

fn meter() -> Meter {
    Meter::new(Instant::now() + Duration::from_secs(30))
}
fn cap(bytes: u64) -> ReadCap {
    ReadCap {
        bytes,
        single_link: true,
    }
}
fn path(root: RootId, relative: &[u8]) -> RepoPath {
    RepoPath::new(root, relative)
}

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let dir = std::env::temp_dir().join(format!(
            "bingsu-git-io-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        fs::create_dir(&dir).unwrap();
        Self(fs::canonicalize(dir).unwrap())
    }
    fn write(&self, name: &str, bytes: impl AsRef<[u8]>) {
        let name = self.0.join(name);
        fs::create_dir_all(name.parent().unwrap()).unwrap();
        fs::write(name, bytes).unwrap();
    }
    fn root(&self, meter: &mut Meter) -> Root {
        safe_read::acquire(
            self.0.as_os_str().as_bytes(),
            DiscoveryQuery::default(),
            meter,
        )
        .unwrap()
        .select_cwd()
        .unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

fn access() -> Access {
    #[cfg(target_os = "linux")]
    let access = Access::probe(&mut meter()).unwrap();
    #[cfg(target_os = "macos")]
    let access = {
        use std::os::fd::AsFd;
        let fixture = Fixture::new();
        fixture.write("value", b"inside");
        fixture.write("dir/file", b"inside");
        fixture.write("hard", b"linked");
        fs::hard_link(fixture.0.join("hard"), fixture.0.join("hard2")).unwrap();
        for (target, name) in [
            ("../value", "dir/inner"),
            ("dir", "linkdir"),
            ("/", "absolute"),
            ("../outside", "escape"),
            ("../../outside", "dir/up"),
        ] {
            symlink(target, fixture.0.join(name)).unwrap();
        }
        let fd = fs::File::open(&fixture.0).unwrap();
        safe_read::macos::probe_unvalidated_for_test(Some(fd.as_fd()), &mut meter()).unwrap()
    };
    assert!(
        access.guarantee().is_some(),
        "BLOCKED: a real kernel read guarantee is required"
    );
    access
}

fn io<'a>(root: &'a Root, access: &'a Access, meter: &'a RefCell<Meter>) -> RepoIo<'a> {
    RepoIo::new(
        RepoRoots {
            worktree: root,
            gitdir: root,
            commondir: root,
        },
        access,
        meter,
    )
}

// 이것을 실패시키는 것: root 선택 혼동·외부 include 해석·loose 우선순위 제거·packed/HEAD 파서 결과 손상.
#[test]
fn git_bytes_ref_reads_are_confined() {
    let worktree = Fixture::new();
    let gitdir = Fixture::new();
    let common = Fixture::new();
    let outside = Fixture::new();
    outside.write("config", b"[test]\nvalue = OUTSIDE\n");
    common.write("config", format!("[test]\nvalue = common\n[include]\npath = {}\n[includeIf \"gitdir:**\"]\npath = {}\n[core]\nhooksPath = /outside\nattributesFile = /outside\nexcludesFile = /outside\nfsmonitor = /outside\n[filter \"evil\"]\nprocess = /outside\n", outside.0.join("config").display(), outside.0.join("config").display()));
    gitdir.write("config.worktree", b"[test]\nvalue = worktree\n");
    worktree.write("config", b"[test]\nvalue = WRONG\n");
    common.write(
        "packed-refs",
        format!("{A} refs/heads/z\n{B} refs/heads/a\n^{A}\n{A} refs/replace/{B}\n"),
    );
    common.write("refs/heads/a", format!("{A}\n"));
    gitdir.write("HEAD", b"ref: refs/heads/a\n");
    common.write("HEAD", format!("{B}\n"));
    gitdir.write("refs/worktree/private", format!("{B}\n"));
    common.write("refs/worktree/private", format!("{A}\n"));
    worktree.write("value", b"worktree");
    gitdir.write("value", b"gitdir");
    common.write("value", b"common");
    let access = access();
    let mut m = meter();
    let wr = worktree.root(&mut m);
    let gr = gitdir.root(&mut m);
    let cr = common.root(&mut m);
    let m = RefCell::new(m);
    let port = RepoIo::new(
        RepoRoots {
            worktree: &wr,
            gitdir: &gr,
            commondir: &cr,
        },
        &access,
        &m,
    );
    let mut repo = git::GuardedRepository::new(port);
    repo.config = Config::load(&repo.io).unwrap();
    repo.refs = Refs::load(&repo.io).unwrap();
    assert_eq!(
        repo.config
            .common()
            .unwrap()
            .string("test.value")
            .unwrap()
            .as_slice(),
        b"common"
    );
    assert_eq!(
        repo.config
            .worktree()
            .unwrap()
            .string("test.value")
            .unwrap()
            .as_slice(),
        b"worktree"
    );
    assert!(!repo.config.has_core_worktree());
    assert!(repo.refs.contains_replace());
    for (name, oid) in [
        (b"HEAD".as_slice(), A),
        (b"refs/heads/z", A),
        (b"refs/heads/a", A),
        (b"refs/worktree/private", B),
    ] {
        assert_eq!(
            repo.refs
                .resolve(&repo.io, name)
                .unwrap()
                .unwrap()
                .to_string(),
            oid
        );
    }
    assert_eq!(
        repo.refs.resolve(&repo.io, b"refs/heads/unborn").unwrap(),
        None
    );
    for (root, expected) in [
        (RootId::Worktree, b"worktree".as_slice()),
        (RootId::GitDir, b"gitdir"),
        (RootId::CommonDir, b"common"),
    ] {
        assert_eq!(
            repo.io.read(path(root, b"value"), cap(16)).unwrap(),
            expected
        );
        assert_eq!(
            repo.io.metadata(path(root, b"value")).unwrap().st_size,
            expected.len() as i64
        );
    }
    // Raw limits include dot entries; a complete list cannot hide truncation.
    #[cfg(target_os = "linux")]
    {
        let list = repo
            .io
            .list(path(RootId::CommonDir, b"refs/heads"), 16)
            .unwrap();
        assert!(list.complete && list.names == [b"a".to_vec()]);
        assert!(
            !repo
                .io
                .list(path(RootId::CommonDir, b"refs/heads"), 1)
                .unwrap()
                .complete
        );
    }
    #[cfg(target_os = "macos")]
    assert!(matches!(
        repo.io.list(path(RootId::CommonDir, b"refs/heads"), 16),
        Err(E::Denied)
    ));
    let before = m.borrow().counts;
    for bad in [b"/outside".as_slice(), b"../outside", b"x\0y"] {
        assert!(repo.io.read(path(RootId::GitDir, bad), cap(64)).is_err());
    }
    assert_eq!(
        m.borrow().counts[Phase::Content as usize].read,
        before[Phase::Content as usize].read
    );
}

// 이것을 실패시키는 것: preflight 뒤 경로 재신뢰·같은 fd 재사용 제거·I/O 중 RefCell borrow 유지.
#[test]
fn git_io_replacement_after_preflight_is_confined() {
    let fixture = Fixture::new();
    let outside = Fixture::new();
    fixture.write("config", b"[test]\nvalue=original\n");
    outside.write("secret", b"[test]\nvalue=OUTSIDE\n");
    let access = access();
    let mut m = meter();
    let root = fixture.root(&mut m);
    let m = Rc::new(RefCell::new(m));
    let port = io(&root, &access, &m);
    let config = Config::load(&port).unwrap(); // already-inspected repository, not a persistent trust grant
    let weak = Rc::downgrade(&m);
    let original = fixture.0.join("config");
    let saved = fixture.0.join("old");
    let secret = outside.0.join("secret");
    let mut replaced = false;
    m.borrow_mut().hook = Some(Box::new(move |event| {
        if event == "before_read" && !replaced {
            let shared = weak.upgrade().unwrap();
            assert_eq!(
                shared
                    .try_borrow_mut()
                    .expect("no borrow across I/O")
                    .check(),
                Err(E::Deadline)
            );
            fs::rename(&original, &saved).unwrap();
            symlink(&secret, &original).unwrap();
            replaced = true;
        }
    }));
    assert_eq!(
        port.read(path(RootId::CommonDir, b"config"), cap(64))
            .unwrap(),
        b"[test]\nvalue=original\n"
    );
    m.borrow_mut().hook = None;
    let before = m.borrow().counts[Phase::Content as usize].read;
    assert!(Config::load(&port).is_err());
    assert_eq!(m.borrow().counts[Phase::Content as usize].read, before);
    assert_eq!(
        config
            .common()
            .unwrap()
            .string("test.value")
            .unwrap()
            .as_slice(),
        b"original"
    );
    // The same post-inspection attack against a ref must never use packed data
    // to hide a denial (only Missing permits packed fallback).
    fixture.write("packed-refs", format!("{A} refs/heads/main\n"));
    fixture.write("refs/heads/main", format!("{B}\n"));
    let refs = Refs::load(&port).unwrap();
    fs::remove_file(fixture.0.join("refs/heads/main")).unwrap();
    symlink(outside.0.join("secret"), fixture.0.join("refs/heads/main")).unwrap();
    assert!(refs.resolve(&port, b"refs/heads/main").is_err());
    assert_eq!(m.borrow().counts[Phase::Content as usize].read, before + 2);
}

// 이것을 실패시키는 것: 보장 없는 일반 I/O 허용·미연결 map/object의 성공 또는 ambient fallback.
#[test]
fn git_io_scope_and_unsupported_are_closed() {
    let fixture = Fixture::new();
    fixture.write("config", b"[core]\nbare=false\n");
    let mut m = meter();
    let root = fixture.root(&mut m);
    let m = RefCell::new(m);
    let access = Access::stage_a_only();
    let port = io(&root, &access, &m);
    let before = m.borrow().counts;
    assert_eq!(
        port.read(path(RootId::GitDir, b"config"), cap(64)),
        Err(E::StageAOnly)
    );
    assert!(matches!(
        port.metadata(path(RootId::GitDir, b"config")),
        Err(E::StageAOnly)
    ));
    assert!(matches!(
        port.list(path(RootId::Worktree, b"."), 16),
        Err(E::StageAOnly)
    ));
    assert!(matches!(Config::load(&port), Err(E::StageAOnly)));
    assert!(matches!(Refs::load(&port), Err(E::StageAOnly)));
    assert_eq!(
        port.map(path(RootId::CommonDir, b"objects/pack/x"), 4096),
        Err(git::io::UNSUPPORTED)
    );
    assert_eq!(
        git::GuardedRepository::new(port).object(A.as_bytes()),
        Err(git::io::UNSUPPORTED)
    );
    assert_eq!(m.borrow().counts, before);
}

// 이것을 실패시키는 것: config/loose/packed cap 제거·공유 RefBytes/RefEntries charge 제거·cap 후 성장 허용.
#[test]
fn git_io_caps_and_shared_ref_budgets_precede_reads() {
    let fixture = Fixture::new();
    let access = access();
    let mut m = meter();
    let root = fixture.root(&mut m);
    let m = RefCell::new(m);
    let port = io(&root, &access, &m);
    let mut config = b"[core]\nworktree=\n#".to_vec();
    config.resize(budget::CONFIG_BYTES as usize, b'x');
    fixture.write("config", &config);
    assert!(Config::load(&port).unwrap().has_core_worktree());
    config.push(b'x');
    fixture.write("config", config);
    let before = m.borrow().counts[Phase::Content as usize].read;
    assert!(matches!(Config::load(&port), Err(E::Limit)));
    assert_eq!(m.borrow().counts[Phase::Content as usize].read, before);
    fixture.write(
        "refs/heads/large",
        vec![b'x'; budget::SMALL_FILE_BYTES as usize + 1],
    );
    assert_eq!(
        Refs::default().resolve(&port, b"refs/heads/large"),
        Err(E::Limit)
    );
    fixture.write("packed-refs", vec![b'x'; budget::REF_BYTES as usize + 1]);
    assert!(matches!(Refs::load(&port), Err(E::Limit)));
    assert_eq!(m.borrow().counts[Phase::Content as usize].read, before);
    fixture.write("refs/heads/main", format!("{A}\n"));
    m.borrow_mut()
        .budget
        .charge(Axis::RefBytes, budget::REF_BYTES - 40)
        .unwrap();
    assert_eq!(
        Refs::default().resolve(&port, b"refs/heads/main"),
        Err(E::Limit)
    );
    assert_eq!(m.borrow().counts[Phase::Content as usize].read, before);
    m.borrow_mut().budget.charge(Axis::RefBytes, 40).unwrap();
    let before_all = m.borrow().counts;
    assert_eq!(
        Refs::default().resolve(&port, b"refs/heads/main"),
        Err(E::Limit)
    );
    assert_eq!(
        m.borrow().counts[Phase::Content as usize].open,
        before_all[Phase::Content as usize].open
    );
    assert_eq!(
        m.borrow().counts[Phase::Content as usize].read,
        before_all[Phase::Content as usize].read
    );
    // Separate entry limit must close before any new filesystem operation.
    let m = RefCell::new(meter());
    m.borrow_mut()
        .budget
        .charge(Axis::RefEntries, budget::REF_ENTRIES)
        .unwrap();
    let port = io(&root, &access, &m);
    assert_eq!(
        Refs::default().resolve(&port, b"refs/heads/main"),
        Err(E::Limit)
    );
    assert_eq!(m.borrow().counts[Phase::Content as usize].open, 0);
    assert_eq!(m.borrow().counts[Phase::Content as usize].read, 0);
    // Mutation during read cannot silently exceed the fstat-sized reservation.
    let m = RefCell::new(meter());
    let file = fixture.0.join("refs/heads/main");
    let mut grown = false;
    m.borrow_mut().hook = Some(Box::new(move |event| {
        if event == "before_read" && !grown {
            fs::write(&file, format!("{A}\nextra")).unwrap();
            grown = true;
        }
    }));
    let port = io(&root, &access, &m);
    assert_eq!(
        Refs::default().resolve(&port, b"refs/heads/main"),
        Err(E::Limit)
    );
    assert_eq!(m.borrow().budget.used(Axis::RefBytes), 41);
    assert_eq!(m.borrow().counts[Phase::Content as usize].read_bytes, 42);
}

// 이것을 실패시키는 것: Missing 외 오류를 없음으로 처리·hardlink/일반 파일 검사 제거·잘못된 config 무시.
#[test]
fn git_config_failures_and_worktree_policy_are_explicit() {
    let fixture = Fixture::new();
    let access = access();
    let mut m = meter();
    let root = fixture.root(&mut m);
    let m = RefCell::new(m);
    let port = io(&root, &access, &m);
    let absent = Config::load(&port).unwrap();
    assert!(absent.common().is_none() && absent.worktree().is_none());
    fixture.write("config.worktree", b"[CoRe]\nWorkTree=/\n");
    assert!(Config::load(&port).unwrap().has_core_worktree());
    fixture.write("config", b"[broken");
    assert!(matches!(Config::load(&port), Err(INVALID)));
    fixture.write("config", b"[core]\nbare=false\n");
    fs::hard_link(fixture.0.join("config"), fixture.0.join("hard")).unwrap();
    assert!(matches!(Config::load(&port), Err(E::Special)));
    fs::remove_file(fixture.0.join("config")).unwrap();
    fs::create_dir(fixture.0.join("config")).unwrap();
    assert!(matches!(Config::load(&port), Err(E::Special)));
    fs::remove_dir(fixture.0.join("config")).unwrap();
    let cpath = std::ffi::CString::new(fixture.0.join("config").as_os_str().as_bytes()).unwrap();
    // SAFETY: test-only FIFO with a live NUL-terminated fixture path.
    assert_eq!(unsafe { libc::mkfifo(cpath.as_ptr(), 0o600) }, 0);
    let before = m.borrow().counts[Phase::Content as usize].read;
    assert!(matches!(Config::load(&port), Err(E::Special)));
    assert_eq!(m.borrow().counts[Phase::Content as usize].read, before);
}

// 이것을 실패시키는 것: symref cycle/depth 제한 제거·잘못된 이름/해시/추가 줄 허용·private ref의 packed fallback.
#[test]
fn git_loose_refs_validate_names_cycles_and_depth() {
    let fixture = Fixture::new();
    let access = access();
    let mut m = meter();
    let root = fixture.root(&mut m);
    let m = RefCell::new(m);
    let port = io(&root, &access, &m);
    assert!(!Refs::load(&port).unwrap().contains_replace());
    for suffix in ["", "\n", "\r\n"] {
        assert_eq!(
            refs::parse_loose(format!("{A}{suffix}").as_bytes()).unwrap(),
            Target::Object(refs::ObjectId::from_hex(A.as_bytes()).unwrap())
        );
    }
    assert_eq!(
        refs::parse_loose(b"ref: refs/heads/main\n"),
        Ok(Target::Symbolic(b"refs/heads/main".to_vec()))
    );
    for bad in [
        b"ref: /outside".as_slice(),
        b"ref: refs/../config",
        b"ref: refs//main",
        b"ref: refs/heads/x.lock",
        b"ref: refs/heads/x\0",
        b"ref: main-worktree/HEAD",
        b"ref: config",
        b"ref: refs/heads/x\nextra",
        b"not-a-hash",
        b"zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
        b"1111111111111111111111111111111111111111111111111111111111111111",
    ] {
        assert!(refs::parse_loose(bad).is_err(), "{bad:?}");
    }
    assert_eq!(
        refs::parse_loose(&vec![b'x'; budget::SMALL_FILE_BYTES as usize + 1]),
        Err(E::Limit)
    );
    for bad in [b"config".as_slice(), b"/outside", b"refs/../config"] {
        let before = m.borrow().counts;
        assert!(Refs::default().resolve(&port, bad).is_err());
        assert_eq!(m.borrow().counts, before);
    }
    let oversized_name = [
        b"refs/heads/".as_slice(),
        &vec![b'x'; budget::SMALL_FILE_BYTES as usize],
    ]
    .concat();
    let before = m.borrow().counts;
    assert_eq!(
        Refs::default().resolve(&port, &oversized_name),
        Err(INVALID)
    );
    assert_eq!(m.borrow().counts, before);
    fixture.write("refs/heads/hard", format!("{A}\n"));
    fs::hard_link(fixture.0.join("refs/heads/hard"), fixture.0.join("alias")).unwrap();
    assert_eq!(
        Refs::default().resolve(&port, b"refs/heads/hard"),
        Err(E::Special)
    );
    fixture.write("refs/heads/x", b"ref: refs/heads/y\n");
    fixture.write("refs/heads/y", b"ref: refs/heads/x\n");
    assert_eq!(
        Refs::default().resolve(&port, b"refs/heads/x"),
        Err(E::Symlink)
    );
    for n in 0..40 {
        fixture.write(
            &format!("refs/heads/{n}"),
            format!("ref: refs/heads/{}\n", n + 1),
        );
    }
    fixture.write(&format!("refs/heads/{}", 40 - 1), format!("{A}\n"));
    assert!(
        Refs::default()
            .resolve(&port, b"refs/heads/0")
            .unwrap()
            .is_some()
    );
    fixture.write(
        &format!("refs/heads/{}", 40 - 1),
        format!("ref: refs/heads/{}\n", 40),
    );
    fixture.write(&format!("refs/heads/{}", 40), format!("{A}\n"));
    assert_eq!(
        Refs::default().resolve(&port, b"refs/heads/0"),
        Err(E::Limit)
    );
    fixture.write("packed-refs", format!("{A} refs/worktree/missing\n"));
    assert_eq!(
        Refs::load(&port)
            .unwrap()
            .resolve(&port, b"refs/worktree/missing")
            .unwrap(),
        None
    );
    fixture.write("packed-refs", format!("{A} refs/heads/broken\n"));
    fixture.write("refs/heads/broken", b"broken");
    assert_eq!(
        Refs::load(&port)
            .unwrap()
            .resolve(&port, b"refs/heads/broken"),
        Err(INVALID)
    );
}

// 이것을 실패시키는 것: packed 항목 사전 charge 제거·sorted 헤더 맹신·중복/손상/잘못된 ref 이름 허용.
#[test]
fn git_packed_refs_validate_every_entry_before_sorting() {
    let fixture = Fixture::new();
    let access = access();
    let mut m = meter();
    let root = fixture.root(&mut m);
    for bytes in [
        format!("# pack-refs with: sorted\n{A} refs/heads/z\n{B} refs/heads/a\n"),
        format!("{A} refs/heads/x\n{B} refs/heads/x\n"),
        format!("{A} refs/heads/good\nmalformed tail\n"),
        format!("{A} config\n"),
        "# broken header\n".into(),
        format!(
            "{A} refs/heads/{}\n",
            "x".repeat(budget::SMALL_FILE_BYTES as usize)
        ),
    ] {
        fixture.write("packed-refs", bytes);
        let m = RefCell::new(meter());
        assert!(matches!(Refs::load(&io(&root, &access, &m)), Err(INVALID)));
    }
    for count in [budget::REF_ENTRIES, budget::REF_ENTRIES + 1] {
        let bytes: String = (0..count)
            .rev()
            .map(|n| format!("{A} refs/heads/{n:04}\n"))
            .collect();
        fixture.write("packed-refs", bytes);
        let m = RefCell::new(meter());
        let port = io(&root, &access, &m);
        let loaded = Refs::load(&port);
        if count == budget::REF_ENTRIES {
            assert!(loaded.is_ok());
        } else {
            assert!(matches!(loaded, Err(E::Limit)));
        }
        assert_eq!(
            m.borrow().budget.used(Axis::RefEntries),
            budget::REF_ENTRIES
        );
    }
    fixture.write("packed-refs", b"");
    let m = RefCell::new(meter());
    assert!(
        !Refs::load(&io(&root, &access, &m))
            .unwrap()
            .contains_replace()
    );
}

// 이것을 실패시키는 것: meter 반환 누락·마감 초기화·panic 때 실제 counters를 잃는 것.
#[test]
fn git_io_meter_restores_counters_on_unwind_and_deadline() {
    let fixture = Fixture::new();
    fixture.write("value", b"original");
    let access = access();
    let mut m = meter();
    let root = fixture.root(&mut m);
    let m = RefCell::new(m);
    let port = io(&root, &access, &m);
    m.borrow_mut().hook = Some(Box::new(|event| {
        if event == "before_read" {
            panic!("injected read panic");
        }
    }));
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(
            || port.read(path(RootId::GitDir, b"value"), cap(8))
        ))
        .is_err()
    );
    assert!(m.borrow().budget.used(Axis::Stats) > 0);
    assert!(m.borrow().counts[Phase::Content as usize].open > 0);
    m.borrow_mut().hook = None;
    assert_eq!(
        port.read(path(RootId::GitDir, b"value"), cap(8)).unwrap(),
        b"original"
    );
    m.replace(Meter::new(Instant::now()));
    assert_eq!(
        port.read(path(RootId::GitDir, b"value"), cap(8)),
        Err(E::Deadline)
    );
    assert_eq!(m.borrow().counts, [meter::Counters::default(); 3]);
}

// 이것을 실패시키는 것: bytes 경계에 ambient 파일/환경/process 또는 path 생성자를 추가하는 것.
#[test]
fn gix_io_has_no_ambient_path_escape() {
    let files = [
        include_str!("../src/git/mod.rs"),
        include_str!("../src/git/io.rs"),
        include_str!("../src/git/config.rs"),
        include_str!("../src/git/refs.rs"),
    ];
    for source in files {
        for forbidden in [
            "std::fs",
            "std::env",
            "std::process",
            "Command::",
            "libc::open",
            "libc::read",
            "from_bytes_owned",
            "from_path",
            "from_globals",
            "from_git_dir",
            "from_env",
            "includes::resolve",
            "::open(",
            "Store::",
            "gix::",
            "gix_status",
            "gix_filter",
            "gix_diff",
            "select_metadata",
            "safe_read::acquire",
        ] {
            assert!(!source.contains(forbidden), "ambient API {forbidden}");
        }
    }
    assert_eq!(
        files[2]
            .matches("gix_config::File::from_bytes_no_includes(")
            .count(),
        1
    );
    assert_eq!(
        files[3]
            .matches("gix_ref::packed::Buffer::from_bytes(")
            .count(),
        1
    );
}

// 이것을 실패시키는 것: 실제 parser 대신 빈 결과를 재거나 I/O를 반복 없이 재사용하는 것.
#[test]
fn git_parser_observations() {
    let fixture = Fixture::new();
    let access = access();
    let root = fixture.root(&mut meter());
    for count in [1024, 4096] {
        let mut config =
            b"[core]\nbare=false\n[branch \"main\"]\nremote=origin\nmerge=refs/heads/main\n"
                .to_vec();
        if count == 4096 {
            // Dense hostile input: 16,384 sections, not padding/comments.
            config = b"[x]\n".repeat(budget::CONFIG_BYTES as usize / 4);
        }
        fixture.write("config", &config);
        let packed: String = (0..count)
            .rev()
            .map(|n| format!("{A} refs/heads/{n:011}\n"))
            .collect();
        fixture.write("packed-refs", &packed);
        let mut samples = Vec::new();
        for _ in 0..201 {
            let m = RefCell::new(meter());
            let port = io(&root, &access, &m);
            let start = Instant::now();
            assert!(Config::load(&port).unwrap().common().is_some());
            assert!(!Refs::load(&port).unwrap().contains_replace());
            samples.push(start.elapsed().as_nanos());
            assert_eq!(m.borrow().budget.used(Axis::RefEntries), count);
            assert_eq!(m.borrow().budget.used(Axis::RefBytes), packed.len() as u64);
            assert_eq!(
                m.borrow().counts[Phase::Content as usize].read_bytes,
                (config.len() + packed.len()) as u64
            );
            if samples.len() == 201 {
                eprintln!(
                    "C2_COUNTS {count} {:?}",
                    m.borrow().counts[Phase::Content as usize]
                );
            }
        }
        assert!(samples.iter().all(|n| *n > 0));
        eprintln!("C2_PARSER_NS {count} {samples:?}");
    }
}
