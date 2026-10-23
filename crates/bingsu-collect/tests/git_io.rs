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

#[path = "support/allocation.rs"]
mod allocation;

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
    outside.write("config", b"[core]\nbare = OUTSIDE\n");
    common.write("config", format!("[core]\nbare = common\n[include]\npath = {}\n[includeIf \"gitdir:**\"]\npath = {}\n[core]\nhooksPath = /outside\nattributesFile = /outside\nexcludesFile = /outside\nfsmonitor = /outside\n[filter \"evil\"]\nprocess = /outside\n", outside.0.join("config").display(), outside.0.join("config").display()));
    gitdir.write("config.worktree", b"[core]\nbare = worktree\n");
    worktree.write("config", b"[core]\nbare = WRONG\n");
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
    let repo = git::GuardedRepository::new(port).unwrap();
    assert_eq!(
        repo.config.common().unwrap().value("core.bare").unwrap(),
        Some(b"common".as_slice())
    );
    assert_eq!(
        repo.config.worktree().unwrap().value("core.bare").unwrap(),
        Some(b"worktree".as_slice())
    );
    assert!(!repo.config.has_core_worktree());
    assert_eq!(repo.object(A.as_bytes()), Err(git::io::UNSUPPORTED));
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
    fixture.write("config", b"[core]\nbare=original\n");
    outside.write("secret", b"[core]\nbare=OUTSIDE\n");
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
        b"[core]\nbare=original\n"
    );
    m.borrow_mut().hook = None;
    let before = m.borrow().counts[Phase::Content as usize].read;
    assert!(Config::load(&port).is_err());
    assert_eq!(m.borrow().counts[Phase::Content as usize].read, before);
    assert_eq!(
        config.common().unwrap().value("core.bare").unwrap(),
        Some(b"original".as_slice())
    );
    // The same post-inspection attack against a ref must never use packed data
    // to hide a denial (only Missing permits packed fallback).
    fs::remove_file(fixture.0.join("config")).unwrap();
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
    assert_eq!(git::GuardedRepository::new(port).err(), Some(E::StageAOnly));
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
    fs::remove_file(fixture.0.join("config")).unwrap();
    fixture.write(
        "refs/heads/large",
        vec![b'x'; budget::SMALL_FILE_BYTES as usize + 1],
    );
    assert_eq!(
        Refs::load(&port)
            .unwrap()
            .resolve(&port, b"refs/heads/large"),
        Err(E::Limit)
    );
    fixture.write("packed-refs", vec![b'x'; budget::REF_BYTES as usize + 1]);
    assert!(matches!(Refs::load(&port), Err(E::Limit)));
    assert_eq!(m.borrow().counts[Phase::Content as usize].read, before);
    fs::remove_file(fixture.0.join("packed-refs")).unwrap();
    let refs = Refs::load(&port).unwrap();
    fixture.write("refs/heads/main", format!("{A}\n"));
    m.borrow_mut()
        .budget
        .charge(Axis::RefBytes, budget::REF_BYTES - 40)
        .unwrap();
    assert_eq!(refs.resolve(&port, b"refs/heads/main"), Err(E::Limit));
    assert_eq!(m.borrow().counts[Phase::Content as usize].read, before);
    m.borrow_mut().budget.charge(Axis::RefBytes, 40).unwrap();
    let before_all = m.borrow().counts;
    assert_eq!(refs.resolve(&port, b"refs/heads/main"), Err(E::Limit));
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
    assert_eq!(refs.resolve(&port, b"refs/heads/main"), Err(E::Limit));
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
    assert_eq!(refs.resolve(&port, b"refs/heads/main"), Err(E::Limit));
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
    let refs = Refs::load(&port).unwrap();
    assert!(!refs.contains_replace());
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
        assert!(refs.resolve(&port, bad).is_err());
        assert_eq!(m.borrow().counts, before);
    }
    let oversized_name = [
        b"refs/heads/".as_slice(),
        &vec![b'x'; budget::SMALL_FILE_BYTES as usize],
    ]
    .concat();
    let before = m.borrow().counts;
    assert_eq!(refs.resolve(&port, &oversized_name), Err(INVALID));
    assert_eq!(m.borrow().counts, before);
    fixture.write("refs/heads/hard", format!("{A}\n"));
    fs::hard_link(fixture.0.join("refs/heads/hard"), fixture.0.join("alias")).unwrap();
    assert_eq!(refs.resolve(&port, b"refs/heads/hard"), Err(E::Special));
    fixture.write("refs/heads/x", b"ref: refs/heads/y\n");
    fixture.write("refs/heads/y", b"ref: refs/heads/x\n");
    assert_eq!(refs.resolve(&port, b"refs/heads/x"), Err(E::Symlink));
    for n in 0..40 {
        fixture.write(
            &format!("refs/heads/{n}"),
            format!("ref: refs/heads/{}\n", n + 1),
        );
    }
    fixture.write(&format!("refs/heads/{}", 40 - 1), format!("{A}\n"));
    // 이것을 실패시키는 것: 40 reads (39 hops) 경계를 39 또는 41 reads로 바꾸는 것.
    let before_reads = m.borrow().budget.used(Axis::RefEntries);
    assert!(refs.resolve(&port, b"refs/heads/0").unwrap().is_some());
    assert_eq!(m.borrow().budget.used(Axis::RefEntries) - before_reads, 40);
    fixture.write(
        &format!("refs/heads/{}", 40 - 1),
        format!("ref: refs/heads/{}\n", 40),
    );
    fixture.write(&format!("refs/heads/{}", 40), format!("{A}\n"));
    assert_eq!(refs.resolve(&port, b"refs/heads/0"), Err(E::Limit));
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
    // 이것을 실패시키는 것: RepoIo::metered의 진입 slot.check() 제거.
    // Inner I/O has its own deadline check, so observe closure entry directly.
    let entered = std::cell::Cell::new(false);
    assert_eq!(
        port.metered(|_| {
            entered.set(true);
            Ok(())
        }),
        Err(E::Deadline)
    );
    assert!(!entered.get());
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
            // Largest accepted structural corpus, padded to the byte cap.
            config = bounded_config("mixed", 256, 1023);
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
            let repo = git::GuardedRepository::new(port).unwrap();
            assert_eq!(
                repo.config.common().unwrap().value("core.bare"),
                Some(Some(b"false".as_slice()))
            );
            assert!(!repo.refs.contains_replace());
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
        assert_eq!(samples.len(), 201);
        // 이것을 실패시키는 것: metered 진입 검사를 지워 만료 뒤 parser closure를 실행하는 것.
        let expired = RefCell::new(Meter::new(Instant::now()));
        let port = io(&root, &access, &expired);
        let entered = std::cell::Cell::new(false);
        assert_eq!(
            port.metered(|_| {
                entered.set(true);
                Ok(())
            }),
            Err(E::Deadline)
        );
        assert!(!entered.get());
        eprintln!("C2_PARSER_NS {count} {samples:?}");
    }
}

fn bounded_config(kind: &str, sections: usize, lines: usize) -> Vec<u8> {
    let mut bytes = match kind {
        "implicit" => [b"[x]".to_vec(), b"a ".repeat(git::config::WORD_LIMIT - 1)].concat(),
        "implicit-sections" => {
            let mut b = (0..sections)
                .map(|n| format!("[x{n}]"))
                .collect::<String>()
                .into_bytes();
            b.extend_from_slice(&b"a ".repeat(git::config::WORD_LIMIT - sections));
            b
        }
        "distributed-implicit" => {
            let mut b = Vec::new();
            let mut remaining = git::config::WORD_LIMIT - sections;
            for n in 0..sections {
                b.extend_from_slice(format!("[x{n}]").as_bytes());
                let keys = remaining.div_ceil(sections - n);
                b.extend_from_slice(&b"a ".repeat(keys));
                remaining -= keys;
            }
            b
        }
        "implicit-policy" => {
            let mut b = (0..sections - 1)
                .map(|n| format!("[x{n}]"))
                .collect::<String>()
                .into_bytes();
            b.extend_from_slice(b"[core]");
            b.extend_from_slice(&b"a ".repeat(git::config::WORD_LIMIT - sections - 1));
            b.extend_from_slice(b"eol=");
            b.resize(budget::CONFIG_BYTES as usize, b'_');
            return b;
        }
        "escaped-subsections" => {
            let mut b = Vec::new();
            let width = (budget::CONFIG_BYTES as usize / sections - 8) / 2;
            for _ in 0..sections {
                b.extend_from_slice(b"[x \"");
                b.extend_from_slice(&b"\\\"".repeat(width));
                b.extend_from_slice(b"\"]\n");
            }
            b
        }
        "adjacent" => b"[x]".repeat(sections),
        "unique" => (0..sections)
            .map(|n| format!("[x{n}]\n"))
            .collect::<String>()
            .into_bytes(),
        "subsections" => (0..sections)
            .map(|n| format!("[x \"{n}\\\"\"]\n"))
            .collect::<String>()
            .into_bytes(),
        "continuations" => [
            b"[core]\neol=".to_vec(),
            b"\\\n".repeat(lines - 2),
            b"x\n".to_vec(),
        ]
        .concat(),
        _ => {
            let mut b = b"[core]\nbare=false\n".to_vec();
            for n in 1..sections {
                b.extend_from_slice(format!("[x{n}]\na=\"b c\"\n").as_bytes());
            }
            while b.iter().filter(|c| **c == b'\n').count() < lines {
                b.extend_from_slice(b"a=\"b c\"\n");
            }
            b
        }
    };
    bytes.push(b'#');
    bytes.resize(budget::CONFIG_BYTES as usize, b'_');
    bytes
}

// 이것을 실패시키는 것: 사전 section/line/word/byte 제한 또는 allocation 예약을 제거하거나 파싱 뒤로 옮기는 것.
#[test]
fn git_config_bounds_refuse_before_parser() {
    for bytes in [
        b"[x]".repeat(257),
        b"[x]\n".repeat(257),
        [b"[x]\n".to_vec(), b"a\n".repeat(1024)].concat(),
        [b"[x]".to_vec(), b"a ".repeat(4096)].concat(),
        vec![b' '; budget::CONFIG_BYTES as usize + 1],
    ] {
        let entered = Rc::new(std::cell::Cell::new(0));
        let counter = entered.clone();
        let mut m = meter();
        m.hook = Some(Box::new(move |event| {
            if event == "before_config_parse" {
                counter.set(counter.get() + 1);
            }
        }));
        let (result, allocations) = allocation::measure(|| git::config::parse(&bytes, &mut m));
        assert!(matches!(result, Err(E::Limit)));
        assert_eq!(entered.get(), 0);
        assert_eq!(allocations.calls, 0);
        assert_eq!(m.counts[Phase::Content as usize].allocated, 0);
    }
    let mut m = meter();
    m.allocation_limit = (git::config::PARSER_ALLOCATION - 1) as u64;
    let (result, allocations) =
        allocation::measure(|| git::config::parse(b"[core]\nbare=false\n", &mut m));
    assert!(matches!(result, Err(E::Limit)));
    assert_eq!(allocations.calls, 0);
}

// 이것을 실패시키는 것: config/packed parser의 선차감량을 실측 peak보다 줄이거나 gix File을 보관하는 것.
#[test]
fn git_parser_charges_cover_counted_peak() {
    let mut max_config = (0, String::new());
    for kind in [
        "mixed",
        "implicit",
        "implicit-sections",
        "distributed-implicit",
        "implicit-policy",
        "escaped-subsections",
        "adjacent",
        "unique",
        "subsections",
        "continuations",
    ] {
        let section_counts: Vec<_> = if kind.ends_with("implicit") || kind == "implicit-sections" {
            (1..=256).collect()
        } else {
            vec![1, 127, 128, 129, 255, 256]
        };
        for sections in section_counts {
            for lines in [512, 513, 1023] {
                let bytes = bounded_config(kind, sections, lines);
                let mut m = meter();
                let (facts, counts) = allocation::measure(|| git::config::parse(&bytes, &mut m));
                let facts = facts.unwrap();
                let charged = m.counts[Phase::Content as usize].allocated;
                assert!(
                    counts.peak as u64 <= charged,
                    "{kind}/{sections}/{lines}: {counts:?} > {charged}"
                );
                assert!(
                    counts.live <= budget::CONFIG_BYTES as usize,
                    "gix File retained: {counts:?}"
                );
                if counts.peak > max_config.0 {
                    max_config = (counts.peak, format!("{kind}/{sections}/{lines}"));
                }
                drop(facts);
            }
        }
    }
    for sections in [1, 127, 255, 256] {
        let mut bytes = bounded_config("implicit-sections", sections, 512);
        let comment = bytes.iter().position(|b| *b == b'#').unwrap();
        bytes[comment..].fill(b' ');
        *bytes.last_mut().unwrap() = b'~';
        let mut m = meter();
        let (bad, counts) = allocation::measure(|| git::config::parse(&bytes, &mut m));
        assert!(matches!(bad, Err(INVALID)));
        assert!(counts.peak as u64 <= m.counts[Phase::Content as usize].allocated);
        if counts.peak > max_config.0 {
            max_config = (counts.peak, format!("malformed/{sections}"));
        }
    }
    // Both repository files are loaded together, but neither gix File survives.
    let fixture = Fixture::new();
    let bytes = bounded_config("implicit-sections", 256, 512);
    fixture.write("config", &bytes);
    fixture.write("config.worktree", &bytes);
    let access = access();
    let root = fixture.root(&mut meter());
    let m = RefCell::new(meter());
    let port = io(&root, &access, &m);
    let (config, counts) = allocation::measure(|| Config::load(&port));
    let config = config.unwrap();
    assert!(config.common().is_some() && config.worktree().is_some());
    assert_eq!(counts.live, 0, "parser trees retained across config files");
    assert!(counts.peak as u64 <= m.borrow().counts[Phase::Content as usize].allocated);
    // Extraction holds a large normalized policy value while File is still live.
    let mut bytes = b"[core]\neol=\"".to_vec();
    bytes.extend_from_slice(&b"\\t".repeat(git::config::WORD_LIMIT - 2));
    bytes.resize(budget::CONFIG_BYTES as usize - 2, b'_');
    bytes.extend_from_slice(b"\"\n");
    let mut m = meter();
    let (facts, counts) = allocation::measure(|| git::config::parse(&bytes, &mut m));
    assert!(
        facts
            .unwrap()
            .value("core.eol")
            .unwrap()
            .unwrap()
            .iter()
            .all(|b| *b == b'\t' || *b == b'_')
    );
    assert!(counts.peak as u64 <= m.counts[Phase::Content as usize].allocated);
    max_config.0 = max_config.0.max(counts.peak);
    let mut max_packed = 0;
    for count in [1, 1023, 1024, 1025, 2047, 2048, 2049, 4095, 4096] {
        for sorted in [false, true] {
            for peeled in [false, true] {
                let header = if sorted {
                    "# pack-refs with: sorted\n"
                } else {
                    ""
                };
                let width = ((budget::REF_BYTES as usize - header.len()) / count)
                    .saturating_sub(53 + usize::from(peeled) * 42)
                    .min(budget::SMALL_FILE_BYTES as usize - 11);
                if width < 4 {
                    continue;
                }
                let mut packed = header.to_owned();
                for i in 0..count {
                    let n = if sorted { i } else { count - i - 1 };
                    packed.push_str(&format!("{A} refs/heads/{n:0width$}\n"));
                    if peeled {
                        packed.push_str(&format!("^{B}\n"));
                    }
                }
                let mut m = meter();
                let (refs, counts) = allocation::measure(|| Refs::parse(packed.as_bytes(), &mut m));
                let refs = refs.unwrap_or_else(|e| {
                    panic!("{count}/{sorted}/{peeled}: {e:?}, bytes={}", packed.len())
                });
                assert!(!refs.contains_replace());
                assert!(
                    counts.peak as u64 <= m.counts[Phase::Content as usize].allocated,
                    "{count}/{sorted}/{peeled}: {counts:?}"
                );
                max_packed = max_packed.max(counts.peak);
            }
        }
    }
    // A missing final LF must fail within the same reservation. Vary
    // early record widths to hit Vec growth just below the byte cap, as well as
    // the entry-vector growth boundary, instead of assuming equal-width refs
    // produce the largest transient allocation.
    for count in [2049, 4096] {
        for first_width in [4, 11, 12, 27, 28, 59, 60, 71, 72, 75, 76, 127, 128, 255] {
            let mut packed = format!("{A} refs/heads/a{0:0first_width$}\n", 0);
            for n in 1..count {
                packed.push_str(&format!("{A} refs/heads/z{n:04}\n"));
            }
            packed.pop();
            let pad = (budget::REF_BYTES as usize - 1 - packed.len())
                .min(budget::SMALL_FILE_BYTES as usize - 16);
            packed.extend(std::iter::repeat_n('_', pad));
            let mut m = meter();
            let (bad, counts) = allocation::measure(|| Refs::parse(packed.as_bytes(), &mut m));
            assert!(matches!(bad, Err(INVALID)));
            assert!(counts.peak as u64 <= m.counts[Phase::Content as usize].allocated);
            packed.push('\n');
            let mut m = meter();
            let (refs, counts) = allocation::measure(|| Refs::parse(packed.as_bytes(), &mut m));
            assert!(
                refs.is_ok(),
                "uneven {count}/{first_width}: {:?}, len={}",
                refs.err(),
                packed.len()
            );
            assert!(
                counts.peak as u64 <= m.counts[Phase::Content as usize].allocated,
                "uneven {count}/{first_width}: {counts:?}"
            );
            max_packed = max_packed.max(counts.peak);
        }
    }
    eprintln!(
        "C2_ALLOC config_peak={} corpus={} config_charge={} packed_peak={} packed_charge={}",
        max_config.0,
        max_config.1,
        git::config::PARSER_ALLOCATION,
        max_packed,
        refs::PARSER_ALLOCATION
    );
    // Measured corpus must really exercise amplification, not an empty parser.
    assert!(max_config.0 > budget::CONFIG_BYTES as usize * 4);
    assert!(max_packed > budget::REF_BYTES as usize * 3);
}

// 이것을 실패시키는 것: implicit core.worktree를 raw_value로 검사하거나 마지막 core section만 보는 것.
#[test]
fn git_config_implicit_worktree_and_retained_facts() {
    let fixture = Fixture::new();
    let access = access();
    let root = fixture.root(&mut meter());
    for file in ["config", "config.worktree"] {
        for value in ["worktree", "WoRkTrEe=", "WORKTREE=/"] {
            fixture.write(file, format!("[CoRe]\n\t{value}\n[core]\nbare=false\n"));
            let m = RefCell::new(meter());
            assert!(
                Config::load(&io(&root, &access, &m))
                    .unwrap()
                    .has_core_worktree()
            );
        }
        fixture.write(file, b"[core \"sub\"]\nworktree\n[core.other]\nworktree=/\n[core]\nrepositoryFormatVersion=1\nbare=false\nfileMode\nsymlinks=true\nignoreCase=false\nprecomposeUnicode=true\ncheckStat=minimal\ntrustCtime=false\nautocrlf=input\neol=lf\n[core]\ncheckStat=default\n[extensions]\nworktreeConfig=true\nobjectFormat=sha1\nrefStorage=files\n[index]\nsparse=false\n");
        let m = RefCell::new(meter());
        let config = Config::load(&io(&root, &access, &m)).unwrap();
        assert!(!config.has_core_worktree());
        let facts = config.common().or_else(|| config.worktree()).unwrap();
        for (key, expected) in [
            ("core.repositoryformatversion", Some(b"1".as_slice())),
            ("core.bare", Some(b"false".as_slice())),
            ("core.symlinks", Some(b"true".as_slice())),
            ("core.ignorecase", Some(b"false".as_slice())),
            ("core.precomposeunicode", Some(b"true".as_slice())),
            ("core.eol", Some(b"lf".as_slice())),
            ("index.sparse", Some(b"false".as_slice())),
            ("extensions.objectformat", Some(b"sha1".as_slice())),
            ("extensions.refstorage", Some(b"files".as_slice())),
            ("core.filemode", None),
            ("core.checkstat", Some(b"default".as_slice())),
            ("core.trustctime", Some(b"false".as_slice())),
            ("core.autocrlf", Some(b"input".as_slice())),
            ("extensions.worktreeconfig", Some(b"true".as_slice())),
        ] {
            assert_eq!(facts.value(key), Some(expected));
        }
        assert_eq!(facts.value("include.path"), None);
        fs::remove_file(fixture.0.join(file)).unwrap();
    }
}

// 이것을 실패시키는 것: refStorage/objectFormat/version/unknown extension 또는 gitdir/commondir reftable 검사를 빼는 것.
#[test]
fn git_unsupported_formats_stop_before_refs_and_objects() {
    let gitdir = Fixture::new();
    let common = Fixture::new();
    let access = access();
    let gr = gitdir.root(&mut meter());
    let cr = common.root(&mut meter());
    // Reftable's refs/heads is a FILE. Without preflight, ENOTDIR becomes Missing
    // in the read layer, and resolving HEAD would incorrectly report unborn.
    common.write("refs/heads", b"this repository uses reftable\n");
    gitdir.write("HEAD", b"ref: refs/heads/main\n");
    common.write("packed-refs", b"malformed: must not be parsed");
    for config in [
        "[extensions]\nrefStorage=reftable\n",
        "[core]\nrepositoryFormatVersion=1\n[extensions]\nobjectFormat=sha256\n",
        "[core]\nrepositoryFormatVersion=2\n",
        "[extensions]\nunknown=true\n",
        "[extensions]\nobjectFormat\n",
        "[extensions]\nrefStorage\n",
    ] {
        for file in [common.0.join("config"), gitdir.0.join("config.worktree")] {
            fs::write(&file, config).unwrap();
            let m = RefCell::new(meter());
            let port = RepoIo::new(
                RepoRoots {
                    worktree: &gr,
                    gitdir: &gr,
                    commondir: &cr,
                },
                &access,
                &m,
            );
            assert!(matches!(Refs::load(&port), Err(E::StageAOnly)));
            assert_eq!(m.borrow().budget.used(Axis::RefBytes), 0);
            assert!(matches!(
                git::GuardedRepository::new(port),
                Err(E::StageAOnly)
            ));
            assert_eq!(m.borrow().budget.used(Axis::RefEntries), 0);
            fs::remove_file(file).unwrap();
        }
    }
    for root in [&gitdir, &common] {
        fs::create_dir(root.0.join("reftable")).unwrap();
        let m = RefCell::new(meter());
        let port = RepoIo::new(
            RepoRoots {
                worktree: &gr,
                gitdir: &gr,
                commondir: &cr,
            },
            &access,
            &m,
        );
        assert!(matches!(Refs::load(&port), Err(E::StageAOnly)));
        assert!(matches!(
            git::GuardedRepository::new(port),
            Err(E::StageAOnly)
        ));
        assert_eq!(m.borrow().counts[Phase::Content as usize].read, 0);
        fs::remove_dir(root.0.join("reftable")).unwrap();
    }
    // 이것을 실패시키는 것: reftable marker의 접근 오류를 Missing으로 삼는 것.
    let outside = Fixture::new();
    symlink(&outside.0, gitdir.0.join("reftable")).unwrap();
    let m = RefCell::new(meter());
    let port = RepoIo::new(
        RepoRoots {
            worktree: &gr,
            gitdir: &gr,
            commondir: &cr,
        },
        &access,
        &m,
    );
    assert!(matches!(
        Refs::load(&port),
        Err(E::Escape | E::Symlink | E::Denied)
    ));
    fs::remove_file(gitdir.0.join("reftable")).unwrap();
    fs::remove_file(common.0.join("packed-refs")).unwrap();
    common.write("config", b"[core]\nrepositoryFormatVersion=1\n[extensions]\nobjectFormat=sha1\nrefStorage=files\nnoop=true\n");
    let m = RefCell::new(meter());
    let port = RepoIo::new(
        RepoRoots {
            worktree: &gr,
            gitdir: &gr,
            commondir: &cr,
        },
        &access,
        &m,
    );
    assert_eq!(
        git::GuardedRepository::new(port)
            .unwrap()
            .object(A.as_bytes()),
        Err(git::io::UNSUPPORTED)
    );
}

// 이것을 실패시키는 것: packed Buffer 생성 전에 byte/entry/할당 상한을 검사하지 않는 것.
#[test]
fn git_packed_bounds_refuse_before_buffer() {
    let bytes: String = (0..=budget::REF_ENTRIES)
        .map(|n| format!("{A} refs/heads/{n:04}\n"))
        .collect();
    let entered = Rc::new(std::cell::Cell::new(0));
    let counter = entered.clone();
    let mut m = meter();
    m.hook = Some(Box::new(move |event| {
        if event == "before_packed_parse" {
            counter.set(counter.get() + 1);
        }
    }));
    assert!(matches!(
        Refs::parse(bytes.as_bytes(), &mut m),
        Err(E::Limit)
    ));
    assert_eq!(entered.get(), 0);
    let mut m = meter();
    m.allocation_limit = (refs::PARSER_ALLOCATION - 1) as u64;
    let bytes = format!("{A} refs/heads/a\n");
    let (result, counts) = allocation::measure(|| Refs::parse(bytes.as_bytes(), &mut m));
    assert!(matches!(result, Err(E::Limit)));
    assert_eq!(counts.calls, 0);
    let bytes = vec![b' '; budget::REF_BYTES as usize + 1];
    let mut m = meter();
    let (result, counts) = allocation::measure(|| Refs::parse(&bytes, &mut m));
    assert!(matches!(result, Err(E::Limit)));
    assert_eq!(counts.calls, 0);
}
