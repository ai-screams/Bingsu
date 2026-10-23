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
    assert!(matches!(
        port.map(path(RootId::CommonDir, b"objects/pack/x"), 4096),
        Err(E::StageAOnly)
    ));
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
    // Each independent negative fixture gets a fresh port: C3 latches the
    // first exhausted budget so subsequent product I/O cannot resume.
    let port = io(&root, &access, &m);
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
    let port = io(&root, &access, &m);
    assert!(matches!(Refs::load(&port), Err(E::Limit)));
    assert_eq!(m.borrow().counts[Phase::Content as usize].read, before);
    fs::remove_file(fixture.0.join("packed-refs")).unwrap();
    let port = io(&root, &access, &m);
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
        include_str!("../src/git/index.rs"),
        include_str!("../src/git/objects.rs"),
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

// C3 fixture encoders only operate on bytes, without the git CLI.
use git::io::{
    index as safe_index,
    objects::{self, SafeObjectDb},
};
use gix_index::hash::{self, Kind as Hash, ObjectId};
use gix_object::Kind;
fn digest(bytes: &[u8]) -> ObjectId {
    let mut h = hash::hasher(Hash::Sha1);
    h.update(bytes);
    h.try_finalize().unwrap()
}
fn seal(bytes: &mut Vec<u8>) {
    bytes.extend_from_slice(digest(bytes).as_slice());
}
fn zip(bytes: &[u8]) -> Vec<u8> {
    use std::io::Write;
    let mut e = gix_zlib::stream::deflate::Write::new(Vec::new(), Default::default());
    e.write_all(bytes).unwrap();
    e.flush().unwrap();
    e.into_inner()
}
fn loose_fixture(f: &Fixture, kind: Kind, body: &[u8]) -> ObjectId {
    let id = gix_object::compute_hash(Hash::Sha1, kind, body).unwrap();
    let h = id.to_string();
    f.write(
        &format!("objects/{}/{}", &h[..2], &h[2..]),
        zip(&[format!("{kind} {}\0", body.len()).as_bytes(), body].concat()),
    );
    id
}
fn idx_fixture(count: usize, version: u32) -> Vec<u8> {
    let mut out = b"DIRC".to_vec();
    out.extend_from_slice(&version.to_be_bytes());
    out.extend_from_slice(&(count as u32).to_be_bytes());
    for n in 0..count {
        let name = format!("file-{n:05}");
        let start = out.len();
        out.extend_from_slice(&[0; 24]);
        out.extend_from_slice(&0o100644u32.to_be_bytes());
        out.extend_from_slice(&[0; 32]);
        out.extend_from_slice(&(name.len() as u16).to_be_bytes());
        if version == 4 {
            out.push(if n == 0 { 0 } else { name.len() as u8 });
        }
        out.extend_from_slice(name.as_bytes());
        out.push(0);
        if version != 4 {
            out.resize(start + (out.len() - start).next_multiple_of(8), 0);
        }
    }
    seal(&mut out);
    out
}
fn extension(bytes: &mut Vec<u8>, signature: &[u8; 4], body: &[u8]) {
    bytes.truncate(bytes.len() - 20);
    bytes.extend_from_slice(signature);
    bytes.extend_from_slice(&(body.len() as u32).to_be_bytes());
    bytes.extend_from_slice(body);
    seal(bytes);
}
fn varint(mut n: usize, out: &mut Vec<u8>) {
    loop {
        let b = (n & 127) as u8;
        n >>= 7;
        out.push(b | if n != 0 { 128 } else { 0 });
        if n == 0 {
            break;
        }
    }
}
struct Packed {
    name: String,
    pack: Vec<u8>,
    index: Vec<u8>,
    ids: Vec<ObjectId>,
    offsets: Vec<u64>,
}
fn packed(bodies: &[Vec<u8>], delta: bool) -> Packed {
    use gix_pack::data::entry::Header;
    let mut pack = b"PACK\0\0\0\x02".to_vec();
    pack.extend_from_slice(&(bodies.len() as u32).to_be_bytes());
    let mut ids = Vec::new();
    let mut offsets = Vec::new();
    for (n, body) in bodies.iter().enumerate() {
        offsets.push(pack.len() as u64);
        let payload = if delta && n != 0 {
            let mut d = Vec::new();
            varint(bodies[n - 1].len(), &mut d);
            varint(body.len(), &mut d);
            for c in body.chunks(127) {
                d.push(c.len() as u8);
                d.extend_from_slice(c);
            }
            let h = if n % 2 == 0 {
                Header::OfsDelta {
                    base_distance: offsets[n] - offsets[n - 1],
                }
            } else {
                Header::RefDelta {
                    base_id: ids[n - 1],
                }
            };
            h.write_to(d.len() as u64, &mut pack).unwrap();
            d
        } else {
            Header::Blob.write_to(body.len() as u64, &mut pack).unwrap();
            body.clone()
        };
        pack.extend(zip(&payload));
        ids.push(gix_object::compute_hash(Hash::Sha1, Kind::Blob, body).unwrap());
    }
    seal(&mut pack);
    let name = format!("pack-{}", digest(&pack));
    let mut index = b"\xfftOc\0\0\0\x02".to_vec();
    let mut ordered: Vec<_> = ids.iter().copied().zip(offsets.iter().copied()).collect();
    ordered.sort_by_key(|x| x.0);
    for n in 0..256 {
        index.extend_from_slice(
            &(ordered
                .iter()
                .filter(|x| x.0.as_slice()[0] as usize <= n)
                .count() as u32)
                .to_be_bytes(),
        );
    }
    for (id, _) in &ordered {
        index.extend_from_slice(id.as_slice());
    }
    index.resize(index.len() + ordered.len() * 4, 0);
    for (_, offset) in &ordered {
        index.extend_from_slice(&(*offset as u32).to_be_bytes());
    }
    index.extend_from_slice(&pack[pack.len() - 20..]);
    seal(&mut index);
    Packed {
        name,
        pack,
        index,
        ids,
        offsets,
    }
}
fn install_pack(f: &Fixture, p: &Packed) {
    f.write(&format!("objects/pack/{}.pack", p.name), &p.pack);
    f.write(&format!("objects/pack/{}.idx", p.name), &p.index);
}
fn midx(packs: &[&Packed]) -> Vec<u8> {
    let mut ordered = packs.to_vec();
    ordered.sort_by_key(|p| &p.name);
    let mut names = Vec::new();
    let mut objects = Vec::new();
    for (n, p) in ordered.iter().enumerate() {
        names.extend_from_slice(format!("{}.idx\0", p.name).as_bytes());
        objects.extend(
            p.ids
                .iter()
                .copied()
                .zip(p.offsets.iter().copied())
                .map(|(id, offset)| (id, n, offset)),
        );
    }
    names.resize(names.len().next_multiple_of(4), 0);
    objects.sort_by_key(|x| x.0);
    let mut fan = Vec::new();
    for n in 0..256 {
        fan.extend_from_slice(
            &(objects
                .iter()
                .filter(|x| x.0.as_slice()[0] as usize <= n)
                .count() as u32)
                .to_be_bytes(),
        );
    }
    let mut ids = Vec::new();
    let mut offsets = Vec::new();
    for (id, p, offset) in objects {
        ids.extend_from_slice(id.as_slice());
        offsets.extend_from_slice(&(p as u32).to_be_bytes());
        offsets.extend_from_slice(&(offset as u32).to_be_bytes());
    }
    let chunks = [
        (b"PNAM", names),
        (b"OIDF", fan),
        (b"OIDL", ids),
        (b"OOFF", offsets),
    ];
    let mut out = b"MIDX\x01\x01\x04\0".to_vec();
    out.extend_from_slice(&(packs.len() as u32).to_be_bytes());
    let mut offset = 72;
    for (id, data) in &chunks {
        out.extend_from_slice(*id);
        out.extend_from_slice(&(offset as u64).to_be_bytes());
        offset += data.len();
    }
    out.extend_from_slice(&[0; 4]);
    out.extend_from_slice(&(offset as u64).to_be_bytes());
    for (_, data) in chunks {
        out.extend(data);
    }
    seal(&mut out);
    out
}

// 이것을 실패시키는 것: same-fd map 읽기·PackBytes 선차감·오류 뒤 정지 또는 backing 해제를 제거하는 것.
#[test]
fn map_uses_validated_fd_and_unmaps_on_error() {
    let f = Fixture::new();
    let outside = Fixture::new();
    f.write("pack", b"original");
    outside.write("secret", b"outside");
    let access = access();
    let mut m = meter();
    let root = f.root(&mut m);
    let m = RefCell::new(m);
    let original = f.0.join("pack");
    let saved = f.0.join("saved");
    let secret = outside.0.join("secret");
    let mut changed = false;
    m.borrow_mut().hook = Some(Box::new(move |event| {
        if event == "before_read" && !changed {
            fs::rename(&original, &saved).unwrap();
            symlink(&secret, &original).unwrap();
            changed = true;
        }
    }));
    let port = io(&root, &access, &m);
    let (_, counts) = allocation::measure(|| {
        let map = port.map(path(RootId::CommonDir, b"pack"), 8).unwrap();
        assert_eq!(&*map, b"original");
    });
    assert!(counts.peak > 0);
    assert_eq!(counts.live, 0);
    assert_eq!(m.borrow().budget.used(Axis::PackBytes), 8);
    assert_eq!(m.borrow().budget.used(Axis::MappedBytes), 0);
    m.borrow_mut().hook = None;
    assert!(port.map(path(RootId::CommonDir, b"pack"), 8).is_err());
    let (result, counts) = allocation::measure(|| port.map(path(RootId::CommonDir, b"saved"), 7));
    assert!(matches!(result, Err(E::Limit)));
    assert_eq!(counts.live, 0);
    let before = m.borrow().counts;
    assert!(matches!(
        port.map(path(RootId::CommonDir, b"saved"), 8),
        Err(E::Limit)
    ));
    assert_eq!(m.borrow().counts, before);
}

// 이것을 실패시키는 것: loose zlib/header/length/hash 검증·Find 결과 buffer 연결을 제거하는 것.
#[test]
fn loose_objects_validate_all_bytes() {
    let f = Fixture::new();
    let access = access();
    let mut m = meter();
    let root = f.root(&mut m);
    let m = RefCell::new(m);
    let id = loose_fixture(&f, Kind::Blob, b"payload");
    let port = io(&root, &access, &m);
    let db = SafeObjectDb::new(&port);
    let mut out = Vec::new();
    let data = gix_object::Find::try_find(&db, &id, &mut out)
        .unwrap()
        .unwrap();
    assert_eq!(data.kind, Kind::Blob);
    assert_eq!(data.data, b"payload");
    let hex = id.to_string();
    let name = format!("objects/{}/{}", &hex[..2], &hex[2..]);
    for raw in [
        b"blob 8\0payload".as_slice(),
        b"blob 6\0payload",
        b"blob 07\0payload",
        b"bad 7\0payload",
        b"blob 7\0changed",
        b"blob -1\0payload",
        b"blob 7payload",
    ] {
        f.write(&name, zip(raw));
        let db = SafeObjectDb::new(&port);
        assert!(matches!(db.find(&id, &mut out), Err(INVALID)), "{raw:?}");
    }
    let mut bytes = zip(b"blob 7\0payload");
    bytes.push(0);
    f.write(&name, &bytes);
    assert!(matches!(
        SafeObjectDb::new(&port).find(&id, &mut out),
        Err(INVALID)
    ));
    bytes.truncate(bytes.len() - 3);
    f.write(&name, bytes);
    assert!(matches!(
        SafeObjectDb::new(&port).find(&id, &mut out),
        Err(INVALID)
    ));
}

// 이것을 실패시키는 것: produced-length 검사만 제거해 부족한 payload를 0으로 채우는 것.
#[test]
fn loose_short_payload_cannot_hash_as_zero_padding() {
    let expected = gix_object::compute_hash(Hash::Sha1, Kind::Blob, b"hello\0").unwrap();
    assert!(
        objects::loose(
            &zip(b"blob 6\0hello"),
            &expected,
            &mut Vec::new(),
            &mut meter()
        )
        .is_err()
    );
}

// 이것을 실패시키는 것: OBJECT_ALLOC·누적 inflate·공유 meter·실패 뒤 신규 I/O0을 제거하는 것.
#[test]
fn object_limit_and_total_inflate_limit_are_independent() {
    let f = Fixture::new();
    let access = access();
    let mut m = meter();
    let root = f.root(&mut m);
    let m = RefCell::new(m);
    let large = loose_fixture(
        &f,
        Kind::Blob,
        &vec![b'x'; budget::OBJECT_ALLOC as usize + 1],
    );
    let port = io(&root, &access, &m);
    let db = SafeObjectDb::new(&port);
    let mut out = Vec::new();
    assert!(matches!(db.find(&large, &mut out), Err(E::Limit)));
    assert_eq!(out.capacity(), 0);
    let before = m.borrow().counts;
    assert!(db.find(&large, &mut out).is_err());
    assert_eq!(m.borrow().counts, before);
    let id = loose_fixture(&f, Kind::Blob, b"small");
    let m = RefCell::new(meter());
    m.borrow_mut()
        .budget
        .charge(Axis::DecompressedBytes, budget::DECOMPRESSED_BYTES - 64)
        .unwrap();
    let port = io(&root, &access, &m);
    assert!(matches!(
        SafeObjectDb::new(&port).find(&id, &mut out),
        Err(E::Limit)
    ));
    let before = m.borrow().counts;
    assert!(matches!(
        SafeObjectDb::new(&port).find(&id, &mut out),
        Err(E::Limit)
    ));
    assert_eq!(m.borrow().counts, before);
}

// 이것을 실패시키는 것: 매 find의 scratch/parser 예약을 누적하거나 loose 읽기를 worktree 예산에 넣는 것.
#[test]
fn thousands_of_loose_trees_share_one_meter() {
    let f = Fixture::new();
    let blob = loose_fixture(&f, Kind::Blob, b"payload");
    let mut root_body = Vec::new();
    for n in 0..2047 {
        let mut body = format!("100644 file-{n:04}\0").into_bytes();
        body.extend_from_slice(blob.as_slice());
        let child = loose_fixture(&f, Kind::Tree, &body);
        root_body.extend_from_slice(format!("40000 dir-{n:04}\0").as_bytes());
        root_body.extend_from_slice(child.as_slice());
    }
    let tree = loose_fixture(&f, Kind::Tree, &root_body);
    let head = loose_fixture(
        &f,
        Kind::Commit,
        format!("tree {tree}\nauthor A <a@b> 0 +0000\ncommitter A <a@b> 0 +0000\n\nwalk\n")
            .as_bytes(),
    );
    let access = access();
    let root = f.root(&mut meter());
    let m = RefCell::new(meter());
    m.borrow_mut().byte_limit = 0;
    let port = io(&root, &access, &m);
    let db = SafeObjectDb::new(&port);
    assert_eq!(db.head_tree(&head).unwrap(), tree);
    let mut buffer = Vec::new();
    let children: Vec<_> = db
        .tree(&tree, &mut buffer)
        .unwrap()
        .map(|entry| entry.unwrap().oid.to_owned())
        .collect();
    let mut visited = 1;
    for child in children {
        assert_eq!(db.tree(&child, &mut buffer).unwrap().count(), 1);
        visited += 1;
    }
    assert_eq!(visited, 2048);
    assert_eq!(m.borrow().budget.used(Axis::IndexEntries), 4094);
    assert_eq!(m.borrow().budget.used(Axis::WorktreeReadBytes), 0);
    assert!(m.borrow().budget.used(Axis::DecompressedBytes) < budget::DECOMPRESSED_BYTES);
    // Cumulative diagnostics can exceed the live allocation limit many times.
    assert!(m.borrow().counts[Phase::Content as usize].allocated > 256 * 1024 * 1024);
}

// 이것을 실패시키는 것: packed find 예약의 다음 find/drop 해제 또는 단일 객체의 OBJECT_ALLOC 검사를 제거하는 것.
#[test]
fn thousands_of_packed_objects_keep_live_scratch_bounded() {
    let f = Fixture::new();
    let bodies: Vec<_> = (0..4096)
        .map(|n| format!("object-{n:04}").into_bytes())
        .collect();
    let p = packed(&bodies, false);
    install_pack(&f, &p);
    f.write("objects/pack/multi-pack-index", midx(&[&p]));
    let large = loose_fixture(
        &f,
        Kind::Blob,
        &vec![b'x'; budget::OBJECT_ALLOC as usize + 1],
    );
    let small = loose_fixture(&f, Kind::Blob, b"loose");
    let access = access();
    let root = f.root(&mut meter());
    let m = RefCell::new(meter());
    m.borrow_mut().byte_limit = 0;
    let port = io(&root, &access, &m);
    let db = SafeObjectDb::new(&port);
    let mut buffer = Vec::new();
    for (n, (id, body)) in p.ids.iter().zip(&bodies).enumerate() {
        assert_eq!(db.find(id, &mut buffer).unwrap().unwrap().data, body);
        if n == 0 {
            // All following packed finds fit exactly the current live usage;
            // the previous reservation must go before the next one is made.
            let live = m.borrow().live_allocated();
            m.borrow_mut().allocation_limit = live;
        }
    }
    assert_eq!(
        m.borrow().budget.used(Axis::DecompressedBytes),
        bodies.iter().map(|b| b.len() as u64).sum()
    );
    assert_eq!(m.borrow().budget.used(Axis::WorktreeReadBytes), 0);
    m.borrow_mut().allocation_limit = 8_388_608;
    let before_drop = m.borrow().live_allocated();
    drop(db);
    assert_eq!(
        before_drop - m.borrow().live_allocated(),
        (objects::DECODER_OVERHEAD + bodies[0].len()) as u64
    );
    // Drop must return the last reservation even without another find. This
    // remaining allocation would fail if every dropped adapter leaked scratch.
    for _ in 0..64 {
        let db = SafeObjectDb::new(&port);
        assert_eq!(
            db.find(&small, &mut buffer).unwrap().unwrap().data,
            b"loose"
        );
    }
    assert!(matches!(
        SafeObjectDb::new(&port).find(&large, &mut buffer),
        Err(E::Limit)
    ));
    assert_eq!(buffer.capacity(), 0);
    assert!(m.borrow().budget.used(Axis::DecompressedBytes) < budget::DECOMPRESSED_BYTES);
}

// 이것을 실패시키는 것: 저장소 snapshot을 worktree 예산으로 다시 차감하거나 호출자의 single_link 정책을 무시하는 것.
#[test]
fn repository_snapshots_use_their_own_byte_axes() {
    let f = Fixture::new();
    let index = idx_fixture(1, 2);
    f.write("index", &index);
    f.write("config", b"[core]\nfilemode=true\n");
    f.write("HEAD", format!("{A}\n"));
    f.write("metadata", b"x");
    fs::hard_link(f.0.join("metadata"), f.0.join("alias")).unwrap();
    f.write("pack", vec![0; budget::PACK_BYTES as usize]);
    let access = access();
    let root = f.root(&mut meter());
    let m = RefCell::new(meter());
    m.borrow_mut().byte_limit = 0;
    m.borrow_mut()
        .budget
        .charge(Axis::WorktreeReadBytes, budget::WORKTREE_READ_BYTES)
        .unwrap();
    let port = io(&root, &access, &m);
    assert_eq!(
        port.read(
            path(RootId::GitDir, b"metadata"),
            ReadCap {
                bytes: 1,
                single_link: false
            }
        )
        .unwrap(),
        b"x"
    );
    assert_eq!(
        port.read(path(RootId::GitDir, b"metadata"), cap(1)),
        Err(E::Special)
    );
    let refs = Refs::load(&port).unwrap();
    assert_eq!(
        refs.resolve(&port, b"HEAD").unwrap().unwrap().to_string(),
        A
    );
    assert_eq!(m.borrow().budget.used(Axis::RefBytes), 41);
    assert_eq!(safe_index::load(&port).unwrap().entries().len(), 1);
    assert_eq!(
        m.borrow().budget.used(Axis::IndexBytes),
        index.len() as u64 + 10
    );
    assert_eq!(
        port.map(path(RootId::CommonDir, b"pack"), budget::PACK_BYTES)
            .unwrap()
            .len() as u64,
        budget::PACK_BYTES
    );
    assert_eq!(m.borrow().budget.used(Axis::PackBytes), budget::PACK_BYTES);
    let before = m.borrow().counts;
    assert!(matches!(
        port.map(path(RootId::CommonDir, b"pack"), budget::PACK_BYTES),
        Err(E::Limit)
    ));
    assert_eq!(m.borrow().counts, before);
}

// 이것을 실패시키는 것: .idx 대신 .pack을 열거해 작성 중인 pack의 Missing/손상을 캐시하는 것.
#[test]
fn unfinished_pack_without_index_does_not_poison_lookup() {
    let f = Fixture::new();
    let p = packed(&[b"published".to_vec()], false);
    install_pack(&f, &p);
    f.write(
        "objects/pack/pack-0000000000000000000000000000000000000000.pack",
        b"PACK incomplete",
    );
    let access = access();
    let root = f.root(&mut meter());
    let m = RefCell::new(meter());
    let port = io(&root, &access, &m);
    let db = SafeObjectDb::new(&port);
    let mut buffer = Vec::new();
    assert_eq!(
        db.find(&p.ids[0], &mut buffer).unwrap().unwrap().data,
        b"published"
    );
    assert_eq!(m.borrow().budget.used(Axis::Packs), 1);
    assert_eq!(
        m.borrow().budget.used(Axis::PackBytes),
        (p.pack.len() + p.index.len()) as u64
    );
    assert!(
        db.find(&ObjectId::null(Hash::Sha1), &mut buffer)
            .unwrap()
            .is_none()
    );
}

// 이것을 실패시키는 것: pack을 객체 접근 전에 읽거나 캐시 후 경로를 재열기·delta 복원 제거.
#[test]
fn lazy_pack_access_never_reopens_a_path() {
    let f = Fixture::new();
    let outside = Fixture::new();
    let p = packed(
        &[b"base".to_vec(), b"changed".to_vec(), b"third".to_vec()],
        true,
    );
    install_pack(&f, &p);
    f.write("objects/pack/multi-pack-index", midx(&[&p]));
    let access = access();
    let mut m = meter();
    let root = f.root(&mut m);
    let m = RefCell::new(m);
    let port = io(&root, &access, &m);
    let before = m.borrow().counts;
    let db = SafeObjectDb::new(&port);
    assert_eq!(m.borrow().counts, before);
    let mut out = Vec::new();
    assert_eq!(
        db.find(&p.ids[2], &mut out).unwrap().unwrap().data,
        b"third"
    );
    assert_eq!(m.borrow().budget.used(Axis::Packs), 1);
    let before = m.borrow().counts[Phase::Content as usize];
    fs::rename(f.0.join("objects/pack"), f.0.join("saved")).unwrap();
    symlink(&outside.0, f.0.join("objects/pack")).unwrap();
    assert_eq!(
        db.find(&p.ids[1], &mut out).unwrap().unwrap().data,
        b"changed"
    );
    let after = m.borrow().counts[Phase::Content as usize];
    assert_eq!(after.open, before.open);
    assert_eq!(after.read, before.read);
}

// 이것을 실패시키는 것: index bytes/entry/path/allocation 선차감·checksum·split Partial·정렬 검사 제거.
#[test]
fn index_budget_precedes_parser_and_split_is_partial() {
    for version in [2, 3, 4] {
        let mut bytes = idx_fixture(3, version);
        let mut m = meter();
        let state = safe_index::parse(&mut bytes, &mut m).unwrap();
        assert_eq!(state.entries().len(), 3);
        assert_eq!(state.entries()[2].path(&state), b"file-00002".as_slice());
        assert_eq!(m.budget.used(Axis::IndexEntries), 3);
        assert_eq!(m.budget.used(Axis::IndexBytes), 30);
    }
    let mut bytes = idx_fixture(1, 2);
    extension(&mut bytes, b"link", &[1; 20]);
    assert!(matches!(
        safe_index::parse(&mut bytes, &mut meter()),
        Err(git::io::UNSUPPORTED)
    ));
    let mut bytes = idx_fixture(1, 2);
    bytes[40] ^= 1;
    assert!(matches!(
        safe_index::parse(&mut bytes, &mut meter()),
        Err(INVALID)
    ));
    let mut bytes = idx_fixture(2, 2);
    bytes[8..12].copy_from_slice(&50_001u32.to_be_bytes());
    let mut m = meter();
    let (result, counts) = allocation::measure(|| safe_index::parse(&mut bytes, &mut m));
    assert!(matches!(result, Err(E::Limit)));
    assert_eq!(counts.calls, 0);
    let mut bytes = idx_fixture(2, 2);
    let mut m = meter();
    m.allocation_limit = 1;
    let (result, counts) = allocation::measure(|| safe_index::parse(&mut bytes, &mut m));
    assert!(matches!(result, Err(E::Limit)));
    assert_eq!(counts.calls, 0);
    let mut bytes = idx_fixture(2, 2);
    let mut m = meter();
    m.budget
        .charge(Axis::IndexBytes, budget::INDEX_BYTES)
        .unwrap();
    assert!(matches!(
        safe_index::parse(&mut bytes, &mut m),
        Err(E::Limit)
    ));
    let mut bytes = idx_fixture(2, 2);
    bytes[92..172].copy_from_slice(&idx_fixture(1, 2)[12..92]);
    bytes.truncate(bytes.len() - 20);
    seal(&mut bytes);
    assert!(matches!(
        safe_index::parse(&mut bytes, &mut meter()),
        Err(INVALID)
    ));
}

// 이것을 실패시키는 것: parser 예약을 실측 peak 아래로 줄이거나 측정에서 실제 gix 호출을 빼는 것.
#[test]
fn object_index_parser_peaks_are_precharged() {
    for version in [2, 3, 4] {
        for count in [0, 1, 19_000, 50_000] {
            let mut bytes = idx_fixture(count, version);
            let input = bytes.len();
            let mut m = meter();
            let start = Instant::now();
            let (state, counts) = allocation::measure(|| safe_index::parse(&mut bytes, &mut m));
            let state = state.unwrap();
            assert_eq!(state.entries().len(), count);
            let charged = m.counts[Phase::Content as usize].allocated as usize;
            assert!(
                counts.peak <= charged,
                "index v{version} count={count}: {counts:?} charge={charged}"
            );
            eprintln!(
                "C3 index version={version} entries={count} input={input} peak={} charge={charged} ns={}",
                counts.peak,
                start.elapsed().as_nanos()
            );
        }
    }
    for size in [0, 4096, 1_048_576] {
        let raw = [format!("blob {size}\0").into_bytes(), vec![b'x'; size]].concat();
        let compressed = zip(&raw);
        let id = gix_object::compute_hash(Hash::Sha1, Kind::Blob, &vec![b'x'; size]).unwrap();
        let mut out = Vec::new();
        let mut m = meter();
        let start = Instant::now();
        let (result, counts) =
            allocation::measure(|| objects::loose(&compressed, &id, &mut out, &mut m));
        assert_eq!(result.unwrap().data.len(), size);
        let charged = m.counts[Phase::Content as usize].allocated as usize;
        assert!(counts.peak <= charged, "loose: {counts:?} charge={charged}");
        eprintln!(
            "C3 loose bytes={size} compressed={} peak={} charge={charged} ns={}",
            compressed.len(),
            counts.peak,
            start.elapsed().as_nanos()
        );
    }
    for count in [1, 8, 64] {
        let bodies: Vec<_> = (0..count).map(|n| vec![n as u8; 1024]).collect();
        let p = packed(&bodies, true);
        let (pack, counts) = allocation::measure(|| {
            gix_pack::data::File::from_data(p.pack.as_slice(), Default::default(), Hash::Sha1)
        });
        let pack = pack
            .unwrap()
            .with_alloc_limit_bytes(Some(budget::OBJECT_ALLOC as usize));
        assert!(counts.peak <= objects::PARSER_OVERHEAD);
        eprintln!("C3 pack constructor peak={}", counts.peak);
        let (idx, counts) = allocation::measure(|| {
            gix_pack::index::File::from_data(p.index.as_slice(), Default::default(), Hash::Sha1)
        });
        let idx = idx.unwrap();
        assert!(counts.peak <= objects::PARSER_OVERHEAD);
        eprintln!("C3 idx constructor peak={}", counts.peak);
        let midx = midx(&[&p]);
        let (multi, counts) = allocation::measure(|| {
            gix_pack::multi_index::File::from_data(
                midx.as_slice(),
                Default::default(),
                Some(midx.len() + objects::PARSER_OVERHEAD),
            )
        });
        assert_eq!(multi.unwrap().num_indices(), 1);
        assert!(counts.peak <= midx.len() + objects::PARSER_OVERHEAD);
        eprintln!("C3 MIDX constructor peak={}", counts.peak);
        let entry = pack.entry(*p.offsets.last().unwrap()).unwrap();
        let mut out = Vec::new();
        let start = Instant::now();
        let (result, counts) = allocation::measure(|| {
            let mut inflate = Default::default();
            pack.decode_entry(
                entry,
                &mut out,
                &mut inflate,
                &|id, _| {
                    idx.lookup(id).map(|n| {
                        gix_pack::data::decode::entry::ResolvedBase::InPack(
                            pack.entry(idx.pack_offset_at_index(n)).unwrap(),
                        )
                    })
                },
                &mut gix_pack::cache::Never,
            )
        });
        assert_eq!(result.unwrap().kind, Kind::Blob);
        assert_eq!(out, bodies[count - 1]);
        let cap = 2 * 1024 + count * 1040;
        assert!(
            counts.peak <= objects::DECODER_OVERHEAD + 3 * cap,
            "{counts:?}"
        );
        eprintln!(
            "C3 decode depth={} peak={} reserve={} ns={}",
            count - 1,
            counts.peak,
            objects::DECODER_OVERHEAD + 3 * cap,
            start.elapsed().as_nanos()
        );
    }
    let tree = b"100644 a\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
    let (n, counts) = allocation::measure(|| {
        gix_object::TreeRefIter::from_bytes(tree, Hash::Sha1)
            .inspect(|e| {
                e.as_ref().unwrap();
            })
            .count()
    });
    assert_eq!(n, 1);
    assert_eq!(counts.peak, 0);
    let commit = format!("tree {A}\n\nmessage\n");
    let (id, counts) = allocation::measure(|| {
        gix_object::CommitRefIter::from_bytes(commit.as_bytes(), Hash::Sha1).tree_id()
    });
    assert_eq!(id.unwrap().to_string(), A);
    assert_eq!(counts.peak, 0);
}

mod c3_extended {
    use super::*;
    // C3 fixtures encode only test inputs. Production parsers remain gitoxide's.
    use git::io::{
        index as git_index,
        objects::{self, SafeObjectDb},
    };
    use gix_index::hash::{self, ObjectId};
    use gix_object::Kind;

    fn hash_bytes(bytes: &[u8]) -> ObjectId {
        let mut h = hash::hasher(hash::Kind::Sha1);
        h.update(bytes);
        h.try_finalize().unwrap()
    }
    fn seal(mut bytes: Vec<u8>) -> Vec<u8> {
        bytes.extend_from_slice(hash_bytes(&bytes).as_slice());
        bytes
    }
    // RFC 1950 stored DEFLATE blocks: independent of the decoder implementation.
    fn zlib(bytes: &[u8]) -> Vec<u8> {
        let mut out = vec![0x78, 0x01];
        let chunks = bytes.len().max(1).div_ceil(65535);
        for n in 0..chunks {
            let start = n * 65535;
            let block = &bytes[start..bytes.len().min(start + 65535)];
            out.push(u8::from(n + 1 == chunks));
            out.extend_from_slice(&(block.len() as u16).to_le_bytes());
            out.extend_from_slice(&(!(block.len() as u16)).to_le_bytes());
            out.extend_from_slice(block);
        }
        let (mut a, mut b) = (1u32, 0u32);
        for byte in bytes {
            a = (a + u32::from(*byte)) % 65521;
            b = (b + a) % 65521;
        }
        out.extend_from_slice(&((b << 16) | a).to_be_bytes());
        out
    }
    fn oid(kind: Kind, bytes: &[u8]) -> ObjectId {
        gix_object::compute_hash(hash::Kind::Sha1, kind, bytes).unwrap()
    }
    fn loose_fixture(f: &Fixture, kind: Kind, bytes: &[u8]) -> ObjectId {
        let id = oid(kind, bytes);
        let mut raw = format!("{} {}\0", kind, bytes.len()).into_bytes();
        raw.extend_from_slice(bytes);
        let hex = id.to_string();
        f.write(&format!("objects/{}/{}", &hex[..2], &hex[2..]), zlib(&raw));
        id
    }
    fn index_bytes(
        version: u32,
        count: usize,
        name_len: usize,
        extension: Option<(&[u8; 4], &[u8])>,
    ) -> Vec<u8> {
        let mut b = b"DIRC".to_vec();
        b.extend_from_slice(&version.to_be_bytes());
        b.extend_from_slice(&(count as u32).to_be_bytes());
        for n in 0..count {
            let start = b.len();
            b.resize(start + 62, 0);
            b[start + 24..start + 28].copy_from_slice(&0o100644u32.to_be_bytes());
            let path = format!("{n:06}{}", "x".repeat(name_len.saturating_sub(6)));
            b[start + 60..start + 62]
                .copy_from_slice(&(path.len().min(0xfff) as u16).to_be_bytes());
            if version == 4 {
                b.push(if n == 0 { 0 } else { path.len() as u8 });
            }
            b.extend_from_slice(path.as_bytes());
            b.push(0);
            if version != 4 && path.len() < 0xfff {
                b.resize(start + (b.len() - start).next_multiple_of(8), 0);
            }
        }
        if let Some((name, data)) = extension {
            b.extend_from_slice(name);
            b.extend_from_slice(&(data.len() as u32).to_be_bytes());
            b.extend_from_slice(data);
        }
        seal(b)
    }
    struct PackFixture {
        data: Vec<u8>,
        index: Vec<u8>,
        entries: Vec<(ObjectId, u64)>,
        name: String,
    }
    fn pack_fixture(depth: usize, ref_delta: bool, bad_delta: bool) -> PackFixture {
        let base = b"hello";
        let mut data = b"PACK\0\0\0\x02".to_vec();
        data.extend_from_slice(&((depth + 1) as u32).to_be_bytes());
        let mut entries = vec![(oid(Kind::Blob, base), 12)];
        data.push(0x35);
        data.extend_from_slice(&zlib(base));
        let mut previous = 12u64;
        for n in 0..depth {
            let offset = data.len() as u64;
            let target = [b'h', b'e', b'l', b'l', (n + 1) as u8];
            let delta = if bad_delta {
                vec![5, 5, 0]
            } else {
                [vec![5, 5, 5], target.to_vec()].concat()
            };
            data.push((if ref_delta { 7 } else { 6 }) << 4 | delta.len() as u8);
            if ref_delta {
                data.extend_from_slice(entries.last().unwrap().0.as_slice());
            } else {
                assert!(offset - previous < 128);
                data.push((offset - previous) as u8);
            }
            data.extend_from_slice(&zlib(&delta));
            entries.push((oid(Kind::Blob, &target), offset));
            previous = offset;
        }
        data = seal(data);
        let mut index = b"\xfftOc\0\0\0\x02".to_vec();
        entries.sort_by_key(|e| e.0);
        for n in 0..256 {
            index.extend_from_slice(
                &(entries
                    .iter()
                    .filter(|e| e.0.as_slice()[0] as usize <= n)
                    .count() as u32)
                    .to_be_bytes(),
            );
        }
        for (id, _) in &entries {
            index.extend_from_slice(id.as_slice());
        }
        index.resize(index.len() + entries.len() * 4, 0); // CRC not used; object+pack hashes verified
        for (_, offset) in &entries {
            index.extend_from_slice(&(*offset as u32).to_be_bytes());
        }
        index.extend_from_slice(&data[data.len() - 20..]);
        let name = format!("pack-{}", hash_bytes(&data));
        PackFixture {
            data,
            index: seal(index),
            entries,
            name,
        }
    }
    fn write_pack(f: &Fixture, pack: &PackFixture) {
        f.write(&format!("objects/pack/{}.pack", pack.name), &pack.data);
        f.write(&format!("objects/pack/{}.idx", pack.name), &pack.index);
    }
    fn midx_bytes(pack: &PackFixture, hostile_name: bool, large: bool) -> Vec<u8> {
        let mut name = if hostile_name {
            b"../outside.idx".to_vec()
        } else {
            format!("{}.idx", pack.name).into_bytes()
        };
        name.push(0);
        name.resize(name.len().next_multiple_of(4), 0);
        let mut fan = Vec::new();
        for n in 0..256 {
            fan.extend_from_slice(
                &(pack
                    .entries
                    .iter()
                    .filter(|e| e.0.as_slice()[0] as usize <= n)
                    .count() as u32)
                    .to_be_bytes(),
            );
        }
        let mut ids = Vec::new();
        let mut offsets = Vec::new();
        for (id, off) in &pack.entries {
            ids.extend_from_slice(id.as_slice());
            offsets.extend_from_slice(&0u32.to_be_bytes());
            offsets.extend_from_slice(&(*off as u32).to_be_bytes());
        }
        let mut chunks = vec![
            (*b"PNAM", name),
            (*b"OIDF", fan),
            (*b"OIDL", ids),
            (*b"OOFF", offsets),
        ];
        if large {
            chunks.push((*b"LOFF", vec![0; 8]));
        }
        let mut bytes = b"MIDX\x01\x01".to_vec();
        bytes.push(chunks.len() as u8);
        bytes.push(0);
        bytes.extend_from_slice(&1u32.to_be_bytes());
        let mut at = 12 + (chunks.len() + 1) * 12;
        for (name, data) in &chunks {
            bytes.extend_from_slice(name);
            bytes.extend_from_slice(&(at as u64).to_be_bytes());
            at += data.len();
        }
        bytes.extend_from_slice(&[0; 4]);
        bytes.extend_from_slice(&(at as u64).to_be_bytes());
        for (_, data) in chunks {
            bytes.extend_from_slice(&data);
        }
        seal(bytes)
    }

    // 이것을 실패시키는 것: same-fd 읽기를 path 재열기로 바꾸거나 오류 뒤 backing/fd를 누수시키는 것.
    #[test]
    fn map_uses_validated_fd_and_unmaps_on_error() {
        let f = Fixture::new();
        let outside = Fixture::new();
        f.write("data", b"original");
        outside.write("value", b"OUTSIDE!");
        let access = access();
        let root = f.root(&mut meter());
        let m = RefCell::new(meter());
        let port = io(&root, &access, &m);
        let dest = f.0.join("data");
        let replacement = outside.0.join("value");
        m.borrow_mut().hook = Some(Box::new(move |event| {
            if event == "before_read" {
                fs::remove_file(&dest).unwrap();
                symlink(&replacement, &dest).unwrap();
            }
        }));
        let map = port.map(path(RootId::GitDir, b"data"), 8).unwrap();
        assert_eq!(&*map, b"original");
        assert_eq!(m.borrow().budget.used(Axis::PackBytes), 8);
        assert_eq!(m.borrow().budget.used(Axis::MappedBytes), 0);
        m.borrow_mut().hook = None;
        assert!(port.map(path(RootId::GitDir, b"data"), 8).is_err());
        drop(map);
        // Repeated error drops must release fd leases; >56 attempts catches leaks.
        for _ in 0..70 {
            assert!(port.map(path(RootId::GitDir, b"missing"), 8).is_err());
        }
        fs::remove_file(f.0.join("data")).unwrap();
        f.write("data", b"small");
        assert_eq!(
            &*port.map(path(RootId::GitDir, b"data"), 5).unwrap(),
            b"small"
        );
    }

    // 이것을 실패시키는 것: lazy pack 검색을 생성자로 옮기거나 snapshot 대신 pack 경로를 재열기 하는 것.
    #[test]
    fn lazy_pack_access_never_reopens_a_path() {
        let f = Fixture::new();
        let p = pack_fixture(3, false, false);
        write_pack(&f, &p);
        let access = access();
        let root = f.root(&mut meter());
        let m = RefCell::new(meter());
        let port = io(&root, &access, &m);
        let before = m.borrow().counts;
        let db = SafeObjectDb::new(&port);
        assert_eq!(m.borrow().counts, before);
        let mut buffer = Vec::new();
        for (id, _) in &p.entries {
            assert!(
                gix_object::Find::try_find(&db, id, &mut buffer)
                    .unwrap()
                    .is_some()
            );
        }
        let before = m.borrow().counts[Phase::Content as usize];
        fs::remove_dir_all(f.0.join("objects/pack")).unwrap();
        for (id, _) in &p.entries {
            assert!(db.find(id, &mut buffer).unwrap().is_some());
        }
        let after = m.borrow().counts[Phase::Content as usize];
        assert_eq!(
            (before.open, before.read, before.list),
            (after.open, after.read, after.list)
        );
        assert_eq!(m.borrow().budget.used(Axis::Packs), 1);
        assert_eq!(
            m.borrow().budget.used(Axis::PackBytes),
            (p.data.len() + p.index.len()) as u64
        );
    }

    // 이것을 실패시키는 것: 객체 상한/총 inflate 상한을 합치거나 실패 뒤 새 I/O를 허용하는 것.
    #[test]
    fn object_limit_and_total_inflate_limit_are_independent() {
        let f = Fixture::new();
        let id = loose_fixture(&f, Kind::Blob, b"hello");
        let access = access();
        let root = f.root(&mut meter());
        for remaining in [64 + 12, 64 + 12 - 1] {
            let m = RefCell::new(meter());
            m.borrow_mut()
                .budget
                .charge(
                    Axis::DecompressedBytes,
                    budget::DECOMPRESSED_BYTES - remaining,
                )
                .unwrap();
            let port = io(&root, &access, &m);
            let db = SafeObjectDb::new(&port);
            let mut b = Vec::new();
            let result = db.find(&id, &mut b);
            if remaining == 76 {
                assert_eq!(result.unwrap().unwrap().data, b"hello");
            } else {
                assert_eq!(result.unwrap_err(), E::Limit);
                let before = m.borrow().counts;
                assert_eq!(db.find(&id, &mut b).unwrap_err(), E::Limit);
                assert_eq!(m.borrow().counts, before);
            }
        }
        for size in [982_987, 982_988] {
            // Stored zlib uses 15 blocks and 81 framing bytes; input + output
            // straddles OBJECT_BUFFER by one byte, independently of total inflate.
            let raw = [format!("blob {size}\0").into_bytes(), vec![b'x'; size]].concat();
            let bytes = zlib(&raw);
            let id = oid(Kind::Blob, &raw[raw.len() - size..]);
            let mut m = meter();
            let mut out = Vec::new();
            let result = objects::loose(&bytes, &id, &mut out, &mut m);
            if size == 982_987 {
                assert_eq!(result.unwrap().data.len(), size);
            } else {
                assert_eq!(result.unwrap_err(), E::Limit);
            }
            assert!(m.budget.used(Axis::DecompressedBytes) < budget::DECOMPRESSED_BYTES);
        }
    }

    // 이것을 실패시키는 것: loose zlib/header/length/hash 검사를 생략하거나 alternates/replace를 해석하는 것.
    #[test]
    fn loose_objects_validate_and_ignore_overrides() {
        let f = Fixture::new();
        let outside = Fixture::new();
        let id = loose_fixture(&f, Kind::Blob, b"hello");
        let replacement = loose_fixture(&outside, Kind::Blob, b"outside");
        f.write("objects/info/alternates", outside.0.as_os_str().as_bytes());
        f.write(&format!("refs/replace/{id}"), replacement.to_string());
        let access = access();
        let root = f.root(&mut meter());
        let m = RefCell::new(meter());
        let port = io(&root, &access, &m);
        let db = SafeObjectDb::new(&port);
        assert_eq!(
            db.find(&id, &mut Vec::new()).unwrap().unwrap().data,
            b"hello"
        );
        assert!(db.find(&replacement, &mut Vec::new()).unwrap().is_none());
        for raw in [
            b"blob 6\0hello".as_slice(),
            b"blob 4\0hello",
            b"blob 05\0hello",
            b"blob -5\0hello",
            b"blob x\0hello",
            b"bogus 5\0hello",
            b"blob 5 hello",
            b"blob 5\0jello",
            b"blob 184467440737095516160\0",
        ] {
            assert!(
                objects::loose(&zlib(raw), &id, &mut Vec::new(), &mut meter()).is_err(),
                "{raw:?}"
            );
        }
        let valid = zlib(b"blob 5\0hello");
        for broken in [
            valid[..valid.len() - 1].to_vec(),
            [valid.clone(), vec![0]].concat(),
            vec![0; 20],
        ] {
            assert!(objects::loose(&broken, &id, &mut Vec::new(), &mut meter()).is_err());
        }
    }

    // 이것을 실패시키는 것: pack 수/bytes 사전 charge 또는 오류 latch를 제거하는 것.
    #[test]
    fn pack_axes_stop_before_further_io() {
        let f = Fixture::new();
        let p = pack_fixture(0, false, false);
        write_pack(&f, &p);
        let access = access();
        let root = f.root(&mut meter());
        for axis in [Axis::Packs, Axis::PackBytes] {
            let m = RefCell::new(meter());
            m.borrow_mut().budget.charge(axis, axis.limit()).unwrap();
            let port = io(&root, &access, &m);
            let db = SafeObjectDb::new(&port);
            let mut b = Vec::new();
            assert_eq!(db.find(&p.entries[0].0, &mut b).unwrap_err(), E::Limit);
            let before = m.borrow().counts;
            assert_eq!(db.find(&p.entries[0].0, &mut b).unwrap_err(), E::Limit);
            assert_eq!(m.borrow().counts, before);
            assert_eq!(before[Phase::Content as usize].read_bytes, 0);
            if axis == Axis::Packs {
                assert_eq!(before[Phase::Content as usize].list, 0);
            }
        }
        for count in [8, 9] {
            let f = Fixture::new();
            for n in 0..count {
                let mut pack = pack_fixture(0, false, false);
                pack.name = format!("pack-{n:040x}");
                write_pack(&f, &pack);
            }
            let root = f.root(&mut meter());
            let m = RefCell::new(meter());
            let port = io(&root, &access, &m);
            let db = SafeObjectDb::new(&port);
            let mut buffer = Vec::new();
            let result = db.find(&p.entries[0].0, &mut buffer);
            if count == 8 {
                assert!(result.unwrap().is_some());
            } else {
                assert_eq!(result.unwrap_err(), E::Limit);
                assert_eq!(m.borrow().counts[Phase::Content as usize].read_bytes, 0);
            }
        }
    }

    // 이것을 실패시키는 것: delta 사전 walk·cycle/depth·ref callback 예산·MIDX 이름/offset 검증을 제거하는 것.
    #[test]
    fn delta_and_midx_are_bounded_bytes_parsers() {
        let access = access();
        for (depth, reference, malformed) in [
            (0, false, false),
            (3, true, false),
            (64, false, false),
            (65, false, false),
            (1, false, true),
        ] {
            let f = Fixture::new();
            let p = pack_fixture(depth, reference, malformed);
            write_pack(&f, &p);
            f.write(
                "objects/pack/multi-pack-index",
                midx_bytes(&p, false, false),
            );
            let root = f.root(&mut meter());
            let m = RefCell::new(meter());
            let port = io(&root, &access, &m);
            let db = SafeObjectDb::new(&port);
            let id = if depth == 0 {
                oid(Kind::Blob, b"hello")
            } else {
                oid(Kind::Blob, &[b'h', b'e', b'l', b'l', depth as u8])
            };
            let mut buffer = Vec::new();
            let result = db.find(&id, &mut buffer);
            if depth > 64 {
                assert_eq!(result.unwrap_err(), E::Limit);
            } else if malformed {
                assert_eq!(result.unwrap_err(), INVALID);
            } else {
                assert_eq!(result.unwrap().unwrap().data.len(), 5);
            }
        }
        for (hostile, large) in [(true, false), (false, true)] {
            let f = Fixture::new();
            let p = pack_fixture(0, false, false);
            write_pack(&f, &p);
            f.write(
                "objects/pack/multi-pack-index",
                midx_bytes(&p, hostile, large),
            );
            let root = f.root(&mut meter());
            let m = RefCell::new(meter());
            let port = io(&root, &access, &m);
            assert!(
                SafeObjectDb::new(&port)
                    .find(&p.entries[0].0, &mut Vec::new())
                    .is_err()
            );
        }
    }

    // 이것을 실패시키는 것: index bytes/entries/할당 사전 검사·checksum·경로 정렬 또는 split Partial을 제거하는 것.
    #[test]
    fn index_allocation_and_split_are_bounded() {
        let f = Fixture::new();
        let access = access();
        let root = f.root(&mut meter());
        for version in [2, 3, 4] {
            let bytes = index_bytes(version, 3, 16, None);
            f.write("index", &bytes);
            let m = RefCell::new(meter());
            let port = io(&root, &access, &m);
            let state = git_index::load(&port).unwrap();
            assert_eq!(state.entries().len(), 3);
            assert_eq!(
                m.borrow().budget.used(Axis::IndexBytes),
                bytes.len() as u64 + 48
            );
            assert_eq!(m.borrow().budget.used(Axis::IndexEntries), 3);
        }
        for entries in [50_000, 50_001] {
            let mut bytes = index_bytes(2, entries, 6, None);
            let mut m = meter();
            m.allocation_limit = 64 * 1024 * 1024;
            let result = git_index::parse(&mut bytes, &mut m);
            if entries == 50_000 {
                assert_eq!(result.unwrap().entries().len(), entries);
            } else {
                assert_eq!(result.unwrap_err(), E::Limit);
            }
        }
        for (name, data, expected) in [
            (
                b"link",
                [vec![1; 20], vec![0; 16]].concat(),
                git::io::UNSUPPORTED,
            ),
            (b"abcd", vec![], git::io::UNSUPPORTED),
            (b"sdir", vec![0], INVALID),
        ] {
            let mut bytes = index_bytes(2, 0, 0, Some((name, &data)));
            assert_eq!(
                git_index::parse(&mut bytes, &mut meter()).unwrap_err(),
                expected
            );
        }
        let mut bytes = index_bytes(2, 1, 6, None);
        let mut m = meter();
        m.allocation_limit = 0;
        assert_eq!(git_index::parse(&mut bytes, &mut m).unwrap_err(), E::Limit);
        let mut bytes = index_bytes(2, 1, 6, None);
        bytes[20] ^= 1;
        assert_eq!(
            git_index::parse(&mut bytes, &mut meter()).unwrap_err(),
            INVALID
        );
        let mut bytes = index_bytes(2, 2, 6, None);
        bytes[84 + 62..84 + 68].copy_from_slice(b"000000");
        let end = bytes.len() - 20;
        bytes.truncate(end);
        let mut bytes = seal(bytes);
        assert_eq!(
            git_index::parse(&mut bytes, &mut meter()).unwrap_err(),
            INVALID
        );
        // Optional recursive caches are not needed; poison must be discarded.
        let mut bytes = index_bytes(2, 1, 6, Some((b"TREE", b"malformed recursive cache")));
        assert_eq!(
            git_index::parse(&mut bytes, &mut meter())
                .unwrap()
                .entries()
                .len(),
            1
        );
    }

    // 이것을 실패시키는 것: HEAD/tree가 adapter를 우회하거나 kind·tree entry 예산을 생략하는 것.
    #[test]
    fn head_tree_shares_object_and_index_budgets() {
        let f = Fixture::new();
        let blob = loose_fixture(&f, Kind::Blob, b"hello");
        let tree = [b"100644 file\0".to_vec(), blob.as_slice().to_vec()].concat();
        let tree_id = loose_fixture(&f, Kind::Tree, &tree);
        let head = loose_fixture(
            &f,
            Kind::Commit,
            format!(
                "tree {tree_id}\nauthor A <a@b> 0 +0000\ncommitter A <a@b> 0 +0000\n\nmessage\n"
            )
            .as_bytes(),
        );
        let access = access();
        let root = f.root(&mut meter());
        let m = RefCell::new(meter());
        let port = io(&root, &access, &m);
        let db = SafeObjectDb::new(&port);
        assert_eq!(db.head_tree(&head).unwrap(), tree_id);
        assert_eq!(db.tree(&tree_id, &mut Vec::new()).unwrap().count(), 1);
        assert_eq!(m.borrow().budget.used(Axis::IndexEntries), 1);
        assert_eq!(m.borrow().budget.used(Axis::IndexBytes), 4);
        assert_eq!(db.head_tree(&blob).unwrap_err(), INVALID);
        assert!(db.tree(&blob, &mut Vec::new()).is_err());
        m.borrow_mut()
            .budget
            .charge(Axis::IndexEntries, budget::INDEX_ENTRIES - 1)
            .unwrap();
        assert!(matches!(db.tree(&tree_id, &mut Vec::new()), Err(E::Limit)));
    }

    // 이것을 실패시키는 것: Find의 읽기 전 buffer 해제 또는 bytes decoder의 이전 capacity 해제를 생략하는 것.
    #[test]
    fn retained_object_buffers_do_not_overlap_next_input() {
        let first = vec![b'x'; 1_572_864];
        let second = vec![b'y'; 943_718];
        let first_raw = [
            format!("blob {}\0", first.len()).into_bytes(),
            first.clone(),
        ]
        .concat();
        let second_raw = [
            format!("blob {}\0", second.len()).into_bytes(),
            second.clone(),
        ]
        .concat();
        let compressed = super::zip(&first_raw);
        let stored = zlib(&second_raw);
        let first_id = oid(Kind::Blob, &first);
        let second_id = oid(Kind::Blob, &second);
        let mut buffer = Vec::new();
        let mut m = meter();
        assert_eq!(
            objects::loose(&compressed, &first_id, &mut buffer, &mut m)
                .unwrap()
                .data,
            first
        );
        assert_eq!(
            objects::loose(&stored, &second_id, &mut buffer, &mut m)
                .unwrap()
                .data,
            second
        );
        assert!(
            buffer.capacity() + stored.len() + 1 + objects::DECODER_OVERHEAD
                <= budget::OBJECT_ALLOC as usize
        );

        let f = Fixture::new();
        let hex = second_id.to_string();
        f.write(&format!("objects/{}/{}", &hex[..2], &hex[2..]), &stored);
        let access = access();
        let root = f.root(&mut meter());
        let m = RefCell::new(meter());
        let port = io(&root, &access, &m);
        let db = SafeObjectDb::new(&port);
        let (result, counts) = allocation::measure(|| {
            let mut previous = vec![0; first_raw.len()];
            db.find(&second_id, &mut previous)
                .map(|data| data.unwrap().data.len())
        });
        assert_eq!(result.unwrap(), second.len());
        assert!(counts.peak <= budget::OBJECT_ALLOC as usize, "{counts:?}");
        eprintln!(
            "C3_REUSE find_peak={} cap={}",
            counts.peak,
            budget::OBJECT_ALLOC
        );

        let p = super::packed(&[b"small".to_vec()], false);
        let index =
            gix_pack::index::File::from_data(p.index.as_slice(), Default::default(), Hash::Sha1)
                .unwrap();
        let mut oversized = vec![0; budget::OBJECT_ALLOC as usize + 1];
        assert_eq!(
            objects::decode(
                &p.pack,
                &index,
                p.offsets[0],
                &p.ids[0],
                &mut oversized,
                &mut meter()
            )
            .unwrap()
            .data,
            b"small"
        );
        assert!(oversized.capacity() <= objects::OBJECT_BUFFER);
    }

    // 이것을 실패시키는 것: gix 할당 선계상을 줄여 counting allocator peak보다 작게 만드는 것.
    #[test]
    fn c3_parser_peaks_are_precharged() {
        for (version, count, length) in [
            (2, 19_000, 12),
            (2, 50_000, 6),
            (4, 2000, 100),
            (2, 1, 60_000),
        ] {
            let mut bytes = index_bytes(version, count, length, None);
            let mut m = meter();
            m.allocation_limit = 64 * 1024 * 1024;
            let (result, counts) = allocation::measure(|| git_index::parse(&mut bytes, &mut m));
            assert_eq!(result.unwrap().entries().len(), count);
            let reserved = m.counts[Phase::Content as usize].allocated;
            eprintln!(
                "C3_PEAK index-v{version}-{count}-{length} input={} peak={} reserved={reserved}",
                bytes.len(),
                counts.peak
            );
            assert!(counts.peak as u64 <= reserved);
        }
        let access = access();
        for depth in [0, 3, 64] {
            let f = Fixture::new();
            let p = pack_fixture(depth, true, false);
            write_pack(&f, &p);
            f.write(
                "objects/pack/multi-pack-index",
                midx_bytes(&p, false, false),
            );
            let root = f.root(&mut meter());
            let m = RefCell::new(meter());
            let port = io(&root, &access, &m);
            let db = SafeObjectDb::new(&port);
            let mut buffer = Vec::new();
            let id = if depth == 0 {
                oid(Kind::Blob, b"hello")
            } else {
                oid(Kind::Blob, &[b'h', b'e', b'l', b'l', depth as u8])
            };
            let (result, counts) = allocation::measure(|| db.find(&id, &mut buffer));
            assert!(result.unwrap().is_some());
            let reserved = m.borrow().counts[Phase::Content as usize].allocated;
            eprintln!(
                "C3_PEAK pack-midx-delta-{depth} peak={} reserved={reserved}",
                counts.peak
            );
            assert!(counts.peak as u64 <= reserved);
        }
        for size in [0, 1024, 512 * 1024] {
            let raw = [format!("blob {size}\0").into_bytes(), vec![b'x'; size]].concat();
            let compressed = zlib(&raw);
            let id = oid(Kind::Blob, &raw[raw.len() - size..]);
            let mut buffer = Vec::new();
            let mut m = meter();
            let (result, counts) =
                allocation::measure(|| objects::loose(&compressed, &id, &mut buffer, &mut m));
            assert_eq!(result.unwrap().data.len(), size);
            let reserved = m.counts[Phase::Content as usize].allocated;
            eprintln!(
                "C3_PEAK loose-{size} peak={} reserved={reserved}",
                counts.peak
            );
            assert!(counts.peak as u64 <= reserved);
        }
    }
}

// 이것을 실패시키는 것: adapter delta 깊이/합산 scratch/inflate/hash 제한 또는 decoder 앞 예약을 제거하는 것.
#[test]
fn packed_decoder_bounds_and_peaks() {
    for count in [1, 8, 64, 65, 66] {
        let bodies: Vec<_> = (0..count).map(|n| vec![n as u8; 1024]).collect();
        let p = packed(&bodies, true);
        let idx =
            gix_pack::index::File::from_data(p.index.as_slice(), Default::default(), Hash::Sha1)
                .unwrap();
        let mut out = Vec::new();
        let mut m = meter();
        let (result, counts) = allocation::measure(|| {
            objects::decode(
                &p.pack,
                &idx,
                *p.offsets.last().unwrap(),
                p.ids.last().unwrap(),
                &mut out,
                &mut m,
            )
        });
        if count <= 65 {
            assert_eq!(result.unwrap().data, bodies[count - 1]);
        } else {
            assert!(matches!(result, Err(E::Limit)));
            assert_eq!(out.capacity(), 0);
        }
        let charged = m.counts[Phase::Content as usize].allocated as usize;
        assert!(
            counts.peak <= charged,
            "depth={count} {counts:?} charge={charged}"
        );
        eprintln!(
            "C3 adapter delta_depth={} peak={} charge={charged} inflated={}",
            count - 1,
            counts.peak,
            m.budget.used(Axis::DecompressedBytes)
        );
    }
    let p = packed(&[vec![b'a'; 32], vec![b'b'; 1_048_576]], true);
    let idx = gix_pack::index::File::from_data(p.index.as_slice(), Default::default(), Hash::Sha1)
        .unwrap();
    let mut out = Vec::new();
    let mut m = meter();
    assert!(matches!(
        objects::decode(&p.pack, &idx, p.offsets[1], &p.ids[1], &mut out, &mut m),
        Err(E::Limit)
    ));
    assert_eq!(out.capacity(), 0);
    let p = packed(&[b"body".to_vec()], false);
    let idx = gix_pack::index::File::from_data(p.index.as_slice(), Default::default(), Hash::Sha1)
        .unwrap();
    for offset in [0, 11, p.pack.len() as u64, u64::MAX] {
        assert!(objects::decode(&p.pack, &idx, offset, &p.ids[0], &mut out, &mut meter()).is_err());
    }
    assert!(
        objects::decode(
            &p.pack,
            &idx,
            12,
            &ObjectId::null(Hash::Sha1),
            &mut out,
            &mut meter()
        )
        .is_err()
    );
    let mut m = meter();
    m.budget
        .charge(Axis::DecompressedBytes, budget::DECOMPRESSED_BYTES - 3)
        .unwrap();
    assert!(matches!(
        objects::decode(&p.pack, &idx, 12, &p.ids[0], &mut out, &mut m),
        Err(E::Limit)
    ));
    let mut m = meter();
    m.allocation_limit = 0;
    let (result, counts) =
        allocation::measure(|| objects::decode(&p.pack, &idx, 12, &p.ids[0], &mut out, &mut m));
    assert!(matches!(result, Err(E::Limit)));
    assert_eq!(counts.calls, 0);
    let empty = packed(&[Vec::new()], false);
    let empty_index =
        gix_pack::index::File::from_data(empty.index.as_slice(), Default::default(), Hash::Sha1)
            .unwrap();
    for offset in [11usize, empty.pack.len() - 20] {
        let mut data = empty.pack.clone();
        let zlib = zip(b"");
        data[offset] = 0x30; // forged empty-blob header in pack header/trailer
        data[offset + 1..offset + 1 + zlib.len()].copy_from_slice(&zlib);
        assert!(
            objects::decode(
                &data,
                &empty_index,
                offset as u64,
                &empty.ids[0],
                &mut Vec::new(),
                &mut meter()
            )
            .is_err()
        );
    }
    let mut corrupt = p.pack.clone();
    corrupt[13] ^= 0xff;
    assert!(objects::decode(&corrupt, &idx, 12, &p.ids[0], &mut out, &mut meter()).is_err());
}

// 이것을 실패시키는 것: index 캐시 확장을 gix에 그대로 넘기거나 V4 경로 확장·framing 검증을 제거하는 것.
#[test]
fn index_hostile_frames_and_extensions_are_bounded() {
    for signature in [b"TREE", b"UNTR", b"REUC", b"FSMN", b"EOIE", b"IEOT"] {
        let mut bytes = idx_fixture(1, 2);
        extension(&mut bytes, signature, &vec![0xff; 8192]);
        let mut m = meter();
        let (state, counts) = allocation::measure(|| safe_index::parse(&mut bytes, &mut m));
        assert_eq!(state.unwrap().entries().len(), 1);
        assert!(counts.peak <= m.counts[Phase::Content as usize].allocated as usize);
    }
    let mut sparse = idx_fixture(0, 2);
    extension(&mut sparse, b"sdir", &[]);
    assert!(
        safe_index::parse(&mut sparse, &mut meter())
            .unwrap()
            .is_sparse()
    );
    for mut bytes in [
        vec![],
        b"DIRC".to_vec(),
        idx_fixture(1, 2),
        idx_fixture(1, 3),
        idx_fixture(1, 4),
    ] {
        if bytes.len() > 32 {
            bytes.truncate(bytes.len() - 21);
            bytes.extend_from_slice(&[0; 20]);
        }
        assert!(safe_index::parse(&mut bytes, &mut meter()).is_err());
    }
    for (offset, value) in [(0, b'X'), (7, 5), (72, b'/'), (73, 0)] {
        let mut bytes = idx_fixture(1, 2);
        bytes[offset] = value;
        bytes.truncate(bytes.len() - 20);
        seal(&mut bytes);
        assert!(
            safe_index::parse(&mut bytes, &mut meter()).is_err(),
            "{offset}"
        );
    }
    for (sig, body) in [(b"abcd", b"".as_slice()), (b"sdir", b"x")] {
        let mut bytes = idx_fixture(1, 2);
        extension(&mut bytes, sig, body);
        assert!(safe_index::parse(&mut bytes, &mut meter()).is_err());
    }
    let mut bytes = idx_fixture(1, 2);
    extension(&mut bytes, b"TREE", b"a");
    let at = bytes.len() - 25;
    bytes[at..at + 4].copy_from_slice(&u32::MAX.to_be_bytes());
    bytes.truncate(bytes.len() - 20);
    seal(&mut bytes);
    assert!(safe_index::parse(&mut bytes, &mut meter()).is_err());
    let mut bytes = idx_fixture(2, 4);
    bytes[74] = 127;
    bytes.truncate(bytes.len() - 20);
    seal(&mut bytes);
    assert!(safe_index::parse(&mut bytes, &mut meter()).is_err());
    let mut huge = vec![0; budget::INDEX_BYTES as usize + 1];
    let mut m = meter();
    let (result, counts) = allocation::measure(|| safe_index::parse(&mut huge, &mut m));
    assert!(matches!(result, Err(E::Limit)));
    assert_eq!(counts.calls, 0);
}

// 이것을 실패시키는 것: HEAD/tree 파싱의 객체 kind·이름 검증 및 IndexEntries/IndexBytes 공유 charge 제거.
#[test]
fn head_tree_uses_find_and_shared_index_budgets() {
    let f = Fixture::new();
    let access = access();
    let mut m = meter();
    let root = f.root(&mut m);
    let m = RefCell::new(m);
    let blob = loose_fixture(&f, Kind::Blob, b"value");
    let mut tree = b"100644 name\0".to_vec();
    tree.extend_from_slice(blob.as_slice());
    let tree_id = loose_fixture(&f, Kind::Tree, &tree);
    let head = loose_fixture(
        &f,
        Kind::Commit,
        format!("tree {tree_id}\n\nmessage\n").as_bytes(),
    );
    let port = io(&root, &access, &m);
    let db = SafeObjectDb::new(&port);
    assert_eq!(db.head_tree(&head).unwrap(), tree_id);
    let mut out = Vec::new();
    let entries: Vec<_> = db
        .tree(&tree_id, &mut out)
        .unwrap()
        .inspect(|e| {
            e.as_ref().unwrap();
        })
        .collect();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].as_ref().unwrap().oid, blob.as_ref());
    assert_eq!(m.borrow().budget.used(Axis::IndexEntries), 1);
    assert_eq!(m.borrow().budget.used(Axis::IndexBytes), 4);
    assert!(db.head_tree(&blob).is_err());
    assert!(db.tree(&blob, &mut out).is_err());
    let mut bad = b"100644 ../escape\0".to_vec();
    bad.extend_from_slice(blob.as_slice());
    let bad_id = loose_fixture(&f, Kind::Tree, &bad);
    assert!(db.tree(&bad_id, &mut out).is_err());
    let wrong_commit = loose_fixture(
        &f,
        Kind::Blob,
        format!("tree {tree_id}\n\nmessage\n").as_bytes(),
    );
    assert_eq!(db.head_tree(&wrong_commit).unwrap_err(), INVALID);
    let wrong_tree = loose_fixture(&f, Kind::Blob, &tree);
    assert!(db.tree(&wrong_tree, &mut out).is_err());
    let remaining = budget::INDEX_ENTRIES - m.borrow().budget.used(Axis::IndexEntries);
    m.borrow_mut()
        .budget
        .charge(Axis::IndexEntries, remaining)
        .unwrap();
    assert!(matches!(db.tree(&tree_id, &mut out), Err(E::Limit)));
    let before = m.borrow().counts;
    assert!(db.head_tree(&head).is_err());
    assert_eq!(m.borrow().counts, before);
}

// 이것을 실패시키는 것: __getdirentries64 심벌 제거·path 재열기·raw/할당/마감 선검사·EOF 검사 제거.
#[test]
#[cfg(target_os = "macos")]
fn darwin_directory_symbol_and_bounded_blocks() {
    let f = Fixture::new();
    for n in 0..300 {
        f.write(&format!("dir/{n:04}-{}", "x".repeat(80)), b"");
    }
    let access = access();
    let root = f.root(&mut meter());
    let directory = safe_read::directory(&root, b"dir", &access, &mut meter()).unwrap();
    fs::rename(f.0.join("dir"), f.0.join("held")).unwrap();
    f.write("dir/REPLACEMENT", b"");
    let mut m = meter();
    let list = safe_read::entries(&directory, 400, &mut m).unwrap();
    assert!(list.complete);
    assert_eq!(list.names.len(), 300);
    assert!(list.names.iter().all(|name| name.len() == 85));
    let count = m.counts[Phase::Content as usize];
    assert_eq!(count.raw_entries, 302); // dots count before filtering
    assert!(count.list > 2); // multiple 8 KiB blocks plus EOF
    assert_eq!((count.open, count.stat, count.read), (0, 0, 0));
    for limit in [0, 1, 302] {
        let directory = safe_read::directory(&root, b"held", &access, &mut meter()).unwrap();
        let mut m = meter();
        let list = safe_read::entries(&directory, limit, &mut m).unwrap();
        assert!(!list.complete);
        assert_eq!(
            m.counts[Phase::Content as usize].raw_entries,
            u64::from(limit)
        );
        if limit == 0 {
            assert_eq!(m.counts[Phase::Content as usize].list, 0);
        }
    }
    for deadline in [false, true] {
        let directory = safe_read::directory(&root, b"held", &access, &mut meter()).unwrap();
        let mut m = if deadline {
            Meter::new(Instant::now())
        } else {
            meter()
        };
        m.allocation_limit = 0;
        let (result, counts) = allocation::measure(|| safe_read::entries(&directory, 400, &mut m));
        assert_eq!(
            result.err().unwrap(),
            if deadline { E::Deadline } else { E::Limit }
        );
        assert_eq!(counts.calls, 0);
        if deadline {
            assert_eq!(m.counts[Phase::Content as usize].list, 0);
        }
    }
}

// 이것을 실패시키는 것: same-fd snapshot의 shrink/growth 거부 또는 소진된 축의 open 전 검사 제거.
#[test]
fn budgeted_snapshots_reject_changes_before_more_io() {
    let f = Fixture::new();
    let access = access();
    let root = f.root(&mut meter());
    for grow in [false, true] {
        f.write("data", b"original");
        let m = RefCell::new(meter());
        let dest = f.0.join("data");
        m.borrow_mut().hook = Some(Box::new(move |event| {
            if event == "before_read" {
                fs::write(
                    &dest,
                    if grow {
                        b"overgrown".as_slice()
                    } else {
                        b"short"
                    },
                )
                .unwrap();
            }
        }));
        let port = io(&root, &access, &m);
        assert_eq!(
            port.map(path(RootId::GitDir, b"data"), 8).unwrap_err(),
            if grow { E::Limit } else { E::Changed }
        );
    }
    for axis in [Axis::IndexBytes, Axis::PackBytes] {
        let m = RefCell::new(meter());
        m.borrow_mut().budget.charge(axis, axis.limit()).unwrap();
        let port = io(&root, &access, &m);
        assert_eq!(
            port.read_budgeted(path(RootId::GitDir, b"data"), 8, axis)
                .unwrap_err(),
            E::Limit
        );
        assert_eq!(m.borrow().counts[Phase::Content as usize].open, 0);
    }
}

// 이것을 실패시키는 것: pack/idx/MIDX checksum·연결·이름·OID 순서·offset 검증을 생략하는 것.
#[test]
fn hostile_pack_metadata_is_not_clean_or_a_panic() {
    let access = access();
    for case in 0..20 {
        let f = Fixture::new();
        let mut p = packed(&[b"one".to_vec(), b"two".to_vec()], false);
        let mut multi = midx(&[&p]);
        let reseal = |data: &mut Vec<u8>| {
            data.truncate(data.len() - 20);
            seal(data);
        };
        match case {
            0 => p.pack[15] ^= 1, // checksum
            1 => p.index[1050] ^= 1,
            2 => multi[80] ^= 1,
            3 => {
                p.index[4] = 1;
                reseal(&mut p.index);
            } // version
            4 => {
                p.index[1032..1052].fill(0);
                reseal(&mut p.index);
            } // fan mismatch
            5 => {
                p.index[1080..1084].copy_from_slice(&u32::MAX.to_be_bytes());
                reseal(&mut p.index);
            }
            6 => {
                multi[5] = 2;
                reseal(&mut multi);
            } // hash
            7 => {
                multi[7] = 1;
                reseal(&mut multi);
            } // chain
            8 => {
                multi[8..12].copy_from_slice(&9u32.to_be_bytes());
                reseal(&mut multi);
            }
            9 => {
                multi[72] = b'/';
                reseal(&mut multi);
            }
            10 => {
                multi[4] = 2;
                reseal(&mut multi);
            }
            11 => {
                // pack number
                let at = u64::from_be_bytes(multi[52..60].try_into().unwrap()) as usize;
                multi[at..at + 4].copy_from_slice(&9u32.to_be_bytes());
                reseal(&mut multi);
            }
            12 => {
                // offset mismatch
                let at = u64::from_be_bytes(multi[52..60].try_into().unwrap()) as usize;
                multi[at + 4..at + 8].copy_from_slice(&11u32.to_be_bytes());
                reseal(&mut multi);
            }
            13 => {
                p.pack[11] = 3;
                reseal(&mut p.pack);
            }
            14 => {
                // duplicate OID, correctly sealed
                let id = p.index[1032..1052].to_vec();
                p.index[1052..1072].copy_from_slice(&id);
                reseal(&mut p.index);
            }
            15 => {
                // matching pack checksum but wrong count
                p.pack[11] = 3;
                reseal(&mut p.pack);
                let end = p.index.len();
                p.index[end - 40..end - 20].copy_from_slice(&p.pack[p.pack.len() - 20..]);
                reseal(&mut p.index);
            }
            16 => {
                // bad MIDX ordering
                let at = u64::from_be_bytes(multi[40..48].try_into().unwrap()) as usize;
                multi[at..at + 20].fill(255);
                reseal(&mut multi);
            }
            17 => {
                let end = p.index.len();
                p.index[end - 40] ^= 1;
                reseal(&mut p.index);
            }
            18 => {
                let at = u64::from_be_bytes(multi[40..48].try_into().unwrap()) as usize;
                let first = multi[at..at + 20].to_vec();
                multi[at + 20..at + 40].copy_from_slice(&first);
                let at = u64::from_be_bytes(multi[52..60].try_into().unwrap()) as usize;
                let first = multi[at..at + 8].to_vec();
                multi[at + 8..at + 16].copy_from_slice(&first);
                reseal(&mut multi);
            }
            19 => {
                let at = u64::from_be_bytes(multi[28..36].try_into().unwrap()) as usize;
                multi[at..at + 255 * 4].fill(0);
                reseal(&mut multi);
            }
            _ => unreachable!(),
        }
        install_pack(&f, &p);
        if case == 2 || (6..=12).contains(&case) || case == 16 || case == 18 || case == 19 {
            f.write("objects/pack/multi-pack-index", multi);
        }
        let root = f.root(&mut meter());
        let m = RefCell::new(meter());
        let port = io(&root, &access, &m);
        assert!(
            SafeObjectDb::new(&port)
                .find(&p.ids[0], &mut Vec::new())
                .is_err(),
            "case {case}"
        );
    }
}

// 이것을 실패시키는 것: 실제 parser/decoder 호출 또는 결과 검증을 제거·손상시키는 것.
#[test]
fn object_index_observations() {
    fn report(name: &str, samples: &mut [u128], cold: u128) {
        samples.sort_unstable();
        let mean = samples.iter().sum::<u128>() as f64 / samples.len() as f64;
        let variance = samples
            .iter()
            .map(|n| (*n as f64 - mean).powi(2))
            .sum::<f64>()
            / samples.len() as f64;
        eprintln!(
            "C3_OBSERVE {{\"case\":\"{name}\",\"rounds\":{},\"cold_ns\":{cold},\"p50_ns\":{},\"p95_ns\":{},\"variance_ns2\":{variance}}}",
            samples.len(),
            samples[samples.len() / 2],
            samples[samples.len() * 95 / 100]
        );
    }
    let pristine = idx_fixture(19_000, 2);
    let mut samples = Vec::new();
    let mut cold = 0;
    for n in 0..201 {
        let mut bytes = pristine.clone();
        let mut m = meter();
        let start = Instant::now();
        let state = safe_index::parse(&mut bytes, &mut m).unwrap();
        let elapsed = start.elapsed().as_nanos();
        assert_eq!(state.entries().len(), 19_000);
        if n == 0 {
            cold = elapsed;
        } else {
            samples.push(elapsed);
        }
    }
    report("index-19000", &mut samples, cold);
    let bodies: Vec<_> = (0..64).map(|n| vec![n as u8; 1024]).collect();
    let p = packed(&bodies, true);
    let index =
        gix_pack::index::File::from_data(p.index.as_slice(), Default::default(), Hash::Sha1)
            .unwrap();
    samples.clear();
    for n in 0..201 {
        let mut m = meter();
        let mut buffer = Vec::new();
        let start = Instant::now();
        let data = objects::decode(
            &p.pack,
            &index,
            p.offsets[63],
            &p.ids[63],
            &mut buffer,
            &mut m,
        )
        .unwrap();
        let elapsed = start.elapsed().as_nanos();
        assert_eq!(data.data, bodies[63]);
        if n == 0 {
            cold = elapsed;
        } else {
            samples.push(elapsed);
        }
    }
    report("delta-63", &mut samples, cold);
}

// 이것을 실패시키는 것: 중복 방어를 통과하도록 만든 입력에서 길이·kind·framing·MIDX 선예약을 제거하는 것.
#[test]
fn c3_guards_have_independent_negative_controls() {
    let f = Fixture::new();
    let access = access();
    let root = f.root(&mut meter());
    let m = RefCell::new(meter());
    let port = io(&root, &access, &m);
    // Hash matches the zero-filled slack, so only the declared-vs-produced
    // length check rejects this deliberately short zlib stream.
    let id = gix_object::compute_hash(Hash::Sha1, Kind::Blob, b"payload\0").unwrap();
    let raw = zip(b"blob 8\0payload");
    assert!(matches!(
        objects::loose(&raw, &id, &mut Vec::new(), &mut meter()),
        Err(INVALID)
    ));
    // Valid tree syntax inside an object whose authenticated kind is Blob.
    let tree = [
        b"100644 a\0".as_slice(),
        ObjectId::null(Hash::Sha1).as_slice(),
    ]
    .concat();
    let id = loose_fixture(&f, Kind::Blob, &tree);
    assert!(matches!(
        SafeObjectDb::new(&port).tree(&id, &mut Vec::new()),
        Err(INVALID)
    ));
    // A shortened path length would otherwise be accepted by gix after its
    // padding skip. All entry bytes and the original checksum are valid.
    let mut index = idx_fixture(1, 2);
    index[73] = 9;
    index.truncate(index.len() - 20);
    seal(&mut index);
    assert!(matches!(
        safe_index::parse(&mut index, &mut meter()),
        Err(INVALID)
    ));
    // MIDX's own allocator is small enough that a missing precharge used to
    // hide under the unrelated pack reservation. Give it zero remaining bytes.
    f.write("empty-midx", midx(&[]));
    let bytes = port
        .map(path(RootId::CommonDir, b"empty-midx"), 4096)
        .unwrap();
    let mut limit = meter();
    limit.allocation_limit = 0;
    assert!(matches!(
        objects::validate_midx(bytes, &[], &mut limit),
        Err(E::Limit)
    ));
    // The first object byte must never overlap PACK's 12-byte header, even if
    // the bytes at offset 8 form a valid empty blob stream with the right hash.
    let mut overlap = b"PACK\0\0\0\x02\x30".to_vec();
    overlap.extend(zip(b""));
    seal(&mut overlap);
    let p = packed(&[Vec::new()], false);
    let idx = gix_pack::index::File::from_data(p.index.as_slice(), Default::default(), Hash::Sha1)
        .unwrap();
    assert!(matches!(
        objects::decode(&overlap, &idx, 8, &p.ids[0], &mut Vec::new(), &mut meter()),
        Err(INVALID)
    ));
}

// 이것을 실패시키는 것: loose 압축 입력과 출력의 동시 생존 bytes를 객체 상한에서 제외하는 것.
#[test]
fn loose_input_and_output_share_the_object_allocation_cap() {
    // Oversized compressed input is rejected even before constructing zlib.
    let excessive = vec![0; 1_966_080];
    let mut m = meter();
    let (result, counts) = allocation::measure(|| {
        objects::loose(
            &excessive,
            &ObjectId::null(Hash::Sha1),
            &mut Vec::new(),
            &mut m,
        )
        .map(|_| ())
    });
    assert!(matches!(result, Err(E::Limit)));
    assert_eq!(counts.calls, 0);
    let f = Fixture::new();
    let access = access();
    let root = f.root(&mut meter());
    f.write(
        "objects/00/00000000000000000000000000000000000000",
        &excessive,
    );
    let m = RefCell::new(meter());
    let port = io(&root, &access, &m);
    assert!(matches!(
        SafeObjectDb::new(&port).find(&ObjectId::null(Hash::Sha1), &mut Vec::new()),
        Err(E::Limit)
    ));
    assert_eq!(m.borrow().counts[Phase::Content as usize].read_bytes, 0);
    // Stored DEFLATE keeps input incompressible without a random fixture.
    let body = vec![b'x'; budget::OBJECT_ALLOC as usize / 2];
    let id = gix_object::compute_hash(Hash::Sha1, Kind::Blob, &body).unwrap();
    let mut plain = format!("blob {}\0", body.len()).into_bytes();
    plain.extend_from_slice(&body);
    let mut compressed = vec![0x78, 0x01];
    for (n, block) in plain.chunks(65535).enumerate() {
        compressed.push(u8::from((n + 1) * 65535 >= plain.len()));
        let len = block.len() as u16;
        compressed.extend_from_slice(&len.to_le_bytes());
        compressed.extend_from_slice(&(!len).to_le_bytes());
        compressed.extend_from_slice(block);
    }
    let (mut a, mut b) = (1u32, 0u32);
    for byte in plain {
        a = (a + u32::from(byte)) % 65521;
        b = (b + a) % 65521;
    }
    compressed.extend_from_slice(&((b << 16) | a).to_be_bytes());
    let mut m = meter();
    let mut out = Vec::new();
    assert!(matches!(
        objects::loose(&compressed, &id, &mut out, &mut m),
        Err(E::Limit)
    ));
    assert_eq!(out.capacity(), 0);
    assert_eq!(
        m.counts[Phase::Content as usize].allocated,
        (objects::DECODER_OVERHEAD + compressed.len() + 1) as u64
    );
}

// 이것을 실패시키는 것: V4의 압축 경로 길이만 계수하고 확장 경로 bytes를 파싱 뒤에 검사하는 것.
#[test]
fn expanded_v4_paths_stop_before_allocation() {
    fn input(count: u32, first_len: usize) -> Vec<u8> {
        let fixed = idx_fixture(1, 4)[12..74].to_vec();
        let mut bytes = b"DIRC\0\0\0\x04".to_vec();
        bytes.extend_from_slice(&count.to_be_bytes());
        for n in 0..count {
            bytes.extend_from_slice(&fixed);
            bytes.push(0);
            if n == 0 {
                bytes.extend(std::iter::repeat_n(b'a', first_len));
            } else {
                bytes.push(b'b');
            }
            bytes.push(0);
        }
        seal(&mut bytes);
        bytes
    }
    for mut bytes in [input(2, 65_536), input(80, 60_000)] {
        assert!(bytes.len() < (budget::INDEX_BYTES as usize));
        let mut m = meter();
        let (result, counts) = allocation::measure(|| safe_index::parse(&mut bytes, &mut m));
        assert!(matches!(result, Err(E::Limit)));
        assert_eq!(counts.calls, 0);
    }
}

// 이것을 실패시키는 것: 실제 index/decoder 호출이나 결과 검증을 생략해 빈 작업 시간을 기록하는 것.
#[test]
fn c3_warm_decoder_and_index_observations() {
    fn report(name: &str, mut samples: Vec<u128>, cold: u128) {
        samples.sort_unstable();
        let mean = samples.iter().sum::<u128>() as f64 / samples.len() as f64;
        let variance = samples
            .iter()
            .map(|n| (*n as f64 - mean).powi(2))
            .sum::<f64>()
            / samples.len() as f64;
        eprintln!(
            "C3_TIME {name} rounds={} cold_ns={cold} p50_ns={} p95_ns={} variance_ns2={variance}",
            samples.len(),
            samples[100],
            samples[190]
        );
    }
    let source = idx_fixture(19_000, 2);
    let mut samples = Vec::new();
    let mut cold = 0;
    for n in 0..201 {
        let mut bytes = source.clone();
        let mut m = meter();
        let start = Instant::now();
        let state = safe_index::parse(&mut bytes, &mut m).unwrap();
        let elapsed = start.elapsed().as_nanos();
        assert_eq!(state.entries().len(), 19_000);
        if n == 0 {
            cold = elapsed;
        } else {
            samples.push(elapsed);
        }
    }
    report("index-19000", samples, cold);
    let bodies: Vec<_> = (0..64).map(|n| vec![n as u8; 1024]).collect();
    let p = packed(&bodies, true);
    let idx = gix_pack::index::File::from_data(p.index.as_slice(), Default::default(), Hash::Sha1)
        .unwrap();
    let mut samples = Vec::new();
    let mut cold = 0;
    for n in 0..201 {
        let mut out = Vec::new();
        let mut m = meter();
        let start = Instant::now();
        let data =
            objects::decode(&p.pack, &idx, p.offsets[63], &p.ids[63], &mut out, &mut m).unwrap();
        let elapsed = start.elapsed().as_nanos();
        assert_eq!(data.data, bodies[63]);
        if n == 0 {
            cold = elapsed;
        } else {
            samples.push(elapsed);
        }
    }
    report("delta-depth-63", samples, cold);
}

// 이것을 실패시키는 것: 참조 객체가 없는 pack의 MIDX 이름 검사 생략 또는 새 pack이 생긴 정상 subset 거부.
#[test]
fn midx_unused_pack_names_are_validated() {
    let access = access();
    for hostile in [false, true] {
        let f = Fixture::new();
        let empty = packed(&[], false);
        let other = packed(&[b"newer pack".to_vec()], false);
        install_pack(&f, &empty);
        install_pack(&f, &other);
        let mut multi = midx(&[&empty, &other]);
        if hostile {
            let name = format!("{}.idx", empty.name);
            let at = multi
                .windows(name.len())
                .position(|b| b == name.as_bytes())
                .unwrap();
            multi[at + 45] = b'/';
            multi.truncate(multi.len() - 20);
            seal(&mut multi);
        }
        f.write("objects/pack/multi-pack-index", multi);
        let root = f.root(&mut meter());
        let m = RefCell::new(meter());
        let port = io(&root, &access, &m);
        let mut buffer = Vec::new();
        let db = SafeObjectDb::new(&port);
        let result = db.find(&other.ids[0], &mut buffer);
        if hostile {
            assert!(matches!(result, Err(INVALID)));
        } else {
            assert_eq!(result.unwrap().unwrap().data, b"newer pack");
        }
    }
}

// 이것을 실패시키는 것: 선택 extension payload를 gix의 initial path allocation 추정에 다시 포함하는 것.
#[test]
fn review_index_extension_peak_stays_inside_reservation() {
    for size in [0, 100_000, 130_000] {
        let mut bytes = idx_fixture(1000, 2);
        extension(&mut bytes, b"TREE", &vec![0; size]);
        let mut m = meter();
        let (state, counts) = allocation::measure(|| safe_index::parse(&mut bytes, &mut m));
        assert_eq!(state.unwrap().entries().len(), 1000);
        assert!(counts.peak <= m.counts[Phase::Content as usize].allocated as usize);
        eprintln!(
            "C3_REVIEW extension={size} peak={} reserved={}",
            counts.peak,
            m.counts[Phase::Content as usize].allocated
        );
    }
}

// 이것을 실패시키는 것: MIDX가 모든 현재 pack을 포함해야 한다고 요구해 신규 standalone pack을 거부하는 것.
#[test]
fn review_midx_can_cover_a_subset_of_current_packs() {
    let f = Fixture::new();
    let first = packed(&[b"old pack".to_vec()], false);
    let newer = packed(&[b"new pack".to_vec()], false);
    install_pack(&f, &first);
    install_pack(&f, &newer);
    f.write("objects/pack/multi-pack-index", midx(&[&first]));
    let access = access();
    let root = f.root(&mut meter());
    let m = RefCell::new(meter());
    let port = io(&root, &access, &m);
    let db = SafeObjectDb::new(&port);
    assert_eq!(
        db.find(&first.ids[0], &mut Vec::new())
            .unwrap()
            .unwrap()
            .data,
        b"old pack"
    );
    assert_eq!(
        db.find(&newer.ids[0], &mut Vec::new())
            .unwrap()
            .unwrap()
            .data,
        b"new pack"
    );
}

// 이것을 실패시키는 것: 이전 caller buffer를 Find/loose/decode에서 유지해 객체별 live-capacity 상한을 넘기는 것.
#[test]
fn reused_output_capacity_never_escapes_object_budget() {
    let oversized = || Vec::with_capacity(budget::OBJECT_ALLOC as usize + 1);
    let f = Fixture::new();
    let access = access();
    let root = f.root(&mut meter());
    let m = RefCell::new(meter());
    let port = io(&root, &access, &m);
    let mut output = oversized();
    assert!(
        SafeObjectDb::new(&port)
            .find(&ObjectId::null(Hash::Sha1), &mut output)
            .unwrap()
            .is_none()
    );
    assert_eq!(output.capacity(), 0);
    let raw = zip(b"blob 1\0x");
    let id = gix_object::compute_hash(Hash::Sha1, Kind::Blob, b"x").unwrap();
    let mut output = oversized();
    assert_eq!(
        objects::loose(&raw, &id, &mut output, &mut meter())
            .unwrap()
            .data,
        b"x"
    );
    assert!(output.capacity() <= objects::OBJECT_BUFFER);
    let p = packed(&[b"x".to_vec()], false);
    let index =
        gix_pack::index::File::from_data(p.index.as_slice(), Default::default(), Hash::Sha1)
            .unwrap();
    let mut output = oversized();
    assert_eq!(
        objects::decode(
            &p.pack,
            &index,
            p.offsets[0],
            &p.ids[0],
            &mut output,
            &mut meter()
        )
        .unwrap()
        .data,
        b"x"
    );
    assert!(output.capacity() <= objects::OBJECT_BUFFER);
}

// 이것을 실패시키는 것: borrowed commit/tree parser도 오류 할당을 할 수 있다는 점을 선예약에서 누락하는 것.
#[test]
fn borrowed_object_parser_peaks_are_precharged() {
    let id = ObjectId::null(Hash::Sha1);
    let commit =
        format!("tree {id}\nauthor A <a@b> 0 +0000\ncommitter A <a@b> 0 +0000\n\nmessage\n");
    let tree = [b"100644 entry\0".as_slice(), id.as_slice()].concat();
    for (input, valid) in [
        (commit.as_bytes(), true),
        (b"tree invalid\n".as_slice(), false),
    ] {
        let (result, counts) = allocation::measure(|| {
            gix_object::CommitRefIter::from_bytes(input, Hash::Sha1).tree_id()
        });
        assert_eq!(result.is_ok(), valid);
        if valid {
            assert_eq!(result.unwrap(), id);
        }
        assert!(counts.peak <= objects::PARSER_OVERHEAD);
        eprintln!(
            "C3_BORROWED commit valid={valid} peak={} reserved={}",
            counts.peak,
            objects::PARSER_OVERHEAD
        );
    }
    for (input, valid) in [(tree.as_slice(), true), (b"bad entry\0".as_slice(), false)] {
        let (result, counts) = allocation::measure(|| {
            gix_object::TreeRefIter::from_bytes(input, Hash::Sha1)
                .next()
                .unwrap()
        });
        assert_eq!(result.is_ok(), valid);
        assert!(counts.peak <= objects::PARSER_OVERHEAD);
        eprintln!(
            "C3_BORROWED tree valid={valid} peak={} reserved={}",
            counts.peak,
            objects::PARSER_OVERHEAD
        );
    }
}
