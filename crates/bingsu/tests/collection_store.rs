//! Atomic publication and bounded reclamation tests use the exact command modules in a test-only target.
#![cfg(unix)]
#![allow(dead_code)]

#[path = "../src/commands/mod.rs"]
mod commands;
#[path = "../src/prompt.rs"]
mod prompt;
#[path = "../src/prompt_io.rs"]
mod prompt_io;
#[path = "../src/prompt_read.rs"]
mod prompt_read;
#[path = "../src/prompt_spawn.rs"]
mod prompt_spawn;
#[cfg(target_os = "linux")]
#[path = "../src/sandbox.rs"]
mod sandbox;
#[cfg(not(target_os = "linux"))]
mod sandbox {
    pub fn enter() -> bingsu_core::front::Sandbox {
        bingsu_core::front::Sandbox::Absent
    }
}

use bingsu_core::{
    collection::{
        response::Completed,
        wire::{Binding, BuildId, EndReason, M3B_REQUEST_ID, Update},
    },
    field::{SegmentDecl, Value},
    snapshot::{self, Clock},
};
use commands::{
    collection_gc::{self, GcBudget},
    collection_store::CollectionStore,
    snapshot_store::{CheckedContextFd, StoreError},
    sys,
};
use std::{
    ffi::OsStr,
    fs::{self, File},
    os::{
        fd::{AsFd, AsRawFd},
        unix::fs::{MetadataExt, PermissionsExt, symlink},
    },
    path::PathBuf,
    process::Command,
    sync::atomic::{AtomicU32, Ordering},
};

// Unrelated fork fixtures must not inherit another test's close-only OFDs.
static TEST_SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());
static SEQUENCE: AtomicU32 = AtomicU32::new(0);
static SCHEMA: [SegmentDecl; 32] = [const {
    SegmentDecl {
        id: "fixture",
        role: "fg",
        fields: &[],
    }
}; 32];
fn clock() -> Clock {
    Clock {
        boot: [1; 16],
        kind: 1,
        domain: [0; 16],
        resume: 0,
        now: 1_000,
    }
}
fn binding(cwd: &[u8]) -> Binding {
    Binding {
        build_id: BuildId([7; 32]),
        snapshot: snapshot::Identity {
            boot: [1; 16],
            epoch: [2; 16],
            generation: 1,
            context: snapshot::context_crc(b"/config", b"/state").unwrap(),
            source: [3; 4],
        },
        clock_kind: 1,
        domain: [0; 16],
        resume: 0,
        config: b"/config".to_vec(),
        state: b"/state".to_vec(),
        cwd: cwd.to_vec(),
        mask: 1 << 31,
    }
}
fn completed(binding: &Binding, value: &[u8]) -> Completed {
    Completed {
        binding: binding.clone(),
        request_id: M3B_REQUEST_ID,
        completed_at_ns: 900,
        reason: EndReason::Complete,
        updates: vec![Update {
            segment: 31,
            value: Some(Value::new(value, vec![])),
        }],
    }
}
struct Fixture {
    _serial: std::sync::MutexGuard<'static, ()>,
    base: PathBuf,
    runtime: File,
    context: CheckedContextFd,
    binding: Binding,
}
impl Fixture {
    fn new(tag: &str) -> Self {
        Self::new_in(
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/c2-fixtures"),
            tag,
        )
    }
    fn new_in(root: PathBuf, tag: &str) -> Self {
        let serial = TEST_SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let base = root.join(format!(
            "{tag}-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&base).unwrap();
        fs::set_permissions(&base, fs::Permissions::from_mode(0o700)).unwrap();
        let runtime = File::open(&base).unwrap();
        let binding = binding(b"/cwd");
        let context = CheckedContextFd::under_runtime(
            &runtime,
            &binding.config,
            &binding.state,
            sys::current_uid(),
            true,
        )
        .unwrap();
        let f = Self {
            _serial: serial,
            base,
            runtime,
            context,
            binding,
        };
        for _ in 0..8 {
            if !f.gc(clock()).incomplete {
                return f;
            }
        }
        panic!("fresh bounded inventory did not complete");
    }
    fn path_for(&self, binding: &Binding) -> PathBuf {
        snapshot::context_components(&binding.config, &binding.state)
            .unwrap()
            .into_iter()
            .chain(binding.components())
            .fold(self.base.clone(), |p, n| p.join(n))
    }
    fn path(&self) -> PathBuf {
        self.path_for(&self.binding)
    }
    fn acquire(&self) -> Result<CollectionStore, StoreError> {
        CollectionStore::fixture(&self.context, &self.binding, clock(), &SCHEMA, None)
    }
    fn gc(&self, now: Clock) -> collection_gc::GcReport {
        collection_gc::fixture_reclaim(&self.runtime, now, GcBudget::default(), &SCHEMA).unwrap()
    }
    fn publish(&self, value: &[u8]) {
        self.acquire()
            .unwrap()
            .publish(&completed(&self.binding, value))
            .unwrap();
    }
    fn read(&self, name: &str) -> Completed {
        Completed::decode_with_catalog(&fs::read(self.path().join(name)).unwrap(), &SCHEMA).unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        // std's remove_dir_all keeps one descriptor per level; the 1,093-level
        // legacy chain needs more than a 1,024 soft limit.
        raise_nofile_soft_limit();
        fs::remove_dir_all(&self.base).unwrap();
    }
}

fn raise_nofile_soft_limit() {
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: getrlimit and setrlimit only read and write `limit`.
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) } == 0
        && limit.rlim_cur < limit.rlim_max
    {
        limit.rlim_cur = limit.rlim_max.min(65_536);
        // SAFETY: as above.
        unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limit) };
    }
}

// 이것을 실패시키는 것: staging의 동일 fd 바이트·stamp·binding 검사 중 하나를 생략하는 것.
#[test]
fn publication_checks_same_fd_bytes_and_identity() {
    let f = Fixture::new("publication");
    f.publish(b"old");
    let original = fs::read(f.path().join("response")).unwrap();
    for (point, change) in [
        ("after_write", 0),
        ("after_write", 1),
        ("after_write", 2),
        ("after_check", 2),
        ("before_rotate", 3),
    ] {
        let mut store = f.acquire().unwrap();
        let path = f.path();
        let result = store.publish_with_hook(&completed(&f.binding, b"new"), &mut |at| {
            if at != point {
                return;
            }
            let stage = path.join(".response.stage");
            match change {
                0 => {
                    let mut b = fs::read(&stage).unwrap();
                    let n = b.len();
                    b[n - 1] ^= 1;
                    fs::write(stage, b).unwrap();
                }
                1 => {
                    File::options()
                        .write(true)
                        .open(stage)
                        .unwrap()
                        .set_len(0)
                        .unwrap();
                }
                2 => {
                    fs::rename(&stage, path.join("saved-stage")).unwrap();
                    fs::write(&stage, b"replacement").unwrap();
                    fs::set_permissions(stage, fs::Permissions::from_mode(0o600)).unwrap();
                }
                _ => fs::set_permissions(stage, fs::Permissions::from_mode(0o644)).unwrap(),
            }
        });
        assert!(result.is_err(), "checkpoint {point}, change {change}");
        assert_eq!(fs::read(path.join("response")).unwrap(), original);
        drop(store);
        let _ = fs::remove_file(path.join(".response.stage"));
        let _ = fs::remove_file(path.join("saved-stage"));
    }
    let mut wrong = completed(&f.binding, b"wrong");
    wrong.binding.snapshot.generation += 1;
    assert!(f.acquire().unwrap().publish(&wrong).is_err());
    assert_eq!(fs::read(f.path().join("response")).unwrap(), original);
}

// 이것을 실패시키는 것: 응답 파일의 nofollow·0600·nlink·길이·CRC 판정을 빼는 것.
#[test]
fn publication_refuses_unsafe_existing_files() {
    let f = Fixture::new("unsafe");
    f.publish(b"old");
    let path = f.path();
    let previous = path.join("previous");
    let original = fs::read(path.join("response")).unwrap();
    for case in 0..7 {
        match case {
            0 => symlink(path.join("response"), &previous).unwrap(),
            1 => fs::hard_link(path.join("response"), &previous).unwrap(),
            2 => {
                fs::write(&previous, &original).unwrap();
                fs::set_permissions(&previous, fs::Permissions::from_mode(0o644)).unwrap();
            }
            3 => sys::make_test_fifo(&previous).unwrap(),
            4..=6 => {
                let data = match case {
                    4 => vec![],
                    5 => vec![0; 262_145],
                    _ => {
                        let mut b = original.clone();
                        b[16] ^= 1;
                        b
                    }
                };
                fs::write(&previous, data).unwrap();
                fs::set_permissions(&previous, fs::Permissions::from_mode(0o600)).unwrap();
            }
            _ => unreachable!(),
        }
        if case == 0 {
            let dir = File::open(&path).unwrap();
            assert!(sys::open_data_at_nofollow(dir.as_fd(), OsStr::new("previous")).is_err());
        }
        assert!(f.acquire().is_err(), "unsafe case {case}");
        assert_eq!(fs::read(path.join("response")).unwrap(), original);
        fs::remove_file(&previous).unwrap();
    }
    for mode in [0o755, 0o770] {
        fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
        assert!(f.acquire().is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    }
}

// 이것을 실패시키는 것: response를 previous로 옮기기 전에 지우거나 stage를 완성본으로 보는 것.
#[test]
fn crash_between_response_rotations_preserves_a_complete_copy() {
    use std::os::unix::process::ExitStatusExt;
    for point in [
        "before_create",
        "before_write",
        "after_write",
        "after_check",
        "before_rotate",
        "after_rotate",
        "before_install",
        "after_install",
    ] {
        for existing in [false, true] {
            let f = Fixture::new("crash");
            if existing {
                f.publish(b"old");
            }
            let output = Command::new(std::env::current_exe().unwrap())
                .args(["--ignored", "--exact", "crash_child", "--nocapture"])
                .env("COLLECTION_CRASH_ROOT", &f.base)
                .env("COLLECTION_CRASH_POINT", point)
                .output()
                .unwrap();
            assert_eq!(
                output.status.signal(),
                Some(libc::SIGKILL),
                "child did not execute {point}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            let copies = ["response", "previous"]
                .iter()
                .filter_map(|name| fs::read(f.path().join(name)).ok())
                .map(|bytes| Completed::decode_with_catalog(&bytes, &SCHEMA).unwrap())
                .collect::<Vec<_>>();
            if existing {
                assert!(!copies.is_empty(), "lost both complete copies at {point}");
            }
            assert!(copies.iter().all(|c| c.binding == f.binding));
            let stage_count = fs::read_dir(f.path())
                .unwrap()
                .filter_map(Result::ok)
                .filter(|e| e.file_name() == ".response.stage")
                .count();
            assert!(stage_count <= 1);
            let mut recovered = f.acquire().unwrap();
            recovered
                .publish(&completed(&f.binding, b"recovered"))
                .unwrap();
            assert_eq!(
                f.read("response").updates[0].value,
                Some(Value::new(b"recovered", vec![]))
            );
        }
    }
}
#[test]
#[ignore = "the crash parent asserts SIGKILL at every publication checkpoint"]
#[allow(
    clippy::disallowed_methods,
    reason = "isolated test subprocess injection only"
)]
fn crash_child() {
    let base = PathBuf::from(std::env::var_os("COLLECTION_CRASH_ROOT").unwrap());
    let point = std::env::var("COLLECTION_CRASH_POINT").unwrap();
    let runtime = File::open(base).unwrap();
    let binding = binding(b"/cwd");
    let context = CheckedContextFd::under_runtime(
        &runtime,
        &binding.config,
        &binding.state,
        sys::current_uid(),
        false,
    )
    .unwrap();
    let mut store = CollectionStore::fixture(&context, &binding, clock(), &SCHEMA, None).unwrap();
    store
        .publish_with_hook(&completed(&binding, b"new"), &mut |at| {
            if at == point {
                // SAFETY: only this disposable test process is killed.
                let pid = unsafe { libc::getpid() };
                // SAFETY: pid is this disposable test process.
                assert_eq!(unsafe { libc::kill(pid, libc::SIGKILL) }, 0);
            }
        })
        .unwrap();
    panic!("crash checkpoint was not reached");
}

// 이것을 실패시키는 것: 해시 일치만으로 cwd를 인정하거나 mask/build를 잠금 주소에 더하는 것.
#[test]
fn hash_collision_never_reuses_or_overwrites_other_cwd() {
    let f = Fixture::new("collision");
    drop(f.acquire().unwrap());
    let mut collision = f.binding.clone();
    collision.cwd = b"/empty-collision".to_vec();
    assert!(matches!(
        CollectionStore::fixture(
            &f.context,
            &collision,
            clock(),
            &SCHEMA,
            Some(f.binding.components()[1].clone())
        ),
        Err(StoreError::Busy)
    ));
    f.publish(b"old");
    let original = fs::read(f.path().join("response")).unwrap();
    let mut other = f.binding.clone();
    other.cwd = b"/other".to_vec();
    assert!(matches!(
        CollectionStore::fixture(
            &f.context,
            &other,
            clock(),
            &SCHEMA,
            Some(f.binding.components()[1].clone())
        ),
        Err(StoreError::Busy)
    ));
    assert_eq!(fs::read(f.path().join("response")).unwrap(), original);
    let mut forged = completed(&f.binding, b"forged");
    forged.binding.cwd = b"/different-cwd".to_vec();
    fs::write(
        f.path().join("response"),
        forged.encode_with_catalog(&SCHEMA).unwrap(),
    )
    .unwrap();
    assert!(matches!(f.acquire(), Err(StoreError::Busy)));
    fs::write(f.path().join("response"), &original).unwrap();
    let held = f.acquire().unwrap();
    other = f.binding.clone();
    other.mask = 0;
    other.build_id = BuildId([9; 32]);
    assert!(matches!(
        CollectionStore::fixture(&f.context, &other, clock(), &SCHEMA, None),
        Err(StoreError::Busy)
    ));
    let mut roots = f.binding.clone();
    roots.state = b"/other-state".to_vec();
    roots.snapshot.context = snapshot::context_crc(&roots.config, &roots.state).unwrap();
    let context = CheckedContextFd::under_runtime(
        &f.runtime,
        &roots.config,
        &roots.state,
        sys::current_uid(),
        true,
    )
    .unwrap();
    let independent = CollectionStore::fixture(&context, &roots, clock(), &SCHEMA, None).unwrap();
    assert_ne!(
        held.worker_lock().unwrap().metadata().unwrap().ino(),
        independent.worker_lock().unwrap().metadata().unwrap().ino()
    );
}

// 이것을 실패시키는 것: 발행 뒤 helper 사본을 닫을 때 worker의 공유 잠금을 푸는 것.
#[test]
fn lock_is_held_until_publication_and_worker_exit() {
    let _serial = TEST_SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let output = Command::new(std::env::current_exe().unwrap())
        .args([
            "--ignored",
            "--exact",
            "lock_is_held_until_publication_and_worker_exit_child",
            "--test-threads=1",
            "--nocapture",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("test result: ok. 1 passed;"),
        "child must run exactly one test"
    );
    eprint!("{}", String::from_utf8_lossy(&output.stderr));
}
#[test]
#[ignore = "the parent asserts one actual passing child, isolated from unrelated fork descriptors"]
fn lock_is_held_until_publication_and_worker_exit_child() {
    let f = Fixture::new("lock");
    let mut store = f.acquire().unwrap();
    let worker = store.worker_lock().unwrap();
    // SAFETY: F_GETFL only observes the owned descriptor.
    assert_eq!(
        // SAFETY: F_GETFL observes the owned descriptor.
        unsafe { libc::fcntl(worker.as_raw_fd(), libc::F_GETFL) } & libc::O_ACCMODE,
        libc::O_RDONLY
    );
    assert!(matches!(f.acquire(), Err(StoreError::Busy)));
    store.publish(&completed(&f.binding, b"done")).unwrap();
    assert!(matches!(f.acquire(), Err(StoreError::Busy)));
    drop(store);
    assert!(matches!(f.acquire(), Err(StoreError::Busy)));
    drop(worker);
    assert!(f.acquire().is_ok());
    let mut samples = Vec::new();
    let mut gc_ops = 0;
    for sample in 0..200 {
        let started = std::time::Instant::now();
        let mut store = f.acquire().unwrap_or_else(|e| {
            let bytes = fs::read(f.base.join(".collections.catalog")).unwrap();
            panic!(
                "sample {sample}: {e:?}, catalog head {:?}",
                &bytes[..64.min(bytes.len())]
            );
        });
        store.publish(&completed(&f.binding, b"sample")).unwrap();
        drop(store);
        samples.push(started.elapsed().as_nanos());
        let report = f.gc(clock());
        if report.incomplete {
            eprintln!("sample {sample}: {report:?}");
        }
        gc_ops = gc_ops.max(report.ops);
    }
    samples.sort_unstable();
    let metadata = fs::metadata(f.path().join("response")).unwrap();
    eprintln!(
        "collection acquire/publish/close: samples=200 p50_ns={} p95_ns={} max_ns={} gc_ops_max={} response_logical_bytes={} response_physical_bytes={} store_file_inodes={}",
        samples[99],
        samples[189],
        samples[199],
        gc_ops,
        metadata.len(),
        metadata.blocks() * 512,
        fs::read_dir(f.path()).unwrap().count()
    );
}

// 이것을 실패시키는 것: helper teardown에 LOCK_UN을 넣는 것.
#[test]
fn helper_close_never_unlocks_live_worker() {
    let _serial = TEST_SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let output = Command::new(std::env::current_exe().unwrap())
        .args([
            "--ignored",
            "--exact",
            "helper_close_never_unlocks_live_worker_child",
            "--test-threads=1",
            "--nocapture",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("test result: ok. 1 passed;"),
        "child must run exactly one test"
    );
    eprint!("{}", String::from_utf8_lossy(&output.stderr));
}
#[test]
#[ignore = "the parent asserts one actual passing child, isolated from unrelated fork descriptors"]
fn helper_close_never_unlocks_live_worker_child() {
    let f = Fixture::new("helper-close");
    let store = f.acquire().unwrap();
    let worker = sys::PausedFork::new();
    drop(store);
    assert!(matches!(f.acquire(), Err(StoreError::Busy)));
    drop(worker);
    assert!(f.acquire().is_ok());
}

// 이것을 실패시키는 것: GC가 살아 있는 lock을 unlink하거나 등록 전에 GC 잠금을 놓는 것.
#[test]
fn gc_cannot_split_lock_inode_or_delete_inflight_store() {
    let f = Fixture::new("gc-lock");
    let mut observed = false;
    let admitted = CollectionStore::fixture_admission_hook(
        &f.context,
        &f.binding,
        clock(),
        &SCHEMA,
        &mut |point| {
            assert_eq!(point, "reserved_before_mkdir");
            assert!(matches!(
                commands::collection_store::close_only_lock(
                    &f.runtime,
                    ".collections.gc.lock",
                    sys::current_uid(),
                    false
                ),
                Err(StoreError::Busy)
            ));
            let racing_gc = f.gc(clock());
            assert!(racing_gc.incomplete);
            assert_eq!(racing_gc.visited, 0);
            assert!(!f.path().exists());
            observed = true;
        },
    )
    .unwrap();
    assert!(observed);
    drop(admitted);
    f.publish(b"safe");
    let store = f.acquire().unwrap();
    let worker = store.worker_lock().unwrap();
    let inode = worker.metadata().unwrap().ino();
    let mut later = clock();
    later.now += 86_400_000_000_001;
    let report = f.gc(later);
    assert_eq!(report.removed_files, 0);
    assert_eq!(report.removed_dirs, 0);
    assert_eq!(
        fs::metadata(f.path().join("collection.lock"))
            .unwrap()
            .ino(),
        inode
    );
    drop(store);
    assert_eq!(f.gc(later).removed_files, 0);
    drop(worker);
    let report = f.gc(later);
    assert!(report.removed_dirs > 0, "{report:?}");
    assert!(!f.path().exists());
    assert!(f.acquire().is_ok());
    for name in ["snapshot", "marker", "trust"] {
        fs::write(f.base.join(name), name).unwrap();
    }
    f.gc(later);
    for name in ["snapshot", "marker", "trust"] {
        assert_eq!(fs::read(f.base.join(name)).unwrap(), name.as_bytes());
    }
}

// 이것을 실패시키는 것: mkdir 전에 store/node/논리 bytes 상한을 검사하지 않는 것, cwd를 경로 조각으로 쓰는 것.
#[test]
fn store_capacity_is_reserved_before_mkdir() {
    for (stores, nodes, bytes) in [(128, 8_192, 10_000_000), (0, 0, 0)] {
        assert!(collection_gc::capacity(stores, nodes, bytes));
    }
    for (stores, nodes, bytes) in [
        (129, 8_192, 10_000_000),
        (128, 8_193, 10_000_000),
        (128, 8_192, 10_000_001),
    ] {
        assert!(!collection_gc::capacity(stores, nodes, bytes));
    }
    let f = Fixture::new("capacity");
    for length in [3_840, 3_841, 65_536] {
        let mut b = f.binding.clone();
        b.cwd = vec![0xff; length];
        b.cwd[0] = b'/';
        let mut store = CollectionStore::fixture(&f.context, &b, clock(), &SCHEMA, None).unwrap();
        assert_eq!(b.components().len(), 3);
        assert_eq!(b.components()[1].len(), 64);
        store.publish(&completed(&b, b"long")).unwrap();
        drop(store);
        f.gc(clock());
    }
    let mut too_long = f.binding.clone();
    too_long.cwd = vec![b'a'; 65_537];
    too_long.cwd[0] = b'/';
    assert!(CollectionStore::fixture(&f.context, &too_long, clock(), &SCHEMA, None).is_err());
    assert!(!f.path_for(&too_long).exists());
    drop(f);
    let f = Fixture::new("reservation-boundary");
    let mut held = Vec::new();
    for i in 0..20 {
        let mut b = f.binding.clone();
        b.cwd = format!("/held-{i}").into_bytes();
        match CollectionStore::fixture(&f.context, &b, clock(), &SCHEMA, None) {
            Ok(store) => held.push(store),
            Err(StoreError::Busy) => {
                assert!(!f.path_for(&b).exists());
                assert_eq!(
                    held.len(),
                    7,
                    "reserve two slots, stage, legacy request and both catalog copies"
                );
                return;
            }
            Err(e) => panic!("unexpected admission failure: {e:?}"),
        }
    }
    panic!("logical reservation did not cap admission");
}

// 이것을 실패시키는 것: 예산을 넘겨 디렉터리 전체를 읽거나 cursor를 버려 매번 처음부터 시작하는 것.
#[test]
fn gc_is_bounded_and_resumable() {
    let f = Fixture::new("bounded");
    for i in 0..8 {
        let mut b = f.binding.clone();
        b.cwd = format!("/cursor-{i}").into_bytes();
        let mut s = CollectionStore::fixture(&f.context, &b, clock(), &SCHEMA, None).unwrap();
        s.publish(&completed(&b, b"v")).unwrap();
        drop(s);
        f.gc(clock());
    }
    fs::write(f.base.join(".collections.catalog"), b"bad crc").unwrap();
    let mut complete = false;
    let mut incomplete = 0;
    let mut ops = 0;
    let mut visited = 0;
    for _ in 0..100 {
        let r = collection_gc::fixture_reclaim(
            &f.runtime,
            clock(),
            GcBudget {
                max_ops: 900,
                max_ns: 20_000_000,
            },
            &SCHEMA,
        )
        .unwrap();
        assert!(r.ops <= 900);
        ops += r.ops;
        visited += r.visited;
        if !r.incomplete {
            complete = true;
            break;
        }
        incomplete += 1;
    }
    assert!(
        incomplete > 0 && complete,
        "bounded cursor did not make progress"
    );
    eprintln!(
        "bounded inventory: stores_visited={visited} sweeps={} total_charged_operations={ops} per_sweep_limit=900",
        incomplete + 1
    );
    let r = collection_gc::fixture_reclaim(
        &f.runtime,
        clock(),
        GcBudget {
            max_ops: u32::MAX,
            max_ns: 0,
        },
        &SCHEMA,
    )
    .unwrap();
    assert!(r.incomplete);
    assert_eq!(r.ops, 0);
}

// 이것을 실패시키는 것: 손상 catalog의 외부 경로·..·symlink를 삭제 권한으로 쓰거나 재구성 중 admission을 허용하는 것.
#[test]
fn gc_catalog_damage_never_authorizes_arbitrary_deletion() {
    let f = Fixture::new("catalog");
    f.publish(b"old");
    let outside = f.base.join("outside");
    fs::create_dir(&outside).unwrap();
    fs::write(outside.join("sentinel"), b"keep").unwrap();
    let raw = fs::read(f.base.join(".collections.catalog")).unwrap();
    let mut outside_path = raw.clone();
    let at = outside_path
        .windows(14)
        .position(|b| b == b"2f636f6e666967")
        .unwrap();
    outside_path[at..at + 14].copy_from_slice(b"../outside/xxx");
    let crc = snapshot::crc32c(&[&outside_path[12..]]);
    outside_path[8..12].copy_from_slice(&crc);
    for damage in [
        outside_path,
        b"../outside".to_vec(),
        {
            let mut b = raw.clone();
            b[8] ^= 1;
            b
        },
        vec![0; 1_048_577],
    ] {
        fs::write(f.base.join(".collections.catalog"), damage).unwrap();
        assert!(f.acquire().is_err());
        if fs::metadata(f.base.join(".collections.catalog"))
            .unwrap()
            .len()
            == 1_048_577
        {
            assert!(
                commands::collection_store::read_checked(
                    &f.runtime,
                    ".collections.catalog",
                    collection_gc::CATALOG_MAX,
                    sys::current_uid()
                )
                .is_err()
            );
        }
        for _ in 0..5 {
            f.gc(clock());
        }
        if let Err(error) = f.acquire() {
            let bytes = fs::read(f.base.join(".collections.catalog")).unwrap();
            panic!(
                "damaged catalog must rebuild: {error:?}, head {:?}",
                &bytes[..64.min(bytes.len())]
            );
        }
        assert_eq!(fs::read(outside.join("sentinel")).unwrap(), b"keep");
        assert_eq!(
            f.read("response").updates[0].value,
            Some(Value::new(b"old", vec![]))
        );
        fs::write(f.base.join(".collections.catalog"), &raw).unwrap();
    }
    let parent = f.path().parent().unwrap().parent().unwrap().to_path_buf();
    symlink(&outside, parent.join("ab")).unwrap();
    fs::write(f.base.join(".collections.catalog"), b"damage").unwrap();
    let r = f.gc(clock());
    assert!(r.incomplete);
    assert!(f.acquire().is_err());
    assert_eq!(fs::read(outside.join("sentinel")).unwrap(), b"keep");
}

// 이것을 실패시키는 것: legacy 긴 사슬을 재귀 순회하거나 살아 있는 공유 prefix를 삭제하는 것.
#[cfg(target_os = "linux")]
#[test]
fn deep_cwd_gc_preserves_shared_prefix_and_live_lock() {
    // The checkout can be a host-shared mount even in a native Linux
    // container. Honor TMPDIR so this chain can live on a Linux filesystem
    // independently of CARGO_MANIFEST_DIR or CARGO_TARGET_DIR.
    let f = Fixture::new_in(std::env::temp_dir(), "bingsu-c2-legacy");
    f.publish(b"current");
    let collections = f.path().parent().unwrap().parent().unwrap().to_path_buf();
    let mut dir = File::open(&collections).unwrap();
    let mut cwd = vec![0xff; 65_536];
    cwd[0] = b'/';
    cwd[61] = 0x1b;
    assert_eq!(cwd.chunks(60).len(), 1_093);
    let mut sibling = None;
    for (i, chunk) in cwd.chunks(60).enumerate() {
        let name = chunk.iter().map(|b| format!("{b:02x}")).collect::<String>();
        assert_eq!(name.len(), chunk.len() * 2, "legacy chunk {i}");
        sys::mkdir_at(dir.as_fd(), OsStr::new(&name), 0o700).unwrap_or_else(|error| {
            // Path-based LSM checks can reject even a single-component *at
            // call. Keep the failure and report the active policy for reruns.
            eprintln!(
                "legacy mkdirat failure: index={i}, chunk_bytes={}, name_bytes={}, security_profile={:?}, apparmor_path_max={:?}",
                chunk.len(),
                name.len(),
                fs::read_to_string("/proc/thread-self/attr/current"),
                fs::read_to_string("/sys/module/apparmor/parameters/path_max"),
            );
            panic!(
                "legacy mkdirat: chunk={i}, name_bytes={}, root={}: {error}",
                name.len(),
                collections.display()
            )
        });
        dir = sys::open_dir_at_nofollow(dir.as_fd(), OsStr::new(&name)).unwrap_or_else(|error| {
            panic!(
                "legacy openat: chunk={i}, name_bytes={}, root={}: {error}",
                name.len(),
                collections.display()
            )
        });
        if i == 0 {
            // Another live legacy cwd shares the first 60 raw bytes.
            sys::mkdir_at(dir.as_fd(), OsStr::new("6c697665"), 0o700).unwrap();
            let branch = sys::open_dir_at_nofollow(dir.as_fd(), OsStr::new("6c697665")).unwrap();
            sys::mkdir_at(branch.as_fd(), OsStr::new("store"), 0o700).unwrap();
            let store = sys::open_dir_at_nofollow(branch.as_fd(), OsStr::new("store")).unwrap();
            let lock = commands::collection_store::close_only_lock(
                &store,
                "collection.lock",
                sys::current_uid(),
                true,
            )
            .unwrap();
            let ino = lock.metadata().unwrap().ino();
            sibling = Some((store, lock, ino));
        }
    }
    sys::mkdir_at(dir.as_fd(), OsStr::new("store"), 0o700).unwrap();
    let leaf = sys::open_dir_at_nofollow(dir.as_fd(), OsStr::new("store")).unwrap();
    let lock = commands::collection_store::close_only_lock(
        &leaf,
        "collection.lock",
        sys::current_uid(),
        true,
    )
    .unwrap();
    let before = lock.metadata().unwrap().ino();
    fs::write(
        f.base.join(".collections.catalog"),
        b"rebuild legacy inventory",
    )
    .unwrap();
    let mut max_ops = 0;
    for _ in 0..4 {
        let report = f.gc(clock());
        assert!(report.incomplete);
        assert!(report.ops <= 4_096);
        max_ops = max_ops.max(report.ops);
    }
    println!("legacy components=1093; bounded sweeps=4; max charged operations={max_ops}");
    assert!(f.acquire().is_err());
    assert_eq!(
        sys::at_stamp(leaf.as_fd(), OsStr::new("collection.lock"))
            .unwrap()
            .ino,
        before
    );
    let (sibling, sibling_lock, sibling_ino) = sibling.unwrap();
    assert_eq!(
        sys::at_stamp(sibling.as_fd(), OsStr::new("collection.lock"))
            .unwrap()
            .ino,
        sibling_ino
    );
    assert!(
        commands::collection_store::close_only_lock(
            &sibling,
            "collection.lock",
            sys::current_uid(),
            false
        )
        .is_err()
    );
    assert!(f.path().exists());
    // Empty chain cleanup uses dirfds, avoiding PATH_MAX even in the fixture.
    drop(lock);
    sys::unlink_at(leaf.as_fd(), OsStr::new("collection.lock")).unwrap();
    drop(leaf);
    sys::remove_dir_at(dir.as_fd(), OsStr::new("store")).unwrap();
    drop(dir);
    drop(sibling_lock);
    drop(sibling);
}

// 이것을 실패시키는 것: 빈 legacy 사슬의 bottom-up rmdir을 빼거나 살아 있는 형제·unknown을 함께 지우는 것.
#[test]
fn legacy_gc_prunes_only_empty_suffixes() {
    let f = Fixture::new("legacy-small");
    f.publish(b"modern");
    let modern = f.acquire().unwrap();
    let collections = f.path().parent().unwrap().parent().unwrap().to_path_buf();
    let prefix_raw = [b"/".as_slice(), &[b'x'; 59]].concat();
    let prefix_name = prefix_raw
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    let prefix = collections.join(&prefix_name);
    fs::create_dir(&prefix).unwrap();
    fs::set_permissions(&prefix, fs::Permissions::from_mode(0o700)).unwrap();
    let mut locks = Vec::new();
    let mut paths = Vec::new();
    for suffix in [b"\xffidle".as_slice(), b"\xfflive"] {
        let name = suffix
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        let path = prefix.join(&name).join("store");
        fs::create_dir_all(&path).unwrap();
        fs::set_permissions(path.parent().unwrap(), fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        let dir = File::open(&path).unwrap();
        let lock = commands::collection_store::close_only_lock(
            &dir,
            "collection.lock",
            sys::current_uid(),
            true,
        )
        .unwrap();
        let mut b = f.binding.clone();
        b.cwd = [prefix_raw.as_slice(), suffix].concat();
        let bytes = completed(&b, b"legacy")
            .encode_with_catalog(&SCHEMA)
            .unwrap();
        let data = sys::create_file_at(dir.as_fd(), OsStr::new("response"), 0o600).unwrap();
        assert_eq!(
            sys::write_fd(data.as_raw_fd(), &bytes),
            sys::WriteOutcome::Done
        );
        for name in [".response.stage", ".stage-request"] {
            let file = sys::create_file_at(dir.as_fd(), OsStr::new(name), 0o600).unwrap();
            assert_eq!(
                sys::write_fd(file.as_raw_fd(), b"partial"),
                sys::WriteOutcome::Done
            );
        }
        locks.push(lock);
        paths.push(path);
    }
    let idle = locks.remove(0);
    drop(idle);
    fs::write(prefix.join("unknown"), b"keep").unwrap();
    fs::write(f.base.join(".collections.catalog"), b"inventory").unwrap();
    let mut later = clock();
    later.now += 86_400_000_000_001;
    let mut removed_files = 0;
    let mut removed_dirs = 0;
    for _ in 0..12 {
        let report = f.gc(later);
        removed_files += report.removed_files;
        removed_dirs += report.removed_dirs;
    }
    eprintln!(
        "legacy eviction: sweeps=12 removed_files={removed_files} removed_dirs={removed_dirs}"
    );
    assert!(!paths[0].exists());
    assert!(!paths[0].parent().unwrap().exists());
    assert!(paths[1].join("response").exists());
    assert!(prefix.join("unknown").exists());
    assert_eq!(
        f.read("response").updates[0].value,
        Some(Value::new(b"modern", vec![]))
    );
    drop(modern);
    drop(locks);
}

fn peer() -> PathBuf {
    static PEER: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
    PEER.get_or_init(|| {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/c2-peer"); fs::create_dir_all(&dir).unwrap();
        let source = dir.join("peer.c"); let exe = dir.join("peer");
        fs::write(&source, r#"
#include <stdint.h>
#include <unistd.h>
#include <string.h>
static unsigned char h[80], b[65536];
static void exact(int fd, void *p, unsigned n) { while(n) { int k=read(fd,p,n); if(k<=0) _exit(31); p=(char*)p+k; n-=k; } }
static void put(const void *p, unsigned n) { while(n) { int k=write(1,p,n); if(k<=0) _exit(32); p=(char*)p+k; n-=k; } }
static void frame(unsigned kind, unsigned size) { memcpy(h,"BNGIPC02",8); h[8]=2; h[10]=kind; memcpy(h+12,&size,4); memset(h+16,7,32); put(h,80); if(size) put(b,size); }
int main(int argc, char **argv) {
  (void)argc; b[0]=3; b[11]=128; b[17]=16; frame(1,24);
  for(;;) { exact(3,h,80); unsigned n; memcpy(&n,h+12,4); if(n>65536) _exit(33); exact(3,b,n); if(h[10]==4) break; }
  memset(b,0,3); b[0]=31; frame(5,3);
  if(argv[1][0]=='c') frame(6,0);
  else if(argv[1][0]=='d') for(;;) pause();
  return 0;
}
"#).unwrap();
        assert!(Command::new("cc").args(["-O2", "-Wall", "-Werror", "-o"]).arg(&exe).arg(&source).status().unwrap().success());
        fs::canonicalize(exe).unwrap()
    }).clone()
}
// 이것을 실패시키는 것: C1의 검증된 Completed를 발행하지 않거나 부분 결과의 종료 사유·마지막 값을 버리는 것.
#[test]
fn supervisor_publishes_complete_and_partial_results() {
    use bingsu_core::collection::{selection::Catalog, wire::Request};
    for (mode, reason) in [
        ("complete", EndReason::Complete),
        ("partial", EndReason::Protocol),
        ("deadline", EndReason::Deadline),
    ] {
        let f = Fixture::new(mode);
        let mut store = f.acquire().unwrap();
        let request = bingsu_core::collection::request(
            &Catalog {
                segments: &SCHEMA,
                workers: 1 << 31,
            },
            f.binding.clone(),
            M3B_REQUEST_ID,
            50,
        )
        .unwrap()
        .unwrap();
        let _: &Request = &request;
        let watchdog = commands::helper_limits::start(std::time::Instant::now()).unwrap();
        // Spawn remains on this live thread; Linux PDEATHSIG refers to it.
        let job = commands::collector_supervisor::CollectorJob::fixture(
            peer().as_os_str(),
            OsStr::new(mode),
            request,
            store.worker_lock().unwrap(),
            &watchdog,
            &SCHEMA,
        )
        .unwrap();
        let handle = job
            .start(Box::new(move |result| store.publish(&result)))
            .unwrap();
        handle.confirm_confinement().unwrap();
        let report = handle.finish();
        assert!(report.published && report.reaped, "{report:?}");
        assert_eq!(report.reason, reason);
        let result = f.read("response");
        assert_eq!(result.reason, reason);
        assert_eq!(
            result.updates,
            vec![Update {
                segment: 31,
                value: None
            }]
        );
        let mut entry = clock();
        entry.now = result.completed_at_ns + 1;
        assert!(result.eligible(&f.binding, entry));
        entry.boot[0] ^= 1;
        assert!(!result.eligible(&f.binding, entry));
        assert!(f.acquire().is_ok());
    }
}

// 이것을 실패시키는 것: store 삭제 뒤 예산 종료 때 빈 사슬 cursor를 버리는 것.
#[test]
fn gc_resumes_empty_suffix_cleanup() {
    let f = Fixture::new("prune-cursor");
    f.publish(b"seed");
    let mut later = clock();
    later.now += 86_400_000_000_001;
    let parent = f.path().parent().unwrap().to_path_buf();
    let mut interrupted = false;
    for max_ops in (360..1_600).step_by(8) {
        let report = collection_gc::fixture_reclaim(
            &f.runtime,
            later,
            GcBudget {
                max_ops,
                max_ns: 20_000_000,
            },
            &SCHEMA,
        )
        .unwrap();
        assert!(report.ops <= max_ops);
        if report.removed_dirs > 0 {
            interrupted = parent.exists();
            break;
        }
    }
    assert!(
        interrupted,
        "the fixture must stop between store and address cleanup"
    );
    for _ in 0..8 {
        f.gc(later);
    }
    assert!(!parent.exists(), "the saved empty suffix must resume");
}

// 이것을 실패시키는 것: mkdir 뒤 lock 생성 전 사망한 빈 store·주소 사슬을 영구 보존하는 것.
#[test]
fn gc_recovers_an_unregistered_empty_store() {
    let f = Fixture::new("empty-registration");
    let path = f.path();
    fs::create_dir_all(&path).unwrap();
    let mut directory = path.as_path();
    for _ in 0..3 {
        fs::set_permissions(directory, fs::Permissions::from_mode(0o700)).unwrap();
        directory = directory.parent().unwrap();
    }
    fs::write(f.base.join(".collections.catalog"), b"lost reservation").unwrap();
    for _ in 0..8 {
        f.gc(clock());
    }
    assert!(!path.parent().unwrap().exists());
    assert!(f.acquire().is_ok());
}

// 이것을 실패시키는 것: tombstone rename 직전에 catalog 경로의 부모 정체를 다시 확인하지 않는 것.
#[test]
fn gc_rechecks_parent_identity_before_eviction() {
    let f = Fixture::new("gc-parent");
    f.publish(b"retained");
    let parent = f.path().parent().unwrap().to_path_buf();
    let displaced = f.base.join("displaced");
    let moved = displaced.clone();
    let ran = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let ran_hook = ran.clone();
    collection_gc::fixture_eviction_hook(Box::new(move || {
        fs::rename(&parent, &moved).unwrap();
        fs::create_dir(&parent).unwrap();
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o700)).unwrap();
        ran_hook.store(true, Ordering::SeqCst);
    }));
    let mut later = clock();
    later.now += 86_400_000_000_001;
    let report = f.gc(later);
    assert!(ran.load(Ordering::SeqCst));
    assert!(report.incomplete);
    assert_eq!(report.removed_files, 0);
    assert_eq!(report.removed_dirs, 0);
    let bytes = fs::read(displaced.join("store/response")).unwrap();
    assert_eq!(
        Completed::decode_with_catalog(&bytes, &SCHEMA).unwrap(),
        completed(&f.binding, b"retained")
    );
}

// 이것을 실패시키는 것: mkdir 전 예약 또는 attach 전 ino=0을 남긴 실패를 재구성하지 않는 것.
#[test]
fn gc_recovers_interrupted_registration() {
    for make_directories in [false, true] {
        let f = Fixture::new("interrupted-registration");
        let path = f.path();
        let aborted = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = CollectionStore::fixture_admission_hook(
                &f.context,
                &f.binding,
                clock(),
                &SCHEMA,
                &mut |_| {
                    if make_directories {
                        fs::create_dir_all(&path).unwrap();
                        let mut directory = path.as_path();
                        for _ in 0..3 {
                            fs::set_permissions(directory, fs::Permissions::from_mode(0o700))
                                .unwrap();
                            directory = directory.parent().unwrap();
                        }
                    }
                    panic!("interrupt before attaching a lock");
                },
            );
        }));
        assert!(aborted.is_err(), "the reservation hook must actually run");
        assert!(f.acquire().is_err());
        for _ in 0..8 {
            f.gc(clock());
        }
        assert!(f.acquire().is_ok(), "directories={make_directories}");
    }
}

// 이것을 실패시키는 것: rmdir 뒤 checkpoint 전 사망해서 사라진 prune 경로를 영구 재시도하는 것.
#[test]
fn gc_rebuilds_after_stale_prune_checkpoint() {
    let f = Fixture::new("stale-prune");
    f.publish(b"seed");
    let mut later = clock();
    later.now += 86_400_000_000_001;
    let parent = f.path().parent().unwrap().to_path_buf();
    let mut interrupted = false;
    for max_ops in (360..1_600).step_by(8) {
        let report = collection_gc::fixture_reclaim(
            &f.runtime,
            later,
            GcBudget {
                max_ops,
                max_ns: 20_000_000,
            },
            &SCHEMA,
        )
        .unwrap();
        if report.removed_dirs > 0 {
            interrupted = parent.exists();
            break;
        }
    }
    assert!(interrupted, "the fixture must retain a prune checkpoint");
    fs::remove_dir(&parent).unwrap();
    let mut finished = false;
    for _ in 0..8 {
        finished |= !f.gc(later).incomplete;
    }
    assert!(finished, "the stale prune path must not block every sweep");
    assert!(f.acquire().is_ok(), "stale accounting must be rebuilt");
}
