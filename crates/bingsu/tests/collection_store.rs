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

// Share the fork/spawn guard with all included command, prompt and sandbox
// tests: even pre-exec children can retain close-only collection/GC OFDs.
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
        path_query: Default::default(),
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
        progress: Default::default(),
        binding: binding.clone(),
        request_id: M3B_REQUEST_ID,
        completed_at_ns: 900,
        reason: EndReason::Complete,
        updates: vec![Update {
            facts: None,
            segment: 31,
            value: Some(Value::new(value, vec![])),
        }],
    }
}
struct Fixture {
    base: PathBuf,
    runtime: File,
    context: CheckedContextFd,
    binding: Binding,
    // Fields drop in declaration order: release the guard after every fd.
    _serial: std::sync::MutexGuard<'static, ()>,
}
impl Fixture {
    fn new(tag: &str) -> Self {
        Self::new_in(
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/c2-fixtures"),
            tag,
        )
    }
    fn new_in(root: PathBuf, tag: &str) -> Self {
        let serial = sys::test_inherited_fd_lock();
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
        collection_gc::fixture_reclaim(&self.context, now, GcBudget::default().max_ops, &SCHEMA)
            .unwrap()
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
        && limit.rlim_cur < limit.rlim_max.min(65_536)
    {
        limit.rlim_cur = limit.rlim_max.min(65_536);
        // SAFETY: as above.
        unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limit) };
    }
}

fn catalog_counts(f: &Fixture) -> (u64, u64, u64) {
    let raw = fs::read(f.base.join(".collections.catalog")).unwrap();
    let u = |offset| u64::from_le_bytes(raw[offset..offset + 8].try_into().unwrap());
    (u(28), u(36), u(44))
}
fn day(n: u64) -> Clock {
    Clock {
        now: 1_000 + n * 86_400_000_000_001,
        ..clock()
    }
}
fn directory_count(path: &std::path::Path) -> u64 {
    if !path.exists() {
        return 0;
    }
    1 + fs::read_dir(path)
        .unwrap()
        .map(|entry| {
            let path = entry.unwrap().path();
            if path.is_dir() {
                directory_count(&path)
            } else {
                0
            }
        })
        .sum::<u64>()
}

// 이것을 실패시키는 것: attach에서 실제 mkdir 수로 +3 예약을 정산하지 않는 것.
#[test]
fn probe_node_drift() {
    let f = Fixture::new("node-drift");
    let keep = f.acquire().unwrap();
    let collections = f.path().parent().unwrap().parent().unwrap().to_path_buf();
    for i in 0..40 {
        let b = binding(format!("/cycle-{i}").as_bytes());
        let mut store = CollectionStore::fixture(&f.context, &b, day(i), &SCHEMA, None).unwrap();
        store.publish(&completed(&b, b"value")).unwrap();
        assert_eq!(
            catalog_counts(&f).1,
            directory_count(&collections),
            "attach {i}"
        );
        drop(store);
        drop(CollectionStore::fixture(&f.context, &b, day(i), &SCHEMA, None).unwrap());
        assert_eq!(
            catalog_counts(&f).1,
            directory_count(&collections),
            "reattach {i}"
        );
        for _ in 0..4 {
            f.gc(day(i + 1));
        }
        assert!(!f.path_for(&b).exists());
        assert_eq!(
            catalog_counts(&f).1,
            directory_count(&collections),
            "reclaim {i}"
        );
    }
    drop(keep);
}

// 이것을 실패시키는 것: 공유 collections-v1 예약 1개를 매 수명마다 누적하는 것.
#[test]
fn probe_node_drift_lockout() {
    let f = Fixture::new("node-lockout");
    let keep = f.acquire().unwrap();
    for i in 0..8_200 {
        let b = binding(format!("/lifetime-{i}").as_bytes());
        drop(
            CollectionStore::fixture(&f.context, &b, day(i), &SCHEMA, None)
                .unwrap_or_else(|error| panic!("admission {i}: {error:?}")),
        );
        for _ in 0..4 {
            f.gc(day(i + 1));
            if !f.path_for(&b).exists() {
                break;
            }
        }
        assert!(!f.path_for(&b).exists(), "reclaim {i}");
    }
    drop(keep);
    for _ in 0..4 {
        f.gc(day(8_201));
    }
    let b = binding(b"/fresh-after-8200");
    assert!(CollectionStore::fixture(&f.context, &b, day(8_202), &SCHEMA, None).is_ok());
    assert_eq!(catalog_counts(&f).1, 3);
}

// 이것을 실패시키는 것: CLOEXEC를 fork 상속 방지로 오해하거나 close-only 잠금을 조기 해제하는 것.
#[test]
fn cloexec_fork_retains_collection_and_gc_locks_until_exit() {
    let f = Fixture::new("fork-cloexec");
    let store = f.acquire().unwrap();
    let worker_lock = store.worker_lock().unwrap();
    for file in [&f.runtime, &worker_lock] {
        // SAFETY: read-only flag query on a live fixture descriptor.
        let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFD) };
        assert!(flags >= 0 && flags & libc::FD_CLOEXEC != 0);
    }
    drop(worker_lock);
    let child = sys::PausedFork::new();
    drop(store);
    for _ in 0..4 {
        f.gc(day(1));
    }
    assert!(
        f.path().exists(),
        "pre-exec child still owns the collection lock"
    );
    assert!(matches!(f.acquire(), Err(StoreError::Busy)));
    drop(child);
    for _ in 0..4 {
        f.gc(day(1));
    }
    assert!(
        !f.path().exists(),
        "last inherited close permits reclamation"
    );

    let gc_lock = commands::collection_store::close_only_lock(
        &f.runtime,
        ".collections.gc.lock",
        sys::current_uid(),
        false,
    )
    .unwrap();
    // SAFETY: read-only query of the live GC lock descriptor.
    let flags = unsafe { libc::fcntl(gc_lock.as_raw_fd(), libc::F_GETFD) };
    assert!(flags >= 0 && flags & libc::FD_CLOEXEC != 0);
    let child = sys::PausedFork::new();
    drop(gc_lock);
    assert!(
        matches!(f.acquire(), Err(StoreError::Busy)),
        "inherited GC lock blocks admission"
    );
    drop(child);
    assert!(f.acquire().is_ok());
}

fn damage_response(path: &std::path::Path, kind: u8) {
    let mut bytes = fs::read(path).unwrap();
    match kind {
        0 => {
            let last = bytes.len() - 1;
            bytes[last] ^= 0xff;
        }
        1 => bytes.truncate(4),
        2 => bytes.push(0),
        _ => unreachable!(),
    }
    fs::write(path, bytes).unwrap();
}

// 이것을 실패시키는 것: lock 아래 내용만 손상된 response/previous를 Unsafe로 반환하는 것.
#[test]
fn publication_replaces_corrupt_response_and_previous() {
    for name in ["response", "previous"] {
        for kind in 0..3 {
            let f = Fixture::new("corrupt-acquire");
            f.publish(b"first");
            f.publish(b"second");
            damage_response(&f.path().join(name), kind);
            let mut store = f.acquire().expect("content damage must be absence");
            assert!(!f.path().join(name).exists());
            store.publish(&completed(&f.binding, b"recovered")).unwrap();
            assert_eq!(
                f.read("response").updates[0].value,
                Some(Value::new(b"recovered", vec![]))
            );
        }
    }
}

// 이것을 실패시키는 것: inspect/evict의 decode 실패를 중단 이유로 쓰거나 최근 손상 store를 남기는 것.
#[test]
fn probe_corrupt_response_wedges_gc() {
    for rebuild in [false, true] {
        for kind in 0..3 {
            let f = Fixture::new("corrupt-gc");
            let mut paths = vec![];
            for i in 0..3 {
                let b = binding(format!("/w-{i}").as_bytes());
                let mut store =
                    CollectionStore::fixture(&f.context, &b, clock(), &SCHEMA, None).unwrap();
                let mut response = completed(&b, b"value");
                response.completed_at_ns = 100 + i;
                store.publish(&response).unwrap();
                paths.push(f.path_for(&b));
            }
            damage_response(&paths[0].join("response"), kind);
            if rebuild {
                fs::write(f.base.join(".collections.catalog"), b"rebuild").unwrap();
            }
            for _ in 0..8 {
                f.gc(clock());
            }
            assert!(
                !paths[0].exists(),
                "recent corrupt store must be tombstoned"
            );
            assert!(paths[1].exists() && paths[2].exists());
            for _ in 0..8 {
                f.gc(day(5));
            }
            assert!(
                paths.iter().all(|path| !path.exists()),
                "later stores must still be reclaimed"
            );
            let b = binding(b"/w-0");
            CollectionStore::fixture(&f.context, &b, day(5), &SCHEMA, None)
                .unwrap()
                .publish(&completed(&b, b"again"))
                .unwrap();
            assert!(paths[0].join("response").exists());
        }
    }
}

// 이것을 실패시키는 것: inventory가 cwd를 못 읽은 손상 store를 acquire에서 영구 Busy로 만드는 것.
#[test]
fn publication_recovers_corrupt_store_after_inventory() {
    let f = Fixture::new("corrupt-inventory");
    f.publish(b"value");
    damage_response(&f.path().join("response"), 0);
    fs::write(f.base.join(".collections.catalog"), b"rebuild").unwrap();
    for _ in 0..8 {
        if !f.gc(clock()).incomplete {
            break;
        }
    }
    f.publish(b"recovered");
    assert_eq!(
        f.read("response").updates[0].value,
        Some(Value::new(b"recovered", vec![]))
    );
}

// 이것을 실패시키는 것: runtime catalog 부재 뒤 lock을 열거나 catalog/lock을 만드는 것.
#[test]
fn gc_absent_catalog_only_attempts_one_open() {
    let f = Fixture::new("absent");
    for _ in 0..3 {
        let report = f.gc(clock());
        assert!(!report.incomplete);
        // open_at conservatively charges open + eventual close even on ENOENT.
        assert_eq!(report.ops, 2);
        assert_eq!(
            report.visited + report.removed_files + report.removed_dirs,
            0
        );
        for name in [
            ".collections.catalog",
            ".collections.catalog.stage",
            ".collections.gc.lock",
        ] {
            assert!(!f.base.join(name).exists(), "unexpected {name}");
        }
    }
    f.publish(b"first admission initializes the catalog");
    assert!(f.base.join(".collections.catalog").exists());
}

struct DeepChain {
    dirs: Vec<File>,
    names: Vec<String>,
}
impl DeepChain {
    fn new(f: &Fixture) -> Self {
        raise_nofile_soft_limit();
        let collections = f.path().parent().unwrap().parent().unwrap().to_path_buf();
        let mut chain = Self {
            dirs: vec![File::open(collections).unwrap()],
            names: vec![],
        };
        // 180 components exceed the old ~151-level stall. Linux exercises
        // full legacy chunks; macOS sandbox path checks require short names.
        // Both use the traversed hex namespace; the Linux-only fixture below
        // also exercises all 1,093 canonical chunks with live locks.
        let mut cwd = vec![0xff; 60 * 180];
        cwd[0] = b'/';
        for chunk in cwd.chunks(60) {
            #[cfg(not(target_os = "linux"))]
            let chunk = &chunk[..1];
            let name = chunk.iter().map(|b| format!("{b:02x}")).collect::<String>();
            let parent = chain.dirs.last().unwrap();
            sys::mkdir_at(parent.as_fd(), OsStr::new(&name), 0o700).unwrap();
            let dir = sys::open_dir_at_nofollow(parent.as_fd(), OsStr::new(&name)).unwrap();
            chain.dirs.push(dir);
            chain.names.push(name);
        }
        chain
    }
}
impl Drop for DeepChain {
    fn drop(&mut self) {
        while let Some(name) = self.names.pop() {
            self.dirs.pop();
            let _ = sys::remove_dir_at(self.dirs.last().unwrap().as_fd(), OsStr::new(&name));
        }
    }
}
fn rebuild_deep_inventory(f: &Fixture) {
    fs::write(f.base.join(".collections.catalog"), b"rebuild").unwrap();
    let mut skipped = 0;
    for _ in 0..32 {
        let report = f.gc(clock());
        assert!(report.ops <= 4_096);
        skipped += report.skipped;
        if !report.incomplete {
            assert_eq!(
                skipped, 1,
                "one unfinished subtree must be skipped exactly once"
            );
            return;
        }
    }
    panic!("deep inventory never completed or skipped its unfinished subtree");
}

// 이것을 실패시키는 것: 한 회차에 재검증할 수 없는 깊은 cursor를 계속 저장하는 것.
#[test]
fn probe_deep_chain_ever_completes() {
    let f = Fixture::new("deep-skip");
    f.publish(b"current");
    let _chain = DeepChain::new(&f);
    rebuild_deep_inventory(&f);
    let counts = catalog_counts(&f);
    assert_eq!(counts.0, 2, "one known store and one unknown occupation");
    // Shared collections-v1, modern hash/store, 1,093 legacy chunks + store.
    assert_eq!(counts.1, 1 + 2 + 1_093 + 1);
    assert_eq!(
        counts.2,
        collection_gc::RESERVATION + fs::metadata(f.path().join("response")).unwrap().len()
    );
    for _ in 0..4 {
        assert!(!f.gc(clock()).incomplete);
        assert_eq!(
            catalog_counts(&f),
            counts,
            "unknown must not accumulate each sweep"
        );
    }
    assert!(f.acquire().is_ok());
}

// 이것을 실패시키는 것: unknown 하나로 runtime 전체 admission을 막거나 unknown bytes를 무시하는 것.
#[test]
fn gc_deep_chain_allows_other_cwd_until_real_budget_is_full() {
    let f = Fixture::new("deep-admission");
    f.publish(b"current");
    let _chain = DeepChain::new(&f);
    rebuild_deep_inventory(&f);
    let before = catalog_counts(&f);
    // Use another context as well as another cwd in the same runtime.
    let mut b = binding(b"/other-cwd");
    b.config = b"/other-config".to_vec();
    b.snapshot.context = snapshot::context_crc(&b.config, &b.state).unwrap();
    let context =
        CheckedContextFd::under_runtime(&f.runtime, &b.config, &b.state, sys::current_uid(), true)
            .unwrap();
    let mut held = vec![];
    for i in 0..16 {
        b.cwd = format!("/other-cwd-{i}").into_bytes();
        let expected =
            before.2 + (i + 1) * collection_gc::RESERVATION + 2 * collection_gc::CATALOG_MAX as u64;
        let acquired = CollectionStore::fixture(&context, &b, clock(), &SCHEMA, None);
        if expected > collection_gc::MAX_BYTES {
            assert!(matches!(acquired, Err(StoreError::Busy)));
            assert!(!f.path_for(&b).exists(), "budget rejection precedes mkdir");
            assert!(
                !held.is_empty(),
                "deep context must leave admission capacity"
            );
            return;
        }
        let mut store = acquired.expect("another context must use the remaining budget");
        store.publish(&completed(&b, b"other context")).unwrap();
        held.push(store);
    }
    panic!("unknown occupation was not charged against the byte budget");
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

// 이것을 실패시키는 것: 응답 파일의 nofollow·0600·nlink·크기 상한 판정을 빼는 것.
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
        if matches!(case, 4 | 6) {
            assert!(f.acquire().is_ok(), "content damage is absence: {case}");
            assert!(!previous.exists());
        } else {
            assert!(f.acquire().is_err(), "unsafe case {case}");
        }
        assert_eq!(fs::read(path.join("response")).unwrap(), original);
        if previous.exists() || previous.is_symlink() {
            fs::remove_file(&previous).unwrap();
        }
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
    let _serial = sys::test_inherited_fd_lock();
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
    let _serial = sys::test_inherited_fd_lock();
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
            // The catalog already exists before mkdir, so runtime-wide GC
            // attempts the global lock and must stop at the admission owner.
            assert!(racing_gc.incomplete);
            assert_eq!(racing_gc.removed_dirs, 0);
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
        let r = collection_gc::fixture_reclaim(&f.context, clock(), 1_200, &SCHEMA).unwrap();
        assert!(r.ops <= 1_200);
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
        "bounded inventory: stores_visited={visited} sweeps={} total_charged_operations={ops} per_sweep_limit=1_200",
        incomplete + 1
    );
}

// 이것을 실패시키는 것: 제품 GC의 시간 제한까지 fixture의 연산 전용 예산으로 바꾸는 것.
#[test]
fn gc_time_cap_stops_before_filesystem_work() {
    let f = Fixture::new("time-cap");
    f.publish(b"keep");
    let before = fs::read(f.base.join(".collections.catalog")).unwrap();
    let r = collection_gc::reclaim(
        &f.runtime,
        clock(),
        GcBudget {
            max_ops: u32::MAX,
            max_ns: 0,
        },
    )
    .unwrap();
    assert!(r.incomplete);
    assert_eq!(r.ops, 0);
    assert_eq!(
        fs::read(f.base.join(".collections.catalog")).unwrap(),
        before
    );
    assert!(f.path().join("response").exists());
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
    let mut skipped = 0;
    let mut complete = false;
    for _ in 0..32 {
        let report = f.gc(clock());
        assert!(report.ops <= 4_096);
        skipped += report.skipped;
        if !report.incomplete {
            complete = true;
            break;
        }
    }
    assert!(
        complete && skipped == 1,
        "deep inventory must finish by skipping one subtree"
    );
    assert!(f.acquire().is_ok());
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
#include <fcntl.h>
static unsigned char h[80], b[65536];
static void exact(int fd, void *p, unsigned n) { while(n) { int k=read(fd,p,n); if(k<=0) _exit(31); p=(char*)p+k; n-=k; } }
static void put(const void *p, unsigned n) { while(n) { int k=write(1,p,n); if(k<=0) _exit(32); p=(char*)p+k; n-=k; } }
static void frame(unsigned kind, unsigned size) { memcpy(h,"BNGIPC03",8); h[8]=3; h[10]=kind; memcpy(h+12,&size,4); memset(h+16,7,32); put(h,80); if(size) put(b,size); }
int main(int argc, char **argv) {
  /* Only the spawn dup2 action makes the CLOEXEC source available as fd 5. */
  if (fcntl(5, F_GETFD) != 0 || (fcntl(5, F_GETFL) & O_ACCMODE) != O_RDONLY) _exit(34);
  (void)argc; b[0]=3; b[11]=128; b[17]=16; frame(1,24);
  for(;;) { exact(3,h,80); unsigned n; memcpy(&n,h+12,4); if(n>65536) _exit(33); exact(3,b,n); if(h[10]==4) break; }
  memset(b,0,4); b[0]=31; frame(5,4);
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
                facts: None,
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

// 이것을 실패시키는 것: 호출되지 않은 publisher가 store 잠금을 가진 채 lock_closed를 먼저 찍는 것.
#[test]
fn lock_clock_includes_store_close_without_publication() {
    use std::sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    };
    struct PublisherStore {
        store: Option<CollectionStore>,
        closed: Arc<AtomicU64>,
    }
    impl PublisherStore {
        fn publish(
            &mut self,
            result: &Completed,
        ) -> Result<(), commands::snapshot_store::StoreError> {
            self.store.as_mut().unwrap().publish(result)
        }
    }
    impl Drop for PublisherStore {
        fn drop(&mut self) {
            drop(self.store.take());
            self.closed.store(
                commands::collector_process::now_ns().unwrap(),
                Ordering::Release,
            );
        }
    }
    for confined in [true, false] {
        let f = Fixture::new(if confined {
            "clock-publish"
        } else {
            "clock-no-publish"
        });
        let store = f.acquire().unwrap();
        let acquired = store.lock_acquired;
        let renamed = store.response_renamed.clone();
        let request = bingsu_core::collection::request(
            &bingsu_core::collection::selection::Catalog {
                segments: &SCHEMA,
                workers: 1 << 31,
            },
            f.binding.clone(),
            M3B_REQUEST_ID,
            50,
        )
        .unwrap()
        .unwrap();
        let watchdog = commands::helper_limits::start(std::time::Instant::now()).unwrap();
        let job = commands::collector_supervisor::CollectorJob::fixture(
            peer().as_os_str(),
            OsStr::new("complete"),
            request,
            store.worker_lock().unwrap(),
            &watchdog,
            &SCHEMA,
        )
        .unwrap()
        .observations(None, None, acquired, renamed);
        let closed = Arc::new(AtomicU64::new(0));
        let mut publisher = PublisherStore {
            store: Some(store),
            closed: closed.clone(),
        };
        let handle = job
            .start(Box::new(move |result| publisher.publish(&result)))
            .unwrap();
        if confined {
            handle.confirm_confinement().unwrap();
        }
        let report = handle.finish();
        assert_eq!(report.published, confined, "{report:?}");
        let actual = closed.load(Ordering::Acquire);
        assert!(actual > 0, "store was not closed");
        assert!(
            report
                .lifecycle
                .lock_closed
                .is_some_and(|stamp| stamp >= actual),
            "{report:?}; actual store close={actual}"
        );
        assert!(
            f.acquire().is_ok(),
            "finished helper still holds the store lock"
        );
    }
}

// 이것을 실패시키는 것: store 삭제 뒤 예산 종료 때 빈 사슬 cursor를 버리는 것.
#[test]
fn gc_resumes_empty_suffix_cleanup() {
    let (f, parent, later) = interrupted_prune_fixture("prune-cursor");
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
    fs::set_permissions(
        f.base.join(".collections.catalog"),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
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
    let report = collection_gc::fixture_reclaim(&f.context, later, 4_096, &SCHEMA);
    assert!(ran.load(Ordering::SeqCst));
    assert!(matches!(report, Err(StoreError::Unsafe)));
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
        // With an absent namespace GC intentionally does no work. Admission
        // recovers a pre-mkdir reservation lazily under the same global lock.
        for _ in 0..8 {
            f.gc(clock());
        }
        assert!(f.acquire().is_ok(), "directories={make_directories}");
    }
}

// 이것을 실패시키는 것: rmdir 뒤 checkpoint 전 사망해서 사라진 prune 경로를 영구 재시도하는 것.
#[test]
fn gc_rebuilds_after_stale_prune_checkpoint() {
    let (f, parent, later) = interrupted_prune_fixture("stale-prune");
    fs::remove_dir(&parent).unwrap();
    let mut finished = false;
    for _ in 0..8 {
        finished |= !f.gc(later).incomplete;
    }
    assert!(finished, "the stale prune path must not block every sweep");
    assert!(f.acquire().is_ok(), "stale accounting must be rebuilt");
}

// 이것을 실패시키는 것: 내용 손상 복구가 metadata/decoded binding 위반까지 허용하는 것.
#[test]
fn gc_still_stops_on_response_metadata_and_identity_violations() {
    for wrong_identity in [false, true] {
        let f = Fixture::new("corrupt-unsafe");
        f.publish(b"keep");
        let response = f.path().join("response");
        if wrong_identity {
            let other = completed(&binding(b"/other"), b"keep")
                .encode_with_catalog(&SCHEMA)
                .unwrap();
            fs::write(&response, other).unwrap();
        } else {
            damage_response(&response, 0);
            fs::set_permissions(&response, fs::Permissions::from_mode(0o644)).unwrap();
        }
        assert!(f.acquire().is_err());
        let bytes = fs::read(&response).unwrap();
        for _ in 0..3 {
            let report = collection_gc::fixture_reclaim(&f.context, day(5), 4_096, &SCHEMA);
            assert!(matches!(report, Err(StoreError::Unsafe)));
            assert_eq!(fs::read(&response).unwrap(), bytes);
        }
    }
}

// 이것을 실패시키는 것: 재개 가능한 깊이를 넘어 cursor를 저장하거나 unknown 점유를 누락하는 것.
#[test]
fn gc_deep_inventory_progress_and_admission_portable() {
    let f = Fixture::new("deep-portable");
    f.publish(b"current");
    let _chain = portable_deep_chain(&f);
    let collections = f.path().parent().unwrap().parent().unwrap().to_path_buf();
    rebuild_deep_inventory(&f);
    let counts = catalog_counts(&f);
    assert!(
        counts.1 >= directory_count(&collections),
        "unknown nodes must cover the chain"
    );
    assert!(
        counts.2 >= collection_gc::RESERVATION,
        "unknown files must stay reserved"
    );
    for _ in 0..3 {
        assert!(!f.gc(clock()).incomplete);
        assert_eq!(
            catalog_counts(&f),
            counts,
            "unknown charge must stay stable"
        );
    }
    let b = binding(b"/other-cwd");
    let mut store = CollectionStore::fixture(&f.context, &b, clock(), &SCHEMA, None).unwrap();
    store.publish(&completed(&b, b"same context")).unwrap();
    drop(store);
    let mut b = binding(b"/other-context-cwd");
    b.config = b"/other-config".to_vec();
    b.snapshot.context = snapshot::context_crc(&b.config, &b.state).unwrap();
    let context =
        CheckedContextFd::under_runtime(&f.runtime, &b.config, &b.state, sys::current_uid(), true)
            .unwrap();
    let before = catalog_counts(&f);
    let mut held = vec![];
    for i in 0..16 {
        b.cwd = format!("/other-{i}").into_bytes();
        let expected =
            before.2 + (i + 1) * collection_gc::RESERVATION + 2 * collection_gc::CATALOG_MAX as u64;
        let acquired = CollectionStore::fixture(&context, &b, clock(), &SCHEMA, None);
        if expected > collection_gc::MAX_BYTES {
            assert!(matches!(acquired, Err(StoreError::Busy)));
            assert!(!f.path_for(&b).exists());
            assert!(!held.is_empty());
            return;
        }
        let mut store = acquired.expect("another context must use the remaining budget");
        store.publish(&completed(&b, b"other context")).unwrap();
        held.push(store);
    }
    panic!("unknown occupation must consume the byte budget");
}

fn portable_deep_chain(f: &Fixture) -> DeepChain {
    raise_nofile_soft_limit();
    let collections = f.path().parent().unwrap().parent().unwrap().to_path_buf();
    let mut chain = DeepChain {
        dirs: vec![File::open(&collections).unwrap()],
        names: vec![],
    };
    // The traversal grammar permits hex prefixes. Short names exercise the
    // same >151 ancestor replay on macOS without its full-path creation limit;
    // the Linux tests above also exercise canonical 120-byte legacy chunks.
    for _ in 0..192 {
        let parent = chain.dirs.last().unwrap();
        sys::mkdir_at(parent.as_fd(), OsStr::new("aa"), 0o700).unwrap();
        chain
            .dirs
            .push(sys::open_dir_at_nofollow(parent.as_fd(), OsStr::new("aa")).unwrap());
        chain.names.push("aa".into());
    }
    chain
}

// 이것을 실패시키는 것: 작은 회차 예산에서도 default의 고정 깊이까지 cursor를 저장하는 것.
#[test]
fn gc_deep_inventory_respects_smaller_sweep_budget() {
    let f = Fixture::new("deep-small-budget");
    f.publish(b"current");
    let _chain = portable_deep_chain(&f);
    fs::write(f.base.join(".collections.catalog"), b"rebuild").unwrap();
    let mut skipped = 0;
    for _ in 0..64 {
        let report = collection_gc::fixture_reclaim(&f.context, clock(), 1_200, &SCHEMA).unwrap();
        assert!(report.ops <= 1_200);
        skipped += report.skipped;
        if !report.incomplete {
            assert_eq!(skipped, 1);
            assert!(catalog_counts(&f).1 >= 195);
            assert!(f.acquire().is_ok());
            return;
        }
    }
    panic!("a smaller sweep budget must also skip the deep subtree");
}

// 이것을 실패시키는 것: 작은 예산에서 정상 hash store의 얕은 context를 unknown으로 영구 건너뛰는 것.
#[test]
fn gc_small_budget_keeps_shallow_store_reachable() {
    let f = Fixture::new("small-budget-shallow");
    f.publish(b"current");
    fs::write(f.base.join(".collections.catalog"), b"rebuild").unwrap();
    for max_ops in (600..1_600).step_by(100) {
        let report = collection_gc::fixture_reclaim(&f.context, clock(), max_ops, &SCHEMA).unwrap();
        assert_eq!(
            report.skipped, 0,
            "a shallow store is resumable at budget {max_ops}"
        );
        assert!(report.ops <= max_ops);
    }
    assert_eq!(catalog_counts(&f).0, 1);
    assert_eq!(catalog_counts(&f).1, 3);
    assert!(f.acquire().is_ok());
}

fn interrupted_prune_fixture(tag: &str) -> (Fixture, PathBuf, Clock) {
    // Each budget starts from the same filesystem state. Reusing the prior
    // attempt can finish file removal and skip the intended directory boundary
    // on the next sweep, depending on the cost of response validation.
    for max_ops in (360..1_600).step_by(8) {
        let f = Fixture::new(tag);
        f.publish(b"seed");
        let later = day(1);
        let parent = f.path().parent().unwrap().to_path_buf();
        let report = collection_gc::fixture_reclaim(&f.context, later, max_ops, &SCHEMA).unwrap();
        assert!(report.ops <= max_ops);
        if report.removed_dirs > 0 && parent.exists() {
            return (f, parent, later);
        }
    }
    panic!("the fixture must stop between store and address cleanup");
}

// Reviewer probe: deep admissions must not collapse into one unknown occupation
// after rebuilding the catalog. Removing reserve's depth check kills this test.
#[test]
fn review_deep_context_undercount() {
    let f = Fixture::new("review-deep");
    f.publish(b"first");
    let mut deep = binding(b"/d");
    deep.config = b"/".to_vec();
    deep.config.extend(std::iter::repeat_n(b'a', 2_700));
    deep.snapshot.context = snapshot::context_crc(&deep.config, &deep.state).unwrap();
    let ctx = CheckedContextFd::under_runtime(
        &f.runtime,
        &deep.config,
        &deep.state,
        sys::current_uid(),
        true,
    )
    .unwrap();
    let gc = |context: &CheckedContextFd, now| {
        collection_gc::fixture_reclaim(context, now, 4_096, &SCHEMA).unwrap()
    };
    let mut admitted = 0;
    for i in 0..120 {
        deep.cwd = format!("/deep-{i}").into_bytes();
        match CollectionStore::fixture(&ctx, &deep, clock(), &SCHEMA, None) {
            Ok(mut store) => {
                store.publish(&completed(&deep, b"v")).unwrap();
                admitted += 1;
            }
            Err(StoreError::Busy) => break,
            Err(error) => panic!("unexpected deep admission error: {error:?}"),
        }
        for _ in 0..3 {
            gc(&ctx, clock());
        }
    }
    assert_eq!(
        admitted, 0,
        "stores beyond the inventory depth must be refused"
    );
    let context_dir = commands::snapshot_store::context_dir_for_test(&ctx);
    assert!(
        sys::open_dir_at_nofollow(context_dir.as_fd(), OsStr::new("collections-v1"))
            .is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound),
        "refusal must precede the first collection mkdir"
    );
    fs::write(f.base.join(".collections.catalog"), b"rebuild").unwrap();
    let mut skipped = 0;
    let mut rebuilt = false;
    for _ in 0..64 {
        let report = gc(&ctx, clock());
        assert!(report.ops <= 4_096);
        skipped += report.skipped;
        if !report.incomplete {
            rebuilt = true;
            break;
        }
    }
    assert!(rebuilt, "catalog rebuild must finish");
    assert_eq!(skipped, 1, "the deep context itself is unknown occupation");
    let deep_real = || {
        (0..120)
            .filter(|i| {
                let mut b = deep.clone();
                b.cwd = format!("/deep-{i}").into_bytes();
                let mut dir = commands::snapshot_store::context_dir_for_test(&ctx);
                for name in b.components() {
                    match sys::open_dir_at_nofollow(dir.as_fd(), OsStr::new(&name)) {
                        Ok(child) => dir = child,
                        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return false,
                        Err(error) => panic!("store census failed: {error:?}"),
                    }
                }
                true
            })
            .count() as u64
    };
    assert_eq!(deep_real(), 0);
    // Retain locks so pressure cannot evict these new stores and conceal an
    // over-admission. The unknown reservation must still consume capacity.
    let before = catalog_counts(&f);
    let mut held = vec![];
    let mut refused = false;
    for i in 0..200 {
        let mut b = f.binding.clone();
        b.cwd = format!("/n-{i}").into_bytes();
        match CollectionStore::fixture(&f.context, &b, clock(), &SCHEMA, None) {
            Ok(mut store) => {
                store.publish(&completed(&b, b"v")).unwrap();
                held.push(store);
            }
            Err(StoreError::Busy) => {
                assert!(!f.path_for(&b).exists());
                refused = true;
                break;
            }
            Err(error) => panic!("unexpected shallow admission error: {error:?}"),
        }
        let counts = catalog_counts(&f);
        assert_eq!(counts.0, before.0 + held.len() as u64);
        assert_eq!(
            counts.2,
            before.2 + held.len() as u64 * collection_gc::RESERVATION
        );
        assert!(collection_gc::capacity(
            counts.0,
            counts.1,
            counts.2 + 2 * collection_gc::CATALOG_MAX as u64
        ));
    }
    assert!(refused && !held.is_empty());
    assert!(1 + held.len() as u64 + deep_real() <= collection_gc::MAX_STORES);
    let counts = catalog_counts(&f);
    assert!(
        counts.2 + collection_gc::RESERVATION + 2 * collection_gc::CATALOG_MAX as u64
            > collection_gc::MAX_BYTES
    );
    for _ in 0..10 {
        gc(&ctx, day(3));
    }
    assert_eq!(deep_real(), 0);
    assert!(matches!(
        CollectionStore::fixture(&ctx, &deep, day(3), &SCHEMA, None),
        Err(StoreError::Busy)
    ));
}

// Reviewer probe: Y must reclaim X's stale stores even before Y has a
// collections-v1 directory. Gating on Y's namespace kills this test.
#[test]
fn review_cross_context_starvation() {
    let f = Fixture::new("review-starve");
    let mut paths = vec![];
    let mut refused = false;
    for i in 0..200 {
        let mut b = f.binding.clone();
        b.cwd = format!("/x-{i}").into_bytes();
        match CollectionStore::fixture(&f.context, &b, clock(), &SCHEMA, None) {
            Ok(mut store) => {
                store.publish(&completed(&b, b"v")).unwrap();
                paths.push(f.path_for(&b));
            }
            Err(StoreError::Busy) => {
                refused = true;
                break;
            }
            Err(error) => panic!("unexpected X admission error: {error:?}"),
        }
    }
    assert!(refused && !paths.is_empty());
    let mut y = binding(b"/y");
    y.config = b"/other-config".to_vec();
    y.snapshot.context = snapshot::context_crc(&y.config, &y.state).unwrap();
    let ycx =
        CheckedContextFd::under_runtime(&f.runtime, &y.config, &y.state, sys::current_uid(), true)
            .unwrap();
    assert!(matches!(
        CollectionStore::fixture(&ycx, &y, day(3), &SCHEMA, None),
        Err(StoreError::Busy)
    ));
    let collections = f
        .path_for(&y)
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf();
    assert!(!collections.exists());
    let mut removed = 0;
    for _ in 0..5 {
        let report = collection_gc::fixture_reclaim(&ycx, day(3), 4_096, &SCHEMA).unwrap();
        assert!(report.ops <= 4_096);
        removed += report.removed_dirs;
    }
    assert!(removed > 0, "GC from Y must reclaim X's stale stores");
    assert!(paths.iter().all(|path| !path.exists()));
    assert!(!collections.exists(), "GC must not create Y's namespace");
    let mut store = CollectionStore::fixture(&ycx, &y, day(3), &SCHEMA, None)
        .expect("Y must be admitted after reclaiming X's stale stores");
    store.publish(&completed(&y, b"Y admitted")).unwrap();
    assert!(f.path_for(&y).join("response").exists());
}

// 이것을 실패시키는 것: 깊이 제한의 >=를 >로 바꾸거나 경계 바로 아래도 거부하는 것.
#[test]
fn reserve_depth_boundary_matches_inventory() {
    for (config_len, depth, allowed) in [(2_340, 47, true), (2_341, 48, false), (2_401, 49, false)]
    {
        let f = Fixture::new("reserve-depth-boundary");
        f.publish(b"initialize catalog before adding the deep context");
        let mut b = binding(b"/boundary");
        b.config = vec![b'a'; config_len];
        b.config[0] = b'/';
        b.snapshot.context = snapshot::context_crc(&b.config, &b.state).unwrap();
        assert_eq!(
            snapshot::context_components(&b.config, &b.state)
                .unwrap()
                .len()
                + b.components().len(),
            depth
        );
        let context = CheckedContextFd::under_runtime(
            &f.runtime,
            &b.config,
            &b.state,
            sys::current_uid(),
            true,
        )
        .unwrap();
        let before = fs::read(f.base.join(".collections.catalog")).unwrap();
        let acquired = CollectionStore::fixture(&context, &b, clock(), &SCHEMA, None);
        if allowed {
            acquired.expect("a store just below the inventory depth must be admitted");
        } else {
            assert!(matches!(acquired, Err(StoreError::Busy)));
            assert_eq!(
                fs::read(f.base.join(".collections.catalog")).unwrap(),
                before
            );
            let dir = commands::snapshot_store::context_dir_for_test(&context);
            assert!(
                sys::open_dir_at_nofollow(dir.as_fd(), OsStr::new("collections-v1"))
                    .is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound)
            );
        }
    }
}

thread_local! {
    static GC_CLOCK: std::cell::Cell<(u64, u64)> = const { std::cell::Cell::new((0, 0)) };
}
fn gc_tick() -> u64 {
    GC_CLOCK.with(|clock| {
        let (now, step) = clock.get();
        clock.set((now + step, step));
        now
    })
}
fn seed_inventory(f: &Fixture, stores: usize) {
    for i in 0..stores {
        let b = binding(format!("/inventory-{i}").as_bytes());
        CollectionStore::fixture(&f.context, &b, clock(), &SCHEMA, None)
            .unwrap()
            .publish(&completed(&b, b"v"))
            .unwrap();
        f.gc(clock());
    }
    fs::remove_file(f.base.join(".collections.catalog")).unwrap();
}

fn snapshot_bytes(generation: u64) -> Vec<u8> {
    use bingsu_core::{
        color::palette::Mode,
        config::{compile, merge::Merged},
    };
    let merged = Merged::default();
    snapshot::Snapshot {
        id: snapshot::Identity {
            generation,
            ..binding(b"/cwd").snapshot
        },
        config: compile::compile(&merged, &merged, Mode::Dark).unwrap().0,
        metadata: snapshot::encode_metadata(b"fixture").unwrap(),
    }
    .encode(1, 0)
    .unwrap()
}

fn publish_snapshot(context: &CheckedContextFd, generation: u64) {
    use commands::snapshot_store::Slot;
    let lock = context.try_lock().unwrap();
    lock.stage(Slot::Snapshot, &snapshot_bytes(generation))
        .unwrap();
    lock.install(Slot::Snapshot).unwrap();
}

fn ordinal_reader(block: usize) -> sys::FixtureDirectoryReader {
    sys::FixtureDirectoryReader::install(Box::new(move |dir, position| {
        let mut names = sys::directory_names(dir)?;
        names.sort();
        let names: Vec<_> = names
            .into_iter()
            .skip(position as usize)
            .take(block)
            .collect();
        Ok((position + names.len() as u64, names))
    }))
}

// 이것을 실패시키는 것: snapshot rename으로 mtime이 바뀐 소진된 조상 cursor에서 하위 진도를 버리는 것.
#[test]
fn gc_snapshot_publication_preserves_active_subtree() {
    use commands::collection_store::Admission;
    let f = Fixture::new("publish-progress");
    seed_inventory(&f, 24);
    let mut yields = 0;
    let mut active = 0;
    for generation in 1..=128 {
        let admission = CollectionStore::fixture_admit(
            &f.context,
            &f.binding,
            clock(),
            &SCHEMA,
            GcBudget {
                max_ops: 1_536,
                ..GcBudget::default()
            },
            None,
        )
        .unwrap();
        if matches!(admission, Admission::Admitted(_)) {
            assert!(yields > 1 && active > 1);
            assert_eq!(catalog_counts(&f).0, 25);
            assert_eq!(catalog_counts(&f).1, 51);
            eprintln!("snapshot publication progress: yields={yields} active={active}");
            return;
        }
        yields += 1;
        active += usize::from(collection_gc::fixture_cursor(&f.context).len() >= 8);
        let dir = commands::snapshot_store::context_dir_for_test(&f.context);
        let before = dir.metadata().unwrap().modified().unwrap();
        publish_snapshot(&f.context, generation);
        assert_ne!(dir.metadata().unwrap().modified().unwrap(), before);
    }
    panic!("snapshot publication stranded admission after {yields} yields");
}

fn inventory_with_empties(f: &Fixture, empty_stores: bool, count: usize, ordinal: bool) {
    use commands::collection_store::Admission;
    seed_inventory(f, 12);
    let collections = f.path().parent().unwrap().parent().unwrap().to_path_buf();
    let mut empties = Vec::new();
    if empty_stores {
        for i in 0..12 {
            let b = binding(format!("/inventory-{i}").as_bytes());
            let empty = f.path_for(&b).parent().unwrap().join(".store.gc");
            fs::create_dir(&empty).unwrap();
            fs::set_permissions(&empty, fs::Permissions::from_mode(0o700)).unwrap();
            empties.push(empty);
        }
    } else {
        for i in 0..count {
            // Sort a valid empty address immediately after each live one.
            // Eager rmdir then skips the next live store with ordinal offsets.
            let name = if i < 12 {
                let b = binding(format!("/inventory-{i}").as_bytes());
                format!(
                    "{}00",
                    f.path_for(&b)
                        .parent()
                        .unwrap()
                        .file_name()
                        .unwrap()
                        .to_str()
                        .unwrap()
                )
            } else {
                format!("{i:064x}")
            };
            let empty = collections.join(name);
            fs::create_dir(&empty).unwrap();
            fs::set_permissions(&empty, fs::Permissions::from_mode(0o700)).unwrap();
            empties.push(empty);
        }
    }
    let bytes: u64 = (0..12)
        .map(|i| {
            fs::metadata(
                f.path_for(&binding(format!("/inventory-{i}").as_bytes()))
                    .join("response"),
            )
            .unwrap()
            .len()
        })
        .sum();
    let _reader = ordinal.then(|| ordinal_reader(1));
    for _ in 0..256 {
        let admission = CollectionStore::fixture_admit(
            &f.context,
            &f.binding,
            clock(),
            &SCHEMA,
            GcBudget {
                max_ops: 1_536,
                ..GcBudget::default()
            },
            None,
        )
        .unwrap();
        if matches!(admission, Admission::Admitted(_)) {
            assert_eq!(
                catalog_counts(f),
                (13, 27, bytes + collection_gc::RESERVATION)
            );
            assert!(empties.iter().all(|path| !path.exists()));
            return;
        }
    }
    panic!("inventory with empty directories never completed");
}

// 이것을 실패시키는 것: 부모 EOF 전에 빈 address를 rmdir하여 다음 ordinal 항목을 건너뛰는 것.
#[test]
fn gc_ordinal_address_removal_waits_for_parent_eof() {
    let f = Fixture::new("ordinal-address");
    inventory_with_empties(&f, false, 12, true);
}

// 이것을 실패시키는 것: 부모 EOF 전에 빈 store를 rmdir하여 다음 store의 수·bytes를 누락하는 것.
#[test]
fn gc_ordinal_store_removal_waits_for_parent_eof() {
    let f = Fixture::new("ordinal-store");
    inventory_with_empties(&f, true, 0, true);
}

// 이것을 실패시키는 것: native tmpfs의 여러 block 사이에서 빈 주소를 지워 미열람 store를 누락하는 것.
#[cfg(target_os = "linux")]
#[test]
fn gc_native_tmpfs_removal_waits_for_parent_eof() {
    let f = Fixture::new_in(PathBuf::from("/dev/shm"), "native-tmpfs");
    // SAFETY: statfs is a C output structure whose fields permit zero values.
    let mut stat: libc::statfs = unsafe { std::mem::zeroed() };
    // SAFETY: live runtime fd and writable statfs storage.
    let rc = unsafe { libc::fstatfs(f.runtime.as_raw_fd(), &mut stat) };
    assert_eq!(rc, 0);
    assert_eq!(stat.f_type as u64, libc::TMPFS_MAGIC as u64);
    inventory_with_empties(&f, false, 512, false);
}

// 이것을 실패시키는 것: 목록에 있던 이름의 open ENOENT를 unsafe_seen으로 기록하는 것.
#[test]
fn gc_pending_name_disappearing_is_absent() {
    let f = Fixture::new("pending-gone");
    seed_inventory(&f, 1);
    let collections = f.path().parent().unwrap().parent().unwrap().to_path_buf();
    let gone = collections.join("00");
    fs::create_dir(&gone).unwrap();
    fs::set_permissions(&gone, fs::Permissions::from_mode(0o700)).unwrap();
    let removed = std::rc::Rc::new(std::cell::Cell::new(false));
    let observed = removed.clone();
    let _reader = sys::FixtureDirectoryReader::install(Box::new(move |dir, position| {
        let mut names = sys::directory_names(dir)?;
        names.sort();
        let block = if names.iter().any(|n| n == "00") {
            512
        } else {
            1
        };
        if block == 512 && !observed.replace(true) {
            fs::remove_dir(&gone)?;
        }
        let names: Vec<_> = names
            .into_iter()
            .skip(position as usize)
            .take(block)
            .collect();
        Ok((position + names.len() as u64, names))
    }));
    for _ in 0..64 {
        let admission = CollectionStore::fixture_admit(
            &f.context,
            &f.binding,
            clock(),
            &SCHEMA,
            GcBudget::default(),
            None,
        )
        .unwrap();
        if matches!(
            admission,
            commands::collection_store::Admission::Admitted(_)
        ) {
            assert!(removed.get());
            assert_eq!(catalog_counts(&f).0, 2);
            return;
        }
    }
    panic!("a vanished pending name must not poison admission");
}

// 이것을 실패시키는 것: 삭제 전 mtime 불일치를 무시하고 rmdir 뒤 시각으로 덮어 새 store를 누락하는 것.
#[test]
fn gc_prune_restarts_if_parent_changed_before_deletion() {
    let f = Fixture::new("prune-mtime");
    seed_inventory(&f, 2);
    let address = f
        .path_for(&binding(b"/inventory-1"))
        .parent()
        .unwrap()
        .to_path_buf();
    let collections = address.parent().unwrap();
    let empty = collections.join("00");
    fs::create_dir(&empty).unwrap();
    fs::set_permissions(&empty, fs::Permissions::from_mode(0o700)).unwrap();
    let ino = fs::metadata(collections).unwrap().ino();
    let held = f.base.join("held");
    fs::rename(&address, &held).unwrap();
    let changed = std::rc::Rc::new(std::cell::Cell::new(false));
    let observed = changed.clone();
    let _reader = sys::FixtureDirectoryReader::install(Box::new(move |dir, position| {
        let mut names = sys::directory_names(dir)?;
        names.sort();
        let names: Vec<_> = names.into_iter().skip(position as usize).take(1).collect();
        if names.is_empty() && sys::fd_facts(dir)?.ino == ino && !observed.replace(true) {
            fs::rename(&held, &address)?;
        }
        Ok((position + names.len() as u64, names))
    }));
    for _ in 0..64 {
        let admission = CollectionStore::fixture_admit(
            &f.context,
            &f.binding,
            clock(),
            &SCHEMA,
            GcBudget::default(),
            None,
        )
        .unwrap();
        if matches!(
            admission,
            commands::collection_store::Admission::Admitted(_)
        ) {
            assert!(changed.get());
            assert_eq!(catalog_counts(&f).0, 3);
            assert_eq!(catalog_counts(&f).1, 7);
            assert!(!empty.exists());
            return;
        }
    }
    panic!("changed parent was not re-inventoried before deletion");
}

// 이것을 실패시키는 것: 큐에 든 빈 store가 채워져 rmdir이 ENOTEMPTY여도 재계수 없이 버리는 것.
#[test]
fn gc_queued_empty_store_is_rechecked_before_removal() {
    let f = Fixture::new("prune-filled");
    seed_inventory(&f, 1);
    let path = f.path_for(&binding(b"/inventory-0"));
    let ino = fs::metadata(path.parent().unwrap()).unwrap().ino();
    let held = f.base.join("held");
    fs::rename(&path, &held).unwrap();
    fs::create_dir(&path).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    let filled = std::rc::Rc::new(std::cell::Cell::new(false));
    let observed = filled.clone();
    let _reader = sys::FixtureDirectoryReader::install(Box::new(move |dir, position| {
        let mut names = sys::directory_names(dir)?;
        names.sort();
        let names: Vec<_> = names.into_iter().skip(position as usize).take(1).collect();
        if names.is_empty() && sys::fd_facts(dir)?.ino == ino && !observed.replace(true) {
            for entry in fs::read_dir(&held)? {
                let entry = entry?;
                fs::rename(entry.path(), path.join(entry.file_name()))?;
            }
        }
        Ok((position + names.len() as u64, names))
    }));
    for _ in 0..64 {
        let admission = CollectionStore::fixture_admit(
            &f.context,
            &f.binding,
            clock(),
            &SCHEMA,
            GcBudget::default(),
            None,
        )
        .unwrap();
        if matches!(
            admission,
            commands::collection_store::Admission::Admitted(_)
        ) {
            assert!(filled.get());
            assert_eq!(catalog_counts(&f).0, 2);
            assert_eq!(catalog_counts(&f).1, 5);
            return;
        }
    }
    panic!("new contents of the queued store were not inventoried");
}

// 이것을 실패시키는 것: __getdirentries64 심벌이 없거나 닫힌 DIR의 telldir cookie로 재개하는 것.
#[test]
fn native_directory_blocks_resume_after_reopen() {
    let f = Fixture::new("native-reopen");
    let path = f.base.join("native");
    fs::create_dir(&path).unwrap();
    let expected: std::collections::BTreeSet<std::ffi::OsString> = (0..300)
        .map(|i| format!("{i:04}-{}", "x".repeat(160)).into())
        .collect();
    for name in &expected {
        fs::write(path.join(name), []).unwrap();
    }
    let mut position = 0;
    let mut found = std::collections::BTreeSet::new();
    let mut blocks = 0;
    loop {
        let dir = File::open(&path).unwrap();
        let (next, names) = sys::directory_batch(dir.as_fd(), position).unwrap();
        drop(dir);
        for name in names {
            assert!(found.insert(name), "repeated native entry");
        }
        if next == position {
            break;
        }
        position = next;
        blocks += 1;
        assert!(blocks <= 300);
    }
    assert!(blocks > 1);
    assert_eq!(found, expected);
}

// 이것을 실패시키는 것: 예산 양보 뒤 cursor/목록 위치를 버리거나 Deferred를 성공으로 바꾸는 것.
#[test]
fn admission_eventually_progresses_after_budget_yields() {
    use collection_gc::GcStop;
    use commands::collection_store::Admission;
    for timed in [false, true] {
        let f = Fixture::new("admission-progress");
        seed_inventory(&f, 12);
        // A raw directory larger than any sweep: listing must not restart at 0.
        for i in 0..2_048 {
            fs::write(f.base.join(format!("ignored-{i:04}")), []).unwrap();
        }
        let budget = if timed {
            GcBudget {
                max_ops: 4_096,
                max_ns: 6_000_000,
            }
        } else {
            GcBudget {
                max_ops: 1_536,
                max_ns: 20_000_000,
            }
        };
        let mut yields = 0;
        let mut admitted = false;
        for _ in 0..128 {
            GC_CLOCK.with(|clock| clock.set((0, 10_000)));
            match CollectionStore::fixture_admit(
                &f.context,
                &f.binding,
                clock(),
                &SCHEMA,
                budget,
                timed.then_some(gc_tick),
            )
            .unwrap()
            {
                Admission::Deferred(stop) => {
                    assert_eq!(
                        stop,
                        if timed {
                            GcStop::YieldTime
                        } else {
                            GcStop::YieldOps
                        }
                    );
                    assert!(!f.path().exists());
                    yields += 1;
                }
                Admission::Admitted(_) => {
                    admitted = true;
                    break;
                }
            }
        }
        assert!(admitted && yields > 1, "timed={timed}, yields={yields}");
        assert_eq!(catalog_counts(&f).0, 13);
        assert_eq!(catalog_counts(&f).1, 27);
        eprintln!("admission progress: timed={timed} yields={yields} stores=13 nodes=27");
    }
}

// 이것을 실패시키는 것: 512 ops·4ms 예약을 줄이거나 전체 마감 뒤 checkpoint I/O를 시작하는 것.
#[test]
fn gc_checkpoint_reserve_is_bounded() {
    use collection_gc::GcStop;
    let f = Fixture::new("checkpoint-reserve");
    seed_inventory(&f, 12);
    // Start inventory through admission, then exercise its actual GC checkpoint.
    let _ = CollectionStore::fixture_admit(
        &f.context,
        &f.binding,
        clock(),
        &SCHEMA,
        GcBudget {
            max_ops: 1_200,
            max_ns: 20_000_000,
        },
        None,
    )
    .unwrap();
    let r = collection_gc::fixture_reclaim(&f.context, clock(), 1_200, &SCHEMA).unwrap();
    assert_eq!(r.stop, GcStop::YieldOps);
    assert!(
        r.checkpoint_saved,
        "the reserved operations must install the checkpoint"
    );
    assert!(r.checkpoint_ops > 0 && r.checkpoint_ops <= 512);
    assert!(r.ops <= 1_200);
    GC_CLOCK.with(|clock| clock.set((16_000_000, 0)));
    let r = collection_gc::fixture_timed_reclaim(
        &f.context,
        clock(),
        GcBudget::default(),
        &SCHEMA,
        gc_tick,
    )
    .unwrap();
    assert_eq!((r.stop, r.ops), (GcStop::YieldTime, 0));
    let before = fs::read(f.base.join(".collections.catalog")).unwrap();
    // Reach inventory first, cross its 16ms boundary during work, then
    // cross 20ms at checkpoint entry (not at the initial catalog open).
    GC_CLOCK.with(|clock| clock.set((0, 100_000)));
    let reached = std::rc::Rc::new(std::cell::Cell::new(false));
    let observed = reached.clone();
    collection_gc::fixture_checkpoint_hook(Box::new(move || {
        observed.set(true);
        GC_CLOCK.with(|clock| {
            assert!(clock.get().0 >= 16_000_000);
            clock.set((20_000_001, 0));
        });
    }));
    let r = collection_gc::fixture_timed_reclaim(
        &f.context,
        clock(),
        GcBudget::default(),
        &SCHEMA,
        gc_tick,
    )
    .unwrap();
    assert!(reached.get(), "must exercise checkpoint() after doing work");
    assert!(r.ops > 0);
    assert_eq!((r.stop, r.checkpoint_ops), (GcStop::YieldTime, 0));
    assert!(!r.checkpoint_saved);
    assert_eq!(
        fs::read(f.base.join(".collections.catalog")).unwrap(),
        before
    );
    let cold = std::time::Instant::now();
    collection_gc::reclaim(&f.runtime, clock(), GcBudget::default()).unwrap();
    let cold_ns = cold.elapsed().as_nanos();
    let mut samples = Vec::new();
    let mut max_checkpoint = 0;
    for _ in 0..200 {
        let start = std::time::Instant::now();
        let r = collection_gc::reclaim(&f.runtime, clock(), GcBudget::default()).unwrap();
        samples.push(start.elapsed().as_nanos());
        assert!(r.ops <= 4_096 && r.checkpoint_ops <= 512);
        max_checkpoint = max_checkpoint.max(r.checkpoint_ops);
    }
    samples.sort_unstable();
    let mean = samples.iter().sum::<u128>() / samples.len() as u128;
    let variance = samples
        .iter()
        .map(|n| n.abs_diff(mean).pow(2))
        .sum::<u128>()
        / samples.len() as u128;
    eprintln!(
        "GC cold_ns={cold_ns} warm: samples=200 p50_ns={} p95_ns={} max_ns={} variance_ns2={variance} max_checkpoint_ops={max_checkpoint}",
        samples[100], samples[190], samples[199]
    );
}

// 이것을 실패시키는 것: directory 정체 변경 때 전체 catalog를 초기화하거나 같은 subtree를 중복 계수하는 것.
#[test]
fn gc_changed_directory_restarts_only_its_cursor() {
    let f = Fixture::new("changed-cursor");
    seed_inventory(&f, 12);
    let mut selected = None;
    for _ in 0..64 {
        let _ = CollectionStore::fixture_admit(
            &f.context,
            &f.binding,
            clock(),
            &SCHEMA,
            GcBudget {
                max_ops: 1_200,
                max_ns: 20_000_000,
            },
            None,
        )
        .unwrap();
        let cursor = collection_gc::fixture_cursor(&f.context);
        if cursor.len() == 9 && cursor.last().unwrap().2 > 0 {
            selected = Some(cursor);
            break;
        }
    }
    let cursor = selected.expect("stop after an earlier sibling was inventoried");
    let path = cursor
        .iter()
        .skip(1)
        .fold(f.base.clone(), |p, c| p.join(&c.0));
    let displaced = f.base.join("displaced-cursor");
    let parent = File::open(path.parent().unwrap()).unwrap();
    let modified = parent.metadata().unwrap().modified().unwrap();
    fs::rename(&path, &displaced).unwrap();
    fs::create_dir(&path).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    // Keep the same contents under a different directory inode.
    fs::rename(displaced.join("store"), path.join("store")).unwrap();
    // Isolate replacement of this inode from a separate parent-list change.
    parent.set_modified(modified).unwrap();
    let prior = cursor.last().unwrap().2;
    let r = collection_gc::fixture_reclaim(&f.context, clock(), 1_200, &SCHEMA).unwrap();
    assert!(r.incomplete);
    assert_eq!(r.restarted_depths, vec![8]);
    assert!(
        catalog_counts(&f).0 >= prior,
        "unrelated completed stores were discarded"
    );
    let resumed = collection_gc::fixture_cursor(&f.context);
    assert_eq!(
        resumed[1].1, cursor[1].1,
        "unrelated ancestor listing restarted"
    );
    for _ in 0..64 {
        if !f.gc(clock()).incomplete {
            break;
        }
    }
    assert_eq!(catalog_counts(&f).0, 12);
    assert_eq!(catalog_counts(&f).1, 25);
}

// 이것을 실패시키는 것: helper가 admission 결과를 .ok()로 버리거나 collection 실패를 refresh 실패로 바꾸는 것.
#[test]
fn admission_errors_are_not_erased() {
    use collection_gc::GcStop;
    use commands::collection_store::Admission;
    let f = Fixture::new("admission-errors");
    f.publish(b"retained");
    let live = f.acquire().unwrap();
    assert!(matches!(
        CollectionStore::admit(&f.context, &f.binding, clock()).unwrap(),
        Admission::Deferred(GcStop::Busy)
    ));
    drop(live);
    let mut wrong = f.binding.clone();
    wrong.config = b"/other".to_vec();
    assert!(matches!(
        CollectionStore::admit(&f.context, &wrong, clock()),
        Err(StoreError::Unsafe)
    ));
    for case in ["time", "ops", "deferred-busy", "busy", "unsafe", "io"] {
        let output = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "admission_run_child",
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .env("A1_ADMISSION_CASE", case)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{case}: {}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed; 0 failed"));
    }
    assert_eq!(f.read("response"), completed(&f.binding, b"retained"));

    // 이것을 실패시키는 것: 잘못된 이름을 검증하기 전에 목록 위치를 진행시켜 다음 admission에서 오류를 건너뛰는 것.
    collection_gc::fixture_invalid_listing(&f.context);
    fs::remove_file(f.base.join(".collections.catalog")).unwrap();

    // 이것을 실패시키는 것: 작업 예산 소진 원인이 뒤따른 checkpoint의 실제 Unsafe 오류를 덮는 것.
    for i in 0..512 {
        fs::write(f.base.join(format!("ignored-{i}")), []).unwrap();
    }
    let stage = f.base.join(".collections.catalog.stage");
    collection_gc::fixture_checkpoint_hook(Box::new(move || {
        if stage.exists() {
            fs::remove_file(&stage).unwrap();
        }
        fs::create_dir(&stage).unwrap();
    }));
    assert!(matches!(
        CollectionStore::fixture_admit(
            &f.context,
            &f.binding,
            clock(),
            &SCHEMA,
            GcBudget {
                max_ops: 1_200,
                max_ns: 20_000_000
            },
            None
        ),
        Err(StoreError::Unsafe)
    ));
}

// 이것을 실패시키는 것: helper::run에서 admission의 .ok()로 오류/Deferred를 버리거나 refresh 발행을 막는 것.
#[test]
#[ignore = "child isolates helper detach and its watchdog"]
#[allow(clippy::disallowed_methods, reason = "isolated helper fixture case")]
fn admission_run_child() {
    use bingsu_core::envelope::LogLevel;
    use collection_gc::GcStop;
    use commands::helper;
    let case = std::env::var("A1_ADMISSION_CASE").unwrap();
    let (outcome, expected, level) = match case.as_str() {
        "time" => (
            Ok(Err(GcStop::YieldTime)),
            "collection deferred: time budget",
            LogLevel::DebugLog,
        ),
        "ops" => (
            Ok(Err(GcStop::YieldOps)),
            "collection deferred: operation budget",
            LogLevel::DebugLog,
        ),
        "deferred-busy" => (Ok(Err(GcStop::Busy)), "collection busy", LogLevel::DebugLog),
        "busy" => (Err(StoreError::Busy), "collection busy", LogLevel::DebugLog),
        "unsafe" => (
            Err(StoreError::Unsafe),
            "collection unsafe",
            LogLevel::Error,
        ),
        "io" => (
            Err(StoreError::Io(std::io::Error::from_raw_os_error(libc::EIO))),
            "collection I/O failure",
            LogLevel::Error,
        ),
        _ => panic!("unknown admission case"),
    };
    let f = Fixture::new("helper-admission");
    f.publish(b"retained");
    let context = CheckedContextFd::under_runtime(
        &f.runtime,
        &f.binding.config,
        &f.binding.state,
        sys::current_uid(),
        false,
    )
    .unwrap();
    let events = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
    let snapshot = snapshot_bytes(2);
    helper::fixture_run(helper::FixtureRun {
        context,
        now: clock(),
        admission: std::cell::RefCell::new(Some(outcome)),
        snapshot: snapshot.clone(),
        events: events.clone(),
    });
    let meta = f.runtime.metadata().unwrap();
    let args = vec![
        "--ctx".into(),
        "1".into(),
        "--record".into(),
        "B1".into(),
        "--width".into(),
        "80".into(),
        format!(
            "--runtime-root={}:{}:{}",
            meta.dev(),
            meta.ino(),
            f.base.display()
        )
        .into(),
        "--config-root=/config".into(),
        "--config-root-written=/config".into(),
        "--state-root=/state".into(),
        "--home=/".into(),
    ];
    let panic_hook = std::panic::take_hook();
    bingsu_core::helper::validate(
        &args
            .iter()
            .map(|a: &std::ffi::OsString| a.as_encoded_bytes())
            .collect::<Vec<_>>(),
    )
    .unwrap();
    let result = helper::run(std::env::current_exe().unwrap().as_os_str(), &args);
    std::panic::set_hook(panic_hook);
    assert_eq!(
        result,
        std::process::ExitCode::SUCCESS,
        "events: {:?}",
        events.borrow()
    );
    assert_eq!(
        *events.borrow(),
        [(level, expected), (LogLevel::Info, "refresh published")]
    );
    let dir = f
        .path()
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf();
    assert_eq!(fs::read(dir.join("snapshot")).unwrap(), snapshot);
    assert_eq!(f.read("response"), completed(&f.binding, b"retained"));
}

// 이것을 실패시키는 것: 1MiB 근처 catalog checkpoint가 512 ops 예약을 넘거나 실제 staging을 생략하는 것.
#[test]
fn gc_large_catalog_checkpoint_cost() {
    let f = Fixture::new("large-checkpoint");
    f.publish(b"seed");
    let (bytes, ops) = collection_gc::fixture_large_checkpoint(&f.context);
    assert!((980_000..=1_048_576).contains(&bytes));
    assert!(ops > 0 && ops <= 512);
    assert_eq!(
        fs::metadata(f.base.join(".collections.catalog"))
            .unwrap()
            .len(),
        bytes as u64
    );
    eprintln!("GC_CHECKPOINT bytes={bytes} ops={ops}");
}
