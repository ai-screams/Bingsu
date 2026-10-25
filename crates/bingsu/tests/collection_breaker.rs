//! Helper-owned breaker and reclamation tests use the exact command modules in a test-only target.
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
        breaker::{self, Admission, Breaker, Key},
        wire::{EndReason, Progress},
    },
    snapshot::Clock,
};
use commands::{
    collection_breaker::{self as store, Decision},
    collection_gc, collection_store,
    snapshot_store::{CheckedContextFd, StoreError},
    sys,
};
use std::{
    fs::{self, File},
    os::unix::fs::{MetadataExt, PermissionsExt, symlink},
    path::PathBuf,
    sync::atomic::{AtomicU32, Ordering},
};
static NEXT: AtomicU32 = AtomicU32::new(0);
const SESSION: &[u8] = b"0123456789abcdef0123456789abcdef";
fn clock(now: u64) -> Clock {
    Clock {
        now,
        kind: 1,
        boot: [1; 16],
        domain: [2; 16],
        resume: 0,
    }
}
struct Fixture {
    root: PathBuf,
    runtime: File,
    _serial: std::sync::MutexGuard<'static, ()>,
}
impl Fixture {
    fn new() -> Self {
        let serial = sys::test_inherited_fd_lock();
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(format!(
            "../../target/e3-fixtures/{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let runtime = File::open(&root).unwrap();
        Self {
            root,
            runtime,
            _serial: serial,
        }
    }
    fn dir(&self) -> PathBuf {
        self.root
            .join(store::ROOT)
            .join("sessions")
            .join(std::str::from_utf8(SESSION).unwrap())
    }
    fn begin(&self, seq: u64, now: u64) -> Decision {
        store::fixture_begin(
            &self.runtime,
            Some(SESSION),
            Some(seq),
            b"/repo",
            clock(now),
        )
    }
    fn ticket(&self, seq: u64, now: u64) -> store::Ticket {
        match self.begin(seq, now) {
            Decision::Run(Some(t)) => t,
            _ => panic!("expected persisted admission seq={seq}"),
        }
    }
    fn read(&self) -> Breaker {
        Breaker::decode(&fs::read(self.dir().join(store::RECORD)).unwrap()).unwrap()
    }
    fn gc(&self, now: Clock) {
        let context = CheckedContextFd::under_runtime(
            &self.runtime,
            b"/config",
            b"/state",
            sys::current_uid(),
            true,
        )
        .unwrap();
        let mut complete = 0;
        for _ in 0..40 {
            let report =
                collection_gc::fixture_reclaim(&context, now, 4096, bingsu_core::field::BUILTIN)
                    .unwrap();
            if !report.incomplete {
                complete += 1;
                if complete == 2 {
                    return;
                }
            }
        }
        panic!("bounded GC did not converge");
    }
    fn trip(&self) {
        for seq in 1..=3 {
            self.ticket(seq, seq)
                .finish(Progress::default(), EndReason::Deadline, clock(seq))
                .unwrap();
        }
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[test]
fn three_missing_a_deadlines_block_for_five_minutes() {
    let f = Fixture::new();
    f.trip();
    assert!(matches!(
        f.begin(4, 3 + breaker::BLOCK_NS - 1),
        Decision::Blocked
    ));
    let probe = f.ticket(4, 3 + breaker::BLOCK_NS);
    assert!(f.read().live(clock(3 + breaker::BLOCK_NS)));
    probe
        .finish(
            Progress {
                stage_a_complete: true,
                device: Some(77),
            },
            EndReason::Deadline,
            clock(3 + breaker::BLOCK_NS),
        )
        .unwrap();
    assert!(matches!(
        f.begin(5, 4 + breaker::BLOCK_NS),
        Decision::Run(Some(_))
    ));
    assert!(!f.root.join("sessions-v1").exists());
    assert!(!f.root.join("collections-v1").exists());
}
#[test]
fn half_open_probe_is_single_and_ordered() {
    let f = Fixture::new();
    f.trip();
    let now = 3 + breaker::BLOCK_NS;
    let probe = f.ticket(4, now);
    assert!(matches!(f.begin(5, now), Decision::Blocked));
    assert!(matches!(f.begin(4, now), Decision::Blocked));
    assert!(matches!(f.begin(3, now), Decision::Blocked));
    probe
        .finish(Progress::default(), EndReason::Complete, clock(now))
        .unwrap();
    let older = f.ticket(5, now + 1);
    let newer = match store::fixture_begin(
        &f.runtime,
        Some(SESSION),
        Some(6),
        b"/other",
        clock(now + 2),
    ) {
        Decision::Run(Some(ticket)) => ticket,
        _ => panic!("independent cwd admission"),
    };
    newer
        .finish(Progress::default(), EndReason::Complete, clock(now + 3))
        .unwrap();
    let saved = fs::read(f.dir().join(store::RECORD)).unwrap();
    assert!(matches!(
        older.finish(Progress::default(), EndReason::Deadline, clock(now + 4)),
        Err(StoreError::Unsafe)
    ));
    assert_eq!(fs::read(f.dir().join(store::RECORD)).unwrap(), saved);
    let dir = File::open(f.dir()).unwrap();
    let lock =
        collection_store::close_only_lock(&dir, store::LOCK, sys::current_uid(), false).unwrap();
    let duplicate = lock.try_clone().unwrap();
    drop(lock);
    assert!(matches!(f.begin(7, now + 5), Decision::Deferred));
    drop(duplicate);
    assert!(matches!(
        f.begin(7, now + breaker::LEASE_NS + 5),
        Decision::Run(Some(_))
    ));
}
#[test]
fn partial_b_d_never_trip_breaker() {
    let f = Fixture::new();
    for seq in 1..=20 {
        f.ticket(seq, seq)
            .finish(
                Progress {
                    stage_a_complete: true,
                    device: Some(10),
                },
                if seq % 2 == 0 {
                    EndReason::Deadline
                } else {
                    EndReason::Complete
                },
                clock(seq),
            )
            .unwrap();
        assert_eq!(
            f.read().admit(&Key::cwd(b"/repo").unwrap(), clock(seq)),
            Admission::Allowed
        );
    }
}
#[test]
fn failed_breaker_write_does_not_block_front() {
    let f = Fixture::new();
    f.ticket(1, 1)
        .finish(Progress::default(), EndReason::Complete, clock(1))
        .unwrap();
    let before = fs::read(f.dir().join(store::RECORD)).unwrap();
    let canary = f.root.join("canary");
    fs::write(&canary, b"unmodified").unwrap();
    symlink(&canary, f.dir().join(store::STAGE)).unwrap();
    assert!(matches!(f.begin(2, 2), Decision::Run(None)));
    assert_eq!(fs::read(&canary).unwrap(), b"unmodified");
    assert_eq!(fs::read(f.dir().join(store::RECORD)).unwrap(), before);
    // The same independent snapshot publication used by helper::run still works.
    let context = CheckedContextFd::under_runtime(
        &f.runtime,
        b"/config",
        b"/state",
        sys::current_uid(),
        true,
    )
    .unwrap();
    let lock = context.try_lock().unwrap();
    let merged = bingsu_core::config::merge::Merged::default();
    let snapshot = bingsu_core::snapshot::Snapshot {
        id: bingsu_core::snapshot::Identity {
            boot: [1; 16],
            epoch: [2; 16],
            generation: 1,
            source: [3; 4],
            context: bingsu_core::snapshot::context_crc(b"/config", b"/state").unwrap(),
        },
        config: bingsu_core::config::compile::compile(
            &merged,
            &merged,
            bingsu_core::color::palette::Mode::Dark,
        )
        .unwrap()
        .0,
        metadata: bingsu_core::snapshot::encode_metadata(b"fixture").unwrap(),
    }
    .encode(1, 0)
    .unwrap();
    lock.stage(commands::snapshot_store::Slot::Snapshot, &snapshot)
        .unwrap();
    lock.install(commands::snapshot_store::Slot::Snapshot)
        .unwrap();
}
#[test]
fn e3_missing_session_sequence_do_no_io_and_symlinks_are_refused() {
    let f = Fixture::new();
    for (session, seq) in [(None, Some(1)), (Some(SESSION), None)] {
        assert!(matches!(
            store::fixture_begin(&f.runtime, session, seq, b"/repo", clock(1)),
            Decision::Run(None)
        ));
        assert_eq!(fs::read_dir(&f.root).unwrap().count(), 0);
    }
    drop(f);
    for component in 0..3 {
        let f = Fixture::new();
        let outside = f.root.join("outside");
        fs::create_dir(&outside).unwrap();
        fs::set_permissions(&outside, fs::Permissions::from_mode(0o700)).unwrap();
        let mut at = f.root.clone();
        for name in store::path(std::str::from_utf8(SESSION).unwrap())
            .iter()
            .take(component)
        {
            at.push(name);
            fs::create_dir(&at).unwrap();
            fs::set_permissions(&at, fs::Permissions::from_mode(0o700)).unwrap();
        }
        symlink(
            &outside,
            at.join(&store::path(std::str::from_utf8(SESSION).unwrap())[component]),
        )
        .unwrap();
        assert!(matches!(f.begin(1, 1), Decision::Run(None)));
        assert_eq!(fs::read_dir(outside).unwrap().count(), 0);
    }
}
#[test]
fn e3_gc_preserves_leases_locks_and_reclaims_after_twenty_four_hours() {
    let f = Fixture::new();
    let ticket = f.ticket(1, 1);
    let before_inode = fs::metadata(f.dir().join(store::LOCK)).unwrap().ino();
    f.gc(clock(1));
    assert!(f.dir().join(store::RECORD).exists());
    assert_eq!(
        fs::metadata(f.dir().join(store::LOCK)).unwrap().ino(),
        before_inode
    );
    ticket
        .finish(Progress::default(), EndReason::Complete, clock(2))
        .unwrap();
    let dir = File::open(f.dir()).unwrap();
    let lock =
        collection_store::close_only_lock(&dir, store::LOCK, sys::current_uid(), false).unwrap();
    let next_day = 86_400_000_000_002;
    f.gc(clock(next_day));
    assert!(f.dir().exists());
    drop(lock);
    f.gc(clock(next_day - 1));
    assert!(f.dir().exists());
    f.gc(clock(next_day));
    assert!(!f.dir().exists());
    assert!(matches!(f.begin(2, next_day + 1), Decision::Run(Some(_))));
}
fn response_store(
    runtime: &File,
    cwd: &[u8],
    now: u64,
) -> Result<collection_store::CollectionStore, StoreError> {
    use bingsu_core::{
        collection::wire::{Binding, BuildId},
        snapshot::{self, Identity},
    };
    let context =
        CheckedContextFd::under_runtime(runtime, b"/config", b"/state", sys::current_uid(), true)?;
    let binding = Binding {
        path_query: Default::default(),
        build_id: BuildId([7; 32]),
        snapshot: Identity {
            boot: [1; 16],
            epoch: [2; 16],
            generation: 1,
            source: [3; 4],
            context: snapshot::context_crc(b"/config", b"/state").unwrap(),
        },
        clock_kind: 1,
        domain: [2; 16],
        resume: 0,
        config: b"/config".to_vec(),
        state: b"/state".to_vec(),
        cwd: cwd.to_vec(),
        mask: 8,
    };
    collection_store::CollectionStore::fixture(
        &context,
        &binding,
        clock(now),
        bingsu_core::field::BUILTIN,
        None,
    )
}

#[test]
fn lost_probe_result_preserves_five_minute_block() {
    // Mutation: retaining only lease_until permits the reviewer's +LEASE retry.
    let f = Fixture::new();
    f.trip();
    let now = 3 + breaker::BLOCK_NS;
    let probe = f.ticket(4, now);
    assert!(matches!(
        store::fixture_begin(&f.runtime, Some(SESSION), Some(5), b"/other", clock(now)),
        Decision::Run(Some(_))
    ));
    assert!(matches!(
        probe.finish(Progress::default(), EndReason::Deadline, clock(now)),
        Err(StoreError::Unsafe)
    ));
    assert!(matches!(
        f.begin(6, now + breaker::LEASE_NS),
        Decision::Blocked
    ));
    assert!(matches!(
        f.begin(6, now + breaker::BLOCK_NS - 1),
        Decision::Blocked
    ));
    assert!(matches!(
        f.begin(6, now + breaker::BLOCK_NS),
        Decision::Run(Some(_))
    ));
}

#[test]
fn healthy_device_lease_allows_another_cwd() {
    // Mutation: treating all live leases as Blocked drops /b while /a runs.
    let f = Fixture::new();
    let begin = |cwd: &[u8], seq| match store::fixture_begin(
        &f.runtime,
        Some(SESSION),
        Some(seq),
        cwd,
        clock(seq),
    ) {
        Decision::Run(Some(ticket)) => ticket,
        _ => panic!("expected tracked Run for seq={seq}"),
    };
    for (cwd, seq) in [(b"/a", 1), (b"/b", 2)] {
        begin(cwd, seq)
            .finish(
                Progress {
                    stage_a_complete: true,
                    device: Some(42),
                },
                EndReason::Complete,
                clock(seq),
            )
            .unwrap();
    }
    let _a_running = begin(b"/a", 3);
    let _b_running = begin(b"/b", 4);
    assert_eq!(
        f.read().admit(&Key::Device(42), clock(4)),
        Admission::Allowed
    );
}

#[test]
fn sequence_rejection_with_live_lease_is_blocked() {
    // Mutation: using normal admission after Sequence bypasses a healthy lease.
    let f = Fixture::new();
    let _running = f.ticket(100, 100);
    let before = fs::read(f.dir().join(store::RECORD)).unwrap();
    assert!(matches!(f.begin(1, 101), Decision::Blocked));
    assert_eq!(fs::read(f.dir().join(store::RECORD)).unwrap(), before);
    assert!(matches!(
        f.begin(1, 100 + breaker::LEASE_NS),
        Decision::Run(None)
    ));
    assert_eq!(fs::read(f.dir().join(store::RECORD)).unwrap(), before);
}

#[test]
fn shared_session_stale_sequence_runs_unblocked_collection() {
    // Mutation: mapping Sequence to Deferred starves shells with cached init.
    let f = Fixture::new();
    f.ticket(100, 100)
        .finish(Progress::default(), EndReason::Complete, clock(100))
        .unwrap();
    let before = fs::read(f.dir().join(store::RECORD)).unwrap();
    assert!(matches!(f.begin(1, 101), Decision::Run(None)));
    assert_eq!(fs::read(f.dir().join(store::RECORD)).unwrap(), before);
    // A live healthy lease and an expired block requiring a probe must not be
    // bypassed by an untracked, stale-sequence collector.
    let _live = f.ticket(101, 102);
    assert!(matches!(f.begin(1, 102), Decision::Blocked));
    assert!(matches!(
        f.begin(1, 102 + breaker::LEASE_NS),
        Decision::Run(None)
    ));
    drop(f);
    let f = Fixture::new();
    f.trip();
    assert!(matches!(f.begin(1, 3), Decision::Blocked));
    assert!(matches!(
        f.begin(1, 3 + breaker::BLOCK_NS),
        Decision::Blocked
    ));
}

#[test]
fn breaker_io_releases_gc_registration_for_concurrent_store_admission() {
    // Mutation: keeping registration alive across load/save makes this Busy.
    let f = Fixture::new();
    f.ticket(1, 1)
        .finish(Progress::default(), EndReason::Complete, clock(1))
        .unwrap();
    for skip in 0..3 {
        let runtime = f.runtime.try_clone().unwrap();
        store::fixture_before_io(skip, move || {
            std::thread::spawn(move || {
                let response =
                    response_store(&runtime, format!("/concurrent-{skip}").as_bytes(), 2);
                assert!(
                    response.is_ok(),
                    "store admission during breaker I/O: {:?}",
                    response.err()
                );
            })
            .join()
            .unwrap();
        });
        f.ticket(2 + skip as u64, 2 + skip as u64)
            .finish(
                Progress::default(),
                EndReason::Complete,
                clock(2 + skip as u64),
            )
            .unwrap();
    }
}

#[test]
fn e3_gc_inventory_counts_actual_control_bytes_and_tolerates_corrupt_records() {
    // Mutation: fixed 2 * MAX_BYTES reservations consume the response budget
    // after 15 sessions, despite the records each occupying only 4 KiB.
    let f = Fixture::new();
    for i in 0..24 {
        let session = format!("{i:032x}");
        assert!(matches!(
            store::fixture_begin(
                &f.runtime,
                Some(session.as_bytes()),
                Some(i),
                b"/repo",
                clock(i)
            ),
            Decision::Run(Some(_))
        ));
    }
    let sessions = f.root.join(store::ROOT).join("sessions");
    assert_eq!(fs::read_dir(&sessions).unwrap().count(), 24);
    drop(response_store(&f.runtime, b"/response", 24).unwrap());
    f.gc(clock(25));
    assert_eq!(
        fs::read_dir(&sessions).unwrap().count(),
        24,
        "preserve live leases"
    );
    fs::remove_file(f.root.join(".collections.catalog")).unwrap();
    // With no catalog, admission starts bounded inventory; a budget yield
    // checkpoints it before GC can resume (GC alone has no catalog to load).
    match response_store(&f.runtime, b"/after-rebuild", 27) {
        Ok(store) => drop(store),
        Err(StoreError::Busy) => {
            f.gc(clock(27));
            drop(response_store(&f.runtime, b"/after-rebuild", 27).unwrap());
        }
        Err(error) => panic!("rebuild: {error:?}"),
    }
    assert_eq!(fs::read_dir(&sessions).unwrap().count(), 24);
    let first = sessions.join(format!("{:032x}", 0));
    fs::write(first.join(store::RECORD), b"torn").unwrap();
    f.gc(clock(breaker::LEASE_NS + 28));
    assert!(!first.exists());
    assert!(matches!(
        f.begin(29, breaker::LEASE_NS + 29),
        Decision::Run(Some(_))
    ));
}

#[test]
fn breaker_growth_is_charged_before_each_write_and_budget_is_unchanged() {
    // Mutation: omitting the pre-write catalog charge lets a second large
    // record grow past the shared 10,000,000-byte bound.
    // Mutation: rounding down undercharges every non-page-aligned record.
    for (len, expected) in [
        (0, 0),
        (1, 4096),
        (4096, 4096),
        (4097, 8192),
        (262_144, 262_144),
    ] {
        assert_eq!(store::rounded_size(len), expected);
    }
    let f = Fixture::new();
    let mut stores = Vec::new();
    for i in 0..7 {
        stores.push(response_store(&f.runtime, format!("/store-{i}").as_bytes(), 1).unwrap());
    }
    for i in 0..2 {
        let session = format!("{i:032x}");
        for seq in 1..=3 {
            let mut cwd = format!("/{seq}/").into_bytes();
            cwd.resize(65_536, b'x');
            let decision = store::fixture_begin(
                &f.runtime,
                Some(session.as_bytes()),
                Some(seq),
                &cwd,
                clock(seq),
            );
            if i == 1 && seq == 2 {
                assert!(matches!(decision, Decision::Run(None)));
                let dir = f.root.join(store::ROOT).join("sessions").join(&session);
                let record = Breaker::decode(&fs::read(dir.join(store::RECORD)).unwrap()).unwrap();
                assert_eq!(
                    record.used(),
                    clock(1),
                    "denied growth must preserve old record"
                );
                return;
            }
            let Decision::Run(Some(ticket)) = decision else {
                panic!("expected capacity for session {i}, sequence {seq}")
            };
            ticket
                .finish(Progress::default(), EndReason::Complete, clock(seq))
                .unwrap();
        }
    }
    panic!("budget should refuse growth");
}

#[test]
fn rebuilt_inventory_admits_response_without_a_reclaim_sweep() {
    // Mutation: charging capped sizes during inventory starves admission even
    // when actual payloads are small and no reclaim sweep has run yet.
    let f = Fixture::new();
    for i in 0..16 {
        let session = format!("{i:032x}");
        assert!(matches!(
            store::fixture_begin(
                &f.runtime,
                Some(session.as_bytes()),
                Some(i),
                b"/repo",
                clock(i)
            ),
            Decision::Run(Some(_))
        ));
    }
    fs::remove_file(f.root.join(".collections.catalog")).unwrap();
    for _ in 0..40 {
        match response_store(&f.runtime, b"/inventory-only", 20) {
            Ok(_) => return,
            Err(StoreError::Busy) => continue,
            Err(error) => panic!("inventory admission: {error:?}"),
        }
    }
    panic!("small records must leave capacity without reclamation");
}

#[test]
fn gc_preserves_large_live_breaker_under_response_pressure() {
    // Mutation: omitting breaker.live evicts a valid lease when the response
    // budget is full; small-record accounting must retain this protection.
    let f = Fixture::new();
    let mut stores = Vec::new();
    for i in 0..7 {
        stores.push(response_store(&f.runtime, format!("/store-{i}").as_bytes(), 1).unwrap());
    }
    for seq in 1..=3 {
        let mut cwd = format!("/{seq}/").into_bytes();
        cwd.resize(65_536, b'x');
        let Decision::Run(Some(ticket)) =
            store::fixture_begin(&f.runtime, Some(SESSION), Some(seq), &cwd, clock(seq))
        else {
            panic!("large record admission")
        };
        ticket
            .finish(Progress::default(), EndReason::Complete, clock(seq))
            .unwrap();
    }
    let live = f.ticket(4, 4);
    f.gc(clock(4));
    assert!(
        f.dir().join(store::RECORD).exists(),
        "GC must preserve the live lease under pressure"
    );
    live.finish(Progress::default(), EndReason::Complete, clock(5))
        .unwrap();
    f.gc(clock(5));
    assert!(
        !f.dir().exists(),
        "unleased record remains reclaimable under pressure"
    );
}

#[test]
#[ignore = "release warm 200-run observations, run explicitly"]
fn e3_release_cost() {
    fn report(name: &str, mut samples: Vec<u128>, bytes: u64) {
        samples.sort();
        let mean = samples.iter().sum::<u128>() as f64 / samples.len() as f64;
        let variance = samples
            .iter()
            .map(|&n| (n as f64 - mean).powi(2))
            .sum::<f64>()
            / samples.len() as f64;
        eprintln!(
            "E3 {name} runs={} p50={}ns p95={}ns variance={}ns2 bytes={bytes}",
            samples.len(),
            samples[100],
            samples[190],
            variance
        );
    }
    let f = Fixture::new();
    let start = std::time::Instant::now();
    f.ticket(0, 0)
        .finish(Progress::default(), EndReason::Complete, clock(0))
        .unwrap();
    eprintln!("E3 cold={}ns", start.elapsed().as_nanos());
    for mode in [
        "normal",
        "missing",
        "blocked",
        "probe",
        "failed_write",
        "busy",
        "domain",
        "sequence",
        "lease",
        "healthy_device_lease",
        "64keys",
        "large",
    ] {
        let mut samples = Vec::new();
        for i in 1..=220u64 {
            let mut state = Breaker::new(clock(0));
            match mode {
                "blocked" | "probe" => {
                    for seq in 1..=3 {
                        state
                            .observe(
                                Key::cwd(b"/repo").unwrap(),
                                seq,
                                Progress::default(),
                                EndReason::Deadline,
                                clock(seq),
                            )
                            .unwrap();
                    }
                }
                "sequence" | "lease" => {
                    if mode == "lease" {
                        state
                            .reserve(&Key::cwd(b"/repo").unwrap(), 5000, clock(0))
                            .unwrap();
                    } else {
                        state
                            .observe(
                                Key::cwd(b"/repo").unwrap(),
                                5000,
                                Progress::default(),
                                EndReason::Complete,
                                clock(0),
                            )
                            .unwrap();
                    }
                }
                "healthy_device_lease" => {
                    let a = Key::cwd(b"/a").unwrap();
                    for (seq, key) in [(0, a.clone()), (1, Key::cwd(b"/repo").unwrap())] {
                        state
                            .observe(
                                key,
                                seq,
                                Progress {
                                    stage_a_complete: true,
                                    device: Some(42),
                                },
                                EndReason::Complete,
                                clock(seq),
                            )
                            .unwrap();
                    }
                    assert_eq!(state.reserve(&a, 2, clock(2)), Ok(Admission::Allowed));
                }
                "domain" => {
                    state = Breaker::new(Clock {
                        domain: [9; 16],
                        ..clock(0)
                    })
                }
                "64keys" => {
                    for seq in 0..64 {
                        state
                            .observe(
                                Key::Device(seq),
                                seq,
                                Progress::default(),
                                EndReason::Complete,
                                clock(seq),
                            )
                            .unwrap();
                    }
                }
                "large" => {
                    for seq in 0..3 {
                        let mut pwd = format!("/{seq}/").into_bytes();
                        pwd.resize(65_536, b'a');
                        state
                            .observe(
                                Key::cwd(&pwd).unwrap(),
                                seq,
                                Progress::default(),
                                EndReason::Complete,
                                clock(seq),
                            )
                            .unwrap();
                    }
                }
                _ => {}
            }
            fs::write(f.dir().join(store::RECORD), state.encode().unwrap()).unwrap();
            if mode == "failed_write" {
                symlink(f.root.join("absent"), f.dir().join(store::STAGE)).unwrap();
            }
            let now = if mode == "probe" {
                breaker::BLOCK_NS + 3
            } else {
                100
            };
            let busy = if mode == "busy" {
                Some(
                    collection_store::close_only_lock(
                        &File::open(f.dir()).unwrap(),
                        store::LOCK,
                        sys::current_uid(),
                        false,
                    )
                    .unwrap(),
                )
            } else {
                None
            };
            let start = std::time::Instant::now();
            let decision = store::begin(
                &f.runtime,
                if mode == "missing" {
                    None
                } else {
                    Some(SESSION)
                },
                Some(1000 + i),
                b"/repo",
                clock(now),
            );
            match (mode, decision) {
                ("blocked" | "lease", Decision::Blocked)
                | ("busy", Decision::Deferred)
                | ("missing" | "failed_write" | "domain" | "sequence", Decision::Run(None)) => {}
                (_, Decision::Run(Some(t))) => t
                    .finish(Progress::default(), EndReason::Complete, clock(now))
                    .unwrap(),
                _ => panic!("benchmark admission: {mode}"),
            }
            if i > 20 {
                samples.push(start.elapsed().as_nanos());
            }
            drop(busy);
            if mode == "failed_write" {
                fs::remove_file(f.dir().join(store::STAGE)).unwrap();
            }
        }
        report(
            mode,
            samples,
            fs::metadata(f.dir().join(store::RECORD)).unwrap().len(),
        );
    }
    let mut samples = Vec::new();
    for i in 1..=220 {
        // Fresh state before each timed reclamation; no wall-clock deadline in
        // the functional GC fixture, whose operation cap is still unchanged.
        fs::remove_file(f.dir().join(store::RECORD)).unwrap();
        f.ticket(10_000 + i, 100)
            .finish(Progress::default(), EndReason::Complete, clock(100))
            .unwrap();
        let start = std::time::Instant::now();
        f.gc(clock(86_400_000_000_100));
        if i > 20 {
            samples.push(start.elapsed().as_nanos());
        }
        assert!(!f.dir().exists());
        // Recreate outside the measured window for the next iteration.
        f.ticket(20_000 + i, 100)
            .finish(Progress::default(), EndReason::Complete, clock(100))
            .unwrap();
    }
    report("gc-expired", samples, 0);
}

#[test]
fn e3_verified_no_repo_and_a_only_complete_reset_but_hidden_progress_does_not() {
    use bingsu_core::{
        collection::{
            git,
            wire::{
                self, Binding, BuildId, Frame, Kind, ProtocolError, Request, Transcript, Update,
            },
        },
        field::{Field, FieldValue},
        snapshot::{self, Identity},
    };
    let f = Fixture::new();
    let request = Request {
        request_id: wire::M3B_REQUEST_ID,
        binding: Binding {
            build_id: BuildId([7; 32]),
            snapshot: Identity {
                boot: [1; 16],
                epoch: [2; 16],
                generation: 1,
                source: [3; 4],
                context: snapshot::context_crc(b"/c", b"/s").unwrap(),
            },
            clock_kind: 1,
            domain: [2; 16],
            resume: 0,
            config: b"/c".to_vec(),
            state: b"/s".to_vec(),
            cwd: b"/repo".to_vec(),
            mask: 8,
            path_query: Default::default(),
        },
        budget_ms: 50,
        environment: vec![],
        global_excludes_known: true,
        global_excludes: vec![],
    };
    for (seq, mode) in ["hidden", "no_repo", "a_only", "constructor_failure"]
        .into_iter()
        .enumerate()
    {
        let now = (seq + 1) as u64;
        let ticket = f.ticket(now, now);
        let mut t = Transcript::new(&request);
        fn frame<'a>(request: &Request, kind: Kind, payload: &'a [u8]) -> Frame<'a> {
            Frame {
                kind,
                build_id: request.binding.build_id,
                request_id: request.request_id,
                payload,
            }
        }
        let mut ready = wire::FEATURES.to_le_bytes().to_vec();
        ready.extend(8u32.to_le_bytes());
        ready.extend([0; 12]);
        t.accept(frame(&request, Kind::Ready, &ready)).unwrap();
        t.request_sent().unwrap();
        let progress = Progress {
            stage_a_complete: false,
            device: Some(7),
        };
        t.accept(frame(&request, Kind::Progress, &progress.encode()))
            .unwrap();
        let value = match mode {
            "hidden" => None,
            "no_repo" => Some(git::no_repo()),
            _ => {
                let mut value = git::no_repo();
                let decl = &bingsu_core::field::BUILTIN[3];
                value.fields[decl.field_index("no_repo").unwrap()] = Field::ABSENT;
                value.fields[decl.field_index("detached").unwrap()] =
                    Field::known(FieldValue::Bool(false));
                value.fields[decl.field_index("partial").unwrap()] =
                    Field::known(FieldValue::Bool(true));
                Some(value)
            }
        };
        t.accept(frame(
            &request,
            Kind::Update,
            &Update {
                segment: 3,
                value,
                facts: None,
            }
            .encode(&request.binding)
            .unwrap(),
        ))
        .unwrap();
        let result = t.accept(frame(
            &request,
            Kind::Progress,
            &Progress {
                stage_a_complete: true,
                ..progress
            }
            .encode(),
        ));
        if mode == "hidden" {
            assert_eq!(result, Err(ProtocolError::Order));
        } else {
            result.unwrap();
        }
        let reason = if mode == "constructor_failure" {
            t.accept(frame(&request, Kind::Complete, &[])).unwrap();
            EndReason::Complete
        } else {
            EndReason::Deadline
        };
        let completed = t.finish(reason, clock(now)).unwrap().unwrap();
        assert_eq!(completed.progress.stage_a_complete, mode != "hidden");
        let report = commands::collector_supervisor::SupervisionReport {
            reason,
            progress: completed.progress,
            bytes: 0,
            frames: 0,
            kill_requested: false,
            reaped: true,
            published: true,
            lifecycle: Default::default(),
            unconfined_reads: 0,
            unconfined_decodes: 0,
        };
        let (progress, reason) = report.breaker_observation();
        ticket.finish(progress, reason, clock(now)).unwrap();
        assert_eq!(
            f.read().admit(&Key::cwd(b"/repo").unwrap(), clock(now)),
            Admission::Allowed
        );
    }
    // Two missing-A deadlines after verified A remain below the threshold.
    for seq in 5..=6 {
        f.ticket(seq, seq)
            .finish(
                Progress {
                    stage_a_complete: false,
                    device: Some(7),
                },
                EndReason::Deadline,
                clock(seq),
            )
            .unwrap();
    }
    assert!(matches!(f.begin(7, 7), Decision::Run(Some(_))));
}

#[test]
fn e3_record_metadata_and_corruption_disable_only_breaker() {
    for mode in ["symlink", "hardlink", "oversize", "corrupt", "directory"] {
        let f = Fixture::new();
        f.ticket(1, 1)
            .finish(Progress::default(), EndReason::Complete, clock(1))
            .unwrap();
        let record = f.dir().join(store::RECORD);
        let before = fs::read(&record).unwrap();
        let canary = f.root.join("outside");
        fs::write(&canary, &before).unwrap();
        fs::set_permissions(&canary, fs::Permissions::from_mode(0o600)).unwrap();
        fs::remove_file(&record).unwrap();
        match mode {
            "symlink" => symlink(&canary, &record).unwrap(),
            "hardlink" => fs::hard_link(&canary, &record).unwrap(),
            "directory" => fs::create_dir(&record).unwrap(),
            "oversize" => fs::write(&record, vec![0; breaker::MAX_BYTES + 1]).unwrap(),
            _ => fs::write(&record, b"invalid").unwrap(),
        }
        assert!(matches!(f.begin(2, 2), Decision::Run(None)), "{mode}");
        assert_eq!(fs::read(canary).unwrap(), before);
    }
}

#[test]
#[ignore = "explicit syscall tracing fixture; no collector or front process"]
fn e3_syscall_trace() {
    let f = Fixture::new();
    f.ticket(1, 1)
        .finish(Progress::default(), EndReason::Complete, clock(1))
        .unwrap();
    eprintln!("E3_TRACE_BEGIN");
    let Decision::Run(Some(ticket)) =
        store::begin(&f.runtime, Some(SESSION), Some(2), b"/repo", clock(2))
    else {
        panic!("trace admission");
    };
    ticket
        .finish(Progress::default(), EndReason::Complete, clock(2))
        .unwrap();
    eprintln!("E3_TRACE_END");
}

#[test]
fn e3_reads_and_writes_are_one_kib_units_and_cap_precedes_read() {
    let f = Fixture::new();
    f.ticket(1, 1)
        .finish(Progress::default(), EndReason::Complete, clock(1))
        .unwrap();
    let mut large = Breaker::new(clock(0));
    for seq in 0..3 {
        let mut path = format!("/{seq}/").into_bytes();
        path.resize(65_536, b'x');
        large
            .observe(
                Key::cwd(&path).unwrap(),
                seq,
                Progress::default(),
                EndReason::Complete,
                clock(seq),
            )
            .unwrap();
    }
    let before = large.encode().unwrap();
    fs::write(f.dir().join(store::RECORD), &before).unwrap();
    store::fixture_io();
    f.ticket(100, 100)
        .finish(Progress::default(), EndReason::Complete, clock(100))
        .unwrap();
    let counts = store::fixture_io();
    let after = fs::read(f.dir().join(store::RECORD)).unwrap().len();
    assert_eq!(counts.reads, 1158);
    assert_eq!(counts.writes, 386);
    assert_eq!(counts.max_read, 1024);
    assert_eq!(counts.max_write, 1024);
    assert_eq!(counts.read_bytes, (2 * before.len() + 4 * after) as u64);
    assert_eq!(counts.write_bytes, (2 * after) as u64);
    eprintln!("E3 bounded I/O {counts:?}");
    fs::write(f.dir().join(store::RECORD), vec![0; 262_145]).unwrap();
    let dir = File::open(f.dir()).unwrap();
    assert!(matches!(
        store::read(&dir, store::RECORD, sys::current_uid()),
        Err(StoreError::Unsafe)
    ));
    assert_eq!(store::fixture_io().reads, 0);
}
