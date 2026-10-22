//! Native lifecycle tests use the exact command modules in a test-only target.
#![cfg(unix)]
#![allow(dead_code)]

#[path = "../src/commands/mod.rs"]
mod commands;
#[cfg(target_os = "linux")]
#[path = "../../bingsu-collect/src/filter.rs"]
mod filter;
#[cfg(target_os = "linux")]
#[path = "../../bingsu-collect/src/landlock.rs"]
mod landlock;
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
#[path = "../../bingsu-collect/src/sys.rs"]
#[allow(
    clippy::disallowed_methods,
    reason = "worker entry has its own policy, outside the prompt adapter"
)]
mod worker_sys;
#[cfg(not(target_os = "linux"))]
mod sandbox {
    pub fn enter() -> bingsu_core::front::Sandbox {
        bingsu_core::front::Sandbox::Absent
    }
}

use bingsu_core::{
    collection::{
        self,
        selection::Catalog,
        wire::{Binding, BuildId, EndReason, M3B_REQUEST_ID},
    },
    field::SegmentDecl,
    snapshot,
};
use commands::{
    collector_process,
    collector_supervisor::{CollectorJob, SupervisionReport},
    helper_limits,
};
use std::{
    ffi::OsStr,
    fs::{File, OpenOptions},
    io::Write,
    os::{fd::AsRawFd, unix::fs::PermissionsExt},
    path::PathBuf,
    process::Command,
    sync::{Arc, Mutex, OnceLock},
    time::{Duration, Instant},
};

const SEGMENTS: [SegmentDecl; 32] = [const {
    SegmentDecl {
        id: "fixture",
        role: "fg",
        fields: &[],
    }
}; 32];
const CATALOG: Catalog<'static> = Catalog {
    segments: &SEGMENTS,
    workers: 1 << 31,
};

// A deliberately untrusted pipe peer. No product switch can select this peer
// or catalog. Compilation belongs to the native Rust suite, never shell tests.
const PEER: &str = r#"
#include <stdint.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <signal.h>
#include <errno.h>
static unsigned char h[80], b[65536];
static void exact(int fd, void *p, size_t n) {
    while(n) { ssize_t k=read(fd,p,n); if(k<=0) _exit(31); p=(char*)p+k; n-=k; }
}
static void put(const void *p, size_t n) {
    while(n) { ssize_t k=write(1,p,n); if(k<=0) _exit(32); p=(char*)p+k; n-=k; }
}
static void header(int kind, uint32_t n) {
    memset(h,0,80); memcpy(h,"BNGIPC03",8); h[8]=3; h[10]=kind;
    memcpy(h+12,&n,4); memset(h+16,7,32);
}
static void frame(int kind, const void *p, uint32_t n) { header(kind,n); put(h,80); put(p,n); }
static void grow_memory(void) {
    char *memory=malloc(40*1024*1024);
    if(!memory) _exit(40);
    memset(memory,0x5a,40*1024*1024);
    asm volatile("" : : "r"(memory) : "memory");
    for(;;) pause();
}
int main(int argc, char **argv) {
    if(argc!=2) return 30;
    alarm(2);
    const char *mode=argv[1];
    if(!strcmp(mode,"exit")) return 0;
    if(!strcmp(mode,"idle")) { for(;;) pause(); }
    if(!strcmp(mode,"sample-memory")) {
        // Let the watchdog register its baseline before allocating.
        exact(3,b,1);
        grow_memory();
    }
    if((fcntl(1,F_GETFL)&O_ACCMODE)!=O_WRONLY ||
       (fcntl(3,F_GETFL)&O_ACCMODE)!=O_RDONLY ||
       (fcntl(5,F_GETFL)&O_ACCMODE)!=O_RDONLY) return 33;
    if(!strcmp(mode,"signals")) {
        sigset_t mask; struct sigaction a;
        sigprocmask(SIG_SETMASK,0,&mask); sigaction(SIGALRM,0,&a);
        if(sigismember(&mask,SIGALRM) || a.sa_handler!=SIG_DFL) return 34;
    }
    unsigned char ready[24]={3}; ready[11]=128;
    if(!strcmp(mode,"baseline") || !strcmp(mode,"memory")) memset(ready+16,255,8);
    if(!strcmp(mode,"drip")) {
        header(1,24);
        for(int i=0;i<80;i++) { put(h+i,1); usleep(49000); }
        return 35;
    }
    // Nonblocking read proves the helper sent zero bytes before Ready.
    int flags=fcntl(3,F_GETFL); fcntl(3,F_SETFL,flags|O_NONBLOCK);
    unsigned char probe; ssize_t n=read(3,&probe,1);
    if(n!=-1 || errno!=EAGAIN) return 36;
    fcntl(3,F_SETFL,flags);
    if(!strcmp(mode,"wrong-build")) {
        header(1,24); h[16]^=1; put(h,80); put(ready,24); for(;;) pause();
    }
    if(!strcmp(mode,"request-closed")) { close(3); frame(1,ready,24); for(;;) pause(); }
    frame(1,ready,24);
    uint32_t body=0;
    for(;;) {
        exact(3,h,80); uint32_t n; memcpy(&n,h+12,4);
        if(n>65456) return 37;
        exact(3,b,n);
        if(h[10]==3) body+=n-4;
        if(h[10]==4) break;
    }
    if(!strcmp(mode,"large") && body<=65536) return 38;
    if(!strcmp(mode,"empty")) { frame(6,0,0); return 0; }
    unsigned char update[]={31,0,1,2,0,0,0,'o','k',0,0,0};
    if(!strcmp(mode,"first-invalid")) update[2]=2;
    frame(5,update,sizeof(update));
    if(!strcmp(mode,"timeout")) { for(;;) pause(); }
    if(!strncmp(mode,"memory",6)) {
        grow_memory();
    }
    if(!strcmp(mode,"partial")) { header(5,11); put(h,17); return 0; }
    if(!strcmp(mode,"invalid-then-valid")) {
        update[2]=2; frame(5,update,sizeof(update));
        update[2]=1; update[7]='n'; frame(5,update,sizeof(update));
    }
    frame(6,0,0);
    if(!strcmp(mode,"complete-open")) { for(;;) pause(); }
    if(!strcmp(mode,"trailing")) put("x",1);
    if(!strcmp(mode,"complete-live")) { close(1); for(;;) pause(); }
    return 0;
}
"#;

fn peer() -> &'static PathBuf {
    static PATH: OnceLock<PathBuf> = OnceLock::new();
    PATH.get_or_init(|| {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../target")
            .join(format!("collector-lifecycle-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let dir = std::fs::canonicalize(dir).unwrap();
        let exe = dir.join("peer");
        let source = dir.join("peer.c");
        std::fs::write(&source, PEER).unwrap();
        let status = Command::new("cc")
            .args(["-O2", "-Wall", "-Werror", "-o"])
            .arg(&exe)
            .arg(&source)
            .status()
            .unwrap();
        assert!(status.success(), "native fixture must compile");
        exe
    })
}
fn lock(tag: &str) -> File {
    static SEQUENCE: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let path = peer().parent().unwrap().join(format!(
        "{tag}-{}",
        SEQUENCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&path)
        .unwrap();
    file.set_permissions(std::fs::Permissions::from_mode(0o600))
        .unwrap();
    drop(file);
    let file = File::open(path).unwrap();
    // SAFETY: test-owned read-only description, shared with only its worker.
    assert_eq!(
        // SAFETY: test-owned read-only description, shared with only its worker.
        unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
        0
    );
    file
}
fn request(large: bool) -> collection::wire::Request {
    let now = commands::collector_supervisor::fixture_clock().unwrap();
    let config = if large {
        let mut path = vec![b'c'; 65_536];
        path[0] = b'/';
        path
    } else {
        b"/c".to_vec()
    };
    let state = b"/s".to_vec();
    let binding = Binding {
        path_query: Default::default(),
        build_id: BuildId([7; 32]),
        snapshot: snapshot::Identity {
            boot: now.boot,
            epoch: [2; 16],
            generation: 1,
            source: [3; 4],
            context: snapshot::context_crc(&config, &state).unwrap(),
        },
        clock_kind: now.kind,
        domain: now.domain,
        resume: now.resume,
        config,
        state,
        cwd: b"/repo".to_vec(),
        mask: CATALOG.workers,
    };
    collection::request(&CATALOG, binding, M3B_REQUEST_ID, 50)
        .unwrap()
        .unwrap()
}
fn run_peer(mode: &str, allow: bool) -> (SupervisionReport, Vec<collection::response::Completed>) {
    let (report, values, _) = run_peer_observed(mode, allow);
    (report, values)
}
fn run_peer_observed(
    mode: &str,
    allow: bool,
) -> (
    SupervisionReport,
    Vec<collection::response::Completed>,
    Vec<(u64, u64, u64)>,
) {
    let exe = peer();
    let watchdog = helper_limits::start(Instant::now()).unwrap();
    let held_lock = lock(mode);
    let lock_started = Instant::now();
    let job = CollectorJob::fixture(
        exe.as_os_str(),
        OsStr::new(mode),
        request(mode == "large"),
        held_lock,
        &watchdog,
        &SEGMENTS,
    )
    .unwrap();
    let values = Arc::new(Mutex::new(Vec::new()));
    let results = values.clone();
    let handle = job
        .start(Box::new(move |value| {
            results.lock().unwrap().push(value);
            Ok(())
        }))
        .unwrap();
    if allow {
        handle.confirm_confinement().unwrap();
    } else {
        std::thread::sleep(Duration::from_millis(20));
        assert!(
            values.lock().unwrap().is_empty(),
            "publication preceded permission"
        );
    }
    let report = handle.finish();
    eprintln!(
        "lifecycle: lock_hold_ns={}",
        lock_started.elapsed().as_nanos()
    );
    let values = values.lock().unwrap().clone();
    #[cfg(target_os = "macos")]
    let observations = watchdog.observations.lock().unwrap().clone();
    #[cfg(not(target_os = "macos"))]
    let observations = Vec::new();
    (report, values, observations)
}

// 이것을 실패시키는 것: Ready 전 요청 송신, 큰 요청의 partial write 진행 또는 정상 EOF 수용 제거.
#[test]
fn request_waits_for_ready_and_pipes_are_backpressured() {
    let _inherited_fds = commands::sys::test_inherited_fd_lock();
    let (report, values) = run_peer("large", true);
    assert_eq!(report.reason, EndReason::Complete);
    assert!(report.reaped && !report.kill_requested, "{report:?}");
    assert_eq!((report.frames, report.bytes, values.len()), (3, 276, 1));
}

// 이것을 실패시키는 것: helper가 envelope home·compiled unique를 요청에 넣지 않거나 환경 항목으로 복원하는 것.
#[test]
fn helper_path_query_uses_envelope_and_compiled_policy() {
    use bingsu_core::{
        collection::{path_facts::PathQuery, selection::Catalog},
        color::palette::Mode,
        config::{
            compile::BUILTIN_TOML,
            report::report,
            source::{ExtendsRef, FileKey, OpenError, Opened, Resolver, Trust},
        },
        envelope::Envelope,
        shorten::Method,
    };
    struct NoSources;
    impl Resolver for NoSources {
        fn open(&mut self, _: &Opened, _: &ExtendsRef) -> Result<Opened, OpenError> {
            unreachable!()
        }
    }
    let mut config = report(
        vec![Opened {
            key: FileKey { dev: 1, ino: 1 },
            bytes: BUILTIN_TOML.as_bytes().to_vec(),
            trust: Trust::Executable,
            display: vec![],
        }],
        &mut NoSources,
        [0, 3, 0],
        Mode::Dark,
    )
    .snapshot
    .unwrap();
    let r = request(false);
    let catalog = Catalog {
        segments: bingsu_core::field::BUILTIN,
        workers: 2,
    };
    let mut envelope = Envelope {
        config_root: Some(r.binding.config.clone()),
        state_root: Some(r.binding.state.clone()),
        pwd: Some(b"/home/me/repo".to_vec()),
        width: 80,
        ..Envelope::default()
    };
    for home in [false, true] {
        for unique in [false, true] {
            envelope.home = home.then(|| b"/home/me".to_vec());
            config.setup[1].methods = if unique {
                vec![Method::Unique]
            } else {
                vec![Method::Abbrev(1)]
            };
            let selected = commands::helper::selected_request(
                &catalog,
                &envelope,
                Some((&config, r.binding.snapshot)),
                commands::collector_supervisor::fixture_clock().unwrap(),
            )
            .unwrap()
            .unwrap();
            assert_eq!(
                selected.binding.path_query,
                PathQuery {
                    home_component: home.then_some(1),
                    unique
                }
            );
            assert!(selected.environment.is_empty());
        }
    }
}

// 이것을 실패시키는 것: 첫 codec Err 뒤 계속 읽어 나중의 Update를 반영하는 것.
#[test]
fn partial_survives_only_after_validated_updates() {
    let _inherited_fds = commands::sys::test_inherited_fd_lock();
    for (mode, reason, count) in [
        ("normal", EndReason::Complete, 1),
        ("empty", EndReason::Complete, 0),
        ("first-invalid", EndReason::Protocol, 0),
        ("wrong-build", EndReason::Protocol, 0),
        ("request-closed", EndReason::WorkerExit, 0),
        ("partial", EndReason::Protocol, 1),
        ("timeout", EndReason::Deadline, 1),
        ("invalid-then-valid", EndReason::Protocol, 1),
        ("trailing", EndReason::Protocol, 1),
    ] {
        let (report, values) = run_peer(mode, true);
        assert_eq!(report.reason, reason, "{mode}: {report:?}");
        assert!(report.reaped, "{mode}");
        assert_eq!(values.len(), count, "{mode}");
        if let Some(value) = values.first() {
            assert_eq!(value.reason, reason);
            assert_eq!(value.updates[0].value.as_ref().unwrap().text(), "ok");
        }
    }
}

// 이것을 실패시키는 것: Complete 뒤 열린 pipe의 Deadline을 Complete로 보고하거나 저장하는 것.
#[test]
fn accepted_complete_without_eof_keeps_deadline_in_report_and_response() {
    let _inherited_fds = commands::sys::test_inherited_fd_lock();
    let (report, values) = run_peer("complete-open", true);
    assert!(report.lifecycle.completed.is_some(), "{report:?}");
    assert_eq!(report.reason, EndReason::Deadline, "{report:?}");
    assert!(report.reaped && report.kill_requested, "{report:?}");
    assert_eq!(values.len(), 1);
    assert_eq!(values[0].reason, EndReason::Deadline);
}

// 이것을 실패시키는 것: 바이트마다 Ready 절대 마감을 재시작하는 것.
#[test]
fn slow_drip_does_not_extend_spawn_deadline() {
    let _inherited_fds = commands::sys::test_inherited_fd_lock();
    peer();
    let start = Instant::now();
    let (report, values) = run_peer("drip", true);
    assert_eq!(report.reason, EndReason::Deadline);
    assert!(report.kill_requested && report.reaped);
    assert!(values.is_empty());
    assert!(start.elapsed() < Duration::from_millis(500));
}

// 이것을 실패시키는 것: Complete 뒤 살아 있는 자식의 감독 등록을 조기에 버리는 것.
#[test]
fn collector_termination_uses_stable_handle() {
    let _inherited_fds = commands::sys::test_inherited_fd_lock();
    passed(&isolated("stable_handle_child"));
}
#[test]
#[ignore = "pidfd signal and waitid must work after the real helper TSYNC filter"]
fn stable_handle_child() {
    peer();
    let watchdog = helper_limits::start(Instant::now()).unwrap();
    let job = CollectorJob::fixture(
        peer().as_os_str(),
        OsStr::new("complete-live"),
        request(false),
        lock("stable"),
        &watchdog,
        &SEGMENTS,
    )
    .unwrap();
    let values = Arc::new(Mutex::new(Vec::new()));
    let stored = values.clone();
    let handle = job
        .start(Box::new(move |value| {
            stored.lock().unwrap().push(value);
            Ok(())
        }))
        .unwrap();
    commands::helper_filter::install(handle.child_pidfd()).unwrap();
    handle.confirm_confinement().unwrap();
    let report = handle.finish();
    assert_eq!(report.reason, EndReason::Complete);
    assert!(report.kill_requested && report.reaped, "{report:?}");
    assert_eq!(values.lock().unwrap().len(), 1);
}

// 이것을 실패시키는 것: 허가 전 발행 또는 handle Drop의 취소·종료 요청 제거.
#[test]
fn helper_filter_failure_cannot_race_publication() {
    let _inherited_fds = commands::sys::test_inherited_fd_lock();
    let (_, values) = run_peer("normal", false);
    assert!(values.is_empty());
}

// 이것을 실패시키는 것: 허가 전 read/decode, 정상 완료 누락, Ready 전 마감이 아닌 실패를 재시도로 숨기는 것.
#[test]
fn immediate_ready_is_not_read_or_decoded_before_confinement() {
    let _inherited_fds = commands::sys::test_inherited_fd_lock();
    let mut deadlines = 0;
    // Limits and TSYNC are irreversible (Linux forbids the next spawn), so
    // every attempt needs a fresh isolated process, including after Deadline.
    for attempt in 1..=3 {
        let out = isolated("immediate_ready_child");
        eprintln!(
            "immediate Ready attempt {attempt}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        // A security assertion or any unexpected outcome fails immediately.
        passed(&out);
        let stdout = String::from_utf8_lossy(&out.stdout);
        if stdout
            .lines()
            .any(|line| line == "immediate Ready: Complete")
        {
            eprintln!(
                "immediate Ready: Complete after {attempt} attempt(s), {deadlines} Ready deadline(s)"
            );
            return;
        }
        assert!(
            stdout
                .lines()
                .any(|line| line == "immediate Ready: Deadline"),
            "{out:?}"
        );
        deadlines += 1;
        eprintln!("immediate Ready: {deadlines} Ready deadline(s)");
    }
    panic!("immediate Ready: no Complete in 3 attempts ({deadlines} Ready deadlines)");
}
#[test]
#[ignore = "installs irreversible helper limits and filter"]
fn immediate_ready_child() {
    let job_peer = peer();
    // Warm and reap this freshly built/copied executable before the measured
    // spawn: first-exec loader/code-signing cost is unrelated to the read gate.
    assert!(
        Command::new(job_peer)
            .arg("exit")
            .status()
            .unwrap()
            .success()
    );
    let watchdog = helper_limits::start(Instant::now()).unwrap();
    let queued_until = Instant::now() + Duration::from_millis(100);
    let job = CollectorJob::fixture(
        job_peer.as_os_str(),
        OsStr::new("normal"),
        request(false),
        lock("confined"),
        &watchdog,
        &SEGMENTS,
    )
    .unwrap();
    let input = job.fixture_input().unwrap();
    let mut pollfd = libc::pollfd {
        fd: input.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // Return as soon as Ready is queued. A cold/overloaded worker can exhaust
    // the unchanged spawn+100ms budget here; validate that outcome below too.
    // SAFETY: live pipe and initialized pollfd; this observes but never reads.
    assert!(unsafe { libc::poll(&mut pollfd, 1, 100) } >= 0);
    let queued_bytes = || {
        let mut bytes: libc::c_int = 0;
        // SAFETY: live pipe and writable integer; FIONREAD never consumes data.
        assert_eq!(
            // SAFETY: live pipe and writable integer; no data is consumed.
            unsafe { libc::ioctl(input.as_raw_fd(), libc::FIONREAD, &mut bytes) },
            0
        );
        bytes
    };
    // POLLIN can arrive between the peer's header and payload writes.
    let queued = loop {
        let bytes = queued_bytes();
        if bytes == 104 || Instant::now() >= queued_until {
            break bytes;
        }
        std::thread::sleep(Duration::from_millis(1));
    };
    let handle = job.start(Box::new(|_| Ok(()))).unwrap();
    // A full Ready (80-byte header + 24-byte payload) must remain untouched
    // while the runnable supervisor gets two scheduling opportunities. Bound
    // this observation to 2ms instead of spending a fixed 20ms of Ready's
    // budget; the report counters also catch partial reads and decode attempts.
    let mut untouched = true;
    for _ in 0..2 {
        std::thread::sleep(Duration::from_millis(1));
        if queued == 104 {
            untouched &= queued_bytes() == queued;
        }
    }
    helper_limits::install(&watchdog).unwrap();
    commands::helper_filter::install(handle.child_pidfd()).unwrap();
    if queued == 104 {
        untouched &= queued_bytes() == queued;
    }
    let confirming_ns = collector_process::now_ns().unwrap();
    handle.confirm_confinement().unwrap();
    let report = handle.finish();
    // These checks precede outcome classification on EVERY attempt: Deadline
    // must never turn an unconfined read/decode into an acceptable retry.
    assert_eq!(report.unconfined_reads, 0, "{report:?}");
    assert_eq!(report.unconfined_decodes, 0, "{report:?}");
    assert!(
        untouched,
        "Ready was read before confirm_confinement: {report:?}"
    );
    assert!(
        report
            .lifecycle
            .ready
            .is_none_or(|ready| ready >= confirming_ns),
        "Ready decoded before confirm_confinement: {report:?}"
    );
    let spawn = report.lifecycle.spawn_enter.unwrap();
    let ready_deadline = spawn + 100_000_000;
    eprintln!(
        "immediate Ready: reason={:?}, spawn_to_ready_ns={:?}, spawn_to_lock_close_ns={:?}, ready_deadline_ns={ready_deadline}",
        report.reason,
        report.lifecycle.ready.map(|ready| ready - spawn),
        report.lifecycle.lock_closed.map(|closed| closed - spawn),
    );
    assert!(report.reaped, "{report:?}");
    match report.reason {
        EndReason::Complete => {
            assert_eq!(
                queued, 104,
                "successful attempt must expose queued Ready before supervision"
            );
            assert_eq!(report.frames, 3, "{report:?}");
            assert!(report.bytes > 0, "{report:?}");
            println!("\nimmediate Ready: Complete");
        }
        EndReason::Deadline => {
            assert!(
                report
                    .lifecycle
                    .ready
                    .is_none_or(|ready| ready > ready_deadline),
                "Deadline after an on-time Ready is not a startup retry: {report:?}"
            );
            assert!(report.kill_requested, "{report:?}");
            println!("\nimmediate Ready: Deadline");
        }
        _ => panic!("unexpected immediate Ready outcome: {report:?}"),
    }
}

// 이것을 실패시키는 것: confinement 대기의 만료 또는 읽기 전 gate를 제거하는 것.
#[test]
fn stalled_confinement_expires_without_reading_ready() {
    let _inherited_fds = commands::sys::test_inherited_fd_lock();
    let job_peer = peer();
    let watchdog = helper_limits::start(Instant::now()).unwrap();
    let job = CollectorJob::fixture(
        job_peer.as_os_str(),
        OsStr::new("normal"),
        request(false),
        lock("confinement-timeout"),
        &watchdog,
        &SEGMENTS,
    )
    .unwrap();
    let handle = job
        .start(Box::new(|_| panic!("unconfined publication")))
        .unwrap();
    // The product still expires at spawn+100ms (also checked by the pure
    // deadline tests). Allow scheduling and reaping to finish on a busy runner;
    // permission stays Pending throughout, so finishing cannot cancel the wait.
    let end = Instant::now() + Duration::from_secs(1);
    while !handle.fixture_finished() {
        assert!(Instant::now() < end, "unconfined supervisor did not finish");
        std::thread::sleep(Duration::from_millis(5));
    }
    // Late confirmation must not restart the Ready deadline.
    handle.confirm_confinement().unwrap();
    let report = handle.finish();
    assert_eq!(report.reason, EndReason::Deadline, "{report:?}");
    assert_eq!((report.bytes, report.frames), (0, 0));
    assert_eq!((report.unconfined_reads, report.unconfined_decodes), (0, 0));
    assert!(report.kill_requested && report.reaped);
}

// 이것을 실패시키는 것: 조기 종료 후 재회수하거나 회수 뒤 숫자 PID로 signal하는 것.
#[test]
fn early_exit_never_signals_recycled_pid() {
    let _inherited_fds = commands::sys::test_inherited_fd_lock();
    let (read, write) = collector_process::pipe().unwrap();
    let (response, result) = collector_process::pipe().unwrap();
    let lock = lock("early");
    let mut child = collector_process::spawn_args(
        peer().as_os_str(),
        &[OsStr::new("exit")],
        &read,
        &result,
        &lock,
        collector_process::now_ns().unwrap() + 1_000_000_000,
    )
    .unwrap();
    let copy = child.signal_copy().unwrap();
    let end = Instant::now() + Duration::from_secs(1);
    while !child.reap().unwrap() {
        assert!(Instant::now() < end);
        std::thread::yield_now();
    }
    copy.signal(libc::SIGKILL).unwrap();
    assert!(!child.kill_requested());
    assert!(child.reap().unwrap());
    drop((write, response));
}

// 이것을 실패시키는 것: Ready의 worker 제공 baseline으로 감독자의 메모리 여유를 늘리는 것.
#[test]
fn ready_cannot_raise_the_memory_allowance() {
    let _inherited_fds = commands::sys::test_inherited_fd_lock();
    let (report, values) = run_peer("baseline", true);
    assert_eq!(report.reason, EndReason::Complete);
    assert_eq!(values.len(), 1);
    #[cfg(target_os = "macos")]
    for mode in ["memory", "memory-low"] {
        let (report, values) = run_peer(mode, true);
        assert_eq!(report.reason, EndReason::Resource);
        assert!(report.kill_requested && report.reaped);
        assert_eq!(values.len(), 1);
    }
}

fn isolated(name: &str) -> std::process::Output {
    Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            name,
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .output()
        .unwrap()
}
fn passed(out: &std::process::Output) {
    assert!(
        out.status.success()
            && String::from_utf8_lossy(&out.stdout)
                .contains("test result: ok. 1 passed; 0 failed;"),
        "{out:?}"
    );
}

// 이것을 실패시키는 것: SETSIGMASK 또는 SETSIGDEF를 없애거나 부모 신호 상태를 바꾸는 것.
#[test]
fn blocked_or_ignored_sigalrm_is_reset_at_spawn() {
    let _inherited_fds = commands::sys::test_inherited_fd_lock();
    passed(&isolated("inherited_alarm_child"));
}
#[test]
#[ignore = "isolates inherited process signal dispositions"]
fn inherited_alarm_child() {
    peer();
    for (blocked, ignored) in [(true, false), (false, true), (true, true)] {
        // SAFETY: initialized signal storage in an isolated process.
        let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
        action.sa_sigaction = if ignored {
            libc::SIG_IGN
        } else {
            libc::SIG_DFL
        };
        // SAFETY: writable mask.
        assert_eq!(unsafe { libc::sigemptyset(&mut action.sa_mask) }, 0);
        // SAFETY: isolated parent's SIGALRM disposition.
        assert_eq!(
            // SAFETY: isolated parent's SIGALRM disposition.
            unsafe { libc::sigaction(libc::SIGALRM, &action, std::ptr::null_mut()) },
            0
        );
        let mut mask = action.sa_mask;
        // SAFETY: initialized mask and valid signal.
        assert_eq!(unsafe { libc::sigaddset(&mut mask, libc::SIGALRM) }, 0);
        // SAFETY: isolated parent's thread signal mask.
        assert_eq!(
            // SAFETY: isolated parent's thread signal mask.
            unsafe {
                libc::pthread_sigmask(
                    if blocked {
                        libc::SIG_BLOCK
                    } else {
                        libc::SIG_UNBLOCK
                    },
                    &mask,
                    std::ptr::null_mut(),
                )
            },
            0
        );
        let (report, values) = run_peer("signals", true);
        assert_eq!(report.reason, EndReason::Complete);
        assert_eq!(values.len(), 1);
        // SAFETY: output pointers refer to valid initialized storage.
        assert_eq!(
            // SAFETY: output pointers refer to valid initialized storage.
            unsafe { libc::sigaction(libc::SIGALRM, std::ptr::null(), &mut action) },
            0
        );
        assert_eq!(
            action.sa_sigaction,
            if ignored {
                libc::SIG_IGN
            } else {
                libc::SIG_DFL
            }
        );
        // SAFETY: read-only mask query into valid storage.
        assert_eq!(
            // SAFETY: read-only mask query into valid storage.
            unsafe { libc::pthread_sigmask(libc::SIG_SETMASK, std::ptr::null(), &mut mask) },
            0
        );
        // SAFETY: initialized mask.
        assert_eq!(
            // SAFETY: initialized mask.
            unsafe { libc::sigismember(&mask, libc::SIGALRM) } == 1,
            blocked
        );
    }
}

// 이것을 실패시키는 것: 자기 SIGKILL 허용을 지워 watchdog이 _exit fallback으로 끝나는 것.
#[test]
fn helper_watchdog_self_sigkill_still_works() {
    let _inherited_fds = commands::sys::test_inherited_fd_lock();
    use std::os::unix::process::ExitStatusExt;
    let out = isolated("filtered_watchdog_child");
    assert_eq!(out.status.signal(), Some(libc::SIGKILL), "{out:?}");
    assert!(String::from_utf8_lossy(&out.stdout).contains("watchdog armed"));
}
#[test]
#[ignore = "intentionally killed under the helper filter"]
fn filtered_watchdog_child() {
    let _watchdog = helper_limits::start(Instant::now() - Duration::from_millis(1750)).unwrap();
    commands::helper_filter::install(None).unwrap();
    println!("watchdog armed");
    std::io::stdout().flush().unwrap();
    std::thread::sleep(Duration::from_secs(3));
    panic!("watchdog did not terminate");
}

// 이것을 실패시키는 것: publisher가 막힐 때 독립 collector/helper 종료 감시를 중단하는 것.
#[test]
fn publisher_stall_does_not_stop_watchdog() {
    let _inherited_fds = commands::sys::test_inherited_fd_lock();
    use std::os::unix::process::ExitStatusExt;
    let start = Instant::now();
    let out = isolated("stalled_publisher_child");
    assert_eq!(out.status.signal(), Some(libc::SIGKILL), "{out:?}");
    assert!(String::from_utf8_lossy(&out.stdout).contains("publisher entered"));
    assert!(start.elapsed() < Duration::from_secs(2));
}
#[test]
#[ignore = "publisher stalls while a live collector retains its lock"]
fn stalled_publisher_child() {
    let exe = peer();
    let watchdog = helper_limits::start(Instant::now() - Duration::from_millis(1500)).unwrap();
    let job = CollectorJob::fixture(
        exe.as_os_str(),
        OsStr::new("complete-live"),
        request(false),
        lock("publisher"),
        &watchdog,
        &SEGMENTS,
    )
    .unwrap();
    let handle = job
        .start(Box::new(|_| {
            println!("publisher entered");
            std::io::stdout().flush().unwrap();
            std::thread::sleep(Duration::from_secs(3));
            Ok(())
        }))
        .unwrap();
    commands::helper_filter::install(handle.child_pidfd()).unwrap();
    handle.confirm_confinement().unwrap();
    handle.finish();
    panic!("stalled helper survived");
}

// 이것을 실패시키는 것: 회수와 마지막 signal의 macOS 공유 직렬화를 제거하는 것.
#[cfg(target_os = "macos")]
#[test]
fn macos_signal_precedes_reap_and_never_targets_reused_pid() {
    let _inherited_fds = commands::sys::test_inherited_fd_lock();
    for _ in 0..40 {
        let (read, write) = collector_process::pipe().unwrap();
        let (input, output) = collector_process::pipe().unwrap();
        let mut child = collector_process::spawn_args(
            peer().as_os_str(),
            &[OsStr::new("exit")],
            &read,
            &output,
            &lock("reap-race"),
            collector_process::now_ns().unwrap() + 1_000_000_000,
        )
        .unwrap();
        let signal = child.signal_copy().unwrap();
        let observer = child.signal_copy().unwrap();
        let sender = std::thread::spawn(move || signal.signal(libc::SIGKILL).unwrap());
        let end = Instant::now() + Duration::from_secs(1);
        while !child.reap().unwrap() {
            assert!(Instant::now() < end);
            std::thread::yield_now();
        }
        sender.join().unwrap();
        assert!(observer.reaped());
        assert!(child.reap().unwrap());
        drop((write, input));
    }
}

// 이것을 실패시키는 것: 첫 완료한 초과 표본의 종료 요청 또는 32MiB 예산을 제거하는 것.
#[cfg(target_os = "macos")]
#[test]
fn macos_first_completed_overlimit_sample_terminates() {
    let _inherited_fds = commands::sys::test_inherited_fd_lock();
    let mut samples = Vec::new();
    let mut overshoots = Vec::new();
    let mut intervals = Vec::new();
    let mut kill_delays = Vec::new();
    peer();
    for _ in 0..200 {
        let start = Instant::now();
        // Exercise the real sampler/signal/reap path with its own finite
        // registration budget. The protocol's 50ms request deadline can win
        // before a loaded runner commits and samples 40MiB; it is tested
        // separately and must not be extended for this measurement.
        let watchdog = helper_limits::start(Instant::now()).unwrap();
        let (read, write) = collector_process::pipe().unwrap();
        let (input, output) = collector_process::pipe().unwrap();
        let mut child = collector_process::spawn_args(
            peer().as_os_str(),
            &[OsStr::new("sample-memory")],
            &read,
            &output,
            &lock("memory-sample"),
            watchdog.expires_ns(),
        )
        .unwrap();
        let registration = watchdog
            .register_collector(&child, collector_process::now_ns().unwrap() + 1_000_000_000)
            .unwrap();
        assert_eq!(
            commands::sys::write_fd(write.as_raw_fd(), &[1]),
            commands::sys::WriteOutcome::Done
        );
        let end = Instant::now() + Duration::from_millis(1500);
        while !child.reap().unwrap() {
            assert!(Instant::now() < end, "overlimit worker was not reaped");
            std::thread::sleep(Duration::from_millis(2));
        }
        let observations = watchdog.observations.lock().unwrap().clone();
        let over = observations
            .iter()
            .find(|v| v.1 > 0)
            .expect("actual overlimit sample");
        assert!(
            over.2 >= over.0,
            "first completed overlimit sample must signal"
        );
        overshoots.push(over.1 as u128);
        kill_delays.push((over.2 - over.0) as u128 / 1000);
        intervals.extend(
            observations
                .windows(2)
                .map(|v| (v[1].0 - v[0].0) as u128 / 1000),
        );
        assert_eq!(registration.reason(), Some(EndReason::Resource));
        assert!(child.kill_requested());
        samples.push(start.elapsed().as_micros());
        drop((registration, read, write, input, output));
    }
    distribution("spawn-to-termination us", &mut samples);
    distribution("footprint overshoot bytes", &mut overshoots);
    distribution("completed sample interval us", &mut intervals);
    distribution("sample-to-kill-request us", &mut kill_delays);
}

fn distribution(name: &str, values: &mut [u128]) {
    assert!(!values.is_empty(), "measurement must actually run");
    values.sort_unstable();
    println!(
        "{name}: count={} p50={} p95={} max={}",
        values.len(),
        values[values.len() / 2],
        values[values.len() * 95 / 100],
        values[values.len() - 1]
    );
}

struct FixedClock(snapshot::Clock);
impl snapshot::ClockSource for FixedClock {
    fn observe(&mut self) -> Result<snapshot::Clock, snapshot::ClockError> {
        Ok(self.0)
    }
}

// 이것을 실패시키는 것: 검증 전 생성, Invalid/만료 안전 화면 누락, mask0/redraw 생성 또는 TSYNC 전 감독 시작 누락.
#[test]
fn verified_screen_spawns_once_before_helper_tsync() {
    let _inherited_fds = commands::sys::test_inherited_fd_lock();
    for case in [
        "valid",
        "invalid",
        "expired",
        "product",
        "empty",
        "redraw",
        "unsafe-runtime",
        "unsafe-context",
        "unsafe-screen",
    ] {
        let out = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "verified_screen_child",
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .env("C1_CASE", case)
            .output()
            .unwrap();
        eprintln!("{case}: {}", String::from_utf8_lossy(&out.stderr));
        passed(&out);
    }
}

// 이것을 실패시키는 것: refresh callback 안에서 수집 완료를 기다려 snapshot lock을 연장하는 것.
#[test]
fn snapshot_lock_is_not_extended_by_collection() {
    let _inherited_fds = commands::sys::test_inherited_fd_lock();
    let out = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "verified_screen_child",
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("C1_CASE", "snapshot-lock")
        .output()
        .unwrap();
    passed(&out);
}

#[test]
#[ignore = "isolates helper limits and TSYNC around the real refresh broker"]
#[allow(clippy::disallowed_methods, reason = "test-only child configuration")]
fn verified_screen_child() {
    use bingsu_core::envelope::Envelope;
    use commands::{
        helper,
        refresh::{self, RefreshRequest, RefreshResult},
        runtime_root::Pinned,
        sys,
    };
    use std::os::unix::{ffi::OsStrExt, fs::MetadataExt};
    let case = std::env::var("C1_CASE").unwrap();
    // A cached target/ can hold this folder from an earlier run whose process
    // had the same pid; start from an empty one.
    let root = peer().parent().unwrap().join("refresh");
    match std::fs::remove_dir_all(&root) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => panic!("{}: {error}", root.display()),
    }
    std::fs::create_dir(&root).unwrap();
    for name in ["runtime", "config", "state"] {
        std::fs::create_dir(root.join(name)).unwrap();
        std::fs::set_permissions(root.join(name), std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let source = root.join("config/config.toml");
    std::fs::write(&source, "icons = 'ascii'\n").unwrap();
    std::fs::set_permissions(&source, std::fs::Permissions::from_mode(0o600)).unwrap();
    let now = commands::collector_supervisor::fixture_clock().unwrap();
    let metadata = std::fs::metadata(root.join("runtime")).unwrap();
    let mut refresh_request = RefreshRequest {
        runtime: Pinned {
            path: root.join("runtime"),
            dev: metadata.dev(),
            ino: metadata.ino(),
        },
        config_written: root.join("config"),
        config_canonical: root.join("config"),
        config_root_shape_only: false,
        state_root: root.join("state"),
        home: root.clone(),
        me: sys::current_uid(),
        user: sys::passwd_entry(sys::current_uid()).unwrap().name,
        version: [0, 3, 0],
        build: Some([1; 40]),
        process_started: now,
    };
    assert!(matches!(
        refresh::refresh(refresh_request.clone(), &mut FixedClock(now)),
        RefreshResult::Published { .. }
    ));
    let context = snapshot::context_components(
        refresh_request.config_canonical.as_os_str().as_bytes(),
        refresh_request.state_root.as_os_str().as_bytes(),
    )
    .unwrap()
    .iter()
    .fold(root.join("runtime"), |path, name| path.join(name));
    if case == "invalid" || case == "unsafe-screen" {
        std::fs::write(&source, "broken = [").unwrap();
    }
    let unsafe_path = match case.as_str() {
        "unsafe-runtime" => Some(root.join("runtime")),
        "unsafe-context" => Some(context.clone()),
        "unsafe-screen" => Some(context.join("snapshot")),
        _ => None,
    };
    if let Some(path) = &unsafe_path {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o777)).unwrap();
    }
    let mut observed = now;
    if case == "expired" {
        observed.now += 10_000_000_000;
        refresh_request.process_started = observed;
    }
    let envelope = Envelope {
        config_root: Some(
            refresh_request
                .config_canonical
                .as_os_str()
                .as_bytes()
                .to_vec(),
        ),
        state_root: Some(refresh_request.state_root.as_os_str().as_bytes().to_vec()),
        pwd: Some(b"/repo".to_vec()),
        width: 80,
        redraw: case == "redraw",
        ..Envelope::default()
    };
    let mut segments = SEGMENTS;
    for (segment, name) in segments[..31].iter_mut().zip([
        "a00", "a01", "a02", "a03", "a04", "a05", "a06", "a07", "a08", "a09", "a10", "a11", "a12",
        "a13", "a14", "a15", "a16", "a17", "a18", "a19", "a20", "a21", "a22", "a23", "a24", "a25",
        "a26", "a27", "a28", "a29", "a30",
    ]) {
        segment.id = name;
    }
    let catalog = Catalog {
        segments: &segments,
        workers: 1 << 31,
    };
    let watchdog = helper_limits::start(Instant::now()).unwrap();
    let (release, released) = std::sync::mpsc::sync_channel(1);
    let (entered, entering) = std::sync::mpsc::sync_channel(1);
    let mut released = Some(released);
    let mut handle = None;
    let mut spawns = 0;
    let mut confined = false;
    let result = refresh::refresh_broker(
        refresh_request.clone(),
        &mut FixedClock(observed),
        &mut |_, display, clock| {
            let adjusted = display.map(|(config, id)| {
                let mut config = config.clone();
                config.bands.clear();
                config.band_order.clear();
                config.variants =
                    vec![bingsu_core::template::compile::compile("{fixture}", &segments).unwrap()];
                config.collect_mask = if case == "empty" { 0 } else { 1 << 31 };
                (config, id)
            });
            let verified_ns = collector_process::now_ns().unwrap();
            let selected = helper::selected_request(
                if case == "product" {
                    &collection::selection::PRODUCT
                } else {
                    &catalog
                },
                &envelope,
                adjusted.as_ref().map(|(c, id)| (c, *id)),
                clock,
            )?;
            if let Some(mut request) = selected {
                assert!(!confined);
                request.binding.build_id = BuildId([7; 32]);
                spawns += 1;
                let held_lock = lock("screen");
                let spawning_ns = collector_process::now_ns().unwrap();
                eprintln!(
                    "lifecycle: verified_to_spawn_ns={}",
                    spawning_ns - verified_ns
                );
                let job = CollectorJob::fixture(
                    peer().as_os_str(),
                    OsStr::new("normal"),
                    request,
                    held_lock,
                    &watchdog,
                    &SEGMENTS,
                )?;
                let released = released.take().unwrap();
                let entered = entered.clone();
                handle = Some(job.start(Box::new(move |_| {
                    entered.send(()).unwrap();
                    released.recv().unwrap();
                    Ok(())
                }))?);
            }
            helper_limits::install(&watchdog)?;
            commands::helper_filter::install(handle.as_ref().and_then(|h| h.child_pidfd()))?;
            confined = true;
            if let Some(handle) = &handle {
                handle.confirm_confinement()?;
            }
            Ok(())
        },
    );
    let expected = usize::from(matches!(
        case.as_str(),
        "valid" | "invalid" | "expired" | "snapshot-lock"
    ));
    assert_eq!(spawns, expected, "{case}: {result:?}");
    if let Some(handle) = handle {
        entering.recv_timeout(Duration::from_millis(300)).unwrap();
        // The publisher is blocked, but refresh already released its own lock.
        let snapshot_lock = File::open(context.join("snapshot.lock")).unwrap();
        // SAFETY: separate description, nonblocking lock proves refresh returned.
        let rc = unsafe { libc::flock(snapshot_lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        assert_eq!(rc, 0, "snapshot lock outlived refresh");
        release.send(()).unwrap();
        let report = handle.finish();
        assert_eq!(report.reason, EndReason::Complete);
        assert!(report.reaped);
    }
}

// 이것을 실패시키는 것: helper 사망 때 worker가 셸 pipe를 붙들거나 고아 타이머/close-only 잠금을 잃는 것.
#[test]
fn helper_exit_and_worker_orphan_do_not_hold_shell() {
    let _inherited_fds = commands::sys::test_inherited_fd_lock();
    use std::os::unix::process::ExitStatusExt;
    for cause in ["kill", "panic", "filter", "stall"] {
        let path = peer().parent().unwrap().join(format!("orphan-{cause}"));
        let file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&path)
            .unwrap();
        file.set_permissions(std::fs::Permissions::from_mode(0o600))
            .unwrap();
        drop(file);
        let start = Instant::now();
        let out = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "orphan_helper_child",
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .env("C1_ORPHAN_LOCK", &path)
            .env("C1_DEATH", cause)
            .output()
            .unwrap();
        assert!(
            start.elapsed() < Duration::from_millis(800),
            "{cause}: shell waited for worker"
        );
        match cause {
            "kill" | "stall" => assert_eq!(out.status.signal(), Some(libc::SIGKILL), "{out:?}"),
            "panic" => assert!(!out.status.success()),
            _ => passed(&out),
        }
        let competing = File::open(&path).unwrap();
        #[cfg(target_os = "macos")]
        if cause == "kill" || cause == "stall" {
            // SAFETY: separate description must remain excluded by the live orphan.
            let rc = unsafe { libc::flock(competing.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
            assert_eq!(rc, -1, "{cause}: live worker lost its inherited lock");
            assert_eq!(
                std::io::Error::last_os_error().raw_os_error(),
                Some(libc::EWOULDBLOCK)
            );
        }
        let end = Instant::now() + Duration::from_millis(1300);
        loop {
            // SAFETY: separate description; success proves all inherited locks closed.
            if unsafe { libc::flock(competing.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
                break;
            }
            assert!(
                Instant::now() < end,
                "orphan retained lock after fallback timer"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
    }
}
#[test]
#[ignore = "helper death fixture with an independently timed worker"]
#[allow(clippy::disallowed_methods, reason = "test-only child configuration")]
fn orphan_helper_child() {
    use std::io::Read;
    let lock = File::open(std::env::var_os("C1_ORPHAN_LOCK").unwrap()).unwrap();
    // SAFETY: own fixture lock.
    assert_eq!(
        // SAFETY: own fixture lock.
        unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
        0
    );
    let (read, _write) = collector_process::pipe().unwrap();
    let (mut input, output) = collector_process::pipe().unwrap();
    let exe = std::env::current_exe().unwrap();
    let child = collector_process::spawn_args(
        exe.as_os_str(),
        &[
            OsStr::new("--exact"),
            OsStr::new("orphan_worker_child"),
            OsStr::new("--ignored"),
            OsStr::new("--nocapture"),
            OsStr::new("--test-threads=1"),
        ],
        &read,
        &output,
        &lock,
        collector_process::now_ns().unwrap() + 1_500_000_000,
    )
    .unwrap();
    drop(output);
    let mut message = Vec::new();
    while !message.ends_with(b"orphan ready\n") {
        let mut byte = [0];
        assert_eq!(
            input.read(&mut byte).unwrap(),
            1,
            "worker did not arm fallback"
        );
        message.push(byte[0]);
        assert!(message.len() < 4096);
    }
    match std::env::var("C1_DEATH").unwrap().as_str() {
        "kill" => {
            // SAFETY: isolated fixture kills itself only.
            let pid = unsafe { libc::getpid() };
            // SAFETY: own process; no destructors run.
            unsafe { libc::kill(pid, libc::SIGKILL) };
            loop {
                // SAFETY: wait for own uncatchable signal without running Drop.
                unsafe { libc::pause() };
            }
        }
        "panic" => panic!("injected helper panic"),
        "filter" => drop(child),
        "stall" => {
            let _watchdog =
                helper_limits::start(Instant::now() - Duration::from_millis(1750)).unwrap();
            let _child = child;
            std::thread::sleep(Duration::from_secs(3));
            panic!("helper lifetime not enforced");
        }
        _ => unreachable!(),
    }
}
#[test]
#[ignore = "real worker orphan guard and fd contract, with no product fixture switch"]
fn orphan_worker_child() {
    worker_sys::orphan_guard().unwrap();
    let _fds = worker_sys::validate_worker_fds().unwrap();
    println!("orphan ready");
    std::io::stdout().flush().unwrap();
    std::thread::sleep(Duration::from_secs(3));
    panic!("worker fallback timer did not terminate");
}

// 이것을 실패시키는 것: pidfd 확보 실패 후 감독을 계속하거나 직계 자식을 정리·회수하지 않는 것.
#[cfg(target_os = "linux")]
#[test]
fn no_pidfd_means_no_collector() {
    let _inherited_fds = commands::sys::test_inherited_fd_lock();
    passed(&isolated("pidfd_failure_child"));
}
#[cfg(target_os = "linux")]
#[test]
#[ignore = "injects pidfd_open refusal in an isolated process"]
fn pidfd_failure_child() {
    use std::io::Read;
    let exe = peer().clone();
    let mut code = [
        libc::sock_filter {
            code: 0x20,
            jt: 0,
            jf: 0,
            k: 0,
        },
        libc::sock_filter {
            code: 0x15,
            jt: 0,
            jf: 1,
            k: libc::SYS_pidfd_open as u32,
        },
        libc::sock_filter {
            code: 0x06,
            jt: 0,
            jf: 0,
            k: libc::SECCOMP_RET_ERRNO | libc::EPERM as u32,
        },
        libc::sock_filter {
            code: 0x06,
            jt: 0,
            jf: 0,
            k: libc::SECCOMP_RET_ALLOW,
        },
    ];
    let program = libc::sock_fprog {
        len: code.len() as u16,
        filter: code.as_mut_ptr(),
    };
    // SAFETY: isolated fixture removes its own privileges.
    assert_eq!(
        // SAFETY: isolated fixture removes its own privileges.
        unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) },
        0
    );
    // SAFETY: initialized fixed test filter and supported operation.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            libc::SECCOMP_SET_MODE_FILTER,
            0,
            &program,
        )
    };
    assert_eq!(rc, 0);
    let (read, _write) = collector_process::pipe().unwrap();
    let (mut input, output) = collector_process::pipe().unwrap();
    let result = collector_process::spawn_args(
        exe.as_os_str(),
        &[OsStr::new("idle")],
        &read,
        &output,
        &lock("pidfd-failed"),
        collector_process::now_ns().unwrap() + 500_000_000,
    );
    assert!(matches!(result,Err(error) if error.raw_os_error()==Some(libc::EPERM)));
    drop(output);
    assert_eq!(
        input.read(&mut [0]).unwrap(),
        0,
        "cleanup must close the child pipe"
    );
    // SAFETY: isolated fixture owns no other child; no competing waiter.
    let rc = unsafe { libc::waitpid(-1, std::ptr::null_mut(), libc::WNOHANG) };
    assert_eq!(rc, -1);
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::ECHILD)
    );
}

// 이것을 실패시키는 것: 정상 fixture의 회수를 생략하거나 완료 회차 수를 줄이는 것.
#[test]
fn four_hundred_requests_leave_no_workers_or_zombies() {
    let _inherited_fds = commands::sys::test_inherited_fd_lock();
    passed(&isolated("four_hundred_child"));
}
#[test]
#[ignore = "isolates the kernel child census after 400 completed exchanges"]
fn four_hundred_child() {
    let mut completed = 0;
    for _ in 0..400 {
        let (report, values) = run_peer("normal", true);
        assert_eq!(report.reason, EndReason::Complete);
        assert!(report.reaped && !report.kill_requested, "{report:?}");
        assert_eq!(values.len(), 1);
        completed += 1;
    }
    assert_eq!(completed, 400, "the full lifecycle workload must run");
    // SAFETY: this isolated fixture owns no other children or waiters.
    let rc = unsafe { libc::waitpid(-1, std::ptr::null_mut(), libc::WNOHANG) };
    assert_eq!(rc, -1, "a worker or zombie remains");
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::ECHILD)
    );
}

// 이것을 실패시키는 것: handle Drop에서 발행 취소·종료 요청을 제거하는 것.
#[test]
fn dropping_supervision_cancels_without_publication() {
    let _inherited_fds = commands::sys::test_inherited_fd_lock();
    passed(&isolated("dropped_handle_child"));
}
#[test]
#[ignore = "isolates cancellation failure from the test runner lifetime"]
fn dropped_handle_child() {
    peer();
    let watchdog = helper_limits::start(Instant::now()).unwrap();
    let job = CollectorJob::fixture(
        peer().as_os_str(),
        OsStr::new("normal"),
        request(false),
        lock("drop"),
        &watchdog,
        &SEGMENTS,
    )
    .unwrap();
    let (send, received) = std::sync::mpsc::channel();
    let handle = job
        .start(Box::new(move |_| {
            send.send(()).unwrap();
            Ok(())
        }))
        .unwrap();
    drop(handle);
    assert!(matches!(
        received.recv_timeout(Duration::from_millis(300)),
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected)
    ));
}

// 이것을 실패시키는 것: watchdog 등록 실패 뒤에도 요청·감독을 시작하는 것.
#[test]
fn watchdog_registration_failure_is_fail_closed() {
    let _inherited_fds = commands::sys::test_inherited_fd_lock();
    peer();
    let watchdog = helper_limits::start(Instant::now()).unwrap();
    let first = CollectorJob::fixture(
        peer().as_os_str(),
        OsStr::new("idle"),
        request(false),
        lock("registration-first"),
        &watchdog,
        &SEGMENTS,
    )
    .unwrap();
    let second = CollectorJob::fixture(
        peer().as_os_str(),
        OsStr::new("normal"),
        request(false),
        lock("registration-second"),
        &watchdog,
        &SEGMENTS,
    );
    assert!(matches!(second,Err(error) if error.to_string()=="collector already registered"));
    drop(first);
}

// 이것을 실패시키는 것: 감독 스레드 생성 실패에서 이미 생성된 자식 정리를 생략하는 것.
#[cfg(target_os = "linux")]
#[test]
fn supervisor_thread_failure_reaps_the_child() {
    let _inherited_fds = commands::sys::test_inherited_fd_lock();
    passed(&isolated("thread_failure_child"));
}
#[cfg(target_os = "linux")]
#[test]
#[ignore = "the helper filter deliberately refuses supervisor thread creation"]
fn thread_failure_child() {
    peer();
    let watchdog = helper_limits::start(Instant::now()).unwrap();
    let job = CollectorJob::fixture(
        peer().as_os_str(),
        OsStr::new("idle"),
        request(false),
        lock("thread-failure"),
        &watchdog,
        &SEGMENTS,
    )
    .unwrap();
    commands::helper_filter::install(job.child_pidfd()).unwrap();
    assert!(
        job.start(Box::new(|_| panic!("failed supervisor published")))
            .is_err()
    );
    // SAFETY: isolated fixture has no other children or competing waiters.
    let rc = unsafe { libc::waitpid(-1, std::ptr::null_mut(), libc::WNOHANG) };
    assert_eq!(rc, -1);
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::ECHILD)
    );
}

// 이것을 실패시키는 것: 실제 EINTR을 자원 실패로 처리하거나 poll을 중단한 뒤 마감을 늘리는 것.
#[test]
fn interrupted_poll_preserves_absolute_deadline() {
    let _inherited_fds = commands::sys::test_inherited_fd_lock();
    passed(&isolated("interrupted_poll_child"));
}
#[test]
#[ignore = "isolates a non-restarting signal handler and interrupts the supervisor poll"]
fn interrupted_poll_child() {
    extern "C" fn received(_: libc::c_int) {}
    peer();
    // SAFETY: integer-only signal action with no restart flag, local to this process.
    let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
    action.sa_sigaction = received as *const () as usize;
    // SAFETY: initialized writable signal mask.
    assert_eq!(unsafe { libc::sigemptyset(&mut action.sa_mask) }, 0);
    // SAFETY: the handler has the required C ABI and does no work.
    assert_eq!(
        // SAFETY: process-local handler with the required C ABI.
        unsafe { libc::sigaction(libc::SIGUSR1, &action, std::ptr::null_mut()) },
        0
    );
    let watchdog = helper_limits::start(Instant::now()).unwrap();
    let started = Instant::now();
    let job = CollectorJob::fixture(
        peer().as_os_str(),
        OsStr::new("drip"),
        request(false),
        lock("interrupt"),
        &watchdog,
        &SEGMENTS,
    )
    .unwrap();
    let handle = job
        .start(Box::new(|_| panic!("incomplete Ready published")))
        .unwrap();
    handle.confirm_confinement().unwrap();
    for _ in 0..20 {
        std::thread::sleep(Duration::from_millis(2));
        handle.fixture_interrupt();
    }
    let report = handle.finish();
    assert_eq!(report.reason, EndReason::Deadline);
    assert!(report.reaped && report.kill_requested);
    assert!(
        commands::collector_supervisor::POLL_INTERRUPTS.load(std::sync::atomic::Ordering::Relaxed)
            > 0,
        "the poll syscall must actually return EINTR"
    );
    assert!(started.elapsed() < Duration::from_millis(500));
}
