//! D3: the real stage pipeline and wire codec, with explicit test-only policy.
#![cfg(unix)]
#![allow(dead_code)]
#[path = "../src/git/mod.rs"]
mod git;
#[cfg(target_os = "linux")]
#[path = "../src/landlock.rs"]
mod landlock;
#[path = "../src/meter.rs"]
mod meter;
#[path = "../src/safe_read/mod.rs"]
mod safe_read;
#[path = "../src/update_sink.rs"]
mod update_sink;

use bingsu_core::{
    collection::{
        path_facts::PathQuery,
        wire::{self, Binding, BuildId, EndReason, Frame, Kind, Request, Transcript},
    },
    field::{self, Field, FieldValue, Value},
    snapshot::{self, Clock, Identity},
};
use git::{CollectError, StageDeadlines};
use meter::Meter;
use safe_read::{Access, ReadError};
use std::{
    cell::RefCell,
    fs,
    os::unix::ffi::OsStrExt,
    path::PathBuf,
    process::Command,
    rc::Rc,
    time::{Duration, Instant},
};
use update_sink::WireSink;

const GENEROUS: StageDeadlines = StageDeadlines {
    a_ms: 30_000,
    b_ms: 30_000,
    c_ms: 30_000,
    d_ms: 30_000,
    path_ms: 30_000,
};
fn meter() -> Meter {
    Meter::new(Instant::now() + Duration::from_secs(120))
}
struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let base =
            std::env::var_os("BINGSU_D3_ROOT").map_or_else(std::env::temp_dir, PathBuf::from);
        let path = base.join(format!(
            "bingsu-d3-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        fs::create_dir_all(&path).unwrap();
        Self(fs::canonicalize(path).unwrap())
    }
    fn write(&self, name: &str, bytes: impl AsRef<[u8]>) {
        let path = self.0.join(name);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, bytes).unwrap();
    }
    fn git(&self, args: &[&str]) -> String {
        let out = Command::new("git")
            .args(args)
            .current_dir(&self.0)
            .env_clear()
            .env("PATH", "/usr/bin:/bin:/opt/homebrew/bin")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_AUTHOR_NAME", "Fixture")
            .env("GIT_AUTHOR_EMAIL", "f@example.org")
            .env("GIT_COMMITTER_NAME", "Fixture")
            .env("GIT_COMMITTER_EMAIL", "f@example.org")
            .output()
            .expect("git oracle required");
        assert!(
            out.status.success(),
            "git {args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8(out.stdout).unwrap()
    }
    fn init(&self) {
        self.git(&["init", "-q", "--initial-branch=main"]);
        self.write("tracked", b"base\n");
        self.git(&["add", "."]);
        self.git(&["commit", "-qm", "base"]);
        self.git(&["branch", "upstream"]);
        self.git(&["branch", "--set-upstream-to=upstream"]);
    }
    fn request(&self) -> Request {
        let cwd = self.0.as_os_str().as_bytes().to_vec();
        Request {
            request_id: wire::M3B_REQUEST_ID,
            binding: Binding {
                build_id: BuildId([7; 32]),
                snapshot: Identity {
                    boot: [1; 16],
                    epoch: [2; 16],
                    generation: 3,
                    source: [4; 4],
                    context: snapshot::context_crc(b"/c", b"/s").unwrap(),
                },
                clock_kind: 1,
                domain: [5; 16],
                resume: 0,
                config: b"/c".to_vec(),
                state: b"/s".to_vec(),
                path_query: PathQuery::for_path(&cwd, Some(&cwd), false),
                cwd,
                mask: 1 << 3,
            },
            budget_ms: 50,
            environment: vec![],
            global_excludes_known: true,
            global_excludes: vec![],
        }
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn access() -> Access {
    #[cfg(target_os = "linux")]
    let access = Access::probe(&mut meter()).unwrap();
    #[cfg(target_os = "macos")]
    let access = {
        use std::os::fd::AsFd;
        let f = Fixture::new();
        f.write("value", b"inside");
        f.write("dir/file", b"inside");
        f.write("hard", b"linked");
        fs::hard_link(f.0.join("hard"), f.0.join("hard2")).unwrap();
        for (target, name) in [
            ("../value", "dir/inner"),
            ("dir", "linkdir"),
            ("/", "absolute"),
            ("../outside", "escape"),
            ("../../outside", "dir/up"),
        ] {
            std::os::unix::fs::symlink(target, f.0.join(name)).unwrap();
        }
        let fd = fs::File::open(&f.0).unwrap();
        safe_read::macos::probe_unvalidated_for_test(Some(fd.as_fd()), &mut meter()).unwrap()
    };
    assert!(
        access.guarantee().is_some(),
        "BLOCKED: kernel guarantee required"
    );
    access
}
fn isolated(name: &str) -> bool {
    if std::env::var("BINGSU_D3_CHILD").ok().as_deref() == Some(name) {
        #[cfg(target_os = "linux")]
        assert_eq!(
            // SAFETY: irreversible restriction only in this disposable child.
            unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) },
            0
        );
        return true;
    }
    let f = Fixture::new();
    let out = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", name, "--nocapture", "--test-threads=1"])
        .env("BINGSU_D3_CHILD", name)
        .env("BINGSU_D3_ROOT", &f.0)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(String::from_utf8_lossy(&out.stdout).contains("1 passed;"));
    false
}
fn field<'a>(v: &'a Value, name: &str) -> &'a Field {
    &v.fields[field::BUILTIN[3].field_index(name).unwrap()]
}
fn stage(v: &Value) -> &str {
    match &field(v, "stage").value {
        FieldValue::Text(t) => t.as_str(),
        other => panic!("stage {other:?}"),
    }
}
fn count(v: &Value, name: &str, n: u32) {
    assert_eq!(
        field(v, name),
        &Field::known(FieldValue::Count {
            n,
            saturated: false
        }),
        "{name}"
    );
}
fn clock() -> Clock {
    Clock {
        boot: [1; 16],
        kind: 1,
        domain: [5; 16],
        resume: 0,
        now: 1,
    }
}
fn ready(r: &Request) -> Vec<u8> {
    let mut p = wire::FEATURES.to_le_bytes().to_vec();
    p.extend(r.binding.mask.to_le_bytes());
    p.extend([0; 12]);
    p
}
fn receiver(r: &Request) -> Transcript {
    let mut t = Transcript::new(r);
    t.accept(Frame {
        kind: Kind::Ready,
        build_id: r.binding.build_id,
        request_id: r.request_id,
        payload: &ready(r),
    })
    .unwrap();
    t.request_sent().unwrap();
    t
}
struct Stream {
    request: Request,
    updates: Vec<wire::Update>,
    result: Result<(), CollectError>,
    frames: Vec<Vec<u8>>,
    values: Vec<Value>,
}
fn stream(f: &Fixture, m: Meter, deadlines: StageDeadlines, truncate: bool) -> Stream {
    stream_request(f.request(), m, deadlines, truncate)
}
fn stream_request(r: Request, m: Meter, deadlines: StageDeadlines, truncate: bool) -> Stream {
    // Exercise the request wire as well as response publication. In particular,
    // neither global patterns nor their knowledge bit may be lost in transit.
    let r = decode_request(&r);
    let mut buffer = [0; wire::FRAME_MAX];
    let mut frames = Vec::new();
    let mut updates = Vec::new();
    let mut values = Vec::new();
    let mut transcript = receiver(&r);
    let write_deadline = std::cell::Cell::new(Instant::now() + Duration::from_secs(120));
    let mut write = |bytes: &[u8]| {
        let frame = wire::decode_frame(bytes).unwrap();
        if frame.kind == Kind::Update {
            assert!(
                write_deadline.get() <= Instant::now() + Duration::from_secs(31),
                "stage deadline was not forwarded to the write loop"
            );
            if truncate && !values.is_empty() {
                frames.push(bytes[..bytes.len() - 1].to_vec());
                return Err(std::io::ErrorKind::BrokenPipe.into());
            }
            transcript.accept(frame).unwrap();
            let segment = u16::from_le_bytes(frame.payload[..2].try_into().unwrap());
            let update = transcript
                .clone()
                .finish(EndReason::WorkerExit, clock())
                .unwrap()
                .unwrap()
                .updates
                .into_iter()
                .find(|update| update.segment == segment)
                .unwrap();
            if let Some(value) = &update.value {
                values.push(value.clone());
            }
            updates.push(update);
        }
        if frame.kind != Kind::Update {
            transcript.accept(frame).unwrap();
        }
        frames.push(bytes.to_vec());
        Ok(())
    };
    let mut sink = WireSink::new(&r, field::BUILTIN, &ready(&r), &mut buffer, &mut write).unwrap();
    sink.attach_write_deadline(&write_deadline);
    let result = git::collect_with_deadlines(&r, &mut sink, m, access(), deadlines);
    if result.is_ok() {
        sink.complete().unwrap();
    }
    Stream {
        request: r,
        updates,
        result,
        frames,
        values,
    }
}

fn decode_request(request: &Request) -> Request {
    let body = request.encode_body().unwrap();
    let mut begin = (body.len() as u32).to_le_bytes().to_vec();
    begin.extend(wire::FEATURES.to_le_bytes());
    let mut chunk = 0u32.to_le_bytes().to_vec();
    chunk.extend(&body);
    let mut decoder = wire::RequestDecoder::new();
    let mut decoded = None;
    for (kind, payload) in [
        (Kind::Ready, ready(request)),
        (Kind::RequestBegin, begin),
        (Kind::RequestChunk, chunk),
        (Kind::RequestEnd, snapshot::crc32c(&[&body]).to_vec()),
    ] {
        let mut bytes = [0; wire::FRAME_MAX];
        let len = wire::encode_frame(
            Frame {
                kind,
                build_id: request.binding.build_id,
                request_id: request.request_id,
                payload: &payload,
            },
            &mut bytes,
        )
        .unwrap();
        decoded = decoder
            .accept(wire::decode_frame(&bytes[..len]).unwrap())
            .unwrap();
    }
    let decoded = decoded.unwrap();
    assert_eq!(&decoded, request);
    decoded
}
fn completed(stream: &Stream, reason: EndReason) -> bingsu_core::collection::response::Completed {
    let mut transcript = receiver(&stream.request);
    for bytes in &stream.frames {
        if let Ok(frame) = wire::decode_frame(bytes) {
            transcript.accept(frame).unwrap();
        }
    }
    transcript
        .finish(
            reason,
            Clock {
                boot: [1; 16],
                kind: 1,
                domain: [5; 16],
                resume: 0,
                now: 1,
            },
        )
        .unwrap()
        .unwrap()
}

// 이것을 실패시키는 것: stage delta로 앞 필드를 잃거나 B/C/D를 누락·중복 실행, partial을 계속 true로 유지.
#[test]
fn cumulative_stages_match_git_and_real_filesystem() {
    if !isolated("cumulative_stages_match_git_and_real_filesystem") {
        return;
    }
    let f = Fixture::new();
    f.init();
    f.write("committed", b"next\n");
    f.git(&["add", "."]);
    f.git(&["commit", "-qm", "next"]);
    f.write("tracked", b"stash\n");
    f.git(&["stash", "push", "-qm", "stash"]);
    f.write("tracked", b"modified\n");
    f.write("added", b"added\n");
    f.git(&["add", "added"]);
    f.write("loose", b"untracked\n");
    let staged = f.git(&["diff", "--cached", "--name-only"]).lines().count() as u32;
    let modified = f.git(&["diff", "--name-only"]).lines().count() as u32;
    let untracked = f
        .git(&["ls-files", "--others", "--exclude-standard"])
        .lines()
        .count() as u32;
    let divergence = f.git(&["rev-list", "--left-right", "--count", "HEAD...@{upstream}"]);
    let divergence: Vec<u32> = divergence
        .split_whitespace()
        .map(|s| s.parse().unwrap())
        .collect();
    let stashes = f.git(&["stash", "list"]).lines().count() as u32;
    assert_eq!((staged, modified, untracked), (1, 1, 1));
    let mut request = f.request();
    request.binding.mask |= 1 << 1;
    let s = stream_request(request, meter(), GENEROUS, false);
    s.result.as_ref().unwrap();
    assert_eq!(
        s.values.iter().map(stage).collect::<Vec<_>>(),
        ["A", "B", "C", "D"]
    );
    for value in &s.values[1..] {
        assert_eq!(field(value, "branch"), field(&s.values[0], "branch"));
    }
    for value in &s.values[1..] {
        count(value, "staged", staged);
        count(value, "modified", modified);
        count(value, "untracked", untracked);
        count(value, "conflicted", 0);
    }
    assert_eq!(field(&s.values[1], "ahead"), &Field::PENDING);
    for value in &s.values[2..] {
        count(value, "ahead", divergence[0]);
        count(value, "behind", divergence[1]);
    }
    count(&s.values[3], "stash", stashes);
    for value in &s.values[..3] {
        assert_eq!(
            field(value, "partial"),
            &Field::known(FieldValue::Bool(true))
        );
    }
    assert_eq!(
        field(&s.values[3], "partial"),
        &Field::known(FieldValue::Bool(false))
    );
    let result = completed(&s, EndReason::Complete);
    assert!(result.progress.stage_a_complete);
    assert_eq!(
        result
            .updates
            .iter()
            .find(|u| u.segment == 3)
            .unwrap()
            .value
            .as_ref(),
        s.values.last()
    );
    assert_eq!(
        s.updates.iter().map(|u| u.segment).collect::<Vec<_>>(),
        [3, 1, 3, 3, 3]
    );
    assert_eq!(s.updates[1].facts.as_ref().unwrap().in_repo, Some(true));
    assert_eq!(
        s.frames
            .iter()
            .map(|f| wire::decode_frame(f).unwrap().kind)
            .collect::<Vec<_>>(),
        [
            Kind::Update,
            Kind::Progress,
            Kind::Update,
            Kind::Update,
            Kind::Update,
            Kind::Update,
            Kind::Complete
        ]
    );
    assert!(s.updates.len() <= wire::UPDATES_MAX as usize);
    assert!(s.frames.len() < wire::FRAMES_MAX);
    assert!(s.frames.iter().map(Vec::len).sum::<usize>() + wire::HEADER + 24 <= wire::STREAM_MAX);
}

// Mutations: discard request patterns, force known=true/false, suppress C/D or
// Complete for a completed partial B, or clear Pending/partial in later stages.
#[test]
fn known_global_excludes_complete_through_stream() {
    if isolated("known_global_excludes_complete_through_stream") {
        global_excludes_stream(true);
    }
}

#[test]
fn unknown_global_excludes_complete_partial_through_stream() {
    if isolated("unknown_global_excludes_complete_partial_through_stream") {
        global_excludes_stream(false);
    }
}

fn global_excludes_stream(known: bool) {
    let f = Fixture::new();
    f.init();
    f.write("tracked", b"modified\n");
    f.write("added", b"staged\n");
    f.git(&["add", "added"]);
    f.write(".DS_Store", b"ignored globally\n");
    f.write("visible", b"untracked\n");
    let mut r = f.request();
    r.binding.mask |= 1 << 1;
    r.global_excludes_known = known;
    r.global_excludes = if known {
        b".DS_Store\n".to_vec()
    } else {
        vec![]
    };
    let s = stream_request(r, meter(), GENEROUS, false);
    s.result.as_ref().unwrap();
    assert_eq!(
        s.values.iter().map(stage).collect::<Vec<_>>(),
        ["A", "B", "C", "D"]
    );
    assert_eq!(
        s.updates.iter().map(|u| u.segment).collect::<Vec<_>>(),
        [3, 1, 3, 3, 3]
    );
    assert_eq!(s.updates[1].facts.as_ref().unwrap().in_repo, Some(true));
    for v in &s.values[1..] {
        count(v, "staged", 1);
        count(v, "modified", 1);
        count(v, "conflicted", 0);
        if known {
            count(v, "untracked", 1);
        } else {
            assert_eq!(field(v, "untracked"), &Field::PENDING);
            assert_eq!(field(v, "filtered"), &Field::PENDING);
        }
    }
    for v in &s.values[..3] {
        assert_eq!(field(v, "partial"), &Field::known(FieldValue::Bool(true)));
    }
    let last = s.values.last().unwrap();
    count(last, "ahead", 0);
    count(last, "behind", 0);
    count(last, "stash", 0);
    assert_eq!(
        field(last, "partial"),
        &Field::known(FieldValue::Bool(!known))
    );
    assert_eq!(
        s.frames
            .iter()
            .map(|f| wire::decode_frame(f).unwrap().kind)
            .collect::<Vec<_>>(),
        [
            Kind::Update,
            Kind::Progress,
            Kind::Update,
            Kind::Update,
            Kind::Update,
            Kind::Update,
            Kind::Complete
        ]
    );
    let result = completed(&s, EndReason::Complete);
    assert!(result.progress.stage_a_complete);
    assert_eq!(
        result
            .updates
            .iter()
            .find(|u| u.segment == 3)
            .unwrap()
            .value
            .as_ref(),
        Some(last)
    );
}

// A path-local timeout leaves A intact and still runs B-D, but never completes.
#[test]
fn path_deadline_keeps_git_stages_without_complete() {
    if isolated("path_deadline_keeps_git_stages_without_complete") {
        path_failure_keeps_git(false);
    }
}

// The optional path stage's unwind is contained by the shared meter boundary.
#[test]
fn path_panic_keeps_git_stages_without_complete() {
    if isolated("path_panic_keeps_git_stages_without_complete") {
        path_failure_keeps_git(true);
    }
}

fn path_failure_keeps_git(panic: bool) {
    let f = Fixture::new();
    f.init();
    let mut r = f.request();
    r.binding.mask |= 1 << 1;
    let events = Rc::new(RefCell::new(Vec::new()));
    let observed = events.clone();
    let mut m = meter();
    let live = m.fd_observer();
    m.hook = Some(Box::new(move |event| {
        observed.borrow_mut().push(event.to_owned());
        if event == "discovery_consumed" || event == "before_read_layer" {
            assert_eq!(live.get(), 2, "only worktree and gitdir survive");
        }
        if panic && event == "path_facts" {
            panic!("injected path facts unwind");
        }
    }));
    let mut deadlines = GENEROUS;
    if !panic {
        deadlines.path_ms = 0;
    }
    let s = stream_request(r, m, deadlines, false);
    if panic {
        assert!(matches!(s.result, Err(CollectError::Panic)));
    } else {
        assert!(matches!(
            s.result,
            Err(CollectError::Read(ReadError::Deadline))
        ));
    }
    assert_eq!(
        s.values.iter().map(stage).collect::<Vec<_>>(),
        ["A", "B", "C", "D"]
    );
    assert_eq!(
        s.updates.iter().map(|u| u.segment).collect::<Vec<_>>(),
        [3, 3, 3, 3]
    );
    let last = s.values.last().unwrap();
    count(last, "staged", 0);
    count(last, "ahead", 0);
    count(last, "behind", 0);
    count(last, "stash", 0);
    let events = events.borrow();
    let ordered = [
        "path_facts",
        "discovery_consumed",
        "before_read_layer",
        "stage_b",
        "stage_c",
        "stage_d",
    ];
    let positions: Vec<_> = ordered
        .iter()
        .map(|wanted| events.iter().position(|event| event == wanted).unwrap())
        .collect();
    assert!(positions.windows(2).all(|pair| pair[0] < pair[1]));
    assert!(
        !s.frames
            .iter()
            .any(|f| wire::decode_frame(f).unwrap().kind == Kind::Complete)
    );
    let result = completed(
        &s,
        if panic {
            EndReason::WorkerExit
        } else {
            EndReason::Deadline
        },
    );
    assert!(result.progress.stage_a_complete);
    assert_eq!(result.updates[0].value.as_ref(), Some(last));
}

#[test]
fn dir_only_repository_deadline_does_not_complete() {
    if isolated("dir_only_repository_deadline_does_not_complete") {
        dir_only_stream(true, true);
    }
}

#[test]
fn dir_only_outside_deadline_does_not_complete() {
    if isolated("dir_only_outside_deadline_does_not_complete") {
        dir_only_stream(false, true);
    }
}

#[test]
fn dir_only_outside_publishes_facts_and_progress() {
    if isolated("dir_only_outside_publishes_facts_and_progress") {
        dir_only_stream(false, false);
    }
}

fn dir_only_stream(repository: bool, expired: bool) {
    let f = Fixture::new();
    if repository {
        f.init();
    }
    let mut r = f.request();
    r.binding.mask = 1 << 1;
    let mut deadlines = GENEROUS;
    if expired {
        deadlines.path_ms = 0;
    }
    let events = Rc::new(RefCell::new(Vec::new()));
    let observed = events.clone();
    let mut m = meter();
    let live = m.fd_observer();
    m.hook = Some(Box::new(move |event| {
        if event == "discovery_consumed" || event == "before_read_layer" {
            assert_eq!(live.get(), if repository { 2 } else { 1 });
        }
        observed.borrow_mut().push(event.to_owned());
    }));
    let s = stream_request(r, m, deadlines, false);
    assert!(s.values.is_empty());
    let events = events.borrow();
    assert!(!events.iter().any(|e| matches!(
        e.as_str(),
        "preflight_start" | "stage_b" | "stage_c" | "stage_d"
    )));
    let closed = events
        .iter()
        .position(|e| e == "discovery_consumed")
        .unwrap();
    let layer = events
        .iter()
        .position(|e| e == "before_read_layer")
        .unwrap();
    assert!(closed < layer);
    if expired {
        assert!(matches!(
            s.result,
            Err(CollectError::Read(ReadError::Deadline))
        ));
        assert!(
            s.frames.is_empty(),
            "expired path stage must not publish late frames"
        );
    } else {
        s.result.as_ref().unwrap();
        assert_eq!(
            s.frames
                .iter()
                .map(|f| wire::decode_frame(f).unwrap().kind)
                .collect::<Vec<_>>(),
            [Kind::Update, Kind::Progress, Kind::Complete]
        );
        let result = completed(&s, EndReason::Complete);
        assert!(result.progress.stage_a_complete);
        assert!(result.progress.device.is_some());
        assert_eq!(result.updates.len(), 1);
        assert_eq!(result.updates[0].segment, 1);
        assert_eq!(
            result.updates[0].facts.as_ref().unwrap().in_repo,
            Some(repository)
        );
    }
}

// A path sink failure must still stop all later writes, like a Git sink failure.
#[test]
fn failed_path_frame_stops_before_git_b() {
    if !isolated("failed_path_frame_stops_before_git_b") {
        return;
    }
    let f = Fixture::new();
    f.init();
    let mut r = f.request();
    r.binding.mask |= 1 << 1;
    let s = stream_request(r, meter(), GENEROUS, true);
    assert!(
        matches!(&s.result, Err(CollectError::Sink(e)) if e.kind() == std::io::ErrorKind::BrokenPipe)
    );
    assert_eq!(s.frames.len(), 3);
    assert_eq!(s.values.iter().map(stage).collect::<Vec<_>>(), ["A"]);
    let result = completed(&s, EndReason::Protocol);
    assert_eq!(result.updates.len(), 1);
    assert_eq!(stage(result.updates[0].value.as_ref().unwrap()), "A");
    assert!(result.progress.stage_a_complete);
}

// 이것을 실패시키는 것: B Partial 뒤 C/D를 생략하거나 손상 index를 clean으로 발행.
#[test]
fn partial_b_keeps_independent_history_and_stash() {
    if !isolated("partial_b_keeps_independent_history_and_stash") {
        return;
    }
    let f = Fixture::new();
    f.init();
    f.write(".git/index", b"broken");
    let s = stream(&f, meter(), GENEROUS, false);
    s.result.as_ref().unwrap();
    assert_eq!(
        s.values.iter().map(stage).collect::<Vec<_>>(),
        ["A", "B", "C", "D"]
    );
    let last = s.values.last().unwrap();
    for name in ["staged", "modified", "untracked", "conflicted", "filtered"] {
        assert_eq!(field(last, name), &Field::PENDING, "{name}");
    }
    count(last, "ahead", 0);
    count(last, "behind", 0);
    count(last, "stash", 0);
    assert_eq!(
        field(last, "partial"),
        &Field::known(FieldValue::Bool(true))
    );
}

// 이것을 실패시키는 것: B-local Deadline에서 요청 전체를 중단하여 C/D를 생략.
#[test]
fn b_deadline_keeps_independent_history_and_stash() {
    if !isolated("b_deadline_keeps_independent_history_and_stash") {
        return;
    }
    local_deadline_keeps_later_stages("stage_b");
}

// 이것을 실패시키는 것: C-local Deadline에서 요청 전체를 중단하여 D를 생략.
#[test]
fn c_deadline_keeps_independent_stash() {
    if !isolated("c_deadline_keeps_independent_stash") {
        return;
    }
    local_deadline_keeps_later_stages("stage_c");
}

fn local_deadline_keeps_later_stages(expired: &'static str) {
    let f = Fixture::new();
    f.init();
    // The real Git oracle fixes the independent C/D results before confinement.
    assert_eq!(
        f.git(&["rev-list", "--left-right", "--count", "HEAD...@{upstream}"])
            .split_whitespace()
            .collect::<Vec<_>>(),
        ["0", "0"]
    );
    assert!(f.git(&["stash", "list"]).is_empty());
    let mut m = meter(); // 120s request; only the selected stage expires.
    m.hook = Some(Box::new(move |event| {
        if event == expired {
            std::thread::sleep(Duration::from_millis(60));
        }
    }));
    let mut deadlines = GENEROUS;
    if expired == "stage_b" {
        deadlines.b_ms = 50;
    } else {
        deadlines.c_ms = 50;
    }
    let s = stream(&f, m, deadlines, false);
    assert!(
        matches!(s.result, Err(CollectError::Read(ReadError::Deadline))),
        "{:?}",
        s.result
    );
    let expected = if expired == "stage_b" {
        ["A", "C", "D"]
    } else {
        ["A", "B", "D"]
    };
    assert_eq!(s.values.iter().map(stage).collect::<Vec<_>>(), expected);
    let last = s.values.last().unwrap();
    for name in ["staged", "modified", "untracked", "conflicted", "filtered"] {
        if expired == "stage_b" {
            assert_eq!(field(last, name), &Field::PENDING, "{name}");
        } else if name == "filtered" {
            assert_eq!(field(last, name), &Field::known(FieldValue::Bool(false)));
        } else {
            count(last, name, 0);
        }
    }
    for name in ["ahead", "behind"] {
        if expired == "stage_c" {
            assert_eq!(field(last, name), &Field::PENDING, "{name}");
        } else {
            count(last, name, 0);
        }
    }
    count(last, "stash", 0);
    assert_eq!(
        field(last, "partial"),
        &Field::known(FieldValue::Bool(true))
    );
    assert!(
        !s.frames
            .iter()
            .any(|f| { wire::decode_frame(f).unwrap().kind == Kind::Complete })
    );
    let result = completed(&s, EndReason::Deadline);
    assert!(result.progress.stage_a_complete);
    assert_eq!(result.updates[0].value.as_ref(), Some(last));
}

// 이것을 실패시키는 것: panic을 stage 밖으로 내보내거나 A를 지우거나 Complete 발행.
#[test]
fn panic_after_a_preserves_a() {
    if !isolated("panic_after_a_preserves_a") {
        return;
    }
    let f = Fixture::new();
    f.init();
    let mut m = meter();
    m.hook = Some(Box::new(|event| {
        if event == "stage_b" {
            panic!("injected stage B unwind");
        }
    }));
    let s = stream(&f, m, GENEROUS, false);
    assert!(
        matches!(s.result, Err(CollectError::Panic)),
        "{:?}",
        s.result
    );
    assert_eq!(s.values.iter().map(stage).collect::<Vec<_>>(), ["A"]);
    let result = completed(&s, EndReason::WorkerExit);
    assert!(result.progress.stage_a_complete);
    assert_eq!(stage(result.updates[0].value.as_ref().unwrap()), "A");
    assert!(
        !s.frames
            .iter()
            .any(|f| wire::decode_frame(f).unwrap().kind == Kind::Complete)
    );
}

// 이것을 실패시키는 것: 잘린 B frame으로 검증 완료 A를 교체하거나 sink 실패 뒤 계속 발행.
#[test]
fn partial_frame_never_replaces_completed_stage() {
    if !isolated("partial_frame_never_replaces_completed_stage") {
        return;
    }
    let f = Fixture::new();
    f.init();
    let s = stream(&f, meter(), GENEROUS, true);
    assert!(
        matches!(&s.result, Err(CollectError::Sink(e)) if e.kind() == std::io::ErrorKind::BrokenPipe)
    );
    assert_eq!(s.frames.len(), 3);
    assert_eq!(
        wire::decode_frame(s.frames.last().unwrap()).unwrap_err(),
        wire::ProtocolError::Length
    );
    let result = completed(&s, EndReason::Protocol);
    assert_eq!(stage(result.updates[0].value.as_ref().unwrap()), "A");
    assert!(result.progress.stage_a_complete);
}

// 이것을 실패시키는 것: A 실패를 임의 branch/성공 Progress/Complete로 바꿈.
#[test]
fn invalid_a_is_hidden_before_any_frame() {
    let f = Fixture::new();
    f.init();
    f.write(".git/HEAD", b"invalid\n");
    let s = stream(&f, meter(), GENEROUS, false);
    assert!(
        matches!(s.result, Err(CollectError::Read(ReadError::Denied))),
        "{:?}",
        s.result
    );
    assert!(s.frames.is_empty());
}

// 이것을 실패시키는 것: B 마감 뒤 신규 read 또는 전체 마감 이후 Update 발행.
// Dedicated product-deadline test: scheduling may exhaust A before any Update.
#[test]
fn stage_deadlines_stop_work_without_confident_partial_values() {
    if !isolated("stage_deadlines_stop_work_without_confident_partial_values") {
        return;
    }
    let f = Fixture::new();
    f.init();
    let events = Rc::new(RefCell::new(Vec::new()));
    let copy = events.clone();
    let mut m = Meter::new(Instant::now() + Duration::from_millis(50));
    m.hook = Some(Box::new(move |event| {
        copy.borrow_mut().push(event.to_owned());
        if event == "stage_b" {
            std::thread::sleep(Duration::from_millis(55));
        }
    }));
    let s = stream(&f, m, StageDeadlines::PRODUCT, false);
    assert!(
        matches!(s.result, Err(CollectError::Read(ReadError::Deadline))),
        "{:?}",
        s.result
    );
    assert!(s.values.iter().all(|v| stage(v) == "A"));
    if let Some(index) = events.borrow().iter().position(|e| e == "stage_b") {
        assert_eq!(events.borrow().len(), index + 1);
    }
    assert!(
        !s.frames
            .iter()
            .any(|f| wire::decode_frame(f).unwrap().kind == Kind::Complete)
    );
}

// 이것을 실패시키는 것: preflight 성공과 repository 초기화를 혼동해 독립 D를 생략.
#[test]
fn constructor_failure_after_preflight_still_runs_independent_d() {
    if !isolated("constructor_failure_after_preflight_still_runs_independent_d") {
        return;
    }
    let f = Fixture::new();
    f.init();
    let config = f.0.join(".git/config");
    let mut m = meter();
    m.hook = Some(Box::new(move |event| {
        if event == "repository_init" {
            fs::write(&config, b"[broken").unwrap();
        }
    }));
    let s = stream(&f, m, GENEROUS, false);
    s.result.as_ref().unwrap();
    assert_eq!(
        s.values.iter().map(stage).collect::<Vec<_>>(),
        ["A", "B", "C", "D"]
    );
    let last = s.values.last().unwrap();
    assert_eq!(field(last, "modified"), &Field::PENDING);
    assert_eq!(field(last, "ahead"), &Field::PENDING);
    count(last, "stash", 0);
    assert_eq!(
        field(last, "partial"),
        &Field::known(FieldValue::Bool(true))
    );
}

// 이것을 실패시키는 것: encode/validation 뒤 actual write 전에 stage 마감을 확인하지 않음.
#[test]
fn expired_stage_is_checked_at_the_wire_write_boundary() {
    use update_sink::UpdateSink;
    let f = Fixture::new();
    let r = f.request();
    let mut buffer = [0; wire::FRAME_MAX];
    let mut frames = Vec::new();
    let mut write = |bytes: &[u8]| {
        frames.push(bytes.to_vec());
        Ok(())
    };
    let deadline = std::cell::Cell::new(Instant::now() + Duration::from_secs(30));
    let expired = Instant::now();
    let mut sink = WireSink::new(&r, field::BUILTIN, &ready(&r), &mut buffer, &mut write).unwrap();
    sink.attach_write_deadline(&deadline);
    sink.stage_deadline(expired);
    assert_eq!(deadline.get(), expired);
    let error = sink
        .update(wire::Update {
            segment: 3,
            value: Some(bingsu_core::collection::git::no_repo()),
            facts: None,
        })
        .unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
    assert_eq!(
        sink.complete().unwrap_err().kind(),
        std::io::ErrorKind::Other
    );
    assert!(frames.is_empty());
}

// Measurement only. Generous semantic allowances expose the full cost rather
// than hiding work at the product cutoff; dedicated tests exercise that cutoff.
#[cfg(target_os = "macos")]
#[test]
#[ignore = "release warm 200-run observations; not a timing assertion"]
fn release_stage_stream_observations() {
    let cases = [
        "no-git",
        "git-clean",
        "git-dirty",
        "19000",
        "budget-bound",
        "known-global",
        "unknown-global",
    ];
    for case in cases {
        let f = Fixture::new();
        if case != "no-git" {
            f.init();
            if case == "19000" {
                for i in 0..19_000 {
                    f.write(&format!("d{:03}/f{i:05}", i / 100), b"file\n");
                }
                f.git(&["add", "."]);
                f.git(&["commit", "-qm", "large"]);
            }
            if case == "git-dirty" {
                f.write("tracked", b"changed\n");
                f.write("loose", b"new\n");
            }
            if matches!(case, "known-global" | "unknown-global") {
                f.write(".DS_Store", b"ignored globally\n");
                f.write("visible", b"untracked\n");
            }
            if case == "budget-bound" {
                f.write(".git/index", vec![0; 4_194_305]);
            }
        }
        let mut r = f.request();
        if case == "known-global" {
            r.global_excludes = b".DS_Store\n".to_vec();
        } else if case == "unknown-global" {
            r.global_excludes_known = false;
        }
        let mut samples = vec![Vec::new(); 5];
        let mut cold = Vec::new();
        let mut sizes = (0, 0);
        for iteration in 0..201 {
            let access = access();
            let mut buffer = [0; wire::FRAME_MAX];
            let mut stamps = Vec::new();
            let mut bytes = 0;
            let start = Instant::now();
            let mut write = |frame: &[u8]| {
                bytes += frame.len();
                if wire::decode_frame(frame).unwrap().kind == Kind::Update {
                    stamps.push(start.elapsed().as_nanos());
                }
                Ok(())
            };
            let mut sink =
                WireSink::new(&r, field::BUILTIN, &ready(&r), &mut buffer, &mut write).unwrap();
            git::collect_with_deadlines(&r, &mut sink, meter(), access, GENEROUS).unwrap();
            sink.complete().unwrap();
            let total = start.elapsed().as_nanos();
            let mut previous = 0;
            let mut values = [0; 5];
            for (i, stamp) in stamps.iter().enumerate().take(4) {
                values[i] = *stamp - previous;
                previous = *stamp;
            }
            values[4] = total;
            if iteration == 0 {
                cold = values.to_vec();
            } else {
                for (sample, value) in samples.iter_mut().zip(values) {
                    sample.push(value);
                }
            }
            sizes = (stamps.len(), bytes + wire::HEADER + 24);
        }
        for (i, name) in ["A", "B-window", "C", "D", "total"].into_iter().enumerate() {
            let raw = &samples[i];
            let mut sorted = raw.clone();
            sorted.sort_unstable();
            let mean = raw.iter().sum::<u128>() as f64 / raw.len() as f64;
            let variance =
                raw.iter().map(|n| (*n as f64 - mean).powi(2)).sum::<f64>() / raw.len() as f64;
            println!(
                "D3_PERF case={case} phase={name} n=200 cold_ns={} p50_ns={} p95_ns={} variance_ns2={variance:.0} updates={} bytes={} raw={raw:?}",
                cold[i], sorted[100], sorted[190], sizes.0, sizes.1
            );
        }
    }
}

#[test]
#[ignore = "release warm 200-run codec/clone cost, including the maximal request binding"]
fn release_wire_clone_observations() {
    use update_sink::UpdateSink;
    let f = Fixture::new();
    for large in [false, true] {
        let mut r = f.request();
        if large {
            r.binding.config = vec![b'c'; 65_536];
            r.binding.config[0] = b'/';
            r.binding.state = vec![b's'; 65_536];
            r.binding.state[0] = b'/';
            r.binding.cwd = vec![b'w'; 65_536];
            r.binding.cwd[0] = b'/';
            r.binding.path_query = PathQuery::default();
            r.binding.snapshot.context =
                snapshot::context_crc(&r.binding.config, &r.binding.state).unwrap();
        }
        let mut samples = Vec::new();
        let mut cold = 0;
        for iteration in 0..201 {
            let mut buffer = [0; wire::FRAME_MAX];
            let mut bytes = 0;
            let mut write = |frame: &[u8]| {
                bytes += frame.len();
                Ok(())
            };
            let start = Instant::now();
            let mut sink =
                WireSink::new(&r, field::BUILTIN, &ready(&r), &mut buffer, &mut write).unwrap();
            for _ in 0..4 {
                sink.update(wire::Update {
                    segment: 3,
                    value: Some(bingsu_core::collection::git::no_repo()),
                    facts: None,
                })
                .unwrap();
            }
            sink.complete().unwrap();
            let ns = start.elapsed().as_nanos();
            if iteration == 0 {
                cold = ns;
            } else {
                samples.push(ns);
            }
            std::hint::black_box(bytes);
        }
        println!("D3_WIRE_RAW large={large} raw_ns={samples:?}");
        samples.sort_unstable();
        println!(
            "D3_WIRE large={large} n=200 cold_ns={cold} p50_ns={} p95_ns={}",
            samples[100], samples[190]
        );
    }
}

#[cfg(target_os = "macos")]
#[test]
#[ignore = "release product-deadline outcomes for 19,000 tracked files, 200 warm runs"]
fn release_product_deadline_observations() {
    let f = Fixture::new();
    f.init();
    for i in 0..19_000 {
        f.write(&format!("d{:03}/f{i:05}", i / 100), b"file\n");
    }
    f.git(&["add", "."]);
    f.git(&["commit", "-qm", "large"]);
    let r = f.request();
    let mut durations = Vec::new();
    let mut stages = [0usize; 5];
    let mut completed = 0;
    for iteration in 0..201 {
        let access = access();
        let start = Instant::now();
        let mut buffer = [0; wire::FRAME_MAX];
        let mut transcript = receiver(&r);
        let mut write = |bytes: &[u8]| {
            transcript.accept_bytes(bytes).unwrap();
            Ok(())
        };
        let mut sink =
            WireSink::new(&r, field::BUILTIN, &ready(&r), &mut buffer, &mut write).unwrap();
        let result = git::collect_with_access(
            &r,
            &mut sink,
            Meter::new(start + Duration::from_millis(50)),
            access,
        );
        let complete = if result.is_ok() {
            use update_sink::UpdateSink;
            sink.stage_deadline(start + Duration::from_millis(50));
            sink.complete().is_ok()
        } else {
            false
        };
        let ns = start.elapsed().as_nanos();
        if iteration > 0 {
            durations.push(ns);
            completed += usize::from(complete);
            let last = transcript.finish(EndReason::Deadline, clock()).unwrap();
            let index =
                last.as_ref()
                    .map_or(0, |s| match stage(s.updates[0].value.as_ref().unwrap()) {
                        "A" => 1,
                        "B" => 2,
                        "C" => 3,
                        "D" => 4,
                        _ => unreachable!(),
                    });
            stages[index] += 1;
            if let Some(last) = last {
                let value = last.updates[0].value.as_ref().unwrap();
                // Every confident B field still agrees with git's clean tree.
                for name in ["staged", "modified", "untracked", "conflicted"] {
                    if field(value, name).state == field::ValueState::Known {
                        count(value, name, 0);
                    }
                }
            }
        } else {
            println!("D3_PRODUCT cold_ns={ns}");
        }
    }
    println!("D3_PRODUCT_RAW raw_ns={durations:?}");
    durations.sort_unstable();
    println!(
        "D3_PRODUCT n=200 p50_ns={} p95_ns={} complete={completed} last_hidden_a_b_c_d={stages:?}",
        durations[100], durations[190]
    );
}

// 이것을 실패시키는 것: stage 전환에서 Meter를 새로 만들어 요청 counter를 초기화.
#[test]
fn request_counters_survive_stage_transitions() {
    if !isolated("request_counters_survive_stage_transitions") {
        return;
    }
    let f = Fixture::new();
    f.init();
    // Unequal tips must consult the exhausted request-wide commit budget.
    f.git(&["commit", "--allow-empty", "-qm", "ahead"]);
    let mut m = meter();
    m.charge_axis(
        bingsu_core::collection::budget::Axis::Commits,
        bingsu_core::collection::budget::COMMITS,
    )
    .unwrap();
    let s = stream(&f, m, GENEROUS, false);
    s.result.as_ref().unwrap();
    let last = s.values.last().unwrap();
    count(last, "staged", 0);
    count(last, "modified", 0);
    count(last, "untracked", 0);
    assert_eq!(field(last, "ahead"), &Field::PENDING);
    assert_eq!(field(last, "behind"), &Field::PENDING);
    count(last, "stash", 0);
    assert_eq!(stage(last), "D");
}
