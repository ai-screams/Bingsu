//! The worker's request loop: decoded helper input must reach collection.
#![cfg(unix)]
#[cfg(target_os = "linux")]
#[allow(dead_code)]
#[path = "../src/filter.rs"]
mod filter;
#[allow(dead_code)]
#[path = "../src/git/mod.rs"]
mod git;
#[cfg(target_os = "linux")]
#[allow(dead_code)]
#[path = "../src/landlock.rs"]
mod landlock;
#[allow(dead_code)]
#[path = "../src/limits.rs"]
mod limits;
#[allow(dead_code)]
#[path = "../src/meter.rs"]
mod meter;
#[allow(dead_code)]
#[path = "../src/safe_read/mod.rs"]
mod safe_read;
#[allow(dead_code)]
#[path = "../src/sys.rs"]
mod sys;
#[allow(dead_code)]
#[path = "../src/update_sink.rs"]
mod update_sink;
#[allow(dead_code)]
#[path = "../src/worker.rs"]
mod worker;
pub use bingsu_identity::build_id;

use bingsu_core::{
    collection::{
        path_facts::PathQuery,
        selection::Catalog,
        wire::{self, Binding, BuildId, EndReason, Frame, Kind, Request, Transcript},
    },
    field::{self, Field, FieldValue, Value},
    snapshot::{self, Clock, Identity},
};
use std::{
    fs::{self, File},
    io::{Read, Write},
    os::{
        fd::{FromRawFd, OwnedFd},
        unix::ffi::OsStrExt,
    },
    path::PathBuf,
    process::Command,
    time::{Duration, Instant},
};

const GENEROUS: git::StageDeadlines = git::StageDeadlines {
    a_ms: 30_000,
    b_ms: 30_000,
    c_ms: 30_000,
    d_ms: 30_000,
    path_ms: 30_000,
};
/// Git only, as the product catalog grants it once enabled.
const GIT_ONLY: Catalog<'static> = Catalog {
    segments: field::BUILTIN,
    workers: 1 << 3,
};

fn meter() -> meter::Meter {
    meter::Meter::new(Instant::now() + Duration::from_secs(120))
}
fn pipe() -> (File, File) {
    let mut fds = [0; 2];
    // SAFETY: pipe writes two descriptors to valid storage.
    assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
    // SAFETY: new read descriptor, transferred exactly once.
    let read = unsafe { OwnedFd::from_raw_fd(fds[0]) };
    // SAFETY: new write descriptor, transferred exactly once.
    let write = unsafe { OwnedFd::from_raw_fd(fds[1]) };
    (File::from(read), File::from(write))
}
struct Dir(PathBuf);
impl Dir {
    fn new(tag: &str) -> Self {
        static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!(
            "bingsu-worker-{tag}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        // Never adopt or delete an existing path; a leftover name fails loudly.
        fs::create_dir(&path).unwrap();
        Self(fs::canonicalize(path).unwrap())
    }
    fn write(&self, name: &str, bytes: &[u8]) {
        let path = self.0.join(name);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, bytes).unwrap();
    }
    fn git(&self, args: &[&str]) {
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
        assert!(out.status.success(), "git {args:?}");
    }
}
impl Drop for Dir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn access() -> safe_read::Access {
    #[cfg(target_os = "linux")]
    let access = safe_read::Access::probe(&mut meter()).unwrap();
    #[cfg(target_os = "macos")]
    let access = {
        use std::os::fd::AsFd;
        let f = Dir::new("probe");
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
        let fd = File::open(&f.0).unwrap();
        safe_read::macos::probe_unvalidated_for_test(Some(fd.as_fd()), &mut meter()).unwrap()
    };
    assert!(
        access.guarantee().is_some(),
        "BLOCKED: kernel guarantee required"
    );
    access
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
fn request(cwd: &[u8], build_id: BuildId) -> Request {
    Request {
        request_id: wire::M3B_REQUEST_ID,
        binding: Binding {
            build_id,
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
            path_query: PathQuery::for_path(cwd, Some(cwd), false),
            cwd: cwd.to_vec(),
            mask: 1 << 3,
        },
        budget_ms: 50,
        environment: vec![],
        global_excludes_known: true,
        global_excludes: b"*.log\n".to_vec(),
    }
}
/// The helper's framing of one request: Begin, offset chunks, End checksum.
fn request_frames(request: &Request) -> Vec<u8> {
    let body = request.encode_body().unwrap();
    let mut buffer = [0; wire::FRAME_MAX];
    let mut out = Vec::new();
    let mut append = |kind, payload: &[u8]| {
        let frame = Frame {
            kind,
            build_id: request.binding.build_id,
            request_id: request.request_id,
            payload,
        };
        let n = wire::encode_frame(frame, &mut buffer).unwrap();
        out.extend_from_slice(&buffer[..n]);
    };
    let mut begin = (body.len() as u32).to_le_bytes().to_vec();
    begin.extend(wire::FEATURES.to_le_bytes());
    append(Kind::RequestBegin, &begin);
    let mut offset = 0u32;
    for part in body.chunks(wire::PAYLOAD_MAX - 4) {
        let mut payload = offset.to_le_bytes().to_vec();
        payload.extend_from_slice(part);
        append(Kind::RequestChunk, &payload);
        offset += part.len() as u32;
    }
    append(Kind::RequestEnd, &snapshot::crc32c(&[&body]));
    out
}
fn field<'a>(v: &'a Value, name: &str) -> &'a Field {
    &v.fields[field::BUILTIN[3].field_index(name).unwrap()]
}

/// The Linux read layer is irreversible and needs no_new_privs, as the shipped
/// worker sets before Ready. Run the body in a disposable child of this test.
fn isolated(name: &str) -> bool {
    if std::env::var("BINGSU_WORKER_EXCHANGE_CHILD")
        .ok()
        .as_deref()
        == Some(name)
    {
        #[cfg(target_os = "linux")]
        assert_eq!(
            // SAFETY: irreversible restriction only in this disposable child.
            unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) },
            0
        );
        return true;
    }
    let out = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", name, "--nocapture", "--test-threads=1"])
        .env("BINGSU_WORKER_EXCHANGE_CHILD", name)
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

// 이것을 실패시키는 것: worker가 디코드한 요청 대신 재구성한 요청(collection::request)을
// collect에 넘기는 것(known=false로 untracked·filtered Pending), 또는 global_excludes
// 바이트만 빠뜨리는 것(전역 패턴에 걸린 파일이 untracked 2로 세어짐).
#[test]
fn decoded_global_excludes_reach_collection_through_exchange() {
    if !isolated("decoded_global_excludes_reach_collection_through_exchange") {
        return;
    }
    let repo = Dir::new("repo");
    repo.git(&["init", "-q", "--initial-branch=main"]);
    repo.write("tracked", b"base\n");
    repo.git(&["add", "."]);
    repo.git(&["commit", "-qm", "base"]);
    repo.write("visible", b"untracked\n");
    repo.write("global.log", b"ignored only by the global input\n");
    // Outside the worktree, where it would count as untracked.
    let lock_dir = Dir::new("lock");
    let lock = File::create(lock_dir.0.join("lock")).unwrap();
    let build = BuildId([7; 32]);
    let request = request(repo.0.as_os_str().as_bytes(), build);

    let (request_read, mut request_write) = pipe();
    let (mut result_read, result_write) = pipe();
    request_write.write_all(&request_frames(&request)).unwrap();
    drop(request_write);
    let reader = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        result_read.read_to_end(&mut bytes).unwrap();
        bytes
    });
    let mut fds = sys::worker_fds_for_test(result_write, request_read, lock);
    let access = access();
    worker::exchange_for_test(&mut fds, &GIT_ONLY, build, |decoded, sink, _| {
        git::collect_with_deadlines(decoded, sink, meter(), access, GENEROUS)
            .map_err(|e| std::io::Error::other(format!("git collection: {e:?}")))
    })
    .unwrap();
    drop(fds);
    let bytes = reader.join().unwrap();

    let mut transcript = Transcript::with_catalog(&request, field::BUILTIN).unwrap();
    let mut rest = &bytes[..];
    let mut first = true;
    while !rest.is_empty() {
        let len = wire::frame_len(&rest[..wire::HEADER]).unwrap();
        transcript
            .accept(wire::decode_frame(&rest[..len]).unwrap())
            .unwrap();
        if first {
            transcript.request_sent().unwrap();
            first = false;
        }
        rest = &rest[len..];
    }
    let completed = transcript
        .finish(EndReason::Complete, clock())
        .unwrap()
        .unwrap();
    let git = completed
        .updates
        .iter()
        .find(|u| u.segment == 3)
        .and_then(|u| u.value.as_ref())
        .expect("git value");
    assert_eq!(
        field(git, "untracked"),
        &Field::known(FieldValue::Count {
            n: 1,
            saturated: false
        }),
        "global pattern excludes global.log; only visible remains"
    );
    assert_eq!(
        field(git, "filtered"),
        &Field::known(FieldValue::Bool(false))
    );
    assert_eq!(
        field(git, "partial"),
        &Field::known(FieldValue::Bool(false))
    );
}
