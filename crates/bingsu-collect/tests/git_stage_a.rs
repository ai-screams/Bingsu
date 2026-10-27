//! Product lower-crate C5 boundary, with an explicit test catalog (mask stays 0).
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
#[allow(dead_code)]
#[path = "../src/update_sink.rs"]
mod update_sink;

use bingsu_core::{
    collection::{
        budget,
        git::{self as schema, StageResult},
        path_facts::PathQuery,
        wire::{self, Binding, BuildId, Progress, Request, Update},
    },
    field::{self, Field, FieldValue, Value},
    snapshot::{self, Identity},
};
use git::{
    CollectError,
    discover::{RepoRoots, discover_with_access},
    preflight::{AOnlyReason, GitAccess, preflight},
    stage_a::{HeadPolicy, stage_a},
};
use meter::{Meter, Phase};
use safe_read::{Access, ReadError as E};
use std::{
    cell::RefCell,
    fs,
    os::unix::{ffi::OsStrExt, fs::symlink},
    path::{Path, PathBuf},
    process::Command,
    rc::Rc,
    time::{Duration, Instant},
};
use update_sink::UpdateSink;

const OID: &[u8] = b"1234567890ABCDEF1234567890ABCDEF12345678";
fn meter() -> Meter {
    Meter::new(Instant::now() + Duration::from_secs(30))
}
// Error kinds, event order and counts must not depend on the product's 5ms A
// or 28ms B allowance. The absolute request deadline is still authoritative.
fn collect(
    request: &Request,
    sink: &mut dyn UpdateSink,
    meter: Meter,
    access: Access,
) -> Result<(), CollectError> {
    git::collect_with_deadlines(
        request,
        sink,
        meter,
        access,
        git::StageDeadlines {
            a_ms: 30_000,
            b_ms: 30_000,
            path_ms: 30_000,
            c_ms: 30_000,
            d_ms: 30_000,
        },
    )
}
struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let base =
            std::env::var_os("BINGSU_C5_CHILD_ROOT").map_or_else(std::env::temp_dir, PathBuf::from);
        let path = base.join(format!(
            "bingsu-c5-{}-{}",
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
    fn repo(&self) {
        self.write(".git/HEAD", b"ref: refs/heads/main\n");
        self.write(".git/refs/heads/main", OID);
        self.write(".git/config", b"[core]\nrepositoryformatversion=0\n");
    }
    fn request(&self) -> Request {
        request(&self.0)
    }
    fn roots(&self, m: &mut Meter) -> RepoRoots {
        discover_with_access(&self.request(), access(), m)
            .unwrap()
            .unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn request(path: &Path) -> Request {
    let cwd = path.as_os_str().as_bytes().to_vec();
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
            mask: 1 << schema::SEGMENT,
        },
        budget_ms: 50,
        environment: vec![],
        global_excludes_known: true,
        global_excludes: vec![],
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
            symlink(target, f.0.join(name)).unwrap();
        }
        let fd = fs::File::open(&f.0).unwrap();
        safe_read::macos::probe_unvalidated_for_test(Some(fd.as_fd()), &mut meter()).unwrap()
    };
    assert!(
        access.guarantee().is_some(),
        "BLOCKED: actual kernel guarantee required"
    );
    access
}
fn value(result: StageResult) -> Value {
    match result {
        StageResult::Partial(v) | StageResult::Value(v) => v,
        StageResult::Hidden => panic!("unexpected Hidden"),
    }
}
fn field<'a>(v: &'a Value, name: &str) -> &'a Field {
    &v.fields[field::BUILTIN[3].field_index(name).unwrap()]
}
fn text(v: &Value, name: &str) -> Option<String> {
    match &field(v, name).value {
        FieldValue::Text(v) => Some(v.as_str().to_owned()),
        _ => None,
    }
}
fn pending(v: &Value) {
    for name in [
        "staged",
        "modified",
        "untracked",
        "conflicted",
        "ahead",
        "behind",
        "stash",
        "filtered",
    ] {
        assert_eq!(field(v, name), &Field::PENDING, "{name}");
    }
    assert_eq!(field(v, "partial"), &Field::known(FieldValue::Bool(true)));
    assert_eq!(text(v, "stage").as_deref(), Some("A"));
}
fn observed() -> (Meter, Rc<RefCell<Vec<String>>>) {
    let events = Rc::new(RefCell::new(Vec::new()));
    let copy = events.clone();
    let mut m = meter();
    m.hook = Some(Box::new(move |event| {
        copy.borrow_mut().push(event.to_owned())
    }));
    (m, events)
}
fn no_objects(m: &Meter, events: &[String]) {
    for axis in [
        budget::Axis::Packs,
        budget::Axis::PackBytes,
        budget::Axis::MappedBytes,
        budget::Axis::DecompressedBytes,
    ] {
        assert_eq!(m.budget.used(axis), 0, "{axis:?}");
    }
    assert!(!events.iter().any(|p| p.contains("objects/pack")
        || p.contains("multi-pack-index")
        || p.contains("commit-graph")));
    assert!(
        !events
            .iter()
            .filter_map(|p| p.strip_prefix("resolve:objects/"))
            .any(|p| p != "info" && !p.starts_with("info/"))
    );
}

// 이것을 실패시키는 것: HEAD 파싱/정제, unborn 부재, operation 우선순위 또는 Pending 유지 제거.
#[test]
fn stage_a_identity_operations_and_hostile_branch() {
    let f = Fixture::new();
    f.repo();
    let mut m = meter();
    let roots = f.roots(&mut m);
    let v = value(stage_a(&roots, HeadPolicy::OwnedMetadata, &mut m));
    assert_eq!(text(&v, "branch").as_deref(), Some("main"));
    pending(&v);
    fs::remove_file(f.0.join(".git/refs/heads/main")).unwrap();
    let v = value(stage_a(&roots, HeadPolicy::OwnedMetadata, &mut m));
    assert_eq!(field(&v, "branch"), &Field::ABSENT);
    assert_eq!(field(&v, "commit"), &Field::ABSENT);
    f.write(".git/HEAD", OID);
    let v = value(stage_a(&roots, HeadPolicy::OwnedMetadata, &mut m));
    assert_eq!(text(&v, "commit").as_deref(), Some("1234567890ab"));
    assert_eq!(field(&v, "detached"), &Field::known(FieldValue::Bool(true)));
    let operations = [
        ("rebase-merge", "rebase"),
        ("rebase-apply", "rebase"),
        ("MERGE_HEAD", "merge"),
        ("CHERRY_PICK_HEAD", "cherry-pick"),
        ("REVERT_HEAD", "revert"),
        ("BISECT_LOG", "bisect"),
    ];
    for (name, _) in operations {
        if name.starts_with("rebase") {
            fs::create_dir(f.0.join(".git").join(name)).unwrap();
        } else {
            f.write(&format!(".git/{name}"), b"");
        }
    }
    for (name, expected) in operations {
        assert_eq!(
            text(
                &value(stage_a(&roots, HeadPolicy::OwnedMetadata, &mut m)),
                "operation"
            )
            .as_deref(),
            Some(expected)
        );
        let p = f.0.join(".git").join(name);
        if p.is_dir() {
            fs::remove_dir(p).unwrap();
        } else {
            fs::remove_file(p).unwrap();
        }
    }
    assert_eq!(
        field(
            &value(stage_a(&roots, HeadPolicy::OwnedMetadata, &mut m)),
            "operation"
        ),
        &Field::ABSENT
    );
    for head in [
        b"ref: refs/heads/evil\x1b[31m\n".as_slice(),
        b"ref: refs/heads/../bad\n",
        b"broken",
        &vec![b'x'; 65_537],
    ] {
        f.write(".git/HEAD", head);
        assert_eq!(
            stage_a(&roots, HeadPolicy::OwnedMetadata, &mut m),
            StageResult::Hidden
        );
    }
    f.write(
        ".git/HEAD",
        "ref: refs/heads/$(touch-pwn);`cmd`-\u{202e}name\n",
    );
    let v = value(stage_a(&roots, HeadPolicy::HeadOnly, &mut m));
    assert!(text(&v, "branch").unwrap().contains("$(touch-pwn)"));
    assert!(!text(&v, "branch").unwrap().contains('\u{202e}'));
}

// 이것을 실패시키는 것: 모든 위험 표식의 차단, false 극성, packed namespace 검사 또는 객체 선행 접근.
#[test]
fn alternates_replace_worktree_stop_before_objects() {
    let cases = [
        ("objects/info/alternates", b"/outside/objects\n".as_slice(), AOnlyReason::Alternates),
        ("objects/info/http-alternates", b"https://example.invalid\n", AOnlyReason::Alternates),
        ("refs/replace/1234567890123456789012345678901234567890", OID, AOnlyReason::LooseReplace),
        ("packed-refs", b"1234567890123456789012345678901234567890 refs/replace/1234567890123456789012345678901234567890\n", AOnlyReason::PackedReplace),
        ("config", b"[core]\nworktree\n", AOnlyReason::CoreWorktree),
        ("config.worktree", b"[core]\nworktree=/\n", AOnlyReason::CoreWorktree),
        ("config", b"[core]\nuseReplaceRefs=false\n", AOnlyReason::UseReplaceRefs),
        ("config", b"[CoRe]\nUsErEpLaCeReFs=true\n", AOnlyReason::UseReplaceRefs),
        ("config.worktree", b"[core]\nuseReplaceRefs\n", AOnlyReason::UseReplaceRefs),
    ];
    for (path, bytes, reason) in cases {
        let f = Fixture::new();
        f.repo();
        f.write(&format!(".git/{path}"), bytes);
        let (mut m, events) = observed();
        let roots = f.roots(&mut m);
        let v = value(stage_a(&roots, roots.head_policy(), &mut m));
        pending(&v);
        assert_eq!(
            preflight(&roots, &mut m).unwrap(),
            GitAccess::StageAOnly,
            "{path}"
        );
        assert_eq!(roots.a_only_reason(), Some(reason));
        pending(&v);
        no_objects(&m, &events.borrow());
    }
}

// 이것을 실패시키는 것: pinned lower crates에서 위험 표식을 무시하거나 config 극성으로 replace를 활성화하는 것.
#[test]
fn x09_replace_and_alternates_are_stage_a_only() {
    for setting in [
        "",
        "[core]\nuseReplaceRefs=true\n",
        "[core]\nuseReplaceRefs=false\n",
    ] {
        for marker in ["alternates", "http-alternates", "loose", "packed"] {
            let f = Fixture::new();
            f.repo();
            f.write(".git/config", setting);
            match marker {
                "alternates" | "http-alternates" => f.write(&format!(".git/objects/info/{marker}"), b""),
                "loose" => f.write(".git/refs/replace/1234567890123456789012345678901234567890", OID),
                "packed" => f.write(".git/packed-refs", b"1234567890123456789012345678901234567890 refs/replace/1234567890123456789012345678901234567890\n"),
                _ => unreachable!(),
            }
            let (mut m, events) = observed();
            let roots = f.roots(&mut m);
            let v = value(stage_a(&roots, roots.head_policy(), &mut m));
            assert_eq!(preflight(&roots, &mut m).unwrap(), GitAccess::StageAOnly);
            pending(&v);
            no_objects(&m, &events.borrow());
        }
    }
}

fn linked(f: &Fixture) -> Request {
    f.write("main/.git/HEAD", OID);
    fs::create_dir_all(f.0.join("main/.git/objects")).unwrap();
    fs::create_dir_all(f.0.join("main/.git/refs")).unwrap();
    f.write("main/.git/worktrees/linked/HEAD", OID);
    f.write("main/.git/worktrees/linked/commondir", b"../..\n");
    f.write(
        "main/.git/worktrees/linked/gitdir",
        f.0.join("linked/.git").as_os_str().as_bytes(),
    );
    f.write("linked/.git", b"gitdir: ../main/.git/worktrees/linked\n");
    request(&f.0.join("linked"))
}

fn submodule(f: &Fixture, worktree: &str, gitdir: &str) -> Request {
    f.write(&format!("{gitdir}/HEAD"), b"ref: refs/heads/main\n");
    f.write(&format!("{gitdir}/refs/heads/main"), OID);
    f.write(
        &format!("{gitdir}/config"),
        format!("[core]\nworktree = {}\n", f.0.join(worktree).display()),
    );
    f.write(
        &format!("{worktree}/.git"),
        format!("gitdir: {}\n", f.0.join(gitdir).display()),
    );
    let mut r = request(&f.0.join(worktree));
    r.binding.path_query =
        PathQuery::for_path(&r.binding.cwd, Some(f.0.as_os_str().as_bytes()), false);
    r
}

fn large_config(f: &Fixture, gitdir: &str) {
    let name = format!("{gitdir}/config");
    let mut bytes = fs::read(f.0.join(&name)).unwrap();
    bytes.extend(b"filemode=true\n".repeat(900));
    bytes.push(b'#');
    bytes.resize(65_536, b' ');
    f.write(&name, bytes);
}

fn depth8(f: &Fixture, large: bool) -> Request {
    let mut r = f.request();
    let mut worktree = String::from("a");
    let mut gitdir = String::from(".git");
    if large {
        large_config(f, &gitdir);
    }
    for _ in 0..8 {
        gitdir.push_str("/modules/a");
        r = submodule(f, &worktree, &gitdir);
        if large {
            large_config(f, &gitdir);
        }
        worktree.push_str("/a");
    }
    r
}

// 이것을 실패시키는 것: discovery/config/ref 임시 예약을 누적하거나 metadata를 worktree bytes에 계상.
#[test]
fn discovery_and_preflight_release_live_scratch() {
    for case in ["plain", "linked", "depth8-large"] {
        let f = Fixture::new();
        let r = match case {
            "linked" => linked(&f),
            "depth8-large" => {
                f.repo();
                depth8(&f, true)
            }
            _ => {
                f.repo();
                f.request()
            }
        };
        let mut m = meter();
        let baseline = m.live_allocated();
        for _ in 0..8 {
            let roots = discover_with_access(&r, access(), &mut m).unwrap().unwrap();
            let discovered = m.live_allocated();
            // Only the two verified binding paths may outlive discovery.
            assert!(discovered - baseline < 1024, "{case}: {discovered}");
            assert_eq!(m.budget.used(budget::Axis::WorktreeReadBytes), 0, "{case}");
            assert_eq!(
                text(
                    &value(stage_a(&roots, roots.head_policy(), &mut m)),
                    "branch"
                )
                .as_deref(),
                (case != "linked").then_some("main")
            );
            assert_eq!(preflight(&roots, &mut m).unwrap(), GitAccess::Objects);
            assert_eq!(m.live_allocated(), discovered, "{case}");
            assert_eq!(m.budget.used(budget::Axis::WorktreeReadBytes), 0, "{case}");
            drop(roots);
            assert_eq!(m.live_allocated(), baseline, "{case}");
        }
    }
}

// 이것을 실패시키는 것: metadata 읽기에 WorktreeReadBytes를 부과하거나 cap/live 예약 생략.
#[test]
fn metadata_reads_have_live_reservations_and_independent_caps() {
    let f = Fixture::new();
    f.repo();
    for access in [access(), Access::stage_a_only()] {
        let mut m = meter();
        let root = safe_read::acquire(f.0.as_os_str().as_bytes(), Default::default(), &mut m)
            .unwrap()
            .select_cwd()
            .unwrap()
            .git_directory(&mut m)
            .unwrap();
        let baseline = m.live_allocated();
        m.byte_limit = 0;
        m.budget
            .charge(budget::Axis::WorktreeReadBytes, budget::WORKTREE_READ_BYTES)
            .unwrap();
        for _ in 0..32 {
            assert_eq!(
                safe_read::read_stage_a(&root, safe_read::StageAFile::Head, &access, &mut m)
                    .unwrap(),
                b"ref: refs/heads/main\n"
            );
            assert_eq!(m.live_allocated(), baseline);
        }
        f.write(".git/HEAD", vec![b'x'; 65_537]);
        assert_eq!(
            safe_read::read_stage_a(&root, safe_read::StageAFile::Head, &access, &mut m),
            Err(E::Limit)
        );
        assert_eq!(m.live_allocated(), baseline);
        f.write(".git/HEAD", vec![b'x'; 65_536]);
        m.allocation_limit = 32_768;
        assert_eq!(
            safe_read::read_stage_a(&root, safe_read::StageAFile::Head, &access, &mut m),
            Err(E::Limit)
        );
        assert_eq!(m.live_allocated(), baseline);
        f.repo();
    }
}

// 이것을 실패시키는 것: 실제 A 5ms 마감 이후 Update/preflight를 허용하는 것.
#[test]
fn depth8_large_config_honors_stage_a_budget() {
    let f = Fixture::new();
    f.repo();
    let r = depth8(&f, true);
    let access = access();
    let events = Rc::new(RefCell::new(Vec::new()));
    let observed = events.clone();
    let mut m = meter();
    m.hook = Some(Box::new(move |event| {
        observed.borrow_mut().push(event.to_owned());
        if event == "discovery_candidate" {
            std::thread::sleep(Duration::from_millis(budget::A_MS + 1));
        }
    }));
    let mut sink = Recording::default();
    assert!(matches!(
        git::collect_with_access(&r, &mut sink, m, access),
        Err(CollectError::Read(E::Deadline))
    ));
    assert!(sink.updates.is_empty() && sink.progress.is_empty());
    assert!(!events.borrow().iter().any(|e| e == "preflight_start"));
}

// 이것을 실패시키는 것: parser 오류/정상 반환에서 scratch를 반환하지 않거나 cap 사전 검사를 생략.
#[test]
fn config_and_packed_parser_reservations_end_with_their_use() {
    let mut m = meter();
    let baseline = m.live_allocated();
    for _ in 0..4096 {
        let facts = git::config::parse(b"[core]\nworktree=../tree\n", &mut m).unwrap();
        assert_eq!(m.live_allocated(), baseline + b"../tree".len() as u64);
        drop(facts);
        assert_eq!(m.live_allocated(), baseline);
        assert!(matches!(
            git::config::parse(b"[broken", &mut m),
            Err(E::Io(libc::EINVAL))
        ));
        assert_eq!(m.live_allocated(), baseline);
    }
    for _ in 0..128 {
        let refs = git::refs::Refs::parse(
            b"1234567890123456789012345678901234567890 refs/heads/main\n",
            &mut m,
        )
        .unwrap();
        assert_eq!(
            m.live_allocated(),
            baseline + git::refs::PARSER_ALLOCATION as u64
        );
        drop(refs);
        assert_eq!(m.live_allocated(), baseline);
        assert!(matches!(
            git::refs::Refs::parse(b"broken\n", &mut m),
            Err(E::Io(libc::EINVAL))
        ));
        assert_eq!(m.live_allocated(), baseline);
    }
}

// 이것을 실패시키는 것: dangling symlink를 Missing으로 낮추거나 alternates leaf를 읽음.
#[test]
fn alternates_presence_includes_dangling_symlinks_and_directories() {
    for name in ["alternates", "http-alternates"] {
        for kind in ["file", "directory", "dangling", "symlink"] {
            let f = Fixture::new();
            f.repo();
            let path = format!(".git/objects/info/{name}");
            f.write(&path, b"");
            match kind {
                "directory" => {
                    fs::remove_file(f.0.join(&path)).unwrap();
                    fs::create_dir(f.0.join(&path)).unwrap();
                }
                "dangling" | "symlink" => {
                    fs::remove_file(f.0.join(&path)).unwrap();
                    if kind == "symlink" {
                        f.write(".git/objects/info/alternates-destination", b"outside");
                    }
                    symlink("alternates-destination", f.0.join(&path)).unwrap();
                }
                _ => {}
            }
            let (mut m, events) = observed();
            let roots = f.roots(&mut m);
            let v = value(stage_a(&roots, roots.head_policy(), &mut m));
            assert_eq!(
                preflight(&roots, &mut m).unwrap(),
                GitAccess::StageAOnly,
                "{name}/{kind}"
            );
            assert_eq!(roots.a_only_reason(), Some(AOnlyReason::Alternates));
            pending(&v);
            assert!(
                !events
                    .borrow()
                    .iter()
                    .any(|event| event == &format!("openat:{name}")
                        || event == "openat:alternates-destination")
            );
            no_objects(&m, &events.borrow());
        }
    }
}

// 이것을 실패시키는 것: 결속 검증 후 바뀐 config 또는 config.worktree를 무조건 신뢰.
#[test]
fn core_worktree_requires_the_discovered_reciprocal_binding() {
    for file in ["config", "config.worktree"] {
        for setting in ["/elsewhere", "", "implicit"] {
            let f = Fixture::new();
            f.repo();
            let r = submodule(&f, "a", ".git/modules/a");
            let (mut m, events) = observed();
            let roots = discover_with_access(&r, access(), &mut m).unwrap().unwrap();
            let v = value(stage_a(&roots, roots.head_policy(), &mut m));
            let entry = if setting == "implicit" {
                "worktree".to_owned()
            } else {
                format!("worktree={setting}")
            };
            f.write(
                &format!(".git/modules/a/{file}"),
                format!("[core]\n{entry}\n"),
            );
            assert_eq!(preflight(&roots, &mut m).unwrap(), GitAccess::StageAOnly);
            assert_eq!(roots.a_only_reason(), Some(AOnlyReason::CoreWorktree));
            pending(&v);
            no_objects(&m, &events.borrow());
        }
    }
    // Even an exact path in a plain repository has no reciprocal proof.
    let f = Fixture::new();
    f.repo();
    f.write(
        ".git/config",
        format!("[core]\nworktree={}\n", f.0.display()),
    );
    let mut m = meter();
    let roots = f.roots(&mut m);
    assert_eq!(preflight(&roots, &mut m).unwrap(), GitAccess::StageAOnly);
    assert_eq!(roots.a_only_reason(), Some(AOnlyReason::CoreWorktree));
}

fn git_oracle(path: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap())
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .env("GIT_TERMINAL_PROMPT", "0")
        .args(args)
        .current_dir(path)
        .output()
        .expect("Git oracle required in tests only");
    assert!(
        output.status.success(),
        "{args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap().trim().to_owned()
}

fn oracle_corpus(f: &Fixture, case: &str) -> Request {
    git_oracle(&f.0, &["init", "-qb", "main"]);
    git_oracle(
        &f.0,
        &[
            "-c",
            "user.name=fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "commit",
            "--allow-empty",
            "-qm",
            "fixture",
        ],
    );
    let mut worktree = f.0.clone();
    if case.starts_with("bare") {
        let name = if case == "bare.git" {
            "bare.git"
        } else {
            "metadata"
        };
        git_oracle(&f.0, &["clone", "-q", "--bare", ".", name]);
        git_oracle(
            &f.0.join(name),
            &["worktree", "add", "-qb", "linked", "../linked"],
        );
        worktree.push("linked");
    } else {
        if case == "submodule-linked" {
            git_oracle(&f.0, &["worktree", "add", "-qb", "linked", "linked"]);
            worktree.push("linked");
        }
        let name = match case {
            "submodule-path" => "vendor/foo",
            "submodule-deep-path" => "a/b/c",
            "submodule-nested-path" => "third_party/bar",
            "submodule-worktrees-name" => "vendor/worktrees/foo",
            _ => "a",
        };
        git_oracle(
            &worktree,
            &[
                "-c",
                "protocol.file.allow=always",
                "submodule",
                "add",
                "-q",
                f.0.to_str().unwrap(),
                name,
            ],
        );
        worktree.push(name);
        if matches!(case, "submodule-nested" | "submodule-nested-path") {
            let nested = if case == "submodule-nested-path" {
                "vendor/foo"
            } else {
                "b"
            };
            git_oracle(
                &worktree,
                &[
                    "-c",
                    "protocol.file.allow=always",
                    "submodule",
                    "add",
                    "-q",
                    f.0.to_str().unwrap(),
                    nested,
                ],
            );
            worktree.push(nested);
        }
    }
    let mut r = request(&worktree);
    r.binding.path_query =
        PathQuery::for_path(&r.binding.cwd, Some(f.0.as_os_str().as_bytes()), false);
    r
}

fn assert_git_identity(r: &Request) {
    let path = Path::new(std::ffi::OsStr::from_bytes(&r.binding.cwd));
    let status = git_oracle(
        path,
        &[
            "status",
            "--porcelain=v2",
            "--branch",
            "--ignore-submodules=all",
        ],
    );
    let header = |key: &str| status.lines().find_map(|s| s.strip_prefix(key)).unwrap();
    let oid = header("# branch.oid ");
    let branch = header("# branch.head ");
    let (mut m, events) = observed();
    let roots = discover_with_access(r, access(), &mut m).unwrap().unwrap();
    assert_eq!(roots.head_policy(), HeadPolicy::OwnedMetadata);
    let v = value(stage_a(&roots, roots.head_policy(), &mut m));
    let detached = branch == "(detached)";
    assert_eq!(
        field(&v, "detached"),
        &Field::known(FieldValue::Bool(detached))
    );
    assert_eq!(
        text(&v, "branch").as_deref(),
        (!detached && oid != "(initial)").then_some(branch)
    );
    assert_eq!(text(&v, "commit").as_deref(), detached.then(|| &oid[..12]));
    assert_eq!(field(&v, "operation"), &Field::ABSENT);
    assert_eq!(field(&v, "no_repo"), &Field::ABSENT);
    pending(&v);
    no_objects(&m, &events.borrow());
    assert_eq!(preflight(&roots, &mut m).unwrap(), GitAccess::Objects);
}

// 이것을 실패시키는 것: 서브모듈/중첩/linked 상위 gitdir 또는 bare 이름을 거부하거나 A identity를 다르게 발행.
#[test]
fn submodule_and_bare_stage_a_match_git_oracle() {
    for case in [
        "submodule",
        "submodule-path",
        "submodule-deep-path",
        "submodule-nested-path",
        "submodule-worktrees-name",
        "submodule-nested",
        "submodule-linked",
        "bare.git",
        "bare-any-name",
    ] {
        let f = Fixture::new();
        let r = oracle_corpus(&f, case);
        assert_git_identity(&r);
        let path = Path::new(std::ffi::OsStr::from_bytes(&r.binding.cwd));
        git_oracle(path, &["checkout", "-q", "--detach"]);
        assert_git_identity(&r);
        git_oracle(path, &["checkout", "-q", "--orphan", "unborn"]);
        // Keep the unborn oracle in the loose-ref corpus: unrelated packed
        // refs intentionally defer C5's identity correction until preflight.
        let common = git_oracle(
            path,
            &["rev-parse", "--path-format=absolute", "--git-common-dir"],
        );
        let packed = Path::new(&common).join("packed-refs");
        if packed.exists() {
            fs::remove_file(packed).unwrap();
        }
        assert_git_identity(&r);
    }
}

// 이것을 실패시키는 것: core.worktree의 경로·값/상한·고립 파싱이나 commondir chain 검사를 생략.
#[test]
fn submodule_binding_is_exact_bounded_and_isolated() {
    let f = Fixture::new();
    f.repo();
    let r = submodule(&f, "a", ".git/modules/a");
    let config = ".git/modules/a/config";
    for bytes in [
        b"[core]\nworktree=../../../a/./\n".as_slice(),
        b"[CoRe]\nworktree=/elsewhere\nWORKTREE=\"../../../a\"\n[include]\npath=/outside/canary\n",
    ] {
        f.write(config, bytes);
        let (mut m, events) = observed();
        let roots = discover_with_access(&r, access(), &mut m).unwrap().unwrap();
        assert_eq!(roots.head_policy(), HeadPolicy::OwnedMetadata);
        pending(&value(stage_a(&roots, roots.head_policy(), &mut m)));
        assert_eq!(preflight(&roots, &mut m).unwrap(), GitAccess::Objects);
        assert_eq!(roots.a_only_reason(), None);
        assert!(!events.borrow().iter().any(|s| s.contains("canary")));
        no_objects(&m, &events.borrow());
    }
    for (bytes, expected) in [
        (b"[core]\nworktree=../../../elsewhere\n".to_vec(), E::Escape),
        (b"[core]\nworktree\n".to_vec(), E::Escape),
        (b"[core]\nworktree=\n".to_vec(), E::Escape),
        (b"[include]\npath=/outside/canary\n".to_vec(), E::Escape),
        (
            b"[core]\nworktree=../../../a\n[core]\nworktree=/elsewhere\n".to_vec(),
            E::Escape,
        ),
        (b"[broken".to_vec(), E::Io(libc::EINVAL)),
        (vec![b'x'; 65_537], E::Limit),
    ] {
        f.write(config, bytes);
        let (m, events) = observed();
        let mut sink = Recording::default();
        assert!(
            matches!(collect(&r, &mut sink, m, access()), Err(CollectError::Read(e)) if e == expected)
        );
        assert!(sink.updates.is_empty() && sink.progress.is_empty());
        assert!(
            !events
                .borrow()
                .iter()
                .any(|s| s == "metadata_shape_validated"
                    || s == "before_read_layer"
                    || s.contains("canary"))
        );
    }
    submodule(&f, "a", ".git/modules/a");
    f.write(".git/modules/a/commondir", b"../..\n");
    let (mut m, events) = observed();
    assert!(matches!(
        discover_with_access(&r, access(), &mut m),
        Err(CollectError::Read(E::Escape))
    ));
    assert!(!events.borrow().iter().any(|s| s == "before_config_parse"));
    fs::remove_file(f.0.join(".git/modules/a/commondir")).unwrap();
    let (mut m, events) = observed();
    assert!(matches!(
        discover_with_access(&r, Access::stage_a_only(), &mut m),
        Err(CollectError::Read(E::StageAOnly))
    ));
    assert!(!events.borrow().iter().any(|s| s == "before_config_parse"));
    fs::remove_file(f.0.join(config)).unwrap();
    symlink("/outside/canary", f.0.join(config)).unwrap();
    assert!(matches!(
        discover_with_access(&r, access(), &mut meter()),
        Err(CollectError::Read(E::Escape))
    ));
}

// 이것을 실패시키는 것: 이름만 modules인 unrelated repo 또는 separate gitdir를 권한으로 인정.
#[test]
fn submodule_requires_ancestor_metadata_before_target_acquisition() {
    for gitdir in [
        "other/.git/modules/x",
        ".git-other/modules/x",
        ".git/modulesevil/x",
        "separate",
    ] {
        let f = Fixture::new();
        f.repo();
        f.write("other/.git/HEAD", OID);
        let r = submodule(&f, "a", gitdir);
        let (mut m, events) = observed();
        assert!(
            matches!(
                discover_with_access(&r, access(), &mut m),
                Err(CollectError::Read(E::Escape))
            ),
            "{gitdir}"
        );
        assert!(!events.borrow().iter().any(|s| s == "before_config_parse"
            || s == "openat:other"
            || s == "metadata_shape_validated"));
    }
    // Multiple modules/name pairs may bind directly to the ancestor gitdir.
    let f = Fixture::new();
    f.repo();
    let r = submodule(&f, "a/b", ".git/modules/a/modules/b");
    assert_eq!(
        discover_with_access(&r, access(), &mut meter())
            .unwrap()
            .unwrap()
            .head_policy(),
        HeadPolicy::OwnedMetadata
    );
    // A nearer independent repository does not invalidate a higher ancestor's
    // reciprocal registration, and is not itself selected as a read root.
    f.write("a/.git/HEAD", OID);
    assert_eq!(
        discover_with_access(&r, access(), &mut meter())
            .unwrap()
            .unwrap()
            .head_policy(),
        HeadPolicy::OwnedMetadata
    );
}

// 이것을 실패시키는 것: 재귀 깊이 또는 누적 ancestor32/HOME 상한을 재설정·제거.
#[test]
fn submodule_ancestor_and_recursion_bounds() {
    let f = Fixture::new();
    f.repo();
    let mut worktree = String::new();
    let mut gitdir = String::from(".git");
    for depth in 1..=9 {
        worktree.push_str(if depth == 1 { "a" } else { "/a" });
        gitdir.push_str("/modules/a");
        let r = submodule(&f, &worktree, &gitdir);
        let result = discover_with_access(&r, access(), &mut meter());
        if depth <= 8 {
            assert_eq!(
                result.unwrap().unwrap().head_policy(),
                HeadPolicy::OwnedMetadata
            );
        } else {
            assert!(matches!(result, Err(CollectError::Read(E::Escape))));
        }
    }
    for levels in [32, 33] {
        let f = Fixture::new();
        f.repo();
        let worktree = vec!["d"; levels].join("/");
        let mut r = submodule(&f, &worktree, ".git/modules/x");
        r.binding.path_query = PathQuery::default();
        let result = discover_with_access(&r, access(), &mut meter());
        if levels == 32 {
            assert_eq!(
                result.unwrap().unwrap().head_policy(),
                HeadPolicy::OwnedMetadata
            );
        } else {
            assert!(matches!(result, Err(CollectError::Read(E::Escape))));
        }
        // A HOME inside the enclosing worktree must stop that same walk.
        r.binding.path_query = PathQuery::for_path(
            &r.binding.cwd,
            Some(f.0.join("d").as_os_str().as_bytes()),
            false,
        );
        assert!(matches!(
            discover_with_access(&r, access(), &mut meter()),
            Err(CollectError::Read(E::Escape))
        ));
    }
}

// 이것을 실패시키는 것: bare common의 HEAD/objects/refs 확인 또는 backlink·commondir 검사를 제거.
#[test]
fn bare_shape_requires_metadata_and_reciprocal_registration() {
    for missing in ["HEAD", "objects", "refs", "worktrees/linked/gitdir"] {
        let f = Fixture::new();
        let r = linked(&f);
        fs::rename(f.0.join("main/.git"), f.0.join("bare")).unwrap();
        f.write("linked/.git", b"gitdir: ../bare/worktrees/linked\n");
        let p = f.0.join("bare").join(missing);
        if p.is_dir() {
            fs::remove_dir(p).unwrap();
        } else {
            fs::remove_file(p).unwrap();
        }
        let (mut m, events) = observed();
        assert!(
            matches!(
                discover_with_access(&r, access(), &mut m),
                Err(CollectError::Read(E::Missing))
            ),
            "{missing}"
        );
        assert!(
            !events
                .borrow()
                .iter()
                .any(|s| s == "metadata_shape_validated")
        );
    }
    for (name, bytes) in [
        ("gitdir", b"/other/.git\n".as_slice()),
        ("commondir", b"../../other\n"),
    ] {
        let f = Fixture::new();
        let r = linked(&f);
        fs::rename(f.0.join("main/.git"), f.0.join("bare")).unwrap();
        f.write("linked/.git", b"gitdir: ../bare/worktrees/linked\n");
        f.write(&format!("bare/worktrees/linked/{name}"), bytes);
        assert!(matches!(
            discover_with_access(&r, access(), &mut meter()),
            Err(CollectError::Read(E::Escape))
        ));
    }
}

// 이것을 실패시키는 것: shape/역방향 binding/commondir cycle/소유·symlink 검증 전에 select_metadata 호출.
#[test]
fn gitdir_commondir_are_owned_directory_capabilities() {
    let f = Fixture::new();
    let r = linked(&f);
    let roots = discover_with_access(&r, access(), &mut meter())
        .unwrap()
        .unwrap();
    assert_eq!(roots.head_policy(), HeadPolicy::OwnedMetadata);
    assert_eq!(preflight(&roots, &mut meter()).unwrap(), GitAccess::Objects);
    for target in [
        f.0.clone(),
        f.0.parent().unwrap().to_path_buf(),
        f.0.join("main/.git"),
    ] {
        f.write("linked/.git", format!("gitdir: {}\n", target.display()));
        assert!(matches!(
            discover_with_access(&r, access(), &mut meter()),
            Err(CollectError::Read(E::Escape))
        ));
    }
    linked(&f);
    for pointer in [b"../../../..\n".as_slice(), b".\n", b"../other\n"] {
        f.write("main/.git/worktrees/linked/commondir", pointer);
        assert!(matches!(
            discover_with_access(&r, access(), &mut meter()),
            Err(CollectError::Read(E::Escape))
        ));
    }
    linked(&f);
    f.write("main/.git/worktrees/linked/gitdir", b"/another/repo/.git\n");
    assert!(matches!(
        discover_with_access(&r, access(), &mut meter()),
        Err(CollectError::Read(E::Escape))
    ));
    linked(&f);
    f.write("main/.git/commondir", b"worktrees/linked\n");
    assert!(matches!(
        discover_with_access(&r, access(), &mut meter()),
        Err(CollectError::Read(E::Escape))
    ));
    fs::remove_file(f.0.join("main/.git/commondir")).unwrap();
    fs::rename(
        f.0.join("main/.git/worktrees/linked"),
        f.0.join("main/.git/worktrees/real"),
    )
    .unwrap();
    symlink("real", f.0.join("main/.git/worktrees/linked")).unwrap();
    assert!(matches!(
        discover_with_access(&r, access(), &mut meter()),
        Err(CollectError::Read(E::Symlink))
    ));
}

// 이것을 실패시키는 것: HOME gitfile을 read ruleset root로 등록하거나 config/HEAD를 그곳에서 읽는 것.
#[test]
fn gitfile_home_never_becomes_a_read_rule() {
    let f = Fixture::new();
    f.write("home/HEAD", OID);
    f.write(
        "repo/.git",
        format!("gitdir: {}\n", f.0.join("home").display()),
    );
    let (m, events) = observed();
    let mut sink = Recording::default();
    assert!(matches!(
        collect(&request(&f.0.join("repo")), &mut sink, m, access()),
        Err(CollectError::Read(E::Escape))
    ));
    assert!(sink.updates.is_empty());
    assert!(!events.borrow().iter().any(|e| e == "before_read_layer"
        || e == "stage_a_head"
        || e == "metadata_shape_validated"
        || e == "openat:home"));
}

// 이것을 실패시키는 것: Missing 이외 config/ref 오류를 없음으로 바꾸거나 B-D를 0으로 확정하는 것.
#[test]
fn corrupt_oversize_and_read_errors_are_not_no_risk() {
    for (path, bytes, expected) in [
        ("config", b"[broken".to_vec(), E::Io(libc::EINVAL)),
        ("packed-refs", vec![b'x'; 262_145], E::Limit),
        ("packed-refs", b"invalid\n".to_vec(), E::Io(libc::EINVAL)),
        ("config", vec![b'x'; 65_537], E::Limit),
    ] {
        let f = Fixture::new();
        f.repo();
        f.write(&format!(".git/{path}"), bytes);
        let (mut m, events) = observed();
        let roots = f.roots(&mut m);
        let v = value(stage_a(&roots, roots.head_policy(), &mut m));
        assert!(matches!(preflight(&roots, &mut m), Err(CollectError::Read(e)) if e == expected));
        assert_eq!(roots.a_only_reason(), Some(AOnlyReason::Read(expected)));
        pending(&v);
        no_objects(&m, &events.borrow());
    }
    let f = Fixture::new();
    f.repo();
    fs::remove_file(f.0.join(".git/config")).unwrap();
    symlink("/outside/config", f.0.join(".git/config")).unwrap();
    let mut m = meter();
    let roots = f.roots(&mut m);
    assert!(matches!(
        preflight(&roots, &mut m),
        Err(CollectError::Read(E::Escape))
    ));
}

// 이것을 실패시키는 것: 32 ancestor/home 경계와 .git symlink 거부를 빼거나 오류를 no-repo로 바꿈.
#[test]
fn discovery_bounds_and_marker_errors() {
    let f = Fixture::new();
    f.repo();
    let mut path = f.0.clone();
    for _ in 0..33 {
        path.push("d");
        fs::create_dir(&path).unwrap();
    }
    let mut r = request(&path);
    r.binding.path_query = PathQuery::default();
    let (mut m, events) = observed();
    assert!(
        discover_with_access(&r, access(), &mut m)
            .unwrap()
            .is_none()
    );
    assert_eq!(
        events
            .borrow()
            .iter()
            .filter(|e| *e == "discovery_candidate")
            .count(),
        33
    );
    path.pop();
    r = request(&path);
    r.binding.path_query = PathQuery::default();
    assert!(
        discover_with_access(&r, access(), &mut meter())
            .unwrap()
            .is_some()
    );
    r.binding.path_query =
        PathQuery::for_path(&r.binding.cwd, Some(path.as_os_str().as_bytes()), false);
    assert!(
        discover_with_access(&r, access(), &mut meter())
            .unwrap()
            .is_none()
    );
    let f = Fixture::new();
    fs::create_dir(f.0.join("metadata")).unwrap();
    symlink("metadata", f.0.join(".git")).unwrap();
    assert!(matches!(
        discover_with_access(&f.request(), access(), &mut meter()),
        Err(CollectError::Read(E::Symlink))
    ));
}

#[derive(Default)]
struct Recording {
    updates: Vec<Update>,
    progress: Vec<Progress>,
}
impl Recording {
    fn stages(&self) -> Vec<String> {
        self.updates
            .iter()
            .map(|update| text(update.value.as_ref().unwrap(), "stage").unwrap())
            .collect()
    }
}
impl UpdateSink for Recording {
    fn update(&mut self, v: Update) -> std::io::Result<()> {
        self.updates.push(v);
        Ok(())
    }
    fn progress(&mut self, p: Progress) -> std::io::Result<()> {
        assert!(!self.updates.is_empty());
        self.progress.push(p);
        Ok(())
    }
}
fn isolated(name: &str, extra: &[(&str, &std::ffi::OsStr)]) -> bool {
    if std::env::var("BINGSU_C5_CHILD").ok().as_deref() == Some(name) {
        #[cfg(target_os = "linux")]
        assert_eq!(
            // SAFETY: matches startup's prerequisite for irreversible read
            // restriction, only in this disposable single-threaded child.
            unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) },
            0,
        );
        return true;
    }
    let f = Fixture::new();
    let mut c = Command::new(std::env::current_exe().unwrap());
    c.args(["--exact", name, "--nocapture", "--test-threads=1"])
        .env("BINGSU_C5_CHILD", name)
        .env("BINGSU_C5_CHILD_ROOT", &f.0);
    for (k, v) in extra {
        c.env(k, v);
    }
    let out = c.output().unwrap();
    assert!(
        out.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(String::from_utf8_lossy(&out.stdout).contains("1 passed"));
    false
}

// 이것을 실패시키는 것: no-repo 표식 대신 None, Pending 필드 또는 Update 이전 Progress 전송.
#[test]
fn no_repo_sends_marker_before_a_complete() {
    if !isolated("no_repo_sends_marker_before_a_complete", &[]) {
        return;
    }
    let f = Fixture::new();
    let r = f.request();
    let mut sink = Recording::default();
    collect(&r, &mut sink, meter(), access()).unwrap();
    assert_eq!(sink.stages(), ["A"]);
    assert_eq!(sink.updates[0].value, Some(schema::no_repo()));
    assert!(sink.updates[0].value.as_ref().unwrap().text().is_empty());
    assert!(matches!(
        sink.progress.as_slice(),
        [Progress {
            stage_a_complete: true,
            ..
        }]
    ));
    assert!(sink.progress[0].stage_a_complete);
}

// 이것을 실패시키는 것: preflight를 A Update 앞으로 옮기거나 거부 config를 clean으로 처리.
#[test]
fn preflight_errors_follow_first_a_update() {
    if !isolated("preflight_errors_follow_first_a_update", &[]) {
        return;
    }
    let f = Fixture::new();
    f.repo();
    f.write(".git/config", vec![b'x'; 65_537]);
    let r = f.request();
    let (m, events) = observed();
    let frames = RefCell::new(Vec::new());
    let started = Instant::now();
    let first = RefCell::new(None);
    let mut write = |bytes: &[u8]| {
        let frame = wire::decode_frame(bytes).unwrap();
        if frame.kind == wire::Kind::Update {
            assert!(
                !events
                    .borrow()
                    .iter()
                    .any(|e| e == "preflight_start" || e == "before_config_parse")
            );
            *first.borrow_mut() = Some(started.elapsed());
        }
        frames.borrow_mut().push(bytes.to_vec());
        Ok(())
    };
    let mut buffer = [0; wire::FRAME_MAX];
    let mut ready = wire::FEATURES.to_le_bytes().to_vec();
    ready.extend(r.binding.mask.to_le_bytes());
    ready.extend([0; 12]);
    let mut sink =
        update_sink::WireSink::new(&r, field::BUILTIN, &ready, &mut buffer, &mut write).unwrap();
    let result = collect(&r, &mut sink, m, access());
    assert!(matches!(result, Err(CollectError::Read(E::Limit))));
    assert!(first.borrow().is_some());
    assert_eq!(
        frames
            .borrow()
            .iter()
            .map(|b| wire::decode_frame(b).unwrap().kind)
            .collect::<Vec<_>>(),
        vec![wire::Kind::Update, wire::Kind::Progress]
    );
    assert!(
        events
            .borrow()
            .iter()
            .position(|e| e == "discovery_consumed")
            .unwrap()
            < events
                .borrow()
                .iter()
                .position(|e| e == "before_read_layer")
                .unwrap()
    );
    assert!(events.borrow().iter().any(|e| e == "preflight_start"));
    println!("first_a_update_us={}", first.borrow().unwrap().as_micros());
}

// Packing between preflight's packed snapshot and its HEAD lookup must leave
// A's branch on screen with B/C/D unknown, never correct it to unborn.
// 이것을 실패시키는 것: refs::resolve의 packed-refs 비교를 빼는 것(두 번째 A
// Update가 branch를 확정 ABSENT로 바꾸고 결과가 Ok).
#[test]
fn preflight_head_packed_after_the_snapshot_keeps_the_branch() {
    if !isolated(
        "preflight_head_packed_after_the_snapshot_keeps_the_branch",
        &[],
    ) {
        return;
    }
    let f = Fixture::new();
    f.repo();
    let other = "1".repeat(40);
    f.write(".git/packed-refs", format!("{other} refs/tags/t\n"));
    f.write(
        ".git/packed-refs.next",
        format!(
            "{} refs/heads/main\n{other} refs/tags/t\n",
            std::str::from_utf8(OID).unwrap()
        ),
    );
    // The read layer confines the collecting thread (Linux); a helper started
    // before it performs git's pack: rename packed-refs, then delete the loose.
    let (go, wait) = std::sync::mpsc::channel::<()>();
    let (done, finished) = std::sync::mpsc::channel::<()>();
    let git_dir = f.0.join(".git");
    let packer = std::thread::spawn(move || {
        if wait.recv().is_ok() {
            fs::rename(
                git_dir.join("packed-refs.next"),
                git_dir.join("packed-refs"),
            )
            .unwrap();
            fs::remove_file(git_dir.join("refs/heads/main")).unwrap();
            done.send(()).unwrap();
        }
    });
    let mut m = meter();
    let mut armed = false;
    m.hook = Some(Box::new(move |event| {
        if event == "preflight_start" {
            armed = true;
        } else if armed && event == "resolve:refs/heads/main" {
            armed = false;
            go.send(()).unwrap();
            finished.recv().unwrap();
        }
    }));
    let mut sink = Recording::default();
    let result = collect(&f.request(), &mut sink, m, access());
    packer.join().unwrap();
    assert!(!f.0.join(".git/refs/heads/main").exists());
    assert!(
        matches!(result, Err(CollectError::Read(E::Changed))),
        "{result:?}"
    );
    assert_eq!(sink.stages(), ["A"]);
    let value = sink.updates[0].value.as_ref().unwrap();
    assert_eq!(text(value, "branch").as_deref(), Some("main"));
    pending(value);
}

// 이것을 실패시키는 것: 느린 preflight가 첫 A 발행보다 먼저 실행되거나 B 마감을 무시함.
#[test]
fn preflight_never_delays_first_a_update() {
    if !isolated("preflight_never_delays_first_a_update", &[]) {
        return;
    }
    let f = Fixture::new();
    f.repo();
    let access = access();
    let (mut m, events) = observed();
    let recorded = events.clone();
    m.hook = Some(Box::new(move |event| {
        recorded.borrow_mut().push(event.to_owned());
        if event == "preflight_start" {
            std::thread::sleep(Duration::from_millis(budget::B_MS + 1));
        }
    }));
    let mut sink = Recording::default();
    struct Ordered<'a>(&'a mut Recording, Rc<RefCell<Vec<String>>>);
    impl UpdateSink for Ordered<'_> {
        fn update(&mut self, update: Update) -> std::io::Result<()> {
            self.1.borrow_mut().push("update".into());
            self.0.update(update)
        }
        fn progress(&mut self, progress: Progress) -> std::io::Result<()> {
            self.1.borrow_mut().push("progress".into());
            self.0.progress(progress)
        }
    }
    // Share the hook log with the sink to compare actual emission and IO order.
    let result = git::collect_with_access(
        &f.request(),
        &mut Ordered(&mut sink, events.clone()),
        m,
        access,
    );
    assert!(matches!(result, Err(CollectError::Read(E::Deadline))));
    let events = events.borrow();
    if let Some(preflight) = events.iter().position(|e| e == "preflight_start") {
        assert!(events.iter().position(|e| e == "update").unwrap() < preflight);
        assert!(events.iter().position(|e| e == "progress").unwrap() < preflight);
        assert!(
            !events[preflight + 1..]
                .iter()
                .any(|e| e.starts_with("openat:"))
        );
    } else {
        // OS scheduling may exhaust A before it can publish anything.
        assert!(sink.updates.is_empty() && sink.progress.is_empty());
    }
}

// 이것을 실패시키는 것: 주입된 A/B 마감을 무시하거나 제품 예산 상수를 변경하는 것.
#[test]
fn injected_deadlines_apply_to_each_stage() {
    if !isolated("injected_deadlines_apply_to_each_stage", &[]) {
        return;
    }
    assert_eq!(git::StageDeadlines::PRODUCT.a_ms, 5);
    assert_eq!(git::StageDeadlines::PRODUCT.b_ms, 28);
    assert_eq!(git::StageDeadlines::PRODUCT.c_ms, 8);
    assert_eq!(git::StageDeadlines::PRODUCT.d_ms, 4);
    assert_eq!(git::StageDeadlines::PRODUCT.path_ms, 3);
    let f = Fixture::new();
    f.repo();
    for a_expired in [true, false] {
        let mut sink = Recording::default();
        let (m, events) = observed();
        assert!(matches!(
            git::collect_with_deadlines(
                &f.request(),
                &mut sink,
                m,
                access(),
                git::StageDeadlines {
                    a_ms: if a_expired { 0 } else { 30_000 },
                    b_ms: if a_expired { 30_000 } else { 0 },
                    path_ms: 30_000,
                    c_ms: 30_000,
                    d_ms: 30_000,
                },
            ),
            Err(CollectError::Read(E::Deadline))
        ));
        assert_eq!(sink.stages(), if a_expired { vec![] } else { vec!["A"] });
        if a_expired {
            assert!(sink.progress.is_empty());
        } else {
            assert!(matches!(
                sink.progress.as_slice(),
                [Progress {
                    stage_a_complete: true,
                    ..
                }]
            ));
        }
        assert_eq!(
            events.borrow().iter().any(|e| e == "preflight_start"),
            !a_expired
        );
    }
}

// 이것을 실패시키는 것: GIT_WORK_TREE/HOME/GIT_DIR/config 환경값을 discovery authority로 사용.
#[test]
fn x10_request_roots_ignore_git_work_tree() {
    let hostile = Path::new("/outside/request-root-canary").as_os_str();
    if !isolated(
        "x10_request_roots_ignore_git_work_tree",
        &[
            ("GIT_WORK_TREE", hostile),
            ("GIT_DIR", hostile),
            ("GIT_CONFIG_GLOBAL", hostile),
            ("GIT_CONFIG_SYSTEM", hostile),
            ("HOME", hostile),
        ],
    ) {
        return;
    }
    let f = Fixture::new();
    f.repo();
    let r = f.request();
    let (mut m, events) = observed();
    assert!(r.environment.is_empty());
    let roots = f.roots(&mut m);
    let v = value(stage_a(&roots, roots.head_policy(), &mut m));
    assert_eq!(text(&v, "branch").as_deref(), Some("main"));
    assert_eq!(preflight(&roots, &mut m).unwrap(), GitAccess::Objects);
    assert!(
        !events
            .borrow()
            .iter()
            .any(|e| e.contains("request-root-canary"))
    );
}

// 이것을 실패시키는 것: owner 판정 후 HeadOnly를 무시하거나 config/gix/operation/ref를 선행함.
#[test]
fn foreign_owner_never_opens_gix() {
    if std::env::var("BINGSU_C5_CHILD").ok().as_deref() != Some("foreign_owner_never_opens_gix") {
        let f = Fixture::new();
        let lib = f.0.join(if cfg!(target_os = "macos") {
            "owner.dylib"
        } else {
            "owner.so"
        });
        let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/support/c5_owner.c");
        let out = Command::new("cc")
            .args(["-Wall", "-Wextra", "-Werror", "-shared", "-fPIC"])
            .arg(source)
            .arg("-o")
            .arg(&lib)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let variable = if cfg!(target_os = "macos") {
            "DYLD_INSERT_LIBRARIES"
        } else {
            "LD_PRELOAD"
        };
        isolated(
            "foreign_owner_never_opens_gix",
            &[(variable, lib.as_os_str())],
        );
        return;
    }
    let f = Fixture::new();
    f.repo();
    f.write(".git/config", b"[core]\nworktree=/\n[safe]\ndirectory=*\n");
    f.write(".git/MERGE_HEAD", OID);
    let (mut m, events) = observed();
    let roots = f.roots(&mut m);
    assert_eq!(roots.head_policy(), HeadPolicy::HeadOnly);
    let before = m.counts[Phase::Content as usize].read_bytes;
    // A malicious caller cannot override the owner-derived policy.
    let v = value(stage_a(&roots, HeadPolicy::OwnedMetadata, &mut m));
    assert_eq!(m.counts[Phase::Content as usize].read_bytes - before, 21);
    assert_eq!(field(&v, "operation"), &Field::PENDING);
    assert_eq!(preflight(&roots, &mut m).unwrap(), GitAccess::HeadOnly);
    pending(&v);
    let e = events.borrow();
    assert!(!e.iter().any(|s| s.contains("config")
        || s == "before_packed_parse"
        || s == "stage_a_ref_presence"
        || s == "stage_a_operations"
        || s.contains("commondir")));
    no_objects(&m, &e);
    drop(e);
    fs::remove_file(f.0.join(".git/HEAD")).unwrap();
    symlink("config", f.0.join(".git/HEAD")).unwrap();
    let before = m.counts[Phase::Content as usize].read_bytes;
    assert_eq!(
        stage_a(&roots, HeadPolicy::HeadOnly, &mut m),
        StageResult::Hidden
    );
    assert_eq!(m.counts[Phase::Content as usize].read_bytes, before);
    let f = Fixture::new();
    let r = linked(&f);
    let mut pointer_meter = meter();
    assert!(matches!(
        discover_with_access(&r, access(), &mut pointer_meter),
        Err(CollectError::Read(E::Denied))
    ));
    assert_eq!(
        pointer_meter
            .counts
            .iter()
            .map(|c| c.read_bytes)
            .sum::<u64>(),
        0
    );
    // Isolate each real owner comparison rather than making every owner
    // foreign at once: worktree, in-place gitdir, external gitdir, commondir.
    // SAFETY: the child was started with this exact test-only interposer.
    let setter = unsafe { libc::dlsym(libc::RTLD_DEFAULT, c"bingsu_c5_owner".as_ptr()) };
    assert!(!setter.is_null());
    // SAFETY: exported C function has precisely this signature.
    let set_owner: unsafe extern "C" fn(u32) = unsafe { std::mem::transmute(setter) };
    for nth in [1, 2] {
        let f = Fixture::new();
        f.repo();
        let access = access();
        // SAFETY: process-local test counter, single-threaded child.
        unsafe {
            set_owner(nth);
        }
        let roots = discover_with_access(&f.request(), access, &mut meter())
            .unwrap()
            .unwrap();
        assert_eq!(
            roots.head_policy(),
            HeadPolicy::HeadOnly,
            "owner call {nth}"
        );
    }
    for nth in [2, 5] {
        let f = Fixture::new();
        let r = linked(&f);
        let access = access();
        let (mut m, events) = observed();
        // SAFETY: as above; these are the gitdir/commondir leaf pre-open checks.
        unsafe {
            set_owner(nth);
        }
        assert!(
            matches!(
                discover_with_access(&r, access, &mut m),
                Err(CollectError::Read(E::Denied))
            ),
            "pointer owner call {nth}"
        );
        if nth == 2 {
            // Only the request cwd was opened. The same-named external
            // metadata leaf must be rejected before open, not at a later uid check.
            assert_eq!(
                events
                    .borrow()
                    .iter()
                    .filter(|e| *e == "openat:linked")
                    .count(),
                1
            );
        }
    }
    // 이것을 실패시키는 것: submodule config 이전 worktree/ancestor/target owner 검사 생략.
    for nth in 1..=6 {
        let f = Fixture::new();
        f.repo();
        let r = submodule(&f, "a", ".git/modules/a");
        let access = access();
        let (mut m, events) = observed();
        // SAFETY: the same child-only uid comparison interposer as above.
        unsafe {
            set_owner(nth);
        }
        let expected = if matches!(nth, 2 | 3) {
            E::Escape
        } else {
            E::Denied
        };
        assert!(
            matches!(discover_with_access(&r, access, &mut m), Err(CollectError::Read(e)) if e == expected),
            "submodule owner call {nth}"
        );
        assert!(
            !events
                .borrow()
                .iter()
                .any(|e| e == "before_config_parse" || e == "resolve:config")
        );
    }
}

// 이것을 실패시키는 것: 보장 없는 경로에서 ref/config/objects 열기 또는 정확한 count 발행.
#[test]
fn no_guarantee_and_bad_commondir_keep_a_only() {
    let f = Fixture::new();
    f.repo();
    let mut m = meter();
    let roots = discover_with_access(&f.request(), Access::stage_a_only(), &mut m)
        .unwrap()
        .unwrap();
    pending(&value(stage_a(&roots, roots.head_policy(), &mut m)));
    assert_eq!(preflight(&roots, &mut m).unwrap(), GitAccess::StageAOnly);
    assert_eq!(roots.a_only_reason(), Some(AOnlyReason::NoGuarantee));
    f.write(".git/commondir", b"../..\n");
    let roots = f.roots(&mut m);
    assert_eq!(roots.head_policy(), HeadPolicy::OwnedMetadata);
    pending(&value(stage_a(&roots, roots.head_policy(), &mut m)));
    assert_eq!(preflight(&roots, &mut m).unwrap(), GitAccess::StageAOnly);
    assert_eq!(roots.a_only_reason(), Some(AOnlyReason::MetadataShape));
}

// 이것을 실패시키는 것: stage 예산으로 request deadline이나 누적 counter를 초기화함.
#[test]
fn stage_deadline_never_extends_request_or_resets_counters() {
    let mut m = meter();
    m.charge_axis(budget::Axis::RefEntries, 7).unwrap();
    m.stage(0, |m| assert_eq!(m.check(), Err(E::Deadline)));
    assert_eq!(m.budget.used(budget::Axis::RefEntries), 7);
    assert_eq!(m.check(), Ok(()));
    let mut expired = Meter::new(Instant::now());
    expired.stage(50, |m| assert_eq!(m.check(), Err(E::Deadline)));
}

// Observation only: real A IO and first encoded Update, 200 warm samples per
// corpus. Object/stat stages are deliberately absent from this C5 measurement.
#[test]
#[ignore = "explicit release timing observation"]
fn git_stage_a_warm_observations() {
    let _ = access(); // warm the one-time resolver/OS capability state before timing
    let mut reports = Vec::new();
    for case in [
        "no-repo",
        "git-clean",
        "git-dirty",
        "linked",
        "submodule",
        "submodule-nested",
        "submodule-linked",
        "submodule-depth8",
        "submodule-depth8-large-config",
        "submodule-ancestor32",
        "submodule-max-config",
        "bare.git",
        "bare-any-name",
        "ancestor32",
        "19000-tracked",
        "max-config",
        "large-packed-refs",
        "budget-bound",
    ] {
        let f = Fixture::new();
        let mut r = f.request();
        if case != "no-repo" {
            f.repo();
        }
        match case {
            "submodule-depth8" | "submodule-depth8-large-config" => {
                r = depth8(&f, case.ends_with("large-config"));
            }
            "submodule-ancestor32" => {
                r = submodule(&f, &vec!["d"; 32].join("/"), ".git/modules/a");
            }
            "submodule-max-config" => {
                r = submodule(&f, "a", ".git/modules/a");
                let mut config = fs::read(f.0.join(".git/modules/a/config")).unwrap();
                config.extend(b"filemode=true\n".repeat(900));
                config.push(b'#');
                config.resize(65_536, b' ');
                f.write(".git/modules/a/config", config);
            }
            "submodule" | "submodule-nested" | "submodule-linked" | "bare.git"
            | "bare-any-name" => {
                fs::remove_dir_all(f.0.join(".git")).unwrap();
                r = oracle_corpus(&f, case);
            }
            "git-dirty" => f.write("dirty", b"untracked worktree file"),
            "linked" => {
                fs::remove_dir_all(f.0.join(".git")).unwrap();
                r = linked(&f);
            }
            "ancestor32" => {
                let mut path = f.0.clone();
                for _ in 0..32 {
                    path.push("d");
                    fs::create_dir(&path).unwrap();
                }
                r = request(&path);
                r.binding.path_query = PathQuery::default();
            }
            "budget-bound" => f.write(".git/config", vec![b'x'; 65_537]),
            "max-config" => {
                let mut config = b"[core]\n".to_vec();
                config.extend(b"filemode=true\n".repeat(900));
                config.push(b'#');
                config.resize(65_536, b' ');
                f.write(".git/config", config);
            }
            "large-packed-refs" => {
                let mut refs = Vec::new();
                for i in 0..4000 {
                    refs.extend(
                        format!("1234567890123456789012345678901234567890 refs/heads/b{i:04}\n")
                            .bytes(),
                    );
                }
                f.write(".git/packed-refs", refs);
            }
            "19000-tracked" => {
                fs::remove_dir_all(f.0.join(".git")).unwrap();
                for n in 0..19_000 {
                    f.write(&format!("d{:03}/f{:03}", n / 100, n % 100), b"x\n");
                }
                for args in [
                    &["init", "-q"][..],
                    &["add", "."],
                    &[
                        "-c",
                        "user.name=fixture",
                        "-c",
                        "user.email=fixture@example.invalid",
                        "commit",
                        "-qm",
                        "fixture",
                    ],
                ] {
                    let output = Command::new("git")
                        .env("GIT_CONFIG_NOSYSTEM", "1")
                        .env("GIT_CONFIG_GLOBAL", "/dev/null")
                        .args(args)
                        .current_dir(&f.0)
                        .output()
                        .unwrap();
                    assert!(
                        output.status.success(),
                        "git oracle required: {}",
                        String::from_utf8_lossy(&output.stderr)
                    );
                }
            }
            _ => {}
        }
        let mut samples = Vec::new();
        let mut firsts = Vec::new();
        let mut preflights = Vec::new();
        let mut last = None;
        let mut cold = (0, 0, 0);
        for n in 0..201 {
            let access = access();
            let mut m = meter();
            let started = Instant::now();
            let roots = discover_with_access(&r, access, &mut m).unwrap();
            let v = roots.as_ref().map_or_else(schema::no_repo, |roots| {
                value(stage_a(roots, roots.head_policy(), &mut m))
            });
            let a_ns = started.elapsed().as_nanos();
            let mut first_ns = 0;
            let mut buffer = [0; wire::FRAME_MAX];
            let mut ready = wire::FEATURES.to_le_bytes().to_vec();
            ready.extend(r.binding.mask.to_le_bytes());
            ready.extend([0; 12]);
            let mut write = |bytes: &[u8]| {
                if wire::decode_frame(bytes).unwrap().kind == wire::Kind::Update {
                    first_ns = started.elapsed().as_nanos();
                }
                Ok(())
            };
            let mut sink =
                update_sink::WireSink::new(&r, field::BUILTIN, &ready, &mut buffer, &mut write)
                    .unwrap();
            sink.update(Update {
                segment: 3,
                value: Some(v),
                facts: None,
            })
            .unwrap();
            let pre = Instant::now();
            if let Some(roots) = &roots {
                let result = preflight(roots, &mut m);
                if case == "budget-bound" {
                    assert!(matches!(result, Err(CollectError::Read(E::Limit))));
                } else {
                    assert_eq!(result.unwrap(), GitAccess::Objects);
                }
            }
            let pre_ns = pre.elapsed().as_nanos();
            if n == 0 {
                cold = (a_ns, first_ns, pre_ns);
                println!(
                    "cold {case} A_us={} first_update_us={}",
                    a_ns / 1000,
                    first_ns / 1000
                );
            } else {
                samples.push(a_ns);
                firsts.push(first_ns);
                preflights.push(pre_ns);
            }
            last = Some(m);
        }
        let stats = |numbers: &[u128]| {
            let mut sorted = numbers.to_vec();
            sorted.sort_unstable();
            let mean = sorted.iter().sum::<u128>() as f64 / sorted.len() as f64;
            let variance = sorted
                .iter()
                .map(|&n| (n as f64 - mean).powi(2))
                .sum::<f64>()
                / sorted.len() as f64;
            (sorted[100], sorted[190], variance)
        };
        let (p50, p95, variance) = stats(&samples);
        let (first50, first95, _) = stats(&firsts);
        let (pre50, pre95, _) = stats(&preflights);
        let m = last.unwrap();
        let counts = m
            .counts
            .iter()
            .fold(meter::Counters::default(), |mut total, c| {
                total.open += c.open;
                total.stat += c.stat;
                total.mount += c.mount;
                total.filesystem += c.filesystem;
                total.read += c.read;
                total.read_bytes += c.read_bytes;
                total.components += c.components;
                total
            });
        println!(
            "{case}: A p50={:.3}ms p95={:.3}ms first={:.3}/{:.3}ms preflight={:.3}/{:.3}ms ops={} open={} stat={} mount={} fs={} reads={} bytes={} fd_peak={}",
            p50 as f64 / 1e6,
            p95 as f64 / 1e6,
            first50 as f64 / 1e6,
            first95 as f64 / 1e6,
            pre50 as f64 / 1e6,
            pre95 as f64 / 1e6,
            m.operations(),
            counts.open,
            counts.stat,
            counts.mount,
            counts.filesystem,
            counts.read,
            counts.read_bytes,
            m.peak_fds
        );
        reports.push(format!("{{\"case\":\"{case}\",\"cold_a_ns\":{},\"cold_first_update_ns\":{},\"cold_preflight_ns\":{},\"live_allocation\":{},\"worktree_read_bytes\":{},\"samples\":{samples:?},\"first_update_samples\":{firsts:?},\"preflight_samples\":{preflights:?},\"a_p50_ns\":{p50},\"a_p95_ns\":{p95},\"a_variance_ns2\":{variance},\"first_p50_ns\":{first50},\"first_p95_ns\":{first95},\"preflight_p50_ns\":{pre50},\"preflight_p95_ns\":{pre95},\"ops\":{},\"open\":{},\"stat\":{},\"mount\":{},\"filesystem\":{},\"reads\":{},\"read_bytes\":{},\"peak_fds\":{}}}",cold.0,cold.1,cold.2,m.live_allocated(),m.budget.used(budget::Axis::WorktreeReadBytes),m.operations(),counts.open,counts.stat,counts.mount,counts.filesystem,counts.read,counts.read_bytes,m.peak_fds));
    }
    let out = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/c5-evidence");
    fs::create_dir_all(&out).unwrap();
    fs::write(out.join("timings.json"),format!("{{\"unit\":\"ns\",\"warm_runs\":200,\"read_layer_timing\":\"Linux lead required\",\"cases\":[{}]}}", reports.join(","))).unwrap();
}

// 이것을 실패시키는 것: Discovery 이후 read confinement 설치를 생략하거나 부모를 허용함.
#[cfg(target_os = "linux")]
#[test]
fn read_layer_narrows_to_selected_roots() {
    if !isolated("read_layer_narrows_to_selected_roots", &[]) {
        return;
    }
    let f = Fixture::new();
    f.write("repo/.git/HEAD", OID);
    f.write("outside", b"must not be readable");
    let mut sink = Recording::default();
    collect(&request(&f.0.join("repo")), &mut sink, meter(), access()).unwrap();
    assert_eq!(fs::read(f.0.join("repo/.git/HEAD")).unwrap(), OID);
    assert_eq!(
        fs::read(f.0.join("outside")).unwrap_err().raw_os_error(),
        Some(libc::EACCES)
    );
}

// 이것을 실패시키는 것: submodule 검증에 쓴 ancestor/HOME을 read rule로 남김.
#[cfg(target_os = "linux")]
#[test]
fn submodule_read_layer_excludes_ancestor_and_home() {
    if !isolated("submodule_read_layer_excludes_ancestor_and_home", &[]) {
        return;
    }
    let f = Fixture::new();
    f.repo();
    f.write("home/private", b"must not be readable");
    let r = submodule(&f, "a", ".git/modules/a");
    let mut sink = Recording::default();
    collect(&r, &mut sink, meter(), access()).unwrap();
    assert_eq!(sink.stages(), ["A", "B", "C", "D"]);
    assert_eq!(
        fs::read(f.0.join(".git/modules/a/refs/heads/main")).unwrap(),
        OID
    );
    for forbidden in [".git/HEAD", "home/private"] {
        assert_eq!(
            fs::read(f.0.join(forbidden)).unwrap_err().raw_os_error(),
            Some(libc::EACCES)
        );
    }
}

// 이것을 실패시키는 것: sink 실패 이후 Progress/preflight 수행 또는 요청 deadline 무시.
#[test]
fn failed_sink_or_deadline_stops_before_preflight() {
    struct Fail;
    impl UpdateSink for Fail {
        fn update(&mut self, _: Update) -> std::io::Result<()> {
            Err(std::io::Error::other("injected write failure"))
        }
        fn progress(&mut self, _: Progress) -> std::io::Result<()> {
            panic!("progress after failed write")
        }
    }
    let f = Fixture::new();
    f.repo();
    let (m, events) = observed();
    assert!(matches!(
        collect(&f.request(), &mut Fail, m, access()),
        Err(CollectError::Sink(_))
    ));
    assert!(
        !events
            .borrow()
            .iter()
            .any(|e| e == "preflight_start" || e == "before_read_layer")
    );
    let mut sink = Recording::default();
    assert!(matches!(
        collect(
            &f.request(),
            &mut sink,
            Meter::new(Instant::now()),
            access()
        ),
        Err(CollectError::Read(E::Deadline))
    ));
    assert!(sink.updates.is_empty());
}

// 이것을 실패시키는 것: unrelated packed refs가 있을 때 unborn을 계속 branch로 발행하거나 packed를 첫 Update 전에 파싱.
#[test]
fn unborn_with_unrelated_packed_refs_corrects_after_first_a() {
    if !isolated(
        "unborn_with_unrelated_packed_refs_corrects_after_first_a",
        &[],
    ) {
        return;
    }
    let f = Fixture::new();
    f.repo();
    fs::remove_file(f.0.join(".git/refs/heads/main")).unwrap();
    f.write(
        ".git/packed-refs",
        b"1234567890123456789012345678901234567890 refs/heads/other\n",
    );
    let mut sink = Recording::default();
    collect(&f.request(), &mut sink, meter(), access()).unwrap();
    assert_eq!(sink.stages(), ["A", "A", "B", "C", "D"]);
    assert_eq!(
        text(sink.updates[0].value.as_ref().unwrap(), "branch").as_deref(),
        Some("main")
    );
    let last = sink.updates[1].value.as_ref().unwrap();
    assert_eq!(field(last, "branch"), &Field::ABSENT);
    assert_eq!(field(last, "commit"), &Field::ABSENT);
    pending(last);
    assert!(matches!(
        sink.progress.as_slice(),
        [Progress {
            stage_a_complete: true,
            ..
        }]
    ));
}

// 이것을 실패시키는 것: pointer 정규화의 구성 요소 상한을 제거하고 uncharged Vec를 키움.
#[test]
fn pointer_components_stop_before_acquisition() {
    let f = Fixture::new();
    f.write(
        ".git",
        format!("gitdir: /{}.git/worktrees/name\n", "x/".repeat(4096)),
    );
    let (mut m, events) = observed();
    assert!(matches!(
        discover_with_access(&f.request(), access(), &mut m),
        Err(CollectError::Read(E::Limit))
    ));
    assert!(!events.borrow().iter().any(|e| e == "openat:x"));
}
