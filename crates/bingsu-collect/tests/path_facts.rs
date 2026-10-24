//! E1 filesystem/shortener oracles and names-only capability boundaries.
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
        path_facts::PathQuery,
        wire::{self, Binding, BuildId, Progress, Request, Update},
    },
    shorten::{self, Anchor, Method, PathFacts, ShortenRequest, Source},
    snapshot::{self, Identity},
    width::WidthProfile,
};
use git::{
    discover::{self, Selection},
    path_facts::collect,
};
use meter::{Meter, Phase};
use safe_read::{Access, Discovery};
use std::{
    cell::RefCell,
    fs,
    os::unix::{
        ffi::{OsStrExt, OsStringExt},
        fs::{PermissionsExt, symlink},
    },
    path::{Path, PathBuf},
    process::Command,
    rc::Rc,
    time::{Duration, Instant},
};

fn meter() -> Meter {
    Meter::new(Instant::now() + Duration::from_secs(60))
}
struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let base =
            std::env::var_os("BINGSU_E1_ROOT").map_or_else(|| PathBuf::from("/tmp"), PathBuf::from);
        let path = base.join(format!(
            "bingsu-e1-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(fs::canonicalize(path).unwrap())
    }
    fn dir(&self, name: &str) -> PathBuf {
        let path = self.0.join(name);
        fs::create_dir_all(&path).unwrap();
        path
    }
    fn repo(&self, name: &str) -> PathBuf {
        let path = self.dir(name);
        fs::create_dir(path.join(".git")).unwrap();
        fs::write(
            path.join(".git/HEAD"),
            b"0123456789012345678901234567890123456789\n",
        )
        .unwrap();
        path
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn request(cwd: &Path, home: &Path, unique: bool) -> Request {
    let cwd = cwd.as_os_str().as_bytes().to_vec();
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
            path_query: PathQuery::for_path(&cwd, Some(home.as_os_str().as_bytes()), unique),
            cwd,
            mask: (1 << 1) | (1 << 3),
        },
        budget_ms: 50,
        environment: vec![],
    }
}
fn discovery(selected: &Selection) -> &Discovery {
    match selected {
        Selection::Repository(_, d) | Selection::Outside(_, _, d) => d,
    }
}
fn selected(r: &Request, m: &mut Meter) -> Selection {
    discover::select(r, Access::stage_a_only(), m).unwrap()
}
fn shorten(f: &PathFacts, method: Method) -> Option<String> {
    shorten::run_builtin(&ShortenRequest {
        source: Source::Path(f),
        budget: u32::MAX,
        profile: WidthProfile::DEFAULT,
        method,
    })
    .map(|r| r.text())
}
fn unique(f: &PathFacts) -> String {
    shorten(f, Method::Unique).unwrap()
}
fn count(path: &Path) -> usize {
    path.as_os_str()
        .as_bytes()
        .split(|b| *b == b'/')
        .filter(|p| !p.is_empty())
        .count()
}

// Fails if unique=false enumerates, names reopen/stat/read, or cwd is rediscovered.
#[test]
fn unique_reads_only_when_requested() {
    let f = Fixture::new();
    let cwd = f.dir("alphabet/leaf");
    f.dir("alpine");
    for enabled in [false, true] {
        let r = request(&cwd, &f.0, enabled);
        if !enabled {
            let mut probe = meter();
            let held =
                safe_read::acquire(&r.binding.cwd, r.binding.path_query, &mut probe).unwrap();
            let facts = collect(&held, r.binding.path_query, &mut probe);
            assert!(facts.siblings.is_empty());
            assert_eq!(probe.counts[Phase::Content as usize].list, 0);
        }
        let mut m = meter();
        let roots = selected(&r, &mut m);
        let before = m.counts;
        let live = m.live_fds();
        let facts = collect(discovery(&roots), r.binding.path_query, &mut m);
        let after = m.counts[Phase::Content as usize];
        let before = before[Phase::Content as usize];
        assert_eq!(after.open, before.open);
        assert_eq!(after.stat, before.stat);
        assert_eq!(after.read, before.read);
        assert_eq!(after.readlink, before.readlink);
        assert_eq!(m.live_fds(), live);
        assert_eq!(after.readonly - before.readonly, 1);
        assert_eq!(after.filesystem - before.filesystem, 1);
        assert_eq!(facts.siblings.len(), if enabled { 2 } else { 0 });
        assert_eq!(after.list - before.list, if enabled { 4 } else { 0 });
        assert_eq!(facts.in_repo, Some(false));
        assert_eq!(facts.readonly, Some(false));
        facts.validate(&r.binding.cwd).unwrap();
    }
}

// Non-directories count toward the raw cap before d_type filtering.
#[test]
fn raw_sibling_limit_precedes_filtering() {
    for entries in [255, 256, 257, 1000] {
        let f = Fixture::new();
        let cwd = f.dir("alphabet");
        for i in 0..entries - 3 {
            fs::write(f.0.join(format!("file-{i:04}")), []).unwrap();
        }
        let r = request(&cwd, &f.0, true);
        let mut m = meter();
        let roots = selected(&r, &mut m);
        let before = m.counts[Phase::Content as usize];
        let facts = collect(discovery(&roots), r.binding.path_query, &mut m);
        let set = &facts.siblings[0];
        assert_eq!(
            m.counts[Phase::Content as usize].raw_entries - before.raw_entries,
            entries.min(256)
        );
        assert_eq!(set.complete, entries < 256);
        if entries < 256 {
            assert_eq!(set.names, vec![b"alphabet".to_vec()]);
        }
        assert_eq!(facts.partial, entries >= 256);
        assert!(set.names.iter().all(|n| n != b"." && n != b".."));
    }
}

// Compare every complete list with read_dir and core's full-input shortener.
#[test]
fn complete_siblings_match_filesystem_and_existing_shortener() {
    let f = Fixture::new();
    let repo = f.repo("alphabet");
    let cwd = f.dir("alphabet/leaf");
    f.dir("alpine");
    fs::write(f.0.join("alphanumeric"), []).unwrap();
    symlink("/nonexistent-e1-target", f.0.join("alpenglow")).unwrap();
    let r = request(&cwd, &f.0, true);
    let mut m = meter();
    let roots = selected(&r, &mut m);
    let facts = collect(discovery(&roots), r.binding.path_query, &mut m);
    assert!(!facts.partial);
    assert_eq!(facts.repo_component, Some((count(&repo) - 1) as u16));
    let mut full = Vec::new();
    for (set, dir) in facts.siblings.iter().zip([&f.0, &repo]) {
        let mut oracle: Vec<Vec<u8>> = fs::read_dir(dir)
            .unwrap()
            .filter_map(|e| {
                let e = e.unwrap();
                if e.file_type().unwrap().is_dir() {
                    Some(e.file_name().into_vec())
                } else {
                    None
                }
            })
            .collect();
        let mut actual = set.names.clone();
        oracle.sort();
        actual.sort();
        assert_eq!(actual, oracle);
        full.push(oracle);
    }
    let refs: Vec<Vec<&[u8]>> = full
        .iter()
        .map(|s| s.iter().map(Vec::as_slice).collect())
        .collect();
    let siblings: Vec<_> = refs.iter().map(|r| Some(r.as_slice())).collect();
    let oracle = PathFacts::new(Anchor::Home, &[b"alphabet", b"leaf"], Some(0), &siblings)
        .with_readonly(Some(false));
    let actual = facts
        .to_path_facts(&r.binding.cwd, r.binding.path_query)
        .unwrap();
    for method in [Method::Unique, Method::Repo, Method::Abbrev(1)] {
        assert_eq!(shorten(&actual, method), shorten(&oracle, method));
    }
    assert_eq!(actual.readonly(), oracle.readonly());
}

// A truncated prefix must never claim uniqueness, regardless of directory order.
#[test]
fn partial_siblings_use_abbrev() {
    let f = Fixture::new();
    let cwd = f.dir("alphabet/leaf");
    for i in 0..300 {
        fs::write(f.0.join(format!("alphabet-{i}")), []).unwrap();
    }
    let r = request(&cwd, &f.0, true);
    let mut m = meter();
    let roots = selected(&r, &mut m);
    let facts = collect(discovery(&roots), r.binding.path_query, &mut m);
    assert!(!facts.siblings[0].complete);
    assert!(facts.partial);
    let actual = facts
        .to_path_facts(&r.binding.cwd, r.binding.path_query)
        .unwrap();
    assert_eq!(unique(&actual), "~/a/leaf");
    let oracle = PathFacts::new(Anchor::Home, &[b"alphabet", b"leaf"], None, &[]);
    assert_eq!(unique(&actual), unique(&oracle));
}

// Symlinks/dot/dotdot cannot map a physical repo or names onto logical indices.
#[test]
fn logical_path_mismatch_never_relabels_repo_root() {
    let f = Fixture::new();
    let repo = f.repo("repo");
    f.dir("repo/child");
    symlink(&repo, f.0.join("alias")).unwrap();
    for cwd in [
        f.0.join("alias"),
        f.0.join("repo/./"),
        f.0.join("repo/child/.."),
    ] {
        let r = request(&cwd, &f.0, true);
        let mut m = meter();
        let roots = selected(&r, &mut m);
        let before = m.counts[Phase::Content as usize];
        let facts = collect(discovery(&roots), r.binding.path_query, &mut m);
        assert_eq!(facts.in_repo, Some(true));
        assert_eq!(facts.repo_component, None);
        assert!(facts.siblings.is_empty());
        assert!(facts.partial);
        assert_eq!(before.list, m.counts[Phase::Content as usize].list);
        let actual = facts
            .to_path_facts(&r.binding.cwd, r.binding.path_query)
            .unwrap();
        assert_eq!(shorten(&actual, Method::Repo), None);
    }
}

// The repo discovery stop is not the ancestor-names boundary: HOME and 32 are.
#[test]
fn ancestors_continue_past_repo_but_stop_at_home_or_thirty_two() {
    for depth in [1, 31, 32, 33, 40] {
        let f = Fixture::new();
        let mut cwd = f.0.clone();
        for _ in 0..depth {
            cwd.push("d");
            fs::create_dir(&cwd).unwrap();
        }
        fs::create_dir(cwd.join(".git")).unwrap();
        fs::write(
            cwd.join(".git/HEAD"),
            b"0123456789012345678901234567890123456789\n",
        )
        .unwrap();
        let r = request(&cwd, &f.0, true);
        let mut m = meter();
        let roots = selected(&r, &mut m);
        let before = m.counts[Phase::Content as usize];
        let peak = m.peak_fds;
        let facts = collect(discovery(&roots), r.binding.path_query, &mut m);
        assert_eq!(facts.siblings.len(), depth.min(32));
        assert_eq!(
            facts.siblings[0].component as usize,
            count(&cwd) - depth.min(32)
        );
        assert!(facts.siblings.iter().all(|s| s.complete));
        assert_eq!(facts.partial, depth > 32);
        assert_eq!(
            m.counts[Phase::Content as usize].list - before.list,
            (2 * depth.min(32)) as u64
        );
        assert_eq!(m.peak_fds, peak);
        assert!(peak <= 35);
    }
}

// Real sibling bytes collide only after sanitization; raw-self exclusion is exact.
#[test]
fn sanitized_collisions_match_full_input_oracle() {
    let f = Fixture::new();
    let name = std::ffi::OsString::from_vec(b"abc\x1b".to_vec());
    let twin = std::ffi::OsString::from_vec(b"abc\x7f".to_vec());
    let parent = f.0.join(name);
    fs::create_dir(&parent).unwrap();
    fs::create_dir(f.0.join(twin)).unwrap();
    let cwd = parent.join("leaf");
    fs::create_dir(&cwd).unwrap();
    let r = request(&cwd, &f.0, true);
    let mut m = meter();
    let roots = selected(&r, &mut m);
    let facts = collect(discovery(&roots), r.binding.path_query, &mut m);
    let oracle = PathFacts::new(
        Anchor::Home,
        &[b"abc\x1b", b"leaf"],
        None,
        &[Some(&[b"abc\x1b", b"abc\x7f"]), None],
    );
    assert_eq!(
        unique(
            &facts
                .to_path_facts(&r.binding.cwd, r.binding.path_query)
                .unwrap()
        ),
        unique(&oracle)
    );
    assert_eq!(unique(&oracle), "~/abc/leaf");
}

// Bytes are bounded before storing: one folder <=8KiB, request <=16KiB.
#[test]
fn sibling_bytes_are_bounded_across_folders() {
    let f = Fixture::new();
    let cwd = f.dir("alphabet/beta/gamma/leaf");
    for dir in [
        &f.0,
        &f.0.join("alphabet"),
        &f.0.join("alphabet/beta"),
        &f.0.join("alphabet/beta/gamma"),
    ] {
        for i in 0..50 {
            fs::create_dir(dir.join(format!("{i:03}{}", "x".repeat(197)))).unwrap();
        }
    }
    let r = request(&cwd, &f.0, true);
    let mut m = meter();
    let roots = selected(&r, &mut m);
    let facts = collect(discovery(&roots), r.binding.path_query, &mut m);
    assert!(facts.partial);
    assert!(facts.siblings.iter().all(|s| !s.complete));
    assert!(
        facts
            .siblings
            .iter()
            .all(|s| s.names.iter().map(Vec::len).sum::<usize>() <= 8192)
    );
    assert!(
        facts
            .siblings
            .iter()
            .flat_map(|s| &s.names)
            .map(Vec::len)
            .sum::<usize>()
            <= 16384
    );
    facts.validate(&r.binding.cwd).unwrap();
    let actual = facts
        .to_path_facts(&r.binding.cwd, r.binding.path_query)
        .unwrap();
    assert_eq!(unique(&actual), "~/a/b/g/leaf");
}

// One request meter across thousands of folders: scratch must return to baseline.
#[test]
fn sibling_scratch_is_live_over_thousands_of_items() {
    let f = Fixture::new();
    let cwd = f.dir("child");
    for i in 0..10 {
        fs::create_dir(f.0.join(format!("{i}{}", "x".repeat(200)))).unwrap();
    }
    let r = request(&cwd, &f.0, true);
    let mut m = meter();
    m.allocation_limit = 100_000;
    for _ in 0..2048 {
        let roots = selected(&r, &mut m);
        let baseline = m.live_allocated();
        let facts = collect(discovery(&roots), r.binding.path_query, &mut m);
        assert!(!facts.partial);
        assert_eq!(m.live_allocated(), baseline);
        drop(roots);
        assert_eq!(m.live_fds(), 0);
        assert_eq!(m.live_allocated(), 0);
    }
}

// Kernel effective-user checks, including root's write override; never touch a file.
#[test]
fn readonly_matches_effective_user_without_creation() {
    let f = Fixture::new();
    let cwd = f.dir("dir");
    for mode in [0o700, 0o500] {
        fs::set_permissions(&cwd, fs::Permissions::from_mode(mode)).unwrap();
        let r = request(&cwd, &f.0, false);
        let mut m = meter();
        let roots = selected(&r, &mut m);
        let facts = collect(discovery(&roots), r.binding.path_query, &mut m);
        // SAFETY: reads current effective identity only.
        let root = unsafe { libc::geteuid() } == 0;
        assert_eq!(facts.readonly, Some(mode == 0o500 && !root));
        assert_eq!(fs::read_dir(&cwd).unwrap().count(), 0);
    }
    fs::set_permissions(&cwd, fs::Permissions::from_mode(0o700)).unwrap();
}

fn isolated(name: &str) -> bool {
    if std::env::var("BINGSU_E1_CHILD").ok().as_deref() == Some(name) {
        #[cfg(target_os = "linux")]
        assert_eq!(
            // SAFETY: irreversible prerequisite only in a disposable child.
            unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) },
            0
        );
        return true;
    }
    let f = Fixture::new();
    let mut child = Command::new(std::env::current_exe().unwrap());
    child.args(["--exact", name, "--nocapture", "--test-threads=1"]);
    // Fails if an ignored parent reports success without running its child.
    if std::env::args_os().any(|arg| arg == "--ignored") {
        child.arg("--ignored");
    }
    let output = child
        .env("BINGSU_E1_CHILD", name)
        .env("BINGSU_E1_ROOT", &f.0)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed; 0 failed"));
    false
}
struct Sink {
    events: Rc<RefCell<Vec<String>>>,
    updates: Vec<Update>,
    progress: Vec<Progress>,
}
impl update_sink::UpdateSink for Sink {
    fn update(&mut self, value: Update) -> std::io::Result<()> {
        self.events
            .borrow_mut()
            .push(format!("update:{}", value.segment));
        self.updates.push(value);
        Ok(())
    }
    fn progress(&mut self, value: Progress) -> std::io::Result<()> {
        self.progress.push(value);
        Ok(())
    }
}
fn deadlines() -> git::StageDeadlines {
    git::StageDeadlines {
        a_ms: 60_000,
        path_ms: 60_000,
        b_ms: 60_000,
        c_ms: 60_000,
        d_ms: 60_000,
    }
}

fn git_oracle(path: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap())
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_TERMINAL_PROMPT", "0")
        .args(args)
        .current_dir(path)
        .output()
        .expect("Git oracle required");
    assert!(output.status.success(), "{args:?}: {output:?}");
    String::from_utf8(output.stdout).unwrap().trim().to_owned()
}

fn full_access() -> Access {
    #[cfg(target_os = "linux")]
    let access = Access::probe(&mut meter()).unwrap();
    #[cfg(target_os = "macos")]
    let access = {
        use std::os::fd::AsFd;
        let f = Fixture::new();
        f.dir("dir");
        fs::write(f.0.join("value"), b"inside").unwrap();
        fs::write(f.0.join("dir/file"), b"inside").unwrap();
        fs::write(f.0.join("hard"), b"linked").unwrap();
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
    assert!(access.guarantee().is_some(), "kernel guarantee required");
    access
}

fn deep_dir(base: &Path, components: usize) -> PathBuf {
    assert!(count(base) <= components);
    let mut path = base.to_owned();
    for _ in count(base)..components {
        path.push("alphabet");
    }
    fs::create_dir_all(&path).unwrap();
    path
}

fn gitfile_fd_fixture(
    f: &Fixture,
    submodule: bool,
    cwd_components: usize,
    common_components: usize,
) -> Request {
    let repo = deep_dir(&f.dir("source"), common_components - 1);
    git_oracle(&repo, &["init", "-qb", "main"]);
    git_oracle(
        &repo,
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
    let cwd = if submodule {
        let relative = vec!["module"; cwd_components - count(&repo)].join("/");
        git_oracle(
            &repo,
            &[
                "-c",
                "protocol.file.allow=always",
                "submodule",
                "add",
                "-q",
                repo.to_str().unwrap(),
                &relative,
            ],
        );
        repo.join(relative)
    } else {
        let path = deep_dir(&f.dir("work"), cwd_components - 1).join("linked");
        git_oracle(
            &repo,
            &["worktree", "add", "-q", "--detach", path.to_str().unwrap()],
        );
        path
    };
    assert_eq!(count(&cwd), cwd_components);
    request(&cwd, &f.0, true)
}

fn assert_gitfile_fd_budget(r: &Request, partial: bool) {
    let cwd = Path::new(std::ffi::OsStr::from_bytes(&r.binding.cwd));
    let oid = git_oracle(cwd, &["rev-parse", "HEAD"]);
    let branch = git_oracle(cwd, &["rev-parse", "--abbrev-ref", "HEAD"]);
    let access = full_access();
    let pipeline_access = full_access();
    let mut m = meter();
    let selection = discover::select(r, access, &mut m).unwrap();
    assert!(matches!(selection, Selection::Repository(..)));
    let facts = collect(discovery(&selection), r.binding.path_query, &mut m);
    assert_eq!(facts.partial, partial);
    assert_eq!(facts.in_repo, Some(true));
    assert_eq!(facts.repo_component, Some((count(cwd) - 1) as u16));
    assert_eq!(facts.readonly, Some(false));
    facts.validate(&r.binding.cwd).unwrap();
    if partial {
        assert!(facts.siblings.is_empty());
        let path = facts
            .to_path_facts(&r.binding.cwd, r.binding.path_query)
            .unwrap();
        assert_eq!(
            shorten(&path, Method::Unique),
            shorten(&path, Method::Abbrev(1))
        );
    } else {
        assert_eq!(
            facts.siblings.len(),
            count(cwd) - usize::from(r.binding.path_query.home_component.unwrap()) - 1
        );
        assert!(facts.siblings.iter().all(|set| set.complete));
    }
    assert!(m.peak_fds <= meter::LIVE_FDS);
    println!(
        "gitfile components={} partial={partial} peak_fds={}",
        count(cwd),
        m.peak_fds
    );
    drop(selection);
    assert_eq!(m.live_fds(), 0);

    let events = Rc::new(RefCell::new(Vec::new()));
    let output = Rc::clone(&events);
    let mut m = meter();
    m.hook = Some(Box::new(move |event| {
        output.borrow_mut().push(event.to_owned())
    }));
    let mut sink = Sink {
        events: Rc::clone(&events),
        updates: vec![],
        progress: vec![],
    };
    git::collect_with_deadlines(r, &mut sink, m, pipeline_access, deadlines()).unwrap();
    let first = &sink.updates[0];
    assert_eq!(first.segment, 3);
    let value = first.value.as_ref().unwrap();
    let field = |name| &value.fields[bingsu_core::field::BUILTIN[3].field_index(name).unwrap()];
    assert_eq!(
        field("stage"),
        &bingsu_core::field::Field::text(b"A", 1, WidthProfile::DEFAULT)
    );
    assert_eq!(
        field("commit"),
        &if branch == "HEAD" {
            bingsu_core::field::Field::text(&oid.as_bytes()[..12], 16, WidthProfile::DEFAULT)
        } else {
            bingsu_core::field::Field::ABSENT
        }
    );
    assert_eq!(
        field("branch"),
        &if branch == "HEAD" {
            bingsu_core::field::Field::ABSENT
        } else {
            bingsu_core::field::Field::text(branch.as_bytes(), 256, WidthProfile::DEFAULT)
        }
    );
    assert_eq!(
        sink.updates.iter().map(|u| u.segment).collect::<Vec<_>>(),
        [3, 1, 3, 3, 3]
    );
    assert_eq!(
        sink.updates
            .iter()
            .filter_map(|u| u.value.as_ref())
            .map(|v| v.fields[bingsu_core::field::BUILTIN[3].field_index("stage").unwrap()].clone())
            .collect::<Vec<_>>(),
        [b"A", b"B", b"C", b"D"]
            .into_iter()
            .map(|stage| bingsu_core::field::Field::text(stage, 1, WidthProfile::DEFAULT))
            .collect::<Vec<_>>()
    );
    assert_eq!(sink.updates[1].facts.as_ref(), Some(&facts));
    assert!(sink.progress[0].stage_a_complete);
    let events = events.borrow();
    let a = events.iter().position(|e| e == "update:3").unwrap();
    let path = events.iter().position(|e| e == "update:1").unwrap();
    let closed = events
        .iter()
        .position(|e| e == "discovery_consumed")
        .unwrap();
    let layer = events
        .iter()
        .position(|e| e == "before_read_layer")
        .unwrap();
    assert!(a < path && path < closed && closed < layer);
    assert_eq!(
        events[..a].iter().any(|e| e == "names_discarded_for_fds"),
        partial
    );
}

// Fails if optional ancestors exhaust the metadata walk and suppress A/dir.
#[test]
fn deep_linked_worktree_keeps_git_with_partial_siblings() {
    if !isolated("deep_linked_worktree_keeps_git_with_partial_siblings") {
        return;
    }
    let f = Fixture::new();
    let r = gitfile_fd_fixture(&f, false, 34, 34);
    assert_gitfile_fd_budget(&r, true);
}

// Fails if the submodule ancestor or target acquisition retains names under pressure.
#[test]
fn deep_submodule_keeps_git_with_partial_siblings() {
    if !isolated("deep_submodule_keeps_git_with_partial_siblings") {
        return;
    }
    let f = Fixture::new();
    let r = gitfile_fd_fixture(&f, true, 34, 34);
    assert_gitfile_fd_budget(&r, true);
}

// Fails if the first margin is reused after acquiring the candidate gitdir:
// 22 live + 34 transient fits, but the next acquisition has 23 live + 34.
#[test]
fn linked_commondir_rechecks_fd_margin() {
    if !isolated("linked_commondir_rechecks_fd_margin") {
        return;
    }
    let f = Fixture::new();
    let r = gitfile_fd_fixture(&f, false, 21, 34);
    assert_gitfile_fd_budget(&r, true);
}

// Fails if names are always discarded for gitfiles, even with ample fd headroom.
#[test]
fn shallow_linked_worktree_keeps_complete_siblings() {
    if !isolated("shallow_linked_worktree_keeps_complete_siblings") {
        return;
    }
    let f = Fixture::new();
    let depth = count(&f.0) + 2;
    let r = gitfile_fd_fixture(&f, false, depth, depth);
    assert_gitfile_fd_budget(&r, false);
}

// The same full-name contract applies to shallow reciprocal submodule metadata.
#[test]
fn shallow_submodule_keeps_complete_siblings() {
    if !isolated("shallow_submodule_keeps_complete_siblings") {
        return;
    }
    let f = Fixture::new();
    let depth = count(&f.0) + 2;
    let r = gitfile_fd_fixture(&f, true, depth, depth);
    assert_gitfile_fd_budget(&r, false);
}

// Fails if deep ordinary repositories lose names without a second acquisition.
#[test]
fn deep_plain_repository_keeps_complete_siblings() {
    let f = Fixture::new();
    let cwd = deep_dir(&f.0, 34);
    fs::create_dir(cwd.join(".git")).unwrap();
    let r = request(&cwd, &f.0, true);
    let mut m = meter();
    let roots = selected(&r, &mut m);
    let facts = collect(discovery(&roots), r.binding.path_query, &mut m);
    assert!(!facts.partial);
    assert!(!facts.siblings.is_empty());
    assert!(facts.siblings.iter().all(|set| set.complete));
    assert!(m.peak_fds <= meter::LIVE_FDS);
}

// Fails if an exact fit discards names, or the next fd is not accounted before I/O.
#[test]
fn metadata_fd_margin_preserves_exact_fit_then_releases_names() {
    for needed in [3, 34] {
        let f = Fixture::new();
        let cwd = f.dir("alphabet/leaf");
        let r = request(&cwd, &f.0, true);
        let mut m = meter();
        let mut d = safe_read::acquire(&r.binding.cwd, r.binding.path_query, &mut m).unwrap();
        let mut leases = Vec::new();
        while m.live_fds() < meter::LIVE_FDS - needed {
            leases.push(m.lease().unwrap());
        }
        let before = m.counts;
        let ancestors = d.ancestors().len();
        d.spare_fds(needed, &mut m);
        assert_eq!(d.ancestors().len(), ancestors);
        leases.push(m.lease().unwrap());
        d.spare_fds(needed, &mut m);
        assert!(d.ancestors().is_empty());
        assert_eq!(m.counts, before, "releasing names performs no acquisition");
        assert!(m.live_fds() + needed <= meter::LIVE_FDS);
        let facts = collect(&d, r.binding.path_query, &mut m);
        assert!(facts.partial);
        assert!(facts.siblings.is_empty());
        assert_eq!(facts.readonly, Some(false));
    }
}

// Fails if --ignored is lost when isolated() re-executes the test binary.
#[test]
fn isolated_forwards_ignored_to_child() {
    let output = Command::new(std::env::current_exe().unwrap())
        .args(["--ignored", "--exact", "isolated_ignored_child_probe"])
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed; 0 failed"));
}

#[test]
#[ignore = "child probe exercised explicitly by isolated_forwards_ignored_to_child"]
fn isolated_ignored_child_probe() {
    if !isolated("isolated_ignored_child_probe") {
        return;
    }
    assert_eq!(
        std::env::var("BINGSU_E1_CHILD").unwrap(),
        "isolated_ignored_child_probe"
    );
}

// Real collection ordering, exact fd release, and Linux read rules (child only).
#[test]
fn ancestor_names_use_held_fds_without_stat_or_landlock_widening() {
    if !isolated("ancestor_names_use_held_fds_without_stat_or_landlock_widening") {
        return;
    }
    let f = Fixture::new();
    let repo = f.repo("home/repo");
    let cwd = f.dir("home/repo/child");
    fs::write(f.0.join("home/private"), b"outside").unwrap();
    fs::write(repo.join("inside"), b"inside").unwrap();
    let r = request(&cwd, &f.0.join("home"), true);
    let events = Rc::new(RefCell::new(Vec::new()));
    let mut m = meter();
    let output = Rc::clone(&events);
    let live = m.fd_observer();
    m.hook = Some(Box::new(move |e| {
        if e == "before_read_layer" {
            assert_eq!(live.get(), 2, "only worktree + gitdir");
        }
        output.borrow_mut().push(e.to_owned());
    }));
    let mut sink = Sink {
        events: Rc::clone(&events),
        updates: vec![],
        progress: vec![],
    };
    git::collect_with_deadlines(&r, &mut sink, m, Access::stage_a_only(), deadlines()).unwrap();
    let events = events.borrow();
    let a = events.iter().position(|s| s == "update:3").unwrap();
    let path = events.iter().position(|s| s == "update:1").unwrap();
    let closed = events
        .iter()
        .position(|s| s == "discovery_consumed")
        .unwrap();
    let layer = events
        .iter()
        .position(|s| s == "before_read_layer")
        .unwrap();
    assert!(a < path && path < closed && closed < layer);
    assert!(
        events[a + 1..path]
            .iter()
            .all(|s| !s.starts_with("openat:") && s != "before_read")
    );
    assert!(
        sink.updates[1]
            .facts
            .as_ref()
            .unwrap()
            .siblings
            .iter()
            .all(|s| s.complete)
    );
    #[cfg(target_os = "linux")]
    {
        assert_eq!(fs::read(repo.join("inside")).unwrap(), b"inside");
        assert_eq!(
            fs::read(f.0.join("home/private"))
                .unwrap_err()
                .raw_os_error(),
            Some(libc::EACCES)
        );
        assert_eq!(
            fs::read_dir(f.0.join("home")).err().unwrap().raw_os_error(),
            Some(libc::EACCES)
        );
    }
}

// Hold the chosen roots, drop discovery, and prove that only those fds remain.
#[test]
fn discovery_drop_releases_every_unselected_ancestor() {
    let f = Fixture::new();
    let cwd = f.repo("home/repo");
    f.dir("home/repo/a/b");
    let r = request(&cwd.join("a/b"), &f.0, true);
    let mut m = meter();
    let roots = selected(&r, &mut m);
    assert!(m.live_fds() > 2);
    let Selection::Repository(roots, discovery) = roots else {
        panic!("repo")
    };
    let facts = collect(&discovery, r.binding.path_query, &mut m);
    assert_eq!(facts.in_repo, Some(true));
    drop(discovery);
    assert_eq!(m.live_fds(), 2);
    drop(roots);
    assert_eq!(m.live_fds(), 0);
}

// Dir-only still publishes valid completion evidence; no object/config preflight.
#[test]
fn dir_only_shares_discovery_and_publishes_progress() {
    if !isolated("dir_only_shares_discovery_and_publishes_progress") {
        return;
    }
    let f = Fixture::new();
    let cwd = f.repo("repo");
    let mut r = request(&cwd, &f.0, true);
    r.binding.mask = 1 << 1;
    let events = Rc::new(RefCell::new(Vec::new()));
    let output = Rc::clone(&events);
    let mut m = meter();
    m.hook = Some(Box::new(move |e| output.borrow_mut().push(e.to_owned())));
    let mut sink = Sink {
        events: Rc::clone(&events),
        updates: vec![],
        progress: vec![],
    };
    let limits = deadlines();
    assert_eq!(git::StageDeadlines::PRODUCT.path_ms, 3);
    git::collect_with_deadlines(&r, &mut sink, m, Access::stage_a_only(), limits).unwrap();
    assert_eq!(sink.updates.len(), 1);
    assert_eq!(sink.updates[0].segment, 1);
    let facts = sink.updates[0].facts.as_ref().unwrap();
    assert!(!facts.partial);
    assert_eq!(facts.readonly, Some(false));
    assert_eq!(facts.siblings.len(), 1);
    assert_eq!(facts.in_repo, Some(true));
    assert!(sink.progress[0].stage_a_complete);
    assert!(
        !events
            .borrow()
            .iter()
            .any(|e| e == "preflight_start" || e == "gix_parse")
    );
}

// Real ACL oracle: mode bits alone are insufficient. Fixture setup is outside collector.
#[test]
// Linux runs this in the CI step that installs acl; macOS runs it in the normal test job.
#[cfg_attr(
    target_os = "linux",
    ignore = "Linux requires setfacl (acl package); run by the CI read-only oracle step"
)]
fn readonly_honors_acl() {
    let f = Fixture::new();
    let cwd = f.dir("acl");
    #[cfg(target_os = "macos")]
    let setup = Command::new("chmod")
        .arg("+a")
        .arg("everyone deny add_file,add_subdirectory,delete_child")
        .arg(&cwd)
        .output()
        .unwrap();
    #[cfg(target_os = "linux")]
    let setup = Command::new("setfacl")
        .args(["-m", "u::r-x"])
        .arg(&cwd)
        .output()
        .expect("BLOCKED: setfacl is required for the ACL oracle");
    assert!(
        setup.status.success(),
        "BLOCKED: ACL fixture: {}",
        String::from_utf8_lossy(&setup.stderr)
    );
    let r = request(&cwd, &f.0, false);
    let mut m = meter();
    let roots = selected(&r, &mut m);
    let facts = collect(discovery(&roots), r.binding.path_query, &mut m);
    // SAFETY: effective identity only. Root may override discretionary ACLs.
    let root = unsafe { libc::geteuid() } == 0;
    assert_eq!(facts.readonly, Some(!root));
    assert_eq!(fs::read_dir(&cwd).unwrap().count(), 0);
    #[cfg(target_os = "macos")]
    assert!(
        Command::new("chmod")
            .arg("-N")
            .arg(&cwd)
            .status()
            .unwrap()
            .success()
    );
    fs::set_permissions(&cwd, fs::Permissions::from_mode(0o700)).unwrap();
}

// A real read-only mount supplied by the Linux lead, or the sealed macOS system volume.
#[test]
// Linux runs this in the CI step that prepares a read-only bind mount; macOS uses the sealed system volume.
#[cfg_attr(
    target_os = "linux",
    ignore = "Linux requires BINGSU_E1_READONLY_MOUNT on a read-only mount; run by the CI read-only oracle step"
)]
fn readonly_mount_is_observed_without_a_write_probe() {
    #[cfg(target_os = "macos")]
    let cwd = PathBuf::from("/System/Library");
    #[cfg(target_os = "linux")]
    let cwd = PathBuf::from(
        std::env::var_os("BINGSU_E1_READONLY_MOUNT")
            .expect("BLOCKED: provide a read-only mount directory"),
    );
    let r = request(&cwd, &cwd, false);
    let mut m = meter();
    let d = safe_read::acquire(&r.binding.cwd, r.binding.path_query, &mut m).unwrap();
    let facts = collect(&d, r.binding.path_query, &mut m);
    assert_eq!(facts.readonly, Some(true));
}

// Enumeration is one-shot: a second read cannot certify the tail as a full list.
#[test]
fn reused_ancestor_offset_never_certifies_a_partial_tail() {
    let f = Fixture::new();
    let cwd = f.dir("alphabet/leaf");
    f.dir("alpine");
    let r = request(&cwd, &f.0, true);
    let mut m = meter();
    let roots = selected(&r, &mut m);
    let first = collect(discovery(&roots), r.binding.path_query, &mut m);
    assert!(!first.partial);
    let before = m.counts[Phase::Content as usize].list;
    let second = collect(discovery(&roots), r.binding.path_query, &mut m);
    assert!(second.partial);
    assert!(
        second
            .siblings
            .iter()
            .all(|s| !s.complete && s.names.is_empty())
    );
    assert_eq!(m.counts[Phase::Content as usize].list, before);
    assert_eq!(
        unique(
            &second
                .to_path_facts(&r.binding.cwd, r.binding.path_query)
                .unwrap()
        ),
        "~/a/leaf"
    );
    assert_eq!(
        discovery(&roots)
            .ancestors()
            .last()
            .unwrap()
            .entries(256, &mut m)
            .err(),
        Some(safe_read::ReadError::Changed)
    );
}

fn load() -> f64 {
    let mut values = [0.0; 3];
    // SAFETY: writable three-element output, no environment or path lookup.
    let rc = unsafe { libc::getloadavg(values.as_mut_ptr(), 3) };
    if rc != 3 { f64::INFINITY } else { values[0] }
}

// Release observations include the new fd-pressure branch; no latency claim at load >=4.
#[test]
#[ignore = "release measurement; writes target/e1-review-evidence/gitfile-observations.json"]
fn gitfile_fd_warm_observations() {
    if cfg!(debug_assertions) {
        panic!("run --release");
    }
    let mut reports = Vec::new();
    for (case, submodule, deep) in [
        ("linked-shallow", false, false),
        ("linked-deep", false, true),
        ("submodule-shallow", true, false),
        ("submodule-deep", true, true),
    ] {
        let f = Fixture::new();
        let depth = if deep { 34 } else { count(&f.0) + 2 };
        let r = gitfile_fd_fixture(&f, submodule, depth, depth);
        let start_load = load();
        let mut selection_times = Vec::new();
        let mut path_times = Vec::new();
        let mut cold = (0, 0);
        let mut expected = None;
        for iteration in 0..=200 {
            let access = full_access();
            let mut m = meter();
            let start = (start_load < 4.0).then(Instant::now);
            let selected = discover::select(&r, access, &mut m).unwrap();
            let selection_ns = start.map(|s| s.elapsed().as_nanos());
            let before = m.counts[Phase::Content as usize];
            let held = m.live_fds();
            let start = (start_load < 4.0).then(Instant::now);
            let facts = collect(discovery(&selected), r.binding.path_query, &mut m);
            let path_ns = start.map(|s| s.elapsed().as_nanos());
            assert_eq!(facts.partial, deep);
            let after = m.counts[Phase::Content as usize];
            assert_eq!(
                (after.open, after.stat, after.read),
                (before.open, before.stat, before.read)
            );
            let counts = (
                after.list - before.list,
                after.raw_entries - before.raw_entries,
                held,
                m.peak_fds,
            );
            assert!(m.peak_fds <= meter::LIVE_FDS);
            if let Some(expected) = expected {
                assert_eq!(counts, expected);
            }
            expected = Some(counts);
            if let (Some(selection_ns), Some(path_ns)) = (selection_ns, path_ns) {
                if iteration == 0 {
                    cold = (selection_ns, path_ns);
                } else {
                    selection_times.push(selection_ns);
                    path_times.push(path_ns);
                }
            }
        }
        let end_load = load();
        let timing = if start_load < 4.0 && end_load < 4.0 {
            selection_times.sort();
            path_times.sort();
            format!(
                "\"selection_cold_ns\":{},\"path_cold_ns\":{},\"selection_p50_ns\":{},\"selection_p95_ns\":{},\"path_p50_ns\":{},\"path_p95_ns\":{},\"selection_samples_ns\":{selection_times:?},\"path_samples_ns\":{path_times:?}",
                cold.0,
                cold.1,
                selection_times[99],
                selection_times[189],
                path_times[99],
                path_times[189]
            )
        } else {
            "\"timing\":\"BLOCKED: load >=4 or unavailable\"".to_owned()
        };
        let (lists, raw, held, peak) = expected.unwrap();
        reports.push(format!("{{\"case\":\"{case}\",\"runs\":200,\"load_start\":{start_load},\"load_end\":{end_load},\"getdents\":{lists},\"raw_entries\":{raw},\"held_fds\":{held},\"peak_fds\":{peak},\"path_open\":0,\"path_stat\":0,\"path_read\":0,{timing}}}"));
    }
    let out = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/e1-review-evidence");
    fs::create_dir_all(&out).unwrap();
    let json = format!(
        "{{\"path_budget_ms\":3,\"cases\":[{}]}}\n",
        reports.join(",")
    );
    fs::write(out.join("gitfile-observations.json"), &json).unwrap();
    println!("{json}");
}

// Observation only: release, warm 200, cold separate, wall-clock only at load <4.
#[test]
#[ignore = "release measurement; writes target/e1-evidence/observations.json"]
fn path_facts_warm_observations() {
    if cfg!(debug_assertions) {
        panic!("run --release");
    }
    let mut reports = Vec::new();
    for (case, depth, width, unique_requested) in [
        ("unique-off", 2, 8, false),
        ("small", 2, 8, true),
        ("depth32", 32, 0, true),
        ("raw255", 1, 252, true),
        ("raw256", 1, 253, true),
        ("raw257", 1, 254, true),
        ("bytes", 4, 80, true),
    ] {
        let f = Fixture::new();
        let mut cwd = f.0.clone();
        for _ in 0..depth {
            for i in 0..width {
                let name = if case == "bytes" {
                    format!("{i:03}{}", "x".repeat(197))
                } else {
                    format!("s{i:03}")
                };
                if case == "bytes" {
                    fs::create_dir(cwd.join(name)).unwrap();
                } else {
                    fs::write(cwd.join(name), []).unwrap();
                }
            }
            cwd.push("alphabet");
            fs::create_dir(&cwd).unwrap();
        }
        let r = request(&cwd, &f.0, unique_requested);
        let start_load = load();
        let timed = start_load < 4.0;
        let mut times = Vec::new();
        let mut core_times = Vec::new();
        let mut cold = None;
        let mut expected = None;
        let mut last = String::new();
        for iteration in 0..=200 {
            let mut m = meter();
            let roots = selected(&r, &mut m);
            let before = m.counts[Phase::Content as usize];
            let fds = m.live_fds();
            let start = timed.then(Instant::now);
            let facts = collect(discovery(&roots), r.binding.path_query, &mut m);
            if let Some(start) = start {
                let ns = start.elapsed().as_nanos();
                if iteration == 0 {
                    cold = Some(ns);
                } else {
                    times.push(ns);
                }
            }
            let after = m.counts[Phase::Content as usize];
            let counts = (
                after.list - before.list,
                after.raw_entries - before.raw_entries,
                fds,
                m.peak_fds,
            );
            if let Some(expected) = expected {
                assert_eq!(counts, expected);
            } else {
                expected = Some(counts);
            }
            assert_eq!(after.open - before.open, 0);
            assert_eq!(after.stat - before.stat, 0);
            assert_eq!(after.read - before.read, 0);
            assert_eq!(fds, m.live_fds());
            let core_start = timed.then(Instant::now);
            std::hint::black_box(
                facts
                    .to_path_facts(&r.binding.cwd, r.binding.path_query)
                    .unwrap(),
            );
            if let Some(start) = core_start {
                if iteration != 0 {
                    core_times.push(start.elapsed().as_nanos());
                }
            }
            last = format!(
                "\"getdents\":{},\"raw_entries\":{},\"held_fds\":{fds},\"peak_fds\":{},\"path_new_fds\":0,\"path_open\":0,\"path_stat\":0,\"path_read\":0,\"readonly_calls\":{},\"fstatfs_calls\":{},\"sets\":{},\"partial\":{}",
                counts.0,
                counts.1,
                m.peak_fds,
                after.readonly - before.readonly,
                after.filesystem - before.filesystem,
                facts.siblings.len(),
                facts.partial
            );
        }
        let end_load = load();
        let latency = if timed && end_load < 4.0 {
            times.sort();
            core_times.sort();
            let mean = times.iter().sum::<u128>() as f64 / 200.0;
            let variance = times
                .iter()
                .map(|n| (*n as f64 - mean).powi(2))
                .sum::<f64>()
                / 200.0;
            format!(
                "\"cold_ns\":{},\"p50_ns\":{},\"p95_ns\":{},\"variance_ns2\":{variance},\"core_p50_ns\":{},\"core_p95_ns\":{},\"samples\":{times:?}",
                cold.unwrap(),
                times[99],
                times[189],
                core_times[99],
                core_times[189]
            )
        } else {
            "\"timing\":\"BLOCKED: load >=4 or unavailable\"".to_owned()
        };
        reports.push(format!("{{\"case\":\"{case}\",\"runs\":200,\"load_start\":{start_load},\"load_end\":{end_load},{last},{latency}}}"));
    }
    let out = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/e1-evidence");
    fs::create_dir_all(&out).unwrap();
    let json = format!(
        "{{\"path_budget_ms\":3,\"cases\":[{}]}}\n",
        reports.join(",")
    );
    fs::write(out.join("observations.json"), &json).unwrap();
    println!("{json}");
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "Linux root and setfacl required; isolated effective-UID test"]
fn readonly_acl_and_root_use_effective_credentials() {
    if !isolated("readonly_acl_and_root_use_effective_credentials") {
        return;
    }
    // SAFETY: process identity query, no mutation.
    assert_eq!(unsafe { libc::geteuid() }, 0, "BLOCKED: root required");
    let f = Fixture::new();
    let cwd = f.dir("acl");
    fs::set_permissions(&cwd, fs::Permissions::from_mode(0o555)).unwrap();
    let mut m = meter();
    let root = safe_read::acquire(cwd.as_os_str().as_bytes(), PathQuery::default(), &mut m)
        .unwrap()
        .select_cwd()
        .unwrap();
    assert_eq!(root.readonly(&mut m).unwrap(), Some(false));
    fs::set_permissions(&cwd, fs::Permissions::from_mode(0o777)).unwrap();
    assert!(
        Command::new("setfacl")
            .args(["-m", "u:65534:r-x"])
            .arg(&cwd)
            .status()
            .expect("BLOCKED: setfacl")
            .success()
    );
    assert_eq!(
        fs::metadata(&cwd).unwrap().permissions().mode() & 0o777,
        0o777
    );
    // SAFETY: disposable child only; saved root identity is restored before cleanup.
    assert_eq!(unsafe { libc::seteuid(65534) }, 0);
    let actual = root.readonly(&mut m);
    // SAFETY: restore saved effective identity in this isolated child.
    assert_eq!(unsafe { libc::seteuid(0) }, 0);
    assert_eq!(actual.unwrap(), Some(true));
    assert_eq!(root.readonly(&mut m).unwrap(), Some(false));
    assert_eq!(fs::read_dir(&cwd).unwrap().count(), 0);
}

// A linked worktree retains exactly three roots; the common directory's parent
// and HOME are names-only, even when discovery had stopped at the worktree.
#[test]
fn linked_worktree_releases_ancestors_and_registers_only_three_roots() {
    if !isolated("linked_worktree_releases_ancestors_and_registers_only_three_roots") {
        return;
    }
    let f = Fixture::new();
    let cwd = f.dir("home/work");
    let common = f.dir("metadata/common");
    let slot = f.dir("metadata/common/worktrees/slot");
    f.dir("metadata/common/refs");
    f.dir("metadata/common/objects");
    let oid = b"0123456789012345678901234567890123456789\n";
    fs::write(common.join("HEAD"), oid).unwrap();
    fs::write(slot.join("HEAD"), oid).unwrap();
    fs::write(cwd.join(".git"), format!("gitdir: {}\n", slot.display())).unwrap();
    fs::write(slot.join("commondir"), b"../..\n").unwrap();
    fs::write(slot.join("gitdir"), format!("{}/.git\n", cwd.display())).unwrap();
    fs::write(f.0.join("metadata/private"), b"secret").unwrap();
    fs::write(f.0.join("home/private"), b"secret").unwrap();
    let r = request(&cwd, &f.0.join("home"), true);
    let events = Rc::new(RefCell::new(Vec::new()));
    let output = Rc::clone(&events);
    let mut m = meter();
    let live = m.fd_observer();
    m.hook = Some(Box::new(move |e| {
        if e == "before_read_layer" {
            assert_eq!(live.get(), 3);
        }
        output.borrow_mut().push(e.to_owned());
    }));
    let mut sink = Sink {
        events,
        updates: vec![],
        progress: vec![],
    };
    git::collect_with_deadlines(&r, &mut sink, m, Access::stage_a_only(), deadlines()).unwrap();
    let facts = sink.updates.iter().find_map(|u| u.facts.as_ref()).unwrap();
    assert_eq!(facts.in_repo, Some(true));
    assert_eq!(facts.siblings.len(), 1);
    assert!(facts.siblings[0].complete);
    #[cfg(target_os = "linux")]
    {
        for path in [common.join("HEAD"), slot.join("HEAD")] {
            assert_eq!(fs::read(path).unwrap(), oid);
        }
        for path in [f.0.join("metadata/private"), f.0.join("home/private")] {
            assert_eq!(
                fs::read(path).unwrap_err().raw_os_error(),
                Some(libc::EACCES)
            );
        }
    }
}

// The 32-level cutoff is not evidence of absence when HOME is still farther away.
#[test]
fn bounded_discovery_never_claims_absence_before_home() {
    let f = Fixture::new();
    let home = f.repo("home");
    let mut cwd = home.clone();
    for _ in 0..33 {
        cwd.push("d");
        fs::create_dir(&cwd).unwrap();
    }
    let r = request(&cwd, &home, true);
    let mut m = meter();
    let roots = selected(&r, &mut m);
    let facts = collect(discovery(&roots), r.binding.path_query, &mut m);
    assert_eq!(facts.in_repo, None);
    assert_eq!(facts.repo_component, None);
    assert!(facts.partial);
    assert_eq!(facts.siblings.len(), 32);
    assert_eq!(facts.readonly, Some(false));
}
