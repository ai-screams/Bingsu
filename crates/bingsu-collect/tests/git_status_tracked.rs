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
#[allow(dead_code)]
#[path = "../src/update_sink.rs"]
mod update_sink;

#[path = "support/allocation.rs"]
mod allocation;

use bingsu_core::{
    collection::budget::Axis,
    field::{Field, FieldValue},
};
use git::{
    GuardedRepository,
    io::{RepoIo, RepoRoots, index},
    status_tracked::{self, StatusCounts},
};
use meter::{Meter, Phase};
use safe_read::{Access, DiscoveryQuery, ReadError as E, Root};
use std::{
    cell::RefCell,
    fs,
    io::Write,
    os::unix::{
        ffi::OsStrExt,
        fs::{PermissionsExt, symlink},
    },
    path::PathBuf,
    process::{Command, Stdio},
    time::{Duration, Instant},
};
fn meter() -> Meter {
    Meter::new(Instant::now() + Duration::from_secs(60))
}
struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let dir = std::env::temp_dir().join(format!(
            "bingsu-tracked-{}-{}",
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

fn command(f: &Fixture, args: &[&str], input: Option<&[u8]>) -> Vec<u8> {
    let mut child = Command::new("git")
        .args(["-C"])
        .arg(&f.0)
        .args(args)
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap())
        .env("HOME", &f.0)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_OPTIONAL_LOCKS", "0")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("git oracle required");
    if let Some(input) = input {
        child.stdin.take().unwrap().write_all(input).unwrap();
    }
    let out = child.wait_with_output().unwrap();
    assert!(
        out.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    out.stdout
}
fn git(f: &Fixture, args: &[&str]) -> Vec<u8> {
    command(f, args, None)
}
fn init() -> Fixture {
    let f = Fixture::new();
    git(&f, &["init", "-q"]);
    git(&f, &["config", "user.name", "Fixture"]);
    git(&f, &["config", "user.email", "fixture@example.invalid"]);
    git(&f, &["config", "core.filemode", "true"]);
    // Keep fixture object layout deterministic and prevent Git's detached
    // maintenance from racing teardown of the large/deep corpora.
    git(&f, &["config", "gc.auto", "0"]);
    git(&f, &["config", "maintenance.auto", "false"]);
    f
}
fn commit(f: &Fixture) {
    git(f, &["add", "."]);
    git(f, &["commit", "-qm", "fixture"]);
}
fn with_repo<T>(f: &Fixture, run: impl FnOnce(&GuardedRepository<'_>, &RefCell<Meter>) -> T) -> T {
    let access = access();
    let mut m = meter();
    let wr = f.root(&mut m);
    let gr = safe_read::acquire(
        f.0.join(".git").as_os_str().as_bytes(),
        DiscoveryQuery::default(),
        &mut m,
    )
    .unwrap()
    .select_cwd()
    .unwrap();
    m.phase = Phase::Content;
    let slot = RefCell::new(m);
    let io = RepoIo::new(
        RepoRoots {
            worktree: &wr,
            gitdir: &gr,
            commondir: &gr,
        },
        &access,
        &slot,
    );
    let repo = GuardedRepository::new(io, &git::refs::RefSnapshot::default()).unwrap();
    run(&repo, &slot)
}
fn status(f: &Fixture) -> StatusCounts {
    with_repo(f, |repo, _| status_tracked::load_status(repo))
}
fn count(n: u32) -> Field {
    Field::known(FieldValue::Count {
        n,
        saturated: false,
    })
}

// Exercise the real B comparator, including HEAD commit and subtree reads.
// A fresh object store in B or C double-charges the 5 MB pack and makes C fail.
#[test]
fn tracked_then_divergence_reuses_pack_and_refs_snapshots() {
    let f = init();
    git(&f, &["branch", "-M", "main"]);
    f.write("dir/file", b"base");
    commit(&f);
    git(&f, &["branch", "upstream"]);
    f.write("dir/file", b"head");
    commit(&f);
    git(&f, &["config", "branch.main.remote", "."]);
    git(&f, &["config", "branch.main.merge", "refs/heads/upstream"]);
    // Reachable incompressible padding exceeds half the shared pack budget,
    // without requiring either stage to inflate a large object.
    let mut state = 0x1234_5678u32;
    let padding: Vec<u8> = (0..5_000_000)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            state as u8
        })
        .collect();
    let blob = command(&f, &["hash-object", "-w", "--stdin"], Some(&padding));
    let blob = std::str::from_utf8(&blob).unwrap().trim();
    git(&f, &["update-ref", "refs/tags/padding", blob]);
    git(&f, &["repack", "-adq"]);
    git(&f, &["multi-pack-index", "write"]);
    git(&f, &["pack-refs", "--all", "--prune"]);
    let packed_refs_bytes = fs::metadata(f.0.join(".git/packed-refs")).unwrap().len();
    let pack_bytes: u64 = fs::read_dir(f.0.join(".git/objects/pack"))
        .unwrap()
        .map(Result::unwrap)
        .filter(|entry| {
            let name = entry.file_name();
            let name = name.as_bytes();
            name.ends_with(b".idx") || name.ends_with(b".pack") || name == b"multi-pack-index"
        })
        .map(|entry| entry.metadata().unwrap().len())
        .sum();
    assert!((5_000_000..5_100_000).contains(&pack_bytes), "{pack_bytes}");
    f.write("dir/file", b"staged");
    git(&f, &["add", "dir/file"]);
    assert_eq!(oracle(&f), (1, 0, 0));

    let mut results = Vec::new();
    for b_first in [false, true] {
        // with_repo injects a generous request deadline; this checks semantics,
        // not the scheduler's ability to finish within product stage limits.
        with_repo(&f, |repo, m| {
            assert_eq!(m.borrow().budget.used(Axis::PackBytes), 0);
            assert_eq!(m.borrow().budget.used(Axis::RefEntries), 3);
            if b_first {
                let idx = index::load(&repo.io).unwrap();
                status_tracked::observations::take();
                let got = status_tracked::tracked_status(repo, &idx);
                assert_eq!(
                    (got.staged, got.modified, got.conflicted),
                    (count(1), count(0), count(0))
                );
                assert_eq!(status_tracked::observations::take().tree_reads, 2);
                assert_eq!(m.borrow().budget.used(Axis::PackBytes), pack_bytes);
            }
            let divergence = git::stage_c::divergence(repo);
            assert_eq!(divergence, Ok(Some((1, 0))));
            results.push(divergence);
            let m = m.borrow();
            assert_eq!(m.budget.used(Axis::Packs), 1);
            assert_eq!(m.budget.used(Axis::PackBytes), pack_bytes);
            assert_eq!(m.budget.used(Axis::MappedBytes), 0);
            assert_eq!(
                m.budget.used(Axis::RefEntries),
                5 + if b_first { 2 } else { 0 }
            );
            assert_eq!(
                m.budget.used(Axis::RefBytes),
                packed_refs_bytes
                    + b"ref: refs/heads/main\n".len() as u64 * if b_first { 2 } else { 1 }
            );
            eprintln!(
                "D1A_SHARED b_first={b_first} pack_bytes={pack_bytes} refs={}",
                m.budget.used(Axis::RefEntries)
            );
        });
    }
    assert_eq!(results, [Ok(Some((1, 0))), Ok(Some((1, 0)))]);
}
fn oracle(f: &Fixture) -> (u32, u32, u32) {
    let raw = git(
        f,
        &[
            "-c",
            "status.renames=false",
            "status",
            "--porcelain=v2",
            "--ignore-submodules=all",
            "--untracked-files=no",
        ],
    );
    let mut counts = (0, 0, 0);
    for line in raw.split(|b| *b == b'\n').filter(|l| !l.is_empty()) {
        match line[0] {
            b'1' => {
                counts.0 += u32::from(line[2] != b'.');
                counts.1 += u32::from(line[3] != b'.');
            }
            b'u' => counts.2 += 1,
            _ => panic!("unexpected porcelain: {}", String::from_utf8_lossy(line)),
        }
    }
    counts
}
fn parity(f: &Fixture) -> StatusCounts {
    let got = status(f);
    let expected = oracle(f);
    // Mutation: cache misses return clean or only the cached path gets parity.
    with_repo(f, |repo, _| {
        let mut index = index::load(&repo.io).unwrap();
        index.remove_tree();
        assert_eq!(status_tracked::tracked_status(repo, &index), got);
    });
    assert_eq!(
        (&got.staged, &got.modified, &got.conflicted),
        (&count(expected.0), &count(expected.1), &count(expected.2)),
        "{got:?}"
    );
    assert_eq!(got.untracked, Field::PENDING);
    got
}

// Mutations: reject mode 120000, follow the target, ignore type changes, or
// apply filemode/text conversion to a symlink instead of hashing its bytes.
#[test]
fn tracked_symlinks_match_git_porcelain() {
    for case in [
        "unchanged",
        "retargeted",
        "retargeted-longer",
        "deleted",
        "file",
        "directory",
        "dangling",
        "outside",
        "file-to-link",
    ] {
        let f = init();
        let outside = Fixture::new();
        outside.write("canary", b"secret: must never be read");
        let target = match case {
            "dangling" => PathBuf::from("missing"),
            "outside" => outside.0.join("canary"),
            _ => PathBuf::from("target"),
        };
        f.write("target", b"ordinary file contents");
        if case == "file-to-link" {
            f.write("link", b"target");
        } else {
            symlink(&target, f.0.join("link")).unwrap();
        }
        commit(&f);
        // Conversions affect regular files, never a tracked symlink blob.
        f.write(".git/info/attributes", b"link text eol=crlf\n");
        match case {
            "retargeted" => {
                fs::remove_file(f.0.join("link")).unwrap();
                symlink("other!", f.0.join("link")).unwrap(); // same target length
            }
            "retargeted-longer" => {
                fs::remove_file(f.0.join("link")).unwrap();
                symlink("a-much-longer-target", f.0.join("link")).unwrap();
            }
            "deleted" => fs::remove_file(f.0.join("link")).unwrap(),
            "file" => {
                fs::remove_file(f.0.join("link")).unwrap();
                f.write("link", b"target"); // same blob, different type
            }
            "directory" => {
                fs::remove_file(f.0.join("link")).unwrap();
                fs::create_dir(f.0.join("link")).unwrap();
            }
            "file-to-link" => {
                fs::remove_file(f.0.join("link")).unwrap();
                symlink("target", f.0.join("link")).unwrap();
            }
            _ => {}
        }
        let expected = u32::from(matches!(
            case,
            "retargeted" | "retargeted-longer" | "deleted" | "file" | "directory" | "file-to-link"
        ));
        let index_bytes = fs::read(f.0.join(".git/index")).unwrap();
        let got = parity(&f);
        assert_eq!(got.modified, count(expected), "{case}");
        assert!(!got.filtered, "symlinks bypass text conversion: {case}");
        // Force stat-mismatch fallback even on coarse Linux
        // timestamps; a fresh index can otherwise take the cheap stat path.
        if matches!(
            case,
            "unchanged" | "dangling" | "outside" | "retargeted" | "retargeted-longer"
        ) {
            with_repo(&f, |repo, m| {
                let mut idx = index::load(&repo.io).unwrap();
                idx.entries_mut()
                    .iter_mut()
                    .find(|e| e.mode == gix_index::entry::Mode::SYMLINK)
                    .unwrap()
                    .stat
                    .size = 0;
                let before = m.borrow().counts[Phase::Content as usize];
                assert_eq!(
                    status_tracked::tracked_status(repo, &idx).modified,
                    count(expected)
                );
                assert_eq!(
                    m.borrow().counts[Phase::Content as usize].readlink,
                    before.readlink + 1
                );
            });
        }
        assert_eq!(fs::read(f.0.join(".git/index")).unwrap(), index_bytes);
    }
}

// Mutations: ignore core.symlinks=false, compare executable bits, or skip
// raw hashing for an ordinary target-containing file without conversion.
#[test]
fn tracked_symlinks_false_hashes_plain_file_contents() {
    let f = init();
    symlink("target", f.0.join("link")).unwrap();
    commit(&f);
    git(&f, &["config", "core.symlinks", "false"]);
    fs::remove_file(f.0.join("link")).unwrap();
    f.write("link", b"target");
    fs::set_permissions(f.0.join("link"), fs::Permissions::from_mode(0o755)).unwrap();
    assert_eq!(parity(&f).modified, count(0));
    f.write("link", b"other!");
    assert_eq!(parity(&f).modified, count(1));
    fs::remove_file(f.0.join("link")).unwrap();
    assert_eq!(parity(&f).modified, count(1));
}

// Mutation: gate conversion on index mode instead of the observed file kind.
// The CRLF file really differs from the blob. Git converts it to clean; our
// deliberate size/mtime approximation reports modified + filtered, just as
// for an ordinary indexed file. Executable bits remain irrelevant.
#[test]
fn tracked_symlinks_false_uses_file_conversion_policy() {
    for config_conversion in [false, true] {
        let f = init();
        symlink("a\nb", f.0.join("link")).unwrap();
        commit(&f);
        git(&f, &["config", "core.symlinks", "false"]);
        if config_conversion {
            git(&f, &["config", "core.autocrlf", "true"]);
        } else {
            f.write(".git/info/attributes", b"link text eol=crlf\n");
        }
        fs::remove_file(f.0.join("link")).unwrap();
        f.write("link", b"a\r\nb");
        fs::set_permissions(f.0.join("link"), fs::Permissions::from_mode(0o755)).unwrap();
        let blob = git(&f, &["rev-parse", "HEAD:link"]);
        let blob = std::str::from_utf8(&blob).unwrap().trim();
        // Clear stale pre-checkout stat data so Git can cache the converted
        // file's size rather than reject the old link's size mismatch first.
        git(&f, &["update-index", "--cacheinfo", "120000", blob, "link"]);
        // Refresh records the converted-clean file's size (4), not blob size (3).
        git(&f, &["update-index", "--refresh"]);
        let path = f.0.join("link");
        let touched = fs::metadata(&path).unwrap().modified().unwrap() + Duration::from_secs(2);
        fs::File::open(&path)
            .unwrap()
            .set_times(fs::FileTimes::new().set_modified(touched))
            .unwrap();
        assert_eq!(oracle(&f), (0, 0, 0));
        with_repo(&f, |repo, m| {
            let mut idx = index::load(&repo.io).unwrap();
            assert_eq!(idx.entries()[0].mode, gix_index::entry::Mode::SYMLINK);
            assert_eq!(idx.entries()[0].stat.size, 4);
            let got = status_tracked::tracked_status(repo, &idx);
            assert_eq!(got.modified, count(1));
            assert!(got.filtered);
            assert_eq!(m.borrow().budget.used(Axis::WorktreeReadBytes), 0);
            idx.entries_mut()[0].mode = gix_index::entry::Mode::FILE_EXECUTABLE;
            assert_eq!(
                status_tracked::tracked_status(repo, &idx).modified,
                got.modified
            );
        });
        assert_eq!(git(&f, &["cat-file", "blob", "HEAD:link"]), b"a\nb");
    }
}

// Mutations: reject symlinked attributes or follow their external target and
// apply its filter. Both tracked and untracked links must be ignored by Git
// and by the collector; only the tracked link's own bytes may be read.
#[test]
fn symlinked_attributes_are_ignored_like_git() {
    for tracked in [false, true] {
        for parent in ["", "d/"] {
            let f = init();
            let outside = Fixture::new();
            outside.write("attributes", b"* filter=evil\n");
            let attrs = format!("{parent}.gitattributes");
            let file = format!("{parent}file");
            f.write(&file, b"base");
            if tracked {
                symlink(outside.0.join("attributes"), f.0.join(&attrs)).unwrap();
            }
            commit(&f);
            if !tracked {
                symlink(outside.0.join("attributes"), f.0.join(&attrs)).unwrap();
            }
            assert_eq!(parity(&f).modified, count(0));
            f.write(&file, b"different content");
            let got = parity(&f);
            assert_eq!(got.modified, count(1));
            assert!(!got.filtered);
            with_repo(&f, |repo, m| {
                assert_eq!(status_tracked::load_status(repo), got);
                assert_eq!(m.borrow().budget.used(Axis::AttributeFiles), 0);
                assert_eq!(m.borrow().budget.used(Axis::AttributeBytes), 0);
            });
        }
    }
}

// Mutation: ignore all non-regular attributes instead of symlinks alone.
#[test]
fn attributes_directory_remains_pending() {
    let f = init();
    f.write("file", b"base");
    commit(&f);
    fs::create_dir(f.0.join(".gitattributes")).unwrap();
    assert_eq!(status(&f).modified, Field::PENDING);
}

fn symlink_corpus() -> Fixture {
    let f = init();
    fs::create_dir(f.0.join("d")).unwrap();
    for i in 0..1000 {
        symlink("../../outside-dangling", f.0.join(format!("d/link{i:04}"))).unwrap();
    }
    commit(&f);
    f
}

// Mutations: accumulate per-link scratch, bypass readlink, or add target opens.
// One request/meter handles every link, with no stage-deadline flakiness.
#[test]
fn tracked_symlinks_1000_deterministic_cost() {
    let f = symlink_corpus();
    let mut results = Vec::new();
    for hash in [false, true] {
        with_repo(&f, |repo, m| {
            let mut idx = index::load(&repo.io).unwrap();
            if hash {
                for entry in idx.entries_mut() {
                    entry.stat.size = 0;
                }
            }
            idx.set_timestamp((std::time::SystemTime::now() + Duration::from_secs(60)).into());
            let before = m.borrow().counts[Phase::Content as usize];
            let ops = m.borrow().operations();
            let live = m.borrow().live_allocated();
            let got = status_tracked::tracked_status(repo, &idx);
            assert_eq!((got.staged, got.modified), (count(0), count(0)));
            let meter = m.borrow();
            let after = meter.counts[Phase::Content as usize];
            assert_eq!(
                after.readlink - before.readlink,
                if hash { 1000 } else { 0 }
            );
            results.push((
                meter.operations() - ops,
                after.open - before.open,
                after.read - before.read,
                meter.live_allocated() - live,
            ));
            eprintln!(
                "SYMLINK_1000 hash={hash} ops={} counters={after:?} live={} delta_live={}",
                meter.operations() - ops,
                meter.live_allocated(),
                meter.live_allocated() - live
            );
        });
    }
    assert_eq!(results[1].0 - results[0].0, 3000); // two lstat + readlinkat per link
    assert_eq!(
        (results[0].1, results[0].2, results[0].3),
        (results[1].1, results[1].2, results[1].3)
    );
    eprintln!("SYMLINK_OPS stat={:?} hash={:?}", results[0], results[1]);
}

#[test]
#[ignore = "release benchmark: 200 warm samples per new path"]
fn tracked_symlinks_release_observations() {
    let f = symlink_corpus();
    for case in ["stat", "readlink", "plain"] {
        if case == "plain" {
            git(&f, &["config", "core.symlinks", "false"]);
            for i in 0..1000 {
                let path = f.0.join(format!("d/link{i:04}"));
                fs::remove_file(&path).unwrap();
                fs::write(path, b"../../outside-dangling").unwrap();
            }
        }
        with_repo(&f, |repo, m| {
            let mut idx = index::load(&repo.io).unwrap();
            if case != "stat" {
                for e in idx.entries_mut() {
                    e.stat.size = 0;
                }
            }
            idx.set_timestamp((std::time::SystemTime::now() + Duration::from_secs(60)).into());
            let mut samples = Vec::new();
            let mut first = 0;
            for run in 0..201 {
                *m.borrow_mut() = meter();
                let start = Instant::now();
                let got = status_tracked::tracked_status(repo, &idx);
                let ns = start.elapsed().as_nanos();
                assert_eq!(got.modified, count(0));
                if run == 0 {
                    first = ns;
                } else {
                    samples.push(ns);
                }
            }
            eprintln!("SYMLINK_SAMPLES case={case} ns={samples:?}");
            samples.sort_unstable();
            let mean = samples.iter().sum::<u128>() as f64 / 200.;
            let variance = samples
                .iter()
                .map(|n| (*n as f64 - mean).powi(2))
                .sum::<f64>()
                / 200.;
            eprintln!(
                "SYMLINK_BENCH case={case} n=200 first_ns={first} p50_ns={} p95_ns={} variance_ns2={variance} load={:?}",
                samples[99],
                samples[189],
                load_average()
            );
        });
    }
}

// Mutations: invert OID/mode/ITA comparison, remove sorting or HEAD deletions.
#[test]
fn staged_sorted_comparison_counts_distinct_paths() {
    let f = init();
    assert_eq!(parity(&f).staged, count(0));
    for name in ["del", "mode", "oid", "z", "a/child", "a.c"] {
        f.write(name, name);
    }
    assert_eq!(parity(&f).staged, count(0));
    git(&f, &["add", "."]);
    assert_eq!(parity(&f).staged, count(6));
    commit(&f);
    assert_eq!(parity(&f).staged, count(0));
    git(&f, &["rm", "-q", "del"]);
    f.write("oid", b"changed");
    f.write("new", b"new");
    fs::set_permissions(f.0.join("mode"), fs::Permissions::from_mode(0o755)).unwrap();
    git(&f, &["add", "."]);
    f.write("intent", b"intent");
    git(&f, &["add", "-N", "intent"]);
    let got = parity(&f);
    assert_eq!(got.staged, count(4));
    assert_eq!(got.modified, count(1));
    git(&f, &["rm", "-q", "z"]);
    assert_eq!(parity(&f).staged, count(5));
    with_repo(&f, |repo, m| {
        let index = index::load(&repo.io).unwrap();
        let remaining = Axis::IndexEntries.limit() - m.borrow().budget.used(Axis::IndexEntries);
        m.borrow_mut()
            .charge_axis(Axis::IndexEntries, remaining)
            .unwrap();
        assert_eq!(
            status_tracked::tracked_status(repo, &index).staged,
            Field::PENDING
        );
    });
}

// Mutations: stat skipped entries, count gitlink OID changes, traverse submodule.
#[test]
fn modified_comparison_excludes_skip_worktree_and_gitlinks() {
    let f = init();
    f.write("skip", b"original");
    f.write("gone", b"original");
    commit(&f);
    let oid = String::from_utf8(git(&f, &["rev-parse", "HEAD"])).unwrap();
    git(
        &f,
        &[
            "update-index",
            "--add",
            "--cacheinfo",
            &format!("160000,{},sub", oid.trim()),
        ],
    );
    git(&f, &["commit", "-qm", "gitlink"]);
    git(&f, &["update-index", "--skip-worktree", "skip", "gone"]);
    f.write("skip", b"changed");
    fs::remove_file(f.0.join("gone")).unwrap();
    git(
        &f,
        &[
            "update-index",
            "--cacheinfo",
            "160000,1111111111111111111111111111111111111111,sub",
        ],
    );
    let outside = Fixture::new();
    outside.write("canary", b"secret");
    symlink(&outside.0, f.0.join("sub")).unwrap();
    with_repo(&f, |repo, m| {
        let idx = index::load(&repo.io).unwrap();
        let got = status_tracked::tracked_status(repo, &idx);
        assert_eq!((got.staged, got.modified), (count(0), count(0)));
        assert_eq!(m.borrow().budget.used(Axis::WorktreeReadBytes), 0);
        assert_eq!(m.borrow().budget.used(Axis::Directories), 0);
        assert_eq!(oracle(&f), (0, 0, 0));
    });
    git(
        &f,
        &[
            "update-index",
            "--cacheinfo",
            "100644,1111111111111111111111111111111111111111,skip",
        ],
    );
    git(&f, &["update-index", "--skip-worktree", "skip"]);
    assert_eq!(parity(&f).staged, count(1));
}

// Mutations: count gitlink additions/deletions (both merge-loop positions),
// or ignore every gitlink type change instead of only gitlink/absent pairs.
#[test]
fn gitlink_transitions_match_ignore_submodules_all() {
    for path in ["a", "z"] {
        for (old, new, expected) in [
            (None, Some("160000"), (0, 0, 0)),
            (Some("160000"), None, (0, 0, 0)),
            (Some("160000"), Some("100644"), (1, 1, 0)),
            (Some("100644"), Some("160000"), (1, 0, 0)),
        ] {
            let f = init();
            f.write("m", b"ordinary file\n");
            commit(&f);
            let commit_id = String::from_utf8(git(&f, &["rev-parse", "HEAD"])).unwrap();
            let blob_id = String::from_utf8(git(&f, &["rev-parse", "HEAD:m"])).unwrap();
            let set = |mode: &str| {
                let id = if mode == "160000" {
                    &commit_id
                } else {
                    &blob_id
                };
                git(
                    &f,
                    &[
                        "update-index",
                        "--add",
                        "--cacheinfo",
                        &format!("{mode},{},{path}", id.trim()),
                    ],
                );
            };
            if let Some(mode) = old {
                if mode == "100644" {
                    f.write(path, b"ordinary file\n");
                }
                set(mode);
                git(&f, &["commit", "-qm", "old entry"]);
            }
            if let Some(mode) = new {
                set(mode);
            } else {
                git(&f, &["update-index", "--force-remove", path]);
            }
            assert_eq!(oracle(&f), expected, "{path}: {old:?} -> {new:?}");
            let got = parity(&f);
            assert_eq!(
                (got.staged, got.modified, got.conflicted),
                (count(expected.0), count(expected.1), count(expected.2))
            );
        }
    }
}

// Mutation: stage != 0 entries counted separately or compared as staged/modified.
#[test]
fn conflicts_count_paths_once() {
    let f = init();
    f.write("conflict", b"base");
    commit(&f);
    let oid = String::from_utf8(git(&f, &["rev-parse", "HEAD:conflict"])).unwrap();
    let records = format!(
        "0 {}\tconflict\n100755 {} 1\tconflict\n100644 {} 2\tconflict\n100644 {} 3\tconflict\n",
        "0".repeat(40),
        oid.trim(),
        oid.trim(),
        oid.trim()
    );
    command(
        &f,
        &["update-index", "--index-info"],
        Some(records.as_bytes()),
    );
    let got = parity(&f);
    assert_eq!(got.conflicted, count(1));
    assert_eq!(got.staged, count(0));
    assert_eq!(got.modified, count(0));
}

// Mutation: link ignored, shared path fallback or empty-index success.
#[test]
fn split_index_is_safely_resolved_or_partial() {
    let f = init();
    f.write("a", b"value");
    commit(&f);
    git(&f, &["update-index", "--split-index"]);
    let shared = fs::read_dir(f.0.join(".git"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| {
            p.file_name()
                .unwrap()
                .as_bytes()
                .starts_with(b"sharedindex.")
        })
        .unwrap();
    for variant in 0..5 {
        match variant {
            1 => {
                fs::write(&shared, b"corrupt").unwrap();
            }
            2 => {
                fs::File::create(&shared)
                    .unwrap()
                    .set_len(4_194_305)
                    .unwrap();
            }
            3 => {
                fs::write(&shared, fs::read(f.0.join(".git/index")).unwrap()).unwrap();
            }
            4 => {
                fs::remove_file(&shared).unwrap();
            }
            _ => {}
        }
        with_repo(&f, |repo, m| {
            assert!(matches!(index::load(&repo.io), Err(E::Io(libc::ENOTSUP))));
            let before = m.borrow().counts[Phase::Content as usize];
            assert_eq!(status_tracked::load_status(repo), StatusCounts::default());
            let after = m.borrow().counts[Phase::Content as usize];
            // Exactly the ordinary index is opened, never sharedindex or objects.
            assert_eq!(
                after.open - before.open,
                if cfg!(target_os = "macos") { 2 } else { 1 }
            );
        });
    }
}

// Mutations: conversion bypass/content hash, omit nested or info attributes.
#[test]
fn filtered_paths_never_stream_content() {
    for attribute in [
        "filter=evil",
        "text",
        "eol=crlf",
        "ident",
        "working-tree-encoding=UTF-16",
    ] {
        let f = init();
        f.write("d/file", b"base");
        commit(&f);
        f.write("d/.gitattributes", format!("file {attribute}\n"));
        f.write("d/file", b"different content");
        with_repo(&f, |repo, m| {
            let got = status_tracked::load_status(repo);
            assert_eq!(got.modified, count(1));
            assert!(got.filtered, "{attribute}: {got:?}");
            assert_eq!(m.borrow().budget.used(Axis::WorktreeReadBytes), 0);
        });
    }
    let f = init();
    f.write("d/file", b"base");
    commit(&f);
    f.write(".git/info/attributes", b"d/file filter=evil\n");
    f.write("d/file", b"different");
    with_repo(&f, |repo, m| {
        let got = status_tracked::load_status(repo);
        assert!(got.filtered);
        assert_eq!(m.borrow().budget.used(Axis::WorktreeReadBytes), 0);
    });
}

// Mutation: index refresh/write or timestamp epoch; byte hash and mtime must stay.
#[test]
fn status_does_not_write_index() {
    let f = init();
    f.write("a", b"base");
    commit(&f);
    f.write("a", b"dirty");
    let path = f.0.join(".git/index");
    let before = fs::read(&path).unwrap();
    let time = fs::metadata(&path).unwrap().modified().unwrap();
    for _ in 0..3 {
        assert_eq!(parity(&f).modified, count(1));
    }
    assert_eq!(before, fs::read(&path).unwrap());
    assert_eq!(time, fs::metadata(&path).unwrap().modified().unwrap());
    with_repo(&f, |repo, _| {
        let idx = index::load(&repo.io).unwrap();
        assert_eq!(idx.timestamp(), time.into());
    });
    assert!(!f.0.join(".git/index.lock").exists());
}

// Mutation: accept sub + sub/x even when sub-foo sorts between them.
#[test]
fn hostile_gitlink_descendants_are_rejected_before_worktree_io() {
    let f = init();
    f.write("sub/x", b"data");
    f.write("sub-foo", b"data");
    commit(&f);
    with_repo(&f, |repo, m| {
        let mut idx = index::load(&repo.io).unwrap();
        let mut entry = idx.entries()[0].clone();
        entry.mode = gix_index::entry::Mode::COMMIT;
        idx.dangerously_push_entry(
            entry.stat,
            entry.id,
            entry.flags,
            entry.mode,
            b"sub".as_slice().into(),
        );
        idx.sort_entries();
        let before = m.borrow().counts;
        assert_eq!(
            status_tracked::tracked_status(repo, &idx),
            StatusCounts::default()
        );
        assert_eq!(before, m.borrow().counts);
        assert_eq!(
            index::validate(&idx, &mut m.borrow_mut()),
            Err(E::Io(libc::EINVAL))
        );
    });
}

// Mutations: continue after cap, reset one axis, publish exact modified on error.
#[test]
fn independent_status_caps_stop_all_new_io() {
    let f = init();
    f.write("d/file", b"old");
    commit(&f);
    f.write("d/file", b"new content");
    f.write("d/.gitattributes", b"unrelated text\n");
    let mut axes = vec![
        Axis::IndexBytes,
        Axis::IndexEntries,
        Axis::DecompressedBytes,
        Axis::Directories,
        Axis::Stats,
        Axis::WorktreeReadBytes,
        Axis::AttributeFiles,
        Axis::AttributeBytes,
        Axis::AttributePatterns,
    ];
    if cfg!(target_os = "macos") {
        axes.push(Axis::WorktreeEntries);
    }
    for axis in axes {
        with_repo(&f, |repo, m| {
            let mut idx = index::load(&repo.io).unwrap();
            // These caps exercise actual HEAD expansion, not a cache-tree hit.
            idx.remove_tree();
            let used = m.borrow().budget.used(axis);
            m.borrow_mut()
                .charge_axis(axis, axis.limit() - used)
                .unwrap();
            let got = status_tracked::tracked_status(repo, &idx);
            assert_eq!(got.conflicted, count(0), "{axis:?}");
            if matches!(
                axis,
                Axis::IndexBytes | Axis::IndexEntries | Axis::DecompressedBytes | Axis::Stats
            ) {
                assert_eq!(got.staged, Field::PENDING, "{axis:?}: {got:?}");
            } else {
                assert_eq!(got.staged, count(0), "{axis:?}: {got:?}");
            }
            assert_eq!(got.modified, Field::PENDING, "{axis:?}: {got:?}");
            let before = m.borrow().counts;
            assert_eq!(
                repo.io.worktree_metadata(b"d/file").map(|_| ()),
                Err(E::Limit),
                "{axis:?}"
            );
            assert_eq!(before, m.borrow().counts, "I/O after {axis:?}");
        });
    }
    with_repo(&f, |repo, m| {
        let idx = index::load(&repo.io).unwrap();
        let live = m.borrow().live_allocated();
        m.borrow_mut().allocation_limit = live;
        let got = status_tracked::tracked_status(repo, &idx);
        assert_eq!(got.staged, Field::PENDING);
        assert_eq!(got.modified, Field::PENDING);
    });
}

// Mutations: root-relative nested patterns, wrong info precedence, stream filters.
#[test]
fn attributes_obey_directory_scope_and_info_precedence() {
    let f = init();
    f.write("a/file", b"base");
    f.write("b/file", b"base");
    commit(&f);
    f.write("a/.gitattributes", b"/file filter=evil\n");
    f.write("a/file", b"changed");
    f.write("b/file", b"changed");
    with_repo(&f, |repo, m| {
        let got = status_tracked::load_status(repo);
        assert!(got.filtered);
        assert_eq!(got.modified, count(2));
        assert_eq!(m.borrow().budget.used(Axis::WorktreeReadBytes), 7);
    });
    f.write(".git/info/attributes", b"a/file -filter\n");
    with_repo(&f, |repo, m| {
        let got = status_tracked::load_status(repo);
        assert!(!got.filtered);
        assert_eq!(got.modified, count(2));
        assert_eq!(m.borrow().budget.used(Axis::WorktreeReadBytes), 14);
    });
}

// Mutations: use single-entry stat/hash scans, retain per-item scratch forever.
#[test]
fn thousands_of_tracked_hashes_share_one_scan_and_meter() {
    let f = init();
    for i in 0..1000 {
        f.write(&format!("a/d{i:04}/nested/file"), b"old");
    }
    commit(&f);
    for i in 0..1000 {
        f.write(&format!("a/d{i:04}/nested/file"), b"changed");
    }
    with_repo(&f, |repo, m| {
        let got = status_tracked::load_status(repo);
        assert_eq!(got.staged, count(0));
        assert_eq!(got.modified, count(1000));
        assert!(m.borrow().budget.used(Axis::Directories) <= 2002);
        assert_eq!(m.borrow().budget.used(Axis::WorktreeReadBytes), 7000);
        assert!(m.borrow().live_allocated() < 3_000_000);
        eprintln!(
            "D1A_THOUSAND axes={:?} counts={:?} live={}",
            m.borrow().budget,
            m.borrow().counts,
            m.borrow().live_allocated()
        );
    });
}

// Mutations: follow an ancestor symlink, unsupported/corrupt inputs become clean.
#[test]
fn unsupported_and_changed_paths_preserve_independent_counts() {
    let f = init();
    f.write("d/file", b"base");
    commit(&f);
    fs::rename(f.0.join("d"), f.0.join("other")).unwrap();
    symlink("other", f.0.join("d")).unwrap();
    assert_eq!(parity(&f).modified, count(1));
    with_repo(&f, |repo, _| {
        let mut idx = index::load(&repo.io).unwrap();
        idx.entries_mut()[0].mode = gix_index::entry::Mode::DIR;
        let got = status_tracked::tracked_status(repo, &idx);
        assert_eq!(got.staged, Field::PENDING);
        assert_eq!(got.modified, Field::PENDING);
        assert_eq!(got.conflicted, count(0));
    });
    f.write(".git/index", b"invalid");
    assert_eq!(status(&f), StatusCounts::default());
}

fn report(name: &str, samples: &mut [u128], first: u128) {
    eprintln!("D1A_SAMPLES {{\"case\":\"{name}\",\"samples_ns\":{samples:?}}}");
    samples.sort_unstable();
    let mean = samples.iter().sum::<u128>() as f64 / samples.len() as f64;
    let variance = samples
        .iter()
        .map(|n| (*n as f64 - mean).powi(2))
        .sum::<f64>()
        / samples.len() as f64;
    eprintln!(
        "D1A_OBSERVE {{\"case\":\"{name}\",\"rounds\":{},\"first_ns\":{first},\"p50_ns\":{},\"p95_ns\":{},\"variance_ns2\":{variance}}}",
        samples.len(),
        samples[samples.len() / 2],
        samples[samples.len() * 95 / 100]
    );
}

fn corpus_directories() -> Vec<String> {
    (0..190)
        .map(|i| format!("{}{:03}", ["b", "ab", "src", "tests", "crates"][i % 5], i))
        .collect()
}
fn corpus_19000() -> Fixture {
    let f = init();
    for dir in corpus_directories() {
        for leaf in 0..100 {
            let path = format!("{dir}/f{leaf:03}");
            f.write(&path, format!("distinct blob for {path}\n"));
        }
    }
    commit(&f);
    refresh_corpus(&f);
    let cache = tree_cache(&f);
    let ids: std::collections::HashSet<_> = cache.children.iter().map(|c| c.id).collect();
    assert_eq!(
        ids.len(),
        190,
        "cached_id reuse must not hide full-walk costs"
    );
    f
}
fn refresh_corpus(f: &Fixture) {
    // Separate index and worktree timestamps even on coarse Linux filesystems.
    std::thread::sleep(Duration::from_millis(1100));
    git(f, &["update-index", "--really-refresh"]);
    git(f, &["write-tree"]);
}
fn change_corpus(f: &Fixture, case: usize) {
    match case {
        0 => {}
        1 | 2 => {
            for dir in corpus_directories()
                .iter()
                .take(if case == 1 { 1 } else { 190 })
            {
                f.write(&format!("{dir}/f000"), format!("staged {case} {dir}\n"));
            }
            git(f, &["add", "."]);
            refresh_corpus(f);
        }
        3 => {
            // Compare the clean baseline with its optional TREE removed.
            // This reset is confined to the test's newly created repository.
            git(f, &["reset", "--hard", "HEAD"]);
            refresh_corpus(f);
            replace_extensions(f, &[]);
        }
        _ => unreachable!(),
    }
}
const CORPUS_CASES: [(&str, u32, usize, usize); 4] = [
    ("clean", 0, 0, 191),
    ("one-staged", 1, 2, 191),
    ("190-subtrees", 190, 191, 191),
    ("no-TREE", 0, 191, 0),
];

// Mutations: discard Git's mixed-length cache; expand clean subtrees; omit the
// consistency memo; reuse one repeated subtree OID throughout the corpus.
#[test]
fn git_written_19000_cache_tree_operation_counts() {
    let f = corpus_19000();
    for (case, (name, staged, reads, calls)) in CORPUS_CASES.into_iter().enumerate() {
        change_corpus(&f, case);
        assert_eq!(oracle(&f), (staged, 0, 0));
        let mut previous = None;
        // Independent requests must reproduce every deterministic counter.
        for _ in 0..2 {
            with_repo(&f, |repo, m| {
                let before = m.borrow().operations();
                status_tracked::observations::take();
                let got = status_tracked::load_status(repo);
                assert_eq!(
                    (got.staged, got.modified, got.conflicted),
                    (count(staged), count(0), count(0))
                );
                let counts = status_tracked::observations::take();
                assert_eq!(
                    counts,
                    status_tracked::observations::Counts {
                        tree_reads: reads,
                        finds: reads + 1,
                        consistency_calls: calls,
                    }
                );
                let m = m.borrow();
                assert_eq!(m.budget.used(Axis::WorktreeReadBytes), 0);
                let observed = (
                    counts,
                    m.operations() - before,
                    m.budget.used(Axis::IndexEntries),
                );
                if let Some(previous) = previous {
                    assert_eq!(observed, previous);
                }
                previous = Some(observed);
                eprintln!(
                    "D1A_DETERMINISTIC case={name} counts={counts:?} ops={} entries={} live={} peak_fds={}",
                    observed.1,
                    observed.2,
                    m.live_allocated(),
                    m.peak_fds
                );
            });
        }
    }
}

fn load_average() -> [f64; 3] {
    let mut load = [0.; 3];
    // SAFETY: getloadavg writes at most three doubles into this live array.
    assert_eq!(unsafe { libc::getloadavg(load.as_mut_ptr(), 3) }, 3);
    load
}

#[test]
#[ignore = "release observations: requires all load averages < 4; 200 warm samples"]
fn tracked_status_release_observations() {
    let load = load_average();
    eprintln!("D1A_LOAD {load:?}");
    if load.iter().any(|n| *n >= 4.) {
        eprintln!("BLOCKED: wall-clock observations require load average < 4");
        return;
    }
    let f = corpus_19000();
    let names: Vec<_> = (0..100).map(|i| format!("f{i:03}").into_bytes()).collect();
    let leaves: Vec<_> = names.iter().map(Vec::as_slice).collect();
    for (case, (name, staged, _, _)) in CORPUS_CASES.into_iter().enumerate() {
        change_corpus(&f, case);
        with_repo(&f, |repo, slot| {
            let mut tracked = Vec::new();
            let mut stat = Vec::new();
            let mut first = [0; 2];
            for run in 0..201 {
                let load = load_average();
                if load.iter().any(|n| *n >= 4.) {
                    // Do not report a percentile from a partially loaded run.
                    eprintln!("BLOCKED: case={name} run={run} load={load:?}");
                    return;
                }
                for kind in if run % 2 == 0 { [0, 1] } else { [1, 0] } {
                    *slot.borrow_mut() = meter();
                    let start = Instant::now();
                    if kind == 0 {
                        let got = status_tracked::load_status(repo);
                        assert_eq!((got.staged, got.modified), (count(staged), count(0)));
                    } else {
                        repo.io
                            .with_worktree_stats(|| {
                                for dir in corpus_directories() {
                                    repo.io.worktree_directory_stats(
                                        dir.as_bytes(),
                                        &leaves,
                                        Default::default(),
                                        |_, stat| {
                                            stat?;
                                            Ok(())
                                        },
                                    )?;
                                }
                                Ok(())
                            })
                            .unwrap();
                    }
                    let ns = start.elapsed().as_nanos();
                    if run == 0 {
                        first[kind] = ns;
                    } else if kind == 0 {
                        tracked.push(ns);
                    } else {
                        stat.push(ns);
                    }
                }
            }
            let load = load_average();
            eprintln!("D1A_LOAD case={name} end={load:?}");
            if load.iter().any(|n| *n >= 4.) {
                eprintln!("BLOCKED: load crossed the threshold during the final sample");
                return;
            }
            report(name, &mut tracked, first[0]);
            report(&format!("{name}-c4-stat"), &mut stat, first[1]);
        });
    }
}

// Mutation: reject legitimate D/F conflicts along with hostile gitlink children.
#[test]
fn directory_file_conflicts_remain_distinct_paths() {
    let f = init();
    f.write("a/child", b"base");
    commit(&f);
    let oid = String::from_utf8(git(&f, &["rev-parse", "HEAD:a/child"])).unwrap();
    let records = format!(
        "0 {}\ta/child\n100644 {} 2\ta\n100644 {} 3\ta/child\n",
        "0".repeat(40),
        oid.trim(),
        oid.trim()
    );
    command(
        &f,
        &["update-index", "--index-info"],
        Some(records.as_bytes()),
    );
    assert_eq!(parity(&f).conflicted, count(2));
}

// Mutation: bypass expansion charges when a decoded HEAD tree is reused.
#[test]
fn cached_tree_expansion_still_consumes_each_entry() {
    let f = init();
    f.write("a/file", b"same");
    f.write("b/file", b"same");
    commit(&f);
    with_repo(&f, |repo, m| {
        let mut idx = index::load(&repo.io).unwrap();
        idx.remove_tree();
        let used = m.borrow().budget.used(Axis::IndexEntries);
        m.borrow_mut()
            .charge_axis(Axis::IndexEntries, Axis::IndexEntries.limit() - used - 3)
            .unwrap();
        assert_eq!(
            status_tracked::tracked_status(repo, &idx).staged,
            Field::PENDING
        );
        assert_eq!(
            m.borrow().budget.used(Axis::IndexEntries),
            Axis::IndexEntries.limit()
        );
    });
}

// Mutation: stat the index pathname after reading rather than use the read fd.
#[test]
fn index_timestamp_is_bound_to_the_read_descriptor() {
    let f = init();
    f.write("a", b"base");
    commit(&f);
    let path = f.0.join(".git/index");
    let expected = fs::metadata(&path).unwrap().modified().unwrap();
    let replacement = fs::read(&path).unwrap();
    with_repo(&f, |repo, m| {
        let mut replaced = false;
        m.borrow_mut().hook = Some(Box::new(move |event| {
            if event == "before_read" && !replaced {
                replaced = true;
                fs::rename(&path, path.with_extension("old")).unwrap();
                fs::write(&path, &replacement).unwrap();
                let times = fs::FileTimes::new()
                    .set_modified(std::time::UNIX_EPOCH + Duration::from_secs(100));
                fs::File::open(&path).unwrap().set_times(times).unwrap();
            }
        }));
        let idx = index::load(&repo.io).unwrap();
        assert_eq!(idx.timestamp(), expected.into());
        assert_eq!(idx.entries().len(), 1);
    });
}

// Mutation: skip index checksum validation even though entry bytes still decode.
#[test]
fn corrupt_index_checksum_never_becomes_clean() {
    let f = init();
    f.write("file", b"base");
    commit(&f);
    let mut bytes = fs::read(f.0.join(".git/index")).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    f.write(".git/index", bytes);
    with_repo(&f, |repo, _| {
        assert!(matches!(index::load(&repo.io), Err(E::Io(libc::EINVAL))));
    });
    assert_eq!(status(&f), StatusCounts::default());
}

// Mutation: omit the file's IndexBytes charge and rely only on decoded paths.
#[test]
fn index_bytes_are_charged_before_any_payload_read() {
    let f = init();
    f.write("file", b"base");
    commit(&f);
    let bytes = fs::metadata(f.0.join(".git/index")).unwrap().len();
    with_repo(&f, |repo, m| {
        m.borrow_mut()
            .charge_axis(Axis::IndexBytes, Axis::IndexBytes.limit() - bytes + 1)
            .unwrap();
        let before = m.borrow().counts[Phase::Content as usize].read;
        assert!(matches!(index::load(&repo.io), Err(E::Limit)));
        assert_eq!(m.borrow().counts[Phase::Content as usize].read, before);
        let stopped = m.borrow().counts;
        assert_eq!(
            repo.io.worktree_metadata(b"file").map(|_| ()),
            Err(E::Limit)
        );
        assert_eq!(m.borrow().counts, stopped);
    });
    with_repo(&f, |repo, m| {
        index::load(&repo.io).unwrap();
        assert_eq!(m.borrow().budget.used(Axis::IndexBytes), bytes + 4);
    });
}

// Mutation: check name collisions only within one directory batch.
#[test]
fn colliding_parent_name_policies_are_partial() {
    let f = init();
    f.write("d/file", b"base");
    commit(&f);
    git(&f, &["config", "core.ignorecase", "true"]);
    with_repo(&f, |repo, _| {
        let mut idx = index::load(&repo.io).unwrap();
        let entry = idx.entries()[0].clone();
        idx.dangerously_push_entry(
            entry.stat,
            entry.id,
            entry.flags,
            entry.mode,
            b"D/file".as_slice().into(),
        );
        idx.sort_entries();
        let got = status_tracked::tracked_status(repo, &idx);
        assert_eq!(got.staged, count(1));
        assert_eq!(got.modified, Field::PENDING);
        assert_eq!(got.conflicted, count(0));
    });
}

// Mutations: normalize a copied repo's NFC/NFD index keys on Linux; ignore
// precomposition on macOS. Directory renames are raw I/O, never normalized.
#[test]
fn precompose_tracked_names_match_git_on_each_os() {
    let f = init();
    git(&f, &["config", "core.precomposeunicode", "true"]);
    let nfc = "\u{d55c}";
    let nfd = "\u{1112}\u{1161}\u{11ab}";
    f.write(&format!("{nfc}/{nfc}"), b"base");
    commit(&f);
    fs::rename(f.0.join(nfc), f.0.join("temporary")).unwrap();
    fs::rename(f.0.join("temporary"), f.0.join(nfd)).unwrap();
    let parent = f.0.join(nfd);
    fs::rename(parent.join(nfc), parent.join("temporary")).unwrap();
    fs::rename(parent.join("temporary"), parent.join(nfd)).unwrap();
    let expected = u32::from(!cfg!(target_os = "macos"));
    assert_eq!(oracle(&f), (0, expected, 0));
    assert_eq!(parity(&f).modified, count(expected));
    f.write(&format!("{nfd}/{nfd}"), b"changed and longer");
    assert_eq!(oracle(&f), (0, 1, 0));
    assert_eq!(parity(&f).modified, count(1));

    // A Linux filesystem can hold both names. Git's copied setting must not
    // turn two distinct index paths into an ambiguous normalized collision.
    #[cfg(target_os = "linux")]
    {
        f.write(&format!("{nfc}/{nfc}"), b"another path");
        commit(&f);
        assert_eq!(oracle(&f), (0, 0, 0));
        assert_eq!(parity(&f).modified, count(0));
    }
}

// Fixtures use Git's ordinary v2/v3 index framing; only the optional extensions
// are replaced. Re-sign so the tests exercise TREE validation, not checksum.
fn extensions_offset(bytes: &[u8]) -> usize {
    let version = u32::from_be_bytes(bytes[4..8].try_into().unwrap());
    assert!((2..=3).contains(&version));
    let count = u32::from_be_bytes(bytes[8..12].try_into().unwrap());
    let mut pos = 12;
    for _ in 0..count {
        let start = pos;
        let flags = u16::from_be_bytes(bytes[pos + 60..pos + 62].try_into().unwrap());
        pos += 62 + if flags & 0x4000 != 0 { 2 } else { 0 };
        pos += bytes[pos..].iter().position(|b| *b == 0).unwrap() + 1;
        pos = start + (pos - start).next_multiple_of(8);
    }
    pos
}
fn replace_extensions(f: &Fixture, extensions: &[u8]) {
    let mut bytes = fs::read(f.0.join(".git/index")).unwrap();
    bytes.truncate(extensions_offset(&bytes));
    bytes.extend_from_slice(extensions);
    let mut hash = gix_index::hash::hasher(gix_index::hash::Kind::Sha1);
    hash.update(&bytes);
    bytes.extend_from_slice(hash.try_finalize().unwrap().as_slice());
    f.write(".git/index", bytes);
}
fn raw_tree_cache(f: &Fixture) -> Vec<u8> {
    let bytes = fs::read(f.0.join(".git/index")).unwrap();
    let mut pos = extensions_offset(&bytes);
    while pos < bytes.len() - 20 {
        let size = u32::from_be_bytes(bytes[pos + 4..pos + 8].try_into().unwrap()) as usize;
        if &bytes[pos..pos + 4] == b"TREE" {
            return bytes[pos + 8..pos + 8 + size].to_vec();
        }
        pos += 8 + size;
    }
    panic!("Git must write the fixture's TREE extension");
}
fn replace_tree_cache(f: &Fixture, payload: &[u8]) {
    let mut ext = b"TREE".to_vec();
    ext.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    ext.extend_from_slice(payload);
    replace_extensions(f, &ext);
}
// Locate fields in Git's serialized records so hostile tests mutate its bytes,
// never serialize a gix Tree (whose child order differs from Git's wire order).
struct CacheRecord {
    record: std::ops::Range<usize>,
    name: std::ops::Range<usize>,
    entries: std::ops::Range<usize>,
    id: std::ops::Range<usize>,
}
fn cache_records(bytes: &[u8]) -> Vec<CacheRecord> {
    let mut records = Vec::new();
    let mut pos = 0;
    while pos < bytes.len() {
        let start = pos;
        let end = pos + bytes[pos..].iter().position(|b| *b == 0).unwrap();
        let name = pos..end;
        pos = end + 1;
        let end = pos + bytes[pos..].iter().position(|b| *b == b' ').unwrap();
        let entries = pos..end;
        let valid = bytes[pos] != b'-';
        pos = end + 1;
        pos += bytes[pos..].iter().position(|b| *b == b'\n').unwrap() + 1;
        let id = pos..pos + if valid { 20 } else { 0 };
        pos = id.end;
        records.push(CacheRecord {
            record: start..pos,
            name,
            entries,
            id,
        });
    }
    records
}
fn cache_entry_count(bytes: &mut Vec<u8>, node: usize, count: Option<usize>) {
    let records = cache_records(bytes);
    let record = &records[node];
    if count.is_none() {
        bytes.drain(record.id.clone());
    }
    let text = count.map_or_else(|| "-1".to_owned(), |n| n.to_string());
    bytes.splice(record.entries.clone(), text.bytes());
}
fn tree_cache(f: &Fixture) -> gix_index::extension::Tree {
    with_repo(f, |repo, _| {
        index::load(&repo.io).unwrap().tree().unwrap().clone()
    })
}
fn remove_object(f: &Fixture, name: &str) {
    let id = String::from_utf8(git(f, &["rev-parse", name])).unwrap();
    let id = id.trim();
    fs::remove_file(f.0.join(format!(".git/objects/{}/{}", &id[..2], &id[2..]))).unwrap();
}

// Mutations: always expand HEAD; trust a mismatching OID; lose cache siblings
// under an invalidated parent; skip a differing subtree's entry comparison.
#[test]
fn cache_tree_hits_avoid_head_subtree_reads() {
    for invalidated in [false, true] {
        let f = init();
        f.write("a/file", b"a");
        f.write("b/file", b"b");
        f.write("c/file", b"c");
        commit(&f);
        assert_eq!(tree_cache(&f).num_entries, Some(3));
        with_repo(&f, |repo, m| {
            assert_eq!(status_tracked::load_status(repo).staged, count(0));
            // A root hit reads the commit but expands zero HEAD tree entries.
            assert_eq!(m.borrow().budget.used(Axis::IndexEntries), 3);
        });
        f.write("a/file", b"changed");
        git(&f, &["add", "a/file"]);
        if !invalidated {
            git(&f, &["write-tree"]);
        }
        assert_eq!(tree_cache(&f).num_entries.is_none(), invalidated);
        assert_eq!(parity(&f).staged, count(1));
        remove_object(&f, "HEAD:b");
        remove_object(&f, "HEAD:c");
        with_repo(&f, |repo, m| {
            let mut index = index::load(&repo.io).unwrap();
            let got = status_tracked::tracked_status(repo, &index);
            assert_eq!(got.staged, count(1));
            assert_eq!(got.modified, count(0));
            assert_eq!(m.borrow().budget.used(Axis::IndexEntries), 7); // 3 index + root 3 + a/file
            index.remove_tree();
            assert_eq!(
                status_tracked::tracked_status(repo, &index).staged,
                Field::PENDING
            );
        });
    }
}

// Mutations: validate raw TREE siblings in byte order; reject all TREE caches;
// expand a matching tree anyway. Git writes these bytes, including nested
// mixed-length names; distinct blobs prevent cached_id from hiding full walks.
#[test]
fn git_written_mixed_length_cache_tree_avoids_tree_reads() {
    let f = init();
    for parent in ["b", "ab", "src", "tests", "crates"] {
        for child in ["b", "ab", "src", "tests", "crates"] {
            let path = format!("{parent}/{child}/file");
            f.write(&path, format!("distinct {path}\n"));
        }
    }
    commit(&f);
    git(&f, &["write-tree"]);
    let raw = raw_tree_cache(&f);
    let records = cache_records(&raw);
    let git_order = [b"b".as_slice(), b"ab", b"src", b"tests", b"crates"];
    assert_eq!(
        records[1..]
            .chunks(6)
            .map(|group| &raw[group[0].name.clone()])
            .collect::<Vec<_>>(),
        git_order
    );
    for group in records[1..].chunks(6) {
        assert_eq!(
            group[1..]
                .iter()
                .map(|r| &raw[r.name.clone()])
                .collect::<Vec<_>>(),
            git_order
        );
    }
    with_repo(&f, |repo, _| {
        let idx = index::load(&repo.io).unwrap();
        let cache = idx
            .tree()
            .expect("Git-written TREE must survive pre-decode validation");
        assert_eq!(
            cache
                .children
                .iter()
                .map(|c| c.name.as_slice())
                .collect::<Vec<_>>(),
            [b"ab".as_slice(), b"b", b"crates", b"src", b"tests"]
        );
        status_tracked::observations::take();
        assert_eq!(status_tracked::tracked_status(repo, &idx).staged, count(0));
        assert_eq!(
            status_tracked::observations::take(),
            status_tracked::observations::Counts {
                tree_reads: 0,
                finds: 1,
                consistency_calls: 31,
            }
        );
    });
    f.write("b/ab/file", b"staged change\n");
    git(&f, &["add", "b/ab/file"]);
    // Both Git's invalidated ancestor cache and its rewritten cache retain
    // the unaffected sibling hits after gix's byte-order re-sort.
    for rewrite in [false, true] {
        if rewrite {
            git(&f, &["write-tree"]);
        }
        with_repo(&f, |repo, _| {
            status_tracked::observations::take();
            assert_eq!(status_tracked::load_status(repo).staged, count(1));
            assert_eq!(
                status_tracked::observations::take(),
                status_tracked::observations::Counts {
                    tree_reads: 3,
                    finds: 4,
                    consistency_calls: 31,
                }
            );
        });
        assert_eq!(parity(&f).staged, count(1));
    }
}

// Mutations: recompute consistency at every HEAD pop; stop at the first bad
// child and throw away valid siblings; accept a parent with a bad descendant.
// The 50 chain nodes each have 100 leaf siblings, plus the root: 5,051 nodes.
#[test]
fn cache_consistency_is_linear_for_deep_bad_descendant() {
    let f = init();
    let mut prefix = String::new();
    for depth in 0..50 {
        for sibling in 0..100 {
            let path = format!("{prefix}a{sibling:03}/file");
            f.write(&path, format!("{depth}/{sibling}\n"));
        }
        prefix.push_str("z/");
    }
    f.write(&format!("{prefix}file"), b"deepest leaf\n");
    commit(&f);
    git(&f, &["write-tree"]);
    let mut raw = raw_tree_cache(&f);
    let records = cache_records(&raw);
    assert_eq!(records.len(), 5_051);
    let deepest = records
        .iter()
        .rposition(|r| &raw[r.name.clone()] == b"z")
        .unwrap();
    cache_entry_count(&mut raw, deepest, Some(0));
    replace_tree_cache(&f, &raw);
    with_repo(&f, |repo, m| {
        let idx = index::load(&repo.io).unwrap();
        assert!(idx.tree().is_some());
        let ops = m.borrow().operations();
        status_tracked::observations::take();
        // The worktree scan may hit its independent directory/fd cap. This
        // test pins staged comparison and the exact memoization work only.
        assert_eq!(status_tracked::tracked_status(repo, &idx).staged, count(0));
        let got = status_tracked::observations::take();
        assert_eq!(
            got,
            status_tracked::observations::Counts {
                tree_reads: 51,
                finds: 52,
                consistency_calls: 5_051,
            }
        );
        eprintln!("D1A_DEEP {got:?} ops={}", m.borrow().operations() - ops);
    });
}

// Mutations: accept range-count mismatch, ignore descendant shape on a root
// hit, trust reordered/duplicate names after gix sorted them, skip invalid OID.
#[test]
fn inconsistent_cache_tree_falls_back_to_entry_comparison() {
    let f = init();
    f.write("a/file", b"a");
    f.write("b/file", b"b");
    commit(&f);
    let original = raw_tree_cache(&f);
    f.write("a/file", b"changed");
    git(&f, &["add", "a/file"]);
    let dirty_index = fs::read(f.0.join(".git/index")).unwrap();
    for mutation in 0..7 {
        f.write(".git/index", &dirty_index);
        let mut cache = original.clone();
        let records = cache_records(&cache);
        match mutation {
            0 => cache_entry_count(&mut cache, 0, Some(1)),
            1 => cache_entry_count(&mut cache, 1, Some(0)),
            2 => {
                let second = cache[records[2].record.clone()].to_vec();
                let first = cache[records[1].record.clone()].to_vec();
                cache.truncate(records[1].record.start);
                cache.extend_from_slice(&second);
                cache.extend_from_slice(&first);
            }
            3 => cache[records[2].name.clone()].copy_from_slice(b"a"),
            4 => {
                cache.splice(records[1].name.clone(), b"../escape".iter().copied());
            }
            5 => cache_entry_count(&mut cache, 1, None),
            _ => {
                cache[records[0].id.clone()].fill(0);
                cache[records[1].id.clone()].fill(0);
            }
        }
        replace_tree_cache(&f, &cache);
        with_repo(&f, |repo, _| {
            let idx = index::load(&repo.io).unwrap();
            if (2..=4).contains(&mutation) {
                assert!(
                    idx.tree().is_none(),
                    "raw order/names must be checked before gix sorts"
                );
            }
            assert_eq!(
                status_tracked::tracked_status(repo, &idx).staged,
                count(1),
                "mutation {mutation}"
            );
        });
    }
    // Missing and malformed optional caches are both ordinary full walks.
    for payload in [b"".as_slice(), b"malformed"] {
        f.write(".git/index", &dirty_index);
        let mut ext = b"TREE".to_vec();
        ext.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        ext.extend_from_slice(payload);
        replace_extensions(&f, &ext);
        assert_eq!(parity(&f).staged, count(1));
    }
    replace_extensions(&f, &[]);
    assert_eq!(parity(&f).staged, count(1));
}

// Mutation: treat an inconsistent child as clean, or discard valid siblings
// because another child is inconsistent. Only a must be fully expanded.
#[test]
fn inconsistent_child_keeps_valid_sibling_cache() {
    let f = init();
    f.write("a/file", b"a");
    f.write("b/file", b"b");
    commit(&f);
    let mut cache = raw_tree_cache(&f);
    cache_entry_count(&mut cache, 0, None);
    cache_entry_count(&mut cache, 1, Some(0));
    f.write("a/file", b"changed");
    git(&f, &["add", "a/file"]);
    replace_tree_cache(&f, &cache);
    remove_object(&f, "HEAD:b");
    assert_eq!(status(&f).staged, count(1));
}

// Deliberate trust policy, matching Git: a structurally plausible forged OID
// can hide the hostile index's own staged changes. It cannot hide modified
// content, conflicts or ITA flags, nor authorize any new read or execution.
#[test]
fn forged_cache_oid_has_git_trust_scope_and_flags_stay_authoritative() {
    let f = init();
    f.write("a/file", b"base");
    commit(&f);
    let cache = raw_tree_cache(&f);
    f.write("a/file", b"staged");
    git(&f, &["add", "a/file"]);
    replace_tree_cache(&f, &cache);
    assert_eq!(oracle(&f), (0, 0, 0));
    with_repo(&f, |repo, _| {
        let mut idx = index::load(&repo.io).unwrap();
        assert_eq!(status_tracked::tracked_status(repo, &idx).staged, count(0));
        idx.remove_tree();
        assert_eq!(status_tracked::tracked_status(repo, &idx).staged, count(1));
    });
    f.write("a/file", b"worktree differs too");
    assert_eq!(status(&f).modified, count(1));
    with_repo(&f, |repo, _| {
        let mut idx = index::load(&repo.io).unwrap();
        idx.entries_mut()[0]
            .flags
            .insert(gix_index::entry::Flags::INTENT_TO_ADD);
        let got = status_tracked::tracked_status(repo, &idx);
        idx.remove_tree();
        assert_eq!(got, status_tracked::tracked_status(repo, &idx));
        assert_eq!(got.staged, count(1));
    });
    with_repo(&f, |repo, _| {
        let mut idx = index::load(&repo.io).unwrap();
        idx.entries_mut()[0].flags |= gix_index::entry::Flags::from_bits_retain(2 << 12);
        let got = status_tracked::tracked_status(repo, &idx);
        assert_eq!(got.conflicted, count(1));
        idx.remove_tree();
        assert_eq!(got, status_tracked::tracked_status(repo, &idx));
    });
}

// Mutations: allow unbounded recursive decoding or undercharge TREE allocations.
#[test]
fn cache_tree_decoder_depth_and_allocations_are_bounded() {
    let f = init();
    for i in 0..200 {
        f.write(
            &format!("directory-with-a-long-name-{i:04}/nested/file"),
            b"x",
        );
    }
    commit(&f);
    let mut bytes = fs::read(f.0.join(".git/index")).unwrap();
    let mut m = meter();
    let (idx, allocations) = allocation::measure(|| index::parse(&mut bytes, &mut m).unwrap());
    assert_eq!(idx.tree().unwrap().children.len(), 200);
    assert!(allocations.peak <= m.live_allocated() as usize);
    let mut data = b"\0-1 1\n".to_vec();
    for _ in 0..1000 {
        data.extend_from_slice(b"a\0-1 1\n");
    }
    data.extend_from_slice(b"z\0-1 0\n");
    let mut ext = b"TREE".to_vec();
    ext.extend_from_slice(&(data.len() as u32).to_be_bytes());
    ext.extend_from_slice(&data);
    replace_extensions(&f, &ext);
    with_repo(&f, |repo, _| {
        let idx = index::load(&repo.io).unwrap();
        assert!(idx.tree().is_none());
        assert_eq!(status_tracked::tracked_status(repo, &idx).staged, count(0));
    });
}
