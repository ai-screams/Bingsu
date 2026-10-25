//! D1b oracle, budget, shared-scan and sparse-index acceptance fixtures.
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
    stage_b,
    status_tracked::StatusCounts,
};
use meter::{Meter, Phase};
use safe_read::{Access, DiscoveryQuery, ReadError as E, Root};
use std::{
    cell::RefCell,
    fs,
    io::Write,
    os::unix::{ffi::OsStrExt, fs::symlink},
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
            "bingsu-untracked-{}-{}",
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
    with_repo(f, |repo, _| stage_b::status(repo, &[]))
}
fn count(n: u32) -> Field {
    Field::known(FieldValue::Count {
        n,
        saturated: false,
    })
}

fn oracle(f: &Fixture) -> (u32, u32, u32, u32) {
    let raw = git(
        f,
        &[
            "-c",
            "status.renames=false",
            "status",
            "--porcelain=v2",
            "--ignore-submodules=all",
            "--untracked-files=all",
            "-z",
        ],
    );
    let mut out = (0, 0, 0, 0);
    for line in raw.split(|b| *b == 0).filter(|l| !l.is_empty()) {
        match line[0] {
            b'1' => {
                out.0 += u32::from(line[2] != b'.');
                out.1 += u32::from(line[3] != b'.');
            }
            b'?' => out.2 += 1,
            b'u' => out.3 += 1,
            _ => panic!("unexpected porcelain {line:?}"),
        }
    }
    out
}
fn parity(f: &Fixture) -> StatusCounts {
    let expected = oracle(f);
    let got = status(f);
    assert_eq!(
        (&got.staged, &got.modified, &got.untracked, &got.conflicted),
        (
            &count(expected.0),
            &count(expected.1),
            &count(expected.2),
            &count(expected.3)
        ),
        "{got:?}"
    );
    got
}

// Mutations: omit buffered patterns; wrong info/exclude base/priority; count
// collapse directories or stop at their first leaf; apply an outside config source.
#[test]
fn untracked_walker_honors_buffered_ignore_and_attributes() {
    let f = init();
    f.write(
        ".gitignore",
        b"*.log\n!important.log\nnode_modules/\n!node_modules/keep\n",
    );
    f.write(".gitattributes", b"*.txt text\n");
    f.write("tracked.txt", b"line\n");
    f.write("src/tracked", b"base");
    commit(&f);
    f.write(".git/info/exclude", b"info-only\nimportant.log\n");
    f.write("info-only", b"ignored");
    f.write("important.log", b"visible");
    f.write("drop.log", b"ignored");
    f.write("node_modules/keep", b"ignored parent wins");
    f.write("src/.gitignore", b"!nested.log\n");
    f.write("src/nested.log", b"visible");
    f.write("src/other.log", b"ignored");
    f.write("new/a", b"one");
    f.write("new/deep/b", b"two");
    fs::create_dir(f.0.join("empty")).unwrap();
    let got = parity(&f);
    assert_eq!(got.untracked, count(5));
    assert!(got.filtered);
    let outside = Fixture::new();
    outside.write("ignore", b"*\n");
    outside.write("attrs", b"* filter=canary\n");
    git(
        &f,
        &[
            "config",
            "core.excludesFile",
            outside.0.join("ignore").to_str().unwrap(),
        ],
    );
    git(
        &f,
        &[
            "config",
            "core.attributesFile",
            outside.0.join("attrs").to_str().unwrap(),
        ],
    );
    // Git's external-config policy differs deliberately; compare to baseline.
    assert_eq!(status(&f), got);
    assert!(!outside.0.join("canary").exists());
}

// Mutations: restore either directory collapse or the first-visible-entry
// return. Multiple batches, descendants and empty dirs all use Git's -uall.
#[test]
fn untracked_directories_count_every_file_like_git_uall() {
    let f = init();
    f.write("new/a", b"one");
    f.write("new/b", b"two");
    assert_eq!(parity(&f).untracked, count(2));
    for i in 0..253 {
        f.write(&format!("new/deep/f{i:04}"), b"x");
    }
    fs::create_dir(f.0.join("empty")).unwrap();
    fs::create_dir(f.0.join("new/empty")).unwrap();
    assert_eq!(parity(&f).untracked, count(255));
}

fn lower_bound(n: u32) -> Field {
    Field::known(FieldValue::Count { n, saturated: true })
}

// Mutations: remove/shift the 256-file cap, publish exact partial counts, or
// discard modified when only an index-free subtree was truncated. At exactly
// the cap, EOF is still unproven, so conservatively keep the plus marker.
#[test]
fn untracked_subtree_cap_boundary() {
    let f = init();
    for i in 0..257 {
        f.write(&format!("new/f{i:04}"), b"x");
        if i >= 254 {
            assert_eq!(oracle(&f), (0, 0, i + 1, 0));
            let got = status(&f);
            assert_eq!(
                got.untracked,
                if i == 254 {
                    count(255)
                } else {
                    lower_bound(256)
                }
            );
            assert_eq!(
                (got.staged, got.modified, got.conflicted),
                (count(0), count(0), count(0))
            );
        }
    }
}

// Mutations: renew the allowance at each nested directory, cap the repository
// globally, or apply the cap to a directory that contains index entries.
// Assertions are independent of directory enumeration order on either OS.
#[test]
fn nested_untracked_subtrees_share_caps_but_tracked_containers_do_not() {
    let f = init();
    for name in ["tracked/a", "tracked/z"] {
        f.write(name, b"base");
    }
    commit(&f);
    for i in 0..1000 {
        f.write(&format!("tracked/f{i:04}"), b"x");
    }
    assert_eq!(parity(&f).untracked, count(1000));
    for dir in ["one", "two"] {
        for i in 0..200 {
            f.write(&format!("{dir}/f{i:04}"), b"x");
        }
    }
    assert_eq!(parity(&f).untracked, count(1400));
    for dir in ["tracked/new/left", "tracked/new/right"] {
        for i in 0..200 {
            f.write(&format!("{dir}/f{i:04}"), b"x");
        }
    }
    f.write("tracked/a", b"staged change");
    git(&f, &["add", "tracked/a"]);
    f.write("tracked/z", b"worktree change");
    assert_eq!(oracle(&f), (1, 1, 1800, 0));
    let got = status(&f);
    assert_eq!(
        (got.staged, got.modified, got.untracked, got.conflicted),
        (count(1), count(1), lower_bound(1656), count(0))
    );
}

// Mutations: share one request-wide cap, stop the whole walk at the first cap,
// or keep scanning a capped directory after reaching its allowance.
#[test]
fn three_large_untracked_directories_have_independent_caps() {
    let f = init();
    f.write("tracked/file", b"base");
    commit(&f);
    f.write("tracked/file", b"modified");
    f.write("added", b"staged");
    git(&f, &["add", "added"]);
    for dir in ["one", "two", "tracked/new"] {
        for i in 0..20_000 {
            f.write(&format!("{dir}/f{i:05}"), b"x");
        }
    }
    assert_eq!(oracle(&f), (1, 1, 60_000, 0));
    with_repo(&f, |repo, slot| {
        let got = stage_b::status(repo, &[]);
        assert_eq!(
            (got.staged, got.modified, got.untracked, got.conflicted),
            (count(1), count(1), lower_bound(768), count(0))
        );
        let m = slot.borrow();
        assert_eq!(m.budget.used(Axis::Directories), 5);
        assert!(m.budget.used(Axis::WorktreeEntries) < 2000);
        eprintln!(
            "UNTRACKED_THREE dirs={} raw={} ops={} lists={}",
            m.budget.used(Axis::Directories),
            m.budget.used(Axis::WorktreeEntries),
            m.operations(),
            m.counts[Phase::Content as usize].list
        );
    });
}

// Mutations: skip held-edge validation after a local cap; turn an unknown
// global excludes input into a numeric lower bound; publish a complete B;
// let a local untracked cap make a completed modified comparison approximate.
#[test]
fn capped_subtrees_revalidate_edges_and_preserve_unknown() {
    use bingsu_core::collection::git::StageResult;
    let f = init();
    for i in 0..2000 {
        f.write(&format!("new/f{i:04}"), b"x");
    }
    assert_eq!(oracle(&f), (0, 0, 2000, 0));
    for kind in 0..3 {
        with_repo(&f, |repo, slot| {
            if kind == 2 {
                let path = f.0.clone();
                let mut changed = false;
                slot.borrow_mut().hook = Some(Box::new(move |event| {
                    if event == "before_worktree_directory_check" && !changed {
                        changed = true;
                        fs::rename(path.join("new"), path.join("moved")).unwrap();
                        fs::create_dir(path.join("new")).unwrap();
                    }
                }));
            }
            let StageResult::Partial(value) = stage_b::stage_b(repo, &[], kind != 1) else {
                panic!("cap/unknown/changed walk must be Partial");
            };
            let decl = &bingsu_core::field::BUILTIN[3];
            let field = |name| value.fields[decl.field_index(name).unwrap()].clone();
            assert_eq!(
                field("untracked"),
                if kind == 0 {
                    lower_bound(256)
                } else {
                    Field::PENDING
                }
            );
            assert_eq!(
                field("modified"),
                if kind == 2 { Field::PENDING } else { count(0) }
            );
            assert_eq!(
                field("filtered"),
                if kind == 0 {
                    Field::known(FieldValue::Bool(false))
                } else {
                    Field::PENDING
                }
            );
            assert_eq!(field("partial"), Field::known(FieldValue::Bool(true)));
            assert_eq!(field("staged"), count(0));
            assert_eq!(field("conflicted"), count(0));
        });
    }
}

// Mutations: tie filtered to untracked saturation again, publish filtered=true
// on a clean tracked tree, or clear partial merely because modified completed.
// Exercise the core formatter with the actual collector fields, including N+.
#[test]
fn capped_untracked_clean_tree_renders_without_approximate_modified() {
    use bingsu_core::{
        collection::git::StageResult, icons::IconSet, shell_values::format_git, width::WidthProfile,
    };
    let f = init();
    f.write("tracked", b"base");
    commit(&f);
    for i in 0..300 {
        f.write(&format!("new/f{i:04}"), b"x");
    }
    assert_eq!(oracle(&f), (0, 0, 300, 0));
    with_repo(&f, |repo, _| {
        let StageResult::Partial(mut value) = stage_b::stage_b(repo, &[], true) else {
            panic!("capped untracked count must remain Partial");
        };
        let decl = &bingsu_core::field::BUILTIN[3];
        // Isolate B's display from fields owned by A/C/D; keep all B fields.
        for name in ["branch", "operation", "ahead", "behind", "stash"] {
            value.fields[decl.field_index(name).unwrap()] = Field::ABSENT;
        }
        assert_eq!(
            format_git(&value, IconSet::Ascii, WidthProfile::DEFAULT).text(),
            "?256+"
        );
        assert_eq!(
            value.fields[decl.field_index("partial").unwrap()],
            Field::known(FieldValue::Bool(true))
        );
    });
}

// Mutations: publish an unvalidated saturated count, finalize through the
// stopped port (losing every lower bound), resume listing after Limit, or
// expose modified/filtered as exact after an incomplete shared walk.
#[test]
fn saturated_untracked_revalidates_edges_and_preserves_unknown() {
    use bingsu_core::collection::git::StageResult;
    let f = init();
    // Keep this directory index-bearing so the global raw budget, rather
    // than the local untracked subtree cap, interrupts the shared scan.
    f.write("new/tracked", b"base");
    commit(&f);
    for i in 0..2000 {
        f.write(&format!("new/f{i:04}"), b"x");
    }
    assert_eq!(oracle(&f), (0, 0, 2000, 0));
    for kind in 0..3 {
        with_repo(&f, |repo, slot| {
            slot.borrow_mut()
                .charge_axis(Axis::WorktreeEntries, Axis::WorktreeEntries.limit() - 1000)
                .unwrap();
            if kind == 2 {
                let path = f.0.clone();
                let mut changed = false;
                slot.borrow_mut().hook = Some(Box::new(move |event| {
                    if event == "before_worktree_directory_check" && !changed {
                        changed = true;
                        fs::rename(path.join("new"), path.join("moved")).unwrap();
                        fs::create_dir(path.join("new")).unwrap();
                    }
                }));
            }
            let StageResult::Partial(value) = stage_b::stage_b(repo, &[], kind != 1) else {
                panic!("budget/unknown/changed walk must be Partial");
            };
            let decl = &bingsu_core::field::BUILTIN[3];
            let untracked = &value.fields[decl.field_index("untracked").unwrap()];
            if kind == 0 {
                assert!(matches!(
                    untracked.value,
                    FieldValue::Count {
                        n: 1..=1000,
                        saturated: true
                    }
                ));
            } else {
                assert_eq!(*untracked, Field::PENDING);
            }
            for name in ["modified", "filtered"] {
                assert_eq!(
                    value.fields[decl.field_index(name).unwrap()],
                    Field::PENDING
                );
            }
            for name in ["staged", "conflicted"] {
                assert_eq!(value.fields[decl.field_index(name).unwrap()], count(0));
            }
            let stopped = slot.borrow().counts;
            assert_eq!(
                repo.io.worktree_listing(b"new", false).err(),
                Some(E::Limit)
            );
            assert_eq!(slot.borrow().counts, stopped);
        });
    }
}

// Mutation: skip final edge checks, reset the stop latch or perform content I/O
// during cleanup. Finalization may spend only the remaining metadata budget.
#[test]
fn limit_cleanup_only_revalidates_with_the_existing_meter() {
    let f = init();
    f.write("new/file", b"x");
    for exhaust_stats in [false, true] {
        with_repo(&f, |repo, slot| {
            let mut stopped = None;
            let result = repo.io.with_worktree_stats(|| {
                let _batch = repo.io.worktree_listing(b"new", true)?;
                repo.io.account(|m| {
                    m.charge_axis(
                        Axis::WorktreeEntries,
                        Axis::WorktreeEntries.limit() - m.budget.used(Axis::WorktreeEntries),
                    )?;
                    if exhaust_stats {
                        m.charge_axis(
                            Axis::Stats,
                            Axis::Stats.limit() - m.budget.used(Axis::Stats),
                        )?;
                    }
                    Ok(())
                })?;
                assert_eq!(repo.io.account(|m| m.raw_entry()), Err(E::Limit));
                stopped = Some(slot.borrow().counts[Phase::Content as usize]);
                Ok(())
            });
            assert_eq!(result, if exhaust_stats { Err(E::Limit) } else { Ok(()) });
            let before = stopped.unwrap();
            let after = slot.borrow().counts[Phase::Content as usize];
            assert_eq!(
                (after.open, after.list, after.read, after.read_bytes),
                (before.open, before.list, before.read, before.read_bytes)
            );
            assert_eq!(after.stat - before.stat, u64::from(!exhaust_stats));
            assert_eq!(repo.io.worktree_metadata(b"new/file").err(), Some(E::Limit));
        });
    }
}

// Mutation: recurse through a gitlink even if it contains visible entries or
// hostile patterns; follow a worktree symlink component.
#[test]
fn untracked_walker_never_opens_submodules() {
    let f = init();
    f.write("base", b"base");
    f.write("a/tracked", b"base");
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
    fs::remove_file(f.0.join(".git/info/exclude")).unwrap();
    f.write("sub/.gitignore", vec![b'x'; 65_537]);
    f.write("sub/visible", b"never opened");
    fs::remove_dir_all(f.0.join("a")).unwrap();
    symlink("sub", f.0.join("a")).unwrap();
    with_repo(&f, |repo, m| {
        let events = std::rc::Rc::new(RefCell::new(Vec::new()));
        let copy = events.clone();
        m.borrow_mut().hook = Some(Box::new(move |e| copy.borrow_mut().push(e.to_owned())));
        let got = stage_b::status(repo, &[]);
        assert_eq!(
            (got.staged, got.modified, got.untracked),
            (count(0), count(1), count(1))
        );
        assert!(
            !events
                .borrow()
                .iter()
                .any(|e| e == "openat:sub" || e == "openat:a")
        );
        assert_eq!(m.borrow().budget.used(Axis::IgnoreFiles), 0);
    });
    assert_eq!(oracle(&f), (0, 1, 1, 0));
}

fn sparse_fixture() -> Fixture {
    let f = init();
    f.write("keep/a", b"visible");
    f.write("omit/a", b"one");
    f.write("omit/b", b"two");
    commit(&f);
    git(&f, &["sparse-checkout", "init", "--cone", "--sparse-index"]);
    git(&f, &["sparse-checkout", "set", "keep"]);
    f
}

// Mutations: skip expansion, drop skip-worktree, bypass either expansion axis,
// continue I/O after a failed charge, or refresh/write the on-disk index.
#[test]
fn sparse_expansion_is_budgeted() {
    let f = sparse_fixture();
    let original = fs::read(f.0.join(".git/index")).unwrap();
    let costs = with_repo(&f, |repo, slot| {
        let idx = index::load(&repo.io).unwrap();
        assert!(idx.entries().iter().any(|e| e.mode.is_sparse()));
        assert_eq!(
            git::untracked::untracked_status(repo, &idx, &[]),
            Field::PENDING
        );
        let before = slot.borrow().budget.clone();
        let idx = index::expand_sparse(repo, idx).unwrap();
        assert_eq!(idx.entries().len(), 3);
        for e in idx.entries() {
            assert_eq!(
                e.flags.contains(gix_index::entry::Flags::SKIP_WORKTREE),
                e.path(&idx).starts_with(b"omit/")
            );
            assert!(!e.mode.is_sparse());
        }
        [Axis::IndexEntries, Axis::IndexBytes]
            .map(|axis| slot.borrow().budget.used(axis) - before.used(axis))
    });
    assert_eq!(costs, [2, 12]); // Two leaves, each full path is omit/{a,b}.
    for (axis, needed) in [Axis::IndexEntries, Axis::IndexBytes]
        .into_iter()
        .zip(costs)
    {
        for remaining in [needed - 1, needed, needed + 1] {
            with_repo(&f, |repo, slot| {
                let idx = index::load(&repo.io).unwrap();
                let used = slot.borrow().budget.used(axis);
                slot.borrow_mut()
                    .charge_axis(axis, axis.limit() - used - remaining)
                    .unwrap();
                let result = index::expand_sparse(repo, idx).map(|_| ());
                assert_eq!(
                    result,
                    if remaining < needed {
                        Err(E::Limit)
                    } else {
                        Ok(())
                    },
                    "{axis:?}/{remaining}"
                );
                if remaining < needed {
                    let before = slot.borrow().counts;
                    assert_eq!(repo.io.worktree_metadata(b"keep/a").err(), Some(E::Limit));
                    assert_eq!(slot.borrow().counts, before);
                }
            });
        }
    }
    assert_eq!(parity(&f).modified, count(0));
    assert_eq!(fs::read(f.0.join(".git/index")).unwrap(), original);
}

// Mutation: omit an individual precharge, return exact zero on failure or
// allow the port to resume reads after the first Limit.
#[test]
fn untracked_limits_are_charged_before_io() {
    let f = init();
    f.write(".gitignore", b"*.log\n");
    f.write(".gitattributes", b"*.txt text\n");
    f.write("dir/file", b"visible");
    let axes = [
        Axis::WorktreeEntries,
        Axis::Directories,
        Axis::Stats,
        Axis::IgnoreFiles,
        Axis::IgnoreBytes,
        Axis::IgnorePatterns,
        Axis::AttributeFiles,
        Axis::AttributeBytes,
        Axis::AttributePatterns,
    ];
    let needed = with_repo(&f, |repo, slot| {
        let idx = index::load(&repo.io).unwrap();
        let before = slot.borrow().budget.clone();
        assert_eq!(git::untracked::untracked_status(repo, &idx, &[]), count(3));
        axes.map(|axis| slot.borrow().budget.used(axis) - before.used(axis))
    });
    assert_eq!(needed[0], if cfg!(target_os = "linux") { 9 } else { 5 });
    assert_eq!(needed[1], 2); // Root and dir, once each.
    assert_eq!((needed[3], needed[6]), (2, 1)); // info/exclude plus local policies.
    for (axis, needed) in axes.into_iter().zip(needed) {
        for remaining in [0, needed - 1, needed, needed + 1] {
            with_repo(&f, |repo, slot| {
                let idx = index::load(&repo.io).unwrap();
                let used = slot.borrow().budget.used(axis);
                slot.borrow_mut()
                    .charge_axis(axis, axis.limit() - used - remaining)
                    .unwrap();
                let got = git::untracked::untracked_status(repo, &idx, &[]);
                if remaining >= needed {
                    assert_eq!(got, count(3), "{axis:?}/{remaining}");
                } else {
                    assert!(
                        got == Field::PENDING
                            || matches!(
                                got.value,
                                FieldValue::Count {
                                    n: 1..=3,
                                    saturated: true
                                }
                            ),
                        "{axis:?}/{remaining}: {got:?}"
                    );
                    let before = slot.borrow().counts;
                    assert_eq!(repo.io.worktree_metadata(b"dir/file").err(), Some(E::Limit));
                    assert_eq!(slot.borrow().counts, before, "I/O after {axis:?}");
                }
            });
        }
    }
}

// Mutations: drop independent D1a counts; publish the provisional filtered
// bool on failure; label a partial walk Value. No assertion depends on whether
// readdir visits new/ before file.txt (Linux) or after it (some macOS volumes).
#[test]
fn stage_b_merges_tracked_and_untracked_without_losing_partial() {
    use bingsu_core::collection::git::StageResult;
    let f = init();
    f.write(".gitattributes", b"*.txt text\n");
    f.write("file.txt", b"base\n");
    commit(&f);
    f.write("staged", b"added");
    git(&f, &["add", "staged"]);
    f.write("file.txt", b"changed and longer\n");
    f.write("new/file", b"untracked");
    assert_eq!(oracle(&f), (1, 1, 1, 0));
    with_repo(&f, |repo, _| {
        let StageResult::Partial(value) = stage_b::stage_b(repo, &[], true) else {
            panic!("approximation must be Partial");
        };
        let decl = &bingsu_core::field::BUILTIN[3];
        for name in ["staged", "modified", "untracked"] {
            assert_eq!(value.fields[decl.field_index(name).unwrap()], count(1));
        }
        assert_eq!(
            value.fields[decl.field_index("filtered").unwrap()],
            Field::known(FieldValue::Bool(true))
        );
    });
    f.write("new/.gitignore", vec![b'x'; 65_537]);
    let got = status(&f);
    assert_eq!((got.staged, got.conflicted), (count(1), count(0)));
    assert_eq!(
        (got.modified, got.untracked),
        (Field::PENDING, Field::PENDING)
    );
    with_repo(&f, |repo, _| {
        let StageResult::Partial(value) = stage_b::stage_b(repo, &[], true) else {
            panic!("incomplete walk must be Partial");
        };
        let decl = &bingsu_core::field::BUILTIN[3];
        for name in ["modified", "untracked", "filtered"] {
            assert_eq!(
                value.fields[decl.field_index(name).unwrap()],
                Field::PENDING,
                "{name}"
            );
        }
        assert_eq!(value.fields[decl.field_index("staged").unwrap()], count(1));
        assert_eq!(
            value.fields[decl.field_index("conflicted").unwrap()],
            count(0)
        );
    });
}

// Mutations: normalize I/O paths; accept ambiguous normalized index keys;
// publish provisional worktree observations before final edge validation.
#[test]
fn shared_walk_preserves_raw_names_and_rejects_changed_edges() {
    let f = init();
    f.write("Dir/File", b"base");
    commit(&f);
    git(&f, &["config", "core.ignorecase", "true"]);
    f.write("Dir/File", b"changed");
    f.write("Dir/Extra", b"untracked");
    assert_eq!(parity(&f).modified, count(1));
    with_repo(&f, |repo, _| {
        let mut idx = index::load(&repo.io).unwrap();
        let entry = idx.entries()[0].clone();
        idx.dangerously_push_entry(
            entry.stat,
            entry.id,
            entry.flags,
            entry.mode,
            b"dir/file".as_slice().into(),
        );
        idx.sort_entries();
        assert_eq!(
            git::untracked::untracked_status(repo, &idx, &[]),
            Field::PENDING
        );
    });
    with_repo(&f, |repo, slot| {
        let path = f.0.clone();
        let mut changed = false;
        slot.borrow_mut().hook = Some(Box::new(move |event| {
            if event == "before_worktree_directory_check" && !changed {
                changed = true;
                fs::rename(path.join("Dir"), path.join("moved")).unwrap();
                fs::create_dir(path.join("Dir")).unwrap();
            }
        }));
        let got = stage_b::status(repo, &[]);
        assert_eq!((got.staged, got.conflicted), (count(0), count(0)));
        assert_eq!(
            (got.modified, got.untracked),
            (Field::PENDING, Field::PENDING)
        );
    });
}

// Mutations: follow a policy-file symlink, reject nonregular policies, or
// stream tracked conversion content. Track only the converted file so Linux's
// second-resolution racy checks cannot hash a tracked .gitattributes fixture.
#[test]
fn walker_patterns_never_read_symlinks_or_filtered_contents() {
    let f = init();
    f.write(".gitattributes", b"*.txt filter=canary\n");
    f.write("file.txt", b"base");
    git(&f, &["add", "file.txt"]);
    git(&f, &["commit", "-qm", "fixture"]);
    f.write("file.txt", b"changed and longer");
    with_repo(&f, |repo, slot| {
        let got = stage_b::status(repo, &[]);
        assert_eq!(got.modified, count(1));
        assert!(got.filtered);
        assert_eq!(slot.borrow().budget.used(Axis::WorktreeReadBytes), 0);
    });
    let outside = Fixture::new();
    outside.write("ignore", b"*\n");
    symlink(outside.0.join("ignore"), f.0.join(".gitignore")).unwrap();
    assert_eq!(oracle(&f), (0, 1, 2, 0));
    with_repo(&f, |repo, slot| {
        let got = stage_b::status(repo, &[]);
        assert_eq!(got.untracked, count(2));
        assert_eq!(slot.borrow().budget.used(Axis::WorktreeReadBytes), 0);
        // Only Git's default info/exclude was read, never the symlink target.
        assert_eq!(slot.borrow().budget.used(Axis::IgnoreFiles), 1);
    });
    fs::remove_file(f.0.join(".gitattributes")).unwrap();
    outside.write("attributes", b"*.txt filter=canary\n");
    symlink(outside.0.join("attributes"), f.0.join(".gitattributes")).unwrap();
    with_repo(&f, |repo, slot| {
        let got = stage_b::status(repo, &[]);
        assert_eq!((got.modified, got.untracked), (count(1), count(2)));
        assert!(!got.filtered);
        assert_eq!(slot.borrow().budget.used(Axis::AttributeFiles), 0);
    });
    fs::remove_file(f.0.join(".gitignore")).unwrap();
    f.write(".gitignore/inner", b"visible");
    assert_eq!(parity(&f).untracked, count(2));

    // Nested attribute symlinks exercise the getdents64/getattrlistbulk visit
    // path, rather than just the tracked-only policy lookup.
    f.write("sub/tracked.txt", b"base");
    git(&f, &["add", "sub/tracked.txt"]);
    git(&f, &["commit", "-qm", "nested"]);
    symlink(outside.0.join("attributes"), f.0.join("sub/.gitattributes")).unwrap();
    assert!(!parity(&f).filtered);
    // Special also covers regular-file hardlink rejection. That is a safety
    // failure, not a nonregular policy to ignore (mutation: swallow Special).
    fs::remove_dir_all(f.0.join(".gitignore")).unwrap();
    f.write("policy", b"*\n");
    fs::hard_link(f.0.join("policy"), f.0.join(".gitignore")).unwrap();
    assert_eq!(status(&f).untracked, Field::PENDING);
}

// Mutations: skip valid .git; read local policies before checking the marker;
// resolve a gitfile target; descend into repositories. Creating .git before or
// after the other entries must not matter, even across multiple listing batches.
#[test]
fn embedded_repositories_count_once_without_reading_local_policies() {
    for kind in 0..4 {
        let f = init();
        f.write("base", b"base");
        commit(&f);
        fs::create_dir(f.0.join("nested")).unwrap();
        let metadata = Fixture::new();
        let make_repo = || {
            if kind < 2 {
                git(&f, &["-C", "nested", "init", "-q"]);
            } else {
                git(
                    &f,
                    &[
                        "-C",
                        "nested",
                        "init",
                        "-q",
                        "--separate-git-dir",
                        metadata.0.to_str().unwrap(),
                    ],
                );
            }
        };
        if kind % 2 == 0 {
            make_repo();
        }
        f.write("nested/.gitignore", b"*\n");
        if kind % 2 != 0 {
            for i in 0..3000 {
                f.write(&format!("nested/d/f{i}"), b"x");
                f.write(&format!("nested/f{i:04}"), b"x");
            }
            make_repo();
        }
        assert_eq!(oracle(&f), (0, 0, 1, 0));
        // A local policy read would exceed the cap. Gitfile targets are outside
        // the worktree: the fixed prefix is sufficient and never grants access.
        f.write("nested/.gitignore", vec![b'x'; 65_537]);
        with_repo(&f, |repo, slot| {
            let got = stage_b::status(repo, &[]);
            assert_eq!(
                (got.staged, got.modified, got.untracked),
                (count(0), count(0), count(1))
            );
            assert_eq!(
                slot.borrow().budget.used(Axis::Directories),
                if kind < 2 { 3 } else { 2 }
            );
            assert_eq!(slot.borrow().budget.used(Axis::IgnoreFiles), 1);
            assert!(slot.borrow().budget.used(Axis::WorktreeEntries) < 600);
        });
    }
}

// Mutations: accept any .git name, accept a directory without all three shape
// entries, or retry marker-name collapse in a later batch. Only ignored content
// makes false embedded detection observable, regardless of listing order.
#[test]
fn junk_repository_markers_are_walked_normally_like_git() {
    for kind in 0..6 {
        let f = init();
        f.write(".gitignore", b"*.o\n");
        f.write("base", b"base");
        commit(&f);
        fs::create_dir(f.0.join("nested")).unwrap();
        match kind {
            0 => fs::create_dir(f.0.join("nested/.git")).unwrap(),
            1 => f.write("nested/.git", b"junk"),
            2 => f.write("nested/.git", b"gitdir:"),
            3..=5 => {
                git(&f, &["-C", "nested", "init", "-q"]);
                match kind {
                    3 => fs::remove_file(f.0.join("nested/.git/HEAD")).unwrap(),
                    4 => fs::remove_dir_all(f.0.join("nested/.git/objects")).unwrap(),
                    _ => fs::remove_dir_all(f.0.join("nested/.git/refs")).unwrap(),
                }
            }
            _ => unreachable!(),
        }
        assert_eq!(oracle(&f), (0, 0, 0, 0), "kind={kind}");
        assert_eq!(parity(&f).untracked, count(0));
        for i in 0..3000 {
            f.write(&format!("nested/f{i:04}.o"), b"ignored");
        }
        assert_eq!(oracle(&f), (0, 0, 0, 0), "kind={kind}");
        assert_eq!(parity(&f).untracked, count(0));
        f.write("nested/visible", b"untracked");
        assert_eq!(oracle(&f), (0, 0, 1, 0));
        assert_eq!(parity(&f).untracked, count(1));
    }
}

// Mutations: follow marker/shape symlinks, read the entire gitfile or its
// target, omit pre-read charging, or accept a replaced marker. The probe must
// use the held batch fd without listing again, independently of entry order.
#[test]
fn embedded_marker_probe_is_bounded_and_never_follows_links() {
    let f = init();
    let outside = init();
    fs::create_dir(f.0.join("nested")).unwrap();
    symlink(outside.0.join(".git"), f.0.join("nested/.git")).unwrap();
    let probe = |expected, bytes| {
        with_repo(&f, |repo, slot| {
            let before = slot.borrow().counts;
            assert_eq!(repo.io.worktree_embedded_repository(), Err(E::Denied));
            assert_eq!(slot.borrow().counts, before);
            repo.io
                .with_worktree_stats(|| {
                    let _batch = repo.io.worktree_listing(b"nested", true)?;
                    let before = slot.borrow().counts[Phase::Content as usize];
                    assert_eq!(repo.io.worktree_embedded_repository(), expected);
                    let after = slot.borrow().counts[Phase::Content as usize];
                    assert_eq!(after.list, before.list);
                    assert_eq!(after.read_bytes - before.read_bytes, bytes);
                    Ok(())
                })
                .unwrap();
        });
    };
    probe(Ok(false), 0);
    fs::remove_file(f.0.join("nested/.git")).unwrap();
    git(&f, &["-C", "nested", "init", "-q"]);
    fs::remove_dir_all(f.0.join("nested/.git/objects")).unwrap();
    symlink(
        outside.0.join(".git/objects"),
        f.0.join("nested/.git/objects"),
    )
    .unwrap();
    probe(Ok(false), 0);
    fs::remove_dir_all(f.0.join("nested/.git")).unwrap();
    let mut pointer = b"gitdir: ".to_vec();
    pointer.resize(65_537, b'x');
    f.write("nested/.git", pointer);
    probe(Ok(true), 8);
    with_repo(&f, |repo, slot| {
        let result = repo.io.with_worktree_stats(|| {
            let _batch = repo.io.worktree_listing(b"nested", true)?;
            let remaining = Axis::RefBytes.limit() - slot.borrow().budget.used(Axis::RefBytes);
            slot.borrow_mut()
                .charge_axis(Axis::RefBytes, remaining - 7)?;
            let before = slot.borrow().counts[Phase::Content as usize].read;
            assert_eq!(repo.io.worktree_embedded_repository(), Err(E::Limit));
            assert_eq!(slot.borrow().counts[Phase::Content as usize].read, before);
            let stopped = slot.borrow().counts;
            assert_eq!(repo.io.worktree_embedded_repository(), Err(E::Limit));
            assert_eq!(slot.borrow().counts, stopped);
            Err::<(), _>(E::Limit)
        });
        assert_eq!(result, Err(E::Limit));
    });
    with_repo(&f, |repo, slot| {
        let result = repo.io.with_worktree_stats(|| {
            let _batch = repo.io.worktree_listing(b"nested", true)?;
            let path = f.0.join("nested/.git");
            let mut replaced = false;
            slot.borrow_mut().hook = Some(Box::new(move |event| {
                if event == "before_read" && !replaced {
                    replaced = true;
                    fs::rename(&path, path.with_extension("old")).unwrap();
                    fs::write(&path, b"junk").unwrap();
                }
            }));
            repo.io.worktree_embedded_repository()
        });
        assert_eq!(result, Err(E::Changed));
    });
}

// Mutation: apply macOS precomposition to a copied repo on Linux (or disable it
// on macOS). This isolates the reviewer's NFD file / NFC ignore-pattern oracle.
#[test]
fn precompose_ignore_matches_git_on_each_os() {
    let f = init();
    git(&f, &["config", "core.precomposeunicode", "true"]);
    f.write(".gitignore", "\u{d55c}.txt\n");
    commit(&f);
    f.write("\u{1112}\u{1161}\u{11ab}.txt", b"untracked on Linux");
    let expected = u32::from(!cfg!(target_os = "macos"));
    assert_eq!(oracle(&f), (0, 0, expected, 0));
    assert_eq!(parity(&f).untracked, count(expected));
}

// Mutations: ignore the OS policy in directory/index/attribute matching;
// normalize I/O paths; leave nested pattern source/base names unnormalized.
#[test]
fn precomposed_ignore_matching_preserves_raw_io_names() {
    let f = init();
    git(&f, &["config", "core.precomposeunicode", "true"]);
    let nfc = "\u{d55c}";
    let nfd = "\u{1112}\u{1161}\u{11ab}";
    f.write(".gitignore", format!("{nfc}.txt\n{nfc}-ignored/\n"));
    f.write(&format!("{nfc}/tracked"), b"base");
    commit(&f);
    fs::rename(f.0.join(nfc), f.0.join("temporary")).unwrap();
    fs::rename(f.0.join("temporary"), f.0.join(nfd)).unwrap();
    f.write(&format!("{nfd}.txt"), b"ignored");
    f.write(&format!("{nfd}-ignored/file"), b"untracked on Linux");
    f.write(&format!("{nfd}/.gitignore"), b"/local\n*.tmp\n");
    f.write(&format!("{nfd}/local"), b"ignored");
    f.write(&format!("{nfd}/new.tmp"), b"ignored");
    f.write(&format!("{nfd}/visible"), b"visible");
    let macos = cfg!(target_os = "macos");
    // Linux keeps NFC/NFD distinct: the renamed tracked file is deleted and
    // five files are untracked. This is a file count, not a directory count.
    assert_eq!(
        oracle(&f),
        (0, u32::from(!macos), if macos { 2 } else { 5 }, 0)
    );
    parity(&f);
    with_repo(&f, |repo, slot| {
        let got = stage_b::status(repo, &[]);
        assert_eq!(
            (got.staged, got.modified, got.untracked),
            (
                count(0),
                count(u32::from(!macos)),
                count(if macos { 2 } else { 5 })
            )
        );
        // Linux visits root, the NFD directory and its ignored-name sibling;
        // macOS prunes that sibling after precomposed ignore matching.
        assert_eq!(
            slot.borrow().budget.used(Axis::Directories),
            if macos { 2 } else { 3 }
        );
    });
    f.write(&format!("{nfd}/.gitattributes"), b"tracked filter=canary\n");
    f.write(&format!("{nfd}/tracked"), b"changed and longer");
    let got = parity(&f);
    // The new policy file adds one untracked file on either OS.
    assert_eq!(
        (got.modified, got.untracked),
        if macos {
            (count(1), count(3))
        } else {
            (count(1), count(6))
        }
    );
    assert_eq!(got.filtered, macos);
}

// Mutations: retain/double a whole directory's stat vector; collapse build/;
// report an exact partial count or discard the verified lower bound at a cap.
// A local cap must leave the tracked scan complete, in any directory order.
#[test]
fn large_directories_use_bounded_batches_and_saturate() {
    let f = init();
    for i in 0..17_000 {
        f.write(&format!("data/f{i:05}"), b"x");
    }
    commit(&f);
    std::thread::sleep(Duration::from_millis(1100));
    git(&f, &["update-index", "--really-refresh"]);
    git(&f, &["write-tree"]);
    assert_eq!(parity(&f).untracked, count(0));
    for i in 0..70_000 {
        f.write(&format!("build/f{i:05}"), b"x");
    }
    assert_eq!(oracle(&f), (0, 0, 70_000, 0));
    with_repo(&f, |repo, slot| {
        let (got, allocated) = allocation::measure(|| stage_b::status(repo, &[]));
        assert_eq!(
            (got.staged, got.modified, got.conflicted),
            (count(0), count(0), count(0))
        );
        assert_eq!(got.untracked, lower_bound(256));
        let m = slot.borrow();
        assert_eq!(m.budget.used(Axis::Directories), 3);
        // Darwin charges an entire kernel batch before exposing any records;
        // Linux charges raw entries individually. Neither may exceed the cap.
        assert!((17_256..18_000).contains(&m.budget.used(Axis::WorktreeEntries)));
        eprintln!(
            "UNTRACKED_LARGE dirs={} raw={} ops={} lists={} count={:?} allocation_peak={}",
            m.budget.used(Axis::Directories),
            m.budget.used(Axis::WorktreeEntries),
            m.operations(),
            m.counts[Phase::Content as usize].list,
            got.untracked,
            allocated.peak
        );
        assert!(allocated.peak < 8_388_608, "{allocated:?}");
    });
}

// Mutations: charge each leaf permanently at 3x, release before the returned
// index dies, keep allocation-heavy stable sorting, or lose valid sparse TREE
// counts and traverse the same 30,000 leaves again in staged comparison.
#[test]
fn sparse_30000_leaves_keep_live_reservations_and_return_values() {
    let f = init();
    f.write("keep/a", b"visible");
    for d in 0..300 {
        for i in 0..100 {
            f.write(&format!("omit/d{d:03}/f{i:03}"), b"x");
        }
    }
    commit(&f);
    git(&f, &["sparse-checkout", "init", "--cone", "--sparse-index"]);
    git(&f, &["sparse-checkout", "set", "keep"]);
    with_repo(&f, |repo, slot| {
        let ((idx, before), allocated) = allocation::measure(|| {
            let idx = index::load(&repo.io).unwrap();
            let before = slot.borrow().live_allocated();
            (index::expand_sparse(repo, idx).unwrap(), before)
        });
        assert_eq!(idx.entries().len(), 30_001);
        assert!(idx.entries().iter().all(|e| !e.mode.is_sparse()));
        let retained = slot.borrow().live_allocated() - before;
        assert!(retained > 3_000_000);
        // Real Vec capacity, not a per-leaf multiplier. The small original
        // decoded index is covered by its existing parser reservation.
        assert!(
            retained.abs_diff(allocated.live as u64) < 16_384,
            "{retained}/{allocated:?}"
        );
        assert!(allocated.peak < 8_388_608, "{allocated:?}");
        eprintln!(
            "D1B_SPARSE leaves=30000 retained={retained} actual_live={} actual_peak={}",
            allocated.live, allocated.peak
        );
        drop(idx);
        assert_eq!(slot.borrow().live_allocated(), before);
    });
    assert_eq!(parity(&f).untracked, count(0));
    // A changed visible path still gets staged/modified comparison after the
    // sparse cache's counts are adjusted.
    f.write("keep/a", b"longer");
    assert_eq!(parity(&f).modified, count(1));
    git(&f, &["add", "keep/a"]);
    let got = parity(&f);
    assert_eq!((got.staged, got.modified), (count(1), count(0)));
}

fn corpus() -> Fixture {
    let f = init();
    f.write(".gitignore", b"node_modules/\n");
    for dir in 0..190 {
        for leaf in 0..if dir == 0 { 99 } else { 100 } {
            f.write(&format!("d{dir:03}/f{leaf:03}"), b"unchanged\n");
        }
    }
    commit(&f);
    // Separate index timestamp on filesystems with second-resolution clocks.
    std::thread::sleep(Duration::from_millis(1100));
    git(&f, &["update-index", "--really-refresh"]);
    git(&f, &["write-tree"]);
    for i in 0..1000 {
        f.write(&format!("u{i:04}"), b"untracked");
    }
    for i in 0..50_000 {
        f.write(&format!("node_modules/f{i:05}"), b"ignored");
    }
    f
}

// Mutations: list twice; walk ignored directory; sum live per-directory scratch;
// bypass raw charging. The large ignored subtree must not enter the counters.
#[test]
fn shared_scan_19000_tracked_1000_untracked_prunes_50000_ignored() {
    let f = corpus();
    assert_eq!(oracle(&f), (0, 0, 1000, 0));
    let mut previous = None;
    for _ in 0..2 {
        with_repo(&f, |repo, slot| {
            let before = slot.borrow().operations();
            let (got, allocations) = allocation::measure(|| stage_b::status(repo, &[]));
            assert_eq!(
                (got.staged, got.modified, got.untracked, got.conflicted),
                (count(0), count(0), count(1000), count(0))
            );
            let m = slot.borrow();
            assert_eq!(m.budget.used(Axis::Directories), 191);
            let expected_raw = 20_192
                + if cfg!(target_os = "linux") {
                    2 * 191
                } else {
                    0
                };
            assert_eq!(m.budget.used(Axis::WorktreeEntries), expected_raw);
            assert_eq!(m.budget.used(Axis::WorktreeReadBytes), 0);
            assert!(m.live_allocated() < 5_000_000);
            // Mutation: restore one heap-owned name per listed or compared leaf.
            assert!(
                allocations.calls < 20_000,
                "per-entry allocation: {allocations:?}"
            );
            let costs = (
                m.operations() - before,
                m.counts[Phase::Content as usize].list,
                m.budget.used(Axis::WorktreeEntries),
                m.budget.used(Axis::Directories),
            );
            if let Some(previous) = previous {
                assert_eq!(costs, previous);
            }
            previous = Some(costs);
            eprintln!(
                "D1B_DETERMINISTIC ops={} list_calls={} entries={} directories={} live={} allocation_peak={} peak_fds={} process_peak_rss_bytes={}",
                costs.0,
                costs.1,
                costs.2,
                costs.3,
                m.live_allocated(),
                allocations.peak,
                m.peak_fds,
                process_peak_rss_bytes()
            );
        });
    }
}

// Thousands of directories with ONE meter: request totals must not retain
// temporary listing, path-key or pattern source allocations after each item.
#[test]
fn untracked_scratch_is_live_across_thousands_of_directories() {
    let f = init();
    for i in 0..3000 {
        f.write(&format!("d{i:04}/file"), b"x");
    }
    with_repo(&f, |repo, slot| {
        let idx = index::load(&repo.io).unwrap();
        let before = slot.borrow().live_allocated();
        assert_eq!(
            git::untracked::untracked_status(repo, &idx, &[]),
            count(3000)
        );
        assert_eq!(slot.borrow().live_allocated(), before);
        assert_eq!(slot.borrow().budget.used(Axis::Directories), 3001);
    });
}

// Whole test-process high-water RSS, including fixture construction; not a
// claim about the product worker's separately supervised footprint.
fn process_peak_rss_bytes() -> u64 {
    let mut usage = std::mem::MaybeUninit::<libc::rusage>::uninit();
    // SAFETY: getrusage receives a valid writable output record.
    let result = unsafe { libc::getrusage(libc::RUSAGE_SELF, usage.as_mut_ptr()) };
    assert_eq!(result, 0);
    // SAFETY: the successful getrusage call initialized the whole record.
    let usage = unsafe { usage.assume_init() };
    usage.ru_maxrss as u64 * if cfg!(target_os = "macos") { 1 } else { 1024 }
}

fn load_average() -> [f64; 3] {
    let mut load = [0.; 3];
    // SAFETY: getloadavg writes at most three doubles to this live array.
    assert_eq!(unsafe { libc::getloadavg(load.as_mut_ptr(), 3) }, 3);
    load
}
fn report(name: &str, times: &mut [u128], cold: u128) {
    let mean = times.iter().sum::<u128>() as f64 / times.len() as f64;
    let variance = times
        .iter()
        .map(|n| (*n as f64 - mean).powi(2))
        .sum::<f64>()
        / times.len() as f64;
    times.sort_unstable();
    eprintln!(
        "D1B_OBSERVE case={name} rounds={} first_ns={cold} p50_ns={} p95_ns={} variance_ns2={variance}",
        times.len(),
        times[times.len() / 2],
        times[times.len() * 95 / 100]
    );
}

// External mode lets a runner alternate base/current release binaries on the
// SAME filesystem fixture, excluding process startup and acquisition from B.
// Observation only: correctness and budget mutations use the active tests.
#[test]
#[ignore = "release measurement: 200 warm samples, or one externally owned fixture"]
fn measure_untracked_file_count() {
    assert!(std::hint::black_box(!cfg!(debug_assertions)));
    let sample = |f: &Fixture| {
        with_repo(f, |repo, slot| {
            let before = slot.borrow().operations();
            let start = Instant::now();
            let got = stage_b::status(repo, &[]);
            let ns = start.elapsed().as_nanos();
            let m = slot.borrow();
            eprintln!(
                "UNTRACKED_SAMPLE ns={ns} dirs={} raw={} ops={} lists={} count={:?} staged={:?} modified={:?} rss={}",
                m.budget.used(Axis::Directories),
                m.budget.used(Axis::WorktreeEntries),
                m.operations() - before,
                m.counts[Phase::Content as usize].list,
                got.untracked,
                got.staged,
                got.modified,
                process_peak_rss_bytes()
            );
            ns
        })
    };
    if let Some(path) = std::env::var_os("BINGSU_UNTRACKED_MEASURE_ROOT") {
        // The alternating runner owns this fixture, including teardown.
        let f = std::mem::ManuallyDrop::new(Fixture(PathBuf::from(path)));
        sample(&f);
        return;
    }
    let large = init();
    for i in 0..70_000 {
        large.write(&format!("build/f{i:05}"), b"x");
    }
    assert_eq!(oracle(&large), (0, 0, 70_000, 0));
    let small = init();
    small.write("new/a", b"one");
    small.write("new/b", b"two");
    let several = corpus();
    for dir in ["build", "output", "d000/new"] {
        for i in 0..20_000 {
            several.write(&format!("{dir}/f{i:05}"), b"x");
        }
    }
    assert_eq!(oracle(&several), (0, 0, 61_000, 0));
    for (name, f) in [
        ("19000+1000+50000", corpus()),
        ("70000", large),
        ("19000+1000+50000+3x20000", several),
        ("two-files", small),
    ] {
        eprintln!("UNTRACKED_LOAD case={name} load={:?}", load_average());
        let cold = sample(&f);
        let mut times = (0..200).map(|_| sample(&f)).collect::<Vec<_>>();
        report(name, &mut times, cold);
    }
}

// Observation only: measure actual B preflight through publication using the
// real pipeline and wire sink. Semantic assertions above use generous time;
// this opt-in probe also exercises the unchanged product 28 ms B deadline.
#[test]
#[ignore = "release measurement on an externally owned fixture"]
fn measure_untracked_pipeline() {
    use bingsu_core::{
        collection::wire::{self, Binding, BuildId, Request},
        snapshot::{self, Identity},
    };
    use std::{cell::Cell, rc::Rc};
    assert!(std::hint::black_box(!cfg!(debug_assertions)));
    let path = std::env::var_os("BINGSU_UNTRACKED_MEASURE_ROOT").unwrap();
    let cwd = PathBuf::from(path).as_os_str().as_bytes().to_vec();
    let request = Request {
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
            path_query: bingsu_core::collection::path_facts::PathQuery::for_path(
                &cwd,
                Some(&cwd),
                false,
            ),
            cwd,
            mask: 1 << 3,
        },
        budget_ms: 50,
        environment: vec![],
        global_excludes_known: true,
        global_excludes: vec![],
    };
    let access = access();
    let started = Rc::new(Cell::new(None));
    let hook_started = started.clone();
    let mut m = meter();
    m.hook = Some(Box::new(move |event| {
        if event == "preflight_start" {
            hook_started.set(Some(Instant::now()));
        }
    }));
    let mut ready = wire::FEATURES.to_le_bytes().to_vec();
    ready.extend(request.binding.mask.to_le_bytes());
    ready.extend(0u32.to_le_bytes());
    ready.extend(0u64.to_le_bytes());
    let mut buffer = [0; wire::FRAME_MAX];
    let mut b_ns = None;
    let mut b_value = None;
    let mut transcript = wire::Transcript::new(&request);
    transcript
        .accept(wire::Frame {
            kind: wire::Kind::Ready,
            build_id: request.binding.build_id,
            request_id: request.request_id,
            payload: &ready,
        })
        .unwrap();
    transcript.request_sent().unwrap();
    let mut write = |bytes: &[u8]| {
        transcript
            .accept(wire::decode_frame(bytes).unwrap())
            .unwrap();
        let completed = transcript
            .clone()
            .finish(
                wire::EndReason::WorkerExit,
                snapshot::Clock {
                    kind: 1,
                    domain: [5; 16],
                    resume: 0,
                    boot: [1; 16],
                    now: 1,
                },
            )
            .unwrap();
        if let Some(value) = completed
            .as_ref()
            .into_iter()
            .flat_map(|c| &c.updates)
            .find(|u| u.segment == 3)
            .and_then(|u| u.value.as_ref())
        {
            let decl = &bingsu_core::field::BUILTIN[3];
            if value.fields[decl.field_index("stage").unwrap()]
                == Field::text(b"B", 1, bingsu_core::width::WidthProfile::DEFAULT)
                && b_ns.is_none()
            {
                b_ns = Some(started.get().unwrap().elapsed().as_nanos());
                b_value = Some(value.clone());
            }
        }
        Ok(())
    };
    let mut sink = update_sink::WireSink::new(
        &request,
        bingsu_core::field::BUILTIN,
        &ready,
        &mut buffer,
        &mut write,
    )
    .unwrap();
    let product = std::env::var_os("BINGSU_UNTRACKED_PRODUCT_B").is_some();
    let deadlines = git::StageDeadlines {
        a_ms: 30_000,
        b_ms: if product { 28 } else { 30_000 },
        c_ms: 30_000,
        d_ms: 30_000,
        path_ms: 30_000,
    };
    let result = git::collect_with_deadlines(&request, &mut sink, m, access, deadlines);
    eprintln!(
        "UNTRACKED_PIPELINE product={product} ns={b_ns:?} result={result:?} value={b_value:?}"
    );
}

#[test]
#[ignore = "release observations: load < 4, 200 alternating warm samples"]
fn stage_b_release_observations() {
    let load = load_average();
    eprintln!("D1B_LOAD {load:?}");
    if load.iter().any(|n| *n >= 4.) {
        eprintln!("BLOCKED: wall-clock observations require load < 4");
        return;
    }
    assert!(
        std::hint::black_box(!cfg!(debug_assertions)),
        "release build required"
    );
    let mut fixtures = vec![("19000+1000+50000", corpus()), ("sparse", sparse_fixture())];
    let gitfile_target = init();
    for name in [
        "empty-gitdir",
        "junk-gitfile",
        "valid-gitdir",
        "valid-gitfile",
    ] {
        let f = init();
        f.write("base", b"base");
        commit(&f);
        fs::create_dir(f.0.join("nested")).unwrap();
        match name {
            "empty-gitdir" => fs::create_dir(f.0.join("nested/.git")).unwrap(),
            "junk-gitfile" => f.write("nested/.git", b"junk"),
            "valid-gitdir" => {
                git(&f, &["-C", "nested", "init", "-q"]);
            }
            _ => f.write(
                "nested/.git",
                format!("gitdir: {}\n", gitfile_target.0.join(".git").display()),
            ),
        }
        parity(&f);
        fixtures.push((name, f));
    }
    for (name, f) in fixtures {
        let mut times = [Vec::new(), Vec::new()];
        let mut cold = [0; 2];
        for run in 0..201 {
            if load_average().iter().any(|n| *n >= 4.) {
                eprintln!("BLOCKED: {name} run={run} load crossed threshold");
                return;
            }
            for kind in if run % 2 == 0 { [0, 1] } else { [1, 0] } {
                with_repo(&f, |repo, _| {
                    let start = Instant::now();
                    let got = if kind == 0 {
                        stage_b::status(repo, &[])
                    } else {
                        git::status_tracked::load_status(repo)
                    };
                    let elapsed = start.elapsed().as_nanos();
                    if kind == 0 {
                        assert_ne!(got.untracked, Field::PENDING);
                    }
                    if run == 0 {
                        cold[kind] = elapsed;
                    } else {
                        times[kind].push(elapsed);
                    }
                });
            }
        }
        if load_average().iter().any(|n| *n >= 4.) {
            eprintln!("BLOCKED: final load crossed threshold");
            return;
        }
        report(name, &mut times[0], cold[0]);
        report(&format!("{name}-d1a-baseline"), &mut times[1], cold[1]);
    }
}

// Mutations: omit helper bytes, load them after info/exclude/.gitignore, give
// the global list a directory base, or consult repository core.excludesFile.
#[test]
fn global_excludes_lowest_precedence_matches_git() {
    let f = init();
    f.write("tracked", b"tracked");
    f.write("sub/tracked", b"tracked");
    f.write(".gitignore", b"!keep.log\n");
    commit(&f);
    let home = Fixture::new();
    let bytes = b".DS_Store\n*.tmp\n*.log\n/root-only\n";
    home.write(".config/git/ignore", bytes);
    f.write(".DS_Store", b"ignored");
    f.write("info-wins", b"ignored");
    f.write("root-only", b"ignored");
    f.write("visible", b"visible");
    f.write("keep.tmp", b"visible");
    f.write("keep.log", b"visible");
    f.write(".git/info/exclude", b"!keep.tmp\ninfo-wins\n");
    f.write(".gitignore", b"!keep.log\n");
    // The directory is tracked so normal status reports individual names.
    f.write("sub/.DS_Store", b"ignored");
    f.write("sub/root-only", b"visible");
    let oracle = || {
        let out = Command::new("git")
            .arg("-C")
            .arg(&f.0)
            .args([
                "-c",
                "status.renames=false",
                "status",
                "--porcelain=v2",
                "--untracked-files=all",
            ])
            .env_clear()
            .env("PATH", std::env::var_os("PATH").unwrap())
            .env("HOME", &home.0)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_OPTIONAL_LOCKS", "0")
            .output()
            .expect("git oracle required");
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        out.stdout
            .split(|b| *b == b'\n')
            .filter(|line| line.starts_with(b"? "))
            .count() as u32
    };
    let expected = oracle();
    assert_eq!(expected, 4); // visible, keep.tmp, keep.log, sub/root-only.
    with_repo(&f, |repo, slot| {
        let counts = stage_b::status(repo, bytes);
        assert_eq!(counts.untracked, count(expected));
        assert_eq!(counts.modified, count(0));
        assert_eq!(slot.borrow().budget.used(Axis::IgnoreFiles), 3);
        assert_eq!(
            slot.borrow().budget.used(Axis::IgnoreBytes),
            (bytes.len() + b"!keep.tmp\ninfo-wins\n".len() + b"!keep.log\n".len()) as u64
        );
    });
    // Recreate the same rules via a trusted global core.excludesFile.
    home.write("custom", bytes);
    home.write(".gitconfig", b"[core]\n excludesFile = ~/custom\n");
    assert_eq!(oracle(), expected);
    // Repository override is deliberately ignored by the helper and collector.
    // An outside rule must not replace the helper-provided input.
    git(
        &f,
        &[
            "config",
            "core.excludesFile",
            home.0.join("hostile").to_str().unwrap(),
        ],
    );
    home.write("hostile", b"*\n");
    assert_eq!(oracle(), 2); // info/exclude and .gitignore re-include keep.*.
    with_repo(&f, |repo, _| {
        assert_eq!(stage_b::status(repo, bytes).untracked, count(expected))
    });
}

// Mutations: bypass file/byte/pattern caps, parse after a failed reservation,
// leave a failed matcher usable, or perform filesystem I/O for global bytes.
#[test]
fn global_excludes_are_budgeted_before_parse_without_io() {
    use git::io::policy::Patterns;
    let f = init();
    with_repo(&f, |repo, slot| {
        let before = slot.borrow().counts;
        let initial_allocation = slot.borrow().live_allocated();
        let mut patterns = Patterns::default();
        patterns.add_global(&repo.io, b".DS_Store\n").unwrap();
        assert!(
            patterns
                .ignored(&repo.io, b"sub/.DS_Store", false, Default::default())
                .unwrap()
        );
        let after = slot.borrow().counts;
        for i in 0..3 {
            assert_eq!(
                (
                    before[i].open,
                    before[i].stat,
                    before[i].read,
                    before[i].list
                ),
                (after[i].open, after[i].stat, after[i].read, after[i].list)
            );
        }
        assert_eq!(slot.borrow().budget.used(Axis::IgnoreFiles), 1);
        assert_eq!(slot.borrow().budget.used(Axis::IgnoreBytes), 10);
        assert_eq!(slot.borrow().budget.used(Axis::IgnorePatterns), 1);
        let retained = slot.borrow().live_allocated();
        let mut name = vec![b'a'; 256];
        name.extend_from_slice(b"e\xcc\x81/.DS_Store");
        for _ in 0..4000 {
            assert!(
                patterns
                    .ignored(
                        &repo.io,
                        &name,
                        false,
                        git::io::policy::NamePolicy {
                            ignore_case: false,
                            precompose_unicode: true,
                        }
                    )
                    .unwrap()
            );
        }
        assert_eq!(slot.borrow().live_allocated(), retained);
        drop(patterns);
        assert_eq!(slot.borrow().live_allocated(), initial_allocation);
    });
    for axis in [Axis::IgnoreFiles, Axis::IgnoreBytes, Axis::IgnorePatterns] {
        with_repo(&f, |repo, slot| {
            slot.borrow_mut().charge_axis(axis, axis.limit()).unwrap();
            let calls = std::rc::Rc::new(std::cell::Cell::new(0));
            let called = calls.clone();
            slot.borrow_mut().hook = Some(Box::new(move |event| {
                if event == "before_pattern_parse" {
                    called.set(called.get() + 1)
                }
            }));
            let mut p = Patterns::default();
            assert_eq!(p.add_global(&repo.io, b"file\n"), Err(E::Limit));
            assert_eq!(
                p.ignored(&repo.io, b"file", false, Default::default()),
                Err(E::Limit)
            );
            assert_eq!(calls.get(), 0);
        });
    }
    for bad in [
        vec![b'#'; 65_537],
        b"bad\0pattern\n".to_vec(),
        b"x\n".repeat(2049),
    ] {
        with_repo(&f, |repo, _| {
            assert_eq!(
                Patterns::default().add_global(&repo.io, &bad),
                Err(E::Limit)
            )
        });
    }
}

#[test]
#[ignore = "release measurement over 200 warm runs"]
fn measure_global_excludes_matcher() {
    use git::io::policy::Patterns;
    let f = init();
    f.write("tracked", b"tracked");
    commit(&f);
    f.write(".DS_Store", b"ignored");
    for (label, bytes) in [
        ("empty", vec![]),
        ("default", b".DS_Store\n".to_vec()),
        ("64k", vec![b'#'; 65_536]),
        (
            "2048-patterns",
            b"unmatched-entry-000000000000000\n".repeat(2048),
        ),
    ] {
        let mut ns = Vec::new();
        for _ in 0..201 {
            with_repo(&f, |repo, _| {
                let start = Instant::now();
                let mut p = Patterns::default();
                p.add_global(&repo.io, &bytes).unwrap();
                std::hint::black_box(
                    p.ignored(&repo.io, b".DS_Store", false, Default::default())
                        .unwrap(),
                );
                ns.push(start.elapsed().as_nanos());
            });
        }
        let cold = ns.remove(0);
        let mean = ns.iter().sum::<u128>() as f64 / 200.0;
        let variance = ns.iter().map(|n| (*n as f64 - mean).powi(2)).sum::<f64>() / 200.0;
        ns.sort_unstable();
        eprintln!(
            "D1C_MATCHER {label} runs=200 cold_ns={cold} p50_ns={} p95_ns={} variance_ns2={variance} samples_ns={ns:?}",
            ns[99], ns[189]
        );
    }
}

// Mutations: omit/invert the wire knowledge flag; skip the shared scan for
// unknown input; publish its untracked/filtered observation as confident;
// mark missing (known-empty) Partial; or lose independent tracked counts.
#[test]
fn global_excludes_knowledge_survives_wire_into_stage_b() {
    use bingsu_core::{
        collection::{
            git::StageResult,
            wire::{self, Binding, BuildId, Frame, Kind, Request, RequestDecoder, RequestId},
        },
        snapshot::{self, Identity},
    };
    let f = init();
    f.write("tracked", b"before");
    commit(&f);
    f.write("tracked", b"modified and longer");
    f.write("added", b"staged");
    git(&f, &["add", "added"]);
    f.write("visible", b"untracked");
    assert_eq!(oracle(&f), (1, 1, 1, 0));
    let mut scans = Vec::new();
    for known in [true, false] {
        let request = Request {
            request_id: RequestId([1; 32]),
            binding: Binding {
                build_id: BuildId([2; 32]),
                snapshot: Identity {
                    boot: [0; 16],
                    epoch: [0; 16],
                    generation: 0,
                    source: [0; 4],
                    context: snapshot::context_crc(b"/c", b"/s").unwrap(),
                },
                clock_kind: 1,
                domain: [0; 16],
                resume: 0,
                config: b"/c".to_vec(),
                state: b"/s".to_vec(),
                cwd: f.0.as_os_str().as_bytes().to_vec(),
                mask: 1 << 3,
                path_query: Default::default(),
            },
            budget_ms: 50,
            environment: vec![],
            global_excludes_known: known,
            global_excludes: vec![],
        };
        let body = request.encode_body().unwrap();
        let mut ready = wire::FEATURES.to_le_bytes().to_vec();
        ready.extend(request.binding.mask.to_le_bytes());
        ready.extend(0u32.to_le_bytes());
        ready.extend(0u64.to_le_bytes());
        let mut begin = (body.len() as u32).to_le_bytes().to_vec();
        begin.extend(wire::FEATURES.to_le_bytes());
        let mut chunk = 0u32.to_le_bytes().to_vec();
        chunk.extend(&body);
        let mut decoder = RequestDecoder::new();
        let mut decoded = None;
        for (kind, payload) in [
            (Kind::Ready, ready),
            (Kind::RequestBegin, begin),
            (Kind::RequestChunk, chunk),
            (Kind::RequestEnd, snapshot::crc32c(&[&body]).to_vec()),
        ] {
            let mut buffer = [0; wire::FRAME_MAX];
            let len = wire::encode_frame(
                Frame {
                    kind,
                    build_id: request.binding.build_id,
                    request_id: request.request_id,
                    payload: &payload,
                },
                &mut buffer,
            )
            .unwrap();
            decoded = decoder
                .accept(wire::decode_frame(&buffer[..len]).unwrap())
                .unwrap();
        }
        let decoded = decoded.unwrap();
        assert_eq!(decoded, request);
        with_repo(&f, |repo, slot| {
            let result = stage_b::stage_b(
                repo,
                &decoded.global_excludes,
                decoded.global_excludes_known,
            );
            let value = match (known, result) {
                (true, StageResult::Value(value)) | (false, StageResult::Partial(value)) => value,
                (_, result) => panic!("wrong knowledge: {known}: {result:?}"),
            };
            let decl = &bingsu_core::field::BUILTIN[3];
            for (name, expected) in [
                ("staged", count(1)),
                ("modified", count(1)),
                ("conflicted", count(0)),
                ("untracked", if known { count(1) } else { Field::PENDING }),
                (
                    "filtered",
                    if known {
                        Field::known(FieldValue::Bool(false))
                    } else {
                        Field::PENDING
                    },
                ),
                ("partial", Field::known(FieldValue::Bool(!known))),
            ] {
                assert_eq!(
                    value.fields[decl.field_index(name).unwrap()],
                    expected,
                    "{name}"
                );
            }
            let entries = slot.borrow().counts[Phase::Content as usize].raw_entries;
            assert!(entries >= 4, "unknown input must still scan the worktree");
            scans.push(entries);
        });
    }
    assert_eq!(scans[0], scans[1]);
}

// Observation only; semantic mutations are covered by the wire-to-B test above.
#[test]
#[ignore = "release measurement over 200 warm runs"]
fn measure_global_excludes_knowledge_stage_b() {
    let f = init();
    f.write("tracked", b"tracked");
    commit(&f);
    f.write("visible", b"untracked");
    for known in [true, false] {
        let mut ns = Vec::new();
        for _ in 0..201 {
            with_repo(&f, |repo, _| {
                let start = Instant::now();
                std::hint::black_box(stage_b::stage_b(repo, &[], known));
                ns.push(start.elapsed().as_nanos());
            });
        }
        let cold = ns.remove(0);
        let mean = ns.iter().sum::<u128>() as f64 / 200.0;
        let variance = ns.iter().map(|n| (*n as f64 - mean).powi(2)).sum::<f64>() / 200.0;
        ns.sort_unstable();
        eprintln!(
            "D1C_KNOWLEDGE known={known} runs=200 cold_ns={cold} p50_ns={} p95_ns={} variance_ns2={variance} samples_ns={ns:?}",
            ns[99], ns[189]
        );
    }
}

// Mutations: skip ignore lookup for directories replacing tracked files, skip
// it for untracked leaves, or suppress comparison of ignored tracked leaves.
#[test]
fn tracked_ignore_shortcut_still_checks_directories_and_untracked_leaves() {
    let f = init();
    f.write("kept", b"base");
    f.write("replaced", b"base");
    commit(&f);
    f.write(".gitignore", b"kept\nreplaced/\n*.log\n");
    commit(&f);
    f.write("kept", b"changed");
    fs::remove_file(f.0.join("replaced")).unwrap();
    f.write("replaced/hidden", b"ignored");
    f.write("hidden.log", b"ignored");
    f.write("visible", b"untracked");
    let got = parity(&f);
    assert_eq!((got.modified, got.untracked), (count(2), count(1)));
}

// Mutations: trust a mutable caller's index without validating it at either
// entry point; this must fail before any worktree listing or content I/O.
#[test]
fn edited_indexes_must_be_validated_before_certification_or_walking() {
    let f = init();
    f.write("tracked", b"base");
    commit(&f);
    for expansion in [false, true] {
        with_repo(&f, |repo, slot| {
            let mut idx = index::load(&repo.io).unwrap();
            let e = idx.entries()[0].clone();
            idx.dangerously_push_entry(
                e.stat,
                e.id,
                e.flags,
                e.mode,
                b"../escape".as_slice().into(),
            );
            idx.sort_entries();
            let before = slot.borrow().counts;
            if expansion {
                assert_eq!(
                    index::expand_sparse(repo, idx).err(),
                    Some(E::Io(libc::EINVAL))
                );
            } else {
                assert_eq!(
                    git::untracked::untracked_status(repo, &idx, &[]),
                    Field::PENDING
                );
            }
            assert_eq!(slot.borrow().counts, before);
        });
    }
}

// Mutations: lose the slash boundary, use a directory-local offset as a global
// entry index, or truncate the candidate range. Raw names still drive I/O.
#[test]
fn directory_key_ranges_preserve_prefix_boundaries_and_offsets() {
    let f = init();
    for (path, content) in [
        ("d/a", "one"),
        ("d/nested/z", "two two"),
        ("d-neighbor/a", "three three three"),
        ("D2/a", "four four four four"),
    ] {
        f.write(path, content);
    }
    commit(&f);
    git(&f, &["config", "core.ignorecase", "true"]);
    f.write("d/extra", b"untracked");
    let got = parity(&f);
    assert_eq!((got.modified, got.untracked), (count(0), count(1)));
    f.write("D2/a", b"changed");
    fs::remove_file(f.0.join("d/nested/z")).unwrap();
    let got = parity(&f);
    assert_eq!((got.modified, got.untracked), (count(2), count(1)));
}
