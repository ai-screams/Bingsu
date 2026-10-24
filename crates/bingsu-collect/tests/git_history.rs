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

#[path = "support/allocation.rs"]
mod allocation;
use bingsu_core::{
    collection::{
        budget::{self, Axis},
        git::StageResult,
        path_facts::PathQuery,
    },
    field::{self, Field, FieldValue, Value},
};
use git::{
    GuardedRepository,
    io::{RepoIo, RepoRoots},
    refs::{ObjectId, RefSnapshot},
    stage_c::{divergence, stage_c, walk},
    stage_d::stash,
};
use meter::Meter;
use safe_read::{Access, ReadError as E, Root};
use std::{
    cell::RefCell,
    fs,
    io::Write,
    os::unix::{ffi::OsStrExt, fs::symlink},
    path::PathBuf,
    process::{Command, Stdio},
    time::{Duration, Instant},
};
const INVALID: E = E::Io(libc::EINVAL);
fn meter() -> Meter {
    Meter::new(Instant::now() + Duration::from_secs(30))
}
struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let dir = std::env::temp_dir().join(format!(
            "bingsu-d2-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        fs::create_dir_all(&dir).unwrap();
        Self(fs::canonicalize(dir).unwrap())
    }
    fn write(&self, name: &str, bytes: impl AsRef<[u8]>) {
        let path = self.0.join(name);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, bytes).unwrap();
    }
    fn stash_ref(&self) {
        self.write("refs/stash", "1".repeat(40));
    }
    fn root(&self) -> Root {
        safe_read::acquire(
            self.0.as_os_str().as_bytes(),
            PathQuery::default(),
            &mut meter(),
        )
        .unwrap()
        .select_cwd()
        .unwrap()
    }
    fn git(&self, args: &[&str], input: &[u8]) -> Vec<u8> {
        let mut child = Command::new("git")
            .args(["--git-dir", self.0.to_str().unwrap()])
            .args(args)
            .env_clear()
            .env("PATH", "/usr/bin:/bin:/opt/homebrew/bin")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_AUTHOR_NAME", "Fixture")
            .env("GIT_AUTHOR_EMAIL", "f@example.org")
            .env("GIT_COMMITTER_NAME", "Fixture")
            .env("GIT_COMMITTER_EMAIL", "f@example.org")
            .env("GIT_AUTHOR_DATE", "1700000000 +0000")
            .env("GIT_COMMITTER_DATE", "1700000000 +0000")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("git oracle required");
        child.stdin.take().unwrap().write_all(input).unwrap();
        let out = child.wait_with_output().unwrap();
        assert!(
            out.status.success(),
            "git {args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        out.stdout
    }
    fn commit(&self, parents: &[ObjectId], label: &str) -> ObjectId {
        let mut body = "tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\n".to_owned();
        for p in parents {
            body += &format!("parent {p}\n");
        }
        body += &format!(
            "author F <f@example.org> 1700000000 +0000\ncommitter F <f@example.org> 1700000000 +0000\n\n{label}\n"
        );
        self.object("commit", body.as_bytes())
    }
    fn object(&self, kind: &str, bytes: &[u8]) -> ObjectId {
        let out = self.git(&["hash-object", "-w", "--stdin", "-t", kind], bytes);
        ObjectId::from_hex(out.trim_ascii()).unwrap()
    }
    fn init(&self) {
        self.git(&["init", "--bare", "-q", "--initial-branch=main"], b"");
        self.object("tree", b"");
    }
    fn refs(&self, head: ObjectId, upstream: ObjectId) {
        self.write("HEAD", b"ref: refs/heads/main\n");
        self.write("refs/heads/main", head.to_string());
        self.write("refs/remotes/origin/main", upstream.to_string());
        self.write("config", b"[core]\nrepositoryformatversion=0\nbare=true\n[branch \"main\"]\nremote=origin\nmerge=refs/heads/main\n[remote \"origin\"]\nfetch=+refs/heads/*:refs/remotes/origin/*\nurl=https://invalid.example/repo\n");
    }
    fn linear(&self, count: u32) {
        let mut input = Vec::new();
        for n in 1..=count {
            input.extend(format!("commit refs/heads/main\nmark :{n}\ncommitter F <f@example.org> 1700000000 +0000\ndata {}\n{n}\n", n.to_string().len()).bytes());
            if n > 1 {
                input.extend(format!("from :{}\n", n - 1).bytes());
            } else {
                input.extend(b"from 0000000000000000000000000000000000000000\n");
            }
            input.extend(b"deleteall\n\n");
        }
        self.git(&["fast-import", "--quiet", "--force"], &input);
        let tip = self.git(&["rev-parse", "refs/heads/main"], b"");
        let base = self.git(&["rev-parse", &format!("main~{}", count / 2)], b"");
        self.refs(
            ObjectId::from_hex(tip.trim_ascii()).unwrap(),
            ObjectId::from_hex(base.trim_ascii()).unwrap(),
        );
    }
    fn graph(&self) -> (ObjectId, ObjectId) {
        self.init();
        let base = self.commit(&[], "base");
        let a = self.commit(&[base], "a");
        let b = self.commit(&[base], "b");
        let a2 = self.commit(&[a], "a2");
        self.refs(a2, b);
        (a2, b)
    }
    fn five_mb_pack(&self) -> (ObjectId, u64) {
        let (head, _) = self.graph();
        // Deterministic incompressible padding, reachable but never inflated by C.
        let mut state = 0x1234_5678u32;
        let bytes: Vec<u8> = (0..5_000_000)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 17;
                state ^= state << 5;
                state as u8
            })
            .collect();
        let blob = self.object("blob", &bytes);
        self.write("refs/tags/padding", blob.to_string());
        self.git(&["repack", "-adq"], b"");
        self.git(&["multi-pack-index", "write"], b"");
        let size = fs::read_dir(self.0.join("objects/pack"))
            .unwrap()
            .map(Result::unwrap)
            .filter(|e| {
                let name = e.file_name();
                let name = name.as_bytes();
                name.ends_with(b".idx") || name.ends_with(b".pack") || name == b"multi-pack-index"
            })
            .map(|e| e.metadata().unwrap().len())
            .sum();
        assert!((5_000_000..5_100_000).contains(&size), "{size}");
        (head, size)
    }

    fn packed_refs(&self, count: u32, head: ObjectId, upstream: ObjectId) -> usize {
        let mut bytes = format!(
            "{head} refs/heads/main\n{upstream} refs/remotes/origin/main\n{head} refs/stash\n"
        );
        for n in 3..count {
            bytes += &format!("{head} refs/tags/{n:04}\n");
        }
        self.write("packed-refs", &bytes);
        for name in ["refs/heads/main", "refs/remotes/origin/main", "refs/stash"] {
            let _ = fs::remove_file(self.0.join(name));
        }
        bytes.len()
    }
}

// Lend the SAME request meter to a short stage without resetting any counters.
fn with_stage<T>(m: &RefCell<Meter>, ms: u64, run: impl FnOnce() -> T) -> T {
    let placeholder = m.borrow().expired_placeholder();
    let mut request = m.replace(placeholder);
    let result = request.stage(ms, |request| {
        let placeholder = request.expired_placeholder();
        m.replace(std::mem::replace(request, placeholder));
        let result = run();
        *request = m.replace(request.expired_placeholder());
        result
    });
    m.replace(request);
    result
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn port<'a>(root: &'a Root, access: &'a Access, meter: &'a RefCell<Meter>) -> RepoIo<'a> {
    RepoIo::new(
        RepoRoots {
            worktree: root,
            gitdir: root,
            commondir: root,
        },
        access,
        meter,
    )
}
fn repository<'a>(
    root: &'a Root,
    access: &'a Access,
    meter: &'a RefCell<Meter>,
) -> GuardedRepository<'a> {
    GuardedRepository::new(
        port(root, access, meter),
        &git::refs::RefSnapshot::default(),
    )
    .unwrap()
}
fn value(r: StageResult) -> Value {
    match r {
        StageResult::Partial(v) | StageResult::Value(v) => v,
        StageResult::Hidden => panic!("hidden history"),
    }
}
fn field<'a>(v: &'a Value, name: &str) -> &'a Field {
    &v.fields[field::BUILTIN[3].field_index(name).unwrap()]
}
fn pending(r: StageResult) {
    assert!(matches!(r, StageResult::Partial(_)));
    let v = value(r);
    assert_eq!(field(&v, "ahead"), &Field::PENDING);
    assert_eq!(field(&v, "behind"), &Field::PENDING);
}
fn line(message: usize) -> Vec<u8> {
    let mut b = format!(
        "{} {} F <f@example.org> 1700000000 +0000\t",
        "0".repeat(40),
        "1".repeat(40)
    )
    .into_bytes();
    b.extend(vec![b'x'; message]);
    b.push(b'\n');
    b
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
// Fails if either reachable set is counted before both traversals finish.
#[test]
fn divergence_matches_local_rev_list() {
    let f = Fixture::new();
    let (a, b) = f.graph();
    let merge = f.commit(&[a, b], "merge");
    let unrelated = f.commit(&[], "unrelated");
    for packed in [false, true] {
        if packed {
            f.git(&["repack", "-adq"], b"");
            f.git(&["multi-pack-index", "write"], b"");
        }
        for (left, right) in [(a, b), (a, a), (merge, b), (a, unrelated)] {
            f.refs(left, right);
            if packed {
                f.git(&["pack-refs", "--all", "--prune"], b"");
            }
            let oracle = f.git(
                &[
                    "rev-list",
                    "--left-right",
                    "--count",
                    "HEAD...refs/remotes/origin/main",
                ],
                b"",
            );
            let expected: Vec<u32> = std::str::from_utf8(&oracle)
                .unwrap()
                .split_whitespace()
                .map(|n| n.parse().unwrap())
                .collect();
            let root = f.root();
            let access = access();
            let m = RefCell::new(meter());
            let repo = repository(&root, &access, &m);
            assert_eq!(divergence(&repo), Ok(Some((expected[0], expected[1]))));
            let v = value(stage_c(&repo));
            assert_eq!(
                field(&v, "ahead"),
                &Field::known(FieldValue::Count {
                    n: expected[0],
                    saturated: false
                })
            );
            assert_eq!(
                field(&v, "behind"),
                &Field::known(FieldValue::Count {
                    n: expected[1],
                    saturated: false
                })
            );
            assert_eq!(m.borrow().budget.used(Axis::MappedBytes), 0);
        }
    }
}

// Fails if a missing branch.remote is guessed as origin, or configured errors
// are turned into absence. Worktree overrides apply only when enabled.
#[test]
fn upstream_absence_and_local_ref_failures_are_distinct() {
    let f = Fixture::new();
    let (a, b) = f.graph();
    let root = f.root();
    let access = access();
    for (config, expected) in [
        ("[core]\nbare=true\n", Ok(None)),
        (
            "[branch \"main\"]\nremote=.\nmerge=refs/remotes/origin/main\n",
            Ok(Some((2, 1))),
        ),
        (
            "[branch \"main\"]\nremote=.\nmerge=refs/heads/missing\n",
            Err(E::Missing),
        ),
        (
            "[branch \"main\"]\nremote\nmerge=refs/heads/main\n",
            Err(INVALID),
        ),
        (
            "[branch \"main\"]\nremote=.\nmerge=../../outside\n",
            Err(INVALID),
        ),
        (
            "[branch \"main\"]\nremote=origin\nmerge=refs/heads/main\n[remote \"origin\"]\nfetch=+refs/heads/*:refs/remotes/origin/*\nfetch=^refs/heads/main\n",
            Err(INVALID),
        ),
        (
            "[branch \"main\"]\nremote=origin\nmerge=refs/heads/main\n[remote \"origin\"]\nfetch=refs/heads/main:refs/remotes/origin/main\n",
            Ok(Some((2, 1))),
        ),
        (
            "[branch \"main\"]\nmerge=refs/heads/main\n[remote \"origin\"]\nfetch=+refs/heads/*:refs/remotes/origin/*\n",
            Ok(None),
        ),
    ] {
        f.write("config", config);
        let m = RefCell::new(meter());
        let repo = repository(&root, &access, &m);
        assert_eq!(divergence(&repo), expected, "{config}");
        if expected.is_err() {
            pending(stage_c(&repo));
        }
        if expected == Ok(None) {
            assert_eq!(field(&value(stage_c(&repo)), "ahead"), &Field::ABSENT);
        }
    }
    for active in [false, true] {
        f.refs(a, b);
        let mut config = fs::read(f.0.join("config")).unwrap();
        config.extend(format!("[extensions]\nworktreeConfig={active}\n").bytes());
        f.write("config", config);
        f.write("config.worktree", b"[branch \"main\"]\nremote=.\n");
        let m = RefCell::new(meter());
        let repo = repository(&root, &access, &m);
        assert_eq!(
            divergence(&repo),
            Ok(Some(if active { (0, 0) } else { (2, 1) }))
        );
    }
    f.refs(a, b);
    f.write("refs/remotes/origin/main", b"broken\n");
    let m = RefCell::new(meter());
    let repo = repository(&root, &access, &m);
    assert_eq!(divergence(&repo), Err(INVALID));
    pending(stage_c(&repo));
    f.write("HEAD", a.to_string());
    let m = RefCell::new(meter());
    let repo = repository(&root, &access, &m);
    assert_eq!(divergence(&repo), Ok(None));
}

// Fails if either include spelling is ignored, even when no upstream is local.
#[test]
fn config_includes_make_effective_upstream_unknown() {
    let f = Fixture::new();
    let (a, b) = f.graph();
    let root = f.root();
    let access = access();
    for section in [
        "include",
        "includeIf \"onbranch:main\"",
        "InClUdE",
        "InClUdEiF \"onbranch:other\"",
    ] {
        for location in ["config", "config.worktree"] {
            for with_path in [false, true] {
                f.refs(a, b);
                f.write("config.worktree", b"");
                let mut bytes = fs::read(f.0.join(location)).unwrap();
                bytes.extend(format!("[{section}]\n").bytes());
                if with_path {
                    bytes.extend(b"path=/outside/must-not-be-opened\n");
                }
                f.write(location, bytes);
                let m = RefCell::new(meter());
                let repo = repository(&root, &access, &m);
                assert_eq!(
                    divergence(&repo),
                    Err(git::io::UNSUPPORTED),
                    "{location}: {section}"
                );
                pending(stage_c(&repo));
                assert_eq!(m.borrow().budget.used(Axis::Commits), 0);
            }
        }
    }
    f.write("config", b"[include]\n");
    f.write("config.worktree", b"");
    let m = RefCell::new(meter());
    pending(stage_c(&repository(&root, &access, &m)));
}

// A synthetic Find is necessary for cycles: verified SHA-1 objects cannot be
// constructed with a self-referential hash without a preimage attack.
struct Synthetic {
    count: u32,
    cycle: bool,
}
fn id(n: u32) -> ObjectId {
    ObjectId::from_hex(
        format!(
            "{:016x}{n:024x}",
            u64::from(n).wrapping_mul(0x9e37_79b9_7f4a_7c15)
        )
        .as_bytes(),
    )
    .unwrap()
}
impl gix_object::Find for Synthetic {
    fn try_find<'a>(
        &self,
        oid: &gix_index::hash::oid,
        buffer: &'a mut Vec<u8>,
    ) -> gix_error::ExnResult<Option<gix_object::Data<'a>>> {
        let n = u32::from_str_radix(&oid.to_string()[32..], 16).unwrap();
        if n == 0 || n > self.count {
            return Ok(None);
        }
        buffer.clear();
        buffer.extend(b"tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\n");
        if n > 1 || self.cycle {
            buffer.extend(
                format!("parent {}\n", id(if n == 1 { self.count } else { n - 1 })).bytes(),
            );
        }
        buffer.extend(b"author F <f@e.org> 1 +0000\ncommitter F <f@e.org> 1 +0000\n\nx\n");
        Ok(Some(gix_object::Data {
            kind: gix_object::Kind::Commit,
            object_hash: gix_index::hash::Kind::Sha1,
            data: buffer,
        }))
    }
}
#[test]
fn incomplete_graph_has_no_false_lower_bound() {
    let f = Fixture::new();
    let (a, b) = f.graph();
    let root = f.root();
    let access = access();
    f.write("shallow", a.to_string());
    let m = RefCell::new(meter());
    let repo = repository(&root, &access, &m);
    assert_eq!(divergence(&repo), Err(git::io::UNSUPPORTED));
    pending(stage_c(&repo));
    assert_eq!(m.borrow().budget.used(Axis::Commits), 0);
    fs::remove_file(f.0.join("shallow")).unwrap();
    for axis in [Axis::Commits, Axis::DecompressedBytes] {
        let m = RefCell::new(meter());
        let repo = repository(&root, &access, &m);
        m.borrow_mut().charge_axis(axis, axis.limit()).unwrap();
        assert_eq!(divergence(&repo), Err(E::Limit));
        pending(stage_c(&repo));
    }
    let missing = id(0xabcdef);
    let broken = f.commit(&[missing], "missing parent");
    f.refs(broken, b);
    let m = RefCell::new(meter());
    let repo = repository(&root, &access, &m);
    assert_eq!(divergence(&repo), Err(E::Missing));
    pending(stage_c(&repo));
    let m = RefCell::new(meter());
    let io = port(&root, &access, &m);
    assert_eq!(
        walk(
            &io,
            &Synthetic {
                count: 3,
                cycle: true
            },
            id(3),
            id(2)
        ),
        Err(INVALID)
    );
    f.refs(a, b);
    let name = a.to_string();
    let path = format!("objects/{}/{}", &name[..2], &name[2..]);
    fs::remove_file(f.0.join(&path)).unwrap();
    f.write(&path, b"corrupt");
    let m = RefCell::new(meter());
    let repo = repository(&root, &access, &m);
    assert_eq!(divergence(&repo), Err(INVALID));
    pending(stage_c(&repo));
}

#[test]
fn graph_budget_is_unique_cumulative_and_scratch_is_live() {
    let f = Fixture::new();
    let root = f.root();
    let access = access();
    let m = RefCell::new(meter());
    let io = port(&root, &access, &m);
    let before = m.borrow().live_allocated();
    let ((result, charged), alloc) = allocation::measure(|| {
        let before = m.borrow().counts[2].allocated;
        let result = walk(
            &io,
            &Synthetic {
                count: 10_000,
                cycle: false,
            },
            id(10_000),
            id(5000),
        );
        (result, m.borrow().counts[2].allocated - before)
    });
    assert_eq!(result, Ok((5000, 0)));
    assert_eq!(m.borrow().budget.used(Axis::Commits), 10_000);
    assert_eq!(m.borrow().live_allocated(), before);
    assert!(alloc.peak as u64 <= charged, "{alloc:?} reserved={charged}");
    assert_eq!(
        walk(
            &io,
            &Synthetic {
                count: 1,
                cycle: false
            },
            id(1),
            id(1)
        ),
        Err(E::Limit)
    );
    eprintln!("history graph 10000: peak={} charged={charged}", alloc.peak);
}

#[test]
fn stash_reflog_boundary_is_exact() {
    let f = Fixture::new();
    f.stash_ref();
    let root = f.root();
    let access = access();
    let sample = line(1);
    let capline = line(budget::REFLOG_BYTES as usize - line(0).len());
    let cases = [
        (Vec::new(), Ok((0, false))),
        (sample.repeat(1024), Ok((1024, false))),
        (sample.repeat(1025), Ok((1024, true))),
        (capline.clone(), Ok((1, false))),
        ([capline.as_slice(), b"x"].concat(), Ok((1, true))),
        ([sample.as_slice(), b"malformed\n"].concat(), Ok((1, true))),
        (
            [sample.as_slice(), &sample[..sample.len() - 1]].concat(),
            Ok((1, true)),
        ),
        (sample[..sample.len() - 1].to_vec(), Err(INVALID)),
        (b"bad\n".to_vec(), Err(INVALID)),
    ];
    let m = RefCell::new(meter());
    assert_eq!(
        stash(
            &port(&root, &access, &m),
            &git::refs::RefSnapshot::default()
        ),
        Ok((0, false))
    );
    for (bytes, expected) in cases {
        f.write("logs/refs/stash", &bytes);
        let m = RefCell::new(meter());
        assert_eq!(
            stash(
                &port(&root, &access, &m),
                &git::refs::RefSnapshot::default()
            ),
            expected,
            "len={}",
            bytes.len()
        );
        assert_eq!(m.borrow().budget.used(Axis::WorktreeReadBytes), 0);
        assert!(m.borrow().counts[2].read_bytes <= budget::REFLOG_BYTES + 1 + 40);
        assert_eq!(m.borrow().live_allocated(), 0);
        if bytes == capline {
            assert_eq!(m.borrow().counts[2].read, 19);
            assert_eq!(
                m.borrow().budget.used(Axis::ReflogBytes),
                budget::REFLOG_BYTES
            );
        }
    }
}

// Removing the ref check reports a stale reflog; ignoring packed-refs loses a
// real stash. An absent/empty reflog must not parse hostile packed-refs at all.
#[test]
fn stash_requires_a_loose_or_packed_ref() {
    let f = Fixture::new();
    let (head, _) = f.graph();
    let root = f.root();
    let access = access();
    let entry = String::from_utf8(line(1))
        .unwrap()
        .replace(&"1".repeat(40), &head.to_string());
    f.write("logs/refs/stash", entry.repeat(2));
    for packed in [false, true] {
        if packed {
            f.write("refs/stash", head.to_string());
            f.git(&["pack-refs", "--all", "--prune"], b"");
            assert!(!f.0.join("refs/stash").exists());
        }
        let oracle = f.git(
            &[
                "--work-tree",
                f.0.to_str().unwrap(),
                "stash",
                "list",
                "--format=%H",
            ],
            b"",
        );
        let count = oracle
            .split(|b| *b == b'\n')
            .filter(|s| !s.is_empty())
            .count() as u32;
        assert_eq!(count, if packed { 2 } else { 0 });
        let m = RefCell::new(meter());
        assert_eq!(
            stash(
                &port(&root, &access, &m),
                &git::refs::RefSnapshot::default()
            ),
            Ok((count, false))
        );
    }
    f.write("packed-refs", b"malformed\n");
    let m = RefCell::new(meter());
    assert_eq!(
        stash(
            &port(&root, &access, &m),
            &git::refs::RefSnapshot::default()
        ),
        Err(INVALID)
    );
    for empty in [true, false] {
        if empty {
            f.write("logs/refs/stash", b"");
        } else {
            fs::remove_file(f.0.join("logs/refs/stash")).unwrap();
        }
        let m = RefCell::new(meter());
        assert_eq!(
            stash(
                &port(&root, &access, &m),
                &git::refs::RefSnapshot::default()
            ),
            Ok((0, false))
        );
        assert_eq!(m.borrow().budget.used(Axis::RefBytes), 0);
        assert_eq!(m.borrow().budget.used(Axis::RefEntries), 0);
    }
}

#[test]
fn stash_uses_one_fd_and_rejects_unsafe_or_changed_files() {
    let f = Fixture::new();
    f.stash_ref();
    let outside = Fixture::new();
    let root = f.root();
    let access = access();
    f.write("logs/refs/stash", line(1));
    outside.write("canary", line(50).repeat(30));
    fs::remove_file(f.0.join("logs/refs/stash")).unwrap();
    symlink(outside.0.join("canary"), f.0.join("logs/refs/stash")).unwrap();
    let m = RefCell::new(meter());
    assert_eq!(
        stash(
            &port(&root, &access, &m),
            &git::refs::RefSnapshot::default()
        ),
        Err(E::Escape)
    );
    assert_eq!(m.borrow().counts[2].read_bytes, 0);
    fs::remove_file(f.0.join("logs/refs/stash")).unwrap();
    f.write("logs/refs/stash", line(1));
    fs::hard_link(f.0.join("logs/refs/stash"), f.0.join("hard")).unwrap();
    let m = RefCell::new(meter());
    assert_eq!(
        stash(
            &port(&root, &access, &m),
            &git::refs::RefSnapshot::default()
        ),
        Err(E::Special)
    );
    assert_eq!(m.borrow().counts[2].read_bytes, 0);
    fs::remove_file(f.0.join("hard")).unwrap();
    let path = f.0.join("logs/refs/stash");
    let canary = outside.0.join("canary");
    let mut fired = false;
    let mut m = meter();
    m.hook = Some(Box::new(move |event| {
        if event == "before_reflog_read" && !fired {
            fired = true;
            fs::rename(&path, path.with_extension("old")).unwrap();
            symlink(&canary, &path).unwrap();
        }
    }));
    let m = RefCell::new(m);
    let result = stash(
        &port(&root, &access, &m),
        &git::refs::RefSnapshot::default(),
    );
    // Linux may preserve a coarse timestamp across rename; both outcomes read
    // only the old held fd, never the replacement's thirty lines.
    assert!(
        matches!(result, Ok((1, false)) | Err(E::Changed)),
        "{result:?}"
    );
    assert_eq!(m.borrow().counts[2].read_bytes, line(1).len() as u64 + 40);
}

#[test]
fn object_budgets_accumulate_between_b_and_c() {
    let f = Fixture::new();
    let (a, _) = f.graph();
    f.git(&["repack", "-adq"], b"");
    f.git(&["multi-pack-index", "write"], b"");
    let root = f.root();
    let access = access();
    for axis in [
        Axis::Packs,
        Axis::PackBytes,
        Axis::DecompressedBytes,
        Axis::Commits,
    ] {
        let m = RefCell::new(meter());
        let repo = repository(&root, &access, &m);
        let db = repo.objects(&repo.io);
        let mut buffer = Vec::new();
        assert!(db.find(&a, &mut buffer).unwrap().is_some());
        drop(db);
        let before = m.borrow().budget.used(axis);
        m.borrow_mut()
            .charge_axis(axis, axis.limit() - before)
            .unwrap();
        // Pack axes were charged at B's load; C only consumes new inflate and
        // commit work. Removing shared snapshots makes these pack cases fail.
        if matches!(axis, Axis::Packs | Axis::PackBytes) {
            assert_eq!(divergence(&repo), Ok(Some((2, 1))), "{axis:?}");
        } else {
            assert_eq!(divergence(&repo), Err(E::Limit), "{axis:?}");
            pending(stage_c(&repo));
        }
        assert_eq!(m.borrow().budget.used(axis), axis.limit());
    }
    f.write("objects/pack/multi-pack-index", b"bad");
    let m = RefCell::new(meter());
    let repo = repository(&root, &access, &m);
    assert_eq!(divergence(&repo), Err(INVALID));
}

// Fails if C constructs its own pack store, charges a second load, or holds the
// shared meter borrow during I/O. B uses the same public adapter entry as D1a.
#[test]
fn b_then_c_reuses_one_five_mb_pack_snapshot() {
    let f = Fixture::new();
    let (head, pack_bytes) = f.five_mb_pack();
    let root = f.root();
    let access = access();
    let mut results = Vec::new();
    for b_first in [false, true] {
        let m = RefCell::new(meter());
        let repo = repository(&root, &access, &m);
        assert_eq!(m.borrow().budget.used(Axis::PackBytes), 0);
        if b_first {
            let db = repo.objects(&repo.io);
            assert!(db.find(&head, &mut Vec::new()).unwrap().is_some());
            assert_eq!(m.borrow().budget.used(Axis::PackBytes), pack_bytes);
        }
        results.push(divergence(&repo));
        assert_eq!(m.borrow().budget.used(Axis::Packs), 1);
        assert_eq!(m.borrow().budget.used(Axis::PackBytes), pack_bytes);
        assert_eq!(m.borrow().budget.used(Axis::MappedBytes), 0);
    }
    assert_eq!(results, [Ok(Some((2, 1))), Ok(Some((2, 1)))]);
}

// Caching B's Deadline poisons C despite its remaining 30-second allowance.
// Resetting the meter on retry also fails the cumulative PackBytes assertion.
#[test]
fn pack_load_deadline_in_b_does_not_poison_c() {
    let f = Fixture::new();
    let (head, _) = f.graph();
    f.git(&["repack", "-adq"], b"");
    let pack_bytes: u64 = fs::read_dir(f.0.join("objects/pack"))
        .unwrap()
        .map(|entry| entry.unwrap())
        .filter(|entry| {
            entry
                .path()
                .extension()
                .is_some_and(|e| e == "idx" || e == "pack")
        })
        .map(|entry| entry.metadata().unwrap().len())
        .sum();
    let root = f.root();
    let access = access();
    let m = RefCell::new(meter());
    let repo = repository(&root, &access, &m);
    let fired = std::rc::Rc::new(std::cell::Cell::new(false));
    let hook_fired = fired.clone();
    m.borrow_mut().hook = Some(Box::new(move |event| {
        if event == "before_read" && !hook_fired.replace(true) {
            std::thread::sleep(Duration::from_millis(80));
        }
    }));
    let result = with_stage(&m, 50, || {
        repo.objects(&repo.io)
            .find(&head, &mut Vec::new())
            .map(|_| ())
    });
    assert_eq!(result, Err(E::Deadline));
    assert!(fired.get());
    let spent = m.borrow().budget.used(Axis::PackBytes);
    assert!(spent > 0, "deadline must occur inside pack loading");
    m.borrow_mut().hook = None;
    assert_eq!(m.borrow().check(), Ok(()));
    assert_eq!(divergence(&repo), Ok(Some((2, 1))));
    assert_eq!(m.borrow().budget.used(Axis::PackBytes), spent + pack_bytes);
    let alone = RefCell::new(meter());
    assert_eq!(
        divergence(&repository(&root, &access, &alone)),
        Ok(Some((2, 1)))
    );
    assert_eq!(alone.borrow().budget.used(Axis::PackBytes), pack_bytes);
}

// Retrying any of these failures after repairing the file would cross the
// request snapshot boundary; disabling error caching makes this test fail.
#[test]
fn pack_snapshot_keeps_deterministic_load_failures() {
    use std::os::unix::fs::PermissionsExt;
    let f = Fixture::new();
    let (head, _) = f.graph();
    f.git(&["repack", "-adq"], b"");
    let index = fs::read_dir(f.0.join("objects/pack"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| p.extension().is_some_and(|e| e == "idx"))
        .unwrap();
    let index_bytes = fs::read(&index).unwrap();
    fs::set_permissions(&index, fs::Permissions::from_mode(0o600)).unwrap();
    let root = f.root();
    let access = access();
    for expected in [E::Limit, E::Changed, INVALID] {
        let m = RefCell::new(meter());
        let repo = repository(&root, &access, &m);
        if expected == E::Limit {
            m.borrow_mut()
                .charge_axis(Axis::PackBytes, budget::PACK_BYTES)
                .unwrap();
        } else if expected == E::Changed {
            let path = index.clone();
            m.borrow_mut().hook = Some(Box::new(move |event| {
                if event == "before_read" {
                    fs::write(&path, b"x").unwrap();
                }
            }));
        } else {
            f.write("objects/pack/multi-pack-index", b"bad");
        }
        assert_eq!(
            repo.objects(&repo.io)
                .find(&head, &mut Vec::new())
                .map(|_| ()),
            Err(expected)
        );
        m.borrow_mut().hook = None;
        fs::write(&index, &index_bytes).unwrap();
        let _ = fs::remove_file(f.0.join("objects/pack/multi-pack-index"));
        let before = m.borrow().counts[2];
        let c = repo.io.next_stage();
        assert_eq!(
            repo.objects(&c).find(&head, &mut Vec::new()).map(|_| ()),
            Err(expected)
        );
        assert_eq!(m.borrow().counts[2], before);
    }
}

// Fresh snapshots in any of preflight/new/D exceed the 4,096-entry budget.
// Charging cached entries/bytes again also fails these exact accounting checks.
#[test]
fn three_thousand_packed_refs_are_shared_by_preflight_b_c_and_d() {
    let work = Fixture::new();
    let f = Fixture(work.0.join(".git"));
    fs::create_dir(&f.0).unwrap();
    let (head, upstream) = f.graph();
    let bytes = f.packed_refs(3000, head, upstream) as u64;
    f.write("logs/refs/stash", line(1).repeat(2));
    let mut m = meter();
    let roots = git::discover::discover_with_access(&request(&work), access(), &mut m)
        .unwrap()
        .unwrap();
    let parses = std::rc::Rc::new(std::cell::Cell::new(0));
    let hook_parses = parses.clone();
    m.hook = Some(Box::new(move |event| {
        if event == "before_packed_parse" {
            hook_parses.set(hook_parses.get() + 1);
        }
    }));
    let before_bytes = m.budget.used(Axis::RefBytes);
    assert_eq!(
        git::preflight::preflight(&roots, &mut m).unwrap(),
        git::preflight::GitAccess::Objects
    );
    assert_eq!(m.budget.used(Axis::RefEntries), 3002); // one parse + HEAD symref hops
    let m = RefCell::new(m);
    let repo = GuardedRepository::from_roots(&roots, &m).unwrap();
    assert_eq!(m.borrow().budget.used(Axis::RefEntries), 3002);
    assert!(
        repo.objects(&repo.io)
            .find(&head, &mut Vec::new())
            .unwrap()
            .is_some()
    );
    assert_eq!(divergence(&repo), Ok(Some((2, 1))));
    let d = git::stage_d::stage_d(&roots, roots.ref_snapshot(), &m);
    assert!(matches!(d, StageResult::Value(_)));
    assert_eq!(
        field(&value(d), "stash"),
        &Field::known(FieldValue::Count {
            n: 2,
            saturated: false
        })
    );
    assert_eq!(parses.get(), 1);
    // Loose lookups still charge their real work: HEAD twice, main twice,
    // upstream and stash once. Only the packed parse is charged once.
    assert_eq!(m.borrow().budget.used(Axis::RefEntries), 3005);
    assert_eq!(
        m.borrow().budget.used(Axis::RefBytes) - before_bytes,
        bytes + 2 * b"ref: refs/heads/main\n".len() as u64
    );
}

// Caching Deadline prevents retry; dropping deterministic failures retries I/O.
#[test]
fn refs_snapshot_retries_only_deadline_and_keeps_real_charges() {
    let f = Fixture::new();
    f.write(
        "packed-refs",
        format!("{} refs/heads/main\n", "1".repeat(40)),
    );
    let root = f.root();
    let access = access();
    let m = RefCell::new(meter());
    let refs = RefSnapshot::default();
    let mut fired = false;
    m.borrow_mut().hook = Some(Box::new(move |event| {
        if event == "before_read" && !fired {
            fired = true;
            std::thread::sleep(Duration::from_millis(80));
        }
    }));
    assert_eq!(
        with_stage(&m, 50, || refs.load(&port(&root, &access, &m)).err()),
        Some(E::Deadline)
    );
    let spent = m.borrow().budget.used(Axis::RefBytes);
    assert!(spent > 0);
    m.borrow_mut().hook = None;
    refs.load(&port(&root, &access, &m)).unwrap();
    assert_eq!(m.borrow().budget.used(Axis::RefBytes), 2 * spent);
    assert_eq!(m.borrow().budget.used(Axis::RefEntries), 1);
    for expected in [E::Limit, E::Changed, INVALID] {
        let m = RefCell::new(meter());
        let refs = RefSnapshot::default();
        if expected == E::Limit {
            m.borrow_mut()
                .charge_axis(Axis::RefEntries, budget::REF_ENTRIES)
                .unwrap();
        } else if expected == INVALID {
            f.write("packed-refs", b"malformed\n");
        } else {
            let path = f.0.join("packed-refs");
            m.borrow_mut().hook = Some(Box::new(move |event| {
                if event == "before_read" {
                    fs::write(&path, b"x").unwrap();
                }
            }));
        }
        assert_eq!(refs.load(&port(&root, &access, &m)).err(), Some(expected));
        m.borrow_mut().hook = None;
        f.write("packed-refs", b"");
        let before = m.borrow().counts[2];
        assert_eq!(refs.load(&port(&root, &access, &m)).err(), Some(expected));
        assert_eq!(m.borrow().counts[2], before);
        f.write(
            "packed-refs",
            format!("{} refs/heads/main\n", "1".repeat(40)),
        );
    }
}

// Fails if grafts are ignored, or if a dangling symlink is followed as missing.
#[test]
fn info_grafts_makes_divergence_pending() {
    let f = Fixture::new();
    let (a, b) = f.graph();
    f.write("info/grafts", format!("{a} {b}\n"));
    let root = f.root();
    let access = access();
    let m = RefCell::new(meter());
    let repo = repository(&root, &access, &m);
    assert_eq!(
        f.git(
            &[
                "rev-list",
                "--left-right",
                "--count",
                "HEAD...refs/remotes/origin/main"
            ],
            b""
        )
        .trim_ascii(),
        b"1\t0"
    );
    assert_eq!(divergence(&repo), Err(git::io::UNSUPPORTED));
    pending(stage_c(&repo));
    fs::remove_file(f.0.join("info/grafts")).unwrap();
    assert_eq!(divergence(&repo), Ok(Some((2, 1))));
    for kind in ["empty", "directory", "symlink", "fifo"] {
        let path = f.0.join("info/grafts");
        match kind {
            "empty" => f.write("info/grafts", b""),
            "directory" => fs::create_dir(&path).unwrap(),
            "symlink" => symlink("missing", &path).unwrap(),
            "fifo" => {
                let path = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
                // SAFETY: a valid test-owned path, no descriptor is opened.
                assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
            }
            _ => unreachable!(),
        }
        let m = RefCell::new(meter());
        let repo = repository(&root, &access, &m);
        assert_eq!(divergence(&repo), Err(git::io::UNSUPPORTED), "{kind}");
        pending(stage_c(&repo));
        if kind == "directory" {
            fs::remove_dir(path).unwrap();
        } else {
            fs::remove_file(path).unwrap();
        }
    }
}

#[test]
fn stage_c_never_reads_commit_graph() {
    let f = Fixture::new();
    f.graph();
    let root = f.root();
    let access = access();
    let run = || {
        let m = RefCell::new(meter());
        let repo = repository(&root, &access, &m);
        assert_eq!(divergence(&repo), Ok(Some((2, 1))));
        let m = m.into_inner();
        assert_eq!(m.budget.used(Axis::MappedBytes), 0);
        m.counts
    };
    let before = run();
    f.git(&["commit-graph", "write", "--reachable"], b"");
    assert_eq!(run(), before);
    fs::remove_file(f.0.join("objects/info/commit-graph")).unwrap();
    f.write("objects/info/commit-graph", b"corrupt");
    assert_eq!(run(), before);
    fs::OpenOptions::new()
        .write(true)
        .open(f.0.join("objects/info/commit-graph"))
        .unwrap()
        .set_len(1 << 30)
        .unwrap();
    assert_eq!(run(), before);
    f.write(
        "objects/info/commit-graphs/commit-graph-chain",
        b"corrupt chain\n",
    );
    assert_eq!(run(), before);
}

// Interpose actual I/O, process and network functions. The normal safe syscall
// hook permits only adapter I/O; commit-graph path opens are forbidden even
// inside that hook. Deliberate open/spawn/socket mutations prove the detector.
#[test]
fn history_never_contacts_remote() {
    if let Ok(mode) = std::env::var("BINGSU_D2_CHILD") {
        detector_child(&mode);
        return;
    }
    let f = Fixture::new();
    let library = f.0.join("history-detector.so");
    let mut source = include_str!("support/io_detector.c").to_owned();
    source=source.replace("#include <dlfcn.h>","#include <dlfcn.h>\n#include <string.h>\n#include <spawn.h>\n#include <sys/socket.h>\n#include <stdlib.h>");
    source=source.replace("static void detect(void)","static void path_check(const char *p) { if (armed && strstr(p, \"commit-graph\")) _exit(87); }\nstatic void detect(void)");
    for (old, new) in [
        (
            "DECL_REAL(int,open,(const char *,int,...)) detect();",
            "DECL_REAL(int,open,(const char *,int,...)) path_check(path); detect();",
        ),
        (
            "DECL_REAL(int,openat,(int,const char *,int,...)) detect();",
            "DECL_REAL(int,openat,(int,const char *,int,...)) path_check(path); detect();",
        ),
        (
            "DECL_REAL(int,open64,(const char *,int,...)) detect();",
            "DECL_REAL(int,open64,(const char *,int,...)) path_check(path); detect();",
        ),
        (
            "DECL_REAL(int,openat64,(int,const char *,int,...)) detect();",
            "DECL_REAL(int,openat64,(int,const char *,int,...)) path_check(path); detect();",
        ),
        (
            "switch(number) {",
            "if (number == SYS_openat || number == SYS_openat2) path_check((const char *)a[1]);\n    switch(number) {",
        ),
    ] {
        assert_eq!(source.matches(old).count(), 1);
        source = source.replace(old, new);
    }
    source += r#"
#define EFFECT(ret,name,args,pass) \
ret EXPORTED(name) args { \
    DECL_REAL(ret,name,args) \
    if (armed) { \
        _exit(88); \
    } \
    return REAL(name) pass; \
} \
REPLACE(name)
EFFECT(int,socket,(int domain,int type,int protocol),(domain,type,protocol))
EFFECT(int,connect,(int fd,const struct sockaddr *addr,socklen_t len),(fd,addr,len))
EFFECT(int,execve,(const char *path,char *const argv[],char *const envp[]),(path,argv,envp))
EFFECT(int,posix_spawn,(pid_t *pid,const char *path,const posix_spawn_file_actions_t *actions,const posix_spawnattr_t *attrs,char *const argv[],char *const envp[]),(pid,path,actions,attrs,argv,envp))
EFFECT(int,posix_spawnp,(pid_t *pid,const char *path,const posix_spawn_file_actions_t *actions,const posix_spawnattr_t *attrs,char *const argv[],char *const envp[]),(pid,path,actions,attrs,argv,envp))
EFFECT(pid_t,fork,(void),())
EFFECT(int,system,(const char *command),(command))
EFFECT(FILE *,popen,(const char *command,const char *mode),(command,mode))
"#;
    f.write("detector.c", source);
    let mut cc = Command::new("cc");
    cc.args(["-Wall", "-Wextra", "-Werror", "-fPIC"]);
    #[cfg(target_os = "macos")]
    cc.arg("-dynamiclib");
    #[cfg(target_os = "linux")]
    cc.args(["-shared", "-ldl"]);
    let out = cc
        .arg(f.0.join("detector.c"))
        .arg("-o")
        .arg(&library)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    for (mode, code) in [
        ("history", 0),
        ("include", 0),
        ("graph", 87),
        ("spawn", 88),
        ("socket", 88),
    ] {
        let mut child = Command::new(std::env::current_exe().unwrap());
        child
            .args([
                "--exact",
                "history_never_contacts_remote",
                "--nocapture",
                "--test-threads=1",
            ])
            .env("BINGSU_D2_CHILD", mode);
        #[cfg(target_os = "macos")]
        child.env("DYLD_INSERT_LIBRARIES", &library);
        #[cfg(target_os = "linux")]
        child.env("LD_PRELOAD", &library);
        let out = child.output().unwrap();
        assert_eq!(
            out.status.code(),
            Some(code),
            "{mode}: {} {}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }
}
fn detector_child(mode: &str) {
    let f = Fixture::new();
    f.graph();
    f.stash_ref();
    f.write("logs/refs/stash", line(1));
    f.write("objects/info/commit-graph", b"hostile");
    let mut config = fs::read(f.0.join("config")).unwrap();
    config.extend(
        b"[core]\nsshCommand=/bin/false\nhooksPath=/outside\n[credential]\nhelper=!false\n",
    );
    if mode == "include" {
        config.extend(format!("[include]\npath={}\n", f.0.join("outside").display()).bytes());
    }
    f.write("config", config);
    let root = f.root();
    let access = access();
    let mut m = meter();
    fn symbol(name: &std::ffi::CStr) -> *mut libc::c_void {
        // SAFETY: constant C symbol name and the test interposer stays loaded.
        let p = unsafe { libc::dlsym(libc::RTLD_DEFAULT, name.as_ptr()) };
        assert!(!p.is_null());
        p
    }
    // SAFETY: exact C signatures in the generated test-only interposer.
    let arm = unsafe {
        std::mem::transmute::<*mut libc::c_void, extern "C" fn(i32)>(symbol(c"bingsu_io_arm"))
    };
    // SAFETY: exact C signatures in the generated test-only interposer.
    let permit = unsafe {
        std::mem::transmute::<*mut libc::c_void, extern "C" fn(i32)>(symbol(c"bingsu_io_permit"))
    };
    m.hook = Some(Box::new(move |event| match event {
        "before_safe_syscall" => permit(1),
        "after_safe_syscall" => permit(0),
        _ => (),
    }));
    let m = RefCell::new(m);
    arm(1);
    match mode {
        "graph" => {
            let _ = fs::read(f.0.join("objects/info/commit-graph"));
        }
        "spawn" => {
            let _ = Command::new("/bin/true").status();
        }
        "socket" => {
            // SAFETY: deliberately intercepted before the socket is created.
            unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
        }
        "history" | "include" => {
            let repo = repository(&root, &access, &m);
            let expected = if mode == "include" {
                Err(git::io::UNSUPPORTED)
            } else {
                Ok(Some((2, 1)))
            };
            assert_eq!(divergence(&repo), expected);
            assert_eq!(
                stash(&repo.io, &git::refs::RefSnapshot::default()),
                Ok((1, false))
            );
        }
        _ => panic!("unknown detector mode"),
    }
    arm(0);
}

#[test]
fn history_deadline_and_reflog_read_budget_are_independent() {
    let f = Fixture::new();
    f.stash_ref();
    f.graph();
    f.write("logs/refs/stash", line(1));
    let root = f.root();
    let access = access();
    let m = RefCell::new(meter());
    let repo = repository(&root, &access, &m);
    let old = m.replace(Meter::new(Instant::now()));
    let used = old.budget.used(Axis::RefBytes);
    assert_eq!(divergence(&repo), Err(E::Deadline));
    pending(stage_c(&repo));
    // A fresh stage port on the SAME restored meter can still do independent D.
    m.replace(old);
    assert_eq!(m.borrow().budget.used(Axis::RefBytes), used);
    assert_eq!(
        stash(
            &port(&root, &access, &m),
            &git::refs::RefSnapshot::default()
        ),
        Ok((1, false))
    );
    let m = RefCell::new(meter());
    m.borrow_mut()
        .charge_axis(Axis::WorktreeReadBytes, budget::WORKTREE_READ_BYTES)
        .unwrap();
    assert_eq!(
        stash(
            &port(&root, &access, &m),
            &git::refs::RefSnapshot::default()
        ),
        Ok((1, false))
    );
}

#[test]
#[ignore = "release warm 200-run observation; run explicitly"]
fn history_release_cost() {
    if cfg!(debug_assertions) {
        panic!("release measurement required");
    }
    let access = access();
    for case in [
        "c-loose",
        "c-packed",
        "c-absent",
        "d-absent",
        "d-empty",
        "d-orphan",
        "d-packed-ref",
        "c-grafts",
        "c-include",
        "d-1024",
        "d-byte-cap",
        "c-1000",
        "c-10000",
        "c-5mb",
        "c-after-b-5mb",
        "bc-5mb",
    ] {
        let f = Fixture::new();
        let (head, pack_bytes) = if case.ends_with("5mb") {
            let (head, size) = f.five_mb_pack();
            (head, Some(size))
        } else {
            (f.graph().0, None)
        };
        let root = f.root();
        if case == "c-grafts" {
            f.write("info/grafts", b"");
        }
        if case == "c-include" {
            f.write("config", b"[include]\npath=/outside\n");
        }
        if case == "d-empty" {
            f.write("logs/refs/stash", b"");
        }
        if case == "d-orphan" || case == "d-packed-ref" {
            f.write("logs/refs/stash", line(1));
        }
        if case == "d-packed-ref" {
            f.write("refs/stash", head.to_string());
            f.git(&["pack-refs", "--all", "--prune"], b"");
        }
        if case == "c-1000" {
            f.linear(1000);
        }
        if case == "c-10000" {
            f.linear(10000);
        }
        if case == "c-packed" {
            f.git(&["repack", "-adq"], b"");
            f.git(&["multi-pack-index", "write"], b"");
        }
        if case == "c-absent" {
            f.write("config", b"[core]\nbare=true\n");
        }
        if case == "d-1024" || case == "d-byte-cap" {
            f.stash_ref();
        }
        if case == "d-1024" {
            f.write("logs/refs/stash", line(1).repeat(1024));
        }
        if case == "d-byte-cap" {
            f.write(
                "logs/refs/stash",
                line(budget::REFLOG_BYTES as usize - line(0).len()),
            );
        }
        let mut samples = Vec::new();
        let mut observed = None;
        let mut axes = [0; 7];
        for i in 0..201 {
            let m = RefCell::new(meter());
            let refs = RefSnapshot::default();
            let repo = GuardedRepository::new(port(&root, &access, &m), &refs).unwrap();
            if case == "c-after-b-5mb" {
                assert!(
                    repo.objects(&repo.io)
                        .find(&head, &mut Vec::new())
                        .unwrap()
                        .is_some()
                );
            }
            let before = m.borrow().counts[2];
            let start = Instant::now();
            if case == "bc-5mb" {
                assert!(
                    repo.objects(&repo.io)
                        .find(&head, &mut Vec::new())
                        .unwrap()
                        .is_some()
                );
            }
            if matches!(case, "c-grafts" | "c-include") {
                assert_eq!(divergence(&repo), Err(git::io::UNSUPPORTED));
            } else if case.starts_with("c-") || case == "bc-5mb" {
                let expected = match case {
                    "c-absent" => None,
                    "c-1000" => Some((500, 0)),
                    "c-10000" => Some((5000, 0)),
                    _ => Some((2, 1)),
                };
                assert_eq!(divergence(&repo), Ok(expected));
            } else {
                assert_eq!(
                    stash(&repo.io, &refs),
                    Ok((
                        match case {
                            "d-absent" | "d-empty" | "d-orphan" => 0,
                            "d-1024" => 1024,
                            _ => 1,
                        },
                        false
                    ))
                );
            }
            let ns = start.elapsed().as_nanos();
            if let Some(bytes) = pack_bytes {
                assert_eq!(m.borrow().budget.used(Axis::PackBytes), bytes);
            }
            if i > 0 {
                samples.push(ns);
            } else {
                eprintln!("history cold {case}: {ns}ns");
            }
            let mut counts = m.borrow().counts[2];
            counts.open -= before.open;
            counts.stat -= before.stat;
            counts.read -= before.read;
            counts.read_bytes -= before.read_bytes;
            counts.allocated -= before.allocated;
            counts.mount -= before.mount;
            counts.filesystem -= before.filesystem;
            counts.readlink -= before.readlink;
            counts.list -= before.list;
            counts.components -= before.components;
            counts.raw_entries -= before.raw_entries;
            counts.retries -= before.retries;
            counts.readonly -= before.readonly;
            axes = [
                Axis::Commits,
                Axis::RefBytes,
                Axis::ReflogBytes,
                Axis::PackBytes,
                Axis::MappedBytes,
                Axis::DecompressedBytes,
                Axis::StashEntries,
            ]
            .map(|axis| m.borrow().budget.used(axis));
            observed = Some(counts);
        }
        eprintln!("history samples {case}: {samples:?}");
        eprintln!("history axes {case}: {axes:?}");
        samples.sort_unstable();
        let mean = samples.iter().sum::<u128>() as f64 / 200.0;
        let variance = samples
            .iter()
            .map(|n| (*n as f64 - mean).powi(2))
            .sum::<f64>()
            / 200.0;
        eprintln!(
            "history cost {case}: p50={}ns p95={}ns variance={variance} counts={:?}",
            samples[100],
            samples[190],
            observed.unwrap()
        );
    }
}

#[test]
fn stash_parser_scratch_is_live_and_precharged() {
    let f = Fixture::new();
    f.stash_ref();
    let root = f.root();
    let access = access();
    for bytes in [
        line(1).repeat(1024),
        [vec![b'x'; budget::REFLOG_BYTES as usize - 1], vec![b'\n']].concat(),
    ] {
        f.write("logs/refs/stash", bytes);
        let m = RefCell::new(meter());
        let io = port(&root, &access, &m);
        let ((result, charged), allocated) = allocation::measure(|| {
            let result = stash(&io, &git::refs::RefSnapshot::default());
            (result, m.borrow().counts[2].allocated)
        });
        assert!(
            matches!(result, Ok((1024, false)) | Err(INVALID)),
            "{result:?}"
        );
        assert!(
            allocated.peak as u64 <= charged,
            "{allocated:?} reservation={charged}"
        );
        assert_eq!(m.borrow().live_allocated(), 0);
        eprintln!(
            "stash allocation: peak={} charged={charged}",
            allocated.peak
        );
    }
}

#[test]
#[ignore = "release warm 200-run observation; run explicitly"]
fn packed_refs_release_cost() {
    if cfg!(debug_assertions) {
        panic!("release measurement required");
    }
    for count in [1400, 2100, 4000] {
        let work = Fixture::new();
        let f = Fixture(work.0.join(".git"));
        fs::create_dir(&f.0).unwrap();
        let (head, upstream) = f.graph();
        let bytes = f.packed_refs(count, head, upstream) as u64;
        f.write("logs/refs/stash", line(1));
        for shared in [false, true] {
            let case = format!("d-refs-{count}-{}", if shared { "shared" } else { "lazy" });
            let mut samples = Vec::new();
            let mut axes = [0; 3];
            // Each sample is a new request. Shared D follows real preflight,
            // repository construction, a B object read and C on the same meter.
            for i in 0..201 {
                let mut m = meter();
                let roots = git::discover::discover_with_access(&request(&work), access(), &mut m)
                    .unwrap()
                    .unwrap();
                let before_bytes = m.budget.used(Axis::RefBytes);
                if shared {
                    assert_eq!(
                        git::preflight::preflight(&roots, &mut m).unwrap(),
                        git::preflight::GitAccess::Objects
                    );
                }
                let m = RefCell::new(m);
                let repo = shared.then(|| GuardedRepository::from_roots(&roots, &m).unwrap());
                if let Some(repo) = &repo {
                    assert!(
                        repo.objects(&repo.io)
                            .find(&head, &mut Vec::new())
                            .unwrap()
                            .is_some()
                    );
                    assert_eq!(divergence(repo), Ok(Some((2, 1))));
                }
                let start = Instant::now();
                let d = git::stage_d::stage_d(&roots, roots.ref_snapshot(), &m);
                let ns = start.elapsed().as_nanos();
                assert!(matches!(d, StageResult::Value(_)));
                assert_eq!(
                    field(&value(d), "stash"),
                    &Field::known(FieldValue::Count {
                        n: 1,
                        saturated: false
                    })
                );
                axes = [Axis::RefEntries, Axis::RefBytes, Axis::ReflogBytes]
                    .map(|a| m.borrow().budget.used(a));
                assert_eq!(axes[0], u64::from(count) + if shared { 5 } else { 1 });
                assert_eq!(
                    axes[1] - before_bytes,
                    bytes
                        + if shared {
                            2 * b"ref: refs/heads/main\n".len() as u64
                        } else {
                            0
                        }
                );
                if i == 0 {
                    eprintln!("history cold {case}: {ns}ns");
                } else {
                    samples.push(ns);
                }
            }
            eprintln!("history samples {case}: {samples:?}");
            eprintln!("history axes {case}: {axes:?}");
            samples.sort_unstable();
            let mean = samples.iter().sum::<u128>() as f64 / 200.0;
            let variance = samples
                .iter()
                .map(|n| (*n as f64 - mean).powi(2))
                .sum::<f64>()
                / 200.0;
            eprintln!(
                "history cost {case}: p50={}ns p95={}ns variance={variance}",
                samples[100], samples[190]
            );
        }
    }
}

fn request(work: &Fixture) -> bingsu_core::collection::wire::Request {
    use bingsu_core::{
        collection::{
            path_facts::PathQuery,
            wire::{Binding, BuildId, M3B_REQUEST_ID, Request},
        },
        snapshot::{self, Identity},
    };
    let cwd = work.0.as_os_str().as_bytes().to_vec();
    Request {
        request_id: M3B_REQUEST_ID,
        budget_ms: 50,
        environment: vec![],
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
            mask: 8,
            path_query: PathQuery::for_path(&cwd, Some(&cwd), false),
            cwd,
        },
    }
}

#[test]
fn stage_d_uses_common_reflog_and_preserves_pending() {
    let work = Fixture::new();
    let f = Fixture(work.0.join(".git"));
    fs::create_dir(&f.0).unwrap();
    f.init();
    f.stash_ref();
    f.write("HEAD", b"ref: refs/heads/main\n");
    f.write("logs/refs/stash", line(2));
    let request = request(&work);
    let roots = git::discover::discover_with_access(&request, access(), &mut meter())
        .unwrap()
        .unwrap();
    let m = RefCell::new(meter());
    let result = git::stage_d::stage_d(&roots, roots.ref_snapshot(), &m);
    assert!(matches!(result, StageResult::Value(_)));
    assert_eq!(
        field(&value(result), "stash"),
        &Field::known(FieldValue::Count {
            n: 1,
            saturated: false
        })
    );
    f.write("logs/refs/stash", b"broken\n");
    let result = git::stage_d::stage_d(&roots, roots.ref_snapshot(), &m);
    assert!(matches!(result, StageResult::Partial(_)));
    assert_eq!(field(&value(result), "stash"), &Field::PENDING);
    let reduced =
        git::discover::discover_with_access(&request, Access::stage_a_only(), &mut meter())
            .unwrap()
            .unwrap();
    let m = RefCell::new(meter());
    assert_eq!(
        field(
            &value(git::stage_d::stage_d(&reduced, reduced.ref_snapshot(), &m)),
            "stash"
        ),
        &Field::PENDING
    );
    assert_eq!(m.borrow().counts[2].read_bytes, 0);
    f.graph();
    f.write("logs/refs/stash", line(2));
    let linked = Fixture::new();
    f.git(
        &[
            "worktree",
            "add",
            "-q",
            "--detach",
            linked.0.to_str().unwrap(),
            "HEAD",
        ],
        b"",
    );
    let pointer = fs::read_to_string(linked.0.join(".git")).unwrap();
    let private = PathBuf::from(pointer.trim().strip_prefix("gitdir: ").unwrap());
    fs::create_dir_all(private.join("logs/refs")).unwrap();
    fs::write(private.join("logs/refs/stash"), line(2).repeat(5)).unwrap();
    let mut request = request;
    request.binding.cwd = linked.0.as_os_str().as_bytes().to_vec();
    request.binding.path_query =
        PathQuery::for_path(&request.binding.cwd, Some(&request.binding.cwd), false);
    let roots = git::discover::discover_with_access(&request, access(), &mut meter())
        .unwrap()
        .unwrap();
    let m = RefCell::new(meter());
    assert_eq!(
        field(
            &value(git::stage_d::stage_d(&roots, roots.ref_snapshot(), &m)),
            "stash"
        ),
        &Field::known(FieldValue::Count {
            n: 1,
            saturated: false
        })
    );
}

#[test]
fn stash_stream_revalidates_after_the_last_read() {
    let f = Fixture::new();
    f.stash_ref();
    f.write("logs/refs/stash", line(1));
    let root = f.root();
    let access = access();
    let path = f.0.join("logs/refs/stash");
    let mut changed = false;
    let mut m = meter();
    m.hook = Some(Box::new(move |event| {
        if event == "before_reflog_read" && !changed {
            changed = true;
            fs::File::open(&path)
                .unwrap()
                .set_modified(std::time::SystemTime::now() + Duration::from_secs(5))
                .unwrap();
        }
    }));
    let m = RefCell::new(m);
    assert_eq!(
        stash(
            &port(&root, &access, &m),
            &git::refs::RefSnapshot::default()
        ),
        Err(E::Changed)
    );
}

// Product-sized deadline only here. Semantic tests use generous deadlines.
#[test]
fn product_history_deadlines_preserve_unknown() {
    let f = Fixture::new();
    f.stash_ref();
    f.graph();
    f.linear(10_000);
    let root = f.root();
    let access = access();
    let mut request = meter();
    let result = request.stage(budget::C_MS, |request| {
        let placeholder = request.expired_placeholder();
        let m = RefCell::new(std::mem::replace(request, placeholder));
        let result = match GuardedRepository::new(
            port(&root, &access, &m),
            &git::refs::RefSnapshot::default(),
        ) {
            Ok(repo) => stage_c(&repo),
            Err(E::Deadline) => {
                *request = m.into_inner();
                return None;
            }
            Err(e) => panic!("unexpected setup error {e:?}"),
        };
        *request = m.into_inner();
        Some(result)
    });
    if let Some(result) = result {
        pending(result);
    }
    assert_eq!(request.check(), Ok(()));
    // The independent D allowance does not reset prior byte/commit accounting.
    f.write("logs/refs/stash", line(2));
    let commits = request.budget.used(Axis::Commits);
    request.stage(budget::D_MS, |request| {
        let placeholder = request.expired_placeholder();
        let m = RefCell::new(std::mem::replace(request, placeholder));
        let result = stash(
            &port(&root, &access, &m),
            &git::refs::RefSnapshot::default(),
        );
        assert!(
            matches!(result, Ok((1, false)) | Err(E::Deadline)),
            "{result:?}"
        );
        *request = m.into_inner();
    });
    assert_eq!(request.budget.used(Axis::Commits), commits);
}

#[test]
fn b_partial_does_not_suppress_independent_history() {
    let f = Fixture::new();
    f.stash_ref();
    f.graph();
    f.write("logs/refs/stash", line(1));
    let root = f.root();
    let access = access();
    let m = RefCell::new(meter());
    let repo = repository(&root, &access, &m);
    m.borrow_mut()
        .charge_axis(Axis::IndexEntries, budget::INDEX_ENTRIES)
        .unwrap();
    assert_eq!(
        repo.io.metered(|m| m.charge_axis(Axis::IndexEntries, 1)),
        Err(E::Limit)
    );
    assert_eq!(repo.io.metered(|m| m.check()), Err(E::Limit));
    assert_eq!(divergence(&repo), Ok(Some((2, 1))));
    assert_eq!(
        stash(&repo.io.next_stage(), &git::refs::RefSnapshot::default()),
        Ok((1, false))
    );
    assert_eq!(
        m.borrow().budget.used(Axis::IndexEntries),
        budget::INDEX_ENTRIES
    );
    assert_eq!(m.borrow().budget.used(Axis::Commits), 4);
}
