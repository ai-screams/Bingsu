//! Exact divergence corpus and deterministic early-stop boundaries.
use super::*;

impl Fixture {
    fn dated_commit(&self, parents: &[ObjectId], timestamp: i64, label: &str) -> ObjectId {
        let mut body = "tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\n".to_owned();
        for parent in parents {
            body += &format!("parent {parent}\n");
        }
        body += &format!(
            "author F <f@example.org> {timestamp} +0000\ncommitter F <f@example.org> {timestamp} +0000\n\n{label}\n"
        );
        self.object("commit", body.as_bytes())
    }

    fn oracle(&self, left: ObjectId, right: ObjectId) -> (u32, u32) {
        self.refs(left, right);
        let output = self.git(&["rev-list", "--left-right", "--count", "HEAD...@{u}"], b"");
        let counts: Vec<u32> = std::str::from_utf8(&output)
            .unwrap()
            .split_whitespace()
            .map(|s| s.parse().unwrap())
            .collect();
        let expected = (counts[0], counts[1]);
        let root = self.root();
        let access = access();
        let m = RefCell::new(meter());
        let repo = repository(&root, &access, &m);
        assert_eq!(divergence(&repo), Ok(Some(expected)));
        expected
    }
}

// 이것을 실패시키는 것: 같은 tip의 조기 반환을 제거하여 object/commit 예산을 소비하는 것.
#[test]
fn equal_tips_use_no_objects() {
    let f = Fixture::new();
    let (head, _) = f.graph();
    assert_eq!(f.oracle(head, head), (0, 0));
    let root = f.root();
    let access = access();
    let m = RefCell::new(meter());
    let repo = repository(&root, &access, &m);
    let status = git::status_tracked::load_status(&repo);
    assert_ne!(status.staged, Field::PENDING);
    for axis in [Axis::Commits, Axis::DecompressedBytes, Axis::Packs] {
        let used = m.borrow().budget.used(axis);
        m.borrow_mut()
            .charge_axis(axis, axis.limit() - used)
            .unwrap();
    }
    let v = value(stage_c(&repo));
    for name in ["ahead", "behind"] {
        assert_eq!(
            field(&v, name),
            &Field::known(FieldValue::Count {
                n: 0,
                saturated: false
            })
        );
    }
    assert_eq!(field(&v, "partial"), &Field::known(FieldValue::Bool(false)));
    // The fast path must still honor the deadline.
    m.replace(Meter::new(Instant::now()));
    pending(stage_c(&repo));
    assert_eq!(
        walk(
            &port(&root, &access, &m),
            &Synthetic {
                count: 1,
                cycle: false
            },
            head,
            head
        ),
        Err(E::Deadline)
    );
}

// 이것을 실패시키는 것: ahead와 behind의 색을 뒤집는 것.
#[test]
fn ahead_only_matches_git() {
    let f = Fixture::new();
    let (a, b) = f.graph();
    let merge = f.commit(&[a, b], "merge");
    assert_eq!(f.oracle(merge, b), (3, 0));
}

// 이것을 실패시키는 것: behind를 0으로 고정하는 것.
#[test]
fn behind_only_matches_git() {
    let f = Fixture::new();
    let (a, b) = f.graph();
    let merge = f.commit(&[a, b], "merge");
    assert_eq!(f.oracle(b, merge), (0, 3));
}

// 이것을 실패시키는 것: 두 reachable set의 색을 뒤집어 2/1을 1/2로 세는 것.
#[test]
fn diverged_matches_git() {
    let f = Fixture::new();
    let (a, b) = f.graph();
    assert_eq!(f.oracle(a, b), (2, 1));
}

// 이것을 실패시키는 것: criss-cross merge의 첫 parent만 걷는 것.
#[test]
fn criss_cross_matches_git() {
    let f = Fixture::new();
    f.init();
    let base = f.commit(&[], "base");
    let a = f.commit(&[base], "a");
    let b = f.commit(&[base], "b");
    let left = f.commit(&[a, b], "left merge");
    let right = f.commit(&[b, a], "right merge");
    let left = f.commit(&[left], "left tip");
    assert_eq!(f.oracle(left, right), (2, 1));
}

// 이것을 실패시키는 것: merge의 첫 parent만 걷는 것.
#[test]
fn many_parents_match_git() {
    let f = Fixture::new();
    f.init();
    let base = f.commit(&[], "base");
    let arms: Vec<_> = (0..64)
        .map(|n| f.commit(&[base], &format!("arm {n}")))
        .collect();
    let left = f.commit(&arms[..48], "left octopus");
    let right = f.commit(&arms[32..], "right octopus");
    assert_eq!(f.oracle(left, right), (33, 17));
}

// 이것을 실패시키는 것: ancestry 증명 없이 timestamp 순서와 common frontier만 믿고 자르는 것.
#[test]
fn clock_skew_recolors_previously_visited_commits() {
    let f = Fixture::new();
    f.init();
    let root = f.dated_commit(&[], 500, "root");
    let old = f.dated_commit(&[root], 900, "visited too early");
    let hidden = f.dated_commit(&[old], 100, "hidden path");
    let common = f.dated_commit(&[hidden], 50, "late common boundary");
    let left = f.dated_commit(&[old, common], 1000, "left shortcut");
    let right = f.dated_commit(&[common], 800, "right");
    assert_eq!(f.oracle(left, right), (1, 1));
    assert_eq!(f.oracle(right, left), (1, 1));
}

// 이것을 실패시키는 것: 이미 칠한 parent를 다시 세거나 중복 parent를 cycle로 거부하는 것.
#[test]
fn duplicate_parents_match_git() {
    let f = Fixture::new();
    let (a, b) = f.graph();
    let left = f.commit(&[a, b, a, b, b], "duplicate parents");
    assert_eq!(f.oracle(left, b), (3, 0));
}

fn check_linear_frontier(count: u32) {
    let access = access();
    {
        let f = Fixture::new();
        f.init();
        f.linear(count);
        let head = ObjectId::from_hex(f.git(&["rev-parse", "HEAD"], b"").trim_ascii()).unwrap();
        let parent = ObjectId::from_hex(f.git(&["rev-parse", "HEAD~1"], b"").trim_ascii()).unwrap();
        for (left, right, expected, commits) in [
            (head, head, (0, 0), 0),
            (head, parent, (1, 0), 2),
            (parent, head, (0, 1), 3),
        ] {
            assert_eq!(f.oracle(left, right), expected);
            let root = f.root();
            let m = RefCell::new(meter());
            let repo = repository(&root, &access, &m);
            git::status_tracked::load_status(&repo);
            assert_eq!(divergence(&repo), Ok(Some(expected)));
            assert_eq!(m.borrow().budget.used(Axis::Commits), commits);
        }
    }
}

// 이것을 실패시키는 것: 공통 색을 이미 확장한 경로에 늦게 전파하여 3000개를 모두 읽는 것.
#[test]
fn linear_3000_stops_at_common_frontier() {
    check_linear_frontier(3000);
}

// 이것을 실패시키는 것: 공통 색을 이미 확장한 경로에 늦게 전파하여 10000개를 모두 읽는 것.
#[test]
fn linear_10000_stops_at_common_frontier() {
    check_linear_frontier(10_000);
}

// 이것을 실패시키는 것: Limit 후의 발견 수를 exact count로 발행하는 것.
#[test]
fn partially_painted_limit_keeps_both_counts_pending() {
    let f = Fixture::new();
    f.graph();
    let root = f.root();
    let access = access();
    let m = RefCell::new(meter());
    let repo = repository(&root, &access, &m);
    m.borrow_mut()
        .charge_axis(Axis::Commits, budget::COMMITS - 2)
        .unwrap();
    pending(stage_c(&repo));
    assert_eq!(m.borrow().budget.used(Axis::Commits), budget::COMMITS);
    assert!(m.borrow().budget.used(Axis::DecompressedBytes) > 0);
}

// 이것을 실패시키는 것: 여러 common 경계를 ancestry 증명 없이 자르는 것.
#[test]
fn skewed_dag_corpus_matches_git() {
    let f = Fixture::new();
    f.init();
    let mut commits = Vec::new();
    let mut state = 37u32;
    for n in 0..80 {
        let mut parents = Vec::new();
        for _ in 0..(n % 5) {
            state = state.wrapping_mul(1664525).wrapping_add(1013904223);
            parents.push(commits[state as usize % commits.len()]);
        }
        commits.push(f.dated_commit(&parents, i64::from(state % 1000), &format!("dag {n}")));
    }
    for n in 40..80 {
        f.oracle(commits[n], commits[(n * 13) % 80]);
    }
}

// 이것을 실패시키는 것: Deadline 후의 발견 수를 exact count로 발행하는 것.
#[test]
fn partially_painted_deadline_keeps_both_counts_pending() {
    let f = Fixture::new();
    f.graph();
    let root = f.root();
    let access = access();
    let m = RefCell::new(meter());
    let repo = repository(&root, &access, &m);
    let fired = std::rc::Rc::new(std::cell::Cell::new(false));
    let hook_fired = fired.clone();
    let mut objects = 0;
    m.borrow_mut().hook = Some(Box::new(move |event| {
        if event.starts_with("resolve:objects/") {
            objects += 1;
            if objects == 3 {
                hook_fired.set(true);
                std::thread::sleep(Duration::from_millis(201));
            }
        }
    }));
    pending(with_stage(&m, 200, || stage_c(&repo)));
    assert!(
        fired.get(),
        "deadline must interrupt an already painted graph"
    );
    assert!(m.borrow().budget.used(Axis::DecompressedBytes) > 0);
    assert_eq!(m.borrow().check(), Ok(()));
}

fn check_linear_difference(count: u32) {
    let f = Fixture::new();
    f.init();
    f.linear(count);
    let head = ObjectId::from_hex(f.git(&["rev-parse", "HEAD"], b"").trim_ascii()).unwrap();
    let middle = ObjectId::from_hex(f.git(&["rev-parse", "@{u}"], b"").trim_ascii()).unwrap();
    assert_eq!(f.oracle(head, middle), (count / 2, 0));
    assert_eq!(f.oracle(middle, head), (0, count / 2));
}

// 이것을 실패시키는 것: 3000 commit corpus에서 ahead와 behind의 색을 뒤집는 것.
#[test]
fn linear_3000_large_difference_matches_git() {
    check_linear_difference(3000);
}

// 이것을 실패시키는 것: 10000 commit corpus에서 ahead와 behind의 색을 뒤집는 것.
#[test]
fn linear_10000_large_difference_matches_git() {
    check_linear_difference(10_000);
}

// 이것을 실패시키는 것: B의 commit/tree 확인 없이 같은 tip을 exact 0/0으로 반환하는 것.
#[test]
fn equal_non_commit_tips_stay_pending_after_stage_b() {
    let f = Fixture::new();
    f.init();
    let missing = ObjectId::from_hex(b"1234567890123456789012345678901234567890").unwrap();
    let blob = f.object("blob", b"x");
    let tree = f.object("tree", b"");
    for tip in [missing, blob, tree] {
        f.refs(tip, tip);
        let oracle = Command::new("git")
            .args([
                "--git-dir",
                f.0.to_str().unwrap(),
                "rev-list",
                "--left-right",
                "--count",
                "HEAD...@{u}",
            ])
            .env_clear()
            .env("PATH", "/usr/bin:/bin:/opt/homebrew/bin")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .output()
            .unwrap();
        assert!(!oracle.status.success());
        let root = f.root();
        let access = access();
        let m = RefCell::new(meter());
        let repo = repository(&root, &access, &m);
        let b = value(git::stage_b::stage_b(&repo, b"", true));
        assert_eq!(field(&b, "staged"), &Field::PENDING);
        pending(stage_c(&repo));
        assert!(divergence(&repo).is_err());
    }
}

// 이것을 실패시키는 것: B를 거치지 않은 같은 tip에 shortcut을 허용하는 것, 또는 사실을
// root tree 읽기 성공에 다시 묶는 것(bad의 Commits가 1이 된다).
#[test]
fn equal_tips_without_stage_b_use_normal_walk() {
    let f = Fixture::new();
    f.init();
    let good = f.commit(&[], "good");
    // The tree is missing: B is Pending, but the commit itself passes the
    // walk's check, so the fact no longer implies a readable root tree.
    let bad = f.object("commit", b"tree 1234567890123456789012345678901234567890\nauthor F <f@example.org> 1700000000 +0000\ncommitter F <f@example.org> 1700000000 +0000\n\nbad tree\n");
    for tip in [good, bad] {
        assert_eq!(f.oracle(tip, tip), (0, 0));
        let root = f.root();
        let access = access();
        let m = RefCell::new(meter());
        let repo = repository(&root, &access, &m);
        assert_eq!(divergence(&repo), Ok(Some((0, 0))));
        assert_eq!(m.borrow().budget.used(Axis::Commits), 1);
        m.borrow_mut()
            .charge_axis(Axis::Commits, budget::COMMITS - 1)
            .unwrap();
        pending(stage_c(&repo));
        if tip == bad {
            let m = RefCell::new(meter());
            let repo = repository(&root, &access, &m);
            assert_eq!(
                git::status_tracked::load_status(&repo).staged,
                Field::PENDING
            );
            assert_eq!(divergence(&repo), Ok(Some((0, 0))));
            assert_eq!(m.borrow().budget.used(Axis::Commits), 0);
        }
    }
}

const EMPTY_TREE: &str = "tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\n";
const SIGNATURES: &str =
    "author F <f@example.org> 1700000000 +0000\ncommitter F <f@example.org> 1700000000 +0000\n";

impl Fixture {
    fn literal_commit(&self, body: &str) -> ObjectId {
        let out = self.git(
            &[
                "hash-object",
                "--literally",
                "-w",
                "--stdin",
                "-t",
                "commit",
            ],
            body.as_bytes(),
        );
        ObjectId::from_hex(out.trim_ascii()).unwrap()
    }

    /// `rev-list --left-right --count HEAD...@{u}`: Some(counts) or None on failure.
    fn git_counts(&self) -> Option<(u32, u32)> {
        let out = Command::new("git")
            .args([
                "--git-dir",
                self.0.to_str().unwrap(),
                "rev-list",
                "--left-right",
                "--count",
                "HEAD...@{u}",
            ])
            .env_clear()
            .env("PATH", "/usr/bin:/bin:/opt/homebrew/bin")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .output()
            .unwrap();
        out.status.success().then(|| {
            let text = String::from_utf8(out.stdout).unwrap();
            let mut n = text.split_whitespace().map(|s| s.parse().unwrap());
            (n.next().unwrap(), n.next().unwrap())
        })
    }
}

// The shortcut must equal the walk on the same tip: a HEAD that the walk
// rejects stays Pending after B even though B itself decoded its tree.
// 이것을 실패시키는 것: head_commit의 checked_commit 호출을 빼거나 그 실패에도 사실을 세우는 것,
// 또는 root tree를 읽은 자리에서 사실을 다시 세우는 것(이 fixture는 cache-tree가 없어 root tree를 읽는다).
#[test]
fn equal_tips_with_unchecked_head_commit_stay_pending() {
    let cases = [
        (
            "malformed parent",
            format!(
                "{EMPTY_TREE}parent zz34567890123456789012345678901234567890\n{SIGNATURES}\nm\n"
            ),
            None,
        ),
        (
            "short parent",
            format!("{EMPTY_TREE}parent 1234\n{SIGNATURES}\nm\n"),
            None,
        ),
        // Git accepts these and prints 0 0; the walk rejects them, so Pending
        // is the conservative answer the shortcut must not overrule.
        (
            "non-numeric timestamp",
            format!(
                "{EMPTY_TREE}author F <f@example.org> 1700000000 +0000\ncommitter F <f@example.org> 17x\n\nm\n"
            ),
            Some((0, 0)),
        ),
        (
            "object cut inside the timestamp",
            format!(
                "{EMPTY_TREE}author F <f@example.org> 1700000000 +0000\ncommitter F <f@example.org> 17000"
            ),
            Some((0, 0)),
        ),
        (
            "no committer",
            format!("{EMPTY_TREE}author F <f@example.org> 1700000000 +0000\n\nm\n"),
            Some((0, 0)),
        ),
        (
            "no message",
            format!("{EMPTY_TREE}{SIGNATURES}"),
            Some((0, 0)),
        ),
    ];
    for (name, body, expected_git) in &cases {
        let f = Fixture::new();
        f.init();
        let tip = f.literal_commit(body);
        f.refs(tip, tip);
        assert_eq!(f.git_counts(), *expected_git, "{name}");
        let root = f.root();
        let access = access();
        let m = RefCell::new(meter());
        let repo = repository(&root, &access, &m);
        assert!(divergence(&repo).is_err(), "{name}: walk");
        let m = RefCell::new(meter());
        let repo = repository(&root, &access, &m);
        git::status_tracked::observations::take();
        // B still succeeds: its root tree parses even when later tokens do not.
        assert_ne!(
            git::status_tracked::load_status(&repo).staged,
            Field::PENDING,
            "{name}"
        );
        assert_eq!(
            git::status_tracked::observations::take().tree_reads,
            1,
            "{name}"
        );
        pending(stage_c(&repo));
    }
}

// Other kinds: Git peels a tag to 0 0 and rejects a blob, but B and the walk
// both require a commit, so the shortcut has nothing to reuse: C is Pending.
// The blob holds commit bytes, so only a kind check (not parsing) rejects it.
// 이것을 실패시키는 것: shortcut에서 사실 일치 조건을 빼는 것, head_commit의 kind 검사를 빼는 것
// (B가 commit 바이트를 가진 blob을 HEAD로 받아들인다).
#[test]
fn equal_other_kind_tips_stay_pending() {
    let f = Fixture::new();
    f.init();
    let commit = f.commit(&[], "tagged");
    let tag = f.object(
        "tag",
        format!(
            "object {commit}\ntype commit\ntag t\ntagger F <f@example.org> 1700000000 +0000\n\nt\n"
        )
        .as_bytes(),
    );
    let blob = f.object(
        "blob",
        format!("{EMPTY_TREE}{SIGNATURES}\nblob\n").as_bytes(),
    );
    for (tip, expected_git) in [(tag, Some((0, 0))), (blob, None)] {
        f.refs(tip, tip);
        assert_eq!(f.git_counts(), expected_git);
        let root = f.root();
        let access = access();
        let m = RefCell::new(meter());
        let repo = repository(&root, &access, &m);
        assert_eq!(
            git::status_tracked::load_status(&repo).staged,
            Field::PENDING
        );
        pending(stage_c(&repo));
    }
}

fn signed(f: &Fixture, parent: &str, signature: usize, message: &str) -> ObjectId {
    let mut body =
        format!("{EMPTY_TREE}{parent}{SIGNATURES}gpgsig -----BEGIN PGP SIGNATURE-----\n");
    for _ in 0..signature / 78 {
        body += &format!(" {}\n", "A".repeat(76));
    }
    body += &format!(" -----END PGP SIGNATURE-----\n\n{message}\n");
    f.literal_commit(&body)
}

// checked_commit copies a multi-line header (gpgsig) once and charges that
// copy first, both when B decodes HEAD and on every commit the walk retains.
// 이것을 실패시키는 것: checked_commit에서 객체 크기만큼의 reserve를 빼는 것(B와 walk 모두
// peak가 charge를 넘는다).
#[test]
fn checked_commit_charges_its_header_copy() {
    let f = Fixture::new();
    f.init();
    for (parent, size) in [("", 600_000), ("", 1_000_000), ("parent 1234\n", 600_000)] {
        let tip = signed(&f, parent, size, "signed");
        f.refs(tip, tip);
        let root = f.root();
        let access = access();
        let m = RefCell::new(meter());
        let charged = || m.borrow().counts.iter().map(|c| c.allocated).sum::<u64>();
        let io = port(&root, &access, &m);
        let db = git::io::objects::SafeObjectDb::new(&io);
        let before = charged();
        let (result, alloc) = allocation::measure(|| walk(&io, &db, tip, tip));
        assert_eq!(result.is_ok(), parent.is_empty(), "{size}");
        assert!(
            alloc.peak as u64 <= charged() - before,
            "walk {alloc:?} reserved={}",
            charged() - before
        );
        let m = RefCell::new(meter());
        let charged = || m.borrow().counts.iter().map(|c| c.allocated).sum::<u64>();
        let repo = repository(&root, &access, &m);
        let db = repo.objects(&repo.io);
        let before = charged();
        let (commit, alloc) = allocation::measure(|| db.head_commit(&tip).unwrap());
        assert_eq!(commit.checked, parent.is_empty(), "{size}");
        assert!(
            alloc.peak as u64 <= charged() - before,
            "B {alloc:?} reserved={}",
            charged() - before
        );
        drop(db);
        assert_ne!(
            git::status_tracked::load_status(&repo).staged,
            Field::PENDING
        );
        if parent.is_empty() {
            assert_eq!(f.git_counts(), Some((0, 0)));
            assert_eq!(divergence(&repo), Ok(Some((0, 0))));
            assert_eq!(m.borrow().budget.used(Axis::Commits), 0);
        } else {
            assert_eq!(f.git_counts(), None);
            pending(stage_c(&repo));
        }
    }
}

// 이것을 실패시키는 것: header 복사 reserve의 실패를 무시하는 것(Limit 대신 Ok가 된다).
#[test]
fn checked_commit_without_room_for_the_copy_is_a_limit() {
    let body = format!("{EMPTY_TREE}{SIGNATURES}\nm\n");
    let data = gix_object::Data {
        kind: gix_object::Kind::Commit,
        object_hash: gix_index::hash::Kind::Sha1,
        data: body.as_bytes(),
    };
    for (room, expected) in [(0, Err(E::Limit)), (1, Ok(()))] {
        let mut m = meter();
        m.allocation_limit = m.live_allocated() + body.len() as u64 - 1 + room;
        assert_eq!(git::io::objects::checked_commit(&data, &mut m), expected);
        assert_eq!(m.live_allocated(), 0);
    }
}

// Commit, then read-tree and write-tree: the index holds a root cache-tree
// equal to HEAD's tree, which is the state right after commit or checkout.
fn clean_index(f: &Fixture, body: impl Fn(ObjectId) -> String) -> ObjectId {
    f.init();
    let blob = f.object("blob", b"file\n");
    let tree = f.git(
        &["mktree"],
        format!("100644 blob {blob}\tfile\n").as_bytes(),
    );
    let tree = std::str::from_utf8(tree.trim_ascii()).unwrap().to_owned();
    let tip = f.literal_commit(&body(ObjectId::from_hex(tree.as_bytes()).unwrap()));
    f.refs(tip, tip);
    f.git(&["read-tree", &tree], b"");
    assert_eq!(f.git(&["write-tree"], b"").trim_ascii(), tree.as_bytes());
    tip
}

// 이것을 실패시키는 것: 사실을 root tree 읽기 뒤에서만 세우는 것(clean index에서 단축이 빠져
// Commits가 1이 된다), 또는 C의 단축 안에서 HEAD 커밋을 다시 읽는 것(DecompressedBytes가 는다).
#[test]
fn clean_index_equal_tips_use_the_shortcut() {
    let f = Fixture::new();
    clean_index(&f, |tree| format!("tree {tree}\n{SIGNATURES}\nclean\n"));
    assert_eq!(f.git_counts(), Some((0, 0)));
    let root = f.root();
    let access = access();
    let m = RefCell::new(meter());
    let repo = repository(&root, &access, &m);
    git::status_tracked::observations::take();
    assert_ne!(
        git::status_tracked::load_status(&repo).staged,
        Field::PENDING
    );
    // The cache-tree hit: one find (the HEAD commit) and no tree object.
    let b = git::status_tracked::observations::take();
    assert_eq!((b.finds, b.tree_reads), (1, 0));
    let before = (
        m.borrow().budget.used(Axis::Commits),
        m.borrow().budget.used(Axis::DecompressedBytes),
    );
    let v = value(stage_c(&repo));
    let after = (
        m.borrow().budget.used(Axis::Commits),
        m.borrow().budget.used(Axis::DecompressedBytes),
    );
    assert_eq!((before.0, after), (0, before));
    for name in ["ahead", "behind"] {
        assert_eq!(
            field(&v, name),
            &Field::known(FieldValue::Count {
                n: 0,
                saturated: false
            })
        );
    }
}

// 이것을 실패시키는 것: cache-tree 분기 앞에서 checked 여부와 무관하게 사실을 세우는 것.
#[test]
fn clean_index_malformed_parent_stays_pending() {
    let f = Fixture::new();
    clean_index(&f, |tree| {
        format!("tree {tree}\nparent 1234\n{SIGNATURES}\nm\n")
    });
    assert_eq!(f.git_counts(), None);
    let root = f.root();
    let access = access();
    let m = RefCell::new(meter());
    let repo = repository(&root, &access, &m);
    git::status_tracked::observations::take();
    assert_ne!(
        git::status_tracked::load_status(&repo).staged,
        Field::PENDING
    );
    assert_eq!(git::status_tracked::observations::take().tree_reads, 0);
    pending(stage_c(&repo));
}

// 이것을 실패시키는 것: B에서 HEAD를 확인했다는 이유만으로 서로 다른 tip도 0/0으로 반환하는 것.
#[test]
fn validated_head_still_compares_distinct_tips() {
    let f = Fixture::new();
    f.graph();
    let root = f.root();
    let access = access();
    let m = RefCell::new(meter());
    let repo = repository(&root, &access, &m);
    assert_ne!(
        git::status_tracked::load_status(&repo).staged,
        Field::PENDING
    );
    assert_eq!(divergence(&repo), Ok(Some((2, 1))));
}

fn check_long_lived_cost(n: usize, every: usize) {
    let f = Fixture::new();
    f.init();
    let mut parents = Vec::new();
    let mut timestamps = Vec::new();
    for i in 0..n {
        parents.push(if i == 0 { vec![] } else { vec![i - 1] });
        timestamps.push(1_700_000_000 + i * 60);
    }
    let mut previous = 0;
    let mut i = 1;
    while i < n - 1 {
        let next = (i + every).min(n - 2);
        let index = parents.len();
        parents.push(if previous == 0 {
            vec![previous]
        } else {
            vec![previous, i]
        });
        timestamps.push(1_700_000_000 + i * 60 + 30);
        previous = index;
        i = next;
        if i == n - 2 {
            let index = parents.len();
            parents.push(vec![previous, n - 2]);
            timestamps.push(1_700_000_000 + n * 60);
            previous = index;
            break;
        }
    }
    let mut input = Vec::new();
    for (i, ps) in parents.iter().enumerate() {
        input.extend(format!("commit refs/heads/tmp\nmark :{}\ncommitter F <f@example.org> {} +0000\ndata 1\n{}\n", i + 1, timestamps[i], i % 10).bytes());
        if ps.is_empty() {
            input.extend(b"from 0000000000000000000000000000000000000000\n");
        } else {
            input.extend(format!("from :{}\n", ps[0] + 1).bytes());
            for p in &ps[1..] {
                input.extend(format!("merge :{}\n", p + 1).bytes());
            }
        }
        input.extend(b"deleteall\n\n");
    }
    let marks = f.0.join("marks.txt");
    f.git(
        &[
            "fast-import",
            "--quiet",
            "--force",
            &format!("--export-marks={}", marks.display()),
        ],
        &input,
    );
    let mut ids = vec![None; parents.len()];
    for line in fs::read_to_string(marks).unwrap().lines() {
        let (mark, id) = line.split_once(' ').unwrap();
        let index: usize = mark.trim_start_matches(':').parse().unwrap();
        ids[index - 1] = Some(ObjectId::from_hex(id.as_bytes()).unwrap());
    }
    let expected = f.oracle(ids[previous].unwrap(), ids[n - 1].unwrap());
    assert_eq!(expected, ((parents.len() - n) as u32, 1));
    let root = f.root();
    let access = access();
    let m = RefCell::new(meter());
    let repo = repository(&root, &access, &m);
    git::stage_c::observations::take();
    assert_eq!(divergence(&repo), Ok(Some(expected)));
    let cost = git::stage_c::observations::take();
    let visited = m.borrow().budget.used(Axis::Commits) as usize;
    // Each prefix of the walk, not just its final graph, must obey the bound.
    assert!(
        cost.proof_work > 0 && cost.proof_work <= 4 * visited,
        "{cost:?}, visited={visited}"
    );
    assert!(cost.max_work_per_node <= 4, "{cost:?}");
    assert_eq!(cost.fallbacks, 1, "fallback must remain disabled: {cost:?}");
    assert_eq!(
        visited,
        parents.len(),
        "fallback must finish full colouring"
    );
}

// 이것을 실패시키는 것: 실패한 frontier마다 DFS를 반복해 누적 증명 비용을 제한하지 않는 것.
#[test]
fn long_lived_1000_has_linear_proof_cost() {
    check_long_lived_cost(1000, 1000);
}

// 이것을 실패시키는 것: 후보 순서만 바꾸고 2000 노드에서도 증명 비용을 제한하지 않는 것.
#[test]
fn long_lived_2000_has_linear_proof_cost() {
    check_long_lived_cost(2000, 1000);
}

// 이것을 실패시키는 것: 50 commit마다 merge할 때 증명 한도를 초기화하거나 fallback 후 재시도하는 것.
#[test]
fn long_lived_every_50_has_linear_proof_cost() {
    check_long_lived_cost(1000, 50);
}

// 이것을 실패시키는 것: stop-proof 한도를 최종 cycle 검증에도 적용하여 검증을 생략하는 것.
#[test]
fn exhausted_proof_still_validates_cycles() {
    struct WideCycle;
    impl gix_object::Find for WideCycle {
        fn try_find<'a>(
            &self,
            oid: &gix_index::hash::oid,
            buffer: &'a mut Vec<u8>,
        ) -> gix_error::ExnResult<Option<gix_object::Data<'a>>> {
            buffer.clear();
            buffer.extend(b"tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\n");
            if oid == id(1) {
                // Exhaust the node-based allowance on duplicate edges before
                // reaching the cycle. Synthetic only: verified hashes forbid it.
                for _ in 0..64 {
                    buffer.extend(format!("parent {}\n", id(2)).bytes());
                }
                buffer.extend(format!("parent {}\n", id(1)).bytes());
            }
            buffer.extend(b"author F <f@example.org> 200 +0000\ncommitter F <f@example.org> 200 +0000\n\ncycle\n");
            Ok(Some(gix_object::Data {
                kind: gix_object::Kind::Commit,
                data: buffer,
                object_hash: gix_index::hash::Kind::Sha1,
            }))
        }
    }
    let f = Fixture::new();
    let root = f.root();
    let access = access();
    let m = RefCell::new(meter());
    git::stage_c::observations::take();
    assert_eq!(
        walk(&port(&root, &access, &m), &WideCycle, id(1), id(2)),
        Err(INVALID)
    );
    let cost = git::stage_c::observations::take();
    assert_eq!(cost.fallbacks, 1, "{cost:?}");
    assert_eq!(cost.proof_work, 8, "{cost:?}");
}
