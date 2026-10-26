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

// 이것을 실패시키는 것: B를 생략했거나 root tree 읽기가 실패해도 shortcut을 허용하는 것.
#[test]
fn equal_tips_without_read_tree_use_normal_walk() {
    let f = Fixture::new();
    f.init();
    let good = f.commit(&[], "good");
    let bad = f.object("commit", b"tree 1234567890123456789012345678901234567890\nauthor F <f@example.org> 1700000000 +0000\ncommitter F <f@example.org> 1700000000 +0000\n\nbad tree\n");
    for tip in [good, bad] {
        f.refs(tip, tip);
        let root = f.root();
        let access = access();
        let m = RefCell::new(meter());
        let repo = repository(&root, &access, &m);
        if tip == bad {
            assert_eq!(
                git::status_tracked::load_status(&repo).staged,
                Field::PENDING
            );
        }
        assert_eq!(divergence(&repo), Ok(Some((0, 0))));
        assert_eq!(m.borrow().budget.used(Axis::Commits), 1);
        m.borrow_mut()
            .charge_axis(Axis::Commits, budget::COMMITS - 1)
            .unwrap();
        pending(stage_c(&repo));
    }
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
