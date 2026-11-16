#![cfg(test)]
use super::*;
use crate::diag::DiagCode;
use alloc::borrow::ToOwned;
use alloc::collections::BTreeMap;
use alloc::vec;

/// Files by name; `extends` entries are names. Trust: names starting
/// with `shape-` are shape-only, `unsafe-` unsafe.
#[derive(Default)]
pub(crate) struct Files(pub BTreeMap<&'static str, String>);

pub(crate) fn opened(name: &str, text: &str, key: u64) -> Opened {
    let trust = if name.starts_with("shape-") {
        Trust::ShapeOnly
    } else if name.starts_with("unsafe-") {
        Trust::Unsafe
    } else {
        Trust::Executable
    };
    Opened {
        key: FileKey { dev: 1, ino: key },
        bytes: text.as_bytes().to_vec(),
        trust,
        display: name.as_bytes().to_vec(),
    }
}

impl Resolver for Files {
    fn open(&mut self, _: &Opened, r: &ExtendsRef) -> Result<Opened, OpenError> {
        let (i, (name, text)) = self
            .0
            .iter()
            .enumerate()
            .find(|(_, (n, _))| **n == r.text)
            .ok_or(OpenError {
                reason: "no such file".to_owned(),
                trust: opened(&r.text, "", 0).trust,
            })?;
        Ok(opened(name, text, 100 + i as u64))
    }
}

pub(crate) fn files(list: &[(&'static str, &str)]) -> Files {
    Files(list.iter().map(|(n, t)| (*n, String::from(*t))).collect())
}

fn name(f: &Found) -> String {
    String::from_utf8(f.opened.display.clone()).unwrap()
}

fn order(g: &LoadReport) -> Vec<String> {
    g.order.iter().map(|id| name(g.get(*id).unwrap())).collect()
}

fn trust_of(g: &LoadReport, n: &str) -> Trust {
    g.files
        .iter()
        .find(|f| f.opened.display == n.as_bytes())
        .unwrap()
        .trust
}

fn codes_of(e: &[Diagnostic]) -> Vec<DiagCode> {
    e.iter().map(|d| d.code).collect()
}

fn leak(s: String) -> &'static str {
    alloc::boxed::Box::leak(s.into_boxed_str())
}

const V: [u32; 3] = [0, 3, 0];

// 이것을 실패시키는 것: 자기보다 extends를 뒤에 적용하거나(앞이 이김), 오른쪽부터 걷거나,
// 다이아몬드에서 같은 파일을 두 번 적용하는 것.
#[test]
fn depth_first_left_first_and_diamond_once() {
    let mut f = files(&[
        ("a", "extends = [\"c\"]\nx = 1\n"),
        ("b", "extends = [\"c\"]\nx = 2\n"),
        ("c", "x = 3\n"),
    ]);
    let g = load(
        vec![opened("root", "extends = [\"a\", \"b\"]\n", 1)],
        &mut f,
        V,
    )
    .unwrap();
    assert_eq!(order(&g), ["c", "a", "b", "root"]);
    assert!(g.files.iter().all(|s| s.tree.get("extends").is_none()));
    let c = g.files.iter().find(|f| f.opened.display == b"c").unwrap();
    assert_eq!(c.via, [SourceId(0), SourceId(1)]);
}

// 이것을 실패시키는 것: 순환을 끝없이 따라가거나 오류로 내지 않는 것.
#[test]
fn a_cycle_is_an_error() {
    let mut f = files(&[("a", "extends = [\"b\"]\n"), ("b", "extends = [\"a\"]\n")]);
    let e = load(vec![opened("root", "extends = [\"a\"]\n", 1)], &mut f, V).unwrap_err();
    assert_eq!(codes_of(&e.errors), [codes::EXTENDS_CYCLE]);
    assert_eq!(e.files.len(), 3, "the catalog keeps every file met");
}

fn chain(n: usize, prefix: &str) -> Files {
    let names: Vec<&'static str> = (0..n)
        .map(|i| leak(alloc::format!("{prefix}{i}")))
        .collect();
    let mut list = Vec::new();
    for i in 0..n {
        let text = if i + 1 < n {
            alloc::format!("extends = [\"{}\"]\n", names[i + 1])
        } else {
            String::new()
        };
        list.push((names[i], text));
    }
    Files(list.into_iter().collect())
}

// 이것을 실패시키는 것: 깊이 8·고유 32·합계 1 MiB 경계를 하나씩 어긋나게 세는 것.
#[test]
fn limits_are_exact() {
    let mut f = chain(8, "f");
    assert!(load(vec![opened("root", "extends = [\"f0\"]\n", 1)], &mut f, V).is_ok());
    let mut f = chain(9, "f");
    let e = load(vec![opened("root", "extends = [\"f0\"]\n", 1)], &mut f, V).unwrap_err();
    assert_eq!(codes_of(&e.errors), [codes::EXTENDS_TOO_DEEP]);
    let fan = |n: usize| {
        let names: Vec<String> = (0..n).map(|i| alloc::format!("\"g{i}\"")).collect();
        let list: Vec<(&'static str, String)> = (0..n)
            .map(|i| (leak(alloc::format!("g{i}")), String::new()))
            .collect();
        (
            alloc::format!("extends = [{}]\n", names.join(", ")),
            Files(list.into_iter().collect()),
        )
    };
    let (root, mut f) = fan(31);
    assert_eq!(
        load(vec![opened("root", &root, 1)], &mut f, V)
            .unwrap()
            .order
            .len(),
        32
    );
    let (root, mut f) = fan(32);
    let e = load(vec![opened("root", &root, 1)], &mut f, V).unwrap_err();
    assert_eq!(codes_of(&e.errors), [codes::EXTENDS_TOO_MANY]);
    let big = |n| alloc::format!("{}\n", "#".repeat(n));
    let quarter = 256 * 1024;
    let head = "extends = [\"h0\", \"h1\", \"h2\"]\n";
    let root = alloc::format!("{head}{}", "#".repeat(quarter - head.len()));
    let mut f = files(&[
        ("h0", &big(quarter - 1)),
        ("h1", &big(quarter - 1)),
        ("h2", &big(quarter - 1)),
    ]);
    assert!(load(vec![opened("root", &root, 1)], &mut f, V).is_ok());
    let mut f = files(&[
        ("h0", &big(quarter - 1)),
        ("h1", &big(quarter - 1)),
        ("h2", &big(quarter)),
    ]);
    let e = load(vec![opened("root", &root, 1)], &mut f, V).unwrap_err();
    assert_eq!(codes_of(&e.errors), [codes::EXTENDS_TOO_BIG]);
}

// 이것을 실패시키는 것: 모양 전용 파일 아래의 파일을 깨끗하다고 보거나(오염 전이 없음),
// 깨끗한 경로로도 닿은 파일을 오염된 채로 두는 것(P-S2), Unsafe 파일 아래를 깨끗하다고 보는 것.
#[test]
fn taint_flows_down_shape_only_edges() {
    let mut f = files(&[
        ("shape-team", "extends = [\"mine\"]\n"),
        ("mine", "x = 1\n"),
        ("other", "extends = [\"deep\"]\ny = 1\n"),
        ("deep", "z = 1\n"),
        ("shape-repo", "extends = [\"other\"]\n"),
        ("unsafe-x", "extends = [\"deep\"]\n"),
    ]);
    let g = load(
        vec![opened("root", "extends = [\"shape-team\"]\n", 1)],
        &mut f,
        V,
    )
    .unwrap();
    assert_eq!(order(&g), ["mine", "shape-team", "root"]);
    assert_eq!(
        (trust_of(&g, "mine"), trust_of(&g, "shape-team")),
        (Trust::ShapeOnly, Trust::ShapeOnly)
    );
    for list in ["\"shape-repo\", \"other\"", "\"other\", \"shape-repo\""] {
        let g = load(
            vec![opened("root", &alloc::format!("extends = [{list}]\n"), 1)],
            &mut f,
            V,
        )
        .unwrap();
        assert_eq!(
            (trust_of(&g, "other"), trust_of(&g, "deep")),
            (Trust::Executable, Trust::Executable),
            "{list}"
        );
    }
    let g = load(
        vec![opened("root", "extends = [\"unsafe-x\"]\n", 1)],
        &mut f,
        V,
    )
    .unwrap();
    assert_eq!(
        (trust_of(&g, "deep"), trust_of(&g, "unsafe-x")),
        (Trust::ShapeOnly, Trust::Unsafe)
    );
}

// 신뢰 파일의 적용 자리는 신뢰 경로만으로 정한다.
// 이것을 실패시키는 것: 모양 전용 파일이 신뢰 파일을 먼저 가리켜 그 자리를 앞당기는 것(뒤가 이기는 순서가 바뀜).
#[test]
fn trusted_files_keep_their_trusted_place() {
    let mut f = files(&[
        ("a", "x = 1\n"),
        ("f", "x = 2\n"),
        ("shape-t", "extends = [\"f\"]\ny = 1\n"),
    ]);
    let g = load(
        vec![opened("root", "extends = [\"shape-t\", \"a\", \"f\"]\n", 1)],
        &mut f,
        V,
    )
    .unwrap();
    assert_eq!(order(&g), ["shape-t", "a", "f", "root"]);
}

// 등록만 된 모양 전용 잎도 DFS로 걷는다. 등록을 완료로 보거나 두 번 적용하면 실패한다.
#[test]
fn registered_shape_leaves_walk_depth_first_once() {
    use crate::config::merge::{MValue, Slot, merge};
    let mut f = files(&[
        ("shape-a", "extends = ['shape-b']\nx = 1"),
        ("shape-b", "x = 2"),
    ]);
    let g = load(
        vec![opened("root", "extends = ['shape-a', 'shape-b']", 1)],
        &mut f,
        V,
    )
    .unwrap();
    assert_eq!(order(&g), ["shape-b", "shape-a", "root"]);
    assert_eq!(g.files.len(), 3);
    assert_eq!(g.files[2].via, [SourceId(0), SourceId(1)]);
    let m = merge(&g, &[], &|_| Slot::Shape);
    assert_eq!(
        m.root.get("x").unwrap().value,
        MValue::Scalar(Value::Int(1))
    );
    assert!(g.warnings.is_empty());
}

// 미리 등록된 A↔B도 순환이다. 실패한 하위 그래프의 등록된 잎을 남기거나 다시 걷으면 실패한다.
#[test]
fn registered_shape_cycle_drops_the_whole_subgraph() {
    let mut f = files(&[
        ("shape-a", "extends = ['shape-b']"),
        ("shape-b", "extends = ['shape-a']"),
        ("shape-good", "x = 1"),
    ]);
    let g = load(
        vec![opened(
            "root",
            "extends = ['shape-a', 'shape-b', 'shape-good']",
            1,
        )],
        &mut f,
        V,
    )
    .unwrap();
    assert_eq!(order(&g), ["shape-good", "root"]);
    assert_eq!(g.files[1].status, Status::Dropped);
    assert_eq!(g.files[2].status, Status::Dropped);
    assert_eq!(
        codes_of(&g.warnings),
        [codes::SHAPE_FILE_DROPPED, codes::EXTENDS_CYCLE]
    );
}

struct BudgetProbe {
    files: Files,
    overrun: bool,
    opens_after_overrun: usize,
}

impl Resolver for BudgetProbe {
    fn open(&mut self, from: &Opened, r: &ExtendsRef) -> Result<Opened, OpenError> {
        // The independent recovery subgraph is allowed to keep working.
        if self.overrun && from.display != b"shape-recovery" {
            self.opens_after_overrun += 1;
        }
        self.files.open(from, r)
    }

    fn adopt(&mut self, _: FileKey, trust: Option<Trust>) {
        // Every rejected candidate in this fixture exceeds a budget.
        if trust.is_none() {
            self.overrun = true;
        }
    }
}

// 초과 뒤 같은 노드·조상의 남은 간선을 열거나, 등록된 잎을 다시 걷거나, 버린 예산을 회수하지 않으면 실패한다.
#[test]
fn shape_budget_overrun_stops_all_opens_in_the_subgraph() {
    for code in [
        codes::EXTENDS_TOO_MANY,
        codes::EXTENDS_TOO_BIG,
        codes::EXTENDS_TOO_DEEP,
    ] {
        let mut f = if code == codes::EXTENDS_TOO_DEEP {
            let mut f = chain(8, "d");
            // d5 is at depth 8: d6 overruns before this sibling edge.
            f.0.insert("d5", "extends = ['d6', 'after-child']".into());
            f
        } else {
            files(&[])
        };
        let fan = if code == codes::EXTENDS_TOO_DEEP {
            String::from("'d0', 'after-child'")
        } else {
            let n = if code == codes::EXTENDS_TOO_MANY {
                32
            } else {
                5
            };
            for i in 0..n {
                f.0.insert(
                    leak(alloc::format!("f{i}")),
                    if code == codes::EXTENDS_TOO_BIG {
                        "#".repeat(tree::FILE_BYTES_MAX)
                    } else {
                        String::new()
                    },
                );
            }
            (0..n)
                .map(|i| alloc::format!("'f{i}'"))
                .chain(core::iter::once(String::from("'after-child'")))
                .collect::<Vec<_>>()
                .join(", ")
        };
        f.0.insert(
            "shape-bad",
            "extends = ['shape-registered', 'after-parent']".into(),
        );
        f.0.insert("shape-registered", alloc::format!("extends = [{fan}]"));
        f.0.insert("after-child", "x = 1".into());
        f.0.insert("after-parent", "x = 1".into());
        f.0.insert("shape-recovery", "extends = ['recovered']".into());
        f.0.insert("recovered", "#".repeat(tree::FILE_BYTES_MAX));
        let mut probe = BudgetProbe {
            files: f,
            overrun: false,
            opens_after_overrun: 0,
        };
        let g = load(
            vec![opened(
                "root",
                "extends = ['shape-bad', 'shape-registered', 'shape-recovery']",
                1,
            )],
            &mut probe,
            V,
        )
        .unwrap();
        assert!(probe.overrun, "{code:?}");
        assert_eq!(probe.opens_after_overrun, 0, "{code:?}");
        assert_eq!(
            order(&g),
            ["recovered", "shape-recovery", "root"],
            "{code:?}"
        );
        assert_eq!(codes_of(&g.warnings), [codes::SHAPE_FILE_DROPPED, code]);
        assert!(
            g.files
                .iter()
                .all(|f| !f.opened.display.starts_with(b"after-"))
        );
        let catalog_len = if code == codes::EXTENDS_TOO_MANY {
            35 // Four registered files, 29 children + rejection, recovery.
        } else if code == codes::EXTENDS_TOO_BIG {
            9 // Four registered files, three 256 KiB children + rejection, recovery.
        } else {
            12 // Four registered files, depths 3..=8 + rejection, recovery.
        };
        assert_eq!(g.files.len(), catalog_len, "{code:?}");
        assert_eq!(g.files[2].status, Status::Dropped);
    }
}

// 이것을 실패시키는 것: 모양 전용 하위 그래프가 예산·깊이·순환·문법으로 신뢰 파일을 실패시키는 것,
// 실패한 하위 그래프를 통째로 버리지 않는 것, 버린 예산을 돌려주지 않는 것.
#[test]
fn a_shape_only_subgraph_that_goes_wrong_is_dropped_alone() {
    // Count: shape-t reaches 31 files; `mine` (trusted) still fits.
    let fans: Vec<String> = (0..31).map(|i| alloc::format!("\"s{i}\"")).collect();
    let mut list: Vec<(&'static str, String)> = (0..31)
        .map(|i| (leak(alloc::format!("s{i}")), String::new()))
        .collect();
    list.push((
        "shape-t",
        alloc::format!("extends = [{}]\n", fans.join(", ")),
    ));
    list.push(("mine", String::from("m = 1\n")));
    let mut f = Files(list.into_iter().collect());
    let g = load(
        vec![opened("root", "extends = [\"shape-t\", \"mine\"]\n", 1)],
        &mut f,
        V,
    )
    .unwrap();
    assert_eq!(
        order(&g),
        ["root", "mine"]
            .iter()
            .rev()
            .map(|s| String::from(*s))
            .collect::<Vec<_>>()
    );
    assert_eq!(codes_of(&g.warnings)[0], codes::SHAPE_FILE_DROPPED);
    // Depth: shape-t reaching `mine` first does not make mine's chain deeper.
    let mut f = chain(7, "c");
    f.0.insert("mine", String::from("extends = [\"c0\"]\n"));
    f.0.insert("shape-t", String::from("extends = [\"mine\"]\n"));
    let g = load(
        vec![opened("root", "extends = [\"shape-t\", \"mine\"]\n", 1)],
        &mut f,
        V,
    )
    .unwrap();
    assert_eq!(trust_of(&g, "c6"), Trust::Executable);
    // Cycle and syntax below a shape-only file: dropped, root fine.
    let mut f = files(&[
        ("shape-a", "extends = [\"shape-b\"]\n"),
        ("shape-b", "extends = [\"shape-a\"]\n"),
        ("shape-x", "extends = [\"bad\"]\n"),
        ("bad", "x = [\n"),
    ]);
    let g = load(
        vec![opened("root", "extends = [\"shape-a\", \"shape-x\"]\n", 1)],
        &mut f,
        V,
    )
    .unwrap();
    assert_eq!(order(&g), ["root"]);
    let w = codes_of(&g.warnings);
    assert!(
        w.contains(&codes::EXTENDS_CYCLE) && w.contains(&codes::TOML_SYNTAX),
        "{w:?}"
    );
    // Bytes: a dropped subgraph gives its budget back to the next one.
    let quarter = 256 * 1024 - 1;
    let big = alloc::format!("{}\n", "#".repeat(quarter));
    // 256 KiB: fits only if the dropped 768 KiB were given back.
    let mid = alloc::format!("{}\n", "#".repeat(256 * 1024 - 1));
    let mut f = files(&[
        ("shape-big", "extends = [\"x1\", \"x2\", \"x3\", \"x4\"]\n"),
        ("x1", &big),
        ("x2", &big),
        ("x3", &big),
        ("x4", &big),
        ("shape-small", "extends = [\"y\"]\n"),
        ("y", &mid),
    ]);
    let g = load(
        vec![opened(
            "root",
            "extends = [\"shape-big\", \"shape-small\"]\n",
            1,
        )],
        &mut f,
        V,
    )
    .unwrap();
    assert_eq!(order(&g), ["y", "shape-small", "root"]);
    // The shape-only file itself is counted: 32 trusted files leave no
    // room for it, and only it is dropped.
    let names: Vec<String> = (0..31).map(|i| alloc::format!("\"g{i}\"")).collect();
    let mut list: Vec<(&'static str, String)> = (0..31)
        .map(|i| (leak(alloc::format!("g{i}")), String::new()))
        .collect();
    list.push(("shape-z", String::from("z = 1\n")));
    let mut f = Files(list.into_iter().collect());
    // Before the trusted fan it waits for phase 2; after it, phase 1
    // already knows that only this leaf exceeds the file budget.
    for root in [
        alloc::format!("extends = [\"shape-z\", {}]\n", names.join(", ")),
        alloc::format!("extends = [{}, \"shape-z\"]\n", names.join(", ")),
    ] {
        let g = load(vec![opened("root", &root, 1)], &mut f, V).unwrap();
        assert_eq!(g.order.len(), 32);
        assert_eq!(
            codes_of(&g.warnings),
            [codes::SHAPE_FILE_DROPPED, codes::EXTENDS_TOO_MANY]
        );
    }
}

fn assert_shape_via(g: &LoadReport, code: DiagCode, expected: &[&str]) {
    let d = g.warnings.iter().find(|d| d.code == code).unwrap();
    let actual: Vec<String> = d.via.iter().map(|id| name(g.get(*id).unwrap())).collect();
    assert_eq!(actual, expected, "{code}");
}

// 이것을 실패시키는 것: 모양 전용 경로 오류에서 현재 파일의 경유 목록을 빼는 것.
#[test]
fn shaped_bad_path_keeps_via() {
    let mut f = files(&[
        ("shape-parent", "extends = [\"leaf\"]"),
        ("leaf", "extends = [\"missing\"]"),
    ]);
    let g = load(
        vec![opened("root", "extends = [\"shape-parent\"]", 1)],
        &mut f,
        V,
    )
    .unwrap();
    assert_shape_via(&g, codes::EXTENDS_BAD_PATH, &["root", "shape-parent"]);
}

// 이것을 실패시키는 것: 모양 전용 순환 오류에서 현재 파일의 경유 목록을 빼는 것.
#[test]
fn shaped_cycle_keeps_via() {
    let mut f = files(&[
        ("shape-parent", "extends = [\"leaf\"]"),
        ("leaf", "extends = [\"shape-parent\"]"),
    ]);
    let g = load(
        vec![opened("root", "extends = [\"shape-parent\"]", 1)],
        &mut f,
        V,
    )
    .unwrap();
    assert_shape_via(&g, codes::EXTENDS_CYCLE, &["root", "shape-parent"]);
}

// 이것을 실패시키는 것: 모양 전용 깊이·파일 수·바이트 예산 오류에서 경유 목록을 빼는 것.
#[test]
fn shaped_edge_budgets_keep_via() {
    for code in [
        codes::EXTENDS_TOO_DEEP,
        codes::EXTENDS_TOO_MANY,
        codes::EXTENDS_TOO_BIG,
    ] {
        let mut f = files(&[
            ("shape-parent", "extends = [\"leaf\"]"),
            ("leaf", "extends = [\"end\"]"),
            ("end", ""),
        ]);
        let mut roots = vec![opened("root", "extends = [\"shape-parent\"]", 1)];
        let mut expected = vec!["root", "shape-parent"];
        if code == codes::EXTENDS_TOO_DEEP {
            for n in 0..7 {
                let next = if n == 6 {
                    "end".to_owned()
                } else {
                    alloc::format!("hop{}", n + 1)
                };
                let name = leak(alloc::format!("hop{n}"));
                f.0.insert(name, alloc::format!("extends = [\"{next}\"]"));
                if n < 6 {
                    expected.push(name);
                }
            }
            f.0.insert("shape-parent", "extends = [\"hop0\"]".to_owned());
        } else if code == codes::EXTENDS_TOO_MANY {
            roots.extend((0..29).map(|n| opened("trusted", "", 2 + n)));
        } else {
            f.0.insert("end", "#".repeat(TOTAL_BYTES_MAX));
        }
        let g = load(roots, &mut f, V).unwrap();
        assert_shape_via(&g, code, &expected);
    }
}

// 이것을 실패시키는 것: 모양 전용 파일 자체가 잔여 예산을 넘을 때 경유 목록을 빼는 것.
#[test]
fn shaped_leaf_over_budget_keeps_via() {
    let mut f = files(&[("shape-leaf", "")]);
    let mut roots = vec![opened("root", "extends = [\"shape-leaf\"]", 1)];
    roots.extend((0..31).map(|n| opened("trusted", "", 2 + n)));
    let g = load(roots, &mut f, V).unwrap();
    assert_shape_via(&g, codes::EXTENDS_TOO_MANY, &["root"]);
}

// 이것을 실패시키는 것: 모양 전용 잎을 열지 못하거나 너무 클 때 그것을 가리킨 신뢰 파일의 문제로 보는 것
// (저장소가 테마 파일을 지우거나 키우는 것만으로 사용자 설정 전체가 거부됨).
#[test]
fn a_shape_only_leaf_that_cannot_be_used_is_dropped_alone() {
    let huge = alloc::format!("{}\n", "#".repeat(1024 * 1024 + 10));
    let mut f = files(&[("shape-big", &huge)]);
    for root in [
        "extends = [\"shape-big\"]\n",
        "extends = [\"shape-gone\"]\n",
    ] {
        let g = load(vec![opened("root", root, 1)], &mut f, V).unwrap();
        assert_eq!(order(&g), ["root"], "{root}");
        assert_eq!(
            codes_of(&g.warnings)[0],
            codes::SHAPE_FILE_DROPPED,
            "{root}"
        );
    }
    // A trusted file that is missing still fails the load.
    let e = load(vec![opened("root", "extends = [\"gone\"]\n", 1)], &mut f, V).unwrap_err();
    assert_eq!(codes_of(&e.errors), [codes::EXTENDS_BAD_PATH]);
}

// 이것을 실패시키는 것: 뿌리(`conf.d`)를 예산 밖에 두는 것. 신뢰 뿌리는 읽기를 실패시키고,
// 모양 전용 뿌리는 그것만 빠진다.
#[test]
fn roots_spend_the_same_budget() {
    let mut f = files(&[]);
    let roots = |n: u64| (0..n).map(|i| opened("r", "", i + 1)).collect::<Vec<_>>();
    assert_eq!(load(roots(32), &mut f, V).unwrap().order.len(), 32);
    let e = load(roots(33), &mut f, V).unwrap_err();
    assert_eq!(codes_of(&e.errors), [codes::EXTENDS_TOO_MANY]);
    let mut r = roots(32);
    r.push(opened("shape-root", "", 99));
    let g = load(r, &mut f, V).unwrap();
    assert_eq!(
        (g.order.len(), codes_of(&g.warnings)[0]),
        (32, codes::SHAPE_FILE_DROPPED)
    );
}

/// Roots on disk: counts what core asked to read.
struct Disk {
    read: Vec<u64>,
    /// Bytes each read returns (a file can grow after `fstat`).
    pad: usize,
}

impl Resolver for Disk {
    fn open(&mut self, _: &Opened, _: &ExtendsRef) -> Result<Opened, OpenError> {
        unreachable!("the roots here have no extends")
    }
    fn open_root(&mut self, r: &RootMeta) -> Result<Opened, OpenError> {
        self.read.push(r.key.ino);
        let name = String::from_utf8(r.display.clone()).unwrap();
        let mut o = opened(&name, "", r.key.ino);
        o.bytes = vec![b'#'; self.pad];
        Ok(o)
    }
}

fn on_disk(name: &str, size: usize, ino: u64) -> Root {
    let o = opened(name, "", ino);
    Root::File(RootMeta {
        key: o.key,
        size,
        trust: o.trust,
        display: o.display,
    })
}

// 초과 뿌리는 읽지도 파싱하지도 않는다. 크기만 보고 판정하고, 모양 전용·unsafe 뿌리는 적용 순서에서 빠진다(W406).
// 이것을 실패시키는 것: 뿌리를 연 뒤 예산을 보는 것, 초과한 unsafe 뿌리를 적용하는 것, 읽은 바이트를 다시 세지 않는 것.
#[test]
fn roots_over_the_budget_are_not_parsed() {
    let mut roots: Vec<Root> = (0..32).map(|i| on_disk("r", 0, i + 1)).collect();
    roots.push(on_disk("unsafe-root", 0, 90));
    roots.push(on_disk("shape-root", 0, 91));
    // Already in memory and not TOML: parsed, it would give a syntax error.
    roots.push(opened("unsafe-mem", "= = =", 92).into());
    let mut disk = Disk {
        read: Vec::new(),
        pad: 0,
    };
    let g = load(roots, &mut disk, V).unwrap();
    assert_eq!(disk.read, (1..=32).collect::<Vec<u64>>());
    assert_eq!(g.order.len(), 32);
    assert!(order(&g).iter().all(|n| n == "r"));
    for n in ["unsafe-root", "shape-root", "unsafe-mem"] {
        let f = g
            .files
            .iter()
            .find(|f| f.opened.display == n.as_bytes())
            .unwrap();
        assert_eq!(
            (f.status, f.opened.bytes.len()),
            (Status::Dropped, 0),
            "{n}"
        );
    }
    let c = codes_of(&g.warnings);
    assert_eq!(
        c.iter()
            .filter(|c| **c == codes::SHAPE_FILE_DROPPED)
            .count(),
        3
    );
    assert!(
        c.iter()
            .all(|c| *c == codes::SHAPE_FILE_DROPPED || *c == codes::EXTENDS_TOO_MANY)
    );
    // The size first seen decides: one big root is not read either.
    let mut disk = Disk {
        read: Vec::new(),
        pad: 0,
    };
    let g = load(
        vec![on_disk("shape-big", TOTAL_BYTES_MAX + 1, 7)],
        &mut disk,
        V,
    )
    .unwrap();
    assert!(disk.read.is_empty() && g.order.is_empty());
    assert!(codes_of(&g.warnings).contains(&codes::EXTENDS_TOO_BIG));
    // The bytes read count, not the size first seen: a trusted root that
    // grew past the budget fails the load.
    let mut disk = Disk {
        read: Vec::new(),
        pad: TOTAL_BYTES_MAX + 1,
    };
    let e = load(vec![on_disk("r", 1, 8)], &mut disk, V).unwrap_err();
    assert!(codes_of(&e.errors).contains(&codes::EXTENDS_TOO_BIG));
}

// 이것을 실패시키는 것: 첫 잘못된 extends에서 멈춰 나머지 오류를 숨기는 것.
#[test]
fn every_bad_edge_is_reported() {
    let mut f = files(&[]);
    let e = load(
        vec![opened("root", "extends = [\"nope1\", \"nope2\"]\n", 1)],
        &mut f,
        V,
    )
    .unwrap_err();
    assert_eq!(
        codes_of(&e.errors),
        [codes::EXTENDS_BAD_PATH, codes::EXTENDS_BAD_PATH]
    );
}

// 이것을 실패시키는 것: 신뢰 파일의 requires·문법 오류를 경고로 낮추는 것.
#[test]
fn trusted_problems_fail_the_load() {
    let mut f = files(&[]);
    let e = load(vec![opened("root", "requires = \">=0.4\"\n", 1)], &mut f, V).unwrap_err();
    assert_eq!(codes_of(&e.errors), [codes::REQUIRES_NEWER]);
    assert!(
        load(
            vec![opened("root", "requires = \">=0.3\"\nversion = 1\n", 1)],
            &mut f,
            V
        )
        .is_ok()
    );
    let mut f = files(&[("shape-t", "requires = \">=9.0\"\n")]);
    let g = load(
        vec![opened("root", "extends = [\"shape-t\"]\n", 1)],
        &mut f,
        V,
    )
    .unwrap();
    assert_eq!(
        codes_of(&g.warnings),
        [codes::SHAPE_FILE_DROPPED, codes::REQUIRES_NEWER]
    );
}

// 이것을 실패시키는 것: `>=` 밖의 형식을 받거나 부분이 하나뿐인 버전을 받는 것.
#[test]
fn requires_grammar() {
    assert_eq!(parse_requires(">=0.3"), Some([0, 3, 0]));
    assert_eq!(parse_requires(">=1.2.3"), Some([1, 2, 3]));
    assert_eq!(parse_requires(">=999999999.0"), Some([999999999, 0, 0]));
    for bad in [
        "0.3",
        ">=0",
        ">=0.3.1.2",
        ">= 0.3",
        ">=0.x",
        ">=0..3",
        "^0.3",
        ">=1000000000.0",
    ] {
        assert_eq!(parse_requires(bad), None, "{bad}");
    }
}

// 이것을 실패시키는 것: `-` 뒤를 패치에 붙여 읽어 패치가 0이 되는 것, pre-release 표지를 버리는 것,
// `+` 뒤의 빌드 정보를 pre-release로 읽는 것, 숫자만 준 판을 pre-release로 만드는 것.
#[test]
fn a_version_keeps_its_patch_and_its_pre_release() {
    let v = |numbers, pre_release| Version {
        numbers,
        pre_release,
    };
    for (text, want) in [
        ("1.22.333", v([1, 22, 333], false)),
        ("0.3", v([0, 3, 0], false)),
        ("1.2.3-rc.4", v([1, 2, 3], true)),
        ("0.1.0-rc.1+build.7", v([0, 1, 0], true)),
        ("1.0.0+build-5", v([1, 0, 0], false)),
    ] {
        assert_eq!(Version::parse(text), want, "{text}");
    }
    assert_eq!(Version::from([0, 3, 0]), v([0, 3, 0], false));
}

// SemVer: a pre-release is below the release with the same numbers.
// 이것을 실패시키는 것: 숫자를 `>=`로 비교하는 것(`0.1.0-rc.1`이 `>=0.1.0`을 만족), 같은 숫자의
// pre-release를 받는 것, 더 높은 숫자의 pre-release를 거절하는 것.
#[test]
fn a_pre_release_does_not_meet_its_own_release() {
    let rc = Version::parse("0.1.0-rc.1");
    assert!(!rc.meets([0, 1, 0]));
    assert!(!rc.meets([0, 1, 1]));
    assert!(rc.meets([0, 0, 9]));
    assert!(Version::parse("0.1.1-rc.1").meets([0, 1, 0]));
    let release = Version::parse("0.1.0");
    assert!(release.meets([0, 1, 0]));
    assert!(!release.meets([0, 1, 1]));
}

// 이것을 실패시키는 것: requires 판정이 pre-release 표지를 보지 않고 숫자만 비교하는 것.
#[test]
fn requires_reads_the_running_pre_release() {
    let rc = Version::parse("0.3.0-rc.1");
    let mut f = files(&[]);
    let root = |text| vec![opened("root", text, 1)];
    let e = load(root("requires = \">=0.3\"\n"), &mut f, rc).unwrap_err();
    assert_eq!(codes_of(&e.errors), [codes::REQUIRES_NEWER]);
    assert!(load(root("requires = \">=0.2.9\"\n"), &mut f, rc).is_ok());
    assert!(load(root("requires = \">=0.3\"\n"), &mut f, V).is_ok());
}

// 이것을 실패시키는 것: 파일 크기 덧셈을 넘치게 하거나, 커진 비신뢰 뿌리를 파싱해 전체를 실패시키는 것.
#[test]
fn oversized_metadata_and_growing_untrusted_roots_are_isolated() {
    for name in ["shape-root", "unsafe-root"] {
        let mut disk = Disk {
            read: Vec::new(),
            pad: TOTAL_BYTES_MAX + 1,
        };
        let g = load(vec![on_disk(name, 1, 7)], &mut disk, V).unwrap();
        assert_eq!(disk.read, [7]);
        assert!(g.order.is_empty());
        assert_eq!(g.files[0].status, Status::Dropped);
        assert_eq!(
            codes_of(&g.warnings),
            [codes::SHAPE_FILE_DROPPED, codes::EXTENDS_TOO_BIG]
        );
    }
    let mut disk = Disk {
        read: Vec::new(),
        pad: 0,
    };
    let g = load(
        vec![
            Root::Read(opened("r", "x = 1", 1)),
            on_disk("shape-huge", usize::MAX, 7),
        ],
        &mut disk,
        V,
    )
    .unwrap();
    assert!(disk.read.is_empty());
    assert_eq!(order(&g), ["r"]);
    assert!(codes_of(&g.warnings).contains(&codes::EXTENDS_TOO_BIG));
}

// 이것을 실패시키는 것: 하위 그래프가 실패한 Unsafe 잎을 무료로 남기거나, 잎 자체가 초과해도 남기는 것.
#[test]
fn retained_unsafe_leaves_still_spend_their_budget() {
    let mut roots = vec![
        opened("unsafe-a", "extends = [\"gone\"]", 90),
        opened("unsafe-b", "extends = [\"gone\"]", 91),
    ];
    roots.extend((0..31).map(|i| opened("r", "", i + 1)));
    let g = load(roots, &mut files(&[]), V).unwrap();
    assert_eq!(g.order.len(), 32);
    assert_eq!(g.files[0].status, Status::Applied);
    assert_eq!(g.files[1].status, Status::Dropped);
    assert_eq!(g.files[0].trust, Trust::Unsafe);

    let mut big = String::from("extends = [\"gone\"]\n#");
    big.push_str(&"#".repeat(tree::FILE_BYTES_MAX - big.len()));
    let mut roots = vec![opened("unsafe-a", &big, 90), opened("shape-b", "x = 1", 91)];
    roots.extend((0..3).map(|i| opened("r", &"#".repeat(tree::FILE_BYTES_MAX), i + 1)));
    let g = load(roots, &mut files(&[]), V).unwrap();
    assert_eq!(order(&g), ["unsafe-a", "r", "r", "r"]);
    assert!(codes_of(&g.warnings).contains(&codes::EXTENDS_TOO_BIG));
}

/// Checks that each resolver read is completed before another begins.
struct Session {
    files: Files,
    root_bytes: Vec<u8>,
    pending: Option<FileKey>,
    adopted: Vec<(FileKey, Option<Trust>)>,
}

impl Resolver for Session {
    fn open(&mut self, from: &Opened, r: &ExtendsRef) -> Result<Opened, OpenError> {
        assert!(self.pending.is_none(), "the preceding read was not adopted");
        let mut o = self.files.open(from, r)?;
        if matches!(r.text.as_str(), "alias" | "shape-alias" | "unsafe-alias") {
            o.key = self
                .files
                .open(
                    from,
                    &ExtendsRef {
                        text: "clean".into(),
                        span: r.span,
                    },
                )?
                .key;
        }
        self.pending = Some(o.key);
        Ok(o)
    }
    fn open_root(&mut self, r: &RootMeta) -> Result<Opened, OpenError> {
        assert!(self.pending.is_none());
        self.pending = Some(r.key);
        Ok(Opened {
            key: r.key,
            bytes: self.root_bytes.clone(),
            trust: r.trust,
            display: r.display.clone(),
        })
    }
    fn adopt(&mut self, key: FileKey, trust: Option<Trust>) {
        if let Some(pending) = self.pending.take() {
            assert_eq!(pending, key);
            self.adopted.push((key, trust));
        }
    }
}

// 이것을 실패시키는 것: 채택 응답 누락, 별칭의 중복 적용, 오염된 자식의 실행 채택, 제외 후보의 실행 증거 보유.
#[test]
fn resolver_adoption_preserves_effective_trust_and_aliases() {
    let huge = "#".repeat(TOTAL_BYTES_MAX + 1);
    let mut session = Session {
        files: files(&[
            ("shape-t", "extends = ['clean', 'tainted', 'big2']"),
            ("clean", "x = 1"),
            ("alias", "x = 1"),
            ("tainted", "x = 2"),
            ("shape-big", &huge),
            ("big2", &huge),
        ]),
        root_bytes: b"extends = ['shape-t', 'clean', 'alias', 'shape-big']".to_vec(),
        pending: None,
        adopted: Vec::new(),
    };
    let g = load(vec![on_disk("root", 100, 1)], &mut session, V).unwrap();
    assert!(session.pending.is_none());
    assert_eq!(order(&g), ["clean", "root"]);
    let key = |name: &[u8]| {
        g.files
            .iter()
            .find(|f| f.opened.display == name)
            .unwrap()
            .opened
            .key
    };
    assert_eq!(
        session.adopted,
        [
            (FileKey { dev: 1, ino: 1 }, Some(Trust::Executable)),
            (key(b"shape-t"), Some(Trust::ShapeOnly)),
            (key(b"clean"), Some(Trust::Executable)),
            (key(b"clean"), Some(Trust::Executable)),
            (key(b"shape-big"), None),
            (key(b"clean"), Some(Trust::Executable)),
            (key(b"tainted"), Some(Trust::ShapeOnly)),
            (key(b"big2"), None),
        ]
    );
    assert_eq!(trust_of(&g, "big2"), Trust::ShapeOnly);
    session.adopted.clear();
    session.root_bytes = huge.into_bytes();
    let g = load(vec![on_disk("shape-root", 1, 1)], &mut session, V).unwrap();
    assert!(session.pending.is_none() && g.order.is_empty());
    assert_eq!(session.adopted, [(FileKey { dev: 1, ino: 1 }, None)]);
}

// 이것을 실패시키는 것: 거절 후보의 정체를 잃거나 큰 바이트를 보유하거나, 별칭을 경로 이름만으로 비교하는 것.
#[test]
fn catalog_keeps_rejected_sources_and_uses_device_and_inode() {
    use crate::diag::SourceView;
    let huge = "#".repeat(TOTAL_BYTES_MAX + 1);
    let g = load(
        vec![opened("root", "extends = ['shape-big']", 1)],
        &mut files(&[("shape-big", &huge)]),
        V,
    )
    .unwrap();
    assert_eq!(g.files.len(), 2);
    assert_eq!(g.files[1].status, Status::Dropped);
    assert_eq!(g.files[1].via, [SourceId(0)]);
    let catalog = Catalog(&g.files);
    assert_eq!(catalog.display(SourceId(1)), b"shape-big");
    assert!(catalog.bytes(SourceId(1)).is_empty());
    assert_eq!(catalog.display(SourceId(999)), b"?");
    assert_eq!(catalog.bytes(SourceId(999)), b"");
    let e = load(
        vec![opened("root", "extends = ['big']", 1)],
        &mut files(&[("big", &huge)]),
        V,
    )
    .unwrap_err();
    assert_eq!(e.files[1].status, Status::Failed);

    let a = opened("a", "x = 1", 1);
    let mut b = a.clone();
    b.key.dev = 2;
    b.display = b"b".to_vec();
    let g = load(vec![a.clone(), a, b], &mut files(&[]), V).unwrap();
    assert_eq!(order(&g), ["a", "b"]);
}

// 이것을 실패시키는 것: 잘못된 메타 키를 받아들이거나, 격리된 원본의 진단 범위·경유 경로를 잃는 것.
#[test]
fn metadata_errors_keep_their_source_and_span() {
    for (text, code) in [
        ("extends = 1", codes::WRONG_TYPE),
        ("extends = [1]", codes::WRONG_TYPE),
        ("version = 2", codes::VERSION_UNKNOWN),
        ("version = false", codes::WRONG_TYPE),
        ("requires = 1", codes::WRONG_TYPE),
        ("requires = '^1.0'", codes::BAD_VALUE),
        ("x = [", codes::TOML_SYNTAX),
    ] {
        let g = load(
            vec![opened("root", "extends = ['shape-bad']", 1)],
            &mut files(&[("shape-bad", text)]),
            V,
        )
        .unwrap();
        assert_eq!(order(&g), ["root"]);
        assert_eq!(
            codes_of(&g.warnings),
            [codes::SHAPE_FILE_DROPPED, code],
            "{text}"
        );
        let d = &g.warnings[1];
        assert_eq!(d.via, [SourceId(0)]);
        let Place::Source { id, span } = d.at else {
            panic!()
        };
        assert_eq!(id, SourceId(1));
        assert!(span.start > 0 && span.start <= span.end && span.end as usize <= text.len());
        let e = load(vec![opened("unsafe-bad", text, 1)], &mut files(&[]), V).unwrap_err();
        assert_eq!(codes_of(&e.errors), [code]);
    }
}

// 이것을 실패시키는 것: 앞서 버린 파일을 뒤 모양 전용 경로에서 다시 살리는 것.
#[test]
fn a_dropped_shared_descendant_stays_dropped() {
    let mut f = files(&[
        ("shape-a", "extends = ['shared', 'gone']"),
        ("shape-b", "extends = ['shared']"),
        ("shared", "x = 1"),
    ]);
    let g = load(
        vec![opened("root", "extends = ['shape-a', 'shape-b']", 1)],
        &mut f,
        V,
    )
    .unwrap();
    assert_eq!(order(&g), ["shape-b", "root"]);
    assert_eq!(
        g.files
            .iter()
            .find(|f| f.opened.display == b"shared")
            .unwrap()
            .status,
        Status::Dropped
    );
}

// 이것을 실패시키는 것: 파서 오류 종류를 다른 안정 코드로 바꾸거나 원래 바이트 범위를 잃는 것.
#[test]
fn syntax_diagnostics_keep_codes_and_ranges() {
    let span = Span { start: 4, end: 7 };
    for (kind, code) in [
        (SyntaxErrorKind::TooLarge, codes::FILE_TOO_LARGE),
        (SyntaxErrorKind::NotUtf8, codes::NOT_UTF8),
        (SyntaxErrorKind::TooDeep, codes::NESTING_TOO_DEEP),
        (SyntaxErrorKind::IntegerRange, codes::INTEGER_RANGE),
        (SyntaxErrorKind::FloatSyntax, codes::TOML_SYNTAX),
        (
            SyntaxErrorKind::Toml("bad syntax".into()),
            codes::TOML_SYNTAX,
        ),
        (SyntaxErrorKind::Json("bad".into()), codes::JSON_SYNTAX),
        (SyntaxErrorKind::Yaml("bad".into()), codes::YAML_SYNTAX),
        (
            SyntaxErrorKind::YamlUnsupported("anchor".into()),
            codes::YAML_UNSUPPORTED,
        ),
    ] {
        let feature = matches!(kind, SyntaxErrorKind::YamlUnsupported(_));
        let d = syntax_diag(SourceId(2), &tree::SyntaxError { span, kind });
        assert_eq!(d.code, code);
        // 이것을 실패시키는 것: E108에 무엇을 거부했는지(`{feature}`)를 싣지 않는 것.
        if feature {
            assert_eq!(d.args[0].name, "feature");
            assert_eq!(d.args[0].value, "anchor");
        }
        assert_eq!(
            d.at,
            Place::Source {
                id: SourceId(2),
                span
            }
        );
    }
}

/// A resolver whose YAML reader returns `tree` for any text.
struct GivenYaml(Result<Table, Vec<tree::SyntaxError>>);
impl Resolver for GivenYaml {
    fn open(&mut self, _: &Opened, _: &ExtendsRef) -> Result<Opened, OpenError> {
        panic!("no extends here")
    }
    fn parse_yaml(&mut self, _: &str) -> Result<Table, Vec<tree::SyntaxError>> {
        self.0.clone()
    }
}

// YAML은 이름으로 고르고, 읽는 쪽이 준 트리를 core가 다시 검사한 뒤에 쓴다. 이것을 실패시키는 것: `.yaml`을 TOML로
// 읽는 것, 읽는 쪽이 없을 때 조용히 빈 표로 두는 것, 읽는 쪽의 트리를 검사 없이 쓰는 것.
#[test]
fn yaml_goes_to_the_reader_and_comes_back_checked() {
    let opened = |text: &str| Opened {
        key: FileKey { dev: 1, ino: 9 },
        bytes: text.as_bytes().to_vec(),
        trust: Trust::Executable,
        display: b"/c/conf.d/a.yaml".to_vec(),
    };
    let codes_of = |e: &LoadError| e.errors.iter().map(|d| d.code).collect::<Vec<_>>();
    // No reader: an error, never an empty file.
    let e = load(vec![opened("theme: x\n")], &mut files(&[]), V).unwrap_err();
    assert_eq!(codes_of(&e), [codes::YAML_SYNTAX]);
    // The reader's tree is used.
    let entry = |key: &str, at: u32| tree::Entry {
        key: key.into(),
        key_span: Span {
            start: at,
            end: at + 1,
        },
        node: tree::Node {
            value: Value::Str("x".into()),
            span: Span {
                start: at + 3,
                end: at + 4,
            },
        },
    };
    let good = Table {
        entries: vec![entry("t", 0)],
    };
    let g = load(vec![opened("t: x\n")], &mut GivenYaml(Ok(good)), V).unwrap();
    assert_eq!(g.files[0].tree.entries[0].key, "t");
    // A tree that breaks a rule is not.
    let twice = Table {
        entries: vec![entry("t", 0), entry("t", 0)],
    };
    let e = load(vec![opened("t: x\n")], &mut GivenYaml(Ok(twice)), V).unwrap_err();
    assert_eq!(codes_of(&e), [codes::YAML_SYNTAX]);
    // The size limit holds on this path too, before the reader sees the
    // text: a reader that would accept anything is not asked.
    // 이것을 실패시키는 것: YAML 길에서 크기 검사를 빼고 UTF-8만 보는 것(256 KiB를 넘는 파일의 앞부분이 읽힘).
    let big = alloc::format!("a: {}\n", "x".repeat(tree::FILE_BYTES_MAX));
    let e = load(vec![opened(&big)], &mut GivenYaml(Ok(Table::default())), V).unwrap_err();
    assert_eq!(codes_of(&e), [codes::FILE_TOO_LARGE]);
}

// 이것을 실패시키는 것: 읽지 못한 비신뢰 뿌리로 전체를 실패시키거나, 신뢰 뿌리의 읽기 실패를 숨기는 것.
#[test]
fn unread_root_errors_are_trust_scoped() {
    for name in ["shape-root", "unsafe-root"] {
        let g = load(vec![on_disk(name, 0, 1)], &mut files(&[]), V).unwrap();
        assert!(g.order.is_empty());
        assert_eq!(g.files[0].status, Status::Dropped);
        assert!(g.files[0].opened.bytes.is_empty());
        assert_eq!(
            codes_of(&g.warnings),
            [codes::SHAPE_FILE_DROPPED, codes::EXTENDS_BAD_PATH]
        );
    }
    let e = load(vec![on_disk("root", 0, 1)], &mut files(&[]), V).unwrap_err();
    assert_eq!(e.files[0].status, Status::Failed);
    assert_eq!(codes_of(&e.errors), [codes::EXTENDS_BAD_PATH]);
    assert!(e.warnings.is_empty());
}

// 한 자리의 두 형식은 그 자리의 신뢰와 무관하게 읽기를 멈춘다(E308). 이것을 실패시키는 것: 공존을 자리의
// 신뢰로 판정하는 것(모양 전용·안전하지 않은 자리면 경고로 내려가 남은 원본이 발행됨).
#[test]
fn two_formats_fail_the_read_at_any_trust() {
    for name in ["root", "shape-root", "unsafe-root"] {
        let Root::File(meta) = on_disk(name, 0, 1) else {
            unreachable!()
        };
        let two = Root::TwoFormats {
            meta,
            other: b"/c/config.toml".to_vec(),
        };
        let e = load(vec![two], &mut files(&[]), V).unwrap_err();
        assert_eq!(codes_of(&e.errors), [codes::TWO_FORMATS], "{name}");
        assert!(e.files[0].opened.bytes.is_empty(), "{name}");
    }
}

// 이것을 실패시키는 것: 비신뢰 별칭을 먼저 본 정체를 신뢰 경로에서도 건너뛰어 신뢰·자리·하위 그래프를 잃는 것.
#[test]
fn a_trusted_alias_promotes_identity_at_its_trusted_place() {
    for alias in ["shape-alias", "unsafe-alias"] {
        let mut session = Session {
            files: files(&[
                (alias, "extends = ['child']"),
                ("clean", "extends = ['child']"),
                ("child", "x = 1"),
                ("middle", "x = 2"),
            ]),
            root_bytes: alloc::format!("extends = ['{alias}', 'middle', 'clean']").into_bytes(),
            pending: None,
            adopted: Vec::new(),
        };
        let g = load(vec![on_disk("root", 100, 1)], &mut session, V).unwrap();
        assert_eq!(order(&g), ["middle", "child", "clean", "root"]);
        assert_eq!(g.files.len(), 4);
        assert!(g.files.iter().all(|f| f.trust == Trust::Executable));
        assert_eq!(g.files[1].via, [SourceId(0)]);
        assert_eq!(session.adopted.last().unwrap().1, Some(Trust::Executable));
        assert!(session.pending.is_none());
    }
}

// ShapeOnly 별칭이 명시적인 Unsafe 원본의 자리·경유 경로·실행 키를 가리면 실패한다.
#[test]
fn unsafe_edge_origin_replaces_shape_alias_and_keeps_execution_keys() {
    use crate::config::merge::{MValue, Slot, merge};
    let unsafe_text = "command = ['blocked']";
    let mut session = Session {
        files: files(&[
            ("shape-alias", unsafe_text),
            ("unsafe-alias", unsafe_text),
            ("clean", unsafe_text),
            ("middle", "command = ['safe']"),
            ("host", "extends = ['unsafe-alias']"),
            ("shape-first", "extends = ['shape-alias']"),
            ("shape-late", "extends = ['shape-alias']"),
        ]),
        root_bytes: b"extends = ['shape-alias', 'shape-first', 'middle', 'host', 'shape-alias', 'shape-late']"
            .to_vec(),
        pending: None,
        adopted: Vec::new(),
    };
    let g = load(vec![on_disk("root", 100, 1)], &mut session, V).unwrap();
    assert_eq!(
        order(&g),
        [
            "shape-first",
            "middle",
            "unsafe-alias",
            "host",
            "shape-late",
            "root"
        ]
    );
    let f = &g.files[1];
    assert_eq!(f.trust, Trust::Unsafe);
    assert_eq!(f.opened.trust, Trust::Unsafe);
    assert_eq!(f.via, [SourceId(0), SourceId(4)]);
    assert_eq!(f.status, Status::Applied);
    let m = merge(&g, &[], &|_| Slot::Exec);
    let cmd = m.root.get("command").unwrap();
    assert_eq!(cmd.origin.trust, Trust::Unsafe);
    assert_eq!(cmd.origin.source, f.id);
    let MValue::Array(args) = &cmd.value else {
        panic!()
    };
    assert_eq!(args[0].value, Value::Str("blocked".into()));
    assert_eq!(
        &f.opened.bytes[cmd.origin.span.start as usize..cmd.origin.span.end as usize],
        b"['blocked']"
    );
    assert_eq!(
        session
            .adopted
            .iter()
            .filter(|(key, _)| *key == f.opened.key)
            .map(|(_, trust)| *trust)
            .collect::<Vec<_>>(),
        [
            Some(Trust::ShapeOnly),
            Some(Trust::Unsafe),
            Some(Trust::Unsafe),
            Some(Trust::Unsafe),
            Some(Trust::Unsafe)
        ]
    );
    assert!(session.pending.is_none());
    assert!(g.warnings.is_empty() && m.warnings.is_empty());
}

// Unsafe 뿌리도 같은 자리 규칙을 따른다. 교체한 ShapeOnly 뿌리를 예산에 이중 계산하면 실패한다.
#[test]
fn unsafe_root_origin_replaces_shape_alias_without_double_charging() {
    use crate::config::merge::{Slot, merge};
    let mut roots = vec![
        opened("shape-alias", "command = ['blocked']", 1),
        opened("middle", "command = ['safe']", 2),
        opened("unsafe-origin", "command = ['blocked']", 1),
        opened("shape-later-alias", "command = ['blocked']", 1),
    ];
    roots.extend((3..32).map(|i| opened("r", "", i)));
    roots.push(opened("shape-last", "", 32));
    let g = load(roots, &mut files(&[]), V).unwrap();
    assert_eq!(&order(&g)[..2], ["middle", "unsafe-origin"]);
    assert_eq!(g.order.len(), 32);
    assert_eq!(g.files.len(), 32);
    assert!(g.warnings.is_empty());
    let f = &g.files[0];
    assert_eq!(f.trust, Trust::Unsafe);
    assert_eq!(f.opened.display, b"unsafe-origin");
    assert!(f.via.is_empty());
    let m = merge(&g, &[], &|_| Slot::Exec);
    let cmd = m.root.get("command").unwrap();
    assert_eq!(cmd.origin.source, f.id);
    assert_eq!(cmd.origin.trust, Trust::Unsafe);
    assert!(m.warnings.is_empty());
}

// 이것을 실패시키는 것: 먼저 본 모양 전용 뿌리가 같은 정체의 신뢰 뿌리를 가리거나, 승격한 뿌리를 비신뢰 예산에 이중 계산하는 것.
#[test]
fn trusted_root_aliases_replace_the_shape_place_and_budget() {
    let mut roots = vec![
        opened("shape-alias", "x = 1", 1),
        opened("middle", "x = 2", 2),
    ];
    roots.push(opened("clean", "x = 1", 1));
    roots.extend((3..32).map(|i| opened("r", "", i)));
    roots.push(opened("shape-last", "", 32));
    let g = load(roots, &mut files(&[]), V).unwrap();
    assert_eq!(&order(&g)[..2], ["middle", "clean"]);
    assert_eq!(g.order.len(), 32);
    assert_eq!(g.files.len(), 32);
    assert_eq!(g.files[0].trust, Trust::Executable);
    assert!(g.warnings.is_empty());
}

// 이것을 실패시키는 것: 깊이 때문에 버린 별칭으로 더 얕은 신뢰 경로까지 버리는 것.
#[test]
fn rejected_aliases_do_not_hide_a_later_trusted_path() {
    let mut session = Session {
        files: chain(8, "f"),
        root_bytes: b"extends = ['f0', 'clean']".to_vec(),
        pending: None,
        adopted: Vec::new(),
    };
    session
        .files
        .0
        .insert("f7", "extends = ['shape-alias']".into());
    session.files.0.insert("shape-alias", "x = 1".into());
    session.files.0.insert("clean", "x = 1".into());
    let g = load(vec![on_disk("root", 100, 1)], &mut session, V).unwrap();
    assert_eq!(trust_of(&g, "clean"), Trust::Executable);
    assert_eq!(g.order.len(), 10);
    assert_eq!(g.files.len(), 10);
    assert!(session.adopted.iter().any(|(_, trust)| trust.is_none()));
    let clean = g
        .files
        .iter()
        .find(|f| f.opened.display == b"clean")
        .unwrap();
    assert_eq!(clean.via, [SourceId(0)]);
}

// 이것을 실패시키는 것: 비신뢰 별칭이 신뢰 조상의 정체를 가리킨다고 신뢰 그래프의 순환으로 처리하는 것.
#[test]
fn a_shape_alias_cannot_create_a_trusted_cycle() {
    let mut session = Session {
        files: files(&[("clean", ""), ("shape-alias", "extends = ['shape-alias']")]),
        root_bytes: b"extends = ['shape-alias']".to_vec(),
        pending: None,
        adopted: Vec::new(),
    };
    // 'clean' is the first entry (key 100), the root's same identity.
    let g = load(vec![on_disk("root", 100, 100)], &mut session, V).unwrap();
    assert_eq!(order(&g), ["root"]);
    assert!(g.warnings.is_empty());
    assert_eq!(session.adopted.len(), 2);
    assert!(
        session
            .adopted
            .iter()
            .all(|(_, t)| *t == Some(Trust::Executable))
    );
}

// 이것을 실패시키는 것: 예산으로 거절한 정체를 재방문할 때 Some(Executable)로 채택해 실행 증거를 보유하는 것.
#[test]
fn rejected_aliases_are_never_adopted_for_execution() {
    let huge = "#".repeat(TOTAL_BYTES_MAX + 1);
    for text in ["extends = ['big', 'big']", "extends = ['shape-t']"] {
        let mut session = Session {
            files: files(&[("big", &huge), ("shape-t", "extends = ['big', 'big']")]),
            root_bytes: text.as_bytes().to_vec(),
            pending: None,
            adopted: Vec::new(),
        };
        let _ = load(vec![on_disk("root", 100, 1)], &mut session, V);
        assert!(session.pending.is_none());
        let big: Vec<_> = session
            .adopted
            .iter()
            .filter(|(k, _)| k.ino == 100)
            .collect();
        assert_eq!(big.len(), if text.contains("shape-t") { 1 } else { 2 });
        assert!(big.iter().all(|(_, trust)| trust.is_none()));
    }
}
