//! Merging the sources (spec section 2 "합치기 규칙"): later wins, tables
//! merge deep, arrays are replaced whole (an explicit `[]` empties), and
//! every value remembers where it came from: the file, the byte range, and
//! the file's trust after taint (rule 6). Provenance lives beside the
//! values here, not in render nodes.
//!
//! Execution keys from a shape-only file are not merged at all: they are
//! dropped with a warning, so the earlier value stays (spec section 2 "키별
//! 출처 검증"). From an unsafe file they are merged and marked, and the
//! compile step does not run that segment.
use crate::config::source::{LoadReport, Trust};
use crate::config::tree::{Node, Span, Table, Value};
use crate::diag::{Diagnostic, Place, SourceId};
use crate::diag_codes as codes;
use alloc::string::String;
use alloc::vec::Vec;

/// What the key table says a path is (Task S3b), for shape-only sources.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Slot {
    /// A table row: a shape-only file may add keys inside.
    Table,
    /// A shape key: a shape-only file may set it.
    Shape,
    /// An execution key, or a path the table does not know.
    Exec,
}

/// Is the key at this path an execution key? (The key table, Task S3b.)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyClass {
    /// Proven to change only how the prompt looks.
    Shape,
    /// Turns execution on, chooses what runs, its arguments, environment or
    /// resources. Every key not proven shape-only is this.
    Exec,
}

/// Where a merged value was written.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Origin {
    pub source: SourceId,
    pub key_span: Span,
    pub span: Span,
    pub trust: Trust,
}

#[derive(Clone, Debug, PartialEq)]
pub enum MValue {
    /// A string, number, boolean or date-time (never a table or array).
    Scalar(Value),
    /// Replaced whole; items keep their spans in `origin.source`.
    Array(Vec<Node>),
    Table(MTable),
}

#[derive(Clone, Debug, PartialEq)]
pub struct MNode {
    pub value: MValue,
    pub origin: Origin,
}

#[derive(Clone, Debug, PartialEq)]
pub struct MEntry {
    pub key: String,
    pub node: MNode,
}

/// Keys in the order they were first written across the sources.
#[derive(Clone, Debug, PartialEq, Default)]
pub struct MTable {
    pub entries: Vec<MEntry>,
}

impl MTable {
    pub fn get(&self, key: &str) -> Option<&MNode> {
        self.entries.iter().find(|e| e.key == key).map(|e| &e.node)
    }
    /// The node at `path`, through tables.
    pub fn at(&self, path: &[&str]) -> Option<&MNode> {
        let (first, rest) = path.split_first()?;
        let n = self.get(first)?;
        match (rest.is_empty(), &n.value) {
            (true, _) => Some(n),
            (false, MValue::Table(t)) => t.at(rest),
            _ => None,
        }
    }
}

#[derive(Debug, Default)]
pub struct Merged {
    pub root: MTable,
    pub warnings: Vec<Diagnostic>,
}

struct Ctx<'a> {
    source: SourceId,
    trust: Trust,
    via: &'a [SourceId],
    slot: &'a dyn Fn(&[&str]) -> Slot,
    warnings: Vec<Diagnostic>,
}

fn convert(n: &Node, path: &mut Vec<String>, cx: &mut Ctx<'_>) -> MValue {
    match &n.value {
        Value::Array(items) => MValue::Array(items.clone()),
        Value::Table(t) => {
            let mut m = MTable::default();
            merge_table(&mut m, t, path, cx);
            MValue::Table(m)
        }
        v => MValue::Scalar(v.clone()),
    }
}

fn dropped(key: &str, path: &[String], n: &Node, cx: &mut Ctx<'_>) {
    let at = Place::Source {
        id: cx.source,
        span: n.span,
    };
    let is_env = key == "kind" && n.value == Value::Str(String::from("env"));
    let mut d = if is_env {
        let id = path.get(1).cloned().unwrap_or_default();
        Diagnostic::new(codes::ENV_SEGMENT_IGNORED, at).arg("id", id)
    } else {
        Diagnostic::new(codes::EXEC_KEY_IGNORED, at).arg("key", path.join("."))
    };
    d.via = cx.via.to_vec();
    cx.warnings.push(d);
}

fn merge_table(into: &mut MTable, from: &Table, path: &mut Vec<String>, cx: &mut Ctx<'_>) {
    for e in &from.entries {
        path.push(e.key.clone());
        let segs: Vec<&str> = path.iter().map(String::as_str).collect();
        let is_table = matches!(e.node.value, Value::Table(_));
        // From a shape-only file a value must have the shape its row has: a
        // table only where the row is a table (its keys are then checked one
        // by one), anything else only where the row is a shape key. So a
        // shape-only file cannot set an execution key, nor put a table or a
        // number where one is (`enabled = {}`, `segment."custom/k" = 1`).
        let fits = match (cx.slot)(&segs) {
            Slot::Table => is_table,
            Slot::Shape => !is_table,
            Slot::Exec => false,
        };
        if cx.trust == Trust::ShapeOnly && !fits {
            dropped(&e.key, path, &e.node, cx);
            path.pop();
            continue;
        }
        let origin = Origin {
            source: cx.source,
            key_span: e.key_span,
            span: e.node.span,
            trust: cx.trust,
        };
        match (
            into.entries.iter_mut().find(|m| m.key == e.key),
            &e.node.value,
        ) {
            (Some(m), Value::Table(t)) if matches!(m.node.value, MValue::Table(_)) => {
                if let MValue::Table(mt) = &mut m.node.value {
                    merge_table(mt, t, path, cx);
                }
            }
            (Some(m), _) => {
                let value = convert(&e.node, path, cx);
                m.node = MNode { value, origin };
            }
            (None, _) => {
                let value = convert(&e.node, path, cx);
                into.entries.push(MEntry {
                    key: e.key.clone(),
                    node: MNode { value, origin },
                });
            }
        }
        path.pop();
    }
}

/// Merges the applied sources in apply order, leaving out `skip` (the
/// shape-only files a later check dropped).
pub fn merge(report: &LoadReport, skip: &[SourceId], slot: &dyn Fn(&[&str]) -> Slot) -> Merged {
    let mut out = Merged::default();
    for id in report.order.iter().filter(|id| !skip.contains(id)) {
        let Some(s) = report.get(*id) else { continue };
        let mut cx = Ctx {
            source: s.id,
            trust: s.trust,
            via: &s.via,
            slot,
            warnings: Vec::new(),
        };
        merge_table(&mut out.root, &s.tree, &mut Vec::new(), &mut cx);
        out.warnings.append(&mut cx.warnings);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::source::load;
    use crate::config::source::tests::{files, opened};
    use alloc::vec;

    /// A small key table: tables, three execution keys, the rest shape.
    fn slot(p: &[&str]) -> Slot {
        match p {
            ["segment", _, "command" | "kind" | "timeout"] => Slot::Exec,
            ["segment"] | ["segment", _] | ["colors"] | ["layout"] | ["layout", _] => Slot::Table,
            _ => Slot::Shape,
        }
    }

    fn merged(root: &str, list: &[(&'static str, &str)]) -> Merged {
        let mut f = files(list);
        let g = load(vec![opened("root", root, 1)], &mut f, [0, 3, 0]).unwrap();
        merge(&g, &[], &slot)
    }

    fn int(m: &Merged, path: &[&str]) -> Option<i64> {
        match m.root.at(path)?.value {
            MValue::Scalar(Value::Int(n)) => Some(n),
            _ => None,
        }
    }

    // 이것을 실패시키는 것: 앞이 이기거나, 표를 깊게 합치지 않고 통째로 바꾸거나, 배열을 이어 붙이는 것,
    // 빈 배열 `[]`이 비우지 않는 것.
    #[test]
    fn later_wins_tables_deep_arrays_whole() {
        let m = merged(
            "extends = [\"base\"]\n[colors]\nmode = \"light\"\n[layout.line1]\nleft = []\n",
            &[(
                "base",
                "[colors]\nmode = \"dark\"\nflavor = \"a\"\n[layout.line1]\nleft = [\"dir\", \"git\"]\nright = [\"time\"]\n",
            )],
        );
        let s = |p: &[&str]| match &m.root.at(p).unwrap().value {
            MValue::Scalar(Value::Str(s)) => s.clone(),
            v => panic!("{v:?}"),
        };
        assert_eq!(s(&["colors", "mode"]), "light");
        assert_eq!(s(&["colors", "flavor"]), "a");
        let arr = |p: &[&str]| match &m.root.at(p).unwrap().value {
            MValue::Array(a) => a.len(),
            v => panic!("{v:?}"),
        };
        assert_eq!(arr(&["layout", "line1", "left"]), 0);
        assert_eq!(arr(&["layout", "line1", "right"]), 1);
    }

    // 이것을 실패시키는 것: 출처를 첫 파일로 남기거나(뒤가 이겼는데), 바이트 범위를 다른 파일 기준으로 남기는 것.
    #[test]
    fn origin_is_the_winning_file_and_range() {
        let root = "extends = [\"base\"]\nx = 2\n";
        let m = merged(root, &[("base", "x = 1\ny = 1\n")]);
        let x = m.root.get("x").unwrap().origin;
        assert_eq!(
            (x.source, x.span.start as usize),
            (SourceId(0), root.find('2').unwrap())
        );
        let y = m.root.get("y").unwrap().origin;
        assert_eq!(y.source, SourceId(1));
        assert_eq!(int(&m, &["x"]), Some(2));
    }

    // 이것을 실패시키는 것: 모양 전용 파일의 실행 키를 합치는 것(앞 값이 남아야 함), 모양 키까지 버리는 것,
    // env 세그먼트를 일반 경고로 알리는 것.
    #[test]
    fn shape_only_files_give_no_execution_keys() {
        let m = merged(
            "extends = [\"shape-team\"]\n[segment.\"custom/kube\"]\nkind = \"command\"\ncommand = [\"kubectl\"]\n",
            &[(
                "shape-team",
                "[segment.\"custom/kube\"]\ncommand = [\"curl\", \"evil\"]\nformat = \"k8s\"\n[segment.\"custom/secret\"]\nkind = \"env\"\n",
            )],
        );
        // Ids are given in the order files are met: root 0, shape-team 1.
        let cmd = m.root.at(&["segment", "custom/kube", "command"]).unwrap();
        assert_eq!(cmd.origin.source, SourceId(0));
        assert!(m.root.at(&["segment", "custom/kube", "format"]).is_some());
        assert!(m.root.at(&["segment", "custom/secret", "kind"]).is_none());
        let got: Vec<_> = m.warnings.iter().map(|d| d.code).collect();
        assert_eq!(got, [codes::EXEC_KEY_IGNORED, codes::ENV_SEGMENT_IGNORED]);
        // A shape-only file applied after the trusted one cannot replace the command.
        let mut f = files(&[(
            "shape-local",
            "[segment.\"custom/kube\"]\ncommand = [\"curl\"]\n",
        )]);
        let g = load(
            vec![
                opened(
                    "root",
                    "[segment.\"custom/kube\"]\nkind = \"command\"\ncommand = [\"kubectl\"]\n",
                    1,
                ),
                opened(
                    "shape-local",
                    "[segment.\"custom/kube\"]\ncommand = [\"curl\"]\n",
                    2,
                ),
            ],
            &mut f,
            [0, 3, 0],
        )
        .unwrap();
        let m = merge(&g, &[], &slot);
        let cmd = m.root.at(&["segment", "custom/kube", "command"]).unwrap();
        assert_eq!(cmd.origin.trust, Trust::Executable);
        let MValue::Array(a) = &cmd.value else {
            panic!()
        };
        assert_eq!(a[0].value, Value::Str("kubectl".into()));
    }

    // 이것을 실패시키는 것: 모양 전용 파일이 표 자리에 값을, 값 자리에 표를 넣어 신뢰 값을 덮게 두는 것
    // (`segment."custom/k" = 1`로 세그먼트를 통째로 지우는 길).
    #[test]
    fn shape_only_values_keep_the_table_shape() {
        let mut f = files(&[]);
        let g = load(
            vec![
                opened("root", "[colors]\nmode = \"dark\"\n", 1),
                opened("shape-a", "colors = 1\n", 2),
                opened("shape-b", "[colors.mode]\nx = 1\n", 3),
            ],
            &mut f,
            [0, 3, 0],
        )
        .unwrap();
        let m = merge(&g, &[], &slot);
        assert_eq!(
            m.root.at(&["colors", "mode"]).unwrap().value,
            MValue::Scalar(Value::Str("dark".into()))
        );
        assert_eq!(m.warnings.len(), 2);
    }

    // 이것을 실패시키는 것: 안전 검사에 실패한 파일의 실행 키를 버리거나(세그먼트를 이름으로 알릴 수 없음),
    // 출처에 그 표시를 남기지 않는 것.
    #[test]
    fn unsafe_files_are_merged_and_marked() {
        let m = merged(
            "extends = [\"unsafe-mine\"]\n",
            &[(
                "unsafe-mine",
                "[segment.\"custom/kube\"]\nkind = \"command\"\ncommand = [\"kubectl\"]\n",
            )],
        );
        let cmd = m.root.at(&["segment", "custom/kube", "command"]).unwrap();
        assert_eq!(cmd.origin.trust, Trust::Unsafe);
        assert!(m.warnings.is_empty());
    }

    // 이것을 실패시키는 것: 쪽·enabled 출처를 줄 출처로 합치거나, 신뢰 보기를 만들 때 skip 원본을 포함하는 것.
    #[test]
    fn layout_sides_and_enabled_keep_independent_origins() {
        let trusted = "[layout.line1]\nleft = ['custom/a']\nright = ['custom/b']\nenabled = false\n[segment.git]\nenabled = false";
        let shape = "[layout.line1]\nleft = ['custom/c']\nenabled = true";
        let unsafe_text = "[segment.git]\nenabled = true";
        let g = load(
            vec![
                opened("root", trusted, 1),
                opened("shape-t", shape, 2),
                opened("unsafe-t", unsafe_text, 3),
            ],
            &mut files(&[]),
            [0, 3, 0],
        )
        .unwrap();
        let full = merge(&g, &[], &slot);
        for (path, source, trust) in [
            (
                &["layout", "line1", "left"][..],
                SourceId(1),
                Trust::ShapeOnly,
            ),
            (
                &["layout", "line1", "right"][..],
                SourceId(0),
                Trust::Executable,
            ),
            (
                &["layout", "line1", "enabled"][..],
                SourceId(1),
                Trust::ShapeOnly,
            ),
            (
                &["segment", "git", "enabled"][..],
                SourceId(2),
                Trust::Unsafe,
            ),
        ] {
            let node = full.root.at(path).unwrap();
            assert_eq!((node.origin.source, node.origin.trust), (source, trust));
            let bytes = &g.get(source).unwrap().opened.bytes;
            assert_eq!(
                &bytes[node.origin.key_span.start as usize..node.origin.key_span.end as usize],
                path.last().unwrap().as_bytes()
            );
        }
        // S3b uses these two views to intersect execution authorization and
        // visibility; the Unsafe enabled origin is needed for W405.
        let trusted = merge(&g, &[SourceId(1), SourceId(2)], &slot);
        assert_eq!(
            trusted
                .root
                .at(&["layout", "line1", "left"])
                .unwrap()
                .origin
                .source,
            SourceId(0)
        );
        assert_eq!(
            trusted
                .root
                .at(&["layout", "line1", "enabled"])
                .unwrap()
                .value,
            MValue::Scalar(Value::Bool(false))
        );
        assert_eq!(
            full.root.at(&["segment", "git", "enabled"]).unwrap().value,
            MValue::Scalar(Value::Bool(true))
        );
    }

    // 이것을 실패시키는 것: 깊게 합칠 때 표를 처음 만든 출처를 바꿔 P-S3의 버려진 kind 판정을 뒤집는 것.
    #[test]
    fn segment_tables_keep_the_origin_that_created_them() {
        let shape = "[segment.\"custom/k\"]\nkind = 'command'\nformat = 'k'";
        let trusted = "[segment.\"custom/k\"]\nenabled = true";
        for (roots, expected) in [
            (
                vec![opened("shape-t", shape, 1), opened("root", trusted, 2)],
                Trust::ShapeOnly,
            ),
            (
                vec![opened("root", trusted, 2), opened("shape-t", shape, 1)],
                Trust::Executable,
            ),
        ] {
            let g = load(roots, &mut files(&[]), [0, 3, 0]).unwrap();
            let m = merge(&g, &[], &slot);
            assert_eq!(
                m.root.at(&["segment", "custom/k"]).unwrap().origin.trust,
                expected
            );
            assert!(m.root.at(&["segment", "custom/k", "kind"]).is_none());
            assert_eq!(
                m.root
                    .at(&["segment", "custom/k", "enabled"])
                    .unwrap()
                    .origin
                    .trust,
                Trust::Executable
            );
        }
    }

    // 이것을 실패시키는 것: 미지 키를 모양 키로 허용하거나, 표를 넣어 enabled·command를 지우게 하는 것.
    #[test]
    fn unknown_keys_and_table_shaped_execution_overrides_are_ignored() {
        let g = load(
            vec![
                opened(
                    "root",
                    "[segment.\"custom/k\"]\ncommand = ['safe']\nenabled = false",
                    1,
                ),
                opened(
                    "shape-t",
                    "unknown = 1\n[segment.\"custom/k\"]\ncommand = {}\nenabled = {}",
                    2,
                ),
            ],
            &mut files(&[]),
            [0, 3, 0],
        )
        .unwrap();
        let strict_slot = |p: &[&str]| match p {
            ["segment"] | ["segment", _] => Slot::Table,
            ["segment", _, "enabled"] => Slot::Shape,
            _ => Slot::Exec,
        };
        let m = merge(&g, &[], &strict_slot);
        assert!(m.root.get("unknown").is_none());
        assert_eq!(
            m.root
                .at(&["segment", "custom/k", "enabled"])
                .unwrap()
                .value,
            MValue::Scalar(Value::Bool(false))
        );
        assert_eq!(
            m.root
                .at(&["segment", "custom/k", "command"])
                .unwrap()
                .origin
                .source,
            SourceId(0)
        );
        assert_eq!(m.warnings.len(), 3);
        assert!(m.warnings.iter().all(|d| d.code == codes::EXEC_KEY_IGNORED));
    }
}
