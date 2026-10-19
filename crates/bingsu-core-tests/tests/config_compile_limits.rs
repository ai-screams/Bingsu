//! Bounded compilation, including input small enough to pass the source caps.
use bingsu_core::bands::{Band, MAX_BANDS, order_bands, order_bands_work};
use bingsu_core::color::palette::Mode;
use bingsu_core::config::compile::BUILTIN_TOML;
use bingsu_core::config::report::{ConfigReport, report};
use bingsu_core::config::source::{
    ExtendsRef, FileKey, OpenError, Opened, Resolver, Status, Trust,
};
use bingsu_core::diag::{Place, SourceId};
use bingsu_core::diag_codes as codes;

#[path = "support/allocation.rs"]
mod allocation;
use allocation::{Counting, counted};

#[global_allocator]
static GLOBAL: Counting = Counting;

struct NoFiles;
impl Resolver for NoFiles {
    fn open(&mut self, _: &Opened, _: &ExtendsRef) -> Result<Opened, OpenError> {
        panic!("fixture has no extends")
    }
}

fn read(user: &str, extra: &str, trust: Trust) -> ConfigReport {
    let roots = [
        (BUILTIN_TOML, Trust::Executable),
        (user, Trust::Executable),
        (extra, trust),
    ]
    .into_iter()
    .enumerate()
    .map(|(i, (text, trust))| Opened {
        key: FileKey {
            dev: 1,
            ino: i as u64,
        },
        bytes: text.as_bytes().to_vec(),
        trust,
        display: format!("fixture-{i}").into_bytes(),
    })
    .collect::<Vec<_>>();
    report(roots, &mut NoFiles, [0, 3, 0], Mode::Dark)
}

fn nested(n: usize) -> String {
    (0..n)
        .map(|i| format!("[layout.when.b{i}]\nmax_cols={}\n", i + 100))
        .collect()
}

fn isolated(r: &ConfigReport) {
    assert!(r.snapshot.is_some(), "{:?}", r.diagnostics);
    assert_eq!(r.files[2].status, Status::Dropped);
    assert_eq!(r.order, [SourceId(0), SourceId(1)]);
    assert!(
        r.diagnostics
            .iter()
            .any(|d| d.code == codes::SHAPE_FILE_DROPPED
                && matches!(
                    d.at,
                    Place::Source {
                        id: SourceId(2),
                        ..
                    }
                ))
    );
}

// 이것을 실패시키는 것: 236 KB 입력의 실제 read/report가 제한 검사 전에 구간 그래프를 만드는 것.
#[test]
fn reviewers_7000_bands_do_no_graph_work() {
    let source = nested(7000);
    assert_eq!(source.len(), 235_990);
    for trust in [Trust::ShapeOnly, Trust::Executable] {
        let mut r = None;
        // Measure the shipped read/report path, including parsing, compilation,
        // shape-only retry and the width-table fallback after a trusted error.
        // The counter lives in this test binary, outside the pure core.
        let counts = counted(|| r = Some(read("", &source, trust)));
        // Baseline allocations: ShapeOnly 136,682; Executable 184,642.
        // Less than 3% headroom: constructing/cloning 7,001 band nodes before
        // rejecting them exceeds this budget, even if diagnostics stay equal.
        let budget = if trust == Trust::ShapeOnly {
            140_000
        } else {
            190_000
        };
        assert!(counts.0 <= budget, "{trust:?}: read allocations {counts:?}");
        let r = r.unwrap();
        if trust == Trust::ShapeOnly {
            isolated(&r);
            assert_eq!(r.snapshot, read("", "", Trust::Executable).snapshot);
        } else {
            assert!(r.snapshot.is_none());
        }
    }
}

// 이것을 실패시키는 것: 현실적인 수천 구간을 거부하거나 한도 초과를 신뢰 파일에 잘못 붙이는 것.
#[test]
fn band_limit_keeps_thousands_and_respects_source_trust() {
    let bands: Vec<_> = (0..MAX_BANDS)
        .map(|i| Band {
            min_cols: None,
            max_cols: Some(i as u16 + 100),
            order: None,
        })
        .collect();
    assert_eq!(
        order_bands(&bands).unwrap(),
        (0..MAX_BANDS).collect::<Vec<_>>()
    );
    let accepted = read("", &nested(MAX_BANDS - 1), Trust::ShapeOnly);
    assert_eq!(accepted.files[2].status, Status::Applied);
    assert_eq!(accepted.snapshot.unwrap().bands.len(), MAX_BANDS);
    // The built-in narrow band also counts, so this is one past the cap.
    let source = nested(MAX_BANDS);
    isolated(&read("", &source, Trust::ShapeOnly));
    let r = read("", &source, Trust::Executable);
    assert!(r.snapshot.is_none());
    assert!(r.diagnostics.iter().any(|d| {
        d.code == codes::BAD_VALUE
            && d.args
                .iter()
                .any(|a| a.name == "expected" && a.value == format!("at most {MAX_BANDS} bands"))
            && matches!(
                d.at,
                Place::Source {
                    id: SourceId(2),
                    ..
                }
            )
    }));
    let mut over = bands;
    over.push(over[0]);
    assert_eq!(
        order_bands(&over),
        Err(bingsu_core::bands::BandError::TooMany)
    );
}

// 이것을 실패시키는 것: 명시적 순서가 섞인 경로에서 매 구간마다 전체 간선을 다시 순회하는 것.
#[test]
fn ordered_bands_at_the_limit_have_quadratic_work() {
    let bands: Vec<_> = (0..MAX_BANDS)
        .map(|i| Band {
            min_cols: None,
            max_cols: Some(i as u16 + 100),
            order: Some(i as i32),
        })
        .collect();
    let (order, work) = order_bands_work(&bands);
    assert_eq!(order.unwrap(), (0..MAX_BANDS).collect::<Vec<_>>());
    // Each initial pair once, then each chosen band against unplaced bands.
    // Count inside `before`, so recomputing predecessors cannot hide work.
    let n = MAX_BANDS;
    assert_eq!(work, n * (n - 1));
}

// 이것을 실패시키는 것: visit 추가 없이 매 구간의 선행자를 전체 구간에서 다시 계산하는 것.
// Small enough that the cubic mutation finishes and fails the comparison budget.
#[test]
fn predecessor_rescans_cannot_hide_relation_comparisons() {
    let n = 64;
    let bands: Vec<_> = (0..n)
        .map(|i| Band {
            min_cols: None,
            max_cols: Some(i as u16 + 100),
            order: Some(i as i32),
        })
        .collect();
    let (order, comparisons) = order_bands_work(&bands);
    assert_eq!(order.unwrap(), (0..n).collect::<Vec<_>>());
    assert_eq!(comparisons, n * (n - 1));
}

fn wide_line() -> String {
    format!(
        "[layout.line1]\nleft = [{}]\nright = []\n",
        vec!["\"dir\""; 156].join(",")
    )
}

// 이것을 실패시키는 것: 상속 확장을 구간 수만으로 제한하거나 오류 원인에서 구간·배열·템플릿을 빼는 것.
#[test]
fn expanded_layout_budget_isolates_shape_only_sources() {
    let user = wide_line();
    let bands = nested(700);
    let baseline = read(&user, "", Trust::Executable).snapshot;
    assert!(baseline.is_some());
    let r = read(&user, &bands, Trust::ShapeOnly);
    isolated(&r);
    assert_eq!(r.snapshot, baseline);
    assert!(r.diagnostics.iter().any(|d| {
        d.args
            .iter()
            .any(|a| a.value.contains("expanded layout work units"))
    }));
    // The expansion can come from the inherited array or template, too.
    for shape in [
        user.clone(),
        format!("[style]\ntemplate = '{}{{char}}'\n", " ".repeat(4090)),
    ] {
        let r = read(&bands, &shape, Trust::ShapeOnly);
        isolated(&r);
        assert_eq!(r.snapshot, read(&bands, "", Trust::Executable).snapshot);
    }
    let r = read(&user, &bands, Trust::Executable);
    assert!(r.snapshot.is_none());
    assert!(r.diagnostics.iter().any(|d| {
        d.args
            .iter()
            .any(|a| a.value.contains("expanded layout work units"))
    }));
}

// 이것을 실패시키는 것: 전체 보기만 제한해 모양 전용 덮어쓰기 뒤의 신뢰 실행 보기를 무제한 확장하는 것.
#[test]
fn trusted_layout_expansion_is_checked_even_when_overridden() {
    let user = wide_line() + &nested(700);
    let r = read(&user, "[layout.line1]\nleft = ['dir']\n", Trust::ShapeOnly);
    assert!(r.snapshot.is_none());
    assert!(r.diagnostics.iter().any(|d| {
        d.code == codes::BAD_VALUE
            && matches!(
                d.at,
                Place::Source {
                    id: SourceId(1),
                    ..
                }
            )
            && d.args
                .iter()
                .any(|a| a.value.contains("expanded layout work units"))
    }));
    assert!(
        !r.diagnostics
            .iter()
            .any(|d| d.code == codes::SHAPE_FILE_DROPPED)
    );
}
