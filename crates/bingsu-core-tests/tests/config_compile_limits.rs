//! Bounded compilation, including input small enough to pass the source caps.
use bingsu_core::bands::{Band, MAX_BANDS, order_bands};
use bingsu_core::color::palette::Mode;
use bingsu_core::config::compile::BUILTIN_TOML;
use bingsu_core::config::report::{ConfigReport, report};
use bingsu_core::config::source::{
    ExtendsRef, FileKey, OpenError, Opened, Resolver, Status, Trust,
};
use bingsu_core::diag::{Place, SourceId};
use bingsu_core::diag_codes as codes;
use std::time::{Duration, Instant};

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

// 이것을 실패시키는 것: 236 KB의 모양 전용 입력이 전체 간선 저장·반복 순회에 들어가는 것.
#[test]
fn reviewers_7000_bands_finish_within_budget() {
    let source = nested(7000);
    assert_eq!(source.len(), 235_990);
    let start = Instant::now();
    let r = read("", &source, Trust::ShapeOnly);
    let elapsed = start.elapsed();
    assert!(
        elapsed < Duration::from_secs(5),
        "7000 bands took {elapsed:?}"
    );
    isolated(&r);
    assert_eq!(r.snapshot, read("", "", Trust::Executable).snapshot);
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
fn ordered_bands_at_the_limit_finish_within_budget() {
    let bands: Vec<_> = (0..MAX_BANDS)
        .map(|i| Band {
            min_cols: None,
            max_cols: Some(i as u16 + 100),
            order: Some(i as i32),
        })
        .collect();
    let start = Instant::now();
    let order = order_bands(&bands).unwrap();
    let elapsed = start.elapsed();
    assert_eq!(order, (0..MAX_BANDS).collect::<Vec<_>>());
    assert!(
        elapsed < Duration::from_secs(5),
        "ordered bands took {elapsed:?}"
    );
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
