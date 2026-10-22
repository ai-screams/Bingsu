use bingsu_core::{
    bands::{self, Band},
    collection::{
        self,
        selection::{self, Catalog},
        wire::{Binding, BuildId, M3B_REQUEST_ID, ProtocolError},
    },
    color::palette::Mode,
    config::{
        compile::{BUILTIN_TOML, CompiledConfig},
        report::report,
        source::{ExtendsRef, FileKey, OpenError, Opened, Resolver, Trust},
    },
    field::{self, FieldDecl, FieldType, SegmentDecl},
    helper,
    layout::{self, Inputs, Options},
    recorder::DecisionLog,
    snapshot::{self, Identity},
    template::compile::compile,
};

const TEST_MASK: u32 = 1 << 31;
const PADDING: SegmentDecl = SegmentDecl {
    id: "unused",
    role: "fg",
    fields: &[],
};
const FIXTURE: SegmentDecl = SegmentDecl {
    id: "fixture",
    role: "fg",
    fields: &[FieldDecl {
        name: "text",
        ty: FieldType::Text { max_cells: 4096 },
    }],
};
fn catalog() -> Vec<SegmentDecl> {
    const IDS: [&str; 31] = [
        "a00", "a01", "a02", "a03", "a04", "a05", "a06", "a07", "a08", "a09", "a10", "a11", "a12",
        "a13", "a14", "a15", "a16", "a17", "a18", "a19", "a20", "a21", "a22", "a23", "a24", "a25",
        "a26", "a27", "a28", "a29", "a30",
    ];
    let mut c = IDS
        .iter()
        .map(|id| SegmentDecl {
            id,
            role: "fg",
            fields: &[],
        })
        .collect::<Vec<_>>();
    c.push(FIXTURE);
    c
}
struct NoSources;
impl Resolver for NoSources {
    fn open(&mut self, _: &Opened, _: &ExtendsRef) -> Result<Opened, OpenError> {
        panic!("no source references")
    }
}
fn opened(bytes: &[u8], ino: u64) -> Opened {
    Opened {
        key: FileKey { dev: 1, ino },
        bytes: bytes.to_vec(),
        trust: Trust::Executable,
        display: b"config".to_vec(),
    }
}
fn config(text: &str) -> CompiledConfig {
    report(
        vec![
            opened(BUILTIN_TOML.as_bytes(), 1),
            opened(text.as_bytes(), 2),
        ],
        &mut NoSources,
        [0, 3, 0],
        Mode::Dark,
    )
    .snapshot
    .unwrap()
}
fn fixture(text: &str) -> CompiledConfig {
    let mut c = config("");
    c.bands.clear();
    c.band_order.clear();
    c.variants = vec![compile(text, &catalog()).unwrap()];
    c.collect_mask = TEST_MASK;
    c
}
fn mask(c: &CompiledConfig, width: u16, redraw: bool) -> u32 {
    Catalog {
        segments: &catalog(),
        workers: TEST_MASK,
    }
    .worker_mask(c, width, redraw)
}
fn binding(mask: u32) -> Binding {
    Binding {
        path_query: Default::default(),
        build_id: BuildId([7; 32]),
        snapshot: Identity {
            boot: [1; 16],
            epoch: [2; 16],
            generation: 1,
            source: [3; 4],
            context: snapshot::context_crc(b"/c", b"/s").unwrap(),
        },
        clock_kind: 1,
        domain: [4; 16],
        resume: 0,
        config: b"/c".to_vec(),
        state: b"/s".to_vec(),
        cwd: b"/r".to_vec(),
        mask,
    }
}

// 이것을 실패시키는 것: 선택 variant 대신 모든 band의 참조를 합치거나 폭에서 마지막 칸을 먼저 빼는 것.
#[test]
fn builtin_mask_uses_the_actual_selected_variant() {
    let cat = catalog();
    let mut c = fixture("{fixture}");
    c.bands = vec![
        Band {
            min_cols: Some(0),
            max_cols: Some(79),
            order: Some(0),
        },
        Band {
            min_cols: Some(80),
            max_cols: Some(65535),
            order: Some(0),
        },
        Band {
            min_cols: Some(0),
            max_cols: Some(65535),
            order: Some(1),
        },
    ];
    c.band_order = bands::order_bands(&c.bands).unwrap();
    c.variants.extend([
        compile("narrow", &cat).unwrap(),
        compile("{fixture}", &cat).unwrap(),
        compile("{fixture}", &cat).unwrap(),
    ]);
    assert_eq!(
        bands::selection_table(&c.band_order, &c.bands),
        [(0, 79, Some(0)), (80, 65535, Some(1))]
    );
    for width in [0, 1, 2, 3, 79, 80, 65535] {
        let mut log = DecisionLog::default();
        layout::layout(
            &c.variants,
            &c.bands,
            &c.band_order,
            &Inputs {
                catalog: &cat,
                values: &[],
                facts: &[],
                setup: &[],
            },
            &Options {
                width,
                profile: c.profile,
                icons: c.icons,
                use_last_column: c.use_last_column,
            },
            &mut log,
        );
        assert_eq!(log.band, Some(usize::from(width >= 80)));
        assert_eq!(
            selection::builtin_mask(&c, width),
            if log.band == Some(1) { TEST_MASK } else { 0 }
        );
    }
    c.bands.clear();
    c.band_order.clear();
    assert_eq!(selection::builtin_mask(&c, 80), TEST_MASK, "default layout");
}

// 이것을 실패시키는 것: 가려진 band·off·빈 대체 layout·참조 없는 layout에서 worker를 선택하는 것.
#[test]
fn unreachable_and_disabled_builtins_never_spawn() {
    let cat = catalog();
    let workers = Catalog {
        segments: &cat,
        workers: TEST_MASK,
    };
    let mut c = fixture("{fixture}");
    c.bands = vec![
        Band {
            min_cols: None,
            max_cols: None,
            order: Some(0),
        },
        Band {
            min_cols: Some(0),
            max_cols: Some(79),
            order: Some(1),
        },
    ];
    c.band_order = bands::order_bands(&c.bands).unwrap();
    c.variants
        .extend([Vec::new(), compile("{fixture}", &cat).unwrap()]);
    for width in [0, 1, 79, 80, 65535] {
        assert_eq!(mask(&c, width, false), 0, "empty winner shadows fixture");
        assert!(
            collection::request(
                &workers,
                binding(mask(&c, width, false)),
                M3B_REQUEST_ID,
                50
            )
            .unwrap()
            .is_none()
        );
    }
    let mut disabled = fixture("{fixture}");
    disabled.collect_mask = 0;
    assert_eq!(mask(&disabled, 80, false), 0);
    assert_eq!(mask(&fixture("plain"), 80, false), 0);
    let off = config("[segment.git]\nenabled = false\n");
    for width in [0, 79, 80, 65535] {
        assert_eq!(selection::builtin_mask(&off, width) & (1 << 3), 0);
    }
}

// 이것을 실패시키는 것: Field·조건 group 참조를 빼거나 중복을 더하거나 실제 값의 폭 탈락을 예측하는 것.
#[test]
fn field_only_and_grouped_fixture_are_reachable() {
    for text in [
        "{fixture.text}",
        "[{fixture.text}]",
        "{fixture}{fixture}{fixture.text}",
        "{fixture}{fixture}",
    ] {
        let c = fixture(text);
        for width in [0, 1, 2, 3, 80, 65535] {
            assert_eq!(mask(&c, width, false), TEST_MASK, "{text}, {width}");
        }
        assert_eq!(mask(&c, 80, true), 0, "redraw does not collect");
    }
}

// 이것을 실패시키는 것: 제품 catalog가 어떤 내장 또는 시험 bit31에 worker 권한을 주는 것.
#[test]
fn product_mask_is_zero_and_fixture_is_unreachable() {
    assert_eq!(selection::PRODUCT.workers, 0);
    assert_eq!(
        selection::PRODUCT
            .segments
            .iter()
            .map(|s| s.id)
            .collect::<Vec<_>>(),
        field::BUILTIN.iter().map(|s| s.id).collect::<Vec<_>>()
    );
    assert!(field::BUILTIN.iter().all(|s| s.id != "fixture"));
    assert_eq!(selection::worker_mask(&fixture("{fixture}"), 80, false), 0);
    assert!(compile("{fixture}", field::BUILTIN).is_err());
    for text in [
        "[segment.fixture]\nenabled = true",
        "[style]\ntemplate = '{fixture.text}'",
    ] {
        assert!(
            report(
                vec![
                    opened(BUILTIN_TOML.as_bytes(), 1),
                    opened(text.as_bytes(), 2)
                ],
                &mut NoSources,
                [0, 3, 0],
                Mode::Dark
            )
            .snapshot
            .is_none()
        );
    }
}

// 이것을 실패시키는 것: fixture catalog 밖의 bit를 허용하거나 상한 밖 catalog를 수용하는 것.
#[test]
fn catalog_bounds_do_not_grant_undeclared_workers() {
    let c = fixture("{fixture}");
    for n in [0, 31, 33] {
        assert_eq!(
            Catalog {
                segments: &(0..n).map(|_| PADDING).collect::<Vec<_>>(),
                workers: u32::MAX
            }
            .worker_mask(&c, 80, false),
            0
        );
    }
    assert_eq!(mask(&c, 80, false), TEST_MASK);
}

// 이것을 실패시키는 것: 32 이상 segment index를 wrap하거나 없는 선택 variant의 renderer fallback을 잃는 것.
#[test]
fn selection_bounds_and_fallback_match_rendering() {
    let mut cat = catalog();
    cat.push(SegmentDecl {
        id: "zz",
        role: "fg",
        fields: &[],
    });
    let mut c = fixture("{fixture}");
    c.collect_mask = u32::MAX;
    c.variants = vec![compile("{zz}", &cat).unwrap()];
    assert_eq!(selection::builtin_mask(&c, 80), 0);
    c.variants = vec![compile("{fixture}", &cat).unwrap()];
    c.bands = vec![Band {
        min_cols: None,
        max_cols: None,
        order: None,
    }];
    c.band_order = vec![0];
    assert_eq!(
        selection::builtin_mask(&c, 80),
        TEST_MASK,
        "missing band variant uses default"
    );
    c.variants.clear();
    assert_eq!(selection::builtin_mask(&c, 80), 0);
}

// 이것을 실패시키는 것: 요청 생성이 binding·예산 검증을 건너뛰거나 환경 항목을 추가하는 것.
#[test]
fn selected_request_uses_the_wire_contract() {
    let workers = Catalog {
        segments: &catalog(),
        workers: TEST_MASK,
    };
    assert!(
        collection::request(&workers, binding(0), M3B_REQUEST_ID, 50)
            .unwrap()
            .is_none()
    );
    let request_id = bingsu_core::collection::wire::RequestId([9; 32]);
    let r = collection::request(&workers, binding(TEST_MASK), request_id, 50)
        .unwrap()
        .unwrap();
    assert_eq!(r.binding, binding(TEST_MASK));
    assert_eq!(r.request_id, request_id);
    assert_eq!(r.budget_ms, 50);
    assert!(r.environment.is_empty());
    for budget in [0, 51] {
        assert_eq!(
            collection::request(&workers, binding(TEST_MASK), M3B_REQUEST_ID, budget),
            Err(ProtocolError::Budget)
        );
    }
    let mut bad = binding(TEST_MASK);
    bad.cwd = b"relative".to_vec();
    assert_eq!(
        collection::request(&workers, bad, M3B_REQUEST_ID, 50),
        Err(ProtocolError::Schema)
    );
}

// 이것을 실패시키는 것: 요청 생성에서 worker 권한 또는 선언된 segment 검사를 제거하는 것.
#[test]
fn request_requires_catalog_worker_and_segment_grants() {
    let cat = catalog();
    let workers = Catalog {
        segments: &cat,
        workers: TEST_MASK,
    };
    assert_eq!(
        collection::request(&selection::PRODUCT, binding(TEST_MASK), M3B_REQUEST_ID, 50),
        Err(ProtocolError::Schema)
    );
    assert_eq!(
        collection::request(&workers, binding(TEST_MASK), M3B_REQUEST_ID, 50)
            .unwrap()
            .unwrap()
            .binding
            .mask,
        TEST_MASK
    );
    // Declared segments still need a worker grant; reject the whole mixed mask.
    for mask in [1, TEST_MASK | 1] {
        assert_eq!(
            collection::request(&workers, binding(mask), M3B_REQUEST_ID, 50),
            Err(ProtocolError::Schema)
        );
    }
    for n in [0, 31, 33] {
        let invalid = Catalog {
            segments: &(0..n).map(|_| PADDING).collect::<Vec<_>>(),
            workers: u32::MAX,
        };
        assert_eq!(
            collection::request(&invalid, binding(TEST_MASK), M3B_REQUEST_ID, 50),
            Err(ProtocolError::Schema),
            "catalog length {n}"
        );
    }
    assert!(
        collection::request(&selection::PRODUCT, binding(0), M3B_REQUEST_ID, 50)
            .unwrap()
            .is_none()
    );
}

// 이것을 실패시키는 것: 폭·redraw를 버리거나 중복을 허용하거나 폭 값 자리를 실행/root 옵션으로 재해석하는 것.
#[test]
fn helper_handoff_preserves_width_and_redraw_without_new_authority() {
    let roots: &[&[u8]] = &[
        b"--runtime-root=1:2:/r",
        b"--config-root=/c",
        b"--config-root-written=/c",
        b"--state-root=/s",
        b"--home=/h",
    ];
    for (word, expected) in [
        (b"79".as_slice(), 79),
        (b"80", 80),
        (b"65535", 65535),
        (b"0", 0),
        (b"080", 0),
        (b"unknown", 0),
        (b"65536", 0),
        (b"--config-root=/attack", 0),
        (b"--exec=/attack", 0),
    ] {
        for redraw in [false, true] {
            let mut raw = roots.to_vec();
            raw.extend([b"--width", word]);
            if redraw {
                raw.push(b"--redraw");
            }
            let words = helper::words(&raw).unwrap();
            let e = helper::validate(&words).unwrap();
            let width_at = words.iter().position(|w| w.as_ref() == b"--width").unwrap();
            assert_eq!(
                words[width_at + 1].as_ref(),
                expected.to_string().as_bytes()
            );
            assert_eq!(e.width, expected);
            assert_eq!(e.redraw, redraw);
            assert_eq!(e.config_root.as_deref(), Some(b"/c".as_slice()));
            raw.extend([b"--width".as_slice(), b"80"]);
            assert!(helper::words(&raw).is_err());
        }
    }
    assert_eq!(
        helper::validate(&helper::words(roots).unwrap())
            .unwrap()
            .width,
        0
    );
    let mut raw = roots.to_vec();
    raw.extend([b"--redraw".as_slice(), b"--redraw"]);
    assert!(helper::words(&raw).is_err());
    let mut raw = roots.to_vec();
    raw.push(b"--width");
    assert!(helper::words(&raw).is_err());
}

// 이것을 실패시키는 것: 검증 전의 긴 폭 문자열을 helper argv에 그대로 전달하는 것.
#[test]
fn helper_handoff_reserializes_oversized_width() {
    let oversized = vec![b'9'; 100_000];
    let words = helper::words(&[
        b"--runtime-root=1:2:/r",
        b"--config-root=/c",
        b"--config-root-written=/c",
        b"--state-root=/s",
        b"--home=/h",
        b"--width",
        &oversized,
    ])
    .unwrap();
    let width_at = words.iter().position(|w| w.as_ref() == b"--width").unwrap();
    assert_eq!(words[width_at + 1].as_ref(), b"0");
    assert!(words.iter().all(|w| w.len() < oversized.len()));
}
