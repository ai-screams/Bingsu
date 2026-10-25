use bingsu_core::{
    collection::{
        budget::{self, Axis, BudgetCounters},
        path_facts::{PathFactInput, PathQuery, SiblingSet},
        response::Completed,
        wire::{
            self, Binding, BuildId, EndReason, Frame, Kind, M3B_REQUEST_ID, Progress,
            ProtocolError as E, Request, Transcript, Update,
        },
    },
    field::{self, Field, FieldType, FieldValue, Value},
    shorten::{self, Method, ShortenRequest, Source},
    snapshot::{self, Clock, Identity},
    width::WidthProfile,
};
fn request(mask: u32) -> Request {
    Request {
        request_id: M3B_REQUEST_ID,
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
            cwd: b"/home/alpine/leaf".to_vec(),
            mask,
            path_query: PathQuery::default(),
        },
        budget_ms: 50,
        environment: vec![],
        global_excludes_known: true,
        global_excludes: vec![],
    }
}
fn frame<'a>(r: &Request, kind: Kind, payload: &'a [u8]) -> Frame<'a> {
    Frame {
        kind,
        build_id: r.binding.build_id,
        request_id: r.request_id,
        payload,
    }
}
fn transcript(r: &Request) -> Transcript {
    let mut t = Transcript::new(r);
    let mut ready = wire::FEATURES.to_le_bytes().to_vec();
    ready.extend(r.binding.mask.to_le_bytes());
    ready.extend([0; 12]);
    t.accept(frame(r, Kind::Ready, &ready)).unwrap();
    t.request_sent().unwrap();
    t
}
fn finish(t: Transcript) -> Option<Completed> {
    t.finish(
        EndReason::Deadline,
        Clock {
            kind: 1,
            boot: [1; 16],
            domain: [5; 16],
            resume: 0,
            now: 99,
        },
    )
    .unwrap()
}
fn git(stage: &[u8]) -> Value {
    let d = &field::BUILTIN[3];
    let mut fields = vec![Field::PENDING; d.fields.len()];
    for (name, value) in [
        ("branch", Field::text(b"main", 256, WidthProfile::DEFAULT)),
        ("detached", Field::known(FieldValue::Bool(false))),
        ("stage", Field::text(stage, 1, WidthProfile::DEFAULT)),
    ] {
        fields[d.field_index(name).unwrap()] = value;
    }
    Value::new(b"", fields)
}
fn put(t: &mut Transcript, r: &Request, update: &Update) {
    t.accept(frame(r, Kind::Update, &update.encode(&r.binding).unwrap()))
        .unwrap();
}
// A trusted test catalog with identical wire types but no git semantics lets
// malformed values reach the real decoder independently of its encoder checks.
fn raw_completed(c: &Completed) -> Vec<u8> {
    let catalog: Vec<_> = field::BUILTIN
        .iter()
        .map(|d| field::SegmentDecl {
            id: if d.id == "git" { "fixture" } else { d.id },
            role: d.role,
            fields: d.fields,
        })
        .collect();
    c.encode_with_catalog(&catalog).unwrap()
}

// 이것을 실패시키는 것: no_repo 생성자의 Known true·A·partial=false·나머지 Absent 계약을 바꾸거나 A 증거에서 표식을 제외하는 것.
#[test]
fn no_repo_marker_completes_a_and_roundtrips() {
    use bingsu_core::collection::git::no_repo;
    let r = request(8);
    let value = no_repo();
    assert_eq!(value.text(), "");
    for (f, d) in value.fields.iter().zip(field::BUILTIN[3].fields) {
        assert_eq!(
            *f,
            match d.name {
                "no_repo" => Field::known(FieldValue::Bool(true)),
                "partial" => Field::known(FieldValue::Bool(false)),
                "stage" => Field::text(b"A", 1, WidthProfile::DEFAULT),
                _ => Field::ABSENT,
            },
            "{}",
            d.name
        );
    }
    let update = Update {
        segment: 3,
        value: Some(value),
        facts: None,
    };
    for started in [false, true] {
        let mut t = transcript(&r);
        if started {
            t.accept(frame(&r, Kind::Progress, &Progress::default().encode()))
                .unwrap();
        }
        put(&mut t, &r, &update);
        assert!(!finish(t.clone()).unwrap().progress.stage_a_complete);
        t.accept(frame(
            &r,
            Kind::Progress,
            &Progress {
                stage_a_complete: true,
                device: None,
            }
            .encode(),
        ))
        .unwrap();
        // Rechecking a repeated cumulative marker must retain A completion.
        put(&mut t, &r, &update);
        for complete in [false, true] {
            let mut t = t.clone();
            if complete {
                t.accept(frame(&r, Kind::Complete, &[])).unwrap();
            }
            let c = finish(t).unwrap();
            assert!(c.progress.stage_a_complete);
            assert_eq!(c.updates, vec![update.clone()]);
            assert_eq!(Completed::decode(&c.encode().unwrap()), Ok(c));
        }
    }
}

// 이것을 실패시키는 것: partial·stage·저장소 필드·표시 text가 섞인 표식 또는 branch/commit 동시 Known을 wire/저장 codec에서 허용하는 것.
#[test]
fn contradictory_git_values_are_refused_by_wire_and_response() {
    use bingsu_core::collection::git::no_repo;
    let r = request(8);
    let decl = &field::BUILTIN[3];
    let mut bad = vec![Value::new(b"visible", no_repo().fields)];
    let mut pending_stage = no_repo();
    pending_stage.fields[decl.field_index("stage").unwrap()].state = field::ValueState::Pending;
    bad.push(pending_stage);
    for d in decl.fields {
        if d.name == "no_repo" {
            continue;
        }
        let mut replacements = vec![Field::PENDING];
        match d.name {
            "partial" => replacements.extend([Field::known(FieldValue::Bool(true)), Field::ABSENT]),
            "stage" => replacements
                .extend([b"B", b"C", b"D"].map(|s| Field::text(s, 1, WidthProfile::DEFAULT))),
            _ => replacements.push(match d.ty {
                FieldType::Bool => Field::known(FieldValue::Bool(false)),
                FieldType::Count => Field::known(FieldValue::Count {
                    n: 0,
                    saturated: false,
                }),
                FieldType::Text { max_cells } => {
                    Field::text(b"x", max_cells, WidthProfile::DEFAULT)
                }
                _ => unreachable!(),
            }),
        }
        for replacement in replacements {
            let mut v = no_repo();
            v.fields[decl.field_index(d.name).unwrap()] = replacement;
            bad.push(v);
        }
    }
    for detached in [false, true] {
        let mut v = git(b"A");
        v.fields[decl.field_index("commit").unwrap()] =
            Field::text(b"012345abcdef", 16, WidthProfile::DEFAULT);
        v.fields[decl.field_index("detached").unwrap()] = Field::known(FieldValue::Bool(detached));
        bad.push(v);
    }
    let mut seed = transcript(&r);
    put(
        &mut seed,
        &r,
        &Update {
            segment: 3,
            value: Some(no_repo()),
            facts: None,
        },
    );
    let mut c = finish(seed).unwrap();
    for value in bad {
        c.updates[0].value = Some(value);
        assert_eq!(c.updates[0].encode(&r.binding), Err(E::Schema));
        assert_eq!(c.encode(), Err(E::Schema));
        let bytes = raw_completed(&c); // Valid CRC, malformed git semantics.
        assert_eq!(Completed::decode(&bytes), Err(E::Schema));
        let mut empty = c.clone();
        empty.updates.clear();
        let offset = empty.encode().unwrap().len();
        let mut t = transcript(&r);
        let before = t.clone();
        assert_eq!(
            t.accept(frame(&r, Kind::Update, &bytes[offset..])),
            Err(E::Schema)
        );
        assert_eq!(t, before);
        c.progress.stage_a_complete = true;
        assert_eq!(c.encode(), Err(E::Schema));
        c.progress.stage_a_complete = false;
    }
}

// 이것을 실패시키는 것: 앞단 merge가 no_repo 표식을 표시 슬롯에 남기거나 요청 mask·binding 확인 없이 숨기는 것.
#[test]
fn no_repo_marker_is_hidden_in_front() {
    use bingsu_core::{collection, envelope, shell_values};
    let mut r = request(8);
    r.binding.cwd = b"/cwd".to_vec();
    let mut t = transcript(&r);
    put(
        &mut t,
        &r,
        &Update {
            segment: 3,
            value: Some(collection::git::no_repo()),
            facts: None,
        },
    );
    let c = finish(t).unwrap();
    let envelope = envelope::parse(&[
        b"--ctx",
        b"1",
        b"--record",
        b"B1",
        b"--width",
        b"80",
        b"--shell",
        b"bash",
        b"--pwd",
        b"/cwd",
    ])
    .unwrap();
    let mut values = shell_values::collect(&envelope);
    values.values[3] = Some(git(b"A"));
    let before = values.values.clone();
    for mask in [0, 2, 10] {
        let mut expected = c.binding.clone();
        expected.mask = mask;
        assert_eq!(
            collection::merge(&mut values, Some(&c), &expected, b"/cwd", None),
            Err(E::Schema)
        );
        assert_eq!(values.values, before);
    }
    for mask in [0, 2] {
        let mut unrequested = c.clone();
        unrequested.binding.mask = mask;
        assert_eq!(
            collection::merge(
                &mut values,
                Some(&unrequested),
                &unrequested.binding,
                b"/cwd",
                None
            ),
            Err(E::Schema)
        );
        assert_eq!(values.values, before);
    }
    let mut repository = c.clone();
    repository.updates[0].value = Some(git(b"A"));
    collection::merge(&mut values, Some(&repository), &r.binding, b"/cwd", None).unwrap();
    assert_eq!(values.values, before);
    let mut invalid = c.clone();
    let d = &field::BUILTIN[3];
    invalid.updates[0].value.as_mut().unwrap().fields[d.field_index("partial").unwrap()] =
        Field::known(FieldValue::Bool(true));
    assert_eq!(
        collection::merge(&mut values, Some(&invalid), &r.binding, b"/cwd", None),
        Err(E::Schema)
    );
    assert_eq!(values.values, before);
    collection::merge(&mut values, Some(&c), &r.binding, b"/cwd", None).unwrap();
    assert_eq!(values.values[3], None);
    for (i, v) in before.iter().enumerate() {
        if i != 3 {
            assert_eq!(&values.values[i], v);
        }
    }
    assert!(c.updates[0].value.is_some());
}
fn facts() -> PathFactInput {
    PathFactInput {
        repo_component: Some(1),
        in_repo: Some(true),
        readonly: Some(true),
        siblings: vec![SiblingSet {
            component: 1,
            complete: true,
            names: vec![b"alpine".to_vec(), b"alps".to_vec()],
        }],
        partial: true,
    }
}

// 이것을 실패시키는 것: git 선언 이름·순서·타입·상한 변경, state alias 복원 또는 fact schema 버전을 1로 되돌리는 것.
#[test]
fn git_field_names_types_and_order_are_fixed() {
    use FieldType::{Bool, Count, Text};
    let expected = [
        ("ahead", Count),
        ("behind", Count),
        ("branch", Text { max_cells: 256 }),
        ("commit", Text { max_cells: 16 }),
        ("conflicted", Count),
        ("detached", Bool),
        ("filtered", Bool),
        ("modified", Count),
        ("no_repo", Bool),
        ("operation", Text { max_cells: 16 }),
        ("partial", Bool),
        ("stage", Text { max_cells: 1 }),
        ("staged", Count),
        ("stash", Count),
        ("untracked", Count),
    ];
    assert_eq!(field::BUILTIN[3].id, "git");
    assert_eq!(field::BUILTIN[1].id, "dir");
    assert_eq!(
        field::BUILTIN[3]
            .fields
            .iter()
            .map(|f| (f.name, f.ty))
            .collect::<Vec<_>>(),
        expected
    );
    for (i, (name, _)) in expected.iter().enumerate() {
        assert_eq!(field::BUILTIN[3].field_index(name), Some(i));
    }
    assert_eq!(field::BUILTIN[3].field_index("state"), None);
    assert_eq!(bingsu_core::config::schema::FACT_SCHEMA_VERSION, 2);
    assert_eq!(
        field::BUILTIN[1]
            .fields
            .iter()
            .map(|f| (f.name, f.ty))
            .collect::<Vec<_>>(),
        [
            ("in_repo", Bool),
            ("path", Text { max_cells: 4096 }),
            ("readonly", Bool)
        ]
    );
}

// 이것을 실패시키는 것: facts의 dir 전용·요청 mask 검사 또는 원시 facts 저장/왕복을 제거하는 것.
#[test]
fn facts_only_attach_to_requested_dir() {
    let r = request((1 << 1) | (1 << 3));
    let update = Update {
        segment: 1,
        value: None,
        facts: Some(facts()),
    };
    let payload = update.encode(&r.binding).unwrap();
    let mut t = transcript(&r);
    t.accept(frame(&r, Kind::Update, &payload)).unwrap();
    let c = finish(t).unwrap();
    assert_eq!(c.updates, vec![update.clone()]);
    assert_eq!(Completed::decode(&c.encode().unwrap()), Ok(c));
    for segment in [0u16, 3] {
        let mut bad = update.clone();
        bad.segment = segment;
        assert_eq!(bad.encode(&r.binding), Err(E::Schema));
        let mut bytes = payload.clone();
        bytes[..2].copy_from_slice(&segment.to_le_bytes());
        let mut t = transcript(&r);
        let before = t.clone();
        assert_eq!(t.accept(frame(&r, Kind::Update, &bytes)), Err(E::Schema));
        assert_eq!(t, before);
    }
    let absent = request(1 << 3);
    let mut t = transcript(&absent);
    assert_eq!(update.encode(&absent.binding), Err(E::Schema));
    assert_eq!(
        t.accept(frame(&absent, Kind::Update, &payload)),
        Err(E::Schema)
    );
}

// 이것을 실패시키는 것: query의 4바이트 또는 Progress의 10바이트를 저장 예산에서 빼거나 재정제 확대분을 무시하는 것.
#[test]
fn v3_max_binding_leaves_65294_update_bytes() {
    use field::{FieldDecl, SegmentDecl};
    const F: [FieldDecl; 32] = [const {
        FieldDecl {
            name: "text",
            ty: FieldType::Text { max_cells: 4096 },
        }
    }; 32];
    const C: [SegmentDecl; 32] = [const {
        SegmentDecl {
            id: "fixture",
            role: "fg",
            fields: &F,
        }
    }; 32];
    let mut r = request(1 << 31);
    let mut path = vec![b'a'; 65_536];
    path[0] = b'/';
    r.binding.config = path.clone();
    r.binding.state = path.clone();
    r.binding.cwd = path;
    r.binding.snapshot.context =
        snapshot::context_crc(&r.binding.config, &r.binding.state).unwrap();
    assert_eq!(r.encode_body().unwrap().len() + 32 - 11, 196_733);
    let mut rest = 65_294 - 266;
    let fields = (0..32)
        .map(|_| {
            let n = rest.min(4096);
            rest -= n;
            Field::text(&vec![b'a'; n], 4096, WidthProfile::DEFAULT)
        })
        .collect();
    let mut c = Completed {
        request_id: r.request_id,
        binding: r.binding,
        completed_at_ns: 98,
        reason: EndReason::Deadline,
        progress: Progress::default(),
        updates: vec![Update {
            segment: 31,
            value: Some(Value::new(b"", fields)),
            facts: None,
        }],
    };
    let bytes = c.encode_with_catalog(&C).unwrap();
    assert_eq!(bytes.len(), 262_144);
    assert_eq!(&bytes[..10], b"BNGRES03\x03\0");
    assert_eq!(bytes.len() - 65_294 - 64, 196_786);
    assert_eq!(Completed::decode_with_catalog(&bytes, &C), Ok(c.clone()));
    let mut expanded = bytes;
    expanded[64 + 196_786 + 17] = 0xff;
    let crc = snapshot::crc32c(&[&expanded[64..]]);
    expanded[16..20].copy_from_slice(&crc);
    assert_eq!(
        Completed::decode_with_catalog(&expanded, &C),
        Err(E::Budget)
    );
    c.updates[0].value.as_mut().unwrap().fields[31] =
        Field::text(b"x", 4096, WidthProfile::DEFAULT);
    assert_eq!(c.encode_with_catalog(&C), Err(E::Budget));
    // 이것을 실패시키는 것: facts의 길이를 Update 예산에서 빼거나 transcript에서 정제 후 길이를 검증하지 않는 것.
    c.binding.mask = 2;
    c.updates[0].segment = 1;
    c.updates[0].facts = Some(PathFactInput::default()); // 12 bytes instead of the absent byte
    let fields = &mut c.updates[0].value.as_mut().unwrap().fields;
    fields[31] = Field::ABSENT;
    let old = match &fields[15].value {
        FieldValue::Text(t) => t.as_str().len(),
        _ => unreachable!(),
    };
    // Restoring field 31's four-byte empty Text length and shrinking field 15
    // by eleven accounts for the exact additional facts bytes.
    fields[31] = Field::text(b"", 4096, WidthProfile::DEFAULT);
    fields[15] = Field::text(&vec![b'a'; old - 11], 4096, WidthProfile::DEFAULT);
    let bytes = c.encode_with_catalog(&C).unwrap();
    assert_eq!(bytes.len(), 262_144);
    let r = Request {
        binding: c.binding.clone(),
        ..r
    };
    let mut t = Transcript::with_catalog(&r, &C).unwrap();
    let mut ready = wire::FEATURES.to_le_bytes().to_vec();
    ready.extend(2u32.to_le_bytes());
    ready.extend([0; 12]);
    t.accept(frame(&r, Kind::Ready, &ready)).unwrap();
    t.request_sent().unwrap();
    t.accept(frame(&r, Kind::Update, &bytes[64 + 196_786..]))
        .unwrap();
    let before = t.clone();
    let mut payload = bytes[64 + 196_786..].to_vec();
    payload[17] = 0xff;
    assert_eq!(t.accept(frame(&r, Kind::Update, &payload)), Err(E::Budget));
    assert_eq!(t, before);
}

// 이것을 실패시키는 것: Progress 도착을 A 성공으로 세거나 Update 전·반복 완료·역행·device 변경·Complete 후 Progress를 허용하는 것.
#[test]
fn progress_is_not_stage_a_success() {
    let r = request((1 << 1) | (1 << 3));
    let started = Progress {
        stage_a_complete: false,
        device: Some(8),
    };
    let done = Progress {
        stage_a_complete: true,
        device: Some(8),
    };
    let mut t = transcript(&r);
    t.accept(frame(&r, Kind::Progress, &started.encode()))
        .unwrap();
    assert!(finish(t.clone()).is_none());
    for p in [started, done] {
        let before = t.clone();
        assert_eq!(
            t.accept(frame(&r, Kind::Progress, &p.encode())),
            Err(E::Order)
        );
        assert_eq!(t, before);
    }
    for value in [
        None,
        Some(git(b"B")),
        Some(Value::new(
            b"",
            vec![Field::PENDING; field::BUILTIN[3].fields.len()],
        )),
    ] {
        put(
            &mut t,
            &r,
            &Update {
                segment: 3,
                value,
                facts: None,
            },
        );
        assert!(!finish(t.clone()).unwrap().progress.stage_a_complete);
        assert_eq!(
            t.accept(frame(&r, Kind::Progress, &done.encode())),
            Err(E::Order)
        );
    }
    put(
        &mut t,
        &r,
        &Update {
            segment: 3,
            value: Some(git(b"A")),
            facts: None,
        },
    );
    let before = t.clone();
    assert_eq!(
        t.accept(frame(
            &r,
            Kind::Progress,
            &Progress {
                device: Some(9),
                ..done
            }
            .encode()
        )),
        Err(E::Schema)
    );
    assert_eq!(t, before);
    t.accept(frame(&r, Kind::Progress, &done.encode())).unwrap();
    // 이것을 실패시키는 것: 완료 뒤 A 증거를 지운 Update를 받아 저장 불가능한 완성본을 만드는 것.
    let before = t.clone();
    assert_eq!(
        t.accept(frame(&r, Kind::Update, &[3, 0, 0, 0])),
        Err(E::Order)
    );
    assert_eq!(t, before);
    for p in [done, started] {
        assert_eq!(
            t.accept(frame(&r, Kind::Progress, &p.encode())),
            Err(E::Order)
        );
    }
    // 이것을 실패시키는 것: 누적 B 결과가 A 완료를 잃거나 저장 Progress를 보존하지 않는 것.
    put(
        &mut t,
        &r,
        &Update {
            segment: 3,
            value: Some(git(b"B")),
            facts: None,
        },
    );
    let c = finish(t.clone()).unwrap();
    assert_eq!(c.progress, done);
    assert_eq!(Completed::decode(&c.encode().unwrap()), Ok(c.clone()));
    let mut forged = c;
    forged.updates.clear();
    assert_eq!(forged.encode(), Err(E::Schema));
    // 이것을 실패시키는 것: CRC가 맞으면 저장 Progress의 A 완료 증거를 다시 검증하지 않는 것.
    forged.progress = Progress::default();
    let mut bytes = forged.encode().unwrap();
    let at = bytes.len() - 10;
    bytes[at] = 1;
    let crc = snapshot::crc32c(&[&bytes[64..]]);
    bytes[16..20].copy_from_slice(&crc);
    assert_eq!(Completed::decode(&bytes), Err(E::Schema));
    t.accept(frame(&r, Kind::Complete, &[])).unwrap();
    let before = t.clone();
    assert_eq!(
        t.accept(frame(&r, Kind::Progress, &done.encode())),
        Err(E::Order)
    );
    assert_eq!(t, before);
    // 이것을 실패시키는 것: git가 요청됐는데 dir Update로 A 성공을 인정하거나 dir-only discovery를 인정하지 않는 것.
    for mask in [1 << 1, (1 << 1) | (1 << 3)] {
        let r = request(mask);
        let mut t = transcript(&r);
        put(
            &mut t,
            &r,
            &Update {
                segment: 1,
                value: None,
                facts: Some(facts()),
            },
        );
        assert_eq!(
            t.accept(frame(&r, Kind::Progress, &done.encode())),
            if mask == 2 { Ok(()) } else { Err(E::Order) }
        );
    }
}

// 이것을 실패시키는 것: detached commit의 12자리 소문자 hex·Known 검사를 제거하거나 unborn의 알려진 Absent를 거부하는 것.
#[test]
fn stage_a_evidence_checks_detached_and_unborn_values() {
    let r = request(8);
    let decl = &field::BUILTIN[3];
    for (text, valid) in [
        (b"012345abcdef".as_slice(), true),
        (b"012345abcdeF", false),
        (b"012345abcde", false),
        (b"012345abcdeg", false),
    ] {
        let mut v = git(b"A");
        v.fields[decl.field_index("detached").unwrap()] = Field::known(FieldValue::Bool(true));
        v.fields[decl.field_index("branch").unwrap()] = Field::ABSENT;
        v.fields[decl.field_index("commit").unwrap()] =
            Field::text(text, 16, WidthProfile::DEFAULT);
        let mut t = transcript(&r);
        put(
            &mut t,
            &r,
            &Update {
                segment: 3,
                value: Some(v),
                facts: None,
            },
        );
        assert_eq!(
            t.accept(frame(
                &r,
                Kind::Progress,
                &Progress {
                    stage_a_complete: true,
                    device: None
                }
                .encode()
            )),
            if valid { Ok(()) } else { Err(E::Order) }
        );
    }
    for (branch, commit, detached, valid) in [
        (
            Field::ABSENT,
            Field::ABSENT,
            Field::known(FieldValue::Bool(false)),
            true,
        ),
        (
            Field::PENDING,
            Field::ABSENT,
            Field::known(FieldValue::Bool(false)),
            false,
        ),
        (Field::ABSENT, Field::ABSENT, Field::PENDING, false),
    ] {
        let mut v = git(b"A");
        for (name, f) in [
            ("branch", branch),
            ("commit", commit),
            ("detached", detached),
        ] {
            v.fields[decl.field_index(name).unwrap()] = f;
        }
        let mut t = transcript(&r);
        put(
            &mut t,
            &r,
            &Update {
                segment: 3,
                value: Some(v),
                facts: None,
            },
        );
        assert_eq!(
            t.accept(frame(
                &r,
                Kind::Progress,
                &Progress {
                    stage_a_complete: true,
                    device: None
                }
                .encode()
            )),
            if valid { Ok(()) } else { Err(E::Order) }
        );
    }
}

// 이것을 실패시키는 것: 미완성 목록을 unique 증거로 사용하거나 home/잘린 앞부분을 repo index에 보정하지 않는 것.
#[test]
fn incomplete_siblings_use_abbrev_and_indices_follow_the_envelope() {
    let mut input = facts();
    let cwd = b"/home/alpine/leaf";
    let query = PathQuery {
        home_component: Some(0),
        unique: true,
    };
    let render = |f: &PathFactInput, q| {
        let path = f.to_path_facts(cwd, q).unwrap();
        assert_eq!(path.readonly(), Some(true));
        shorten::run_builtin(&ShortenRequest {
            source: Source::Path(&path),
            budget: 100,
            profile: WidthProfile::DEFAULT,
            method: Method::Unique,
        })
        .unwrap()
        .text()
    };
    assert_eq!(render(&input, query), "~/alpi/leaf");
    input.siblings[0].complete = false;
    assert_eq!(render(&input, query), "~/a/leaf");
    input.siblings[0].complete = true;
    assert_eq!(
        render(
            &input,
            PathQuery {
                unique: false,
                ..query
            }
        ),
        "~/a/leaf"
    );
    let path = input.to_path_facts(cwd, query).unwrap();
    assert_eq!(
        shorten::run_builtin(&ShortenRequest {
            source: Source::Path(&path),
            budget: 100,
            profile: WidthProfile::DEFAULT,
            method: Method::Repo
        })
        .unwrap()
        .text(),
        "alpine/leaf"
    );
    // 이것을 실패시키는 것: 논리 dot 경로의 repo/sibling 증거를 보존하는 것.
    let dot = b"/home/./alpine/leaf";
    input.siblings[0].component = 2;
    assert_eq!(
        input
            .to_path_facts(
                dot,
                PathQuery {
                    unique: true,
                    ..Default::default()
                }
            )
            .unwrap(),
        bingsu_core::shell_values::path_facts(dot, None).with_readonly(Some(true))
    );
    let long = format!("{}alpine/leaf", "/x".repeat(4097) + "/");
    input.repo_component = Some(4097);
    input.siblings.clear();
    let path = input
        .to_path_facts(long.as_bytes(), PathQuery::default())
        .unwrap();
    assert_eq!(path.steps(), 4096);
    assert_eq!(
        shorten::run_builtin(&ShortenRequest {
            source: Source::Path(&path),
            budget: 100,
            profile: WidthProfile::DEFAULT,
            method: Method::Repo
        })
        .unwrap()
        .text(),
        "alpine/leaf"
    );
}

// 이것을 실패시키는 것: home component prefix·dot·root 구분 또는 exact binding의 query 비교를 제거하는 것.
#[test]
fn path_query_is_canonical_and_part_of_binding() {
    for (cwd, home, expected) in [
        (b"/a/b".as_slice(), b"/a/".as_slice(), Some(0)),
        (b"/a/b", b"/a/b", Some(1)),
        (b"/ab", b"/a", None),
        (b"/a/../b", b"/a", None),
        (b"/a", b"/", None),
        (b"/a", b"a", None),
        (b"/a/./b", b"/a/.", None),
    ] {
        assert_eq!(
            PathQuery::for_path(cwd, Some(home), true),
            PathQuery {
                home_component: expected,
                unique: true
            }
        );
    }
    let r = request(2);
    for query in [
        PathQuery {
            home_component: Some(0),
            unique: false,
        },
        PathQuery {
            home_component: None,
            unique: true,
        },
    ] {
        let mut other = r.clone();
        other.binding.path_query = query;
        assert!(!other.binding.matches(&r.binding));
        assert_eq!(
            Request::decode_body(
                other.binding.build_id,
                other.request_id,
                &other.encode_body().unwrap()
            ),
            Ok(other)
        );
    }
    for (offset, value) in [(77, 2), (78, 1), (80, 2)] {
        let mut raw = r.encode_body().unwrap();
        raw[offset] = value;
        assert_eq!(
            Request::decode_body(r.binding.build_id, r.request_id, &raw),
            Err(E::Schema)
        );
    }
    let mut bad = r;
    bad.binding.path_query.home_component = Some(3);
    assert_eq!(bad.encode_body(), Err(E::Schema));
    // 이것을 실패시키는 것: decode 시 home index 범위를 검사하지 않는 것.
    bad.binding.path_query.home_component = None;
    let mut raw = bad.encode_body().unwrap();
    raw[77] = 1;
    raw[78] = 3;
    assert_eq!(
        Request::decode_body(bad.binding.build_id, bad.request_id, &raw),
        Err(E::Schema)
    );
}

// 이것을 실패시키는 것: 축별 상한을 바꾸거나 charge의 checked 덧셈·초과 거부·실패 시 불변성을 제거하는 것.
#[test]
fn counters_charge_independent_axes_before_work() {
    let limits = [
        4_194_304, 50_000, 65_536, 4_096, 100_000, 128, 262_144, 8_192, 128, 262_144, 8_192, 8,
        8_388_608, 8_388_608, 8_388_608, 8_388_608, 10_000, 262_144, 4_096, 262_144, 1_024,
    ];
    let mut counters = BudgetCounters::default();
    for (axis, limit) in Axis::ALL.into_iter().zip(limits) {
        assert_eq!(axis.limit(), limit);
        assert_eq!(counters.used(axis), 0);
        counters.charge(axis, limit).unwrap();
        assert_eq!(counters.used(axis), limit);
        counters.charge(axis, 0).unwrap();
        for excess in [1, u64::MAX] {
            let before = counters.clone();
            assert_eq!(
                counters.charge(axis, excess),
                Err(budget::BudgetExceeded { axis })
            );
            assert_eq!(counters, before);
        }
    }
    assert_eq!(
        [
            budget::A_MS,
            budget::PATH_MS,
            budget::B_MS,
            budget::C_MS,
            budget::D_MS,
            budget::RESERVE_MS
        ],
        [5, 3, 28, 8, 4, 2]
    );
    assert_eq!(
        [
            budget::CONFIG_BYTES,
            budget::SMALL_FILE_BYTES,
            budget::OBJECT_ALLOC,
            budget::LIVE_FDS,
            budget::READ_CHUNK,
            budget::DIRENT_CHUNK
        ],
        [65_536, 65_536, 2_097_152, 56, 16_384, 8_192]
    );
}
