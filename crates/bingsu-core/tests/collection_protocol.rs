use bingsu_core::{
    collection::{
        response::{self, Completed},
        wire::{
            self, Binding, BuildId, EndReason, Frame, Kind, M3B_REQUEST_ID, ProtocolError as E,
            Request, RequestDecoder, RequestId, Transcript,
        },
    },
    field::{Field, FieldDecl, FieldType, SegmentDecl, Value, ValueState},
    snapshot::{self, Clock, Identity},
    width::WidthProfile,
};
const TEXT_FIELDS: [FieldDecl; 32] = [const {
    FieldDecl {
        name: "text",
        ty: FieldType::Text { max_cells: 4096 },
    }
}; 32];
const CATALOG: [SegmentDecl; 32] = [const {
    SegmentDecl {
        id: "fixture",
        role: "fg",
        fields: &TEXT_FIELDS,
    }
}; 32];
fn request(max: bool) -> Request {
    let path = |c| {
        let mut p = vec![c; if max { 65_536 } else { 2 }];
        p[0] = b'/';
        p
    };
    let config = path(b'c');
    let state = path(b's');
    Request {
        request_id: M3B_REQUEST_ID,
        binding: Binding {
            path_query: Default::default(),
            build_id: BuildId([7; 32]),
            snapshot: Identity {
                boot: [1; 16],
                epoch: [2; 16],
                generation: 3,
                source: [4; 4],
                context: snapshot::context_crc(&config, &state).unwrap(),
            },
            clock_kind: 1,
            domain: [5; 16],
            resume: 6,
            config,
            state,
            cwd: path(b'w'),
            mask: 1 << 31,
        },
        budget_ms: 50,
        environment: vec![],
    }
}
fn clock(r: &Request, now: u64) -> Clock {
    Clock {
        kind: r.binding.clock_kind,
        boot: r.binding.snapshot.boot,
        domain: r.binding.domain,
        resume: r.binding.resume,
        now,
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
fn ready(mask: u32) -> Vec<u8> {
    let mut b = 3u64.to_le_bytes().to_vec();
    b.extend(mask.to_le_bytes());
    b.extend(0u32.to_le_bytes());
    b.extend(123u64.to_le_bytes());
    b
}
fn transcript(r: &Request) -> Transcript {
    let mut t = Transcript::with_catalog(r, &CATALOG).unwrap();
    t.accept(frame(r, Kind::Ready, &ready(r.binding.mask)))
        .unwrap();
    t.request_sent().unwrap();
    t
}
fn decoder(r: &Request) -> RequestDecoder {
    let mut d = RequestDecoder::new();
    d.accept(frame(r, Kind::Ready, &ready(r.binding.mask)))
        .unwrap();
    d
}
fn begin(n: usize) -> Vec<u8> {
    let mut p = (n as u32).to_le_bytes().to_vec();
    p.extend(3u64.to_le_bytes());
    p
}
fn chunk(offset: usize, b: &[u8]) -> Vec<u8> {
    let mut p = (offset as u32).to_le_bytes().to_vec();
    p.extend(b);
    p
}
fn put_text(p: &mut Vec<u8>, b: &[u8]) {
    p.extend((b.len() as u32).to_le_bytes());
    p.extend(b);
}
fn update(segment: u16, text: &[u8], fields: &[(u16, u8, u8, Vec<u8>)]) -> Vec<u8> {
    let mut p = segment.to_le_bytes().to_vec();
    p.push(1);
    put_text(&mut p, text);
    p.extend((fields.len() as u16).to_le_bytes());
    for (i, state, tag, value) in fields {
        p.extend(i.to_le_bytes());
        p.push(*state);
        p.push(*tag);
        p.extend(value);
    }
    p.push(0);
    p
}
fn text_field(i: u16, b: &[u8]) -> (u16, u8, u8, Vec<u8>) {
    let mut p = vec![];
    put_text(&mut p, b);
    (i, 0, 0, p)
}
fn sized_update(n: usize) -> Vec<u8> {
    assert!((266..=266 + 32 * 4096).contains(&n));
    let mut rest = n - 266;
    let mut fields = vec![];
    for i in 0..32 {
        let len = rest.min(4096);
        fields.push(text_field(i, &vec![b'a'; len]));
        rest -= len;
    }
    assert_eq!(rest, 0);
    let p = update(31, b"", &fields);
    assert_eq!(p.len(), n);
    p
}
fn completed(r: &Request, p: &[u8]) -> Completed {
    let mut t = transcript(r);
    t.accept(frame(r, Kind::Update, p)).unwrap();
    t.finish(EndReason::Deadline, clock(r, 99))
        .unwrap()
        .unwrap()
}
fn fix_crc(b: &mut [u8]) {
    let crc = snapshot::crc32c(&[&b[64..]]);
    b[16..20].copy_from_slice(&crc);
}

// 이것을 실패시키는 것: 헤더 길이 검사 전에 payload 할당하거나 최대 프레임을 1바이트 줄이는 것.
#[test]
fn frame_length_is_checked_before_allocation() {
    let r = request(false);
    let payload = vec![0; 65_456];
    let mut out = [0; 65_536];
    assert_eq!(
        wire::encode_frame(frame(&r, Kind::Update, &payload), &mut out),
        Ok(65_536)
    );
    assert_eq!(wire::decode_frame(&out).unwrap().payload.len(), 65_456);
    for len in [65_457, u32::MAX] {
        let mut p = out[..80].to_vec();
        p[12..16].copy_from_slice(&len.to_le_bytes());
        assert_eq!(wire::decode_frame(&p), Err(E::Length));
        assert_eq!(wire::frame_len(&p), Err(E::Length));
    }
    assert_eq!(wire::decode_frame(&out[..79]), Err(E::Length));
    assert_eq!(wire::frame_len(&out[..79]), Err(E::Length));
    // 이것을 실패시키는 것: 동시 위반에서 length/magic/version/kind/flags 우선순위를 바꾸는 것.
    let mut bad = out[..80].to_vec();
    bad[..8].fill(0);
    bad[8] = 2;
    bad[10] = 8;
    bad[11] = 1;
    assert_eq!(wire::decode_frame(&bad), Err(E::Length));
    bad[12..16].fill(0);
    assert_eq!(wire::decode_frame(&bad), Err(E::Magic));
    bad[..8].copy_from_slice(b"BNGIPC03");
    assert_eq!(wire::decode_frame(&bad), Err(E::Version));
    bad[8] = 3;
    assert_eq!(wire::decode_frame(&bad), Err(E::Kind));
    bad[10] = 6;
    assert_eq!(wire::decode_frame(&bad), Err(E::Flags));
    assert_eq!(
        wire::encode_frame(frame(&r, Kind::Update, &vec![0; 65_457]), &mut out),
        Err(E::Length)
    );
}
// 이것을 실패시키는 것: 방향 총량에서 헤더를 빼거나 frame/update/text/field 상한을 하나 늘리는 것.
#[test]
fn stream_and_update_limits_include_framing() {
    let mut r = request(false);
    r.binding.mask = u32::MAX;
    for extra in [0, 1] {
        let mut t = transcript(&r);
        for _ in 0..3 {
            t.accept(frame(&r, Kind::Update, &sized_update(65_430)))
                .unwrap();
        }
        let old = t.clone();
        let result = t.accept(frame(&r, Kind::Update, &sized_update(65_430 + extra)));
        if extra == 0 {
            assert_eq!(result, Ok(()));
        } else {
            assert_eq!(result, Err(E::Budget));
            assert_eq!(t, old);
        }
    }
    let mut t = transcript(&r);
    for n in 0..63 {
        let p = [(n / 16) as u8, 0, 0, 0];
        t.accept(frame(&r, Kind::Update, &p)).unwrap();
    }
    assert_eq!(t.accept(frame(&r, Kind::Complete, &[])), Err(E::Budget)); // frame 65
    let mut t = transcript(&r);
    for _ in 0..16 {
        t.accept(frame(&r, Kind::Update, &[31, 0, 0, 0])).unwrap();
    }
    assert_eq!(
        t.accept(frame(&r, Kind::Update, &[31, 0, 0, 0])),
        Err(E::Budget)
    );
    for n in [4096, 4097] {
        assert_eq!(
            transcript(&r).accept(frame(&r, Kind::Update, &update(31, &vec![b'a'; n], &[]))),
            if n == 4096 { Ok(()) } else { Err(E::Budget) }
        );
    }
    // 이것을 실패시키는 것: field Text에만 4096바이트 원문 상한을 적용하지 않는 것.
    for n in [4096, 4097] {
        assert_eq!(
            transcript(&r).accept(frame(
                &r,
                Kind::Update,
                &update(31, b"", &[text_field(0, &vec![b'a'; n])])
            )),
            if n == 4096 { Ok(()) } else { Err(E::Budget) }
        );
    }
    for n in [32, 33] {
        let fields = (0..n).map(|i| text_field(i, b"x")).collect::<Vec<_>>();
        assert_eq!(
            transcript(&r).accept(frame(&r, Kind::Update, &update(31, b"", &fields))),
            if n == 32 { Ok(()) } else { Err(E::Budget) }
        );
    }
    // 이것을 실패시키는 것: 활성 catalog 밖 segment 또는 33개 segment를 허용하는 것.
    let mut t = transcript(&r);
    for segment in 0..32 {
        t.accept(frame(&r, Kind::Update, &[segment, 0, 0, 0]))
            .unwrap();
    }
    let c = t
        .finish(EndReason::Deadline, clock(&r, 99))
        .unwrap()
        .unwrap();
    assert_eq!(c.updates.len(), 32);
    assert_eq!(
        Completed::decode_with_catalog(&c.encode_with_catalog(&CATALOG).unwrap(), &CATALOG),
        Ok(c)
    );
    // 이것을 실패시키는 것: catalog 밖 Request를 생성 시점에 거부하지 않는 것.
    assert_eq!(
        Transcript::with_catalog(&r, bingsu_core::field::BUILTIN),
        Err(E::Schema)
    );
    let mut local = r.clone();
    local.binding.mask = 1 << 3;
    let mut short = Transcript::new(&local);
    short
        .accept(frame(&local, Kind::Ready, &ready(local.binding.mask)))
        .unwrap();
    short.request_sent().unwrap();
    assert_eq!(
        short.accept(frame(&local, Kind::Update, &[31, 0, 0, 0])),
        Err(E::Schema)
    );
    const BIG: [SegmentDecl; 33] = [const {
        SegmentDecl {
            id: "fixture",
            role: "fg",
            fields: &TEXT_FIELDS,
        }
    }; 33];
    assert_eq!(Transcript::with_catalog(&r, &BIG), Err(E::Budget));
    // Request-direction accounting includes every Begin/Chunk/End header.
    for extra in [0, 1] {
        let mut r = request(true);
        let initial = r.encode_body().unwrap().len();
        let remove = (initial + 176) % 84;
        let target_body = initial - remove;
        r.binding.cwd.truncate(r.binding.cwd.len() - remove);
        // 262144 modulo 84 is 64; tune body to that residue after fixed overhead.
        let adjust = (target_body + 176 + 84 - (262_144 % 84)) % 84;
        r.binding.cwd.truncate(r.binding.cwd.len() - adjust);
        r.binding.cwd.extend(vec![b'x'; extra]);
        let body = r.encode_body().unwrap();
        let count = (262_144 - (body.len() - extra) - 176) / 84;
        let mut d = decoder(&r);
        d.accept(frame(&r, Kind::RequestBegin, &begin(body.len())))
            .unwrap();
        let mut offset = 0;
        for i in 0..count {
            let left = count - i;
            let n = (body.len() - offset).div_ceil(left);
            d.accept(frame(
                &r,
                Kind::RequestChunk,
                &chunk(offset, &body[offset..offset + n]),
            ))
            .unwrap();
            offset += n;
        }
        assert_eq!(
            d.accept(frame(&r, Kind::RequestEnd, &snapshot::crc32c(&[&body]))),
            if extra == 0 {
                Ok(Some(r))
            } else {
                Err(E::Budget)
            }
        );
    }
}
// 이것을 실패시키는 것: 최대 binding을 저장 예산에서 빼거나 교체·정제 후 길이를 계산하지 않는 것.
#[test]
fn response_budget_includes_max_binding_and_last_values() {
    let r = request(true);
    let mut t = transcript(&r);
    t.accept(frame(&r, Kind::Update, &sized_update(266)))
        .unwrap();
    t.accept(frame(&r, Kind::Update, &sized_update(65_294)))
        .unwrap();
    let previous = t.clone();
    assert_eq!(
        t.accept(frame(&r, Kind::Update, &sized_update(65_295))),
        Err(E::Budget)
    );
    assert_eq!(t, previous);
    let c = t
        .clone()
        .finish(EndReason::Protocol, clock(&r, 99))
        .unwrap()
        .unwrap();
    let encoded = c.encode_with_catalog(&CATALOG).unwrap();
    assert_eq!(encoded.len(), 262_144);
    // 이것을 실패시키는 것: 저장 파일 decode 뒤 재정제로 늘어난 길이를 예산에서 제외하는 것.
    let mut expanded = encoded.clone();
    expanded[64 + 32 + 196_733 + 8 + 1 + 2 + 10 + 17] = 0xff;
    fix_crc(&mut expanded);
    assert_eq!(
        Completed::decode_with_catalog(&expanded, &CATALOG),
        Err(E::Budget)
    );
    // 이것을 실패시키는 것: 직접 encode할 때 262145바이트 완성 파일을 허용하는 것.
    let mut too_large = c.clone();
    let fields = &mut too_large.updates[0].value.as_mut().unwrap().fields;
    fields[15] = Field::text(&vec![b'a'; 3604], 4096, WidthProfile::DEFAULT);
    assert_eq!(too_large.encode_with_catalog(&CATALOG), Err(E::Budget));

    assert_eq!(Completed::decode_with_catalog(&encoded, &CATALOG), Ok(c));
    t.accept(frame(&r, Kind::Update, &sized_update(266)))
        .unwrap();
    assert!(
        t.finish(EndReason::Deadline, clock(&r, 99))
            .unwrap()
            .unwrap()
            .encode_with_catalog(&CATALOG)
            .unwrap()
            .len()
            < 262_144
    );
    let mut fields = (0..32)
        .map(|i| text_field(i, &vec![b'a'; if i < 15 { 4096 } else { 0 }]))
        .collect::<Vec<_>>();
    fields[15] = text_field(15, &vec![0xff; 1202]); // 3606 bytes after replacement, 65311 total.
    let p = update(31, b"", &fields);
    assert!(p.len() < 65_294);
    let mut t = transcript(&r);
    t.accept(frame(&r, Kind::Update, &[31, 0, 0, 0])).unwrap();
    let old = t.clone();
    assert_eq!(t.accept(frame(&r, Kind::Update, &p)), Err(E::Budget));
    assert_eq!(t, old);
    assert!(
        t.finish(EndReason::Protocol, clock(&r, 99))
            .unwrap()
            .unwrap()
            .encode_with_catalog(&CATALOG)
            .unwrap()
            .len()
            <= 262_144
    );
}
// 이것을 실패시키는 것: 중복·순서 검사를 정체 검사 뒤로 옮기거나 필드·기능 검사를 생략하는 것.
#[test]
fn protocol_rejects_duplicate_id_field_and_order() {
    let r = request(false);
    let mut t = Transcript::with_catalog(&r, &CATALOG).unwrap();
    assert_eq!(
        t.accept(frame(&r, Kind::Update, &[31, 0, 0, 0])),
        Err(E::Order)
    );
    assert_eq!(t.request_sent(), Err(E::Order));
    t.accept(frame(&r, Kind::Ready, &ready(r.binding.mask)))
        .unwrap();
    let mut duplicate = frame(&r, Kind::Ready, &[]);
    duplicate.build_id = BuildId([0; 32]);
    assert_eq!(t.accept(duplicate), Err(E::Duplicate));
    assert_eq!(
        t.accept(frame(&r, Kind::Update, &[31, 0, 0, 0])),
        Err(E::Order)
    );
    t.request_sent().unwrap();
    assert_eq!(t.request_sent(), Err(E::Order));
    // 이것을 실패시키는 것: Complete의 payload를 허용하는 것.
    assert_eq!(t.accept(frame(&r, Kind::Complete, &[0])), Err(E::Schema));
    let p = update(31, b"", &[text_field(0, b"a"), text_field(0, b"b")]);
    assert_eq!(t.accept(frame(&r, Kind::Update, &p)), Err(E::Duplicate));
    assert_eq!(
        t.accept(frame(&r, Kind::Update, &[0, 0, 0])),
        Err(E::Schema)
    );
    let mut wrong = frame(&r, Kind::Update, &[31, 0, 0, 0]);
    wrong.request_id = RequestId([3; 32]);
    assert_eq!(t.accept(wrong), Err(E::Id));
    let p = update(31, b"", &[(0, 0, 4, vec![1])]);
    assert_eq!(t.accept(frame(&r, Kind::Update, &p)), Err(E::Schema));
    let p = update(31, b"", &[text_field(32, b"a")]);
    assert_eq!(t.accept(frame(&r, Kind::Update, &p)), Err(E::Schema));
    t.accept(frame(&r, Kind::Complete, &[])).unwrap();
    assert_eq!(t.accept_bytes(&[0]), Err(E::Order));
    for id in [r.request_id, RequestId([9; 32])] {
        let mut d = decoder(&r);
        d.accept(frame(&r, Kind::RequestBegin, &begin(1))).unwrap();
        let p = begin(1);
        let mut f = frame(&r, Kind::RequestBegin, &p);
        f.request_id = id;
        assert_eq!(d.accept(f), Err(E::Duplicate));
    }
    let mut d = decoder(&r);
    let mut p = begin(1);
    p[4] = 2;
    assert_eq!(d.accept(frame(&r, Kind::RequestBegin, &p)), Err(E::Feature));
    p.push(0);
    assert_eq!(d.accept(frame(&r, Kind::RequestBegin, &p)), Err(E::Feature));
    let mut bytes = [0; 65_536];
    let n = wire::encode_frame(frame(&r, Kind::Complete, &[]), &mut bytes).unwrap();
    for (at, value, error) in [(10, 0, E::Kind), (10, 8, E::Kind), (11, 1, E::Flags)] {
        let mut b = bytes[..n].to_vec();
        b[at] = value;
        assert_eq!(wire::decode_frame(&b), Err(error));
    }
    // 이것을 실패시키는 것: 지원 mask 부족·Facts/trailing·알 수 없는 state/tag를 받는 것.
    assert_eq!(
        Transcript::with_catalog(&r, &CATALOG)
            .unwrap()
            .accept(frame(&r, Kind::Ready, &ready(0))),
        Err(E::Schema)
    );
    for payload in [
        vec![31, 0, 0, 99],
        update(31, b"", &[(0, 2, 5, vec![])]),
        update(31, b"", &[(0, 0, 6, vec![])]),
    ] {
        assert_eq!(
            transcript(&r).accept(frame(&r, Kind::Update, &payload)),
            Err(E::Schema)
        );
    }
    // 이것을 실패시키는 것: 동시에 위반한 헤더의 오류 우선순위를 바꾸는 것.
    let mut bad = bytes[..80].to_vec();
    bad[0] = 0;
    bad[8] = 1;
    bad[10] = 0;
    bad[11] = 1;
    bad[12..16].copy_from_slice(&u32::MAX.to_le_bytes());
    assert_eq!(wire::decode_frame(&bad), Err(E::Length));
    bad[12..16].copy_from_slice(&0u32.to_le_bytes());
    assert_eq!(wire::decode_frame(&bad), Err(E::Magic));
    bad[..8].copy_from_slice(b"BNGIPC03");
    assert_eq!(wire::decode_frame(&bad), Err(E::Version));
    bad[8] = 3;
    assert_eq!(wire::decode_frame(&bad), Err(E::Kind));
    bad[10] = 6;
    assert_eq!(wire::decode_frame(&bad), Err(E::Flags));
    let mut d = RequestDecoder::new();
    assert_eq!(
        d.accept(frame(&r, Kind::RequestBegin, &begin(1))),
        Err(E::Order)
    );
    // 이것을 실패시키는 것: decoder의 두 번째 Ready 또는 잘못된 교환 id를 허용하는 것.
    let mut d = decoder(&r);
    assert_eq!(d.accept(frame(&r, Kind::Ready, &[])), Err(E::Duplicate));
    let p = begin(1);
    let mut f = frame(&r, Kind::RequestBegin, &p);
    f.request_id = RequestId([3; 32]);
    assert_eq!(d.accept(f), Err(E::Id));
}
// 이것을 실패시키는 것: Complete 뒤 빈 EOF도 decode_eof로 넘겨 Truncated를 반환하는 것.
#[test]
fn empty_eof_after_complete_is_ok() {
    let r = request(false);
    let mut t = transcript(&r);
    t.accept(frame(&r, Kind::Update, &[31, 0, 0, 0])).unwrap();
    t.accept(frame(&r, Kind::Complete, &[])).unwrap();
    let before = t.clone();
    assert_eq!(t.accept_bytes(&[]), Ok(()));
    assert_eq!(t, before);
}

// 이것을 실패시키는 것: Complete 전에도 빈 EOF를 Ok(())로 처리하는 것.
#[test]
fn empty_eof_before_complete_is_truncated() {
    let r = request(false);
    let initial = Transcript::with_catalog(&r, &CATALOG).unwrap();
    let mut ready_only = initial.clone();
    ready_only
        .accept(frame(&r, Kind::Ready, &ready(r.binding.mask)))
        .unwrap();
    let sent = transcript(&r);
    let mut updated = sent.clone();
    updated
        .accept(frame(&r, Kind::Update, &[31, 0, 0, 0]))
        .unwrap();

    assert_eq!(wire::decode_eof(&[]), Err(E::Truncated));
    for mut t in [initial, ready_only, sent, updated] {
        let before = t.clone();
        assert_eq!(t.accept_bytes(&[]), Err(E::Truncated));
        assert_eq!(t, before);
    }
}

// 이것을 실패시키는 것: build/version/features를 협상하거나 EOF를 완전한 메시지로 취급하는 것.
#[test]
fn mixed_build_or_version_exits_without_reply() {
    let r = request(false);
    let p = ready(r.binding.mask);
    let mut f = frame(&r, Kind::Ready, &p);
    f.build_id = BuildId([8; 32]);
    let mut t = Transcript::with_catalog(&r, &CATALOG).unwrap();
    assert_eq!(t.accept(f), Err(E::Build));
    assert_eq!(t.request_sent(), Err(E::Order));
    let mut t = transcript(&r);
    let mut f = frame(&r, Kind::Update, &[31, 0, 0, 0]);
    f.build_id = BuildId([8; 32]);
    assert_eq!(t.accept(f), Err(E::Build));
    let mut d = decoder(&r);
    let p = begin(1);
    let mut f = frame(&r, Kind::RequestBegin, &p);
    f.build_id = BuildId([8; 32]);
    assert_eq!(d.accept(f), Err(E::Build));
    let mut p = ready(r.binding.mask);
    p[0] = 2;
    let mut t = Transcript::with_catalog(&r, &CATALOG).unwrap();
    assert_eq!(t.accept(frame(&r, Kind::Ready, &p)), Err(E::Feature));
    assert_eq!(t.request_sent(), Err(E::Order));
    let mut bytes = [0; 65_536];
    let n = wire::encode_frame(frame(&r, Kind::Ready, &ready(r.binding.mask)), &mut bytes).unwrap();
    for v in [1u16, 2, 4] {
        let mut b = bytes[..n].to_vec();
        b[8..10].copy_from_slice(&v.to_le_bytes());
        assert_eq!(wire::decode_frame(&b), Err(E::Version));
    }
    let mut b = bytes[..n].to_vec();
    b[0] ^= 1;
    assert_eq!(wire::decode_frame(&b), Err(E::Magic));
    for len in 1..80 {
        assert_eq!(wire::decode_eof(&bytes[..len]), Err(E::Truncated));
    }
    assert_eq!(wire::decode_eof(&bytes[..n - 1]), Err(E::Truncated));
    // The pure acceptance API returns no outbound frame; failed Ready cannot
    // enable request_sent. There is no Reject kind or negotiation state.
    for tag in [0, 8] {
        b = bytes[..n].to_vec();
        b[10] = tag;
        assert_eq!(wire::decode_frame(&b), Err(E::Kind));
    }
}
// 이것을 실패시키는 것: 요청을 한 프레임으로 줄이거나 chunk 연속성·CRC·경로 검사를 제거하는 것.
#[test]
fn large_request_is_chunked_without_reducing_path_limit() {
    let r = request(true);
    let body = r.encode_body().unwrap();
    assert_eq!(
        Request::decode_body(r.binding.build_id, r.request_id, &body),
        Ok(r.clone())
    );
    let mut d = decoder(&r);
    d.accept(frame(&r, Kind::RequestBegin, &begin(body.len())))
        .unwrap();
    let mut at = 0;
    for b in body.chunks(65_452) {
        d.accept(frame(&r, Kind::RequestChunk, &chunk(at, b)))
            .unwrap();
        at += b.len();
    }
    assert_eq!(
        d.accept(frame(&r, Kind::RequestEnd, &snapshot::crc32c(&[&body]))),
        Ok(Some(r.clone()))
    );
    assert_eq!(
        d.accept(frame(&r, Kind::RequestBegin, &begin(body.len()))),
        Err(E::Duplicate)
    );
    // 이것을 실패시키는 것: 완성 요청을 두 번 반환하거나 환경 항목을 encode하는 것.
    assert_eq!(
        d.accept(frame(&r, Kind::RequestEnd, &snapshot::crc32c(&[&body]))),
        Err(E::Order)
    );
    let mut q = r.clone();
    q.budget_ms = 1;
    assert!(q.encode_body().is_ok());
    q.environment.push((b"KEY".to_vec(), b"value".to_vec()));
    assert_eq!(q.encode_body(), Err(E::Schema));
    for index in 0..3 {
        for bad in [vec![b'/'; 65_537], b"/a\0b".to_vec(), b"relative".to_vec()] {
            let mut q = r.clone();
            match index {
                0 => q.binding.config = bad,
                1 => q.binding.state = bad,
                _ => q.binding.cwd = bad,
            };
            assert_eq!(q.encode_body(), Err(E::Schema));
        }
    }
    for budget in [0, 51] {
        let mut q = r.clone();
        q.budget_ms = budget;
        assert_eq!(q.encode_body(), Err(E::Budget));
        let mut b = body.clone();
        b[81..85].copy_from_slice(&budget.to_le_bytes());
        assert_eq!(
            Request::decode_body(r.binding.build_id, r.request_id, &b),
            Err(E::Budget)
        );
    }
    for offset in [0, 1, 3] {
        let mut d = decoder(&r);
        d.accept(frame(&r, Kind::RequestBegin, &begin(body.len())))
            .unwrap();
        d.accept(frame(&r, Kind::RequestChunk, &chunk(0, &body[..2])))
            .unwrap();
        let old = d.clone();
        assert_eq!(
            d.accept(frame(&r, Kind::RequestChunk, &chunk(offset, &body[2..3]))),
            Err(E::Order)
        );
        assert_eq!(d, old);
    }
    let mut d = decoder(&r);
    d.accept(frame(&r, Kind::RequestBegin, &begin(1))).unwrap();
    d.accept(frame(&r, Kind::RequestChunk, &chunk(0, b"x")))
        .unwrap();
    assert_eq!(
        d.accept(frame(&r, Kind::RequestEnd, &[0; 4])),
        Err(E::Checksum)
    );
    // 이것을 실패시키는 것: decode의 경로 길이·절대성·NUL·context·시계 검사를 생략하는 것.
    for length_at in [85, 85 + 4 + 65536, 85 + 2 * (4 + 65536)] {
        for (at, value) in [(length_at + 4, b'x'), (length_at + 5, 0)] {
            let mut b = body.clone();
            b[at] = value;
            assert_eq!(
                Request::decode_body(r.binding.build_id, r.request_id, &b),
                Err(E::Schema)
            );
        }
        let mut b = body.clone();
        b[length_at..length_at + 4].copy_from_slice(&65537u32.to_le_bytes());
        assert_eq!(
            Request::decode_body(r.binding.build_id, r.request_id, &b),
            Err(E::Schema)
        );
    }
    for at in [44, 48] {
        let mut b = body.clone();
        b[at] = 3;
        assert_eq!(
            Request::decode_body(r.binding.build_id, r.request_id, &b),
            Err(E::Schema)
        );
    }
    let mut b = body.clone();
    b.push(0);
    assert_eq!(
        Request::decode_body(r.binding.build_id, r.request_id, &b),
        Err(E::Schema)
    );
    let mut b = body.clone();
    let end = b.len();
    b[end - 2..].copy_from_slice(&1u16.to_le_bytes());
    assert_eq!(
        Request::decode_body(r.binding.build_id, r.request_id, &b),
        Err(E::Schema)
    );
    let mut b = [0; 80];
    b[..8].copy_from_slice(b"BNGCOL01");
    assert_eq!(wire::decode_frame(&b), Err(E::Magic));
}
// 이것을 실패시키는 것: binding을 CRC·해시로만 비교하거나 요청 id/예산을 재사용 키에 넣는 것.
#[test]
fn response_binding_and_build_id_are_exact() {
    let r = request(false);
    let c = completed(&r, &[31, 0, 0, 0]);
    assert!(c.eligible(&r.binding, clock(&r, 100)));
    for change in 0..13 {
        let mut b = r.binding.clone();
        match change {
            0 => b.config.push(b'x'),
            1 => b.state.push(b'x'),
            2 => b.cwd.push(b'x'),
            3 => b.snapshot.boot[0] ^= 1,
            4 => b.snapshot.epoch[0] ^= 1,
            5 => b.snapshot.generation += 1,
            6 => b.snapshot.source[0] ^= 1,
            7 => b.mask ^= 1,
            8 => b.clock_kind = 2,
            9 => b.domain[0] ^= 1,
            10 => b.resume += 1,
            11 => b.build_id.0[0] ^= 1,
            _ => b.snapshot.context[0] ^= 1,
        };
        assert!(!c.eligible(&b, clock(&r, 100)), "change {change}");
    }
    let mut other = r.clone();
    other.request_id = RequestId([9; 32]);
    other.budget_ms = 1;
    assert!(c.eligible(&other.binding, clock(&r, 100)));
    for at in [100, 101, u64::MAX] {
        let mut other = c.clone();
        other.completed_at_ns = at;
        assert!(!other.eligible(&r.binding, clock(&r, 100)));
    }
    for change in 0..4 {
        let mut now = clock(&r, 100);
        match change {
            0 => now.kind = 2,
            1 => now.domain[0] ^= 1,
            2 => now.resume += 1,
            _ => now.boot[0] ^= 1,
        };
        assert!(!c.eligible(&r.binding, now));
    }
    assert_eq!(
        r.binding.components(),
        [
            "collections-v1".into(),
            bingsu_core::collection::cwd_hash::address(&r.binding.cwd),
            "store".into()
        ]
    );
    // These canonical roots have the same context CRC, but different bytes.
    let mut a = r.clone();
    let mut b = r.clone();
    a.binding.config = b"/collision/308a0945c21a0320".to_vec();
    b.binding.config = b"/collision/3d806b964d5618d8".to_vec();
    a.binding.snapshot.context =
        snapshot::context_crc(&a.binding.config, &a.binding.state).unwrap();
    b.binding.snapshot.context =
        snapshot::context_crc(&b.binding.config, &b.binding.state).unwrap();
    assert_eq!(a.binding.snapshot.context, b.binding.snapshot.context);
    assert!(!a.binding.matches(&b.binding));
    assert!(!completed(&a, &[31, 0, 0, 0]).eligible(&b.binding, clock(&b, 100)));
}
// 이것을 실패시키는 것: 잘린 Update의 일부 필드를 축적하거나 Hidden/무결과를 혼동하는 것.
#[test]
fn logical_partial_is_not_a_torn_file() {
    let r = request(false);
    let mut t = transcript(&r);
    let p = update(
        31,
        b"partial",
        &[text_field(0, b"known"), (2, 0, 5, vec![])],
    );
    t.accept(frame(&r, Kind::Update, &p)).unwrap();
    let saved = t.clone();
    let p = update(
        31,
        b"changed",
        &[
            text_field(0, b"changed"),
            (1, 0, 0, vec![10, 0, 0, 0, b'x']),
        ],
    );
    assert_eq!(t.accept(frame(&r, Kind::Update, &p)), Err(E::Schema));
    assert_eq!(t, saved);
    assert_eq!(t.accept_bytes(&[0; 79]), Err(E::Truncated));
    let c = t
        .finish(EndReason::Protocol, clock(&r, 99))
        .unwrap()
        .unwrap();
    let v = c.updates[0].value.as_ref().unwrap();
    assert_eq!(v.text(), "partial");
    assert_eq!(v.fields[0].state, ValueState::Known);
    assert_eq!(v.fields[1], Field::PENDING);
    assert_eq!(v.fields[2], Field::ABSENT);
    assert_eq!(
        Completed::decode_with_catalog(&c.encode_with_catalog(&CATALOG).unwrap(), &CATALOG),
        Ok(c)
    );
    assert_eq!(
        transcript(&r).finish(EndReason::WorkerExit, clock(&r, 99)),
        Ok(None)
    );
    assert!(completed(&r, &[31, 0, 0, 0]).updates[0].value.is_none());
    let mut t = transcript(&r);
    t.accept(frame(&r, Kind::Complete, &[])).unwrap();
    assert_eq!(t.finish(EndReason::Complete, clock(&r, 99)), Ok(None));
}
// 이것을 실패시키는 것: 저장 텍스트를 정제 없이 읽거나 reserved/CRC/중복/trailing 검사를 생략하는 것.
#[test]
fn untrusted_text_is_resanitized() {
    let r = request(false);
    let mut cases = vec![b"$(touch pwned)".to_vec(), vec![0xff; 4096]];
    for row in include_str!("../../../tests/hostile/classes.tsv")
        .lines()
        .filter(|s| !s.is_empty() && !s.starts_with('#'))
    {
        let cells = row.split('\t').collect::<Vec<_>>();
        let spec = cells[1];
        let bytes = if let Some(rest) = spec.strip_prefix("repeat:") {
            let (b, n) = rest.split_once(':').unwrap();
            vec![u8::from_str_radix(b, 16).unwrap(); n.parse().unwrap()]
        } else {
            (0..spec.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&spec[i..i + 2], 16).unwrap())
                .collect()
        };
        cases.push(bytes);
    }
    for raw in cases {
        let p = update(31, &raw, &[text_field(0, &raw)]);
        if raw.len() > 4096 {
            assert_eq!(
                transcript(&r).accept(frame(&r, Kind::Update, &p)),
                Err(E::Length)
            );
            continue;
        }
        let c = completed(&r, &p);
        let bytes = c.encode_with_catalog(&CATALOG).unwrap();
        let decoded = Completed::decode_with_catalog(&bytes, &CATALOG).unwrap();
        assert_eq!(c, decoded);
        let v = decoded.updates[0].value.as_ref().unwrap();
        assert_eq!(v.text(), Value::new(&raw, vec![]).text());
        assert_eq!(v.fields[0], Field::text(&raw, 4096, WidthProfile::DEFAULT));
        // 이것을 실패시키는 것: Field::text의 정제만 우회하여 제어문자를 보존하는 것.
        let bingsu_core::field::FieldValue::Text(text) = &v.fields[0].value else {
            panic!("expected Text field");
        };
        assert!(
            !text
                .as_str()
                .chars()
                .any(|c| { c.is_control() || matches!(c, '\u{202e}' | '\u{2066}' | '\u{200b}') })
        );
        assert!(
            !v.text()
                .chars()
                .any(|c| c.is_control() || matches!(c, '\u{202e}' | '\u{2066}' | '\u{200b}'))
        );
        assert_eq!(Value::new(v.text().as_bytes(), v.fields.clone()), *v);
        use bingsu_core::{
            color::{
                palette::{Knobs, Mode, PaletteInput, resolve_palette},
                sgr::{ColorDepth, Style},
            },
            emit::emit,
            layout::Run,
            shell_word::Shell,
        };
        let palette = resolve_palette(&PaletteInput {
            mode: Mode::Dark,
            knobs: Knobs::default(),
            overrides: &[],
            roles: &[],
        })
        .unwrap();
        for shell in [Shell::Bash, Shell::Zsh, Shell::Fish] {
            let runs = [Run {
                text: v.text().into(),
                style: Style::default(),
            }];
            let mut rendered = vec![];
            emit(shell, &runs, &palette, ColorDepth::TrueColor, &mut rendered);
            let expected = if shell == Shell::Zsh {
                v.text().replace('%', "%%")
            } else {
                v.text().to_owned()
            };
            assert!(rendered.ends_with(expected.as_bytes()));
            // Only the emitter's leading reset may contain an ESC.
            assert_eq!(rendered.iter().filter(|b| **b == 27).count(), 1);
        }
    }
    let c = completed(&r, &update(31, b"abcd", &[]));
    let mut stored = c.encode_with_catalog(&CATALOG).unwrap();
    let first_update = 64
        + 32
        + 125
        + r.binding.config.len()
        + r.binding.state.len()
        + r.binding.cwd.len()
        + 8
        + 1
        + 2
        + 10;
    stored[first_update + 7] = 27;
    stored[first_update + 8] = 0xff;
    fix_crc(&mut stored);
    let cleaned = Completed::decode_with_catalog(&stored, &CATALOG).unwrap();
    assert_eq!(
        cleaned.updates[0].value.as_ref().unwrap().text(),
        "\u{fffd}cd"
    );
    // 이것을 실패시키는 것: 저장 EndReason tag를 enum ordinal로 복사하거나 미지 tag를 받는 것.
    for (reason, tag) in [
        (EndReason::Complete, 0),
        (EndReason::Deadline, 1),
        (EndReason::Protocol, 2),
        (EndReason::Resource, 3),
        (EndReason::WorkerExit, 4),
    ] {
        let mut c = completed(&r, &[31, 0, 0, 0]);
        c.reason = reason;
        let mut b = c.encode_with_catalog(&CATALOG).unwrap();
        let at = b.len() - 17;
        assert_eq!(b[at], tag);
        assert_eq!(Completed::decode_with_catalog(&b, &CATALOG), Ok(c));
        b[at] = 5;
        fix_crc(&mut b);
        assert_eq!(Completed::decode_with_catalog(&b, &CATALOG), Err(E::Schema));
    }
    let c = completed(&r, &[31, 0, 0, 0]);
    let b = c.encode_with_catalog(&CATALOG).unwrap();
    // 이것을 실패시키는 것: 저장 magic/version/header 길이 및 잘린 본문을 허용하는 것.
    for (at, value, error) in [(0, 0, E::Magic), (8, 2, E::Version), (10, 63, E::Schema)] {
        let mut bad = b.clone();
        bad[at] = value;
        assert_eq!(Completed::decode_with_catalog(&bad, &CATALOG), Err(error));
    }
    for len in [63, b.len() - 1] {
        assert_eq!(
            Completed::decode_with_catalog(&b[..len], &CATALOG),
            Err(E::Truncated)
        );
    }
    for at in 20..64 {
        let mut bad = b.clone();
        bad[at] = 1;
        assert_eq!(
            Completed::decode_with_catalog(&bad, &CATALOG),
            Err(E::Schema)
        );
    }
    let mut bad = b.clone();
    *bad.last_mut().unwrap() ^= 1;
    assert_eq!(
        Completed::decode_with_catalog(&bad, &CATALOG),
        Err(E::Checksum)
    );
    let mut bad = b.clone();
    bad.push(0);
    assert_eq!(
        Completed::decode_with_catalog(&bad, &CATALOG),
        Err(E::Schema)
    );
    let mut bad = b.clone();
    let end = bad.len();
    bad[end - 16..end - 14].copy_from_slice(&2u16.to_le_bytes());
    bad.extend([31, 0, 0, 0]);
    let body_len = (bad.len() - 64) as u32;
    bad[12..16].copy_from_slice(&body_len.to_le_bytes());
    fix_crc(&mut bad);
    assert_eq!(
        Completed::decode_with_catalog(&bad, &CATALOG),
        Err(E::Duplicate)
    );
    let mut bad = b.clone();
    bad.resize(262_145, 0);
    assert_eq!(
        Completed::decode_with_catalog(&bad, &CATALOG),
        Err(E::Budget)
    );
    let mut bad = b;
    bad[12..16].copy_from_slice(&u32::MAX.to_le_bytes());
    assert_eq!(response::declared_len(&bad), Err(E::Budget));
    // Exercise every explicit field tag with the product declarations.
    let mut q = request(false);
    q.binding.mask = (1 << 0) | (1 << 2) | (1 << 3) | (1 << 6);
    let mut t = Transcript::new(&q);
    t.accept(frame(&q, Kind::Ready, &ready(q.binding.mask)))
        .unwrap();
    t.request_sent().unwrap();
    for p in [
        update(0, b"", &[(0, 0, 4, vec![1]), (1, 0, 5, vec![])]),
        update(2, b"", &[(0, 0, 3, 55u64.to_le_bytes().to_vec())]),
        update(
            3,
            b"",
            &[(0, 0, 1, vec![4, 0, 0, 0, 1]), text_field(2, b"branch")],
        ),
        update(6, b"", &[(0, 0, 2, (-4i64).to_le_bytes().to_vec())]),
    ] {
        t.accept(frame(&q, Kind::Update, &p)).unwrap();
    }
    let c = t
        .finish(EndReason::Resource, clock(&q, 99))
        .unwrap()
        .unwrap();
    assert_eq!(Completed::decode(&c.encode().unwrap()), Ok(c));
}
