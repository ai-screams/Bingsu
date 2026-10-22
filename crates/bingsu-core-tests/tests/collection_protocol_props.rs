use bingsu_core::{
    collection::{
        response::Completed,
        wire::{
            self, Binding, BuildId, EndReason, Frame, Kind, M3B_REQUEST_ID, ProtocolError, Request,
            RequestDecoder, Transcript,
        },
    },
    field::{self, FieldType, SegmentDecl},
    snapshot::{self, Clock, Identity},
};
use proptest::prelude::*;
#[path = "support/allocation.rs"]
mod allocation;
#[global_allocator]
static ALLOC: allocation::Counting = allocation::Counting;
fn request() -> Request {
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
                context: snapshot::context_crc(b"/c", b"/s").unwrap(),
            },
            clock_kind: 1,
            domain: [5; 16],
            resume: 0,
            config: b"/c".to_vec(),
            state: b"/s".to_vec(),
            cwd: b"/w".to_vec(),
            mask: 1 << 3,
        },
        budget_ms: 50,
        environment: vec![],
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
fn ready() -> Vec<u8> {
    let mut p = 3u64.to_le_bytes().to_vec();
    p.extend((1u32 << 3).to_le_bytes());
    p.extend([0; 12]);
    p
}
fn clock() -> Clock {
    Clock {
        kind: 1,
        domain: [5; 16],
        resume: 0,
        boot: [1; 16],
        now: 99,
    }
}
// 이것을 실패시키는 것: 거부할 prefix 길이로 payload를 할당하는 것.
#[test]
fn frame_length_is_checked_before_allocation() {
    let r = request();
    let mut buffer = [0u8; 65_536];
    wire::encode_frame(frame(&r, Kind::Complete, &[]), &mut buffer).unwrap();
    for len in [65_457, u32::MAX] {
        buffer[12..16].copy_from_slice(&len.to_le_bytes());
        assert_eq!(
            allocation::counted(|| {
                assert_eq!(
                    wire::decode_frame(&buffer[..80]),
                    Err(ProtocolError::Length)
                );
                assert_eq!(wire::frame_len(&buffer[..80]), Err(ProtocolError::Length));
            }),
            (0, 0, 0)
        );
    }
    assert_eq!(
        allocation::counted(|| assert_eq!(
            wire::decode_frame(&buffer[..79]),
            Err(ProtocolError::Length)
        )),
        (0, 0, 0)
    );
}

proptest! {
    #![proptest_config(ProptestConfig { cases:128, .. ProptestConfig::default() })]
    // 이것을 실패시키는 것: 거부 입력 전에 상태·계수를 바꾸거나 선언 길이를 무제한 할당하거나 present=1 Update 정제 경로에서 panic을 일으키는 것.
    #[test]
    fn protocol_proptest_is_bounded_and_transactional(
        raw in prop::collection::vec(any::<u8>(),0..2048),
        length in prop_oneof![0usize..1024,Just(65_535),Just(65_536),Just(65_537),Just(262_144),Just(262_145)],
        changes in prop::collection::vec((any::<usize>(),any::<u8>(),0u8..7),1..12),
    ) {
        let r=request();let p=ready();let mut d=RequestDecoder::new();let mut t=Transcript::new(&r);
        d.accept(frame(&r,Kind::Ready,&p)).unwrap();t.accept(frame(&r,Kind::Ready,&p)).unwrap();t.request_sent().unwrap();
        t.accept(frame(&r,Kind::Update,&[3, 0, 0, 0])).unwrap();
        let original=t.clone().finish(EndReason::Deadline,clock()).unwrap().unwrap();
        let body=r.encode_body().unwrap();let mut begin=(body.len() as u32).to_le_bytes().to_vec();begin.extend(3u64.to_le_bytes());
        d.accept(frame(&r,Kind::RequestBegin,&begin)).unwrap();
        let mut chunk=0u32.to_le_bytes().to_vec();chunk.extend(&body);
        d.accept(frame(&r,Kind::RequestChunk,&chunk)).unwrap();
        let mut raw_bytes=vec![0;length];if !raw.is_empty() {for (i,b) in raw_bytes.iter_mut().enumerate() {*b=raw[i%raw.len()];}}
        let saved_d=d.clone();let saved_t=t.clone();
        // A fixed input buffer, one <=256 KiB request body, <=256 KiB stored
        // result, and temporary sanitized fields (at most 3x wire input),
        // plus <=32x32 declarations fit below this conservative live bound.
        let allocation_max=4*wire::STREAM_MAX+wire::FRAME_MAX;
        let mut raw_dr = Ok(None); let mut raw_tr = Ok(());
        let counts=allocation::counted(||{
            match wire::decode_frame(&raw_bytes) {
                Ok(f) => {raw_dr=d.accept(f);raw_tr=t.accept(f);}
                Err(e) => {raw_dr=Err(e);raw_tr=Err(e);}
            }
            let _=Completed::decode(&raw_bytes);
        });
        prop_assert!(counts.2<=allocation_max,"allocation {counts:?}");
        if raw_dr.is_err() {prop_assert_eq!(&d,&saved_d);}
        if raw_tr.is_err() {prop_assert_eq!(&t,&saved_t);}
        // Arbitrary bytes almost always fail at the header. Also exercise
        // all payload kinds against a fully valid prefix below.
        d=saved_d;t=saved_t;
        for (offset,byte,kind) in changes {
            let kind=match kind {0=>Kind::Ready,1=>Kind::RequestBegin,2=>Kind::RequestChunk,3=>Kind::RequestEnd,4=>Kind::Update,5=>Kind::Complete,_=>Kind::Progress};
            let mut payload=match kind {Kind::Ready=>ready(),Kind::RequestBegin=>begin.clone(),Kind::RequestChunk=>chunk.clone(),Kind::RequestEnd=>snapshot::crc32c(&[&body]).to_vec(),Kind::Update=>vec![3,0,1,0,0,0,0,1,0,0,0,0,1,4,0,0,0,1,0],Kind::Complete=>vec![],Kind::Progress=>vec![0;10]};
            if !payload.is_empty() {let i=offset%payload.len();payload[i]^=byte;} else if byte!=0 {payload.push(byte);}
            let f=frame(&r,kind,&payload);let before_d=d.clone();let before_t=t.clone();
            let mut dr=Ok(None);let mut tr=Ok(());
            let counts=allocation::counted(||{dr=d.accept(f);tr=t.accept(f);});
            prop_assert!(counts.2<=allocation_max);prop_assert!(counts.0+counts.1<=256);
            if dr.is_err() {prop_assert_eq!(&d,&before_d);}
            if tr.is_err() {prop_assert_eq!(&t,&before_t);}
            let mut stored=original.encode().unwrap();let index=offset%stored.len();stored[index]^=byte;
            let counts=allocation::counted(||{let _=Completed::decode(&stored);});
            prop_assert!(counts.2<=allocation_max);
        }
        if let Some(c)=t.finish(EndReason::Protocol,clock()).unwrap() {prop_assert!(c.encode().unwrap().len()<=wire::STREAM_MAX);}
    }
}

fn begin(n: usize) -> Vec<u8> {
    let mut p = (n as u32).to_le_bytes().to_vec();
    p.extend(wire::FEATURES.to_le_bytes());
    p
}
fn chunk(offset: usize, bytes: &[u8]) -> Vec<u8> {
    let mut p = (offset as u32).to_le_bytes().to_vec();
    p.extend(bytes);
    p
}
fn encoded(f: Frame<'_>) -> Vec<u8> {
    let mut buffer = [0; wire::FRAME_MAX];
    let n = wire::encode_frame(f, &mut buffer).unwrap();
    buffer[..n].to_vec()
}
// These fixtures have only hidden updates: rejection must allocate ZERO bytes
// in either state machine. Setup, clones and assertion formatting are unarmed.
fn refuse_request(d: &RequestDecoder, f: Frame<'_>, expected: ProtocolError) {
    let mut probe = d.clone();
    let mut result = Ok(None);
    let counts = allocation::counted(|| result = probe.accept(f));
    assert_eq!(result, Err(expected));
    assert_eq!(probe, *d);
    assert_eq!(counts, (0, 0, 0));
}
fn refuse_transcript(t: &Transcript, bytes: &[u8], expected: ProtocolError) {
    let mut probe = t.clone();
    let mut result = Ok(());
    let counts = allocation::counted(|| result = probe.accept_bytes(bytes));
    assert_eq!(result, Err(expected));
    assert_eq!(probe, *t);
    assert_eq!(counts, (0, 0, 0));
}
fn fix_response(bytes: &mut [u8]) {
    let body = bytes.len() - 64;
    bytes[12..16].copy_from_slice(&(body as u32).to_le_bytes());
    let crc = snapshot::crc32c(&[&bytes[64..]]);
    bytes[16..20].copy_from_slice(&crc);
}
// Exact live bound for this corpus: declaration Vecs, the three path copies,
// and one hidden Update slot. No raw text/field sanitization allocation exists.
fn response_bound(r: &Request) -> (usize, usize) {
    let schema_bytes = field::BUILTIN.len() * size_of::<Vec<FieldType>>()
        + field::BUILTIN
            .iter()
            .map(|s| s.fields.len() * size_of::<FieldType>())
            .sum::<usize>();
    let schema_allocs = 1 + field::BUILTIN
        .iter()
        .filter(|s| !s.fields.is_empty())
        .count();
    (
        schema_allocs + 4,
        schema_bytes
            + r.binding.config.len()
            + r.binding.state.len()
            + r.binding.cwd.len()
            + size_of::<wire::Update>(),
    )
}
fn refuse_response(bytes: &[u8], r: &Request, expected: ProtocolError) -> (usize, usize, usize) {
    let mut result = Ok(None);
    let counts = allocation::counted(|| result = Completed::decode(bytes).map(Some));
    assert_eq!(result, Err(expected));
    let (allocs, peak) = response_bound(r);
    assert!(counts.0 <= allocs, "{counts:?}");
    assert_eq!(counts.1, 0);
    assert!(counts.2 <= peak, "{counts:?} > {peak}");
    counts
}
proptest! {
    #![proptest_config(ProptestConfig { cases: 64, .. ProptestConfig::default() })]
    // 이것을 실패시키는 것: Ready 전 Begin, Begin 전 Chunk, 잘못된 offset/길이/정체를 받거나 거부 경로에서 1바이트라도 할당하는 것.
    #[test]
    fn request_intermediate_refusals_are_transactional_and_allocation_free(
        split_seed in any::<usize>(), extra in 1usize..128, delta in 1u8..=255,
    ) {
        let r = request(); let body = r.encode_body().unwrap();
        let split = 1 + split_seed % (body.len() - 1);
        let mut d = RequestDecoder::new();
        let p = ready(); let b = begin(body.len());
        let first = chunk(0, &body[..split]);
        let last = chunk(split, &body[split..]);
        let crc = snapshot::crc32c(&[&body]);
        // Every generated case visits NONE, Ready, Begin, partial Chunk,
        // full Chunk and End, rather than randomly missing intermediate states.
        for state in 0..6 {
            let wrong = match state {
                0 => frame(&r, Kind::RequestBegin, &b),
                1 => frame(&r, Kind::RequestChunk, &first),
                2 | 3 => frame(&r, Kind::RequestEnd, &crc),
                4 => frame(&r, Kind::RequestChunk, &last),
                _ => frame(&r, Kind::Complete, &[]),
            };
            refuse_request(&d, wrong, ProtocolError::Order);
            if (1..5).contains(&state) {
                let valid = match state {
                    1 => frame(&r, Kind::RequestBegin, &b),
                    2 => frame(&r, Kind::RequestChunk, &first),
                    3 => frame(&r, Kind::RequestChunk, &last),
                    _ => frame(&r, Kind::RequestEnd, &crc),
                };
                let mut wrong = valid; wrong.build_id.0[0] ^= delta;
                refuse_request(&d, wrong, ProtocolError::Build);
                wrong = valid; wrong.request_id.0[0] ^= delta;
                refuse_request(&d, wrong, ProtocolError::Id);
                // Every header/payload truncation boundary, not just empty EOF.
                // These cuts fail in framing before RequestDecoder::accept;
                // state preservation is checked by refuse_request above/below.
                let bytes = encoded(valid);
                for cut in 0..bytes.len() {
                    let mut result = Ok(());
                    let counts = allocation::counted(|| {
                        result = wire::decode_eof(&bytes[..cut]).map(|_| ());
                    });
                    prop_assert_eq!(result, Err(ProtocolError::Truncated));
                    prop_assert_eq!(counts, (0, 0, 0));
                }
            }
            if state == 1 {
                let mut bad = b.clone(); bad[4] ^= delta;
                refuse_request(&d, frame(&r, Kind::RequestBegin, &bad), ProtocolError::Feature);
                let bad = begin(wire::STREAM_MAX + extra);
                refuse_request(&d, frame(&r, Kind::RequestBegin, &bad), ProtocolError::Budget);
                for cut in 0..b.len() {
                    refuse_request(&d, frame(&r, Kind::RequestBegin, &b[..cut]), ProtocolError::Schema);
                }
            }
            if state == 2 || state == 3 {
                let offset = if state == 2 { 0 } else { split };
                let bad = chunk(offset + extra, b"x");
                refuse_request(&d, frame(&r, Kind::RequestChunk, &bad), ProtocolError::Order);
                let bad = chunk(offset, &vec![0; body.len() - offset + extra]);
                refuse_request(&d, frame(&r, Kind::RequestChunk, &bad), ProtocolError::Order);
            }
            match state {
                0 => { d.accept(frame(&r, Kind::Ready, &p)).unwrap(); }
                1 => { d.accept(frame(&r, Kind::RequestBegin, &b)).unwrap(); }
                2 => { d.accept(frame(&r, Kind::RequestChunk, &first)).unwrap(); }
                3 => { d.accept(frame(&r, Kind::RequestChunk, &last)).unwrap(); }
                4 => { prop_assert_eq!(d.accept(frame(&r, Kind::RequestEnd, &crc)), Ok(Some(r.clone()))); }
                _ => {}
            }
        }
        // A valid RequestEnd checksum must not hide an invalid binding. All
        // read_paths validation precedes copying, hence the exact zero bound.
        for at in [44, 48, 89, 95, 101] { // context, clock kind, path starts
            let mut bad = body.clone(); bad[at] = if at == 48 { 0 } else { bad[at] ^ delta };
            let mut d = RequestDecoder::new();
            d.accept(frame(&r, Kind::Ready, &p)).unwrap();
            d.accept(frame(&r, Kind::RequestBegin, &b)).unwrap();
            d.accept(frame(&r, Kind::RequestChunk, &chunk(0, &bad))).unwrap();
            refuse_request(&d, frame(&r, Kind::RequestEnd, &snapshot::crc32c(&[&bad])), ProtocolError::Schema);
        }
    }
    // 이것을 실패시키는 것: Ready 전/요청 전 Update, Complete 후 프레임, 잘못된 Ready 길이·기능·mask·정체 또는 EOF 절단을 허용하는 것.
    #[test]
    fn transcript_intermediate_refusals_are_transactional_and_allocation_free(delta in 1u8..=255) {
        let r = request(); let p = ready(); let mut t = Transcript::new(&r);
        for state in 0..5 {
            let wrong = if state < 2 { frame(&r, Kind::Update, &[3, 0, 0, 0]) }
                else { frame(&r, Kind::RequestBegin, &[]) };
            refuse_transcript(&t, &encoded(wrong), ProtocolError::Order);
            if state < 4 {
                let valid = if state == 0 { frame(&r, Kind::Ready, &p) }
                    else if state == 1 { frame(&r, Kind::Complete, &[]) }
                    else { frame(&r, Kind::Update, &[3, 0, 0, 0]) };
                if state != 1 {
                    let mut bad = valid; bad.build_id.0[0] ^= delta;
                    refuse_transcript(&t, &encoded(bad), ProtocolError::Build);
                    bad = valid; bad.request_id.0[0] ^= delta;
                    refuse_transcript(&t, &encoded(bad), ProtocolError::Id);
                }
                let bytes = encoded(valid);
                for cut in 0..bytes.len() {
                    refuse_transcript(&t, &bytes[..cut], ProtocolError::Truncated);
                }
            }
            if state == 0 {
                for cut in 0..p.len() {
                    refuse_transcript(&t, &encoded(frame(&r, Kind::Ready, &p[..cut])), ProtocolError::Schema);
                }
                let mut bad = p.clone(); bad[0] ^= delta;
                refuse_transcript(&t, &encoded(frame(&r, Kind::Ready, &bad)), ProtocolError::Feature);
                bad = p.clone(); bad[8..12].fill(0);
                refuse_transcript(&t, &encoded(frame(&r, Kind::Ready, &bad)), ProtocolError::Schema);
            }
            if state == 2 || state == 3 {
                for bad in [&[32,0,0][..], &[3,0,2], &[3,0,0,0,0]] {
                    refuse_transcript(&t, &encoded(frame(&r, Kind::Update, bad)), ProtocolError::Schema);
                }
                refuse_transcript(&t, &encoded(frame(&r, Kind::Complete, &[delta])), ProtocolError::Schema);
            }
            match state {
                0 => t.accept(frame(&r, Kind::Ready, &p)).unwrap(),
                1 => t.request_sent().unwrap(),
                2 => t.accept(frame(&r, Kind::Update, &[3, 0, 0, 0])).unwrap(),
                3 => t.accept(frame(&r, Kind::Complete, &[])).unwrap(),
                _ => {}
            }
        }
    }
    // 이것을 실패시키는 것: CRC가 맞는 저장 응답의 잘린 내부 필드·binding·중복·길이 오류를 허용하거나 고정 선언/경로/Update 상한 밖으로 할당하는 것.
    #[test]
    fn response_refusals_with_recomputed_crc_have_an_exact_allocation_bound(
        path_extra in 0usize..128, delta in 1u8..=255,
    ) {
        let mut r = request(); r.binding.cwd.extend(vec![b'w'; path_extra]);
        let c = Completed {progress: Default::default(), request_id:r.request_id, binding:r.binding.clone(),
            completed_at_ns:98, reason:EndReason::Deadline,
            updates:vec![wire::Update {facts: None,segment:3,value:None}] };
        let good = c.encode().unwrap();
        prop_assert_eq!(Completed::decode(&good), Ok(c));
        // Recomputed length AND CRC force every cut through the body parser.
        for cut in 0..good.len() {
            let mut bad = good[..cut].to_vec();
            if cut >= 64 { fix_response(&mut bad); }
            refuse_response(&bad, &r, if cut < 64 { ProtocolError::Truncated } else { ProtocolError::Schema });
        }
        // Binding's context/clock/path starts are wrong but CRC is valid.
        for at in [128+44, 128+48, 128+85, 128+91, 128+97] {
            let mut bad = good.clone(); bad[at] = if at == 176 { 0 } else { bad[at] ^ delta }; fix_response(&mut bad);
            refuse_response(&bad, &r, ProtocolError::Schema);
        }
        let mut bad = good.clone(); bad[good.len()-4..good.len()-2].copy_from_slice(&32u16.to_le_bytes());
        fix_response(&mut bad); refuse_response(&bad, &r, ProtocolError::Schema);
        // Same allocation bound is actually reached: all declared storage is
        // allocated before trailing bytes/invalid present are refused.
        let (allocs, peak) = response_bound(&r);
        let mut bad = good.clone(); bad.push(delta); fix_response(&mut bad);
        prop_assert_eq!(refuse_response(&bad, &r, ProtocolError::Schema), (allocs,0,peak));
        let mut bad = good.clone(); *bad.last_mut().unwrap()=2; fix_response(&mut bad);
        prop_assert_eq!(refuse_response(&bad, &r, ProtocolError::Schema), (allocs,0,peak));
        // Structurally valid but foreign bindings must be refused at eligibility,
        // rather than mistaken for corrupt encodings. CRC is recomputed here too.
        for at in [96, 128, 144, 160, 168, 177, 193, 226] {
            let mut bad=good.clone(); bad[at] = if at == 226 { b'x' } else { bad[at]^delta }; fix_response(&mut bad);
            let mut result=Ok(None);
            let counts=allocation::counted(|| {
                result=Completed::decode(&bad).map(|c| c.eligible(&r.binding,clock()).then_some(c));
            });
            prop_assert_eq!(result,Ok(None));
            prop_assert_eq!(counts,(allocs,0,peak));
        }
        // Incorrect outer length is refused without any allocation.
        let mut bad=good.clone(); bad[12..16].copy_from_slice(&u32::MAX.to_le_bytes());
        prop_assert_eq!(refuse_response(&bad, &r, ProtocolError::Budget), (0,0,0));
    }
    // 이것을 실패시키는 것: 중복 필드를 허용하거나 거부할 때 선언된 필드/텍스트 사본보다 1바이트라도 더 할당하는 것.
    #[test]
    fn late_duplicate_refusal_has_an_exact_field_allocation_bound(n in 1usize..=256) {
        let r=request();
        // segment 3, present, empty raw text, two fields, first = branch text;
        // the duplicate index is refused after the first sanitized allocation.
        let mut payload=vec![3,0,1,0,0,0,0,2,0,2,0,0,0];
        payload.extend((n as u32).to_le_bytes()); payload.extend(vec![b'a';n]);
        payload.extend(2u16.to_le_bytes());
        let fields_bytes=field::BUILTIN[3].fields.len()*size_of::<field::Field>();
        let mut t=Transcript::new(&r);
        t.accept(frame(&r,Kind::Ready,&ready())).unwrap(); t.request_sent().unwrap();
        let saved=t.clone(); let mut result=Ok(());
        let counts=allocation::counted(|| result=t.accept(frame(&r,Kind::Update,&payload)));
        prop_assert_eq!(result,Err(ProtocolError::Duplicate));
        prop_assert_eq!(t,saved);
        prop_assert_eq!(counts,(2,0,fields_bytes+n));
        let c=Completed {progress: Default::default(),request_id:r.request_id,binding:r.binding.clone(), completed_at_ns:98,
            reason:EndReason::Deadline, updates:vec![wire::Update {facts: None,segment:3,value:None}]};
        let mut bad=c.encode().unwrap(); bad.truncate(bad.len()-4); bad.extend(payload); fix_response(&mut bad);
        let mut result=Ok(None);
        let counts=allocation::counted(|| result=Completed::decode(&bad).map(Some));
        prop_assert_eq!(result,Err(ProtocolError::Duplicate));
        let (allocs,peak)=response_bound(&r);
        prop_assert_eq!(counts,(allocs+2,0,peak+fields_bytes+n));
    }

}

// 이것을 실패시키는 것: catalog 밖 mask를 허용하거나 Request의 경로·예산·environment 검사를 생략하는 것.
#[test]
fn with_catalog_validates_request_before_allocating() {
    let r = request();
    for len in [0, 3] {
        let mut result = Ok(None);
        let counts = allocation::counted(|| {
            result = Transcript::with_catalog(&r, &field::BUILTIN[..len]).map(Some)
        });
        assert_eq!(result, Err(ProtocolError::Schema));
        assert_eq!(counts, (0, 0, 0));
    }
    assert!(Transcript::with_catalog(&r, &field::BUILTIN[..4]).is_ok());
    const CATALOG: [SegmentDecl; 33] = [const {
        SegmentDecl {
            id: "fixture",
            role: "fg",
            fields: &[],
        }
    }; 33];
    let mut max = r.clone();
    max.binding.mask = u32::MAX;
    assert!(Transcript::with_catalog(&max, &CATALOG[..32]).is_ok());
    let mut result = Ok(None);
    let counts =
        allocation::counted(|| result = Transcript::with_catalog(&max, &CATALOG).map(Some));
    assert_eq!(result, Err(ProtocolError::Budget));
    assert_eq!(counts, (0, 0, 0));
    let mut empty = r.clone();
    empty.binding.mask = 0;
    assert!(Transcript::with_catalog(&empty, &[]).is_ok());
    for case in 0..4 {
        let mut bad = r.clone();
        let expected = match case {
            0 => {
                bad.binding.cwd[0] = b'x';
                ProtocolError::Schema
            }
            1 => {
                bad.binding.snapshot.context[0] ^= 1;
                ProtocolError::Schema
            }
            2 => {
                bad.budget_ms = 0;
                ProtocolError::Budget
            }
            _ => {
                bad.environment.push((vec![], vec![]));
                ProtocolError::Schema
            }
        };
        let mut result = Ok(None);
        let counts = allocation::counted(|| {
            result = Transcript::with_catalog(&bad, field::BUILTIN).map(Some)
        });
        assert_eq!(result, Err(expected));
        assert_eq!(counts, (0, 0, 0));
    }
}
// 이것을 실패시키는 것: Complete를 받았다는 이유로 감독자의 Deadline을 Complete로 덮어쓰는 것.
#[test]
fn complete_then_deadline_keeps_supervisor_reason() {
    let r = request();
    let mut t = Transcript::new(&r);
    t.accept(frame(&r, Kind::Ready, &ready())).unwrap();
    t.request_sent().unwrap();
    t.accept(frame(&r, Kind::Update, &[3, 0, 0, 0])).unwrap();
    t.accept(frame(&r, Kind::Complete, &[])).unwrap();
    let completed = t.finish(EndReason::Deadline, clock()).unwrap().unwrap();
    assert_eq!(completed.reason, EndReason::Deadline);
    assert_eq!(
        Completed::decode(&completed.encode().unwrap())
            .unwrap()
            .reason,
        EndReason::Deadline
    );
}

// Independent encoder deliberately permits invalid counts, indices and lengths.
fn raw_facts(f: &bingsu_core::collection::path_facts::PathFactInput) -> Vec<u8> {
    let mut out = vec![u8::from(f.repo_component.is_some())];
    out.extend(f.repo_component.unwrap_or(0).to_le_bytes());
    for b in [f.in_repo, f.readonly] {
        out.push(match b {
            None => 0,
            Some(false) => 1,
            Some(true) => 2,
        });
    }
    out.push(u8::from(f.partial));
    out.push(f.siblings.len() as u8);
    for set in &f.siblings {
        out.extend(set.component.to_le_bytes());
        out.push(u8::from(set.complete));
        out.extend((set.names.len() as u16).to_le_bytes());
        for name in &set.names {
            out.extend((name.len() as u16).to_le_bytes());
            out.extend(name);
        }
    }
    out
}
fn facts_update(bytes: &[u8]) -> Vec<u8> {
    let mut out = vec![1, 0, 0, 1];
    out.extend((bytes.len() as u32).to_le_bytes());
    out.extend(bytes);
    out
}
fn dir_request() -> Request {
    let mut r = request();
    r.binding.mask = 2;
    r.binding.cwd = "/x".repeat(40).into_bytes();
    r
}
fn dir_transcript(r: &Request) -> Transcript {
    let mut t = Transcript::new(r);
    let mut p = ready();
    p[8..12].copy_from_slice(&2u32.to_le_bytes());
    t.accept(frame(r, Kind::Ready, &p)).unwrap();
    t.request_sent().unwrap();
    t
}
proptest! {
    #![proptest_config(ProptestConfig { cases: 32, .. ProptestConfig::default() })]
    // 이것을 실패시키는 것: 32/33 sets·256/257 names·이름/단계/전체 raw bytes·인코딩 bytes 상한이나 component 중복·순서·범위 검사를 제거하는 것.
    #[test]
    fn path_facts_boundaries_are_transactional_and_preflight_allocations_are_zero(byte in any::<u8>()) {
        use bingsu_core::collection::path_facts::{PathFactInput, SiblingSet};
        let r = dir_request();
        let base = PathFactInput { in_repo: Some(true), repo_component: Some(0), ..Default::default() };
        let set = |component, n, len| SiblingSet { component, complete: true, names: vec![vec![byte; len]; n] };
        let mut cases = vec![(base.clone(), Ok(()))];
        for (n, result) in [(32, Ok(())), (33, Err(ProtocolError::Budget))] {
            cases.push((PathFactInput { siblings: (0..n).map(|i| set(i, 0, 0)).collect(), ..base.clone() }, result));
        }
        for (n, result) in [(256, Ok(())), (257, Err(ProtocolError::Budget))] {
            cases.push((PathFactInput { siblings: vec![set(0,n,1)], ..base.clone() }, result));
        }
        for (len, result) in [(1024, Ok(())), (1025, Err(ProtocolError::Budget))] {
            cases.push((PathFactInput { siblings: vec![set(0,1,len)], ..base.clone() }, result));
        }
        for (extra, result) in [(0, Ok(())), (1, Err(ProtocolError::Budget))] {
            let mut step = set(0,8,1024); step.names.push(vec![byte;extra]);
            cases.push((PathFactInput { siblings: vec![step], ..base.clone() }, result));
            cases.push((PathFactInput { siblings: vec![set(0,8,1024),set(1,8,1024),set(2,1,extra)], ..base.clone() }, result));
            let mut sets: Vec<_> = (0..32).map(|i| set(i,256,2)).collect();
            for name in &mut sets[0].names[..167-extra] { name.pop(); }
            let f = PathFactInput { siblings: sets, ..base.clone() };
            prop_assert_eq!(raw_facts(&f).len(), 32_768+extra);
            cases.push((f, result));
        }
        for indices in [[0,0], [1,0], [0,40]] {
            cases.push((PathFactInput { siblings: indices.map(|i|set(i,0,0)).to_vec(), ..base.clone() }, Err(ProtocolError::Schema)));
        }
        cases.push((PathFactInput { repo_component: Some(40), ..base.clone() }, Err(ProtocolError::Schema)));
        cases.push((PathFactInput { in_repo: Some(false), ..base.clone() }, Err(ProtocolError::Schema)));
        // in_repo=true with no logical repo index is a supported mismatch.
        cases.push((PathFactInput { repo_component: None, ..base }, Ok(())));
        for (facts, expected) in cases {
            let bytes = raw_facts(&facts); let payload = facts_update(&bytes);
            prop_assert_eq!(facts.validate(&r.binding.cwd), expected);
            let mut decoded = Ok(None);
            let counts = allocation::counted(|| decoded = PathFactInput::decode(&bytes, &r.binding.cwd).map(Some));
            if let Err(error) = expected {
                prop_assert_eq!(decoded, Err(error)); prop_assert_eq!(counts, (0,0,0));
                prop_assert_eq!(facts.encode(&r.binding.cwd), Err(error));
            } else {
                prop_assert_eq!(decoded, Ok(Some(facts.clone())));
                prop_assert_eq!(facts.encode(&r.binding.cwd), Ok(bytes));
                prop_assert!(counts.0 <= 1 + 32 + 8192); prop_assert_eq!(counts.1, 0);
                prop_assert!(counts.2 <= 32 * size_of::<SiblingSet>() + 8192 * size_of::<Vec<u8>>() + 16_384);
            }
            let mut t = dir_transcript(&r); let before = t.clone(); let mut result = Ok(());
            let counts = allocation::counted(|| result = t.accept(frame(&r, Kind::Update, &payload)));
            prop_assert_eq!(result, expected);
            if expected.is_err() { prop_assert_eq!(t, before); prop_assert_eq!(counts, (0,0,0)); }
            else { let c = t.finish(EndReason::Deadline,clock()).unwrap().unwrap();
                prop_assert_eq!(&c.updates[0].facts, &Some(facts));
                prop_assert_eq!(Completed::decode(&c.encode().unwrap()), Ok(c)); }
        }
    }
    // 이것을 실패시키는 것: facts/query/Progress의 비정규 bool·tag·absent payload·trailing bytes 또는 구 wire/response 버전을 허용하는 것.
    #[test]
    fn v3_tags_versions_and_progress_order_are_closed(invalid in 3u8..=255) {
        use bingsu_core::collection::{path_facts::{PathFactInput, SiblingSet}, wire::Progress};
        let r = dir_request();
        let facts = PathFactInput { siblings: vec![SiblingSet { component:0, complete:true, names:vec![vec![b'a']] }], ..Default::default() };
        let good = raw_facts(&facts);
        for (at,b) in [(0,invalid), (1,1), (3,invalid), (4,invalid), (5,invalid), (9,invalid)] {
            let mut bad=good.clone();bad[at]=b;
            let mut result=Ok(None); let counts=allocation::counted(|| result=PathFactInput::decode(&bad,&r.binding.cwd).map(Some));
            prop_assert_eq!(result,Err(ProtocolError::Schema));prop_assert_eq!(counts,(0,0,0));
        }
        for cut in 0..good.len() { prop_assert_eq!(PathFactInput::decode(&good[..cut],&r.binding.cwd),Err(ProtocolError::Schema)); }
        let mut bad=good.clone();bad.push(0);prop_assert_eq!(PathFactInput::decode(&bad,&r.binding.cwd),Err(ProtocolError::Schema));
        for (at,b) in [(0,invalid),(1,invalid),(2,1)] {
            let mut p=[0;10];p[at]=b;
            prop_assert_eq!(Progress::decode(&p),Err(ProtocolError::Schema));
            let t=dir_transcript(&r);refuse_transcript(&t,&encoded(frame(&r,Kind::Progress,&p)),ProtocolError::Schema);
        }
        for size in [0,9,11] { prop_assert_eq!(Progress::decode(&vec![0;size]),Err(ProtocolError::Schema)); }
        let mut t=dir_transcript(&r);
        let mut closed=t.clone(); closed.accept(frame(&r,Kind::Complete,&[])).unwrap();
        refuse_transcript(&closed,&encoded(frame(&r,Kind::Progress,&[0;10])),ProtocolError::Order);
        let before=closed.clone();
        prop_assert_eq!(closed.accept(frame(&r,Kind::Progress,&[0;10])),Err(ProtocolError::Order));
        prop_assert_eq!(closed,before);
        t.accept(frame(&r,Kind::Update,&facts_update(&good))).unwrap();
        let c=t.clone().finish(EndReason::Deadline,clock()).unwrap().unwrap();
        for magic in [false,true] {
            let mut bytes=encoded(frame(&r,Kind::Complete,&[]));
            if magic { bytes[7]=b'2'; } else { bytes[8]=2; }
            refuse_transcript(&t,&bytes,if magic {ProtocolError::Magic}else{ProtocolError::Version});
            let mut bytes=c.encode().unwrap();if magic {bytes[7]=b'2';}else{bytes[8]=2;}
            prop_assert_eq!(Completed::decode(&bytes),Err(if magic{ProtocolError::Magic}else{ProtocolError::Version}));
        }
        // Observed dir-only discovery is required; an empty/unknown dir fact is not enough.
        let done=Progress {stage_a_complete:true,device:None}.encode();
        refuse_transcript(&t,&encoded(frame(&r,Kind::Progress,&done)),ProtocolError::Order);
        let mut observed=facts; observed.in_repo=Some(false);
        t.accept(frame(&r,Kind::Update,&facts_update(&raw_facts(&observed)))).unwrap();
        t.accept(frame(&r,Kind::Progress,&done)).unwrap();
        refuse_transcript(&t,&encoded(frame(&r,Kind::Progress,&done)),ProtocolError::Order);
        t.accept(frame(&r,Kind::Complete,&[])).unwrap();
        refuse_transcript(&t,&encoded(frame(&r,Kind::Progress,&done)),ProtocolError::Order);
    }
}
