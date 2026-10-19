use bingsu_core::{
    collection::{
        response::Completed,
        wire::{
            self, Binding, BuildId, EndReason, Frame, Kind, M3B_REQUEST_ID, ProtocolError, Request,
            RequestDecoder, Transcript,
        },
    },
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
    // 이것을 실패시키는 것: 거부 입력 전에 상태·계수를 바꾸거나 선언 길이를 무제한 할당하는 것.
    #[test]
    fn protocol_proptest_is_bounded_and_transactional(
        raw in prop::collection::vec(any::<u8>(),0..2048),
        length in prop_oneof![0usize..1024,Just(65_535),Just(65_536),Just(65_537),Just(262_144),Just(262_145)],
        changes in prop::collection::vec((any::<usize>(),any::<u8>(),0u8..6),1..12),
    ) {
        let r=request();let p=ready();let mut d=RequestDecoder::new();let mut t=Transcript::new(&r);
        d.accept(frame(&r,Kind::Ready,&p)).unwrap();t.accept(frame(&r,Kind::Ready,&p)).unwrap();t.request_sent().unwrap();
        t.accept(frame(&r,Kind::Update,&[3,0,0])).unwrap();
        let original=t.clone().finish(EndReason::Deadline,clock()).unwrap().unwrap();let original_before=original.clone();
        let body=r.encode_body().unwrap();let mut begin=(body.len() as u32).to_le_bytes().to_vec();begin.extend(3u64.to_le_bytes());
        d.accept(frame(&r,Kind::RequestBegin,&begin)).unwrap();
        let mut chunk=0u32.to_le_bytes().to_vec();chunk.extend(&body);
        d.accept(frame(&r,Kind::RequestChunk,&chunk)).unwrap();
        let mut raw_bytes=vec![0;length];if !raw.is_empty() {for (i,b) in raw_bytes.iter_mut().enumerate() {*b=raw[i%raw.len()];}}
        let raw_before=raw_bytes.clone();let saved_d=d.clone();let saved_t=t.clone();
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
        prop_assert_eq!(&raw_bytes,&raw_before);prop_assert_eq!(&original,&original_before);
        // Arbitrary bytes almost always fail at the header. Also exercise
        // all payload kinds against a fully valid prefix below.
        d=saved_d;t=saved_t;
        for (offset,byte,kind) in changes {
            let kind=match kind {0=>Kind::Ready,1=>Kind::RequestBegin,2=>Kind::RequestChunk,3=>Kind::RequestEnd,4=>Kind::Update,_=>Kind::Complete};
            let mut payload=match kind {Kind::Ready=>ready(),Kind::RequestBegin=>begin.clone(),Kind::RequestChunk=>chunk.clone(),Kind::RequestEnd=>snapshot::crc32c(&[&body]).to_vec(),Kind::Update=>vec![3,0,1,0,0,0,0,1,0,0,0,0,1,4,0,0,0,1],Kind::Complete=>vec![]};
            if !payload.is_empty() {let i=offset%payload.len();payload[i]^=byte;} else if byte!=0 {payload.push(byte);}
            let f=frame(&r,kind,&payload);let before_d=d.clone();let before_t=t.clone();
            let mut dr=Ok(None);let mut tr=Ok(());
            let counts=allocation::counted(||{dr=d.accept(f);tr=t.accept(f);});
            prop_assert!(counts.2<=allocation_max);prop_assert!(counts.0+counts.1<=256);
            if dr.is_err() {prop_assert_eq!(&d,&before_d);}
            if tr.is_err() {prop_assert_eq!(&t,&before_t);}
            let mut stored=original.encode().unwrap();let index=offset%stored.len();stored[index]^=byte;
            let before=stored.clone();let counts=allocation::counted(||{let _=Completed::decode(&stored);});
            prop_assert!(counts.2<=allocation_max);prop_assert_eq!(&stored,&before);prop_assert_eq!(&original,&original_before);
        }
        if let Some(c)=t.finish(EndReason::Protocol,clock()).unwrap() {prop_assert!(c.encode().unwrap().len()<=wire::STREAM_MAX);}
    }
}
