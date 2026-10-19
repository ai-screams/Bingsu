//! Deterministic worker inputs for the shared protocol and response pipeline.
//! This is a Cargo test target, never a feature of a shipped crate.
#[cfg(not(test))]
compile_error!("collector_builtin is a test target only");

use bingsu_core::{
    collection::{
        self,
        response::Completed,
        selection::Catalog,
        wire::{
            self, Binding, BuildId, EndReason, Frame, Kind, M3B_REQUEST_ID, ProtocolError, Request,
            RequestDecoder, Transcript, Update,
        },
    },
    field::{Field, FieldDecl, FieldType, FieldValue, SegmentDecl, Value, ValueState},
    snapshot::{self, Clock, Identity},
    width::WidthProfile,
};

pub const TEST_MASK: u32 = 1u32 << 31;
pub const SENTINEL: &str = "collector_builtin_test_only_31";
const NAMES: [&str; 31] = [
    "a00", "a01", "a02", "a03", "a04", "a05", "a06", "a07", "a08", "a09", "a10", "a11", "a12",
    "a13", "a14", "a15", "a16", "a17", "a18", "a19", "a20", "a21", "a22", "a23", "a24", "a25",
    "a26", "a27", "a28", "a29", "a30",
];
const FIELDS: [FieldDecl; 32] = {
    let mut fields = [const {
        FieldDecl {
            name: "text",
            ty: FieldType::Text { max_cells: 4096 },
        }
    }; 32];
    let mut i = 0;
    while i < 31 {
        fields[i].name = NAMES[i];
        i += 1;
    }
    fields
};
pub const SEGMENTS: [SegmentDecl; 32] = {
    let mut segments = [const {
        SegmentDecl {
            id: "fixture",
            role: "fg",
            fields: &FIELDS,
        }
    }; 32];
    let mut i = 0;
    while i < 31 {
        segments[i] = SegmentDecl {
            id: NAMES[i],
            role: "fg",
            fields: &[],
        };
        i += 1;
    }
    segments
};
pub const CATALOG: Catalog<'static> = Catalog {
    segments: &SEGMENTS,
    workers: TEST_MASK,
};

#[derive(Clone, Copy)]
pub enum Sample {
    Normal,
    Hidden,
    Pending,
    Hostile,
    Fields32,
    Partial,
}

pub fn update(sample: Sample) -> Update {
    let value = match sample {
        Sample::Hidden => None,
        Sample::Normal => Some(Value::new(SENTINEL.as_bytes(), vec![Field::ABSENT; 32])),
        Sample::Pending => Some(Value::new(b"pending", vec![Field::PENDING; 32])),
        Sample::Hostile => Some(Value::new(
            b"a\x1b]0;attack\x07\xff\nb",
            vec![Field::text(b"x\x1b[31m\x00\xff", 4096, WidthProfile::DEFAULT); 32],
        )),
        Sample::Fields32 => Some(Value::new(
            b"fields",
            (0..32)
                .map(|i| Field::text(format!("field-{i}").as_bytes(), 4096, WidthProfile::DEFAULT))
                .collect(),
        )),
        Sample::Partial => {
            let mut fields = vec![Field::PENDING; 32];
            fields[0] = Field::text(b"first", 4096, WidthProfile::DEFAULT);
            Some(Value::new(b"partial", fields))
        }
    };
    Update { segment: 31, value }
}

fn request() -> Request {
    collection::request(
        Binding {
            build_id: BuildId([0x71; 32]),
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
            cwd: b"/r".to_vec(),
            mask: TEST_MASK,
        },
        M3B_REQUEST_ID,
        50,
    )
    .unwrap()
    .unwrap()
}
fn frame<'a>(r: &Request, kind: Kind, payload: &'a [u8]) -> Frame<'a> {
    Frame {
        kind,
        build_id: r.binding.build_id,
        request_id: r.request_id,
        payload,
    }
}
fn encoded(r: &Request, kind: Kind, payload: &[u8]) -> Vec<u8> {
    let mut out = [0; wire::FRAME_MAX];
    let n = wire::encode_frame(frame(r, kind, payload), &mut out).unwrap();
    out[..n].to_vec()
}
fn ready() -> Vec<u8> {
    let mut p = wire::FEATURES.to_le_bytes().to_vec();
    p.extend(TEST_MASK.to_le_bytes());
    p.extend(0u32.to_le_bytes());
    p.extend(0u64.to_le_bytes());
    p
}
fn put_text(out: &mut Vec<u8>, text: &[u8]) {
    out.extend((text.len() as u32).to_le_bytes());
    out.extend(text);
}
fn payload(u: &Update) -> Vec<u8> {
    let mut p = u.segment.to_le_bytes().to_vec();
    let Some(v) = &u.value else {
        p.push(0);
        return p;
    };
    p.push(1);
    put_text(&mut p, v.text().as_bytes());
    p.extend((v.fields.len() as u16).to_le_bytes());
    for (i, field) in v.fields.iter().enumerate() {
        p.extend((i as u16).to_le_bytes());
        p.push(u8::from(field.state == ValueState::Pending));
        match &field.value {
            FieldValue::Text(t) => {
                p.push(0);
                put_text(&mut p, t.as_str().as_bytes());
            }
            FieldValue::Absent => p.push(5),
            _ => panic!("fixture has only text or absent fields"),
        }
    }
    p
}
fn hostile_payload() -> Vec<u8> {
    let mut p = 31u16.to_le_bytes().to_vec();
    p.push(1);
    put_text(&mut p, b"a\x1b]0;attack\x07\xff\nb");
    p.extend(32u16.to_le_bytes());
    for i in 0..32u16 {
        p.extend(i.to_le_bytes());
        p.extend([0, 0]);
        put_text(&mut p, b"x\x1b[31m\x00\xff");
    }
    p
}
fn supervisor(r: &Request) -> Transcript {
    let ready = encoded(r, Kind::Ready, &ready());
    let mut worker = RequestDecoder::new();
    worker.accept(wire::decode_frame(&ready).unwrap()).unwrap();
    let mut supervisor = Transcript::with_catalog(r, CATALOG.segments).unwrap();
    supervisor.accept_bytes(&ready).unwrap();
    let body = r.encode_body().unwrap();
    let mut begin = (body.len() as u32).to_le_bytes().to_vec();
    begin.extend(wire::FEATURES.to_le_bytes());
    let mut chunk = 0u32.to_le_bytes().to_vec();
    chunk.extend(&body);
    for (kind, p) in [
        (Kind::RequestBegin, begin),
        (Kind::RequestChunk, chunk),
        (Kind::RequestEnd, snapshot::crc32c(&[&body]).to_vec()),
    ] {
        let b = encoded(r, kind, &p);
        let got = worker.accept(wire::decode_frame(&b).unwrap()).unwrap();
        if kind == Kind::RequestEnd {
            assert_eq!(got.as_ref(), Some(r));
        } else {
            assert!(got.is_none());
        }
    }
    supervisor.request_sent().unwrap();
    supervisor
}
fn clock(r: &Request) -> Clock {
    Clock {
        kind: r.binding.clock_kind,
        boot: r.binding.snapshot.boot,
        domain: r.binding.domain,
        resume: r.binding.resume,
        now: 10,
    }
}

// 이것을 실패시키는 것: 시험 bit31·Hidden·Pending·32필드·부분 값 또는 정제된 논리 값의 보존을 깨는 것.
#[test]
fn test_builtin_covers_updates_without_product_time() {
    assert_eq!(TEST_MASK, 1u32 << 31);
    assert_eq!(CATALOG.workers, TEST_MASK);
    let r = request();
    for sample in [
        Sample::Normal,
        Sample::Hidden,
        Sample::Pending,
        Sample::Hostile,
        Sample::Fields32,
        Sample::Partial,
    ] {
        let u = update(sample);
        assert_eq!(u.segment, 31);
        match sample {
            Sample::Hidden => assert!(u.value.is_none()),
            Sample::Normal => assert_eq!(u.value.as_ref().unwrap().text(), SENTINEL),
            Sample::Pending => assert!(
                u.value
                    .as_ref()
                    .unwrap()
                    .fields
                    .iter()
                    .all(|f| f.state == ValueState::Pending)
            ),
            Sample::Hostile => assert!(
                !u.value
                    .as_ref()
                    .unwrap()
                    .text()
                    .chars()
                    .any(char::is_control)
            ),
            Sample::Fields32 => {
                let v = u.value.as_ref().unwrap();
                assert_eq!(v.fields.len(), 32);
                for (i, f) in v.fields.iter().enumerate() {
                    assert_eq!(
                        *f,
                        Field::text(format!("field-{i}").as_bytes(), 4096, WidthProfile::DEFAULT)
                    );
                }
            }
            Sample::Partial => {
                let fields = &u.value.as_ref().unwrap().fields;
                assert_eq!(
                    fields[0],
                    Field::text(b"first", 4096, WidthProfile::DEFAULT)
                );
                assert!(fields[1..].iter().all(|f| f.state == ValueState::Pending));
            }
        }
        let mut t = supervisor(&r);
        let p = if matches!(sample, Sample::Hostile) {
            hostile_payload()
        } else {
            payload(&u)
        };
        t.accept_bytes(&encoded(&r, Kind::Update, &p)).unwrap();
        let partial = matches!(sample, Sample::Partial);
        if !partial {
            t.accept_bytes(&encoded(&r, Kind::Complete, &[])).unwrap();
            t.accept_bytes(&[]).unwrap();
        }
        let reason = if partial {
            EndReason::Deadline
        } else {
            EndReason::Complete
        };
        let complete = t.finish(reason, clock(&r)).unwrap().unwrap();
        assert_eq!(
            complete.reason,
            if partial {
                EndReason::Deadline
            } else {
                EndReason::Complete
            }
        );
        assert_eq!(complete.updates, [u]);
        let stored = complete.encode_with_catalog(CATALOG.segments).unwrap();
        let read = Completed::decode_with_catalog(&stored, CATALOG.segments).unwrap();
        assert_eq!(read, complete);
        let mut entry = clock(&r);
        entry.now += 1;
        assert!(read.eligible(&r.binding, entry));
        assert!(
            Completed::decode(&stored).is_err(),
            "product catalog rejects fixture"
        );
    }
}

// 이것을 실패시키는 것: 첫 거부 뒤 정상 frame을 받아 partial을 덮어쓰는 어댑터.
#[test]
fn fixture_adapter_stops_at_the_first_error() {
    let r = request();
    let mut t = supervisor(&r);
    let first = update(Sample::Partial);
    let mut accepted = 0;
    for b in [
        encoded(&r, Kind::Update, &payload(&first)),
        vec![0],
        encoded(&r, Kind::Update, &payload(&update(Sample::Normal))),
    ] {
        if t.accept_bytes(&b).is_err() {
            break;
        }
        accepted += 1;
    }
    assert_eq!(accepted, 1);
    let c = t.finish(EndReason::Protocol, clock(&r)).unwrap().unwrap();
    assert_eq!(c.updates, [first]);
    assert_eq!(c.reason, EndReason::Protocol);
    assert_eq!(collection::selection::PRODUCT.workers, 0);
    assert!(matches!(
        wire::decode_frame(&[0]),
        Err(ProtocolError::Length)
    ));
}
