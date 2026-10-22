use std::{cell::RefCell, io};

use bingsu_core::{
    collection::{
        git,
        path_facts::{PathFactInput, PathQuery},
        wire::{
            self, Binding, BuildId, EndReason, Frame, Kind, Progress, Request, Transcript, Update,
        },
    },
    field::{self, Field, FieldDecl, FieldType, FieldValue, SegmentDecl, Value},
    snapshot::{self, Clock, Identity},
    width::WidthProfile,
};

#[path = "../src/update_sink.rs"]
mod update_sink;
use update_sink::{UpdateSink, WireSink};

fn request(mask: u32) -> Request {
    Request {
        request_id: wire::M3B_REQUEST_ID,
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
            cwd: b"/home/work/repo".to_vec(),
            mask,
            path_query: PathQuery::default(),
        },
        budget_ms: 50,
        environment: vec![],
    }
}

fn ready(r: &Request) -> Vec<u8> {
    let mut payload = wire::FEATURES.to_le_bytes().to_vec();
    payload.extend(r.binding.mask.to_le_bytes());
    payload.extend([0; 12]);
    payload
}

fn git_update(stage: &[u8]) -> Update {
    let decl = &field::BUILTIN[3];
    let mut fields = vec![Field::PENDING; decl.fields.len()];
    for (name, value) in [
        ("branch", Field::text(b"main", 256, WidthProfile::DEFAULT)),
        ("detached", Field::known(FieldValue::Bool(false))),
        ("stage", Field::text(stage, 1, WidthProfile::DEFAULT)),
    ] {
        fields[decl.field_index(name).unwrap()] = value;
    }
    Update {
        segment: 3,
        value: Some(Value::new(b"", fields)),
        facts: None,
    }
}

fn hidden(segment: u16) -> Update {
    Update {
        segment,
        value: None,
        facts: None,
    }
}

fn progress(complete: bool, device: u64) -> Progress {
    Progress {
        stage_a_complete: complete,
        device: Some(device),
    }
}

fn receiver(r: &Request, catalog: &[SegmentDecl]) -> Transcript {
    let mut t = Transcript::with_catalog(r, catalog).unwrap();
    t.accept(Frame {
        kind: Kind::Ready,
        build_id: r.binding.build_id,
        request_id: r.request_id,
        payload: &ready(r),
    })
    .unwrap();
    t.request_sent().unwrap();
    t
}

fn assert_stopped(sink: &mut WireSink<'_>, output: &RefCell<Vec<Vec<u8>>>) {
    let before = output.borrow().clone();
    assert!(sink.update(git_update(b"A")).is_err());
    assert!(sink.progress(progress(false, 8)).is_err());
    assert!(sink.complete().is_err());
    assert_eq!(
        *output.borrow(),
        before,
        "no write after first error or Complete"
    );
}

// 이것을 실패시키는 것: Update를 Complete까지 모아 두거나, Progress 순서를 바꾸거나,
// 누적 snapshot을 delta로 보내거나, 첫 값만 남기거나, Complete 뒤 전송을 허용하는 것.
#[test]
fn sink_accepts_ordered_updates_before_complete() {
    for (mask, first) in [
        ((1 << 1) | (1 << 3), git_update(b"A")),
        (
            1 << 3,
            Update {
                segment: 3,
                value: Some(git::no_repo()),
                facts: None,
            },
        ),
        (
            1 << 1,
            Update {
                segment: 1,
                value: None,
                facts: Some(PathFactInput {
                    in_repo: Some(false),
                    ..Default::default()
                }),
            },
        ),
    ] {
        let r = request(mask);
        let output = RefCell::new(Vec::new());
        let mut write = |bytes: &[u8]| {
            output.borrow_mut().push(bytes.to_vec());
            Ok(())
        };
        let mut buffer = [0; wire::FRAME_MAX];
        let mut sink =
            WireSink::new(&r, field::BUILTIN, &ready(&r), &mut buffer, &mut write).unwrap();
        let mut t = receiver(&r, field::BUILTIN);
        let mut sent = 0;
        let mut observed = || {
            let output = output.borrow();
            assert_eq!(output.len(), sent + 1, "each call writes immediately, once");
            t.accept_bytes(&output[sent]).unwrap();
            sent += 1;
        };
        sink.progress(progress(false, 8)).unwrap();
        observed();
        sink.update(first.clone()).unwrap();
        observed();
        sink.progress(progress(true, 8)).unwrap();
        observed();
        let mut last = first;
        if mask == (1 << 1) | (1 << 3) {
            for stage in [b"B", b"C", b"D"] {
                last = git_update(stage);
                sink.update(last.clone()).unwrap();
                observed();
            }
        }
        sink.complete().unwrap();
        observed();
        let result = t
            .finish(
                EndReason::Complete,
                Clock {
                    kind: 1,
                    boot: [1; 16],
                    domain: [5; 16],
                    resume: 0,
                    now: 99,
                },
            )
            .unwrap()
            .unwrap();
        assert_eq!(result.updates, vec![last]);
        assert_eq!(result.progress, progress(true, 8));
        assert_stopped(&mut sink, &output);
    }
}

// 이것을 실패시키는 것: 부분 write 오류를 무시하거나, Update 인코딩/수신 검증 오류 뒤
// latch를 풀어 다음 Update·Progress·Complete를 쓰는 것.
#[test]
fn sink_stops_on_first_write_or_budget_error() {
    for failed_kind in [Kind::Update, Kind::Progress, Kind::Complete] {
        let r = request(1 << 3);
        let output = RefCell::new(Vec::new());
        let mut write = |bytes: &[u8]| {
            output.borrow_mut().push(bytes[..7].to_vec());
            Err(io::Error::new(io::ErrorKind::BrokenPipe, "partial write"))
        };
        let mut buffer = [0; wire::FRAME_MAX];
        let mut sink =
            WireSink::new(&r, field::BUILTIN, &ready(&r), &mut buffer, &mut write).unwrap();
        let error = match failed_kind {
            Kind::Update => sink.update(git_update(b"A")),
            Kind::Progress => sink.progress(progress(false, 8)),
            Kind::Complete => sink.complete(),
            _ => unreachable!(),
        }
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
        assert_eq!(output.borrow().len(), 1);
        assert_stopped(&mut sink, &output);
    }
    for bad in [
        hidden(32),
        Update {
            segment: 3,
            value: Some(Value::new(
                &[vec![b'x'; 4095], "é".as_bytes().to_vec()].concat(),
                git_update(b"A").value.unwrap().fields,
            )),
            facts: None,
        },
    ] {
        let r = request(1 << 3);
        let output = RefCell::new(Vec::new());
        let mut write = |bytes: &[u8]| {
            output.borrow_mut().push(bytes.to_vec());
            Ok(())
        };
        let mut buffer = [0; wire::FRAME_MAX];
        let mut sink =
            WireSink::new(&r, field::BUILTIN, &ready(&r), &mut buffer, &mut write).unwrap();
        let mut valid = git_update(b"A");
        valid.value = Some(Value::new(&vec![b'x'; 4096], valid.value.unwrap().fields));
        sink.update(valid).unwrap();
        assert_eq!(
            sink.update(bad).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(output.borrow().len(), 1);
        assert_stopped(&mut sink, &output);
    }
}

// 이것을 실패시키는 것: A 증거 없는 완료, 두 번의 미완료/완료, device 변경,
// B 뒤 늦은 A 완료 또는 완료된 A 증거 삭제를 wire 검증 없이 전송하는 것.
#[test]
fn sink_rejects_invalid_progress_order() {
    for case in 0..6 {
        let r = request(1 << 3);
        let output = RefCell::new(Vec::new());
        let mut write = |bytes: &[u8]| {
            output.borrow_mut().push(bytes.to_vec());
            Ok(())
        };
        let mut buffer = [0; wire::FRAME_MAX];
        let mut sink =
            WireSink::new(&r, field::BUILTIN, &ready(&r), &mut buffer, &mut write).unwrap();
        if case != 0 {
            sink.progress(progress(false, 8)).unwrap();
            sink.update(git_update(if case == 4 { b"B" } else { b"A" }))
                .unwrap();
        }
        if case == 3 || case == 5 {
            sink.progress(progress(true, 8)).unwrap();
        }
        let before = output.borrow().clone();
        let result = match case {
            1 => sink.progress(progress(false, 8)),
            2 => sink.progress(progress(true, 9)),
            5 => sink.update(hidden(3)),
            _ => sink.progress(progress(true, 8)),
        };
        assert!(result.is_err(), "case {case}");
        assert_eq!(*output.borrow(), before, "case {case}");
        assert_stopped(&mut sink, &output);
    }
}

// 이것을 실패시키는 것: segment당 16번째 갱신을 거부하거나 17번째를 쓰는 것,
// Ready/Complete를 64 frame 계수에서 제외하거나 Complete 예산 오류 뒤 전송하는 것.
#[test]
fn sink_counts_ready_complete_and_per_segment_updates() {
    for updates in [16, 62, 63] {
        let r = request(0b1111);
        let output = RefCell::new(Vec::new());
        let mut write = |bytes: &[u8]| {
            output.borrow_mut().push(bytes.to_vec());
            Ok(())
        };
        let mut buffer = [0; wire::FRAME_MAX];
        let mut sink =
            WireSink::new(&r, field::BUILTIN, &ready(&r), &mut buffer, &mut write).unwrap();
        for index in 0..updates {
            sink.update(hidden(index / 16)).unwrap();
        }
        if updates == 16 {
            assert!(sink.update(hidden(0)).is_err());
        } else if updates == 62 {
            sink.complete().unwrap();
        } else {
            assert!(sink.complete().is_err());
        }
        assert_eq!(
            output.borrow().len(),
            usize::from(updates) + usize::from(updates == 62)
        );
        assert_stopped(&mut sink, &output);
    }
}

const FIELDS: [FieldDecl; 32] = [const {
    FieldDecl {
        name: "text",
        ty: FieldType::Text { max_cells: 4096 },
    }
}; 32];
const CATALOG: [SegmentDecl; 32] = [const {
    SegmentDecl {
        id: "fixture",
        role: "fg",
        fields: &FIELDS,
    }
}; 32];

// Test-only arbitrary-sized payload, all individual strings at most 4096 bytes.
fn payload(size: usize) -> Vec<u8> {
    let mut bytes = vec![31, 0, 1, 0, 0, 0, 0, 32, 0];
    let mut remaining = size.checked_sub(266).unwrap();
    for index in 0u16..32 {
        let n = remaining.min(4096);
        bytes.extend(index.to_le_bytes());
        bytes.extend([0, 0]);
        bytes.extend((n as u32).to_le_bytes());
        bytes.resize(bytes.len() + n, b'x');
        remaining -= n;
    }
    bytes.push(0);
    assert_eq!(bytes.len(), size);
    bytes
}

// 이것을 실패시키는 것: 65,536 frame/262,144 stream 한도를 늘리거나 Ready·Complete
// 바이트를 제외하거나, 최대 binding의 저장 여유 65,294를 넘는 Update를 쓰는 것.
#[test]
fn sink_enforces_exact_frame_stream_and_storage_bytes() {
    for case in ["frame", "stream", "complete", "complete_exact", "storage"] {
        let mut r = request(1 << 31);
        if case == "storage" {
            let mut path = vec![b'a'; 65_536];
            path[0] = b'/';
            r.binding.config = path.clone();
            r.binding.state = path.clone();
            r.binding.cwd = path;
            r.binding.snapshot.context =
                snapshot::context_crc(&r.binding.config, &r.binding.state).unwrap();
        }
        let output = RefCell::new(Vec::new());
        let mut write = |bytes: &[u8]| {
            output.borrow_mut().push(bytes.to_vec());
            Ok(())
        };
        let mut buffer = [0; wire::FRAME_MAX];
        let mut sink = WireSink::new(&r, &CATALOG, &ready(&r), &mut buffer, &mut write).unwrap();
        let result = match case {
            "frame" => {
                sink.fixture_update(&payload(65_456)).unwrap();
                sink.fixture_update(&payload(65_457))
            }
            "storage" => {
                sink.fixture_update(&payload(65_294)).unwrap();
                sink.fixture_update(&payload(65_295))
            }
            _ => {
                for _ in 0..3 {
                    sink.fixture_update(&payload(65_456)).unwrap();
                }
                let remaining = 262_144 - 104 - 3 * 65_536;
                let reserve = if case == "stream" {
                    0
                } else if case == "complete_exact" {
                    wire::HEADER
                } else {
                    wire::HEADER - 1
                };
                sink.fixture_update(&payload(remaining - wire::HEADER - reserve))
                    .unwrap();
                if case == "stream" {
                    sink.fixture_update(&payload(266))
                } else {
                    sink.complete()
                }
            }
        };
        if case == "complete_exact" {
            result.unwrap();
            assert_eq!(
                output.borrow().iter().map(Vec::len).sum::<usize>() + wire::HEADER + 24,
                262_144
            );
        } else {
            let error = result.unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidData, "{case}");
            assert!(
                error
                    .to_string()
                    .contains(if case == "frame" { "Length" } else { "Budget" })
            );
        }
        assert_eq!(
            output.borrow().len(),
            if case == "frame" || case == "storage" {
                1
            } else if case == "complete_exact" {
                5
            } else {
                4
            }
        );
        assert_stopped(&mut sink, &output);
    }
}

// 이것을 실패시키는 것: 요청/catalog 또는 실제 Ready의 검증·request_sent 전이를
// 생략해 잘못된 mask/예산/features에서도 sink를 만들거나, Ready를 다시 쓰는 것.
#[test]
fn sink_rejects_invalid_setup_without_writing() {
    for case in 0..4 {
        let mut r = request(1 << 3);
        let mut ready = ready(&r);
        match case {
            0 => {
                r.binding.mask = 1 << 31;
                ready[8..12].copy_from_slice(&r.binding.mask.to_le_bytes());
            }
            1 => r.budget_ms = 0,
            2 => ready[8..12].fill(0),
            _ => ready[0] ^= 1,
        }
        let output = RefCell::new(Vec::new());
        let mut write = |bytes: &[u8]| {
            output.borrow_mut().push(bytes.to_vec());
            Ok(())
        };
        let mut buffer = [0; wire::FRAME_MAX];
        assert!(WireSink::new(&r, field::BUILTIN, &ready, &mut buffer, &mut write).is_err());
        assert!(output.borrow().is_empty());
    }
}
