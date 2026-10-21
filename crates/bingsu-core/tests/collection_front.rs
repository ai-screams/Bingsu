//! Collection reads use the same continuation as the confined adapter.
use bingsu_core::{
    bands::{self, Band},
    collection::{
        self,
        response::Completed,
        selection::{Catalog, PRODUCT},
        wire::{Binding, BuildId, EndReason, M3B_REQUEST_ID, Update},
    },
    color::palette::Mode,
    config::{
        compile::{BUILTIN_TOML, CompiledConfig},
        report::report,
        source::{ExtendsRef, FileKey, OpenError, Opened, Resolver, Trust},
    },
    field::{self, Field, FieldDecl, FieldType, SegmentDecl, Value},
    front::{
        output::Deadline,
        staged::{self, FdFacts, Observation, Operation, Step},
    },
    fs_trust::{AclFacts, Facts},
    snapshot::{self, Clock, Identity, Marker, Snapshot},
    template::compile::compile,
};

const TEST_MASK: u32 = 1 << 31;
const BUILD: BuildId = BuildId([7; 32]);
const CATALOG: [SegmentDecl; 32] = {
    let mut c = [const {
        SegmentDecl {
            id: "unused",
            role: "fg",
            fields: &[],
        }
    }; 32];
    let ids = [
        "a00", "a01", "a02", "a03", "a04", "a05", "a06", "a07", "a08", "a09", "a10", "a11", "a12",
        "a13", "a14", "a15", "a16", "a17", "a18", "a19", "a20", "a21", "a22", "a23", "a24", "a25",
        "a26", "a27", "a28", "a29", "a30", "fixture",
    ];
    let mut i = 0;
    while i < 32 {
        c[i] = SegmentDecl {
            id: ids[i],
            role: "fg",
            fields: &[],
        };
        i += 1;
    }
    c[31] = SegmentDecl {
        id: "fixture",
        role: "fg",
        fields: &[FieldDecl {
            name: "text",
            ty: FieldType::Text { max_cells: 4096 },
        }],
    };
    c
};
fn clock(now: u64) -> Clock {
    Clock {
        boot: [1; 16],
        kind: 1,
        domain: [2; 16],
        resume: 0,
        now,
    }
}
fn identity() -> Identity {
    Identity {
        boot: clock(0).boot,
        epoch: [3; 16],
        generation: 7,
        source: [4; 4],
        context: snapshot::context_crc(b"/c", b"/s").unwrap(),
    }
}
fn binding() -> Binding {
    Binding {
        build_id: BUILD,
        snapshot: identity(),
        clock_kind: 1,
        domain: clock(0).domain,
        resume: 0,
        config: b"/c".to_vec(),
        state: b"/s".to_vec(),
        cwd: b"/cwd".to_vec(),
        mask: TEST_MASK,
    }
}
fn completed(at: u64, text: &[u8]) -> Completed {
    Completed {
        request_id: M3B_REQUEST_ID,
        binding: binding(),
        completed_at_ns: at,
        reason: EndReason::Deadline,
        updates: vec![Update {
            segment: 31,
            value: Some(Value::new(
                text,
                vec![Field::text(
                    text,
                    4096,
                    bingsu_core::width::WidthProfile::DEFAULT,
                )],
            )),
        }],
    }
}
fn wire(r: &Completed) -> Vec<u8> {
    r.encode_with_catalog(&CATALOG).unwrap()
}
fn args() -> Vec<Vec<u8>> {
    [
        "--ctx",
        "1",
        "--record",
        "B1",
        "--width",
        "80",
        "--shell",
        "bash",
        "--runtime-root=1:9:/r",
        "--config-root=/c",
        "--state-root=/s",
        "--pwd",
        "/cwd",
    ]
    .map(|s| s.as_bytes().to_vec())
    .to_vec()
}
struct NoSources;
impl Resolver for NoSources {
    fn open(&mut self, _: &Opened, _: &ExtendsRef) -> Result<Opened, OpenError> {
        panic!("no config source I/O")
    }
}
fn snapshot() -> Snapshot {
    let c = report(
        vec![Opened {
            key: FileKey { dev: 1, ino: 1 },
            bytes: BUILTIN_TOML.as_bytes().to_vec(),
            trust: Trust::Executable,
            display: vec![],
        }],
        &mut NoSources,
        [0, 3, 0],
        Mode::Dark,
    )
    .snapshot
    .unwrap();
    Snapshot {
        id: identity(),
        config: c,
        metadata: snapshot::encode_metadata(b"not read").unwrap(),
    }
}
fn fixture_config() -> CompiledConfig {
    let mut s = snapshot();
    s.config.bands = vec![Band {
        min_cols: Some(0),
        max_cols: Some(79),
        order: None,
    }];
    s.config.band_order = bands::order_bands(&s.config.bands).unwrap();
    s.config.collect_mask = TEST_MASK;
    s.config.variants = vec![
        compile("{fixture}", &CATALOG).unwrap(),
        compile("narrow", &CATALOG).unwrap(),
    ];
    s.config
}
fn facts(directory: bool, size: usize) -> FdFacts {
    FdFacts {
        entry: Facts {
            dev: 1,
            ino: 9,
            uid: 501,
            gid: 20,
            mode: if directory { 0o040700 } else { 0o100600 },
            ownership: Some(true),
            acl: AclFacts::None,
        },
        local: Some(true),
        nlink: 1,
        size: size as u64,
    }
}
pub struct Harness {
    snapshot: Vec<u8>,
    last_good: Option<Vec<u8>>,
    marker: Vec<u8>,
    responses: [Option<Vec<u8>>; 2],
    selected: &'static [u8],
    offset: usize,
    reads: Vec<(&'static [u8], usize, usize)>,
    operations: Vec<String>,
    short: usize,
    clocks: usize,
    entry: Clock,
    start: Clock,
    end: Clock,
    fail_final_clock: bool,
    prefetch: Option<Vec<String>>,
    args: Vec<Vec<u8>>,
    fixture: bool,
    schema: &'static [SegmentDecl],
    render_config: CompiledConfig,
}
impl Harness {
    fn new(current: Option<Completed>, previous: Option<Completed>) -> Self {
        let s = snapshot();
        let marker = Marker {
            id: s.id,
            seq: 1,
            verified_at: 100,
            kind: 1,
            domain: clock(0).domain,
            resume: 0,
            invalid: false,
        }
        .encode()
        .to_vec();
        Self {
            snapshot: s.encode(1, 0).unwrap(),
            last_good: None,
            marker,
            responses: [current.as_ref().map(wire), previous.as_ref().map(wire)],
            selected: b"",
            offset: 0,
            reads: vec![],
            operations: vec![],
            short: usize::MAX,
            clocks: 0,
            entry: clock(100),
            start: clock(102),
            end: clock(103),
            fail_final_clock: false,
            prefetch: None,
            args: args(),
            fixture: true,
            schema: &CATALOG,
            render_config: fixture_config(),
        }
    }
    fn bytes(&self) -> &[u8] {
        match self.selected {
            b"snapshot" => &self.snapshot,
            b"last-good" => self.last_good.as_deref().unwrap(),
            b"marker" => &self.marker,
            b"response" => self.responses[0].as_deref().unwrap(),
            b"previous" => self.responses[1].as_deref().unwrap(),
            _ => panic!("unexpected file"),
        }
    }
    pub fn run(&mut self) -> staged::Response {
        self.clocks = 0;
        self.reads.clear();
        self.operations.clear();
        let raw = self.args.iter().map(Vec::as_slice).collect::<Vec<_>>();
        let mut plan = staged::prepare(&raw)
            .with_entry(self.entry)
            .with_build_id(BUILD)
            .with_deadline(Deadline::from_entry(100, 50).unwrap());
        if self.fixture {
            plan = plan.with_catalog(
                Catalog {
                    segments: self.schema,
                    workers: TEST_MASK,
                },
                self.render_config.clone(),
            );
        }
        let mut previous = None;
        for _ in 0..20_000 {
            let effect = match staged::next(&mut plan, previous.take()) {
                Step::Done(o) => return staged::finish(plan, o),
                Step::Read(e) => e,
            };
            if let Some(p) = plan.prefetch(&effect) {
                self.prefetch = p.collection_components().map(Iterator::collect);
            }
            let o = match effect.operation() {
                Operation::Uid => Observation::Uid(501),
                Operation::Clock => {
                    self.clocks += 1;
                    if self.clocks > 1 && self.fail_final_clock {
                        Observation::Failed
                    } else {
                        Observation::Clock(Some(if self.clocks == 1 {
                            self.start
                        } else {
                            self.end
                        }))
                    }
                }
                Operation::OpenDirectory { .. } => Observation::Opened,
                Operation::Inspect(staged::Slot::File) => {
                    Observation::Facts(facts(false, self.bytes().len()))
                }
                Operation::Inspect(_) => Observation::Facts(facts(true, 0)),
                Operation::OpenFile { name, .. } => {
                    self.selected = name;
                    self.offset = 0;
                    if *name == b"last-good" && self.last_good.is_none() {
                        Observation::Failed
                    } else {
                        Observation::Opened
                    }
                }
                Operation::OpenCollection(copy) => {
                    self.selected = copy.name();
                    self.offset = 0;
                    if self.responses[copy.index()].is_some() {
                        Observation::Opened
                    } else {
                        Observation::Failed
                    }
                }
                Operation::Read { len, .. } => {
                    let n = (*len).min(self.short).min(self.bytes().len() - self.offset);
                    let bytes = self.bytes()[self.offset..self.offset + n].to_vec();
                    self.reads.push((self.selected, self.offset, *len));
                    self.offset += n;
                    Observation::Bytes(bytes)
                }
                Operation::Close(_) => Observation::Closed,
            };
            self.operations.push(format!("{:?}", effect.operation()));
            previous = Some(o);
        }
        panic!("continuation must terminate")
    }
    fn text(&mut self) -> String {
        String::from_utf8(self.run().record).unwrap()
    }
}

// 이것을 실패시키는 것: 완료 cutoff를 선취·decode 시각으로 늦추거나 entry와 같은 완료 시각을 허용하는 것.
#[test]
fn entry_cutoff_and_selected_binding_are_independent_of_prefetch_time() {
    for at in [100, 101, 102, 103] {
        let mut h = Harness::new(
            Some(completed(at, b"CURRENT")),
            Some(completed(99, b"PREVIOUS")),
        );
        let record = h.text();
        assert!(
            record.contains("PREVIOUS") && !record.contains("CURRENT"),
            "{at}: {record}"
        );
    }
    let mut h = Harness::new(
        Some(completed(99, b"CURRENT")),
        Some(completed(98, b"PREVIOUS")),
    );
    assert!(h.text().contains("CURRENT"));
    for kind in [1, 2] {
        let mut r = completed(99, b"CLOCK");
        r.binding.clock_kind = kind;
        let mut h = Harness::new(Some(r), None);
        h.entry.kind = kind;
        h.start.kind = kind;
        h.end.kind = kind;
        assert!(h.text().contains("CLOCK"));
    }
}

// 이것을 실패시키는 것: 최종 시계 관찰 Failed 뒤 이미 읽은 collection을 렌더하는 것.
#[test]
fn failed_final_clock_discards_an_already_selected_collection() {
    for previous in [false, true] {
        let response = completed(99, b"COLLECTED");
        let mut h = if previous {
            Harness::new(None, Some(response))
        } else {
            Harness::new(Some(response), None)
        };
        assert!(h.text().contains("COLLECTED"));
        h.fail_final_clock = true;
        let record = h.text();
        assert_eq!(h.clocks, 2);
        let selected = if previous {
            b"previous".as_slice()
        } else {
            b"response"
        };
        assert!(h.reads.iter().any(|(name, _, _)| *name == selected));
        assert!(
            record.contains('?') && !record.contains("COLLECTED"),
            "{record}"
        );
    }
}

// 이것을 실패시키는 것: 원문 cwd 외 roots·build·request를 주소에 넣거나 긴 경로를 자르는 것.
#[test]
fn helper_and_front_compute_the_same_cwd_address() {
    for cwd in [
        b"/".to_vec(),
        b"/\xff/raw".to_vec(),
        [b"/".as_slice(), &vec![b'a'; 65_535]].concat(),
    ] {
        let mut h = Harness::new(None, None);
        *h.args.last_mut().unwrap() = cwd.clone();
        h.run();
        let mut b = binding();
        b.cwd = cwd;
        assert_eq!(h.prefetch.as_ref().unwrap(), &b.components());
        b.config = b"/other-config".to_vec();
        b.state = b"/other-state".to_vec();
        b.build_id = BuildId([8; 32]);
        assert_eq!(h.prefetch.as_ref().unwrap(), &b.components());
        assert_ne!(
            snapshot::context_components(&b.config, &b.state).unwrap(),
            snapshot::context_components(b"/c", b"/s").unwrap()
        );
    }
}

// 이것을 실패시키는 것: binding 비교의 어느 필드라도 빼거나 request_id를 재사용 정체에 넣는 것.
#[test]
fn front_refuses_all_binding_mismatches_without_wait() {
    for i in 0..12 {
        let mut r = completed(99, b"REJECT");
        let b = &mut r.binding;
        match i {
            0 => {
                b.config.push(b'x');
                b.snapshot.context = snapshot::context_crc(&b.config, &b.state).unwrap();
            }
            1 => {
                b.state.push(b'x');
                b.snapshot.context = snapshot::context_crc(&b.config, &b.state).unwrap();
            }
            2 => b.cwd.push(b'x'),
            3 => b.snapshot.boot[0] ^= 1,
            4 => b.snapshot.epoch[0] ^= 1,
            5 => b.snapshot.generation += 1,
            6 => b.snapshot.source[0] ^= 1,
            7 => b.mask |= 1,
            8 => b.clock_kind = 2,
            9 => b.domain[0] ^= 1,
            10 => b.resume += 1,
            _ => b.build_id.0[0] ^= 1,
        }
        if r.binding.mask == 0 {
            r.updates.clear();
        }
        let mut h = Harness::new(Some(r), None);
        assert!(!h.text().contains("REJECT"), "binding field {i}");
        assert!(
            h.operations
                .iter()
                .any(|op| op == "OpenCollection(Previous)"),
            "mismatched current must fall through: binding field {i}"
        );
    }
    let mut r = completed(99, b"EXCHANGE");
    r.request_id.0[0] = 9;
    let mut h = Harness::new(Some(r), None);
    assert!(h.text().contains("EXCHANGE"));
    h.last_good = Some(h.snapshot.clone());
    h.snapshot[0] ^= 1;
    let mut m = Marker::decode(&h.marker).unwrap();
    m.invalid = true;
    m.id.generation += 1;
    h.marker = m.encode().to_vec();
    let out = h.run();
    assert!(String::from_utf8(out.record).unwrap().contains("EXCHANGE"));
    assert!(out.execution.permit().is_none());
}

// 이것을 실패시키는 것: 재사용 mask 계산에 redraw를 적용하거나 변경된 폭의 mask를 무시하는 것.
#[test]
fn redraw_reuses_the_collection_mask_without_spawning() {
    let mut h = Harness::new(Some(completed(99, b"REUSE")), None);
    h.args.push(b"--redraw".to_vec());
    let r = h.run();
    assert_eq!(r.worker_mask, 0);
    assert!(String::from_utf8(r.record).unwrap().contains("REUSE"));
    h.args[5] = b"79".to_vec();
    let r = h.run();
    assert_eq!(r.worker_mask, 0);
    assert!(!String::from_utf8(r.record).unwrap().contains("REUSE"));
    assert!(
        h.operations
            .iter()
            .any(|op| op == "OpenCollection(Previous)")
    );
}

// 이것을 실패시키는 것: 잘린/손상된 current에서 previous를 생략하거나 추가 EOF read·상한 초과 read를 하는 것.
#[test]
fn front_reads_only_bounded_completed_files() {
    let valid = wire(&completed(99, b"VALUE"));
    let mut cases = vec![
        vec![],
        vec![0; 63],
        vec![0; 262_145],
        valid[..valid.len() - 1].to_vec(),
    ];
    for at in [0, 8, 16, 20, 63, valid.len() - 1] {
        let mut b = valid.clone();
        b[at] ^= 1;
        cases.push(b);
    }
    for bytes in cases {
        let mut h = Harness::new(None, Some(completed(99, b"FALLBACK")));
        h.responses[0] = Some(bytes);
        assert!(h.text().contains("FALLBACK"));
    }
    let mut h = Harness::new(Some(completed(99, b"VALUE")), None);
    assert!(h.text().contains("VALUE"));
    let reads: Vec<_> = h
        .reads
        .iter()
        .filter(|(n, _, _)| *n == b"response")
        .copied()
        .collect();
    assert_eq!(
        reads,
        vec![
            (b"response".as_slice(), 0, 64),
            (b"response".as_slice(), 64, valid.len() - 64)
        ]
    );
    assert!(
        h.operations
            .iter()
            .all(|op| !op.contains("OpenCollection(Previous)"))
    );
    h.short = 1;
    assert!(h.text().contains("VALUE"));
    let mut h = Harness::new(None, Some(completed(99, b"CRASH")));
    assert!(h.text().contains("CRASH"));
    h.responses = [None, None];
    assert!(h.text().contains('?'));
}

// 이것을 실패시키는 것: worker 값이 봉투 내장·Facts를 덮거나 mask0에서도 병합하는 것.
#[test]
fn collected_values_do_not_override_shell_values() {
    let raw = args();
    let refs = raw.iter().map(Vec::as_slice).collect::<Vec<_>>();
    let e = bingsu_core::envelope::parse(&refs).unwrap();
    let mut values = bingsu_core::shell_values::collect(&e);
    let original = values.values.clone();
    let original_facts = format!("{:?}", values.facts);
    let mut r = completed(99, b"\x1b]0;ATTACK\x07\nVALUE");
    for i in 0..field::BUILTIN.len() {
        r.updates.push(Update {
            segment: i as u16,
            value: Some(Value::new(b"OVERRIDE", vec![])),
        });
    }
    collection::merge(&mut values, Some(&r), 0);
    assert_eq!(values.values, original);
    collection::merge(&mut values, Some(&r), TEST_MASK);
    assert_eq!(&values.values[..original.len()], &original);
    assert_eq!(format!("{:?}", values.facts), original_facts);
    assert!(!values.values[31].as_ref().unwrap().text().contains('\x1b'));
    let mut h = Harness::new(Some(completed(99, b"PRODUCT")), None);
    h.fixture = false;
    let r = h.run();
    assert_eq!(r.worker_mask, PRODUCT.workers);
    assert!(!String::from_utf8(r.record).unwrap().contains("PRODUCT"));
}

fn maximum() -> Harness {
    const MAX_FIELDS: [FieldDecl; 32] = [const {
        FieldDecl {
            name: "text",
            ty: FieldType::Text { max_cells: 4096 },
        }
    }; 32];
    const MAX_CATALOG: [SegmentDecl; 32] = [const {
        SegmentDecl {
            id: "fixture",
            role: "fg",
            fields: &MAX_FIELDS,
        }
    }; 32];
    let mut r = completed(99, b"");
    r.updates[0].value = Some(Value::new(
        b"",
        (0..32)
            .map(|_| Field::text(b"", 4096, bingsu_core::width::WidthProfile::DEFAULT))
            .collect(),
    ));
    let mut remaining = 262144 - r.encode_with_catalog(&MAX_CATALOG).unwrap().len();
    for f in &mut r.updates[0].value.as_mut().unwrap().fields {
        let n = remaining.min(12288);
        remaining -= n;
        let text = "\u{fffd}".repeat(n / 3) + &"a".repeat(n % 3);
        *f = Field::text(
            text.as_bytes(),
            4096,
            bingsu_core::width::WidthProfile::DEFAULT,
        );
    }
    assert_eq!(remaining, 0);
    let bytes = r.encode_with_catalog(&MAX_CATALOG).unwrap();
    assert_eq!(bytes.len(), 262144);
    let mut h = Harness::new(None, None);
    h.schema = &MAX_CATALOG;
    h.responses[0] = Some(bytes);
    h
}

// 이것을 실패시키는 것: 최대 파일에서 64-byte 머리/16KiB 본문 경계나 EOF read0을 깨는 것.
#[test]
fn maximum_response_uses_one_header_and_sixteen_body_reads() {
    let mut h = maximum();
    h.run();
    let reads: Vec<_> = h
        .reads
        .iter()
        .filter(|(name, _, _)| *name == b"response")
        .collect();
    assert_eq!(reads.len(), 17);
    assert_eq!(reads[0].2, 64);
    assert_eq!(reads.iter().map(|r| r.2).sum::<usize>(), 262144);
    assert!(reads[1..16].iter().all(|r| r.2 == 16384));
    assert_eq!(reads[16].2, 16320);
}

// 이것을 실패시키는 것: entry의 boot/domain/kind/resume 또는 시계 역행을 무시하는 것.
#[test]
fn entry_identity_and_final_clock_fail_closed() {
    for change in 0..9 {
        let mut h = Harness::new(Some(completed(99, b"FORBIDDEN")), None);
        match change {
            0 => h.start.boot[0] ^= 1,
            1 => h.start.domain[0] ^= 1,
            2 => h.start.kind = 2,
            3 => h.start.resume = 1,
            4 => h.start.now = 99,
            5 => h.end.boot[0] ^= 1,
            6 => h.end.domain[0] ^= 1,
            7 => h.end.resume = 1,
            _ => h.end.now = 101,
        }
        assert!(!h.text().contains("FORBIDDEN"), "clock condition {change}");
    }
}

/// Benchmark inputs are prepared outside the measured continuation.
pub fn bench_case(case: u8) -> Harness {
    match case {
        0 => Harness::new(None, None),
        1 => Harness::new(Some(completed(99, b"CURRENT")), None),
        2 => Harness::new(
            Some(completed(101, b"NEW")),
            Some(completed(99, b"PREVIOUS")),
        ),
        3 => maximum(),
        _ => {
            let mut h = Harness::new(Some(completed(99, b"CURRENT")), None);
            h.args[5] = b"79".to_vec();
            h
        }
    }
}

// 이것을 실패시키는 것: config/state 원문 대신 같은 context CRC만 비교하는 것.
#[test]
fn colliding_root_bytes_never_authorize_reuse() {
    let first = b"/collision/308a0945c21a0320";
    let second = b"/collision/3d806b964d5618d8";
    for config in [true, false] {
        let (c, s) = if config {
            (first.as_slice(), b"/s".as_slice())
        } else {
            (b"/c".as_slice(), first.as_slice())
        };
        let context = snapshot::context_crc(c, s).unwrap();
        let mut r = completed(99, b"COLLISION");
        r.binding.config = c.to_vec();
        r.binding.state = s.to_vec();
        r.binding.snapshot.context = context;
        if config {
            r.binding.config = second.to_vec();
        } else {
            r.binding.state = second.to_vec();
        }
        assert_eq!(
            snapshot::context_crc(&r.binding.config, &r.binding.state).unwrap(),
            context
        );
        let mut h = Harness::new(Some(r), None);
        for (prefix, value) in [
            (b"--config-root=".as_slice(), c),
            (b"--state-root=".as_slice(), s),
        ] {
            *h.args.iter_mut().find(|a| a.starts_with(prefix)).unwrap() = [prefix, value].concat();
        }
        let mut saved = snapshot();
        saved.id.context = context;
        h.snapshot = saved.encode(1, 0).unwrap();
        let mut marker = Marker::decode(&h.marker).unwrap();
        marker.id.context = context;
        h.marker = marker.encode().to_vec();
        assert!(!h.text().contains("COLLISION"));
    }
}
