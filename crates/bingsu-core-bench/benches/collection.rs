//! First appearance records positive instruction counts; later runs compare them.
use bingsu_core::{bands::Band, collection::selection, config::compile::CompiledConfig};
use bingsu_core::{
    collection::{
        cwd_hash,
        response::Completed,
        wire::{self, Binding, BuildId, EndReason, M3B_REQUEST_ID, ProtocolError, Request, Update},
    },
    field::{Field, FieldDecl, FieldType, SegmentDecl, Value},
    snapshot::{self, Identity},
    width::WidthProfile,
};
use gungraun::{library_benchmark, library_benchmark_group, main};
use std::hint::black_box;
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
fn request() -> Request {
    let mut path = vec![b'a'; 65_536];
    path[0] = b'/';
    Request {
        request_id: M3B_REQUEST_ID,
        binding: Binding {
            build_id: BuildId([7; 32]),
            snapshot: Identity {
                boot: [1; 16],
                epoch: [2; 16],
                generation: 3,
                source: [4; 4],
                context: snapshot::context_crc(&path, &path).unwrap(),
            },
            clock_kind: 1,
            domain: [5; 16],
            resume: 0,
            config: path.clone(),
            state: path.clone(),
            cwd: path,
            mask: 1 << 31,
        },
        budget_ms: 50,
        environment: vec![],
    }
}
fn request_bytes() -> Vec<u8> {
    request().encode_body().unwrap()
}
fn completed() -> Completed {
    let r = request();
    let mut rest = 65_308 - 265;
    let mut fields = vec![];
    for _ in 0..32 {
        let n = rest.min(4096);
        rest -= n;
        fields.push(Field::text(&vec![b'a'; n], 4096, WidthProfile::DEFAULT));
    }
    Completed {
        request_id: r.request_id,
        binding: r.binding,
        completed_at_ns: 99,
        reason: EndReason::Deadline,
        updates: vec![Update {
            segment: 31,
            value: Some(Value::new(b"", fields)),
        }],
    }
}
fn response_bytes() -> Vec<u8> {
    let b = completed().encode_with_catalog(&CATALOG).unwrap();
    assert_eq!(b.len(), 262_144);
    b
}
fn binding_pair() -> (Binding, Binding) {
    let b = request().binding;
    (b.clone(), b)
}
fn cwd(n: usize) -> Vec<u8> {
    let mut p = vec![b'a'; n];
    p[0] = b'/';
    p
}
fn prefix() -> [u8; 80] {
    let mut p = [0; 80];
    p[..8].copy_from_slice(b"BNGIPC02");
    p[12..16].copy_from_slice(&u32::MAX.to_le_bytes());
    p
}
#[inline(never)]
fn encode_request(r: &Request) -> Result<Vec<u8>, ProtocolError> {
    r.encode_body()
}
#[inline(never)]
fn decode_request(b: &[u8]) -> Result<Request, ProtocolError> {
    Request::decode_body(BuildId([7; 32]), M3B_REQUEST_ID, b)
}
#[inline(never)]
fn encode_response(c: &Completed) -> Result<Vec<u8>, ProtocolError> {
    c.encode_with_catalog(&CATALOG)
}
#[inline(never)]
fn decode_response(b: &[u8]) -> Result<Completed, ProtocolError> {
    Completed::decode_with_catalog(b, &CATALOG)
}
#[inline(never)]
fn compare(a: &Binding, b: &Binding) -> bool {
    a.matches(b)
}
#[inline(never)]
fn hash(b: &[u8]) -> [u8; 32] {
    cwd_hash::sha256(b)
}
#[inline(never)]
fn reject(b: &[u8]) -> Result<usize, ProtocolError> {
    wire::frame_len(b)
}
#[library_benchmark]
#[bench::maximum(setup=request)]
fn request_encode(r: Request) -> (Request, Vec<u8>) {
    let b = black_box(encode_request(black_box(&r))).unwrap();
    (r, b)
}
#[library_benchmark]
#[bench::maximum(setup=request_bytes)]
fn request_decode(b: Vec<u8>) -> (Vec<u8>, Request) {
    let r = black_box(decode_request(black_box(&b))).unwrap();
    (b, r)
}
#[library_benchmark]
#[bench::maximum(setup=completed)]
fn response_encode(c: Completed) -> (Completed, Vec<u8>) {
    let b = black_box(encode_response(black_box(&c))).unwrap();
    (c, b)
}
#[library_benchmark]
#[bench::maximum(setup=response_bytes)]
fn response_decode(b: Vec<u8>) -> (Vec<u8>, Completed) {
    let c = black_box(decode_response(black_box(&b))).unwrap();
    (b, c)
}
#[library_benchmark]
#[bench::maximum(setup=binding_pair)]
fn binding_compare(pair: (Binding, Binding)) -> ((Binding, Binding), bool) {
    let equal = black_box(compare(black_box(&pair.0), black_box(&pair.1)));
    (pair, equal)
}
#[library_benchmark]
#[bench::one(args=[1],setup=cwd)]
#[bench::maximum(args=[65_536],setup=cwd)]
fn cwd_sha256(b: Vec<u8>) -> (Vec<u8>, [u8; 32]) {
    let h = black_box(hash(black_box(&b)));
    (b, h)
}
#[library_benchmark]
#[bench::oversize(setup=prefix)]
fn rejected_prefix(b: [u8; 80]) -> Result<usize, ProtocolError> {
    black_box(reject(black_box(&b)))
}

fn selected_config() -> CompiledConfig {
    use bingsu_core::{
        color::palette::Mode,
        config::{
            compile::BUILTIN_TOML,
            report::report,
            source::{ExtendsRef, FileKey, OpenError, Opened, Resolver, Trust},
        },
    };
    struct NoSources;
    impl Resolver for NoSources {
        fn open(&mut self, _: &Opened, _: &ExtendsRef) -> Result<Opened, OpenError> {
            panic!("no source references")
        }
    }
    let mut c = report(
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
    c.bands = (0..4096)
        .map(|i| Band {
            min_cols: Some(i * 16),
            max_cols: Some(i * 16 + 15),
            order: None,
        })
        .collect();
    c.band_order = (0..4096).collect();
    c.variants = vec![c.variants[0].clone(); 4097];
    c
}
#[inline(never)]
fn selected(c: &CompiledConfig) -> u32 {
    selection::builtin_mask(c, 65535)
}
#[library_benchmark]
#[bench::bands4096(setup=selected_config)]
fn selected_variant(c: CompiledConfig) -> (CompiledConfig, u32) {
    let mask = black_box(selected(black_box(&c)));
    assert_ne!(mask, 0);
    (c, mask)
}
// The same deterministic fixture drives continuation tests and instruction counts.
#[allow(
    dead_code,
    unused_imports,
    reason = "shared integration fixture; bench measures only its continuation"
)]
#[path = "../../bingsu-core/tests/collection_front.rs"]
mod front_fixture;
#[library_benchmark]
#[bench::absent(args=[0], setup=front_fixture::bench_case)]
#[bench::current(args=[1], setup=front_fixture::bench_case)]
#[bench::previous(args=[2], setup=front_fixture::bench_case)]
#[bench::maximum(args=[3], setup=front_fixture::bench_case)]
#[bench::width_change(args=[4], setup=front_fixture::bench_case)]
fn front_collection(mut fixture: front_fixture::Harness) -> (front_fixture::Harness, Vec<u8>) {
    let record = black_box(fixture.run().record);
    (fixture, record)
}
// Product policy remains empty even when a compiled display requests builtins.
// Keep selection cost separate from the test-catalog completed-file continuation.
#[library_benchmark]
#[bench::bands4096(setup=selected_config)]
fn product_mask_zero(c: CompiledConfig) -> (CompiledConfig, u32) {
    let mask = black_box(selection::PRODUCT.worker_mask(black_box(&c), 65535, false));
    assert_eq!(mask, 0);
    (c, mask)
}
library_benchmark_group!(
    name = collection,
    benchmarks = [
        request_encode,
        request_decode,
        response_encode,
        response_decode,
        binding_compare,
        cwd_sha256,
        rejected_prefix,
        selected_variant,
        front_collection,
        product_mask_zero
    ]
);
main!(library_benchmark_groups = collection);
