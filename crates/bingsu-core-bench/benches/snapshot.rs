//! Codec/CRC costs, separate from source parsing and template compilation.
use bingsu_core::{
    bands::{Band, MAX_BANDS},
    config::compile::CompiledConfig,
    snapshot::{Clock, Identity, Marker, Refusal, crc32c, eligible},
    snapshot_codec::{Error, decode_compiled, encode_compiled},
};
use gungraun::prelude::*;
use std::hint::black_box;
#[path = "../../bingsu-core-tests/src/snapshot_fixture.rs"]
#[allow(
    dead_code,
    reason = "shared native/wasm fixture; this bench measures the codec"
)]
mod fixture;
fn compiled() -> CompiledConfig {
    fixture::config()
}
fn encoded() -> Vec<u8> {
    encode_compiled(&compiled()).unwrap()
}
#[inline(never)]
fn encode(c: &CompiledConfig) -> Result<Vec<u8>, Error> {
    encode_compiled(c)
}
#[inline(never)]
fn decode(b: &[u8]) -> Result<CompiledConfig, Error> {
    decode_compiled(b)
}
#[inline(never)]
fn crc(b: &[u8]) -> [u8; 4] {
    crc32c(&[b])
}
#[library_benchmark]
#[bench::fixture(setup = compiled)]
fn snapshot_encode(c: CompiledConfig) -> (CompiledConfig, Vec<u8>) {
    let b = black_box(encode(black_box(&c))).unwrap();
    (c, b)
}
#[library_benchmark]
#[bench::fixture(setup = encoded)]
fn snapshot_decode(b: Vec<u8>) -> (Vec<u8>, CompiledConfig) {
    let c = black_box(decode(black_box(&b))).unwrap();
    (b, c)
}
fn payload(n: usize) -> Vec<u8> {
    vec![42; n]
}
#[library_benchmark]
#[bench::kib4(args = [4096], setup = payload)]
#[bench::mib16(args = [16*1024*1024], setup = payload)]
fn snapshot_crc(b: Vec<u8>) -> (Vec<u8>, [u8; 4]) {
    let sum = black_box(crc(black_box(&b)));
    (b, sum)
}
fn eligibility_case() -> (Identity, Marker, Clock) {
    let id = Identity {
        boot: [1; 16],
        epoch: [2; 16],
        context: [3; 4],
        generation: 7,
        source: [4; 4],
    };
    let marker = Marker {
        id,
        seq: 9,
        verified_at: 100,
        kind: 1,
        domain: [5; 16],
        resume: 0,
        invalid: false,
    };
    let clock = Clock {
        boot: id.boot,
        domain: marker.domain,
        kind: 1,
        resume: 0,
        now: 101,
    };
    (id, marker, clock)
}
#[inline(never)]
fn eligibility(input: (Identity, Marker, Clock)) -> Result<u64, Refusal> {
    eligible(input.0, Some(input.1), input.2, input.0.context)
}
// N7 keeps eligibility separate from codec and the existing render bench.
#[library_benchmark]
#[bench::fresh(setup = eligibility_case)]
fn snapshot_eligibility(input: (Identity, Marker, Clock)) -> Result<u64, Refusal> {
    black_box(eligibility(black_box(input)))
}
// Baseline for the front's whole-config decode: the ordinary config and the
// 4,096-band ceiling. The selected-band decode is measured against these.
fn encoded_normal() -> Vec<u8> {
    encoded()
}
fn encoded_4096_bands() -> Vec<u8> {
    // The built-in theme's variant is small enough that 4,097 copies stay
    // under the codec's 16 MiB cap, as the selected-variant bench does.
    let mut c = fixture::compile("");
    c.bands = (0..MAX_BANDS)
        .map(|i| Band {
            min_cols: Some(i as u16 * 16),
            max_cols: Some(i as u16 * 16 + 15),
            order: None,
        })
        .collect();
    c.band_names = (0..MAX_BANDS).map(|i| format!("b{i}")).collect();
    // The built-in widths name the band that was just replaced.
    c.widths.clear();
    c.band_order = (0..MAX_BANDS).collect();
    c.variants = vec![c.variants[0].clone(); MAX_BANDS + 1];
    let b = encode_compiled(&c).unwrap();
    assert_eq!(decode_compiled(&b).unwrap().bands.len(), MAX_BANDS);
    b
}
#[library_benchmark]
#[bench::normal(setup = encoded_normal)]
fn front_decode_normal(b: Vec<u8>) -> (Vec<u8>, CompiledConfig) {
    let c = black_box(decode(black_box(&b))).unwrap();
    assert!(c.bands.len() < 8);
    (b, c)
}
#[library_benchmark]
#[bench::bands4096(setup = encoded_4096_bands)]
fn front_decode_4096_bands(b: Vec<u8>) -> (Vec<u8>, CompiledConfig) {
    let c = black_box(decode(black_box(&b))).unwrap();
    assert_eq!(c.bands.len(), MAX_BANDS);
    (b, c)
}
library_benchmark_group!(
    name = snapshot,
    benchmarks = [
        snapshot_encode,
        snapshot_decode,
        snapshot_crc,
        snapshot_eligibility,
        front_decode_normal,
        front_decode_4096_bands
    ]
);
main!(library_benchmark_groups = snapshot);
