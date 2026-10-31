//! Forged integers in the band index, with checksums resealed. These reach the
//! decoders only through a write the user made; they must still stay in bounds
//! and change nothing the front uses. Also run on wasm32-wasip1: every range
//! here is computed from u32 values, where a 32-bit usize would wrap first.
#[path = "support/sections.rs"]
mod sections;
use bingsu_core::{
    bands::Band,
    config::compile::CompiledConfig,
    snapshot::{READ_CHUNK, Snapshot, crc32c},
    snapshot_codec::Error,
};
use bingsu_core_tests::snapshot_fixture as fixture;
use sections::{P, Sections, le32, put32, reframe, resign};

const ROUNDS: u64 = if cfg!(debug_assertions) {
    20_000
} else {
    300_000
};

fn banded(n: usize) -> CompiledConfig {
    let a = fixture::compile("").variants[0].clone();
    let mut c = fixture::compile("");
    c.bands = (0..n)
        .map(|i| Band {
            min_cols: Some(i as u16),
            max_cols: Some(10000),
            order: None,
        })
        .collect();
    c.band_names = (0..n).map(|i| format!("b{i}")).collect();
    c.band_order = (0..n).rev().collect();
    c.variants = vec![a; n + 1];
    c.widths.clear();
    c
}

fn wire(n: usize) -> Vec<u8> {
    let mut s = fixture::frame();
    s.config = banded(n);
    s.encode(1, 0).unwrap()
}

fn front(b: &[u8], width: u16) -> Result<(bingsu_core::layout_view::FrontConfig, usize), Error> {
    fixture::front_read(b, width, READ_CHUNK).map(|(s, read)| (s.config, read))
}

// 이것을 실패시키는 것: 색인 연속성 조건(`e.offset != end`)을 빼는 것(읽기가 metadata로 넘거나 슬라이스가
// panic한다), `checked_add`를 감기는 덧셈으로 바꿔 32비트에서 범위가 감기는 것, 정확한 경계 비교를 빼는 것.
#[test]
fn forged_integers_never_panic_or_overrun() {
    let base = wire(8);
    let c_len = le32(&base, 76);
    let s = Sections::of(&base[P..P + c_len]);
    let index = P + s.index;
    let front_len = s.front;
    let pick = |v: usize, r: u64| -> usize {
        let list = [
            0,
            1,
            15,
            16,
            19,
            20,
            0x7fff_ffff,
            0x8000_0000,
            0xffff_ffff,
            0xffff_fff0,
            c_len,
            c_len - 1,
            c_len + 1,
            16 << 20,
            (16 << 20) + 1,
            base.len(),
            v + 1,
            v.wrapping_sub(1),
            v + 16,
            v.wrapping_sub(16),
        ];
        list[(r % list.len() as u64) as usize]
    };
    let mut x = 0x9e37_79b9_7f4a_7c15u64;
    let mut rnd = move || {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x
    };
    let widths: Vec<_> = (0..12).map(|w| front(&base, w).unwrap().0).collect();
    let (mut accepted, mut refused) = (0u64, 0u64);
    for _ in 0..ROUNDS {
        let mut b = base.clone();
        for _ in 0..1 + rnd() % 3 {
            let at = match rnd() % 5 {
                0 => P + 12,
                1 => P + 16,
                2 => index + (rnd() % 9) as usize * 16,
                3 => index + (rnd() % 9) as usize * 16 + 4,
                _ => index + (rnd() % 9) as usize * 16 + 12,
            };
            let v = le32(&b, at);
            put32(&mut b, at, pick(v, rnd()));
        }
        if rnd() % 2 == 0 {
            resign(&mut b, front_len);
        } else {
            // Over the original front length, whatever the forged fields say.
            let sum = crc32c(&[b"bingsu-snapshot-v3\0", &b[..160], &b[P..P + front_len]]);
            b[160..164].copy_from_slice(&sum);
        }
        let width = (rnd() % 12) as u16;
        match front(&b, width) {
            Ok((config, read)) => {
                assert!(read <= P + c_len, "read {read}");
                assert!(config == widths[usize::from(width)], "forged front result");
                accepted += 1;
            }
            Err(_) => refused += 1,
        }
        let helper = Snapshot::decode(&b);
        assert!(
            helper.is_err() || b == base,
            "forged file passed the helper"
        );
    }
    assert!(accepted > 0 && refused > accepted, "{accepted} {refused}");
}

// 이것을 실패시키는 것: 색인 연속성 조건을 빼는 것(겹침·빈틈이 받아지고 넘는 오프셋은 슬라이스 panic).
#[test]
fn shifted_boundaries_with_good_checksums_are_refused() {
    let base = wire(2);
    let c_len = le32(&base, 76);
    let s = Sections::of(&base[P..P + c_len]);
    let index = P + s.index;
    let cases: [(&str, fn(&mut Vec<u8>, usize)); 5] = [
        ("overlap", |b, i| {
            let v = le32(b, i + 16);
            put32(b, i + 16, v - 1)
        }),
        ("gap", |b, i| {
            let v = le32(b, i + 16);
            put32(b, i + 16, v + 1)
        }),
        ("past end", |b, i| put32(b, i + 32 + 4, 1 << 24)),
        ("len wraps", |b, i| put32(b, i + 32 + 4, 0xffff_ffff)),
        ("offset wraps", |b, i| put32(b, i + 32, 0xffff_fff0)),
    ];
    for (name, forge) in cases {
        let mut b = base.clone();
        forge(&mut b, index);
        resign(&mut b, s.front);
        for width in [0, 1, 2, 3, 120] {
            assert_eq!(front(&b, width).err(), Some(Error::Shape), "{name} {width}");
        }
        assert_eq!(Snapshot::decode(&b).err(), Some(Error::Shape), "{name}");
    }
}

// 이것을 실패시키는 것: 경계 비교를 `end > c_len`으로 되돌리는 것(변종과 이름 사이, 이름 뒤의 남는 바이트를
// 앞단이 받는 것).
#[test]
fn a_spare_byte_around_the_names_is_refused_by_the_front() {
    let base = wire(4);
    let c_len = le32(&base, 76);
    let c = &base[P..P + c_len];
    let s = Sections::of(c);
    for at in [s.names, c_len] {
        let mut forged = c[..at].to_vec();
        forged.push(0);
        forged.extend(&c[at..]);
        let b = reframe(&base, &forged);
        for width in [0, 2, 120] {
            assert_eq!(front(&b, width).err(), Some(Error::Shape), "{at} {width}");
        }
        assert!(Snapshot::decode(&b).is_err(), "{at}");
    }
}
