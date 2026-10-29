//! K63: the prompt front materializes only the variant its width selects.
//! The selected path must draw, collect and reject exactly as the whole
//! decode does, and allocate nothing for the variants it did not select.
#[path = "support/allocation.rs"]
mod allocation;
use allocation::{Counting, counted};

use bingsu_core::{
    bands::{Band, order_bands},
    collection::selection,
    color::palette::Mode,
    config::compile::CompiledConfig,
    envelope,
    field::BUILTIN,
    front,
    layout_view::{FrontConfig, LayoutView},
    snapshot::{Identity, Snapshot, encode_metadata},
    snapshot_codec::{Error, decode_compiled, encode_compiled, scan_compiled},
    status::Status,
    template::compile::compile,
};
use bingsu_core_tests::snapshot_fixture as fixture;
use proptest::prelude::*;

#[global_allocator]
static GLOBAL: Counting = Counting;

const TEMPLATES: [&str; 6] = [
    "{dir} {git} {char}",
    "{dir}{char}",
    "x {char}",
    "{@style:bold}{dir}{@end} {@fill} {git}",
    "{@group}[{git}]{@end}{dir} {char}",
    "a long fixed text that overflows a narrow width {dir} {char}",
];

/// `bands` with variant `i + 1` drawn from `templates[i]`, the default from
/// `default`. None when the bands do not order (the compiler would refuse).
fn banded(bands: &[Band], default: usize, templates: &[usize]) -> Option<CompiledConfig> {
    let mut c = fixture::compile("");
    c.band_order = order_bands(bands).ok()?;
    c.bands = bands.to_vec();
    c.band_names = (0..bands.len()).map(|i| format!("b{i}")).collect();
    c.widths.clear();
    c.variants = core::iter::once(default)
        .chain(templates.iter().copied())
        .map(|t| compile(TEMPLATES[t], BUILTIN).unwrap())
        .collect();
    Some(c)
}

fn band() -> impl Strategy<Value = Band> {
    (
        prop::option::of(0u16..200),
        prop::option::of(0u16..200),
        prop::option::of(-3i32..3),
    )
        .prop_map(|(a, b, order)| {
            let (min_cols, max_cols) = match (a, b) {
                (Some(a), Some(b)) => (Some(a.min(b)), Some(a.max(b))),
                other => other,
            };
            Band {
                min_cols,
                max_cols,
                order,
            }
        })
}

fn envelope_args(width: u16, shell: &str, redraw: bool) -> Vec<Vec<u8>> {
    let mut a: Vec<Vec<u8>> = [
        "--ctx",
        "1",
        "--record",
        "B1",
        "--width",
        &width.to_string(),
        "--runtime-root=1:2:/r",
        "--home=/home/u",
        "--shell",
        shell,
        "--pwd",
        "/home/u/proj/src",
        "--status",
        "1",
    ]
    .iter()
    .map(|s| s.as_bytes().to_vec())
    .collect();
    if redraw {
        a.push(b"--redraw".to_vec());
    }
    a
}

fn record<L: LayoutView>(config: &L, args: &[Vec<u8>], status: Status, mode: Mode) -> Vec<u8> {
    let argv: Vec<&[u8]> = args.iter().map(Vec::as_slice).collect();
    let e = envelope::parse(&argv).unwrap();
    let mut out = Vec::new();
    front::render_selected(
        &e,
        e.shell.unwrap(),
        status,
        Some(config),
        mode,
        None,
        &mut out,
    );
    out
}

/// The front's decode of `c` at `width`, through the snapshot frame.
fn front_decode(c: &CompiledConfig, width: u16) -> FrontConfig {
    let s = Snapshot {
        id: Identity {
            boot: [1; 16],
            epoch: [2; 16],
            context: [3; 4],
            generation: 7,
            source: [4; 4],
        },
        config: c.clone(),
        metadata: encode_metadata(b"m").unwrap(),
    };
    let b = s.encode(1, 0).unwrap();
    let end = b.len() - s.metadata.len();
    Snapshot::decode_front(&b[..end], b.len(), width)
        .unwrap()
        .config
}

fn widths(c: &CompiledConfig) -> Vec<u16> {
    let mut w = vec![0, 1, 40, 80, 99, 100, 120, 199, 200, u16::MAX];
    for b in &c.bands {
        for x in [b.min_cols, b.max_cols].into_iter().flatten() {
            w.extend([x.saturating_sub(1), x, x.saturating_add(1)]);
        }
    }
    w
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 96, ..ProptestConfig::default() })]

    // 이것을 실패시키는 것: 선택 경로가 다른 variant를 고르는 것(`band + 1` 대신 `band`, 기본 variant로의
    // fallback 생략), 렌더가 envelope 폭이 아닌 폭으로 고르는 것, FrontConfig가 팔레트·아이콘·폭 설정·
    // transient·vi 중 하나를 빠뜨리거나 바꾸는 것.
    #[test]
    fn front_record_matches_full_decode(
        bands in prop::collection::vec(band(), 0..6),
        default in 0..TEMPLATES.len(),
        templates in prop::collection::vec(0..TEMPLATES.len(), 6),
        shell in prop::sample::select(vec!["zsh", "bash", "fish"]),
        redraw in any::<bool>(),
        light in any::<bool>(),
        warn in any::<bool>(),
    ) {
        let Some(c) = banded(&bands, default, &templates[..bands.len()]) else {
            return Err(TestCaseError::reject("bands do not order"));
        };
        let full = decode_compiled(&encode_compiled(&c).unwrap()).unwrap();
        let mode = if light { Mode::Light } else { Mode::Dark };
        let status = if warn { Status::DEGRADED_TRUST_UNVERIFIED } else { Status::OK_NONE };
        for width in widths(&c) {
            let args = envelope_args(width, shell, redraw);
            let selected = front_decode(&c, width);
            prop_assert_eq!(&selected, &FrontConfig::from_compiled(full.clone(), width));
            prop_assert_eq!(
                record(&selected, &args, status, mode),
                record(&full, &args, status, mode),
                "width {}", width
            );
        }
    }

    // 이것을 실패시키는 것: worker mask나 path query를 선택하지 않은 variant로 계산하는 것, FrontConfig의
    // collect_mask·setup을 바꾸는 것, redraw의 0을 잃는 것.
    #[test]
    fn worker_mask_matches_full_decode(
        bands in prop::collection::vec(band(), 0..6),
        default in 0..TEMPLATES.len(),
        templates in prop::collection::vec(0..TEMPLATES.len(), 6),
        redraw in any::<bool>(),
        unique in any::<bool>(),
    ) {
        let Some(mut c) = banded(&bands, default, &templates[..bands.len()]) else {
            return Err(TestCaseError::reject("bands do not order"));
        };
        if unique {
            c.setup[1].methods = vec![bingsu_core::shorten::Method::Unique];
        }
        let full = decode_compiled(&encode_compiled(&c).unwrap()).unwrap();
        for width in widths(&c) {
            let selected = front_decode(&c, width);
            prop_assert_eq!(
                selection::worker_mask(&selected, width, redraw),
                selection::worker_mask(&full, width, redraw)
            );
            prop_assert_eq!(
                selection::builtin_mask(&selected, width),
                selection::builtin_mask(&full, width)
            );
            prop_assert_eq!(
                selection::path_query(&selected, width, b"/home/u/a/b", Some(b"/home/u")),
                selection::path_query(&full, width, b"/home/u/a/b", Some(b"/home/u"))
            );
        }
    }
}

// 이것을 실패시키는 것: FrontConfig가 선택한 폭이 아닌 폭에서 자기 variant를 그리거나 수집하는 것
// (`lines_at`의 band 비교 생략).
#[test]
fn a_front_config_draws_nothing_at_a_width_it_was_not_selected_for() {
    let c = fixture::config();
    let wide = FrontConfig::from_compiled(c.clone(), 120);
    assert!(wide.band().is_some() && c.lines_at(80) != c.lines_at(120));
    assert_eq!(wide.lines_at(120), c.lines_at(120));
    assert_eq!(wide.lines_at(80), None);
    assert_eq!(selection::builtin_mask(&wide, 80), 0);
    let args = envelope_args(80, "zsh", false);
    let empty = record(&wide, &args, Status::OK_NONE, Mode::Dark);
    assert_ne!(empty, record(&c, &args, Status::OK_NONE, Mode::Dark));
}

/// `compile("x")`: one Text node, origin 0..1, no fill (23 bytes on the wire).
const X_LINE: [u8; 23] = [
    1, 0, 0, 0, 0, 1, 0, 0, 0, b'x', 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0,
];

fn u32le(n: usize) -> [u8; 4] {
    (n as u32).to_le_bytes()
}

/// A variant of `lines` hand-written lines.
fn variant(lines: &[&[u8]]) -> Vec<u8> {
    let mut v = u32le(lines.len()).to_vec();
    for l in lines {
        v.extend_from_slice(l);
    }
    v
}

/// Header and every field after the variants, from a real one-band config
/// whose two variants are `X_LINE`. The asserts pin the layout used here.
fn frame() -> (Vec<u8>, Vec<u8>) {
    let mut c = fixture::compile("");
    c.bands = vec![Band {
        min_cols: Some(100),
        max_cols: None,
        order: None,
    }];
    c.band_names = vec!["wide".into()];
    c.band_order = vec![0];
    c.widths.clear();
    c.variants = vec![compile("x", BUILTIN).unwrap(); 2];
    let b = encode_compiled(&c).unwrap();
    let head = b[..12].to_vec();
    assert_eq!(&head[..8], b"BNGCFG03");
    let x = variant(&[&X_LINE]);
    assert_eq!(b[12..16], u32le(2));
    assert_eq!(b[16..16 + x.len()], x[..]);
    assert_eq!(b[16 + x.len()..16 + 2 * x.len()], x[..]);
    let rest = b[16 + 2 * x.len()..].to_vec();
    // One band (100.., no order), then the names: one, "wide".
    assert_eq!(
        rest[..21],
        [
            1, 0, 0, 0, 1, 100, 0, 0, 0, 1, 0, 0, 0, 4, 0, 0, 0, b'w', b'i', b'd', b'e'
        ]
    );
    (head, rest)
}

/// `config_bytes` of two `X_LINE` variants with `n` band names "a".
fn with_names(n: usize) -> Vec<u8> {
    let (head, rest) = frame();
    let x = variant(&[&X_LINE]);
    let mut b = head;
    b.extend(u32le(2));
    b.extend(&x);
    b.extend(&x);
    b.extend(&rest[..9]);
    b.extend(u32le(n));
    for _ in 0..n {
        b.extend([1, 0, 0, 0, b'a']);
    }
    b.extend(&rest[21..]);
    b
}

fn config_bytes(variants: &[Vec<u8>]) -> Vec<u8> {
    let (head, rest) = frame();
    let mut b = head;
    b.extend(u32le(variants.len()));
    for v in variants {
        b.extend(v);
    }
    b.extend(rest);
    b
}

fn same_verdict(bytes: &[u8], what: &str) -> Result<(), Error> {
    let full = decode_compiled(bytes).map(drop);
    let scan = scan_compiled(bytes).map(drop);
    assert_eq!(scan, full, "{what}");
    full
}

/// A line with `n` nodes of tag `tag` and nothing after them.
fn nodes(n: usize, tag: u8) -> Vec<u8> {
    let mut l = u32le(n).to_vec();
    l.resize(4 + n, tag);
    l
}

// 이것을 실패시키는 것: scan이 선택하지 않을 variant의 길이 검사·할당 예산 charge·줄 검사(N1)·UTF-8
// 검사·줄 수 검사를 건너뛰는 것, Trailing·머리 검사를 빠뜨리는 것, 오류 종류를 바꾸는 것.
#[test]
fn scan_rejects_exactly_what_full_decode_rejects() {
    let x = variant(&[&X_LINE]);
    assert_eq!(
        same_verdict(&config_bytes(&[x.clone(), x.clone()]), "valid"),
        Ok(())
    );
    // The unselected variant (index 1 at width 80) carries each fault.
    let mut control = X_LINE;
    control[9] = 0x07;
    let mut utf8 = X_LINE;
    utf8[9] = 0xff;
    let mut overlong = X_LINE;
    overlong[5] = 2;
    let group = {
        // Group{len: 2}, Text "x", GroupEnd: a group without a reference.
        let mut l = u32le(3).to_vec();
        l.extend([10, 2, 0, 0, 0]);
        l.extend(&X_LINE[4..10]);
        l.push(11);
        l.extend(u32le(3));
        l.extend([0; 24]);
        l.push(0);
        l
    };
    let cases: Vec<(Vec<u8>, Error)> = vec![
        (variant(&[]), Error::Shape),
        (variant(&[&X_LINE, &X_LINE, &X_LINE]), Error::Shape),
        (variant(&[&control]), Error::Shape),
        (variant(&[&utf8]), Error::Utf8),
        (variant(&[&group]), Error::Shape),
        (variant(&[&overlong]), Error::Shape),
        // 3M StyleEnd nodes: 3 MB of wire, past the 64 MiB charge for nodes.
        (variant(&[&nodes(3_000_000, 9)]), Error::Limit),
        // A node count past the bytes left.
        (variant(&[&u32le(1 << 30)]), Error::Limit),
        (variant(&[&nodes(3, 12)]), Error::Tag),
    ];
    for (i, (bad, error)) in cases.into_iter().enumerate() {
        let what = format!("case {i}");
        assert_eq!(
            same_verdict(&config_bytes(&[x.clone(), bad]), &what),
            Err(error),
            "{what}"
        );
    }
    // More variants than bands + 1, and past the 4,097 offsets the scan keeps.
    assert_eq!(
        same_verdict(&config_bytes(&vec![x.clone(); 3]), "3 variants"),
        Err(Error::Shape)
    );
    assert_eq!(
        same_verdict(&config_bytes(&vec![x.clone(); 5000]), "5000 variants"),
        Err(Error::Shape)
    );
    assert_eq!(
        same_verdict(&with_names(2), "two names, one band"),
        Err(Error::Shape)
    );
    assert_eq!(
        same_verdict(&with_names(5000), "5000 names"),
        Err(Error::Shape)
    );
    // 3M variants: 3 MB of wire, past the 64 MiB charge for the variant table.
    let (head, _) = frame();
    let mut table = head;
    table.extend(u32le(3_000_000));
    table.resize(table.len() + 3_000_000, 0);
    assert_eq!(same_verdict(&table, "variant table"), Err(Error::Limit));
    // Past the 16 MiB section cap, before any read.
    let mut big = config_bytes(&[x.clone(), x.clone()]);
    big.resize(16 * 1024 * 1024 + 1, 0);
    assert_eq!(same_verdict(&big, "size cap"), Err(Error::Limit));
    let mut trailing = config_bytes(&[x.clone(), x.clone()]);
    trailing.push(0);
    assert_eq!(same_verdict(&trailing, "trailing"), Err(Error::Trailing));

    // Every truncation and one bit flip per byte of real configs.
    let mut wide = banded(
        &(0..16)
            .map(|i| Band {
                min_cols: Some(i * 10),
                max_cols: Some(i * 10 + 9),
                order: None,
            })
            .collect::<Vec<_>>(),
        0,
        &[1, 2, 3, 4, 5, 0, 1, 2, 3, 4, 5, 0, 1, 2, 3, 4],
    )
    .unwrap();
    wide.exec_units = fixture::config().exec_units;
    for u in &mut wide.exec_units {
        for r in u.approved_by.iter_mut().chain(&mut u.shown_at) {
            if r.band.is_some() {
                r.band = Some("b3".into());
            }
        }
    }
    for c in [fixture::config(), wide] {
        let b = encode_compiled(&c).unwrap();
        for end in 0..b.len() {
            assert!(same_verdict(&b[..end], &format!("cut {end}")).is_err());
        }
        for at in 0..b.len() {
            for bit in [0x01, 0x80] {
                let mut x = b.clone();
                x[at] ^= bit;
                let _ = same_verdict(&x, &format!("flip {at} {bit:#x}"));
            }
        }
    }
}

// 이것을 실패시키는 것: select가 모든 variant를 materialize한 뒤 고른 것만 남기는 것, scan이 variant·
// band 이름을 복사하는 것, 남기는 offset·이름 수의 상한을 없애는 것(4,097을 넘는 variant 수에서 재할당).
#[test]
fn selected_band_allocates_only_selected_variant() {
    let bands = |n: u16| -> Vec<Band> {
        (0..n)
            .map(|i| Band {
                min_cols: Some(i * 10),
                max_cols: Some(i * 10 + 9),
                order: None,
            })
            .collect()
    };
    // Every unselected variant has Text nodes; the selected one (band 1,
    // width 15) is the same template in both configs.
    let config = |n: u16| {
        let t: Vec<usize> = (0..n).map(|i| if i == 1 { 0 } else { 5 }).collect();
        encode_compiled(&banded(&bands(n), 5, &t).unwrap()).unwrap()
    };
    let (small, large) = (config(2), config(64));
    let front = |b: &[u8]| {
        let mut out = None;
        let counts = counted(|| out = Some(scan_compiled(b).unwrap().select(15).unwrap()));
        assert_eq!(out.unwrap().band(), Some(1));
        counts
    };
    let full = |b: &[u8]| counted(|| drop(decode_compiled(b).unwrap()));
    let (fs, fl) = (front(&small), front(&large));
    let (ds, dl) = (full(&small), full(&large));
    // The whole decode allocates at least three times per unselected variant
    // (lines, nodes, spans). What the front adds per band is the name
    // uniqueness set (one node per several names, as in the whole decode).
    assert!(dl.0 > ds.0 + 62 * 3, "full {ds:?} {dl:?}");
    assert!(fl.0 <= fs.0 + 62 / 4, "front {fs:?} {fl:?}");
    assert_eq!((fs.1, fl.1), (0, 0));
    // Per band: the band, its order entry, its offset, its name reference and
    // its share of the set, not a variant.
    assert!(fl.2 <= fs.2 + 62 * 128, "front peak {fs:?} {fl:?}");

    // Past the kept offsets and names the scan still reads, never grows.
    let x = variant(&[&X_LINE]);
    let many = config_bytes(&vec![x; 5000]);
    let (_, reallocs, peak) = counted(|| assert!(scan_compiled(&many).is_err()));
    assert_eq!(reallocs, 0);
    assert!(peak < 64 * 1024, "{peak}");
    assert!(scan_compiled(&with_names(1)).is_ok());
    let names = with_names(5000);
    let (_, reallocs, peak) = counted(|| assert!(scan_compiled(&names).is_err()));
    assert_eq!(reallocs, 0);
    assert!(peak < 128 * 1024, "{peak}");
}
