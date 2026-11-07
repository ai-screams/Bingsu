//! K63: the prompt front materializes only the variant its width selects.
//! The selected path must draw and collect as the whole decode does, accept
//! whatever the whole decode accepts, and allocate nothing for the variants it
//! did not select. The whole decode alone sees the rest of the file.
#[path = "support/allocation.rs"]
mod allocation;
#[path = "support/sections.rs"]
mod sections;
use allocation::{Counting, counted};
use sections::{P, Sections, assemble, names_block, reframe};

use bingsu_core::{
    bands::{Band, order_bands},
    collection::selection,
    color::palette::Mode,
    config::compile::CompiledConfig,
    diag_widths::WidthRun,
    envelope,
    field::BUILTIN,
    front,
    layout_view::{FrontConfig, LayoutView},
    snapshot::{FrontDecoder, Identity, READ_CHUNK, Snapshot, encode_metadata},
    snapshot_codec::{Error, HEAD, decode_compiled, encode_compiled},
    status::Status,
    template::compile::{compile, compile_with},
};
use bingsu_core_tests::snapshot_fixture as fixture;
use proptest::prelude::*;

#[global_allocator]
static GLOBAL: Counting = Counting;

const TEMPLATES: [&str; 9] = [
    "{dir} {git} {char}",
    "{dir}{char}",
    "x {char}",
    "{@style:bold}{dir}{@end} {@fill} {git}",
    "{@group}[{git}]{@end}{dir} {char}",
    "a long fixed text that overflows a narrow width {dir} {char}",
    // A user language that may run: drawn as a segment, as a field only,
    // and beside git (the dir bit then comes from the language alone).
    "{custom/deno} {char}",
    "{custom/deno.value}{char}",
    "{git} {custom/deno} {char}",
];

/// The user language the templates above name, drawn by a trusted layout
/// so its unit may run.
const LANGUAGE: &str = "[segment.\"custom/deno\"]\nkind = \"language\"\n\
    detect_files = [\"deno.json\"]\ninterpreter = \"/bin/deno\"\n\
    [layout.line2]\nleft = [\"custom/deno\", \"char\"]\n";

/// `bands` with variant `i + 1` drawn from `templates[i]`, the default from
/// `default`. None when the bands do not order (the compiler would refuse).
fn banded(bands: &[Band], default: usize, templates: &[usize]) -> Option<CompiledConfig> {
    let mut c = fixture::compile(LANGUAGE);
    c.band_order = order_bands(bands).ok()?;
    c.bands = bands.to_vec();
    c.band_names = (0..bands.len()).map(|i| format!("b{i}")).collect();
    c.widths.clear();
    c.variants = core::iter::once(default)
        .chain(templates.iter().copied())
        .map(|t| compile_with(TEMPLATES[t], BUILTIN, &["custom/deno"]).unwrap())
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
    let b = wire(c);
    let end = b.len() - META;
    Snapshot::decode_front(&b[..end], b.len(), width)
        .unwrap()
        .config
}

/// Length of `encode_metadata(b"m")`.
const META: usize = 21;

fn wire(c: &CompiledConfig) -> Vec<u8> {
    let metadata = encode_metadata(b"m").unwrap();
    assert_eq!(metadata.len(), META);
    Snapshot {
        id: Identity {
            boot: [1; 16],
            epoch: [2; 16],
            context: [3; 4],
            generation: 7,
            source: [4; 4],
        },
        config: c.clone(),
        metadata,
    }
    .encode(1, 0)
    .unwrap()
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
    // collect_mask·setup을 바꾸는 것, redraw의 0을 잃는 것, 앞단 decode가 사용자 segment 목록이나 실행 단위(그
    // `not_run`)를 잃어 사용자 language의 dir 비트가 수집 요청과 달라지는 것.
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

// 이것을 실패시키는 것: 공용 view가 segment setup의 우선순위·필수·단축 방법·조건을 바꾸거나 빠뜨리는 것,
// dark/light 팔레트를 바꿔 쥐는 것, transient·vi를 다른 줄로 잡는 것(두 view가 같은 코드를 지나
// 비교 시험으로는 보이지 않는 결함).
#[test]
fn shared_view_carries_the_stored_setup_and_palettes() {
    let mut c = fixture::config();
    c.transient = compile("{dir} ", BUILTIN).unwrap().remove(0);
    assert_ne!(c.transient, c.vi);
    let f = FrontConfig::from_compiled(c.clone(), 120);
    for view in [c.shared(), f.shared()] {
        let setup = view.segment_setup();
        assert_eq!(setup.len(), c.setup.len());
        for (got, want) in setup.iter().zip(&c.setup) {
            assert_eq!(
                (got.priority, got.required, got.methods, got.when),
                (want.priority, want.required, &want.methods[..], want.when)
            );
        }
        assert!(
            c.setup.iter().any(|s| s.required) && c.setup.iter().any(|s| !s.methods.is_empty())
        );
        let lines = c.lines_at(120);
        for (mode, palette) in [(Mode::Dark, &c.palette), (Mode::Light, &c.light_palette)] {
            let t = view.theme(lines, mode);
            assert_eq!(t.palette, palette);
            assert_eq!((t.transient, t.vi), (&c.transient, &c.vi));
        }
    }
    assert_ne!(c.palette, c.light_palette);
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

/// A real one-band config (band "wide", 100 and up) whose two variants are
/// `X_LINE`, and its compiled section. The asserts pin the layout used here.
fn one_band() -> (Vec<u8>, Vec<u8>) {
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
    assert_eq!(&b[..8], b"BNGCFG12");
    let s = Sections::of(&b);
    let x = variant(&[&X_LINE]);
    assert_eq!(
        (s.count, s.variant(&b, 0), s.variant(&b, 1)),
        (2, &x[..], &x[..])
    );
    (wire(&c), b)
}

/// The one-band file with its variants and names replaced.
fn file(variants: &[Vec<u8>], names: &[u8]) -> Vec<u8> {
    let (wire, c) = one_band();
    let s = Sections::of(&c);
    reframe(&wire, &assemble(&c, &c[HEAD..s.index], variants, names))
}

fn whole(wire: &[u8]) -> Result<(), Error> {
    Snapshot::decode(wire).map(drop)
}

fn front(wire: &[u8], width: u16) -> Result<FrontConfig, Error> {
    fixture::front_read(wire, width, READ_CHUNK).map(|(s, _)| s.config)
}

/// The direction the front's smaller check set has to keep: whatever the whole
/// decode accepts, the front accepts at `width` through every read size, and
/// gives what the whole config selects there.
fn implies_front(wire: &[u8], width: u16) {
    let Ok(s) = Snapshot::decode(wire) else {
        return;
    };
    let want = FrontConfig::from_compiled(s.config, width);
    for chunk in [1, 13, 4097, READ_CHUNK] {
        // One-byte reads are only worth their cost on small files.
        if chunk > 1 || wire.len() < 8 * 1024 {
            let (got, _) = fixture::front_read(wire, width, chunk)
                .unwrap_or_else(|e| panic!("width {width} chunk {chunk}: {e:?}"));
            assert_eq!(got.config, want, "width {width} chunk {chunk}");
        }
    }
}

/// A line with `n` nodes of tag `tag` and nothing after them.
fn nodes(n: usize, tag: u8) -> Vec<u8> {
    let mut l = u32le(n).to_vec();
    l.resize(4 + n, tag);
    l
}

/// Faults a variant can carry, with the error decoding it gives.
fn variant_faults() -> Vec<(Vec<u8>, Error)> {
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
    let mut trailing = variant(&[&X_LINE]);
    trailing.push(0);
    vec![
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
        (trailing, Error::Trailing),
    ]
}

// 이것을 실패시키는 것: 고른 variant의 줄 수·Trailing 검사를 빼는 것.
#[test]
fn a_fault_reaches_the_front_only_in_the_selected_variant() {
    let x = variant(&[&X_LINE]);
    let name = names_block(&["wide"]);
    assert_eq!(whole(&file(&[x.clone(), x.clone()], &name)), Ok(()));
    for (i, (bad, error)) in variant_faults().into_iter().enumerate() {
        // Width 80 selects the default variant, 120 the band's.
        for (faulty, clean, variants) in [
            (120, 80, [x.clone(), bad.clone()]),
            (80, 120, [bad.clone(), x.clone()]),
        ] {
            let b = file(&variants, &name);
            assert_eq!(whole(&b), Err(error), "case {i}");
            assert_eq!(front(&b, faulty), Err(error), "case {i} selected");
            assert!(front(&b, clean).is_ok(), "case {i} unselected");
        }
    }
}

// 이것을 실패시키는 것: 앞단이 공통부의 이름 개수나 variant 상한을 대조하지 않는 것, 도우미가 공통부의 이름 개수와
// 이름 구획을 대조하지 않는 것(앞단만 거부해 "도우미 통과 ⇒ 앞단 통과"가 깨진다).
#[test]
fn counts_names_and_cap_are_checked_where_their_bytes_are() {
    let x = variant(&[&X_LINE]);
    let name = names_block(&["wide"]);
    // More variants than bands + 1 is in the front's reach.
    let b = file(&vec![x.clone(); 3], &name);
    assert_eq!(
        (whole(&b), front(&b, 80).err()),
        (Err(Error::Shape), Some(Error::Shape))
    );
    // Past what any index can name, before any entry is read.
    let b = file(&vec![x.clone(); 5000], &name);
    assert_eq!(
        (whole(&b), front(&b, 80).err()),
        (Err(Error::Limit), Some(Error::Limit))
    );
    // COMMON's name count disagrees with the bands.
    let (wire, c) = one_band();
    let s = Sections::of(&c);
    let mut common = c[HEAD..s.index].to_vec();
    let at = common.len() - 12;
    common[at..at + 4].copy_from_slice(&u32le(2));
    let b = reframe(
        &wire,
        &assemble(&c, &common, &[x.clone(), x.clone()], &name),
    );
    assert_eq!(
        (whole(&b), front(&b, 80).err()),
        (Err(Error::Shape), Some(Error::Shape))
    );
    // What only the name block shows belongs to the helper, as the band-name
    // references do; the front neither reads nor needs it.
    let mut padded = name.clone();
    padded.push(0);
    for (names, error) in [
        (names_block(&["wide", "tall"]), Error::Shape),
        (names_block(&["a"; 5000]), Error::Shape),
        (padded, Error::Trailing),
    ] {
        let b = file(&[x.clone(), x.clone()], &names);
        assert_eq!(whole(&b), Err(error));
        assert!(front(&b, 80).is_ok());
    }
    // Past the 16 MiB section cap, before any read.
    let mut big = encode_compiled(&fixture::config()).unwrap();
    big.resize(16 * 1024 * 1024 + 1, 0);
    assert_eq!(decode_compiled(&big), Err(Error::Limit));
    // A section cut anywhere, through the compiled-level API and the frame.
    let c = encode_compiled(&fixture::config()).unwrap();
    for end in 0..c.len() {
        assert!(decode_compiled(&c[..end]).is_err(), "cut {end}");
        assert!(
            fixture::front_compiled(&c[..end], 120).is_err(),
            "cut {end}"
        );
    }
}

fn wide_config() -> CompiledConfig {
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
                r.band = Some(3);
            }
        }
    }
    wide
}

// 이것을 실패시키는 것: 머리 체크섬이 앞부분 일부를 덮지 않는 것, 앞단이 고른 variant의 CRC를 비교하지 않는 것,
// 도우미가 구획 CRC를 비교하지 않는 것.
#[test]
fn a_bit_flip_stops_whole_decode_and_the_front_exactly_where_it_reads() {
    for c in [fixture::config(), wide_config()] {
        let b = wire(&c);
        let end = b.len() - META;
        for width in [15u16, 120] {
            let good = front(&b, width).unwrap();
            let selected = fixture::selected_end(&b, width);
            let first = selected - good_variant_len(&b, width);
            let covered = |at: usize| {
                let s = Sections::of(&b[P..end]);
                at < P + s.front || (first..selected).contains(&at)
            };
            for at in 0..end {
                for bit in [0x01, 0x80] {
                    let mut x = b.clone();
                    x[at] ^= bit;
                    assert!(whole(&x).is_err(), "flip {at} {bit:#x}");
                    match front(&x, width) {
                        Ok(got) => {
                            assert!(!covered(at), "front took {at} {bit:#x}");
                            assert_eq!(got, good, "flip {at} {bit:#x}");
                        }
                        Err(_) => assert!(covered(at), "front refused {at} {bit:#x}"),
                    }
                }
            }
        }
    }
}

fn good_variant_len(b: &[u8], width: u16) -> usize {
    let (c, _) = bingsu_core::snapshot::lengths(b).unwrap();
    let compiled = &b[P..P + c];
    let s = Sections::of(compiled);
    let end = fixture::selected_end(b, width) - P;
    (0..s.count)
        .map(|i| s.variant(compiled, i))
        .find(|v| v.as_ptr_range().end == compiled[end..].as_ptr())
        .unwrap()
        .len()
}

// 이것을 실패시키는 것: 이름 CRC 비교를 빼는 것(공통부에 저장한 값과 구획을 대조하지 않으면 유효한 UTF-8·
// 고유 이름으로 바뀐 뒤집기를 도우미가 받아 last-good으로 복사된다).
#[test]
fn every_bit_of_the_name_block_stops_the_whole_decode() {
    let b = wire(&wide_config());
    let (c, _) = bingsu_core::snapshot::lengths(&b).unwrap();
    let names = P + Sections::of(&b[P..P + c]).names;
    assert!(P + c - names > 16);
    for at in names..P + c {
        for bit in 0..8 {
            let mut x = b.clone();
            x[at] ^= 1 << bit;
            assert!(whole(&x).is_err(), "{at} bit {bit}");
            assert!(front(&x, 15).is_ok(), "{at} bit {bit}");
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 48, ..ProptestConfig::default() })]

    // 이것을 실패시키는 것: 앞단이 도우미에 없는 조건으로 거부하는 것, 앞단 예산이 도우미보다 작아지는 것,
    // 건너뛰는 바이트를 잘못 세는 것, 다른 variant를 고르는 것.
    #[test]
    fn whole_decode_accepting_implies_the_front_at_every_width(
        bands in prop::collection::vec(band(), 0..6),
        default in 0..TEMPLATES.len(),
        templates in prop::collection::vec(0..TEMPLATES.len(), 6),
        names in prop::collection::vec("[a-z]{1,3}", 6),
        flips in prop::collection::vec((any::<prop::sample::Index>(), any::<u8>()), 0..3),
    ) {
        let Some(mut c) = banded(&bands, default, &templates[..bands.len()]) else {
            return Err(TestCaseError::reject("bands do not order"));
        };
        for (i, name) in c.band_names.iter_mut().enumerate() {
            *name = format!("{}{i}", names[i]);
        }
        let mut b = wire(&c);
        let end = b.len() - META;
        // Flips resealed: a damaged file whose frame checksum still matches.
        let front_end = P + Sections::of(&b[P..end]).front;
        for (at, xor) in flips {
            b[P + HEAD + at.index(front_end - P - HEAD)] ^= xor;
        }
        sections::resign(&mut b, front_end - P);
        for width in widths(&c) {
            implies_front(&b, width);
        }
    }
}

// 이것을 실패시키는 것: 앞단이 특정 폭에서만 다른 variant를 고르거나 거부하는 것(경곗값 표본을 벗어난 폭).
#[test]
fn whole_decode_accepting_implies_the_front_at_every_u16_width() {
    let c = wide_config();
    let b = wire(&c);
    let full = Snapshot::decode(&b).unwrap().config;
    for width in 0..=u16::MAX {
        let got = front(&b, width).unwrap();
        assert_eq!(
            got,
            FrontConfig::from_compiled(full.clone(), width),
            "{width}"
        );
    }
}

// 이것을 실패시키는 것: 앞단이 고르지 않은 variant마다 할당하는 것.
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
        let counts = counted(|| out = Some(fixture::front_compiled(b, 15).unwrap()));
        assert_eq!(out.unwrap().band(), Some(1));
        counts
    };
    let full = |b: &[u8]| counted(|| drop(decode_compiled(b).unwrap()));
    let (fs, fl) = (front(&small), front(&large));
    let (ds, dl) = (full(&small), full(&large));
    // The whole decode allocates at least three times per unselected variant
    // (lines, nodes, spans). The front allocates the same for any band count.
    assert!(dl.0 > ds.0 + 62 * 3, "full {ds:?} {dl:?}");
    assert_eq!(fl.0, fs.0, "front {fs:?} {fl:?}");
    assert_eq!((fs.1, fl.1), (0, 0));
    // Per band: the band and its order entry, not a variant.
    assert!(fl.2 <= fs.2 + 62 * 128, "front peak {fs:?} {fl:?}");

    // A variant count past any index stops at HEAD.
    let x = variant(&[&X_LINE]);
    let many = file(&vec![x; 5000], &names_block(&["wide"]));
    let (_, reallocs, peak) = counted(|| assert!(front_err(&many)));
    assert_eq!(reallocs, 0);
    assert!(peak < 64 * 1024, "{peak}");
}

fn front_err(wire: &[u8]) -> bool {
    fixture::front_read(wire, 80, READ_CHUNK).is_err()
}

const MAX_ALLOC: usize = 64 * 1024 * 1024;

/// One line of `n` one-byte StyleEnd nodes, no spans, no fill: it charges
/// `n * size_of::<Node>()` and then fails `from_snapshot`.
fn charged_line(n: usize) -> Vec<u8> {
    let mut l = nodes(n, 9);
    l.extend([0; 5]);
    l
}

// 이것을 실패시키는 것: 공통부 뒤 예산을 넘겨받지 않는 것(앞단 variant, 도우미 variant가 각자 새 상한을 갖게 된다).
#[test]
fn the_section_has_one_allocation_budget() {
    let (wire, c) = one_band();
    let s = Sections::of(&c);
    let (node, line) = (size_of::<bingsu_core::template::compile::Node>(), 96);
    // COMMON's widths take most of the budget, the selected variant the rest
    // and more: either alone fits 64 MiB, together they do not.
    let run = size_of::<bingsu_core::diag_widths::WidthRun>();
    let runs = (MAX_ALLOC - 2 * 1024 * 1024) / run;
    let widths_at = s.index - HEAD - 16;
    let common = &c[HEAD..s.index];
    assert_eq!(
        common[widths_at..widths_at + 4],
        [0; 4],
        "empty widths last"
    );
    let mut forged = common[..widths_at].to_vec();
    forged.extend(u32le(runs));
    forged.resize(forged.len() + runs * 5, 0);
    forged.extend(&common[widths_at + 4..]);
    let nn = (MAX_ALLOC - line) / node - 8;
    let v = variant(&[&charged_line(nn)]);
    let name = names_block(&["wide"]);
    let b = reframe(&wire, &assemble(&c, &forged, &[v.clone(), v], &name));
    let mut got = None;
    let (_, _, peak) = counted(|| got = Some(front(&b, 80).err()));
    assert_eq!(got, Some(Some(Error::Limit)));
    assert!(peak <= MAX_ALLOC + b.len(), "front peak {peak}");

    // 4,096 bands whose variants fit the wire but not, together, the budget:
    // each is `k` empty lines.
    let n = bingsu_core::bands::MAX_BANDS;
    let bands: Vec<Band> = (0..n as u32)
        .map(|i| Band {
            min_cols: Some(i as u16),
            max_cols: Some(i as u16),
            order: None,
        })
        .collect();
    let base = banded(&bands, 2, &vec![2; n]).unwrap();
    let w = self::wire(&base);
    let (cl, _) = bingsu_core::snapshot::lengths(&w).unwrap();
    let c = &w[P..P + cl];
    let s = Sections::of(c);
    let empty_line = [0u8; 9];
    let k = 448;
    let lines: Vec<&[u8]> = vec![&empty_line; k];
    let v = variant(&lines);
    assert!(v.len() * (n + 1) + s.front < 16 * 1024 * 1024);
    let b = reframe(
        &w,
        &assemble(c, &c[HEAD..s.index], &vec![v; n + 1], &c[s.names..]),
    );
    let mut got = None;
    let (_, _, peak) = counted(|| got = Some(whole(&b)));
    assert_eq!(got, Some(Err(Error::Limit)));
    assert!(peak <= MAX_ALLOC + b.len(), "helper peak {peak}");
}

// 이것을 실패시키는 것: 색인 뒤 읽기 한도를 고른 variant 끝으로 줄이지 않는 것.
#[test]
fn reads_end_at_the_selected_variant() {
    let n = bingsu_core::bands::MAX_BANDS;
    let bands: Vec<Band> = (0..n as u32)
        .map(|i| Band {
            min_cols: Some((i * 16) as u16),
            max_cols: Some((i * 16 + 15) as u16),
            order: None,
        })
        .collect();
    let c = banded(&bands, 2, &vec![2; n]).unwrap();
    let b = wire(&c);
    let (cl, _) = bingsu_core::snapshot::lengths(&b).unwrap();
    let front_end = P + Sections::of(&b[P..P + cl]).front;
    for width in [0, 16, 2000, 40_000, u16::MAX] {
        let (_, read) = fixture::front_read(&b, width, READ_CHUNK).unwrap();
        let selected = fixture::selected_end(&b, width);
        // Chunks count from the compiled section's start.
        let chunks = (front_end - P).next_multiple_of(READ_CHUNK);
        assert_eq!(read, selected.max(P + chunks.min(cl)), "{width}");
        assert!(read <= P + cl);
    }
}

/// A file whose INDEX ends one byte into its second chunk and whose selected
/// variant (width 80, the default) comes first: the read that finishes INDEX
/// passes that variant by as much as any read can.
fn longest_tail() -> (CompiledConfig, usize) {
    let mut c = fixture::compile("");
    c.bands = (0..8)
        .map(|i| Band {
            min_cols: Some(100 + i * 10),
            max_cols: Some(109 + i * 10),
            order: None,
        })
        .collect();
    c.band_names = (0..8).map(|i| format!("b{i}")).collect();
    c.band_order = (0..8).collect();
    c.widths.clear();
    c.variants = vec![compile(&"y".repeat(3000), BUILTIN).unwrap(); 9];
    c.variants[0] = compile("x", BUILTIN).unwrap();
    let b = encode_compiled(&c).unwrap();
    // Plain runs take 5 bytes, runs naming "b0" take 11: any length past 40.
    let need = READ_CHUNK + 1 - Sections::of(&b).front;
    let named = (0..5).find(|n| (need - n * 11) % 5 == 0).unwrap();
    let run = |band: Option<&str>| WidthRun {
        from: 0,
        to: 0,
        band: band.map(Into::into),
    };
    c.widths = vec![run(None); (need - named * 11) / 5];
    c.widths.extend(vec![run(Some("b0")); named]);
    let front = Sections::of(&encode_compiled(&c).unwrap()).front;
    assert_eq!(front, READ_CHUNK + 1);
    (c, front)
}

// 이것을 실패시키는 것: 앞단이 고른 variant 뒤로 받은 바이트를 해석하는 것(다음 variant의 줄 수를 읽어 거부).
#[test]
fn the_tail_read_past_the_selected_variant_changes_nothing() {
    let (c, front_end) = longest_tail();
    let b = wire(&c);
    let (good, read) = fixture::front_read(&b, 80, READ_CHUNK).unwrap();
    let selected = fixture::selected_end(&b, 80);
    // Bytes the last read brought past the variant, up to READ_CHUNK - 1.
    let tail = read - selected;
    assert_eq!(read, P + 2 * READ_CHUNK);
    assert_eq!(selected - P - front_end + tail, READ_CHUNK - 1);
    let mut x = b.clone();
    for byte in &mut x[selected..selected + READ_CHUNK - 1] {
        *byte ^= 0xff;
    }
    assert_eq!(fixture::front_read(&x, 80, READ_CHUNK), Ok((good, read)));
    assert!(whole(&x).is_err());
}

// 이것을 실패시키는 것: 색인 전 읽기 한도가 `c_len`을 넘어 metadata까지 가는 것, 색인을 끝낸 다음 읽기가 옛 한도를
// 쓰는 것, 한도를 고른 variant 끝으로 줄이지 않는 것.
#[test]
fn bytes_and_reads_are_exact_per_fixture() {
    let bands = |n: u32| -> Vec<Band> {
        (0..n)
            .map(|i| Band {
                min_cols: Some((i * 16 + 1) as u16),
                max_cols: Some((i * 16 + 15) as u16),
                order: None,
            })
            .collect()
    };
    let cases: Vec<(CompiledConfig, &[u16])> = vec![
        (fixture::compile(""), &[80]),
        (fixture::config(), &[80, 120]),
        (banded(&bands(1), 2, &[2]).unwrap(), &[1, 80]),
        (banded(&bands(64), 2, &[2; 64]).unwrap(), &[1, 80, 1024]),
        (
            banded(&bands(4096), 2, &[2; 4096]).unwrap(),
            &[1, 40_000, u16::MAX],
        ),
        (longest_tail().0, &[80, 105]),
    ];
    for (c, widths) in cases {
        let b = wire(&c);
        let (body, _) = bingsu_core::snapshot::lengths(&b).unwrap();
        let front = Sections::of(&b[P..P + body]).front;
        for &width in widths {
            let variant_end = fixture::selected_end(&b, width) - P;
            for chunk in [13, 4097, READ_CHUNK] {
                let want = variant_end.max(front.next_multiple_of(chunk).min(body));
                let mut d = FrontDecoder::new(b.len() as u64, width).unwrap();
                let (mut at, mut reads) = (0, 0);
                while d.read_len() != 0 {
                    let n = d.read_len().min(chunk);
                    assert!(at + d.read_len() <= P + body, "past c_len at {at}");
                    d.push(&b[at..at + n]).unwrap();
                    at += n;
                    reads += usize::from(at > P);
                }
                d.finish().unwrap();
                assert_eq!(at, P + want, "bytes, width {width} chunk {chunk}");
                assert_eq!(
                    reads,
                    want.div_ceil(chunk),
                    "reads, width {width} chunk {chunk}"
                );
            }
        }
    }
}
