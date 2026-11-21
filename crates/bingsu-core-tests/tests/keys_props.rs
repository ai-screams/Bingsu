//! Layer 1 properties of the key reader (`bingsu_core::keys`): keys come
//! out the same wherever the reads split the input, the payload of a
//! string, a paste or a late sequence never becomes a key, and a burst
//! gives only its Ctrl-C.
use bingsu_core::keys::{
    BURST, DRAIN_QUIET, ESC_WAIT, Key, KeyReader, LATE_WAIT, PASTE_TIME, SEQ_TIME, STR_TIME,
};
use core::time::Duration;
use proptest::prelude::*;

fn ms(n: u64) -> Duration {
    Duration::from_millis(n)
}

/// Ticks at each deadline until nothing waits on time; the time it ends at.
fn settle(r: &mut KeyReader, mut now: Duration, out: &mut Vec<Key>) -> Duration {
    for _ in 0..8 {
        let Some(d) = r.deadline() else { break };
        now = now.max(d);
        out.extend_from_slice(r.tick(now).as_slice());
    }
    now
}

/// `bytes` cut before each position of `cuts` (any order, out of range
/// ignored), each read `gaps[i]` ms after the one before (cycled), from
/// `start`; then `settle`. The keys and the reader.
fn run_from(
    r: &mut KeyReader,
    start: Duration,
    bytes: &[u8],
    cuts: &[usize],
    gaps: &[u64],
) -> (Vec<Key>, Duration) {
    let mut at: Vec<usize> = cuts
        .iter()
        .copied()
        .filter(|&c| c > 0 && c < bytes.len())
        .collect();
    at.sort_unstable();
    at.dedup();
    let mut out = Vec::new();
    let mut now = start;
    let mut from = 0;
    for (i, &to) in at.iter().chain([bytes.len()].iter()).enumerate() {
        out.extend_from_slice(r.feed(&bytes[from..to], now).as_slice());
        let gap = gaps.get(i % gaps.len().max(1)).copied().unwrap_or(0);
        now = now.saturating_add(ms(gap));
        from = to;
    }
    let now = settle(r, now, &mut out);
    (out, now)
}

fn run(bytes: &[u8], cuts: &[usize], gaps: &[u64]) -> Vec<Key> {
    run_from(&mut KeyReader::new(), Duration::ZERO, bytes, cuts, gaps).0
}

/// Input that is one key (kept or dropped), and what it gives.
const ATOMS: &[(&[u8], Option<Key>)] = &[
    (b"q", Some(Key::Char(b'q'))),
    (b"5", Some(Key::Char(b'5'))),
    (b" ", Some(Key::Char(b' '))),
    (b"\r", Some(Key::Enter)),
    (b"\n", Some(Key::Enter)),
    (b"\t", Some(Key::Tab)),
    (b"\x7f", Some(Key::Backspace)),
    (b"\x03", Some(Key::Ctrl(b'c'))),
    (b"\x04", Some(Key::Ctrl(b'd'))),
    (b"\x1b[A", Some(Key::Up)),
    (b"\x1bOB", Some(Key::Down)),
    (b"\x1b[Z", Some(Key::BackTab)),
    (b"\x1b\x1b[C", None),
    ("é".as_bytes(), None),
    ("한".as_bytes(), None),
    ("😀".as_bytes(), None),
    (b"\x1b[1;5C", None),
    (b"\x1b[12;40R", None),
    (b"\x1bq", None),
];

fn atoms(n: std::ops::Range<usize>) -> impl Strategy<Value = Vec<usize>> {
    prop::collection::vec(0..ATOMS.len(), n)
}

/// The bytes of `atoms` and the keys they give alone (`ESC ESC [ C` is the
/// Esc key and Right, so two keys).
fn joined(picked: &[usize]) -> (Vec<u8>, Vec<Key>, usize) {
    let mut bytes = Vec::new();
    let mut keys = Vec::new();
    let mut count = 0;
    for &i in picked {
        let (b, k) = ATOMS[i];
        bytes.extend_from_slice(b);
        if b == b"\x1b\x1b[C" {
            keys.extend([Key::Esc, Key::Right]);
            count += 2;
        } else {
            keys.extend(k);
            count += 1;
        }
    }
    (bytes, keys, count)
}

/// What a string or paste that begins with ESC gives when cut at `cuts`
/// with `gaps`: no key, or the Esc key alone when the first read is that
/// ESC and the next comes `ESC_WAIT` or more later (the rest is then a late
/// sequence).
fn esc_alone_if_cut_after_it(cuts: &[usize], gaps: &[u64]) -> Vec<Key> {
    let first = cuts.iter().copied().filter(|&c| c > 0).min();
    if first == Some(1)
        && gaps
            .first()
            .is_some_and(|&g| u128::from(g) >= ESC_WAIT.as_millis())
    {
        vec![Key::Esc]
    } else {
        vec![]
    }
}

/// The bytes a key may carry: printable ASCII for `Char`, and for `Ctrl`
/// the letter of a C0 control that has no key of its own.
fn allowed(key: &Key) -> bool {
    match *key {
        Key::Char(c) => (0x20..=0x7e).contains(&c),
        Key::Ctrl(c) => b"@abcdefgklnopqrstuvwxyz\\]^_".contains(&c),
        _ => true,
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 512, ..ProptestConfig::default() })]

    // 이것을 실패시키는 것: 읽기 경계나 시퀀스 안의 짧은 틈(20 ms까지)에서 시퀀스를 끊는 것, 키를 하나라도 다르게
    // 읽는 것.
    #[test]
    fn keys_do_not_depend_on_where_reads_split(
        picked in atoms(1..4),
        cuts in prop::collection::vec(0usize..40, 0..12),
        gaps in prop::collection::vec(0u64..=20, 1..12),
    ) {
        let (bytes, want, count) = joined(&picked);
        prop_assume!(count < BURST);
        prop_assert_eq!(run(&bytes, &cuts, &gaps), want);
    }

    // 이것을 실패시키는 것: 키 넷 이상의 읽기에서 Ctrl-C 말고 키를 내는 것, 그 안의 Ctrl-C를 버리는 것, 다음 읽기를
    // 버리는 것.
    #[test]
    fn a_read_of_four_keys_or_more_gives_only_a_cancel(picked in atoms(4..24), gap in 0u64..100) {
        let (bytes, _, _) = joined(&picked);
        let cancel = picked.iter().any(|&i| ATOMS[i].0 == b"\x03");
        let want = if cancel { vec![Key::Ctrl(b'c')] } else { vec![] };
        let mut r = KeyReader::new();
        prop_assert_eq!(r.feed(&bytes, Duration::ZERO).as_slice().to_vec(), want);
        prop_assert_eq!(r.feed(b"q", ms(gap)).as_slice().to_vec(), vec![Key::Char(b'q')]);
    }

    // 이것을 실패시키는 것: 문자열 내용이나 끝난 뒤 같은 흐름의 바이트를 키로 내는 것, 시간 상한을 넘긴 뒤 Ground로
    // 가는 것, 끝난 뒤 Ground로 돌아오지 않는 것.
    #[test]
    fn a_string_gives_no_keys(
        intro in prop::sample::select(b"]P_^X".to_vec()),
        st in any::<bool>(),
        payload in prop::collection::vec(any::<u8>(), 0..300),
        tail in prop::collection::vec(any::<u8>(), 0..20),
        cuts in prop::collection::vec(0usize..340, 0..20),
        gaps in prop::collection::vec(0u64..=50, 1..20),
    ) {
        let mut bytes = vec![0x1b, intro];
        bytes.extend(payload.iter().copied().filter(|&b| b != 0x07 && b != 0x1b));
        bytes.extend_from_slice(if st { b"\x1b\\" } else { b"\x07" });
        bytes.extend(tail.iter().copied().filter(|&b| b != 0x1b));
        let mut r = KeyReader::new();
        let (keys, now) = run_from(&mut r, Duration::ZERO, &bytes, &cuts, &gaps);
        prop_assert_eq!(keys, esc_alone_if_cut_after_it(&cuts, &gaps));
        prop_assert_eq!(r.feed(b"q", now).as_slice().to_vec(), vec![Key::Char(b'q')]);
    }

    // 이것을 실패시키는 것: 붙여 넣기 내용(0x03, 0x1a, 다른 시퀀스의 시작 포함)이나 끝 표지 뒤의 바이트를 키로 내는 것,
    // 나뉜 끝 표지를 놓쳐 Ground로 돌아오지 않는 것.
    #[test]
    fn a_bracketed_paste_gives_no_keys(
        payload in prop::collection::vec(any::<u8>(), 0..2000),
        tail in prop::collection::vec(any::<u8>(), 0..20),
        cuts in prop::collection::vec(0usize..2040, 0..30),
        gaps in prop::collection::vec(0u64..=50, 1..30),
    ) {
        let end = b"\x1b[201~";
        prop_assume!(!payload.windows(end.len()).any(|w| w == end));
        let mut bytes = b"\x1b[200~".to_vec();
        bytes.extend_from_slice(&payload);
        bytes.extend_from_slice(end);
        bytes.extend(tail.iter().copied().filter(|&b| b != 0x1b));
        let mut r = KeyReader::new();
        let (keys, now) = run_from(&mut r, Duration::ZERO, &bytes, &cuts, &gaps);
        prop_assert_eq!(keys, esc_alone_if_cut_after_it(&cuts, &gaps));
        prop_assert_eq!(r.feed(b"q", now).as_slice().to_vec(), vec![Key::Char(b'q')]);
    }

    // 이것을 실패시키는 것: Esc 판정 뒤 늦은 창(100 ms) 안에 온 시퀀스의 나머지를 키로 내는 것.
    #[test]
    fn the_late_rest_of_a_sequence_gives_no_keys(
        tail in prop::sample::select(vec![
            &b"[A"[..],
            b"OA",
            b"O5A",
            b"[1;5D",
            b"[12;40R",
            b"]11;rgb:0000/0000/0000\x07",
            b"]11;rgb:ffff/ffff/ffff\x1b\\",
            b"P1$r0m\x1b\\",
            b"[200~q\rs1u\x1b[201~",
        ]),
        first in 0u64..LATE_WAIT.as_millis() as u64,
        cuts in prop::collection::vec(0usize..32, 0..8),
        gaps in prop::collection::vec(0u64..=20, 1..8),
    ) {
        let mut r = KeyReader::new();
        let mut out = r.feed(b"\x1b", Duration::ZERO).as_slice().to_vec();
        let at = ESC_WAIT.saturating_add(ms(first));
        let (rest, _) = run_from(&mut r, at, tail, &cuts, &gaps);
        out.extend(rest);
        prop_assert_eq!(out, vec![Key::Esc]);
    }

    // 이것을 실패시키는 것: 어떤 바이트·분할·틈에서든 패닉하는 것, 묶이지 않은 바이트로 Char·Ctrl을 내는 것(DEL,
    // 0x80 위, Tab·Enter·Backspace·ESC를 Ctrl로), 입력이 그친 뒤에도 기한이 남는 것.
    #[test]
    fn any_input_ends_in_ground_with_allowed_keys(
        bytes in prop::collection::vec(any::<u8>(), 0..400),
        cuts in prop::collection::vec(0usize..400, 0..40),
        gaps in prop::collection::vec(0u64..=700, 1..40),
    ) {
        let mut r = KeyReader::new();
        let (keys, _) = run_from(&mut r, Duration::ZERO, &bytes, &cuts, &gaps);
        prop_assert!(keys.iter().all(allowed), "{:?}", keys);
        prop_assert_eq!(r.deadline(), None);
    }
}

// The bounds the properties lean on: gaps of at most 20 ms keep a sequence
// inside its Esc wait and time bound, gaps of at most 50 ms keep a drain
// going.
const _: () = {
    assert!(20 < ESC_WAIT.as_millis());
    assert!(20 * 8 < SEQ_TIME.as_millis());
    assert!(50 < DRAIN_QUIET.as_millis());
    assert!(STR_TIME.as_millis() < PASTE_TIME.as_millis());
};
