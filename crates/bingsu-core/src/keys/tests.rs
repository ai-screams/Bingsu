#![cfg(test)]
use super::*;
use alloc::vec::Vec;

fn ms(n: u64) -> Duration {
    Duration::from_millis(n)
}

/// Ticks at each deadline until nothing waits on time (a few rounds at
/// most), collecting the keys; the time it ends at.
fn settle(r: &mut KeyReader, mut now: Duration, out: &mut Vec<Key>) -> Duration {
    for _ in 0..8 {
        let Some(d) = r.deadline() else { break };
        now = now.max(d);
        out.extend_from_slice(r.tick(now).as_slice());
    }
    now
}

/// Each part as one read, `gap` apart from t = 0, then `settle`.
fn run(parts: &[&[u8]], gap: Duration) -> Vec<Key> {
    run_ended(parts, gap).0
}

/// As `run`, and whether the input had ended its sequences by the last
/// read: what waits on time then is at most a drain (or a lone Esc), not a
/// string or paste still waiting for its end.
fn run_ended(parts: &[&[u8]], gap: Duration) -> (Vec<Key>, bool) {
    let mut r = KeyReader::new();
    let mut out = Vec::new();
    let mut now = Duration::ZERO;
    let mut last = now;
    for part in parts {
        out.extend_from_slice(r.feed(part, now).as_slice());
        last = now;
        now = now.saturating_add(gap);
    }
    let ended = r
        .deadline()
        .is_none_or(|d| d <= last.saturating_add(DRAIN_QUIET));
    settle(&mut r, now, &mut out);
    (out, ended)
}

fn one(bytes: &[u8]) -> Vec<Key> {
    run(&[bytes], ms(1))
}

/// After `bytes` the reader is back in Ground: a `q` read at once is a key.
fn back_in_ground(bytes: &[u8]) -> bool {
    let mut r = KeyReader::new();
    let mut out = Vec::new();
    out.extend_from_slice(r.feed(bytes, Duration::ZERO).as_slice());
    let now = settle(&mut r, ms(1), &mut out);
    r.feed(b"q", now).as_slice() == [Key::Char(b'q')]
}

use Key::*;

// 이것을 실패시키는 것: 묶인 키 하나를 다른 키로 읽거나 버리는 것(CR·LF·DEL·BS의 갈래, Ctrl 글자 계산, 화살표 표,
// Shift-Tab, Ss3 화살표, 홀로 된 Esc).
#[test]
fn every_key_the_editor_binds() {
    let cases: &[(&[u8], &[Key])] = &[
        (b"q", &[Char(b'q')]),
        (b" ", &[Char(b' ')]),
        (b"~", &[Char(b'~')]),
        (b"S", &[Char(b'S')]),
        (b"7", &[Char(b'7')]),
        (b"\r", &[Enter]),
        (b"\n", &[Enter]),
        (b"\t", &[Tab]),
        (b"\x7f", &[Backspace]),
        (b"\x08", &[Backspace]),
        (b"\x03", &[Ctrl(b'c')]),
        (b"\x04", &[Ctrl(b'd')]),
        (b"\x0c", &[Ctrl(b'l')]),
        (b"\x1a", &[Ctrl(b'z')]),
        (b"\x00", &[Ctrl(b'@')]),
        (b"\x1c", &[Ctrl(b'\\')]),
        (b"\x1f", &[Ctrl(b'_')]),
        (b"\x1b[A", &[Up]),
        (b"\x1b[B", &[Down]),
        (b"\x1b[C", &[Right]),
        (b"\x1b[D", &[Left]),
        (b"\x1bOA", &[Up]),
        (b"\x1bOB", &[Down]),
        (b"\x1bOC", &[Right]),
        (b"\x1bOD", &[Left]),
        (b"\x1b[Z", &[BackTab]),
        (b"\x1b", &[Esc]),
    ];
    for (bytes, want) in cases {
        assert_eq!(one(bytes), *want, "{bytes:?}");
    }
}

// 이것을 실패시키는 것: 매개 바이트가 있는 시퀀스, 모르는 최종 바이트, Ss3의 Z, 떠도는 끝 표지, Alt 키, 아스키 밖
// 글자, 잘못된 UTF-8을 키로 내는 것, 그 뒤에 Ground로 돌아가지 않는 것.
#[test]
fn other_input_is_dropped_and_the_reader_goes_on() {
    let dropped: &[&[u8]] = &[
        b"\x1b[1;5A",
        b"\x1b[3~",
        b"\x1b[12;40R",
        b"\x1b[?1;2c",
        b"\x1b[201~",
        b"\x1bOZ",
        b"\x1bO5A",
        b"\x1bq",
        b"\x1b\r",
        b"\x1b\x7f",
        b"\x1b \x1b",
        "é".as_bytes(),
        "한".as_bytes(),
        "😀".as_bytes(),
        b"\xf4\x8f\xbf\xbf",
        b"\xff",
        b"\x80",
        b"\xc0\x80",
        b"\xe0\x80\x80",
        b"\xed\xa0\x80",
        b"\xf0\x80\x80\x80",
        b"\xf4\x90\x80\x80",
        b"\xf5",
    ];
    for bytes in dropped {
        let keys = one(bytes);
        // `ESC SP ESC`: the Alt key, then a lone Esc.
        let want: &[Key] = if *bytes == b"\x1b \x1b" { &[Esc] } else { &[] };
        assert_eq!(keys, want, "{bytes:?}");
        assert!(back_in_ground(bytes), "{bytes:?}");
    }
}

// 이것을 실패시키는 것: 잘못된 UTF-8을 글자 하나로 세는 것(이어지는 바이트 범위를 보지 않아 과장 부호화·대리 쌍이
// 글자가 되고, 넷째 키로 세어 묶음이 됨).
#[test]
fn invalid_utf8_is_no_key() {
    assert_eq!(one(b"q\xe0\x80\x80q\xed\xa0\x80"), [Char(b'q'); 2]);
    assert_eq!(one(b"q\xf0\x80\x80\x80q\xf4\x90\x80\x80"), [Char(b'q'); 2]);
    assert_eq!(one(b"q\x80\xbfq\xc0\xaf"), [Char(b'q'); 2]);
}

// 이것을 실패시키는 것: 깨는 바이트를 다시 읽지 않는 것(`0xE2 ESC [ A`의 화살표, `0xC3 q`의 q, `0xE2 ESC [200~`의
// 붙여 넣기를 잃음), ESC 뒤 아스키 밖 바이트를 다시 읽지 않는 것.
#[test]
fn a_byte_that_breaks_a_character_is_read_again() {
    assert_eq!(one(b"\xe2\x1b[A"), [Up]);
    assert_eq!(one(b"\xc3q"), [Char(b'q')]);
    assert_eq!(one(b"\xe2\x82q"), [Char(b'q')]);
    assert_eq!(one(b"\xf0\x9f\x98\r"), [Enter]);
    assert_eq!(one(b"\x1b\xe2\x1b[A"), [Up]);
    // The paste mark after a broken character still begins a paste.
    assert_eq!(one(b"\xe2\x1b[200~2\x1b[201~"), []);
}

// 이것을 실패시키는 것: 시퀀스 안의 ESC를 새 시퀀스로 읽지 않는 것, 다른 깨는 바이트에서 Drain으로 가지 않는 것
// (잘린 시퀀스의 나머지 `\r`가 Enter가 됨).
#[test]
fn a_broken_sequence_begins_again_or_drains() {
    assert_eq!(one(b"\x1b[1\x1b[A"), [Up]);
    assert_eq!(one(b"\x1bO\x1bOB"), [Down]);
    assert_eq!(run(&[b"\x1b[1\rq", b"q"], ms(1)), []);
    assert_eq!(run(&[b"\x1b[1\x03"], ms(1)), []);
}

// 이것을 실패시키는 것: ESC ESC의 둘째를 다시 읽지 않는 것.
#[test]
fn esc_esc_is_an_esc_and_a_new_start() {
    assert_eq!(one(b"\x1b\x1b[A"), [Esc, Up]);
    assert_eq!(one(b"\x1b\x1b"), [Esc, Esc]);
}

/// Samples that end in Ground with these keys, split anywhere.
const SAMPLES: &[(&[u8], &[Key])] = &[
    (b"\x1b[A", &[Up]),
    (b"\x1bOD", &[Left]),
    (b"\x1b[Z", &[BackTab]),
    (b"\x1b\x1b[B", &[Esc, Down]),
    (b"\xe2\x1b[C", &[Right]),
    (b"q\r", &[Char(b'q'), Enter]),
    (b"\x1b[1;5Aj", &[Char(b'j')]),
    ("é".as_bytes(), &[]),
    ("😀".as_bytes(), &[]),
    (b"\x1b[200~q\rs1u\x03\x1a\x1b[201~", &[]),
    (b"\x1b[200~\x1b\x1b[20\x1b[201~", &[]),
    (b"\x1b]11;rgb:0000/0000/0000\x07", &[]),
    (b"\x1b]11;rgb:ffff/ffff/ffff\x1b\\", &[]),
    (b"\x1bP1$r0m\x1b\\", &[]),
    (b"\x1b_q\rs\x1b\x1b\\", &[]),
    (b"\x1b[12;40R", &[]),
];

// 이것을 실패시키는 것: 읽기 경계에서 시퀀스를 끊는 것(어느 분할 지점에서든 `[`, `A`, 내용의 `q`가 키가 됨),
// 나뉜 끝 표지·ST·UTF-8을 놓치는 것(마지막 읽기 뒤에도 문자열·붙여 넣기가 끝을 기다림).
#[test]
fn every_split_point_of_every_sample() {
    let ended = |want: &[Key]| (want.to_vec(), true);
    for (bytes, want) in SAMPLES {
        assert_eq!(run_ended(&[bytes], ms(1)), ended(want), "{bytes:?} whole");
        for i in 1..bytes.len() {
            let (a, b) = bytes.split_at(i);
            assert_eq!(run_ended(&[a, b], ms(1)), ended(want), "{bytes:?} at {i}");
            for j in i + 1..bytes.len() {
                let (b, c) = b.split_at(j - i);
                let got = run_ended(&[a, b, c], ms(1));
                assert_eq!(got, ended(want), "{bytes:?} at {i}, {j}");
            }
        }
        // One byte per read, 1 ms apart.
        let parts: Vec<&[u8]> = bytes.chunks(1).collect();
        assert_eq!(run_ended(&parts, ms(1)), ended(want), "{bytes:?} bytewise");
        assert!(back_in_ground(bytes), "{bytes:?}");
    }
}

/// Bytes the editor binds, as a payload.
const COMMANDS: &[u8] = b"qs\r\n19ur\x03\x1a\x04gilc";

// 이것을 실패시키는 것: 문자열·붙여 넣기·Drain 안의 바이트를 키로 내는 것(0x03, 0x1a 포함), 끝난 뒤 바로 Ground로
// 가는 것(같은 읽기의 나머지 `q`가 키가 됨).
#[test]
fn payload_never_becomes_keys() {
    let mut wrapped: Vec<Vec<u8>> = Vec::new();
    for intro in *b"]P_^X" {
        for end in [&b"\x07"[..], b"\x1b\\"] {
            let mut v = alloc::vec![0x1b, intro];
            v.extend_from_slice(COMMANDS);
            v.extend_from_slice(end);
            v.extend_from_slice(COMMANDS);
            wrapped.push(v);
        }
    }
    let mut paste = b"\x1b[200~".to_vec();
    paste.extend_from_slice(COMMANDS);
    paste.extend_from_slice(b"\x1b[201~");
    paste.extend_from_slice(COMMANDS);
    wrapped.push(paste);
    // Over the length cap: the rest of the sequence and of the read drains.
    let mut long = b"\x1b[".to_vec();
    long.extend_from_slice(&[b'1'; SEQ_MAX]);
    long.extend_from_slice(COMMANDS);
    wrapped.push(long);
    for bytes in &wrapped {
        assert_eq!(one(bytes), [], "{:?}", bytes.escape_ascii());
        for i in 1..bytes.len() {
            let (a, b) = bytes.split_at(i);
            assert_eq!(run(&[a, b], ms(1)), [], "{:?} at {i}", bytes.escape_ascii());
        }
    }
}

// 이것을 실패시키는 것: Esc 판정 시간을 30 ms가 아닌 값으로 보는 것, 판정 전에 다음 바이트가 와도 Esc로 내는 것.
#[test]
fn a_lone_esc_waits_for_esc_wait() {
    let mut r = KeyReader::new();
    assert_eq!(r.feed(b"\x1b", Duration::ZERO).as_slice(), []);
    assert_eq!(r.deadline(), Some(ESC_WAIT));
    assert_eq!(r.tick(ms(29)).as_slice(), []);
    assert_eq!(r.tick(ms(30)).as_slice(), [Esc]);
    assert_eq!(r.deadline(), None);

    let mut r = KeyReader::new();
    r.feed(b"\x1b", Duration::ZERO);
    assert_eq!(r.feed(b"[A", ms(29)).as_slice(), [Up]);
}

// 이것을 실패시키는 것: 늦은 `[`·`O`·`]`를 키로 읽는 것, 늦은 창(100 ms)이 지나도 늦은 것으로 보는 것, 창을 Esc를
// 알아챈 때부터 세는 것, 바로 다음 바이트가 아닌데도 늦은 것으로 보는 것, 늦은 붙여 넣기 표지를 붙여 넣기로 보지
// 않는 것.
#[test]
fn a_late_rest_of_a_sequence_is_dropped() {
    // The read that brings the rest also ends the wait.
    let mut r = KeyReader::new();
    r.feed(b"\x1b", Duration::ZERO);
    assert_eq!(r.feed(b"[A", ms(30)).as_slice(), [Esc]);
    assert_eq!(r.feed(b"q", ms(31)).as_slice(), [Char(b'q')]);

    for (tail, after) in [
        (&b"[A"[..], &b""[..]),
        (b"OA", b""),
        (b"O5A", b""),
        (b"]11;rgb:0000/0000/0000\x07", b""),
        (b"P1$r0m\x1b\\", b""),
        (b"[200~q\rs1\x1b[201~", b""),
    ] {
        for at in [30, 129] {
            let mut r = KeyReader::new();
            let mut out = Vec::new();
            r.feed(b"\x1b", Duration::ZERO);
            out.extend_from_slice(r.tick(ms(30)).as_slice());
            out.extend_from_slice(r.feed(tail, ms(at)).as_slice());
            out.extend_from_slice(r.feed(after, ms(at)).as_slice());
            settle(&mut r, ms(at), &mut out);
            assert_eq!(out, [Esc], "{:?} at {at}", tail.escape_ascii());
        }
    }

    // The window runs from the end of the Esc wait, also when the wait's
    // end is seen late.
    let mut r = KeyReader::new();
    r.feed(b"\x1b", Duration::ZERO);
    assert_eq!(r.tick(ms(100)).as_slice(), [Esc]);
    assert_eq!(r.feed(b"O", ms(130)).as_slice(), [Char(b'O')]);

    // Past the window, or not the very next byte: keys.
    let mut r = KeyReader::new();
    r.feed(b"\x1b", Duration::ZERO);
    r.tick(ms(30));
    assert_eq!(r.feed(b"O", ms(130)).as_slice(), [Char(b'O')]);
    let mut r = KeyReader::new();
    r.feed(b"\x1b", Duration::ZERO);
    r.tick(ms(30));
    assert_eq!(r.feed(b"x", ms(40)).as_slice(), [Char(b'x')]);
    assert_eq!(r.feed(b"O", ms(50)).as_slice(), [Char(b'O')]);
}

// 이것을 실패시키는 것: 키 넷의 읽기를 버리지 않는 것, 셋을 버리는 것, 시퀀스를 바이트 수로 세는 것, 아스키 밖 글자를
// 세지 않는 것, 묶음 앞에 시간이 끝낸 Esc를 함께 버리는 것.
#[test]
fn a_burst_of_four_keys_is_dropped() {
    assert_eq!(one(b"qqqq"), []);
    assert_eq!(one(b"qqq"), [Char(b'q'); 3]);
    assert_eq!(one(b"\x1b[A\x1b[A\x1b[A"), [Up; 3]);
    assert_eq!(one(b"\x1b[A\x1b[A\x1b[A\x1b[A"), []);
    assert_eq!(one("qéq".as_bytes()), [Char(b'q'); 2]);
    assert_eq!(one("qéqé".as_bytes()), []);
    let mut r = KeyReader::new();
    r.feed(b"\x1b", Duration::ZERO);
    assert_eq!(r.feed(b"qqqq", ms(40)).as_slice(), [Esc]);
    let mut r = KeyReader::new();
    r.feed(b"\x1b", Duration::ZERO);
    assert_eq!(
        r.feed(b"abc", ms(40)).as_slice(),
        [Esc, Char(b'a'), Char(b'b'), Char(b'c')]
    );
}

// 이것을 실패시키는 것: 묶음 뒤 Drain으로 가지 않는 것(다음 읽기의 키가 들어옴), Drain이 끝나지 않는 것, 붙여 넣기
// 안에서 끝난 묶음 뒤 Drain으로 바꾸는 것(5 s 상한 대신 100 ms).
#[test]
fn a_burst_drains_what_follows() {
    let mut r = KeyReader::new();
    assert_eq!(r.feed(b"qqqq", Duration::ZERO).as_slice(), []);
    assert_eq!(r.feed(b"q", ms(99)).as_slice(), []);
    assert_eq!(r.deadline(), Some(ms(199)));
    assert_eq!(r.tick(ms(199)).as_slice(), []);
    assert_eq!(r.feed(b"q", ms(200)).as_slice(), [Char(b'q')]);

    // A burst that ends inside a paste: the paste goes on to its end mark.
    let mut r = KeyReader::new();
    assert_eq!(r.feed(b"qqqq\x1b[200~", ms(10)).as_slice(), []);
    assert_eq!(r.deadline(), Some(ms(10).saturating_add(PASTE_TIME)));
}

// 이것을 실패시키는 것: 길이 상한을 하나 어긋나게 보는 것(32바이트 시퀀스를 버리거나 33바이트를 받음), 문자열·붙여
// 넣기의 길이 상한을 보지 않는 것(상한을 넘어도 시간 상한까지 기다림).
#[test]
fn length_bounds() {
    // ESC [, 29 parameter bytes and the final byte: 32 bytes, one key
    // (dropped: it has parameters); the next read is Ground.
    let mut at_cap = b"\x1b[".to_vec();
    at_cap.extend_from_slice(&[b'1'; SEQ_MAX - 3]);
    at_cap.push(b'A');
    assert_eq!(at_cap.len(), SEQ_MAX);
    let mut r = KeyReader::new();
    assert_eq!(r.feed(&at_cap, Duration::ZERO).as_slice(), []);
    assert_eq!(r.feed(b"q", ms(1)).as_slice(), [Char(b'q')]);
    // One byte more: drained, and so is the next read.
    let mut over = b"\x1b[".to_vec();
    over.extend_from_slice(&[b'1'; SEQ_MAX - 2]);
    over.push(b'A');
    let mut r = KeyReader::new();
    assert_eq!(r.feed(&over, Duration::ZERO).as_slice(), []);
    assert_eq!(r.feed(b"q", ms(1)).as_slice(), []);

    // A string of `STR_MAX` bytes still waits for its end (its time bound);
    // one byte more drains (the quiet bound).
    for (n, deadline) in [(STR_MAX, STR_TIME), (STR_MAX + 1, DRAIN_QUIET)] {
        let mut s = b"\x1b]".to_vec();
        s.resize(2 + n, b'x');
        let mut r = KeyReader::new();
        r.feed(&s, Duration::ZERO);
        assert_eq!(r.deadline(), Some(deadline), "{n}");
    }
    for (n, deadline) in [(PASTE_MAX, PASTE_TIME), (PASTE_MAX + 1, DRAIN_QUIET)] {
        let mut s = b"\x1b[200~".to_vec();
        s.resize(6 + n, b'x');
        let mut r = KeyReader::new();
        r.feed(&s, Duration::ZERO);
        assert_eq!(r.deadline(), Some(deadline), "{n}");
    }
}

// 이것을 실패시키는 것: 시간 상한을 보지 않는 것, 상한에서 Drain 대신 Ground로 가는 것(나머지 `A q`가 키가 됨),
// 상한 비교를 하나 어긋나게 하는 것, Drain의 조용한 시간을 마지막 바이트부터 세지 않는 것.
#[test]
fn time_bounds() {
    for (start, bound) in [
        (&b"\x1b[1"[..], SEQ_TIME),
        (b"\x1bO1", SEQ_TIME),
        (b"\x1b]11;", STR_TIME),
        (b"\x1b[200~", PASTE_TIME),
    ] {
        let mut r = KeyReader::new();
        r.feed(start, Duration::ZERO);
        assert_eq!(r.deadline(), Some(bound), "{start:?}");
        let before = bound.saturating_sub(ms(1));
        assert_eq!(r.tick(before).as_slice(), []);
        assert_eq!(r.deadline(), Some(bound), "{start:?}");
        assert_eq!(r.tick(bound).as_slice(), []);
        // Drain now: the rest is dropped, and each byte restarts the wait.
        assert_eq!(r.deadline(), Some(bound.saturating_add(DRAIN_QUIET)));
        let later = bound.saturating_add(ms(50));
        assert_eq!(r.feed(b"Aq\r", later).as_slice(), [], "{start:?}");
        assert_eq!(r.deadline(), Some(later.saturating_add(DRAIN_QUIET)));
        let quiet = later.saturating_add(DRAIN_QUIET);
        assert_eq!(r.feed(b"q", quiet.saturating_sub(ms(1))).as_slice(), []);
        let quiet = quiet.saturating_add(DRAIN_QUIET);
        assert_eq!(r.feed(b"q", quiet).as_slice(), [Char(b'q')], "{start:?}");
    }
    // A bound that passed before a read is applied before its bytes.
    let mut r = KeyReader::new();
    r.feed(b"\x1b[1", Duration::ZERO);
    assert_eq!(r.feed(b";5A", SEQ_TIME).as_slice(), []);
}

// 이것을 실패시키는 것: 상태별 기한을 잘못 내는 것(Ground·Utf8에 기한, Esc에 다른 상한).
#[test]
fn the_deadline_of_each_state() {
    let at = ms(1000);
    for (bytes, want) in [
        (&b""[..], None),
        (b"\xe2", None),
        (b"\x1b", Some(at + ESC_WAIT)),
        (b"\x1b[", Some(at + SEQ_TIME)),
        (b"\x1bO", Some(at + SEQ_TIME)),
        (b"\x1bX", Some(at + STR_TIME)),
        (b"\x1b[200~", Some(at + PASTE_TIME)),
        (b"\x1b]\x07", Some(at + DRAIN_QUIET)),
        // A `\` ends a string only after ESC.
        (b"\x1b]a\\b", Some(at + STR_TIME)),
        (b"\x1b]\x1bx\\", Some(at + STR_TIME)),
        // The end mark after an ESC of the paste's own.
        (b"\x1b[200~\x1b\x1b[201~", Some(at + DRAIN_QUIET)),
    ] {
        let mut r = KeyReader::new();
        r.feed(bytes, at);
        assert_eq!(r.deadline(), want, "{bytes:?}");
    }
}

// 이것을 실패시키는 것: reset이 진행 중인 시퀀스나 늦은 창을 남기는 것(멈췄다 재개한 뒤의 첫 키를 잃음).
#[test]
fn reset_forgets_a_sequence_in_progress() {
    for start in [&b"\x1b["[..], b"\x1b]11;", b"\x1b[200~", b"\x1b", b"qqqq"] {
        let mut r = KeyReader::new();
        r.feed(start, Duration::ZERO);
        r.reset();
        assert_eq!(r.deadline(), None);
        assert_eq!(r.feed(b"A", ms(1)).as_slice(), [Char(b'A')], "{start:?}");
    }
    let mut r = KeyReader::new();
    r.feed(b"\x1b", Duration::ZERO);
    r.tick(ms(30));
    r.reset();
    assert_eq!(r.feed(b"O", ms(31)).as_slice(), [Char(b'O')]);
}

// 이것을 실패시키는 것: 시각 덧셈이 넘치는 것(release에서도 Duration 덧셈은 패닉), 시각이 뒤로 갈 때 패닉하는 것.
#[test]
fn times_saturate() {
    let mut r = KeyReader::new();
    r.feed(b"\x1b", Duration::MAX);
    assert_eq!(r.deadline(), Some(Duration::MAX));
    assert_eq!(r.tick(Duration::MAX).as_slice(), [Esc]);
    for start in [&b"\x1b["[..], b"\x1b]", b"\x1b[200~", b"qqqq"] {
        let mut r = KeyReader::new();
        r.feed(start, Duration::MAX);
        assert_eq!(r.deadline(), Some(Duration::MAX));
        r.tick(Duration::MAX);
        r.feed(b"q", Duration::ZERO);
        r.tick(Duration::ZERO);
    }
}
