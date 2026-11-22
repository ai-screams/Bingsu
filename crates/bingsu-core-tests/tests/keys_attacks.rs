//! Regression tests of the key reader (`bingsu_core::keys`) against inputs
//! built to get keys through: an unmarked paste padded so that each read
//! stays under the burst guess. Reads are 1,024 bytes, as the full-screen
//! session reads them.
use bingsu_core::keys::{Key, KeyReader};
use core::time::Duration;

const READ: usize = 1024;

fn ms(n: u64) -> Duration {
    Duration::from_millis(n)
}

/// Each call's keys, `stream` read in `READ`-byte reads after a first read
/// of `first` bytes, `gap` ms apart, then a tick once time ran out.
fn calls(stream: &[u8], first: usize, gap: u64) -> Vec<Vec<Key>> {
    let mut r = KeyReader::new();
    let (a, b) = stream.split_at(first.min(stream.len()));
    let mut parts: Vec<&[u8]> = vec![a];
    parts.extend(b.chunks(READ));
    let mut t = 1000;
    let mut out = Vec::new();
    for part in parts {
        out.push(r.feed(part, ms(t)).as_slice().to_vec());
        t += gap;
    }
    out.push(r.tick(ms(t + 10_000)).as_slice().to_vec());
    out
}

/// `keys`, each after `pad`, in one stream.
fn padded(keys: &[&[u8]], pad: &[u8]) -> Vec<u8> {
    let mut v = Vec::new();
    for k in keys {
        v.extend_from_slice(pad);
        v.extend_from_slice(k);
    }
    v
}

/// How many calls gave an Enter key.
fn enter_calls(calls: &[Vec<Key>]) -> usize {
    calls.iter().filter(|k| k.contains(&Key::Enter)).count()
}

// 이것을 실패시키는 것: 끊긴 시퀀스를 묶음에 세지 않는 것(`ESC [`를 512번 되풀이해 채운 붙여 넣기 하나가 s, s, Enter,
// Enter를 네 호출에 하나씩 내어 다음 읽기의 두 번째 Enter로 쓰기를 확인함).
#[test]
fn a_paste_padded_with_cut_sequences_cannot_confirm() {
    let mut pad = b"\x1b[".repeat(512);
    pad.push(b'~');
    let stream = padded(&[b"s", b"s", b"\n", b"\n"], &pad);
    for gap in [0, 1, 5] {
        let got = calls(&stream, READ, gap);
        assert!(enter_calls(&got) <= 1, "gap {gap}: {got:?}");
    }
    for first in 0..READ {
        let got = calls(&stream, first, 1);
        assert!(enter_calls(&got) <= 1, "first read {first}: {got:?}");
    }
}

// 이것을 실패시키는 것: 떠도는 바이트(0xff, 0xb1), 깨진 글자(Latin-1의 0xe9), 도입 바이트가 아닌 C1(0x85)을 묶음에
// 세지 않는 것(그것으로 채운 붙여 넣기의 Enter 둘이 두 호출에서 나옴).
#[test]
fn a_paste_padded_with_dropped_bytes_cannot_confirm() {
    for byte in [0xffu8, 0xb1, 0xe9, 0x85] {
        let stream = padded(&[b"\n", b"\n"], &[byte; READ]);
        for first in [0, 1, 2, 3, READ / 2, READ] {
            let got = calls(&stream, first, 1);
            assert!(
                enter_calls(&got) <= 1,
                "{byte:#x}, first read {first}: {got:?}"
            );
        }
    }
}
