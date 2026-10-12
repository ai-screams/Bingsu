//! Untrusted text cleanup, step 1 of spec section 3 "셸별 출력과 보안".
//! Branch and folder names, environment values, command output and theme,
//! template and icon text all pass through here before width counting and
//! shell escaping. Every outside value goes through this function; the type
//! that forces it (`Clean`) is Task A6.
use crate::ucd::REMOVED_FORMAT;
use alloc::string::String;

/// True for a code point that never reaches a prompt: C0 (newlines and ESC
/// included), DEL, C1, and every format character (gc Cf) except ZWJ
/// U+200D, plus the line and paragraph separators U+2028 and U+2029. The Cf
/// set covers the bidi controls U+202A–202E, U+2066–2069, U+200E, U+200F
/// and U+061C. Variation selectors (gc Mn) stay.
pub fn is_removed(c: char) -> bool {
    let cp = c as u32;
    cp < 0x20 || (0x7F..=0x9F).contains(&cp) || in_ranges(REMOVED_FORMAT, cp)
}

/// Index of the sorted, non-overlapping range in `table` that holds `cp`;
/// `bounds` reads `(lo, hi)` (inclusive) from a row.
pub(crate) fn range_index<T>(
    table: &[T],
    cp: u32,
    bounds: impl Fn(&T) -> (u32, u32),
) -> Option<usize> {
    table
        .binary_search_by(|row| {
            let (lo, hi) = bounds(row);
            if hi < cp {
                core::cmp::Ordering::Less
            } else if lo > cp {
                core::cmp::Ordering::Greater
            } else {
                core::cmp::Ordering::Equal
            }
        })
        .ok()
}

pub(crate) fn in_ranges(table: &[(u32, u32)], cp: u32) -> bool {
    range_index(table, cp, |&r| r).is_some()
}

/// Appends `input` to `out` without removed code points. Invalid UTF-8
/// becomes U+FFFD, one per maximal invalid subsequence (the same rule as
/// `String::from_utf8_lossy`).
pub fn sanitize_into(input: &[u8], out: &mut String) {
    for chunk in input.utf8_chunks() {
        out.extend(chunk.valid().chars().filter(|&c| !is_removed(c)));
        if !chunk.invalid().is_empty() {
            out.push('\u{FFFD}');
        }
    }
}

/// Bytes `sanitize_into_capped` decodes at a time, so it reads at most this
/// much past the point where it stops.
const WINDOW: usize = 256;

/// `sanitize_into` that stops reading `input` once it has appended more than
/// `limit` bytes to `out`. Returns how many bytes of `input` it read (up to
/// the end of the window where it stopped) when it stopped that way, so
/// `out` holds only a prefix of the full result (longer than `limit`); None
/// when it appended the whole result. Removed code points add nothing, so input
/// that is all removed (1 MiB of ESC) is still read to the end.
pub(crate) fn sanitize_into_capped(input: &[u8], out: &mut String, limit: usize) -> Option<usize> {
    let start = out.len();
    let mut rest = input;
    while !rest.is_empty() {
        // Decoding one window at a time keeps `utf8_chunks` from checking
        // the whole input before the first chunk. The cut goes before a
        // byte that is not a continuation byte (0x80-0xBF), or after three
        // continuation bytes in a row (no lead byte is close enough): either
        // way no sequence, valid or not, crosses it, so each window decodes
        // as it would inside the whole input.
        let mut cut = rest.len().min(WINDOW);
        if cut < rest.len() {
            if let Some(at) = (cut - 3..=cut).rev().find(|&i| rest[i] & 0xC0 != 0x80) {
                cut = at;
            }
        }
        let (window, tail) = rest.split_at(cut);
        rest = tail;
        for chunk in window.utf8_chunks() {
            for c in chunk.valid().chars().filter(|&c| !is_removed(c)) {
                out.push(c);
                if out.len() - start > limit {
                    return Some(input.len() - rest.len());
                }
            }
            if !chunk.invalid().is_empty() {
                out.push('\u{FFFD}');
                if out.len() - start > limit {
                    return Some(input.len() - rest.len());
                }
            }
        }
    }
    None
}

/// Returns `input` as a new `String` without removed code points (see
/// [`is_removed`]). `input` is bytes that may not be valid UTF-8; it is
/// decoded as UTF-8 only. Invalid UTF-8 becomes U+FFFD, one per maximal
/// invalid subsequence, so the result is always valid UTF-8 free of C0, DEL
/// and C1 controls.
pub fn sanitize(input: &[u8]) -> String {
    // The output is at most 3 times the input (one invalid byte becomes the
    // 3-byte U+FFFD); a reallocation is therefore bounded, and the cap on the
    // value's byte length is Task A6.
    let mut out = String::with_capacity(input.len());
    sanitize_into(input, &mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // 이것을 실패시키는 것: C0·DEL·C1·양방향·보이지 않는 서식 문자 중 하나를 남기는 것,
    // ZWJ·variation selector를 지우는 것.
    #[test]
    fn removes_controls_and_format_keeps_zwj_and_vs() {
        let cases: &[(&[u8], &str)] = &[
            (b"a\x1b]0;x\x07b", "a]0;xb"),
            (b"a\x7fb", "ab"),
            ("a\u{85}b\u{9b}c".as_bytes(), "abc"),
            (
                "a\u{202E}b\u{2066}c\u{2069}d\u{200E}e\u{200F}f\u{061C}g".as_bytes(),
                "abcdefg",
            ),
            ("a\u{200B}b\u{2060}c\u{FEFF}d\u{00AD}e".as_bytes(), "abcde"),
            ("a\u{2028}b\u{2029}c".as_bytes(), "abc"),
            (b"a\nb\rc\td\x00e\x01f\x02g\x1fh\x1ei", "abcdefghi"),
            (
                "\u{1F3F3}\u{FE0F}\u{200D}\u{1F308}".as_bytes(),
                "\u{1F3F3}\u{FE0F}\u{200D}\u{1F308}",
            ),
            ("\u{2764}\u{FE0E}".as_bytes(), "\u{2764}\u{FE0E}"),
        ];
        for (input, want) in cases {
            assert_eq!(sanitize(input), *want, "{input:?}");
        }
    }

    // 이것을 실패시키는 것: 잘못된 UTF-8을 버리거나, 최대 잘못된 부분열마다 하나가 아닌 수의 U+FFFD를 넣는 것.
    #[test]
    fn invalid_utf8_becomes_one_replacement_per_maximal_subpart() {
        assert_eq!(sanitize(b"a\xff\xfeb"), "a\u{FFFD}\u{FFFD}b");
        assert_eq!(sanitize(b"a\xe2\x82b"), "a\u{FFFD}b");
        assert_eq!(sanitize(b"\xf0\x9f\x98"), "\u{FFFD}");
    }

    // 이것을 실패시키는 것: sanitize_into가 out을 비우거나 덮어쓰는 것(덧붙이기 계약).
    #[test]
    fn sanitize_into_appends_to_existing_out() {
        let mut out = String::from("pre");
        sanitize_into(b"a\x1bb\xffc", &mut out);
        assert_eq!(out, "preab\u{FFFD}c");
        sanitize_into("\u{202E}x".as_bytes(), &mut out);
        assert_eq!(out, "preab\u{FFFD}cx");
    }

    // 이것을 실패시키는 것: 상한을 넘은 뒤에도 읽기를 계속하는 것(1 MiB를 끝까지 정제하거나 끝까지 UTF-8 검사), 상한을 넘기 전에 멈추는 것,
    // 멈춘 결과가 전체 결과의 앞부분이 아닌 것, 멈췄는지를 잘못 알리는 것.
    #[test]
    fn capped_sanitize_stops_past_the_limit() {
        let mut out = String::from("pre");
        let read = sanitize_into_capped(&alloc::vec![b'a'; 1 << 20], &mut out, 1040);
        // ASCII keeps one byte per input byte: it kept 1,041 bytes and read
        // only to the end of that window, not the whole 1 MiB.
        assert_eq!(out.len(), 3 + 1041);
        assert_eq!(read, Some(1041usize.next_multiple_of(WINDOW)));
        let mut out = String::new();
        let read = sanitize_into_capped(&alloc::vec![0x1b; 1 << 20], &mut out, 16);
        assert_eq!(read, None);
        assert_eq!(out, "");
        let inputs: [&[u8]; 3] = [
            b"ab\x1bc\xffd",
            "\u{AC00}x\u{202E}y\u{1F600}".as_bytes(),
            b"",
        ];
        for input in inputs {
            let full = sanitize(input);
            for limit in 0..=full.len() + 1 {
                let mut out = String::new();
                let stopped = sanitize_into_capped(input, &mut out, limit);
                assert!(full.starts_with(&out), "{input:?} {limit}");
                if stopped.is_some() {
                    let last = out.chars().last().unwrap().len_utf8();
                    assert!(
                        out.len() > limit && out.len() - last <= limit,
                        "{input:?} {limit}"
                    );
                } else {
                    assert_eq!(out, full, "{input:?} {limit}");
                    assert!(out.len() <= limit, "{input:?} {limit}");
                }
            }
        }
    }

    // 이것을 실패시키는 것: 창(WINDOW) 경계에서 UTF-8 sequence를 가르는 것(경계에 걸친 글자가 U+FFFD 둘이 되거나,
    // 잘못된 부분열의 U+FFFD 개수가 달라지는 것), 경계를 고르는 조건을 빼는 것.
    #[test]
    fn capped_sanitize_decodes_across_windows_like_the_whole() {
        let zoo: [&[u8]; 12] = [
            b"\xf0\x9f\x98\x80",
            b"\xe2\x82\xac",
            b"\xc3\xa9",
            b"\xf0\x9f\x98",
            b"\xe2\x82",
            b"\x80\x80\x80\x80\x80",
            b"\xed\xa0\x80",
            b"\xf4\x90\x80\x80",
            b"\xff",
            b"\xc0\x80",
            b"\xe0\x80\xaf",
            b"\x1b[0m",
        ];
        let check = |input: &[u8]| {
            let mut out = String::new();
            assert_eq!(sanitize_into_capped(input, &mut out, usize::MAX), None);
            assert_eq!(out, sanitize(input), "{input:02x?}");
        };
        for off in WINDOW - 6..=WINDOW + 1 {
            let pre = alloc::vec![b'a'; off];
            for z in zoo {
                check(&[&pre[..], z, b"z"].concat());
                check(&[&pre[..], z].concat());
            }
            check(&[&pre[..], &zoo.concat(), &zoo.concat()].concat());
        }
        for v in 0..=0xFFFFu16 {
            check(&[&[b'a'; WINDOW - 1][..], &v.to_be_bytes(), b"\xbf\xbf"].concat());
        }
    }

    // 이것을 실패시키는 것: overlong·서로게이트·범위 밖·맨 8비트 C1 바이트가 제어 문자나
    // 다른 개수의 U+FFFD로 살아나는 것.
    #[test]
    fn malformed_encodings_never_yield_controls() {
        let cases: &[(&[u8], &str)] = &[
            (b"a\xc0\x9bb", "a\u{FFFD}\u{FFFD}b"),
            (b"a\xc0\x80b", "a\u{FFFD}\u{FFFD}b"),
            (b"a\xed\xa0\x80b", "a\u{FFFD}\u{FFFD}\u{FFFD}b"),
            (b"a\xf4\x90\x80\x80b", "a\u{FFFD}\u{FFFD}\u{FFFD}\u{FFFD}b"),
            (b"a\xf5b", "a\u{FFFD}b"),
            (b"a\x9b31mb", "a\u{FFFD}31mb"),
        ];
        for (input, want) in cases {
            let got = sanitize(input);
            assert_eq!(got, *want, "{input:?}");
        }
    }

    // 독립 술어(is_removed를 쓰지 않음)로, 한 바이트 전부와 두 바이트 전부의 출력에
    // C0·DEL·C1이 하나도 없음을 확인한다. 두 바이트 입력은 U+0080–07FF의 C1을 덮는다.
    // 이것을 실패시키는 것: is_removed의 C0·DEL·C1 범위가 줄어드는 것(예: 0x7F..=0x9E).
    #[test]
    fn no_control_survives_any_one_or_two_byte_input() {
        let is_control = |c: char| (c as u32) < 0x20 || (0x7F..=0x9F).contains(&(c as u32));
        for b in 0..=0xFFu8 {
            let got = sanitize(&[b]);
            assert!(!got.chars().any(is_control), "input [{b:#04x}] -> {got:?}");
        }
        for v in 0..=0xFFFFu16 {
            let input = v.to_be_bytes();
            let got = sanitize(&input);
            assert!(
                !got.chars().any(is_control),
                "input {input:02x?} -> {got:?}"
            );
        }
    }

    // 이것을 실패시키는 것: 표 탐색이 범위 끝 값을 놓치는 것(이진 탐색 경계).
    #[test]
    fn range_edges() {
        assert!(is_removed('\u{E0020}') && is_removed('\u{E007F}'));
        assert!(!is_removed('\u{E0080}') && !is_removed('\u{200D}'));
        assert!(is_removed('\u{0600}') && is_removed('\u{0605}') && !is_removed('\u{0606}'));
    }

    // 이것을 실패시키는 것: 생성기(KEEP_CF)나 표가 바뀌어 아래 코드 포인트 중 하나가 빠지거나
    // ZWJ·FE0F가 들어가는 것, 표 크기가 171에서 벗어나는 것.
    #[test]
    fn removed_format_table_meaning() {
        let must: &[(u32, u32)] = &[
            (0x202A, 0x202E),
            (0x2066, 0x2069),
            (0x200E, 0x200F),
            (0x061C, 0x061C),
            (0xE0001, 0xE0001),
            (0xE0020, 0xE007F),
            (0xFEFF, 0xFEFF),
            (0x00AD, 0x00AD),
            (0x2028, 0x2029),
            (0xFFF9, 0xFFF9),
            (0x200B, 0x200B),
        ];
        for &(lo, hi) in must {
            for cp in lo..=hi {
                assert!(in_ranges(REMOVED_FORMAT, cp), "U+{cp:04X} must be removed");
            }
        }
        for cp in [0x200D, 0xFE0F, 0xFE0E] {
            assert!(!in_ranges(REMOVED_FORMAT, cp), "U+{cp:04X} must stay");
        }
        let count: u32 = REMOVED_FORMAT.iter().map(|&(lo, hi)| hi - lo + 1).sum();
        assert_eq!(count, 171);
    }

    // 이진 탐색의 전제: 범위가 정렬되고 서로 겹치지 않는다.
    // 이것을 실패시키는 것: 표의 두 줄 순서를 바꾸거나 범위를 겹치게 하는 것.
    #[test]
    fn removed_format_table_is_sorted_and_disjoint() {
        for w in REMOVED_FORMAT.windows(2) {
            assert!(w[0].0 <= w[0].1 && w[0].1 < w[1].0, "{w:?}");
        }
    }
}
