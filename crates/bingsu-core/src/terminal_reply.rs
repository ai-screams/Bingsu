//! A terminal's cursor position report (`bingsu doctor` measures how many
//! cells a character moves the cursor by). The bytes come from a terminal, or
//! from whatever sits on the other end of the line, so they are not trusted:
//! one fixed shape, a length cap, and anything else is no answer.

/// A report is `ESC [ row ; col R` with up to five digits each: 14 bytes at
/// most. The reader that collects the bytes stops at this many (32 leaves room
/// for nothing else); the grammar below rejects anything longer anyway.
pub const CPR_MAX: usize = 32;

/// The report `ESC [ row ; col R` as `(row, column)`, both at least 1.
/// Nothing may precede or follow it; a private form (`ESC [ ? ...`), another
/// final byte, a missing or extra number, a sign or an empty number is no
/// answer.
pub fn parse_cpr(reply: &[u8]) -> Option<(u16, u16)> {
    let body = reply.strip_prefix(b"\x1b[")?.strip_suffix(b"R")?;
    let mut parts = body.split(|&b| b == b';');
    let row = number(parts.next()?)?;
    let col = number(parts.next()?)?;
    if parts.next().is_some() {
        return None;
    }
    Some((row, col))
}

/// One to five decimal digits, at least 1.
fn number(digits: &[u8]) -> Option<u16> {
    if digits.is_empty() || digits.len() > 5 || !digits.iter().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let mut v: u32 = 0;
    for &d in digits {
        v = v * 10 + u32::from(d - b'0');
    }
    u16::try_from(v).ok().filter(|&v| v >= 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    // 이것을 실패시키는 것: 자릿수 상한(1–5)·0 값·부호·빈 숫자·사설 형식(`?`)·다른 최종 바이트·앞뒤 군더더기·
    // 길이 상한·u16을 넘는 값을 받아들이는 것, 정상 보고를 못 읽는 것.
    #[test]
    fn reports_are_read_strictly() {
        assert_eq!(parse_cpr(b"\x1b[1;1R"), Some((1, 1)));
        assert_eq!(parse_cpr(b"\x1b[24;80R"), Some((24, 80)));
        assert_eq!(parse_cpr(b"\x1b[65535;65535R"), Some((65535, 65535)));
        let bad: [&[u8]; 15] = [
            b"",
            b"\x1b[1;1",
            b"\x1b[1;1R\x1b",
            b"x\x1b[1;1R",
            b"\x1b[?1;1R",
            b"\x1b[1;1S",
            b"\x1b[1R",
            b"\x1b[1;2;3R",
            b"\x1b[;1R",
            b"\x1b[1;R",
            b"\x1b[0;1R",
            b"\x1b[1;+2R",
            b"\x1b[123456;1R",
            b"\x1b[65536;1R",
            b"\x1b[000001;1R",
        ];
        for r in bad {
            assert_eq!(parse_cpr(r), None, "{r:?}");
        }
        let long = [b"\x1b[1;".as_slice(), &[b'1'; 40], b"R"].concat();
        assert_eq!(parse_cpr(&long), None);
        assert!(long.len() > CPR_MAX);
    }
}
