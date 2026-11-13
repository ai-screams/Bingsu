//! The terminal's answer to the background color query `OSC 11 ; ?`
//! (`bingsu setup`). The bytes come from a terminal, or from whatever sits
//! on the other end of the line, so they are not trusted: one fixed shape,
//! a length cap, and anything else is no answer.
use crate::color::math::{Srgb8, luminance};

/// The longest reply read: `ESC ] 11 ; rgb:` and three four-digit channels
/// are 24 bytes; 64 leaves room for the terminator and nothing else.
pub const REPLY_MAX: usize = 64;

/// The luminance at which black and white text have the same contrast
/// (WCAG): a darker background is `dark`, a lighter one `light`.
pub const LIGHT_LUMINANCE: f64 = 0.179;

/// Reads `ESC ] 11 ; rgb:R/G/B` ended by BEL or `ESC \`, each channel one
/// to four hex digits (so a reply is at most 31 bytes). Nothing may follow
/// the terminator and nothing may precede the reply: a prefix such as
/// typed-ahead input makes it no answer.
pub fn parse_osc11(reply: &[u8]) -> Option<Srgb8> {
    let body = reply.strip_prefix(b"\x1b]11;rgb:")?;
    let body = body
        .strip_suffix(b"\x07")
        .or_else(|| body.strip_suffix(b"\x1b\\"))?;
    let mut parts = body.split(|&b| b == b'/');
    let r = channel(parts.next()?)?;
    let g = channel(parts.next()?)?;
    let b = channel(parts.next()?)?;
    if parts.next().is_some() {
        return None;
    }
    Some(Srgb8 { r, g, b })
}

/// The reply inside `buf`, which may start with typed-ahead input: from the
/// first `ESC ] 11 ;` through the first BEL or `ESC \\`. `None` while the
/// terminator has not arrived yet (or the introducer never did).
pub fn find_reply(buf: &[u8]) -> Option<&[u8]> {
    const START: &[u8] = b"\x1b]11;";
    let from = buf.windows(START.len()).position(|w| w == START)?;
    let rest = &buf[from..];
    let end = rest
        .iter()
        .enumerate()
        .skip(START.len())
        .find_map(|(i, &b)| match b {
            0x07 => Some(i + 1),
            0x5c if rest[i - 1] == 0x1b => Some(i + 1),
            _ => None,
        })?;
    Some(&rest[..end])
}

/// One to four hex digits scaled to 0–255, rounded to nearest.
fn channel(digits: &[u8]) -> Option<u8> {
    if digits.is_empty() || digits.len() > 4 {
        return None;
    }
    let mut v: u32 = 0;
    for &d in digits {
        v = v * 16 + char::from(d).to_digit(16)?;
    }
    let max = (1u32 << (4 * digits.len() as u32)) - 1;
    Some(((v * 255 + max / 2) / max) as u8)
}

pub fn is_light(background: Srgb8) -> bool {
    luminance(background) > LIGHT_LUMINANCE
}

#[cfg(test)]
mod tests {
    use super::*;

    const fn c(r: u8, g: u8, b: u8) -> Srgb8 {
        Srgb8 { r, g, b }
    }

    // 이것을 실패시키는 것: 자릿수별 환산(1–4자리), BEL·ST 종결, 앞뒤 군더더기·길이 상한·16진수 아닌 글자·
    // 채널 수 오류를 받아들이는 것.
    #[test]
    fn replies_are_read_strictly() {
        let ok: [(&[u8], Srgb8); 6] = [
            (b"\x1b]11;rgb:0000/0000/0000\x07", c(0, 0, 0)),
            (b"\x1b]11;rgb:ffff/ffff/ffff\x1b\\", c(255, 255, 255)),
            (b"\x1b]11;rgb:f/0/8\x07", c(255, 0, 136)),
            (b"\x1b]11;rgb:ff/80/00\x07", c(255, 128, 0)),
            (b"\x1b]11;rgb:fff/000/800\x07", c(255, 0, 128)),
            (b"\x1b]11;rgb:1e1e/1e1e/2e2e\x1b\\", c(30, 30, 46)),
        ];
        for (reply, want) in ok {
            assert_eq!(parse_osc11(reply), Some(want), "{reply:?}");
        }
        let bad: [&[u8]; 12] = [
            b"",
            b"\x1b]11;rgb:0000/0000/0000",
            b"\x1b]11;rgb:0000/0000/0000\x07x",
            b"x\x1b]11;rgb:0000/0000/0000\x07",
            b"\x1b]11;rgb:00000/0000/0000\x07",
            b"\x1b]11;rgb:/0000/0000\x07",
            b"\x1b]11;rgb:0000/0000\x07",
            b"\x1b]11;rgb:0000/0000/0000/0000\x07",
            b"\x1b]11;rgb:zz00/0000/0000\x07",
            b"\x1b]11;rgb:+f00/0000/0000\x07",
            b"\x1b]11;#ffffff\x07",
            b"\x1b]10;rgb:0000/0000/0000\x07",
        ];
        for reply in bad {
            assert_eq!(parse_osc11(reply), None, "{reply:?}");
        }
        let long = [
            b"\x1b]11;rgb:0000/0000/0000".as_slice(),
            &[b'0'; 64],
            b"\x07",
        ]
        .concat();
        assert_eq!(parse_osc11(&long), None);
    }

    // 이것을 실패시키는 것: 앞에 붙은 입력(미리 친 글자)을 응답으로 치는 것, 종결자가 오기 전에 잘라 내는 것,
    // 첫 종결자를 넘어 뒤 입력까지 응답에 넣는 것.
    #[test]
    fn the_reply_is_found_inside_typed_ahead_input() {
        let r = b"\x1b]11;rgb:0000/0000/0000\x1b\\";
        assert_eq!(
            find_reply(&[b"ls\r".as_slice(), r, b"x"].concat()),
            Some(&r[..])
        );
        let bel = b"\x1b]11;rgb:f/f/f\x07";
        assert_eq!(find_reply(&[bel.as_slice(), r].concat()), Some(&bel[..]));
        assert_eq!(find_reply(b"\x1b]11;rgb:0000/00"), None);
        assert_eq!(find_reply(b"\x1b]11;rgb:0000/0000/0000\x1b"), None);
        // A backslash that is not the second byte of ST does not end the reply.
        let odd = b"\x1b]11;rgb:\\x/0\x07";
        assert_eq!(find_reply(odd), Some(&odd[..]));
        assert_eq!(find_reply(b"abc"), None);
        assert_eq!(find_reply(b""), None);
    }

    // 이것을 실패시키는 것: 밝기 경계를 뒤집거나(어두운 배경을 light로), 임계값을 바꾸는 것.
    #[test]
    fn light_and_dark_backgrounds() {
        assert!(!is_light(c(0, 0, 0)));
        assert!(!is_light(c(30, 30, 46)));
        assert!(is_light(c(255, 255, 255)));
        assert!(is_light(c(239, 241, 245)));
        // Mid gray (sRGB 118 is about 0.18 linear) sits on the line.
        assert!(!is_light(c(117, 117, 117)));
        assert!(is_light(c(119, 119, 119)));
    }
}
