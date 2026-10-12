//! Color notations accepted for overrides (spec section 2 "색 token과 색
//! 표기"): `oklch(L C H)`, `#rrggbb`, a 256-color number and `term.ansi.N`.
//! Parsed once when the config is compiled, never per prompt.
use super::math::{Oklch, Srgb8};

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum ColorSpec {
    Oklch(Oklch),
    Rgb(Srgb8),
    /// 16..=255 from the xterm palette; 0..=15 are written `term.ansi.N`.
    Index256(u8),
    /// A slot of the terminal's 16-color scheme.
    Ansi(u8),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ColorError {
    Syntax,
    OutOfRange,
}

/// `[0-9]+ ( "." [0-9]+ )?`, at most 12 characters; no sign, exponent,
/// `inf` or `nan`.
fn number(s: &str) -> Result<f64, ColorError> {
    let (int, frac) = s.split_once('.').unwrap_or((s, "0"));
    let digits = |t: &str| !t.is_empty() && t.bytes().all(|b| b.is_ascii_digit());
    if s.len() > 12 || !digits(int) || !digits(frac) {
        return Err(ColorError::Syntax);
    }
    s.parse::<f64>().map_err(|_| ColorError::Syntax)
}

pub fn parse_color(s: &str) -> Result<ColorSpec, ColorError> {
    if let Some(hex) = s.strip_prefix('#') {
        if hex.len() != 6 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(ColorError::Syntax);
        }
        let byte =
            |i: usize| u8::from_str_radix(&hex[i..i + 2], 16).map_err(|_| ColorError::Syntax);
        return Ok(ColorSpec::Rgb(Srgb8 {
            r: byte(0)?,
            g: byte(2)?,
            b: byte(4)?,
        }));
    }
    if let Some(n) = s.strip_prefix("term.ansi.") {
        // `u8::parse` accepts a leading `+`, so the digits are checked first.
        if n.is_empty()
            || !n.bytes().all(|b| b.is_ascii_digit())
            || (n.len() > 1 && n.starts_with('0'))
        {
            return Err(ColorError::Syntax);
        }
        return match n.parse::<u8>() {
            Ok(v) if v < 16 => Ok(ColorSpec::Ansi(v)),
            // Valid digits that are too large (16..=255 or overflow).
            _ => Err(ColorError::OutOfRange),
        };
    }
    if let Some(args) = s.strip_prefix("oklch(").and_then(|r| r.strip_suffix(')')) {
        let mut it = args.split(' ').filter(|t| !t.is_empty());
        let (Some(l), Some(c), Some(h), None) = (it.next(), it.next(), it.next(), it.next()) else {
            return Err(ColorError::Syntax);
        };
        let l = match l.strip_suffix('%') {
            Some(p) => number(p)? / 100.0,
            None => number(l)?,
        };
        let (c, h) = (number(c)?, number(h)?);
        if l > 1.0 || c > 0.5 || h > 360.0 {
            return Err(ColorError::OutOfRange);
        }
        return Ok(ColorSpec::Oklch(Oklch { l, c, h }));
    }
    if !s.is_empty()
        && s.len() <= 3
        && s.bytes().all(|b| b.is_ascii_digit())
        && (s == "0" || !s.starts_with('0'))
    {
        return match s.parse::<u16>() {
            Ok(v @ 16..=255) => Ok(ColorSpec::Index256(v as u8)),
            Ok(_) => Err(ColorError::OutOfRange),
            Err(_) => Err(ColorError::Syntax),
        };
    }
    Err(ColorError::Syntax)
}

#[cfg(test)]
mod tests {
    use super::*;

    // 이것을 실패시키는 것: 네 표기 중 하나를 못 읽거나, 범위 밖·지수·부호·앞자리 0을 받는 것.
    #[test]
    fn notations() {
        assert_eq!(
            parse_color("#8FB8f0"),
            Ok(ColorSpec::Rgb(Srgb8 {
                r: 0x8f,
                g: 0xb8,
                b: 0xf0
            }))
        );
        assert_eq!(
            parse_color("oklch(0.78 0.12 60)"),
            Ok(ColorSpec::Oklch(Oklch {
                l: 0.78,
                c: 0.12,
                h: 60.0
            }))
        );
        assert_eq!(
            parse_color("oklch(78% 0.12 60)"),
            Ok(ColorSpec::Oklch(Oklch {
                l: 0.78,
                c: 0.12,
                h: 60.0
            }))
        );
        assert_eq!(parse_color("208"), Ok(ColorSpec::Index256(208)));
        assert_eq!(parse_color("term.ansi.0"), Ok(ColorSpec::Ansi(0)));
        assert_eq!(parse_color("term.ansi.15"), Ok(ColorSpec::Ansi(15)));
        for (bad, e) in [
            ("#8fb8f", ColorError::Syntax),
            ("#8fb8fg", ColorError::Syntax),
            ("oklch(0.7 0.1)", ColorError::Syntax),
            ("oklch(1e0 0.1 2)", ColorError::Syntax),
            ("oklch(-0.1 0.1 2)", ColorError::Syntax),
            ("oklch(1.2 0.1 2)", ColorError::OutOfRange),
            ("oklch(0.5 0.1 361)", ColorError::OutOfRange),
            ("15", ColorError::OutOfRange),
            ("256", ColorError::OutOfRange),
            ("016", ColorError::Syntax),
            ("term.ansi.16", ColorError::OutOfRange),
            ("term.ansi.01", ColorError::Syntax),
            ("oklch(nan 0.1 2)", ColorError::Syntax),
            ("blue", ColorError::Syntax),
        ] {
            assert_eq!(parse_color(bad), Err(e), "{bad}");
        }
    }

    // 이것을 실패시키는 것: 16진 길이·문자 검사를 푸는 것(`from_str_radix`는 `+`를 받고, 비ASCII는 슬라이스에서 패닉한다).
    #[test]
    fn hex_rejections() {
        for bad in ["#", "#8fb8f00", "#+1+2+3", "#ééé", "8fb8f0", "#8fb8f0 "] {
            assert_eq!(parse_color(bad), Err(ColorError::Syntax), "{bad}");
        }
        assert_eq!(
            parse_color("#000000"),
            Ok(ColorSpec::Rgb(Srgb8 { r: 0, g: 0, b: 0 }))
        );
        assert_eq!(
            parse_color("#ffffff"),
            Ok(ColorSpec::Rgb(Srgb8 {
                r: 255,
                g: 255,
                b: 255
            }))
        );
    }

    // 이것을 실패시키는 것: 경계(포함/미포함)와 l·c·h 각각의 범위 검사, `||`를 `&&`로 바꾸는 것.
    #[test]
    fn oklch_bounds_and_shape() {
        assert_eq!(
            parse_color("oklch(1 0.5 360)"),
            Ok(ColorSpec::Oklch(Oklch {
                l: 1.0,
                c: 0.5,
                h: 360.0
            }))
        );
        assert_eq!(
            parse_color("oklch(0 0 0)"),
            Ok(ColorSpec::Oklch(Oklch {
                l: 0.0,
                c: 0.0,
                h: 0.0
            }))
        );
        assert_eq!(
            parse_color("oklch(100% 0.1 2)"),
            Ok(ColorSpec::Oklch(Oklch {
                l: 1.0,
                c: 0.1,
                h: 2.0
            }))
        );
        for bad in [
            "oklch(1.01 0.1 2)",
            "oklch(101% 0.1 2)",
            "oklch(0.5 0.51 2)",
            "oklch(0.5 0.1 360.5)",
        ] {
            assert_eq!(parse_color(bad), Err(ColorError::OutOfRange), "{bad}");
        }
        for bad in [
            "oklch(0.5 0.1 2 3)",
            "oklch(0.5 0.1 +2)",
            "oklch(0.5 .1 2)",
            "oklch(0.5 1. 2)",
            "oklch(0.5 0.1 2.2.2)",
            "oklch(inf 0.1 2)",
            "oklch(% 0.1 2)",
            "oklch(0.00000000001 0.1 2)",
            "oklch(0.5 0.1 2",
            "oklch()",
            "",
        ] {
            assert_eq!(parse_color(bad), Err(ColorError::Syntax), "{bad}");
        }
        // 인자 사이의 공백은 몇 칸이든, 앞뒤 공백도 받는다.
        assert_eq!(
            parse_color("oklch( 0.5   0.1  2 )"),
            Ok(ColorSpec::Oklch(Oklch {
                l: 0.5,
                c: 0.1,
                h: 2.0
            }))
        );
        // 12자까지는 받는다.
        assert_eq!(
            parse_color("oklch(0.0000000001 0.1 2)"),
            Ok(ColorSpec::Oklch(Oklch {
                l: 1e-10,
                c: 0.1,
                h: 2.0
            }))
        );
    }

    // 이것을 실패시키는 것: 번호 경계(16, 255, 0), 자릿수 제한, `term.ansi.`의 부호·빈 값·큰 값 처리.
    #[test]
    fn number_and_ansi_edges() {
        assert_eq!(parse_color("16"), Ok(ColorSpec::Index256(16)));
        assert_eq!(parse_color("255"), Ok(ColorSpec::Index256(255)));
        assert_eq!(parse_color("0"), Err(ColorError::OutOfRange));
        assert_eq!(parse_color("1000"), Err(ColorError::Syntax));
        assert_eq!(parse_color("+16"), Err(ColorError::Syntax));
        assert_eq!(parse_color("term.ansi.9"), Ok(ColorSpec::Ansi(9)));
        for bad in [
            "term.ansi.",
            "term.ansi.+1",
            "term.ansi.-1",
            "term.ansi.x",
            "term.ansi.00",
            "term.ansi.1.0",
        ] {
            assert_eq!(parse_color(bad), Err(ColorError::Syntax), "{bad}");
        }
        for bad in [
            "term.ansi.16",
            "term.ansi.255",
            "term.ansi.256",
            "term.ansi.99999999999",
        ] {
            assert_eq!(parse_color(bad), Err(ColorError::OutOfRange), "{bad}");
        }
    }
}
