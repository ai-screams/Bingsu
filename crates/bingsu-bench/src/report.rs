//! One JSON object per line (one row of a cost matrix each); the M1
//! results document reads them.
use crate::stats::Summary;

/// JSON string contents for `s`: quote, backslash and control characters
/// escaped (RFC 8259 section 7); everything else passes through.
fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if u32::from(c) < 0x20 => out.push_str(&format!("\\u{:04x}", u32::from(c))),
            c => out.push(c),
        }
    }
    out
}

/// `matrix`, `row` and the `extra` keys are escaped as JSON strings. Each
/// `extra` value is a JSON fragment inserted as is (a number, or a string
/// the caller already quoted), so the caller owns its validity.
pub fn json_line(matrix: &str, row: &str, s: &Summary, extra: &[(&str, String)]) -> String {
    let mut out = format!(
        r#"{{"matrix":"{}","row":"{}","os":"{}","arch":"{}","n":{},"median_ns":{},"p95_ns":{},"min_ns":{},"max_ns":{}"#,
        escape(matrix),
        escape(row),
        std::env::consts::OS,
        std::env::consts::ARCH,
        s.n,
        s.median_ns,
        s.p95_ns,
        s.min_ns,
        s.max_ns
    );
    for (k, v) in extra {
        out.push_str(&format!(r#","{}":{v}"#, escape(k)));
    }
    out.push('}');
    out
}

/// A row that could not be measured: `na` carries the reason. All three
/// strings are escaped like `json_line`'s.
pub fn json_na(matrix: &str, row: &str, why: &str) -> String {
    format!(
        r#"{{"matrix":"{}","row":"{}","os":"{}","arch":"{}","na":"{}"}}"#,
        escape(matrix),
        escape(row),
        std::env::consts::OS,
        std::env::consts::ARCH,
        escape(why)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn line_shape() {
        let s = Summary {
            n: 2,
            median_ns: 1,
            p95_ns: 2,
            min_ns: 1,
            max_ns: 2,
        };
        let l = json_line(
            "spawn",
            "bare/dedicated",
            &s,
            &[("binary_bytes", "123".into())],
        );
        assert!(l.starts_with(r#"{"matrix":"spawn","row":"bare/dedicated""#));
        assert!(l.ends_with(r#""binary_bytes":123}"#));
    }

    // 이것을 실패시키는 것: 따옴표·역슬래시·개행·제어 문자 중 하나라도 escape하지 않는 것, 또는 key를 escape하지 않는 것.
    #[test]
    fn strings_are_escaped() {
        assert_eq!(
            escape("a\"b\\c\nd\re\tf\u{1}g\u{1f}é"),
            r#"a\"b\\c\nd\re\tf\u0001g\u001fé"#
        );
        let s = Summary {
            n: 1,
            median_ns: 1,
            p95_ns: 1,
            min_ns: 1,
            max_ns: 1,
        };
        let l = json_line("m\"", "r\n", &s, &[("k\\", "1".into())]);
        assert!(l.starts_with(r#"{"matrix":"m\"","row":"r\n","#), "{l}");
        assert!(l.ends_with(r#","k\\":1}"#), "{l}");
    }

    // 이것을 실패시키는 것: na 이유(또는 matrix·row)를 escape하지 않는 것, os·arch를 빼는 것.
    #[test]
    fn na_line_is_escaped() {
        let l = json_na("spawn", "r\"", "clone3: \"x\"\\y\nz");
        assert_eq!(
            l,
            format!(
                r#"{{"matrix":"spawn","row":"r\"","os":"{}","arch":"{}","na":"clone3: \"x\"\\y\nz"}}"#,
                std::env::consts::OS,
                std::env::consts::ARCH
            )
        );
    }
}
