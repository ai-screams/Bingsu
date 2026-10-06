//! One JSON object per line; bench/summarize.py reads them.
use crate::stats::Summary;

pub fn json_line(matrix: &str, row: &str, s: &Summary, extra: &[(&str, String)]) -> String {
    let mut out = format!(
        r#"{{"matrix":"{matrix}","row":"{row}","os":"{}","arch":"{}","n":{},"median_ns":{},"p95_ns":{},"min_ns":{},"max_ns":{}"#,
        std::env::consts::OS,
        std::env::consts::ARCH,
        s.n,
        s.median_ns,
        s.p95_ns,
        s.min_ns,
        s.max_ns
    );
    for (k, v) in extra {
        out.push_str(&format!(r#","{k}":{v}"#));
    }
    out.push('}');
    out
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
}
