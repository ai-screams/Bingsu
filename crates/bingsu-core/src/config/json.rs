//! JSON config files (RFC 8259, strict) into the same tree as TOML (spec
//! section 2 "합치기 규칙" 4: one model, TOML the source format). Every
//! value keeps its byte span. The limits are the TOML ones: the file size is
//! checked before this runs, and nesting counts each `{` or `[` below the top
//! object as one level, so a value at the top is depth 1 and an object or
//! array deeper than `NESTING_MAX` is refused before it is entered.
//!
//! Refused, beyond the grammar: duplicate keys (compared after escapes are
//! decoded), `null` (TOML has no such value), a top value that is not an
//! object, a byte order mark, numbers that do not fit (integers outside i64,
//! floats that overflow), and anything after the top object. The top
//! `$schema` key is left out by `config::source` for both formats.
use crate::config::tree::{
    Entry, NESTING_MAX, Node, Span, SyntaxError, SyntaxErrorKind, Table, Value,
};
use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

/// Parses one JSON file whose size and encoding were already checked.
/// Stops at the first error.
pub(crate) fn parse(text: &str) -> Result<Table, SyntaxError> {
    let mut p = Parser {
        bytes: text.as_bytes(),
        text,
        at: 0,
    };
    if text.starts_with('\u{feff}') {
        return Err(p.error(0, 3, "a byte order mark is not allowed"));
    }
    p.skip_space();
    if p.peek() != Some(b'{') {
        let end = p.token_end();
        return Err(p.error(p.at, end, "the file must hold one object"));
    }
    let table = p.object(0)?;
    p.skip_space();
    if p.at < p.bytes.len() {
        let end = p.token_end();
        return Err(p.error(p.at, end, "nothing may follow the object"));
    }
    Ok(table)
}

struct Parser<'a> {
    bytes: &'a [u8],
    text: &'a str,
    at: usize,
}

impl Parser<'_> {
    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.at).copied()
    }

    fn error(&self, start: usize, end: usize, message: &str) -> SyntaxError {
        self.error_span(
            Span {
                start: start as u32,
                end: end.max(start) as u32,
            },
            message,
        )
    }

    fn error_span(&self, span: Span, message: &str) -> SyntaxError {
        SyntaxError {
            span,
            kind: SyntaxErrorKind::Json(String::from(message)),
        }
    }

    /// The end of the token at `self.at`, for an error's range: one
    /// character, or the end of the file.
    fn token_end(&self) -> usize {
        match self.text[self.at.min(self.text.len())..].chars().next() {
            Some(c) => self.at + c.len_utf8(),
            None => self.at,
        }
    }

    /// RFC 8259 whitespace only: space, tab, line feed, carriage return.
    fn skip_space(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.at += 1;
        }
    }

    fn expect(&mut self, byte: u8, what: &str) -> Result<(), SyntaxError> {
        self.skip_space();
        if self.peek() == Some(byte) {
            self.at += 1;
            Ok(())
        } else {
            let end = self.token_end();
            Err(self.error(self.at, end, what))
        }
    }

    /// `{ … }` at `self.at`. `depth` is the object's own depth (the top
    /// object is 0); its values are one deeper.
    fn object(&mut self, depth: u32) -> Result<Table, SyntaxError> {
        self.at += 1; // `{`
        let mut entries = Vec::new();
        // Decoded key -> where it was first written, for duplicates.
        let mut seen: BTreeMap<String, Span> = BTreeMap::new();
        self.skip_space();
        if self.peek() == Some(b'}') {
            self.at += 1;
            return Ok(Table { entries });
        }
        loop {
            self.skip_space();
            if self.peek() != Some(b'"') {
                let end = self.token_end();
                return Err(self.error(self.at, end, "expected a key in double quotes"));
            }
            let key_start = self.at;
            let key = self.string()?;
            let key_span = Span {
                start: key_start as u32,
                end: self.at as u32,
            };
            if let Some(first) = seen.get(&key) {
                return Err(self.error_span(
                    key_span,
                    &format!(
                        "duplicate key `{key}` (first written at line {})",
                        self.line_of(first.start)
                    ),
                ));
            }
            seen.insert(key.clone(), key_span);
            self.expect(b':', "expected `:` after the key")?;
            let node = self.value(depth + 1)?;
            entries.push(Entry {
                key,
                key_span,
                node,
            });
            self.skip_space();
            match self.peek() {
                Some(b',') => self.at += 1,
                Some(b'}') => {
                    self.at += 1;
                    return Ok(Table { entries });
                }
                _ => {
                    let end = self.token_end();
                    return Err(self.error(self.at, end, "expected `,` or `}`"));
                }
            }
        }
    }

    fn line_of(&self, offset: u32) -> usize {
        1 + self.bytes[..offset as usize]
            .iter()
            .filter(|&&b| b == b'\n')
            .count()
    }

    /// One value at depth `depth` (a value of the top object is 1).
    fn value(&mut self, depth: u32) -> Result<Node, SyntaxError> {
        self.skip_space();
        let start = self.at;
        let value = match self.peek() {
            Some(open @ (b'{' | b'[')) => {
                // Refused before it is entered: the call stack never holds
                // more than NESTING_MAX nested values.
                if depth > NESTING_MAX {
                    return Err(SyntaxError {
                        span: Span {
                            start: start as u32,
                            end: start as u32 + 1,
                        },
                        kind: SyntaxErrorKind::TooDeep,
                    });
                }
                if open == b'{' {
                    Value::Table(self.object(depth)?)
                } else {
                    Value::Array(self.array(depth)?)
                }
            }
            Some(b'"') => Value::Str(self.string()?),
            Some(b't') => self.literal("true", Value::Bool(true))?,
            Some(b'f') => self.literal("false", Value::Bool(false))?,
            Some(b'n') if self.bytes[start..].starts_with(b"null") => {
                return Err(self.error(start, start + 4, "`null` is not a setting value"));
            }
            Some(b'-' | b'0'..=b'9') => self.number()?,
            _ => {
                let end = self.token_end();
                return Err(self.error(start, end, "expected a value"));
            }
        };
        Ok(Node {
            value,
            span: Span {
                start: start as u32,
                end: self.at as u32,
            },
        })
    }

    fn array(&mut self, depth: u32) -> Result<Vec<Node>, SyntaxError> {
        self.at += 1; // `[`
        let mut items = Vec::new();
        self.skip_space();
        if self.peek() == Some(b']') {
            self.at += 1;
            return Ok(items);
        }
        loop {
            items.push(self.value(depth + 1)?);
            self.skip_space();
            match self.peek() {
                Some(b',') => self.at += 1,
                Some(b']') => {
                    self.at += 1;
                    return Ok(items);
                }
                _ => {
                    let end = self.token_end();
                    return Err(self.error(self.at, end, "expected `,` or `]`"));
                }
            }
        }
    }

    fn literal(&mut self, word: &str, value: Value) -> Result<Value, SyntaxError> {
        if self.bytes[self.at..].starts_with(word.as_bytes()) {
            self.at += word.len();
            Ok(value)
        } else {
            let end = self.token_end();
            Err(self.error(self.at, end, "expected a value"))
        }
    }

    /// `-?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?`. Without a fraction
    /// or an exponent it is an integer (i64); otherwise a float that must
    /// stay finite.
    fn number(&mut self) -> Result<Value, SyntaxError> {
        let start = self.at;
        let digits = |p: &mut Self| {
            let from = p.at;
            while matches!(p.peek(), Some(b'0'..=b'9')) {
                p.at += 1;
            }
            p.at - from
        };
        if self.peek() == Some(b'-') {
            self.at += 1;
        }
        match self.peek() {
            Some(b'0') => {
                self.at += 1;
                if matches!(self.peek(), Some(b'0'..=b'9')) {
                    return Err(self.error(
                        start,
                        self.token_end(),
                        "a number may not start with 0",
                    ));
                }
            }
            Some(b'1'..=b'9') => {
                digits(self);
            }
            // The range ends inside the text, on a character boundary.
            _ => return Err(self.error(start, self.token_end(), "expected digits")),
        }
        let mut float = false;
        if self.peek() == Some(b'.') {
            self.at += 1;
            float = true;
            if digits(self) == 0 {
                return Err(self.error(start, self.at, "expected digits after `.`"));
            }
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            self.at += 1;
            float = true;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.at += 1;
            }
            if digits(self) == 0 {
                return Err(self.error(start, self.at, "expected digits in the exponent"));
            }
        }
        let written = &self.text[start..self.at];
        if !float {
            return written
                .parse::<i64>()
                .map(Value::Int)
                .map_err(|_| SyntaxError {
                    span: Span {
                        start: start as u32,
                        end: self.at as u32,
                    },
                    kind: SyntaxErrorKind::IntegerRange,
                });
        }
        match written.parse::<f64>() {
            Ok(x) if x.is_finite() => Ok(Value::Float(x)),
            _ => Err(self.error(start, self.at, "the number is too large")),
        }
    }

    /// A string at `self.at` (the opening quote), decoded.
    fn string(&mut self) -> Result<String, SyntaxError> {
        let open = self.at;
        self.at += 1;
        let mut out = String::new();
        loop {
            let run = self.at;
            while matches!(self.peek(), Some(b) if b != b'"' && b != b'\\' && b >= 0x20) {
                self.at += 1;
            }
            // Runs end on an ASCII byte, so they are whole characters.
            out.push_str(&self.text[run..self.at]);
            match self.peek() {
                Some(b'"') => {
                    self.at += 1;
                    return Ok(out);
                }
                Some(b'\\') => {
                    let escape = self.at;
                    self.at += 1;
                    let c = match self.peek() {
                        Some(b'"') => '"',
                        Some(b'\\') => '\\',
                        Some(b'/') => '/',
                        Some(b'b') => '\u{8}',
                        Some(b'f') => '\u{c}',
                        Some(b'n') => '\n',
                        Some(b'r') => '\r',
                        Some(b't') => '\t',
                        Some(b'u') => {
                            self.at += 1;
                            let c = self.unicode(escape)?;
                            out.push(c);
                            continue;
                        }
                        _ => {
                            return Err(self.error(escape, self.token_end(), "unknown escape"));
                        }
                    };
                    self.at += 1;
                    out.push(c);
                }
                Some(_) => {
                    return Err(self.error(
                        self.at,
                        self.at + 1,
                        "a control character must be escaped",
                    ));
                }
                None => return Err(self.error(open, self.at, "the string is not closed")),
            }
        }
    }

    /// The four hex digits after `\u` (and a low surrogate's `\uXXXX` after
    /// a high one). `escape` is where the backslash was.
    fn unicode(&mut self, escape: usize) -> Result<char, SyntaxError> {
        let hex4 = |p: &mut Self| -> Option<u32> {
            let digits = p.text.get(p.at..p.at + 4)?;
            if !digits.bytes().all(|b| b.is_ascii_hexdigit()) {
                return None;
            }
            p.at += 4;
            u32::from_str_radix(digits, 16).ok()
        };
        let bad = |p: &Self, why: &str| p.error(escape, p.at, why);
        let Some(first) = hex4(self) else {
            return Err(bad(self, "`\\u` needs four hex digits"));
        };
        match first {
            0xD800..=0xDBFF => {
                if !self.bytes[self.at..].starts_with(b"\\u") {
                    return Err(bad(self, "a high surrogate must be followed by a low one"));
                }
                self.at += 2;
                match hex4(self) {
                    Some(low @ 0xDC00..=0xDFFF) => {
                        let c = 0x10000 + ((first - 0xD800) << 10) + (low - 0xDC00);
                        char::from_u32(c).ok_or_else(|| bad(self, "not a character"))
                    }
                    _ => Err(bad(self, "a high surrogate must be followed by a low one")),
                }
            }
            0xDC00..=0xDFFF => Err(bad(self, "a low surrogate without a high one")),
            c => char::from_u32(c).ok_or_else(|| bad(self, "not a character")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::tree::{Format, format_of, parse as parse_toml, parse_as};
    use alloc::string::ToString;

    fn json(text: &str) -> Result<Table, SyntaxError> {
        parse(text)
    }

    fn message(text: &str) -> String {
        match json(text) {
            Err(SyntaxError {
                kind: SyntaxErrorKind::Json(m),
                ..
            }) => m,
            other => panic!("{text:?}: {other:?}"),
        }
    }

    /// The tree without spans, for comparing two files.
    fn shape(t: &Table) -> Vec<(String, String)> {
        fn value(v: &Value) -> String {
            match v {
                Value::Str(s) => alloc::format!("s{s:?}"),
                Value::Int(n) => alloc::format!("i{n}"),
                Value::Float(x) => alloc::format!("f{x:?}"),
                Value::Bool(b) => alloc::format!("b{b}"),
                Value::DateTime(d) => alloc::format!("d{d}"),
                Value::Array(a) => {
                    let items: Vec<String> = a.iter().map(|n| value(&n.value)).collect();
                    alloc::format!("[{}]", items.join(","))
                }
                Value::Table(t) => {
                    let items: Vec<String> = shape(t)
                        .into_iter()
                        .map(|(k, v)| alloc::format!("{k:?}={v}"))
                        .collect();
                    alloc::format!("{{{}}}", items.join(","))
                }
            }
        }
        let mut out: Vec<(String, String)> = t
            .entries
            .iter()
            .map(|e| (e.key.clone(), value(&e.node.value)))
            .collect();
        out.sort();
        out
    }

    // 같은 설정을 두 형식으로 쓴 것은 span을 빼면 같은 트리다. 이것을 실패시키는 것: 키를 점으로 나누는 것,
    // 정수를 실수로 읽는 것, 배열·표의 값을 잃는 것, 마지막 키를 빠뜨리는 것.
    #[test]
    fn the_same_settings_give_the_same_tree() {
        let toml = "version = 1\n[colors]\nmode = \"auto\"\noverride = { \"git.dirty\" = \"#ff0000\" }\nknobs = { hue = 280, accent_l = 0.76 }\n[layout.line1]\nleft = [\"dir\", \"git\"]\nright = []\n[segment.\"custom/a\"]\nkind = \"text\"\nshow = true\n";
        let json_text = r##"{"version": 1, "colors": {"mode": "auto", "override": {"git.dirty": "#ff0000"},
            "knobs": {"hue": 280, "accent_l": 0.76}}, "layout": {"line1": {"left": ["dir", "git"], "right": []}},
            "segment": {"custom/a": {"kind": "text", "show": true}}}"##;
        assert_eq!(
            shape(&json(json_text).unwrap()),
            shape(&parse_toml(toml.as_bytes()).unwrap())
        );
    }

    // 이것을 실패시키는 것: 값과 키의 span을 다른 자리로 두는 것(진단이 엉뚱한 줄을 가리킴).
    #[test]
    fn keys_and_values_keep_their_bytes() {
        let text = "{\n  \"a\": [1, {\"b\": \"x\"}],\n  \"c\": -2.5e1\n}";
        let t = json(text).unwrap();
        let at = |e: &Entry| {
            (
                &text[e.key_span.start as usize..e.key_span.end as usize],
                &text[e.node.span.start as usize..e.node.span.end as usize],
            )
        };
        assert_eq!(at(&t.entries[0]), ("\"a\"", "[1, {\"b\": \"x\"}]"));
        assert_eq!(at(&t.entries[1]), ("\"c\"", "-2.5e1"));
        assert_eq!(t.entries[1].node.value, Value::Float(-25.0));
        let Value::Array(items) = &t.entries[0].node.value else {
            panic!()
        };
        assert_eq!(
            &text[items[1].span.start as usize..items[1].span.end as usize],
            "{\"b\": \"x\"}"
        );
    }

    // 이것을 실패시키는 것: 디코드한 뒤가 아니라 쓴 그대로 중복을 비교하는 것(`a`와 `\u0061`), 중복 검사를 빼는 것,
    // 깊은 표 안의 중복을 놓치는 것.
    #[test]
    fn a_key_appears_once_per_object() {
        let m = message("{\"a\": 1,\n\"\\u0061\": 2}");
        assert_eq!(m, "duplicate key `a` (first written at line 1)");
        let e = json("{\"x\": {\"k\": 1, \"k\": 2}}").unwrap_err();
        assert_eq!((e.span.start, e.span.end), (15, 18));
        assert!(json("{\"x\": {\"k\": 1}, \"y\": {\"k\": 2}}").is_ok());
    }

    // 이것을 실패시키는 것: RFC 8259 밖의 모양(주석, 끝 쉼표, 홑따옴표, 앞의 0, `.5`·`1.`·`+1`, NaN, 다른 공백,
    // BOM, 맨 위 배열, 뒤에 남은 글자, null, 제어 문자, 잘못된 이스케이프, 짝 없는 서로게이트)을 받는 것, 오류 범위를
    // 파일 끝 밖이나 글자 가운데로 내는 것.
    #[test]
    fn only_strict_json_is_read() {
        for bad in [
            "{\"a\": 1,}",
            "{\"a\": [1,]}",
            "{'a': 1}",
            "{\"a\": 01}",
            "{\"a\": .5}",
            "{\"a\": 1.}",
            "{\"a\": +1}",
            "{\"a\": NaN}",
            "{\"a\": Infinity}",
            "{\"a\": 1e}",
            "{\"a\": -}",
            "{\"a\":\u{a0}1}",
            "{\"a\":\u{c}1}",
            "\u{feff}{}",
            "[1]",
            "{} {}",
            "{}x",
            "{\"a\": null}",
            "{\"a\": \"\u{1}\"}",
            "{\"a\": \"\\x41\"}",
            "{\"a\": \"\\ud800\"}",
            "{\"a\": \"\\udc00\"}",
            "{\"a\": \"\\ud800\\u0041\"}",
            "{\"a\": \"\\u12\"}",
            "{\"a\": \"open}",
            "{\"a\" 1}",
            "{\"a\": 1 \"b\": 2}",
            "{a: 1}",
            "// c\n{}",
            "{\"a\": 1} // c",
            "{\"a\": tru}",
            "",
            "   ",
            "{\"a\":-",
            "{\"a\":-\u{e9}}",
            "{\"a\": 0\u{e9}}",
            "{\"a\": \"\u{e9}",
        ] {
            // The error's range stays inside the text, on character boundaries.
            let e = json(bad).expect_err(bad);
            let (start, end) = (e.span.start as usize, e.span.end as usize);
            assert!(start <= end && end <= bad.len(), "{bad:?}: {:?}", e.span);
            assert!(
                bad.is_char_boundary(start) && bad.is_char_boundary(end),
                "{bad:?}: {:?}",
                e.span
            );
        }
        assert_eq!(message("{\"a\": null}"), "`null` is not a setting value");
        assert_eq!(message("[]"), "the file must hold one object");
    }

    // 이것을 실패시키는 것: 이스케이프를 잘못 풀거나 서로게이트 쌍을 합치지 못하는 것, 수의 형을 바꾸는 것,
    // i64 경계와 무한대를 넘기는 것.
    #[test]
    fn values_decode_as_written() {
        let t = json(r#"{"s": "a\"\\\/\b\f\n\r\t\u00e9\ud83d\ude00", "i": -9223372036854775808, "z": -0, "f": 1E2, "t": true, "n": false}"#)
            .unwrap();
        let get = |k: &str| t.get(k).unwrap().node.value.clone();
        assert_eq!(
            get("s"),
            Value::Str("a\"\\/\u{8}\u{c}\n\r\t\u{e9}\u{1f600}".to_string())
        );
        assert_eq!(get("i"), Value::Int(i64::MIN));
        assert_eq!(get("z"), Value::Int(0));
        assert_eq!(get("f"), Value::Float(100.0));
        assert_eq!(
            (get("t"), get("n")),
            (Value::Bool(true), Value::Bool(false))
        );
        assert_eq!(
            json("{\"i\": 9223372036854775808}").unwrap_err().kind,
            SyntaxErrorKind::IntegerRange
        );
        assert_eq!(message("{\"f\": 1e400}"), "the number is too large");
        assert!(json("{\"f\": 1e-400}").is_ok());
    }

    // 깊이 상한은 두 형식이 같다: 같은 모양의 표를 31–34단으로 쌓으면 같은 판정이다. 이것을 실패시키는 것: 맨 위
    // object를 한 단으로 세는 것, 배열을 세지 않는 것, 상한 검사를 `>=`로 바꾸는 것.
    #[test]
    fn nesting_limit_matches_toml() {
        for depth in [31usize, 32, 33, 34] {
            let mut toml = String::from("a = ");
            let mut json_text = String::from("{\"a\": ");
            for i in 0..depth {
                if i % 2 == 0 {
                    toml.push_str("{ b = ");
                    json_text.push_str("{\"b\": ");
                } else {
                    toml.push('[');
                    json_text.push('[');
                }
            }
            toml.push('1');
            json_text.push('1');
            for i in (0..depth).rev() {
                let close = if i % 2 == 0 { '}' } else { ']' };
                toml.push(close);
                json_text.push(close);
            }
            toml.push('\n');
            json_text.push('}');
            let t = parse_toml(toml.as_bytes())
                .map(|_| ())
                .map_err(|e| e[0].kind.clone());
            let j = json(&json_text).map(|_| ()).map_err(|e| e.kind);
            assert_eq!(t, j, "depth {depth}");
            assert_eq!(t.is_ok(), depth <= NESTING_MAX as usize, "depth {depth}");
        }
    }

    // 이것을 실패시키는 것: 깊이 검사를 재귀 뒤에 두는 것(아주 깊은 입력에서 스택이 넘침).
    #[test]
    fn deep_input_stops_at_the_limit() {
        let mut text = String::from("{\"a\": ");
        text.push_str(&"[".repeat(200_000));
        let e = json(&text).unwrap_err();
        assert_eq!(e.kind, SyntaxErrorKind::TooDeep);
        assert_eq!(e.span.start, 6 + NESTING_MAX);
    }

    // 이것을 실패시키는 것: 확장자 판별을 이름 전체가 아닌 경로 중간에서 하거나, `.json` 외의 이름을 JSON으로 읽는 것,
    // JSON의 크기·인코딩 상한을 TOML과 다르게 두는 것.
    #[test]
    fn the_name_picks_the_format_and_the_limits_are_shared() {
        assert_eq!(format_of(b"/c/config.json"), Format::Json);
        for toml in [
            &b"/c/config.toml"[..],
            b"(built-in)",
            b"/c/x.json/config",
            b"/c/.json",
            b"/c/x.JSON",
            b"x.json.bak",
        ] {
            assert_eq!(format_of(toml), Format::Toml, "{toml:?}");
        }
        let big = alloc::format!(
            "{{\"a\": \"{}\"}}",
            "x".repeat(crate::config::tree::FILE_BYTES_MAX)
        );
        for format in [Format::Toml, Format::Json] {
            assert_eq!(
                parse_as(format, big.as_bytes()).unwrap_err()[0].kind,
                SyntaxErrorKind::TooLarge
            );
            assert_eq!(
                parse_as(format, b"\xff").unwrap_err()[0].kind,
                SyntaxErrorKind::NotUtf8
            );
        }
        assert!(parse_as(Format::Json, b"{\"a\": 1}").is_ok());
        assert!(parse_as(Format::Toml, b"{\"a\": 1}").is_err());
    }
}
