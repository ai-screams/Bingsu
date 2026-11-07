//! A command segment's `match` (spec section 3, U-9c): a regular expression
//! the refresh helper applies to the sanitized first line of a command's
//! output before it publishes the value. One check (`Matcher::new`, also used
//! by config check and when a snapshot is made) and one apply
//! (`Matcher::value`). The prompt never runs a pattern: it only compares the
//! pattern digest in the command response with its snapshot's.
#![forbid(unsafe_code)]

/// Bytes the compiled program of one pattern may take (U-29). Without the
/// perf engines the search is a Pike VM whose time grows with the states a
/// line keeps alive: at 256 KiB a pattern of thousands of alternatives took
/// over a second on a 4 KB line. At 64 KiB, with `MAX_PATTERN_BYTES`, the
/// slowest shape measured is a short bounded repeat, tens of milliseconds a
/// line; the helper's round budget (`commands::command_match`) bounds the
/// sum. Version and path patterns (`([^/]+)$`,
/// `(?P<value>[0-9]+\.[0-9]+\.[0-9]+)`, `(?P<value>\w+)`) fit; a long Unicode
/// class repeat such as `\w{10}` does not.
pub const SIZE_LIMIT: usize = 64 * 1024;
/// Bytes of pattern text (U-29): thousands of alternatives fit 64 KiB of
/// program yet keep thousands of states alive; 256 bytes leaves room for
/// any version or path pattern.
pub const MAX_PATTERN_BYTES: usize = 256;
/// Capture groups one pattern may have. The Pike VM keeps two tables of
/// one slot pair per group for every state, so groups multiply the memory
/// the size limit allows: 1,500 groups under 256 KiB would take about
/// 200 MiB on a 4 KB line. The value is one group (`value` or the first),
/// so a few more than that is plenty.
pub const MAX_GROUPS: usize = 16;
// No `dfa_size_limit`: the lazy DFA is a perf engine this build leaves out
// (C4c ruling Q6), so its cap would change nothing and no test could tell.

/// A checked pattern.
#[derive(Clone, Debug)]
pub struct Matcher {
    regex: regex::Regex,
    /// Which part of a match is the value (decided once from the pattern).
    group: Group,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Group {
    /// The pattern names a group `value`.
    Named,
    /// No `value` group; the first capture group.
    First,
    /// No capture group; the whole match.
    Whole,
}

/// Why a pattern does not compile: its syntax, or a size past the limits.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Error(pub String);

impl Matcher {
    /// Compiles `pattern` of at most `MAX_PATTERN_BYTES` under `SIZE_LIMIT`
    /// with at most `MAX_GROUPS` capture groups.
    pub fn new(pattern: &str) -> Result<Self, Error> {
        if pattern.len() > MAX_PATTERN_BYTES {
            return Err(Error(format!(
                "{} bytes exceed the pattern limit of {MAX_PATTERN_BYTES}",
                pattern.len()
            )));
        }
        let regex = regex::RegexBuilder::new(pattern)
            .size_limit(SIZE_LIMIT)
            .build()
            .map_err(|e| Error(e.to_string()))?;
        // `captures_len` counts the whole match as group 0.
        if regex.captures_len() > MAX_GROUPS + 1 {
            return Err(Error(format!(
                "{} capture groups exceed the limit of {MAX_GROUPS}",
                regex.captures_len() - 1
            )));
        }
        let group = if regex.capture_names().any(|n| n == Some("value")) {
            Group::Named
        } else if regex.captures_len() > 1 {
            Group::First
        } else {
            Group::Whole
        };
        Ok(Self { regex, group })
    }

    /// The value `line` shows: the group `value` when the pattern names one,
    /// else the first capture group, else the whole match. Empty when the
    /// pattern does not match or that part is empty or did not take part.
    pub fn value<'a>(&self, line: &'a str) -> &'a str {
        // Capture slots cost time and memory per state; a line the pattern
        // does not match pays only for the plain search, and a match is
        // re-run with captures from where it starts, the haystack whole so
        // `^`, `$` and `\b` see the same text.
        let Some(m) = self.regex.find(line) else {
            return "";
        };
        let Some(c) = self.regex.captures_at(line, m.start()) else {
            return "";
        };
        let part = match self.group {
            Group::Named => c.name("value"),
            Group::First => c.get(1),
            Group::Whole => c.get(0),
        };
        part.map_or("", |m| m.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn value(pattern: &str, line: &str) -> String {
        Matcher::new(pattern).unwrap().value(line).into()
    }

    // 값 규칙(스펙 908행): 이름 붙은 그룹 `value` → 첫 캡처 그룹 → 맞은 전체. 맞지 않거나 그 부분이 비거나 참여하지
    // 않으면 빈 값(숨김). 이것을 실패시키는 것: 그룹 순서를 바꾸는 것(`(?P<value>b)(a)`가 a를 냄), 이름 그룹이
    // 있는데 첫 그룹을 쓰는 것, 캡처가 없는데 첫 그룹을 찾는 것(빈 값), 맞지 않을 때 원문을 내는 것.
    #[test]
    fn named_group_then_first_capture_then_whole() {
        assert_eq!(value(r"(a)(?P<value>b)", "ab"), "b");
        assert_eq!(value(r"(?P<value>b)(a)", "ba"), "b");
        assert_eq!(
            value(r"go version go([^ ]+)", "go version go1.23.1 darwin"),
            "1.23.1"
        );
        assert_eq!(value(r"[0-9]+\.[0-9]+", "Python 3.12"), "3.12");
        assert_eq!(value(r"([^/]+)$", "a/b/kube-ctx"), "kube-ctx");
        assert_eq!(value(r"x([0-9]+)", "no digits"), "");
        assert_eq!(value(r"(?P<value>[0-9]*)x", "x"), "");
        assert_eq!(value(r"(?P<value>q)?x", "x"), "");
        assert_eq!(value(r"(?P<value>\w+)", "caf\u{e9}!"), "caf\u{e9}");
    }

    // 크기 상한(U-29): 프로그램 64 KiB, 패턴 글 256 B. 버전·경로 패턴은 받고, 경계 바로 위(`[\s\S]{158}`, 257 B)와
    // `\w{10}`, 중첩 반복은 거부한다. 이것을 실패시키는 것: size_limit 지정을 빼는 것(기본 10 MiB), 상한을 80 KiB
    // 이상으로 올리는 것(`{158}`을 받음), 48 KiB 이하로 내리는 것(`{157}`을 거부), 패턴 길이 검사를 지우거나 257 B
    // 이상으로 늘리는 것, 255 B 이하로 줄이는 것.
    #[test]
    fn the_size_limit_takes_version_patterns_and_refuses_large_programs() {
        for ok in [
            r"([^/]+)$",
            r"(?P<value>[0-9]+\.[0-9]+\.[0-9]+)",
            r"(?P<value>\w+)",
            r"(a|b)*a(a|b){20}",
            r"[\s\S]{157}",
        ] {
            assert!(Matcher::new(ok).is_ok(), "{ok}");
        }
        // 64 KiB of program: `[\s\S]{157}` fits, `{158}` does not (it would
        // fit 80 KiB); `{157}` would not fit 48 KiB (117 at most).
        for big in [r"[\s\S]{158}", r"\w{10}", r"((a{1000}){1000}){1000}"] {
            let e = Matcher::new(big).unwrap_err();
            assert!(e.0.contains("size limit"), "{big}: {}", e.0);
        }
        // 256 bytes of pattern text, then refused before compiling.
        assert!(Matcher::new(&"a".repeat(256)).is_ok());
        let e = Matcher::new(&"a".repeat(257)).unwrap_err();
        assert!(e.0.contains("pattern limit"), "{}", e.0);
        assert!(Matcher::new("(unclosed").is_err());
    }

    // 캡처 그룹 상한: 그룹마다 Pike VM이 상태별 슬롯 표를 두 벌 두므로, 크기 상한 안에 드는 `(a)` 1,500개 패턴이
    // 4 KB 줄에서 helper 메모리를 넘길 수 있다(약 200 MiB). 16개는 받고 17개부터 거부한다. 이것을 실패시키는 것:
    // 그룹 수 검사를 지우는 것(1,500개를 받음), 상한을 17 이상으로 두는 것, 그룹 0까지 세어 16개를 거부하는 것.
    #[test]
    fn capture_groups_are_capped() {
        assert!(Matcher::new(&"(a)".repeat(16)).is_ok());
        let e = Matcher::new(&"(a)".repeat(17)).unwrap_err();
        assert!(e.0.contains("capture groups"), "{}", e.0);
        assert!(Matcher::new(&"(a)".repeat(1500)).is_err());
        assert!(Matcher::new(&format!("(?P<value>a){}", "(b)".repeat(15))).is_ok());
    }
}
