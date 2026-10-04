//! Status value `class ":" code` carried in the last record field
//! (spec section 3 record ABNF, decision 19).

/// Known classes. Shells treat any other class as `degraded`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StatusClass {
    Ok,
    Notice,
    Degraded,
    Error,
}

impl StatusClass {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Notice => "notice",
            Self::Degraded => "degraded",
            Self::Error => "error",
        }
    }
}

/// A status the engine can emit. `code` is `1*( a-z / "-" )`, checked at
/// construction: in a `const` a bad code is a compile error, at run time a panic.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Status {
    class: StatusClass,
    code: &'static str,
}

/// `code = 1*( %x61-7A / "-" )`.
const fn is_valid_code(code: &str) -> bool {
    let b = code.as_bytes();
    if b.is_empty() {
        return false;
    }
    let mut i = 0;
    while i < b.len() {
        if !(b[i].is_ascii_lowercase() || b[i] == b'-') {
            return false;
        }
        i += 1;
    }
    true
}

impl Status {
    pub const fn new(class: StatusClass, code: &'static str) -> Self {
        assert!(is_valid_code(code), "status code must be 1*(a-z / \"-\")");
        Self { class, code }
    }

    pub const fn class(self) -> StatusClass {
        self.class
    }

    pub const fn code(self) -> &'static str {
        self.code
    }

    pub const OK_NONE: Self = Self::new(StatusClass::Ok, "none");
    pub const ERROR_BAD_ARGS: Self = Self::new(StatusClass::Error, "bad-args");
    pub const ERROR_INTERNAL: Self = Self::new(StatusClass::Error, "internal");
    pub const DEGRADED_RUNTIME_ROOT: Self = Self::new(StatusClass::Degraded, "runtime-root");
    pub const DEGRADED_OVERSIZE: Self = Self::new(StatusClass::Degraded, "oversize");
    pub const DEGRADED_TRUST_UNVERIFIED: Self =
        Self::new(StatusClass::Degraded, "trust-unverified");
    pub const DEGRADED_TRUST_EXPIRED: Self = Self::new(StatusClass::Degraded, "trust-expired");
    pub const ERROR_CONFIG_LAST_GOOD: Self = Self::new(StatusClass::Error, "config-last-good");
    pub const ERROR_CONFIG_DEFAULT: Self = Self::new(StatusClass::Error, "config-default");

    /// Non-ok statuses that `init` embeds as constants in the shell reader,
    /// so each gets its own fixed message (spec section 5 receive table).
    pub const KNOWN_NON_OK: &'static [Self] = &[
        Self::ERROR_BAD_ARGS,
        Self::ERROR_INTERNAL,
        Self::DEGRADED_RUNTIME_ROOT,
        Self::DEGRADED_OVERSIZE,
        Self::DEGRADED_TRUST_UNVERIFIED,
        Self::DEGRADED_TRUST_EXPIRED,
        Self::ERROR_CONFIG_LAST_GOOD,
        Self::ERROR_CONFIG_DEFAULT,
    ];

    pub fn write_to(self, out: &mut Vec<u8>) {
        out.extend_from_slice(self.class.as_str().as_bytes());
        out.push(b':');
        out.extend_from_slice(self.code.as_bytes());
    }
}

/// `status = 1*%x61-7A ":" 1*( %x61-7A / "-" )`, exactly one colon.
pub fn is_valid_status(s: &[u8]) -> bool {
    let Some(colon) = s.iter().position(|&b| b == b':') else {
        return false;
    };
    let (class, code) = (&s[..colon], &s[colon + 1..]);
    !class.is_empty()
        && class.iter().all(u8::is_ascii_lowercase)
        && !code.is_empty()
        && code.iter().all(|&b| b.is_ascii_lowercase() || b == b'-')
}

#[cfg(test)]
mod tests {
    use super::*;

    // 이것을 실패시키는 것: 문법 검사가 `:` 없는 값, 빈 쪽, 대문자, 숫자, 두 번째 `:`를 통과시키는 것.
    #[test]
    fn grammar_vectors() {
        for ok in [
            "ok:none",
            "notice:future-code",
            "degraded:x",
            "weird:thing",
            "a:-",
        ] {
            assert!(is_valid_status(ok.as_bytes()), "{ok}");
        }
        for bad in [
            "",
            "ok",
            "ok:",
            ":none",
            ":",
            "OK:none",
            "ok:None",
            "ok:e1",
            "ok:a:b",
            "ok:a;b",
            "$(touch x):y",
            "`id`:x",
            "degraded:$(touch x)",
            "ok :none",
            "ok:none\n",
        ] {
            assert!(!is_valid_status(bad.as_bytes()), "{bad:?}");
        }
    }

    #[test]
    fn known_codes_are_valid_and_unique() {
        let mut seen = Vec::new();
        for s in Status::KNOWN_NON_OK {
            let mut b = Vec::new();
            s.write_to(&mut b);
            assert!(is_valid_status(&b), "{s:?}");
            assert_ne!(s.class, StatusClass::Ok, "ok codes never need a notice");
            assert!(!seen.contains(&b), "duplicate {s:?}");
            seen.push(b);
        }
    }

    #[test]
    #[should_panic(expected = "status code")]
    fn new_rejects_uppercase_code() {
        let _ = Status::new(StatusClass::Ok, "Bad");
    }

    #[test]
    #[should_panic(expected = "status code")]
    fn new_rejects_empty_code() {
        let _ = Status::new(StatusClass::Ok, "");
    }

    #[test]
    fn write_to_formats_class_colon_code() {
        let mut b = Vec::new();
        Status::DEGRADED_RUNTIME_ROOT.write_to(&mut b);
        assert_eq!(b, b"degraded:runtime-root");
    }
}
