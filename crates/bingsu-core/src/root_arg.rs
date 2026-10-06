//! Grammar of the root arguments init pins into the hook (spec section 4
//! "runtime root" 3 and 7). Walking and checking the path is M3a.

pub const RUNTIME_ROOT_PREFIX: &[u8] = b"--runtime-root=";
pub const CONFIG_ROOT_PREFIX: &[u8] = b"--config-root=";
pub const STATE_ROOT_PREFIX: &[u8] = b"--state-root=";
pub const LOG_ROOT_PREFIX: &[u8] = b"--log-root=";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RuntimeRoot<'a> {
    pub dev: u64,
    pub ino: u64,
    pub path: &'a [u8],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RootArgError {
    MissingSeparator,
    BadDev,
    BadIno,
    EmptyPath,
    NotAbsolute,
}

/// ASCII decimal without leading zeros ("0" itself is allowed), no sign.
pub fn parse_decimal(s: &[u8]) -> Option<u64> {
    if s.is_empty() || (s.len() > 1 && s[0] == b'0') {
        return None;
    }
    s.iter().try_fold(0u64, |acc, &b| {
        if !b.is_ascii_digit() {
            return None;
        }
        acc.checked_mul(10)?.checked_add(u64::from(b - b'0'))
    })
}

/// `<dev>:<ino>:<path>`: only the first two colons separate.
pub fn parse_runtime_root(v: &[u8]) -> Result<RuntimeRoot<'_>, RootArgError> {
    let c1 = v
        .iter()
        .position(|&b| b == b':')
        .ok_or(RootArgError::MissingSeparator)?;
    let rest = &v[c1 + 1..];
    let c2 = rest
        .iter()
        .position(|&b| b == b':')
        .ok_or(RootArgError::MissingSeparator)?;
    let dev = parse_decimal(&v[..c1]).ok_or(RootArgError::BadDev)?;
    let ino = parse_decimal(&rest[..c2]).ok_or(RootArgError::BadIno)?;
    let path = parse_abs_path(&rest[c2 + 1..])?;
    Ok(RuntimeRoot { dev, ino, path })
}

pub fn parse_abs_path(v: &[u8]) -> Result<&[u8], RootArgError> {
    match v.first() {
        None => Err(RootArgError::EmptyPath),
        Some(b'/') => Ok(v),
        Some(_) => Err(RootArgError::NotAbsolute),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Decomposition vector fixed by the spec (section 9, M1 row).
    #[test]
    fn decomposes_spec_vector() {
        let r = parse_runtime_root(b"12:34:/a/56:x").unwrap();
        assert_eq!((r.dev, r.ino, r.path), (12, 34, &b"/a/56:x"[..]));
    }

    #[test]
    fn accepts_zero_and_max() {
        assert_eq!(parse_runtime_root(b"0:0:/").unwrap().path, b"/");
        assert_eq!(
            parse_runtime_root(b"18446744073709551615:1:/a")
                .unwrap()
                .dev,
            u64::MAX
        );
    }

    // 이것을 실패시키는 것: 앞자리 0·숫자 아닌 글자·빈 값·넘침·`:` 부족·빈 경로·상대 경로를 받아 주는 것.
    #[test]
    fn rejection_vectors() {
        use RootArgError::*;
        let cases: &[(&[u8], RootArgError)] = &[
            (b"012:34:/a", BadDev),
            (b"12:034:/a", BadIno),
            (b"1a:2:/a", BadDev),
            (b"1:2b:/a", BadIno),
            (b":2:/a", BadDev),
            (b"1::/a", BadIno),
            (b"18446744073709551616:1:/a", BadDev),
            (b"1:2", MissingSeparator),
            (b"12", MissingSeparator),
            (b"", MissingSeparator),
            (b"1:2:", EmptyPath),
            (b"1:2:rel/path", NotAbsolute),
            (b"+1:2:/a", BadDev),
            (b"1_0:2:/a", BadDev),
            (b" 1:2:/a", BadDev),
            (b"1 :2:/a", BadDev),
        ];
        for (input, want) in cases {
            assert_eq!(
                parse_runtime_root(input).err(),
                Some(*want),
                "{:?}",
                String::from_utf8_lossy(input)
            );
        }
    }

    #[test]
    fn decimal_edge_vectors() {
        for bad in [&b"1_0"[..], b" 1", b"1 "] {
            assert_eq!(
                parse_decimal(bad),
                None,
                "{:?}",
                String::from_utf8_lossy(bad)
            );
        }
        assert_eq!(parse_decimal(b"0"), Some(0));
    }

    // 이것을 실패시키는 것: 접두사 값 변경(`=` 누락 등), 한 접두사가 다른 접두사의 접두사가 되는 것.
    #[test]
    fn prefixes_are_pinned_and_disjoint() {
        let all = [
            (RUNTIME_ROOT_PREFIX, &b"--runtime-root="[..]),
            (CONFIG_ROOT_PREFIX, b"--config-root="),
            (STATE_ROOT_PREFIX, b"--state-root="),
            (LOG_ROOT_PREFIX, b"--log-root="),
        ];
        for (i, (a, want)) in all.iter().enumerate() {
            assert_eq!(a, want);
            for (j, (b, _)) in all.iter().enumerate() {
                assert!(i == j || !a.starts_with(b));
            }
        }
    }

    #[test]
    fn abs_path_rules() {
        assert_eq!(parse_abs_path(b"/x y/z"), Ok(&b"/x y/z"[..]));
        assert_eq!(parse_abs_path(b""), Err(RootArgError::EmptyPath));
        assert_eq!(parse_abs_path(b"x"), Err(RootArgError::NotAbsolute));
    }
}
