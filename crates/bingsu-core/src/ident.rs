//! Segment ids (spec section 2 "세그먼트 이름 공간, id 문법"). One grammar for
//! the config table name `[segment."<id>"]`, layout arrays and templates:
//!
//! ```text
//! seg-id  = id-part [ "/" id-part ]
//! id-part = %x61-7A *( %x61-7A / DIGIT / "_" / "-" )   ; 1-32 bytes
//! ```
//!
//! A part does not end in `_` or `-`; the whole id is at most 65 bytes. No
//! case folding or normalization: an id is compared as written, and shown as
//! written. A one-part id names a built-in segment; `custom/<name>` a user
//! segment; any other two-part id a plugin segment. The first parts
//! `bingsu`, `topping` and `file` are reserved, and so are the reference
//! schemes `topping:` and `file:` (not supported yet).
//!
//! Token names (`git.dirty`) use `.` and have their own rule; they are not
//! segment ids.

/// Bytes of one part, and of the whole id.
pub const PART_MAX: usize = 32;
pub const ID_MAX: usize = 2 * PART_MAX + 1;

/// First parts no user or plugin segment may take.
pub const RESERVED_NAMESPACES: [&str; 3] = ["bingsu", "topping", "file"];
/// Reference schemes kept for later (`topping:git-extra`).
pub const RESERVED_SCHEMES: [&str; 2] = ["topping", "file"];

/// Which namespace an id is in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Namespace {
    Builtin,
    Custom,
    Plugin,
}

/// A checked segment id, borrowed from where it was written.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct SegmentId<'a>(&'a str);

impl<'a> SegmentId<'a> {
    pub fn as_str(self) -> &'a str {
        self.0
    }
    pub fn namespace(self) -> Namespace {
        match self.0.split_once('/') {
            None => Namespace::Builtin,
            Some(("custom", _)) => Namespace::Custom,
            Some(_) => Namespace::Plugin,
        }
    }
}

/// Why a text is not a segment id. Byte offsets are into the text.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IdError {
    Empty,
    /// The whole id is longer than `ID_MAX` bytes.
    TooLong,
    /// A part is empty or longer than `PART_MAX` bytes.
    PartLength {
        at: usize,
    },
    /// A byte the grammar does not allow (a part must start with a-z).
    BadByte {
        at: usize,
    },
    /// A part ends in `_` or `-`.
    BadEnd {
        at: usize,
    },
    /// More than one `/`.
    TooManyParts {
        at: usize,
    },
    /// `bingsu/…`, `topping/…`, `file/…`.
    ReservedNamespace,
    /// `topping:…` or `file:…`: kept for later, not supported yet.
    UnsupportedScheme,
}

fn part(s: &str, base: usize) -> Result<(), IdError> {
    let b = s.as_bytes();
    if b.is_empty() || b.len() > PART_MAX {
        return Err(IdError::PartLength { at: base });
    }
    for (i, &c) in b.iter().enumerate() {
        let ok = if i == 0 {
            c.is_ascii_lowercase()
        } else {
            c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_' || c == b'-'
        };
        if !ok {
            return Err(IdError::BadByte { at: base + i });
        }
    }
    if matches!(b[b.len() - 1], b'_' | b'-') {
        return Err(IdError::BadEnd {
            at: base + b.len() - 1,
        });
    }
    Ok(())
}

/// Checks `s` against the grammar and the reserved names.
pub fn parse_segment_id(s: &str) -> Result<SegmentId<'_>, IdError> {
    if s.is_empty() {
        return Err(IdError::Empty);
    }
    if let Some((scheme, _)) = s.split_once(':') {
        if RESERVED_SCHEMES.contains(&scheme) {
            return Err(IdError::UnsupportedScheme);
        }
    }
    if s.len() > ID_MAX {
        return Err(IdError::TooLong);
    }
    match s.split_once('/') {
        None => part(s, 0)?,
        Some((a, b)) => {
            part(a, 0)?;
            if let Some(i) = b.find('/') {
                return Err(IdError::TooManyParts {
                    at: a.len() + 1 + i,
                });
            }
            part(b, a.len() + 1)?;
            if RESERVED_NAMESPACES.contains(&a) {
                return Err(IdError::ReservedNamespace);
            }
        }
    }
    Ok(SegmentId(s))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::String;

    // 이것을 실패시키는 것: 문법이 허용하는 id를 거부하는 것(경계 길이 32·65 포함).
    #[test]
    fn accepts_the_grammar() {
        let p32 = String::from("a") + &"b".repeat(31);
        let full = alloc::format!("{p32}/{p32}");
        assert_eq!(full.len(), ID_MAX);
        for ok in [
            "a",
            "dir",
            "git",
            "custom",
            "bingsu",
            "topping",
            "file",
            "custom/kube",
            "vendor/name",
            "a1_b-c",
            "x9",
            &p32,
            &full,
        ] {
            assert_eq!(parse_segment_id(ok).map(SegmentId::as_str), Ok(ok), "{ok}");
        }
        assert_eq!(
            parse_segment_id("dir").unwrap().namespace(),
            Namespace::Builtin
        );
        assert_eq!(
            parse_segment_id("custom/kube").unwrap().namespace(),
            Namespace::Custom
        );
        assert_eq!(
            parse_segment_id("acme/k8s").unwrap().namespace(),
            Namespace::Plugin
        );
    }

    // 이것을 실패시키는 것: 대문자·숫자 시작·끝의 `_`·`-`·빈 부분·`/` 둘·길이 초과·예약 이름을 받는 것,
    // 또는 템플릿 구분 문자(`{` `}` `:` `@`)가 든 id를 받는 것.
    #[test]
    fn refuses_what_the_grammar_does_not_allow() {
        let p33 = "a".repeat(33);
        let cases = [
            ("", IdError::Empty),
            ("Dir", IdError::BadByte { at: 0 }),
            ("1dir", IdError::BadByte { at: 0 }),
            ("di r", IdError::BadByte { at: 2 }),
            ("dir_", IdError::BadEnd { at: 3 }),
            ("custom/kube-", IdError::BadEnd { at: 11 }),
            ("/kube", IdError::PartLength { at: 0 }),
            ("custom/", IdError::PartLength { at: 7 }),
            ("custom/1kube", IdError::BadByte { at: 7 }),
            ("custom/ku be", IdError::BadByte { at: 9 }),
            ("a/b/c", IdError::TooManyParts { at: 3 }),
            (&p33, IdError::PartLength { at: 0 }),
            ("bingsu/x", IdError::ReservedNamespace),
            ("topping/x", IdError::ReservedNamespace),
            ("file/x", IdError::ReservedNamespace),
            ("topping:git-extra", IdError::UnsupportedScheme),
            ("file:theme.toml", IdError::UnsupportedScheme),
            ("dir}{@nl", IdError::BadByte { at: 3 }),
            ("dir@nl", IdError::BadByte { at: 3 }),
            ("dir:block", IdError::BadByte { at: 3 }),
            ("é", IdError::BadByte { at: 0 }),
        ];
        for (s, want) in cases {
            assert_eq!(parse_segment_id(s), Err(want), "{s:?}");
        }
        let long_part = alloc::format!("a/{p33}");
        assert_eq!(
            parse_segment_id(&long_part),
            Err(IdError::PartLength { at: 2 })
        );
        let long = alloc::format!("{}/{}", "a".repeat(32), "b".repeat(33));
        assert_eq!(parse_segment_id(&long), Err(IdError::TooLong));
    }

    // 이것을 실패시키는 것: 템플릿이 설정과 다른 id 문법을 쓰는 것(설정이 거부한 id를 템플릿이 받음).
    #[test]
    fn templates_use_the_same_grammar() {
        use crate::template::syntax::parse;
        let p32 = "a".repeat(32);
        let full = alloc::format!("{p32}/{p32}");
        for ok in ["dir", "custom/kube", "acme/k8s", &full] {
            for template in [
                alloc::format!("{{{ok}}}"),
                alloc::format!("{{{ok}:block}}"),
                alloc::format!("{{{ok}.text}}"),
            ] {
                assert!(parse(&template).is_ok(), "{template}");
            }
        }
        let p33 = "a".repeat(33);
        for bad in ["dir_", "bingsu/x", "topping/x", "file/x", "a/b-", &p33] {
            for template in [
                alloc::format!("{{{bad}}}"),
                alloc::format!("{{{bad}:block}}"),
                alloc::format!("{{{bad}.text}}"),
            ] {
                assert!(parse(&template).is_err(), "{template}");
            }
        }
    }

    // 공개 필드 이름은 M3에서 확정된다(스펙 4절 "세그먼트 선언"): 템플릿과 설정이 이 이름을 쓴다.
    // 이것을 실패시키는 것: 내장 세그먼트·필드 이름을 하나라도 바꾸거나 더하거나 지우는 것
    // (바꾸려면 이 표와 스키마 버전을 같은 PR에서 고친다).
    #[test]
    fn public_field_names_are_fixed() {
        let got: alloc::vec::Vec<(&str, alloc::vec::Vec<&str>)> = crate::field::BUILTIN
            .iter()
            .map(|d| (d.id, d.fields.iter().map(|f| f.name).collect()))
            .collect();
        let want: [(&str, &[&str]); 9] = [
            ("char", &["failed", "vicmd"]),
            ("dir", &["in_repo", "path", "readonly"]),
            ("duration", &["ms"]),
            (
                "git",
                &[
                    "ahead",
                    "behind",
                    "branch",
                    "commit",
                    "conflicted",
                    "detached",
                    "filtered",
                    "modified",
                    "staged",
                    "stash",
                    "state",
                    "untracked",
                ],
            ),
            ("host", &["name", "root", "ssh", "user"]),
            ("jobs", &["count"]),
            ("status", &["code", "pipestatus", "signal"]),
            ("time", &["text"]),
            ("venv", &["name"]),
        ];
        assert_eq!(got.len(), want.len());
        for ((id, fields), (wid, wfields)) in got.iter().zip(want) {
            assert_eq!((*id, fields.as_slice()), (wid, wfields));
        }
    }

    // 이것을 실패시키는 것: 내장 세그먼트 이름이 문법 밖이 되는 것(설정이 내장 세그먼트를 못 가리킴).
    #[test]
    fn builtin_ids_follow_the_grammar() {
        for d in crate::field::BUILTIN {
            let id = parse_segment_id(d.id).unwrap();
            assert_eq!(id.namespace(), Namespace::Builtin, "{}", d.id);
        }
    }
}
