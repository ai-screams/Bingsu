//! B1 record encoder (spec section 3). The shell side checks only the frame;
//! field content grammar is this producer's promise.
use crate::status::{Status, is_valid_status};

pub const RECORD_MAX_BYTES: usize = 65_536;
pub const US: u8 = 0x1F;
pub const RS: u8 = 0x1E;
/// Left field of the minimal record. Plain ASCII so it is one cell per byte
/// under every width profile.
pub const MINIMAL_LEFT: &[u8] = b"> ";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecordVersion {
    B1,
}

impl RecordVersion {
    pub fn parse(s: &[u8]) -> Option<Self> {
        (s == b"B1").then_some(Self::B1)
    }
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::B1 => "B1",
        }
    }
}

/// The six display fields, in record order.
#[derive(Clone, Copy, Debug, Default)]
pub struct Fields<'a> {
    pub left: &'a [u8],
    pub right: &'a [u8],
    pub transient_left: &'a [u8],
    pub transient_right: &'a [u8],
    pub vi_insert: &'a [u8],
    pub vi_command: &'a [u8],
}

impl<'a> Fields<'a> {
    fn in_order(&self) -> [&'a [u8]; 6] {
        [
            self.left,
            self.right,
            self.transient_left,
            self.transient_right,
            self.vi_insert,
            self.vi_command,
        ]
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FieldError {
    ForbiddenByte {
        field: usize,
        offset: usize,
        byte: u8,
    },
    BadSgr {
        field: usize,
        offset: usize,
    },
    InvalidUtf8 {
        field: usize,
    },
    C1Control {
        field: usize,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Encoded {
    Full,
    /// The record exceeded RECORD_MAX_BYTES; `out` holds the minimal record
    /// with `degraded:oversize` instead.
    ReplacedBySizeLimit,
}

/// Field bytes: UTF-8 text without C0, DEL or C1, plus renderer-made SGR
/// (`ESC [ *(DIGIT / ";" / ":") m`) and SOH/STX.
fn check_field(field: usize, bytes: &[u8]) -> Result<(), FieldError> {
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            0x1B => {
                if bytes.get(i + 1) != Some(&b'[') {
                    return Err(FieldError::BadSgr { field, offset: i });
                }
                let mut j = i + 2;
                while j < bytes.len()
                    && (bytes[j].is_ascii_digit() || bytes[j] == b';' || bytes[j] == b':')
                {
                    j += 1;
                }
                if bytes.get(j) != Some(&b'm') {
                    return Err(FieldError::BadSgr { field, offset: i });
                }
                i = j + 1;
            }
            0x01 | 0x02 => i += 1,
            b @ (0x00..=0x1F | 0x7F) => {
                return Err(FieldError::ForbiddenByte {
                    field,
                    offset: i,
                    byte: b,
                });
            }
            _ => i += 1,
        }
    }
    let text = core::str::from_utf8(bytes).map_err(|_| FieldError::InvalidUtf8 { field })?;
    if text.chars().any(|c| ('\u{80}'..='\u{9F}').contains(&c)) {
        return Err(FieldError::C1Control { field });
    }
    Ok(())
}

fn push_b1(fields: [&[u8]; 6], status: Status, out: &mut Vec<u8>) {
    out.extend_from_slice(b"B1");
    out.push(US);
    out.push(b'7');
    out.push(US);
    for f in fields {
        out.extend_from_slice(f);
        out.push(US);
    }
    status.write_to(out);
    out.push(RS);
}

/// Exact encoded length, or `None` on overflow: the frame (`B1`, `US`, `7`,
/// `US`), each field plus its `US`, the status and the closing `RS`.
fn encoded_len(parts: &[&[u8]; 6], status: Status) -> Option<usize> {
    let mut n: usize = 5;
    for f in parts {
        n = n.checked_add(f.len())?.checked_add(1)?;
    }
    n.checked_add(status.class().as_str().len())?
        .checked_add(1)?
        .checked_add(status.code().len())?
        .checked_add(1)
}

/// Appends a B1 record to `out`. Records over RECORD_MAX_BYTES are replaced
/// by the minimal record (spec section 3, size rule; the only formal bound).
/// The length is computed before anything is copied; `out` keeps its prefix.
pub fn encode_b1(
    fields: &Fields<'_>,
    status: Status,
    out: &mut Vec<u8>,
) -> Result<Encoded, FieldError> {
    debug_assert!({
        let mut s = Vec::new();
        status.write_to(&mut s);
        is_valid_status(&s)
    });
    let parts = fields.in_order();
    for (i, f) in parts.iter().enumerate() {
        check_field(i, f)?;
    }
    // The precomputed length is the real bound: an oversize field is never
    // copied, so `out` does not grow to the oversize size first.
    if encoded_len(&parts, status).is_none_or(|n| n > RECORD_MAX_BYTES) {
        write_minimal_b1(Status::DEGRADED_OVERSIZE, out);
        return Ok(Encoded::ReplacedBySizeLimit);
    }
    let start = out.len();
    push_b1(parts, status, out);
    // Guards `encoded_len` and `push_b1` against drifting apart.
    debug_assert_eq!(
        Some(out.len() - start),
        encoded_len(&parts, status),
        "encoded_len must match the bytes push_b1 writes"
    );
    Ok(Encoded::Full)
}

/// Appends the minimal record: left = MINIMAL_LEFT, other fields empty.
pub fn write_minimal_b1(status: Status, out: &mut Vec<u8>) {
    debug_assert!({
        let mut s = Vec::new();
        status.write_to(&mut s);
        is_valid_status(&s)
    });
    push_b1([MINIMAL_LEFT, b"", b"", b"", b"", b""], status, out);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::status::Status;

    fn enc(f: &Fields<'_>) -> (Result<Encoded, FieldError>, Vec<u8>) {
        let mut out = Vec::new();
        let r = encode_b1(f, Status::OK_NONE, &mut out);
        (r, out)
    }

    #[test]
    fn empty_fields_layout_is_exact() {
        let (r, out) = enc(&Fields::default());
        assert_eq!(r, Ok(Encoded::Full));
        assert_eq!(out, b"B1\x1f7\x1f\x1f\x1f\x1f\x1f\x1f\x1fok:none\x1e");
    }

    #[test]
    fn minimal_record_is_exact() {
        let mut out = Vec::new();
        write_minimal_b1(Status::ERROR_BAD_ARGS, &mut out);
        assert_eq!(
            out,
            b"B1\x1f7\x1f> \x1f\x1f\x1f\x1f\x1f\x1ferror:bad-args\x1e"
        );
    }

    // 이것을 실패시키는 것: 필드 검사가 구분자·줄바꿈·NUL·DEL·CR·C1을 통과시키는 것.
    #[test]
    fn forbidden_bytes_are_rejected() {
        for bad in [
            &b"a\x1fb"[..],
            b"a\x1eb",
            b"a\nb",
            b"a\0b",
            b"a\x7fb",
            b"a\rb",
            b"a\x1bb",
            "a\u{85}b".as_bytes(),
            b"\xff",
        ] {
            let f = Fields {
                left: bad,
                ..Fields::default()
            };
            assert!(enc(&f).0.is_err(), "{bad:?}");
        }
    }

    #[test]
    fn renderer_control_bytes_are_allowed() {
        for good in [
            &b"\x01\x1b[31m\x02X\x01\x1b[0m\x02"[..],
            b"\x1b[38;2;1;2;3m",
            b"\x1b[38:5:1m",
            b"\x1b[m",
            "한글 *[\\%!".as_bytes(),
        ] {
            let f = Fields {
                right: good,
                ..Fields::default()
            };
            assert_eq!(enc(&f).0, Ok(Encoded::Full), "{good:?}");
        }
    }

    #[test]
    fn malformed_sgr_is_rejected() {
        for bad in [&b"\x1b[31X"[..], b"\x1b[31", b"\x1b]0;t\x07", b"\x1bX"] {
            let f = Fields {
                left: bad,
                ..Fields::default()
            };
            assert_eq!(
                enc(&f).0,
                Err(FieldError::BadSgr {
                    field: 0,
                    offset: 0
                }),
                "{bad:?}"
            );
        }
    }

    // 이것을 실패시키는 것: 바이트 상한 비교를 `>=`로 바꾸거나 글자 수로 세는 것.
    #[test]
    fn size_bound_is_bytes_and_inclusive() {
        let overhead = enc(&Fields::default()).1.len();
        let exact = vec![b'x'; RECORD_MAX_BYTES - overhead];
        let (r, out) = enc(&Fields {
            left: &exact,
            ..Fields::default()
        });
        assert_eq!((r, out.len()), (Ok(Encoded::Full), RECORD_MAX_BYTES));

        let over = vec![b'x'; RECORD_MAX_BYTES - overhead + 1];
        let (r, out) = enc(&Fields {
            left: &over,
            ..Fields::default()
        });
        assert_eq!(r, Ok(Encoded::ReplacedBySizeLimit));
        let mut minimal = Vec::new();
        write_minimal_b1(Status::DEGRADED_OVERSIZE, &mut minimal);
        assert_eq!(out, minimal);
    }

    #[test]
    fn multibyte_record_over_bytes_but_under_chars_is_replaced() {
        let ko = "가".repeat(22_000); // 22,000 chars, 66,000 bytes
        let (r, _) = enc(&Fields {
            left: ko.as_bytes(),
            ..Fields::default()
        });
        assert_eq!(r, Ok(Encoded::ReplacedBySizeLimit));
    }

    #[test]
    fn encoder_appends_without_touching_existing_bytes() {
        let mut out = b"prefix".to_vec();
        write_minimal_b1(Status::OK_NONE, &mut out);
        assert!(out.starts_with(b"prefix"));
        assert_eq!(out.iter().filter(|&&b| b == RS).count(), 1);
        assert_eq!(*out.last().unwrap(), RS);
    }

    #[test]
    fn version_parse() {
        assert_eq!(RecordVersion::parse(b"B1"), Some(RecordVersion::B1));
        assert_eq!(RecordVersion::parse(b"B2"), None);
        assert_eq!(RecordVersion::parse(b"b1"), None);
        assert_eq!(RecordVersion::B1.as_str(), "B1");
    }

    // 이것을 실패시키는 것: C1 범위 상한을 U+0085 같은 값으로 줄이는 것.
    #[test]
    fn c1_boundaries() {
        for bad in ["\u{80}", "\u{9b}", "\u{9f}"] {
            let f = Fields {
                left: bad.as_bytes(),
                ..Fields::default()
            };
            assert_eq!(
                enc(&f).0,
                Err(FieldError::C1Control { field: 0 }),
                "{bad:?}"
            );
        }
        let f = Fields {
            left: "\u{a0}".as_bytes(),
            ..Fields::default()
        };
        assert_eq!(enc(&f).0, Ok(Encoded::Full));
    }

    // 이것을 실패시키는 것: `in_order()`에서 필드 하나를 빼먹는 것, 필드 번호를 어긋나게 보고하는 것.
    #[test]
    fn forbidden_byte_reports_each_field_index() {
        for idx in 0..6 {
            let mut parts: [&[u8]; 6] = [b""; 6];
            parts[idx] = b"a\x1fb";
            let f = Fields {
                left: parts[0],
                right: parts[1],
                transient_left: parts[2],
                transient_right: parts[3],
                vi_insert: parts[4],
                vi_command: parts[5],
            };
            assert_eq!(
                enc(&f).0,
                Err(FieldError::ForbiddenByte {
                    field: idx,
                    offset: 1,
                    byte: 0x1f
                })
            );
        }
    }

    // 이것을 실패시키는 것: C0 중 SOH·STX·올바른 SGR 외의 바이트(예: BEL)를 허용하는 것.
    #[test]
    fn c0_exhaustive() {
        for b in 0x00u8..=0x1F {
            let one = [b];
            let f = Fields {
                left: &one,
                ..Fields::default()
            };
            let r = enc(&f).0;
            match b {
                0x01 | 0x02 => assert_eq!(r, Ok(Encoded::Full), "{b:#x}"),
                0x1B => assert_eq!(
                    r,
                    Err(FieldError::BadSgr {
                        field: 0,
                        offset: 0
                    })
                ),
                _ => assert_eq!(
                    r,
                    Err(FieldError::ForbiddenByte {
                        field: 0,
                        offset: 0,
                        byte: b
                    }),
                    "{b:#x}"
                ),
            }
        }
        let f = Fields {
            left: b"\x1b[31m",
            ..Fields::default()
        };
        assert_eq!(enc(&f).0, Ok(Encoded::Full));
        let f = Fields {
            left: b"\x1bX",
            ..Fields::default()
        };
        assert!(enc(&f).0.is_err());
    }

    // 이것을 실패시키는 것: 사전 길이 검사를 없애 큰 필드를 먼저 복사하는 것.
    #[test]
    fn oversize_field_is_not_copied_into_out() {
        let big = vec![b'x'; 70_000];
        let mut out = Vec::new();
        let r = encode_b1(
            &Fields {
                left: &big,
                ..Fields::default()
            },
            Status::OK_NONE,
            &mut out,
        );
        assert_eq!(r, Ok(Encoded::ReplacedBySizeLimit));
        assert!(out.capacity() < 1024, "capacity {}", out.capacity());
    }

    // 이것을 실패시키는 것: 대체 때 `truncate(start)` 대신 `clear()`로 앞선 내용을 지우는 것.
    #[test]
    fn oversize_replacement_keeps_existing_prefix() {
        let overhead = enc(&Fields::default()).1.len();
        let over = vec![b'x'; RECORD_MAX_BYTES - overhead + 1];
        let mut out = b"abc".to_vec();
        let r = encode_b1(
            &Fields {
                left: &over,
                ..Fields::default()
            },
            Status::OK_NONE,
            &mut out,
        );
        assert_eq!(r, Ok(Encoded::ReplacedBySizeLimit));
        let mut minimal = b"abc".to_vec();
        write_minimal_b1(Status::DEGRADED_OVERSIZE, &mut minimal);
        assert_eq!(out, minimal);
    }
}
