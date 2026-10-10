//! Layer 1 properties of the M1 record encoder, so the test crate has a
//! real test from its first commit (Task A1).
use bingsu_core::record::{Encoded, Fields, RS, US, encode_b1};
use bingsu_core::status::Status;
use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig { cases: 256, ..ProptestConfig::default() })]

    // 이것을 실패시키는 것: 제어 문자 없는 UTF-8 필드를 거부하거나, 구분자 수·끝 RS가 틀린 레코드.
    #[test]
    fn printable_fields_encode(left in "[^\\x00-\\x1f\\x7f-\\u{9f}]{0,64}", right in "[^\\x00-\\x1f\\x7f-\\u{9f}]{0,64}") {
        let mut out = Vec::new();
        let f = Fields { left: left.as_bytes(), right: right.as_bytes(), ..Fields::default() };
        prop_assert_eq!(encode_b1(&f, Status::OK_NONE, &mut out), Ok(Encoded::Full));
        prop_assert_eq!(out.iter().filter(|b| **b == US).count(), 8);
        prop_assert_eq!(out.last(), Some(&RS));
    }

    // 이것을 실패시키는 것: SOH·STX가 아닌 C0 바이트(줄바꿈·US·RS 포함)를 받는 인코더.
    #[test]
    fn other_c0_is_rejected(prefix in "[a-z]{0,8}", b in (0u8..0x20).prop_filter("SOH/STX/ESC are allowed or SGR", |b| !matches!(b, 1 | 2 | 0x1b))) {
        let mut field = prefix.into_bytes();
        field.push(b);
        let mut out = Vec::new();
        let f = Fields { left: &field, ..Fields::default() };
        let rejected = encode_b1(&f, Status::OK_NONE, &mut out).is_err();
        prop_assert!(rejected);
    }
}
