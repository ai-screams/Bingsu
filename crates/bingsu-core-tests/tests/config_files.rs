//! File-backed core checks live outside the no_std crate.
use bingsu_core::diag_codes::{CODES, CodeStatus};

// 이것을 실패시키는 것: 코드를 지우는 것, 목록 파일에 적지 않고 코드를 더하는 것,
// 상태를 파일과 다르게 바꾸는 것, 번호 순서·중복을 어기는 것.
#[test]
fn registry_matches_the_listed_codes() {
    let listed = include_str!("../../bingsu-core/diag-codes.txt");
    let status = |s: CodeStatus| match s {
        CodeStatus::Stable => String::from("stable"),
        CodeStatus::Deprecated { since } => format!("deprecated {since}"),
    };
    let got: Vec<String> = CODES
        .iter()
        .map(|c| format!("{} {}", c.code, status(c.status)))
        .collect();
    let want: Vec<&str> = listed
        .lines()
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect();
    assert_eq!(got, want);
    assert!(CODES.windows(2).all(|p| p[0].code < p[1].code));
}
