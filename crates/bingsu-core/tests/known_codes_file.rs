//! The shell golden harness reads tests/golden/record/known_codes.txt;
//! init embeds Status::KNOWN_NON_OK. They must be the same list.
use bingsu_core::status::Status;

// 이것을 실패시키는 것: KNOWN_NON_OK에 코드를 더하고 파일을 고치지 않는 것(또는 반대).
#[test]
fn known_codes_file_matches_core() {
    let text = include_str!("../../../tests/golden/record/known_codes.txt");
    let file: Vec<&str> = text.lines().filter(|l| !l.is_empty()).collect();
    let core: Vec<String> = Status::KNOWN_NON_OK
        .iter()
        .map(|s| {
            let mut b = Vec::new();
            s.write_to(&mut b);
            String::from_utf8(b).unwrap()
        })
        .collect();
    assert_eq!(file, core);
}
