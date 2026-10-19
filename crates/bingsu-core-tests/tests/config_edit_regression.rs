use bingsu_core::config::edit::{EditError, remove};

// 이것을 실패시키는 것: 인라인 자식을 지우며 형제/조상까지 손상시키는 것.
// K39: remove의 header/dotted-table 앞단 거부만 삭제하는 변이는 동등하다.
// 표 머리/점 키는 독립된 키 줄이 아니므로 뒤의 !alone 검사가 같은
// Unsupported로 거부한다. verify도 결과의 대상·이웃 보존을 확인한다.
// 앞단의 명시적 방어와 결과 검증은 유지한다. inside_inline 검사는 이
// 동등 변이에 포함하지 않는다(여러 줄 인라인 자식에는 꼭 필요하다).
#[test]
fn removal_keeps_redundant_table_defence() {
    for (source, path) in [
        ("[a]\nb = 1\n", &["a"][..]),
        ("a.b = 1\n", &["a"][..]),
        ("a = {\n b = 1\n}\n", &["a", "b"][..]),
        ("a = {\n b.c = 1\n}\n", &["a", "b", "c"][..]),
        ("[t]\na = { b = {\n c = 1\n} }\n", &["t", "a", "b", "c"][..]),
    ] {
        assert_eq!(remove(source.as_bytes(), path), Err(EditError::Unsupported));
    }
}
