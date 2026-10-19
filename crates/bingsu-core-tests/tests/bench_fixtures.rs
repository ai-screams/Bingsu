#[path = "../../bingsu-core-bench/benches/support/catalog.rs"]
mod catalog;

// 이것을 실패시키는 것: 벤치 id 오타를 char의 인덱스 0으로 대체하는 것.
#[test]
fn missing_benchmark_index_panics() {
    for d in bingsu_core::field::BUILTIN {
        assert_eq!(bingsu_core::field::BUILTIN[catalog::index(d.id)].id, d.id);
    }
    assert!(std::panic::catch_unwind(|| catalog::index("duraton")).is_err());
}

// 이것을 실패시키는 것: 벤치 값의 id 오타를 None으로 숨겨 빈 렌더를 측정하는 것.
#[test]
fn missing_benchmark_value_panics() {
    assert!(catalog::value("dir", b"fixture").is_some());
    assert!(std::panic::catch_unwind(|| catalog::value("duraton", b"fixture")).is_err());
}
