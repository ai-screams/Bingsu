#![no_std]
#![forbid(unsafe_code)]
include!(concat!(env!("OUT_DIR"), "/build_id.rs"));

// 이것을 실패시키는 것: 함수 본문의 macro_rules 토큰 차단을 제거하여 토큰 생성을 허용하는 것.
fn hidden_input() {
    macro_rules! hidden { () => { 0 }; }
    let _ = hidden!();
}
