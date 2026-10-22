#![no_std]
#![forbid(unsafe_code)]
include!(concat!(env!("OUT_DIR"), "/build_id.rs"));

// 이것을 실패시키는 것: 함수 본문의 include_bytes 토큰 차단을 제거하여 외부 바이트를 받는 것.
fn hidden_input() {
    let _ = include_bytes!("extra.bin");
}
