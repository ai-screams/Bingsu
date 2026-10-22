#![no_std]
#![forbid(unsafe_code)]
include!(concat!(env!("OUT_DIR"), "/build_id.rs"));

// 이것을 실패시키는 것: 함수 본문의 env 토큰 차단을 제거하여 빌드 환경을 받는 것.
fn hidden_input() {
    let _ = env!("IDENTITY_EXTRA");
}
