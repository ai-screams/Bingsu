#![no_std]
#![forbid(unsafe_code)]
include!(concat!(env!("OUT_DIR"), "/build_id.rs"));
// 이것을 실패시키는 것: cfg 뒤에 숨긴 worker import를 identity gate가 놓치는 것.
#[cfg(target_os = "linux")]
pub mod worker {
    pub use gix_config::File;
}
