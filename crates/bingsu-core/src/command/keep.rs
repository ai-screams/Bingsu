//! The environment names every config unit may pass (spec, sanitized
//! environment: keep list), plus every `LC_*`. The prompt reads them too:
//! they decide its environment digest and which frame names it keeps
//! (`plan.rs`), so this file is pinned with the prompt's files. The grant
//! re-exports them for the helper's approval.

/// Names every config unit may pass.
pub const KEEP: [&[u8]; 6] = [b"HOME", b"USER", b"LANG", b"TERM", b"TZ", b"PATH"];
/// Every name with this prefix may pass too.
pub const KEEP_PREFIX: &[u8] = b"LC_";

#[cfg(test)]
mod tests {
    use super::*;

    // 옮기기 전 grant.rs의 값 그대로다. 이것을 실패시키는 것: 이름 하나를 바꾸거나 빼거나 더하는 것, 접두사를
    // 바꾸는 것.
    #[test]
    fn the_moved_names_are_unchanged() {
        assert_eq!(
            KEEP,
            [&b"HOME"[..], b"USER", b"LANG", b"TERM", b"TZ", b"PATH"]
        );
        assert_eq!(KEEP_PREFIX, b"LC_");
    }
}
