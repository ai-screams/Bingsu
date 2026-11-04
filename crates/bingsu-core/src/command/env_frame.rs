//! The command environment the prompt hands the refresh helper: the shell's
//! environ entries (`NAME=VALUE\0`, as the shell passed them) in one frame of
//! magic, body length, CRC32C and body. The prompt writes it with one write
//! into an empty pipe whose read end the helper gets at [`FD`]; the helper's
//! envp stays empty, so its dynamic loader never sees these bytes. Neither
//! side parses the body here, and the helper never derives a location from it.

/// The helper descriptor the prompt hands the pipe's read end to.
pub const FD: i32 = 4;
const MAGIC: &[u8; 8] = b"BNGENV01";
const DOMAIN: &[u8] = b"bingsu-env-frame-v1\0";
/// Magic, body length (u32 little endian), CRC32C over domain, magic, length and body.
pub const HEADER: usize = 16;
/// The whole frame, header included: the default pipe capacity measured on
/// Linux (`F_GETPIPE_SZ`) and accepted by one non-blocking write on macOS,
/// so a frame this size fits one write into an empty pipe.
pub const FRAME_MAX: usize = 65_536;
/// What is left for the entries.
pub const BODY_MAX: usize = FRAME_MAX - HEADER;

/// The frame of `entries` in order, or `None` once they pass [`BODY_MAX`]
/// (the prompt then writes nothing). Entries after the crossing one are not
/// visited, so an oversize environment costs no more than the cap.
pub fn encode<'a>(entries: impl IntoIterator<Item = &'a [u8]>) -> Option<alloc::vec::Vec<u8>> {
    let mut out = alloc::vec::Vec::with_capacity(FRAME_MAX);
    out.extend_from_slice(&[0; HEADER]);
    for entry in entries {
        if entry.len() > BODY_MAX - (out.len() - HEADER) {
            return None;
        }
        out.extend_from_slice(entry);
    }
    let len = u32::try_from(out.len() - HEADER).ok()?;
    out[..8].copy_from_slice(MAGIC);
    out[8..12].copy_from_slice(&len.to_le_bytes());
    let crc = crate::snapshot::crc32c(&[DOMAIN, &out[..12], &out[HEADER..]]);
    out[12..16].copy_from_slice(&crc);
    Some(out)
}

/// The total frame size the header declares, once `prefix` holds the header:
/// the reader stops there instead of reading again for end of file.
pub fn declared(prefix: &[u8]) -> Option<usize> {
    let len = prefix.get(8..12)?;
    let len = u32::from_le_bytes([len[0], len[1], len[2], len[3]]) as usize;
    Some(HEADER.saturating_add(len))
}

/// The body of a complete frame. `None` (no environment for the round) for
/// a frame cut short, longer than declared, over the cap, with another
/// magic or with a wrong checksum.
pub fn body(frame: &[u8]) -> Option<&[u8]> {
    if frame.len() < HEADER || &frame[..8] != MAGIC {
        return None;
    }
    let total = declared(frame)?;
    if total > FRAME_MAX || frame.len() != total {
        return None;
    }
    let body = &frame[HEADER..total];
    if crate::snapshot::crc32c(&[DOMAIN, &frame[..12], body]) != frame[12..16] {
        return None;
    }
    Some(body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn entries(total: usize) -> alloc::vec::Vec<u8> {
        let mut e = b"BIG=".to_vec();
        e.resize(total - 1, b'x');
        e.push(0);
        e
    }

    // 이것을 실패시키는 것: 상한을 본문 기준 65,536으로 두는 것(HEADER를 빼지 않음). 본문이
    // 65,536 − 16 + 1바이트인 환경이 프레임 65,537바이트가 되어 한 번의 쓰기에 들어가지 않는다.
    #[test]
    fn frame_cap_counts_the_header() {
        let max = entries(BODY_MAX);
        let frame = encode([max.as_slice()]).unwrap();
        assert_eq!(frame.len(), FRAME_MAX);
        assert_eq!(body(&frame), Some(max.as_slice()));
        let over = entries(BODY_MAX + 1);
        assert_eq!(encode([over.as_slice()]), None);
        // The cap is on the sum, not on each entry.
        let half = entries(BODY_MAX / 2 + 1);
        assert_eq!(encode([half.as_slice(), half.as_slice()]), None);
    }

    // 이것을 실패시키는 것: encode의 상한 검사를 지우는 것(70 KB 환경이 프레임이 된다).
    #[test]
    fn oversize_environment_has_no_frame() {
        let big = entries(70 * 1024);
        assert_eq!(encode([b"A=1\0".as_slice(), big.as_slice()]), None);
        assert_eq!(encode(core::iter::empty()).map(|f| f.len()), Some(HEADER));
    }

    // 이것을 실패시키는 것: body의 길이 검사(`frame.len() != total`)를 지우는 것. 중간에 끊긴
    // 프레임은 slice가 panic하고, 선언보다 긴 프레임은 뒤 바이트가 조용히 버려진다.
    #[test]
    fn cut_or_long_frame_is_no_environment() {
        let frame = encode([b"HOME=/h\0".as_slice(), b"TERM=xterm\0"]).unwrap();
        for cut in 0..frame.len() {
            assert_eq!(body(&frame[..cut]), None, "cut at {cut}");
        }
        let mut long = frame.clone();
        long.push(0);
        assert_eq!(body(&long), None);
        assert_eq!(body(&frame), Some(b"HOME=/h\0TERM=xterm\0".as_slice()));
    }

    // 이것을 실패시키는 것: CRC 비교를 지우는 것(본문 바이트 뒤집기), magic 비교를 지우는 것
    // (CRC를 다시 계산한 다른 magic).
    #[test]
    fn damaged_frame_is_no_environment() {
        let frame = encode([b"HOME=/h\0".as_slice()]).unwrap();
        for i in 0..frame.len() {
            let mut bad = frame.clone();
            bad[i] ^= 0x20;
            assert_eq!(body(&bad), None, "flip at {i}");
        }
        let mut other = frame.clone();
        other[7] = b'2';
        let crc = crate::snapshot::crc32c(&[DOMAIN, &other[..12], &other[HEADER..]]);
        other[12..16].copy_from_slice(&crc);
        assert_eq!(body(&other), None);
        // 이것을 실패시키는 것: body의 `total > FRAME_MAX`를 지우는 것(읽는 쪽 버퍼가 아니라 디코더가 상한을 지킨다).
        let mut over = vec![0u8; HEADER];
        over[..8].copy_from_slice(MAGIC);
        over[8..12].copy_from_slice(&((BODY_MAX + 1) as u32).to_le_bytes());
        over.resize(FRAME_MAX + 1, b'x');
        let crc = crate::snapshot::crc32c(&[DOMAIN, &over[..12], &over[HEADER..]]);
        over[12..16].copy_from_slice(&crc);
        assert_eq!(body(&over), None);
        // A declared length over the cap is refused before any slice.
        let mut huge = vec![0u8; HEADER];
        huge[..8].copy_from_slice(MAGIC);
        huge[8..12].copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(body(&huge), None);
        assert_eq!(declared(&huge[..11]), None);
    }
}
