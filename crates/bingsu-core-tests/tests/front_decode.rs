use bingsu_core::layout_view::FrontConfig;
use bingsu_core::snapshot::{FrontDecoder, HEADER, PREFIX, READ_CHUNK, Snapshot};
use bingsu_core_tests::snapshot_fixture;

// 이것을 실패시키는 것: compiled clock kind/resume 누락, metadata 읽기, EOF/전체 fd 길이 불일치 허용.
#[test]
fn staged_decode_preserves_clock_and_never_requests_metadata() {
    let s = snapshot_fixture::frame();
    for (kind, resume) in [(1, 0), (2, 999)] {
        let bytes = s.encode(kind, resume).unwrap();
        let (c, _) = bingsu_core::snapshot::lengths(&bytes).unwrap();
        let end = HEADER + PREFIX + c;
        for (chunk, width) in [(1, 80), (13, 120), (READ_CHUNK, 99)] {
            let (decoded, read) = snapshot_fixture::front_read(&bytes, width, chunk).unwrap();
            assert!(read <= end);
            assert_eq!((decoded.clock_kind, decoded.resume), (kind, resume));
            assert_eq!(
                decoded.config,
                FrontConfig::from_compiled(s.config.clone(), width)
            );
        }
        for length in 0..end {
            assert!(Snapshot::decode_front(&bytes[..length], bytes.len(), 80).is_err());
        }
        assert!(Snapshot::decode_front(&bytes[..end], bytes.len() + 1, 80).is_err());
    }
}

// 이것을 실패시키는 것: read 승인 길이보다 큰 관찰을 받아 본문 버퍼를 키우거나 손상 CRC를 허용하는 것.
#[test]
fn staged_decode_rejects_overlong_observations_and_corruption() {
    let s = snapshot_fixture::frame();
    let bytes = s.encode(1, 0).unwrap();
    let end = bytes.len() - s.metadata.len();
    let mut decoder = FrontDecoder::new(bytes.len() as u64, 80).unwrap();
    assert!(decoder.push(&bytes[..HEADER + 1]).is_err());
    assert!(decoder.push(&[]).is_err());
    for at in [
        0,
        8,
        16,
        24,
        60,
        64,
        76,
        80,
        84,
        88,
        120,
        152,
        160,
        192,
        snapshot_fixture::selected_end(&bytes, 80) - 1,
    ] {
        let mut bad = bytes.clone();
        bad[at] ^= 0x80;
        assert!(
            snapshot_fixture::front_read(&bad, 80, READ_CHUNK).is_err(),
            "byte {at}"
        );
    }
    assert!(end > snapshot_fixture::selected_end(&bytes, 80));
}
