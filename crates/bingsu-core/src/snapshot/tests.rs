// The purity checker scans every source file independently.
#[cfg(test)]
mod cases {
    use super::super::*;
    // 이것을 실패시키는 것: 해당 wire·CRC·정체·문맥 검사나 필드 보존을 생략하는 것.
    #[test]
    fn crc32c_vectors() {
        assert_eq!(crc32c(&[]), [0; 4]);
        assert_eq!(crc32c(&[b"123456789"]), 0xe306_9283u32.to_le_bytes());
        assert_eq!(crc32c(&[b"123", b"", b"456789"]), crc32c(&[b"123456789"]));
        assert_eq!(crc32c(&[&[0; 32]]), 0x8a91_36aau32.to_le_bytes());
    }
    // 이것을 실패시키는 것: 해당 wire·CRC·정체·문맥 검사나 필드 보존을 생략하는 것.
    #[test]
    fn crc_reserved_and_legacy_rejected() {
        let (_, m, _) = fixture();
        for i in [0, 8, 10, 13, 14, 84, 116, 160, 180, 207] {
            let mut b = m.encode();
            b[i] ^= 0x80;
            let sum = crc32c(&[b"bingsu-marker-v2\0", &b[..176]]);
            b[176..180].copy_from_slice(&sum);
            assert!(Marker::decode(&b).is_err(), "{i}");
        }
        let mut b = m.encode();
        b[7] = b'1';
        b[8] = 1;
        let sum = crc32c(&[b"bingsu-marker-v2\0", &b[..176]]);
        b[176..180].copy_from_slice(&sum);
        assert!(Marker::decode(&b).is_err());
    }
    // 이것을 실패시키는 것: 해당 wire·CRC·정체·문맥 검사나 필드 보존을 생략하는 것.
    #[test]
    fn contexts_share_only_canonical_root() {
        let mut long = alloc::vec![b'/'];
        long.extend_from_slice(&alloc::vec![b'x';COMPILED_MAX]);
        assert!(context_components(&long[..65537], b"/").is_ok());
        assert!(context_components(&long, b"/").is_err());
        assert!(context_crc(b"/", &long).is_err());
        assert!(context_components(b"/", b"/").is_ok());

        let a = context_components(b"/cfg/a", b"/state/a").unwrap();
        assert_eq!(a, context_components(b"/cfg/a", b"/state/a").unwrap());
        assert_eq!(
            a,
            [
                "contexts-v2",
                "config",
                "2f6366672f61",
                "state",
                "2f73746174652f61",
                "store"
            ]
        );
        for (c, s) in [
            (b"/cfg/b".as_slice(), b"/state/a".as_slice()),
            (b"/cfg/a", b"/state/b"),
            (b"/cfg/a", b"/state/aa"),
            (b"/cfg/a", b"/state/\xff"),
        ] {
            assert_ne!(a, context_components(c, s).unwrap());
            assert_ne!(context_crc(b"/cfg/a", b"/state/a"), context_crc(c, s));
        }
        assert_ne!(
            context_components(b"/a", b"/b/c"),
            context_components(b"/a/b", b"/c")
        );
        let mut root = alloc::vec![b'/'];
        root.extend_from_slice(&[b'x'; 200]);
        assert!(
            context_components(&root, &root)
                .unwrap()
                .iter()
                .all(|s| s.len() <= 120)
        );
        for bad in [
            b"relative".as_slice(),
            b"",
            b"/a\0b",
            b"/a/../b",
            b"/a/./b",
            b"/a//b",
            b"/a/",
        ] {
            assert!(context_components(bad, b"/state").is_err());
            assert!(context_components(b"/cfg", bad).is_err());
        }
    }
    // 이것을 실패시키는 것: 해당 wire·CRC·정체·문맥 검사나 필드 보존을 생략하는 것.
    #[test]
    fn frame_reserved_rejected() {
        let (id, _, _) = fixture();
        let s = Snapshot {
            id,
            config: crate::config::report::tests::read("", &[])
                .snapshot
                .unwrap(),
            metadata: encode_metadata(b"").unwrap(),
        };
        for i in [28, 124, 164] {
            let mut b = s.encode(1, 0).unwrap();
            b[i] ^= 0x80;
            let sum = crc32c(&[
                b"bingsu-snapshot-v2\0",
                &b[..160],
                &b[192..b.len() - s.metadata.len()],
            ]);
            b[160..164].copy_from_slice(&sum);
            assert!(
                Snapshot::decode_front(&b[..b.len() - s.metadata.len()], b.len(), 80).is_err(),
                "{i}"
            );
        }
    }
    fn valid_header() -> Vec<u8> {
        let (id, _, _) = fixture();
        Snapshot {
            id,
            config: crate::config::report::tests::read("", &[])
                .snapshot
                .unwrap(),
            metadata: encode_metadata(b"").unwrap(),
        }
        .encode(1, 0)
        .unwrap()
    }
    // 이것을 실패시키는 것: N7 magic 검사를 머리 단계에서 생략하는 것.
    #[test]
    fn wire_reject_magic() {
        let mut b = valid_header();
        assert_eq!(header(&b[..HEADER]), Ok(()));
        b[0] ^= 0x80;
        assert_eq!(header(&b[..HEADER]), Err(Error::Tag));
    }
    // 이것을 실패시키는 것: N7 version 검사를 머리 단계에서 생략하는 것.
    #[test]
    fn wire_reject_version() {
        let mut b = valid_header();
        assert_eq!(header(&b[..HEADER]), Ok(()));
        b[8] ^= 0x80;
        assert_eq!(header(&b[..HEADER]), Err(Error::Tag));
    }
    // 이것을 실패시키는 것: N7 header_length 검사를 머리 단계에서 생략하는 것.
    #[test]
    fn wire_reject_header_length() {
        let mut b = valid_header();
        assert_eq!(header(&b[..HEADER]), Ok(()));
        b[10] ^= 0x80;
        assert_eq!(header(&b[..HEADER]), Err(Error::Tag));
    }
    // 이것을 실패시키는 것: N7 reserved 검사를 머리 단계에서 생략하는 것.
    #[test]
    fn wire_reject_reserved() {
        let mut b = valid_header();
        assert_eq!(header(&b[..HEADER]), Ok(()));
        b[13] ^= 0x80;
        assert_eq!(header(&b[..HEADER]), Err(Error::Tag));
    }
    // 이것을 실패시키는 것: N7 abi 검사를 머리 단계에서 생략하는 것.
    #[test]
    fn wire_reject_abi() {
        let mut b = valid_header();
        assert_eq!(header(&b[..HEADER]), Ok(()));
        b[72] ^= 0x80;
        assert_eq!(lengths(&b), Err(Error::Tag));
    }
    // 이것을 실패시키는 것: compiled 길이 상한 검사를 머리 단계에서 생략하는 것.
    #[test]
    fn wire_reject_compiled_length() {
        let mut b = valid_header();
        b[60..64].copy_from_slice(&((PREFIX + COMPILED_MAX + 1) as u32).to_le_bytes());
        assert_eq!(header(&b[..HEADER]), Err(Error::Limit));
    }

    // 이것을 실패시키는 것: fd 크기 상한을 없애 본문 할당 단계로 진행하는 것.
    #[test]
    fn wire_reject_file_capacity() {
        let cap = (HEADER + PREFIX + COMPILED_MAX + META_MAX) as u64;
        assert!(FrontDecoder::new(cap).is_ok());
        assert!(matches!(FrontDecoder::new(cap + 1), Err(Error::Limit)));
    }

    fn fixture() -> (Identity, Marker, Clock) {
        let id = Identity {
            boot: [1; 16],
            epoch: [2; 16],
            context: [3; 4],
            generation: 7,
            source: [4; 4],
        };
        (
            id,
            Marker {
                id,
                seq: 9,
                verified_at: 100,
                kind: 1,
                domain: [5; 16],
                resume: 0,
                invalid: false,
            },
            Clock {
                kind: 1,
                domain: [5; 16],
                resume: 0,
                boot: [1; 16],
                now: 101,
            },
        )
    }
    // 이것을 실패시키는 것: 표식 조건 하나를 제거하면 해당 한 조건만 바꾼 행이 통과한다.
    // 이것을 실패시키는 것: 해당 wire·CRC·정체·문맥 검사나 필드 보존을 생략하는 것.
    #[test]
    fn eligibility_each_condition() {
        let (id, m, c) = fixture();
        assert_eq!(eligible(id, Some(m), c, id.context), Ok(100 + T_NS));
        assert_eq!(eligible(id, None, c, id.context), Err(Refusal::Missing));
        // 이것을 실패시키는 것: 서로 일치하는 외부 문맥의 사본·표식을 허용하는 것.
        assert_eq!(eligible(id, Some(m), c, [99; 4]), Err(Refusal::Pair));
        let mut x = m;
        x.invalid = true;
        assert_eq!(eligible(id, Some(x), c, id.context), Err(Refusal::Invalid));
        for field in 0..5 {
            let mut x = m;
            match field {
                0 => x.id.generation += 1,
                1 => x.id.source[0] ^= 1,
                2 => x.id.boot[0] ^= 1,
                3 => x.id.epoch[0] ^= 1,
                _ => x.id.context[0] ^= 1,
            };
            assert_eq!(
                eligible(id, Some(x), c, id.context),
                Err(Refusal::Pair),
                "{field}"
            );
        }
        let mut x = c;
        x.boot[0] ^= 1;
        assert_eq!(eligible(id, Some(m), x, id.context), Err(Refusal::Boot));
        let mut x = c;
        x.kind = 2;
        assert_eq!(eligible(id, Some(m), x, id.context), Err(Refusal::Clock));
        let mut x = c;
        x.domain[0] ^= 1;
        assert_eq!(eligible(id, Some(m), x, id.context), Err(Refusal::Clock));
        let mut x = c;
        x.resume = 1;
        assert_eq!(eligible(id, Some(m), x, id.context), Err(Refusal::Resume));
        let mut x = c;
        x.now = 99;
        assert_eq!(eligible(id, Some(m), x, id.context), Err(Refusal::Future));
        let mut x = c;
        x.now = 100 + T_NS;
        assert_eq!(eligible(id, Some(m), x, id.context), Err(Refusal::Expired));
        let mut x = m;
        x.verified_at = u64::MAX - 1;
        let mut c = c;
        c.now = u64::MAX - 1;
        assert_eq!(eligible(id, Some(x), c, id.context), Err(Refusal::Expired));
        assert!(!same_boot(id, None, id.context));
        assert!(!same_boot(id, Some([0; 16]), id.context));
        assert!(same_boot(id, Some(id.boot), id.context));
    }
    // 이것을 실패시키는 것: 해당 wire·CRC·정체·문맥 검사나 필드 보존을 생략하는 것.
    #[test]
    fn marker_wire() {
        let (_, m, _) = fixture();
        let b = m.encode();
        assert_eq!(&b[..16], b"BNGMRK02\x02\0\xd0\0\x01\x01\0\0");
        assert_eq!(Marker::decode(&b), Ok(m));
        for i in 0..b.len() {
            let mut x = b;
            x[i] ^= 0x80;
            assert!(Marker::decode(&x).is_err(), "{i}")
        }
        for n in 0..MARKER {
            assert!(Marker::decode(&b[..n]).is_err())
        }
    }
    // 이것을 실패시키는 것: 본문 필드 생략, 머리/본문 체크섬·길이·태그 검사를 제거한다.
    // 이것을 실패시키는 것: 해당 wire·CRC·정체·문맥 검사나 필드 보존을 생략하는 것.
    #[test]
    fn compiled_roundtrip_and_frame() {
        for root in [
            "",
            "icons='ascii'\n[width]\nambiguous=2\n",
            "[segment.\"custom/hello\"]\nkind='command'\ncommand=['echo','ok']\n[layout.line2]\nleft=['custom/hello','char']\n",
        ] {
            let report = crate::config::report::tests::read(root, &[]);
            let c = report.snapshot.expect("valid fixture");
            let b = snapshot_codec::encode_compiled(&c).expect("encode");
            assert_eq!(snapshot_codec::decode_compiled(&b), Ok(c.clone()));
            let (id, _, _) = fixture();
            let s = Snapshot {
                id,
                config: c,
                metadata: encode_metadata(&[1, 2, 3]).unwrap(),
            };
            let b = s.encode(1, 0).unwrap();
            let front = &b[..b.len() - s.metadata.len()];
            let got = Snapshot::decode_front(front, b.len(), 80).unwrap();
            assert_eq!(got.id, id);
            assert_eq!(
                got.config,
                crate::layout_view::FrontConfig::from_compiled(s.config.clone(), 80)
            );
            assert_eq!((got.clock_kind, got.resume), (1, 0));
            assert!(Snapshot::decode_front(front, b.len() + 1, 80).is_err());
            for i in [
                0,
                8,
                10,
                12,
                13,
                16,
                24,
                56,
                60,
                64,
                72,
                74,
                76,
                80,
                84,
                85,
                88,
                104,
                120,
                152,
                160,
                192,
                front.len() - 1,
            ] {
                let mut x = front.to_vec();
                x[i] ^= 0x80;
                assert!(Snapshot::decode_front(&x, b.len(), 80).is_err(), "{i}");
            }
        }
    }

    // 이것을 실패시키는 것: fact schema 저장·읽기 검사를 빼거나 구 codec의 field index를 허용하는 것.
    #[test]
    fn compiled_fact_schema_mismatch_is_rejected_before_field_indices() {
        let config = crate::config::report::tests::read(
            "[style]\ntemplate='{git.operation}{git.staged}{git.stash}{char}'\n",
            &[],
        )
        .snapshot
        .unwrap();
        let original = snapshot_codec::encode_compiled(&config).unwrap();
        // 이것을 실패시키는 것: 크기 사전 계산에서 schema bytes를 빼 재할당하게 만드는 것.
        assert_eq!(original.capacity(), original.len());
        assert_eq!(&original[..12], b"BNGCFG03\x03\0\x02\0");
        assert_eq!(snapshot_codec::decode_compiled(&original), Ok(config));
        for version in [0u16, 1, 3, u16::MAX] {
            let mut bytes = original.clone();
            bytes[10..12].copy_from_slice(&version.to_le_bytes());
            assert_eq!(snapshot_codec::decode_compiled(&bytes), Err(Error::Tag));
        }
        for (offset, value) in [(7, b'2'), (8, 2)] {
            let mut bytes = original.clone();
            bytes[offset] = value;
            assert_eq!(snapshot_codec::decode_compiled(&bytes), Err(Error::Tag));
        }
        // Old codecs had no fact schema field. Even otherwise valid nodes
        // must not be reinterpreted using today's declaration order.
        let mut legacy = original;
        legacy.drain(10..12);
        legacy[..10].copy_from_slice(b"BNGCFG02\x02\0");
        assert_eq!(snapshot_codec::decode_compiled(&legacy), Err(Error::Tag));
    }

    // 이것을 실패시키는 것: 재계산 CRC만 믿고 예약 영역·flags/mask·길이·codec 구조 검사를 빼는 것(앞단의
    // 선택 디코드와 도우미의 전체 디코드 어느 쪽에서든).
    #[test]
    fn rechecksummed_frames_and_limits() {
        let (id, _, _) = fixture();
        let s = Snapshot {
            id,
            config: crate::config::report::tests::read("", &[])
                .snapshot
                .unwrap(),
            metadata: encode_metadata(b"evidence").unwrap(),
        };
        let original = s.encode(1, 0).unwrap();
        assert_eq!(Snapshot::decode(&original).unwrap(), s);
        let end = original.len() - s.metadata.len();
        for at in [
            0, 8, 10, 12, 13, 28, 56, 60, 64, 72, 74, 76, 80, 84, 85, 124, 164, 192, 200,
        ] {
            let mut b = original.clone();
            b[at] ^= 0x80;
            let crc = crc32c(&[b"bingsu-snapshot-v2\0", &b[..160], &b[192..end]]);
            b[160..164].copy_from_slice(&crc);
            assert!(
                Snapshot::decode_front(&b[..end], b.len(), 80).is_err(),
                "{at}"
            );
            // The helper's whole decode shares the frame checks, not the code path.
            assert!(Snapshot::decode(&b).is_err(), "{at}");
        }
        // Advertise one extra compiled byte and a matching fstat length, while
        // supplying a complete (shorter) codec with a recomputed frame CRC.
        let mut short = original.clone();
        let c = end - HEADER - PREFIX + 1;
        short[76..80].copy_from_slice(&(c as u32).to_le_bytes());
        short[60..64].copy_from_slice(&((PREFIX + c) as u32).to_le_bytes());
        let sum = crc32c(&[b"bingsu-snapshot-v2\0", &short[..160], &short[192..end]]);
        short[160..164].copy_from_slice(&sum);
        assert!(Snapshot::decode_front(&short[..end], short.len() + 1, 80).is_err());
        let mut changed = original.clone();
        changed[12] ^= 1;
        let sum = crc32c(&[b"bingsu-snapshot-v2\0", &changed[..160], &changed[192..end]]);
        changed[160..164].copy_from_slice(&sum);
        assert!(Snapshot::decode_front(&changed[..end], changed.len(), 80).is_err());
        assert!(Snapshot::decode(&changed).is_err());
        for (at, n) in [(76, COMPILED_MAX + 1), (80, META_MAX + 1)] {
            let mut b = original.clone();
            b[at..at + 4].copy_from_slice(&(n as u32).to_le_bytes());
            if at == 76 {
                b[60..64].copy_from_slice(&((n + PREFIX) as u32).to_le_bytes());
            }
            assert!(lengths(&b).is_err());
        }
        for n in 0..original.len() {
            assert!(Snapshot::decode(&original[..n]).is_err(), "{n}");
        }
        assert!(Snapshot::decode_front(&original[..end - 1], original.len(), 80).is_err());
        let mut b = original.clone();
        b[end + 16] ^= 1;
        assert!(Snapshot::decode(&b).is_err());
        assert!(Snapshot::decode_front(&b[..end], b.len(), 80).is_ok()); // front cannot inspect trust payload
        assert!(s.encode(3, 0).is_err());
        let mut s = s;
        s.metadata = alloc::vec![0;META_MAX+1];
        assert!(s.encode(1, 0).is_err());
    }

    // 이것을 실패시키는 것: sequence의 G/V 예약·overflow·길이·예약·CRC 또는 metadata framing을 바꾸는 것.
    #[test]
    fn sequence_and_metadata_wire() {
        let s = Sequence {
            boot: [1; 16],
            epoch: [2; 16],
            generation: 7,
            verified: 9,
        };
        let b = s.encode();
        assert_eq!(Sequence::decode(&b), Ok(s));
        assert_eq!(s.reserve(false).unwrap().generation, 7);
        assert_eq!(s.reserve(true).unwrap().generation, 8);
        assert_eq!(s.reserve(false).unwrap().verified, 10);
        assert!(
            Sequence {
                generation: u64::MAX,
                ..s
            }
            .reserve(true)
            .is_err()
        );
        assert!(
            Sequence {
                verified: u64::MAX,
                ..s
            }
            .reserve(false)
            .is_err()
        );
        for i in 0..96 {
            let mut x = b;
            x[i] ^= 1;
            assert!(Sequence::decode(&x).is_err());
        }
        for end in 0..96 {
            assert!(Sequence::decode(&b[..end]).is_err());
        }
        for at in [0, 8, 10, 12, 68] {
            let mut x = b;
            x[at] ^= 1;
            let sum = crc32c(&[b"bingsu-sequence-v2\0", &x[..64]]);
            x[64..68].copy_from_slice(&sum);
            assert!(Sequence::decode(&x).is_err());
        }
        let b = encode_metadata(b"path/\xff\0evidence").unwrap();
        assert_eq!(decode_metadata(&b).unwrap(), b"path/\xff\0evidence");
        for i in 0..b.len() {
            let mut x = b.clone();
            x[i] ^= 1;
            assert!(decode_metadata(&x).is_err());
        }
        for end in 0..b.len() {
            assert!(decode_metadata(&b[..end]).is_err());
        }
        for at in [0, 8, 10, 12] {
            let mut x = b.clone();
            x[at] ^= 1;
            let len = x.len();
            let sum = crc32c(&[b"bingsu-trust-v2\0", &x[..len - 4]]);
            x[len - 4..].copy_from_slice(&sum);
            assert!(decode_metadata(&x).is_err());
        }
        assert_eq!(
            encode_metadata(&alloc::vec![0;META_MAX-19]),
            Err(Error::Limit)
        );
        assert_eq!(
            decode_metadata(&alloc::vec![0;META_MAX+1]),
            Err(Error::Limit)
        );
        assert_eq!(
            source_crc(b"catalog"),
            crc32c(&[b"bingsu-sources-v2\0", b"catalog"])
        );
    }

    // 이것을 실패시키는 것: T 경계·Invalid의 우선순위·문맥·부팅 부재를 잘못 인정하는 것.
    #[test]
    fn deadline_boot_and_invalid_boundaries() {
        let (id, m, c) = fixture();
        for offset in [T_NS - 1, T_NS, T_NS + 1] {
            assert_eq!(
                eligible(
                    id,
                    Some(m),
                    Clock {
                        now: m.verified_at + offset,
                        ..c
                    },
                    id.context
                )
                .is_ok(),
                offset < T_NS
            );
        }
        assert_eq!(
            eligible(
                Identity {
                    generation: 999,
                    ..id
                },
                Some(Marker { invalid: true, ..m }),
                Clock { now: u64::MAX, ..c },
                id.context
            ),
            Err(Refusal::Invalid)
        );
        assert!(!same_boot(id, Some(id.boot), [99; 4]));
        assert_eq!(
            eligible(
                id,
                Some(Marker { kind: 3, ..m }),
                Clock { kind: 3, ..c },
                id.context
            ),
            Err(Refusal::Clock)
        );
        let mut unknown = Marker::encode(m);
        unknown[12] = 3;
        let crc = crc32c(&[b"bingsu-marker-v2\0", &unknown[..176]]);
        unknown[176..180].copy_from_slice(&crc);
        assert!(Marker::decode(&unknown).is_err());
    }

    // 이것을 실패시키는 것: namespace의 관찰 실패를 기능 부재로 낮추거나 환산에서 u64 곱셈·wrap을 쓰는 것.
    #[test]
    fn namespace_absence_and_timebase() {
        assert_eq!(namespace_domain(None, true, [true; 3]), Ok([0; 16]));
        let d = namespace_domain(Some((125, 333)), true, [false; 3]).unwrap();
        assert_eq!(&d[..8], &125u64.to_le_bytes());
        assert_eq!(&d[8..], &333u64.to_le_bytes());
        for handle in [None, Some((1, 2))] {
            assert_eq!(
                namespace_domain(handle, false, [true; 3]),
                Err(ClockError::Domain)
            );
        }
        for missing in [
            [false, true, true],
            [true, false, true],
            [true, true, false],
        ] {
            assert!(namespace_domain(None, true, missing).is_err());
        }
        for handle in [Some((0, 2)), Some((1, 0))] {
            assert!(namespace_domain(handle, true, [false; 3]).is_err());
        }
        assert_eq!(ticks_to_ns(3, 125, 3), Ok(125));
        assert_eq!(ticks_to_ns(u64::MAX, 1, 1), Ok(u64::MAX));
        assert_eq!(ticks_to_ns(u64::MAX, 2, 2), Ok(u64::MAX));
        assert!(ticks_to_ns(u64::MAX, 125, 3).is_err());
        assert!(ticks_to_ns(1, 0, 1).is_err());
        assert!(ticks_to_ns(1, 1, 0).is_err());
    }
}

#[cfg(test)]
mod publication {
    use super::super::*;
    // 이것을 실패시키는 것: Incomplete 보존·Invalid 번호·G/V 증가·마감/역행/overflow 검사 중 하나를 지우는 것.
    #[test]
    fn publication_transitions_obey_deadlines_and_never_wrap() {
        assert_eq!(
            decide(Outcome::Incomplete, true, 1, 2, 0, 1, 10),
            Action::Keep
        );
        assert_eq!(
            decide(Outcome::Invalid, true, 1, 2, 0, 1, 10),
            Action::Invalidate { seq: 3 }
        );
        assert_eq!(
            decide(Outcome::Publish, false, 1, 2, 0, 1, 10),
            Action::Refresh {
                generation: 1,
                seq: 3
            }
        );
        assert_eq!(
            decide(Outcome::Publish, true, 1, 2, 0, 1, 10),
            Action::Replace {
                generation: 2,
                seq: 3
            }
        );
        assert_eq!(
            decide(Outcome::Publish, true, 1, 2, 0, 10, 10),
            Action::Keep
        );
        assert_eq!(decide(Outcome::Publish, true, 1, 2, 2, 1, 10), Action::Keep);
        assert_eq!(
            decide(Outcome::Publish, true, 1, 2, 0, T_NS, T_NS + 1),
            Action::Keep
        );
        assert_eq!(
            decide(Outcome::Publish, true, u64::MAX, 2, 0, 1, 10),
            Action::Keep
        );
        assert_eq!(
            decide(Outcome::Publish, true, 1, u64::MAX, 0, 1, 10),
            Action::Keep
        );
        assert_eq!(
            decide(
                Outcome::Publish,
                true,
                1,
                2,
                u64::MAX - 1,
                u64::MAX - 1,
                u64::MAX
            ),
            Action::Keep
        );
    }
}
