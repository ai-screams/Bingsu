#[cfg(test)]
mod cases {
    use super::super::*;
    use alloc::{format, string::ToString, vec};

    fn binding() -> Binding {
        let config = b"/home/u/.config/bingsu".to_vec();
        let state = b"/home/u/.local/state/bingsu".to_vec();
        Binding {
            build_id: BuildId([7; 32]),
            boot: [1; 16],
            epoch: [2; 16],
            context: snapshot::context_crc(&config, &state).unwrap(),
            clock_kind: 1,
            domain: [3; 16],
            resume: 4,
            config,
            state,
            cwd: b"/home/u/repo".to_vec(),
        }
    }

    fn entry(id: &str, attempted_at: u64, completed_at: u64) -> Entry {
        Entry {
            origin: Origin::Config,
            id: id.to_string(),
            policy: [5; 32],
            environment: [6; 32],
            pattern: [0; 32],
            attempted_at,
            completed_at,
            status: Status::Ok,
            value: format!("v-{id}"),
            raw: format!("v-{id}"),
        }
    }

    // 왕복과 머리 검사. 이것을 실패시키는 것: decode의 CRC 비교를 지우는 것(본문 1바이트를 바꾼 파일을 받음),
    // 마지막 항목 뒤 남는 바이트 검사를 지우는 것(길이·CRC가 맞는 꼬리를 받음).
    #[test]
    fn response_round_trips_and_refuses_damage() {
        let r = Response {
            binding: binding(),
            entries: vec![entry("custom/a", 10, 20), entry("custom/b", 11, 21)],
        };
        let bytes = r.encode().unwrap();
        assert_eq!(Response::decode(&bytes).unwrap(), r);
        let mut flipped = bytes.clone();
        *flipped.last_mut().unwrap() ^= 1;
        assert_eq!(Response::decode(&flipped), Err(Error::Checksum));
        let mut long = bytes.clone();
        long.push(0);
        assert!(Response::decode(&long).is_err());
        // A byte after the last entry, inside a body whose length and checksum agree.
        let mut padded = bytes.clone();
        padded.push(0);
        let body = (padded.len() - HEADER) as u32;
        padded[12..16].copy_from_slice(&body.to_le_bytes());
        let crc = snapshot::crc32c(&[&padded[HEADER..]]);
        padded[16..20].copy_from_slice(&crc);
        assert_eq!(Response::decode(&padded), Err(Error::Trailing));
        let mut magic = bytes;
        magic[0] = b'X';
        assert_eq!(Response::decode(&magic), Err(Error::Magic));
    }

    // 항목 상한과 같은 단위 중복. 이것을 실패시키는 것: check_entries의 개수 상한을 지우는 것, 같은 origin·id 중복
    // 거부를 지우는 것, 값 4 KB 상한을 지우는 것.
    #[test]
    fn response_refuses_too_many_duplicate_or_long_entries() {
        let mut r = Response {
            binding: binding(),
            entries: (0..ENTRIES_MAX + 1)
                .map(|i| entry(&format!("custom/u{i}"), 1, 2))
                .collect(),
        };
        assert_eq!(r.encode(), Err(Error::Limit));
        r.entries = vec![entry("custom/a", 1, 2), entry("custom/a", 3, 4)];
        assert_eq!(r.encode(), Err(Error::Flags));
        let mut long = entry("custom/a", 1, 2);
        long.value = "x".repeat(VALUE_MAX + 1);
        r.entries = vec![long];
        assert_eq!(r.encode(), Err(Error::Limit));
        // The same id under the other origin is another unit.
        let mut builtin = entry("custom/a", 1, 2);
        builtin.origin = Origin::Builtin;
        r.entries = vec![entry("custom/a", 1, 2), builtin];
        assert!(r.encode().is_ok());
    }

    // 최대 크기 응답도 상한 안에서 왕복한다. 이것을 실패시키는 것: RESPONSE_MAX 계산에서 항목 하나의 최대를 줄이는 것.
    #[test]
    fn the_largest_response_fits_its_cap() {
        let mut b = binding();
        b.cwd = [b"/".as_slice(), &[b'a'; PATH_MAX - 1]].concat();
        let r = Response {
            binding: b,
            entries: (0..ENTRIES_MAX)
                .map(|i| Entry {
                    id: format!("custom/{i:0>width$}", width = ID_MAX - 7),
                    value: "v".repeat(VALUE_MAX),
                    raw: "r".repeat(VALUE_MAX),
                    ..entry("x", 1, 2)
                })
                .collect(),
        };
        let bytes = r.encode().unwrap();
        assert_eq!(Response::decode(&bytes).unwrap(), r);
    }

    // 내 회차가 실행한 단위만, 더 늦게 끝났을 때만 바꾼다. 다른 단위의 항목은 남는다. 이것을 실패시키는 것:
    // merge가 현재 항목을 버리고 mine만 쓰는 것, 완료 시각 비교를 지우는 것(늦게 온 옛 결과가 새 결과를 덮음),
    // binding 비교를 지우는 것(다른 문맥의 항목이 섞임).
    #[test]
    fn merge_keeps_other_units_and_newer_results() {
        let current = Response {
            binding: binding(),
            entries: vec![entry("custom/a", 10, 50), entry("custom/b", 10, 20)],
        };
        let mine = [
            entry("custom/a", 30, 40),
            entry("custom/b", 30, 60),
            entry("custom/c", 30, 35),
        ];
        let r = merge(Some(&current), &binding(), &mine);
        assert_eq!(
            r.entry(Origin::Config, "custom/a").unwrap().completed_at,
            50
        );
        assert_eq!(
            r.entry(Origin::Config, "custom/b").unwrap().completed_at,
            60
        );
        assert!(r.entry(Origin::Config, "custom/c").is_some());
        let mut other = binding();
        other.cwd = b"/elsewhere".to_vec();
        let r = merge(Some(&current), &other, &mine[2..]);
        assert_eq!(r.entries.len(), 1);
    }

    // 32개를 넘으면 이 회차가 쓰지 않은 항목 가운데 가장 오래 전에 시도한 것부터 뺀다. 이것을 실패시키는 것:
    // 넘친 항목을 자르지 않는 것(인코딩이 Limit으로 실패), 내 항목을 빼는 것.
    #[test]
    fn merge_drops_the_oldest_other_entries_past_the_cap() {
        let current = Response {
            binding: binding(),
            entries: (0..ENTRIES_MAX)
                .map(|i| entry(&format!("custom/u{i}"), 100 + i as u64, 200 + i as u64))
                .collect(),
        };
        // Tried before every entry there: still never the one dropped.
        let mine = [entry("custom/new", 1, 600)];
        let r = merge(Some(&current), &binding(), &mine);
        assert_eq!(r.entries.len(), ENTRIES_MAX);
        assert!(r.entry(Origin::Config, "custom/new").is_some());
        assert!(r.entry(Origin::Config, "custom/u0").is_none());
        assert!(r.encode().is_ok());
    }

    // 적중: 정책·환경이 같고 기간 안. 실패는 10초. 이것을 실패시키는 것: hit의 환경 요약값 비교를 지우는 것,
    // 정책 비교를 지우는 것, 기간 비교를 `>=`로 바꾸는 것(경계에서 적중), 실패를 cache_ns로 세는 것, 완료 시각이
    // now 뒤인 항목을 받는 것.
    #[test]
    fn hit_needs_the_same_policy_env_and_time() {
        let e = entry("custom/a", 0, 1_000);
        assert!(e.hit(&[5; 32], &[6; 32], 1_500, 1_000));
        assert!(!e.hit(&[5; 32], &[9; 32], 1_500, 1_000));
        assert!(!e.hit(&[9; 32], &[6; 32], 1_500, 1_000));
        assert!(!e.hit(&[5; 32], &[6; 32], 2_000, 1_000));
        assert!(!e.hit(&[5; 32], &[6; 32], 1_500, 0));
        // A completion after `now` (another clock) is no hit.
        assert!(!e.hit(&[5; 32], &[6; 32], 999, 1_000));
        let failed = Entry {
            status: Status::Failed,
            ..e
        };
        assert!(failed.hit(&[5; 32], &[6; 32], 1_000 + FAILURE_NS - 1, 0));
        assert!(!failed.hit(&[5; 32], &[6; 32], 1_000 + FAILURE_NS, 0));
    }

    // 표시 자격: binding과 시계가 같을 때만. 이것을 실패시키는 것: eligible의 boot·domain·resume 비교 중 하나를
    // 지우는 것.
    #[test]
    fn eligible_needs_the_same_binding_and_clock() {
        let r = Response {
            binding: binding(),
            entries: vec![],
        };
        let now = Clock {
            kind: 1,
            now: 5,
            boot: [1; 16],
            resume: 4,
            domain: [3; 16],
        };
        assert!(r.eligible(&binding(), now));
        for c in [
            Clock {
                boot: [9; 16],
                ..now
            },
            Clock {
                domain: [9; 16],
                ..now
            },
            Clock { resume: 5, ..now },
            Clock { kind: 2, ..now },
        ] {
            assert!(!r.eligible(&binding(), c), "{c:?}");
        }
        let mut other = binding();
        other.cwd = b"/x".to_vec();
        assert!(!r.eligible(&other, now));
    }

    /// `bytes` with its body checksum made right again after an edit.
    fn resealed(mut bytes: Vec<u8>) -> Vec<u8> {
        let crc = snapshot::crc32c(&[&bytes[HEADER..]]);
        bytes[16..20].copy_from_slice(&crc);
        bytes
    }

    // 머리·binding·항목의 각 거부. 이것을 실패시키는 것(줄마다 하나): 버전 비교, 머리의 예약 바이트 0 검사,
    // 선언 길이 상한, binding의 context crc 비교, 절대 경로 검사, origin 태그 거부, 상태 태그 거부, 시도 시각 >
    // 완료 시각 거부, 빈 id 거부, id 길이 상한, 원본 줄 4 KB 상한, 경로 길이 상한, 경로의 NUL 거부, 시계 종류
    // 검사, 잘린 파일 거부를 지우는 것.
    #[test]
    fn decode_refuses_each_malformed_part() {
        let good = Response {
            binding: binding(),
            entries: vec![entry("custom/a", 10, 20)],
        };
        let bytes = good.encode().unwrap();
        let mut version = bytes.clone();
        version[8] = 2;
        assert_eq!(Response::decode(&version), Err(Error::Version));
        let mut reserved = bytes.clone();
        reserved[30] = 1;
        assert_eq!(Response::decode(&reserved), Err(Error::Flags));
        let mut long = bytes.clone();
        long[12..16].copy_from_slice(&(RESPONSE_MAX as u32).to_le_bytes());
        assert_eq!(declared_len(&long), Err(Error::Length));
        // The binding's context digest is at a fixed place after build, boot, epoch.
        let mut context = bytes.clone();
        context[HEADER + 32 + 16 + 16] ^= 1;
        assert_eq!(Response::decode(&resealed(context)), Err(Error::Flags));
        for cwd in [
            b"repo".to_vec(),
            b"/a\0b".to_vec(),
            [b"/".as_slice(), &[b'a'; PATH_MAX]].concat(),
        ] {
            let mut bad = good.clone();
            bad.binding.cwd = cwd;
            assert_eq!(bad.encode(), Err(Error::Utf8));
        }
        let mut kind = good.clone();
        kind.binding.clock_kind = 3;
        assert_eq!(kind.encode(), Err(Error::Flags));
        assert_eq!(
            Response::decode(&bytes[..bytes.len() - 1]),
            Err(Error::Short)
        );
        // Entry tags: origin and status follow the id and the digests.
        // From the end: raw and value (4 + 10 bytes each), then the status byte.
        let status_at = bytes.len() - 2 * (4 + 10) - 1;
        let origin_at = status_at - 16 - 96 - 1;
        let mut origin = bytes.clone();
        origin[origin_at] = 9;
        assert_eq!(Response::decode(&resealed(origin)), Err(Error::Kind));
        let mut status = bytes.clone();
        status[status_at] = 7;
        assert_eq!(Response::decode(&resealed(status)), Err(Error::Kind));
        for broken in [
            Entry {
                attempted_at: 30,
                ..entry("custom/a", 10, 20)
            },
            Entry {
                id: String::new(),
                ..entry("custom/a", 10, 20)
            },
            Entry {
                id: "x".repeat(ID_MAX + 1),
                ..entry("custom/a", 10, 20)
            },
            Entry {
                raw: "r".repeat(VALUE_MAX + 1),
                ..entry("custom/a", 10, 20)
            },
        ] {
            let r = Response {
                binding: binding(),
                entries: vec![broken.clone()],
            };
            assert_eq!(r.encode(), Err(Error::Limit), "{broken:?}");
        }
    }

    // 값은 첫 줄(줄 끝 제외)을 정제한 것이고 4 KB까지다. 이것을 실패시키는 것: 첫 줄 자르기를 지우는 것(둘째 줄이
    // 섞임), 정제를 건너뛰는 것(ESC와 CR이 남음), 4 KB 자르기를 지우는 것, 글자 경계 맞추기를 지우는 것.
    #[test]
    fn first_line_is_sanitized_and_bounded() {
        assert_eq!(first_line(b"v1.2\r\nnext\n"), "v1.2");
        assert!(!first_line(b"a\x1b[31mb").contains('\x1b'));
        let long = alloc::vec![b'x'; VALUE_MAX + 10];
        assert_eq!(first_line(&long).len(), VALUE_MAX);
        // A cut never splits a character.
        let mut wide = alloc::vec![b'x'; VALUE_MAX - 1];
        wide.extend_from_slice("\u{AC00}".as_bytes());
        assert!(first_line(&wide).len() < VALUE_MAX);
    }

    // 종료 0만 값, 다른 끝은 실패(10초), 감독이 거부한 것은 항목 없음. 이것을 실패시키는 것: Exited의 0 비교를
    // 지우는 것, Refused를 실패 항목으로 쓰는 것, 시도 시각을 완료 시각 이하로 맞추지 않는 것.
    #[test]
    fn entry_for_keeps_runs_only() {
        use crate::command::{grant::Refusal, wire::Outcome};
        let o = |reason| Outcome {
            origin: Origin::Config,
            index: 0,
            reason,
            approved_at: 10,
            ended_at: 20,
            stdout: b"1.0\n".to_vec(),
        };
        let ok = entry_for(
            "custom/a".into(),
            [1; 32],
            [2; 32],
            5,
            &o(Reason::Exited(0)),
        )
        .unwrap();
        assert_eq!(
            (ok.status, ok.value.as_str(), ok.attempted_at),
            (Status::Ok, "1.0", 5)
        );
        let bad = entry_for(
            "custom/a".into(),
            [1; 32],
            [2; 32],
            5,
            &o(Reason::Exited(256)),
        )
        .unwrap();
        assert_eq!((bad.status, bad.value.as_str()), (Status::Failed, ""));
        assert_eq!(
            entry_for("custom/a".into(), [1; 32], [2; 32], 5, &o(Reason::Timeout))
                .unwrap()
                .status,
            Status::Failed
        );
        assert!(
            entry_for(
                "custom/a".into(),
                [1; 32],
                [2; 32],
                5,
                &o(Reason::Refused(Refusal::Trust))
            )
            .is_none()
        );
        let late = entry_for(
            "custom/a".into(),
            [1; 32],
            [2; 32],
            50,
            &o(Reason::Exited(0)),
        )
        .unwrap();
        assert_eq!(late.attempted_at, 20);
        // m6-P1: the value is the part the prompt reads to cut a user
        // segment, the raw line the whole first line (4 KB here).
        let mut long = o(Reason::Exited(0));
        long.stdout = "kube-\u{D55C}\u{AE00}-ctx/".repeat(300).into_bytes();
        let e = entry_for("custom/a".into(), [1; 32], [2; 32], 5, &long).unwrap();
        assert!(e.raw.len() > 4_000);
        assert_eq!(
            e.value,
            crate::field::Clean::read_prefix(&e.raw, crate::field::CUSTOM_TEXT_CELLS)
        );
        assert!(
            e.value.len() <= 276 && e.value.len() >= 272,
            "{}",
            e.value.len()
        );
    }
    // 앞단이 이 파일의 값을 터미널에 그대로 쓰므로(C4b) 값과 원본 줄에는 sanitize가 지우는 문자가 없어야 하고,
    // 실패 항목은 값이 비어야 한다. encode와 decode가 같은 검사를 한다. 이것을 실패시키는 것: check_entries의
    // is_removed 검사를 지우는 것, 그 검사에서 raw를 빼는 것, 실패 항목의 빈 값 검사를 지우는 것.
    #[test]
    fn values_are_sanitized_text_and_failures_have_none() {
        for bad in [
            "\u{1b}]0;pwn\u{7}",
            "a\u{0}b",
            "a\rb",
            "a\u{9b}b",
            "a\u{202e}b",
        ] {
            for raw in [false, true] {
                let mut e = entry("custom/a", 10, 20);
                if raw {
                    e.raw = bad.to_string();
                } else {
                    e.value = bad.to_string();
                }
                let r = Response {
                    binding: binding(),
                    entries: vec![e],
                };
                assert_eq!(r.encode(), Err(Error::Utf8), "{bad:?} raw={raw}");
            }
        }
        let mut failed = entry("custom/a", 10, 20);
        failed.status = Status::Failed;
        let mut r = Response {
            binding: binding(),
            entries: vec![failed.clone()],
        };
        assert_eq!(r.encode(), Err(Error::Flags));
        failed.value.clear();
        r.entries = vec![failed.clone()];
        assert_eq!(r.encode(), Err(Error::Flags), "raw is still set");
        failed.raw.clear();
        r.entries = vec![failed];
        assert!(r.encode().is_ok());
        // decode: the same file with an ESC put into the value and the raw
        // line, and a failure that keeps its value, each resealed.
        let good = Response {
            binding: binding(),
            entries: vec![entry("custom/a", 10, 20)],
        }
        .encode()
        .unwrap();
        let at = good.windows(2).rposition(|w| w == b"v-").unwrap();
        for place in [
            at,
            good.windows(2)
                .position(|w| w == b"v-")
                .filter(|&p| p != at)
                .unwrap_or(at),
        ] {
            let mut bytes = good.clone();
            bytes[place] = 0x1b;
            assert_eq!(Response::decode(&resealed(bytes)), Err(Error::Utf8));
        }
        let status = good.len() - 2 * (4 + "v-custom/a".len()) - 1;
        assert_eq!(good[status], 0);
        let mut bytes = good.clone();
        bytes[status] = 1;
        assert_eq!(Response::decode(&resealed(bytes)), Err(Error::Flags));
    }

    // 앞단 decode(decode_shown)는 그리지 않는 원본 줄의 글자를 검사하지 않고 비워서 돌려주며, 값은 그대로 검사한다.
    // helper의 decode와 encode는 원본 줄도 거부한다. 이것을 실패시키는 것: decode_shown이 원본 줄을 검사하는 것(제어
    // 문자가 든 원본 줄 때문에 값을 잃음), 원본 줄을 그대로 돌려주는 것, decode_shown이 값 검사까지 빼는 것, decode가
    // 원본 줄 검사를 빼는 것, 원본 줄의 UTF-8·길이·실패 항목 검사를 빼는 것.
    #[test]
    fn the_prompt_decode_skips_only_the_raw_line_characters() {
        let good = Response {
            binding: binding(),
            entries: vec![entry("custom/a", 10, 20)],
        }
        .encode()
        .unwrap();
        // Value first, then the raw line: both are "v-custom/a".
        let value = good.windows(2).position(|w| w == b"v-").unwrap();
        let raw = good.windows(2).rposition(|w| w == b"v-").unwrap();
        assert!(value < raw);
        let mut bytes = good.clone();
        bytes[raw] = 0x1b;
        let bytes = resealed(bytes);
        assert_eq!(Response::decode(&bytes), Err(Error::Utf8));
        let shown = Response::decode_shown(&bytes).unwrap();
        assert_eq!(shown.entries[0].value, "v-custom/a");
        // The undrawn raw line is left out, checked or not.
        assert_eq!(shown.entries[0].raw, "");
        assert_eq!(Response::decode_shown(&good).unwrap().entries[0].raw, "");
        let mut bytes = good.clone();
        bytes[value] = 0x1b;
        assert_eq!(Response::decode_shown(&resealed(bytes)), Err(Error::Utf8));
        // A raw line that is not UTF-8 is refused by both.
        let mut bytes = good;
        bytes[raw] = 0xff;
        let bytes = resealed(bytes);
        assert_eq!(Response::decode_shown(&bytes), Err(Error::Utf8));
        assert_eq!(Response::decode(&bytes), Err(Error::Utf8));
        // A failure that keeps a raw line, and a raw line over 4 KB.
        let mut e = entry("custom/a", 10, 20);
        e.value.clear();
        e.raw = "r".into();
        let one = Response {
            binding: binding(),
            entries: vec![e.clone()],
        }
        .encode()
        .unwrap();
        let mut bytes = one.clone();
        let status = bytes.len() - 4 - (4 + 1) - 1;
        assert_eq!(bytes[status], 0);
        bytes[status] = 1;
        let bytes = resealed(bytes);
        assert_eq!(Response::decode(&bytes), Err(Error::Flags));
        assert_eq!(Response::decode_shown(&bytes), Err(Error::Flags));
        e.raw = "r".repeat(VALUE_MAX);
        let mut bytes = Response {
            binding: binding(),
            entries: vec![e],
        }
        .encode()
        .unwrap();
        let at = bytes.len() - VALUE_MAX - 4;
        bytes[at..at + 4].copy_from_slice(&(VALUE_MAX as u32 + 1).to_le_bytes());
        bytes.push(b'r');
        let body = u32::from_le_bytes(bytes[12..16].try_into().unwrap()) + 1;
        bytes[12..16].copy_from_slice(&body.to_le_bytes());
        let bytes = resealed(bytes);
        assert_eq!(Response::decode(&bytes), Err(Error::Limit));
        assert_eq!(Response::decode_shown(&bytes), Err(Error::Limit));
    }
}
