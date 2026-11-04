use bingsu_core::{
    command::{
        Error,
        wire::{self, BODY_MAX, FRAME_MAX, Grant, HEADER, Message, Policy, Probe, Unit},
    },
    handoff::{self, Cwd, ExecFrame, Origin, Permit},
};
use proptest::prelude::*;
#[path = "support/allocation.rs"]
mod allocation;
#[global_allocator]
static ALLOC: allocation::Counting = allocation::Counting;

fn permit() -> Permit {
    Permit {
        kind: 1,
        deadline: 100,
        boot: [1; 16],
        resume: 0,
        domain: [2; 16],
    }
}
fn grant(units: usize, environment: usize) -> Message {
    let policy = Policy::Argv {
        argv: vec![b"kubectl".to_vec(), b"config".to_vec()],
    };
    Message::Grant(Grant {
        permit: permit(),
        helper_deadline: 9,
        cwd: b"/home/u".to_vec(),
        neutral: b"/run/bingsu/neutral".to_vec(),
        units: (0..units)
            .map(|i| Unit {
                id: format!("custom/u{i}"),
                digest: wire::policy_digest(&policy, Cwd::Neutral, 7, &[b"LANG".to_vec()]),
                policy: policy.clone(),
                cwd: Cwd::Neutral,
                environment: vec![b'x'; environment],
                timeout: 7,
                env_allow: vec![b"LANG".to_vec()],
                executable: b"/usr/bin/kubectl".to_vec(),
                pin: None,
                interpreter: None,
            })
            .collect(),
        probes: vec![Probe {
            profile: 1,
            executable: b"/usr/bin/node".to_vec(),
            pin: None,
        }],
    })
}

// 이것을 실패시키는 것: frame_len의 BODY_MAX 비교를 지우는 것(거짓 길이 머리가 Length 대신 Short가 됨),
// 또는 머리 검사 전에 본문 크기로 할당하는 것.
#[test]
fn header_is_refused_before_allocation() {
    let mut b = wire::encode(&Message::Done).unwrap();
    for len in [BODY_MAX as u32 + 1, u32::MAX] {
        b[12..16].copy_from_slice(&len.to_le_bytes());
        let mut result = Ok(Message::Done);
        let counts = allocation::counted(|| result = wire::decode(&b[..HEADER]));
        assert_eq!(result, Err(Error::Length));
        assert_eq!(counts, (0, 0, 0));
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 256, .. ProptestConfig::default() })]
    // 이것을 실패시키는 것: 선언된 개수·길이로 미리 할당하는 것(peak가 입력 크기에 비례하지 않음),
    // 또는 거부 경로에서 panic하는 것.
    #[test]
    fn arbitrary_bytes_are_bounded(raw in prop::collection::vec(any::<u8>(), 0..4096)) {
        let counts = allocation::counted(|| { let _ = wire::decode(&raw); });
        prop_assert!(counts.2 <= 16 * raw.len() + 1024, "{counts:?}");
        let counts = allocation::counted(|| { let _ = handoff::read_relay_input(&raw, 16_384); });
        prop_assert!(counts.2 <= 2 * raw.len() + 64, "{counts:?}");
    }

    // 이것을 실패시키는 것: CRC 비교를 지우는 것(재봉인하지 않은 변조가 통과), 또는 변조된
    // 프레임에서 panic하는 것. CRC를 다시 계산한 변조는 구조 검사만 거부할 수 있으므로 decode가
    // panic 없이 끝나고 할당이 입력 크기에 묶이는지만 본다.
    #[test]
    fn mutated_grant_is_refused_or_bounded(
        units in 0usize..8, environment in 0usize..512, at in any::<prop::sample::Index>(), x in 1u8..=255,
    ) {
        let mut b = wire::encode(&grant(units, environment)).unwrap();
        let i = at.index(b.len());
        b[i] ^= x;
        prop_assert!(wire::decode(&b).is_err());
        let crc = bingsu_core::snapshot::crc32c(&[b"bingsu-command-v1\0", &b[..16], &b[HEADER..]]);
        b[16..20].copy_from_slice(&crc);
        let counts = allocation::counted(|| { let _ = wire::decode(&b); });
        prop_assert!(counts.2 <= 16 * b.len() + 1024, "{counts:?}");
    }

    // 이것을 실패시키는 것: 잘린 프레임을 Short 외의 결과로 받거나 그 길이를 넘게 할당하는 것.
    #[test]
    fn truncated_frames_are_short(units in 0usize..8, environment in 0usize..512, cut in any::<prop::sample::Index>()) {
        let b = wire::encode(&grant(units, environment)).unwrap();
        let n = cut.index(b.len());
        prop_assert_eq!(wire::decode(&b[..n]), Err(Error::Short));
        let f = ExecFrame { origin: Origin::Config, run_deadline: 5, environment: vec![b'e'; environment], pin: None, interpreter: None, cwd: b"/".to_vec() };
        let r = handoff::relay_input(permit(), &f, 16_384).unwrap();
        let n = cut.index(r.len());
        prop_assert_eq!(handoff::read_relay_input(&r[..n], 16_384), Err(Error::Short));
    }
}

// 양성 대조: 머리 포함 정확히 65,536바이트인 허가 프레임이 인코딩·디코딩된다.
#[test]
fn largest_frame_roundtrips() {
    let Message::Grant(mut g) = grant(1, 0) else {
        unreachable!()
    };
    let base = wire::encode(&Message::Grant(g.clone())).unwrap().len();
    g.units[0].environment = vec![b'x'; FRAME_MAX - base];
    let m = Message::Grant(g);
    let b = wire::encode(&m).unwrap();
    assert_eq!(b.len(), FRAME_MAX);
    assert_eq!(wire::decode(&b), Ok(m));
}
