//! D3a: the builtin probes' fixed profiles and the probe toolchain on the wire.
use bingsu_core::{
    command::{
        Error,
        profile::{self, GO, NODE, PYTHON, RUST},
        wire::{self, Grant, Message, Probe},
    },
    handoff::Permit,
};

// 프로필 표: 인자와 환경은 고정이고, Rust만 해석기가 고른 toolchain 하나를 받는다. 이것을 실패시키는 것: Python의
// `-I`·`-S`를 빼는 것, Go의 GOTOOLCHAIN=local이나 Rust의 RUSTUP_AUTO_INSTALL=0을 빼는 것, toolchain 문법 검사를
// 지우는 것(경로 꼴 이름), 다른 프로필에 toolchain을 받는 것, 모르는 프로필에 표를 주는 것.
#[test]
fn profiles_build_fixed_environments() {
    let args = |id| profile::profile(id).map(|p| p.args.to_vec());
    assert_eq!(args(PYTHON), Some(vec![&b"-I"[..], b"-S", b"--version"]));
    assert_eq!(args(NODE), Some(vec![&b"--version"[..]]));
    assert_eq!(args(RUST), Some(vec![&b"--version"[..]]));
    assert_eq!(args(GO), Some(vec![&b"version"[..]]));
    assert_eq!(args(0), None);
    assert_eq!(args(5), None);
    let env = |id, t: Option<&[u8]>| profile::environment(id, t, b"/n");
    assert_eq!(env(PYTHON, None), Some(Vec::new()));
    assert_eq!(env(NODE, None), Some(Vec::new()));
    assert_eq!(
        env(GO, None),
        Some(b"HOME=/n\0GOTOOLCHAIN=local\0".to_vec())
    );
    assert_eq!(
        env(RUST, None),
        Some(b"HOME=/n\0RUSTUP_AUTO_INSTALL=0\0".to_vec())
    );
    assert_eq!(
        env(RUST, Some(b"1.80.0")),
        Some(b"HOME=/n\0RUSTUP_AUTO_INSTALL=0\0RUSTUP_TOOLCHAIN=1.80.0\0".to_vec())
    );
    for bad in [&b"../x"[..], b"/opt/rust", b""] {
        assert_eq!(env(RUST, Some(bad)), None, "{bad:?}");
    }
    for id in [PYTHON, NODE, GO] {
        assert_eq!(env(id, Some(b"1.80.0")), None, "{id}");
    }
    assert_eq!(env(9, None), None);
}

fn grant(toolchain: &[u8]) -> Message {
    Message::Grant(Grant {
        permit: Permit {
            kind: 1,
            deadline: 100,
            boot: [1; 16],
            resume: 0,
            domain: [2; 16],
        },
        helper_deadline: 9,
        cwd: b"/home/u".to_vec(),
        neutral: b"/run/bingsu/neutral".to_vec(),
        units: Vec::new(),
        probes: vec![Probe {
            profile: RUST,
            executable: b"/r/toolchains/1.80.0-h/bin/rustc".to_vec(),
            pin: None,
            toolchain: Some(toolchain.to_vec()),
        }],
    })
}

// grant의 toolchain은 받는 감독이 버전 문법으로 다시 검사한다(경로 꼴 이름 거부). 이것을 실패시키는 것: decode의
// version_ok 검사를 지우는 것.
#[test]
fn probe_toolchain_is_a_version_name() {
    let good = grant(b"1.80.0");
    assert_eq!(wire::decode(&wire::encode(&good).unwrap()), Ok(good));
    let bad = wire::encode(&grant(b"../x")).unwrap();
    assert_eq!(wire::decode(&bad), Err(Error::Utf8));
}
