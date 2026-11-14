//! D2: the version manager resolvers' pure rules (rustup and pyenv).
use bingsu_core::collection::manager::{
    Decision, Facts, Hidden, Install, Manager, Plan, Selection, Settings, concrete, early,
    installed, plan, rustup_settings,
};

fn known(host: Option<&[u8]>, overridden: bool) -> Settings {
    Settings::Known {
        host: host.map(<[u8]>::to_vec),
        overridden,
    }
}

fn run(name: Option<&[u8]>) -> Plan {
    Plan::Done(Decision::Run(name.map(<[u8]>::to_vec)))
}

fn check(folder: &[u8], value: &[u8], host: Option<&[u8]>) -> Plan {
    Plan::Check {
        folder: folder.to_vec(),
        value: value.to_vec(),
        host: host.map(<[u8]>::to_vec),
    }
}

// 우선순위 출처마다 빠른 경로를 끄는 칸. 이것을 실패시키는 것: 환경이 오지 않은 경우를 끄지 않는 것, override 변수
// (RUSTUP_TOOLCHAIN·PYENV_VERSION)를 무시하는 것, rustup 설정을 모르는데 진행하는 것, 폴더 override를 무시하는 것,
// 선택 파일이 없거나 값이 없는데 진행하는 것, path 툴체인을 숨기지 않는 것, pyenv의
// `system`을 버전으로 보는 것, settings에 host가 없을 때 빌드 triple로 설치 확인을 하지 않는 것,
// path를 환경 없음·settings 모름보다 늦게 보는 것(리뷰 M3).
#[test]
fn decision_table() {
    let host = known(Some(b"aarch64-apple-darwin"), false);
    let cases: [(Manager, Option<bool>, Selection<'_>, Settings, Plan); 13] = [
        (
            Manager::Rustup,
            Some(false),
            Selection::Value(b"1.80.0"),
            host.clone(),
            check(b"toolchains", b"1.80.0", Some(b"aarch64-apple-darwin")),
        ),
        (
            Manager::Rustup,
            None,
            Selection::Value(b"1.80.0"),
            host.clone(),
            run(None),
        ),
        (
            Manager::Rustup,
            Some(true),
            Selection::Value(b"1.80.0"),
            host.clone(),
            run(None),
        ),
        (
            Manager::Rustup,
            Some(false),
            Selection::Value(b"1.80.0"),
            Settings::Unknown,
            run(None),
        ),
        (
            Manager::Rustup,
            Some(false),
            Selection::Value(b"1.80.0"),
            known(Some(b"aarch64-apple-darwin"), true),
            run(None),
        ),
        (
            Manager::Rustup,
            Some(false),
            Selection::Value(b"1.80.0"),
            known(None, false),
            check(b"toolchains", b"1.80.0", Some(b"x86_64-unknown-linux-gnu")),
        ),
        (
            Manager::Rustup,
            Some(false),
            Selection::Absent,
            host.clone(),
            run(None),
        ),
        (
            Manager::Rustup,
            Some(false),
            Selection::Unusable,
            host.clone(),
            run(None),
        ),
        (
            Manager::Rustup,
            Some(false),
            Selection::Path,
            host.clone(),
            Plan::Done(Decision::Hidden(Hidden::ToolchainPath)),
        ),
        (
            Manager::Pyenv,
            Some(false),
            Selection::Value(b"3.12.1"),
            Settings::Unknown,
            check(b"versions", b"3.12.1", None),
        ),
        (
            Manager::Pyenv,
            Some(true),
            Selection::Value(b"3.12.1"),
            Settings::Unknown,
            run(None),
        ),
        (
            Manager::Pyenv,
            None,
            Selection::Value(b"3.12.1"),
            Settings::Unknown,
            run(None),
        ),
        (
            Manager::Pyenv,
            Some(false),
            Selection::Value(b"system"),
            Settings::Unknown,
            run(None),
        ),
    ];
    // Path first: hidden even with no environment or unknown settings.
    for override_set in [None, Some(true), Some(false)] {
        let facts = Facts {
            manager: Manager::Rustup,
            override_set,
            selection: Selection::Path,
            settings: &Settings::Unknown,
            build_host: b"h",
        };
        assert_eq!(
            plan(&facts),
            Plan::Done(Decision::Hidden(Hidden::ToolchainPath))
        );
    }
    // What needs no file is decided by `early`; the rest needs the files.
    assert_eq!(early(Some(false), Selection::Value(b"1.80.0")), None);
    assert_eq!(
        early(Some(false), Selection::Absent),
        Some(Decision::Run(None))
    );
    for (manager, override_set, selection, settings, want) in cases {
        let facts = Facts {
            manager,
            override_set,
            selection,
            settings: &settings,
            build_host: b"x86_64-unknown-linux-gnu",
        };
        assert_eq!(plan(&facts), want, "{facts:?}");
    }
}

// 설치 확인 뒤: 설치되어 있고 이름이 그대로 버전일 때만 빠른 경로다(이름이 정확히 같은 폴더만). 신뢰
// 위반은 숨김이고 실행하지 않는다. 이것을 실패시키는 것: 설치 확인 결과를 무시하는 것(없는 버전을 보임),
// concrete 검사를 지우는 것(`stable`을 보임), 신뢰 위반을 미설치처럼 실행으로 보내는 것.
#[test]
fn install_check_decides_the_fast_path() {
    assert_eq!(
        installed(b"1.80.0", Install::Present),
        Decision::Fast(b"1.80.0".to_vec())
    );
    assert_eq!(
        installed(b"1.80.0", Install::Absent),
        Decision::Run(Some(b"1.80.0".to_vec()))
    );
    assert_eq!(
        installed(b"stable", Install::Present),
        Decision::Run(Some(b"stable".to_vec()))
    );
    assert_eq!(
        installed(b"1.80.0", Install::Untrusted),
        Decision::Hidden(Hidden::Untrusted)
    );
}

// 그대로 버전인 이름은 숫자 세 마디뿐이다. 이것을 실패시키는 것: 마디 수 검사를 지우는 것(`1.80`), 숫자 검사를
// 지우는 것(`3.12.1t`, `stable`), 빈 마디를 받는 것(`1..2`).
#[test]
fn concrete_names() {
    for ok in [&b"1.80.0"[..], b"3.12.1", b"10.0.12"] {
        assert!(concrete(ok), "{:?}", String::from_utf8_lossy(ok));
    }
    for bad in [
        &b"1.80"[..],
        b"3.12",
        b"1.80.0.1",
        b"3.12.1t",
        b"stable",
        b"nightly-2026-01-01",
        b"pypy3.10-7.3.15",
        b"1..2",
        b"",
    ] {
        assert!(!concrete(bad), "{:?}", String::from_utf8_lossy(bad));
    }
}

// rustup settings.toml. 이것을 실패시키는 것: 다른 표를 받는 것, 따옴표 최상위 키를 받는 것, 여러 줄 값(열린 배열,
// 세 따옴표 문자열 두 종류)을 받는 것,
// escape가 든 override 키를 받는 것, override가 shell 폴더의 부모를 덮는 것을 놓치는 것, 이름 앞부분만 같은 폴더
// (`/w/re`)를 부모로 보는 것, default_host_triple을 읽지 않는 것, 루트(`/`)와 끝 `/`가 붙은 override를 놓치는 것,
// 빈 키나 따옴표 없는 override 값을 받는 것, 이 파일이 주는 이름(override 값, host, default_toolchain)에 버전 문법을
// 적용하지 않는 것(경로 꼴 이름), `false` 값을 받지 않는 것, inline table·한 줄 배열·따옴표 없는 문자열 같은 값 모양을 받는 것, rustup 1.29의
// `default_host_tuple`을 읽지 않는 것, 두 host 키를 함께 받는 것(rustup 1.29.2는 이 파일을 거부함).
#[test]
fn settings_forms() {
    let cwd = b"/w/repo/sub";
    let cases: [(&[u8], Settings); 28] = [
        (
            b"version = \"12\"\ndefault_toolchain = \"stable-aarch64-apple-darwin\"\nprofile = \"default\"\n\n[overrides]\n",
            known(None, false),
        ),
        (
            b"default_host_triple = \"x86_64-unknown-linux-gnu\"\n[overrides]\n\"/other\" = \"nightly\"\n",
            known(Some(b"x86_64-unknown-linux-gnu"), false),
        ),
        (
            b"[overrides]\n\"/w/repo\" = \"nightly-aarch64-apple-darwin\"\n",
            known(None, true),
        ),
        (b"[overrides]\n\"/w/repo/sub\" = \"nightly\"\n", known(None, true)),
        (b"[overrides]\n\"/w/re\" = \"nightly\"\n", known(None, false)),
        (b"[overrides]\n\"/w/repo/sub/deeper\" = \"nightly\"\n", known(None, false)),
        (b"[pgp_keys]\n", Settings::Unknown),
        (b"\"default_host_triple\" = \"x\"\n", Settings::Unknown),
        (b"list = [\n\"a\",\n]\n", Settings::Unknown),
        (b"list = [\"a\"]\n", Settings::Unknown),
        (b"overrides = { \"/w\" = \"nightly\" }\n", Settings::Unknown),
        (b"profile = minimal\n", Settings::Unknown),
        (
            b"auto_self_update = true\nversion = 12\nprofile = \"default\"\n",
            known(None, false),
        ),
        (
            b"auto_self_update = false\n",
            known(None, false),
        ),
        (
            b"default_host_tuple = \"aarch64-apple-darwin\"\n",
            known(Some(b"aarch64-apple-darwin"), false),
        ),
        (
            b"default_host_tuple = \"h\"\ndefault_host_triple = \"h\"\n",
            Settings::Unknown,
        ),
        (b"default_host_tuple = \"a/b\"\n", Settings::Unknown),
        (b"[overrides]\n\"/\" = \"nightly\"\n", known(None, true)),
        (b"[overrides]\n\"/w/repo/\" = \"nightly\"\n", known(None, true)),
        (b" = \"x\"\n", Settings::Unknown),
        (b"[overrides]\n\"/w\" = \"/opt/toolchain\"\n", Settings::Unknown),
        (b"default_host_triple = \"a/b\"\n", Settings::Unknown),
        (b"default_toolchain = \"../x\"\n", Settings::Unknown),
        (b"[overrides]\n\"/other\" = nightly\n", Settings::Unknown),
        (b"a = [\nb = 1 ]\n", Settings::Unknown),
        (b"a = \"\"\"x\nb = 1 \"\"\"\n", Settings::Unknown),
        (b"a = '''x\nb = 1 '''\n", Settings::Unknown),
        (b"[overrides]\n\"/w/\\u0072epo\" = \"nightly\"\n", Settings::Unknown),
    ];
    for (bytes, want) in cases {
        assert_eq!(
            rustup_settings(bytes, cwd),
            want,
            "{:?}",
            String::from_utf8_lossy(bytes)
        );
    }
}
