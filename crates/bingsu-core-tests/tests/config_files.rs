//! File-backed core checks live outside the no_std crate.
use bingsu_core::config::check::parse_duration_ms;
use bingsu_core::diag_codes::{CODES, CodeStatus};

// 이것을 실패시키는 것: 코드를 지우는 것, 목록 파일에 적지 않고 코드를 더하는 것,
// 상태를 파일과 다르게 바꾸는 것, 번호 순서·중복을 어기는 것.
#[test]
fn registry_matches_the_listed_codes() {
    let listed = include_str!("../../bingsu-core/diag-codes.txt");
    let status = |s: CodeStatus| match s {
        CodeStatus::Stable => String::from("stable"),
        CodeStatus::Deprecated { since } => format!("deprecated {since}"),
    };
    let got: Vec<String> = CODES
        .iter()
        .map(|c| format!("{} {}", c.code, status(c.status)))
        .collect();
    let want: Vec<&str> = listed
        .lines()
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect();
    assert_eq!(got, want);
    assert!(CODES.windows(2).all(|p| p[0].code < p[1].code));
}

// 이것을 실패시키는 것: parse_duration_ms가 corpus와 다른 값을 받는 것, corpus 파일을 갱신하지 않는 것.
#[test]
fn duration_corpus_is_shared() {
    let corpus = include_str!("../../bingsu-core/schema/duration-corpus.json");
    let mut n = 0;
    for line in corpus.lines().filter(|l| l.trim_start().starts_with("[\"")) {
        let v: Vec<&str> = line
            .trim()
            .trim_end_matches(',')
            .trim_matches(['[', ']'])
            .split(", ")
            .collect();
        let (text, ok) = (v[0].trim_matches('"'), v[1] == "true");
        assert_eq!(parse_duration_ms(text).is_some(), ok, "{text}");
        n += 1;
    }
    assert!(n >= 20);
}

/// The prompt path stays independent of config parsing and checking.
const PROMPT_PATH: [(&str, &str); 5] = [
    (
        "default_theme.rs",
        include_str!("../../bingsu-core/src/default_theme.rs"),
    ),
    ("render.rs", include_str!("../../bingsu-core/src/render.rs")),
    ("layout.rs", include_str!("../../bingsu-core/src/layout.rs")),
    ("front.rs", include_str!("../../bingsu-core/src/front.rs")),
    (
        "shell_values.rs",
        include_str!("../../bingsu-core/src/shell_values.rs"),
    ),
];

// 매 프롬프트는 설정을 파싱하지 않는다: 앞단은 컴파일된 snapshot만 읽는다(N4). 파서·합치기·검사는
// 설정이 바뀔 때 갱신 도우미에서만 돈다.
// 이것을 실패시키는 것: 앞단 경로의 파일이 `config` 모듈(파서·합치기·검사·컴파일)을 부르는 것.
#[test]
fn the_prompt_path_never_reads_config() {
    for (name, text) in PROMPT_PATH {
        for needle in ["config::", "toml::"] {
            assert!(!text.contains(needle), "{name} uses {needle}");
        }
    }
}
