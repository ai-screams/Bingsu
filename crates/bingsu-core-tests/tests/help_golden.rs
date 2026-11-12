//! `bingsu help` text, byte for byte (BINGSU_UPDATE_GOLDEN=1 rewrites the
//! file; review the diff). One golden holds every code, so the wording of
//! each severity and each security reason (E207, E210-E213, W401-W405,
//! W409-W411) is reviewed in one place.
use bingsu_core::diag_codes::CODES;
use bingsu_core::diag_help::render;

const PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/golden/help/help.txt"
);

fn all() -> String {
    let mut out = String::new();
    for (i, c) in CODES.iter().enumerate() {
        if i > 0 {
            out.push_str("\n----\n\n");
        }
        out.push_str(&render(c.code).unwrap());
    }
    out
}

// 이것을 실패시키는 것: 어느 코드의 설명 문구나 형식(제목줄, 칸 이름, 들여쓰기)을 바꾸는 것,
// 코드를 더하고 golden을 갱신하지 않는 것.
#[test]
fn help_text_matches_the_golden() {
    let got = all();
    if std::env::var_os("BINGSU_UPDATE_GOLDEN").is_some() {
        std::fs::write(PATH, &got).unwrap();
        return;
    }
    let want = std::fs::read_to_string(PATH).unwrap().replace("\r\n", "\n");
    assert_eq!(
        got, want,
        "run with BINGSU_UPDATE_GOLDEN=1 and review the diff"
    );
}

// 이것을 실패시키는 것: 보안 이유 코드 중 하나의 설명을 golden에서 빼는 것(CODES 전체를 돌지 않고 일부만 도는 것).
#[test]
fn golden_holds_every_security_reason_code() {
    let got = all();
    for code in [
        "E207", "E210", "E211", "E212", "E213", "W401", "W402", "W403", "W404", "W405", "W409",
        "W410", "W411",
    ] {
        assert!(
            got.contains(&format!("\n{code} (")) || got.starts_with(&format!("{code} (")),
            "{code}"
        );
    }
}
