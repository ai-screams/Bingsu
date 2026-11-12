//! `bingsu help <code>` through the real binary.
use std::process::Command;

fn run(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_bingsu"))
        .args(args)
        .output()
        .unwrap()
}

// 이것을 실패시키는 것: help 분기를 지우는 것(사용법 오류 2), 출력을 stderr로 보내는 것, 성공을 0이 아니게 끝내는 것.
#[test]
fn a_known_code_prints_its_explanation_and_exits_0() {
    let out = run(&["help", "E201"]);
    assert_eq!(out.status.code(), Some(0), "{out:?}");
    assert!(out.stderr.is_empty());
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(text.starts_with("E201 (error)\n"), "{text}");
    for part in ["What happened\n", "Why\n", "How to fix\n"] {
        assert!(text.contains(part), "{text}");
    }
    // The lower-case form of the same code is the same explanation.
    assert_eq!(run(&["help", "e201"]).stdout, text.as_bytes());
}

// 이것을 실패시키는 것: 모르는 코드·잘못된 모양·인자 없음·인자 둘을 0이나 1로 끝내는 것, stdout에 쓰는 것.
#[test]
fn an_unknown_code_or_wrong_use_exits_2_with_nothing_on_stdout() {
    for args in [
        &["help", "E999"][..],
        &["help", "nope"],
        &["help", "B101"],
        &["help"],
        &["help", "E201", "E202"],
    ] {
        let out = run(args);
        assert_eq!(out.status.code(), Some(2), "{args:?} {out:?}");
        assert!(out.stdout.is_empty(), "{args:?}");
        assert!(
            String::from_utf8(out.stderr)
                .unwrap()
                .contains("usage: bingsu help"),
            "{args:?}"
        );
    }
}

// 이것을 실패시키는 것: 입력의 제어 문자를 오류 문구에 그대로 되돌려 쓰는 것.
#[test]
fn an_unknown_argument_is_not_echoed_raw() {
    let out = run(&["help", "\u{1b}[31m"]);
    assert_eq!(out.status.code(), Some(2));
    let err = String::from_utf8(out.stderr).unwrap();
    assert!(!err.contains('\u{1b}'), "{err}");
}
