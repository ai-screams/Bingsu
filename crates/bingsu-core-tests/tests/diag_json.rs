//! The JSON text of diagnostics (`diag_json`): a string from a file can
//! neither break the document nor carry a control or bidi character (an
//! escaping property over arbitrary bytes, invalid UTF-8 included), every
//! diagnostic shape matches `schema/diag-output-v1.json` (`additionalProperties:
//! false`, so a renamed, dropped or added field fails), and representative
//! output is pinned byte for byte (BINGSU_UPDATE_GOLDEN=1 rewrites it).
use bingsu_core::config::tree::Span;
use bingsu_core::diag::{Diagnostic, Place, SourceId, SourceView};
use bingsu_core::diag_codes::{
    BAND_NEVER_CHOSEN, EXTENDS_BAD_PATH, KEY_PLANNED, NOT_RUN_UNSAFE_FILE, UNKNOWN_KEY,
};
use bingsu_core::diag_json::{Writer, diagnostics};
use bingsu_core::sanitize::sanitize;
use bingsu_core_tests::json_schema::validate;
use proptest::prelude::*;

const GOLDEN: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/golden/json/diagnostics.json"
);

struct Files;
impl SourceView for Files {
    fn display(&self, id: SourceId) -> &[u8] {
        // The second file has a name that is not UTF-8.
        if id.0 == 0 {
            b"/home/u/.config/bingsu/config.toml"
        } else {
            b"/tmp/\xff\x1b[2Jtheme.toml"
        }
    }
    fn bytes(&self, _: SourceId) -> &[u8] {
        "a = 1\n한글 = 2\nclr = 3\n".as_bytes()
    }
}

fn sample() -> Vec<Diagnostic> {
    let span = |start| Span {
        start,
        end: start + 1,
    };
    let mut at_theme = Diagnostic::new(
        UNKNOWN_KEY,
        Place::Source {
            id: SourceId(1),
            span: span(13),
        },
    )
    .arg("key", "co\u{1b}[31m\"lor\\\u{202e}");
    at_theme.via = vec![SourceId(0)];
    vec![
        at_theme,
        Diagnostic::new(
            NOT_RUN_UNSAFE_FILE,
            Place::Source {
                id: SourceId(0),
                span: span(0),
            },
        )
        .arg("id", "custom/a")
        .arg("key", "command")
        .arg("reason", "the file failed the owner and permission check"),
        Diagnostic::new(BAND_NEVER_CHOSEN, Place::Builtin).arg("id", "wide"),
        Diagnostic::new(
            EXTENDS_BAD_PATH,
            Place::Foreign {
                file: 3,
                span: span(17),
            },
        )
        .arg("path", "http://x/\n")
        .arg("reason", "only local files are read"),
        Diagnostic::new(KEY_PLANNED, Place::Builtin)
            .arg("key", "layout.transient")
            .arg("milestone", "M5"),
    ]
}

fn array(list: &[Diagnostic]) -> String {
    let mut w = Writer::new();
    diagnostics(&mut w, list, &Files);
    w.finish()
}

// 이것을 실패시키는 것: 필드 이름을 바꾸거나 빼거나 더하는 것(스키마의 additionalProperties·required), 위치 종류의 모양을 바꾸는 것,
// 심각도·코드 모양을 바꾸는 것, 정제하지 않은 값(ESC, 따옴표, 비UTF-8 이름)을 문서에 넣는 것.
#[test]
fn diagnostics_match_the_schema_and_the_golden() {
    let got = array(&sample());
    if let Err(e) = validate(Some("diagnostics"), &[&got]) {
        panic!("{e}\n{got}");
    }
    assert!(
        !got.contains('\u{1b}') && !got.contains('\u{202e}'),
        "{got}"
    );
    #[allow(clippy::disallowed_methods, reason = "golden update switch of a test")]
    let update = std::env::var_os("BINGSU_UPDATE_GOLDEN").is_some();
    if update {
        std::fs::write(GOLDEN, &got).unwrap();
        return;
    }
    let want = std::fs::read_to_string(GOLDEN)
        .unwrap()
        .replace("\r\n", "\n");
    assert_eq!(
        got, want,
        "run with BINGSU_UPDATE_GOLDEN=1 and review the diff"
    );
}

// 이것을 실패시키는 것: 스키마가 일부러 어긋난 문서(필드 하나 빠짐, 이름 바뀜, 필드 더해짐, 모르는 심각도)를 통과시키는 것.
#[test]
fn the_schema_refuses_a_changed_shape() {
    let good = array(&sample());
    assert!(validate(Some("diagnostics"), &[&good]).is_ok());
    let first_why = good.replacen("\"why\":", "\"because\":", 1);
    let no_help = good.replacen(",\"help\":\"bingsu help E201\"", "", 1);
    let extra = good.replacen("\"code\":\"E201\"", "\"code\":\"E201\",\"extra\":1", 1);
    let severity = good.replacen("\"severity\":\"error\"", "\"severity\":\"fatal\"", 1);
    // Python's `$` also matches before a final newline; `maxLength` closes that.
    let newline = good.replacen("\"code\":\"E201\"", "\"code\":\"E201\\n\"", 1);
    for (name, doc) in [
        ("code with a final newline", &newline),
        ("renamed", &first_why),
        ("dropped", &no_help),
        ("added", &extra),
        ("severity", &severity),
    ] {
        assert_ne!(doc, &good, "{name}: the edit did not apply");
        assert!(validate(Some("diagnostics"), &[doc]).is_err(), "{name}");
    }
}

fn one_string(bytes: &[u8]) -> String {
    let mut w = Writer::new();
    w.begin_array();
    w.bytes(bytes);
    w.end_array();
    w.finish()
}

fn check_escape(bytes: &[u8]) {
    let text = one_string(bytes);
    let parsed: serde_json::Value =
        serde_json::from_str(&text).unwrap_or_else(|e| panic!("{e}: {text:?}"));
    assert_eq!(parsed, serde_json::json!([sanitize(bytes)]), "{text:?}");
    assert!(
        !text.trim_end().chars().any(|c| c.is_control()),
        "a control character is in the document: {text:?}"
    );
}

proptest! {
    // 이것을 실패시키는 것: 문자열의 이스케이프를 빼는 것(따옴표·역슬래시·제어 문자가 문서를 깨뜨림), 정제를 빼는 것
    // (ESC·bidi가 그대로 남음), 비UTF-8 바이트를 U+FFFD로 바꾸지 않는 것.
    #[test]
    fn any_bytes_make_a_valid_document(bytes in prop::collection::vec(any::<u8>(), 0..64)) {
        check_escape(&bytes);
    }

    #[test]
    fn hostile_characters_make_a_valid_document(
        parts in prop::collection::vec(
            prop::sample::select(vec![
                "\"", "\\", "\u{0}", "\u{1b}", "\n", "\r", "\u{7f}", "\u{85}", "\u{202e}", "\u{2028}",
                "\u{2029}", "\u{200b}", "a", "é", "한", "😀", "/",
            ]),
            0..24,
        )
    ) {
        check_escape(parts.concat().as_bytes());
    }
}

// 이것을 실패시키는 것: 비UTF-8 파일 이름과 ESC가 든 이름이 `file`에 정제 없이 들어가는 것.
#[test]
fn a_file_name_that_is_not_utf8_is_cleaned() {
    let got = array(&sample());
    let doc: serde_json::Value = serde_json::from_str(&got).unwrap();
    assert_eq!(doc[0]["at"]["file"], "/tmp/\u{fffd}[2Jtheme.toml");
    assert_eq!(doc[0]["via"][0], "/home/u/.config/bingsu/config.toml");
}
