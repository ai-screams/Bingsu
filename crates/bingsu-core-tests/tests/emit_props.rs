//! Layer 1 properties of shell output (spec section 3 "셸 경계의 요구
//! 행동"): hostile text and arbitrary styles through every shell, then a
//! parser of each shell's field grammar reads the bytes back. Data bytes
//! must never turn into prompt syntax (zsh `%`, bash SOH/STX, ESC).
use bingsu_core::color::palette::{
    Knobs, Mode, PaletteInput, ResolvedPalette, TOKENS, resolve_palette,
};
use bingsu_core::color::sgr::{Color, ColorDepth, Style};
use bingsu_core::emit::{emit, readline_mode_string};
use bingsu_core::layout::Run;
use bingsu_core::record::{Encoded, Fields, encode_b1};
use bingsu_core::sanitize::is_removed;
use bingsu_core::shell_word::Shell;
use bingsu_core::status::Status;
use bingsu_core_tests::{parse_field, parse_readline};
use proptest::prelude::*;
use std::sync::OnceLock;

fn pal() -> &'static ResolvedPalette {
    static P: OnceLock<ResolvedPalette> = OnceLock::new();
    P.get_or_init(|| {
        resolve_palette(&PaletteInput {
            mode: Mode::Dark,
            knobs: Knobs::default(),
            overrides: &[],
            roles: &[],
        })
        .unwrap()
    })
}

fn accepted_by_b1(field: &[u8]) -> bool {
    let mut rec = Vec::new();
    let f = Fields {
        left: field,
        ..Fields::default()
    };
    matches!(
        encode_b1(&f, Status::OK_NONE, &mut rec),
        Ok(Encoded::Full | Encoded::ReplacedBySizeLimit)
    )
}

fn expected_text(runs: &[Run]) -> String {
    runs.iter()
        .flat_map(|r| r.text.chars())
        .filter(|&c| !is_removed(c))
        .collect()
}

fn check_all_shells(runs: &[Run], depth: ColorDepth) -> Result<(), String> {
    for shell in [Shell::Zsh, Shell::Bash, Shell::Fish] {
        let mut out = Vec::new();
        emit(shell, runs, pal(), depth, &mut out);
        let text = parse_field(shell, &out).map_err(|e| format!("{shell:?}: {e}: {out:?}"))?;
        if text != expected_text(runs) {
            return Err(format!(
                "{shell:?}: text {text:?} != {:?}",
                expected_text(runs)
            ));
        }
        if !accepted_by_b1(&out) {
            return Err(format!("{shell:?}: B1 rejects {out:?}"));
        }
    }
    Ok(())
}

fn hostile_char() -> impl Strategy<Value = char> {
    prop_oneof![
        3 => prop::sample::select(vec![
            '%', '\\', '!', '$', '`', '{', '}', '(', ')', '"', '\'', '\x01', '\x02', '\x1b', '\n',
            '\x1e', '\x1f', '\x7f', '\u{85}', '\u{9b}', '\u{202E}', '\u{200B}', '\u{2028}',
            '\u{200D}', '[', 'm', '0', '1', ';',
        ]),
        1 => any::<char>(),
    ]
}

fn color() -> impl Strategy<Value = Color> {
    // A little past the end of TOKENS: an unknown index writes no color.
    let n = TOKENS.len() as u16 + 2;
    prop_oneof![
        Just(Color::Default),
        (0..n).prop_map(Color::Text),
        (0..n).prop_map(Color::Block),
        (0..n).prop_map(Color::OnBlock),
    ]
}

fn style() -> impl Strategy<Value = Style> {
    (color(), color(), 0u8..16).prop_map(|(fg, bg, attrs)| Style { fg, bg, attrs })
}

fn run() -> impl Strategy<Value = Run> {
    (prop::collection::vec(hostile_char(), 0..12), style()).prop_map(|(t, style)| Run {
        text: t.into_iter().collect(),
        style,
    })
}

fn depth() -> impl Strategy<Value = ColorDepth> {
    prop::sample::select(vec![
        ColorDepth::TrueColor,
        ColorDepth::Ansi256,
        ColorDepth::Ansi16,
    ])
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 512, ..ProptestConfig::default() })]

    // 이것을 실패시키는 것: 마지막 방어(정제 대상 글자 지우기)를 빼는 것, zsh `%%`를 빼는 것, 셸별 표식을
    // 바꾸거나 빠뜨리는 것, 글자를 잘못 지우는 것(되읽은 글자가 입력과 다름).
    #[test]
    fn hostile_runs_keep_the_field_grammar(runs in prop::collection::vec(run(), 0..6), d in depth()) {
        prop_assert_eq!(check_all_shells(&runs, d), Ok(()));
    }

    // 이것을 실패시키는 것: readline 쪽 글자의 마지막 방어를 빼는 것, `"`·`\`를 이스케이프하지 않는 것,
    // SOH·STX를 짧은 `\1`·`\2`로 쓰는 것(되읽기에서 다음 숫자와 합쳐짐), ESC 자리를 `e`로 바꾸지
    // 않는 것. 되읽은 바이트는 같은 run의 bash 필드와 같아야 한다.
    #[test]
    fn readline_mode_string_reads_back(runs in prop::collection::vec(run(), 0..6), d in depth()) {
        let mut out = Vec::new();
        readline_mode_string(&runs, pal(), d, &mut out);
        let mut bash = Vec::new();
        emit(Shell::Bash, &runs, pal(), d, &mut bash);
        prop_assert_eq!(parse_readline(&out), Ok(bash));
        prop_assert!(accepted_by_b1(&out));
    }
}

fn payload(spec: &str) -> Vec<u8> {
    if let Some(rest) = spec.strip_prefix("repeat:") {
        let (byte, n) = rest.split_once(':').unwrap();
        return vec![u8::from_str_radix(byte, 16).unwrap(); n.parse().unwrap()];
    }
    (0..spec.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&spec[i..i + 2], 16).unwrap())
        .collect()
}

// Every row of the hostile matrix, as raw text (not sanitized first), so
// emit's own filter is the only defense. CANARY is left as is: no shell
// runs these bytes here.
// 이것을 실패시키는 것: 마지막 방어(정제 대상 글자 지우기)를 빼는 것, zsh `%%`를 빼는 것.
#[test]
fn hostile_matrix_through_every_shell() {
    let text = include_str!("../../../tests/hostile/classes.tsv");
    let mut rows = 0;
    for line in text
        .lines()
        .filter(|l| !l.starts_with('#') && !l.is_empty())
    {
        let c: Vec<&str> = line.split('\t').collect();
        let t = String::from_utf8_lossy(&payload(c[1])).into_owned();
        let styled = Style {
            fg: Color::Text(0),
            ..Style::default()
        };
        let runs = [
            Run {
                text: t.clone(),
                style: Style::default(),
            },
            Run {
                text: t,
                style: styled,
            },
        ];
        for d in [ColorDepth::TrueColor, ColorDepth::Ansi16] {
            assert_eq!(check_all_shells(&runs, d), Ok(()), "{}", c[0]);
        }
        rows += 1;
    }
    assert!(rows > 0);
}
