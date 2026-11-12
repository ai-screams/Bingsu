//! `explain` makes its decisions with the prompt's own render
//! (`front::render_selected_recorded`, through `decision_text::decide`). At
//! every width from 1 to 140 (the band edges 40 and 41 included): the
//! recorded render gives the same record bytes as the unrecorded one and the
//! band in the log is the one `bands::select` picks. Outside the band, a
//! segment the log calls hidden by overflow is not in the drawn text and one
//! it does not mention is.
use bingsu_core::{
    bands, color::palette::Mode, decision_text::decide, envelope, front, recorder::HideReason,
    shell_word::Shell, status::Status,
};
use bingsu_core_tests::{parse_field, snapshot_fixture as fixture};

const LEFT: usize = 2;
const RIGHT: usize = 3;
const UPPER: usize = 8;

/// Two user segments with long, distinct texts in the default layout and a
/// band up to 40 cells that draws only the left one.
const CONFIG: &str = r#"
[segment."custom/a"]
kind = "text"
text = "AAAAAAAAAAAAAAAA"
[segment."custom/b"]
kind = "text"
text = "BBBBBBBBBBBBBBBB"
[layout.line2]
left = ["custom/a", "dir", "char"]
right = ["custom/b"]
[layout.when.narrow]
max_cols = 40
[layout.when.narrow.line2]
left = ["custom/a", "char"]
"#;

fn envelope_at(width: u16) -> envelope::Envelope {
    let args: Vec<Vec<u8>> = [
        "--ctx",
        "1",
        "--record",
        "B1",
        "--width",
        &width.to_string(),
        "--runtime-root=1:2:/r",
        "--home=/home/u",
        "--shell",
        "zsh",
        "--pwd",
        "/home/u/project/src",
        "--status",
        "0",
    ]
    .iter()
    .map(|s| s.as_bytes().to_vec())
    .collect();
    let argv: Vec<&[u8]> = args.iter().map(Vec::as_slice).collect();
    envelope::parse(&argv).unwrap()
}

fn texts(record: &mut Vec<u8>) -> String {
    assert_eq!(record.pop(), Some(0x1e));
    let el: Vec<&[u8]> = record.split(|&b| b == 0x1f).collect();
    let mut t = parse_field(Shell::Zsh, el[LEFT]).unwrap();
    t.push_str(&parse_field(Shell::Zsh, el[RIGHT]).unwrap());
    t.push_str(&parse_field(Shell::Zsh, el[UPPER]).unwrap());
    t
}

// 이것을 실패시키는 것: 기록기를 쓰는 렌더가 기록기 없는 렌더와 다른 바이트를 내는 것, 기록기에 구간 번호를 틀리게 넘기는 것
// (경계 40·41), 기록기를 `NoopRecorder`로 바꿔 로그를 비우는 것(구간 단언), 숨김 기록을 다른 세그먼트에 붙이는 것.
#[test]
fn explain_decides_what_the_prompt_draws() {
    let c = fixture::compile(CONFIG);
    let ids: Vec<&str> = ["custom/a", "custom/b"].to_vec();
    let base = bingsu_core::field::BUILTIN.len();
    let mut saw_hidden = false;
    let mut saw_band = (false, false);
    for width in 1..=140u16 {
        let e = envelope_at(width);
        let mut plain = Vec::new();
        front::render_selected_with_values(
            &e,
            Shell::Zsh,
            Status::OK_NONE,
            Some(&c),
            Mode::Dark,
            None,
            &[],
            &mut plain,
        );
        let (log, mut recorded) = decide(&c, &e, Mode::Dark);
        assert_eq!(plain, recorded, "width {width}");
        let want = bands::select(&c.band_order, &c.bands, width);
        assert_eq!(log.band, want, "width {width}");
        saw_band = (saw_band.0 || want.is_some(), saw_band.1 || want.is_none());
        let drawn = texts(&mut recorded);
        for (i, id) in ids.iter().enumerate() {
            let letter = if *id == "custom/a" { 'A' } else { 'B' };
            let hidden = log.hidden.iter().any(|(_, s, r)| {
                *s == base + i
                    && matches!(
                        r,
                        HideReason::Priority
                            | HideReason::RightHidden
                            | HideReason::LeftOptional
                            | HideReason::Minimal
                    )
            });
            // Inside the band the lines are the band's: it does not list
            // the two user segments, so neither is drawn there. (This fails
            // when `lines_at` hands back the default variant.)
            if want.is_some() {
                assert!(!drawn.contains(letter), "{id} at {width}: {drawn:?}");
                continue;
            }
            if hidden {
                saw_hidden = true;
                assert!(!drawn.contains(letter), "{id} at {width}: {drawn:?}");
            } else {
                assert!(drawn.contains(letter), "{id} at {width}: {drawn:?} {log:?}");
            }
        }
    }
    assert!(saw_hidden, "the sweep never reached an overflow");
    assert_eq!(saw_band, (true, true));
    // The band edge: 40 is inside, 41 is outside.
    for (w, inside) in [(40u16, true), (41, false)] {
        let (log, _) = decide(&c, &envelope_at(w), Mode::Dark);
        assert_eq!(log.band.is_some(), inside, "width {w}");
    }
}
