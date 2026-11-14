//! The vi command mode fields of a whole B1 record:
//! from `front::render_selected`, so band selection, the notice and the
//! encoder all take part, split the way the shell readers split.
use bingsu_core::{
    color::palette::Mode,
    config::compile::CompiledConfig,
    envelope::Envelope,
    front::render_selected,
    layout_view::LayoutView,
    shell_word::Shell,
    status::Status,
    width::{WidthProfile, str_width},
};
use bingsu_core_tests::{parse_field, snapshot_fixture::compile};

const SHELLS: [Shell; 3] = [Shell::Zsh, Shell::Bash, Shell::Fish];
/// Record indices counted from 0, as bash reads them.
const LEFT: usize = 2;
const RIGHT: usize = 3;
const UPPER: usize = 8;
const LEFT_VICMD: usize = 9;
const RIGHT_VICMD: usize = 10;
const UPPER_VICMD: usize = 11;
const VI_LINES: usize = 12;
const STATUS: usize = 13;
const VICMD_SYMBOL: char = '\u{276E}';

fn envelope(width: u16) -> Envelope {
    Envelope {
        width,
        pwd: Some(b"/project/long-folder".to_vec()),
        duration_ms: Some(3000),
        ..Envelope::default()
    }
}

fn record<L: LayoutView>(
    shell: Shell,
    e: &Envelope,
    config: Option<&L>,
    status: Status,
) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    render_selected(e, shell, status, config, Mode::Dark, None, &mut out);
    assert_eq!(out.pop(), Some(0x1e));
    let elements: Vec<Vec<u8>> = out.split(|&b| b == 0x1f).map(<[u8]>::to_vec).collect();
    assert_eq!(elements.len(), 14);
    assert_eq!(elements[1], b"12");
    elements
}

fn default_record(shell: Shell, width: u16, status: Status) -> Vec<Vec<u8>> {
    record::<CompiledConfig>(shell, &envelope(width), None, status)
}

fn text(shell: Shell, f: &[u8]) -> String {
    parse_field(shell, f).unwrap()
}

// 이것을 실패시키는 것: 필드 순서를 바꾸는 것, vicmd로 다시 배치하지 않는 것(`vi_lines` 판정을 비움), 입력 줄이 아닌
// 줄을 고르는 것. 폭 80의 왼쪽은 triangle 블록이라 `vi_command` 필드로 바꿔 끼울 수 없는 경우다.
#[test]
fn default_theme_draws_the_command_symbol_at_80_and_50() {
    for shell in SHELLS {
        for width in [80, 50] {
            let r = default_record(shell, width, Status::OK_NONE);
            assert_eq!(r[VI_LINES], b"l", "{shell:?} {width}");
            let (main, vicmd) = (text(shell, &r[LEFT]), text(shell, &r[LEFT_VICMD]));
            assert!(vicmd.contains(VICMD_SYMBOL), "{shell:?} {width}: {vicmd:?}");
            assert!(!main.contains(VICMD_SYMBOL), "{shell:?} {width}: {main:?}");
            assert_eq!(
                main.replace('\u{276F}', &VICMD_SYMBOL.to_string()),
                vicmd,
                "{shell:?} {width}"
            );
            assert!(r[RIGHT_VICMD].is_empty() && r[UPPER_VICMD].is_empty());
        }
    }
}

// 이것을 실패시키는 것: `vi_lines`를 줄 비교 없이 언제나 `lru`로 채우는 것, 같은 줄의 vicmd 필드를 레코드에 싣는 것.
#[test]
fn a_layout_without_char_names_no_line() {
    let config = compile("[style]\ntemplate='{dir}{@fill:space}{duration}'");
    for shell in SHELLS {
        let r = record(shell, &envelope(80), Some(&config), Status::OK_NONE);
        assert!(!r[LEFT].is_empty() && !r[RIGHT].is_empty(), "{shell:?}");
        for i in [LEFT_VICMD, RIGHT_VICMD, UPPER_VICMD, VI_LINES] {
            assert!(r[i].is_empty(), "{shell:?} {i}: {:?}", r[i]);
        }
    }
}

// 이것을 실패시키는 것: 같은 내용의 필드와 빈 줄을 가르지 않는 것, 다시 배치하지 않고 왼쪽 글자만 바꾸는 것(폭이 달라진
// 왼쪽이 오른쪽을 밀어낸다), `vi_lines`에 `r`을 넣지 않는 것. 명령 모드에서만 넓어지는 왼쪽이 오른쪽을 없앤다. `r`이
// 있고 필드가 비었으므로 hook은 main의 오른쪽을 지운다.
#[test]
fn test_vi_lines_keeps_a_really_empty_line() {
    let config = compile(
        "[style]\ntemplate='{@group}{char.vicmd}a-long-text-only-in-command-mode-that-fills-the-line-up-to-the-right{@end}{char} text{@fill:space}{duration}'",
    );
    for shell in SHELLS {
        let r = record(shell, &envelope(70), Some(&config), Status::OK_NONE);
        assert!(!r[RIGHT].is_empty(), "{shell:?}: main has a right side");
        assert_eq!(r[VI_LINES], b"lr", "{shell:?}");
        assert!(r[RIGHT_VICMD].is_empty(), "{shell:?}");
    }
}

// 이것을 실패시키는 것: `vi_lines` 글자 순서를 바꾸는 것, 윗줄을 비교에서 빼는 것, 윗줄에 왼쪽 값을 싣는 것.
#[test]
fn every_changed_line_is_named_in_order() {
    let config = compile(
        "[style]\ntemplate='{dir}{@group}{char.vicmd}U{@end}{@nl}{char}{@fill:space}{@group}{char.vicmd}R{@end}{duration}'",
    );
    for shell in SHELLS {
        let r = record(shell, &envelope(80), Some(&config), Status::OK_NONE);
        assert_eq!(r[VI_LINES], b"lru", "{shell:?}");
        assert_ne!(r[UPPER_VICMD], r[UPPER], "{shell:?}");
        assert_ne!(r[RIGHT_VICMD], r[RIGHT], "{shell:?}");
        assert_ne!(r[UPPER_VICMD], r[LEFT_VICMD], "{shell:?}");
    }
}

// 이것을 실패시키는 것: vicmd 필드를 대상 셸이 아닌 셸의 문법으로 쓰는 것(같은 설정 → 같은 칸 내용, 스펙 목표 1).
#[test]
fn every_shell_reads_the_same_command_mode_line() {
    for width in [80, 50] {
        let [z, b, f] =
            SHELLS.map(|s| text(s, &default_record(s, width, Status::OK_NONE)[LEFT_VICMD]));
        assert!(z == b && b == f, "{width}: {z:?} {b:?} {f:?}");
    }
}

fn line_cells(shell: Shell, left: &[u8], right: &[u8]) -> u32 {
    str_width(&text(shell, left), WidthProfile::DEFAULT)
        + str_width(&text(shell, right), WidthProfile::DEFAULT)
}

// 이것을 실패시키는 것: vicmd 배치에 notice를 넘기지 않는 것(`!`가 없고 입력 줄이 한 칸 넓어져 상태 알림과 정렬이
// 전환 때 흔들린다), 줄임 폭을 main과 다르게 고르는 것. 상태를 지나 끝까지 다시 나눠 왕복을 본다.
#[test]
fn test_vi_variants_keep_notice_mark() {
    let config = compile("[style]\ntemplate='{dir}{@fill:space}{duration}{@nl}{char} {dir}'");
    for shell in SHELLS {
        for width in [2, 3, 10, 20, 50, 80] {
            for status in [
                Status::DEGRADED_RUNTIME_ROOT,
                Status::ERROR_CONFIG_LAST_GOOD,
            ] {
                for r in [
                    default_record(shell, width, status),
                    record(shell, &envelope(width), Some(&config), status),
                ] {
                    let at = format!("{shell:?} {width}");
                    let mut want = Vec::new();
                    status.write_to(&mut want);
                    assert_eq!(r[STATUS], want, "{at}");
                    assert!(text(shell, &r[LEFT]).starts_with('!'), "{at}");
                    if r[VI_LINES].contains(&b'l') {
                        assert!(text(shell, &r[LEFT_VICMD]).starts_with('!'), "{at}");
                        assert_eq!(
                            line_cells(shell, &r[LEFT_VICMD], &r[RIGHT]),
                            line_cells(shell, &r[LEFT], &r[RIGHT]),
                            "{at}"
                        );
                    }
                }
            }
        }
    }
}

// 이것을 실패시키는 것: notice를 받는 쪽만 고치고 정상 상태에도 `!`를 그리는 것, vicmd 쪽 폭 예약을 정상 상태에도 두는 것.
#[test]
fn a_healthy_status_has_no_mark_in_either_mode() {
    for shell in SHELLS {
        let r = default_record(shell, 80, Status::OK_NONE);
        assert!(!text(shell, &r[LEFT_VICMD]).contains('!'), "{shell:?}");
    }
}
