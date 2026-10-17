use bingsu_core::{
    color::{palette::Mode, sgr::ColorDepth},
    envelope::Envelope,
    icons::IconSet,
    layout::{Inputs, Options, target},
    record::encode_b1,
    recorder::NoopRecorder,
    render::{Notice, Target, render_prompt, render_prompt_with_notice, to_b1_fields},
    shell_values,
    shell_word::Shell,
    status::Status,
    width::{WidthProfile, str_width},
};
use bingsu_core_tests::{parse_field, snapshot_fixture::compile};

// 이것을 실패시키는 것: notice의 폭 예약·셸 emitter를 우회, band를 줄인 폭으로 선택, 사용자 팔레트/아이콘 변경.
#[test]
fn warning_reserves_only_the_input_line_and_keeps_shell_grammar() {
    for template in [
        "{dir}{@fill:space}{duration}{@nl}{char}",
        "{dir} {char}{@fill:space}{duration}",
    ] {
        let mut cfg = compile(&format!("[style]\ntemplate='{template}'"));
        for icons in [
            IconSet::Ascii,
            IconSet::Unicode,
            IconSet::Light,
            IconSet::Nerd,
        ] {
            cfg.icons = icons;
            for profile in [WidthProfile::DEFAULT, WidthProfile::new(2, 2).unwrap()] {
                for mode in [Mode::Dark, Mode::Light] {
                    let e = Envelope {
                        pwd: Some(b"/project/long-folder".to_vec()),
                        duration_ms: Some(3000),
                        ..Envelope::default()
                    };
                    let collected = shell_values::collect(&e);
                    let setup = cfg.setup();
                    let inp = Inputs {
                        catalog: bingsu_core::field::BUILTIN,
                        values: &collected.values,
                        facts: &collected.facts,
                        setup: &setup,
                    };
                    for shell in [Shell::Zsh, Shell::Bash, Shell::Fish] {
                        for width in [0, 1, 2, 3, 10, 59, 60, 80] {
                            for use_last_column in [false, true] {
                                let t = Target {
                                    shell,
                                    depth: ColorDepth::TrueColor,
                                    options: Options {
                                        width,
                                        profile,
                                        icons,
                                        use_last_column,
                                    },
                                };
                                let theme = cfg.theme_for(mode);
                                let old = render_prompt(&theme, &inp, &t, &mut NoopRecorder);
                                assert_eq!(
                                    render_prompt_with_notice(
                                        &theme,
                                        &inp,
                                        &t,
                                        None,
                                        &mut NoopRecorder
                                    ),
                                    old
                                );
                                let warning = render_prompt_with_notice(
                                    &theme,
                                    &inp,
                                    &t,
                                    Some(Notice::Warning),
                                    &mut NoopRecorder,
                                );
                                assert_eq!(warning.upper, old.upper);
                                assert_eq!(warning.transient_left, old.transient_left);
                                assert_eq!(warning.transient_right, old.transient_right);
                                assert_eq!(warning.vi_insert, old.vi_insert);
                                assert_eq!(warning.vi_command, old.vi_command);
                                let left = parse_field(shell, &warning.left).unwrap();
                                let right = parse_field(shell, &warning.right).unwrap();
                                assert_eq!(left.starts_with('!'), width != 0);
                                assert!(
                                    str_width(&left, profile) + str_width(&right, profile)
                                        <= target(&t.options)
                                );
                                if width == 1 {
                                    assert_eq!(left, "!");
                                    assert!(right.is_empty());
                                }
                                let mut record = Vec::new();
                                encode_b1(
                                    &to_b1_fields(&warning),
                                    Status::ERROR_CONFIG_LAST_GOOD,
                                    &mut record,
                                )
                                .unwrap();
                            }
                        }
                    }
                }
            }
        }
    }
}

// 이것을 실패시키는 것: notice를 뺀 폭으로 band를 골라 원래 60칸 레이아웃이 바뀌는 것.
#[test]
fn warning_keeps_the_band_selected_by_the_terminal_width() {
    let cfg = compile(
        "[style]\ntemplate='wide {dir} {char}'\n[layout.when.narrow]\nmax_cols=59\n[layout.when.narrow.style]\ntemplate='small {dir} {char}'",
    );
    let setup = cfg.setup();
    let c = shell_values::collect(&Envelope::default());
    let inp = Inputs {
        catalog: bingsu_core::field::BUILTIN,
        values: &c.values,
        facts: &c.facts,
        setup: &setup,
    };
    for (width, wanted) in [(59, "small"), (60, "wide")] {
        let t = Target {
            shell: Shell::Fish,
            depth: ColorDepth::TrueColor,
            options: Options {
                width,
                profile: cfg.profile,
                icons: cfg.icons,
                use_last_column: false,
            },
        };
        let r = render_prompt_with_notice(
            &cfg.theme(),
            &inp,
            &t,
            Some(Notice::Warning),
            &mut NoopRecorder,
        );
        assert!(parse_field(Shell::Fish, &r.left).unwrap().contains(wanted));
    }
}
