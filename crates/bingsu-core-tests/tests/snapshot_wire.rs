use bingsu_core::{
    color::{palette::Mode, sgr::ColorDepth},
    field::{BUILTIN, Value},
    icons::IconSet,
    layout::{Inputs, Options},
    recorder::NoopRecorder,
    render::{Target, render_prompt},
    shell_word::Shell,
    snapshot::*,
    snapshot_codec::*,
};
use bingsu_core_tests::snapshot_fixture as fixture;

// 이것을 실패시키는 것: field 순서·폭·버전·CRC·팔레트 쌍의 한 바이트를 바꾸는 것.
#[test]
fn native_snapshot_golden() {
    assert_eq!(
        fixture::bytes(),
        include_bytes!("../../../tests/golden/snapshot/fixture.bin")
    );
    let s = fixture::frame();
    let b = s.encode(1, 0).unwrap();
    assert_eq!(Snapshot::decode(&b).unwrap(), s);
}
// 이것을 실패시키는 것: CompiledConfig 필드·팔레트·템플릿·아이콘·폭 설정을 누락하거나 바꾸는 것.
#[test]
fn full_config_roundtrip_preserves_render_bytes() {
    let mut c = fixture::config();
    let values = vec![Some(Value::new(b"fixture", vec![])); BUILTIN.len()];
    let facts = vec![None; BUILTIN.len()];
    for icons in [
        IconSet::Nerd,
        IconSet::Light,
        IconSet::Unicode,
        IconSet::Ascii,
    ] {
        c.icons = icons;
        let d = decode_compiled(&encode_compiled(&c).unwrap()).unwrap();
        assert_eq!(d, c);
        for mode in [Mode::Dark, Mode::Light] {
            for shell in [Shell::Zsh, Shell::Bash, Shell::Fish] {
                for width in [1, 49, 60, 100, 200] {
                    let render = |cfg: &bingsu_core::config::compile::CompiledConfig| {
                        let setup = cfg.setup();
                        render_prompt(
                            &cfg.theme_for(mode),
                            &Inputs {
                                catalog: BUILTIN,
                                values: &values,
                                facts: &facts,
                                setup: &setup,
                            },
                            &Target {
                                shell,
                                depth: ColorDepth::TrueColor,
                                options: Options {
                                    width,
                                    profile: cfg.profile,
                                    icons: cfg.icons,
                                    use_last_column: cfg.use_last_column,
                                },
                            },
                            &mut NoopRecorder,
                        )
                    };
                    assert_eq!(render(&d), render(&c));
                }
            }
        }
    }
    for mode in ["dark", "light"] {
        let c = fixture::compile(&format!("[colors]\nmode='{mode}'"));
        assert_eq!(c.palette, c.light_palette);
        assert_eq!(decode_compiled(&encode_compiled(&c).unwrap()).unwrap(), c);
    }
}
