//! `bingsu list presets --preview` draws through the prompt renderer.
use bingsu_core::color::sgr::ColorDepth;
use bingsu_core::icons::IconSet;
use bingsu_core::preview::{MIN_WIDTH, PreviewInput, preview_line};
use bingsu_core::style::PRESETS;
use bingsu_core::width::{WidthProfile, str_width};

fn input(width: u16, icons: IconSet, depth: Option<ColorDepth>) -> PreviewInput<'static> {
    PreviewInput {
        pwd: b"/home/u/src/\xE2\x80\xAEevil\x1b[31m",
        home: Some(b"/home/u"),
        width,
        icons,
        depth,
    }
}

// 이것을 실패시키는 것: 미리보기가 현재 폴더 값을 쓰지 않거나(`~/src`가 없음), 프리셋마다 다른 모양을 내지 않는 것,
// 폴더 이름의 제어 글자·bidi가 그대로 나가는 것, 폭을 넘는 것, 색 없는 모드에 escape가 섞이는 것,
// 색 모드에 escape가 없는 것.
#[test]
fn every_preset_draws_the_folder_inside_the_width() {
    let mut seen = Vec::new();
    for p in PRESETS {
        for w in [0u16, 40, 60, 80, 200] {
            let plain = preview_line(p.name, &input(w, IconSet::Ascii, None)).unwrap();
            let s = String::from_utf8(plain).unwrap();
            assert!(
                s.contains("~/src/") && s.contains("main"),
                "{} {w}: {s:?}",
                p.name
            );
            assert!(
                !s.contains('\x1b') && !s.contains('\u{202E}'),
                "{} {w}: {s:?}",
                p.name
            );
            let cap = u32::from(w.max(MIN_WIDTH)) - 1;
            assert!(
                str_width(&s, WidthProfile::DEFAULT) <= cap,
                "{} {w}: {s:?}",
                p.name
            );
            if w == 80 {
                // The ASCII set draws some shapes alike; Nerd tells them apart.
                let n = preview_line(p.name, &input(w, IconSet::Nerd, None)).unwrap();
                seen.push(String::from_utf8(n).unwrap());
            }
        }
        let color = preview_line(
            p.name,
            &input(80, IconSet::Ascii, Some(ColorDepth::TrueColor)),
        )
        .unwrap();
        assert!(color.contains(&b'\x1b'), "{}", p.name);
    }
    let mut uniq = seen.clone();
    uniq.sort();
    uniq.dedup();
    assert_eq!(uniq.len(), PRESETS.len(), "{seen:?}");
}
