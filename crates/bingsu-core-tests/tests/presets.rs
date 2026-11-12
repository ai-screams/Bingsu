//! The seven built-in presets: the ASCII icon set draws only ASCII, every
//! preset ends a full upper line on the target cell (all widths 0–200), and
//! the `bracket` preset drops a segment's brackets with the segment.
use bingsu_core::field::{BUILTIN, Field, Value, segment};
use bingsu_core::icons::IconSet;
use bingsu_core::layout::{Inputs, Options, SegmentSetup, When, layout, runs_width, target};
use bingsu_core::recorder::NoopRecorder;
use bingsu_core::shorten::{Anchor, Method, PathFacts};
use bingsu_core::style::{LineLayout, PRESETS, StyleOptions, generate};
use bingsu_core::template::compile::compile;
use bingsu_core::width::WidthProfile;

const LINES: [LineLayout<'static>; 2] = [
    LineLayout {
        left: &["dir", "git"],
        right: &["time"],
    },
    LineLayout {
        left: &["char"],
        right: &[],
    },
];

/// Text of every laid-out line at `width`; `with_git` false leaves the git
/// segment without a value.
fn lines_at(preset: &str, set: IconSet, width: u16, with_git: bool) -> Vec<(String, u32, u32)> {
    let i = |id| BUILTIN.iter().position(|d| d.id == id).unwrap();
    let v = |id: &str, text: &[u8]| {
        let d = segment(id).unwrap();
        Some(Value::new(text, vec![Field::ABSENT; d.fields.len()]))
    };
    let mut values = vec![None; BUILTIN.len()];
    let mut facts = vec![None; BUILTIN.len()];
    let mut setup = vec![
        SegmentSetup {
            priority: 10,
            required: false,
            methods: &[],
            when: When::Needed
        };
        BUILTIN.len()
    ];
    values[i("char")] = v("char", b"");
    values[i("dir")] = v("dir", b"");
    facts[i("dir")] = Some(PathFacts::new(
        Anchor::Home,
        &[b"Works".as_slice(), b"themes"],
        Some(1),
        &[],
    ));
    if with_git {
        values[i("git")] = v("git", b"main");
    }
    values[i("time")] = v("time", b"12:34:56");
    setup[i("char")].required = true;
    setup[i("dir")] = SegmentSetup {
        priority: 100,
        required: true,
        methods: &[Method::Repo, Method::Abbrev(1), Method::Depth(1)],
        when: When::Needed,
    };
    let inputs = Inputs {
        catalog: BUILTIN,
        values: &values,
        facts: &facts,
        setup: &setup,
    };
    let p = PRESETS.iter().find(|p| p.name == preset).unwrap();
    let t = generate(p, &StyleOptions::default(), &LINES).unwrap();
    let lines = compile(&t, BUILTIN).unwrap();
    let profile = WidthProfile::new(1, 2).unwrap();
    let o = Options {
        width,
        profile,
        icons: set,
        use_last_column: false,
    };
    layout(
        std::slice::from_ref(&lines),
        &[],
        &[],
        &inputs,
        &o,
        &mut NoopRecorder,
    )
    .into_iter()
    .map(|l| {
        let s: String = l
            .left
            .iter()
            .chain(&l.right)
            .map(|r| r.text.as_str())
            .collect();
        (
            s,
            runs_width(&l.left, profile) + runs_width(&l.right, profile),
            target(&o),
        )
    })
    .collect()
}

// 이것을 실패시키는 것: 프리셋의 머리·꼬리·구분자 글리프가 ASCII 세트에서 ASCII 아닌 글자를 내는 것
// (아이콘 표의 ASCII 칸이 비거나 유니코드인 것), 폭 0–200 어디서든 윗줄이 목표 칸을 넘는 것.
#[test]
fn every_preset_fits_and_has_an_ascii_form() {
    for p in PRESETS {
        for w in 0..=200u16 {
            for (s, used, max) in lines_at(p.name, IconSet::Ascii, w, true) {
                // `…` comes from shortening a name, not from the preset.
                assert!(
                    s.replace('\u{2026}', "").is_ascii(),
                    "{} w={w}: {s:?}",
                    p.name
                );
                assert!(used <= max, "{} w={w}: {s:?}", p.name);
            }
        }
    }
}

// 이것을 실패시키는 것: 값 없는 세그먼트의 `[`·`]`가 남는 것(`{@group}` 없이 글을 잇는 것).
#[test]
fn bracket_drops_with_a_segment_that_has_no_value() {
    let with = lines_at("bracket", IconSet::Ascii, 80, true);
    assert!(
        with[0].0.starts_with("[~/Works/themes] [main]"),
        "{:?}",
        with[0].0
    );
    let without = lines_at("bracket", IconSet::Ascii, 80, false);
    assert!(
        !without[0].0.contains("[]") && !without[0].0.contains("[main"),
        "{:?}",
        without[0].0
    );
    assert!(without[0].0.starts_with('['), "{:?}", without[0].0);
    // The input marker is never bracketed.
    assert!(!with[1].0.contains('['), "{:?}", with[1].0);
}
