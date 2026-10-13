//! Layer 1 property (spec section 7): over random names, widths 0–200,
//! both profiles and every icon set, no line exceeds the target width,
//! measured on the joined text as a terminal reads it.
use bingsu_core::field::{BUILTIN, Field, FieldValue, Value, segment};
use bingsu_core::icons::IconSet;
use bingsu_core::layout::{Inputs, Options, SegmentSetup, When, layout, runs_width, target};
use bingsu_core::recorder::NoopRecorder;
use bingsu_core::shorten::{Anchor, Keep, Method, PathFacts};
use bingsu_core::style::{LineLayout, StyleOptions, generate, preset};
use bingsu_core::template::compile::compile;
use bingsu_core::width::{WidthProfile, str_width};
use proptest::prelude::*;
use proptest::test_runner::{Config, TestRunner};
use std::cell::Cell;

/// Names mixing ASCII, Hangul (precomposed and NFD), combining marks,
/// ambiguous-width, emoji sequences, private use, control bytes, and a lone
/// U+FE0F or ZWJ that joins whatever is drawn before the name.
fn name() -> impl Strategy<Value = Vec<u8>> {
    let atoms = prop::sample::select(vec![
        "a",
        "Z",
        "-",
        "/",
        "%",
        "!",
        "#",
        "한",
        "\u{1112}\u{1161}\u{11AB}",
        "e\u{0301}",
        "\u{2026}",
        "\u{2500}",
        "\u{1F600}",
        "\u{1F3F3}\u{FE0F}\u{200D}\u{1F308}",
        "\u{1F1F0}\u{1F1F7}",
        "\u{E0B0}",
        "\u{1b}[31m",
        "\u{202E}",
        "\u{FFFD}",
        "\u{FE0F}",
        "\u{200D}",
    ]);
    prop::collection::vec(atoms, 0..40).prop_map(|v| v.concat().into_bytes())
}

const PATH_METHODS: &[Method] = &[Method::Repo, Method::Abbrev(1), Method::Depth(1)];
const BRANCH_METHODS: &[Method] = &[Method::Truncate {
    max: 24,
    keep: Keep::Start,
}];
const SETS: [IconSet; 4] = [
    IconSet::Nerd,
    IconSet::Light,
    IconSet::Unicode,
    IconSet::Ascii,
];

fn value(id: &str, text: &[u8]) -> Option<Value> {
    let d = segment(id).unwrap();
    let mut fields = vec![Field::ABSENT; d.fields.len()];
    if id == "git" {
        fields[d.field_index("ahead").unwrap()] = Field::known(FieldValue::Count {
            n: 3,
            saturated: false,
        });
    }
    Some(Value::new(text, fields))
}

/// Boundaries the sweep must reach, so a pass is not a pass over easy widths only.
#[derive(Default)]
struct Reached {
    minimal: Cell<usize>,
    dot: Cell<usize>,
    tight: Cell<usize>,
    wide_cut: Cell<usize>,
}

fn bump(c: &Cell<usize>, yes: bool) {
    c.set(c.get() + usize::from(yes));
}

// 이것을 실패시키는 것: 넘칠 때 7단계 중 어느 단계든 목표 폭을 넘는 줄을 남기는 것, 이어 붙인 글자가
// 조각별로 잰 폭보다 넓어지는 것(이름이 U+FE0F·U+FE0E로 시작할 때), 결합하지 않는 곳에 칸을 더해 오른쪽 끝이
// 목표 칸에 닿지 않는 것. 경계 도달은 끝에서 센다.
#[test]
fn no_line_overflows() {
    let reached = Reached::default();
    let strategy = (
        prop::collection::vec(name(), 0..8),
        name(),
        1u8..=2,
        1u8..=2,
        0usize..4,
        0usize..4,
    );
    let mut runner = TestRunner::new(Config {
        cases: 64,
        ..Config::default()
    });
    runner
        .run(&strategy, |(steps, branch, amb, emoji, style, set)| {
            let i = |id| BUILTIN.iter().position(|d| d.id == id).unwrap();
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
            values[i("char")] = value("char", b"");
            values[i("dir")] = value("dir", b"");
            let raw: Vec<&[u8]> = steps.iter().map(Vec::as_slice).collect();
            facts[i("dir")] = Some(PathFacts::new(Anchor::Home, &raw, Some(1), &[]));
            // The `#` and `⌚` templates get a branch that starts with the
            // selector that widens what is drawn before it.
            let branch = match style {
                2 => ["\u{FE0F}".as_bytes(), &branch].concat(),
                3 => ["\u{FE0E}".as_bytes(), &branch].concat(),
                _ => branch,
            };
            values[i("git")] = value("git", &branch);
            values[i("time")] = value("time", b"12:34:56");
            setup[i("char")].required = true;
            setup[i("dir")] = SegmentSetup {
                priority: 100,
                required: true,
                methods: PATH_METHODS,
                when: When::Needed,
            };
            setup[i("git")].methods = BRANCH_METHODS;
            let inputs = Inputs {
                catalog: BUILTIN,
                values: &values,
                facts: &facts,
                setup: &setup,
            };
            // Two presets, and templates that put the branch right after `#`
            // (U+FE0F makes a keycap emoji, 2 cells when `emoji = 2`) or `⌚`
            // (U+FE0E makes it the 2-cell text form when `emoji = 1`).
            let t = match style {
                0 | 1 => generate(
                    preset(if style == 0 { "lean" } else { "triangle" }).unwrap(),
                    &StyleOptions::default(),
                    &[
                        LineLayout {
                            left: &["dir", "git"],
                            right: &["time"],
                        },
                        LineLayout {
                            left: &["char"],
                            right: &[],
                        },
                    ],
                )
                .unwrap(),
                2 => String::from("{dir} #{git}{@fill}{time}{@nl}{char}"),
                _ => String::from("{dir} \u{231A}{git}{@fill}{time}{@nl}{char}"),
            };
            let lines = compile(&t, BUILTIN).unwrap();
            let profile = WidthProfile::new(amb, emoji).unwrap();
            for w in 0..=200u16 {
                let o = Options {
                    width: w,
                    profile,
                    icons: SETS[set],
                    use_last_column: false,
                };
                for (n, l) in layout(
                    std::slice::from_ref(&lines),
                    &[],
                    &[],
                    &inputs,
                    &o,
                    &mut NoopRecorder,
                )
                .into_iter()
                .enumerate()
                {
                    let lw = runs_width(&l.left, profile);
                    prop_assert!(
                        lw + runs_width(&l.right, profile) <= target(&o),
                        "w={w} {l:?}"
                    );
                    let s: String = l.left.iter().map(|r| r.text.as_str()).collect();
                    // An upper line that still shows its right part (the
                    // time; names have no digits) ends on the target cell:
                    // no join is counted that the terminal does not draw.
                    if n == 0 && !l.minimal && s.contains("12:34:56") {
                        prop_assert_eq!(lw, target(&o), "w={} {:?}", w, s);
                    }
                    bump(&reached.minimal, l.minimal && w >= 2);
                    bump(&reached.dot, amb == 2 && s.contains('.'));
                    bump(&reached.tight, w >= 2 && lw == target(&o));
                    let cut = s.contains('\u{2026}') || (amb == 2 && s.contains('.'));
                    let wide = s
                        .chars()
                        .any(|c| str_width(c.encode_utf8(&mut [0; 4]), profile) == 2);
                    bump(&reached.wide_cut, cut && wide);
                }
            }
            Ok(())
        })
        .unwrap();
    let r = [
        reached.minimal.get(),
        reached.dot.get(),
        reached.tight.get(),
        reached.wide_cut.get(),
    ];
    assert!(
        r.iter().all(|&n| n > 0),
        "boundaries reached (minimal, dot, tight, wide cut): {r:?}"
    );
}
