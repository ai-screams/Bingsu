#![cfg(test)]
use super::*;
use crate::color::sgr::DIM;
use crate::field::{BUILTIN, Field, FieldValue, segment};
use crate::recorder::{DecisionLog, HideReason, NoopRecorder, Step};
use crate::shorten::Anchor;
use crate::style::{LineLayout, StyleOptions, generate, preset};
use crate::template::compile::compile;
use alloc::vec;

pub(crate) struct Fixture {
    pub values: Vec<Option<Value>>,
    pub facts: Vec<Option<PathFacts>>,
    pub setup: Vec<SegmentSetup<'static>>,
}

const PATH_METHODS: &[Method] = &[Method::Repo, Method::Abbrev(1), Method::Depth(1)];
const BRANCH_METHODS: &[Method] = &[Method::Truncate {
    max: 24,
    keep: Keep::Start,
}];

fn idx(id: &str) -> usize {
    BUILTIN.iter().position(|d| d.id == id).unwrap()
}

fn value(id: &str, text: &str, set: &[(&str, FieldValue)]) -> Option<Value> {
    let d = segment(id).unwrap();
    let mut fields = vec![Field::ABSENT; d.fields.len()];
    for (name, v) in set {
        fields[d.field_index(name).unwrap()] = Field::known(v.clone());
    }
    Some(Value::new(text.as_bytes(), fields))
}

pub(crate) fn fixture(steps: &[&str], branch: &str) -> Fixture {
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
    values[idx("char")] = value("char", "", &[]);
    values[idx("dir")] = value("dir", "", &[]);
    let raw: Vec<&[u8]> = steps.iter().map(|s| s.as_bytes()).collect();
    facts[idx("dir")] = Some(PathFacts::new(Anchor::Home, &raw, Some(2), &[]));
    values[idx("git")] = value(
        "git",
        branch,
        &[(
            "ahead",
            FieldValue::Count {
                n: 2,
                saturated: false,
            },
        )],
    );
    values[idx("status")] = value("status", "1", &[("code", FieldValue::Int(1))]);
    values[idx("time")] = value("time", "12:34", &[]);
    setup[idx("char")].required = true;
    setup[idx("dir")] = SegmentSetup {
        priority: 100,
        required: true,
        methods: PATH_METHODS,
        when: When::Needed,
    };
    setup[idx("git")].methods = BRANCH_METHODS;
    setup[idx("time")].priority = 1;
    Fixture {
        values,
        facts,
        setup,
    }
}

impl Fixture {
    pub(crate) fn inputs(&self) -> Inputs<'_> {
        Inputs {
            catalog: BUILTIN,
            values: &self.values,
            facts: &self.facts,
            setup: &self.setup,
        }
    }
}

pub(crate) fn opts(width: u16) -> Options {
    Options {
        width,
        profile: WidthProfile::DEFAULT,
        icons: IconSet::Nerd,
        use_last_column: false,
    }
}

pub(crate) fn two_lines(preset_name: &str) -> Vec<CompiledLine> {
    let t = generate(
        preset(preset_name).unwrap(),
        &StyleOptions::default(),
        &[
            LineLayout {
                left: &["dir", "git"],
                right: &["status", "time"],
            },
            LineLayout {
                left: &["char"],
                right: &[],
            },
        ],
    )
    .unwrap();
    compile(&t, BUILTIN).unwrap()
}

fn text(runs: &[Run]) -> String {
    runs.iter().map(|r| r.text.as_str()).collect()
}

fn lay(lines: &[CompiledLine], f: &Fixture, o: &Options) -> Vec<LaidLine> {
    layout(
        &[lines.to_vec()],
        &[],
        &[],
        &f.inputs(),
        o,
        &mut NoopRecorder,
    )
}

/// Every line's joined width is within the target.
fn assert_fits(out: &[LaidLine], o: &Options, what: &str) {
    for l in out {
        let lw = runs_width(&l.left, o.profile) + runs_width(&l.right, o.profile);
        assert!(
            lw <= target(o),
            "{what} w={}: {lw} > {} {l:?}",
            o.width,
            target(o)
        );
    }
}

// 이것을 실패시키는 것: 첫 줄이 목표 폭(셸 폭 − 1)과 다르게 끝나는 것(오른쪽 끝 정렬, 마지막 칸 비움).
// `target`의 `w - 1`을 `w`로 바꾸면 80칸에서 실패한다(변이 E3).
#[test]
fn upper_line_ends_on_the_second_to_last_cell() {
    let f = fixture(&["Works", "AiScream", "themes"], "main");
    for name in ["lean", "triangle"] {
        let out = lay(&two_lines(name), &f, &opts(80));
        assert_eq!(
            runs_width(&out[0].left, WidthProfile::DEFAULT),
            79,
            "{name}"
        );
        assert!(
            text(&out[0].left).ends_with("12:34 ") || text(&out[0].left).ends_with("12:34"),
            "{name}"
        );
        let mut lc = opts(80);
        lc.use_last_column = true;
        assert_eq!(
            runs_width(
                &lay(&two_lines(name), &f, &lc)[0].left,
                WidthProfile::DEFAULT
            ),
            80,
            "{name}"
        );
    }
}

// 이것을 실패시키는 것: 0–200 어느 폭·어느 프로필에서든 줄이 목표 폭을 넘는 것.
// 경계가 실제로 닿는지(최소 프롬프트, `…`, amb=2의 `.`, 목표 폭에 꼭 맞는 줄) 센다.
#[test]
fn never_overflows_any_width() {
    let long = "x".repeat(300);
    let cases = [
        fixture(
            &["Works", "AiScream", "themes", "src", "render"],
            "feature/very-long-branch-name",
        ),
        fixture(
            &[
                "프로젝트",
                "\u{1112}\u{1161}\u{11AB}\u{1100}\u{1173}\u{11AF}",
                long.as_str(),
            ],
            "\u{1F3F3}\u{FE0F}\u{200D}\u{1F308}-\u{2026}",
        ),
    ];
    let (mut minimal, mut ell, mut dot, mut tight) = (0, 0, 0, 0);
    for f in &cases {
        for name in ["lean", "triangle"] {
            let lines = two_lines(name);
            for amb in [1, 2] {
                for w in 0..=200u16 {
                    let o = Options {
                        profile: WidthProfile::new(amb, 2).unwrap(),
                        ..opts(w)
                    };
                    let out = lay(&lines, f, &o);
                    assert_fits(&out, &o, name);
                    for l in &out {
                        assert!(
                            l.left.iter().chain(&l.right).all(|r| !r.text.is_empty()),
                            "{name} w={w} {l:?}"
                        );
                        let t = text(&l.left);
                        minimal += usize::from(l.minimal);
                        ell += usize::from(amb == 1 && t.contains('\u{2026}'));
                        dot += usize::from(amb == 2 && t.contains('.'));
                        tight +=
                            usize::from(w >= 2 && runs_width(&l.left, o.profile) == target(&o));
                    }
                }
            }
        }
    }
    assert!(
        minimal > 0 && ell > 0 && dot > 0 && tight > 0,
        "{minimal} {ell} {dot} {tight}"
    );
}

// 이것을 실패시키는 것: 폭 0·1·2·3 규칙(빈 문자열, `>`, `char`+공백) 중 하나가 틀리는 것.
#[test]
fn tiny_widths() {
    let f = fixture(&["Works"], "main");
    let lines = two_lines("triangle");
    let input = |w| text(&lay(&lines, &f, &opts(w)).pop().unwrap().left);
    assert_eq!(input(0), "");
    assert_eq!(input(1), ">");
    assert_eq!(input(2), "\u{276F}");
    // Width 3 (target 2): step 6 already fits the plain `❯`.
    assert_eq!(input(3), "\u{276F}");
    assert!(lay(&lines, &f, &opts(1))[0].minimal);
    assert_eq!(text(&lay(&lines, &f, &opts(3))[0].left), "\u{2026}");
}

// 이것을 실패시키는 것: lean의 빈 host·git·duration 앞뒤에 공백이 남거나 빈 값 때문에 경로를 일찍 줄이는 것.
#[test]
fn lean_gaps_follow_visible_segments() {
    let template = generate(
        preset("lean").unwrap(),
        &StyleOptions::default(),
        &[
            LineLayout {
                left: &["host", "dir", "git"],
                right: &[],
            },
            LineLayout {
                left: &["duration", "char"],
                right: &[],
            },
        ],
    )
    .unwrap();
    let lines = compile(&template, BUILTIN).unwrap();
    for mask in 0..8 {
        let mut f = fixture(&["Works"], "main");
        f.values[idx("host")] = (mask & 1 != 0).then(|| value("host", "host", &[]).unwrap());
        f.values[idx("git")] = (mask & 2 != 0).then(|| value("git", "main", &[]).unwrap());
        f.values[idx("duration")] = (mask & 4 != 0).then(|| value("duration", "3s", &[]).unwrap());
        let out = lay(&lines, &f, &opts(80));
        let upper = [
            if mask & 1 != 0 { "host" } else { "" },
            "~/Works",
            if mask & 2 != 0 { "main" } else { "" },
        ]
        .into_iter()
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join(" ");
        assert_eq!(text(&out[0].left), upper, "mask {mask}");
        assert_eq!(
            text(&out[1].left),
            if mask & 4 != 0 { "3s ❯" } else { "❯" },
            "mask {mask}"
        );
        if mask == 0 {
            assert_eq!(text(&lay(&lines, &f, &opts(8))[0].left), "~/Works");
        }
    }
    // Each side cleans its own leading, duplicate and trailing gaps.
    let mut f = fixture(&["Works"], "main");
    f.values[idx("status")] = None;
    let out = one(
        "{dir}{@fill}{status}{@sep:flat}{time}{@sep:flat}{host}{@nl}{char}",
        &f,
        80,
    );
    assert!(text(&out[0].left).ends_with("12:34"));
    assert_eq!(
        text(&out[0].left).trim_end().len(),
        text(&out[0].left).len()
    );
}

// 이것을 실패시키는 것: 배경 제거 단계에서 flat 공백까지 지워 이웃 세그먼트를 붙이는 것.
#[test]
fn flat_gaps_survive_background_removal() {
    let f = fixture(&["Works"], "main");
    let out = one("{char:block}{@sep:flat}{char:block}{@nl}{char}", &f, 4);
    assert_eq!(text(&out[0].left), "❯ ❯");
}

// 이것을 실패시키는 것: 뒤의 리터럴만 보고 기존 블록 구분자를 남기거나,
// 가장 가까운 콘텐츠 대신 앞의 다른 plain 콘텐츠로 간격을 판단하는 것.
#[test]
fn flat_block_separators_keep_the_block_ahead_rule() {
    let mut f = fixture(&["Works"], "main");
    let template = "{dir:block}{@sep:flat}{git:block} x{@nl}{char}";
    assert_eq!(text(&one(template, &f, 80)[0].left), " ~/Works   main  x");
    f.values[idx("git")] = None;
    assert_eq!(text(&one(template, &f, 80)[0].left), " ~/Works  x");
    for (template, expected) in [
        ("p{dir:block}{@sep:flat} x{@nl}{char}", "p ~/Works  x"),
        ("{dir:block}p{@sep:flat}x{@nl}{char}", " ~/Works p x"),
        (
            "{dir}{@sep:flat}x{time:block}{@nl}{char}",
            "~/Works x 12:34 ",
        ),
        (
            "{dir:block}{@sep:flat}x{time:block}{@nl}{char}",
            " ~/Works  x 12:34 ",
        ),
    ] {
        assert_eq!(text(&one(template, &f, 80)[0].left), expected, "{template}");
    }
}

// 이것을 실패시키는 것: flat 간격이 head/tail 경계를 넘어 콘텐츠를 찾는 것.
#[test]
fn flat_plain_gaps_respect_heads_and_tails() {
    let f = fixture(&["Works"], "main");
    for boundary in ["{@head:flat}", "{@tail:flat}"] {
        for template in [
            alloc::format!("{{dir}}{boundary}{{@sep:flat}}x{{@nl}}{{char}}"),
            alloc::format!("{{dir}}{{@sep:flat}}{boundary}x{{@nl}}{{char}}"),
        ] {
            assert_eq!(
                text(&one(&template, &f, 80)[0].left),
                "~/Worksx",
                "{template}"
            );
        }
    }
}

// 이것을 실패시키는 것: 값이 없는 세그먼트의 구분자가 남거나 겹치는 것, 꼬리가 사라지는 것.
#[test]
fn separator_cleanup() {
    let mut f = fixture(&["Works"], "main");
    f.values[idx("git")] = None;
    f.values[idx("status")] = None;
    let out = lay(&two_lines("triangle"), &f, &opts(80));
    let t = text(&out[0].left);
    assert_eq!(t.matches('\u{E0B0}').count(), 1, "{t:?}");
    assert!(t.starts_with(" ~/Works \u{E0B0}"), "{t:?}");
    assert_eq!(t.matches('\u{E0B2}').count(), 1, "{t:?}");
}

// 이것을 실패시키는 것: ambiguous=2에서 채움 `─`(2칸)를 그대로 쓰거나 남은 칸을 못 채우는 것.
#[test]
fn fill_under_ambiguous_two() {
    let f = fixture(&["Works"], "main");
    let t = "{dir}{@fill:line}{time}{@nl}{char}";
    let lines = compile(t, BUILTIN).unwrap();
    let o = Options {
        profile: WidthProfile::new(2, 2).unwrap(),
        ..opts(41)
    };
    let out = lay(&lines, &f, &o);
    let s = text(&out[0].left);
    assert!(!s.contains('\u{2500}') && s.contains("----"), "{s:?}");
    assert_eq!(runs_width(&out[0].left, o.profile), 40);
}

// 이것을 실패시키는 것: 4단계의 동점을 줄 위치가 아니라 카탈로그 순서로 고르는 것(`git`이 카탈로그에서 `time`보다 앞),
// 또는 자른 조각을 흐리게(DIM) 그리지 않는 것.
#[test]
fn step4_cuts_the_leftmost_of_equal_widths() {
    let mut f = fixture(&["Works"], "main");
    f.values[idx("time")] = value("time", "aaaaaa", &[]);
    f.values[idx("git")] = value("git", "bbbbbb", &[]);
    f.setup[idx("git")].methods = &[];
    let lines = compile("{time} {git}{@nl}{char}", BUILTIN).unwrap();
    let out = lay(&lines, &f, &opts(11));
    assert_eq!(text(&out[0].left), "aa\u{2026} bbbbbb");
    let cut = out[0]
        .left
        .iter()
        .find(|r| r.text.contains('\u{2026}'))
        .unwrap();
    assert_ne!(cut.style.attrs & DIM, 0, "{cut:?}");
}

// 이것을 실패시키는 것: 조각마다 잰 폭만 믿는 것. `#` 뒤에 U+FE0F로 시작하는 값이 오면 터미널은 둘을
// 2칸 이모지 하나로 읽고, `emoji = 1`에서 `⌚` 뒤에 U+FE0E가 오면 2칸 글자 꼴로 읽으므로, 이어 붙인 폭이
// 목표 폭을 넘는다(`join_risk`가 0을 돌려주거나 U+FE0E를 빼면 실패).
#[test]
fn a_joining_value_never_widens_the_line() {
    let mut f = fixture(&["Works"], "main");
    f.setup[idx("git")].methods = &[];
    for (t, v, emoji) in [
        ("#{git}{@nl}{char}", "\u{FE0F}abc", 2),
        ("\u{231A}{git}{@nl}{char}", "\u{FE0E}abc", 1),
    ] {
        f.values[idx("git")] = value("git", v, &[]);
        let lines = compile(t, BUILTIN).unwrap();
        for w in 0..=12 {
            let o = Options {
                profile: WidthProfile::new(1, emoji).unwrap(),
                ..opts(w)
            };
            assert_fits(&lay(&lines, &f, &o), &o, t);
        }
    }
    let mut buf = String::new();
    let d = |t, h, e| join_delta(t, h, &mut String::new(), WidthProfile::new(1, e).unwrap());
    assert_eq!(d("#", "\u{FE0F}", 2), 1);
    assert_eq!(d("\u{231A}", "\u{FE0E}", 1), 1);
    assert_eq!(d("a", "\u{FE0F}", 2), 0);
    assert_eq!(d("\u{1F468}", "\u{200D}", 2), 0);
    assert_eq!(d("e", "\u{0301}", 2), 0);
    assert_eq!(join_delta("a", "b", &mut buf, WidthProfile::DEFAULT), 0);
    // Below U+0300 the measure is skipped and the buffer stays unused.
    assert_eq!(buf.capacity(), 0);
}

// 이것을 실패시키는 것: 공개 필드로 만든 어긋난 입력에서 색인 패닉이 나는 것. `values`·`facts`·`setup`이
// 카탈로그보다 짧은 것, 다른 카탈로그로 컴파일한 줄, 선언보다 필드가 적은 값, 범위 밖 band 순서, 빈 variants.
#[test]
fn ragged_inputs_do_not_panic() {
    let lines = compile(
        "{@group}{git.ahead}{@end}{dir:block}{@sep:round}{git:block}{venv}{@fill:dot}{time}{@nl}{char}",
        BUILTIN,
    )
    .unwrap();
    let values = vec![
        Some(Value::new(b"x", Vec::new())),
        None,
        Some(Value::new(b"y", Vec::new())),
        Some(Value::new(b"main", Vec::new())),
    ];
    let facts = vec![None];
    // Shortened segments read `facts` past its end.
    let setup = [SegmentSetup {
        priority: 1,
        required: false,
        methods: BRANCH_METHODS,
        when: When::Always,
    }; 4];
    for catalog in [BUILTIN, &BUILTIN[..3]] {
        let inp = Inputs {
            catalog,
            values: &values,
            facts: &facts,
            setup: &setup,
        };
        for w in 0..=40 {
            let o = opts(w);
            // A recording log reads the same ragged inputs.
            let _ = layout(
                core::slice::from_ref(&lines),
                &[],
                &[],
                &inp,
                &o,
                &mut DecisionLog::default(),
            );
            assert_fits(
                &layout(
                    core::slice::from_ref(&lines),
                    &[],
                    &[],
                    &inp,
                    &o,
                    &mut NoopRecorder,
                ),
                &o,
                "ragged",
            );
            assert_fits(
                &layout(
                    core::slice::from_ref(&lines),
                    &[Band {
                        min_cols: None,
                        max_cols: None,
                        order: None,
                    }],
                    &[3],
                    &inp,
                    &o,
                    &mut NoopRecorder,
                ),
                &o,
                "band",
            );
            // Band 0 has no variant: the default layout is used.
            let out = layout(
                core::slice::from_ref(&lines),
                &[Band {
                    min_cols: None,
                    max_cols: None,
                    order: None,
                }],
                &[0],
                &inp,
                &o,
                &mut NoopRecorder,
            );
            assert_eq!(out.len(), 2);
            assert_fits(&out, &o, "variant");
            assert!(layout(&[], &[], &[], &inp, &o, &mut NoopRecorder).is_empty());
        }
    }
}

// 이것을 실패시키는 것: 채움 글리프가 어떤 세트·프로필에서 1칸이 아닌 것(채움은 `gap`개를 이어 붙이므로 칸 수가 어긋난다).
#[test]
fn fill_glyphs_are_one_cell() {
    for kind in [FillKind::Space, FillKind::Dot, FillKind::Line] {
        for set in [
            IconSet::Nerd,
            IconSet::Light,
            IconSet::Unicode,
            IconSet::Ascii,
        ] {
            for (a, e) in [(1, 1), (1, 2), (2, 1), (2, 2)] {
                let o = Options {
                    profile: WidthProfile::new(a, e).unwrap(),
                    icons: set,
                    ..opts(80)
                };
                let g = icon_glyph(kind.icon(), &o);
                assert_eq!(
                    (g.width, str_width(g.text, o.profile)),
                    (1, 1),
                    "{kind:?} {set:?} {a} {e}"
                );
            }
        }
    }
}

fn one(t: &str, f: &Fixture, w: u16) -> Vec<LaidLine> {
    lay(&compile(t, BUILTIN).unwrap(), f, &opts(w))
}

// 이것을 실패시키는 것: 숨은 블록 뒤 꼬리를 앞 구분자의 글리프로 그리는 것, 블록이 하나도 남지 않은 머리를
// 남기는 것, 앞 내용 없는 구분자나 머리 바로 뒤 구분자를 남기는 것, 숨은 블록 양쪽의 구분자를 둘 다 남기는 것.
#[test]
fn merged_separator_draws_the_tail() {
    let mut f = fixture(&["Works"], "main");
    f.values[idx("git")] = None;
    let t = "{dir:block}{@sep:triangle}{git:block}{@sep:triangle}{status:block}{@nl}{char}";
    assert_eq!(text(&one(t, &f, 80)[0].left), " ~/Works \u{E0B0} 1 ");
    let t = "{dir:block}{@tail:triangle} {@head:round}{git:block}{@sep:triangle}{status:block}{@nl}{char}";
    let s = text(&one(t, &f, 80)[0].left);
    assert_eq!(s, " ~/Works \u{E0B0} \u{E0B6} 1 ", "{s:?}");
    let mut f = fixture(&["Works"], "main");
    f.values[idx("time")] = None;
    let t = "{dir}{@fill}{@head:triangle}{status:block}{@sep:triangle}{time:block}{@tail:round}{@nl}{char}";
    let s = text(&one(t, &f, 80)[0].left);
    assert!(s.ends_with(" 1 \u{E0B4}"), "{s:?}");
    assert_eq!(s.matches('\u{E0B2}').count(), 1, "{s:?}");
    // Nothing visible on the right: the head goes too.
    f.values[idx("status")] = None;
    let s = text(&one(t, &f, 80)[0].left);
    assert!(!s.contains('\u{E0B2}') && !s.contains('\u{E0B4}'), "{s:?}");
    // A separator with nothing before it goes.
    f.values[idx("git")] = None;
    let s = text(&one("{git:block}{@sep:triangle}{dir:block}{@nl}{char}", &f, 80)[0].left);
    assert_eq!(s, " ~/Works ", "{s:?}");
}

// 이것을 실패시키는 것: 왼쪽 구분자의 글자색·배경을 앞뒤 블록과 바꿔 칠하는 것.
#[test]
fn left_separator_takes_the_blocks_around_it() {
    let f = fixture(&["Works"], "main");
    let out = lay(&two_lines("triangle"), &f, &opts(80));
    let sep = out[0].left.iter().find(|r| r.text == "\u{E0B0}").unwrap();
    assert_eq!(sep.style.fg, Color::Block(tok("path")));
    assert_eq!(sep.style.bg, Color::Block(tok("git.branch")));
}

// 이것을 실패시키는 것: 조건 묶음의 보임 판정(안의 필드가 비면 숨김)이 틀리는 것.
#[test]
fn group_hides_with_its_references() {
    let mut f = fixture(&["Works"], "main");
    let t = "{dir}{@group} +{git.ahead}{@end}{@nl}{char}";
    assert_eq!(text(&one(t, &f, 80)[0].left), "~/Works +2");
    f.values[idx("git")] = value(
        "git",
        "main",
        &[(
            "ahead",
            FieldValue::Count {
                n: 0,
                saturated: false,
            },
        )],
    );
    assert_eq!(text(&one(t, &f, 80)[0].left), "~/Works");
    f.values[idx("git")] = None;
    assert_eq!(text(&one(t, &f, 80)[0].left), "~/Works");
}

// 이것을 실패시키는 것: 1단계에서 오른쪽 값을 왼쪽 경로보다 먼저 줄이는 것.
#[test]
fn step1_shortens_left_before_right() {
    let mut f = fixture(
        &["Works", "AiScream", "themes"],
        "feature/very-long-branch-name",
    );
    f.setup[idx("dir")].methods = &[Method::Repo];
    let t = "{dir}{@fill}{git}{@nl}{char}";
    // 23 + 29 = 52 cells; "themes" saves 17, the branch cut to 24 saves 5.
    let s = text(&one(t, &f, 48)[0].left);
    assert!(
        s.starts_with("themes ") && s.ends_with("feature/very-long-branch-name"),
        "{s:?}"
    );
}

// 이것을 실패시키는 것: 2단계가 우선순위 높은 것부터 숨기거나, 동점에서 왼쪽 것을 먼저 숨기는 것.
#[test]
fn step2_hides_low_priority_then_rightmost() {
    let mut f = fixture(&["Works"], "main");
    f.values[idx("status")] = value("status", "E", &[]);
    let t = "{dir}{@fill}{status} {time}{@nl}{char}";
    // "~/Works" 7 + "E 12:34" 7: target 13 drops one right segment.
    let shown = |f: &Fixture| {
        let s = text(&one(t, f, 14)[0].left);
        (s.contains('E'), s.contains("12:34"))
    };
    assert_eq!(shown(&f), (true, false));
    f.setup[idx("time")].priority = 50;
    assert_eq!(shown(&f), (false, true));
    f.setup[idx("time")].priority = 10;
    assert_eq!(shown(&f), (true, false));
}

// 이것을 실패시키는 것: 실패한 `char`의 색이나 기호 중 하나만 바뀌는 것, vi 명령 모드 기호를 쓰지 않는 것.
#[test]
fn char_failure_changes_glyph_and_color() {
    let mut f = fixture(&["Works"], "main");
    f.values[idx("char")] = value("char", "", &[("failed", FieldValue::Bool(true))]);
    let out = one("{dir}{@nl}{char}", &f, 80);
    assert_eq!(out[1].left[0].text, "\u{2717}");
    assert_eq!(out[1].left[0].style.fg, Color::Text(tok("prompt.err")));
    f.values[idx("char")] = value("char", "", &[("vicmd", FieldValue::Bool(true))]);
    let out = one("{dir}{@nl}{char}", &f, 80);
    assert_eq!(out[1].left[0].text, "\u{276E}");
    assert_eq!(out[1].left[0].style.fg, Color::Text(tok("prompt.ok")));
}

// 이것을 실패시키는 것: `when = always`의 첫 방식을 넘치지 않을 때 적용하지 않는 것.
#[test]
fn always_shortens_even_when_it_fits() {
    let mut f = fixture(&["Works", "AiScream", "themes"], "main");
    f.setup[idx("dir")].when = When::Always;
    assert_eq!(text(&one("{dir}{@nl}{char}", &f, 80)[0].left), "themes");
}

// 이것을 실패시키는 것: 4단계가 경로의 앞을 남기는 것(경로는 끝, 다른 값은 앞을 남긴다),
// `char` 없는 줄의 7단계가 `>`+공백이 아닌 것.
#[test]
fn step4_keeps_the_end_of_a_path() {
    let f = fixture(&["folder"], "main");
    assert_eq!(text(&one("{dir}{@nl}{char}", &f, 5)[0].left), "\u{2026}der");
    assert_eq!(text(&one("abc{dir}", &f, 3)[0].left), "> ");
}

// 이것을 실패시키는 것: 4단계가 이미 줄인 조각을 이어 붙여 다시 자르면서 흐림 표시를 잃는 것.
#[test]
fn step4_keeps_dim_marks_of_whole_pieces() {
    let mut f = fixture(&["Works", "AiScream", "themes"], "main");
    f.setup[idx("dir")].methods = &[Method::Abbrev(1)];
    let out = one("{dir}{@nl}{char}", &f, 10);
    assert_eq!(text(&out[0].left), "\u{2026}A/themes");
    assert_eq!(out[0].left[0].text, "\u{2026}A");
    assert_ne!(out[0].left[0].style.attrs & DIM, 0);
    assert_eq!(out[0].left[1].style.attrs & DIM, 0);
}

// 이것을 실패시키는 것: `layout_into`가 이미 있는 줄·run 버퍼를 다시 쓰지 않고 새로 잡는 것.
#[test]
fn layout_into_reuses_buffers() {
    let f = fixture(&["Works"], "main");
    let lines = [two_lines("triangle")];
    let mut out = Vec::new();
    layout_into(
        &lines,
        &[],
        &[],
        &f.inputs(),
        &opts(80),
        &mut NoopRecorder,
        &mut out,
    );
    let before = (
        out.as_ptr(),
        out[0].left.as_ptr(),
        out[0].left[0].text.as_ptr(),
    );
    layout_into(
        &lines,
        &[],
        &[],
        &f.inputs(),
        &opts(80),
        &mut NoopRecorder,
        &mut out,
    );
    assert_eq!(
        before,
        (
            out.as_ptr(),
            out[0].left.as_ptr(),
            out[0].left[0].text.as_ptr()
        )
    );
}

// 판정 A(2026-10-13). 이것을 실패시키는 것: 뒤에 블록이 없는 구분자를 남기는 것(구분자의 `ok` 판정을 끄면 실패).
#[test]
fn ruling_a_drops_a_separator_with_no_block_after() {
    let mut f = fixture(&["Works"], "main");
    f.values[idx("time")] = None;
    let t = "{dir}{@fill}{@head:triangle}{status:block}{@sep:triangle}{time:block}{@nl}{char}";
    let s = text(&one(t, &f, 80)[0].left);
    assert!(s.ends_with("\u{E0B2} 1 "), "{s:?}");
    assert_eq!(s.matches('\u{E0B2}').count(), 1, "{s:?}");
}

// 판정 B(2026-10-13). 이것을 실패시키는 것: 앞에 블록이 없는 구역의 꼬리를 남기는 것, 머리가 구역을
// 새로 열지 않아 그 앞 블록을 꼬리의 블록으로 세는 것.
#[test]
fn ruling_b_drops_a_tail_with_no_block_before() {
    let mut f = fixture(&["Works"], "main");
    f.values[idx("git")] = None;
    let t = "{@head:triangle}{dir:block}{@tail:triangle} {@head:triangle}{git:block}{@tail:triangle}{@nl}{char}";
    assert_eq!(text(&one(t, &f, 80)[0].left), "\u{E0B2} ~/Works \u{E0B0} ");
    let t = "{dir:block}{@head:round}{git:block}{@tail:triangle}{@nl}{char}";
    assert_eq!(text(&one(t, &f, 80)[0].left), " ~/Works ");
}

// 이것을 실패시키는 것: 역할이 있는 블록 글자를 `block.text` 하나로 그리는 것(해석기가 블록마다 고른
// 글자색 `OnBlock`을 쓰지 않음, 2026-10-13). 줄이 그리는 segment의 role token은 Lay::new가 글자를 재는
// 반복에서만 정한다(그리지 않는 내장 segment마다 조회하지 않음). 이것을 실패시키는 것: 그 대입 삭제
// (`slot.role = role_tok(decl.role)`, role이 None으로 남아 기본색이 됨).
#[test]
fn role_block_text_is_picked_per_block() {
    let f = fixture(&["Works"], "main");
    let out = one("{dir:block}{@nl}{char}", &f, 80);
    let r = out[0]
        .left
        .iter()
        .find(|r| r.text.contains("Works"))
        .unwrap();
    assert_eq!(
        r.style,
        Style {
            fg: Color::OnBlock(tok("path")),
            bg: Color::Block(tok("path")),
            attrs: 0
        }
    );
}

// 판정(2026-10-13, 대비 구현 중). 이것을 실패시키는 것: 단계 6이 배경을 빼고도 블록 글자색
// `OnBlock`을 남기는 것(단계 6에서 `push_segment`에 블록으로 넘기는 것). light `fg` 블록(time)의
// 글자는 밝은 색으로 골라져 있어, 남으면 밝은 터미널 바탕 위에서 보이지 않는다. 단계 6에서는 역할의
// 일반 글자색이어야 한다. 폭 3은 블록(" … ")이 들어가지 않아 단계 6까지 간다.
#[test]
fn plain_step_uses_the_role_text_color() {
    use crate::color::math::contrast_milli;
    use crate::color::palette::{Knobs, Mode, PaletteInput, resolve_palette};
    let mut f = fixture(&["Works"], "main");
    f.setup[idx("time")].required = true;
    let t = "{time:block}{@nl}{char}";
    let first = |w| one(t, &f, w)[0].left[0].style;
    assert_eq!(first(80).fg, Color::OnBlock(tok("fg")));
    let plain = first(3);
    assert_eq!(plain.bg, Color::Default);
    assert_eq!(plain.fg, Color::Text(tok("fg")));
    let p = resolve_palette(&PaletteInput {
        mode: Mode::Light,
        knobs: Knobs::default(),
        overrides: &[],
        roles: &[],
    })
    .unwrap();
    let fg = p.get("fg").unwrap();
    assert!(contrast_milli(fg.fg, p.background) >= 4_500);
    assert_eq!(fg.on_block, p.background, "the color step 6 must not keep");
}

// 판정 C(2026-10-13). 이것을 실패시키는 것: 단계 6에서 사용자 `{@style:bg=…}` 배경을 남기거나,
// 글자색·속성까지 지우는 것.
#[test]
fn ruling_c_plain_step_drops_user_backgrounds() {
    let f = fixture(&["Works"], "main");
    let t = "{@style:bg=path,fg=git.branch,bold}abcdefgh{@end}{dir:block}{@nl}{char}";
    let run = |w| {
        one(t, &f, w)[0]
            .left
            .iter()
            .find(|r| r.text.starts_with("abc"))
            .unwrap()
            .style
    };
    let wide = run(80);
    assert_eq!(wide.bg, Color::Block(tok("path")));
    // "abcdefgh" + " … " is 11 cells; target 10 needs step 6.
    let plain = run(11);
    assert_eq!(
        plain,
        Style {
            fg: Color::Text(tok("git.branch")),
            bg: Color::Default,
            attrs: crate::color::sgr::BOLD
        }
    );
}

// 판정 D(2026-10-13). 이것을 실패시키는 것: token이 아닌 역할을 색 0번으로 그리는 것.
#[test]
fn ruling_d_unknown_role_is_the_default_color() {
    const CAT: &[SegmentDecl] = &[SegmentDecl {
        id: "x",
        role: "no.such.role",
        fields: &[],
    }];
    let lines = compile("{x:block} {x}", CAT).unwrap();
    let values = vec![Some(Value::new(b"v", Vec::new()))];
    let inp = Inputs {
        catalog: CAT,
        values: &values,
        facts: &[],
        setup: &[],
    };
    let out = layout(
        core::slice::from_ref(&lines),
        &[],
        &[],
        &inp,
        &opts(80),
        &mut NoopRecorder,
    );
    let styles: Vec<Style> = out[0].left.iter().map(|r| r.style).collect();
    assert_eq!(
        styles[0],
        Style {
            fg: Color::Text(tok("block.text")),
            bg: Color::Default,
            attrs: 0
        }
    );
    assert_eq!(styles.last().unwrap().fg, Color::Default);
}

// 판정 E(2026-10-13). 이것을 실패시키는 것: 단계 3이 `required`인 오른쪽 세그먼트를 남기는 것.
#[test]
fn ruling_e_step3_hides_required_right_segments() {
    let mut f = fixture(&["Works"], "main");
    f.setup[idx("time")].required = true;
    // "~/Works" 7 + "12:34" 5 = 12 cells, target 11.
    assert_eq!(
        text(&one("{dir}{@fill}{time}{@nl}{char}", &f, 12)[0].left),
        "~/Works"
    );
}

// 리뷰 #2. 이것을 실패시키는 것: 필드만 참조하는 세그먼트를 단계 대상에서 빼는 것, 같은 세그먼트를 첫 출현 쪽으로만
// 분류해 단계 3이 오른쪽 출현을 남기는 것.
#[test]
fn steps_see_fields_and_both_sides() {
    let f = fixture(&["Works"], "main");
    let out = one("abcdefg{@fill}{git.ahead}{@nl}{char}", &f, 8);
    assert_eq!(
        (text(&out[0].left).as_str(), out[0].minimal),
        ("abcdefg", false)
    );
    let out = one("{time}{@fill}{time}{@nl}{char}", &f, 10);
    assert_eq!(
        (text(&out[0].left).as_str(), out[0].minimal),
        ("12:34", false)
    );
}

// 리뷰 #3. 이것을 실패시키는 것: 앞 grapheme을 보지 않고 결합 가능 접미사마다 칸을 더하는 것(`a`+U+FE0F는 1칸으로
// 남으므로, 윗줄이 목표 폭보다 짧게 끝난다), 또는 결합으로 넓어지는 칸을 세지 않는 것(`#`+U+FE0F).
#[test]
fn joins_count_exactly() {
    let mut f = fixture(&["Works"], "main");
    f.setup[idx("git")].methods = &[];
    for (t, v, emoji) in [
        ("a{git}{@fill}{time}{@nl}{char}", "\u{FE0F}b", 2),
        ("#{git}{@fill}{time}{@nl}{char}", "\u{FE0F}b", 2),
        ("\u{231A}{git}{@fill}{time}{@nl}{char}", "\u{FE0E}b", 1),
        // A prepended mark takes the block's trailing pad into its
        // grapheme; a spacing mark joins the fill space before it.
        ("{git:block}{@fill}{time}{@nl}{char}", "\u{0D4E}", 2),
        ("{dir}{@fill}{git}{@nl}{char}", "\u{0903}b", 2),
        // A spacing mark joins the block's leading pad; a prepended
        // letter takes in the first fill glyph.
        ("{git:block}{@fill}{time}{@nl}{char}", "\u{0903}b", 2),
        ("{git}{@fill}{time}{@nl}{char}", "a\u{0D4E}", 2),
        // Joins that reach past the first grapheme: a ZWJ sequence takes
        // in the emoji after it, a virama joins the next consonant.
        (
            "~ \u{231A}{git}{@fill}{time}{@nl}{char}",
            "\u{FE0E}\u{200D}\u{1F600}",
            1,
        ),
        (
            "\u{0915}\u{094D}{git}{@fill}{time}{@nl}{char}",
            "\u{0937}x",
            2,
        ),
        (
            "\u{1F468}\u{200D}{git}{@fill}{time}{@nl}{char}",
            "\u{1F469}x",
            2,
        ),
        // A join inside the right side.
        ("{dir}{@fill}#{git}{@nl}{char}", "\u{FE0F}b", 2),
    ] {
        f.values[idx("git")] = value("git", v, &[]);
        let o = Options {
            profile: WidthProfile::new(1, emoji).unwrap(),
            ..opts(80)
        };
        assert_eq!(
            runs_width(
                &lay(&compile(t, BUILTIN).unwrap(), &f, &o)[0].left,
                o.profile
            ),
            79,
            "{t}"
        );
    }
    // With no room for a fill, the two sides touch: `#` and U+FE0F join.
    f.values[idx("git")] = value("git", "\u{FE0F}b", &[]);
    let lines = compile("#{@fill}{git}{@nl}{char}", BUILTIN).unwrap();
    for w in 0..=10 {
        assert_fits(&lay(&lines, &f, &opts(w)), &opts(w), "touch");
    }
}

// 리뷰 #4. 이것을 실패시키는 것: 빈 필드를 내용으로 세어 줄 맨 앞 구분자를 남기거나, 자동색의 이전 블록을 놓치는 것.
#[test]
fn empty_fields_are_not_content() {
    let mut f = fixture(&["Works"], "main");
    // An icon with no glyph in the set and a plain segment with no text
    // draw nothing either.
    let o = Options {
        icons: IconSet::Unicode,
        ..opts(80)
    };
    let lines = compile(
        "{@icon:git.branch}{@sep:triangle}{dir:block}{@nl}{char}",
        BUILTIN,
    )
    .unwrap();
    assert_eq!(text(&lay(&lines, &f, &o)[0].left), " ~/Works ");
    f.values[idx("venv")] = value("venv", "", &[]);
    let out = one("{venv}{@sep:triangle}{dir:block}{@nl}{char}", &f, 80);
    assert_eq!(text(&out[0].left), " ~/Works ");
    let out = one(
        "{status.signal}{@sep:triangle}{dir:block}{@nl}{char}",
        &f,
        80,
    );
    assert_eq!(text(&out[0].left), " ~/Works ");
    let out = one(
        "{dir:block}{status.signal}{@sep:triangle}{status:block}{@nl}{char}",
        &f,
        80,
    );
    let sep = out[0].left.iter().find(|r| r.text == "\u{E0B0}").unwrap();
    assert_eq!(
        (sep.style.fg, sep.style.bg),
        (Color::Block(tok("path")), Color::Block(tok("status")))
    );
}

// 이것을 실패시키는 것: `SEG_PIECES_MAX`보다 조각이 많은 줄이기 결과를 받는 것(600단계 경로의 `abbrev`가 미리
// 걸러지지 않거나, 저장소 루트에 따라 조각 수가 정해지는 `repo` 결과가 실행 뒤에 버려지지 않는 것).
#[test]
fn results_over_the_piece_cap_are_skipped() {
    let names: Vec<String> = (0..600).map(|n| alloc::format!("folder-{n:03}")).collect();
    let raw: Vec<&[u8]> = names.iter().map(|s| s.as_bytes()).collect();
    let mut f = fixture(&["Works"], "main");
    f.facts[idx("dir")] = Some(PathFacts::new(Anchor::Home, &raw, None, &[]));
    f.setup[idx("dir")].methods = &[Method::Abbrev(1)];
    let s = text(&one("{dir}{@nl}{char}", &f, 40)[0].left);
    assert!(s.ends_with("/folder-599") && !s.contains("f/f/"), "{s:?}");
    // `repo`'s piece count depends on the repository root, so it runs and
    // its result (1,199 pieces) is dropped afterwards. At 6,600 columns
    // that result (6,599 cells) would fit where the whole path (6,601)
    // does not; dropped, the path is cut instead.
    f.facts[idx("dir")] = Some(PathFacts::new(Anchor::Home, &raw, Some(0), &[]));
    f.setup[idx("dir")].methods = &[Method::Repo];
    let s = text(&one("{dir}{@nl}{char}", &f, 6600)[0].left);
    assert!(
        s.starts_with('\u{2026}') && s.ends_with("/folder-599"),
        "{}",
        &s[..20]
    );
}

// 이것을 실패시키는 것: 폭은 맞아도 `LINE_BYTES_MAX`를 넘는 줄을 맞는 것으로 보는 것.
#[test]
fn a_line_over_the_byte_cap_does_not_fit() {
    let mut f = fixture(&["Works"], "main");
    let heavy = alloc::format!("e{}", "\u{0301}".repeat(4000));
    f.values[idx("git")] = value("git", &heavy, &[]);
    f.setup[idx("git")].methods = &[];
    let out = one("{git}{git}{git}{dir}{@nl}{char}", &f, 80);
    let bytes: usize = out[0].left.iter().map(|r| r.text.len()).sum();
    assert!(
        bytes <= LINE_BYTES_MAX && text(&out[0].left).starts_with('~'),
        "{bytes} {:?}",
        text(&out[0].left)
    );
}

// 이것을 실패시키는 것: 방식 사슬을 `METHODS_MAX`(8) 너머까지 돌리는 것(아홉째 `depth 1`이 `…/themes`를 만든다).
#[test]
fn only_the_first_methods_run() {
    const NINE: &[Method] = &[
        Method::None,
        Method::None,
        Method::None,
        Method::None,
        Method::None,
        Method::None,
        Method::None,
        Method::None,
        Method::Depth(1),
    ];
    let mut f = fixture(&["Works", "AiScream", "themes"], "main");
    f.setup[idx("dir")].methods = NINE;
    let s = text(&one("{dir}{@nl}{char}", &f, 15)[0].left);
    assert!(
        s.ends_with("Scream/themes") && s.starts_with('\u{2026}'),
        "{s:?}"
    );
    f.setup[idx("dir")].methods = &NINE[1..];
    assert_eq!(
        text(&one("{dir}{@nl}{char}", &f, 15)[0].left),
        "\u{2026}/themes"
    );
}

// 이것을 실패시키는 것: `PATH_BYTES_MAX`를 넘는 경로를 읽어 그리거나 줄이는 것(흐린 생략 기호 하나로 그린다).
#[test]
fn a_path_too_long_to_read_is_an_ellipsis() {
    let name = alloc::format!("e{}", "\u{0301}".repeat(300));
    let raw: Vec<&[u8]> = (0..120).map(|_| name.as_bytes()).collect();
    let mut f = fixture(&["Works"], "main");
    f.facts[idx("dir")] = Some(PathFacts::new(Anchor::Home, &raw, None, &[]));
    assert!(f.facts[idx("dir")].as_ref().unwrap().display_len() > PATH_BYTES_MAX);
    let out = one("{dir}{@nl}{char}", &f, 80);
    assert_eq!(text(&out[0].left), "\u{2026}");
    assert_ne!(out[0].left[0].style.attrs & DIM, 0);
}

// 이것을 실패시키는 것: 채움 글리프 바이트를 `LINE_BYTES_MAX`에 넣지 않거나 글리프당 1바이트로 세는 것(폭 6000의 `─`는
// 약 18 KB, 1바이트로 세면 약 6 KB), 채움이
// 없는 입력 줄에서도 채움 바이트를 세는 것.
#[test]
fn fill_bytes_count_toward_the_byte_cap() {
    let f = fixture(&["Works"], "main");
    let out = one("{dir}{@fill:line}{time}{@nl}{char}", &f, u16::MAX);
    let bytes: usize = out[0].left.iter().map(|r| r.text.len()).sum();
    assert!(bytes <= LINE_BYTES_MAX, "{bytes}");
    let out = one("{dir}{@fill:line}{time}{@nl}{char}", &f, 5000);
    assert!(text(&out[0].left).ends_with("12:34"));
    // At 6000 columns about 5,980 fill cells are 3 bytes each (about
    // 18 KiB, over the cap) but would be under it at 1 byte each: the
    // right side goes and the line stays within the cap.
    let out = one("{dir}{@fill:line}{time}{@nl}{char}", &f, 6000);
    let bytes: usize = out[0].left.iter().map(|r| r.text.len()).sum();
    assert!(
        bytes <= LINE_BYTES_MAX && !text(&out[0].left).contains("12:34"),
        "{bytes}"
    );
    // An input line draws no fill: its right side is the right prompt.
    let out = one("{dir}{@fill:line}{time}", &f, u16::MAX);
    assert_eq!(text(&out[0].right), "12:34");
}

fn logged(t: &str, f: &Fixture, w: u16) -> (Vec<LaidLine>, DecisionLog) {
    let mut log = DecisionLog::default();
    let out = layout(
        &[compile(t, BUILTIN).unwrap()],
        &[],
        &[],
        &f.inputs(),
        &opts(w),
        &mut log,
    );
    (out, log)
}

// 이것을 실패시키는 것: 맞는 방식의 번호를 0으로 기록하는 것, 기록하는 단계·줄인 방식·숨긴 이유가 실제 단계와 어긋나는 것(경로를 오른쪽보다 먼저 줄이고,
// 그다음 우선순위 낮은 `time`을 숨긴다), `DecisionLog::step`이 기록하지 않는 것.
#[test]
fn steps_in_order() {
    let f = fixture(&["Works", "AiScream", "themes", "src", "render"], "main");
    let t = "{dir} {git}{@fill}{status} {time}{@nl}{char}";
    let (out, log) = logged(t, &f, 40);
    assert!(
        text(&out[0].left).starts_with("themes/src/render"),
        "{out:?}"
    );
    assert_eq!(log.steps, vec![(0, Step::ShortenNames)]);
    assert_eq!(log.shortened, vec![(0, idx("dir"), 0)]);
    // The first method does not fit, the second does: index 1.
    let mut g = fixture(&["Works", "AiScream", "themes", "src", "render"], "main");
    g.setup[idx("dir")].methods = &[
        Method::Truncate {
            max: 60,
            keep: Keep::End,
        },
        Method::Repo,
    ];
    assert_eq!(logged(t, &g, 40).1.shortened, vec![(0, idx("dir"), 1)]);
    let (_, log) = logged(t, &f, 16);
    assert_eq!(
        log.steps[..2],
        [(0, Step::ShortenNames), (0, Step::HideRightByPriority)]
    );
    assert_eq!(
        log.hidden.first(),
        Some(&(0, idx("time"), HideReason::Priority))
    );
    assert_eq!(log.band, None);
}

// 이것을 실패시키는 것: 3단계가 맞은 뒤에도 4단계 이후(왼쪽 선택 항목 숨기기 등)로 넘어가는 것.
#[test]
fn the_steps_stop_at_the_first_one_that_fits() {
    let mut f = fixture(&["Works"], "main");
    f.values[idx("status")] = value("status", "EEEEEEEEEE", &[]);
    f.setup[idx("status")].required = true;
    let t = "{dir} {git}{@fill}{status}{@nl}{char}";
    let (out, log) = logged(t, &f, 20);
    assert!(!out[0].minimal);
    let steps: Vec<Step> = log.steps.iter().map(|s| s.1).collect();
    assert_eq!(steps.last(), Some(&Step::HideRight), "{steps:?}");
    assert!(
        text(&out[0].left).contains("main"),
        "step 5 must not run: {out:?}"
    );
}

// 이것을 실패시키는 것: 단계와 숨김(값 없음, 2·3·5·7단계)이 기록되지 않거나, 다른 이유로·두 번·줄에 없는 세그먼트까지
// 기록되는 것, 맞는 방식이 없을 때 고른 방식 번호가 틀리는 것, 7단계가 `char`를 숨긴 것으로 기록하는 것.
#[test]
fn every_step_and_reason_is_recorded() {
    let mut f = fixture(&["Works"], "main");
    f.values[idx("venv")] = None;
    // Present but not in the line: never recorded.
    f.values[idx("host")] = value("host", "me@host", &[]);
    f.setup[idx("time")].required = true;
    // Literal text cannot be cut, so the line ends at step 7.
    let t = "{venv}abcd{dir} {git}{@fill}{status} {time}{@nl}{char}";
    let (out, log) = logged(t, &f, 4);
    assert!(out[0].minimal);
    let steps: Vec<Step> = log.steps.iter().map(|s| s.1).collect();
    use HideReason::{LeftOptional, NoValue, Priority, RightHidden};
    use Step::*;
    assert_eq!(
        steps,
        [
            ShortenNames,
            HideRightByPriority,
            HideRight,
            TruncateLeft,
            HideLeftOptional,
            DropDecoration,
            Minimal
        ]
    );
    // No method fits 3 cells: the narrowest, `abbrev 1` (index 1; `repo`
    // does not apply), is recorded; then the branch's `truncate`.
    assert_eq!(log.shortened, vec![(0, idx("dir"), 1), (0, idx("git"), 0)]);
    let line0: Vec<(usize, HideReason)> = log
        .hidden
        .iter()
        .filter(|h| h.0 == 0)
        .map(|h| (h.1, h.2))
        .collect();
    // Once each, in order: no value, step 2, step 3, step 5, step 7.
    assert_eq!(
        line0,
        [
            (idx("venv"), NoValue),
            (idx("status"), Priority),
            (idx("time"), RightHidden),
            (idx("git"), LeftOptional),
            (idx("dir"), HideReason::Minimal)
        ]
    );
    // The input line keeps `char` and records nothing.
    assert!(!log.hidden.iter().any(|h| h.0 == 1));
    // An input line at step 7 keeps `char`: only `dir` is recorded.
    let (out, log) = logged("abcd{dir}{char}", &f, 3);
    assert!(out[0].minimal);
    assert_eq!(log.hidden, [(0, idx("dir"), HideReason::Minimal)]);
}

// 이것을 실패시키는 것: 고른 폭 구간을 기록하지 않는 것.
#[test]
fn the_band_is_recorded() {
    let f = fixture(&["Works"], "main");
    let lines = compile("{dir}{@nl}{char}", BUILTIN).unwrap();
    let band = Band {
        min_cols: None,
        max_cols: Some(60),
        order: None,
    };
    let mut log = DecisionLog::default();
    layout(
        &[lines.clone(), lines],
        &[band],
        &[0],
        &f.inputs(),
        &opts(40),
        &mut log,
    );
    assert_eq!(log.band, Some(0));
}

// 이것을 실패시키는 것: 기록기를 켜면 결과가 바뀌는 것(결정 기록은 관찰만 한다).
#[test]
fn recorder_does_not_change_output() {
    let f = fixture(
        &["Works", "AiScream", "themes", "src", "render"],
        "feature/very-long-branch-name",
    );
    for name in ["lean", "triangle"] {
        let lines = two_lines(name);
        for w in 0..=120u16 {
            let a = layout(
                core::slice::from_ref(&lines),
                &[],
                &[],
                &f.inputs(),
                &opts(w),
                &mut NoopRecorder,
            );
            let b = layout(
                core::slice::from_ref(&lines),
                &[],
                &[],
                &f.inputs(),
                &opts(w),
                &mut DecisionLog::default(),
            );
            assert_eq!(a, b, "{name} {w}");
        }
    }
}

// 리뷰 #1. 이것을 실패시키는 것: 비어서 사라진 조건 묶음을 기록하지 않는 것, 한 묶음의 같은 세그먼트를 두 번
// 기록하는 것, 값이 없어서(NoValue) 또는 오른쪽에서 숨어서(Priority) 사라진 묶음까지 EmptyGroup으로 기록하는 것.
#[test]
fn empty_groups_are_recorded() {
    let mut f = fixture(&["Works"], "main");
    let t = "{dir}{@group} +{git.ahead}/{git.behind}{@end}{@nl}{char}";
    f.values[idx("git")] = value(
        "git",
        "main",
        &[(
            "ahead",
            FieldValue::Count {
                n: 0,
                saturated: false,
            },
        )],
    );
    let (out, log) = logged(t, &f, 80);
    assert_eq!(text(&out[0].left), "~/Works");
    assert_eq!(log.hidden, [(0, idx("git"), HideReason::EmptyGroup)]);
    f.values[idx("git")] = value(
        "git",
        "main",
        &[(
            "ahead",
            FieldValue::Count {
                n: 2,
                saturated: false,
            },
        )],
    );
    assert!(logged(t, &f, 80).1.hidden.is_empty());
    f.values[idx("git")] = None;
    assert_eq!(
        logged(t, &f, 80).1.hidden,
        [(0, idx("git"), HideReason::NoValue)]
    );
    // On the right, step 2 hides git's group: "main" + "+2 12:34" is 12
    // cells, target 11. Still drawn on the left, it is no empty group.
    f.values[idx("git")] = value(
        "git",
        "main",
        &[(
            "ahead",
            FieldValue::Count {
                n: 2,
                saturated: false,
            },
        )],
    );
    f.setup[idx("git")].priority = 0;
    let (out, log) = logged(
        "{git}{@fill}{@group}+{git.ahead}{@end} {time}{@nl}{char}",
        &f,
        12,
    );
    assert!(text(&out[0].left).ends_with(" 12:34"), "{out:?}");
    assert_eq!(log.hidden, [(0, idx("git"), HideReason::Priority)]);
}

// 리뷰 #2. 이것을 실패시키는 것: fill 양쪽에 있는 세그먼트를 단계 1이 쪽마다 줄여 같은 기록을 두 번 남기는 것.
#[test]
fn a_segment_on_both_sides_is_shortened_once() {
    let f = fixture(&["Works", "AiScream", "themes"], "main");
    let (out, log) = logged("{dir}{@fill}{dir}{@nl}{char}", &f, 30);
    assert_eq!(log.shortened, [(0, idx("dir"), 0)]);
    // Both occurrences draw the one shortened text.
    assert_eq!(text(&out[0].left).matches("themes").count(), 2, "{out:?}");
    // Still too wide after the left entry: the right entry is skipped,
    // not shortened (and recorded) again.
    let (_, log) = logged("{dir}{@fill}{dir}{@nl}{char}", &f, 12);
    assert_eq!(log.shortened, [(0, idx("dir"), 0)]);
    // Referenced only by a field on the left, the segment is shortened
    // from its right entry.
    let (out, log) = logged("{dir.in_repo}x{@fill}{dir}{@nl}{char}", &f, 12);
    assert_eq!(log.shortened, [(0, idx("dir"), 0)]);
    assert!(text(&out[0].left).ends_with("themes"), "{out:?}");
}

// 리뷰 #3. 이것을 실패시키는 것: 폭 0·1의 최소 프롬프트가 단계 7과 숨긴 세그먼트를 기록하지 않는 것.
#[test]
fn tiny_widths_are_recorded() {
    let mut f = fixture(&["Works"], "main");
    f.values[idx("venv")] = None;
    for w in [0, 1] {
        // `dir` twice: recorded once.
        let (out, log) = logged("{venv}{dir} {git} {dir}{@nl}{char}", &f, w);
        assert!(out.iter().all(|l| l.minimal));
        assert_eq!(log.steps, [(0, Step::Minimal), (1, Step::Minimal)], "{w}");
        assert_eq!(
            log.hidden,
            [
                (0, idx("venv"), HideReason::NoValue),
                (0, idx("dir"), HideReason::Minimal),
                (0, idx("git"), HideReason::Minimal)
            ],
            "{w}"
        );
    }
}

// 리뷰 #5. 이것을 실패시키는 것: `layout`이 기록기를 비우지 않고 이어 쌓는 것.
#[test]
fn each_layout_starts_a_new_log() {
    let f = fixture(&["Works", "AiScream", "themes", "src", "render"], "main");
    let lines = [two_lines("triangle")];
    let mut log = DecisionLog::default();
    layout(&lines, &[], &[], &f.inputs(), &opts(30), &mut log);
    let once = log.clone();
    assert!(!once.steps.is_empty());
    layout(&lines, &[], &[], &f.inputs(), &opts(30), &mut log);
    assert_eq!(log, once);
}
