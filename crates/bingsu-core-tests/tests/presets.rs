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
    let present: &[&str] = if with_git {
        &["git", "time"]
    } else {
        &["time"]
    };
    laid(preset, set, width, &LINES, present)
}

/// Like `lines_at` for any layout; only the ids in `present` (plus `dir`
/// and `char`) have a value.
fn laid(
    preset: &str,
    set: IconSet,
    width: u16,
    lines_layout: &[LineLayout<'_>],
    present: &[&str],
) -> Vec<(String, u32, u32)> {
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
    for id in present {
        values[i(id)] = v(id, b"x1");
    }
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
    let t = generate(p, &StyleOptions::default(), lines_layout).unwrap();
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

// 이것을 실패시키는 것: (윗줄 오른쪽 끝이 폭 40 이상에서 마지막 칸에 닿지 않는 것) 프리셋의 머리·꼬리·구분자 글리프가 ASCII 세트에서 ASCII 아닌 글자를 내는 것
// (아이콘 표의 ASCII 칸이 비거나 유니코드인 것), 폭 0–200 어디서든 윗줄이 목표 칸을 넘는 것.
#[test]
fn every_preset_fits_and_has_an_ascii_form() {
    for p in PRESETS {
        for w in 0..=200u16 {
            for (n, (s, used, max)) in lines_at(p.name, IconSet::Ascii, w, true)
                .into_iter()
                .enumerate()
            {
                // `…` comes from shortening a name, not from the preset.
                assert!(
                    s.replace('\u{2026}', "").is_ascii(),
                    "{} w={w}: {s:?}",
                    p.name
                );
                assert!(used <= max, "{} w={w}: {s:?}", p.name);
                // Room for everything: the right edge is on the last cell.
                if n == 0 && w >= 40 {
                    assert_eq!(used, max, "{} w={w}: {s:?}", p.name);
                    // An empty `jobs` after `time` leaves no gap at the right edge.
                    let with_jobs = two(&["dir", "git"], &["time", "jobs"]);
                    let j = laid(p.name, IconSet::Ascii, w, &with_jobs, &["git", "time"]);
                    assert_eq!(j[0].0, s, "{} w={w}", p.name);
                }
            }
        }
    }
}

// 이것을 실패시키는 것: 값 없는 세그먼트의 `[`·`]`가 남는 것(`{@group}` 없이 글을 잇는 것).
#[test]
fn bracket_drops_with_a_segment_that_has_no_value() {
    let with = lines_at("bracket", IconSet::Ascii, 80, true);
    assert!(
        with[0].0.starts_with("[~/Works/themes] [x1]"),
        "{:?}",
        with[0].0
    );
    assert_eq!(with[0].0.matches("[x1]").count(), 2, "{:?}", with[0].0);
    let without = lines_at("bracket", IconSet::Ascii, 80, false);
    assert!(
        !without[0].0.contains("[]") && without[0].0.matches("[x1]").count() == 1,
        "{:?}",
        without[0].0
    );
    assert!(without[0].0.starts_with('['), "{:?}", without[0].0);
    // The input marker is never bracketed.
    assert!(!with[1].0.contains('['), "{:?}", with[1].0);
}

fn two(left: &'static [&'static str], right: &'static [&'static str]) -> [LineLayout<'static>; 2] {
    [
        LineLayout { left, right },
        LineLayout {
            left: &["char"],
            right: &[],
        },
    ]
}

// 이것을 실패시키는 것: 값 없는 세그먼트가 간격 공백을 남기는 것(Spaced 생성기가 조건 없는 공백을 쓸 때:
// 오른쪽 끝이 마지막 칸에 닿지 않고, 가운데가 비면 공백이 두 겹이 됨). 값 없는 세그먼트는 레이아웃에서
// 뺀 것과 같은 글자·폭을 내야 하고, 오른쪽이 있는 윗줄은 어떤 폭에서도 목표 칸에서 끝난다.
#[test]
fn an_empty_segment_leaves_no_gap_and_the_right_edge_stays_aligned() {
    // (with an empty one, the same without it, the ids with a value)
    let cases: [([LineLayout<'static>; 2], [LineLayout<'static>; 2], &[&str]); 4] = [
        // last on the right empty
        (
            two(&["dir"], &["duration", "time"]),
            two(&["dir"], &["duration"]),
            &["duration"],
        ),
        // middle on the right empty
        (
            two(&["dir"], &["duration", "jobs", "time"]),
            two(&["dir"], &["duration", "time"]),
            &["duration", "time"],
        ),
        // first on the right empty
        (
            two(&["dir"], &["status", "duration"]),
            two(&["dir"], &["duration"]),
            &["duration"],
        ),
        // on the left: first and last empty
        (
            two(&["host", "dir", "git"], &["time"]),
            two(&["dir"], &["time"]),
            &["time"],
        ),
    ];
    for p in PRESETS {
        for set in [IconSet::Ascii, IconSet::Nerd] {
            for (n, (with_empty, without, present)) in cases.iter().enumerate() {
                for w in 0..=200u16 {
                    let a = laid(p.name, set, w, with_empty, present);
                    // An empty segment in the middle or at the end of the right
                    // side draws exactly what leaving it out draws: no stray gap
                    // and no doubled one. At the start of a run, or on the
                    // left, the gap beside the fill may stay (one cell).
                    if n < 2 {
                        let b = laid(p.name, set, w, without, present);
                        assert_eq!(a[0].0, b[0].0, "{} case {n} w={w}", p.name);
                    }
                    // Room for everything: the right edge is on the last cell.
                    let (text, used, max) = &a[0];
                    if w >= 40 {
                        assert_eq!(used, max, "{} case {n} w={w} {text:?}", p.name);
                    }
                }
            }
        }
    }
}
