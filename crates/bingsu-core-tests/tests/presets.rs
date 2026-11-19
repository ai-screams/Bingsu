//! The eight built-in presets: the ASCII icon set draws only ASCII, every
//! preset ends a full upper line on the target cell (all widths 0–200), and
//! the `bracket` preset drops a segment's brackets with the segment. The
//! block-shape options (body, ends, joint, gap) keep the same promises in
//! every combination.
use bingsu_core::color::palette::token_index;
use bingsu_core::color::sgr::{Color, Style};
use bingsu_core::field::{BUILTIN, Field, Value, segment};
use bingsu_core::icons::{self, IconSet};
use bingsu_core::layout::{
    Inputs, LaidLine, Options, SegmentSetup, When, layout, runs_width, target,
};
use bingsu_core::recorder::{DecisionLog, NoopRecorder, Recorder, Step};
use bingsu_core::shorten::{Anchor, Method, PathFacts};
use bingsu_core::style::{Body, Cap, Joining, LineLayout, PRESETS, StyleOptions, generate};
use bingsu_core::template::compile::{CompiledLine, FillKind, Shape, compile};
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
    laid_with(
        preset,
        &StyleOptions::default(),
        set,
        width,
        lines_layout,
        present,
    )
}

/// `laid` with `options` over the preset.
fn laid_with(
    preset: &str,
    options: &StyleOptions,
    set: IconSet,
    width: u16,
    lines_layout: &[LineLayout<'_>],
    present: &[&str],
) -> Vec<(String, u32, u32)> {
    let p = PRESETS.iter().find(|p| p.name == preset).unwrap();
    let t = generate(p, options, lines_layout).unwrap();
    let lines = compile(&t, BUILTIN).unwrap();
    let profile = WidthProfile::new(1, 2).unwrap();
    let o = options_at(set, width);
    draw(std::slice::from_ref(&lines), &o, present, &mut NoopRecorder)
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

fn options_at(set: IconSet, width: u16) -> Options {
    Options {
        width,
        profile: WidthProfile::new(1, 2).unwrap(),
        icons: set,
        use_last_column: false,
    }
}

/// Lays out `variant` (one layout, no bands); only the ids in `present`
/// (plus `dir` and `char`) have a value.
fn draw<R: Recorder>(
    variant: &[Vec<CompiledLine>],
    o: &Options,
    present: &[&str],
    r: &mut R,
) -> Vec<LaidLine> {
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
    layout(variant, &[], &[], &inputs, o, r)
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

// The brackets of `bracket` touch, and go with a segment that has no value.
// 이것을 실패시키는 것: 값 없는 세그먼트의 `[`·`]`가 남는 것(`{@group}` 없이 글을 잇는 것), 괄호 사이에
// `{@sep:flat}`을 남기는 것(빈칸이 생김).
#[test]
fn bracket_drops_with_a_segment_that_has_no_value() {
    let with = lines_at("bracket", IconSet::Ascii, 80, true);
    assert!(
        with[0].0.starts_with("[~/Works/themes][x1]"),
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

// 이것을 실패시키는 것: 값 없는 세그먼트가 간격 공백을 남기는 것(빈칸 생성기가 조건 없는 공백을 쓸 때:
// 오른쪽 끝이 마지막 칸에 닿지 않고, 가운데가 비면 공백이 두 겹이 됨), 빈칸 없는 프리셋에 빈칸을 더하는 것
// (첫 세그먼트가 빈 오른쪽 줄과 마지막 세그먼트가 빈 왼쪽 줄에서 채움 옆에 한 칸이 남음). 값 없는 세그먼트는
// 레이아웃에서 뺀 것과 같은 글자·폭을 내야 하고, 오른쪽이 있는 윗줄은 어떤 폭에서도 목표 칸에서 끝난다.
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
                    // An empty segment draws exactly what leaving it out draws,
                    // wherever it is: no stray gap and no doubled one. No preset
                    // has a gap, so not even beside the fill (cases 2 and 3).
                    let b = laid(p.name, set, w, without, present);
                    assert_eq!(a, b, "{} case {n} w={w}", p.name);
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

// Brackets belong to the body: changing one end of `bracket` keeps them on both sides of the
// fill, in the template and on screen.
// 이것을 실패시키는 것: 괄호를 거울로 바꾼 끝(왼쪽 줄은 바깥 끝, 오른쪽 줄은 안쪽 끝)에서 다시 정하는 것
// (`outer_end`만 바꾸면 왼쪽 줄에서, `inner_end`만 바꾸면 오른쪽 줄에서 괄호가 사라짐).
#[test]
fn one_end_of_bracket_keeps_both_sides_bracketed() {
    let layout = two(&["dir", "git"], &["duration", "time"]);
    let present = ["git", "duration", "time"];
    let round = Some(Cap::Shape(Shape::Round));
    let base = laid("bracket", IconSet::Ascii, 80, &layout, &present);
    for (outer_end, inner_end) in [(round, None), (None, round)] {
        let o = StyleOptions {
            outer_end,
            inner_end,
            ..StyleOptions::default()
        };
        let p = PRESETS.iter().find(|p| p.name == "bracket").unwrap();
        let t = generate(p, &o, &layout).unwrap();
        for id in ["dir", "git", "duration", "time"] {
            assert!(t.contains(&format!("[{{{id}}}]")), "{o:?}: {t}");
        }
        let drawn = laid_with("bracket", &o, IconSet::Ascii, 80, &layout, &present);
        let line = drawn[0].0.as_str();
        assert!(line.starts_with("[~/Works/themes][x1]"), "{o:?}: {line:?}");
        assert!(line.ends_with("[x1][x1]"), "{o:?}: {line:?}");
        assert_eq!(drawn, base, "{o:?}");
    }
}

/// Line 1 of the combination test: four segments a side, `dir` (required) second on the
/// left; line 2 the input marker.
const LEFT: [&str; 4] = ["host", "dir", "git", "venv"];
const RIGHT: [&str; 4] = ["status", "duration", "jobs", "time"];
/// The optional segments the test empties in turn: first, middle and last of each side.
/// `venv` (last on the left) and `status` (first on the right) sit next to the fill.
const EMPTIED: [&str; 6] = ["host", "git", "venv", "status", "duration", "time"];
const WIDTHS: [u16; 7] = [0, 20, 40, 60, 80, 120, 200];

/// Every (body, outer end, joint, inner end, gap): 3 × 3 × 6 × 3 × 2. The fill is dots so a
/// stray blank cell beside it shows.
fn combinations() -> Vec<StyleOptions> {
    let ends = [Cap::None, Cap::Shape(Shape::Round), Cap::Shape(Shape::Flat)];
    let joints = [
        (Some(Shape::Triangle), Joining::Attached),
        (Some(Shape::Round), Joining::Attached),
        (Some(Shape::Slant), Joining::Attached),
        (Some(Shape::Flat), Joining::Attached),
        (None, Joining::Adjacent),
        (None, Joining::Capped),
    ];
    let mut out = Vec::new();
    for body in [Body::Block, Body::Plain, Body::Bracket] {
        for outer in ends {
            for (separator, joining) in joints {
                for inner in ends {
                    for gap in [false, true] {
                        out.push(StyleOptions {
                            body: Some(body),
                            separator: separator.or(Some(Shape::Flat)),
                            outer_end: Some(outer),
                            inner_end: Some(inner),
                            joining: Some(joining),
                            gap: Some(gap),
                            fill: Some(FillKind::Dot),
                            frame: Some(false),
                        });
                    }
                }
            }
        }
    }
    out
}

/// One drawn cell: a character and its style.
type Cell = (char, Style);

fn cells(l: &LaidLine) -> Vec<Cell> {
    l.left
        .iter()
        .chain(&l.right)
        .flat_map(|r| r.text.chars().map(move |c| (c, r.style)))
        .collect()
}

fn fill_style() -> Style {
    Style {
        fg: Color::Text(token_index("muted").unwrap() as u16),
        ..Style::default()
    }
}

fn glyph(name: &str, set: IconSet) -> char {
    icons::lookup(name)
        .unwrap()
        .glyph(set)
        .chars()
        .next()
        .unwrap()
}

/// `cell` draws end `c` (`head`: before its block): its glyph, and for `flat` a blank on a
/// block background.
fn is_end(cell: Option<&Cell>, c: Cap, head: bool, set: IconSet) -> bool {
    let Cap::Shape(s) = c else { return true };
    let Some(&(ch, style)) = cell else {
        return false;
    };
    ch == glyph(s.icon(!head), set) && (s != Shape::Flat || style.bg != Color::Default)
}

/// Checks the end shapes of every visible run of blocks at a width where the layout kept its
/// decoration (before step 6): the left run starts with the outer end and ends with the inner
/// one, the right run the mirror. With a gap, one blank cell beside the fill is allowed.
fn check_ends(
    o: &StyleOptions,
    set: IconSet,
    lines: &[LaidLine],
    log: &DecisionLog,
    right_drawn: bool,
    what: &str,
) {
    if o.body != Some(Body::Block) {
        return;
    }
    let (outer, inner) = (o.outer_end.unwrap(), o.inner_end.unwrap());
    let stray = o.joining == Some(Joining::Capped) && o.gap == Some(true);
    let blank = (' ', Style::default());
    let fill = fill_style();
    for (n, line) in lines.iter().enumerate() {
        if line.minimal || log.steps.contains(&(n, Step::DropDecoration)) {
            continue;
        }
        let c = cells(line);
        let at = c.iter().position(|x| x.1 == fill);
        let (mut left, mut right): (&[Cell], &[Cell]) = match at {
            Some(a) => {
                let b = a + c[a..].iter().take_while(|x| x.1 == fill).count();
                (&c[..a], &c[b..])
            }
            None if n == 0 && right_drawn => {
                // The sides touch: only the screen-edge ends can be told apart.
                assert!(
                    is_end(c.first(), outer, true, set),
                    "{what} line {n}: {c:?}"
                );
                assert!(
                    is_end(c.last(), outer, false, set),
                    "{what} line {n}: {c:?}"
                );
                continue;
            }
            None => (&c[..], &[]),
        };
        if stray {
            left = left.strip_suffix(&[blank]).unwrap_or(left);
            right = right.strip_prefix(&[blank]).unwrap_or(right);
        }
        if !left.is_empty() {
            assert!(
                is_end(left.first(), outer, true, set),
                "{what} line {n}: {c:?}"
            );
            assert!(
                is_end(left.last(), inner, false, set),
                "{what} line {n}: {c:?}"
            );
        }
        if !right.is_empty() {
            assert!(
                is_end(right.first(), inner, true, set),
                "{what} line {n}: {c:?}"
            );
            assert!(
                is_end(right.last(), outer, false, set),
                "{what} line {n}: {c:?}"
            );
        }
    }
}

/// A right-side segment with a value is drawn on line 1 (no step hid it).
fn right_drawn(log: &DecisionLog, present: &[&str]) -> bool {
    let i = |id| BUILTIN.iter().position(|d| d.id == id).unwrap();
    RIGHT
        .iter()
        .filter(|id| present.contains(id))
        .any(|id| !log.hidden.iter().any(|h| h.0 == 0 && h.1 == i(*id)))
}

fn compiled(o: &StyleOptions, left: &[&str], right: &[&str]) -> Vec<CompiledLine> {
    let lines = [
        LineLayout { left, right },
        LineLayout {
            left: &["char"],
            right: &[],
        },
    ];
    let t = generate(&PRESETS[0], o, &lines).unwrap();
    compile(&t, BUILTIN).unwrap()
}

// Every combination of body, ends, joint and gap draws a sound line at sampled widths: within
// the target, ASCII only in the ASCII set, the right edge on the last cell when the line has
// a fill, the end shapes on every visible run, and an empty segment (first, middle or last of
// a side) draws exactly what leaving it out draws. With a gap between blocks that have ends of
// their own, an empty segment next to the fill may leave its blank cell there (one cell, on
// the fill side only).
// 이것을 실패시키는 것: `none` + 빈칸을 그룹으로 만들어 바깥 끝을 첫 그룹 안에 두는 것(첫 세그먼트가 비면 끝이
// 사라짐), 끝을 빈칸 그룹 밖에 두는 것(마지막 세그먼트가 비면 꼬리 앞에 빈칸이 남고 꼬리 색이 빠짐), 빈칸을 채움
// 반대쪽(화면 가장자리)에 두는 것, 오른쪽 줄에서 끝을 바꿔 쓰지 않는 것.
#[test]
fn every_block_shape_combination_draws_a_sound_line() {
    let all: Vec<&str> = LEFT.iter().chain(&RIGHT).copied().collect();
    let present_full: Vec<&str> = all.iter().filter(|id| **id != "dir").copied().collect();
    let blank = (' ', Style::default());
    let fill = fill_style();
    for o in combinations() {
        let full = compiled(&o, &LEFT, &RIGHT);
        let without: Vec<(Vec<CompiledLine>, Vec<&str>)> = EMPTIED
            .iter()
            .map(|gone| {
                let l: Vec<&str> = LEFT.iter().filter(|x| *x != gone).copied().collect();
                let r: Vec<&str> = RIGHT.iter().filter(|x| *x != gone).copied().collect();
                let p: Vec<&str> = present_full
                    .iter()
                    .filter(|x| *x != gone)
                    .copied()
                    .collect();
                (compiled(&o, &l, &r), p)
            })
            .collect();
        let stray = o.body == Some(Body::Block)
            && o.joining == Some(Joining::Capped)
            && o.gap == Some(true);
        for set in [IconSet::Ascii, IconSet::Nerd] {
            for w in WIDTHS {
                let opt = options_at(set, w);
                let what = format!("{o:?} {set:?} w={w}");
                let mut log = DecisionLog::default();
                let f = draw(std::slice::from_ref(&full), &opt, &present_full, &mut log);
                for (n, l) in f.iter().enumerate() {
                    let used = runs_width(&l.left, opt.profile) + runs_width(&l.right, opt.profile);
                    assert!(used <= target(&opt), "{what} line {n}");
                    if set == IconSet::Ascii {
                        let text: String = cells(l).iter().map(|c| c.0).collect();
                        assert!(text.replace('\u{2026}', "").is_ascii(), "{what}: {text:?}");
                    }
                    if n == 0 && cells(l).iter().any(|c| c.1 == fill) {
                        assert_eq!(used, target(&opt), "{what}");
                    }
                }
                check_ends(&o, set, &f, &log, right_drawn(&log, &present_full), &what);
                for (k, gone) in EMPTIED.iter().enumerate() {
                    let (lines, present) = &without[k];
                    let mut la = DecisionLog::default();
                    let a = draw(std::slice::from_ref(&full), &opt, present, &mut la);
                    let mut lb = DecisionLog::default();
                    let b = draw(std::slice::from_ref(lines), &opt, present, &mut lb);
                    let what = format!("{what} empty {gone}");
                    check_ends(&o, set, &a, &la, right_drawn(&la, present), &what);
                    assert_eq!(a[1], b[1], "{what}");
                    let fill_side = *gone == "venv" || *gone == "status";
                    if !(stray && fill_side) {
                        assert_eq!(cells(&a[0]), cells(&b[0]), "{what}");
                        continue;
                    }
                    // The blank cell beside the fill: compared only where the extra cell
                    // changed no overflow step.
                    let stepped = |log: &DecisionLog| log.steps.iter().any(|s| s.0 == 0);
                    if stepped(&la) || stepped(&lb) {
                        continue;
                    }
                    let mut want = cells(&b[0]);
                    let dots: Vec<usize> = (0..want.len()).filter(|i| want[*i].1 == fill).collect();
                    let at = if *gone == "venv" {
                        dots[0]
                    } else {
                        dots[dots.len() - 1]
                    };
                    want[at] = blank;
                    assert_eq!(cells(&a[0]), want, "{what}");
                }
            }
        }
    }
}
