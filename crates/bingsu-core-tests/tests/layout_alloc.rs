//! Layout allocates its buffers at their final size: a line that fits
//! never grows a String or a Vec (no `realloc`), a second `layout_into`
//! into the same output reuses its run buffers, and the largest input the
//! limits allow stays within a fixed amount of memory. Its own test binary;
//! counters are thread-local, so harness/other-test allocations are excluded.
use bingsu_core::field::{BUILTIN, Field, FieldValue, Value, segment};
use bingsu_core::icons::IconSet;
use bingsu_core::layout::{
    Inputs, LINE_BYTES_MAX, LaidLine, Options, SegmentSetup, When, layout_into, runs_width, target,
};
use bingsu_core::recorder::{DecisionLog, NoopRecorder};
use bingsu_core::shorten::{Anchor, Keep, MAX_STEPS, Method, PathFacts};
use bingsu_core::template::compile::compile;
use bingsu_core::template::syntax::MAX_TEMPLATE_BYTES;
use bingsu_core::width::WidthProfile;
#[path = "support/allocation.rs"]
mod allocation;
use allocation::{Counting, counted};

#[global_allocator]
static GLOBAL: Counting = Counting;

fn value(id: &str, text: &[u8]) -> Option<Value> {
    let d = segment(id).unwrap();
    let mut fields = vec![Field::ABSENT; d.fields.len()];
    if id == "git" {
        fields[d.field_index("ahead").unwrap()] = Field::known(FieldValue::Count {
            n: u32::MAX,
            saturated: true,
        });
    }
    Some(Value::new(text, fields))
}

// 이것을 실패시키는 것: 항목·run·필드 버퍼의 크기 계산이 모자라 측정 중에 버퍼가 자라는 것(`realloc`),
// 두 번째 호출이 run 버퍼를 다시 쓰지 않고 새로 잡는 것, 줄이 그리지 않는 세그먼트를 줄이는 것.
#[test]
fn a_fitting_line_never_grows_a_buffer() {
    let i = |id| BUILTIN.iter().position(|d| d.id == id).unwrap();
    let mut values = vec![None; BUILTIN.len()];
    values[i("char")] = value("char", b"");
    // No `PathFacts`: building the path text is the shortener module's
    // work and grows its own String.
    values[i("dir")] = value("dir", b"~/Works/AiScream/themes");
    values[i("git")] = value("git", b"main");
    values[i("time")] = value("time", b"12:34");
    // A segment with a value and `when = always` that the template does not
    // draw costs nothing: it is not shortened.
    values[i("venv")] = value("venv", b"a-virtual-environment");
    let facts = vec![None; BUILTIN.len()];
    let mut setup = vec![
        SegmentSetup {
            priority: 10,
            required: false,
            methods: &[],
            when: When::Needed
        };
        BUILTIN.len()
    ];
    setup[i("venv")] = SegmentSetup {
        priority: 10,
        required: false,
        methods: &[Method::Truncate {
            max: 4,
            keep: Keep::Start,
        }],
        when: When::Always,
    };
    let inputs = Inputs {
        catalog: BUILTIN,
        values: &values,
        facts: &facts,
        setup: &setup,
    };
    let t = "{@head:round}{dir:block}{@sep:triangle}{git:block}{@group} +{git.ahead}{@end}{@tail:triangle}{@fill:dot}{time}{@nl}{char}";
    let lines = compile(t, BUILTIN).unwrap();
    let o = Options {
        width: 80,
        profile: WidthProfile::DEFAULT,
        icons: IconSet::Nerd,
        use_last_column: false,
    };
    let mut out = Vec::new();
    layout_into(
        std::slice::from_ref(&lines),
        &[],
        &[],
        &inputs,
        &o,
        &mut NoopRecorder,
        &mut out,
    );
    let (allocs, reallocs, _) = counted(|| {
        layout_into(
            std::slice::from_ref(&lines),
            &[],
            &[],
            &inputs,
            &o,
            &mut NoopRecorder,
            &mut out,
        )
    });
    assert_eq!(reallocs, 0, "a buffer grew");
    // Per line: slots, step entries, node info, field text (line 1 only),
    // the two item buffers (the right one of line 2 is empty), references,
    // style stack, join buffer: 9 + 7. No run String.
    assert_eq!(allocs, 16);
    assert!(
        out[0].left.iter().any(|r| r.text.contains("+4294967295+")),
        "{out:?}"
    );
}

/// Peak live bytes and allocations of one `layout_into` call on a path of
/// MAX_STEPS folders named by `name`, under `template` at `width`.
fn largest(
    name: impl Fn(usize) -> String,
    methods: &[Method],
    template: &str,
    width: u16,
) -> (usize, usize) {
    let names: Vec<String> = (0..MAX_STEPS).map(name).collect();
    let raw: Vec<&[u8]> = names.iter().map(|s| s.as_bytes()).collect();
    let i = |id| BUILTIN.iter().position(|d| d.id == id).unwrap();
    let mut values = vec![None; BUILTIN.len()];
    let mut facts = vec![None; BUILTIN.len()];
    values[i("char")] = value("char", b"");
    values[i("dir")] = value("dir", b"");
    values[i("time")] = value("time", b"12:34:56");
    facts[i("dir")] = Some(PathFacts::new(Anchor::Home, &raw, Some(1), &[]));
    let mut setup = vec![
        SegmentSetup {
            priority: 10,
            required: false,
            methods: &[],
            when: When::Needed
        };
        BUILTIN.len()
    ];
    setup[i("dir")] = SegmentSetup {
        priority: 100,
        required: true,
        methods,
        when: When::Needed,
    };
    let inputs = Inputs {
        catalog: BUILTIN,
        values: &values,
        facts: &facts,
        setup: &setup,
    };
    let lines = vec![compile(template, BUILTIN).unwrap()];
    let o = Options {
        width,
        profile: WidthProfile::DEFAULT,
        icons: IconSet::Nerd,
        use_last_column: false,
    };
    let mut out: Vec<LaidLine> = Vec::new();
    let (allocs, _, peak) =
        counted(|| layout_into(&lines, &[], &[], &inputs, &o, &mut NoopRecorder, &mut out));
    for l in &out {
        assert!(runs_width(&l.left, o.profile) <= target(&o));
        assert!(l.left.iter().map(|r| r.text.len()).sum::<usize>() <= LINE_BYTES_MAX);
    }
    (peak, allocs)
}

// The largest inputs the limits allow, each pinned just above what it
// measured:
// - a path of MAX_STEPS ordinary folders, `{dir}` repeated to
//   MAX_TEMPLATE_BYTES (819 times): `abbrev` and `unique` are not run
//   (over SEG_PIECES_MAX pieces by the step count), `repo` runs and its
//   8,191 pieces are dropped;
// - the same path with folder names of 3,001 bytes (a letter and 1,500
//   combining marks): over PATH_BYTES_MAX, so the path is never read;
// - `{@fill:line}` at 65535 columns: the fill's bytes count, the line is
//   over LINE_BYTES_MAX, and the right side goes.
// 이것을 실패시키는 것: 항목 버퍼를 노드 수 × 조각 상한으로 잡는 것(변이 R7), 조각 수나 바이트가 확실히 넘는 방식을
// 돌리는 것(`abbrev`·`unique`·`depth 1000`·`none`), PATH_BYTES_MAX를 넘는 경로를 읽는 것(표시 글자 약 12 MB),
// fill 바이트를 세지 않는 것(약 192 KB 줄).
#[test]
fn the_largest_inputs_stay_small() {
    let dirs = "{dir}".repeat(MAX_TEMPLATE_BYTES / 5);
    assert_eq!(dirs.len(), 4095);
    // Ordinary names; `depth 1000` keeps 1,000 steps (2,001 pieces) and
    // `depth 5000` all 4,096 (8,193), so neither is run either.
    let chain = [
        Method::Repo,
        Method::Abbrev(1),
        Method::Unique,
        Method::Depth(1000),
        Method::Depth(5000),
        Method::Depth(1),
    ];
    let ordinary = largest(|n| format!("folder-{n:04}"), &chain, &dirs, 200);
    let long = largest(
        |_| format!("e{}", "\u{0301}".repeat(1500)),
        &chain,
        &dirs,
        200,
    );
    let fill = largest(
        |n| format!("folder-{n:04}"),
        &chain,
        "{@fill:line}{time}{@nl}{char}",
        u16::MAX,
    );
    // `none` would give the whole 49 KiB path, over LINE_BYTES_MAX: not run.
    let none = largest(
        |n| format!("folder-{n:04}"),
        &[Method::None],
        "{dir}{@nl}{char}",
        200,
    );
    // Measured (bytes at peak, allocations), the same in release and debug:
    // ordinary (834,093, 8,219), long (96,864, 17), fill (1,846, 18), none
    // (99,792, 25). The bounds sit about 10% above: the counts are exact, so
    // running one skipped method (thousands of pieces, or the whole path
    // text and its checked copy) goes past them.
    assert!(
        ordinary.0 <= 920_000 && ordinary.1 <= 9_000,
        "ordinary {ordinary:?}"
    );
    assert!(long.0 <= 110_000 && long.1 <= 25, "long {long:?}");
    assert!(fill.0 <= 2_100 && fill.1 <= 25, "fill {fill:?}");
    assert!(none.0 <= 110_000 && none.1 <= 30, "none {none:?}");
}

// A decision log reused across `layout_into` calls holds one call's records
// and keeps its memory: the second call allocates exactly what a call
// without a log does. The worst case: every catalog segment on both sides
// of an upper line and in emptied groups, at a width where every step runs.
// 이것을 실패시키는 것: `begin`이 기록을 비우지 않는 것(두 번째 호출의 기록이 두 배), 용량을 버리고 새로 잡는 것
// (두 번째 호출의 할당이 기록 없는 호출보다 많다), 줄당 기록 수가 `Recorder` 문서의 상한을 넘는 것.
#[test]
fn a_reused_log_keeps_one_call_and_its_memory() {
    let i = |id| BUILTIN.iter().position(|d| d.id == id).unwrap();
    let mut values: Vec<Option<Value>> = BUILTIN
        .iter()
        .map(|d| value(d.id, d.id.as_bytes()))
        .collect();
    values[i("venv")] = None;
    let mut facts = vec![None; BUILTIN.len()];
    let steps: [&[u8]; 4] = [b"Works", b"AiScream", b"themes", b"src"];
    facts[i("dir")] = Some(PathFacts::new(Anchor::Home, &steps, Some(2), &[]));
    let mut setup = vec![
        SegmentSetup {
            priority: 10,
            required: false,
            methods: &[Method::Truncate {
                max: 3,
                keep: Keep::Start
            }],
            when: When::Always
        };
        BUILTIN.len()
    ];
    setup[i("dir")] = SegmentSetup {
        priority: 100,
        required: true,
        methods: &[Method::Repo, Method::Depth(1)],
        when: When::Needed,
    };
    let inputs = Inputs {
        catalog: BUILTIN,
        values: &values,
        facts: &facts,
        setup: &setup,
    };
    // Every segment on both sides, and every field of git in a group whose
    // fields are all empty (the git value has absent fields only).
    let ids: Vec<&str> = BUILTIN.iter().map(|d| d.id).collect();
    let side: String = ids.iter().map(|id| format!("{{{id}}} ")).collect();
    let group: String = BUILTIN[i("git")]
        .fields
        .iter()
        .map(|f| format!("{{git.{}}}", f.name))
        .collect();
    let t = format!("abcd{side}{{@group}}+{group}{{@end}}{{@fill}}{side}{{@nl}}{{char}}");
    let lines = vec![compile(&t, BUILTIN).unwrap()];
    let o = Options {
        width: 4,
        profile: WidthProfile::DEFAULT,
        icons: IconSet::Nerd,
        use_last_column: false,
    };
    let mut out = Vec::new();
    let mut log = DecisionLog::default();
    layout_into(&lines, &[], &[], &inputs, &o, &mut log, &mut out);
    let once = log.clone();
    let (allocs_log, reallocs_log, _) =
        counted(|| layout_into(&lines, &[], &[], &inputs, &o, &mut log, &mut out));
    let (allocs_noop, reallocs_noop, _) =
        counted(|| layout_into(&lines, &[], &[], &inputs, &o, &mut NoopRecorder, &mut out));
    assert_eq!(log, once);
    // The shortener grows its own results in both runs.
    assert_eq!((allocs_log, reallocs_log), (allocs_noop, reallocs_noop));
    // Per line: 7 steps, 2 shortened per catalog segment, 5 hidden per
    // catalog segment plus one per field node.
    let c = BUILTIN.len();
    let fields = BUILTIN[i("git")].fields.len();
    for n in 0..2 {
        let steps = log.steps.iter().filter(|x| x.0 == n).count();
        let short = log.shortened.iter().filter(|x| x.0 == n).count();
        let hidden = log.hidden.iter().filter(|x| x.0 == n).count();
        assert!(
            steps <= 7 && short <= 2 * c && hidden <= 5 * c + fields,
            "line {n}: {steps} {short} {hidden}"
        );
    }
    // Measured: line 0 reaches step 7 (all 7 steps); 16 shortened, 2 for
    // each of the 8 segments with a value (`always`, then step 1); 17 hidden.
    assert_eq!(
        (log.steps.len(), log.shortened.len(), log.hidden.len()),
        (7, 16, 17)
    );
}

// 이것을 실패시키는 것: 측정 중 다른 스레드의 할당·재할당·해제를 합산하는 것.
#[test]
fn another_threads_allocations_are_not_counted() {
    use std::sync::atomic::{AtomicBool, Ordering};
    let start = AtomicBool::new(false);
    let done = AtomicBool::new(false);
    std::thread::scope(|scope| {
        let worker = scope.spawn(|| {
            while !start.load(Ordering::Acquire) {
                std::hint::spin_loop();
            }
            let mut bytes = Vec::with_capacity(16);
            bytes.extend_from_slice(&[7u8; 16]);
            bytes.reserve_exact(4096);
            std::hint::black_box(&bytes);
            drop(bytes);
            done.store(true, Ordering::Release);
        });
        let own = counted(|| {
            start.store(true, Ordering::Release);
            while !done.load(Ordering::Acquire) {
                std::hint::spin_loop();
            }
        });
        worker.join().unwrap();
        assert_eq!(own, (0, 0, 0));
    });
}

// 이것을 실패시키는 것: 같은 스레드의 측정까지 끄거나 이전 측정값을 누적하는 것.
#[test]
fn local_allocations_are_counted_and_reset() {
    for _ in 0..2 {
        let counts = counted(|| {
            let mut bytes = Vec::with_capacity(16);
            bytes.extend_from_slice(&[7u8; 16]);
            bytes.reserve_exact(4096);
            std::hint::black_box(&bytes);
        });
        assert_eq!(counts, (1, 1, 16 + 4112));
    }
}

// 이것을 실패시키는 것: 측정한 함수의 panic 뒤에도 계수를 켠 채로 두는 것.
#[test]
fn panic_disarms_the_counter() {
    assert!(std::panic::catch_unwind(|| counted(|| panic!("fixture"))).is_err());
    assert_eq!(counted(|| {}), (0, 0, 0));
}
