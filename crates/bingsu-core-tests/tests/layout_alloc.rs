//! Layout allocates its buffers at their final size: a line that fits
//! never grows a String or a Vec (no `realloc`), a second `layout_into`
//! into the same output reuses its run buffers, and the largest input the
//! limits allow stays within a fixed amount of memory. Its own test binary;
//! the tests here take `SERIAL` so only one counts at a time.
use bingsu_core::field::{BUILTIN, Field, FieldValue, Value, segment};
use bingsu_core::icons::IconSet;
use bingsu_core::layout::{
    Inputs, LINE_BYTES_MAX, LaidLine, Options, SegmentSetup, When, layout_into, runs_width, target,
};
use bingsu_core::shorten::{Anchor, Keep, MAX_STEPS, Method, PathFacts};
use bingsu_core::template::compile::compile;
use bingsu_core::template::syntax::MAX_TEMPLATE_BYTES;
use bingsu_core::width::WidthProfile;
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

struct Counting;

static SERIAL: Mutex<()> = Mutex::new(());
static ARMED: AtomicBool = AtomicBool::new(false);
static ALLOCS: AtomicUsize = AtomicUsize::new(0);
static REALLOCS: AtomicUsize = AtomicUsize::new(0);
/// Bytes allocated while armed and not yet freed, and their high mark.
static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

fn grow(n: usize) {
    let live = LIVE.fetch_add(n, Ordering::Relaxed) + n;
    PEAK.fetch_max(live, Ordering::Relaxed);
}

fn shrink(n: usize) {
    // Memory allocated before arming may be freed while armed.
    // A plain compare-exchange loop: `fetch_update` is deprecated on newer
    // toolchains and its replacement is missing on older ones.
    let mut live = LIVE.load(Ordering::Relaxed);
    while let Err(now) = LIVE.compare_exchange_weak(
        live,
        live.saturating_sub(n),
        Ordering::Relaxed,
        Ordering::Relaxed,
    ) {
        live = now;
    }
}

// SAFETY: every method forwards to `System` with the caller's arguments
// unchanged; the counters are atomics and never allocate.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if ARMED.load(Ordering::Relaxed) {
            ALLOCS.fetch_add(1, Ordering::Relaxed);
            grow(layout.size());
        }
        // SAFETY: the caller's contract for `alloc` is passed on as is.
        unsafe { System.alloc(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if ARMED.load(Ordering::Relaxed) {
            shrink(layout.size());
        }
        // SAFETY: `ptr` came from `System` through this allocator.
        unsafe { System.dealloc(ptr, layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        if ARMED.load(Ordering::Relaxed) {
            REALLOCS.fetch_add(1, Ordering::Relaxed);
            grow(new_size);
            shrink(layout.size());
        }
        // SAFETY: `ptr` came from `System` through this allocator.
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static GLOBAL: Counting = Counting;

/// Runs `f` with the counters reset and armed: (allocations, reallocations,
/// peak live bytes).
fn counted(f: impl FnOnce()) -> (usize, usize, usize) {
    for c in [&ALLOCS, &REALLOCS, &LIVE, &PEAK] {
        c.store(0, Ordering::Relaxed);
    }
    ARMED.store(true, Ordering::Relaxed);
    f();
    ARMED.store(false, Ordering::Relaxed);
    (
        ALLOCS.load(Ordering::Relaxed),
        REALLOCS.load(Ordering::Relaxed),
        PEAK.load(Ordering::Relaxed),
    )
}

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
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
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
        &mut out,
    );
    let (allocs, reallocs, _) = counted(|| {
        layout_into(
            std::slice::from_ref(&lines),
            &[],
            &[],
            &inputs,
            &o,
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
    let (allocs, _, peak) = counted(|| layout_into(&lines, &[], &[], &inputs, &o, &mut out));
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
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
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
