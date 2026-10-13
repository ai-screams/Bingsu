//! Layout allocates its buffers at their final size: a line that fits
//! never grows a String or a Vec (no `realloc`), a second `layout_into`
//! into the same output reuses its run buffers, and the largest input the
//! limits allow stays within a fixed amount of memory. Its own test binary;
//! the tests here take `SERIAL` so only one counts at a time.
use bingsu_core::field::{BUILTIN, Field, FieldValue, Value, segment};
use bingsu_core::icons::IconSet;
use bingsu_core::layout::{
    Inputs, LaidLine, Options, SegmentSetup, When, layout_into, runs_width, target,
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
    let _ = LIVE.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |l| {
        Some(l.saturating_sub(n))
    });
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

/// About twice what the largest input measured (1,055,301 bytes at peak,
/// 16,415 allocations, nearly all of them the shortener's 8,193-piece
/// results that the piece cap then drops).
const PEAK_MAX: usize = 2 << 20;
const ALLOCS_MAX: usize = 32 << 10;

// The largest input the limits allow: a path of MAX_STEPS folders and a
// template of `{dir}` repeated to MAX_TEMPLATE_BYTES (819 times). `abbrev`
// and `repo` give results over SEG_PIECES_MAX pieces and are skipped; the
// steps end in the minimal prompt.
// 이것을 실패시키는 것: 항목 버퍼를 노드 수가 아니라 노드 수 × 조각 상한으로 잡는 것(변이 R7, 수십 MB). 상한은 이
// 입력에서 잰 값(release·debug 같음)의 약 2배다.
#[test]
fn the_largest_input_stays_small() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let names: Vec<String> = (0..MAX_STEPS).map(|n| format!("folder-{n:04}")).collect();
    let raw: Vec<&[u8]> = names.iter().map(|s| s.as_bytes()).collect();
    let i = |id| BUILTIN.iter().position(|d| d.id == id).unwrap();
    let mut values = vec![None; BUILTIN.len()];
    let mut facts = vec![None; BUILTIN.len()];
    values[i("char")] = value("char", b"");
    values[i("dir")] = value("dir", b"");
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
        methods: &[Method::Repo, Method::Abbrev(1), Method::Depth(1)],
        when: When::Needed,
    };
    let inputs = Inputs {
        catalog: BUILTIN,
        values: &values,
        facts: &facts,
        setup: &setup,
    };
    let t = "{dir}".repeat(MAX_TEMPLATE_BYTES / 5);
    assert_eq!(t.len(), 4095);
    let lines = vec![compile(&t, BUILTIN).unwrap()];
    let o = Options {
        width: 200,
        profile: WidthProfile::DEFAULT,
        icons: IconSet::Nerd,
        use_last_column: false,
    };
    let mut out: Vec<LaidLine> = Vec::new();
    let (allocs, _, peak) = counted(|| layout_into(&lines, &[], &[], &inputs, &o, &mut out));
    assert!(runs_width(&out[0].left, o.profile) <= target(&o));
    assert!(
        peak <= PEAK_MAX && allocs <= ALLOCS_MAX,
        "peak {peak} bytes, {allocs} allocations"
    );
}
