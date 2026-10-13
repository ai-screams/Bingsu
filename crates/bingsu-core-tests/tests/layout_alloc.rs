//! Layout allocates its buffers at their final size: a line that fits
//! never grows a String or a Vec (no `realloc`), and a second
//! `layout_into` into the same output reuses its run buffers. Its own test
//! binary, so no other test allocates while the counter is armed.
use bingsu_core::field::{BUILTIN, Field, FieldValue, Value, segment};
use bingsu_core::icons::IconSet;
use bingsu_core::layout::{Inputs, Options, SegmentSetup, When, layout_into};
use bingsu_core::template::compile::compile;
use bingsu_core::width::WidthProfile;
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

struct Counting;

static ARMED: AtomicBool = AtomicBool::new(false);
static ALLOCS: AtomicUsize = AtomicUsize::new(0);
static REALLOCS: AtomicUsize = AtomicUsize::new(0);

// SAFETY: every method forwards to `System` with the caller's arguments
// unchanged; the counters are atomics and never allocate.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if ARMED.load(Ordering::Relaxed) {
            ALLOCS.fetch_add(1, Ordering::Relaxed);
        }
        // SAFETY: the caller's contract for `alloc` is passed on as is.
        unsafe { System.alloc(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: `ptr` came from `System` through this allocator.
        unsafe { System.dealloc(ptr, layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        if ARMED.load(Ordering::Relaxed) {
            REALLOCS.fetch_add(1, Ordering::Relaxed);
        }
        // SAFETY: `ptr` came from `System` through this allocator.
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

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
// 또는 두 번째 호출이 run 버퍼를 다시 쓰지 않고 새로 잡는 것.
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
    let facts = vec![None; BUILTIN.len()];
    let setup = vec![
        SegmentSetup {
            priority: 10,
            required: false,
            methods: &[],
            when: When::Needed
        };
        BUILTIN.len()
    ];
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
    ARMED.store(true, Ordering::Relaxed);
    layout_into(
        std::slice::from_ref(&lines),
        &[],
        &[],
        &inputs,
        &o,
        &mut out,
    );
    ARMED.store(false, Ordering::Relaxed);
    let (allocs, reallocs) = (
        ALLOCS.load(Ordering::Relaxed),
        REALLOCS.load(Ordering::Relaxed),
    );
    assert_eq!(reallocs, 0, "a buffer grew");
    // Per line: slots, segments, node info, field text (line 1 only), the
    // two item buffers, references, style stack: 8 + 7. No run String.
    assert_eq!(allocs, 15);
    assert!(
        out[0].left.iter().any(|r| r.text.contains("+4294967295+")),
        "{out:?}"
    );
}
