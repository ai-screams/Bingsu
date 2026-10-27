//! Thread-local counting avoids unrelated allocations from parallel libtest tests.
use std::{
    alloc::{GlobalAlloc, Layout, System},
    cell::Cell,
};

#[derive(Clone, Copy, Default, Debug)]
pub struct Counts {
    pub live: usize,
    pub peak: usize,
    pub calls: usize,
}
thread_local! {
    static COUNTS: Cell<Option<Counts>> = const { Cell::new(None) };
}
struct Allocator;
// SAFETY: every allocation is delegated unchanged to System. The const TLS
// Cell neither allocates nor locks; unmeasured threads never affect the sample.
unsafe impl GlobalAlloc for Allocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: forwarded allocator contract.
        let ptr = unsafe { System.alloc(layout) };
        if !ptr.is_null() {
            let _ = COUNTS.try_with(|slot| {
                if let Some(mut counts) = slot.get() {
                    counts.live += layout.size();
                    counts.peak = counts.peak.max(counts.live);
                    counts.calls += 1;
                    slot.set(Some(counts));
                }
            });
        }
        ptr
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        let _ = COUNTS.try_with(|slot| {
            if let Some(mut counts) = slot.get() {
                counts.live -= layout.size();
                slot.set(Some(counts));
            }
        });
        // SAFETY: forwarded allocator contract.
        unsafe { System.dealloc(ptr, layout) };
    }
    // GlobalAlloc's default realloc counts old + new during the copy, including
    // transient Vec growth even if the system allocator could grow in place.
}
#[global_allocator]
static ALLOCATOR: Allocator = Allocator;

/// Heap bytes live right now inside `measure`; 0 outside it. Only the fuzz
/// entries read it, so the other test crates that include this file skip it.
#[allow(dead_code)]
pub fn live() -> usize {
    COUNTS.with(|slot| slot.get().map_or(0, |counts| counts.live))
}

pub fn measure<T>(f: impl FnOnce() -> T) -> (T, Counts) {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            COUNTS.with(|slot| slot.set(None));
        }
    }
    COUNTS.with(|slot| {
        assert!(slot.get().is_none());
        slot.set(Some(Counts::default()));
    });
    let reset = Reset;
    let result = f();
    let counts = COUNTS.with(|slot| slot.get().unwrap());
    drop(reset);
    (result, counts)
}
