//! Counters belong to the measured thread, including while the harness or
//! another test allocates. Const TLS access does not allocate or borrow.
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
struct Counts {
    armed: bool,
    allocs: usize,
    reallocs: usize,
    live: usize,
    peak: usize,
}

thread_local! {
    static COUNTS: Cell<Counts> = const { Cell::new(Counts {
        armed: false, allocs: 0, reallocs: 0, live: 0, peak: 0,
    }) };
}

fn update(allocs: usize, reallocs: usize, grow: usize, shrink: usize) {
    // A thread can deallocate during TLS destruction. No measurement is
    // active then, so unavailable TLS is deliberately ignored.
    let _ = COUNTS.try_with(|cell| {
        let mut c = cell.get();
        if c.armed {
            c.allocs += allocs;
            c.reallocs += reallocs;
            c.live += grow;
            c.peak = c.peak.max(c.live);
            c.live = c.live.saturating_sub(shrink);
            cell.set(c);
        }
    });
}

pub struct Counting;

// SAFETY: System receives the caller's arguments unchanged. The bookkeeping
// uses allocation-free const TLS and Cell; no references escape a TLS access.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        update(1, 0, layout.size(), 0);
        // SAFETY: forward the caller's allocation contract.
        unsafe { System.alloc(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        update(0, 0, 0, layout.size());
        // SAFETY: ptr came from System with this layout.
        unsafe { System.dealloc(ptr, layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        update(0, 1, new_size, layout.size());
        // SAFETY: forward System's original pointer/layout and requested size.
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

struct Disarm;
impl Drop for Disarm {
    fn drop(&mut self) {
        COUNTS.with(|cell| {
            let mut c = cell.get();
            c.armed = false;
            cell.set(c);
        });
    }
}

/// (allocations, reallocations, peak live bytes) on this thread only.
pub fn counted(f: impl FnOnce()) -> (usize, usize, usize) {
    COUNTS.with(|cell| {
        assert!(!cell.get().armed, "nested allocation measurement");
        cell.set(Counts {
            armed: true,
            ..Counts::default()
        });
    });
    let guard = Disarm;
    f();
    drop(guard);
    COUNTS.with(|cell| {
        let c = cell.get();
        (c.allocs, c.reallocs, c.peak)
    })
}
