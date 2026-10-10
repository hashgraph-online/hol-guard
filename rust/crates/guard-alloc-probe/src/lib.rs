//! Test-only counting allocator.
//!
//! Source inspection of a library is not proof of its allocation behavior, so
//! adversarial-corpus tests install [`CountingAllocator`] as the global
//! allocator and read back [`measure`]d bounds. Accounting is per thread: the
//! archive inspector is synchronous, so everything it allocates happens on the
//! calling thread and parallel test threads never pollute each other.
//!
//! This crate is a `dev-dependency` only. It is the sole crate in the workspace
//! that does not forbid unsafe code, and its unsafe surface is the three
//! methods of one `GlobalAlloc` impl that forward unchanged to [`System`].

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

thread_local! {
    static LIVE: Cell<i64> = const { Cell::new(0) };
    static PEAK: Cell<i64> = const { Cell::new(0) };
    static MAX_SINGLE: Cell<usize> = const { Cell::new(0) };
    static TOTAL: Cell<u64> = const { Cell::new(0) };
    static CALLS: Cell<u64> = const { Cell::new(0) };
}

/// Bounds observed while a closure ran on the current thread.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Measurement {
    /// Highest number of live heap bytes above the starting baseline.
    pub peak_live_bytes: u64,
    /// Largest single allocation (or reallocation target) requested.
    pub max_single_alloc: u64,
    /// Cumulative bytes requested from the allocator.
    pub total_allocated: u64,
    /// Number of allocation and reallocation calls.
    pub alloc_calls: u64,
}

fn note_alloc(size: usize) {
    let _ = LIVE.try_with(|live| {
        live.set(live.get() + size as i64);
        let _ = PEAK.try_with(|peak| {
            if live.get() > peak.get() {
                peak.set(live.get());
            }
        });
    });
    let _ = MAX_SINGLE.try_with(|max| {
        if size > max.get() {
            max.set(size);
        }
    });
    let _ = TOTAL.try_with(|total| total.set(total.get().saturating_add(size as u64)));
    let _ = CALLS.try_with(|calls| calls.set(calls.get().saturating_add(1)));
}

fn note_free(size: usize) {
    let _ = LIVE.try_with(|live| live.set(live.get() - size as i64));
}

/// Install with `#[global_allocator] static A: CountingAllocator = CountingAllocator;`.
pub struct CountingAllocator;

// SAFETY: every method forwards its arguments unchanged to `System`, which
// upholds the `GlobalAlloc` contract; the bookkeeping only touches
// const-initialized, destructor-free thread-locals and never allocates.
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: forwarded under the caller's `GlobalAlloc::alloc` contract.
        let ptr = unsafe { System.alloc(layout) };
        if !ptr.is_null() {
            note_alloc(layout.size());
        }
        ptr
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // SAFETY: forwarded under the caller's `GlobalAlloc::alloc_zeroed` contract.
        let ptr = unsafe { System.alloc_zeroed(layout) };
        if !ptr.is_null() {
            note_alloc(layout.size());
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        note_free(layout.size());
        // SAFETY: forwarded under the caller's `GlobalAlloc::dealloc` contract.
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // SAFETY: forwarded under the caller's `GlobalAlloc::realloc` contract.
        let new_ptr = unsafe { System.realloc(ptr, layout, new_size) };
        if !new_ptr.is_null() {
            note_free(layout.size());
            note_alloc(new_size);
        }
        new_ptr
    }
}

/// Run `work` and report the allocation bounds it reached on this thread.
/// Only meaningful in a binary that installed [`CountingAllocator`].
pub fn measure<T>(work: impl FnOnce() -> T) -> (T, Measurement) {
    let baseline = LIVE.with(Cell::get);
    PEAK.with(|peak| peak.set(baseline));
    MAX_SINGLE.with(|max| max.set(0));
    TOTAL.with(|total| total.set(0));
    CALLS.with(|calls| calls.set(0));
    let value = work();
    let measurement = Measurement {
        peak_live_bytes: (PEAK.with(Cell::get) - baseline).max(0) as u64,
        max_single_alloc: MAX_SINGLE.with(Cell::get) as u64,
        total_allocated: TOTAL.with(Cell::get),
        alloc_calls: CALLS.with(Cell::get),
    };
    (value, measurement)
}
