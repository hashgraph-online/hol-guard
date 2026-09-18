//! Explicit test-only allocation counters. Default production has no observer.
use serde_json::{json, Value};
use stats_alloc::{Region, StatsAlloc, INSTRUMENTED_SYSTEM};
use std::alloc::System;
use std::hint::black_box;
use std::time::Instant;

#[global_allocator]
static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

fn distribution(mut values: Vec<f64>) -> Value {
    values.sort_by(f64::total_cmp);
    json!({
        "samples": values.len(), "p50": values[(values.len() - 1) / 2],
        "p95": values[(95 * values.len()).div_ceil(100) - 1],
        "max": values[values.len() - 1],
    })
}

pub(crate) fn measure<I, O>(
    fixture: &str,
    phase: &str,
    bytes: usize,
    prepare: impl Fn() -> I,
    execute: impl Fn(I) -> O,
    verify: impl Fn(&O),
) {
    let mut wall = Vec::with_capacity(30);
    let mut allocations = Vec::with_capacity(30);
    let mut deallocations = Vec::with_capacity(30);
    let mut reallocations = Vec::with_capacity(30);
    let mut allocated = Vec::with_capacity(30);
    let mut deallocated = Vec::with_capacity(30);
    let mut reallocated = Vec::with_capacity(30);
    verify(&execute(prepare()));
    for _ in 0..30 {
        // Fixture construction/cloning and returned-value destruction are
        // outside the interval. Consumed-input destruction remains included.
        let input = prepare();
        let region = Region::new(GLOBAL);
        let started = Instant::now();
        let result = black_box(execute(black_box(input)));
        let elapsed = started.elapsed().as_secs_f64() * 1_000_000.0;
        let stats = region.change();
        wall.push(elapsed);
        allocations.push(stats.allocations as f64);
        deallocations.push(stats.deallocations as f64);
        reallocations.push(stats.reallocations as f64);
        allocated.push(stats.bytes_allocated as f64);
        deallocated.push(stats.bytes_deallocated as f64);
        reallocated.push(stats.bytes_reallocated as f64);
        verify(&result);
    }
    println!(
        "{}",
        json!({
            "schema":"guard.native-allocation-phase.v1", "fixture":fixture, "phase":phase,
            "request_bytes":bytes, "samples":30, "instrumented_wall_us":distribution(wall),
            "allocations":distribution(allocations), "deallocations":distribution(deallocations),
            "reallocations":distribution(reallocations), "bytes_allocated":distribution(allocated),
            "bytes_deallocated":distribution(deallocated), "bytes_reallocated":distribution(reallocated),
            "allocator_scope":"process-global; run only this ignored test with test-threads=1",
            "peak_live_bytes":"not_measured", "installed_slo_qualified":false,
        })
    );
}
