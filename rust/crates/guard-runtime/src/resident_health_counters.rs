//! Bounded aggregate counters for the serving resident.
//!
//! A resident that is up but slow, that is refusing frames it cannot read, or
//! that is being handed requests it cannot authenticate, looks exactly like a
//! healthy one to a caller that can only see whether a reply came back. These
//! counters are what the difference looks like from inside the process: how
//! much work was served, how long it took, how big it was, and how it failed.
//!
//! Every figure here is a fixed counter in a fixed table. Nothing is keyed by
//! an operation, a command, a path or a caller, so the table cannot grow with
//! the work the resident does and cannot describe it either. A diagnostic that
//! is not allowed to read requests may read all of this.
//!
//! Totals saturate rather than wrap, and the two queue gauges are the only
//! figures that fall: everything else only rises for the life of the process.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use guard_contracts::ResidentCountersV1;

static SERVED_REQUESTS: AtomicU64 = AtomicU64::new(0);
static SERVICE_MICROS_TOTAL: AtomicU64 = AtomicU64::new(0);
static SERVICE_MICROS_MAX: AtomicU64 = AtomicU64::new(0);
static REQUEST_BYTES_TOTAL: AtomicU64 = AtomicU64::new(0);
static REQUEST_BYTES_MAX: AtomicU64 = AtomicU64::new(0);
static AUTH_FAILURES: AtomicU64 = AtomicU64::new(0);
static FRAME_ERRORS: AtomicU64 = AtomicU64::new(0);
static DEADLINE_EXCEEDED: AtomicU64 = AtomicU64::new(0);
static DIGEST_MISMATCHES: AtomicU64 = AtomicU64::new(0);
static PANICS: AtomicU64 = AtomicU64::new(0);

static EVALUATION_QUEUED: AtomicU64 = AtomicU64::new(0);
static EVALUATION_QUEUED_MAX: AtomicU64 = AtomicU64::new(0);
static CONTROL_QUEUED: AtomicU64 = AtomicU64::new(0);
static CONTROL_QUEUED_MAX: AtomicU64 = AtomicU64::new(0);

/// Which dispatch queue a request is sitting in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum QueueLane {
    Evaluation,
    Control,
}

impl QueueLane {
    fn gauges(self) -> (&'static AtomicU64, &'static AtomicU64) {
        match self {
            Self::Evaluation => (&EVALUATION_QUEUED, &EVALUATION_QUEUED_MAX),
            Self::Control => (&CONTROL_QUEUED, &CONTROL_QUEUED_MAX),
        }
    }
}

/// Add to a running total without wrapping. A total that wrapped would read as
/// a resident that had suddenly done less work than it had an hour ago.
fn add(counter: &AtomicU64, value: u64) {
    let _ = counter.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
        Some(current.saturating_add(value))
    });
}

/// Count one request that was answered, however it was answered, and charge
/// its service time and payload size to the aggregates.
///
/// `accepted_at` is when the resident took the request's header, so the span
/// covers the queue wait as well as the evaluation: a caller waiting on a
/// loaded resident is waiting for all of it.
pub(crate) fn record_served(accepted_at: Instant, request_bytes: usize) {
    SERVED_REQUESTS.fetch_add(1, Ordering::Relaxed);
    let micros = u64::try_from(accepted_at.elapsed().as_micros()).unwrap_or(u64::MAX);
    add(&SERVICE_MICROS_TOTAL, micros);
    SERVICE_MICROS_MAX.fetch_max(micros, Ordering::Relaxed);
    let bytes = u64::try_from(request_bytes).unwrap_or(u64::MAX);
    add(&REQUEST_BYTES_TOTAL, bytes);
    REQUEST_BYTES_MAX.fetch_max(bytes, Ordering::Relaxed);
}

/// Count one connection that never got past the shared-secret handshake.
pub(crate) fn record_auth_failure() {
    AUTH_FAILURES.fetch_add(1, Ordering::Relaxed);
}

/// Count one frame whose header, payload or reply could not be moved.
pub(crate) fn record_frame_error() {
    FRAME_ERRORS.fetch_add(1, Ordering::Relaxed);
}

/// Count one request whose total budget ran out before a worker reached it.
pub(crate) fn record_deadline_exceeded() {
    DEADLINE_EXCEEDED.fetch_add(1, Ordering::Relaxed);
}

/// Count one payload that did not match the digest in its own header.
pub(crate) fn record_digest_mismatch() {
    DIGEST_MISMATCHES.fetch_add(1, Ordering::Relaxed);
}

/// Count one evaluation that panicked and was answered rather than lost.
pub(crate) fn record_panic() {
    PANICS.fetch_add(1, Ordering::Relaxed);
}

/// Add one to a queue's depth and raise its peak to match.
fn claim(queued: &AtomicU64, peak: &AtomicU64) {
    let depth = queued.fetch_add(1, Ordering::Relaxed).saturating_add(1);
    peak.fetch_max(depth, Ordering::Relaxed);
}

/// Take one off a queue's depth. A gauge already at zero stays there: a depth
/// that wrapped below zero would read as a queue holding more than the process
/// could ever have admitted.
fn release(queued: &AtomicU64) {
    let _ = queued.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
        Some(current.saturating_sub(1))
    });
}

/// Charge one request to a lane's queue and raise that lane's peak.
pub(crate) fn enter_queue(lane: QueueLane) {
    let (queued, peak) = lane.gauges();
    claim(queued, peak);
}

/// Release one request from a lane's queue once a worker has taken it.
pub(crate) fn leave_queue(lane: QueueLane) {
    release(lane.gauges().0);
}

/// This lane's queue depth now, and the deepest it has been.
pub(crate) fn lane_depth(lane: QueueLane) -> (u32, u32) {
    let (queued, peak) = lane.gauges();
    (
        u32::try_from(queued.load(Ordering::Relaxed)).unwrap_or(u32::MAX),
        u32::try_from(peak.load(Ordering::Relaxed)).unwrap_or(u32::MAX),
    )
}

/// Read every counter for one reply. The reads are independent, so a reply
/// built while the resident is working can hold figures from either side of a
/// single request. They are rates and sizes, not a ledger that has to balance.
pub(crate) fn snapshot() -> ResidentCountersV1 {
    ResidentCountersV1 {
        served_requests: SERVED_REQUESTS.load(Ordering::Relaxed),
        service_micros_total: SERVICE_MICROS_TOTAL.load(Ordering::Relaxed),
        service_micros_max: SERVICE_MICROS_MAX.load(Ordering::Relaxed),
        request_bytes_total: REQUEST_BYTES_TOTAL.load(Ordering::Relaxed),
        request_bytes_max: REQUEST_BYTES_MAX.load(Ordering::Relaxed),
        auth_failures: AUTH_FAILURES.load(Ordering::Relaxed),
        frame_errors: FRAME_ERRORS.load(Ordering::Relaxed),
        deadline_exceeded: DEADLINE_EXCEEDED.load(Ordering::Relaxed),
        digest_mismatches: DIGEST_MISMATCHES.load(Ordering::Relaxed),
        panics: PANICS.load(Ordering::Relaxed),
    }
}

#[cfg(test)]
#[path = "resident_health_counters_tests.rs"]
mod tests;
