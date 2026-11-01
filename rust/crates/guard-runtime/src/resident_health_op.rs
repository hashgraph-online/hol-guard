//! `ResidentHealth` — resident op that answers from the reserved control lane.
//!
//! The older `health` operation is dispatched like evaluation work, so a
//! resident with a full evaluation queue refuses it with `native_overloaded`.
//! A caller reading that refusal learns nothing it did not already know: every
//! request is being refused, and the process may equally be wedged or gone.
//! This operation is routed onto the control lane, whose worker and queue are
//! reserved out of the evaluation budget, so a loaded resident still answers
//! it. The answer itself is the liveness proof; the figures in it say how much
//! room is left.
//!
//! The reply carries counts, durations and the build identifiers the runtime
//! already publishes in `capabilities`. It never carries a path, a command, a
//! request payload or anything about a caller. The aggregate counters beside
//! the lane shapes come from [`crate::resident_health_counters`], which keeps
//! a fixed table of totals rather than anything keyed by the work served.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;
use std::time::Instant;

use guard_contracts::{
    ResidentHealthRequestV1, ResidentHealthResultV1, ResidentLaneV1,
    RESIDENT_HEALTH_MAX_REQUEST_BYTES, RESIDENT_HEALTH_REQUEST_SCHEMA,
    RESIDENT_HEALTH_RESULT_SCHEMA,
};

use crate::resident_health_counters::{lane_depth, snapshot, QueueLane};

use crate::package_authority_op::request_digest_with_limit;

static SERVING_SINCE: OnceLock<Instant> = OnceLock::new();
static OVERLOADED_REQUESTS: AtomicU64 = AtomicU64::new(0);

/// Start this resident's uptime clock. Called once as the worker pools start;
/// a later call keeps the first instant, so a handoff cannot rewind it.
pub(crate) fn mark_serving() {
    let _ = SERVING_SINCE.set(Instant::now());
}

/// Charge one refusal to the overload counter.
pub(crate) fn record_overload() {
    crate::resident_health_counters::add(&OVERLOADED_REQUESTS, 1);
}

/// Milliseconds since the worker pools started, saturating rather than
/// wrapping. Zero before they start, which no served request can observe.
fn uptime_ms() -> u64 {
    SERVING_SINCE.get().map_or(0, |since| {
        u64::try_from(since.elapsed().as_millis()).unwrap_or(u64::MAX)
    })
}

fn lane(which: QueueLane, workers: usize, queue_capacity: usize) -> ResidentLaneV1 {
    let (queued, queued_max) = lane_depth(which);
    ResidentLaneV1 {
        workers: u32::try_from(workers).unwrap_or(u32::MAX),
        queue_capacity: u32::try_from(queue_capacity).unwrap_or(u32::MAX),
        queued,
        queued_max,
    }
}

pub(crate) fn evaluate_resident_health(
    request: &ResidentHealthRequestV1,
) -> Result<Vec<u8>, String> {
    let request_sha256 = request_digest_with_limit(request, RESIDENT_HEALTH_MAX_REQUEST_BYTES)?;
    if request.schema != RESIDENT_HEALTH_REQUEST_SCHEMA {
        return Err("native_resident_health_schema_mismatch".to_owned());
    }
    if request.request_id.is_empty() {
        return Err("native_resident_health_invalid".to_owned());
    }
    let (evaluation, control) = crate::resident_transport::lane_shape();
    crate::encode_response(&ResidentHealthResultV1 {
        schema: RESIDENT_HEALTH_RESULT_SCHEMA.to_owned(),
        request_id: request.request_id.clone(),
        request_sha256,
        status: "serving".to_owned(),
        protocol_version: crate::RESIDENT_PROTOCOL_VERSION,
        runtime_version: crate::PACKAGE_VERSION.to_owned(),
        build_sha: crate::BUILD_SHA.to_owned(),
        target: format!("{}-{}", std::env::consts::ARCH, std::env::consts::OS),
        uptime_ms: uptime_ms(),
        evaluation: lane(QueueLane::Evaluation, evaluation.0, evaluation.1),
        control: lane(QueueLane::Control, control.0, control.1),
        overloaded_requests: OVERLOADED_REQUESTS.load(Ordering::Relaxed),
        counters: snapshot(),
    })
}

#[cfg(test)]
#[path = "resident_health_op_tests.rs"]
mod tests;
