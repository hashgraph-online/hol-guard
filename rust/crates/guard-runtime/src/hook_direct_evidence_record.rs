//! What a direct answer left to the daemon, recorded as its page leaves.
//!
//! The drain records a paged record whose receipt the resident has not
//! written yet: the receipt, then, for a tool answer the bound daemon let the
//! resident record, its command activity. A hook the resident held through a
//! policy update's fence also leaves its wait, which is saved as the fence
//! window event the daemon would record. This starts the hook evidence writer
//! with the source of the store the bound daemon publishes, as the daemon's
//! own submission would, and marks the queued record `receipt_recorded`,
//! `activity_recorded` and `fence_wait_recorded` for what the writer took, so
//! a page sent again does not record it twice. Whatever the writer refuses,
//! or a lane bound without a source, stays with the daemon.

use std::path::Path;

use guard_command::hook_evidence_writer::{
    RuntimeHookEvidenceWriter, POLICY_SOURCE_FENCE_WINDOW_EVENT,
};
use guard_command::local_supply_chain::Timestamp;
use serde_json::{json, Value};

use super::{DirectEvidenceQueue, Paged, RECEIPT_VALID};
use crate::edge_receipt::{DIRECT_ACTIVITY_RECORDED, DIRECT_RECEIPT_RECORDED};

/// The writer took the fence window this record's wait reports.
const FENCE_WAIT_RECORDED: &str = "fence_wait_recorded";
/// `hook_policy_fence_window.REBUILD_WAIT_SECONDS`, in milliseconds: no
/// window reports a longer wait than a hook may poll.
const REBUILD_WAIT_MS: u64 = 8_000;

fn flagged(record: &Value, field: &str) -> bool {
    record.get(field) == Some(&Value::Bool(true))
}

/// The fence wait a record reports and has not had recorded.
fn fence_wait_ms(record: &Value) -> Option<u64> {
    if flagged(record, FENCE_WAIT_RECORDED) {
        return None;
    }
    record
        .get("fence_wait_ms")
        .and_then(Value::as_u64)
        .filter(|waited| *waited > 0)
}

fn receipt_pending(paged: &Paged) -> bool {
    flagged(&paged.record, RECEIPT_VALID)
        && (!flagged(&paged.record, DIRECT_RECEIPT_RECORDED)
            || (paged.activity && !flagged(&paged.record, DIRECT_ACTIVITY_RECORDED)))
}

/// `PolicySourceFenceWindow.absorb_direct` for a wait no daemon window holds:
/// a window of its own that ends now and admitted the one hook.
fn submit_fence_window(writer: &RuntimeHookEvidenceWriter, waited_ms: u64) -> bool {
    let ended = Timestamp::now_utc();
    let waited = waited_ms.min(REBUILD_WAIT_MS) as f64 / 1_000.0;
    let ended_at = ended.isoformat();
    let Value::Object(payload) = json!({
        "started_at": ended.add_seconds_f64(-waited).isoformat(),
        "ended_at": ended_at,
        "absorbed_calls": 1,
        "exhausted_calls": 0,
    }) else {
        return false;
    };
    writer.submit_guard_event(POLICY_SOURCE_FENCE_WINDOW_EVENT, payload, &ended_at)
}

/// Record the receipts, the activity the bound daemon allowed and the fence
/// waits that the paged records still leave to the daemon, and mark them on
/// the page and in the queue. Returns the store failure the writer holds, or
/// `None` when the writer could not run, or no record needed it and none is
/// running.
pub(super) fn leftovers(
    queue: &DirectEvidenceQueue,
    guard_home: &str,
    source: &str,
    paged: &mut [Paged],
) -> Option<Value> {
    let pending = |paged: &Paged| receipt_pending(paged) || fence_wait_ms(&paged.record).is_some();
    if !paged.iter().any(pending) {
        // The writer saves on its own thread, so a store failure can follow
        // the page that gave it the last record.
        return crate::hook_evidence_writer_op::drained_fatal(Path::new(guard_home));
    }
    let (marks, fatal) =
        crate::hook_evidence_writer_op::record_drained(Path::new(guard_home), source, |writer| {
            let mut marks = Vec::new();
            for paged in paged.iter().filter(|paged| pending(paged)) {
                let mut recorded = Vec::new();
                if fence_wait_ms(&paged.record)
                    .is_some_and(|waited| submit_fence_window(writer, waited))
                {
                    recorded.push(FENCE_WAIT_RECORDED);
                }
                if receipt_pending(paged) {
                    let mut receipt_taken = flagged(&paged.record, DIRECT_RECEIPT_RECORDED);
                    if !receipt_taken {
                        receipt_taken = paged
                            .record
                            .get("receipt")
                            .and_then(Value::as_object)
                            .is_some_and(|receipt| writer.submit_native_decision_receipt(receipt));
                        if receipt_taken {
                            recorded.push(DIRECT_RECEIPT_RECORDED);
                        }
                    }
                    // The activity cites the receipt, so it follows one the writer took.
                    if receipt_taken
                        && paged.activity
                        && !flagged(&paged.record, DIRECT_ACTIVITY_RECORDED)
                        && crate::edge_receipt::submit_activity(writer, &paged.record)
                    {
                        recorded.push(DIRECT_ACTIVITY_RECORDED);
                    }
                }
                marks.push((paged.seq, recorded));
            }
            marks
        })?;
    let mut state = queue.state.lock().ok();
    for (seq, recorded) in &marks {
        if let Some(state) = state.as_mut() {
            state.mark(*seq, recorded);
        }
        let page = paged.iter_mut().find(|paged| paged.seq == *seq);
        if let Some(fields) = page.and_then(|paged| paged.record.as_object_mut()) {
            for marker in recorded {
                fields.insert((*marker).to_owned(), Value::Bool(true));
            }
        }
    }
    Some(fatal)
}
