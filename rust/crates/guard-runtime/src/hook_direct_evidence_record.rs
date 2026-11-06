//! What a direct answer left to the daemon, recorded as its page leaves.
//!
//! The drain records a paged record whose receipt the resident has not
//! written yet: the receipt, then, for a tool answer the bound daemon let the
//! resident record, its command activity. This starts the hook evidence
//! writer with the source of the store the bound daemon publishes, as the
//! daemon's own submission would, and marks the queued record
//! `receipt_recorded` and `activity_recorded` for what the writer took, so a
//! page sent again does not record it twice. Whatever the writer refuses, or
//! a lane bound without a source, stays with the daemon.

use std::path::Path;

use serde_json::Value;

use super::{DirectEvidenceQueue, Paged, RECEIPT_VALID};
use crate::edge_receipt::{DIRECT_ACTIVITY_RECORDED, DIRECT_RECEIPT_RECORDED};

/// Record the receipts, and the activity the bound daemon allowed, that the
/// paged records still leave to the daemon, and mark them on the page and in
/// the queue. Returns the store failure the writer holds, or `None` when no
/// record needed the writer or it could not run.
pub(super) fn leftovers(
    queue: &DirectEvidenceQueue,
    guard_home: &str,
    source: &str,
    paged: &mut [Paged],
) -> Option<Value> {
    let flagged = |record: &Value, field: &str| record.get(field) == Some(&Value::Bool(true));
    let pending = |paged: &Paged| {
        flagged(&paged.record, RECEIPT_VALID)
            && (!flagged(&paged.record, DIRECT_RECEIPT_RECORDED)
                || (paged.activity && !flagged(&paged.record, DIRECT_ACTIVITY_RECORDED)))
    };
    if !paged.iter().any(pending) {
        return None;
    }
    let (marks, fatal) =
        crate::hook_evidence_writer_op::record_drained(Path::new(guard_home), source, |writer| {
            let mut marks = Vec::new();
            for paged in paged.iter().filter(|paged| pending(*paged)) {
                let mut recorded = Vec::new();
                if !flagged(&paged.record, DIRECT_RECEIPT_RECORDED) {
                    let Some(receipt) = paged.record.get("receipt").and_then(Value::as_object)
                    else {
                        continue;
                    };
                    if !writer.submit_native_decision_receipt(receipt) {
                        continue;
                    }
                    recorded.push(DIRECT_RECEIPT_RECORDED);
                }
                // The activity cites the receipt, so it follows one the writer took.
                if paged.activity
                    && !flagged(&paged.record, DIRECT_ACTIVITY_RECORDED)
                    && crate::edge_receipt::submit_activity(writer, &paged.record)
                {
                    recorded.push(DIRECT_ACTIVITY_RECORDED);
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
