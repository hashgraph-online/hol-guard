//! The edge records its own decision receipt.
//!
//! The daemon used to submit every edge answer's receipt to the hook evidence
//! writer in a second resident request. When the envelope asks for it, the
//! edge queues the receipt with the writer itself and says so in its answer,
//! so the daemon skips that request.
//!
//! Only a writer already running for the request's Guard home takes the
//! receipt: starting one replays its journal, and a stop drains it, neither of
//! which a hook answer waits for. Without a live writer free to take it, or
//! when the writer refuses it, the answer says nothing was recorded and the
//! daemon submits the receipt as before, which starts the writer. The receipt
//! is queued only once the answer is encoded, so a call that fails closed on
//! an answer too large to send leaves no receipt behind. It is queued before
//! the answer leaves, so it precedes the command activity that links to it.
//!
//! A hook the resident answers directly records its receipt the same way:
//! with a writer already running, the resident queues the receipt and marks
//! the evidence record it queues for the daemon's drain, which then submits
//! the rest of that record's evidence but not the receipt. For a `PreToolUse`
//! answer it queues the command activity behind that receipt as well and
//! marks the record for that too, which saves the drain another writer
//! request per hook.

use std::path::Path;
use std::time::Instant;

use guard_command::hook_evidence_writer::RuntimeHookEvidenceWriter;
use guard_contracts::{GuardHookEdgeResultV2, GuardHookEnvelopeV2};
use serde_json::Value;

use crate::hook_direct_evidence::DirectEvidenceQueue;
use crate::hook_evidence_writer_op as writer_op;

/// The resident feature under which an envelope may ask for this.
pub(crate) const EDGE_RECEIPT_RECORD_FEATURE: &str = "edge-receipt-record-v1";
/// The field of a direct answer's evidence record that says the resident
/// already queued its receipt with the writer.
const DIRECT_RECEIPT_RECORDED: &str = "receipt_recorded";
/// The field that says the resident queued its command activity as well.
const DIRECT_ACTIVITY_RECORDED: &str = "activity_recorded";

/// Encode the checked `edge`, recording its receipt when the envelope asked
/// and a writer runs for its Guard home. `resident` is false for a caller
/// outside the resident's own edge request, which never records.
pub(crate) fn encode(
    envelope: &GuardHookEnvelopeV2,
    resident: bool,
    edge: GuardHookEdgeResultV2,
    started: Instant,
) -> Result<Vec<u8>, String> {
    let mut edge = crate::edge_structured::attached(envelope, edge, started);
    if resident && envelope.record_receipt {
        edge.receipt_recorded = true;
        let recorded = writer_op::record_edge_receipt(
            Path::new(&envelope.source.guard_home),
            &edge.receipt,
            || crate::encode_response(&edge),
        );
        if let Some(encoded) = recorded {
            return encoded;
        }
        edge.receipt_recorded = false;
    }
    crate::encode_response(&edge)
}

/// Queue a direct answer's `evidence` for the drain, recording its receipt
/// and then, with `record_activity`, its command activity first when a writer
/// already runs for `guard_home`. The record carries `receipt_recorded` and
/// `activity_recorded` only for what that writer accepted; the drain submits
/// the rest itself, which starts the writer when none runs. False when the
/// queue cannot hold the record: nothing was queued or recorded, so the
/// daemon answering the hook records it once.
pub(crate) fn offer_direct(
    queue: &DirectEvidenceQueue,
    guard_home: &Path,
    evidence: Value,
    record_activity: bool,
) -> bool {
    if !evidence.get("receipt").is_some_and(Value::is_object) {
        return queue.offer(evidence);
    }
    let mut pending = Some(evidence);
    let queued = writer_op::record_direct(guard_home, |writer| {
        pending.take().is_some_and(|record| {
            let markers = [DIRECT_RECEIPT_RECORDED, DIRECT_ACTIVITY_RECORDED];
            queue
                .try_offer_recorded(record, &markers, |record| {
                    let Some(receipt) = record.get("receipt").and_then(Value::as_object) else {
                        return 0;
                    };
                    if !writer.submit_native_decision_receipt(receipt) {
                        return 0;
                    }
                    1 + usize::from(record_activity && submit_pre_tool_activity(writer, record))
                })
                .is_ok()
        })
    });
    queued.unwrap_or_else(|| pending.is_some_and(|record| queue.offer(record)))
}

/// Queue a direct `PreToolUse` answer's command activity as the drain would,
/// citing the receipt the writer just accepted. False leaves it to the drain,
/// which also gets any answer whose fields the activity cannot take.
fn submit_pre_tool_activity(writer: &RuntimeHookEvidenceWriter, record: &Value) -> bool {
    if record.get("event").and_then(Value::as_str) != Some("PreToolUse") {
        return false;
    }
    let (Some(harness), Some(payload), Some(response)) = (
        record.get("harness").and_then(Value::as_str),
        record.get("payload").and_then(Value::as_object),
        record.get("harness_response").and_then(Value::as_object),
    ) else {
        return false;
    };
    let policy_action = match response.get("policy_action") {
        None | Some(Value::Null) => None,
        Some(Value::String(action)) => Some(action.as_str()),
        Some(_) => return false,
    };
    let approval_reuse_status = match response.get("approval_reuse_status") {
        None => "not-applicable",
        Some(Value::String(status)) => status.as_str(),
        Some(_) => return false,
    };
    let receipt_id = record
        .get("receipt")
        .and_then(|receipt| receipt.get("decision_id"))
        .and_then(Value::as_str);
    writer.submit_command_activity(
        harness,
        "PreToolUse",
        payload,
        true,
        policy_action,
        receipt_id,
        response.get("prompted") == Some(&Value::Bool(true)),
        approval_reuse_status,
    )
}

#[cfg(test)]
#[path = "edge_receipt_tests.rs"]
mod tests;
