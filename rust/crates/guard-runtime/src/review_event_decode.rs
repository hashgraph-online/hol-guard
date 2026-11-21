//! `review_event_decode` runner-authority kind: authenticate one stored
//! Review outbox event for Cloud delivery.
//!
//! `runtime/review_event_delivery.py` reads the outbox row and projects the
//! decoded event for Cloud. What it asks here is whether the row's integrity
//! digest, envelope and payload agree, and what immutable request snapshot
//! the row carries.
//!
//! The request is `{"row": {...}}`: the stored row's columns. It answers
//! `{"event": {...}}` with the decoded snapshot (JSON text fields parsed), the
//! terminal continuation result, the native replay discriminator, the
//! sequences and the Cloud wire event type, or `{"reason": str, "message":
//! str}` naming why the row is quarantined.

use serde_json::{json, Value};

use crate::guard_store_outbox_decode::decode_checked;
use crate::runner_authority_detector::args_object;
use crate::runner_authority_op::{KindResult, ERR_INVALID};

pub(crate) fn dispatch(args: &Value) -> KindResult {
    let row = args_object(args)?
        .get("row")
        .and_then(Value::as_object)
        .ok_or(ERR_INVALID)?;
    Ok(match decode_checked(row) {
        Ok(event) => json!({
            "event": {
                "continuation_result": event.continuation_result,
                "event_id": event.event_id,
                "wire_event_type": wire_event_type(&event.event_type),
                "event_type": event.event_type,
                "native_replay": event.native_replay,
                "request_sequence": event.request_sequence,
                "snapshot": event.snapshot,
                "stream_sequence": event.stream_sequence,
            }
        }),
        Err(refusal) => json!({ "reason": refusal.reason, "message": refusal.message }),
    })
}

/// The Cloud event type a stored event type is delivered as.
fn wire_event_type(event_type: &str) -> String {
    match event_type.strip_prefix("review.continuation.") {
        Some(status) => format!("continuation_{status}"),
        None if event_type == "review.request.resolved" => "request_resolved".to_owned(),
        None => "request_created".to_owned(),
    }
}

#[cfg(test)]
#[path = "review_event_decode_tests.rs"]
mod tests;
