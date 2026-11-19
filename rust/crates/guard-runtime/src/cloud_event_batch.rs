//! How many queued Guard events one upload body can carry.

use serde_json::Value;

use super::EVENTS_BODY_LIMIT;

/// `{"events":[]}`.
const EVENTS_BODY_OVERHEAD: usize = 13;

/// The leading events whose upload body fits the egress broker's request limit;
/// the rest go in the next round. One event always goes; [`too_large_alone`]
/// tells whether that one can go at all.
pub(super) fn batch_within_body_limit(pending: &[Value]) -> Vec<Value> {
    let mut size = EVENTS_BODY_OVERHEAD;
    let mut payloads = Vec::new();
    for event in pending {
        let payload = event.get("payload").cloned().unwrap_or(Value::Null);
        size += serde_json::to_vec(&payload).map_or(0, |bytes| bytes.len()) + 1;
        if !payloads.is_empty() && size > EVENTS_BODY_LIMIT {
            break;
        }
        payloads.push(payload);
    }
    payloads
}

/// The id of a lone event no upload body can carry: the broker refuses a body
/// above its limit before any request, so the event could never leave and
/// would hold back every event queued after it.
pub(super) fn too_large_alone(payloads: &[Value]) -> Option<String> {
    let [payload] = payloads else {
        return None;
    };
    let size = EVENTS_BODY_OVERHEAD + serde_json::to_vec(payload).map_or(0, |bytes| bytes.len());
    if size <= EVENTS_BODY_LIMIT {
        return None;
    }
    payload
        .get("eventId")
        .and_then(Value::as_str)
        .map(str::to_owned)
}
