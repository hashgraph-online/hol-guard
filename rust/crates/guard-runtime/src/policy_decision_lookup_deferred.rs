//! A lookup on a snapshot the caller cannot write to: the audit events the
//! lookup raises are handed back rather than written, so the caller writes
//! them on a connection it can.

use rusqlite::Connection;
use serde_json::Value;

use guard_contracts::{
    canonical_utc_timestamp, PolicyDecisionLookupRequestV1, POLICY_DECISION_LOOKUP_REQUEST_SCHEMA,
};

use super::{canonical_json, evaluate_in_connection};

/// One audit event a lookup raised: its name, payload and the lookup's time.
pub(crate) type AuditEvent = (String, Value, String);

/// Write the events, or hand them to `deferred` when the caller collects them.
pub(super) fn emit_events(
    conn: &Connection,
    events: &[(String, Value)],
    current_time: &str,
    deferred: &mut Option<&mut Vec<AuditEvent>>,
) -> rusqlite::Result<()> {
    match deferred {
        Some(sink) => {
            sink.extend(
                events.iter().map(|(name, payload)| {
                    (name.clone(), payload.clone(), current_time.to_owned())
                }),
            );
            Ok(())
        }
        // `_flush_events`: a failed insert aborts the lookup rather than
        // silently dropping the event.
        None => events
            .iter()
            .try_for_each(|(name, payload)| insert_event(conn, name, payload, current_time)),
    }
}

/// `evaluate_non_consuming`, with the audit events it raises appended to
/// `deferred` instead of written to the store.
pub(crate) fn evaluate_non_consuming_deferred(
    request: &PolicyDecisionLookupRequestV1,
    conn: &Connection,
    deferred: &mut Vec<AuditEvent>,
) -> Result<Value, String> {
    if request.consume_one_shot
        || request.portable_workspace.is_some()
        || request.evidence_binding.is_some()
        || request.schema != POLICY_DECISION_LOOKUP_REQUEST_SCHEMA
    {
        return Err("native_policy_decision_lookup_invalid".to_owned());
    }
    let current_time = canonical_utc_timestamp(&request.now)
        .ok_or_else(|| "native_policy_decision_lookup_invalid_now".to_owned())?;
    // Collected apart first, so a lookup that fails leaves `deferred` as it was.
    let mut raised = Vec::new();
    let payload = evaluate_in_connection(request, conn, &current_time, &mut Some(&mut raised))?;
    deferred.append(&mut raised);
    Ok(payload)
}

/// Write events a deferred lookup raised, each at the time its lookup ran.
/// A failed insert propagates, as it does for a lookup that writes its own.
pub(crate) fn write_audit_events(conn: &Connection, events: &[AuditEvent]) -> rusqlite::Result<()> {
    events
        .iter()
        .try_for_each(|(name, payload, occurred_at)| insert_event(conn, name, payload, occurred_at))
}

/// The one `guard_events` row every lookup audit event is written as.
fn insert_event(
    conn: &Connection,
    name: &str,
    payload: &Value,
    occurred_at: &str,
) -> rusqlite::Result<()> {
    conn.execute(
        "insert into guard_events (event_name, payload_json, occurred_at) values (?, ?, ?)",
        rusqlite::params![name, canonical_json(payload), occurred_at],
    )
    .map(|_| ())
}
