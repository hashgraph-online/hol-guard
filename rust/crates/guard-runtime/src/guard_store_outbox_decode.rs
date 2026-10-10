//! Authenticated decoding of stored Review outbox events: verifies the
//! integrity digest and the envelope/payload agreement, then projects the
//! immutable request snapshot.

use serde_json::{Map, Value};

use crate::guard_store_db::Row;
use crate::guard_store_json::py_strip;
use crate::guard_store_outbox_identity::payload_digest;

pub(crate) const EVENT_SCHEMA_NAME: &str = "guard-cloud-review-event-v2";
pub(crate) const EVENT_SCHEMA_VERSION: i64 = 1;

/// Columns of `approval_requests` captured in an event's request snapshot.
pub(crate) const SNAPSHOT_COLUMNS: [&str; 49] = [
    "request_id",
    "harness",
    "artifact_id",
    "artifact_name",
    "artifact_type",
    "artifact_hash",
    "publisher",
    "policy_action",
    "recommended_scope",
    "changed_fields_json",
    "source_scope",
    "oauth_source",
    "config_path",
    "workspace",
    "launch_target",
    "normalized_identity_key",
    "action_identity",
    "queue_group_id",
    "dedupe_count",
    "last_seen_at",
    "transport",
    "risk_summary",
    "risk_signals_json",
    "artifact_label",
    "source_label",
    "trigger_summary",
    "why_now",
    "launch_summary",
    "risk_headline",
    "action_envelope_json",
    "decision_v2_json",
    "fallback_cli_command",
    "scanner_evidence_json",
    "browser_intent_json",
    "continuation_snapshot_json",
    "desktop_notified_at",
    "raw_command_text",
    "guard_version",
    "first_seen_guard_version",
    "last_seen_guard_version",
    "watch_only_observation",
    "review_command",
    "approval_url",
    "status",
    "resolution_action",
    "resolution_scope",
    "reason",
    "created_at",
    "resolved_at",
];

/// Snapshot fields stored as JSON text.
pub(crate) const SNAPSHOT_JSON_FIELDS: [&str; 7] = [
    "action_envelope_json",
    "browser_intent_json",
    "continuation_snapshot_json",
    "changed_fields_json",
    "decision_v2_json",
    "risk_signals_json",
    "scanner_evidence_json",
];

const REQUIRED_NONEMPTY: [&str; 18] = [
    "request_id",
    "harness",
    "artifact_id",
    "artifact_name",
    "artifact_type",
    "artifact_hash",
    "policy_action",
    "recommended_scope",
    "changed_fields_json",
    "source_scope",
    "oauth_source",
    "config_path",
    "risk_signals_json",
    "scanner_evidence_json",
    "review_command",
    "approval_url",
    "status",
    "created_at",
];

const REQUEST_EVENT_TYPES: [&str; 4] = [
    "review.request.created",
    "review.request.refreshed",
    "review.request.resolved",
    "review.request.snapshot_requeued",
];
const CONTINUATION_STATUSES: [&str; 6] = [
    "resumed",
    "already_resumed",
    "manual_retry_required",
    "blocked_not_resumed",
    "unsupported",
    "failed",
];

/// An authenticated event.
pub(crate) struct StoredEvent {
    pub stream_sequence: i64,
    pub event_id: String,
    pub event_type: String,
    pub snapshot: Map<String, Value>,
}

fn nonblank(value: &Value) -> bool {
    value
        .as_str()
        .is_some_and(|text| !py_strip(text).is_empty())
}

fn decode_snapshot(payload: &Map<String, Value>) -> Option<Map<String, Value>> {
    let mut snapshot = payload.get("requestSnapshot")?.as_object()?.clone();
    if SNAPSHOT_COLUMNS
        .iter()
        .any(|name| *name != "continuation_snapshot_json" && !snapshot.contains_key(*name))
    {
        return None;
    }
    if snapshot
        .keys()
        .any(|key| !SNAPSHOT_COLUMNS.contains(&key.as_str()))
    {
        return None;
    }
    snapshot
        .entry("continuation_snapshot_json")
        .or_insert(Value::Null);
    if REQUIRED_NONEMPTY
        .iter()
        .any(|name| !nonblank(&snapshot[*name]))
    {
        return None;
    }
    for field in SNAPSHOT_JSON_FIELDS {
        if let Some(Value::String(text)) = snapshot.get(field) {
            let parsed = serde_json::from_str::<Value>(text).ok()?;
            snapshot.insert(field.to_owned(), parsed);
        }
    }
    Some(snapshot)
}

fn valid_continuation(payload: &Map<String, Value>, event_type: &str) -> bool {
    let result = payload.get("continuationResult");
    let Some(status) = event_type.strip_prefix("review.continuation.") else {
        return result.is_none() || result == Some(&Value::Null);
    };
    if !CONTINUATION_STATUSES.contains(&status) {
        return false;
    }
    let Some(Value::Object(result)) = result else {
        return false;
    };
    const FIELDS: [&str; 7] = [
        "action",
        "capability",
        "completedAt",
        "correlationId",
        "evidenceId",
        "reason",
        "status",
    ];
    result.len() == FIELDS.len()
        && FIELDS.iter().all(|field| result.contains_key(*field))
        && result.get("status").and_then(Value::as_str) == Some(status)
        && matches!(
            result.get("action").and_then(Value::as_str),
            Some("allow_once" | "block")
        )
        && [
            "capability",
            "completedAt",
            "correlationId",
            "evidenceId",
            "reason",
        ]
        .iter()
        .all(|field| nonblank(&result[*field]))
}

/// Authenticate one stored event row; `None` when it cannot be trusted.
pub(crate) fn decode_stored_event(row: &Row) -> Option<StoredEvent> {
    if row.get("event_schema_version")?.as_i64()? != EVENT_SCHEMA_VERSION {
        return None;
    }
    let payload_json = row.get("payload_json")?.as_str()?;
    let payload_hash = row.get("payload_hash")?.as_str()?;
    let null = Value::Null;
    let field = |name: &str| row.get(name).unwrap_or(&null);
    let actual = payload_digest(
        payload_json,
        [
            field("oauth_source"),
            field("oauth_subject_hash"),
            field("workspace_id"),
            field("machine_id"),
            field("machine_installation_id"),
        ],
    );
    if !constant_time_equal(actual.as_bytes(), payload_hash.as_bytes()) {
        return None;
    }
    let Value::Object(payload) = serde_json::from_str::<Value>(payload_json).ok()? else {
        return None;
    };
    let event_type = row.get("event_type")?.as_str()?;
    let local_request_id = row.get("local_request_id")?;
    let wire_known =
        REQUEST_EVENT_TYPES.contains(&event_type) || event_type.starts_with("review.continuation.");
    if !wire_known
        || payload.get("schema").and_then(Value::as_str) != Some(EVENT_SCHEMA_NAME)
        || payload.get("eventType").and_then(Value::as_str) != Some(event_type)
        || payload.get("localRequestId") != Some(local_request_id)
    {
        return None;
    }
    let oauth_source = field("oauth_source");
    if payload.get("oauthSource").unwrap_or(&null) != oauth_source {
        return None;
    }
    match payload.get("nativeReplay") {
        None | Some(Value::Null) => {}
        Some(Value::Bool(_)) if event_type == "review.request.snapshot_requeued" => {}
        Some(_) => return None,
    }
    let snapshot = decode_snapshot(&payload)?;
    if !valid_continuation(&payload, event_type) {
        return None;
    }
    if snapshot.get("request_id") != Some(local_request_id)
        || snapshot.get("oauth_source").unwrap_or(&null)
            != payload.get("oauthSource").unwrap_or(&null)
    {
        return None;
    }
    row.get("request_sequence")?.as_i64()?;
    Some(StoredEvent {
        stream_sequence: row.get("stream_sequence")?.as_i64()?,
        event_id: row.get("event_id")?.as_str()?.to_owned(),
        event_type: event_type.to_owned(),
        snapshot,
    })
}

fn constant_time_equal(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .zip(right)
            .fold(0_u8, |acc, (a, b)| acc | (a ^ b))
            == 0
}
