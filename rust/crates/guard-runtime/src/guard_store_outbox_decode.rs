//! Authenticated decoding of stored Review outbox events: verifies the
//! integrity digest and the envelope/payload agreement, then projects the
//! immutable request snapshot.

use serde_json::{Map, Value};

use crate::cloud_review_ack::py_repr;
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
    pub request_sequence: i64,
    pub event_id: String,
    pub event_type: String,
    pub native_replay: Option<bool>,
    pub continuation_result: Option<Map<String, Value>>,
    pub snapshot: Map<String, Value>,
}

/// Why a stored event cannot be trusted: its quarantine reason and message.
pub(crate) struct Refusal {
    pub reason: &'static str,
    pub message: String,
}

fn refuse<T>(reason: &'static str, message: impl Into<String>) -> Result<T, Refusal> {
    Err(Refusal {
        reason,
        message: message.into(),
    })
}

fn nonblank(value: &Value) -> bool {
    value
        .as_str()
        .is_some_and(|text| !py_strip(text).is_empty())
}

fn decode_snapshot(payload: &Map<String, Value>) -> Result<Map<String, Value>, Refusal> {
    let raw = match payload.get("requestSnapshot") {
        None | Some(Value::Null) => {
            return refuse(
                "payload_snapshot_missing",
                "Stored Review event has no immutable request snapshot.",
            )
        }
        Some(raw) => raw,
    };
    let Some(snapshot) = raw.as_object() else {
        return refuse(
            "payload_snapshot_invalid",
            "Stored Review event request snapshot is invalid.",
        );
    };
    let mut snapshot = snapshot.clone();
    let mut missing: Vec<&str> = SNAPSHOT_COLUMNS
        .iter()
        .copied()
        .filter(|name| *name != "continuation_snapshot_json" && !snapshot.contains_key(*name))
        .collect();
    if !missing.is_empty() {
        missing.sort_unstable();
        return refuse(
            "payload_snapshot_incomplete",
            format!(
                "Stored Review event snapshot is missing canonical fields: {}.",
                missing.join(", ")
            ),
        );
    }
    let mut unexpected: Vec<&str> = snapshot
        .keys()
        .map(String::as_str)
        .filter(|key| !SNAPSHOT_COLUMNS.contains(key))
        .collect();
    if !unexpected.is_empty() {
        unexpected.sort_unstable();
        return refuse(
            "payload_snapshot_unexpected_fields",
            format!(
                "Stored Review event snapshot has unexpected fields: {}.",
                unexpected.join(", ")
            ),
        );
    }
    snapshot
        .entry("continuation_snapshot_json")
        .or_insert(Value::Null);
    let invalid: Vec<&str> = REQUIRED_NONEMPTY
        .iter()
        .copied()
        .filter(|name| !nonblank(&snapshot[*name]))
        .collect();
    if !invalid.is_empty() {
        return refuse(
            "payload_snapshot_incomplete",
            format!(
                "Stored Review event snapshot has invalid canonical fields: {}.",
                invalid.join(", ")
            ),
        );
    }
    for field in SNAPSHOT_JSON_FIELDS {
        if let Some(Value::String(text)) = snapshot.get(field) {
            let Ok(parsed) = serde_json::from_str::<Value>(text) else {
                return refuse(
                    "payload_snapshot_invalid",
                    format!("Stored Review event snapshot field {field} is invalid JSON."),
                );
            };
            snapshot.insert(field.to_owned(), parsed);
        }
    }
    Ok(snapshot)
}

fn decode_continuation(
    payload: &Map<String, Value>,
    event_type: &str,
) -> Result<Option<Map<String, Value>>, Refusal> {
    let result = payload
        .get("continuationResult")
        .filter(|value| !value.is_null());
    let Some(status) = event_type.strip_prefix("review.continuation.") else {
        if result.is_some() {
            return refuse(
                "payload_continuation_unexpected",
                "Stored Review request event contains unexpected continuation evidence.",
            );
        }
        return Ok(None);
    };
    let Some(Value::Object(result)) = result else {
        return refuse(
            "payload_continuation_missing",
            "Stored Review continuation event has no terminal result.",
        );
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
    const INVALID: &str = "payload_continuation_invalid";
    if result.len() != FIELDS.len() || !FIELDS.iter().all(|field| result.contains_key(*field)) {
        return refuse(
            INVALID,
            "Stored Review continuation result fields are invalid.",
        );
    }
    if result.get("status").and_then(Value::as_str) != Some(status) {
        return refuse(
            INVALID,
            "Stored Review continuation status does not match its event.",
        );
    }
    if !matches!(
        result.get("action").and_then(Value::as_str),
        Some("allow_once" | "block")
    ) {
        return refuse(INVALID, "Stored Review continuation action is invalid.");
    }
    if ![
        "capability",
        "completedAt",
        "correlationId",
        "evidenceId",
        "reason",
    ]
    .iter()
    .all(|field| nonblank(&result[*field]))
    {
        return refuse(INVALID, "Stored Review continuation result is incomplete.");
    }
    Ok(Some(result.clone()))
}

fn known_event_type(event_type: &str) -> bool {
    REQUEST_EVENT_TYPES.contains(&event_type)
        || event_type
            .strip_prefix("review.continuation.")
            .is_some_and(|status| CONTINUATION_STATUSES.contains(&status))
}

/// Authenticate one stored event row; `None` when it cannot be trusted.
pub(crate) fn decode_stored_event(row: &Row) -> Option<StoredEvent> {
    decode_checked(row).ok()
}

/// Authenticate one stored event row, or say why it cannot be trusted.
pub(crate) fn decode_checked(row: &Row) -> Result<StoredEvent, Refusal> {
    let null = Value::Null;
    let field = |name: &str| row.get(name).unwrap_or(&null);
    let version = field("event_schema_version");
    if version.as_i64() != Some(EVENT_SCHEMA_VERSION) {
        return refuse(
            "unsupported_event_schema",
            format!(
                "Unsupported Review event schema version: {}.",
                py_repr(version)
            ),
        );
    }
    let (Some(payload_json), Some(payload_hash)) = (
        field("payload_json").as_str(),
        field("payload_hash").as_str(),
    ) else {
        return refuse(
            "payload_hash_mismatch",
            "Stored Review event payload metadata is invalid.",
        );
    };
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
        return refuse(
            "payload_hash_mismatch",
            "Stored Review event payload integrity check failed.",
        );
    }
    let payload = match serde_json::from_str::<Value>(payload_json) {
        Ok(Value::Object(payload)) => payload,
        Ok(_) => {
            return refuse(
                "payload_json_invalid",
                "Stored Review event payload is not an object.",
            )
        }
        Err(_) => {
            return refuse(
                "payload_json_invalid",
                "Stored Review event payload is invalid JSON.",
            )
        }
    };
    let event_type = match field("event_type").as_str() {
        Some(event_type) if known_event_type(event_type) => event_type,
        _ => {
            return refuse(
                "unsupported_event_type",
                format!(
                    "Unsupported Review event type: {}.",
                    py_repr(field("event_type"))
                ),
            )
        }
    };
    let local_request_id = field("local_request_id");
    if payload.get("schema").and_then(Value::as_str) != Some(EVENT_SCHEMA_NAME)
        || payload.get("eventType").and_then(Value::as_str) != Some(event_type)
        || payload.get("localRequestId").unwrap_or(&null) != local_request_id
    {
        return refuse(
            "payload_metadata_mismatch",
            "Stored Review event payload does not match its authenticated envelope.",
        );
    }
    let payload_source = payload.get("oauthSource").unwrap_or(&null);
    if payload_source != field("oauth_source") {
        return refuse(
            "payload_source_binding_mismatch",
            "Stored Review event OAuth source does not match its delivery binding.",
        );
    }
    let native_replay = match payload.get("nativeReplay") {
        None | Some(Value::Null) => None,
        Some(Value::Bool(flag)) if event_type == "review.request.snapshot_requeued" => Some(*flag),
        Some(_) => {
            return refuse(
                "payload_native_replay_invalid",
                "Stored Review event native replay discriminator is invalid.",
            )
        }
    };
    let snapshot = decode_snapshot(&payload)?;
    let continuation_result = decode_continuation(&payload, event_type)?;
    if snapshot.get("request_id") != Some(local_request_id) {
        return refuse(
            "payload_snapshot_request_mismatch",
            "Stored Review event snapshot request does not match its authenticated envelope.",
        );
    }
    if snapshot.get("oauth_source").unwrap_or(&null) != payload_source {
        return refuse(
            "payload_snapshot_source_mismatch",
            "Stored Review event snapshot OAuth source does not match its authenticated envelope.",
        );
    }
    let (Some(stream_sequence), Some(request_sequence), Some(event_id)) = (
        field("stream_sequence").as_i64(),
        field("request_sequence").as_i64(),
        field("event_id").as_str(),
    ) else {
        return refuse(
            "payload_metadata_mismatch",
            "Stored Review event sequence metadata is invalid.",
        );
    };
    Ok(StoredEvent {
        stream_sequence,
        request_sequence,
        event_id: event_id.to_owned(),
        event_type: event_type.to_owned(),
        native_replay,
        continuation_result,
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
