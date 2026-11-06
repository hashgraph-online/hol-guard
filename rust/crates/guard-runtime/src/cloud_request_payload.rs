//! Cloud-safe local request payload (`local_request_snapshots.py`
//! `_cloud_safe_local_request_payload` and `_optional_payload_mapping`).

use guard_contracts::{normalize_guard_action_result, GuardAction};
use serde_json::{json, Map, Value};

use super::cloud_action_envelope::{
    cloud_safe_action_envelope, EnvelopeContext, ERR_DECISION_INCONSISTENT,
};
use super::cloud_request_text::{
    first_optional_string, optional_string, py_strip, scrubbed_command, scrubbed_text,
};

const PAYLOAD_KEYS: [&str; 25] = [
    "request_id",
    "status",
    "harness",
    "artifact_id",
    "artifact_name",
    "artifact_type",
    "artifact_hash",
    "artifact_label",
    "source_label",
    "trigger_summary",
    "why_now",
    "risk_headline",
    "risk_summary",
    "policy_action",
    "recommended_scope",
    "created_at",
    "last_seen_at",
    "queue_group_id",
    "review_kind",
    "risk_category",
    "capability_category",
    "publisher",
    "package_manager",
    "package_name",
    "resolution_action",
];
const EXTRA_PAYLOAD_KEYS: [&str; 1] = ["resolution_scope"];
const COMMAND_KEYS: [&str; 4] = [
    "raw_command_text",
    "rawCommandText",
    "command_text",
    "commandText",
];

fn malformed(reason: &str) -> Map<String, Value> {
    let Value::Object(map) = json!({
        "action_type": "unknown",
        "operation": "parse_action_envelope",
        "malformed": true,
        "reason": reason,
    }) else {
        unreachable!("object literal");
    };
    map
}

/// `_optional_payload_mapping`.
pub(crate) fn optional_payload_mapping(value: Option<&Value>) -> Option<Map<String, Value>> {
    match value? {
        Value::Object(map) => Some(map.clone()),
        Value::String(text) if !py_strip(text).is_empty() => {
            Some(match serde_json::from_str::<Value>(text) {
                Ok(Value::Object(map)) => map,
                Ok(_) => malformed("non_object_action_envelope"),
                Err(_) => malformed("invalid_action_envelope"),
            })
        }
        _ => None,
    }
}

/// `_local_request_command_text`.
pub(crate) fn local_request_command_text(
    item: &Map<String, Value>,
    envelope: Option<&Map<String, Value>>,
) -> Option<String> {
    COMMAND_KEYS
        .iter()
        .find_map(|key| optional_string(item.get(*key)))
        .or_else(|| envelope.and_then(|map| optional_string(map.get("command"))))
        .map(str::to_owned)
}

/// `_cloud_safe_local_request_payload`.
pub(crate) fn cloud_safe_local_request_payload(
    item: &Map<String, Value>,
    redaction_level: &str,
    routing: Option<&Map<String, Value>>,
) -> Result<Map<String, Value>, &'static str> {
    let mut payload = Map::new();
    for key in PAYLOAD_KEYS.iter().chain(EXTRA_PAYLOAD_KEYS.iter()) {
        match item.get(*key) {
            Some(Value::String(text)) => {
                payload.insert((*key).to_owned(), Value::String(scrubbed_text(text)));
            }
            Some(scalar @ (Value::Number(_) | Value::Bool(_))) => {
                payload.insert((*key).to_owned(), scalar.clone());
            }
            None | Some(Value::Null) => {
                payload.insert((*key).to_owned(), Value::Null);
            }
            Some(_) => {}
        }
    }
    let raw_action = item.get("policy_action").unwrap_or(&Value::Null);
    let normalized = normalize_guard_action_result(raw_action, GuardAction::RequireReapproval);
    // Rows that predate `policy_action` stay syncable through the fail-closed
    // projection; an explicit unknown value is a corrupt authority contract.
    if normalized.reason_code.is_some() && !raw_action.is_null() {
        return Err(ERR_DECISION_INCONSISTENT);
    }
    let action_text = Value::String(normalized.action.as_str().to_owned());
    payload.insert("policy_action".to_owned(), action_text.clone());
    payload.insert("policyAction".to_owned(), action_text);
    if payload.get("status") == Some(&Value::String("expired".to_owned())) {
        payload.insert("status".to_owned(), Value::String("pending".to_owned()));
    }
    if let Some(routing) = routing {
        payload.extend(
            routing
                .iter()
                .map(|(key, value)| (key.clone(), value.clone())),
        );
    }
    let redaction_enabled = redaction_level != "none";
    payload.insert(
        "redaction_enabled".to_owned(),
        Value::Bool(redaction_enabled),
    );
    payload.insert(
        "redactionEnabled".to_owned(),
        Value::Bool(redaction_enabled),
    );

    let envelope = optional_payload_mapping(item.get("action_envelope_json"));
    let reason = first_optional_string(
        item,
        &[
            "risk_summary",
            "why_now",
            "trigger_summary",
            "risk_headline",
            "policy_action",
        ],
    );
    let context = EnvelopeContext {
        redaction_level,
        reason,
        policy_action: normalized.action,
        fallback_action_id: optional_string(item.get("request_id")),
        fallback_harness: optional_string(item.get("harness")),
    };
    let mut safe_envelope = cloud_safe_action_envelope(envelope.as_ref(), &context)?;
    let command_text = local_request_command_text(item, envelope.as_ref());
    let scrubbed = command_text.as_deref().map(scrubbed_command);
    if redaction_enabled {
        for key in ["raw_command_text", "rawCommandText"] {
            payload.insert(key.to_owned(), Value::Null);
        }
    } else if let (Some(command), Some(map)) = (scrubbed.as_ref(), safe_envelope.as_mut()) {
        map.insert("command".to_owned(), Value::String(command.clone()));
    }
    if let Some(map) = safe_envelope {
        let value = Value::Object(map);
        payload.insert("action_envelope_json".to_owned(), value.clone());
        payload.insert("actionEnvelope".to_owned(), value.clone());
        if redaction_enabled {
            payload.insert("envelope_redacted".to_owned(), value.clone());
            payload.insert("envelopeRedacted".to_owned(), value);
        }
    }
    let command_value = scrubbed.map_or(Value::Null, Value::String);
    payload.insert("command_text".to_owned(), command_value.clone());
    payload.insert("commandText".to_owned(), command_value.clone());
    if !redaction_enabled {
        payload.insert("raw_command_text".to_owned(), command_value.clone());
        payload.insert("rawCommandText".to_owned(), command_value);
    }
    Ok(payload)
}
