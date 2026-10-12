//! Cloud-safe action envelope projection (`local_request_snapshots.py`
//! `_cloud_safe_action_envelope` and helpers). The projection never carries an
//! action other than the authoritative one: an envelope that names a
//! different action is a corrupt authority contract and is refused.

use guard_contracts::{is_action_bearing_key, normalize_guard_action_result, GuardAction};
use serde_json::{Map, Value};

use super::cloud_action_envelope_fields::{
    operation_for_action_type, preserve_portal_fields, target_class_for_action_type,
    target_count_for_envelope,
};
use super::cloud_request_text::{
    bounded_cloud_value, bounded_text, first_optional_string, is_py_int, optional_string, py_eq,
    py_strip, scrubbed_command, scrubbed_text, set_dual_key,
};

pub(crate) const ERR_DECISION_INCONSISTENT: &str = "native_runner_authority_decision_inconsistent";

const ALLOWED_ACTION_FIELDS: [&str; 8] = [
    "action_id",
    "action_type",
    "policy_action",
    "pre_execution_result",
    "actionId",
    "actionType",
    "policyAction",
    "preExecutionResult",
];
const DASHBOARD_ACTION_TYPES: [&str; 10] = [
    "prompt",
    "shell_command",
    "file_read",
    "file_write",
    "mcp_tool",
    "package_script",
    "network_request",
    "config_change",
    "browser_action",
    "harness_start",
];
const COPIED_SCALAR_KEYS: [&str; 12] = [
    "schema_version",
    "harness",
    "event_name",
    "workspace_hash",
    "tool_name",
    "mcp_server",
    "mcp_tool",
    "target_path_count",
    "network_host_count",
    "package_manager",
    "malformed",
    "reason",
];
const NULLABLE_FIELDS: [&str; 10] = [
    "workspace",
    "workspace_hash",
    "tool_name",
    "command",
    "prompt_excerpt",
    "mcp_server",
    "mcp_tool",
    "package_manager",
    "package_name",
    "script_name",
];
const ALIAS_PAIRS: [(&str, &str); 20] = [
    ("schema_version", "schemaVersion"),
    ("action_id", "actionId"),
    ("action_type", "actionType"),
    ("policy_action", "policyAction"),
    ("pre_execution_result", "preExecutionResult"),
    ("workspace_hash", "workspaceHash"),
    ("tool_name", "toolName"),
    ("mcp_server", "mcpServer"),
    ("mcp_tool", "mcpTool"),
    ("package_manager", "packageManager"),
    ("package_name", "packageName"),
    ("package_targets", "packageTargets"),
    ("target_paths", "targetPaths"),
    ("network_hosts", "networkHosts"),
    ("target_resource", "targetResource"),
    ("source_path", "sourcePath"),
    ("skill_name", "skillName"),
    ("requested_permission", "requestedPermission"),
    ("access_mode", "accessMode"),
    ("content_state", "contentState"),
];
pub(crate) struct EnvelopeContext<'a> {
    pub redaction_level: &'a str,
    pub reason: Option<&'a str>,
    pub policy_action: GuardAction,
    pub fallback_action_id: Option<&'a str>,
    pub fallback_harness: Option<&'a str>,
}

/// `_matching_action_envelope_alias`.
fn matching_alias<'a>(
    envelope: &'a Map<String, Value>,
    snake: &str,
    camel: &str,
) -> Result<Option<&'a Value>, &'static str> {
    if let (Some(left), Some(right)) = (envelope.get(snake), envelope.get(camel)) {
        if !py_eq(left, right) {
            return Err(ERR_DECISION_INCONSISTENT);
        }
    }
    Ok(envelope.get(snake).or_else(|| envelope.get(camel)))
}

fn scalar_or_null(value: Option<&Value>) -> Option<Value> {
    match value {
        None | Some(Value::Null) => Some(Value::Null),
        Some(Value::String(text)) => Some(Value::String(bounded_text(text))),
        Some(scalar @ (Value::Number(_) | Value::Bool(_))) => Some(scalar.clone()),
        Some(_) => None,
    }
}

fn stripped_string(value: Option<&Value>) -> Option<&str> {
    value
        .and_then(Value::as_str)
        .map(py_strip)
        .filter(|text| !text.is_empty())
}

/// `_cloud_safe_action_envelope`; `Ok(None)` for an absent envelope.
pub(crate) fn cloud_safe_action_envelope(
    envelope: Option<&Map<String, Value>>,
    context: &EnvelopeContext,
) -> Result<Option<Map<String, Value>>, &'static str> {
    let Some(envelope) = envelope else {
        return Ok(None);
    };
    if envelope
        .keys()
        .any(|key| is_action_bearing_key(key) && !ALLOWED_ACTION_FIELDS.contains(&key.as_str()))
    {
        return Err(ERR_DECISION_INCONSISTENT);
    }
    let action_id = matching_alias(envelope, "action_id", "actionId")?;
    let action_type_value = matching_alias(envelope, "action_type", "actionType")?;
    let policy_value = matching_alias(envelope, "policy_action", "policyAction")?;
    let pre_execution = matching_alias(envelope, "pre_execution_result", "preExecutionResult")?;
    let mut safe = Map::new();
    for key in COPIED_SCALAR_KEYS {
        if let Some(value) = scalar_or_null(envelope.get(key)) {
            safe.insert(key.to_owned(), value);
        }
    }
    if let Some(text) = stripped_string(action_id) {
        safe.insert("action_id".to_owned(), Value::String(bounded_text(text)));
    }
    if let Some(text) = stripped_string(action_type_value) {
        safe.insert("action_type".to_owned(), Value::String(bounded_text(text)));
    }
    for (key, raw) in [
        ("policy_action", policy_value),
        ("pre_execution_result", pre_execution),
    ] {
        let Some(raw) = raw.filter(|value| !value.is_null()) else {
            continue;
        };
        let normalized = normalize_guard_action_result(raw, GuardAction::RequireReapproval);
        if normalized.reason_code.is_some() || normalized.action != context.policy_action {
            return Err(ERR_DECISION_INCONSISTENT);
        }
        safe.insert(
            key.to_owned(),
            Value::String(normalized.action.as_str().to_owned()),
        );
    }
    safe.insert(
        "policy_action".to_owned(),
        Value::String(context.policy_action.as_str().to_owned()),
    );
    let action_type = optional_string(action_type_value);
    let operation = first_optional_string(envelope, &["operation"]);
    if let Some(kind) = action_type {
        set_dual_key(
            &mut safe,
            "action_type",
            "actionType",
            &Value::String(kind.to_owned()),
        );
    }
    if let Some(resolved) = operation.or_else(|| operation_for_action_type(action_type)) {
        safe.insert(
            "operation".to_owned(),
            Value::String(bounded_text(resolved)),
        );
    }
    let redaction_enabled = context.redaction_level != "none";
    if let Some(Value::String(command)) = envelope.get("command") {
        if !py_strip(command).is_empty() {
            safe.insert(
                "command".to_owned(),
                Value::String(scrubbed_command(command)),
            );
        }
    }
    if redaction_enabled {
        let target_class = target_class_for_action_type(action_type, envelope);
        set_dual_key(
            &mut safe,
            "target_class",
            "targetClass",
            &Value::String(target_class.to_owned()),
        );
        let count = target_count_for_envelope(envelope);
        set_dual_key(
            &mut safe,
            "target_count",
            "targetCount",
            &Value::from(count),
        );
        let redacted_reason = context
            .reason
            .or_else(|| first_optional_string(envelope, &["reason", "pre_execution_result"]));
        if let Some(reason) = redacted_reason {
            safe.insert("reason".to_owned(), Value::String(bounded_text(reason)));
        }
    } else {
        for key in [
            "target_paths",
            "network_hosts",
            "package_name",
            "package_targets",
        ] {
            match envelope.get(key) {
                Some(Value::Array(items)) => {
                    let texts = items
                        .iter()
                        .filter_map(Value::as_str)
                        .map(|text| Value::String(bounded_text(text)))
                        .collect();
                    safe.insert(key.to_owned(), Value::Array(texts));
                }
                Some(Value::String(text)) => {
                    safe.insert(key.to_owned(), Value::String(bounded_text(text)));
                }
                _ => {}
            }
        }
        preserve_portal_fields(&mut safe, envelope);
    }
    complete_dashboard_envelope(&mut safe, envelope, action_type, context, redaction_enabled);
    add_aliases(&mut safe);
    Ok(Some(safe))
}

fn complete_dashboard_envelope(
    safe: &mut Map<String, Value>,
    envelope: &Map<String, Value>,
    action_type: Option<&str>,
    context: &EnvelopeContext,
    redaction_enabled: bool,
) {
    let Some(action_type) = action_type.filter(|kind| DASHBOARD_ACTION_TYPES.contains(kind)) else {
        return;
    };
    if !safe.get("schema_version").is_some_and(is_py_int) {
        safe.insert("schema_version".to_owned(), Value::from(1));
    }
    let defaults = [
        (
            "action_id",
            context.fallback_action_id.unwrap_or("cloud-review-action"),
            true,
        ),
        (
            "harness",
            context.fallback_harness.unwrap_or("guard-cloud"),
            true,
        ),
        ("event_name", "guard_cloud_review", false),
    ];
    for (key, fallback, bounded) in defaults {
        if stripped_string(safe.get(key)).is_none() {
            let text = if bounded {
                bounded_text(fallback)
            } else {
                fallback.to_owned()
            };
            safe.insert(key.to_owned(), Value::String(text));
        }
    }
    safe.insert(
        "action_type".to_owned(),
        Value::String(action_type.to_owned()),
    );
    for key in NULLABLE_FIELDS {
        if !safe.contains_key(key) {
            let value = if redaction_enabled {
                None
            } else {
                envelope.get(key)
            };
            safe.insert(
                key.to_owned(),
                value
                    .and_then(Value::as_str)
                    .map_or(Value::Null, |text| Value::String(scrubbed_text(text))),
            );
        }
    }
    for key in ["target_paths", "network_hosts"] {
        if !safe.get(key).is_some_and(Value::is_array) {
            safe.insert(key.to_owned(), Value::Array(Vec::new()));
        }
    }
    let raw_payload = match envelope.get("raw_payload_redacted") {
        Some(value @ Value::Object(_)) if !redaction_enabled => bounded_cloud_value(value, None),
        _ => Value::Object(Map::new()),
    };
    safe.insert("raw_payload_redacted".to_owned(), raw_payload);
}

fn add_aliases(safe: &mut Map<String, Value>) {
    for (snake, camel) in ALIAS_PAIRS {
        if let Some(value) = safe.get(snake).cloned() {
            safe.entry(camel.to_owned()).or_insert(value);
        }
    }
}
