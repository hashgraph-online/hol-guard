//! Cloud-safe redaction of receipt action envelopes.
//!
//! Receipts persist two envelope views: the full action envelope and a
//! redacted summary that carries counts and booleans instead of command text,
//! paths or package names. A well-formed envelope is redacted through its typed
//! shape; anything older or malformed takes the legacy scalar whitelist.

use guard_contracts::is_action_bearing_key;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use crate::cloud_request_text::py_eq;
use crate::guard_store_json::{dumps_sorted, py_strip};

const ACTION_TYPES: [&str; 10] = [
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
const FROM_DICT_ALLOWED_ACTION_KEYS: [&str; 7] = [
    "action_id",
    "action_type",
    "pre_execution_result",
    "actionId",
    "actionType",
    "preExecutionResult",
    "command_category",
];
const LEGACY_SCALAR_KEYS: [&str; 18] = [
    "schema_version",
    "action_id",
    "actionId",
    "harness",
    "event_name",
    "action_type",
    "actionType",
    "workspace_hash",
    "tool_name",
    "mcp_server",
    "mcp_tool",
    "package_manager",
    "package_intent_kind",
    "pre_execution_result",
    "preExecutionResult",
    "script_name",
    "policy_action",
    "policyAction",
];
const POLICY_FIELDS: [&str; 2] = ["policy_action", "policyAction"];

fn chars(text: &str) -> usize {
    text.chars().count()
}

fn text_of<'a>(map: &'a Map<String, Value>, key: &str) -> Option<&'a str> {
    map.get(key).and_then(Value::as_str)
}

fn array_len(value: Option<&Value>) -> usize {
    value.and_then(Value::as_array).map_or(0, Vec::len)
}

fn cell(map: &Map<String, Value>, key: &str) -> Value {
    map.get(key).cloned().unwrap_or(Value::Null)
}

/// `GuardActionEnvelope._string_value`: a stripped non-blank string, else None.
fn string_value(value: Option<&Value>) -> Option<String> {
    let text = value?.as_str()?;
    let stripped = py_strip(text);
    (!stripped.is_empty()).then(|| stripped.to_owned())
}

/// `GuardActionEnvelope._string_tuple`: non-blank string items, unstripped.
fn string_tuple(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .filter(|item| !py_strip(item).is_empty())
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

/// `_matching_aliased_value`: the snake value (or camel when absent); the two
/// spellings must agree when both are present.
fn aliased(map: &Map<String, Value>, snake: &str, camel: &str) -> Result<Value, ()> {
    if let (Some(left), Some(right)) = (map.get(snake), map.get(camel)) {
        if !py_eq(left, right) {
            return Err(());
        }
    }
    Ok(map
        .get(snake)
        .or_else(|| map.get(camel))
        .cloned()
        .unwrap_or(Value::Null))
}

fn required_string(map: &Map<String, Value>, key: &str) -> Result<String, ()> {
    match text_of(map, key) {
        Some(text) if !py_strip(text).is_empty() => Ok(text.to_owned()),
        _ => Err(()),
    }
}

/// The checked projection `GuardActionEnvelope.from_dict` builds.
struct Typed {
    schema_version: Value,
    action_id: String,
    harness: String,
    event_name: String,
    action_type: String,
    workspace_hash: Option<String>,
    tool_name: Option<String>,
    command: Option<String>,
    prompt_excerpt: Option<String>,
    target_paths: Vec<String>,
    network_hosts: Vec<String>,
    mcp_server: Option<String>,
    mcp_tool: Option<String>,
    package_manager: Option<String>,
    package_name: Option<String>,
    package_intent_kind: Option<String>,
    package_targets: usize,
    pre_execution_result: Option<String>,
    script_name: Option<String>,
}

fn from_dict(payload: &Map<String, Value>) -> Result<Typed, ()> {
    for key in payload.keys() {
        if is_action_bearing_key(key) && !FROM_DICT_ALLOWED_ACTION_KEYS.contains(&key.as_str()) {
            return Err(());
        }
    }
    let action_id = aliased(payload, "action_id", "actionId")?;
    let action_type = aliased(payload, "action_type", "actionType")?;
    let pre_execution = aliased(payload, "pre_execution_result", "preExecutionResult")?;
    let schema_version = payload
        .get("schema_version")
        .cloned()
        .unwrap_or(Value::Null);
    let version_is_one = match &schema_version {
        Value::Bool(flag) => *flag,
        Value::Number(number) => (number.is_i64() || number.is_u64()) && number.to_string() == "1",
        _ => false,
    };
    if !version_is_one {
        return Err(());
    }
    let action_type = match action_type.as_str() {
        Some(text) if ACTION_TYPES.contains(&text) => text.to_owned(),
        _ => return Err(()),
    };
    let mut typed = Typed {
        schema_version,
        action_id: string_value(Some(&action_id)).unwrap_or_default(),
        harness: required_string(payload, "harness")?,
        event_name: required_string(payload, "event_name")?,
        action_type,
        workspace_hash: string_value(payload.get("workspace_hash")),
        tool_name: string_value(payload.get("tool_name")),
        command: string_value(payload.get("command")),
        prompt_excerpt: string_value(payload.get("prompt_excerpt")),
        target_paths: string_tuple(payload.get("target_paths")),
        network_hosts: string_tuple(payload.get("network_hosts")),
        mcp_server: string_value(payload.get("mcp_server")),
        mcp_tool: string_value(payload.get("mcp_tool")),
        package_manager: string_value(payload.get("package_manager")),
        package_name: string_value(payload.get("package_name")),
        package_intent_kind: string_value(payload.get("package_intent_kind")),
        package_targets: string_tuple(payload.get("package_targets")).len(),
        pre_execution_result: string_value(Some(&pre_execution)),
        script_name: string_value(payload.get("script_name")),
    };
    if typed.action_id.is_empty() {
        typed.action_id = stable_action_hash(&typed);
    }
    Ok(typed)
}

/// `stable_action_hash`: deterministic action identity without raw payload.
fn stable_action_hash(typed: &Typed) -> String {
    let payload = json!({
        "schema_version": typed.schema_version,
        "harness": typed.harness,
        "event_name": typed.event_name,
        "action_type": typed.action_type,
        "workspace_hash": typed.workspace_hash,
        "tool_name": typed.tool_name,
        "command": typed.command.as_deref().map(py_strip),
        "prompt_excerpt": typed.prompt_excerpt,
        "target_paths": typed.target_paths,
        "network_hosts": typed.network_hosts,
        "mcp_server": typed.mcp_server,
        "mcp_tool": typed.mcp_tool,
        "package_manager": Value::Null,
        "package_name": Value::Null,
        "script_name": typed.script_name,
    });
    let encoded = dumps_sorted(&payload).unwrap_or_default();
    hex::encode(Sha256::digest(encoded.as_bytes()))
}

fn optional(value: &Option<String>) -> Value {
    value.clone().map_or(Value::Null, Value::String)
}

fn typed_redacted(typed: &Typed) -> Map<String, Value> {
    let mut base = Map::new();
    let mut put = |key: &str, value: Value| {
        base.insert(key.to_owned(), value);
    };
    put("schema_version", typed.schema_version.clone());
    put("action_id", Value::String(typed.action_id.clone()));
    put("harness", Value::String(typed.harness.clone()));
    put("event_name", Value::String(typed.event_name.clone()));
    put("action_type", Value::String(typed.action_type.clone()));
    put("workspace_hash", optional(&typed.workspace_hash));
    put("tool_name", optional(&typed.tool_name));
    put(
        "command_length",
        json!(typed.command.as_deref().map_or(0, chars)),
    );
    put("target_paths_count", json!(typed.target_paths.len()));
    put("network_hosts_count", json!(typed.network_hosts.len()));
    put("mcp_server", optional(&typed.mcp_server));
    put("mcp_tool", optional(&typed.mcp_tool));
    put("package_manager", optional(&typed.package_manager));
    put(
        "has_package_name",
        Value::Bool(
            typed
                .package_name
                .as_deref()
                .is_some_and(|name| !name.is_empty()),
        ),
    );
    put("package_intent_kind", optional(&typed.package_intent_kind));
    put("package_targets_count", json!(typed.package_targets));
    put(
        "pre_execution_result",
        optional(&typed.pre_execution_result),
    );
    put("script_name", optional(&typed.script_name));
    base
}

/// `_redacted_envelope_dict` for a typed envelope handed over by the native
/// edge: its fields are already validated, so nothing is re-checked or
/// stripped. Missing keys read as absent.
pub(crate) fn redact_typed(envelope: &Map<String, Value>) -> Map<String, Value> {
    let package_name_present =
        text_of(envelope, "package_name").is_some_and(|name| !name.is_empty());
    let mut base = Map::new();
    for key in [
        "schema_version",
        "action_id",
        "harness",
        "event_name",
        "action_type",
        "workspace_hash",
        "tool_name",
        "mcp_server",
        "mcp_tool",
        "package_manager",
        "package_intent_kind",
        "pre_execution_result",
        "script_name",
    ] {
        base.insert(key.to_owned(), cell(envelope, key));
    }
    base.insert(
        "command_length".to_owned(),
        json!(text_of(envelope, "command").map_or(0, chars)),
    );
    base.insert(
        "target_paths_count".to_owned(),
        json!(array_len(envelope.get("target_paths"))),
    );
    base.insert(
        "network_hosts_count".to_owned(),
        json!(array_len(envelope.get("network_hosts"))),
    );
    base.insert(
        "has_package_name".to_owned(),
        Value::Bool(package_name_present),
    );
    base.insert(
        "package_targets_count".to_owned(),
        json!(array_len(envelope.get("package_targets"))),
    );
    base
}

fn legacy_redacted(envelope: &Map<String, Value>) -> Map<String, Value> {
    let mut safe = Map::new();
    for key in LEGACY_SCALAR_KEYS {
        if let Some(value) = envelope.get(key) {
            if !matches!(value, Value::Array(_) | Value::Object(_)) {
                safe.insert(key.to_owned(), value.clone());
            }
        }
    }
    let command = match envelope.get("command") {
        Some(Value::String(text)) => Some(text.as_str()),
        _ => text_of(envelope, "redacted_command"),
    };
    safe.insert("command_length".to_owned(), json!(command.map_or(0, chars)));
    for (count, source) in [
        ("target_paths_count", "target_paths"),
        ("network_hosts_count", "network_hosts"),
        ("package_targets_count", "package_targets"),
    ] {
        safe.insert(count.to_owned(), json!(array_len(envelope.get(source))));
    }
    safe.insert(
        "has_package_name".to_owned(),
        Value::Bool(text_of(envelope, "package_name").is_some_and(|name| !name.is_empty())),
    );
    safe
}

/// `_redacted_envelope_dict` for a persisted mapping: a well-formed envelope is
/// redacted through its typed shape; anything else takes the legacy whitelist.
pub(crate) fn redact_mapping(envelope: &Map<String, Value>) -> Map<String, Value> {
    let mut typed_payload = envelope.clone();
    let mut policy_fields = Map::new();
    for key in POLICY_FIELDS {
        if let Some(value) = typed_payload.remove(key) {
            policy_fields.insert(key.to_owned(), value);
        }
    }
    match from_dict(&typed_payload) {
        Ok(typed) => {
            let mut redacted = typed_redacted(&typed);
            redacted.extend(policy_fields);
            redacted
        }
        Err(()) => legacy_redacted(envelope),
    }
}
