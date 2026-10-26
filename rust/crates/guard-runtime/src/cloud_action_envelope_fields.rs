//! Portal-contract fields of the Cloud-safe action envelope: operation,
//! target class/count and the preserved resource fields.

use serde_json::{Map, Value};

use super::cloud_request_text::{
    bounded_cloud_value, bounded_text, first_optional_string, optional_string, py_strip,
};

const PORTAL_KEYS: [&str; 23] = [
    "operation",
    "resource",
    "resource_uri",
    "target",
    "target_resource",
    "skill_name",
    "source_path",
    "permission",
    "requested_permission",
    "path",
    "access_mode",
    "content_state",
    "url",
    "uri",
    "endpoint",
    "origin",
    "host",
    "selector",
    "method",
    "args",
    "arguments",
    "input",
    "parameters",
];
pub(super) const FILE_ACTIONS: [&str; 4] = [
    "file_read",
    "file_write",
    "file_read_request",
    "file_write_request",
];

pub(super) fn operation_for_action_type(action_type: Option<&str>) -> Option<&'static str> {
    Some(match action_type? {
        "shell_command" => "run",
        "file_read" | "file_read_request" => "read",
        "file_write" | "file_write_request" => "write",
        "mcp_tool" => "call",
        "package_script" => "install",
        "network_request" => "request",
        "browser_action" => "browse",
        "config_change" => "update",
        "harness_start" => "start",
        "prompt" => "submit",
        "skill" | "skill_request" => "use",
        _ => return None,
    })
}

pub(super) fn target_class_for_action_type(
    action_type: Option<&str>,
    envelope: &Map<String, Value>,
) -> &'static str {
    match action_type {
        Some(kind) if FILE_ACTIONS.contains(&kind) => "file",
        Some("mcp_tool") => "mcp_tool",
        kind if kind == Some("package_script")
            || first_optional_string(envelope, &["package_name", "packageName"]).is_some() =>
        {
            "package"
        }
        Some("network_request") => "network",
        Some("browser_action") => "browser",
        Some("skill" | "skill_request") => "skill",
        Some("shell_command") => "shell_command",
        _ => "action",
    }
}

pub(super) fn target_count_for_envelope(envelope: &Map<String, Value>) -> u64 {
    let mut count = 0u64;
    for key in [
        "target_paths",
        "targetPaths",
        "network_hosts",
        "networkHosts",
        "package_targets",
        "packageTargets",
    ] {
        match envelope.get(key) {
            Some(Value::Array(items)) => {
                count += items
                    .iter()
                    .filter(|item| item.as_str().is_some_and(|text| !py_strip(text).is_empty()))
                    .count() as u64;
            }
            Some(Value::String(text)) if !py_strip(text).is_empty() => count += 1,
            _ => {}
        }
    }
    if count > 0 {
        return count;
    }
    let single = [
        "path",
        "file_path",
        "filePath",
        "url",
        "uri",
        "endpoint",
        "origin",
        "host",
        "selector",
        "package_name",
        "packageName",
        "target_resource",
        "targetResource",
        "resource",
    ];
    u64::from(
        single
            .iter()
            .any(|key| optional_string(envelope.get(*key)).is_some()),
    )
}

fn string_list_from_envelope(envelope: &Map<String, Value>, keys: &[&str]) -> Vec<String> {
    for key in keys {
        match envelope.get(*key) {
            Some(Value::String(text)) if !py_strip(text).is_empty() => {
                return vec![bounded_text(py_strip(text))];
            }
            Some(Value::Array(items)) => {
                let texts: Vec<String> = items
                    .iter()
                    .filter_map(Value::as_str)
                    .filter(|text| !py_strip(text).is_empty())
                    .map(|text| bounded_text(py_strip(text)))
                    .collect();
                if !texts.is_empty() {
                    return texts;
                }
            }
            _ => {}
        }
    }
    Vec::new()
}

fn action_arguments_from_raw_payload(envelope: &Map<String, Value>) -> Option<Value> {
    let Some(Value::Object(raw)) = envelope.get("raw_payload_redacted") else {
        return None;
    };
    for key in [
        "tool_input",
        "toolInput",
        "args",
        "arguments",
        "input",
        "parameters",
    ] {
        if let Some(value) = raw.get(key) {
            return Some(bounded_cloud_value(value, None)).filter(|found| !found.is_null());
        }
    }
    None
}

fn set_default(safe: &mut Map<String, Value>, key: &str, value: Value) {
    safe.entry(key.to_owned()).or_insert(value);
}

pub(super) fn preserve_portal_fields(safe: &mut Map<String, Value>, envelope: &Map<String, Value>) {
    for key in PORTAL_KEYS.iter() {
        if let Some(value) = envelope.get(*key) {
            if !safe.contains_key(*key) {
                safe.insert((*key).to_owned(), bounded_cloud_value(value, None));
            }
        }
    }
    let action_type = first_optional_string(envelope, &["action_type", "actionType"]);
    let target_paths = string_list_from_envelope(envelope, &["target_paths", "targetPaths"]);
    if let (Some(kind), Some(first)) = (action_type, target_paths.first()) {
        if FILE_ACTIONS.contains(&kind) {
            set_default(safe, "path", Value::String(first.clone()));
            let mode = if kind.contains("read") {
                "read"
            } else {
                "write"
            };
            set_default(safe, "access_mode", Value::String(mode.to_owned()));
            set_default(
                safe,
                "content_state",
                Value::String("metadata_only".to_owned()),
            );
        }
    }
    let hosts = string_list_from_envelope(envelope, &["network_hosts", "networkHosts"]);
    if let (Some("network_request"), Some(first)) = (action_type, hosts.first()) {
        set_default(safe, "host", Value::String(first.clone()));
    }
    if let Some(name) = first_optional_string(envelope, &["package_name", "packageName"]) {
        set_default(safe, "package_name", Value::String(bounded_text(name)));
    }
    if let Some(manager) = first_optional_string(envelope, &["package_manager", "packageManager"]) {
        set_default(
            safe,
            "package_manager",
            Value::String(bounded_text(manager)),
        );
    }
    if action_type == Some("mcp_tool") {
        if let Some(tool) = first_optional_string(envelope, &["mcp_tool", "mcpTool"]) {
            set_default(safe, "tool_name", Value::String(bounded_text(tool)));
        }
        if let Some(first) = target_paths.first() {
            set_default(safe, "target_resource", Value::String(first.clone()));
        }
    }
    let has_arguments = ["args", "arguments", "input", "parameters"]
        .iter()
        .any(|key| safe.contains_key(*key));
    if !has_arguments {
        if let Some(arguments) = action_arguments_from_raw_payload(envelope) {
            safe.insert("arguments".to_owned(), arguments.clone());
            safe.insert("args".to_owned(), arguments);
        }
    }
}
