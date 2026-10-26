//! The per-item request fields of `queue_blocked_approvals`, derived from one
//! evaluation item and the detected artifact it names, as the former Python
//! helpers in `approvals.py` spelled them.

use serde_json::{Map, Value};

use crate::cloud_request_text::py_truthy;
use crate::guard_store_json::{py_str, py_strip};
use crate::guard_store_policy_source_labels::{posix_parts, windows_parts};

/// `_GENERIC_TOOL_LABELS`: tool names that never stand for the action itself.
const GENERIC_TOOL_LABELS: [&str; 22] = [
    "Bash",
    "Shell",
    "shell_command",
    "Read",
    "Write",
    "Edit",
    "MultiEdit",
    "Glob",
    "Grep",
    "WebFetch",
    "TodoWrite",
    "tool",
    "mcp",
    "skill",
    "bash",
    "rg",
    "cat",
    "mcp_tool",
    "package_request",
    "file_read_request",
    "file_write_request",
    "tool_action_request",
];
const EXTENSION_ALLOW_HINT_SCHEMA: &str = "guard.extension-allow-hint.v1";
/// `MAX_HINT_PERMISSIONS * 4`.
const MAX_HINT_IDS: usize = 12;

/// The detected artifact an item names, as the Python wrapper sends it.
pub(crate) struct Artifact<'a>(pub(crate) &'a Map<String, Value>);

impl<'a> Artifact<'a> {
    fn wire(&self, key: &str) -> &'a Value {
        self.0
            .get("wire")
            .and_then(|wire| wire.get(key))
            .unwrap_or(&Value::Null)
    }

    pub(crate) fn wire_value(&self) -> &'a Value {
        self.0.get("wire").unwrap_or(&Value::Null)
    }

    /// A `GuardArtifact` string attribute, rendered as Python's `str`.
    pub(crate) fn wire_text(&self, key: &str) -> String {
        py_str(self.wire(key)).unwrap_or_default()
    }

    /// An optional `GuardArtifact` attribute: `None` stays null.
    pub(crate) fn wire_optional(&self, key: &str) -> Value {
        self.wire(key).clone()
    }

    pub(crate) fn fact(&self, key: &str) -> &'a Value {
        self.0.get(key).unwrap_or(&Value::Null)
    }
}

/// `_is_generic_tool_label`.
fn is_generic(value: &str) -> bool {
    let stripped = py_strip(value);
    let lowered = stripped.to_lowercase();
    GENERIC_TOOL_LABELS
        .iter()
        .any(|label| *label == stripped || label.to_lowercase() == lowered)
}

/// `_string_from_mapping`.
fn string_from<'a>(mapping: &'a Map<String, Value>, key: &str) -> Option<&'a str> {
    let value = py_strip(mapping.get(key)?.as_str()?);
    (!value.is_empty()).then_some(value)
}

fn first_string<'a>(mapping: &'a Map<String, Value>, keys: &[&str]) -> Option<&'a str> {
    keys.iter().find_map(|key| string_from(mapping, key))
}

/// `_string_list_from_mapping`.
fn string_list_from<'a>(mapping: &'a Map<String, Value>, key: &str) -> Vec<&'a str> {
    match mapping.get(key) {
        Some(Value::String(text)) if !py_strip(text).is_empty() => vec![py_strip(text)],
        Some(Value::Array(items)) => items
            .iter()
            .filter_map(Value::as_str)
            .map(py_strip)
            .filter(|item| !item.is_empty())
            .collect(),
        _ => Vec::new(),
    }
}

fn first_list<'a>(mapping: &'a Map<String, Value>, keys: [&str; 2]) -> Vec<&'a str> {
    let first = string_list_from(mapping, keys[0]);
    if first.is_empty() {
        string_list_from(mapping, keys[1])
    } else {
        first
    }
}

/// `_review_action_text_from_envelope`.
fn envelope_review_text(envelope: &Map<String, Value>) -> Option<String> {
    for key in ["raw_command_text", "rawCommandText", "command", "cmd"] {
        if let Some(direct) = string_from(envelope, key).filter(|text| !is_generic(text)) {
            return Some(direct.to_owned());
        }
    }
    let action_type = string_from(envelope, "action_type");
    if let Some(identity) = first_string(envelope, &["action_identity", "actionIdentity"])
        .filter(|text| !is_generic(text))
    {
        return Some(identity.to_owned());
    }
    if let Some(
        action_type @ ("file_read" | "file_write" | "file_read_request" | "file_write_request"),
    ) = action_type
    {
        let mut paths = first_list(envelope, ["target_paths", "targetPaths"]);
        if paths.is_empty() {
            paths.extend(first_string(
                envelope,
                &["target_path", "targetPath", "path", "file_path", "filePath"],
            ));
        }
        if !paths.is_empty() {
            let verb = if action_type.starts_with("file_read") {
                "Read"
            } else {
                "Write"
            };
            return Some(format!("{verb} {}", paths.join(", ")));
        }
    }
    if action_type == Some("mcp_tool") {
        let server = first_string(envelope, &["mcp_server", "mcpServer", "server"]);
        let tool = first_string(envelope, &["mcp_tool", "mcpTool", "tool_name", "toolName"]);
        return match (server, tool) {
            (Some(server), Some(tool)) => Some(format!("{server}.{tool}")),
            (server, tool) => server.or(tool).map(str::to_owned),
        };
    }
    let manager = first_string(envelope, &["package_manager", "packageManager"])?;
    let name = first_string(envelope, &["package_name", "packageName"])?;
    let targets = first_list(envelope, ["package_targets", "packageTargets"]);
    let target = targets.first().copied().unwrap_or(name);
    Some(if target.starts_with(name) {
        format!("{manager} install {target}")
    } else {
        format!("{manager} install {name}@{target}")
    })
}

/// `_review_action_text_from_item`: the first concrete action text.
pub(crate) fn review_text(
    item: &Map<String, Value>,
    artifact: Option<&Artifact>,
    envelope: Option<&Map<String, Value>>,
) -> Option<String> {
    let mut candidates: Vec<Option<&str>> = Vec::new();
    if let Some(artifact) = artifact {
        candidates.push(artifact.fact("raw_command_text").as_str());
        candidates.push(artifact.fact("command_text").as_str());
        candidates.push(artifact.wire("command").as_str());
    }
    for key in [
        "raw_command_text",
        "rawCommandText",
        "review_command",
        "reviewCommand",
        "action_identity",
        "actionIdentity",
    ] {
        candidates.push(item.get(key).and_then(Value::as_str));
    }
    let from_envelope = envelope.and_then(envelope_review_text);
    candidates.push(from_envelope.as_deref());
    candidates
        .into_iter()
        .flatten()
        .map(py_strip)
        .find(|text| !text.is_empty() && !is_generic(text))
        .map(str::to_owned)
}

/// `_item_action_envelope_json`.
pub(crate) fn envelope(item: &Map<String, Value>) -> Option<Map<String, Value>> {
    match item.get("action_envelope_json") {
        Some(Value::String(text)) if !py_strip(text).is_empty() => {
            match serde_json::from_str::<Value>(text) {
                Ok(Value::Object(map)) => Some(map),
                _ => None,
            }
        }
        Some(Value::Object(map)) => Some(map.clone()),
        _ => None,
    }
}

/// `_item_with_command_category`: name the matched command extension on an
/// envelope that carries no category.
pub(crate) fn with_command_category(
    item: &Map<String, Value>,
    artifact: Option<&Artifact>,
) -> Map<String, Value> {
    let mut item = item.clone();
    let Some(mut envelope) = envelope(&item) else {
        return item;
    };
    if envelope
        .get("command_category")
        .is_some_and(Value::is_string)
    {
        return item;
    }
    let matches = match artifact.map(|artifact| artifact.fact("command_rule_matches")) {
        Some(Value::Array(matches)) => Some(matches),
        _ => item.get("command_rule_matches").and_then(Value::as_array),
    };
    let category = matches.into_iter().flatten().find_map(|entry| {
        entry
            .get("extension_id")
            .and_then(Value::as_str)
            .filter(|id| entry.is_object() && id.starts_with("command."))
    });
    if let Some(category) = category {
        envelope.insert(
            "command_category".to_owned(),
            Value::String(category.to_owned()),
        );
        item.insert("action_envelope_json".to_owned(), Value::Object(envelope));
    }
    item
}

/// `_item_scanner_evidence`.
pub(crate) fn scanner_evidence(item: &Map<String, Value>) -> Vec<Value> {
    item.get("scanner_evidence")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|entry| entry.is_object())
        .cloned()
        .collect()
}

/// A non-empty string field, as `isinstance(value, str) and value`.
pub(crate) fn nonempty<'a>(item: &'a Map<String, Value>, key: &str) -> Option<&'a str> {
    item.get(key)
        .and_then(Value::as_str)
        .filter(|text| !text.is_empty())
}

/// `str(item.get(key) or fallback)`.
pub(crate) fn str_or(item: &Map<String, Value>, key: &str, fallback: &str) -> String {
    match item.get(key) {
        Some(value) if py_truthy(value) => py_str(value).unwrap_or_default(),
        _ => fallback.to_owned(),
    }
}

/// `_string_list`.
pub(crate) fn string_list(value: Option<&Value>) -> Vec<Value> {
    value
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|item| item.is_string())
        .cloned()
        .collect()
}

/// `_item_risk_summary`.
pub(crate) fn risk_summary(item: &Map<String, Value>, artifact: Option<&Artifact>) -> Value {
    match nonempty(item, "risk_summary") {
        Some(summary) => Value::String(summary.to_owned()),
        None => artifact.map_or(Value::Null, |artifact| {
            artifact.fact("risk_summary").clone()
        }),
    }
}

/// `_item_risk_signals`.
pub(crate) fn risk_signals(item: &Map<String, Value>, artifact: Option<&Artifact>) -> Value {
    let signals: Vec<Value> = item
        .get("risk_signals")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|signal| signal.as_str().is_some_and(|text| !text.is_empty()))
        .cloned()
        .collect();
    if !signals.is_empty() {
        return Value::Array(signals);
    }
    match artifact.map(|artifact| artifact.fact("risk_signals")) {
        Some(Value::Array(signals)) => Value::Array(signals.clone()),
        _ => Value::Array(Vec::new()),
    }
}

/// `_launch_target`.
pub(crate) fn launch_target(item: &Map<String, Value>, artifact: Option<&Artifact>) -> Value {
    if let Some(target) = nonempty(item, "launch_target") {
        return Value::String(target.to_owned());
    }
    let Some(artifact) = artifact else {
        return Value::Null;
    };
    let url = artifact.wire("url");
    if py_truthy(url) {
        return url.clone();
    }
    let command = artifact.wire("command");
    if !py_truthy(command) {
        return Value::Null;
    }
    let mut parts = vec![py_str(command).unwrap_or_default()];
    if let Some(args) = artifact.wire("args").as_array() {
        parts.extend(args.iter().filter_map(py_str));
    }
    Value::String(parts.join(" "))
}

/// `_item_extension_allow_hint`: the artifact's hint, else the item's, if it
/// passes `validated_extension_allow_hint`.
pub(crate) fn extension_allow_hint(
    item: &Map<String, Value>,
    artifact: Option<&Artifact>,
) -> Value {
    let value = match artifact.map(|artifact| artifact.fact("extension_allow_hint")) {
        Some(value) if !value.is_null() => value,
        _ => item.get("extension_allow_hint").unwrap_or(&Value::Null),
    };
    validated_hint(value).map_or(Value::Null, Value::Object)
}

fn validated_hint(value: &Value) -> Option<Map<String, Value>> {
    let hint = value.as_object()?;
    if hint.get("schema").and_then(Value::as_str) != Some(EXTENSION_ALLOW_HINT_SCHEMA) {
        return None;
    }
    let mut result = Map::new();
    result.insert(
        "schema".to_owned(),
        Value::from(EXTENSION_ALLOW_HINT_SCHEMA),
    );
    for key in ["permission_ids", "rule_ids", "extension_ids"] {
        result.insert(key.to_owned(), hint_ids(hint.get(key), false)?);
    }
    let empty = Value::Array(Vec::new());
    let relied = hint_ids(
        Some(hint.get("relied_permission_ids").unwrap_or(&empty)),
        true,
    )?;
    result.insert("relied_permission_ids".to_owned(), relied);
    let digest = hint.get("catalog_digest")?.as_str()?;
    if digest.chars().count() != 64 {
        return None;
    }
    result.insert("catalog_digest".to_owned(), Value::from(digest));
    Some(result)
}

/// `_valid_hint_ids`.
fn hint_ids(value: Option<&Value>, allow_empty: bool) -> Option<Value> {
    let items = value?.as_array()?;
    if (items.is_empty() && !allow_empty) || items.len() > MAX_HINT_IDS {
        return None;
    }
    items
        .iter()
        .all(|item| {
            item.as_str()
                .is_some_and(|id| id.starts_with("command.") && id.chars().count() <= 256)
        })
        .then(|| Value::Array(items.clone()))
}

/// `_workspace_scope_target`: the effective workspace, else the config's
/// directory, one level higher for a dot directory such as `.codex`.
pub(crate) fn workspace(item: &Map<String, Value>, config_path: &str) -> Value {
    if let Some(workspace) = item.get("effective_workspace").and_then(Value::as_str) {
        let workspace = py_strip(workspace);
        if !workspace.is_empty() {
            return Value::from(workspace);
        }
    }
    if config_path.is_empty() {
        return Value::Null;
    }
    Value::String(workspace_root(config_path, cfg!(windows)))
}

/// `str(parent.parent if parent.name.startswith(".") else parent)` for
/// `parent = Path(config_path).parent`.
fn workspace_root(config_path: &str, windows: bool) -> String {
    let (root, mut parts, separator) = if windows {
        let (root, parts) = windows_parts(config_path);
        (root, parts, "\\")
    } else {
        let (root, parts) = posix_parts(config_path);
        (root.to_owned(), parts, "/")
    };
    parts.pop();
    if parts.last().is_some_and(|name| name.starts_with('.')) {
        parts.pop();
    }
    match format!("{root}{}", parts.join(separator)) {
        rendered if rendered.is_empty() => ".".to_owned(),
        rendered => rendered,
    }
}

#[cfg(test)]
mod tests {
    use super::workspace_root;

    #[test]
    fn windows_workspace_root_follows_pure_windows_path() {
        assert_eq!(
            workspace_root(r"C:\repo\.codex\config.toml", true),
            r"C:\repo"
        );
        assert_eq!(workspace_root("C:/repo/sub/x.toml", true), r"C:\repo\sub");
        assert_eq!(workspace_root(r"C:\x.toml", true), r"C:\");
        assert_eq!(workspace_root("x.toml", true), ".");
    }
}
