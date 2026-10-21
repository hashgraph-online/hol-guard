//! The managed Claude hook-group contract and the settings check of the
//! native SessionStart lane.
//!
//! `guard/contracts/claude-hook-groups.v1.json` is the one declaration both
//! sides read: Python builds `~/.claude/settings.json` from it, and this
//! module shape-checks the same bytes (a port of
//! `parse_claude_hook_groups_contract` in `adapters/claude_hook_config.py`)
//! and decides whether the installed Guard hook entries already equal what
//! `refresh_runtime_hook_urls` would write. Entries without a Guard marker
//! are ignored, as the Python merge keeps them. Any doubt is a mismatch, and
//! a mismatch hands the session start to the Python transaction.

use serde_json::{Map, Value};

use crate::hook_env_stamp::json_string;

const CONTRACT_TEXT: &str =
    include_str!("../../../../src/codex_plugin_scanner/guard/contracts/claude-hook-groups.v1.json");
const CONTRACT_SCHEMA: &str = "hol-guard.claude-hook-groups.v1";
const REQUIRED_EVENTS: [&str; 4] = ["PreToolUse", "PostToolUse", "Notification", "Stop"];
const FALLBACK_DAEMON_URL_KEY: &str = "fallback_daemon_url";

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RuntimeGroup {
    pub(crate) event: String,
    pub(crate) matcher: Option<String>,
    pub(crate) timeout_seconds: u64,
    pub(crate) status_message: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct HookGroupsContract {
    pub(crate) settings_path: String,
    pub(crate) runtime_groups: Vec<RuntimeGroup>,
    pub(crate) pruned_events: Vec<String>,
    pub(crate) session_start_event: String,
    pub(crate) session_start_context: String,
    pub(crate) daemon_hook_marker: String,
    pub(crate) session_start_hook_marker: String,
    pub(crate) bridge_required_keys: Vec<String>,
    pub(crate) bridge_optional_keys: Vec<String>,
}

fn invalid(field: &str) -> String {
    format!("claude_hook_groups_contract_invalid: {field}")
}

fn field<'a>(map: &'a Map<String, Value>, name: &str) -> Result<&'a Value, String> {
    map.get(name).ok_or_else(|| invalid(name))
}

fn mapping<'a>(value: &'a Value, label: &str) -> Result<&'a Map<String, Value>, String> {
    value.as_object().ok_or_else(|| invalid(label))
}

fn text(value: &Value, label: &str) -> Result<String, String> {
    match value.as_str() {
        Some(text) if !text.is_empty() => Ok(text.to_owned()),
        _ => Err(invalid(label)),
    }
}

fn optional_text(value: &Value, label: &str) -> Result<Option<String>, String> {
    if value.is_null() {
        Ok(None)
    } else {
        text(value, label).map(Some)
    }
}

fn texts(value: &Value, label: &str) -> Result<Vec<String>, String> {
    let items = value.as_array().ok_or_else(|| invalid(label))?;
    items.iter().map(|item| text(item, label)).collect()
}

/// A positive JSON integer; booleans and floats are refused as in Python.
fn seconds(value: &Value, label: &str) -> Result<u64, String> {
    value
        .as_u64()
        .filter(|seconds| *seconds > 0)
        .ok_or_else(|| invalid(label))
}

fn runtime_group(value: &Value) -> Result<RuntimeGroup, String> {
    let group = mapping(value, "runtime_groups")?;
    Ok(RuntimeGroup {
        event: text(field(group, "event")?, "runtime_groups.event")?,
        matcher: optional_text(field(group, "matcher")?, "runtime_groups.matcher")?,
        timeout_seconds: seconds(
            field(group, "timeout_seconds")?,
            "runtime_groups.timeout_seconds",
        )?,
        status_message: optional_text(
            field(group, "status_message")?,
            "runtime_groups.status_message",
        )?,
    })
}

/// `parse_claude_hook_groups_contract`, with the settings path and the
/// SessionStart event this lane also needs.
pub(crate) fn parse_contract(document: &Value) -> Result<HookGroupsContract, String> {
    let contract = mapping(document, "document")?;
    if contract.get("schema").and_then(Value::as_str) != Some(CONTRACT_SCHEMA) {
        return Err(invalid("schema"));
    }
    let markers = mapping(field(contract, "markers")?, "markers")?;
    let session_start = mapping(field(contract, "session_start")?, "session_start")?;
    let bridge_config = mapping(field(contract, "bridge_config")?, "bridge_config")?;
    let group_values = field(contract, "runtime_groups")?
        .as_array()
        .filter(|groups| !groups.is_empty())
        .ok_or_else(|| invalid("runtime_groups"))?;
    let runtime_groups = group_values
        .iter()
        .map(runtime_group)
        .collect::<Result<Vec<_>, _>>()?;
    let mut events: Vec<&str> = runtime_groups.iter().map(|g| g.event.as_str()).collect();
    events.sort_unstable();
    events.dedup();
    if events.len() != runtime_groups.len()
        || !REQUIRED_EVENTS.iter().all(|event| events.contains(event))
    {
        return Err(invalid("runtime_groups.event"));
    }
    // Shape-checked like Python; this lane leaves the SessionStart group to
    // the installer, so the values are not kept.
    texts(field(session_start, "matchers")?, "session_start.matchers")?;
    seconds(
        field(session_start, "timeout_seconds")?,
        "session_start.timeout_seconds",
    )?;
    Ok(HookGroupsContract {
        settings_path: text(field(contract, "settings_path")?, "settings_path")?,
        runtime_groups,
        pruned_events: texts(field(contract, "pruned_events")?, "pruned_events")?,
        session_start_event: text(field(session_start, "event")?, "session_start.event")?,
        session_start_context: text(
            field(session_start, "additional_context")?,
            "session_start.additional_context",
        )?,
        daemon_hook_marker: text(field(markers, "daemon_hook")?, "markers.daemon_hook")?,
        session_start_hook_marker: text(
            field(markers, "session_start_hook")?,
            "markers.session_start_hook",
        )?,
        bridge_required_keys: texts(
            field(bridge_config, "required_keys")?,
            "bridge_config.required_keys",
        )?,
        bridge_optional_keys: texts(
            field(bridge_config, "optional_keys")?,
            "bridge_config.optional_keys",
        )?,
    })
}

/// The contract compiled into this binary.
pub(crate) fn contract() -> Result<HookGroupsContract, String> {
    let document: Value = serde_json::from_str(CONTRACT_TEXT).map_err(|_| invalid("document"))?;
    parse_contract(&document)
}

/// `is_guard_hook_command`.
fn is_guard_command(contract: &HookGroupsContract, command: &str) -> bool {
    if command.contains(&contract.daemon_hook_marker)
        || command.contains(&contract.session_start_hook_marker)
    {
        return true;
    }
    if command.contains("codex_plugin_scanner.cli") {
        return command.contains("guard hook")
            || command.contains("'guard', 'hook'")
            || command.contains("\"guard\", \"hook\"");
    }
    command.contains("ensure_guard_daemon(") && command.contains(&contract.session_start_context)
}

/// `command_handler_argv`: the exec form when every part is a string.
fn handler_argv(handler: &Map<String, Value>) -> Option<Vec<&str>> {
    let command = handler.get("command")?.as_str()?;
    let args = handler.get("args")?.as_array()?;
    let mut argv = vec![command];
    for arg in args {
        argv.push(arg.as_str()?);
    }
    Some(argv)
}

/// `is_guard_hook_handler`. `Err` is a handler type Python cannot hash,
/// where the Python refresh itself would fail.
fn is_guard_handler(contract: &HookGroupsContract, handler: &Value) -> Result<bool, ()> {
    let Some(handler) = handler.as_object() else {
        return Ok(false);
    };
    match handler.get("type") {
        None | Some(Value::Null) => Ok(is_guard_command_handler(contract, handler)),
        Some(Value::String(kind)) if kind == "command" => {
            Ok(is_guard_command_handler(contract, handler))
        }
        Some(Value::String(kind)) if kind == "http" => Ok(handler
            .get("url")
            .and_then(Value::as_str)
            .is_some_and(|url| {
                url.starts_with("http://127.0.0.1:") && url.contains("/v1/hooks/claude-code")
            })),
        Some(Value::Array(_) | Value::Object(_)) => Err(()),
        Some(_) => Ok(false),
    }
}

fn is_guard_command_handler(contract: &HookGroupsContract, handler: &Map<String, Value>) -> bool {
    match handler_argv(handler) {
        Some(argv) => argv.iter().any(|part| is_guard_command(contract, part)),
        None => handler
            .get("command")
            .and_then(Value::as_str)
            .is_some_and(|command| is_guard_command(contract, command)),
    }
}

/// The installer's description of the daemon hook argv the Python refresh
/// writes: the bridge command and its config, less the live daemon URL.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct DaemonHookTemplate {
    pub(crate) command: Vec<String>,
    pub(crate) bridge_config: Map<String, Value>,
}

fn json_text_or_list(value: &Value) -> Option<String> {
    match value {
        Value::String(text) => Some(json_string(text, false, false)),
        Value::Array(items) => {
            let parts = items
                .iter()
                .map(|item| item.as_str().map(|text| json_string(text, false, false)))
                .collect::<Option<Vec<_>>>()?;
            Some(format!("[{}]", parts.join(",")))
        }
        _ => None,
    }
}

/// `json.dumps(config, ensure_ascii=False, separators=(",", ":"))` of the
/// bridge config in the contract's key order, with the live daemon URL.
pub(crate) fn bridge_config_text(
    contract: &HookGroupsContract,
    template: &DaemonHookTemplate,
    daemon_url: &str,
) -> Option<String> {
    let known = |key: &String| {
        contract.bridge_required_keys.contains(key) || contract.bridge_optional_keys.contains(key)
    };
    if template.bridge_config.contains_key(FALLBACK_DAEMON_URL_KEY)
        || !template.bridge_config.keys().all(known)
    {
        return None;
    }
    let mut parts = Vec::new();
    let keys = contract
        .bridge_required_keys
        .iter()
        .map(|key| (key, true))
        .chain(contract.bridge_optional_keys.iter().map(|key| (key, false)));
    for (key, required) in keys {
        let value = if key == FALLBACK_DAEMON_URL_KEY {
            json_string(daemon_url, false, false)
        } else {
            match template.bridge_config.get(key) {
                Some(value) => json_text_or_list(value)?,
                None if required => return None,
                None => continue,
            }
        };
        parts.push(format!("{}:{value}", json_string(key, false, false)));
    }
    Some(format!("{{{}}}", parts.join(",")))
}

/// `guard_command_handler(argv, timeout=..., status_message=...)`.
fn expected_handler(group: &RuntimeGroup, argv: &[String]) -> Value {
    let mut handler = Map::new();
    handler.insert("type".to_owned(), Value::from("command"));
    handler.insert("command".to_owned(), Value::from(argv[0].clone()));
    handler.insert("args".to_owned(), Value::from(argv[1..].to_vec()));
    handler.insert("timeout".to_owned(), Value::from(group.timeout_seconds));
    if let Some(status) = &group.status_message {
        handler.insert("statusMessage".to_owned(), Value::from(status.clone()));
    }
    Value::Object(handler)
}

/// The Guard handlers of one event's entries, each with its entry's
/// matcher. `Err` when an entry is itself a flat Guard handler or a handler
/// is unreadable, which the Python refresh would rewrite or fail on.
fn guard_handlers<'a>(
    contract: &HookGroupsContract,
    entries: &'a [Value],
) -> Result<Vec<(Option<&'a Value>, &'a Value)>, ()> {
    let mut found = Vec::new();
    for entry in entries {
        let Some(object) = entry.as_object() else {
            continue;
        };
        if is_guard_handler(contract, entry)? {
            return Err(());
        }
        let Some(handlers) = object.get("hooks").and_then(Value::as_array) else {
            continue;
        };
        for handler in handlers {
            if is_guard_handler(contract, handler)? {
                found.push((object.get("matcher"), handler));
            }
        }
    }
    Ok(found)
}

fn group_matches(
    contract: &HookGroupsContract,
    group: &RuntimeGroup,
    entries: Option<&Value>,
    expected: &Value,
) -> bool {
    let Some(entries) = entries.and_then(Value::as_array) else {
        return false;
    };
    let Ok(found) = guard_handlers(contract, entries) else {
        return false;
    };
    let [(matcher, handler)] = found.as_slice() else {
        return false;
    };
    let matcher_ok = match &group.matcher {
        Some(expected) => matcher.and_then(Value::as_str) == Some(expected.as_str()),
        None => matcher.is_none(),
    };
    matcher_ok && *handler == expected
}

/// Whether the Guard entries of `settings` already equal what the Python
/// refresh would write for `daemon_url`: one exact Guard handler per runtime
/// group and none left in a pruned event. Non-Guard entries are ignored.
pub(crate) fn settings_current(
    contract: &HookGroupsContract,
    settings: &Value,
    template: &DaemonHookTemplate,
    daemon_url: &str,
) -> bool {
    let Some(hooks) = settings.get("hooks").and_then(Value::as_object) else {
        return false;
    };
    if template.command.is_empty() {
        return false;
    }
    let Some(config) = bridge_config_text(contract, template, daemon_url) else {
        return false;
    };
    let mut argv = template.command.clone();
    argv.push(config);
    let groups_current = contract.runtime_groups.iter().all(|group| {
        let expected = expected_handler(group, &argv);
        group_matches(contract, group, hooks.get(&group.event), &expected)
    });
    let pruned_clean = contract.pruned_events.iter().all(|event| {
        match hooks.get(event).and_then(Value::as_array) {
            None => true,
            Some(entries) => {
                matches!(guard_handlers(contract, entries), Ok(found) if found.is_empty())
            }
        }
    });
    groups_current && pruned_clean
}

#[cfg(all(test, unix))]
#[path = "claude_session_start_contract_tests.rs"]
mod tests;
