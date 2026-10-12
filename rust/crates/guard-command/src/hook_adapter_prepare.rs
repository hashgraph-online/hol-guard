//! Per-harness hook payload preparation (Grok, ZCode, Devin, Cursor, Hermes,
//! Kimi; Cline lives in `hook_adapter_prepare_cline`). Ports the Python
//! `prepare_*_hook_payload` functions that map host stdin JSON onto the shared
//! Guard hook shape.

use crate::hook_adapter_prepare_cursor::prepare_cursor;
use crate::hook_adapter_pytext::{py_lower, py_strip};
use crate::hook_adapter_value::{OMap, OValue, PyJsonError};

/// Typed failure of the adapter port. Every variant fails closed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdapterError {
    /// `ClinePayloadError(message)`.
    ClinePayload(String),
    /// A value CPython accepts but the port cannot represent faithfully.
    Unsupported(&'static str),
    /// `Unsupported Guard harness for action normalization: {harness}`.
    UnsupportedHarness(String),
}

impl From<PyJsonError> for AdapterError {
    fn from(_: PyJsonError) -> Self {
        Self::Unsupported("native_hook_adapter_json_unsupported")
    }
}

/// Harness names the prepare step knows. Everything else is identity.
pub fn prepare_payload(
    harness: &str,
    payload: &OMap,
    devin_project_dir: Option<&str>,
) -> Result<OMap, AdapterError> {
    match harness {
        "grok" => Ok(prepare_grok(payload)),
        "zcode" => Ok(prepare_zcode(payload)),
        "devin" => Ok(prepare_devin(payload, devin_project_dir)),
        "cursor" => prepare_cursor(payload),
        "hermes" => Ok(prepare_hermes(payload)),
        "kimi" => Ok(prepare_kimi(payload)),
        "cline" => crate::hook_adapter_prepare_cline::prepare_cline(payload),
        _ => Ok(payload.clone()),
    }
}

/// Python `a or b` over optional JSON values: `a` when truthy, else `b`.
pub fn first_truthy<'a>(
    first: Option<&'a OValue>,
    second: Option<&'a OValue>,
) -> Option<&'a OValue> {
    match first {
        Some(value) if value.truthy() => Some(value),
        _ => second,
    }
}

/// Python `_string(x)`: stripped text for a non-blank string, else `None`.
pub fn string_value(value: Option<&OValue>) -> Option<String> {
    value
        .and_then(OValue::non_blank_str)
        .map(|text| py_strip(text).to_owned())
}

pub(crate) fn raw_event_name(payload: &OMap, keys: &[&str]) -> String {
    for key in keys {
        if let Some(text) = payload.get(key).and_then(OValue::non_blank_str) {
            return py_lower(py_strip(text));
        }
    }
    String::new()
}

fn compact_event(raw_event: &str) -> String {
    py_lower(&raw_event.replace(['_', '-'], ""))
}

fn canonical_name_or(table: &[(&str, &str)], raw_event: &str) -> String {
    let compact = compact_event(raw_event);
    for (key, canonical) in table {
        if *key == compact {
            return (*canonical).to_owned();
        }
    }
    if raw_event.is_empty() {
        "PreToolUse".to_owned()
    } else {
        raw_event.to_owned()
    }
}

fn canonical_tool_name(table: &[(&str, &str)], raw_tool: Option<&OValue>) -> Option<String> {
    let stripped = string_value(raw_tool)?;
    let lowered = py_lower(&stripped);
    for (alias, canonical) in table {
        if *alias == lowered {
            return Some((*canonical).to_owned());
        }
    }
    Some(stripped)
}

/// `normalize_session_and_workspace_aliases`.
pub fn normalize_session_and_workspace_aliases(normalized: &mut OMap) {
    if normalized.get_non_null("session_id").is_none() {
        if let Some(OValue::Str(alias)) = normalized.get("sessionId").cloned() {
            normalized.insert("session_id", OValue::Str(alias));
        }
    }
    if normalized.get_non_null("workspace_root").is_none() {
        if let Some(OValue::Str(alias)) = normalized.get("workspaceRoot").cloned() {
            normalized.insert("workspace_root", OValue::Str(alias));
        } else if let Some(OValue::Str(cwd)) = normalized.get("cwd").cloned() {
            normalized.insert("workspace_root", OValue::Str(cwd));
        }
    }
}

fn first_present<'a>(payload: &'a OMap, keys: &[&str]) -> Option<&'a OValue> {
    keys.iter().find_map(|key| payload.get_non_null(key))
}

// ---------------------------------------------------------------- Grok

const GROK_TOOL_ALIASES: &[(&str, &str)] = &[
    ("run_terminal_command", "Bash"),
    ("read_file", "Read"),
    ("search_replace", "Edit"),
    ("write", "Edit"),
    ("write_file", "Edit"),
    ("multi_edit", "Edit"),
    ("multiedit", "Edit"),
    ("grep", "Grep"),
    ("glob", "Grep"),
    ("list_dir", "Read"),
    ("listdir", "Read"),
    ("web_fetch", "WebFetch"),
    ("web_search", "WebFetch"),
    ("open_page", "WebFetch"),
    ("open_page_with_find", "WebFetch"),
    ("spawn_subagent", "Task"),
    ("task", "Task"),
    ("use_tool", "MCPTool"),
    ("callmcptool", "MCPTool"),
];

const GROK_EVENT_NAMES: &[(&str, &str)] = &[
    ("pretooluse", "PreToolUse"),
    ("userpromptsubmit", "UserPromptSubmit"),
    ("userpromptsubmitted", "UserPromptSubmit"),
    ("posttooluse", "PostToolUse"),
    ("posttoolusefailure", "PostToolUse"),
    ("sessionstart", "SessionStart"),
    ("sessionend", "SessionEnd"),
    ("stop", "Stop"),
    ("subagentstart", "SubagentStart"),
    ("subagentstop", "SubagentStop"),
    ("subagentend", "SubagentStop"),
    ("permissiondenied", "PermissionDenied"),
];

fn native_mcp_envelope(tool_input: &OMap) -> bool {
    tool_input
        .get("server")
        .and_then(OValue::non_blank_str)
        .is_some()
        && tool_input
            .get("tool")
            .and_then(OValue::non_blank_str)
            .is_some()
}

fn unwrap_dispatcher_tool(
    tool_name: Option<String>,
    tool_input: Option<OMap>,
) -> (Option<String>, Option<OMap>) {
    let (Some(name), Some(input)) = (&tool_name, &tool_input) else {
        return (tool_name, tool_input);
    };
    if name != "MCPTool" || native_mcp_envelope(input) {
        return (tool_name, tool_input);
    }
    for key in ["tool_name", "toolName", "name", "tool"] {
        let Some(inner) = input.get(key).and_then(OValue::non_blank_str) else {
            continue;
        };
        let inner = py_strip(inner);
        if inner == "MCPTool" {
            continue;
        }
        let nested = first_truthy(input.get("arguments"), input.get("toolInput"))
            .and_then(OValue::as_map)
            .filter(|map| !map.is_empty())
            .cloned();
        return (Some(inner.to_owned()), nested.or(tool_input.clone()));
    }
    (tool_name, tool_input)
}

fn apply_qualified_mcp_tool(normalized: &mut OMap, tool_name: String) -> String {
    let lowered = py_lower(&tool_name);
    if !tool_name.contains("__") || GROK_TOOL_ALIASES.iter().any(|(alias, _)| *alias == lowered) {
        return tool_name;
    }
    let Some((server, tool)) = tool_name.split_once("__") else {
        return tool_name;
    };
    if server.is_empty() || tool.is_empty() {
        return tool_name;
    }
    normalized.insert("mcp_server", OValue::str(server));
    normalized.insert("mcp_tool", OValue::str(tool));
    normalized.insert("original_tool_name", OValue::str(tool_name.as_str()));
    "MCPTool".to_owned()
}

fn prepare_grok(payload: &OMap) -> OMap {
    let mut normalized = payload.clone();
    let raw_event = raw_event_name(&normalized, &["hook_event_name", "hookEventName"]);
    if !raw_event.is_empty() {
        normalized.insert(
            "hook_event_name",
            OValue::Str(canonical_name_or(GROK_EVENT_NAMES, &raw_event)),
        );
        if compact_event(&raw_event) == "posttoolusefailure" {
            normalized.insert("failed", OValue::Bool(true));
        }
    }
    let tool_name = first_present(&normalized, &["tool_name", "toolName"]).cloned();
    let tool_input = first_present(&normalized, &["tool_input", "toolInput"]).cloned();
    let mapped_input = tool_input.as_ref().and_then(OValue::as_map).cloned();
    let canonical_tool = canonical_tool_name(GROK_TOOL_ALIASES, tool_name.as_ref());
    let (mut canonical_tool, mapped_input) = unwrap_dispatcher_tool(canonical_tool, mapped_input);
    if let Some(current) = canonical_tool.take() {
        let remapped = canonical_tool_name(GROK_TOOL_ALIASES, Some(&OValue::Str(current.clone())))
            .unwrap_or(current);
        let qualified = apply_qualified_mcp_tool(&mut normalized, remapped);
        normalized.insert("tool_name", OValue::str(qualified.as_str()));
        canonical_tool = Some(qualified);
    }
    let mut effective_input = tool_input.clone();
    if let Some(mapped) = mapped_input {
        if canonical_tool.as_deref() == Some("MCPTool") && native_mcp_envelope(&mapped) {
            let server = string_value(mapped.get("server")).unwrap_or_default();
            let tool = string_value(mapped.get("tool")).unwrap_or_default();
            normalized.set_default("mcp_server", OValue::Str(server));
            normalized.set_default("mcp_tool", OValue::Str(tool));
        }
        normalized.insert("tool_input", OValue::Map(mapped.clone()));
        effective_input = Some(OValue::Map(mapped));
    } else if let Some(original) = tool_input {
        normalized.insert("tool_input", original);
    }
    normalize_session_and_workspace_aliases(&mut normalized);
    for (camel, snake) in [
        ("permissionMode", "permission_mode"),
        ("subagentType", "subagent_type"),
    ] {
        if let Some(OValue::Str(value)) = normalized.get(camel).cloned() {
            normalized.set_default(snake, OValue::Str(value));
        }
    }
    let prompt_absent = normalized.get_non_null("prompt").is_none();
    if prompt_absent {
        if let Some(OValue::Str(value)) = normalized.get("userPrompt").cloned() {
            normalized.insert("prompt", OValue::Str(value));
        }
    }
    let task_input = match (&canonical_tool, &effective_input) {
        (Some(tool), Some(OValue::Map(map))) if tool == "Task" => Some(map),
        _ => None,
    };
    if let Some(map) = task_input {
        if prompt_absent {
            if let Some(OValue::Str(value)) = map.get("prompt") {
                normalized.insert("prompt", OValue::Str(value.clone()));
            }
        }
        let subagent = first_truthy(map.get("subagent_type"), map.get("subagentType"));
        if let Some(text) = subagent.and_then(OValue::non_blank_str) {
            normalized.insert("subagent_type", OValue::str(py_strip(text)));
        }
    }
    normalized
}

// --------------------------------------------------------------- ZCode

const ZCODE_TOOL_ALIASES: &[(&str, &str)] = &[
    ("run_terminal_command", "Bash"),
    ("run_command", "Bash"),
    ("read_file", "Read"),
    ("write_file", "Write"),
    ("search_replace", "Edit"),
    ("multi_edit", "MultiEdit"),
    ("grep", "Grep"),
    ("web_fetch", "WebFetch"),
    ("web_search", "WebSearch"),
];

const ZCODE_EVENT_NAMES: &[(&str, &str)] = &[
    ("pretooluse", "PreToolUse"),
    ("userpromptsubmit", "UserPromptSubmit"),
    ("posttooluse", "PostToolUse"),
    ("posttoolusefailure", "PostToolUseFailure"),
    ("sessionstart", "SessionStart"),
    ("notification", "Notification"),
    ("permissionrequest", "PermissionRequest"),
    ("stop", "Stop"),
];

fn prepare_claude_shaped(payload: &OMap, events: &[(&str, &str)], tools: &[(&str, &str)]) -> OMap {
    let mut normalized = payload.clone();
    let raw_event = raw_event_name(&normalized, &["hook_event_name", "hookEventName"]);
    if !raw_event.is_empty() {
        normalized.insert(
            "hook_event_name",
            OValue::Str(canonical_name_or(events, &raw_event)),
        );
    }
    let tool_name = first_present(&normalized, &["tool_name", "toolName"]).cloned();
    if let Some(canonical) = canonical_tool_name(tools, tool_name.as_ref()) {
        normalized.insert("tool_name", OValue::Str(canonical));
    }
    if let Some(tool_input) =
        first_present(&normalized, &["tool_input", "toolInput", "arguments"]).cloned()
    {
        normalized.insert("tool_input", tool_input);
    }
    normalized
}

fn finish_claude_shaped(normalized: &mut OMap) {
    normalize_session_and_workspace_aliases(normalized);
    if normalized.get_non_null("prompt").is_none() {
        if let Some(OValue::Str(value)) = normalized.get("userPrompt").cloned() {
            normalized.insert("prompt", OValue::Str(value));
        }
    }
}

fn prepare_zcode(payload: &OMap) -> OMap {
    let mut normalized = prepare_claude_shaped(payload, ZCODE_EVENT_NAMES, ZCODE_TOOL_ALIASES);
    finish_claude_shaped(&mut normalized);
    normalized
}

// --------------------------------------------------------------- Devin

const DEVIN_TOOL_ALIASES: &[(&str, &str)] = &[
    ("exec", "Bash"),
    ("read", "Read"),
    ("notebook_read", "Read"),
    ("write", "Write"),
    ("edit", "Edit"),
    ("notebook_edit", "Edit"),
    ("webfetch", "WebFetch"),
    ("grep", "Grep"),
    ("glob", "Glob"),
];

const DEVIN_EVENT_NAMES: &[(&str, &str)] = &[
    ("pretooluse", "PreToolUse"),
    ("userpromptsubmit", "UserPromptSubmit"),
    ("posttooluse", "PostToolUse"),
    ("permissionrequest", "PermissionRequest"),
    ("postcompaction", "PostCompaction"),
    ("sessionstart", "SessionStart"),
    ("sessionend", "SessionEnd"),
    ("notification", "Notification"),
    ("stop", "Stop"),
];

fn apply_devin_mcp_call(normalized: &mut OMap) {
    let is_dispatch = match normalized.get("tool_name") {
        Some(OValue::Str(name)) => py_lower(py_strip(name)) == "mcp_call_tool",
        _ => false,
    };
    if !is_dispatch {
        return;
    }
    let Some(OValue::Map(tool_input)) = normalized.get("tool_input").cloned() else {
        return;
    };
    let (Some(OValue::Str(server)), Some(OValue::Str(tool))) =
        (tool_input.get("server_name"), tool_input.get("tool_name"))
    else {
        return;
    };
    if py_strip(server).is_empty() || py_strip(tool).is_empty() {
        return;
    }
    let mut call = OMap::new();
    call.insert("server_name", OValue::str(server.as_str()));
    call.insert("tool_name", OValue::str(tool.as_str()));
    normalized.insert("devin_mcp_call", OValue::Map(call));
    normalized.insert(
        "tool_name",
        OValue::Str(format!("mcp__{}__{}", py_strip(server), py_strip(tool))),
    );
    let arguments = match tool_input.get("arguments") {
        Some(OValue::Map(map)) => map.clone(),
        _ => OMap::new(),
    };
    normalized.insert("tool_input", OValue::Map(arguments));
}

fn prepare_devin(payload: &OMap, project_dir: Option<&str>) -> OMap {
    let mut normalized = prepare_claude_shaped(payload, DEVIN_EVENT_NAMES, DEVIN_TOOL_ALIASES);
    apply_devin_mcp_call(&mut normalized);
    if normalized.get_non_null("cwd").is_none() && normalized.get_non_null("workspace").is_none() {
        if let Some(dir) = project_dir.filter(|dir| !py_strip(dir).is_empty()) {
            normalized.insert("cwd", OValue::str(py_strip(dir)));
        }
    }
    finish_claude_shaped(&mut normalized);
    normalized
}

// -------------------------------------------------------------- Hermes

fn prepare_hermes(payload: &OMap) -> OMap {
    let mut normalized = payload.clone();
    if let Some(OValue::Str(event)) = normalized.get("hook_event_name") {
        if py_lower(&event.replace(['_', '-'], "")) == "pretoolcall" {
            normalized.insert("hook_event_name", OValue::str("PreToolUse"));
        }
    }
    if !matches!(normalized.get("tool_input"), Some(OValue::Map(_))) {
        if let Some(OValue::Map(args)) = normalized.get("args").cloned() {
            normalized.insert("tool_input", OValue::Map(args));
        }
    }
    normalized
}

// ---------------------------------------------------------------- Kimi

fn prepare_kimi(payload: &OMap) -> OMap {
    let mut normalized = payload.clone();
    let prompt = match normalized.get_non_null("prompt") {
        None => OValue::Null,
        Some(OValue::List(items)) => {
            let parts: Vec<&str> = items
                .iter()
                .filter_map(|item| item.as_map()?.get("text")?.as_str())
                .collect();
            if parts.is_empty() {
                OValue::List(items.clone())
            } else {
                OValue::Str(parts.join("\n"))
            }
        }
        Some(other) => other.clone(),
    };
    normalized.insert("prompt", prompt);
    normalized
}
