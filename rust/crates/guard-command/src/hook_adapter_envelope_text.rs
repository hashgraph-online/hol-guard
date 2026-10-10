//! Text, tool-input and MCP helpers behind the hook action envelope
//! (`runtime/actions.py`).

use std::sync::LazyLock;

use fancy_regex::Regex as FancyRegex;

pub(crate) use crate::hook_adapter_envelope_tables::*;
use crate::hook_adapter_prepare::AdapterError;
use crate::hook_adapter_pytext::{
    compile, compile_fancy, dedupe_preserving_order, fancy_find_group_all, py_lower, py_strip,
    shlex_join,
};
use crate::hook_adapter_value::{parse_python_json, OMap, OValue, PyJsonError};

static PATCH_HEADER: LazyLock<regex::Regex> =
    LazyLock::new(|| compile(r"(?m)^\*\*\* (?:Add|Delete|Update) File: (?P<path>.+)$"));
pub static PROMPT_PATH: LazyLock<FancyRegex> = LazyLock::new(|| {
    compile_fancy(concat!(
        r"(?<![A-Za-z0-9_./-])",
        r"(?P<path>(?:",
        r"(?:~|\.{1,2})?/?(?:[A-Za-z0-9_.-]+/)*(?:\.npmrc|\.env(?:\.[A-Za-z0-9_-]+)?|id_rsa|id_ed25519)",
        r"|(?:~|\.{1,2})?/?(?:[A-Za-z0-9_.-]+/)+credentials",
        r"))",
        r"(?![A-Za-z0-9_.-])"
    ))
});
static NETWORK_HOST: LazyLock<FancyRegex> = LazyLock::new(|| {
    compile_fancy(r"(?:https?|wss?|grpcs?)://(?P<host>[A-Za-z0-9.-]+)(?::\d+)?(?:[/?#]|(?=\n?\z))")
});
static SECRET_KEY_BOUNDARY: LazyLock<regex::Regex> =
    LazyLock::new(|| compile(r"([a-z0-9])([A-Z])"));
static MCP_TOKEN_RUN: LazyLock<regex::Regex> = LazyLock::new(|| compile(r"[^a-z0-9]+"));

pub fn is_shell_tool(tool_name: Option<&str>) -> bool {
    tool_name.is_some_and(|name| SHELL_TOOL_NAMES.contains(&py_lower(py_strip(name)).as_str()))
}

/// `_string_value`: stripped non-blank string.
pub fn string_value(value: Option<&OValue>) -> Option<String> {
    value
        .and_then(OValue::non_blank_str)
        .map(|text| py_strip(text).to_owned())
}

fn string_from_keys(payload: &OMap, keys: &[&str]) -> Option<String> {
    keys.iter().find_map(|key| string_value(payload.get(key)))
}

pub fn tool_name_from_payload(payload: &OMap) -> Option<String> {
    string_from_keys(payload, &["tool_name", "toolName", "name", "tool"])
}

/// `_mapping_from_value`.
pub fn mapping_from_value(value: Option<&OValue>) -> Result<Option<OMap>, AdapterError> {
    match value {
        Some(OValue::Map(map)) => Ok(Some(map.clone())),
        Some(OValue::Str(text)) if !py_strip(text).is_empty() => match parse_python_json(text) {
            Ok(OValue::Map(map)) => Ok(Some(map)),
            Ok(_) | Err(PyJsonError::Decode) => Ok(None),
            Err(PyJsonError::Unsupported) => Err(PyJsonError::Unsupported.into()),
        },
        _ => Ok(None),
    }
}

pub fn tool_input_from_payload(payload: &OMap) -> Result<OMap, AdapterError> {
    for key in ["tool_input", "toolInput", "toolArgs", "arguments"] {
        if let Some(parsed) = mapping_from_value(payload.get(key))? {
            return Ok(parsed);
        }
    }
    Ok(OMap::new())
}

/// `_tool_call_from_payload`.
pub fn tool_call_from_payload(
    value: Option<&OValue>,
    expected: Option<&str>,
) -> Result<(Option<String>, Option<OMap>), AdapterError> {
    let Some(OValue::List(items)) = value else {
        return Ok((None, None));
    };
    let mut fallback: Option<(String, Option<OMap>)> = None;
    for item in items {
        let OValue::Map(item) = item else { continue };
        let Some(name) = string_value(item.get("name")) else {
            continue;
        };
        let input = mapping_from_value(item.get("args"))?;
        if fallback.is_none() {
            fallback = Some((name.clone(), input.clone()));
        }
        if expected.is_none() || expected == Some(name.as_str()) {
            return Ok((Some(name), input));
        }
    }
    Ok(match fallback {
        Some((name, input)) => (Some(name), input),
        None => (None, None),
    })
}

const HOOK_EVENT_NAME_MAP: &[(&str, &str)] = &[
    ("prompt", "UserPromptSubmit"),
    ("userpromptsubmit", "UserPromptSubmit"),
    ("userpromptsubmitted", "UserPromptSubmit"),
    ("pretool", "PreToolUse"),
    ("pretooluse", "PreToolUse"),
    ("posttool", "PostToolUse"),
    ("posttooluse", "PostToolUse"),
    ("permissionrequest", "PermissionRequest"),
    ("permissionrequestv2", "PermissionRequest"),
];

pub fn hook_event_name(payload: &OMap) -> String {
    for key in [
        "event",
        "eventName",
        "hook_event_name",
        "hookEventName",
        "hook_name",
        "hookName",
    ] {
        if let Some(text) = payload.get(key).and_then(OValue::non_blank_str) {
            let stripped = py_strip(text);
            let lowered = py_lower(stripped);
            return HOOK_EVENT_NAME_MAP
                .iter()
                .find(|(alias, _)| *alias == lowered)
                .map_or_else(|| stripped.to_owned(), |(_, name)| (*name).to_owned());
        }
    }
    "PreToolUse".to_owned()
}

/// `_prompt_value`: the first non-blank string (unstripped).
pub fn prompt_value(payload: &OMap) -> Option<String> {
    [
        "prompt",
        "userPrompt",
        "user_prompt",
        "message",
        "text",
        "input",
    ]
    .iter()
    .find_map(|key| payload.get(key).and_then(OValue::non_blank_str))
    .map(str::to_owned)
}

fn first_input_string(tool_input: &OMap, keys: &[&str]) -> Option<String> {
    keys.iter()
        .find_map(|key| string_value(tool_input.get(key)))
}

fn nonnegative_int(value: Option<&OValue>) -> Option<String> {
    match value? {
        OValue::Int(token) => Some(if token.starts_with('-') {
            "0".to_owned()
        } else {
            token.clone()
        }),
        OValue::Float(token) => {
            let parsed: f64 = token.parse().ok()?;
            (parsed.is_finite() && parsed.fract() == 0.0).then(|| {
                if parsed <= 0.0 {
                    "0".to_owned()
                } else {
                    format!("{parsed:.0}")
                }
            })
        }
        _ => None,
    }
}

fn flag_true(tool_input: &OMap, key: &str) -> bool {
    matches!(tool_input.get(key), Some(OValue::Bool(true)))
}

fn grep_tool_command_text(executable: &str, tool_input: &OMap) -> Option<String> {
    let pattern = first_input_string(tool_input, SEARCH_PATTERN_KEYS)?;
    let mut args = vec![executable.to_owned()];
    if flag_true(tool_input, "ignoreCase") || flag_true(tool_input, "ignore_case") {
        args.push("-i".to_owned());
    }
    if flag_true(tool_input, "literal") || executable == "fgrep" {
        args.push("-F".to_owned());
    }
    if let Some(context) = nonnegative_int(tool_input.get("context")) {
        if context != "0" {
            args.push("-C".to_owned());
            args.push(context);
        }
    }
    if let Some(glob) = first_input_string(tool_input, &["glob", "include", "includes"]) {
        args.push(
            if executable == "rg" {
                "--glob"
            } else {
                "--include"
            }
            .to_owned(),
        );
        args.push(glob);
    }
    args.push(pattern);
    let path = first_input_string(
        tool_input,
        &[
            "path",
            "file_path",
            "filePath",
            "filepath",
            "file",
            "filename",
        ],
    );
    args.push(path.unwrap_or_else(|| ".".to_owned()));
    Some(shlex_join(&args))
}

/// `_mcp_parts` for a tool name and the known server list.
pub fn mcp_parts(
    tool_name: Option<&str>,
    known_servers: &[String],
) -> (Option<String>, Option<String>) {
    let Some(name) = tool_name else {
        return (None, None);
    };
    if let Some((server, tool)) = name.split_once('/') {
        return if !server.is_empty() && !tool.is_empty() {
            (Some(server.to_owned()), Some(tool.to_owned()))
        } else {
            (None, None)
        };
    }
    if name.starts_with("mcp__") {
        let parts: Vec<&str> = name.splitn(3, "__").collect();
        if parts.len() == 3 && !parts[1].is_empty() && !parts[2].is_empty() {
            return (Some(parts[1].to_owned()), Some(parts[2].to_owned()));
        }
        return (None, None);
    }
    if let Some(suffix) = name.strip_prefix("mcp_") {
        for server in known_servers {
            let prefix = format!("{}_", mcp_server_token(server));
            if let Some(tool) = suffix.strip_prefix(prefix.as_str()) {
                return if tool.is_empty() {
                    (None, None)
                } else {
                    (Some(server.clone()), Some(tool.to_owned()))
                };
            }
        }
    }
    (None, None)
}

fn mcp_server_token(value: &str) -> String {
    let lowered = py_lower(py_strip(value));
    let replaced = MCP_TOKEN_RUN.replace_all(&lowered, "_");
    replaced.trim_matches('_').to_owned()
}

/// `command_text_from_tool_payload`.
pub fn command_text_from_tool_payload(
    tool_name: Option<&str>,
    tool_input: &OMap,
) -> Option<String> {
    for key in EXPLICIT_COMMAND_KEYS {
        if let Some(value) = string_value(tool_input.get(key)) {
            return Some(value);
        }
    }
    if let Some(name) = tool_name {
        let lowered = py_lower(py_strip(name));
        if matches!(lowered.as_str(), "grep" | "egrep" | "fgrep" | "rg") {
            if let Some(command) = grep_tool_command_text(&lowered, tool_input) {
                return Some(command);
            }
        }
    }
    let normalized_tool = tool_name.map(py_strip);
    if mcp_parts(normalized_tool, &[]).0.is_some() {
        return None;
    }
    first_input_string(tool_input, COMMAND_KEYS)
}

fn known_mcp_servers(payload: &OMap) -> Vec<String> {
    let mut servers: Vec<String> = Vec::new();
    for key in ["mcp_servers", "mcpServers", "servers"] {
        match payload.get(key) {
            Some(OValue::Map(map)) => {
                servers.extend(map.iter().map(|(name, _)| py_strip(name).to_owned()));
            }
            Some(OValue::List(items)) => {
                servers.extend(
                    items
                        .iter()
                        .filter_map(OValue::non_blank_str)
                        .map(|text| py_strip(text).to_owned()),
                );
            }
            _ => {}
        }
    }
    servers.retain(|server| !server.is_empty());
    servers.sort();
    servers.dedup();
    servers.sort_by_key(|server| std::cmp::Reverse(mcp_server_token(server).chars().count()));
    servers
}

/// `_mcp_details`.
pub fn mcp_details(payload: &OMap, tool_name: Option<&str>) -> (Option<String>, Option<String>) {
    let explicit_server = string_from_keys(
        payload,
        &["mcp_server", "mcpServer", "server", "serverName"],
    );
    let explicit_tool = string_from_keys(payload, &["mcp_tool", "mcpTool"]);
    let tool_name_value = string_from_keys(payload, &["tool_name", "toolName"]);
    let (parts_server, parts_tool) = mcp_parts(tool_name, &known_mcp_servers(payload));
    let server = explicit_server.or(parts_server);
    let mut tool = explicit_tool.or(parts_tool);
    if tool.is_none() && server.is_some() {
        tool = tool_name_value;
    }
    (server, tool)
}

/// `_action_type`.
pub fn action_type(
    event_name: &str,
    tool_name: Option<&str>,
    command: Option<&str>,
    prompt_excerpt: Option<&str>,
    mcp_server: Option<&str>,
) -> &'static str {
    let tool = tool_name.map(py_lower).unwrap_or_default();
    let tool = tool.as_str();
    if event_name == "UserPromptSubmit" && prompt_excerpt.is_some() {
        "prompt"
    } else if mcp_server.is_some() {
        "mcp_tool"
    } else if FILE_READ_TOOL_NAMES.contains(&tool) {
        "file_read"
    } else if FILE_WRITE_TOOL_NAMES.contains(&tool) {
        "file_write"
    } else if SHELL_TOOL_NAMES.contains(&tool) || command.is_some() {
        "shell_command"
    } else {
        "config_change"
    }
}

fn input_strings(tool_input: &OMap, key: &str, out: &mut Vec<String>) {
    match tool_input.get(key) {
        Some(OValue::Str(text)) if !py_strip(text).is_empty() => {
            out.push(py_strip(text).to_owned())
        }
        Some(OValue::List(items)) => out.extend(
            items
                .iter()
                .filter_map(OValue::non_blank_str)
                .map(|text| py_strip(text).to_owned()),
        ),
        _ => {}
    }
}

/// Raw (pre-redaction) target paths, in Python order.
pub fn raw_target_paths(
    tool_name: Option<&str>,
    tool_input: &OMap,
    command: Option<&str>,
    prompt_text: Option<&str>,
) -> Vec<String> {
    let mut paths = Vec::new();
    for key in PATH_KEYS {
        input_strings(tool_input, key, &mut paths);
    }
    if tool_name.is_some_and(|name| py_lower(py_strip(name)) == "apply_patch") {
        paths.extend(apply_patch_target_paths(tool_input));
    }
    for text in [command, prompt_text].into_iter().flatten() {
        paths.extend(fancy_find_group_all(&PROMPT_PATH, text, "path"));
    }
    paths
}

pub fn apply_patch_target_paths(tool_input: &OMap) -> Vec<String> {
    let mut paths = Vec::new();
    for key in PATCH_INPUT_KEYS {
        let Some(patch) = tool_input.get(key).and_then(OValue::non_blank_str) else {
            continue;
        };
        for captures in PATCH_HEADER.captures_iter(patch) {
            if let Some(path) = captures.name("path") {
                paths.push(py_strip(path.as_str()).to_owned());
            }
        }
    }
    dedupe_preserving_order(paths)
}

/// `_cursor_tool_input_urls`.
pub fn cursor_tool_input_urls(tool_input: Option<&OValue>) -> Vec<String> {
    let Some(OValue::Map(map)) = tool_input else {
        return Vec::new();
    };
    let mut urls = Vec::new();
    for key in CURSOR_NETWORK_URL_KEYS {
        input_strings(map, key, &mut urls);
    }
    urls
}

/// Hosts found in `texts`, de-duplicated in first-seen order.
pub fn hosts_in(texts: &[&str]) -> Vec<String> {
    let mut hosts = Vec::new();
    for text in texts {
        hosts.extend(fancy_find_group_all(&NETWORK_HOST, text, "host"));
    }
    dedupe_preserving_order(hosts)
}

/// `_network_hosts(command, prompt)`.
pub fn network_hosts(command: Option<&str>, prompt_text: Option<&str>) -> Vec<String> {
    let text = [command, prompt_text]
        .into_iter()
        .flatten()
        .filter(|value| !value.is_empty())
        .collect::<Vec<_>>()
        .join("\n");
    if text.is_empty() {
        return Vec::new();
    }
    hosts_in(&[text.as_str()])
}

/// `_normalized_secret_key`.
pub fn normalized_secret_key(key: &str) -> String {
    let replaced = key.replace('-', "_");
    py_lower(&SECRET_KEY_BOUNDARY.replace_all(&replaced, "${1}_${2}"))
}

/// `_payload_with_default_event`.
pub fn payload_with_default_event(payload: &OMap, event_name: &str) -> OMap {
    let mut normalized = payload.clone();
    if py_strip(event_name).is_empty() {
        return normalized;
    }
    for key in [
        "event",
        "eventName",
        "hook_event_name",
        "hookEventName",
        "hook_name",
        "hookName",
    ] {
        if normalized
            .get(key)
            .and_then(OValue::non_blank_str)
            .is_some()
        {
            return normalized;
        }
    }
    normalized.insert("hook_event_name", OValue::str(event_name));
    normalized
}
