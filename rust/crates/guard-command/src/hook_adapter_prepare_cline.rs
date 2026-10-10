//! Cline hook payload preparation (typed `tool_call` and legacy `preToolUse`
//! shapes reconciled onto the shared Guard hook shape).

use crate::hook_adapter_cline_tables::*;
use crate::hook_adapter_prepare::{first_truthy, string_value, AdapterError};
use crate::hook_adapter_pytext::{dedupe_preserving_order, py_lower, py_repr_str, py_strip};
use crate::hook_adapter_value::{parse_python_json, OMap, OValue, PyJsonError};

/// Lowercased tool name when the host sent a string (`_NETWORK_TOOLS` gate).
pub fn is_cline_network_tool(name: &str) -> bool {
    NETWORK_TOOLS.contains(&py_lower(name).as_str())
}

type ToolParts = (Option<String>, OValue, Option<OValue>);

fn mapping(value: Option<&OValue>) -> OMap {
    value.and_then(OValue::as_map).cloned().unwrap_or_default()
}

fn decoded_parameter(value: &OValue) -> Result<OValue, AdapterError> {
    let OValue::Str(text) = value else {
        return Ok(value.clone());
    };
    let stripped = py_strip(text);
    let Some(first) = stripped.chars().next() else {
        return Ok(value.clone());
    };
    if !"[{\"-0123456789tfn".contains(first) {
        return Ok(value.clone());
    }
    match parse_python_json(stripped) {
        Ok(decoded) => Ok(decoded),
        Err(PyJsonError::Decode) => Ok(value.clone()),
        Err(PyJsonError::Unsupported) => Err(PyJsonError::Unsupported.into()),
    }
}

fn decode_parameter_map(value: Option<&OValue>) -> Result<OValue, AdapterError> {
    let mut decoded = OMap::new();
    for (key, item) in mapping(value).iter() {
        decoded.insert(key, decoded_parameter(item)?);
    }
    Ok(OValue::Map(decoded))
}

fn event_name(payload: &OMap) -> String {
    for key in [
        "hook_event_name",
        "hookEventName",
        "hook_name",
        "hookName",
        "event",
        "eventName",
    ] {
        if let Some(value) = string_value(payload.get(key)) {
            let lookup = py_lower(&value).replace('-', "_");
            return EVENT_NAMES
                .iter()
                .find(|(alias, _)| *alias == lookup)
                .map_or(value, |(_, canonical)| (*canonical).to_owned());
        }
    }
    let is_map = |key: &str| matches!(payload.get(key), Some(OValue::Map(_)));
    if is_map("tool_call") || is_map("preToolUse") {
        "PreToolUse"
    } else if is_map("tool_result") || is_map("postToolUse") {
        "PostToolUse"
    } else if is_map("userPromptSubmit") {
        "UserPromptSubmit"
    } else {
        "PreToolUse"
    }
    .to_owned()
}

fn current_tool(payload: &OMap, event: &str) -> ToolParts {
    let post = event == "PostToolUse";
    let current = mapping(payload.get(if post { "tool_result" } else { "tool_call" }));
    if current.is_empty() {
        return (None, OValue::Map(OMap::new()), None);
    }
    let name = string_value(current.get("name"));
    let input = current
        .get("input")
        .cloned()
        .unwrap_or_else(|| OValue::Map(OMap::new()));
    let output = if post {
        current.get("output").cloned()
    } else {
        None
    };
    (name, input, output)
}

fn legacy_tool(payload: &OMap, event: &str) -> Result<ToolParts, AdapterError> {
    let post = event == "PostToolUse";
    let legacy = mapping(payload.get(if post { "postToolUse" } else { "preToolUse" }));
    if legacy.is_empty() {
        return Ok((None, OValue::Map(OMap::new()), None));
    }
    let name = string_value(first_truthy(
        legacy.get("toolName"),
        legacy.get("tool_name"),
    ));
    let input = decode_parameter_map(legacy.get("parameters"))?;
    let output = if post {
        legacy.get("result").cloned()
    } else {
        None
    };
    Ok((name, input, output))
}

fn single(key: &str, value: &OValue) -> OValue {
    let mut map = OMap::new();
    map.insert(key, value.clone());
    OValue::Map(map)
}

fn input_object(tool_name: Option<&str>, value: &OValue) -> OMap {
    if let OValue::Map(map) = value {
        return map.clone();
    }
    let lowered = tool_name.map(py_lower).unwrap_or_default();
    let lowered = lowered.as_str();
    let is_str_or_list = matches!(value, OValue::Str(_) | OValue::List(_));
    let is_str = matches!(value, OValue::Str(_));
    let wrapped = if SHELL_TOOLS.contains(&lowered) && is_str_or_list {
        Some(single("commands", value))
    } else if READ_TOOLS.contains(&lowered) && is_str_or_list {
        Some(single("files", value))
    } else if WRITE_TOOLS.contains(&lowered) && is_str {
        let key = if matches!(lowered, "apply_patch" | "patch") {
            "patch"
        } else {
            "path"
        };
        Some(single(key, value))
    } else if NETWORK_TOOLS.contains(&lowered) && is_str {
        Some(single("url", value))
    } else if !value.is_empty_dict_or_null() {
        Some(single("value", value))
    } else {
        None
    };
    match wrapped {
        Some(OValue::Map(map)) => map,
        _ => OMap::new(),
    }
}

fn assert_compatible(current: &ToolParts, legacy: &ToolParts) -> Result<(), AdapterError> {
    if let (Some(left), Some(right)) = (&current.0, &legacy.0) {
        if left != right {
            return Err(AdapterError::ClinePayload(format!(
                "Cline hook tool names disagree: {} != {}",
                py_repr_str(left),
                py_repr_str(right)
            )));
        }
    }
    let name = current.0.as_deref().or(legacy.0.as_deref());
    let left = input_object(name, &current.1);
    let right = input_object(name, &legacy.1);
    if !left.is_empty()
        && !right.is_empty()
        && OValue::Map(left).canonical_json() != OValue::Map(right).canonical_json()
    {
        return Err(AdapterError::ClinePayload(
            "Cline hook typed and compatibility tool inputs disagree".to_owned(),
        ));
    }
    Ok(())
}

fn commands_from_input(tool_input: &OMap) -> Vec<String> {
    match tool_input.get("commands") {
        Some(OValue::Str(text)) if !py_strip(text).is_empty() => {
            return vec![py_strip(text).to_owned()];
        }
        Some(OValue::List(items)) => {
            let mut output = Vec::new();
            for item in items {
                match item {
                    OValue::Str(text) if !py_strip(text).is_empty() => {
                        output.push(py_strip(text).to_owned());
                    }
                    OValue::Map(map) => {
                        if let Some(command) =
                            string_value(first_truthy(map.get("command"), map.get("cmd")))
                        {
                            output.push(command);
                        }
                    }
                    _ => {}
                }
            }
            if !output.is_empty() {
                return output;
            }
        }
        _ => {}
    }
    for key in ["command", "cmd"] {
        if let Some(value) = string_value(tool_input.get(key)) {
            return vec![value];
        }
    }
    Vec::new()
}

fn visit_paths(key: &str, value: &OValue, paths: &mut Vec<String>) {
    let normalized = py_lower(&key.replace('-', "_"));
    let is_path_key = PATH_KEYS.contains(&normalized.as_str());
    match value {
        OValue::Str(text) => {
            if is_path_key && !py_strip(text).is_empty() {
                paths.push(py_strip(text).to_owned());
            }
        }
        OValue::List(items) => {
            for item in items {
                match item {
                    OValue::Str(text) if is_path_key && !py_strip(text).is_empty() => {
                        paths.push(py_strip(text).to_owned());
                    }
                    OValue::Map(map) => {
                        for (child_key, child) in map.iter() {
                            visit_paths(child_key, child, paths);
                        }
                    }
                    _ => {}
                }
            }
        }
        OValue::Map(map) => {
            for (child_key, child) in map.iter() {
                visit_paths(child_key, child, paths);
            }
        }
        _ => {}
    }
}

fn paths_from_input(tool_input: &OMap) -> Vec<String> {
    let mut paths = Vec::new();
    for (key, value) in tool_input.iter() {
        visit_paths(key, value, &mut paths);
    }
    dedupe_preserving_order(paths)
}

fn urls_from_input(tool_input: &OMap) -> Vec<String> {
    let mut urls = Vec::new();
    for key in ["url", "urls", "uri", "href"] {
        match tool_input.get(key) {
            Some(OValue::Str(text)) if !py_strip(text).is_empty() => {
                urls.push(py_strip(text).to_owned());
            }
            Some(OValue::List(items)) => {
                urls.extend(
                    items
                        .iter()
                        .filter_map(OValue::non_blank_str)
                        .map(|text| py_strip(text).to_owned()),
                );
            }
            _ => {}
        }
    }
    dedupe_preserving_order(urls)
}

fn first_truthy_of<'a>(map: &'a OMap, keys: &[&str]) -> Option<&'a OValue> {
    keys.iter()
        .filter_map(|key| map.get(key))
        .find(|value| value.truthy())
}

/// `_mcp_parts(name, tool_input)`.
pub fn cline_mcp_parts(name: Option<&str>, tool_input: &OMap) -> (Option<String>, Option<String>) {
    let server = string_value(first_truthy_of(
        tool_input,
        &["server", "serverName", "server_name", "mcpServer"],
    ));
    let tool = string_value(first_truthy_of(
        tool_input,
        &["tool", "toolName", "tool_name", "resource"],
    ));
    if server.is_some() && tool.is_some() {
        return (server, tool);
    }
    let Some(name) = name.filter(|name| !name.is_empty()) else {
        return (None, None);
    };
    if name.starts_with("mcp__") {
        let parts: Vec<&str> = name.splitn(3, "__").collect();
        if parts.len() == 3 && !parts[1].is_empty() && !parts[2].is_empty() {
            return (Some(parts[1].to_owned()), Some(parts[2].to_owned()));
        }
    }
    if let Some((first, second)) = name.split_once('/') {
        if !first.is_empty() && !second.is_empty() {
            return (Some(first.to_owned()), Some(second.to_owned()));
        }
    }
    (server, tool)
}

fn string_list(items: &[String]) -> OValue {
    OValue::List(
        items
            .iter()
            .map(|item| OValue::str(item.as_str()))
            .collect(),
    )
}

fn set_paths(input: &mut OMap) {
    let paths = paths_from_input(input);
    if !paths.is_empty() {
        input.insert("paths", string_list(&paths));
    }
}

fn normalized_tool(name: Option<String>, tool_input: OMap) -> (Option<String>, OMap) {
    let Some(name) = name.filter(|name| !name.is_empty()) else {
        return (None, tool_input);
    };
    let normalized_name = py_strip(&name).to_owned();
    let lowered = py_lower(&normalized_name);
    let lowered = lowered.as_str();
    let mut input = tool_input;
    input.set_default("cline_tool_name", OValue::str(normalized_name.as_str()));
    if SHELL_TOOLS.contains(&lowered) {
        let commands = commands_from_input(&input);
        if commands.len() == 1 {
            input.insert("command", OValue::str(commands[0].as_str()));
        } else if commands.len() > 1 {
            let encoded = string_list(&commands);
            input.insert(
                "command",
                OValue::Str(format!("cline-parallel:{}", encoded.compact_json())),
            );
            input.insert("cline_parallel_commands", encoded);
        }
        return (Some("bash".to_owned()), input);
    }
    if READ_TOOLS.contains(&lowered) {
        set_paths(&mut input);
        return (Some("read_file".to_owned()), input);
    }
    if WRITE_TOOLS.contains(&lowered) {
        set_paths(&mut input);
        let tool = if matches!(lowered, "apply_patch" | "patch") {
            "apply_patch"
        } else {
            "edit_file"
        };
        return (Some(tool.to_owned()), input);
    }
    if MCP_TOOLS.contains(&lowered) {
        if let (Some(server), Some(tool)) = cline_mcp_parts(Some(&normalized_name), &input) {
            return (Some(format!("mcp__{server}__{tool}")), input);
        }
        input.insert("cline_action_bearing_unknown", OValue::Bool(true));
        return (Some(normalized_name), input);
    }
    if NETWORK_TOOLS.contains(&lowered) {
        let urls = urls_from_input(&input);
        if !urls.is_empty() {
            input.set_default("command", OValue::Str(urls.join(" ")));
        }
        return (Some("network_request".to_owned()), input);
    }
    let bearing = input
        .iter()
        .any(|(key, _)| ACTION_BEARING_KEYS.contains(&py_lower(key).replace('-', "_").as_str()));
    if bearing {
        input.insert("cline_action_bearing_unknown", OValue::Bool(true));
    }
    (Some(normalized_name), input)
}

fn present_or<'a>(payload: &'a OMap, first: &str, second: &str) -> Option<&'a OValue> {
    payload.get(first).or_else(|| payload.get(second))
}

pub fn prepare_cline(payload: &OMap) -> Result<OMap, AdapterError> {
    let mut normalized = payload.clone();
    let event = event_name(payload);
    normalized.insert("hook_event_name", OValue::str(event.as_str()));
    if event == "UserPromptSubmit" {
        let nested = mapping(payload.get("userPromptSubmit"));
        let prompt = match nested.get("prompt") {
            Some(OValue::Str(text)) => Some(text.clone()),
            _ => match payload.get("prompt") {
                Some(OValue::Str(text)) => Some(text.clone()),
                _ => None,
            },
        };
        if let Some(prompt) = prompt {
            normalized.insert("prompt", OValue::Str(prompt));
        }
        return Ok(normalized);
    }
    if event != "PreToolUse" && event != "PostToolUse" {
        return Ok(normalized);
    }
    let current = current_tool(payload, &event);
    let legacy = legacy_tool(payload, &event)?;
    assert_compatible(&current, &legacy)?;
    let original_name = current.0.clone().or_else(|| legacy.0.clone()).or_else(|| {
        string_value(first_truthy(
            payload.get("tool_name"),
            payload.get("toolName"),
        ))
    });
    let mut raw_input = if current.0.is_some() || !current.1.is_empty_dict_or_null() {
        current.1.clone()
    } else {
        legacy.1.clone()
    };
    if raw_input.is_empty_dict_or_null() {
        raw_input = present_or(payload, "tool_input", "arguments")
            .cloned()
            .unwrap_or_else(|| OValue::Map(OMap::new()));
    }
    let tool_input = input_object(original_name.as_deref(), &raw_input);
    let (tool_name, tool_input) = normalized_tool(original_name.clone(), tool_input);
    if event == "PreToolUse"
        && matches!(
            tool_input.get("cline_action_bearing_unknown"),
            Some(OValue::Bool(true))
        )
    {
        return Err(AdapterError::ClinePayload(format!(
            "Cline action-bearing tool is not mapped safely: {}",
            original_name.as_deref().unwrap_or("unknown")
        )));
    }
    if let Some(name) = tool_name.as_deref().filter(|name| !name.is_empty()) {
        normalized.insert("tool_name", OValue::str(name));
    }
    let mcp_name = original_name.as_deref().or(tool_name.as_deref());
    let (server, tool) = cline_mcp_parts(mcp_name, &tool_input);
    if !tool_input.is_empty() {
        normalized.insert("tool_input", OValue::Map(tool_input));
    }
    if let Some(server) = server.filter(|text| !text.is_empty()) {
        normalized.insert("mcp_server", OValue::Str(server));
    }
    if let Some(tool) = tool.filter(|text| !text.is_empty()) {
        normalized.insert("mcp_tool", OValue::Str(tool));
    }
    if event == "PostToolUse" {
        let output = current
            .2
            .filter(|value| !value.is_null())
            .or(legacy.2.filter(|value| !value.is_null()));
        if let Some(output) = output {
            normalized.insert("tool_response", output.clone());
            normalized.insert("output", output);
        }
    }
    Ok(normalized)
}
