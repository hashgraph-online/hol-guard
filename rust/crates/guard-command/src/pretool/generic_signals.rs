use super::*;

/// Keys whose string value may carry JSON-encoded tool arguments.
pub(crate) const EMBEDDED_ARGUMENT_KEYS: [&str; 12] = [
    "toolArgs",
    "tool_args",
    "toolArgsJson",
    "tool_input",
    "toolInput",
    "toolArguments",
    "tool_arguments",
    "arguments",
    "args",
    "input",
    "parameters",
    "params",
];

/// Every key whose value may name a file the tool reads or writes.
const PATH_KEYS: [&str; 11] = [
    "path",
    "paths",
    "file",
    "files",
    "file_path",
    "filePath",
    "file_paths",
    "target_file",
    "targetFile",
    "target_directory",
    "targetDirectory",
];

/// Whether a key names something the call opens, searches, lists or matches.
/// The shape of the name decides this rather than a fixed list, so a key an
/// adapter spells its own way still counts as a target.
fn names_a_target(key: &str) -> bool {
    let compact = key.replace(['_', '-', ' '], "").to_ascii_lowercase();
    [
        "path", "file", "dir", "folder", "pattern", "glob", "uri", "url", "notebook", "target",
        "source", "location",
    ]
    .iter()
    .any(|term| compact.contains(term))
}

/// Every map holding the tool's own arguments, nested maps included. A target
/// named outside them belongs to the session envelope, not to this call.
fn argument_maps(root: &Map<String, Value>) -> Vec<&Map<String, Value>> {
    let mut output = Vec::new();
    for key in EMBEDDED_ARGUMENT_KEYS {
        if let Some(value) = root.get(key) {
            collect_maps(value, &mut output);
        }
    }
    output
}

/// Whether the call names its targets and names none of them, which opens
/// nothing. Every argument key that names a target has to be empty, so an
/// empty path list beside a search pattern or a notebook path is not an empty
/// request. A call that names no target at all is a different case: its target
/// may sit under a key this extractor does not read, so it must not pass here.
fn empty_argument_targets(maps: &[&Map<String, Value>]) -> bool {
    let mut present = false;
    for record in maps {
        for (key, value) in record.iter() {
            if !names_a_target(key) {
                continue;
            }
            present = true;
            match value {
                Value::Array(items) if items.is_empty() => {}
                Value::Null => {}
                _ => return false,
            }
        }
    }
    present
}

pub(crate) fn extract_generic_signals(
    payload: &Value,
) -> Result<GenericSignals, GenericExtractionError> {
    let mut keys = 0usize;
    bounded_payload(payload, 0, &mut keys)?;
    let Some(root) = payload.as_object() else {
        return Err(GenericExtractionError::Malformed);
    };
    let mut maps = Vec::new();
    collect_maps(payload, &mut maps);
    // Some harnesses (for example GitHub Copilot) ship tool arguments as a
    // JSON-encoded string instead of an object. Decode those strings once so
    // their nested fields join the same bounded signal surface.
    let mut embedded = Vec::new();
    for record in &maps {
        for key in EMBEDDED_ARGUMENT_KEYS {
            if let Some(Value::String(text)) = record.get(key) {
                let trimmed = text.trim();
                if !(trimmed.starts_with('{') || trimmed.starts_with('['))
                    || trimmed.len() > MAX_COMMAND_BYTES
                {
                    continue;
                }
                if let Ok(parsed) = parse_strict_nested_json(trimmed.as_bytes()) {
                    if embedded.len() >= MAX_PRE_TOOL_STRINGS {
                        return Err(GenericExtractionError::Bounds);
                    }
                    embedded.push(parsed);
                }
            }
        }
    }
    for value in &embedded {
        collect_maps(value, &mut maps);
    }
    let command = collect_commands(&maps)?;
    let tool_name = collect_tool_names(payload)?;
    let mut path_values = collect_key_strings(&maps, &PATH_KEYS)?;
    // Adapter aliases can repeat one target; distinct targets must still
    // prevent the single-file benign proof.
    path_values.sort();
    path_values.dedup();
    let package_values = collect_key_strings(
        &maps,
        &[
            "package",
            "package_name",
            "packageName",
            "package_manager",
            "packageManager",
        ],
    )?;
    let url_values = collect_key_strings(&maps, &["url", "urls", "uri", "href", "endpoint"])?;
    let prompt_values = collect_key_strings(
        &maps,
        &["prompt", "user_prompt", "userPrompt", "message", "query"],
    )?;
    let text_values = collect_key_strings(&maps, &["text"])?;
    let event_hint = collect_event_hint(root)?;
    let env_reference = prompt_values.iter().any(|value| {
        let lowered = value.to_ascii_lowercase();
        lowered.split(".env").skip(1).any(|suffix| {
            !suffix.starts_with(".example")
                && suffix
                    .chars()
                    .next()
                    .is_none_or(|character| !character.is_ascii_alphanumeric() && character != '_')
        })
    });
    let guard_bypass_intent = guard_bypass_prompt(&prompt_values);
    let prompt_injection_intent = prompt_injection_intent(&prompt_values);
    let exfil_intent = exfil_prompt_intent(&prompt_values);
    let destructive_intent = destructive_prompt_intent(&prompt_values);
    let subprocess_intent = subprocess_prompt_intent(&prompt_values);
    let benign_prompt = !guard_bypass_intent
        && !prompt_injection_intent
        && !exfil_intent
        && !destructive_intent
        && !subprocess_intent
        && prompt_values.len() == 1
        && command.is_none()
        && tool_name.is_none()
        && path_values.is_empty()
        && package_values.is_empty()
        && url_values.is_empty()
        && text_values.is_empty()
        && benign_prompt_text(&prompt_values[0]);
    let independent_sensitive_target = sensitive_text(&path_values)
        || sensitive_text(&url_values)
        || prompt_values
            .iter()
            .any(|value| prompt_sensitive_text(value))
        || sensitive_text(&text_values);
    let content_sensitive = independent_sensitive_target
        || command
            .as_deref()
            .is_some_and(super::super::super::sensitive_command_input);
    let sensitive_target = guard_bypass_intent || content_sensitive;
    Ok(GenericSignals {
        command,
        business_action_present: maps.iter().any(|record| {
            record.contains_key("business_action") || record.contains_key("businessAction")
        }),
        tool_name,
        package_present: !package_values.is_empty(),
        package_values,
        empty_read_request: path_values.is_empty() && empty_argument_targets(&argument_maps(root)),
        path_values,
        url_values,
        request_body_or_method: request_body_or_method(&maps),
        github_read_only: false,
        prompt_present: !prompt_values.is_empty(),
        env_reference,
        benign_prompt,
        guard_bypass_intent,
        prompt_injection_intent,
        exfil_intent,
        destructive_intent,
        subprocess_intent,
        content_sensitive,
        sensitive_target,
        independent_sensitive_target: guard_bypass_intent || independent_sensitive_target,
        event_hint,
    })
}

/// A tool that exposes a request body, headers or a non-GET method is not a
/// plain read of public content.
fn request_body_or_method(maps: &[&serde_json::Map<String, Value>]) -> bool {
    maps.iter().any(|record| {
        record
            .iter()
            .any(|(key, value)| match key.to_ascii_lowercase().as_str() {
                "method" | "http_method" | "httpmethod" => value
                    .as_str()
                    .is_none_or(|method| !method.trim().eq_ignore_ascii_case("get")),
                "body" | "data" | "json" | "form" | "headers" | "header" | "cookies"
                | "request_body" | "requestbody" => !value.is_null(),
                _ => false,
            })
    })
}
