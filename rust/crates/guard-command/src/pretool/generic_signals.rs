use super::*;

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
        for key in [
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
        ] {
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
    let mut path_values = collect_key_strings(
        &maps,
        &[
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
        ],
    )?;
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
    let content_sensitive = sensitive_text(&path_values)
        || sensitive_text(&url_values)
        || sensitive_text(&prompt_values)
        || sensitive_text(&text_values)
        || command
            .as_deref()
            .is_some_and(super::super::super::sensitive_command_input);
    let sensitive_target = guard_bypass_intent || content_sensitive;
    Ok(GenericSignals {
        command,
        tool_name,
        package_present: !package_values.is_empty(),
        package_values,
        path_values,
        url_values,
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
        event_hint,
    })
}
