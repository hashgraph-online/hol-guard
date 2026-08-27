use serde_json::Value;

pub(super) fn envelope_targets(payload: &Value) -> Vec<String> {
    let Some(input) = payload
        .get("tool_input")
        .or_else(|| payload.get("toolInput"))
        .and_then(Value::as_object)
    else {
        return Vec::new();
    };
    let mut targets = Vec::new();
    for key in [
        "file_path",
        "path",
        "filePath",
        "file_paths",
        "paths",
        "filePaths",
    ] {
        match input.get(key) {
            Some(Value::String(value)) if !value.trim().is_empty() => {
                targets.push(value.trim().to_owned());
            }
            Some(Value::Array(values)) => targets.extend(
                values
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .map(str::to_owned),
            ),
            _ => {}
        }
    }
    targets.sort();
    targets.dedup();
    targets
}

pub(super) fn envelope_target(payload: &Value) -> Option<String> {
    let targets = envelope_targets(payload);
    (targets.len() == 1).then(|| targets[0].clone())
}
