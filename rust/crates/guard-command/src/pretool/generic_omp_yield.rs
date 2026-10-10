//! Typed OMP result reports: file references describe work, never execute it.
use super::{strict_tool_input, OmpContext};
use serde_json::{json, Value};

pub(super) fn signal_payload(payload: &Value) -> Option<Value> {
    if payload.get("tool_name")?.as_str()? != "yield"
        || serde_json::to_vec(payload).ok()?.len() > 16 * 1024
    {
        return None;
    }
    let input = strict_tool_input(payload)?;
    if input.is_empty()
        || !input
            .keys()
            .all(|key| matches!(key.as_str(), "data" | "error" | "type"))
    {
        return None;
    }
    if input.get("error").is_some_and(|value| !value.is_string())
        || input.get("type").is_some_and(|value| {
            !value.is_string()
                && !value.as_array().is_some_and(|items| {
                    !items.is_empty() && items.len() <= 16 && items.iter().all(Value::is_string)
                })
        })
    {
        return None;
    }
    let mut projected_input = input.clone();
    if let Some(data) = input.get("data") {
        if let Some(report) = data.as_object() {
            if !report.iter().all(|(key, value)| match key.as_str() {
                "summary" | "report" | "architecture" => value.is_string(),
                "files" => value.as_array().is_some_and(|files| {
                    files.len() <= 24
                        && files.iter().all(|file| {
                            file.as_object().is_some_and(|record| {
                                record
                                    .get("path")
                                    .and_then(Value::as_str)
                                    .is_some_and(|path| !path.is_empty())
                                    && record.iter().all(|(key, value)| {
                                        matches!(key.as_str(), "path" | "description")
                                            && value.is_string()
                                    })
                            })
                        })
                }),
                _ => false,
            }) {
                return None;
            }
            if let Some(files) = report.get("files").and_then(Value::as_array) {
                // Preserve every referenced path for the ordinary sensitive-file
                // and symlink proof. The raw report still reaches output scanning.
                projected_input.get_mut("data")?["files"] =
                    Value::Array(files.iter().map(|file| file["path"].clone()).collect());
            }
        } else if !data.is_string() {
            return None;
        }
    } else if !input.contains_key("error") {
        return None;
    }
    let mut projected = payload.clone();
    for alias in super::super::extract::EMBEDDED_ARGUMENT_KEYS {
        if projected.get(alias).is_some() {
            projected[alias] = Value::Object(projected_input.clone());
        }
    }
    Some(projected)
}

pub(super) fn references_are_readable(paths: &[String], context: &OmpContext<'_>) -> bool {
    paths.iter().all(|path| {
        if path.contains("://") || path.trim() != path || path.chars().any(char::is_control) {
            return false;
        }
        let result = crate::pretool::generic::evaluate_envelope(
            context.harness,
            context.event,
            &json!({"tool_name":"read", "tool_input":{"path":path}}),
            context.controls,
            context.deadline,
            context.path,
            context.execution_environment,
            true,
        );
        result.minimum_action == "allow" && !result.action.sensitive_target
    })
}
