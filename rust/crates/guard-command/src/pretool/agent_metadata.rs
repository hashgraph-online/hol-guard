use serde_json::Value;

/// Only host task-list data is admitted here, never commands or external tools.
pub(super) fn bounded_task_list(payload: &Value, tool_name: Option<&str>) -> bool {
    if tool_name != Some("TodoWrite") {
        return false;
    }
    let Some(root) = payload.as_object() else {
        return false;
    };
    if root.keys().any(|key| {
        !matches!(
            key.as_str(),
            "tool_name"
                | "toolName"
                | "tool_input"
                | "hook_event_name"
                | "hookEventName"
                | "session_id"
                | "tool_use_id"
                | "tool_call_id"
                | "tool_id"
                | "turn_id"
                | "cwd"
                | "transcript_path"
                | "permission_mode"
                | "harness"
                | "guard_execution_environment"
        )
    }) {
        return false;
    }
    let Some(input) = payload.get("tool_input").and_then(Value::as_object) else {
        return false;
    };
    if input.len() != 1 {
        return false;
    }
    let Some(todos) = input.get("todos").and_then(Value::as_array) else {
        return false;
    };
    todos.len() <= 64
        && todos.iter().all(|todo| {
            let Some(item) = todo.as_object() else {
                return false;
            };
            item.contains_key("content")
                && item.contains_key("status")
                && item.keys().all(|key| {
                    matches!(
                        key.as_str(),
                        "content" | "status" | "priority" | "activeForm" | "id"
                    )
                })
                && item.iter().all(|(key, value)| {
                    let Some(text) = value.as_str() else {
                        return false;
                    };
                    match key.as_str() {
                        "status" => matches!(text, "pending" | "in_progress" | "completed"),
                        "priority" => matches!(text, "low" | "medium" | "high"),
                        _ => !text.is_empty() && text.len() <= 2048,
                    }
                })
        })
}
