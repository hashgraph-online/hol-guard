use guard_command::pretool::evaluate_pre_tool_envelope;
use guard_command::MAX_COMMAND_BYTES;
use guard_contracts::PreToolResultV1;
use serde_json::{json, Value};

const BOUNDS: &str = "native_pre_tool_bounds_exceeded";

fn cursor(payload: &Value) -> PreToolResultV1 {
    evaluate_pre_tool_envelope("cursor", "PreToolUse", payload)
}

fn large_body() -> String {
    "x".repeat(MAX_COMMAND_BYTES + 1)
}

fn assert_same_decision(with_body: &PreToolResultV1, without_body: &PreToolResultV1) {
    assert_ne!(with_body.reason_code, BOUNDS);
    assert_eq!(with_body.minimum_action, without_body.minimum_action);
    assert_eq!(with_body.reason_code, without_body.reason_code);
}

fn cursor_read(content: Option<String>) -> Value {
    let mut payload = json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Read",
        "file_path": "README.md",
        "tool_input": {"file_path": "README.md", "path": "README.md"}
    });
    if let Some(content) = content {
        payload["content"] = Value::String(content);
    }
    payload
}

#[test]
fn cursor_read_of_large_file_is_judged_on_its_path() {
    let with_body = cursor(&cursor_read(Some(large_body())));
    let without_body = cursor(&cursor_read(None));
    assert_same_decision(&with_body, &without_body);
}

#[test]
fn large_write_and_edit_bodies_are_judged_on_their_path() {
    for keys in [
        &["content"][..],
        &["contents"][..],
        &["old_string", "new_string"][..],
        &["oldString", "newString"][..],
    ] {
        let mut input = json!({"file_path": "docs/notes.md"});
        for key in keys {
            input[*key] = Value::String(large_body());
        }
        let with_body = cursor(&json!({
            "hook_event_name": "PreToolUse",
            "tool_name": "Edit",
            "tool_input": input
        }));
        let without_body = cursor(&json!({
            "hook_event_name": "PreToolUse",
            "tool_name": "Edit",
            "tool_input": {"file_path": "docs/notes.md"}
        }));
        assert_same_decision(&with_body, &without_body);
    }
}

#[test]
fn large_body_beside_a_path_list_is_judged_on_the_paths() {
    let with_body = cursor(&json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Write",
        "tool_input": {"paths": ["docs/notes.md"], "content": large_body()}
    }));
    let without_body = cursor(&json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Write",
        "tool_input": {"paths": ["docs/notes.md"]}
    }));
    assert_same_decision(&with_body, &without_body);
}

#[test]
fn oversized_decision_inputs_still_fail_closed() {
    let path = "README.md";
    for payload in [
        json!({"tool_name": "Shell", "tool_input": {"command": large_body(), "path": path}}),
        json!({"tool_name": "Read", "tool_input": {"file_path": large_body()}}),
        json!({"tool_name": "Read", "tool_input": {"file_path": path, "text": large_body()}}),
        json!({"tool_name": "Read", "tool_input": {"file_path": path}, "prompt": large_body()}),
        json!({"tool_name": "Write", "tool_input": {"content": large_body()}}),
        json!({"tool_name": "Write", "tool_input": {"file_path": 7, "content": large_body()}}),
        json!({"tool_name": "Write", "tool_input": {"paths": [], "content": large_body()}}),
        json!({"tool_name": "Write", "tool_input": {"paths": [large_body()], "content": "x"}}),
        json!({
            "tool_name": "Write",
            "file_path": path,
            "tool_input": {"content": {"nested": large_body()}}
        }),
    ] {
        let result = cursor(&payload);
        assert_eq!(result.minimum_action, "block", "{payload}");
        assert_eq!(result.reason_code, BOUNDS, "{payload}");
    }
}
