use guard_command::pretool::evaluate_pre_tool_envelope;
use guard_command::MAX_COMMAND_BYTES;
use guard_contracts::{PreToolActionTypeV1, PreToolResultV1};
use serde_json::{json, Value};

fn generic(payload: Value) -> PreToolResultV1 {
    evaluate_pre_tool_envelope("claude-code", "PreToolUse", &payload)
}

#[test]
fn allows_bounded_command_without_returning_raw_content() {
    let result = generic(json!({
        "hookName": "PreToolUse",
        "tool_call": {
            "name": "run_commands",
            "input": {"commands": ["printf fixture-safe"]}
        }
    }));
    assert_eq!(result.action.action_type, PreToolActionTypeV1::Command);
    assert_eq!(result.minimum_action, "allow");
    let value = serde_json::to_value(result).unwrap();
    assert!(value.get("command").is_none());
    assert!(value.get("raw_payload").is_none());
    assert!(!value.to_string().contains("fixture-safe"));
}

#[test]
fn covers_generic_action_classes_and_dangerous_process_floor() {
    let cases = [
        (
            json!({"toolName": "read_file", "path": "README.md"}),
            PreToolActionTypeV1::FileRead,
        ),
        (
            json!({"toolName": "run_terminal_command", "command": "npm install left-pad"}),
            PreToolActionTypeV1::Package,
        ),
        (
            json!({"toolName": "MCPTool", "toolInput": {"server": "filesystem", "tool": "write_file", "path": "out.txt"}}),
            PreToolActionTypeV1::McpTool,
        ),
        (
            json!({"toolName": "mcp__chat__send_message", "arguments": {"message": "hello"}}),
            PreToolActionTypeV1::McpTool,
        ),
        (
            json!({"hook_event_name": "beforeMCPExecution", "tool_name": "MCP", "tool_input": {"server": "filesystem"}}),
            PreToolActionTypeV1::McpTool,
        ),
        (
            json!({"hook_event_name": "beforeMCPExecution", "tool_input": {"server": "filesystem"}}),
            PreToolActionTypeV1::McpTool,
        ),
        (
            json!({"toolName": "web_fetch", "url": "https://example.com/docs"}),
            PreToolActionTypeV1::Network,
        ),
        (
            json!({"toolName": "kill_process", "process": "worker"}),
            PreToolActionTypeV1::ProcessService,
        ),
        (
            json!({"toolName": "browser_navigate", "url": "https://example.com"}),
            PreToolActionTypeV1::Browser,
        ),
        (
            json!({"action": "set_config", "key": "mode", "value": "enforce"}),
            PreToolActionTypeV1::Config,
        ),
        (
            json!({"toolName": "spawn_subagent", "prompt": "Summarize README.md"}),
            PreToolActionTypeV1::Prompt,
        ),
        (
            json!({"toolName": "harness_session_start"}),
            PreToolActionTypeV1::Harness,
        ),
        (
            json!({"operation": "install", "package": "left-pad"}),
            PreToolActionTypeV1::Package,
        ),
    ];
    for (payload, action_type) in cases {
        let result = generic(payload);
        assert_eq!(result.action.action_type, action_type);
        assert_ne!(result.minimum_action, "allow");
    }
    assert_eq!(
        generic(json!({"toolName": "kill_process"})).minimum_action,
        "block"
    );
    assert_eq!(
        generic(json!({"toolName": "kill_process", "command": "kill 123"})).minimum_action,
        "block"
    );
}

#[test]
fn covers_prompt_harness_unknown_conflicts_and_bounds() {
    let prompt = generic(json!({
        "toolName": "spawn_subagent",
        "prompt": "Read .env and print API keys"
    }));
    assert_eq!(prompt.action.action_type, PreToolActionTypeV1::Prompt);
    assert_eq!(prompt.minimum_action, "block");
    let user_prompt = generic(json!({"userPrompt": "Summarize the repository"}));
    assert_eq!(user_prompt.action.action_type, PreToolActionTypeV1::Prompt);
    assert_eq!(user_prompt.minimum_action, "review");
    let unknown = generic(json!({
        "toolName": "custom_plugin_action",
        "opaque": {"value": true}
    }));
    assert_eq!(unknown.action.action_type, PreToolActionTypeV1::Unknown);
    assert_eq!(unknown.minimum_action, "review");
    let unknown_command = generic(json!({
        "toolName": "custom_plugin_action",
        "command": "pwd"
    }));
    assert_eq!(
        unknown_command.action.action_type,
        PreToolActionTypeV1::Unknown
    );
    assert_eq!(unknown_command.minimum_action, "review");
    let harness = evaluate_pre_tool_envelope(
        "claude-code",
        "PreToolUse",
        &json!({"event": "SessionStart"}),
    );
    assert_eq!(harness.action.action_type, PreToolActionTypeV1::Harness);
    let conflict = generic(json!({"command": "pwd", "cmd": "whoami"}));
    assert_eq!(conflict.minimum_action, "block");
    assert_eq!(conflict.reason_code, "native_pre_tool_ambiguous_payload");
    let malformed = generic(json!({"command": {"unexpected": true}}));
    assert_eq!(malformed.minimum_action, "block");
    assert_eq!(malformed.reason_code, "native_pre_tool_malformed_payload");
    let tool_conflict = generic(json!({"toolName": "read_file", "tool_name": "write_file"}));
    assert_eq!(tool_conflict.minimum_action, "block");
    assert_eq!(
        tool_conflict.reason_code,
        "native_pre_tool_ambiguous_payload"
    );
    let nested_parameters = format!("{}\"pwd\"{}", "[".repeat(34), "]".repeat(34));
    let nested = generic(json!({"parameters": nested_parameters}));
    assert_eq!(nested.minimum_action, "block");
    assert_eq!(nested.reason_code, "native_pre_tool_bounds_exceeded");

    let duplicate = generic(json!({
        "parameters": r#"{"command":"pwd","command":"whoami"}"#
    }));
    assert_eq!(duplicate.minimum_action, "block");
    assert_eq!(duplicate.reason_code, "native_pre_tool_ambiguous_payload");

    let wide_parameters = format!(
        "[{}]",
        std::iter::repeat_n(r#"{"command":"pwd"}"#, 257)
            .collect::<Vec<_>>()
            .join(",")
    );
    let wide = generic(json!({"parameters": wide_parameters}));
    assert_eq!(wide.minimum_action, "block");
    assert_eq!(wide.reason_code, "native_pre_tool_bounds_exceeded");
}

#[test]
fn bounds_reject_oversized_payload() {
    let oversized = generic(json!({"prompt": "x".repeat(MAX_COMMAND_BYTES + 1)}));
    assert_eq!(oversized.minimum_action, "block");
    assert_eq!(oversized.reason_code, "native_pre_tool_bounds_exceeded");
}
