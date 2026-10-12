use guard_command::pretool::evaluate_pre_tool_envelope;
use guard_contracts::PreToolActionTypeV1;
use serde_json::json;

#[test]
fn powershell_type_literal_commands_are_evaluated_as_commands() {
    let command = "[System.IO.File]::WriteAllText((Join-Path (Get-Location) 'docs/change.md'), \"Retry limit increased from 3 to 5.`n\", [System.Text.UTF8Encoding]::new($false))";
    let result = evaluate_pre_tool_envelope(
        "codex",
        "PreToolUse",
        &json!({
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": command}
        }),
    );
    assert_eq!(result.action.action_type, PreToolActionTypeV1::Command);
    assert_eq!(result.minimum_action, "review");
}

#[test]
fn json_encoded_command_arguments_keep_strict_decoding() {
    let duplicate = evaluate_pre_tool_envelope(
        "claude-code",
        "PreToolUse",
        &json!({"command": r#"{"command":"pwd","command":"whoami"}"#}),
    );
    assert_eq!(duplicate.minimum_action, "block");
    assert_eq!(duplicate.reason_code, "native_pre_tool_ambiguous_payload");
}
