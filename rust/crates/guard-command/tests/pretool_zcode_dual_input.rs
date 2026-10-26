//! ZCode sends each tool input twice: `tool_input` and `toolInput`.
//! Redirect projection must treat both copies as one command.

use guard_command::pretool::evaluate_pre_tool_envelope_with_context;
use serde_json::{json, Value};

const CWD: &str = "/tmp/hol-guard-zcode-dual-input";

fn payload(input: &Value, dual: bool) -> Value {
    let mut payload = json!({
        "cwd": CWD,
        "hook_event_name": "PreToolUse",
        "hookEventName": "PreToolUse",
        "session_id": "s1",
        "sessionId": "s1",
        "tool_name": "Bash",
        "tool_input": input,
        "tool_use_id": "c1",
        "toolCallId": "c1",
    });
    if dual {
        payload["toolName"] = json!("Bash");
        payload["toolInput"] = input.clone();
    }
    payload
}

fn verdict(payload: &Value) -> (Value, Value) {
    let result = evaluate_pre_tool_envelope_with_context(
        "zcode",
        "PreToolUse",
        payload,
        None,
        None,
        Some(CWD),
        Some(CWD),
    );
    let value = serde_json::to_value(&result).expect("result serializes");
    (value["decision"].clone(), value["reason_code"].clone())
}

#[test]
fn duplicated_tool_input_matches_single_copy_for_redirect_commands() {
    for command in [
        "cd /tmp/hol-guard-zcode-dual-input && ls > /dev/null",
        "cd /tmp/hol-guard-zcode-dual-input && ls > out.txt",
        "ls 2>/dev/null",
        "cat ~/.ssh/id_rsa > /tmp/hol-guard-zcode-dual-input/key",
        "cd /tmp/hol-guard-zcode-dual-input\nprintf 'a\\n' > notes.txt",
    ] {
        let input = json!({"command": command, "description": "probe"});
        let single = verdict(&payload(&input, false));
        let dual = verdict(&payload(&input, true));
        assert_ne!(
            dual.1,
            json!("native_pre_tool_ambiguous_payload"),
            "{command}"
        );
        assert_eq!(dual, single, "{command}");
    }
}

#[test]
fn duplicated_tool_input_keeps_protected_redirects_stopped() {
    let input = json!({"command": "cat ~/.ssh/id_rsa > /tmp/hol-guard-zcode-dual-input/key"});
    let (decision, _) = verdict(&payload(&input, true));
    assert_ne!(decision, json!("allow"));
}

#[test]
fn conflicting_tool_input_copies_still_block_as_ambiguous() {
    let mut conflicting = payload(&json!({"command": "ls > /dev/null"}), true);
    conflicting["toolInput"] = json!({"command": "rm -rf ~ > /dev/null"});
    let (decision, reason_code) = verdict(&conflicting);
    assert_eq!(reason_code, json!("native_pre_tool_ambiguous_payload"));
    assert_ne!(decision, json!("allow"));
}
