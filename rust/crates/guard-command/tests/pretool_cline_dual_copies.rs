//! Cline 4.1 sends each tool call twice: a typed `tool_call` and a
//! compatibility `preToolUse` whose parameters are JSON strings, under the
//! event label `tool_call`. Prepare keeps both copies for the receipt, and
//! evaluation must still read them as one call.

use guard_command::hook_adapter_prepare::prepare_payload;
use guard_command::hook_adapter_value::{parse_python_json, OValue};
use guard_command::pretool::evaluate_pre_tool_envelope_with_context;
use serde_json::{json, Value};

const CWD: &str = "/tmp/hol-guard-cline-dual-copies";

fn cline_payload(hook_name: &str, tool: &str, input: &Value, parameters: &Value) -> Value {
    json!({
        "clineVersion": "",
        "hookName": hook_name,
        "timestamp": "2026-01-01T00:00:00Z",
        "taskId": "t1",
        "sessionContext": {"rootSessionId": "t1"},
        "workspaceRoots": [CWD],
        "userId": "u1",
        "agent_id": "a1",
        "parent_agent_id": null,
        "iteration": 1,
        "tool_call": {"id": "c1", "name": tool, "input": input},
        "preToolUse": {"toolName": tool, "parameters": parameters},
    })
}

fn prepared(payload: &Value) -> Result<Value, String> {
    let Ok(OValue::Map(map)) = parse_python_json(&payload.to_string()) else {
        panic!("payload parses");
    };
    let output = prepare_payload("cline", &map, None).map_err(|error| format!("{error:?}"))?;
    Ok(
        serde_json::from_str(&OValue::Map(output).compact_json())
            .expect("prepared payload is JSON"),
    )
}

fn verdict(payload: &Value) -> (Value, Value) {
    verdict_for("PreToolUse", payload)
}

fn verdict_for(event: &str, payload: &Value) -> (Value, Value) {
    let result = evaluate_pre_tool_envelope_with_context(
        "cline",
        event,
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
fn dual_copy_read_is_one_unambiguous_call() {
    let payload = cline_payload(
        "tool_call",
        "read_files",
        &json!({"files": [{"path": "README.md"}]}),
        &json!({"files": "[{\"path\":\"README.md\"}]"}),
    );
    let prepared = prepared(&payload).expect("copies agree");
    assert_eq!(prepared["tool_name"], json!("read_file"));
    assert!(
        prepared.get("tool_call").is_some(),
        "the receipt keeps the copy"
    );
    let (_, reason_code) = verdict(&prepared);
    assert_ne!(reason_code, json!("native_pre_tool_ambiguous_payload"));
}

#[test]
fn dual_copy_command_is_one_unambiguous_call() {
    let payload = cline_payload(
        "tool_call",
        "run_commands",
        &json!({"commands": ["git status"]}),
        &json!({"commands": "[\"git status\"]"}),
    );
    let prepared = prepared(&payload).expect("copies agree");
    assert_eq!(prepared["tool_name"], json!("bash"));
    assert_eq!(prepared["tool_input"]["command"], json!("git status"));
    let (_, reason_code) = verdict(&prepared);
    assert_ne!(reason_code, json!("native_pre_tool_ambiguous_payload"));
}

#[test]
fn split_command_from_the_managed_worker_is_unambiguous() {
    let payload = json!({
        "hookName": "PreToolUse",
        "hook_event_name": "PreToolUse",
        "tool_call": {"id": "c1", "name": "run_command", "input": {"command": "git status"}},
    });
    let prepared = prepared(&payload).expect("single copy");
    let (_, reason_code) = verdict(&prepared);
    assert_ne!(reason_code, json!("native_pre_tool_ambiguous_payload"));
}

#[test]
fn dual_copy_protected_read_still_stops() {
    let payload = cline_payload(
        "tool_call",
        "run_commands",
        &json!({"commands": ["cat ~/.ssh/id_rsa"]}),
        &json!({"commands": "[\"cat ~/.ssh/id_rsa\"]"}),
    );
    let (decision, _) = verdict(&prepared(&payload).expect("copies agree"));
    assert_ne!(decision, json!("allow"));
}

#[test]
fn disagreeing_copies_are_still_refused() {
    let payload = cline_payload(
        "tool_call",
        "run_commands",
        &json!({"commands": ["ls"]}),
        &json!({"commands": "[\"rm -rf ~\"]"}),
    );
    assert!(prepared(&payload).is_err());
}

#[test]
fn a_copy_naming_another_tool_is_still_refused() {
    let payload = cline_payload(
        "tool_call",
        "run_commands",
        &json!({"commands": ["git status"]}),
        &json!({"commands": "[\"git status\"]"}),
    );
    let mut prepared = prepared(&payload).expect("copies agree");
    prepared["tool_call"]["name"] = json!("write_to_file");
    let (decision, reason_code) = verdict(&prepared);
    assert_ne!(decision, json!("allow"));
    assert_eq!(reason_code, json!("native_pre_tool_ambiguous_payload"));
}

#[test]
fn a_copy_from_the_other_phase_is_still_refused() {
    let payload = cline_payload(
        "tool_call",
        "run_commands",
        &json!({"commands": ["git status"]}),
        &json!({"commands": "[\"git status\"]"}),
    );
    let mut prepared = prepared(&payload).expect("copies agree");
    prepared["postToolUse"] = json!({
        "toolName": "run_commands",
        "parameters": {"commands": "[\"rm -rf ~\"]"},
    });
    let (decision, _) = verdict(&prepared);
    assert_ne!(decision, json!("allow"));
}

#[test]
fn prompt_event_label_reads_as_one_event() {
    let payload = json!({
        "hookName": "prompt_submit",
        "userPromptSubmit": {"prompt": "summarize the readme"},
    });
    let prepared = prepared(&payload).expect("prompt prepares");
    assert_eq!(prepared["hook_event_name"], json!("UserPromptSubmit"));
    let (_, reason_code) = verdict_for("UserPromptSubmit", &prepared);
    assert_ne!(reason_code, json!("native_pre_tool_ambiguous_payload"));
}
