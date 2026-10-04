use guard_command::pretool::evaluate_pre_tool_envelope;
use serde_json::{json, Value};

fn evaluate(payload: Value) -> guard_contracts::PreToolResultV1 {
    evaluate_pre_tool_envelope("claude-code", "PreToolUse", &payload)
}

#[test]
fn host_task_lists_do_not_execute_their_descriptions() {
    let result = evaluate(json!({"tool_name":"TodoWrite", "tool_input":{"todos":[
        {"content":"Deploy after reviewing safety gates", "status":"pending", "priority":"high"},
        {"content":"Never delete live deployment locks", "status":"completed"}
    ]}}));
    assert_eq!(result.minimum_action, "allow");
    assert_eq!(result.reason_code, "native_agent_task_metadata");
    let transported = evaluate(json!({
        "hook_event_name":"PreToolUse", "tool_name":"TodoWrite", "toolName":"TodoWrite",
        "tool_input":{"todos":[]}, "toolInput":{"todos":[]},
        "cwd":"/project", "workspace_root":"/project", "workspaceRoot":"/project",
        "session_id":"session", "sessionId":"session", "toolCallId":"call"
        ,"turnId":"turn", "traceId":"trace", "timestamp":1234,
        "mode":"build", "riskLevel":"low", "sideEffectScope":"session",
        "transcriptPath":"/project/transcript.jsonl", "transcript_path":"/project/transcript.jsonl"
    }));
    assert_eq!(transported.minimum_action, "allow");
    assert_eq!(transported.reason_code, "native_agent_task_metadata");
}

#[test]
fn task_list_proof_rejects_external_aliases_and_executable_inputs() {
    for payload in [
        json!({"tool_name":"mcp__server__TodoWrite", "tool_input":{"todos":[]}}),
        json!({"tool_name":"TodoWrite", "mcp_server":"external", "tool_input":{"todos":[]}}),
        json!({"tool_name":"TodoWrite", "command":"echo unsafe", "tool_input":{"todos":[]}}),
        json!({"tool_name":"TodoWrite", "tool_input":{"todos":[]}, "toolInput":{"command":"echo unsafe"}}),
        json!({"tool_name":"TodoWrite", "tool_input":{"todos":[], "command":"echo unsafe"}}),
        json!({"tool_name":"TodoWrite", "tool_input":{"todos":[{"content":"Task", "status":"execute"}]}}),
        json!({"tool_name":"TodoWrite", "tool_input":{"todos":[{"content":"Task", "status":"pending", "path":".env"}]}}),
        json!({"tool_name":"TodoWrite", "tool_input":{"todos":vec![json!({"content":"Task", "status":"pending"});65]}}),
    ] {
        assert_ne!(evaluate(payload).minimum_action, "allow");
    }
}

#[test]
fn task_output_only_retrieves_a_bounded_existing_host_task() {
    let result = evaluate(json!({"tool_name":"TaskOutput", "tool_input":{
        "task_id":"exec_01234567-89ab-cdef", "block":true, "timeout":600000
    }}));
    assert_eq!(result.minimum_action, "allow");
    assert_eq!(result.reason_code, "native_agent_task_metadata");
    for input in [
        json!({"task_id":"../.env"}),
        json!({"task_id":"task", "command":"echo unsafe"}),
        json!({"task_id":"task", "timeout":600001}),
        json!({"task_id":"task", "block":"true"}),
    ] {
        assert_ne!(
            evaluate(json!({"tool_name":"TaskOutput", "tool_input":input})).minimum_action,
            "allow"
        );
    }
    assert_ne!(
        evaluate(json!({"tool_name":"mcp__external__TaskOutput", "tool_input":{"task_id":"task"}}))
            .minimum_action,
        "allow"
    );
}
