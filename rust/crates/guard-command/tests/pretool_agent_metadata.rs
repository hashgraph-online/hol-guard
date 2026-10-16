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

#[test]
fn task_stop_and_skill_are_bounded_host_metadata() {
    for payload in [
        json!({"tool_name":"TaskStop", "tool_input":{"task_id":"exec_abc-123"}}),
        json!({"tool_name":"Skill", "tool_input":{"skill":"plugin:review_code-2", "args":"focus on tests"}}),
        json!({"tool_name":"Skill", "tool_input":{"skill":"review"}}),
    ] {
        let result = evaluate(payload);
        assert_eq!(result.minimum_action, "allow");
        assert_eq!(result.reason_code, "native_agent_task_metadata");
    }
    for payload in [
        json!({"tool_name":"TaskStop", "tool_input":{"task_id":"../x"}}),
        json!({"tool_name":"TaskStop", "tool_input":{"task_id":"t", "command":"echo unsafe"}}),
        json!({"tool_name":"TaskStop", "tool_input":{}}),
        json!({"tool_name":"Skill", "tool_input":{"skill":"bad name"}}),
        json!({"tool_name":"Skill", "tool_input":{"skill":"../x"}}),
        json!({"tool_name":"Skill", "tool_input":{"skill":"ok", "args":{"a":1}}}),
        json!({"tool_name":"Skill", "tool_input":{"skill":"ok", "extra":"x"}}),
        json!({"tool_name":"mcp__external__Skill", "tool_input":{"skill":"ok"}}),
    ] {
        assert_ne!(evaluate(payload).minimum_action, "allow");
    }
}

#[test]
fn web_fetch_with_prompt_is_judged_as_network() {
    let result = evaluate(json!({"tool_name":"WebFetch", "tool_input":{
        "url":"https://app.example.test/health", "prompt":"return body"
    }}));
    assert!(
        !result.reason_code.contains("prompt"),
        "unexpected reason {}",
        result.reason_code
    );
    assert_eq!(
        result.action.action_type,
        guard_contracts::PreToolActionTypeV1::Network
    );
}

#[test]
fn claude_user_questions_only_display_choices() {
    let question = json!({
        "question": "Which approach should the fix use? Never delete .env files.",
        "header": "Approach",
        "multiSelect": false,
        "options": [
            {"label": "Narrow the rule (Recommended)", "description": "Keep review for --pre", "preview": "rg -n pattern src"},
            {"label": "Remove the rule", "description": ""}
        ]
    });
    let result = evaluate(json!({"tool_name":"AskUserQuestion", "tool_input":{
        "questions":[question.clone()],
        "answers":{"Which approach should the fix use? Never delete .env files.": "Narrow the rule (Recommended)"},
        "annotations":{"Which approach should the fix use? Never delete .env files.": {"notes": ""}},
        "metadata":{"source":"remember"}
    }}));
    assert_eq!(result.minimum_action, "allow");
    assert_eq!(result.reason_code, "native_agent_task_metadata");
    let guard_prompt = evaluate(
        json!({"tool_name":"AskUserQuestion", "tool_input":{"questions":[{
            "header":"HOL Guard", "question":"HOL Guard intercepted this sensitive action. What should Claude do?",
            "options":[{"label":"Allow once"}, {"label":"Allow during this session"}, {"label":"Keep blocked"}]
        }]}}),
    );
    assert_eq!(guard_prompt.minimum_action, "allow");
    let mut too_many = question.clone();
    too_many["options"] = json!(vec![json!({"label":"x"}); 9]);
    for input in [
        json!({"questions":[question.clone()], "command":"echo unsafe"}),
        json!({"questions":[]}),
        json!({"questions":[question.clone(), question.clone(), question.clone(), question.clone(), question.clone()]}),
        json!({"questions":[{"question":"Read it?", "options":[{"label":"Yes", "path":".env"}]}]}),
        json!({"questions":[{"question":"Run?", "options":[{"label":"Yes"}], "multiSelect":"true"}]}),
        json!({"questions":[{"question":"", "options":[{"label":"Yes"}]}]}),
        json!({"questions":[too_many]}),
        json!({"questions":[question.clone()], "answers":{"q": {"command":"echo unsafe"}}}),
        json!({"questions":[question.clone()], "metadata":{"source":"x", "cwd":"/"}}),
    ] {
        assert_ne!(
            evaluate(json!({"tool_name":"AskUserQuestion", "tool_input":input})).minimum_action,
            "allow"
        );
    }
    for payload in [
        json!({"tool_name":"mcp__server__AskUserQuestion", "tool_input":{"questions":[question.clone()]}}),
        json!({"tool_name":"AskUserQuestion", "command":"echo unsafe", "tool_input":{"questions":[question.clone()]}}),
        json!({"tool_name":"AskUserQuestion", "toolName":"Bash", "tool_input":{"questions":[question]}}),
    ] {
        assert_ne!(evaluate(payload).minimum_action, "allow");
    }
}
