use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use super::*;

fn build(request: Value, action: &str, redaction_enabled: bool) -> Value {
    let args = json!({
        "request": request,
        "action": action,
        "resolved_at": "2026-07-07T00:00:00Z",
        "redaction_enabled": redaction_enabled,
    });
    dispatch(&args).unwrap()["event"].clone()
}

fn withheld(extra: Value) -> Value {
    let mut request = json!({
        "request_id": "req-1",
        "review_command": "hol-guard approvals approve req-1",
        "artifact_type": "tool_action_request",
    });
    for (key, value) in extra.as_object().unwrap() {
        request[key] = value.clone();
    }
    build(request, "allow", false)
}

fn display(extra: Value) -> String {
    withheld(extra)["command_display"]
        .as_str()
        .unwrap()
        .to_owned()
}

#[test]
fn approved_install_carries_the_raw_command_and_its_fingerprint() {
    let event = build(
        json!({
            "request_id": " req-1 ",
            "raw_command_text": "npm install lodash",
            "artifact_id": "npm:lodash",
            "artifact_type": "package",
            "harness": "codex",
            "queue_group_id": "queue-1",
            "reason": "  ",
            "resolution_reason": "trusted",
            "risk_headline": "Supply-chain install",
            "risk_signals": [" network_install ", "", "  ", 7, "filesystem_write"],
            "workspacePath": "/repo",
        }),
        "allow",
        false,
    );
    let expected_id = hex::encode(Sha256::digest(
        "memory_decision:req-1:approved:2026-07-07T00:00:00Z",
    ));
    assert_eq!(
        event["event_id"],
        format!("guard-memory-decision-{}", &expected_id[..32])
    );
    assert_eq!(event["request_id"], "req-1");
    assert_eq!(event["decision_action"], "approved");
    assert_eq!(event["redaction_state"], "disabled");
    assert_eq!(event["command_display"], "npm install lodash");
    assert_eq!(event["command_raw"], "npm install lodash");
    assert_eq!(event["decision_reason"], "trusted");
    assert_eq!(event["risk_summary"], "Supply-chain install");
    assert_eq!(
        event["risk_signals"],
        json!(["network_install", "filesystem_write"])
    );
    assert_eq!(event["project_id"], "/repo");
    assert_eq!(event["action_identity"], Value::Null);
    assert_eq!(event["memory_pattern"]["kind"], "package_install_pattern");
    assert!(event["memory_pattern"]["components"]
        .as_array()
        .unwrap()
        .contains(&json!(["package", "lodash"])));
}

#[test]
fn redaction_keeps_the_display_but_drops_the_raw_command() {
    let event = build(
        json!({"request_id": "req-1", "raw_command_text": "git push origin main"}),
        "approve",
        true,
    );
    assert_eq!(event["redaction_state"], "enabled");
    assert_eq!(event["command_display"], "git push origin main");
    assert_eq!(event["command_raw"], Value::Null);
}

#[test]
fn actions_normalize_and_unknown_ones_answer_no_event() {
    let request = json!({"request_id": "req-1", "raw_command_text": "git status"});
    for (action, expected) in [
        (" Allowed ", "approved"),
        ("REJECT", "blocked"),
        ("deny", "blocked"),
        ("keep-asking", "dismissed_keep_asking"),
        ("dismiss", "dismissed_keep_asking"),
    ] {
        assert_eq!(
            build(request.clone(), action, false)["decision_action"],
            expected,
            "{action}"
        );
    }
    assert_eq!(build(request, "maybe", false), Value::Null);
    for request_id in [json!(""), json!("  "), json!(7), Value::Null] {
        let request = json!({"request_id": request_id, "raw_command_text": "git status"});
        assert_eq!(build(request, "allow", false), Value::Null);
    }
}

#[test]
fn withheld_commands_show_the_guarded_action_from_the_envelope() {
    let cases = [
        (
            json!({"action_type": "file_read", "target_paths": ["src/a.ts"]}),
            "Read src/a.ts",
        ),
        (
            json!({"actionType": "file_write_request", "path": " out.json "}),
            "Write out.json",
        ),
        (
            json!({"action_type": "mcp_tool", "mcp_server": "tavily", "mcp_tool": "search"}),
            "mcp tavily.search",
        ),
        (
            json!({"action_type": "mcp_tool", "tool_name": "search"}),
            "mcp search",
        ),
        (
            json!({"packageManager": "npm", "package_name": "lodash"}),
            "npm install lodash",
        ),
        (
            json!({"endpoint": "https://api.test/v1", "method": "post"}),
            "POST https://api.test/v1",
        ),
        (json!({"host": "api.test"}), "api.test"),
        (json!({"toolName": "WebFetch"}), "WebFetch"),
    ];
    for (envelope, expected) in cases {
        assert_eq!(
            display(json!({"action_envelope_json": envelope.clone()})),
            expected
        );
        let text = serde_json::to_string(&envelope).unwrap();
        assert_eq!(display(json!({"action_envelope_json": text})), expected);
    }
}

#[test]
fn envelope_lookups_follow_python_truthiness() {
    // A falsy first spelling falls through to the second.
    let envelope = json!({"action_type": "", "actionType": "file_read", "target_paths": [], "targetPaths": ["b"]});
    assert_eq!(display(json!({"action_envelope_json": envelope})), "Read b");
    // A truthy non-string value wins the `or` and then reads as absent.
    let envelope =
        json!({"url": ["https://x.test"], "uri": "https://y.test", "tool_name": "Fetch"});
    assert_eq!(display(json!({"action_envelope_json": envelope})), "Fetch");
    let envelope = json!({"url": 0, "uri": "https://y.test"});
    assert_eq!(
        display(json!({"action_envelope_json": envelope})),
        "https://y.test"
    );
}

#[test]
fn withheld_fallbacks_skip_wrappers_and_generic_fragments() {
    let generic = json!({"action_envelope_json": {"tool_name": " Bash "}, "artifact_name": "rg"});
    assert_eq!(display(generic), "Command withheld");
    let fallback = json!({
        "action_envelope_json": "not json",
        "launch_target": "hol-guard approvals approve req-9",
        "artifact_name": "MCP",
        "artifact_id": "codex_tool:project:search",
    });
    assert_eq!(display(fallback), "codex_tool:project:search");
    let launch = json!({"launch_target": "deploy.sh", "artifact_name": "Deploy"});
    assert_eq!(display(launch), "deploy.sh");
    let event = withheld(json!({}));
    assert_eq!(event["redaction_state"], "withheld");
    assert_eq!(event["command_display"], "Command withheld");
    assert_eq!(event["command_raw"], Value::Null);
}

#[test]
fn malformed_arguments_are_refused() {
    for args in [
        json!({"action": "allow", "resolved_at": "t"}),
        json!({"request": [], "action": "allow", "resolved_at": "t"}),
        json!({"request": {}, "action": 1, "resolved_at": "t"}),
        json!({"request": {}, "action": "allow"}),
        json!({"request": {}, "action": "allow", "resolved_at": "t", "redaction_enabled": "yes"}),
    ] {
        assert_eq!(dispatch(&args), Err(ERR_INVALID), "{args}");
    }
}
