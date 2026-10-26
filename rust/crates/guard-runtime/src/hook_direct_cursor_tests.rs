//! The Cursor `after*` observers and prompts the resident records.

use super::{drain, lane, prompt_payload, run_as, HOME};
use serde_json::json;

#[test]
fn a_cursor_observer_is_recorded_as_the_daemon_records_it() {
    // Cursor's client prepares its `after*` observers as themselves; the
    // daemon reviews both as a `PostToolUse` and returns the edge response.
    for (label, payload) in [
        (
            "cursor-after-shell",
            json!({
                "hook_event_name": "afterShellExecution",
                "tool_name": "Shell",
                "command": "pwd",
                "output": "/repo",
                "tool_input": { "command": "pwd" },
            }),
        ),
        (
            "cursor-after-mcp",
            json!({
                "hook_event_name": "afterMCPExecution",
                "tool_name": "lookup",
                "tool_input": { "query": "x" },
                "result_json": "{}",
            }),
        ),
    ] {
        let lane = lane(label, json!({}));
        let mut payload = payload;
        payload["cwd"] = json!(lane.workspace);
        let result = run_as(&lane, "cursor", Some(HOME), payload);
        assert_eq!(result["outcome"], "answer", "{label}: {result}");
        assert_eq!(result["edge"]["event_name"], "PostToolUse", "{label}");
        let page = drain(&lane, None);
        let records = page["records"].as_array().unwrap();
        assert_eq!(records.len(), 1, "{label}");
        assert_eq!(records[0]["event"], "PostToolUse", "{label}");
        assert_eq!(records[0]["harness"], "cursor", "{label}");
        assert_eq!(
            records[0]["harness_response"], result["edge"]["harness_response"],
            "{label}"
        );
    }
}

#[test]
fn a_cursor_prompt_is_answered_with_the_edge_response_in_either_posture() {
    // The daemon accepts a Cursor prompt's receipt and returns the edge's
    // response; only Claude Code's carries Guard's notice.
    for (label, extra) in [
        ("cursor-prompt", json!({})),
        (
            "cursor-prompt-watch",
            json!({ "harness_postures": { "cursor": "watch" } }),
        ),
    ] {
        let reviewed = lane(label, extra);
        let result = run_as(&reviewed, "cursor", Some(HOME), prompt_payload(&reviewed));
        assert_eq!(result["outcome"], "answer", "{label}: {result}");
        assert_eq!(result["edge"]["event_name"], "UserPromptSubmit", "{label}");
        let page = drain(&reviewed, None);
        let record = &page["records"][0];
        assert_eq!(record["event"], "UserPromptSubmit", "{label}");
        assert_eq!(record["harness"], "cursor", "{label}");
        assert_eq!(record["receipt"], result["edge"]["receipt"], "{label}");
        assert_eq!(
            record["harness_response"], result["edge"]["harness_response"],
            "{label}"
        );
    }
}
