//! The Cursor `after*` observers and prompts the resident records, and the
//! route probe it answers without a record.

use super::{deferred, drain, lane, prompt_payload, run_as, HOME};
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

fn route_probe(lane: &super::Lane, tool_cwd: &str) -> serde_json::Value {
    json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Shell",
        "tool_input": { "command": "make build", "cwd": tool_cwd },
        "cwd": lane.workspace,
        "cursor_route_probe": true,
    })
}

#[test]
fn a_route_probe_for_another_directory_is_a_plain_allow_with_no_record() {
    let probed = lane(
        "cursor-probe-elsewhere",
        json!({ "contained_sink_command": ["/opt/guard/bin/python", "-I"] }),
    );
    let result = run_as(&probed, "cursor", Some(HOME), route_probe(&probed, "/"));
    assert_eq!(result["outcome"], "answer", "{result}");
    assert_eq!(
        result["edge"],
        json!({ "harness_response": { "policy_action": "allow" } })
    );
    let page = drain(&probed, None);
    assert!(
        page["records"].as_array().is_none_or(Vec::is_empty),
        "{page}"
    );
}

#[test]
fn a_route_probe_without_its_sink_or_its_name_keeps_the_daemon() {
    let unbound = lane("cursor-probe-unbound", json!({}));
    let result = run_as(&unbound, "cursor", Some(HOME), route_probe(&unbound, "/"));
    assert_eq!(deferred(&result), "direct_hook_binding_incomplete");

    let mut unnamed = route_probe(&unbound, "/");
    unnamed
        .as_object_mut()
        .unwrap()
        .remove("cursor_route_probe");
    let result = run_as(&unbound, "cursor", Some(HOME), unnamed);
    assert_eq!(deferred(&result), "direct_hook_cursor_probe_unnamed");
}
