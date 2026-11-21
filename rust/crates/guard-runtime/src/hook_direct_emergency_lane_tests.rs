//! The emergency-safe profile over the lane it actually answers on.
//!
//! `hook_direct_emergency_safe_tests.rs` pins the match and the shapes; these
//! run a request the bridge sends after the daemon failed through `evaluate`,
//! against a published snapshot, and check what the hook is told.

use super::{deferred, drain, lane, Lane, HOME};
use crate::hook_direct::{evaluate, HookDirectRequestV1};
use serde_json::{json, Value};

fn emergency(lane: &Lane, harness: &str, command: &str) -> Value {
    let request = HookDirectRequestV1 {
        harness: harness.to_owned(),
        guard_home: lane.fixture.root.to_str().unwrap().to_owned(),
        home_dir: Some(HOME.to_owned()),
        workspace: None,
        deadline_budget_ms: None,
        emergency_safe_only: true,
        payload: json!({
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": { "command": command },
            "cwd": lane.workspace,
        }),
    };
    serde_json::from_slice(&evaluate(request, &lane.fixture.store).unwrap()).unwrap()
}

fn answered(result: &Value) -> &Value {
    assert_eq!(result["outcome"], "answer", "{result}");
    &result["edge"]
}

#[test]
fn a_ratified_read_only_command_continues_and_is_queued() {
    let lane = lane("emergency-continue", json!({}));
    let result = emergency(&lane, "copilot", "hol-guard runtime status --json");
    let edge = answered(&result);
    assert_eq!(edge["event_name"], json!("PreToolUse"));
    assert_eq!(
        edge["emergency_safe_operation"],
        json!("guard_runtime_status"),
    );
    assert_eq!(
        edge["harness_response"],
        json!({ "permissionDecision": "allow" }),
    );
    let page = drain(&lane, None);
    let records = page["records"].as_array().unwrap();
    assert_eq!(records.len(), 1, "{page}");
    let record = &records[0];
    assert_eq!(record["harness"], json!("copilot"));
    assert_eq!(record["workspace"], json!(lane.workspace));
    assert_eq!(record["receipt"], Value::Null);
    assert_eq!(
        record["reason_code"],
        json!("native_emergency_safe_profile")
    );
}

/// A command the profile does not name pauses even on this pass, and leaves
/// nothing behind.
#[test]
fn a_command_outside_the_profile_pauses() {
    let lane = lane("emergency-outside", json!({}));
    let result = emergency(&lane, "copilot", "rm -rf /tmp/work");
    assert_eq!(deferred(&result), "direct_hook_emergency_safe_profile");
    let page = drain(&lane, None);
    assert!(page["records"].as_array().unwrap().is_empty(), "{page}");
}

/// The continue is only recorded if the bound daemon collects it. A daemon
/// that does not drain the direct queue leaves the call unrecorded, which is
/// the one thing this profile promises it is not, so the hook pauses with the
/// reason the ordinary lane gives.
#[test]
fn a_daemon_that_does_not_drain_evidence_pauses_the_call() {
    let lane = lane("emergency-undrained", json!({ "evidence_drain": false }));
    let result = emergency(&lane, "copilot", "hol-guard runtime status --json");
    assert_eq!(deferred(&result), "direct_hook_evidence_undrained");
    let page = drain(&lane, None);
    assert!(page["records"].as_array().unwrap().is_empty(), "{page}");
}

/// A harness without a bounded bridge never reaches this pass.
#[test]
fn an_unbounded_harness_pauses() {
    let lane = lane("emergency-harness", json!({}));
    let result = emergency(&lane, "codex", "hol-guard runtime status --json");
    assert_eq!(deferred(&result), "direct_hook_harness_unsupported");
}
