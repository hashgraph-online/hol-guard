//! Cursor's answer when the daemon edge has no native decision for a tool
//! hook: every fail-closed code the edge can send is a denial, never an
//! allow.

use serde_json::{json, Value};

use super::tests::{guard_home, map};
use super::*;

/// The daemon edge's answer when it has no native decision for a hook, as
/// the shared fail-closed envelope builds it for Cursor.
fn edge_fail_safe(code: &str) -> OMap {
    map(json!({
        "policy_action": "block",
        "reason_code": code,
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": "HOL Guard could not complete the native hook decision safely.",
        },
    }))
}

#[test]
fn an_edge_answer_without_a_native_decision_denies_every_cursor_tool_hook() {
    let home = guard_home("no-decision", false);
    for event in [
        "preToolUse",
        "beforeShellExecution",
        "beforeMCPExecution",
        "beforeReadFile",
    ] {
        for code in [
            "native_hook_worker_unavailable",
            "daemon_hook_deadline_exhausted",
            "daemon_hook_queue_capacity",
            "daemon_hook_queue_bytes",
        ] {
            let (stdout, exit) = rendered(event, &edge_fail_safe(code), &home, false)
                .unwrap_or_else(|| panic!("{event} {code} has no answer"));
            let answer: Value = serde_json::from_str(&stdout).unwrap();
            assert_eq!(answer["permission"], "deny", "{event} {code}");
            assert_eq!(exit, 2, "{event} {code}");
        }
    }
}
