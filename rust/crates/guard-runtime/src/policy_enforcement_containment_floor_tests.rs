//! An installed policy's deny outranks a containment floor.
//!
//! A command the native evaluators route into the workspace sandbox still
//! carries the deny the installed policy asks for, and a policy that blocks
//! the harness or the action raises that floor to a block. The containment
//! reason must not survive as the reason the user is shown.

use super::{apply_pre_tool_policy, policy, snapshot};
use serde_json::json;

#[test]
fn test_containment_never_overrides_installed_policy_denies() {
    let payload = json!({"tool_name":"bash","tool_input":{"command":"python3 -m pytest -q"}});
    let result = guard_command::pretool::evaluate_pre_tool_envelope_with_context(
        "omp",
        "PreToolUse",
        &payload,
        None,
        None,
        Some("/home/tester"),
        Some("/home/tester/project"),
    );
    let expected_floor = if cfg!(windows) || guard_command::pretool::workspace_sandbox_available() {
        "sandbox-required"
    } else {
        "review"
    };
    let expected_reason = result.reason_code.clone();
    assert_eq!(result.minimum_action, expected_floor);
    let ordinary =
        apply_pre_tool_policy(&snapshot(policy("allow")), &payload, result.clone()).unwrap();
    assert_eq!(ordinary.minimum_action, expected_floor);
    assert_eq!(ordinary.decision, "deny");
    assert_eq!(ordinary.reason_code, expected_reason);
    let blocked =
        apply_pre_tool_policy(&snapshot(policy("block")), &payload, result.clone()).unwrap();
    assert_eq!(blocked.minimum_action, "block");
    assert_ne!(
        blocked.reason_code,
        "native_pytest_readonly_containment_required"
    );
    let mut harness_denied = policy("allow");
    harness_denied
        .harness_actions
        .insert("omp".into(), "block".into());
    let blocked = apply_pre_tool_policy(&snapshot(harness_denied), &payload, result).unwrap();
    assert_eq!(blocked.minimum_action, "block");
}
