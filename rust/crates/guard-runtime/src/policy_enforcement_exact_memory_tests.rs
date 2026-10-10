use super::*;

fn exact_memory_policy(command: &str, action: &str, expires_at: &str) -> EffectiveNativePolicyV3 {
    use sha2::{Digest, Sha256};

    let mut configured = policy("allow");
    configured.cloud_workspace_id = Some("workspace-a".into());
    configured.exact_command_actions = vec![guard_policy_snapshot::ExactCommandPolicyV1 {
        harness: "claude-code".into(),
        command_sha256: hex::encode(Sha256::digest(command.as_bytes())),
        cloud_workspace_id: "workspace-a".into(),
        action: action.into(),
        expires_at: expires_at.into(),
    }];
    configured
}

#[test]
fn exact_memory_enforces_raw_command_and_harness_without_widening() {
    let configured = snapshot(exact_memory_policy(
        "git status --short",
        "block",
        "2099-01-01T00:00:00Z",
    ));
    let payload =
        serde_json::json!({"tool_name": "Bash", "tool_input": {"command": "git status --short"}});
    let blocked = apply_pre_tool_policy(&configured, &payload, generic_result("allow")).unwrap();
    assert_eq!(blocked.minimum_action, "block");
    assert_eq!(blocked.decision, "deny");

    for command in ["git status", " git status --short", "git status --short "] {
        let unrelated =
            serde_json::json!({"tool_name": "Bash", "tool_input": {"command": command}});
        let baseline = apply_pre_tool_policy(
            &snapshot(policy("allow")),
            &unrelated,
            generic_result("allow"),
        )
        .unwrap();
        let actual =
            apply_pre_tool_policy(&configured, &unrelated, generic_result("allow")).unwrap();
        assert_eq!(actual.minimum_action, baseline.minimum_action);
    }
    let mut other_harness = generic_result("allow");
    other_harness.action.harness = "codex".into();
    let baseline =
        apply_pre_tool_policy(&snapshot(policy("allow")), &payload, other_harness.clone()).unwrap();
    let actual = apply_pre_tool_policy(&configured, &payload, other_harness).unwrap();
    assert_eq!(actual.minimum_action, baseline.minimum_action);
}

#[test]
fn exact_memory_cannot_cross_cloud_workspace_or_lower_native_floor() {
    let mut mismatched = exact_memory_policy("git status --short", "block", "2099-01-01T00:00:00Z");
    mismatched.cloud_workspace_id = Some("workspace-b".into());
    assert!(AdmittedPolicySnapshot::new(snapshot(mismatched)).is_err());

    let configured = snapshot(exact_memory_policy(
        "git status --short",
        "allow",
        "2099-01-01T00:00:00Z",
    ));
    let payload =
        serde_json::json!({"tool_name": "Bash", "tool_input": {"command": "git status --short"}});
    let critical = apply_pre_tool_policy(&configured, &payload, generic_result("block")).unwrap();
    assert_eq!(critical.minimum_action, "block");
    assert_eq!(critical.decision, "deny");
    let review = apply_pre_tool_policy(&configured, &payload, generic_result("review")).unwrap();
    assert_eq!(review.minimum_action, "review");
    assert_eq!(review.decision, "deny");
}

#[test]
fn expired_and_revoked_exact_memory_stop_enforcing() {
    let payload =
        serde_json::json!({"tool_name": "Bash", "tool_input": {"command": "git status --short"}});
    let expired = snapshot(exact_memory_policy(
        "git status --short",
        "block",
        "2000-01-01T00:00:00Z",
    ));
    let baseline = apply_pre_tool_policy(
        &snapshot(policy("allow")),
        &payload,
        generic_result("allow"),
    )
    .unwrap();
    let actual = apply_pre_tool_policy(&expired, &payload, generic_result("allow")).unwrap();
    assert_eq!(actual.minimum_action, baseline.minimum_action);

    let mut revoked = exact_memory_policy("git status --short", "block", "2099-01-01T00:00:00Z");
    let before = apply_pre_tool_policy(
        &snapshot(revoked.clone()),
        &payload,
        generic_result("allow"),
    )
    .unwrap();
    assert_eq!(before.minimum_action, "block");
    revoked.exact_command_actions.clear();
    revoked.cloud_workspace_id = None;
    let after =
        apply_pre_tool_policy(&snapshot(revoked), &payload, generic_result("allow")).unwrap();
    assert_eq!(after.minimum_action, baseline.minimum_action);
}
