use super::*;

#[test]
fn inner_action_deny_overrides_outer_allow_and_benign_classification() {
    let tool = "mcp__codex_apps__composio__composio_multi_execute_tool";
    let mut policy = policy("allow");
    policy
        .mcp_tool_actions
        .insert(format!("codex:{tool}"), "allow".into());
    policy.mcp_provider_actions.insert(
        "codex:mcp__codex_apps__composio__:composio:all-accounts:SLACK_SEND_MESSAGE".into(),
        "block".into(),
    );
    let mut result = generic_result("allow");
    result.action.harness = "codex".into();
    result.action.action_type = PreToolActionTypeV1::McpTool;
    let output = apply_pre_tool_policy(
        &snapshot(policy),
        &json!({
            "tool_name":tool, "tool_input":{"tools":[
                {"tool_slug":"SLACK_SEARCH_MESSAGES","arguments":{}},
                {"tool_slug":"SLACK_SEND_MESSAGE","arguments":{},"account":"other"}
            ]}
        }),
        result,
    )
    .unwrap();
    assert_eq!(output.minimum_action, "block");
    assert_eq!(output.reason_code, "native_composio_denied_batch_member");
    assert_eq!(output.decision, "deny");
}

#[test]
fn explicit_mcp_review_is_a_floor_for_benign_calls() {
    let tool = "mcp__codex_apps__composio__composio_search_tools";
    for initial in ["allow", "warn", "review", "require-reapproval", "block"] {
        let mut policy = policy("allow");
        policy
            .mcp_tool_actions
            .insert(format!("codex:{tool}"), "review".into());
        let mut result = generic_result(initial);
        result.action.harness = "codex".into();
        result.action.action_type = PreToolActionTypeV1::McpTool;
        let output =
            apply_pre_tool_policy(&snapshot(policy), &json!({"tool_name": tool}), result).unwrap();
        assert_eq!(
            output.minimum_action,
            if matches!(initial, "allow" | "warn" | "review") {
                "review"
            } else {
                initial
            }
        );
    }
}

#[test]
fn composio_wrappers_cannot_inherit_coarse_allow() {
    for name in [
        "composio_multi_execute_tool",
        "composio_remote_workbench",
        "composio_remote_bash_tool",
        "composio_manage_connections",
        "composio_future_executor",
    ] {
        for initial in ["allow", "review", "block"] {
            for choice in ["allow", "block"] {
                let tool = format!("mcp__codex_apps__composio__{name}");
                let mut policy = policy("allow");
                policy
                    .mcp_tool_actions
                    .insert(format!("codex:{tool}"), choice.into());
                let mut result = generic_result(initial);
                result.action.harness = "codex".into();
                result.action.action_type = PreToolActionTypeV1::McpTool;
                result.reason_code = "native_mcp_tool_review".into();
                let output = apply_pre_tool_policy(
                    &snapshot(policy),
                    &json!({"tool_name": tool, "tool_input": {"tools": [{
                        "tool_slug": "SLACK_SEND_MESSAGE", "arguments": {"channel": "test"}
                    }]}}),
                    result,
                )
                .unwrap();
                assert_eq!(
                    output.minimum_action,
                    if initial == "block" || choice == "block" {
                        "block"
                    } else {
                        "review"
                    }
                );
            }
        }
    }
}

#[test]
fn observed_mcp_root_operation_aliases_honor_saved_choices() {
    let tool = "mcp__codex_apps__composio__search";
    for alias in ["action", "operation"] {
        for choice in ["allow", "block"] {
            let mut policy = policy("allow");
            policy
                .mcp_tool_actions
                .insert(format!("codex:{tool}"), choice.into());
            let mut result = generic_result("review");
            result.action.harness = "codex".into();
            result.action.action_type = PreToolActionTypeV1::McpTool;
            result.reason_code = "native_mcp_tool_review".into();
            let mut payload = Map::new();
            payload.insert(alias.into(), json!(tool));
            let output =
                apply_pre_tool_policy(&snapshot(policy), &Value::Object(payload), result).unwrap();
            assert_eq!(output.minimum_action, choice, "{alias}");
        }
    }
}

#[test]
fn observed_mcp_permissions_apply_only_to_the_exact_tool_and_harness() {
    let tool = "mcp__codex_apps__composio__search";
    let mut policy = policy("allow");
    policy
        .mcp_tool_actions
        .insert(format!("codex:{tool}"), "allow".into());
    let snapshot = snapshot(policy);
    let mut result = generic_result("review");
    result.action.harness = "codex".into();
    result.action.action_type = PreToolActionTypeV1::McpTool;
    result.reason_code = "native_mcp_tool_review".into();
    let allowed =
        apply_pre_tool_policy(&snapshot, &json!({"tool_name": tool}), result.clone()).unwrap();
    assert_eq!(allowed.decision, "allow");
    assert_eq!(allowed.reason_code, "native_custom_mcp_tool_allow");
    let dispatcher = apply_pre_tool_policy(
        &snapshot,
        &json!({"tool_name": tool, "tool_input": {"tool_name": "a_dynamic_action"}}),
        result.clone(),
    )
    .unwrap();
    assert_eq!(dispatcher.decision, "allow");
    for unknown in [
        "mcp__codex_apps__composio__execute",
        "mcp__codex_apps__github__search",
    ] {
        let output =
            apply_pre_tool_policy(&snapshot, &json!({"tool_name": unknown}), result.clone())
                .unwrap();
        assert_eq!(output.minimum_action, "review");
    }
    result.action.harness = "claude-code".into();
    let other_harness =
        apply_pre_tool_policy(&snapshot, &json!({"tool_name": tool}), result).unwrap();
    assert_eq!(other_harness.minimum_action, "review");
}

#[test]
fn observed_mcp_allow_preserves_native_findings_and_security_policy() {
    let tool = "mcp__codex_apps__composio__search";
    let mut policy = policy("allow");
    policy
        .mcp_tool_actions
        .insert(format!("codex:{tool}"), "allow".into());
    policy
        .risk_actions
        .insert("mcp_dangerous_tool".into(), "review".into());
    let snapshot = snapshot(policy);
    let mut result = generic_result("review");
    result.action.harness = "codex".into();
    result.action.action_type = PreToolActionTypeV1::McpTool;
    result.reason_code = "native_mcp_tool_review".into();
    let output =
        apply_pre_tool_policy(&snapshot, &json!({"tool_name": tool}), result.clone()).unwrap();
    assert_eq!(output.minimum_action, "review");
    result.reason_code = "native_sensitive_access_review".into();
    let output =
        apply_pre_tool_policy(&snapshot, &json!({"tool_name": tool}), result.clone()).unwrap();
    assert_eq!(output.reason_code, "native_sensitive_access_review");
    result.minimum_action = "block".into();
    result.policy_action = "block".into();
    result.reason_code = "native_secret_exfiltration".into();
    let output = apply_pre_tool_policy(&snapshot, &json!({"tool_name": tool}), result).unwrap();
    assert_eq!(output.minimum_action, "block");
    assert_eq!(output.reason_code, "native_secret_exfiltration");
}

#[test]
fn observed_mcp_server_block_does_not_block_another_connector() {
    let mut policy = policy("allow");
    policy
        .mcp_tool_actions
        .insert("codex:mcp__codex_apps__composio__*".into(), "block".into());
    let snapshot = snapshot(policy);
    let mut result = generic_result("review");
    result.action.harness = "codex".into();
    result.action.action_type = PreToolActionTypeV1::McpTool;
    result.reason_code = "native_mcp_tool_review".into();
    let output = apply_pre_tool_policy(
        &snapshot,
        &json!({"tool_name": "mcp__codex_apps__composio__execute"}),
        result.clone(),
    )
    .unwrap();
    assert_eq!(output.minimum_action, "block");
    let other = apply_pre_tool_policy(
        &snapshot,
        &json!({"tool_name": "mcp__codex_apps__github__execute"}),
        result,
    )
    .unwrap();
    assert_eq!(other.minimum_action, "review");
}

#[test]
fn observed_mcp_allow_cannot_override_a_stronger_unknown_publisher_policy() {
    for floor in ["require-reapproval", "sandbox-required", "block"] {
        let tool = "mcp__codex_apps__composio__search";
        let mut policy = policy("allow");
        policy
            .mcp_tool_actions
            .insert(format!("codex:{tool}"), "allow".into());
        policy.unknown_publisher_action = floor.into();
        let mut result = generic_result("review");
        result.action.harness = "codex".into();
        result.action.action_type = PreToolActionTypeV1::McpTool;
        result.reason_code = "native_mcp_tool_review".into();
        let output =
            apply_pre_tool_policy(&snapshot(policy), &json!({"tool_name": tool}), result).unwrap();
        assert_eq!(output.minimum_action, floor);
        assert_eq!(output.decision, "deny");
    }
}

#[test]
fn observed_mcp_choices_apply_to_supported_envelopes_only() {
    let tool = "mcp__codex_apps__composio__search";
    for envelope in ["tool_call", "toolCall", "preToolUse", "pre_tool_use"] {
        for choice in ["allow", "block"] {
            let mut policy = policy("allow");
            policy
                .mcp_tool_actions
                .insert(format!("codex:{tool}"), choice.into());
            let mut result = generic_result("review");
            result.action.harness = "codex".into();
            result.action.action_type = PreToolActionTypeV1::McpTool;
            result.reason_code = "native_mcp_tool_review".into();
            let mut payload = Map::new();
            payload.insert(envelope.into(), json!({"tool_name": tool}));
            let output =
                apply_pre_tool_policy(&snapshot(policy), &Value::Object(payload), result).unwrap();
            assert_eq!(output.minimum_action, choice, "{envelope}");
        }
    }
}

#[test]
fn observed_namespace_blocks_apply_to_wrapped_calls() {
    let mut policy = policy("allow");
    policy
        .mcp_tool_actions
        .insert("codex:mcp__codex_apps__composio__*".into(), "block".into());
    let mut result = generic_result("review");
    result.action.harness = "codex".into();
    result.action.action_type = PreToolActionTypeV1::McpTool;
    result.reason_code = "native_mcp_tool_review".into();
    let output = apply_pre_tool_policy(
        &snapshot(policy),
        &json!({"tool_call": {"tool_name": "mcp__codex_apps__composio__unseen"}}),
        result,
    )
    .unwrap();
    assert_eq!(output.minimum_action, "block");
}
