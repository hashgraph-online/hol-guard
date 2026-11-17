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
fn observed_mcp_allow_answers_the_unreviewed_tool_setting() {
    let tool = "mcp__composio__COMPOSIO_SEARCH_TOOLS";
    for (setting, expected) in [
        ("review", "allow"),
        ("require-reapproval", "allow"),
        ("block", "block"),
    ] {
        let mut policy = policy("allow");
        policy
            .mcp_tool_actions
            .insert(format!("claude-code:{tool}"), "allow".into());
        policy
            .risk_actions
            .insert("mcp_dangerous_tool".into(), setting.into());
        let snapshot = snapshot(policy);
        let mut result = generic_result("review");
        result.action.harness = "claude-code".into();
        result.action.action_type = PreToolActionTypeV1::McpTool;
        result.reason_code = "native_mcp_tool_review".into();
        let output =
            apply_pre_tool_policy(&snapshot, &json!({"tool_name": tool}), result.clone()).unwrap();
        assert_eq!(output.minimum_action, expected, "{setting}");
        let other = apply_pre_tool_policy(
            &snapshot,
            &json!({"tool_name": "mcp__composio__COMPOSIO_MULTI_EXECUTE_TOOL"}),
            result,
        )
        .unwrap();
        assert_ne!(other.minimum_action, "allow", "{setting}");
    }
}

#[test]
fn observed_mcp_allow_cannot_cover_a_renamed_composio_executor() {
    for tool in [
        "mcp__work_COMPOSIO_MULTI_EXECUTE_TOOL",
        "mcp__work__COMPOSIO_MULTI_EXECUTE_TOOL",
        "work_composio_remote_bash_tool",
    ] {
        let mut policy = policy("allow");
        policy
            .mcp_tool_actions
            .insert(format!("omp:{tool}"), "allow".into());
        policy
            .risk_actions
            .insert("mcp_dangerous_tool".into(), "require-reapproval".into());
        let mut result = generic_result("review");
        result.action.harness = "omp".into();
        result.action.action_type = PreToolActionTypeV1::McpTool;
        result.reason_code = "native_mcp_tool_review".into();
        let output =
            apply_pre_tool_policy(&snapshot(policy), &json!({"tool_name": tool}), result).unwrap();
        assert_ne!(output.decision, "allow", "{tool}");
    }
}

#[test]
fn observed_mcp_allow_answers_the_unreviewed_tool_setting_for_its_output() {
    let tool = "mcp__composio__COMPOSIO_SEARCH_TOOLS";
    let mut policy = policy("allow");
    policy
        .mcp_tool_actions
        .insert(format!("claude-code:{tool}"), "allow".into());
    policy
        .risk_actions
        .insert("mcp_dangerous_tool".into(), "require-reapproval".into());
    let snapshot = snapshot(policy);
    let post = |tool: &str, response: HookReviewResponseV1| {
        apply_post_tool_policy(
            &snapshot,
            &post_request(json!({
                "tool_name": tool,
                "tool_input": {"queries": [{"use_case": "find issues"}]},
                "tool_response": "results"
            })),
            GuardHookPayloadKindV2::Inline,
            response,
        )
        .unwrap()
    };
    let output = post(tool, HookReviewResponseV1::allow("output_scan_allow"));
    assert_eq!(output.decision, "allow", "{:?}", output.reason);
    let other = post(
        "mcp__composio__COMPOSIO_MULTI_EXECUTE_TOOL",
        HookReviewResponseV1::allow("output_scan_allow"),
    );
    assert_eq!(other.decision, "deny");
    let secret = post(
        tool,
        HookReviewResponseV1::deny("output_secret_match", "output contains a secret"),
    );
    assert_eq!(secret.decision, "deny");
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

#[test]
fn grok_dispatched_calls_take_the_choice_for_the_tool_they_name() {
    let tool = "mcp__ads_api__list_ads";
    let call = |name: &str, other: &str| {
        json!({
            "toolName": "use_tool",
            "tool_input": {"tool_name": name, "tool_input": {"limit": 5}},
            "toolInput": {"tool_name": other, "tool_input": {"limit": 5}},
        })
    };
    for (choice, expected) in [("allow", "allow"), ("block", "block")] {
        let mut policy = policy("allow");
        policy
            .mcp_tool_actions
            .insert(format!("grok:{tool}"), choice.into());
        let snapshot = snapshot(policy);
        let mut result = generic_result("review");
        result.action.harness = "grok".into();
        result.action.action_type = PreToolActionTypeV1::McpTool;
        result.reason_code = "native_mcp_tool_review".into();
        let named = apply_pre_tool_policy(
            &snapshot,
            &call("ads_api__list_ads", "ads_api__list_ads"),
            result.clone(),
        )
        .unwrap();
        assert_eq!(named.minimum_action, expected, "{choice}");
        let prepared = |tool: &str| {
            json!({
                "toolName": "MCPTool", "mcp_server": "ads_api", "mcp_tool": tool,
                "tool_input": {"tool_name": "ads_api__list_ads"},
            })
        };
        let output = apply_pre_tool_policy(&snapshot, &prepared("list_ads"), result.clone());
        assert_eq!(output.unwrap().minimum_action, expected, "{choice}");
        // Another tool, two different names, or another harness's dispatcher
        // keep the review.
        for payload in [
            call("ads_api__delete_ads", "ads_api__delete_ads"),
            call("ads_api__list_ads", "ads_api__delete_ads"),
            json!({"toolName": "use_tool", "toolInput": {"tool_name": "list_ads"}}),
            prepared("delete_ads"),
        ] {
            let output = apply_pre_tool_policy(&snapshot, &payload, result.clone()).unwrap();
            assert_eq!(output.minimum_action, "review", "{choice} {payload}");
        }
        result.action.harness = "codex".into();
        let codex = apply_pre_tool_policy(
            &snapshot,
            &call("ads_api__list_ads", "ads_api__list_ads"),
            result,
        )
        .unwrap();
        assert_eq!(codex.minimum_action, "review", "{choice}");
    }
}

#[test]
fn grok_dispatched_output_takes_the_choice_for_the_tool_it_ran() {
    let mut policy = policy("allow");
    policy
        .mcp_tool_actions
        .insert("grok:mcp__ads_api__list_ads".into(), "allow".into());
    policy
        .risk_actions
        .insert("mcp_dangerous_tool".into(), "require-reapproval".into());
    let snapshot = snapshot(policy);
    let post = |name: &str| {
        let mut request = post_request(json!({
            "toolName": "use_tool",
            "tool_input": {"tool_name": name, "tool_input": {"limit": 5}},
            "tool_response": "results"
        }));
        request.harness = "grok".into();
        apply_post_tool_policy(
            &snapshot,
            &request,
            GuardHookPayloadKindV2::Inline,
            HookReviewResponseV1::allow("output_scan_allow"),
        )
        .unwrap()
    };
    let output = post("ads_api__list_ads");
    assert_eq!(output.decision, "allow", "{:?}", output.reason);
    assert_eq!(post("ads_api__delete_ads").decision, "deny");
}
