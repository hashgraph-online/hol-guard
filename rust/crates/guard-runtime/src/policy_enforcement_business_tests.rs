use super::*;
use guard_policy_snapshot::business_policy::BUSINESS_POLICY_BINDING_SCHEMA;
use serde_json::json;

fn binding(default: &str, rule: &str) -> BusinessPolicyBindingV1 {
    serde_json::from_value(json!({"schema": BUSINESS_POLICY_BINDING_SCHEMA,
        "version": 1, "defaultAction": default, "rules": [{"id":"mail.fixture",
        "action":rule,"match":{"schema":"guard.business-policy-match.v1","version":1,
        "services":["google_gmail"],"operations":["mail_send"]}}]}))
    .unwrap()
}

fn facts() -> BusinessActionV1 {
    BusinessActionV1::from_bounded_json(
        &serde_json::to_vec(&json!({
            "schema":"guard.business-action.v1","version":1,
            "provider":{"service":"google_gmail","account_binding":"a".repeat(64),
            "tenant_binding":"b".repeat(64),"identity_state":"known",
            "tool_identity_digest":"c".repeat(64),"tool_schema_digest":"d".repeat(64)},
            "operation":"mail_send","audience":{"kind":"named","expansion_state":"known",
            "recipients":[{"identity_binding":"e".repeat(64),"domain":"example.test","kind":"to"},
            {"identity_binding":"f".repeat(64),"domain":"example.test","kind":"bcc"}]},
            "content":{"snapshot_digest":"1".repeat(64),"attachment_digests":[],
            "inspection_state":"known","inspected_bytes":128,"sensitivity_labels":["confidential"]},
            "target":{"resource_binding":"3".repeat(64),"revision_binding":"4".repeat(64),
            "field_diff_digest":"5".repeat(64),"batch_manifest_digest":"6".repeat(64)},
            "volume":{"recipient_count":2,"record_count":1,"byte_count":128},"completeness":"known"
        }))
        .unwrap(),
    )
    .unwrap()
}

fn snapshot(binding: Option<BusinessPolicyBindingV1>, mode: &str) -> AdmittedPolicySnapshot {
    let mut value = super::super::tests::snapshot(super::super::tests::policy("allow"));
    value.business_policy = binding;
    value.mode = mode.into();
    AdmittedPolicySnapshot::new(value).unwrap()
}

#[test]
fn every_default_rule_and_intrinsic_floor_combination_preserves_the_strongest_floor() {
    let names = [
        "allow",
        "warn",
        "review",
        "require-reapproval",
        "sandbox-required",
        "block",
    ];
    let facts = facts();
    for intrinsic in names {
        for default in names {
            for rule in names {
                let policy = CompiledBusinessPolicy::new(&binding(default, rule)).unwrap();
                let intrinsic = ActionFloor::parse(intrinsic).unwrap();
                let output = policy.floor(intrinsic, Some(&facts));
                assert_eq!(
                    output.action,
                    intrinsic.max(ActionFloor::parse(rule).unwrap())
                );
                assert_eq!(output.matched_rule_ids, ["mail.fixture"]);
            }
        }
    }
}

#[test]
fn rule_order_cannot_hide_later_blocks_and_explanation_ids_are_stable() {
    let mut value = binding("allow", "allow");
    let mut block = value.rules[0].clone();
    block.id = "a.block".into();
    block.action = "block".into();
    value.rules.push(block);
    let forward = CompiledBusinessPolicy::new(&value)
        .unwrap()
        .floor(ActionFloor::Allow, Some(&facts()));
    value.rules.reverse();
    let reverse = CompiledBusinessPolicy::new(&value)
        .unwrap()
        .floor(ActionFloor::Allow, Some(&facts()));
    assert_eq!(forward, reverse);
    assert_eq!(forward.action, ActionFloor::Block);
    assert_eq!(forward.matched_rule_ids, ["a.block", "mail.fixture"]);
}

#[test]
fn scoped_allow_overrides_business_fallback_but_checks_every_recipient_role() {
    let mut value = binding("block", "allow");
    value.rules[0].selector.account_bindings = Some(vec!["a".repeat(64)]);
    value.rules[0].selector.recipient_domains = Some(vec!["example.test".into()]);
    let policy = CompiledBusinessPolicy::new(&value).unwrap();
    let mut scoped = facts();
    let mut cc = scoped.audience.recipients[0].clone();
    cc.identity_binding = "7".repeat(64);
    cc.kind = serde_json::from_value(json!("cc")).unwrap();
    scoped.audience.recipients.push(cc);
    scoped.volume.recipient_count = 3;
    assert_eq!(
        policy.floor(ActionFloor::Allow, Some(&scoped)).action,
        ActionFloor::Allow
    );
    for index in 0..scoped.audience.recipients.len() {
        let mut outside = scoped.clone();
        outside.audience.recipients[index].domain = "external.test".into();
        assert_eq!(
            policy.floor(ActionFloor::Allow, Some(&outside)).action,
            ActionFloor::Block
        );
    }
    let mut swapped = scoped.clone();
    swapped.provider.account_binding = Some("0".repeat(64));
    assert_eq!(
        policy.floor(ActionFloor::Allow, Some(&swapped)).action,
        ActionFloor::Block
    );
    assert_eq!(
        policy.floor(ActionFloor::Block, Some(&scoped)).action,
        ActionFloor::Block
    );
}

#[test]
fn absent_incomplete_or_contradictory_facts_cannot_fall_through_an_allow() {
    let policy = CompiledBusinessPolicy::new(&binding("allow", "allow")).unwrap();
    assert_eq!(
        policy.floor(ActionFloor::Allow, None).action,
        ActionFloor::Block
    );
    let mut unknown = facts();
    unknown.provider.account_binding = None;
    unknown.provider.tenant_binding = None;
    unknown.provider.identity_state = serde_json::from_value(json!("unknown")).unwrap();
    unknown.completeness = serde_json::from_value(json!("unknown")).unwrap();
    assert!(unknown.require_complete_facts().is_err());
    assert_eq!(
        policy.floor(ActionFloor::Allow, Some(&unknown)).action,
        ActionFloor::Block
    );
    let mut invalid = facts();
    invalid.volume.recipient_count = 0;
    assert_eq!(
        policy.floor(ActionFloor::Allow, Some(&invalid)).action,
        ActionFloor::Block
    );
    let mut inspected = facts();
    inspected.content.inspected_bytes = 0;
    assert_eq!(
        policy.floor(ActionFloor::Allow, Some(&inspected)).action,
        ActionFloor::Block
    );
}

#[test]
fn complete_nonmatches_use_default_without_weakening_intrinsic_secret_floors() {
    let mut value = binding("review", "allow");
    value.rules[0].selector.operations = vec![serde_json::from_value(json!("mail_read")).unwrap()];
    let policy = CompiledBusinessPolicy::new(&value).unwrap();
    let result = policy.floor(ActionFloor::Allow, Some(&facts()));
    assert_eq!(result.action, ActionFloor::Review);
    assert!(result.matched_rule_ids.is_empty());
    assert_eq!(
        policy.floor(ActionFloor::Block, Some(&facts())).action,
        ActionFloor::Block
    );
}

#[test]
fn ordinary_hook_business_claims_and_google_cli_calls_require_native_context_even_in_observe() {
    for mode in ["enforce", "observe"] {
        let installed = snapshot(Some(binding("allow", "allow")), mode);
        for payload in [
            json!({"tool_name":"bash","tool_input":{"command":"gws gmail users messages send --json '{}'"}}),
            json!({"tool_name":"bash","tool_input":{"command":"env FIXTURE=1 gws gmail users messages send"}}),
            json!({"tool_name":"bash","tool_input":{"command":"env FIXTURE=1 echo fixture"}}),
            json!({"tool_name":"bash","tool_input":{"command":"gog gmail send"}}),
            json!({"tool_name":"bash","tool_input":{"command":"echo fixture"},"business_action":facts()}),
            json!({"tool_call":{"tool_name":"bash","tool_input":{"command":"echo fixture"},"businessAction":null}}),
        ] {
            let result = super::super::tests::generic_result("allow");
            let output = super::super::apply_pre_tool_policy(&installed, &payload, result).unwrap();
            assert_eq!(
                output.minimum_action, "block",
                "mode={mode}, payload={payload}"
            );
            assert_eq!(output.decision, "deny");
            assert!(!output.explicitly_benign);
            assert_eq!(output.reason_code, "native_business_context_unavailable");
        }
    }
}

#[test]
fn native_command_aliases_encoded_inputs_and_invalid_shapes_fail_closed() {
    for mode in ["enforce", "observe"] {
        let installed = snapshot(Some(binding("allow", "allow")), mode);
        let mut payloads = Vec::new();
        for key in [
            "command",
            "cmd",
            "command_line",
            "commandLine",
            "shell_command",
            "shellCommand",
            "commands",
        ] {
            for command in [
                json!("gws gmail users messages send"),
                json!(["gog gmail send"]),
                json!(""),
                json!("  "),
                json!(["echo fixture", "gws gmail send"]),
            ] {
                payloads.push(json!({"tool_name":"bash","tool_input":{key:command}}));
            }
            payloads.push(json!({"tool_name":"bash","tool_input":{"command":serde_json::to_string(&json!({key:"gws gmail users messages send"})).unwrap()}}));
        }
        for key in [
            "toolArgs",
            "tool_args",
            "toolArgsJson",
            "tool_input",
            "toolInput",
            "toolArguments",
            "tool_arguments",
            "arguments",
            "args",
            "input",
            "parameters",
            "params",
        ] {
            payloads.push(json!({"tool_name":"bash",key:r#"{"shell_command":"gws gmail users messages send"}"#}));
            payloads.push(json!({"tool_name":"bash",key:r#"{"command":"echo fixture","business_action":null}"#}));
        }
        payloads.push(json!({"tool_name":"bash","tool_input":{"command":"echo fixture","businessAction":null}}));
        payloads.push(json!({"tool_name":"bash","tool_input":{"command":"x".repeat(guard_command::MAX_COMMAND_BYTES+1)}}));
        for payload in payloads {
            let output = super::super::apply_pre_tool_policy(
                &installed,
                &payload,
                super::super::tests::generic_result("allow"),
            )
            .unwrap();
            assert_eq!(
                output.minimum_action, "block",
                "mode={mode}, payload={payload}"
            );
            assert_eq!(output.decision, "deny");
            assert_eq!(output.reason_code, "native_business_context_unavailable");
            assert!(!output.explicitly_benign);
        }
    }
}

#[test]
fn opt_in_unrelated_commands_and_mcp_data_do_not_activate_business_guards() {
    let google =
        json!({"tool_name":"bash","tool_input":{"command":"gws gmail users messages send"}});
    let mut result = super::super::tests::generic_result("allow");
    guard_untrusted_business_context(&snapshot(None, "enforce"), &google, &mut result).unwrap();
    assert_eq!(result.minimum_action, "allow");
    let installed = snapshot(Some(binding("allow", "allow")), "enforce");
    for payload in [
        json!({"tool_name":"bash","tool_input":{"command":"ls -la"}}),
        json!({"tool_name":"bash","tool_input":{"command":"echo 'gws gmail users messages send'"}}),
    ] {
        let mut result = super::super::tests::generic_result("allow");
        guard_untrusted_business_context(&installed, &payload, &mut result).unwrap();
        assert_eq!(result.minimum_action, "allow");
    }
    let mut result = super::super::tests::generic_result("allow");
    result.action.action_type = PreToolActionTypeV1::McpTool;
    let data = json!({"tool_name":"mcp__fixture__store","tool_input":{"command":"gws gmail users messages send","business_action":{"example":true}}});
    guard_untrusted_business_context(&installed, &data, &mut result).unwrap();
    assert_eq!(result.minimum_action, "allow");
}

#[test]
fn intrinsic_blocks_keep_their_reason_and_oversized_commands_fail_without_echo() {
    let installed = snapshot(Some(binding("allow", "allow")), "enforce");
    let payload =
        json!({"tool_name":"bash","tool_input":{"command":"gws gmail users messages send"}});
    let mut result = super::super::tests::generic_result("block");
    result.reason_code = "fixture_secret_floor".into();
    let output = super::super::apply_pre_tool_policy(&installed, &payload, result).unwrap();
    assert_eq!(output.minimum_action, "block");
    assert_eq!(output.reason_code, "fixture_secret_floor");
    let huge = json!({"tool_name":"bash","tool_input":{"command":"x".repeat(guard_command::MAX_COMMAND_BYTES+1)}});
    assert_eq!(
        requires_business_context(&huge, PreToolActionTypeV1::Command),
        Ok(true)
    );
}
