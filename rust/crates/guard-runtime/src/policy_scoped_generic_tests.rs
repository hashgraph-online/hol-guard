use super::*;
use guard_command::pretool::evaluate_pre_tool_envelope;
use serde_json::json;

fn vectors() -> Value {
    super::policy_vector_generic::vectors()
}

fn envelope(case: &Value) -> GuardHookEnvelopeV2 {
    serde_json::from_value(json!({
        "schema":"guard-hook-envelope.v2", "harness":case["harness"],
        "event":"PreToolUse", "raw_payload":case["payload"],
        "policy_generation":1, "policy_snapshot":{},
        "source":{"cwd":std::env::temp_dir(), "home_dir":std::env::temp_dir(), "guard_home":std::env::temp_dir()}
    })).unwrap()
}

fn snapshot(case: &Value) -> PolicySnapshotV4 {
    let vector: Value = serde_json::from_str(include_str!(
        "../../../../contracts/native-policy-snapshot/v4/policy-snapshot-vector.json"
    ))
    .unwrap();
    let mut value = vector["snapshot"].clone();
    value["effective_policy"] = case["localEffectivePolicy"].clone();
    value["mode"] = case["mode"].clone();
    value["scoped_authority"] = json!({
        "schema":"guard-native-policy-authority.v1", "generic_precedence":"specificity-recency.v1",
        "rows":[], "managed":null
    });
    if !case["managedConfiguration"].is_null() {
        value["scoped_authority"]["managed_config"] = case["managedConfiguration"].clone();
    }
    serde_json::from_value(value).unwrap()
}

#[test]
fn actual_generic_origin_and_tool_vectors_reach_native_composition() {
    let fixture = vectors();
    let cases = fixture["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 260);
    for case in cases {
        let source = envelope(case);
        let request = derive_scoped_policy_request(&source, &source.harness).unwrap();
        assert_eq!(request.artifact_id(), case["artifactId"].as_str());
        let policy = snapshot(case);
        let configured = generic_command_configuration(
            &policy.effective_policy,
            policy.scoped_authority.managed_config(),
            &source,
            &source.harness,
            request.artifact_id().unwrap(),
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            configured.evaluated_action(),
            case["expected"]["currentConfigAction"].as_str().unwrap(),
            "{}",
            case["name"]
        );
        let intrinsic =
            evaluate_pre_tool_envelope(&source.harness, "PreToolUse", &source.raw_payload);
        let source_reason = format!(
            "{} {:?}",
            intrinsic.reason_code, intrinsic.action.action_type
        );
        let result =
            apply_scoped_pre_tool_policy(&policy, &source, &source.harness, intrinsic, 100)
                .unwrap();
        assert_eq!(
            result.result.policy_action,
            case["expected"]["finalPolicyAction"].as_str().unwrap(),
            "{} {source_reason}",
            case["name"]
        );
        assert_eq!(result.result.minimum_action, result.result.policy_action);
        assert_eq!(
            result.result.decision,
            if case["expected"]["exitCode"] == 0 {
                "allow"
            } else {
                "deny"
            }
        );
        assert_eq!(
            result.observed_policy_action,
            case["expected"]["observedPolicyAction"].as_str(),
            "{}",
            case["name"]
        );
        assert_eq!(result.selected_decision_id, None);
    }
}

#[test]
fn actual_generic_edge_vectors_preserve_receipt_mode_without_inventing_projection() {
    let fixture = vectors();
    let cases = fixture["cases"].as_array().unwrap();
    let mut mismatches = Vec::new();
    for (index, case) in cases.iter().enumerate() {
        let mut source = envelope(case);
        source.request_id = Some(format!("generic-source-{index}"));
        let policy = snapshot(case);
        source.policy_generation = policy.generation;
        let encoded = crate::edge_v4::evaluate(source, &policy, 3).unwrap();
        let edge: Value = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(
            edge["result"]["policy_action"],
            case["expected"]["finalPolicyAction"]
        );
        assert_eq!(
            edge["observed_policy_action"],
            case["expected"]["observedPolicyAction"]
        );
        assert_eq!(
            edge["receipt"]["observed_policy_action"],
            edge["observed_policy_action"]
        );
        if edge["receipt"]["observe_mode"] != (policy.mode == "observe") {
            mismatches.push(case["name"].clone());
        }
        println!(
            "GENERIC_EDGE_VECTOR={}",
            json!({
                "name": case["name"], "edge": edge,
                "expectedBinding": {
                    "generation":policy.generation,"policy_digest":policy.policy_digest,
                    "source_input_digest":policy.source_input_digest,"runtime_identity":policy.runtime_identity,
                    "resident_generation":3,"mode":policy.mode
                }
            })
        );
    }
    assert_eq!(cases.len(), 260);
    assert!(
        mismatches.is_empty(),
        "receipt mode mismatches: {mismatches:?}"
    );
}

fn permissive_case(fixture: &Value) -> &Value {
    fixture["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["name"] == "Shell-enforce-managed-default-allow-printf '%s' Synthetic")
        .unwrap()
}

#[test]
fn independent_native_floors_survive_generic_configuration_and_observe() {
    let fixture = vectors();
    let case = permissive_case(&fixture);
    let source = envelope(case);
    for mode in ["enforce", "observe"] {
        let mut policy = snapshot(case);
        policy.mode = mode.to_owned();
        for floor in [
            "warn",
            "review",
            "require-reapproval",
            "sandbox-required",
            "block",
        ] {
            let mut intrinsic =
                evaluate_pre_tool_envelope(&source.harness, "PreToolUse", &source.raw_payload);
            intrinsic.reason_code = "independent_native_fixture_floor".to_owned();
            intrinsic.minimum_action = floor.to_owned();
            intrinsic.policy_action = floor.to_owned();
            intrinsic.decision = if floor == "warn" { "allow" } else { "deny" }.to_owned();
            intrinsic.explicitly_benign = false;
            let result =
                apply_scoped_pre_tool_policy(&policy, &source, &source.harness, intrinsic, 100)
                    .unwrap();
            assert_eq!(result.result.policy_action, floor);
            assert_eq!(result.observed_policy_action, None);
        }
    }
}

#[test]
fn generic_lockdown_is_terminal_without_inventing_unrelated_control_matches() {
    let fixture = vectors();
    let case = permissive_case(&fixture);
    let source = envelope(case);
    for mode in ["enforce", "observe"] {
        for lockdown in [false, true] {
            for state in ["enabled", "disabled"] {
                let mut policy = snapshot(case);
                policy.mode = mode.to_owned();
                let mut authority = serde_json::to_value(&policy.scoped_authority).unwrap();
                authority["managed"] = json!({
                    "revision":2, "managed_revision":7,
                    "catalog_digest":crate::policy_scoped_managed::catalog_digest(),
                    "global_lockdown":lockdown, "controls":[{
                        "target_kind":"permission", "target_id":"command.git.permission.force-push", "state":state
                    }]
                });
                policy.scoped_authority = serde_json::from_value(authority).unwrap();
                let intrinsic =
                    evaluate_pre_tool_envelope(&source.harness, "PreToolUse", &source.raw_payload);
                let result =
                    apply_scoped_pre_tool_policy(&policy, &source, &source.harness, intrinsic, 100)
                        .unwrap();
                assert_eq!(
                    result.result.policy_action,
                    if lockdown { "block" } else { "allow" }
                );
                assert_eq!(result.observed_policy_action, None);
            }
        }
    }
}

#[test]
fn managed_generic_configuration_refuses_unproved_source_shapes() {
    let fixture = vectors();
    let case = permissive_case(&fixture);
    let policy = snapshot(case);
    for (tool, command) in [
        ("Shell", "ssh synthetic@example.invalid whoami"),
        ("Shell", "true"),
        ("Shell", "whoami"),
        ("Shell", "uname"),
        ("Shell", "echo Synthetic"),
        ("Shell", "pwd -P"),
        ("BASH", "pwd"),
        ("unknown", "printf Synthetic"),
        ("Shell", "env printf Synthetic"),
        ("Shell", "printf Synthetic; pwd"),
    ] {
        let mut source = envelope(case);
        source.raw_payload["tool_name"] = json!(tool);
        source.raw_payload["tool_input"] = json!({"command":command});
        let intrinsic =
            evaluate_pre_tool_envelope(&source.harness, "PreToolUse", &source.raw_payload);
        assert!(
            apply_scoped_pre_tool_policy(&policy, &source, &source.harness, intrinsic, 100)
                .is_err(),
            "{tool} {command}"
        );
    }
    let mut alias = snapshot(case);
    alias
        .effective_policy
        .harness_actions
        .insert("Codex".to_owned(), "allow".to_owned());
    let source = envelope(case);
    let intrinsic = evaluate_pre_tool_envelope(&source.harness, "PreToolUse", &source.raw_payload);
    assert!(
        apply_scoped_pre_tool_policy(&alias, &source, &source.harness, intrinsic, 100).is_err()
    );
}

#[test]
fn managed_origin_and_command_expression_mix_remains_explicitly_unproved() {
    let fixture = vectors();
    let case = permissive_case(&fixture);
    let mut policy = snapshot(case);
    let mut authority = serde_json::to_value(&policy.scoped_authority).unwrap();
    authority["rows"] = json!([{
        "decision_id":1,"harness":"codex","scope":"global","action":"block",
        "source_kind":"signed-bundle","updated_at_us":1,"artifact_id":null,
        "artifact_hash":null,"workspace":null,"publisher":null,"expires_at_ms":null,
        "exact_command_sha256":null,"requires_exact_context":false
    }]);
    authority["command_expressions"] = json!([{"decision_id":1,"expression":{
        "combinator":"all","conditions":[
            {"field":"command","operator":"startsWith","value":"printf","caseSensitive":true}
        ]
    }}]);
    policy.scoped_authority = serde_json::from_value(authority).unwrap();
    let source = envelope(case);
    let intrinsic = evaluate_pre_tool_envelope(&source.harness, "PreToolUse", &source.raw_payload);
    assert_eq!(
        apply_scoped_pre_tool_policy(&policy, &source, &source.harness, intrinsic, 100)
            .err()
            .as_deref(),
        Some("native_managed_configuration_request_unsupported")
    );
}
