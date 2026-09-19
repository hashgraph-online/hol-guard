use super::*;
use guard_command::pretool::evaluate_pre_tool_envelope;
use guard_policy_snapshot::scoped_authority::NativePolicyAuthority;
use serde_json::json;

fn vectors() -> Value {
    super::policy_vector_ordinary::vectors()
}

fn envelope(case: &Value) -> GuardHookEnvelopeV2 {
    serde_json::from_value(json!({
        "schema":"guard-hook-envelope.v2", "harness":case["harness"],
        "event":"PreToolUse", "raw_payload":case["payload"],
        "policy_generation":1, "policy_snapshot":{}, "source":case["source"]
    }))
    .unwrap()
}

fn snapshot(case: &Value, rows: Vec<Value>) -> PolicySnapshotV4 {
    let vector: Value = serde_json::from_str(include_str!(
        "../../../../contracts/native-policy-snapshot/v4/policy-snapshot-vector.json"
    ))
    .unwrap();
    let mut value = vector["snapshot"].clone();
    value["effective_policy"] = case
        .get("localEffectivePolicy")
        .unwrap_or(&case["effectivePolicy"])
        .clone();
    value["mode"] = case["mode"].clone();
    value["scoped_authority"] = json!({
        "schema":"guard-native-policy-authority.v1", "generic_precedence":"specificity-recency.v1",
        "rows":rows, "managed":null
    });
    serde_json::from_value(value).unwrap()
}

fn row(case: &Value, action: &str, source_kind: &str) -> Value {
    json!({
        "decision_id":7, "harness":case["harness"], "scope":"artifact", "action":action,
        "source_kind":source_kind, "updated_at_us":1, "artifact_id":case["artifactId"],
        "artifact_hash":null, "workspace":null, "publisher":null, "expires_at_ms":null,
        "exact_command_sha256":null, "requires_exact_context":false
    })
}

#[test]
fn actual_sensitive_python_vectors_reach_scoped_native_composition() {
    let values = vectors();
    let cases = values["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 133);
    for case in cases {
        let source = envelope(case);
        let intrinsic =
            evaluate_pre_tool_envelope(&source.harness, "PreToolUse", &source.raw_payload);
        assert_eq!(
            intrinsic.reason_code, "native_file_read_review",
            "{}",
            case["name"]
        );
        let request = derive_scoped_policy_request(&source, &source.harness).unwrap();
        assert_eq!(request.artifact_id(), case["artifactId"].as_str());
        let result = apply_scoped_pre_tool_policy(
            &snapshot(case, vec![]),
            &source,
            &source.harness,
            intrinsic,
            100,
        )
        .unwrap();
        let expected = if case["mode"] == "observe" {
            assert_eq!(
                result.observed_policy_action,
                case["expected"]["evaluatedPolicyAction"].as_str()
            );
            &case["expected"]["finalPolicyAction"]
        } else {
            assert_eq!(result.observed_policy_action, None);
            &case["expected"]["evaluatedPolicyAction"]
        };
        assert_eq!(
            result.result.policy_action,
            expected.as_str().unwrap(),
            "{}",
            case["name"]
        );
        assert_eq!(result.result.minimum_action, result.result.policy_action);
        assert_eq!(
            result.result.decision,
            if rank(action(expected.as_str().unwrap()).unwrap()) <= 1 {
                "allow"
            } else {
                "deny"
            }
        );
        assert_eq!(result.selected_decision_id, None);
    }
}

#[test]
fn independent_native_floors_survive_sensitive_configuration_in_both_modes() {
    let values = vectors();
    let case = &values["cases"][0];
    let source = envelope(case);
    for mode in ["enforce", "observe"] {
        let mut policy = snapshot(case, vec![]);
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
            assert_eq!(result.selected_decision_id, None);
        }
    }
}

#[test]
fn saved_allow_is_not_a_sensitive_read_approval_and_block_still_restricts() {
    let values = vectors();
    let case = values["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| {
            case["mode"] == "enforce"
                && case["expected"]["evaluatedPolicyAction"] == "require-reapproval"
        })
        .unwrap();
    let source = envelope(case);
    for source_kind in ["local", "signed-memory", "signed-bundle"] {
        let intrinsic =
            evaluate_pre_tool_envelope(&source.harness, "PreToolUse", &source.raw_payload);
        let result = apply_scoped_pre_tool_policy(
            &snapshot(case, vec![row(case, "allow", source_kind)]),
            &source,
            &source.harness,
            intrinsic.clone(),
            100,
        )
        .unwrap();
        assert_eq!(result.result.policy_action, "require-reapproval");
        assert_eq!(result.selected_decision_id, None);
        let blocked = apply_scoped_pre_tool_policy(
            &snapshot(case, vec![row(case, "block", source_kind)]),
            &source,
            &source.harness,
            intrinsic,
            100,
        )
        .unwrap();
        assert_eq!(blocked.result.policy_action, "block");
        assert_eq!(blocked.selected_decision_id, Some(7));
    }
}

#[test]
fn saved_warning_remains_executable_in_sensitive_observe_mode() {
    let values = vectors();
    let case = &values["cases"][0];
    let source = envelope(case);
    let mut policy = snapshot(case, vec![row(case, "warn", "local")]);
    policy.mode = "observe".to_owned();
    let intrinsic = evaluate_pre_tool_envelope(&source.harness, "PreToolUse", &source.raw_payload);
    let result =
        apply_scoped_pre_tool_policy(&policy, &source, &source.harness, intrinsic, 100).unwrap();
    assert_eq!(result.result.policy_action, "warn");
    assert_eq!(result.result.decision, "allow");
    assert_eq!(result.selected_decision_id, Some(7));
}

#[test]
fn content_bound_policy_is_not_invented_from_a_path_identity() {
    let values = vectors();
    let case = &values["cases"][0];
    let source = envelope(case);
    let mut policy = snapshot(case, vec![]);
    let mut content_row = row(case, "block", "local");
    content_row["artifact_hash"] = json!("b".repeat(64));
    policy.scoped_authority = NativePolicyAuthority::from_slice(&serde_json::to_vec(&json!({
        "schema":"guard-native-policy-authority.v1", "generic_precedence":"specificity-recency.v1",
        "rows":[content_row], "managed":null
    })).unwrap()).unwrap();
    let intrinsic = evaluate_pre_tool_envelope(&source.harness, "PreToolUse", &source.raw_payload);
    assert!(
        apply_scoped_pre_tool_policy(&policy, &source, &source.harness, intrinsic, 100).is_err()
    );
}

#[test]
fn actual_mixed_origin_python_vectors_reach_scoped_native_composition() {
    let values = super::policy_vector_mixed::vectors();
    let cases = values["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 188);
    for case in cases {
        let source = envelope(case);
        let mut policy = snapshot(case, vec![]);
        policy.effective_policy =
            serde_json::from_value(case["localEffectivePolicy"].clone()).unwrap();
        let mut authority = serde_json::to_value(&policy.scoped_authority).unwrap();
        authority["managed_config"] = case["managedConfiguration"].clone();
        policy.scoped_authority = serde_json::from_value(authority).unwrap();
        let intrinsic =
            evaluate_pre_tool_envelope(&source.harness, "PreToolUse", &source.raw_payload);
        let result =
            apply_scoped_pre_tool_policy(&policy, &source, &source.harness, intrinsic, 100)
                .unwrap_or_else(|error| panic!("{}: {error}", case["name"]));
        let expected = if case["mode"] == "observe" {
            assert_eq!(
                result.observed_policy_action,
                case["expected"]["evaluatedPolicyAction"].as_str(),
                "{} evaluated",
                case["name"]
            );
            &case["expected"]["finalPolicyAction"]
        } else {
            assert_eq!(result.observed_policy_action, None);
            &case["expected"]["evaluatedPolicyAction"]
        };
        assert_eq!(
            result.result.policy_action,
            expected.as_str().unwrap(),
            "{} final",
            case["name"]
        );
        assert_eq!(result.result.minimum_action, result.result.policy_action);
        assert_eq!(
            result.result.decision,
            if rank(action(expected.as_str().unwrap()).unwrap()) <= 1 {
                "allow"
            } else {
                "deny"
            }
        );
        assert_eq!(result.selected_decision_id, None);
    }
}

fn managed_snapshot(case: &Value, lockdown: bool, state: &str) -> PolicySnapshotV4 {
    let mut policy = snapshot(case, vec![row(case, "allow", "signed-bundle")]);
    let mut authority = serde_json::to_value(&policy.scoped_authority).unwrap();
    authority["managed"] = json!({"revision":2,"managed_revision":7,
    "catalog_digest":crate::policy_scoped_managed::catalog_digest(),
    "global_lockdown":lockdown,"controls":[{
        "target_kind":"extension","target_id":"command.filesystem","state":state
    }]});
    policy.scoped_authority = serde_json::from_value(authority).unwrap();
    policy
}

#[test]
fn sensitive_managed_lockdown_survives_allow_and_observe() {
    let values = vectors();
    let case = &values["cases"][0];
    assert_eq!(case["expected"]["evaluatedPolicyAction"], "allow");
    let source = envelope(case);
    for mode in ["enforce", "observe"] {
        for state in ["enabled", "disabled"] {
            let mut policy = managed_snapshot(case, true, state);
            policy.mode = mode.to_owned();
            let intrinsic =
                evaluate_pre_tool_envelope(&source.harness, "PreToolUse", &source.raw_payload);
            let result =
                apply_scoped_pre_tool_policy(&policy, &source, &source.harness, intrinsic, 100)
                    .unwrap();
            assert_eq!(result.result.policy_action, "block");
            assert_eq!(result.result.minimum_action, "block");
            assert_eq!(result.result.decision, "deny");
            assert_eq!(
                result.observed_policy_action,
                (mode == "observe").then_some("block")
            );
            assert_eq!(result.selected_decision_id, None);
        }
    }
}

#[test]
fn sensitive_unrelated_controls_preserve_all_proven_configuration_cases() {
    let values = vectors();
    for case in values["cases"].as_array().unwrap() {
        let source = envelope(case);
        for state in ["enabled", "disabled"] {
            let policy = managed_snapshot(case, false, state);
            let intrinsic =
                evaluate_pre_tool_envelope(&source.harness, "PreToolUse", &source.raw_payload);
            let result =
                apply_scoped_pre_tool_policy(&policy, &source, &source.harness, intrinsic, 100)
                    .unwrap();
            let expected = if case["mode"] == "observe" {
                "finalPolicyAction"
            } else {
                "evaluatedPolicyAction"
            };
            assert_eq!(
                result.result.policy_action,
                case["expected"][expected].as_str().unwrap(),
                "{} {state}",
                case["name"]
            );
            assert_eq!(result.selected_decision_id, None);
        }
    }
}

#[test]
fn managed_sensitive_support_does_not_admit_unmodeled_requests() {
    let values = vectors();
    let case = &values["cases"][0];
    let policy = managed_snapshot(case, false, "enabled");
    for payload in [
        json!({"tool_name":"Write","tool_input":{"file_path":"/synthetic/.npmrc","content":"value"}}),
        json!({"tool_name":"mcp__synthetic__read","tool_input":{"file_path":"/synthetic/.npmrc"}}),
        json!({"tool_name":"Read","tool_input":{"file_path":"/synthetic/ordinary.txt"}}),
    ] {
        let mut source = envelope(case);
        source.raw_payload = payload;
        assert!(crate::policy_scoped_managed::request_is_blocked(
            policy.scoped_authority.managed(),
            &source,
            &source.harness
        )
        .is_err());
    }
}

#[test]
fn managed_configuration_origin_refuses_unproven_generic_request_semantics() {
    let vector: Value = serde_json::from_str(include_str!(
        "../../../../contracts/native-policy-snapshot/v4/managed-configuration-vector.json"
    ))
    .unwrap();
    let mut value = vector["snapshot"].clone();
    value["scoped_authority"]["rows"] = json!([]);
    value["scoped_authority"]["managed"] = Value::Null;
    let policy: PolicySnapshotV4 = serde_json::from_value(value).unwrap();
    let values = vectors();
    let case = &values["cases"][0];
    for payload in [
        json!({"tool_name":"Shell","tool_input":{"command":"true"}}),
        json!({"tool_name":"Shell","tool_input":{"command":"whoami"}}),
    ] {
        let mut source = envelope(case);
        source.harness = "codex".to_owned();
        source.raw_payload = payload;
        source.source.cwd = Some(std::env::temp_dir().to_str().unwrap().to_owned());
        assert!(derive_scoped_policy_request(&source, &source.harness).is_ok());
        let intrinsic =
            evaluate_pre_tool_envelope(&source.harness, "PreToolUse", &source.raw_payload);
        assert_eq!(
            apply_scoped_pre_tool_policy(&policy, &source, &source.harness, intrinsic, 100)
                .err()
                .as_deref(),
            Some("native_managed_configuration_request_unsupported")
        );
    }
}
