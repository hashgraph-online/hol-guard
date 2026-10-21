use super::*;
use guard_contracts::{HookArtifactV1, HOOK_ARTIFACT_FACTS_REQUEST_SCHEMA};
use serde_json::json;

fn artifact(artifact_type: &str, metadata: Value) -> HookArtifactV1 {
    HookArtifactV1 {
        artifact_type: artifact_type.to_owned(),
        metadata,
        configured_override: None,
    }
}

fn request(artifact_type: &str, metadata: Value) -> HookArtifactFactsRequestV1 {
    HookArtifactFactsRequestV1 {
        schema: HOOK_ARTIFACT_FACTS_REQUEST_SCHEMA.to_owned(),
        request_id: "hook-artifact-facts-test".to_owned(),
        artifacts: vec![artifact(artifact_type, metadata)],
    }
}

fn facts(artifact_type: &str, metadata: Value) -> Value {
    evaluate(&artifact(artifact_type, metadata))
}

#[test]
fn empty_metadata_derives_the_quiet_facts() {
    let value = facts("tool_action_request", json!({}));
    assert_eq!(value["hard_block"], json!(false));
    assert_eq!(value["configured_override"], Value::Null);
    assert_eq!(value["command_action_floor"], Value::Null);
    assert_eq!(value["explicit_permission_allow"], json!(false));
    assert_eq!(value["risk_classes"], json!([]));
    assert_eq!(value["guard_default_action"], Value::Null);
    assert_eq!(value["confidence_text"], json!(""));
    assert_eq!(value["action_class"], Value::Null);
    assert_eq!(value["skill_is_known_bad"], json!(false));
}

#[test]
fn the_payload_round_trips_as_the_compose_facts() {
    let value = facts(
        "prompt_request",
        json!({"prompt_request_class": "secret_read"}),
    );
    let parsed: PolicyArtifactFactsV1 = serde_json::from_value(value).expect("facts");
    assert_eq!(parsed.risk_classes, vec!["local_secret_read".to_owned()]);
}

#[test]
fn the_caller_override_rides_through_untouched() {
    let mut subject = artifact("tool_action_request", json!({}));
    subject.configured_override = Some("review".to_owned());
    assert_eq!(evaluate(&subject)["configured_override"], json!("review"));
}

#[test]
fn a_bypass_prompt_class_hard_blocks() {
    assert_eq!(
        facts(
            "prompt_request",
            json!({"prompt_request_classes": ["guard_bypass_intent"]})
        )["hard_block"],
        json!(true)
    );
    assert_eq!(
        facts(
            "prompt_request",
            json!({"prompt_request_class": "guard_bypass_intent"})
        )["hard_block"],
        json!(true)
    );
    assert_eq!(
        facts(
            "prompt_request",
            json!({"prompt_request_classes": ["secret_read"]})
        )["hard_block"],
        json!(false)
    );
}

#[test]
fn a_classes_list_overrides_the_singular_class() {
    // The list is read even when it does not hold the bypass class, so a
    // caller cannot hide a bypass list behind a quiet singular class.
    assert_eq!(
        facts(
            "prompt_request",
            json!({
                "prompt_request_classes": ["secret_read"],
                "prompt_request_class": "guard_bypass_intent",
            }),
        )["hard_block"],
        json!(false)
    );
}

#[test]
fn an_unrecognized_floor_normalizes_to_block() {
    assert_eq!(
        facts(
            "tool_action_request",
            json!({"command_action_floor": "not-an-action"})
        )["command_action_floor"],
        json!("block")
    );
    assert_eq!(
        facts(
            "tool_action_request",
            json!({"command_action_floor": Value::Null})
        )["command_action_floor"],
        json!("block")
    );
    assert_eq!(
        facts(
            "tool_action_request",
            json!({"command_action_floor": "ask"})
        )["command_action_floor"],
        json!("review")
    );
}

fn explicit_allow_metadata() -> Value {
    json!({
        "command_action_floor": "allow",
        "extension_control_resolution": {
            "blocked": false,
            "explicitly_enabled_permission_ids": ["command.git.status"],
        },
        "command_decision_plane": {
            "action": "allow",
            "proof_routes": ["verified"],
            "controlling_reasons": [
                {"source": "control", "reason_code": "control.explicitly-enabled-permission"},
            ],
        },
    })
}

#[test]
fn a_verified_explicit_permission_allow_is_recognized() {
    assert_eq!(
        facts("tool_action_request", explicit_allow_metadata())["explicit_permission_allow"],
        json!(true)
    );
}

#[test]
fn the_native_floor_is_skipped_for_a_package_request_or_an_explicit_allow() {
    assert_eq!(
        facts("package_request", json!({}))["skip_native_floor"],
        json!(true)
    );
    assert_eq!(
        facts("tool_action_request", explicit_allow_metadata())["skip_native_floor"],
        json!(true)
    );
    assert_eq!(
        facts("tool_action_request", json!({}))["skip_native_floor"],
        json!(false)
    );
    assert_eq!(
        facts("prompt_request", json!({}))["skip_native_floor"],
        json!(false)
    );
}

#[test]
fn every_explicit_permission_condition_is_required() {
    let drop = |mutate: fn(&mut Value)| {
        let mut metadata = explicit_allow_metadata();
        mutate(&mut metadata);
        facts("tool_action_request", metadata)["explicit_permission_allow"].clone()
    };
    assert_eq!(
        drop(|m| m["command_action_floor"] = json!("review")),
        json!(false)
    );
    assert_eq!(
        drop(|m| m["extension_control_resolution"]["blocked"] = json!(true)),
        json!(false)
    );
    assert_eq!(
        drop(
            |m| m["extension_control_resolution"]["explicitly_enabled_permission_ids"] = json!([])
        ),
        json!(false)
    );
    assert_eq!(
        drop(|m| {
            m["extension_control_resolution"]["explicitly_enabled_permission_ids"] =
                json!(["command.git.status", "skill.write"]);
        }),
        json!(false)
    );
    assert_eq!(
        drop(|m| m["command_decision_plane"]["action"] = json!("review")),
        json!(false)
    );
    assert_eq!(
        drop(|m| m["command_decision_plane"]["proof_routes"] = json!(["claimed"])),
        json!(false)
    );
    assert_eq!(
        drop(|m| {
            m["command_decision_plane"]["controlling_reasons"] = json!([{"source": "policy", "reason_code": "control.explicitly-enabled-permission"}]);
        }),
        json!(false)
    );
}

#[test]
fn risk_classes_follow_the_artifact_type() {
    assert_eq!(
        facts("file_read_request", json!({}))["risk_classes"],
        json!(["local_secret_read"])
    );
    assert_eq!(
        facts("package_request", json!({}))["risk_classes"],
        json!(["package_script"])
    );
    assert_eq!(
        facts(
            "prompt_request",
            json!({"prompt_request_classes": ["exfil_intent", "destructive_intent", "subprocess_intent"]}),
        )["risk_classes"],
        json!(["credential_exfiltration", "destructive_shell"])
    );
    assert_eq!(facts("skill", json!({}))["risk_classes"], json!([]));
}

#[test]
fn a_tool_action_class_contributes_its_command_risk_classes() {
    let expected: Vec<String> =
        risk_classes_for_command_action("credential exfiltration shell command")
            .iter()
            .map(|item| (*item).to_owned())
            .collect();
    assert!(
        !expected.is_empty(),
        "the fixture action class carries risk classes"
    );
    assert_eq!(
        facts(
            "tool_action_request",
            json!({"action_class": "credential exfiltration shell command"}),
        )["risk_classes"],
        serde_json::to_value(expected).expect("classes")
    );
}

#[test]
fn composite_classes_lead_and_duplicates_collapse() {
    assert_eq!(
        facts(
            "file_read_request",
            json!({"risk_classes": ["  policy_violation  ", "local_secret_read", "", 7]}),
        )["risk_classes"],
        json!(["policy_violation", "local_secret_read"])
    );
}

#[test]
fn the_pytest_sandbox_fact_needs_all_three_markers() {
    let full = json!({
        "action_class": "pytest repository-code execution",
        "reason_code": "pytest_restricted_profile_required",
        "restricted_profile_version": "2",
    });
    assert_eq!(
        facts("tool_action_request", full.clone())["pytest_restricted_sandbox"],
        json!(true)
    );
    let mut without_version = full.clone();
    without_version["restricted_profile_version"] = json!(2);
    assert_eq!(
        facts("tool_action_request", without_version)["pytest_restricted_sandbox"],
        json!(false)
    );
    let mut other_reason = full;
    other_reason["reason_code"] = json!("shell_local_script_execution_review");
    let value = facts("tool_action_request", other_reason);
    assert_eq!(value["pytest_restricted_sandbox"], json!(false));
    assert_eq!(value["shell_local_script_review"], json!(true));
}

#[test]
fn a_non_string_default_action_arrives_as_the_unknown_action() {
    assert_eq!(
        facts("tool_action_request", json!({"guard_default_action": 7}))["guard_default_action"],
        json!("")
    );
    assert_eq!(
        facts(
            "tool_action_request",
            json!({"guard_default_action": "review"})
        )["guard_default_action"],
        json!("review")
    );
}

#[test]
fn the_confidence_falls_back_through_the_signals() {
    assert_eq!(
        facts("tool_action_request", json!({"risk_confidence": "strong"}))["confidence_text"],
        json!("strong")
    );
    assert_eq!(
        facts("tool_action_request", json!({"confidence": "moderate"}))["confidence_text"],
        json!("moderate")
    );
    assert_eq!(
        facts(
            "tool_action_request",
            json!({
                "risk_confidence": "   ",
                "risk_signals": [{"confidence": " "}, {"confidence": "strong"}],
            }),
        )["confidence_text"],
        json!("strong")
    );
    assert_eq!(
        facts(
            "tool_action_request",
            json!({"risk_confidence": "  ", "risk_signals": []}),
        )["confidence_text"],
        json!("  ")
    );
    assert_eq!(
        facts("tool_action_request", json!({"risk_confidence": 7}))["confidence_text"],
        json!("7")
    );
}

#[test]
fn a_strong_confidence_text_reads_strong_in_the_compose_facts() {
    let value = facts(
        "tool_action_request",
        json!({"risk_confidence": " Strong "}),
    );
    let parsed: PolicyArtifactFactsV1 = serde_json::from_value(value).expect("facts");
    assert!(parsed.confidence_strong());
}

#[test]
fn a_known_bad_skill_is_recognized_from_each_marker() {
    for metadata in [
        json!({"known_bad_skill": true}),
        json!({"skill_is_known_bad": true}),
        json!({"threat_intel": {"known_bad": true}}),
    ] {
        assert_eq!(facts("skill", metadata)["skill_is_known_bad"], json!(true));
    }
    assert_eq!(
        facts("skill", json!({"known_bad_skill": "true"}))["skill_is_known_bad"],
        json!(false)
    );
}

#[test]
fn a_launch_agent_write_is_recognized_only_from_the_boolean() {
    assert_eq!(
        facts(
            "tool_action_request",
            json!({"persistence_writes_launch_agent": true})
        )["writes_launch_agent"],
        json!(true)
    );
    assert_eq!(
        facts(
            "tool_action_request",
            json!({"persistence_writes_launch_agent": "yes"})
        )["writes_launch_agent"],
        json!(false)
    );
}

#[test]
fn the_result_binds_its_request_digest() {
    let wire = request("tool_action_request", json!({"action_class": "file read"}));
    let encoded = evaluate_hook_artifact_facts_request(&wire).expect("response");
    let decoded: HookArtifactFactsResultV1 = serde_json::from_slice(&encoded).expect("result");
    assert_eq!(decoded.schema, HOOK_ARTIFACT_FACTS_RESULT_SCHEMA);
    assert_eq!(decoded.request_id, wire.request_id);
    assert_eq!(decoded.status, "ok");
    assert_eq!(decoded.code, "ok");
    assert_eq!(
        decoded.request_sha256,
        request_digest_with_limit(&wire, HOOK_ARTIFACT_FACTS_MAX_BYTES).expect("digest")
    );
    assert_eq!(
        decoded.payload.expect("payload")["facts"][0]["action_class"],
        json!("file read")
    );
}

#[test]
fn an_unknown_request_field_is_rejected() {
    let wire = json!({
        "schema": HOOK_ARTIFACT_FACTS_REQUEST_SCHEMA,
        "request_id": "hook-artifact-facts-test",
        "artifacts": [{"artifact_type": "tool_action_request", "metadata": {}}],
        "risk_classes": ["destructive_shell"],
    });
    assert!(serde_json::from_value::<HookArtifactFactsRequestV1>(wire).is_err());
}

#[test]
fn every_requested_artifact_is_answered_in_order() {
    let wire = HookArtifactFactsRequestV1 {
        schema: HOOK_ARTIFACT_FACTS_REQUEST_SCHEMA.to_owned(),
        request_id: "hook-artifact-facts-test".to_owned(),
        artifacts: vec![
            artifact("tool_action_request", json!({"action_class": "file read"})),
            artifact("file_read_request", json!({})),
        ],
    };
    let answered = evaluate_request(&wire);
    let facts = answered["facts"].as_array().expect("facts");
    assert_eq!(facts.len(), 2);
    assert_eq!(facts[0]["action_class"], json!("file read"));
    assert_eq!(facts[1]["risk_classes"], json!(["local_secret_read"]));
}

#[test]
fn a_request_naming_another_contract_is_refused() {
    let mut wire = request("tool_action_request", json!({}));
    wire.schema = "guard-hook-compose-request.v1".to_owned();
    let encoded = evaluate_hook_artifact_facts_request(&wire).expect("response");
    let decoded: HookArtifactFactsResultV1 = serde_json::from_slice(&encoded).expect("result");
    assert_eq!(decoded.status, "error");
    assert_eq!(decoded.code, "native_hook_artifact_facts_schema_mismatch");
    assert!(decoded.payload.is_none());
}

#[test]
fn more_artifacts_than_the_contract_admits_are_refused() {
    let mut wire = request("tool_action_request", json!({}));
    wire.artifacts =
        vec![artifact("tool_action_request", json!({})); HOOK_ARTIFACT_FACTS_MAX_ARTIFACTS + 1];
    let encoded = evaluate_hook_artifact_facts_request(&wire).expect("response");
    let decoded: HookArtifactFactsResultV1 = serde_json::from_slice(&encoded).expect("result");
    assert_eq!(decoded.status, "error");
    assert_eq!(
        decoded.code,
        "native_hook_artifact_facts_too_many_artifacts"
    );
    assert!(decoded.payload.is_none());
}

#[test]
fn a_separator_padded_confidence_falls_through_to_the_signals() {
    // `str.strip()` removes U+001C-U+001F, so a confidence made only of them
    // is empty in Python and the signals decide the evidence strength.
    assert_eq!(
        facts(
            "tool_action_request",
            json!({
                "risk_confidence": "\u{1c}\u{1f}",
                "risk_signals": [{"confidence": "strong"}],
            }),
        )["confidence_text"],
        json!("strong")
    );
}

#[test]
fn a_separator_padded_risk_label_is_still_recognized() {
    // `str.strip()` removes U+001C-U+001F, so a label padded with them read as
    // its own class in Python and must not reach composition unrecognized.
    let value = facts(
        "tool_action_request",
        json!({"risk_classes": ["\u{1c}credential_exfiltration\u{1f}", "  \u{1e}  "]}),
    );
    assert_eq!(value["risk_classes"], json!(["credential_exfiltration"]));
}
