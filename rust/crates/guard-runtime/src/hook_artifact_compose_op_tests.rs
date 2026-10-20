//! Recorded vectors and transport binding checks for `HookArtifactCompose`.

use flate2::read::GzDecoder;
use guard_contracts::{
    GuardAction, HookArtifactComposeQueryV1, NativeEdgeFactsV1, PolicyConfigFactsV1,
    HOOK_ARTIFACT_COMPOSE_REQUEST_SCHEMA,
};
use serde_json::{json, Value};
use std::io::Read;

use super::{compose, native_edge_floor};

const VECTORS: &str = include_str!("../tests/fixtures/hook_artifact_compose_vectors.json");
const CONFIG_ACTION_VECTORS: &[u8] =
    include_bytes!("../tests/fixtures/config_action_vectors.json.gz");

#[test]
fn matches_recorded_vectors() {
    let vectors: Vec<Value> = serde_json::from_str(VECTORS).unwrap();
    assert!(vectors.len() >= 78);
    for vector in vectors {
        let name = vector["name"].as_str().unwrap();
        let query: HookArtifactComposeQueryV1 = serde_json::from_value(vector["query"].clone())
            .unwrap_or_else(|error| panic!("{name}: {error}"));
        assert_eq!(compose(&query).unwrap(), vector["expected"], "{name}");
    }
}

#[test]
fn fused_decision_copy_preserves_recorded_factory_and_overlay_outcomes() {
    let decisions: Value = serde_json::from_str(include_str!(
        "../../../../tests/fixtures/decision_authority_vectors.json"
    ))
    .unwrap();
    let copies: Vec<Value> = serde_json::from_str(VECTORS).unwrap();
    let mut checked = 0;
    for decision in decisions["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|v| v["kind"] == "decision_legacy" && v["expected"]["status"] == "ok")
    {
        for copy in copies
            .iter()
            .filter(|v| v["query"]["kind"] == "decision_copy")
        {
            let mut original = copy["query"].clone();
            original["policy_action"] = decision["args"]["action"].clone();
            let mut expected = decision["expected"]["value"].clone();
            for field in ["user_body", "harness_message", "dashboard_primary_detail"] {
                original[format!("base_{field}")] = expected[field].clone();
            }
            let query = serde_json::from_value(original.clone()).unwrap();
            let overlay = compose(&query).unwrap();
            expected
                .as_object_mut()
                .unwrap()
                .extend(overlay["decision_overrides"].as_object().unwrap().clone());
            original.as_object_mut().unwrap().remove("kind");
            // Caller-supplied base copy cannot replace the canonical native base.
            for field in [
                "base_user_body",
                "base_harness_message",
                "base_dashboard_primary_detail",
            ] {
                original[field] = json!("forged caller copy");
            }
            let fused = serde_json::from_value(json!({
                "kind": "decision_build_copy", "copy": original,
                "reason": decision["args"]["reason"], "signals": decision["args"]["signals"],
            }))
            .unwrap();
            let actual = compose(&fused).unwrap();
            assert_eq!(actual["decision_v2"], expected);
            assert_eq!(actual["risk_headline"], overlay["risk_headline"]);
            checked += 1;
        }
    }
    assert!(checked >= 600);
}

#[test]
fn config_action_matches_recorded_python_vectors() {
    let mut text = String::new();
    GzDecoder::new(CONFIG_ACTION_VECTORS)
        .read_to_string(&mut text)
        .unwrap();
    let vectors: Vec<Value> = serde_json::from_str(&text).unwrap();
    assert!(vectors.len() >= 900);
    for vector in vectors {
        let name = vector["name"].as_str().unwrap();
        let mut query = vector["query"].clone();
        query["kind"] = json!("config_action");
        let query: HookArtifactComposeQueryV1 =
            serde_json::from_value(query).unwrap_or_else(|error| panic!("{name}: {error}"));
        assert_eq!(compose(&query).unwrap(), vector["expected"], "{name}");
        // The previous Python hook evaluation sent this configured data-flow
        // action; an unrecognised value never became an action.
        let config: PolicyConfigFactsV1 =
            serde_json::from_value(vector["query"]["policy_config"].clone()).unwrap();
        for (key, strong) in [("weak", false), ("strong", true)] {
            let expected = vector["data_flow"][key]
                .as_str()
                .and_then(GuardAction::from_canonical);
            assert_eq!(
                crate::hook_policy_config::data_flow_configured_action(&config, strong),
                expected,
                "{name} {key}"
            );
        }
    }
}

fn resident(request: Value) -> Result<Value, String> {
    crate::resident_protocol::evaluate_resident_bytes(request.to_string().as_bytes(), None)
        .map(|bytes| serde_json::from_slice(&bytes).unwrap())
}

fn envelope(schema: &str, query: Value) -> Value {
    json!({
        "operation": "hook_artifact_compose",
        "request": {"schema": schema, "request_id": "req-compose", "query": query},
    })
}

#[test]
fn resident_transport_binds_request_and_composes() {
    let reply = resident(envelope(
        HOOK_ARTIFACT_COMPOSE_REQUEST_SCHEMA,
        json!({"kind": "tool_grant_apply"}),
    ))
    .unwrap();
    assert_eq!(reply["status"], "ok");
    assert_eq!(reply["code"], "ok");
    assert_eq!(reply["schema"], "guard-hook-artifact-compose-result.v1");
    assert_eq!(reply["request_id"], "req-compose");
    assert!(reply["request_sha256"]
        .as_str()
        .unwrap()
        .starts_with("sha256:"));
    assert_eq!(reply["payload"]["policy_action"], "allow");
}

#[test]
fn rejects_wrong_schema_unknown_fields_and_missing_fields() {
    let err = resident(envelope("bogus", json!({"kind": "tool_grant_apply"}))).unwrap_err();
    assert_eq!(err, "native_hook_artifact_compose_schema_mismatch");

    let surprise = json!({
        "kind": "grant_settle", "current_action": "review", "policy_action": "review",
        "approval_context_action": "review", "granted_action": "review",
        "native_floor": null, "surprise": true,
    });
    assert!(resident(envelope(HOOK_ARTIFACT_COMPOSE_REQUEST_SCHEMA, surprise)).is_err());

    let missing = json!({"kind": "grant_settle", "current_action": "review"});
    assert!(resident(envelope(HOOK_ARTIFACT_COMPOSE_REQUEST_SCHEMA, missing)).is_err());

    let unknown = json!({"kind": "not_a_query"});
    assert!(resident(envelope(HOOK_ARTIFACT_COMPOSE_REQUEST_SCHEMA, unknown)).is_err());
}

#[test]
fn unknown_actions_never_lower_the_composed_action() {
    let reply = resident(envelope(
        HOOK_ARTIFACT_COMPOSE_REQUEST_SCHEMA,
        json!({
            "kind": "grant_settle", "current_action": 7, "policy_action": null,
            "approval_context_action": "???", "granted_action": "bogus", "native_floor": "also-bogus",
        }),
    ))
    .unwrap();
    for key in [
        "current_policy_action",
        "policy_action",
        "approval_context_policy_action",
    ] {
        assert_eq!(reply["payload"][key], "review", "{key}");
    }
}

fn edge(event: &str, fields: Value) -> NativeEdgeFactsV1 {
    NativeEdgeFactsV1 {
        event_name: Some(event.to_owned()),
        policy_action: fields["policy_action"].clone(),
        minimum_action: fields["minimum_action"].clone(),
        decision: fields["decision"].clone(),
        reason_code: fields["reason_code"].clone(),
        package_request: fields["package_request"].as_bool().unwrap_or(false),
    }
}

#[test]
fn edge_floors_after_execution_only_through_reapproval() {
    let deny = json!({"decision": "deny"});
    assert_eq!(
        native_edge_floor(&edge("PreToolUse", deny.clone()), None),
        None
    );
    let block = json!({"decision": "deny", "policy_action": "block"});
    assert_eq!(
        native_edge_floor(&edge("UserPromptSubmit", block), None),
        None
    );
    assert_eq!(
        native_edge_floor(&edge("PostToolUse", deny.clone()), None),
        Some(GuardAction::RequireReapproval)
    );
    assert_eq!(
        native_edge_floor(&edge("PostToolUse", deny), Some("warn")),
        None
    );
    let allow = json!({"policy_action": "allow"});
    assert_eq!(
        native_edge_floor(&edge("PostToolUse", allow), None),
        Some(GuardAction::Allow)
    );
    let reapproval = json!({"policy_action": "require-reapproval"});
    assert_eq!(
        native_edge_floor(&edge("PostToolUse", reapproval), Some("warn")),
        Some(GuardAction::RequireReapproval)
    );
}

#[test]
fn a_terminal_pre_tool_edge_cannot_be_relaxed_to_review() {
    for (action, expected) in [
        ("block", GuardAction::Block),
        ("sandbox-required", GuardAction::SandboxRequired),
    ] {
        let terminal = json!({"decision": "deny", "policy_action": action});
        assert_eq!(
            native_edge_floor(&edge("PreToolUse", terminal), Some("warn")),
            Some(expected)
        );
    }
    for action in ["review", "allow"] {
        let soft = json!({"policy_action": action});
        assert_eq!(native_edge_floor(&edge("PreToolUse", soft), None), None);
    }
    // An unrecognized edge action fails closed.
    let unknown = json!({"policy_action": "teleport"});
    assert_eq!(
        native_edge_floor(&edge("PreToolUse", unknown), None),
        Some(GuardAction::Block)
    );
}

#[test]
fn the_package_evaluator_owns_command_control_failures_but_not_secret_denies() {
    let failure = |package_request| {
        edge(
            "PreToolUse",
            json!({
                "policy_action": "block",
                "reason_code": "native_command_extension_evaluation_failed",
                "package_request": package_request,
            }),
        )
    };
    assert_eq!(native_edge_floor(&failure(true), None), None);
    assert_eq!(
        native_edge_floor(&failure(false), None),
        Some(GuardAction::Block)
    );
    let secret = edge(
        "PreToolUse",
        json!({
            "policy_action": "block",
            "reason_code": "native_secret_exfiltration",
            "package_request": true,
        }),
    );
    assert_eq!(native_edge_floor(&secret, None), Some(GuardAction::Block));
}

fn observe_query(fields: Value) -> HookArtifactComposeQueryV1 {
    let mut query = json!({
        "kind": "observe_executable_action",
        "current_config_action": Value::Null,
        "current_action_override": Value::Null,
        "trusted_cli_override": Value::Null,
        "untrusted_hook_payload_hint": Value::Null,
        "package_action": Value::Null,
        "data_flow_action": Value::Null,
        "scanner_action": Value::Null,
        "package_evaluation_action": Value::Null,
    });
    for (key, value) in fields.as_object().unwrap() {
        query[key] = value.clone();
    }
    serde_json::from_value(query).unwrap()
}

#[test]
fn observe_mode_records_an_allow_when_nothing_let_work_through() {
    let answer = compose(&observe_query(json!({}))).unwrap();

    assert_eq!(answer["executable_action"], "allow");
}

#[test]
fn observe_mode_keeps_the_strictest_source_that_still_executes() {
    // The warning ran; the block is the gate observe mode removed, so it does
    // not name the action the harness would have taken.
    let answer = compose(&observe_query(json!({
        "current_config_action": "allow",
        "scanner_action": "warn",
        "package_action": "block",
    })))
    .unwrap();

    assert_eq!(answer["executable_action"], "warn");
}

#[test]
fn observe_mode_ignores_every_source_that_asked_for_a_gate() {
    for gate in ["review", "require-reapproval", "sandbox-required", "block"] {
        let answer = compose(&observe_query(json!({ "data_flow_action": gate }))).unwrap();

        assert_eq!(answer["executable_action"], "allow", "{gate}");
    }
}

#[test]
fn observe_mode_contributes_nothing_for_a_source_name_this_build_cannot_read() {
    let answer = compose(&observe_query(json!({
        "trusted_cli_override": "quarantine",
        "untrusted_hook_payload_hint": "warn",
    })))
    .unwrap();

    assert_eq!(answer["executable_action"], "warn");
}

#[test]
fn observe_mode_reads_the_package_evaluations_own_action() {
    let answer = compose(&observe_query(
        json!({ "package_evaluation_action": "warn" }),
    ))
    .unwrap();

    assert_eq!(answer["executable_action"], "warn");
}

fn prompt_request_reason(
    harness: Value,
    classes: &[&str],
    summary: Value,
    action: Value,
) -> String {
    let query: HookArtifactComposeQueryV1 = serde_json::from_value(json!({
        "kind": "prompt_request_reason",
        "harness": harness,
        "prompt_classes": classes,
        "prompt_summary": summary,
        "policy_action": action,
    }))
    .unwrap();
    compose(&query).unwrap()["reason"]
        .as_str()
        .unwrap()
        .to_string()
}

#[test]
fn a_codex_secret_read_prompt_names_the_file_its_summary_reported() {
    let credential = prompt_request_reason(
        json!("codex"),
        &["secret_read"],
        json!("Reads a credential-looking local file"),
        json!("block"),
    );
    assert!(
        credential.contains("open a credential-looking local file."),
        "{credential}"
    );
    let sensitive = prompt_request_reason(
        json!("codex"),
        &["secret_read"],
        Value::Null,
        json!("block"),
    );
    assert!(
        sensitive.contains("open a sensitive local file."),
        "{sensitive}"
    );
}

#[test]
fn another_harness_asking_for_secrets_keeps_the_prompt_copy() {
    let reason = prompt_request_reason(
        json!("claude-code"),
        &["secret_read"],
        Value::Null,
        json!("review"),
    );
    assert!(
        reason.starts_with("HOL Guard flagged this prompt because"),
        "{reason}"
    );
}

fn remembered_rule_reason(remembered_rules: &str, integrity_message: Value) -> Value {
    let query: HookArtifactComposeQueryV1 = serde_json::from_value(json!({
        "kind": "remembered_rule_reason",
        "remembered_rules": remembered_rules,
        "integrity_message": integrity_message,
        "artifact_summary": "git push",
    }))
    .unwrap();
    compose(&query).unwrap()
}

#[test]
fn a_reported_rule_state_other_than_degraded_names_no_reason() {
    for state in ["enabled", "unknown", "disabled"] {
        assert_eq!(
            remembered_rule_reason(state, Value::Null)["reason"],
            Value::Null,
            "{state}"
        );
    }
}

#[test]
fn a_degraded_rule_state_names_the_request_and_what_still_works() {
    let reason = remembered_rule_reason("disabled_degraded", Value::Null);
    let text = reason["reason"].as_str().unwrap();
    assert!(
        text.starts_with("HOL Guard kept git push in review because"),
        "{text}"
    );
    assert!(text.contains("One-time approvals still work"), "{text}");
    assert!(!text.contains("  "), "{text}");
}

#[test]
fn an_integrity_detail_is_appended_as_its_own_sentence() {
    let reason = remembered_rule_reason("disabled_degraded", json!("Store digest changed"));
    let text = reason["reason"].as_str().unwrap();
    assert!(
        text.contains("degraded. Store digest changed. One-time"),
        "{text}"
    );
}

#[test]
fn an_integrity_detail_that_ends_a_sentence_gains_no_second_period() {
    let reason = remembered_rule_reason("disabled_degraded", json!("  Store digest changed.  "));
    let text = reason["reason"].as_str().unwrap();
    assert!(
        text.contains("degraded. Store digest changed. One-time"),
        "{text}"
    );
}

#[test]
fn a_blank_integrity_detail_is_left_out() {
    let blank = remembered_rule_reason("disabled_degraded", json!("   "));
    assert_eq!(
        blank,
        remembered_rule_reason("disabled_degraded", Value::Null)
    );
}

fn settle(query: Value) -> Value {
    compose(&serde_json::from_value(query).unwrap()).unwrap()
}

fn package_settle(reasons: Value, stored_action: Value, claim: bool) -> Value {
    settle(json!({
        "kind": "package_reuse_settle",
        "reasons": reasons,
        "claim_saved_approval": claim,
        "current_action": "review",
        "evaluation_policy_action": "allow",
        "stored_policy_action": stored_action,
        "stored_artifact_hash": Value::Null,
        "approval_reuse_source": Value::Null,
    }))
}

#[test]
fn a_package_request_with_no_saved_reason_keeps_the_composed_action() {
    let answer = package_settle(json!([{"code": "package_unverified"}]), Value::Null, false);

    assert_eq!(answer["reuse_applied"], json!(false));
    assert_eq!(answer["policy_action"], json!("review"));
    assert_eq!(answer["approval_reuse_source"], Value::Null);
    assert_eq!(answer["evidence_appends"], json!([]));
    assert_eq!(answer["settled_evidence_appends"], json!([]));
}

#[test]
fn a_saved_package_approval_applies_the_evaluations_action_and_names_its_source() {
    let answer = package_settle(
        json!([{"code": "saved_package_approval", "approval_claim_disposition": "consumed"}]),
        Value::Null,
        false,
    );

    assert_eq!(answer["reuse_applied"], json!(true));
    assert_eq!(answer["saved_allow_applied"], json!(true));
    assert_eq!(answer["claim_disposition"], json!("consumed"));
    assert_eq!(answer["policy_action"], json!("allow"));
    assert_eq!(
        answer["approval_reuse_source"],
        json!("saved_package_policy")
    );
    assert_eq!(answer["revalidate_required"], json!(false));
}

#[test]
fn a_claimed_saved_allow_revalidates_at_the_execution_boundary() {
    let answer = package_settle(
        json!([{"code": "saved_package_approval"}]),
        Value::Null,
        true,
    );

    assert_eq!(answer["revalidate_required"], json!(true));
    assert_eq!(answer["claim_disposition"], Value::Null);
}

#[test]
fn only_a_disposition_the_claim_can_report_is_kept() {
    let answer = package_settle(
        json!([{"code": "saved_package_approval", "approval_claim_disposition": "elsewhere"}]),
        Value::Null,
        false,
    );

    assert_eq!(answer["claim_disposition"], Value::Null);
}

#[test]
fn the_first_reason_carrying_reuse_evidence_ends_the_scan() {
    let answer = package_settle(
        json!([
            {"code": "saved_package_block", "approval_reuse": {"action": "block", "status": "accepted"}},
            {"code": "saved_package_approval", "approval_claim_disposition": "retained"},
        ]),
        Value::Null,
        true,
    );

    // The second reason is never read, so no saved allow is applied and the
    // claim never revalidates -- the behaviour the Python loop's break had.
    assert_eq!(answer["saved_allow_applied"], json!(false));
    assert_eq!(answer["revalidate_required"], json!(false));
    assert_eq!(
        answer["reuse_evidence"],
        json!({"action": "block", "status": "accepted"})
    );
    assert_eq!(
        answer["evidence_appends"],
        json!([{
            "source": "approval_reuse",
            "input_source": "saved_package_policy",
            "action": "block",
            "status": "accepted",
        }])
    );
}

#[test]
fn a_stopped_prompt_says_what_it_requested() {
    for action in ["block", "sandbox-required"] {
        let reason =
            prompt_request_reason(Value::Null, &["secret_read"], Value::Null, json!(action));
        assert_eq!(
            reason,
            "HOL Guard blocked this prompt because it requests guarded local secret access.",
            "{action}"
        );
    }
}

#[test]
fn a_bypass_prompt_is_blocked_on_its_own_terms_whatever_the_action() {
    for action in [json!("block"), json!("review"), Value::Null] {
        let reason = prompt_request_reason(
            Value::Null,
            &["guard_bypass_intent", "secret_read"],
            Value::Null,
            action,
        );
        assert_eq!(
            reason,
            "HOL Guard blocked this prompt because it asks to bypass or disable Guard."
        );
    }
}

#[test]
fn a_prompt_with_no_recognised_class_is_flagged_as_higher_risk() {
    let reason = prompt_request_reason(json!("codex"), &[], Value::Null, json!("review"));
    assert!(
        reason.starts_with("HOL Guard flagged this prompt as higher risk."),
        "{reason}"
    );
}

#[test]
fn a_stored_block_holds_the_request_and_names_the_saved_decision() {
    let answer = package_settle(json!([]), json!("block"), false);

    assert_eq!(answer["policy_action"], json!("block"));
    assert_eq!(
        answer["approval_reuse_source"],
        json!("saved_policy_decision")
    );
    assert_eq!(answer["approval_reuse"]["action"], json!("block"));
    assert_eq!(
        answer["settled_evidence_appends"][0]["input_source"],
        json!("saved_policy_decision")
    );
}

#[test]
fn a_stored_block_beside_package_reuse_keeps_the_package_source_and_adds_no_second_evidence() {
    let answer = package_settle(
        json!([{"code": "saved_package_approval"}]),
        json!("block"),
        false,
    );

    // The reason scan already recorded the reuse, so the settlement names the
    // package source and does not describe the same reuse twice.
    assert_eq!(answer["policy_action"], json!("block"));
    assert_eq!(
        answer["approval_reuse_source"],
        json!("saved_package_policy")
    );
    assert_eq!(answer["settled_evidence_appends"], json!([]));
}

fn entitlement_query(now: Value, oauth_health: Value) -> HookArtifactComposeQueryV1 {
    serde_json::from_value(json!({
        "kind": "package_firewall_entitlement",
        "bundle_payload": null,
        "oauth_payload": null,
        "oauth_health": oauth_health,
        "connect_state": null,
        "has_cloud_sync_profile": false,
        "now": now,
    }))
    .unwrap()
}

#[test]
fn an_entitlement_clock_that_is_not_an_instant_is_refused() {
    assert_eq!(
        compose(&entitlement_query(json!("whenever"), Value::Null)).unwrap_err(),
        "now must be an ISO-8601 instant"
    );
}

#[test]
fn an_entitlement_row_of_the_wrong_shape_is_refused() {
    assert_eq!(
        compose(&entitlement_query(Value::Null, json!("healthy"))).unwrap_err(),
        "oauth_health must be an object or null"
    );
}

#[test]
fn a_policy_lookup_selection_with_nothing_to_select_is_refused() {
    let query: HookArtifactComposeQueryV1 =
        serde_json::from_value(json!({"kind": "policy_lookup_select", "lookups": []})).unwrap();
    assert_eq!(
        compose(&query).unwrap_err(),
        "at least one policy lookup is required"
    );
}

#[test]
fn a_package_firewall_entitlement_that_is_not_an_object_is_refused() {
    let query: HookArtifactComposeQueryV1 = serde_json::from_value(json!({
        "kind": "package_firewall_access",
        "entitlement": "allowed",
        "operation": "install",
        "has_installed_managers": false,
    }))
    .unwrap();

    assert_eq!(
        compose(&query).unwrap_err(),
        "entitlement must be an object"
    );
}

#[test]
fn a_signal_the_contract_rejects_refuses_the_composition() {
    // A payload this side cannot decode is not composed over a guessed-at
    // signal: the request is refused and the caller fails closed.
    let reply = resident(envelope(
        HOOK_ARTIFACT_COMPOSE_REQUEST_SCHEMA,
        json!({
            "kind": "signal_composition",
            "base_action": "allow",
            "signals": [{"signal_id": "risk:x", "category": "not-a-category"}],
        }),
    ))
    .unwrap();
    assert_eq!(reply["status"], "error");
    assert_eq!(
        reply["code"],
        "native_hook_artifact_compose_validation_refused"
    );
    assert!(reply["payload"]["message"]
        .as_str()
        .unwrap()
        .starts_with("signals[0] is not a risk signal:"));
}

#[test]
fn signal_composition_requires_both_fields() {
    let missing = json!({"kind": "signal_composition", "base_action": "allow"});
    assert!(resident(envelope(HOOK_ARTIFACT_COMPOSE_REQUEST_SCHEMA, missing)).is_err());

    let surprise = json!({
        "kind": "signal_composition", "base_action": "allow", "signals": [], "surprise": true,
    });
    assert!(resident(envelope(HOOK_ARTIFACT_COMPOSE_REQUEST_SCHEMA, surprise)).is_err());
}
