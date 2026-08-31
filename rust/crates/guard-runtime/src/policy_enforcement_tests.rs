use super::*;
use guard_contracts::{
    PreToolActionV1, PreToolOperationV1, NATIVE_PROTOCOL_VERSION, PRE_TOOL_ACTION_V1_SCHEMA,
};
use guard_policy_snapshot::{
    EffectiveNativePolicyV3, ScopeContractV3, SnapshotIntegrityV3,
    POLICY_SNAPSHOT_INTEGRITY_ALGORITHM, POLICY_SNAPSHOT_SCHEMA,
};
use serde_json::{json, Map};
use std::collections::BTreeMap;

fn policy(default_action: &str) -> EffectiveNativePolicyV3 {
    EffectiveNativePolicyV3 {
        protection_posture: "protected".into(),
        security_level: "balanced".into(),
        default_action: default_action.into(),
        unknown_publisher_action: "review".into(),
        changed_hash_action: "require-reapproval".into(),
        new_network_domain_action: "allow".into(),
        subprocess_action: "allow".into(),
        risk_actions: BTreeMap::new(),
        harness_risk_actions: BTreeMap::new(),
        harness_actions: BTreeMap::new(),
        publisher_actions: BTreeMap::new(),
        artifact_actions: BTreeMap::new(),
        sandbox_analysis: "off".into(),
        receipt_redaction_level: "full".into(),
    }
}

fn snapshot(policy: EffectiveNativePolicyV3) -> PolicySnapshotV3 {
    PolicySnapshotV3 {
        schema: POLICY_SNAPSHOT_SCHEMA.into(),
        version: 3,
        generation: 1,
        policy_digest: "a".repeat(64),
        config_digest: "b".repeat(64),
        rule_digest: "c".repeat(64),
        runtime_identity: "d".repeat(64),
        protocol_version: 1,
        mode: "enforce".into(),
        scope_contract: ScopeContractV3 {
            schema: "guard-native-scope.v1".into(),
            kind: "guard-home".into(),
            scope_digest: "e".repeat(64),
            workspace_binding: "request-source".into(),
        },
        effective_policy: policy,
        issued_at_ms: 1,
        expires_at_ms: 2,
        integrity: SnapshotIntegrityV3 {
            algorithm: POLICY_SNAPSHOT_INTEGRITY_ALGORITHM.into(),
            key_id: "f".repeat(64),
            mac: "0".repeat(64),
        },
    }
}

fn generic_result(minimum_action: &str) -> PreToolResultV1 {
    PreToolResultV1 {
        schema: "guard-pre-tool-result.v1".into(),
        version: 1,
        authority: "rust".into(),
        action: PreToolActionV1 {
            schema: PRE_TOOL_ACTION_V1_SCHEMA.into(),
            version: 1,
            harness: "claude-code".into(),
            event: "PreToolUse".into(),
            action_type: PreToolActionTypeV1::Command,
            operation: PreToolOperationV1::Execute,
            bounded: true,
            sensitive_target: false,
        },
        decision: if matches!(minimum_action, "allow" | "warn") {
            "allow"
        } else {
            "deny"
        }
        .into(),
        policy_action: minimum_action.into(),
        minimum_action: minimum_action.into(),
        reason_code: "native_test".into(),
        reason: "native test".into(),
        explicitly_benign: minimum_action == "allow",
    }
}

#[test]
fn warning_policy_preserves_allow_with_warning() {
    let result = apply_pre_tool_policy(
        &snapshot(policy("warn")),
        &Value::Object(Map::new()),
        generic_result("allow"),
    )
    .unwrap();
    assert_eq!(result.minimum_action, "warn");
    assert_eq!(result.policy_action, "warn");
    assert_eq!(result.decision, "allow");
    assert!(!result.explicitly_benign);
}

#[test]
fn observe_pre_policy_floor_is_non_blocking_but_intrinsic_block_is_hard() {
    let mut observed_snapshot = snapshot(policy("block"));
    observed_snapshot.mode = "observe".into();
    let policy_only = apply_pre_tool_policy(
        &observed_snapshot,
        &Value::Object(Map::new()),
        generic_result("allow"),
    )
    .unwrap();
    assert_eq!(policy_only.minimum_action, "warn");
    assert_eq!(policy_only.decision, "allow");

    let intrinsic = apply_pre_tool_policy(
        &observed_snapshot,
        &Value::Object(Map::new()),
        generic_result("block"),
    )
    .unwrap();
    assert_eq!(intrinsic.minimum_action, "block");
    assert_eq!(intrinsic.decision, "deny");
}

#[test]
fn observe_preserves_every_intrinsic_non_allow_pre_floor() {
    let mut observed_snapshot = snapshot(policy("block"));
    observed_snapshot.mode = "observe".into();
    for action in ["review", "require-reapproval", "sandbox-required", "block"] {
        let intrinsic = apply_pre_tool_policy(
            &observed_snapshot,
            &Value::Object(Map::new()),
            generic_result(action),
        )
        .unwrap();
        assert_eq!(intrinsic.minimum_action, action);
        assert_eq!(intrinsic.decision, "deny");
        assert_eq!(intrinsic.reason_code, "native_test");
    }

    let mut malformed = generic_result("block");
    malformed.action.action_type = PreToolActionTypeV1::Unknown;
    malformed.reason_code = "native_pre_tool_malformed_payload".into();
    let malformed =
        apply_pre_tool_policy(&observed_snapshot, &Value::Object(Map::new()), malformed).unwrap();
    assert_eq!(malformed.minimum_action, "block");
    assert_eq!(malformed.decision, "deny");
    assert_eq!(malformed.reason_code, "native_pre_tool_malformed_payload");
}

fn post_request(payload: Value) -> NativeHookRequestV1 {
    NativeHookRequestV1 {
        protocol_version: NATIVE_PROTOCOL_VERSION,
        request_id: Some("policy-test".into()),
        harness: "claude-code".into(),
        event_name: "PostToolUse".into(),
        payload,
        cwd: None,
        home_dir: "/home/test".into(),
        guard_home: "/home/test/.hol-guard".into(),
        source_ref_external_allowed: false,
        observe_mode: false,
        deadline_budget_ms: Some(750),
    }
}

#[test]
fn policy_allow_cannot_lower_intrinsic_review_or_block() {
    let snapshot = snapshot(policy("allow"));
    for action in ["review", "block"] {
        let result = apply_pre_tool_policy(
            &snapshot,
            &Value::Object(Map::new()),
            generic_result(action),
        )
        .unwrap();
        assert_eq!(result.minimum_action, action);
        assert_eq!(result.decision, "deny");
    }
}

#[test]
fn policy_block_raises_intrinsic_allow() {
    let snapshot = snapshot(policy("block"));
    let result = apply_pre_tool_policy(
        &snapshot,
        &Value::Object(Map::new()),
        generic_result("allow"),
    )
    .unwrap();
    assert_eq!(result.minimum_action, "block");
    assert_eq!(result.reason_code, "native_policy_block");
}

#[test]
fn conflicting_harness_aliases_fail_closed() {
    let mut effective = policy("allow");
    effective
        .harness_actions
        .insert("claude".into(), "review".into());
    effective
        .harness_actions
        .insert("claude-code".into(), "block".into());
    let result = apply_pre_tool_policy(
        &snapshot(effective),
        &Value::Object(Map::new()),
        generic_result("allow"),
    );
    assert_eq!(
        result.unwrap_err(),
        "native_policy_harness_selector_conflict"
    );
}

#[test]
fn conflicting_harness_risk_aliases_fail_closed() {
    let mut effective = policy("allow");
    effective.harness_risk_actions.insert(
        "claude".into(),
        BTreeMap::from([(String::from("execution"), String::from("review"))]),
    );
    effective.harness_risk_actions.insert(
        "claude-code".into(),
        BTreeMap::from([(String::from("execution"), String::from("block"))]),
    );
    let result = apply_pre_tool_policy(
        &snapshot(effective),
        &Value::Object(Map::new()),
        generic_result("allow"),
    );
    assert_eq!(
        result.unwrap_err(),
        "native_policy_harness_selector_conflict"
    );
}

#[test]
fn post_intrinsic_block_cannot_be_lowered_by_allow_policy() {
    let request = post_request(json!({
        "tool_name": "read_file",
        "tool_response": "safe-looking output"
    }));
    let response =
        HookReviewResponseV1::deny("source_secret_match", "native source content was blocked");
    let result = apply_post_tool_policy(
        &snapshot(policy("allow")),
        &request,
        GuardHookPayloadKindV2::Inline,
        response,
    )
    .unwrap();
    assert_eq!(result.decision, "deny");
    assert_eq!(result.policy_action.as_deref(), Some("block"));
    let encoded = serde_json::to_string(&result).unwrap();
    assert!(!encoded.contains("safe-looking"));
}

#[test]
fn post_warning_policy_preserves_allow_with_warning() {
    let request = post_request(json!({
        "tool_name": "read_file",
        "tool_response": "safe-looking output"
    }));
    let result = apply_post_tool_policy(
        &snapshot(policy("warn")),
        &request,
        GuardHookPayloadKindV2::Inline,
        HookReviewResponseV1::allow("output_scan_allow"),
    )
    .unwrap();
    assert_eq!(result.decision, "allow");
    assert_eq!(result.policy_action.as_deref(), Some("warn"));
    assert_eq!(result.notice, "warning");
}

#[test]
fn post_policy_fields_raise_without_python_semantic_input() {
    let mut effective = policy("allow");
    effective.unknown_publisher_action = "review".into();
    effective.changed_hash_action = "block".into();
    effective
        .publisher_actions
        .insert("trusted".into(), "allow".into());
    effective
        .artifact_actions
        .insert("pkg-a".into(), "block".into());
    let request = post_request(json!({
        "tool_name": "npm_install",
        "publisher": "trusted",
        "artifact_id": "pkg-a",
        "changed": true,
        "tool_response": "ok"
    }));
    let result = apply_post_tool_policy(
        &snapshot(effective),
        &request,
        GuardHookPayloadKindV2::Inline,
        HookReviewResponseV1::allow("output_scan_allow"),
    )
    .unwrap();
    assert_eq!(result.decision, "deny");
    assert_eq!(result.policy_action.as_deref(), Some("block"));
}

#[test]
fn unknown_post_action_is_review_even_when_default_allows() {
    let request = post_request(json!({
        "tool_name": "future_tool_v9",
        "tool_response": "ok"
    }));
    let result = apply_post_tool_policy(
        &snapshot(policy("allow")),
        &request,
        GuardHookPayloadKindV2::Inline,
        HookReviewResponseV1::allow("output_scan_allow"),
    )
    .unwrap();
    assert_eq!(result.decision, "deny");
    assert_eq!(result.policy_action.as_deref(), Some("review"));
    assert_eq!(result.reason_code, "native_policy_review_required");
}

#[test]
fn conflicting_request_selectors_fail_closed() {
    let request = post_request(json!({
        "tool_name": "read_file",
        "publisher": "one",
        "publisherId": "two",
        "tool_response": "ok"
    }));
    let result = apply_post_tool_policy(
        &snapshot(policy("allow")),
        &request,
        GuardHookPayloadKindV2::Inline,
        HookReviewResponseV1::allow("output_scan_allow"),
    );
    assert_eq!(result.unwrap_err(), "native_policy_selector_conflict");
}

#[test]
fn observe_preserves_intrinsic_block_but_does_not_enforce_policy_only_floor() {
    let request = post_request(json!({
        "tool_name": "read_file",
        "tool_response": "ok"
    }));
    let mut observed_snapshot = snapshot(policy("block"));
    observed_snapshot.mode = "observe".into();
    let policy_only = apply_post_tool_policy(
        &observed_snapshot,
        &request,
        GuardHookPayloadKindV2::Inline,
        HookReviewResponseV1::allow("output_scan_allow"),
    )
    .unwrap();
    assert_eq!(policy_only.decision, "allow");
    assert_eq!(policy_only.policy_action.as_deref(), Some("block"));

    let intrinsic_observed =
        HookReviewResponseV1::deny("source_secret_match", "blocked").observed(None);
    let intrinsic = apply_post_tool_policy(
        &observed_snapshot,
        &request,
        GuardHookPayloadKindV2::Inline,
        intrinsic_observed,
    )
    .unwrap();
    assert_eq!(intrinsic.decision, "deny");
    assert_eq!(intrinsic.policy_action.as_deref(), Some("block"));
    assert!(intrinsic.observe_mode);
}
