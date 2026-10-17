use serde_json::{json, Value};

use super::*;

const DIGEST: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

fn evidence(policy_action: &str) -> Value {
    Value::Object(
        policy_only_pre_hook_evidence(
            "activity-1",
            "2026-10-17T20:00:00+00:00",
            "claude-code",
            policy_action,
            None,
            None,
            false,
            NOT_APPLICABLE,
        )
        .expect("evidence"),
    )
}

fn handle(kind: &str, harness: &str) -> CorrelationHandle {
    CorrelationHandle {
        kind: kind.to_owned(),
        harness: harness.to_owned(),
        key_id: "install-key".to_owned(),
        digest: DIGEST.to_owned(),
    }
}

#[test]
fn an_allowed_action_carries_the_whole_policy_only_wire_row() {
    assert_eq!(
        evidence("allow"),
        json!({
            "activity": {
                "activity_id": "activity-1",
                "occurred_at": "2026-10-17T20:00:00+00:00",
                "harness": "claude-code",
                "hook_phase": "pre",
                "execution_status": "allowed_unconfirmed",
                "proof_level": "pre_hook",
                "policy_action": "allow",
                "decision_reason_code": "policy",
                "controlling_rule_id": null,
                "parse_confidence": null,
                "uncertainty_class": null,
                "match_count": 0,
                "prompted": 0,
                "approval_reuse_status": "not-applicable",
                "receipt_link_status": "not_applicable",
                "receipt_id": null,
                "evaluation_latency_bucket": "not_measured",
                "persistence_latency_bucket": "not_measured",
                "schema_version": "1.0.0",
                "request_correlation": null,
                "session_correlation": null,
            },
            "matches": [],
        })
    );
}

#[test]
fn a_review_or_stronger_action_prevented_the_command() {
    for action in ["review", "require-reapproval", "sandbox-required", "block"] {
        assert_eq!(
            evidence(action)["activity"]["execution_status"],
            json!("prevented"),
            "{action}"
        );
    }
    for action in ["allow", "warn"] {
        assert_eq!(
            evidence(action)["activity"]["execution_status"],
            json!("allowed_unconfirmed"),
            "{action}"
        );
    }
}

#[test]
fn a_receipt_links_the_activity_to_it() {
    let row = policy_only_pre_hook_evidence(
        "activity-1",
        "2026-10-17T20:00:00+00:00",
        "codex",
        "block",
        None,
        Some("receipt:9"),
        true,
        "rejected",
    )
    .expect("evidence");
    let activity = &row["activity"];
    assert_eq!(activity["receipt_link_status"], json!("linked"));
    assert_eq!(activity["receipt_id"], json!("receipt:9"));
    assert_eq!(activity["prompted"], json!(1));
    assert_eq!(activity["approval_reuse_status"], json!("rejected"));
}

#[test]
fn a_proven_request_handle_becomes_its_wire_mapping() {
    let row = policy_only_pre_hook_evidence(
        "activity-1",
        "2026-10-17T20:00:00Z",
        "codex",
        "warn",
        Some(&handle("request", "codex")),
        None,
        false,
        NOT_APPLICABLE,
    )
    .expect("evidence");
    assert_eq!(
        row["activity"]["request_correlation"],
        json!({
            "kind": "request",
            "harness": "codex",
            "key_id": "install-key",
            "digest": DIGEST,
        })
    );
    assert_eq!(
        row["activity"]["occurred_at"],
        json!("2026-10-17T20:00:00+00:00")
    );
}

#[test]
fn a_session_handle_or_another_harness_is_not_this_requests_correlation() {
    for wrong in [handle("session", "codex"), handle("request", "cursor")] {
        let rejected = policy_only_pre_hook_evidence(
            "activity-1",
            "2026-10-17T20:00:00+00:00",
            "codex",
            "warn",
            Some(&wrong),
            None,
            false,
            NOT_APPLICABLE,
        );
        assert!(rejected.is_err(), "{wrong:?}");
    }
    let mut short = handle("request", "codex");
    short.digest = "abc".to_owned();
    assert!(policy_only_pre_hook_evidence(
        "activity-1",
        "2026-10-17T20:00:00+00:00",
        "codex",
        "warn",
        Some(&short),
        None,
        false,
        NOT_APPLICABLE,
    )
    .is_err());
}

#[test]
fn an_accepted_reuse_cannot_also_claim_a_prompt() {
    assert!(policy_only_pre_hook_evidence(
        "activity-1",
        "2026-10-17T20:00:00+00:00",
        "codex",
        "allow",
        None,
        None,
        true,
        "accepted",
    )
    .is_err());
    assert!(policy_only_pre_hook_evidence(
        "activity-1",
        "2026-10-17T20:00:00+00:00",
        "codex",
        "allow",
        None,
        None,
        false,
        "accepted",
    )
    .is_ok());
    assert!(policy_only_pre_hook_evidence(
        "activity-1",
        "2026-10-17T20:00:00+00:00",
        "codex",
        "allow",
        None,
        None,
        false,
        "reused",
    )
    .is_err());
}

#[test]
fn an_uncanonical_action_harness_id_or_timestamp_never_reaches_the_store() {
    let cases: [(&str, &str, &str, &str); 5] = [
        ("activity-1", "2026-10-17T20:00:00+00:00", "codex", "deny"),
        ("activity-1", "2026-10-17T20:00:00+00:00", "claude", "allow"),
        ("activity-1", "2026-10-17T20:00:00+02:00", "codex", "allow"),
        ("activity-1", "2026-10-17T20:00:00", "codex", "allow"),
        ("_activity", "2026-10-17T20:00:00+00:00", "codex", "allow"),
    ];
    for (activity_id, occurred_at, harness, policy_action) in cases {
        assert!(
            policy_only_pre_hook_evidence(
                activity_id,
                occurred_at,
                harness,
                policy_action,
                None,
                None,
                false,
                NOT_APPLICABLE,
            )
            .is_err(),
            "{activity_id} {occurred_at} {harness} {policy_action}"
        );
    }
}

#[test]
fn the_seam_renders_the_redacted_preview_of_the_checked_command() {
    let correlation = NativeCorrelation::new(PathBuf::from("/nonexistent-guard-home"));
    let payload = json!({"tool_name": "Bash", "tool_input": {"command": "echo hi # tail"}})
        .as_object()
        .expect("payload")
        .clone();
    assert_eq!(
        correlation
            .build_invocation_preview_from_payload(&payload)
            .expect("preview")
            .as_deref(),
        Some("echo hi")
    );
}
