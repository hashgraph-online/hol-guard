//! The view op replayed against the cases the Python `from_cache_dict` and
//! `_normalize_package_user_copy` grammar used to answer: every default, the
//! unrecognised policy action, the terminal and review spellings of the user
//! copy, and the sha256 shape an external archive hash has to have.

use guard_contracts::{
    PackageEvaluationViewRequestV1, PACKAGE_AUTHORITY_REQUEST_SCHEMA,
    PACKAGE_AUTHORITY_RESULT_SCHEMA,
};
use serde_json::{json, Value};

use super::*;

const INBOX: &str = "https://cloud.example.test/guard/inbox";

fn request(payload: Value) -> PackageEvaluationViewRequestV1 {
    PackageEvaluationViewRequestV1 {
        schema: PACKAGE_AUTHORITY_REQUEST_SCHEMA.to_owned(),
        request_id: "view-1".to_owned(),
        payload,
        package_intent_hash: "intent-hash".to_owned(),
        policy_version: "2026.10.1".to_owned(),
        bundle_version: Some("bundle-7".to_owned()),
        workspace_fingerprint: Some("fingerprint-9".to_owned()),
    }
}

fn view(payload: Value) -> Value {
    let reply: Value =
        serde_json::from_slice(&evaluate_package_evaluation_view(&request(payload)).unwrap())
            .unwrap();
    assert_eq!(reply["schema"], PACKAGE_AUTHORITY_RESULT_SCHEMA);
    assert_eq!(reply["request_id"], "view-1");
    assert_eq!(reply["status"], "ok");
    assert_eq!(reply["code"], "ok");
    reply["payload"].clone()
}

#[test]
fn an_empty_payload_reads_as_the_monitoring_defaults() {
    let payload = view(json!({}));
    assert_eq!(payload["decision"], "monitor");
    assert_eq!(payload["enforcement"], "offline_cached");
    assert_eq!(payload["entitlement_state"], "premium");
    assert_eq!(payload["cache_status"], "hit");
    assert_eq!(
        payload["risk_summary"],
        "HOL Guard recorded this package request."
    );
    assert_eq!(payload["user_copy"]["title"], "Monitoring this package");
    assert_eq!(
        payload["user_copy"]["summary"],
        "HOL Guard recorded this package request."
    );
    assert_eq!(payload["user_copy"]["next_step"], Value::Null);
    assert_eq!(payload["refresh_required"], false);
    assert_eq!(payload["record_monitor_evidence"], false);
    assert_eq!(payload["evidence_ids"], json!([]));
}

#[test]
fn the_identity_the_row_does_not_carry_comes_from_the_request() {
    let payload = view(json!({"decision": "allow", "policy_action": "allow"}));
    assert_eq!(payload["package_intent_hash"], "intent-hash");
    assert_eq!(payload["policy_version"], "2026.10.1");
    assert_eq!(payload["bundle_version"], "bundle-7");
    assert_eq!(payload["workspace_fingerprint"], "fingerprint-9");
}

#[test]
fn an_unknown_policy_action_becomes_a_reapproval_with_its_own_reason() {
    let payload = view(json!({
        "policy_action": "sure-go-ahead",
        "reasons": [{"code": "existing_reason"}],
    }));
    assert_eq!(payload["policy_action"], "require-reapproval");
    let reasons = payload["reasons"].as_array().unwrap();
    assert_eq!(reasons.len(), 2);
    assert_eq!(reasons[0]["code"], "existing_reason");
    assert_eq!(reasons[1]["code"], "guard_action_unknown");
    assert_eq!(reasons[1]["original_action"], "sure-go-ahead");
    assert_eq!(reasons[1]["normalized_action"], "require-reapproval");
    assert_eq!(
        reasons[1]["message"],
        "Cached package policy action was missing or unknown; Guard requires review."
    );
}

#[test]
fn a_missing_policy_action_is_unknown_too() {
    let payload = view(json!({"decision": "monitor"}));
    assert_eq!(payload["policy_action"], "require-reapproval");
    let reasons = payload["reasons"].as_array().unwrap();
    assert_eq!(reasons.len(), 1);
    assert_eq!(reasons[0]["code"], "guard_action_unknown");
    assert_eq!(reasons[0]["original_action"], Value::Null);
}

#[test]
fn a_recognised_action_leaves_the_reasons_alone() {
    let payload = view(json!({
        "policy_action": "allow",
        "reasons": [{"code": "only_reason"}, "not-a-reason"],
    }));
    let reasons = payload["reasons"].as_array().unwrap();
    assert_eq!(reasons.len(), 1);
    assert_eq!(reasons[0]["code"], "only_reason");
}

#[test]
fn a_cloud_inbox_has_no_place_on_the_local_route() {
    let payload = view(json!({
        "policy_action": "allow",
        "user_copy": {
            "title": "Package allowed",
            "summary": "Allowed.",
            "dashboard_url": INBOX,
            "harness_message": format!("Allowed. Open {INBOX} to see it."),
        },
    }));
    assert_eq!(payload["user_copy"]["dashboard_url"], Value::Null);
    assert_eq!(
        payload["user_copy"]["harness_message"],
        "Allowed. Open to see it."
    );
}

#[test]
fn a_terminal_action_keeps_no_approval_route_in_the_copy() {
    let payload = view(json!({
        "policy_action": "block",
        "user_copy": {
            "title": "Blocked",
            "summary": "Blocked.",
            "dashboard_url": "https://cloud.example.test/requests/42",
            "harness_message": "Blocked. Approve this request in HOL Guard, then retry. \
                 https://cloud.example.test/requests/42 \
                 Review this request in HOL Guard, then retry.",
        },
    }));
    assert_eq!(payload["user_copy"]["dashboard_url"], Value::Null);
    let message = payload["user_copy"]["harness_message"].as_str().unwrap();
    assert_eq!(message, "Blocked.");
}

#[test]
fn a_terminal_action_drops_the_legacy_approval_instruction() {
    let payload = view(json!({
        "policy_action": "block",
        "user_copy": {
            "title": "Blocked",
            "summary": "Blocked.",
            "harness_message": "Blocked by policy. Open HOL Guard to approve or keep this blocked: \
                 http://127.0.0.1:4781/requests/req-7 \
                 After you choose, retry the same npm install action.",
        },
    }));
    let message = payload["user_copy"]["harness_message"].as_str().unwrap();
    assert_eq!(message, "Blocked by policy.");
}

#[test]
fn a_review_gains_the_local_instruction_once() {
    let payload = view(json!({
        "policy_action": "review",
        "user_copy": {
            "title": "Review",
            "summary": "Review.",
            "harness_message": "This package needs a look.",
        },
    }));
    assert_eq!(
        payload["user_copy"]["harness_message"],
        "This package needs a look. Review this request in HOL Guard, then retry."
    );

    let already = view(json!({
        "policy_action": "require-reapproval",
        "user_copy": {
            "title": "Review",
            "summary": "Review.",
            "harness_message": "Review this request in HOL Guard, then retry.",
        },
    }));
    assert_eq!(
        already["user_copy"]["harness_message"],
        "Review this request in HOL Guard, then retry."
    );
}

#[test]
fn the_harness_message_falls_back_to_the_risk_summary() {
    let payload = view(json!({
        "policy_action": "allow",
        "risk_summary": "Two new transitive dependencies.",
        "user_copy": {"title": "Allowed", "summary": "Allowed."},
    }));
    assert_eq!(
        payload["user_copy"]["harness_message"],
        "Two new transitive dependencies."
    );
}

#[test]
fn a_review_evidence_tail_is_dropped() {
    let payload = view(json!({
        "policy_action": "allow",
        "user_copy": {
            "title": "Allowed",
            "summary": "Allowed.",
            "harness_message": "Allowed. Review evidence:",
        },
    }));
    assert_eq!(payload["user_copy"]["harness_message"], "Allowed.");
}

#[test]
fn only_a_lowercase_sha256_survives_as_an_archive_hash() {
    let good = "a".repeat(64);
    let upper = "A".repeat(64);
    let short = "b".repeat(63);
    let payload = view(json!({
        "policy_action": "allow",
        "external_archive_source_hashes": [good, upper, short, 7, null],
    }));
    assert_eq!(
        payload["external_archive_source_hashes"],
        json!(["a".repeat(64)])
    );
}

#[test]
fn a_package_row_carries_its_ecosystem_support() {
    let payload = view(json!({
        "policy_action": "allow",
        "packages": [{"name": "left-pad", "ecosystem": "npm"}, "not-a-package"],
    }));
    let packages = payload["packages"].as_array().unwrap();
    assert_eq!(packages.len(), 1);
    assert_eq!(packages[0]["name"], "left-pad");
    assert!(packages[0].get("supportLevel").is_some());
    assert!(packages[0].get("supportLabel").is_some());
}

#[test]
fn a_payload_that_names_no_evaluation_has_no_view() {
    for payload in [json!(null), json!([]), json!("monitor"), json!(3)] {
        let error = evaluate_package_evaluation_view(&request(payload)).unwrap_err();
        assert_eq!(error, "native_package_evaluation_view_invalid");
    }
}

#[test]
fn a_foreign_schema_or_an_unnamed_request_is_refused() {
    let mut wrong_schema = request(json!({}));
    wrong_schema.schema = "guard-other-request.v1".to_owned();
    assert_eq!(
        evaluate_package_evaluation_view(&wrong_schema).unwrap_err(),
        "native_package_evaluation_view_schema_mismatch"
    );

    let mut unnamed = request(json!({}));
    unnamed.request_id = String::new();
    assert_eq!(
        evaluate_package_evaluation_view(&unnamed).unwrap_err(),
        "native_package_evaluation_view_invalid"
    );
}

#[test]
fn the_reply_binds_the_request_it_answered() {
    let reply: Value =
        serde_json::from_slice(&evaluate_package_evaluation_view(&request(json!({}))).unwrap())
            .unwrap();
    let digest = reply["request_sha256"].as_str().unwrap();
    assert!(digest.starts_with("sha256:"), "{digest}");
    let other: Value = serde_json::from_slice(
        &evaluate_package_evaluation_view(&request(json!({"decision": "allow"}))).unwrap(),
    )
    .unwrap();
    assert_ne!(other["request_sha256"], reply["request_sha256"]);
}

#[test]
fn absent_identity_still_occupies_the_digested_request() {
    // The caller canonicalizes the request it sent to compare the reply's
    // digest. A field this side drops when it is null would hash different
    // bytes than the caller hashed, and every request without a bundle or a
    // workspace fingerprint would read as answered by some other request.
    let mut bare = request(json!({}));
    bare.bundle_version = None;
    bare.workspace_fingerprint = None;
    let material = serde_json::to_value(&bare).unwrap();
    assert_eq!(material["bundle_version"], Value::Null);
    assert_eq!(material["workspace_fingerprint"], Value::Null);

    let reply: Value =
        serde_json::from_slice(&evaluate_package_evaluation_view(&bare).unwrap()).unwrap();
    assert_eq!(reply["payload"]["bundle_version"], Value::Null);
    assert_eq!(reply["payload"]["workspace_fingerprint"], Value::Null);
}

#[test]
fn a_request_larger_than_a_reply_is_refused_before_any_view_is_built() {
    let oversized = "x".repeat(guard_contracts::MAX_NATIVE_RESPONSE_BYTES);
    let refused = evaluate_package_evaluation_view(&request(json!({ "risk_summary": oversized })));
    assert!(refused.is_err());
}
