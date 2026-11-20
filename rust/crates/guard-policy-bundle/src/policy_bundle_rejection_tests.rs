//! The rejection record both sync routes store when a bundle is not applied.

use serde_json::{json, Value};

use crate::policy_bundle_rejection::{message, payload};

/// Each reason with the exact sentence the Python sync route stored for it.
const SENTENCES: &[(&str, &str)] = &[
        ("canonical_compile_unsupported_policy_match", "The policy bundle was not applied because one of its rules cannot be enforced on this device. Guard enforces match on artifacts, exact commands, harnesses, publishers, tools and workspaces; other match fields, such as packages, domains or paths, are not enforced on this device. Tools cannot be combined with artifacts or publishers, and an exact command cannot be combined with artifacts, tools or publishers. Change the rule in Guard Cloud and publish again; this device keeps the policy it already had."),
        ("canonical_compile_invalid_policy_spec", "The policy bundle was not applied because its policy cannot be enforced on this device. Change the policy in Guard Cloud and publish again; this device keeps the policy it already had."),
        ("canonical_compile_not_a_code", "The policy bundle was not applied because one of its rules cannot be enforced on this device. Change the rule in Guard Cloud and publish again; this device keeps the policy it already had."),
        ("inactive_rollout_state", "The authenticated policy bundle is not active for local enforcement. Approve or publish the rollout in Guard Cloud, then sync again."),
        ("native_policy_bundle_unavailable", "The policy bundle was not applied because the Guard native runtime could not be reached. Check that Guard is healthy, then sync again."),
        ("untrusted_signing_key", "The policy bundle was not applied because its signing authority could not be verified. Sync again after the workspace policy signing key is provisioned or rotated."),
        ("bundle_signature_invalid", "The policy bundle was not applied because its signing authority could not be verified. Sync again after the workspace policy signing key is provisioned or rotated."),
        ("payload_hash_mismatch", "The policy bundle was not applied because its integrity checks failed. Sync again to fetch a complete policy bundle; if the error persists, contact your workspace administrator."),
        ("missing_required_field", "The policy bundle was not applied because its schema or required fields are invalid. Sync again to fetch a complete policy bundle; if the error persists, contact your workspace administrator."),
        ("wrong_workspace", "The policy bundle was not applied because it does not match the connected workspace. Reconnect Guard to the intended workspace. Sync again after the workspace connection is confirmed."),
        ("bundle_expired", "The policy bundle was not applied because its validity period is not current. Check the system clock. Sync again to fetch the current workspace policy."),
        ("bundle_version_downgrade", "The policy bundle was not applied because it is older than, or conflicts with, the policy this device already accepted. This device keeps the policy it already had. Publish the policy again in Guard Cloud so it gets a newer version, then sync again. If a newer publish is also rejected, the policy record on this device may be damaged; contact your workspace administrator."),
        ("unsupported_daemon_version", "The policy bundle was not applied because its contract or daemon version is incompatible. Update Guard to a supported version if required. Sync again to fetch the current workspace policy."),
];

#[test]
fn every_reason_keeps_the_sentence_it_had() {
    for (reason, sentence) in SENTENCES {
        assert_eq!(message(reason).as_deref(), Some(*sentence), "{reason}");
    }
    assert_eq!(message("something_else"), None);
    assert_eq!(message(""), None);
}

#[test]
fn a_missing_reason_is_an_invalid_bundle() {
    for reason in [None, Some("")] {
        let record = payload(reason, None);
        assert_eq!(record["reason"], json!("invalid_policy_bundle"));
        assert!(record["message"]
            .as_str()
            .is_some_and(|text| text.contains("schema")));
        assert_eq!(record.get("ruleId"), None);
    }
}

#[test]
fn a_rule_that_does_not_compile_is_named_and_truncated() {
    let long = "r".repeat(200);
    let record = payload(
        Some("canonical_compile_unsupported_policy_effect"),
        Some(&long),
    );
    assert_eq!(record["ruleId"], json!("r".repeat(128)));
    let unicode = "\u{e9}".repeat(130);
    let record = payload(
        Some("canonical_compile_unsupported_policy_effect"),
        Some(&unicode),
    );
    assert_eq!(
        record["ruleId"].as_str().map(|rule| rule.chars().count()),
        Some(128)
    );
    assert_eq!(
        payload(Some("wrong_workspace"), Some("")).get("ruleId"),
        None
    );
}

#[test]
fn a_document_compile_code_names_no_rule() {
    let record = payload(
        Some("canonical_compile_invalid_policy_rules"),
        Some("rule-1"),
    );
    assert_eq!(record.get("ruleId"), None);
    assert!(record["message"]
        .as_str()
        .is_some_and(|text| text.contains("its policy")));
}

#[test]
fn an_unknown_reason_is_stored_without_a_message() {
    assert_eq!(payload(Some("odd"), None), json!({"reason": "odd"}));
}

#[test]
fn the_op_answers_the_record_and_refuses_malformed_input() {
    let ask = |input: Value| {
        crate::policy_bundle_rejection::handle(
            "rejection_payload",
            input.as_object().expect("object"),
        )
        .expect("handled")
    };
    let answer = ask(json!({"reason": "bundle_expired", "rule_id": null})).ok();
    assert_eq!(
        answer.as_ref().map(|record| record["reason"].clone()),
        Some(json!("bundle_expired"))
    );
    assert!(ask(json!({"reason": 7})).is_err());
    assert!(ask(json!({"reason": "x", "extra": true})).is_err());
    assert!(crate::policy_bundle_rejection::handle("other", &serde_json::Map::new()).is_none());
}
