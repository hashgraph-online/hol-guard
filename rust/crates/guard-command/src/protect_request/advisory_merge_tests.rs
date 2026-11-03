use serde_json::{json, Map, Value};

use super::*;

fn object(value: Value) -> Map<String, Value> {
    match value {
        Value::Object(map) => map,
        other => panic!("expected an object, got {other}"),
    }
}

fn allowed_payload() -> Map<String, Value> {
    object(json!({
        "request": {"executor": "npm", "install_kind": "install"},
        "verdict": {
            "action": "allow",
            "reason": "Initial package authority allowed execution.",
            "risk_signals": [],
            "matched_advisories": [],
            "blocking": false,
        },
        "matched_advisories": [],
        "executed": false,
        "dry_run": false,
        "supply_chain_evaluation": {
            "decision": "allow",
            "policy_action": "allow",
            "risk_summary": "Initial package authority allowed execution.",
            "user_copy": {
                "title": "Package allowed",
                "summary": "Initial package authority allowed execution.",
                "next_step": "Continue.",
                "harness_message": "Package allowed.",
                "extra": "kept",
            },
        },
        "receipt": {
            "receipt_id": "cached-action-change-receipt",
            "artifact_id": "guard-cli:project:package-request:npm-change",
            "artifact_name": "npm install badpkg@1.0.0",
            "policy_decision": "allow",
            "action_envelope_json": {
                "package_manager": "npm",
                "policy_action": "allow",
            },
        },
    }))
}

fn merge(
    payload: &Map<String, Value>,
    action: &str,
    signals: &[Value],
    advisories: &[Value],
) -> Option<AdvisoryMerge> {
    let cached = CachedAdvisoryVerdict {
        action,
        reason: "Cached advisory blocks execution.",
        risk_signals: signals,
        matched_advisories: advisories,
    };
    merge_cached_advisory(payload, &cached, false, 0).unwrap()
}

#[test]
fn cached_block_overrides_an_allowed_package_and_records_the_change() {
    let signals = [json!("Cached advisory blocks execution.")];
    let advisories = [json!({"id": "adv-action-change", "action": "block"})];
    let merged = merge(&allowed_payload(), "block", &signals, &advisories).unwrap();

    assert_eq!(merged.exit_code, 2);
    let payload = Value::Object(merged.payload);
    assert_eq!(payload["verdict"]["action"], "block");
    assert_eq!(
        payload["verdict"]["reason"],
        "Cached advisory blocks execution."
    );
    assert_eq!(payload["verdict"]["blocking"], true);
    assert_eq!(payload["verdict"]["matched_advisories"], json!(advisories));
    assert_eq!(payload["matched_advisories"], json!(advisories));
    assert_eq!(payload["executed"], false);
    assert_eq!(payload["dry_run"], true);
    assert_eq!(payload["receipt"]["policy_decision"], "block");
    assert_eq!(
        payload["receipt"]["action_envelope_json"],
        json!({"package_manager": "npm", "policy_action": "block"})
    );
    let evaluation = &payload["supply_chain_evaluation"];
    assert_eq!(evaluation["decision"], "block");
    assert_eq!(evaluation["policy_action"], "block");
    assert_eq!(
        evaluation["risk_summary"],
        "Cached advisory blocks execution."
    );
    let title = evaluation["user_copy"]["title"].as_str().unwrap();
    assert!(title.to_lowercase().contains("blocked"), "{title}");
    assert_eq!(evaluation["user_copy"]["extra"], "kept");
    assert_eq!(
        merged.receipt_policy_update,
        Some((
            "cached-action-change-receipt".to_owned(),
            "block".to_owned()
        ))
    );
    let (name, fields) = merged.event.unwrap();
    assert_eq!(name, "install_time_block");
    let keys: Vec<&str> = fields.iter().map(|(key, _)| key.as_str()).collect();
    assert_eq!(
        keys,
        [
            "artifact_id",
            "artifact_name",
            "executor",
            "install_kind",
            "action",
            "risk_signals",
            "cached_advisory_override",
        ]
    );
    assert_eq!(fields[2].1, "npm");
    assert_eq!(fields[5].1, json!(signals));
    assert_eq!(fields[6].1, true);
}

#[test]
fn cached_review_tightens_allow_but_not_block() {
    let merged = merge(&allowed_payload(), "review", &[], &[]).unwrap();
    let payload = Value::Object(merged.payload);
    assert_eq!(payload["verdict"]["action"], "review");
    assert_eq!(payload["supply_chain_evaluation"]["decision"], "ask");
    assert_eq!(merged.exit_code, 2);
    assert_eq!(merged.event.unwrap().0, "install_time_review");

    let mut blocked = allowed_payload();
    blocked["verdict"]["action"] = json!("block");
    assert!(merge(&blocked, "review", &[], &[]).is_none());
}

#[test]
fn new_advisories_alone_update_the_payload_without_writes() {
    let mut blocked = allowed_payload();
    blocked["verdict"]["action"] = json!("block");
    blocked["verdict"]["reason"] = json!("Package policy blocked it.");
    let advisories = [json!({"id": "adv-new"})];
    let merged = merge(&blocked, "review", &[], &advisories).unwrap();
    let payload = Value::Object(merged.payload);
    assert_eq!(payload["verdict"]["action"], "block");
    assert_eq!(payload["verdict"]["reason"], "Package policy blocked it.");
    assert_eq!(payload["matched_advisories"], json!(advisories));
    assert_eq!(merged.receipt_policy_update, None);
    assert_eq!(merged.event, None);

    // An advisory already present is not a change.
    blocked["verdict"]["matched_advisories"] = json!(advisories);
    assert!(merge(&blocked, "review", &[], &advisories).is_none());
}

#[test]
fn saved_approval_executed_and_allow_results_are_left_unchanged() {
    let mut saved = allowed_payload();
    saved["supply_chain_evaluation"]["reasons"] = json!([{"code": "saved_package_approval"}]);
    assert!(merge(&saved, "block", &[], &[]).is_none());

    let mut executed = allowed_payload();
    executed["executed"] = json!(true);
    assert!(merge(&executed, "block", &[], &[]).is_none());

    let mut missing = allowed_payload();
    missing.remove("executed");
    assert!(merge(&missing, "block", &[], &[]).is_none());

    assert!(merge(&allowed_payload(), "allow", &[], &[json!({"id": "a"})]).is_none());
}

#[test]
fn receipt_without_an_id_skips_the_store_update_but_keeps_the_event() {
    let mut payload = allowed_payload();
    payload["receipt"]["receipt_id"] = json!("");
    payload.remove("request");
    let merged = merge(&payload, "block", &[], &[]).unwrap();
    assert_eq!(merged.receipt_policy_update, None);
    let (_, fields) = merged.event.unwrap();
    assert_eq!(fields[2].1, Value::Null);
    assert_eq!(fields[3].1, Value::Null);
}

#[test]
fn missing_evaluation_and_receipt_are_not_created() {
    let mut payload = allowed_payload();
    payload.remove("supply_chain_evaluation");
    payload.remove("receipt");
    let merged = merge(&payload, "block", &[], &[]).unwrap();
    assert!(!merged.payload.contains_key("supply_chain_evaluation"));
    assert!(!merged.payload.contains_key("receipt"));
    assert_eq!(merged.event, None);
    assert_eq!(merged.exit_code, 2);
}

#[test]
fn verdict_lists_must_be_lists_or_empty() {
    let mut payload = allowed_payload();
    payload["verdict"]["risk_signals"] = Value::Null;
    assert!(merge(&payload, "block", &[], &[]).is_some());

    payload["verdict"]["risk_signals"] = json!("not a list");
    let cached = CachedAdvisoryVerdict {
        action: "block",
        reason: "r",
        risk_signals: &[],
        matched_advisories: &[],
    };
    assert_eq!(
        merge_cached_advisory(&payload, &cached, false, 0),
        Err(AdvisoryMergePayloadInvalid)
    );
}

#[test]
fn missing_verdict_or_non_string_fields_fall_back_like_python() {
    let mut payload = allowed_payload();
    payload.remove("verdict");
    assert!(merge(&payload, "block", &[], &[]).is_none());

    let mut payload = allowed_payload();
    payload["verdict"]["action"] = json!(7);
    payload["verdict"]["reason"] = Value::Null;
    let merged = merge(&payload, "review", &[], &[]).unwrap();
    let payload = Value::Object(merged.payload);
    assert_eq!(payload["verdict"]["action"], "review");
    assert_eq!(
        payload["verdict"]["reason"],
        "Cached advisory blocks execution."
    );
}
