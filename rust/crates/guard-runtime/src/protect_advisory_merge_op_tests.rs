use guard_contracts::ProtectCachedVerdictV1;
use serde_json::json;

use super::*;

fn request(payload: Value, action: &str) -> ProtectAdvisoryMergeRequestV1 {
    ProtectAdvisoryMergeRequestV1 {
        schema: PROTECT_ADVISORY_MERGE_REQUEST_SCHEMA.to_owned(),
        request_id: "merge-1".to_owned(),
        payload,
        cached: ProtectCachedVerdictV1 {
            action: action.to_owned(),
            reason: "Cached advisory blocks execution.".to_owned(),
            risk_signals: vec![json!("Cached advisory blocks execution.")],
            matched_advisories: vec![json!({"id": "adv-1", "action": "block"})],
        },
        requested_dry_run: false,
        exit_code: 0,
    }
}

fn payload() -> Value {
    json!({
        "request": {"executor": "npm", "install_kind": "install"},
        "verdict": {"action": "allow", "reason": "ok", "risk_signals": [], "matched_advisories": []},
        "executed": false,
        "receipt": {"receipt_id": "r-1", "artifact_id": "a", "artifact_name": "n"},
    })
}

fn decode(request: &ProtectAdvisoryMergeRequestV1) -> ProtectAdvisoryMergeResultV1 {
    serde_json::from_slice(&evaluate_protect_advisory_merge_op(request).unwrap()).unwrap()
}

#[test]
fn block_returns_the_merged_payload_and_the_writes_bound_to_the_request() {
    let request = request(payload(), "block");
    let result = decode(&request);
    assert_eq!(result.schema, PROTECT_ADVISORY_MERGE_RESULT_SCHEMA);
    assert_eq!(result.request_id, "merge-1");
    assert_eq!(
        result.request_sha256,
        request_digest_with_limit(&request, PROTECT_ADVISORY_MERGE_MAX_REQUEST_BYTES).unwrap()
    );
    assert_eq!((result.status.as_str(), result.code.as_str()), ("ok", "ok"));
    let merged = result.merged.unwrap();
    assert_eq!(merged.exit_code, 2);
    assert_eq!(merged.payload["verdict"]["action"], "block");
    assert_eq!(
        merged.receipt_policy_update,
        Some(ProtectReceiptPolicyUpdateV1 {
            receipt_id: "r-1".to_owned(),
            action: "block".to_owned(),
        })
    );
    let event = merged.event.unwrap();
    assert_eq!(event.name, "install_time_block");
    assert_eq!(event.fields.len(), 7);
}

#[test]
fn unchanged_result_omits_the_merged_body() {
    let mut executed = payload();
    executed["executed"] = json!(true);
    let result = decode(&request(executed, "block"));
    assert_eq!(result.status, "ok");
    assert_eq!(result.merged, None);
    let encoded = evaluate_protect_advisory_merge_op(&request(payload(), "allow")).unwrap();
    let value: Value = serde_json::from_slice(&encoded).unwrap();
    assert!(value.get("merged").is_none());
}

#[test]
fn invalid_requests_fail_with_typed_codes() {
    let mut wrong_schema = request(payload(), "block");
    wrong_schema.schema = "other".to_owned();
    assert_eq!(
        decode(&wrong_schema).code,
        "native_protect_advisory_merge_schema_mismatch"
    );
    let result = decode(&request(json!([]), "block"));
    assert_eq!(
        (result.status.as_str(), result.code.as_str()),
        ("error", "native_protect_advisory_merge_payload_invalid")
    );
    assert_eq!(
        decode(&request(payload(), "warn")).code,
        "native_protect_advisory_merge_cached_invalid"
    );
    let mut bad_list = payload();
    bad_list["verdict"]["matched_advisories"] = json!("x");
    assert_eq!(
        decode(&request(bad_list, "block")).code,
        "native_protect_advisory_merge_payload_invalid"
    );
}

#[test]
fn oversized_request_is_refused_before_merging() {
    let mut big = payload();
    big["padding"] = json!("x".repeat(PROTECT_ADVISORY_MERGE_MAX_REQUEST_BYTES));
    assert_eq!(
        evaluate_protect_advisory_merge_op(&request(big, "block")).unwrap_err(),
        TOO_LARGE
    );
}

#[test]
fn the_resident_advertises_the_merge_feature() {
    assert!(crate::resident_op_features::RESIDENT_OP_FEATURES
        .contains(&guard_contracts::PROTECT_ADVISORY_MERGE_FEATURE));
}
