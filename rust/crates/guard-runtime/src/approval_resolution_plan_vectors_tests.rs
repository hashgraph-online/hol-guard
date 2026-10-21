//! Parity vectors recorded from the retired Python approval-resolution
//! derivation (`apply_approval_resolution` and its key helpers): every case
//! carries the narrowed wire request and the plan the Python produced.

use guard_contracts::{ApprovalResolutionPlanRequestV1, APPROVAL_RESOLUTION_PLAN_REQUEST_SCHEMA};
use serde_json::Value;

use super::evaluate;
use crate::store_vectors_support_tests::gunzip_json;

const VECTORS: &[u8] = include_bytes!("../tests/fixtures/approval_plan_vectors.json.gz");

#[test]
fn plans_match_the_retired_python() {
    let vectors = gunzip_json(VECTORS);
    let cases = vectors["cases"].as_array().expect("cases");
    assert!(cases.len() > 5000);
    for (index, case) in cases.iter().enumerate() {
        let mut wire = case["wire"].clone();
        wire["schema"] = Value::String(APPROVAL_RESOLUTION_PLAN_REQUEST_SCHEMA.to_owned());
        let request: ApprovalResolutionPlanRequestV1 =
            serde_json::from_value(wire).unwrap_or_else(|error| panic!("case {index}: {error}"));
        let expected = &case["expected"];
        let actual = evaluate(&request);
        let unbound_native_once = request.action == "allow"
            && request
                .approval
                .artifact_id
                .as_deref()
                .is_some_and(|id| id.contains(":native-pretool:"))
            && !request
                .approval
                .artifact_hash
                .as_deref()
                .is_some_and(|hash| {
                    crate::guard_store_native_review_consume::binding_pattern().is_match(hash)
                })
            && !(request.scope == "artifact"
                && request.persist_policy == Some(true)
                && [&request.approval.artifact_hash, &request.native_exact_token]
                    .iter()
                    .any(|token| {
                        token.as_ref().is_some_and(|token| {
                            crate::context_digest::parse_context_token(&Value::String(
                                token.clone(),
                            ))
                            .is_some()
                        })
                    }));
        if unbound_native_once {
            assert_eq!(
                actual,
                Err("execution_binding_unavailable".to_owned()),
                "case {index}"
            );
            continue;
        }
        if expected["status"] == "error" {
            assert!(
                actual.is_err(),
                "case {index}: expected error, got {actual:?}"
            );
            continue;
        }
        let mut want = expected.clone();
        want.as_object_mut().unwrap().remove("status");
        assert_eq!(
            actual.as_ref().ok(),
            Some(&want),
            "case {index}: {}",
            case["wire"]
        );
    }
}

#[test]
fn older_clients_cannot_save_unavailable_once_consent() {
    let vectors = gunzip_json(VECTORS);
    let case = vectors["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["expected"]["status"] != "error")
        .unwrap();
    let mut wire = case["wire"].clone();
    wire["schema"] = Value::String(APPROVAL_RESOLUTION_PLAN_REQUEST_SCHEMA.to_owned());
    let mut request: ApprovalResolutionPlanRequestV1 = serde_json::from_value(wire).unwrap();
    request.action = "allow".to_owned();
    request.scope = "artifact".to_owned();
    request.persist_policy = Some(false);
    request.approval.harness = Some("omp".to_owned());
    request.approval.artifact_id = Some("omp:native-pretool:bash".to_owned());
    request.approval.artifact_hash = Some("unbound-request".to_owned());
    request.native_exact_token = None;
    assert_eq!(
        evaluate(&request),
        Err("execution_binding_unavailable".to_owned())
    );
    request.approval.artifact_hash = Some(format!(
        "native-review-v4:{}:deny:review:review:test",
        "a".repeat(64)
    ));
    assert!(evaluate(&request).is_ok());
    request.action = "block".to_owned();
    request.approval.artifact_hash = Some("unbound-request".to_owned());
    assert!(evaluate(&request).is_ok());
}

#[test]
fn malformed_tokens_are_not_context_tokens() {
    use crate::context_digest::parse_context_token;
    let valid = |token: &str| parse_context_token(&Value::String(token.to_owned())).is_some();
    assert!(!valid("guard-approval-context:v1:"));
    assert!(!valid("guard-approval-context:v1:@@@"));
    assert!(!valid("guard-approval-context:v1:A"));
    assert!(!valid("not-a-token"));
}

#[test]
fn native_bash_legacy_descriptors_cannot_save_consent_but_can_record_refusal() {
    use guard_contracts::ContextDigestComponentsV1;
    use serde_json::json;
    let token = crate::context_digest::build_context_token(&ContextDigestComponentsV1 {
        identity: json!({}),
        content: json!({}),
        capabilities: json!({}),
        policy: json!({}),
        sandbox: json!({}),
        extension_control_digest: "a".repeat(64),
    })
    .unwrap();
    let vectors = gunzip_json(VECTORS);
    let mut wire = vectors["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["expected"]["status"] != "error")
        .unwrap()["wire"]
        .clone();
    wire["schema"] = json!(APPROVAL_RESOLUTION_PLAN_REQUEST_SCHEMA);
    let mut request: ApprovalResolutionPlanRequestV1 = serde_json::from_value(wire).unwrap();
    request.scope = "artifact".into();
    request.approval.harness = Some("omp".into());
    request.approval.artifact_type = Some("tool_call".into());
    request.approval.artifact_id = Some(guard_contracts::NATIVE_BASH_ARTIFACT_ID.into());
    request.approval.artifact_hash = Some(token.clone());
    request.native_exact_token = Some(token);
    request.action = "allow".into();
    for persist in [None, Some(false), Some(true)] {
        request.persist_policy = persist;
        assert_eq!(
            evaluate(&request),
            Err("execution_binding_unavailable".into())
        );
    }
    request.action = "block".into();
    for persist in [None, Some(false)] {
        request.persist_policy = persist;
        let plan = evaluate(&request).unwrap();
        assert_eq!(plan["persistence"], "none");
        assert!(
            plan["matching"].is_null(),
            "another user intent must remain pending"
        );
        assert!(plan["local_once"].is_null());
    }
    request.persist_policy = Some(true);
    assert_eq!(
        evaluate(&request),
        Err("execution_binding_unavailable".into())
    );
}
