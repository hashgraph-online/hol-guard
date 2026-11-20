//! Parity vectors recorded from the retired Python `request_scope_contract`:
//! every case carries the stored request and the contract, digest and
//! exact-action token the Python produced.

use guard_contracts::{ApprovalScopeItemV1, ApprovalScopeRequestV1, APPROVAL_SCOPE_REQUEST_SCHEMA};
use serde_json::{json, Value};

use super::evaluate;
use super::fixture_upgrade::upgrade_recorded_contract;
use crate::store_vectors_support_tests::gunzip_json;

const VECTORS: &[u8] = include_bytes!("../tests/fixtures/approval_scope_vectors.json.gz");

const FIELDS: [&str; 14] = [
    "artifact_id",
    "artifact_type",
    "artifact_hash",
    "artifact_name",
    "policy_action",
    "harness",
    "publisher",
    "source_scope",
    "config_path",
    "wrapper_chain",
    "action_identity",
    "raw_command_text",
    "action_envelope_json",
    "scanner_evidence",
];

fn item_for(request: &Value, workspace_target: &Value) -> ApprovalScopeItemV1 {
    let mut object = serde_json::Map::new();
    for field in FIELDS {
        if let Some(value) = request.get(field) {
            object.insert(field.to_owned(), value.clone());
        }
    }
    object.insert("workspace_target".to_owned(), workspace_target.clone());
    serde_json::from_value(Value::Object(object)).expect("item")
}

fn evaluate_one(item: ApprovalScopeItemV1) -> Value {
    let request = ApprovalScopeRequestV1 {
        schema: APPROVAL_SCOPE_REQUEST_SCHEMA.to_owned(),
        request_id: "vector".to_owned(),
        items: vec![item],
    };
    evaluate(&request).expect("evaluate")["items"][0].clone()
}

#[test]
fn contracts_match_the_retired_python() {
    let vectors = gunzip_json(VECTORS);
    let cases = vectors["cases"].as_array().expect("cases");
    assert!(cases.len() > 5000);
    let (mut global, mut workspace, mut persist, mut task) = (0, 0, 0, 0);
    let mut exact_default_beside_project = 0;
    for (index, case) in cases.iter().enumerate() {
        let expected = &case["expected"];
        let item = item_for(&case["request"], &expected["workspace_target"]);
        let actual = evaluate_one(item.clone());
        let mut contract = actual.clone();
        contract
            .as_object_mut()
            .unwrap()
            .remove("execution_approval");
        let token = contract
            .as_object_mut()
            .and_then(|object| object.remove("exact_context_token"))
            .expect("token");
        let mut want = expected["contract"].clone();
        upgrade_recorded_contract(&item, &mut want);
        assert_eq!(contract, want, "contract mismatch, case {index}");
        assert_eq!(
            token, expected["exact_context_token"],
            "token mismatch, case {index}"
        );
        let allow = &contract["allowed_scopes_by_action"]["allow"];
        global += usize::from(
            allow
                .as_array()
                .is_some_and(|a| a.contains(&json!("global"))),
        );
        workspace += usize::from(
            allow
                .as_array()
                .is_some_and(|a| a.contains(&json!("workspace"))),
        );
        persist += usize::from(contract["exact_action_persistence_eligible"] == json!(true));
        task += usize::from(contract["task_capability_eligibility"]["eligible"] == json!(true));
        if allow
            .as_array()
            .is_some_and(|a| a.contains(&json!("artifact")))
        {
            assert_eq!(
                contract["recommended_scope_by_action"]["allow"],
                json!("artifact"),
                "the exact action is the default allow scope, case {index}"
            );
            exact_default_beside_project += usize::from(
                allow
                    .as_array()
                    .is_some_and(|a| a.contains(&json!("workspace"))),
            );
        }
    }
    assert!(global > 20 && workspace > 200 && persist > 100 && task > 100);
    // A project scope is offered in these cases, yet the exact action stays preselected.
    assert!(exact_default_beside_project > 200);
}

#[test]
fn unbound_native_reviews_cannot_offer_execution_approval() {
    let mut item = ApprovalScopeItemV1 {
        artifact_id: Some(json!("omp:native-pretool:bash")),
        artifact_type: Some(json!("tool_call")),
        artifact_hash: Some(json!("unbound-request")),
        policy_action: Some(json!("review")),
        ..Default::default()
    };
    let unbound = evaluate_one(item.clone());
    assert_eq!(unbound["allowed_scopes_by_action"]["allow"], json!([]));
    assert_eq!(
        unbound["allowed_scopes_by_action"]["block"],
        json!(["artifact"])
    );
    assert_eq!(
        unbound["execution_approval"],
        json!({
            "schema": "guard.execution-approval.v1", "can_record_decision": true,
            "can_run_once": false, "can_persist_exact_version": false,
            "delivery_reason": "execution_binding_unavailable",
        })
    );
    item.artifact_hash = Some(json!(format!(
        "native-review-v4:{}:deny:review:review:test",
        "a".repeat(64)
    )));
    let bound = evaluate_one(item);
    assert_eq!(bound["execution_approval"]["can_run_once"], json!(true));
    assert_ne!(
        bound["scope_contract_digest"],
        unbound["scope_contract_digest"]
    );
}

#[test]
fn script_delivery_refusal_survives_a_valid_legacy_retry_binding() {
    let item = ApprovalScopeItemV1 {
        artifact_id: Some(json!("omp:native-pretool:bash")),
        artifact_type: Some(json!("tool_call")),
        artifact_hash: Some(json!(format!(
            "native-review-v4:{}:deny:review:review:test",
            "a".repeat(64)
        ))),
        policy_action: Some(json!("review")),
        raw_command_text: Some(json!("python3 report.py")),
        action_envelope_json: Some(json!({
            "once_only_reason": "script_execution_binding_unavailable"
        })),
        ..Default::default()
    };
    let actual = evaluate_one(item);
    assert_eq!(actual["allowed_scopes_by_action"]["allow"], json!([]));
    assert_eq!(
        actual["allowed_scopes_by_action"]["block"],
        json!(["artifact"])
    );
    assert_eq!(
        actual["once_only_reason"],
        "script_execution_binding_unavailable"
    );
    assert_eq!(actual["execution_approval"]["can_run_once"], false);
    assert_eq!(
        actual["execution_approval"]["can_persist_exact_version"],
        false
    );
    assert_eq!(actual["execution_approval"]["can_record_decision"], true);
}

#[test]
fn malformed_native_binding_never_advertises_once_delivery() {
    for hash in ["native-review-v4:", "native-review-v4:not-a-binding"] {
        let item = ApprovalScopeItemV1 {
            artifact_id: Some(json!("omp:native-pretool:bash")),
            artifact_type: Some(json!("tool_call")),
            artifact_hash: Some(json!(hash)),
            policy_action: Some(json!("review")),
            ..Default::default()
        };
        let actual = evaluate_one(item);
        assert_eq!(actual["execution_approval"]["can_run_once"], json!(false));
        assert_eq!(actual["allowed_scopes_by_action"]["allow"], json!([]));
    }
}

#[test]
fn a_request_without_fields_gets_the_conservative_contract() {
    let item = evaluate_one(ApprovalScopeItemV1::default());
    assert_eq!(item["allowed_scopes_by_action"]["allow"], json!([]));
    assert_eq!(item["allowed_scopes_by_action"]["block"], json!([]));
    assert_eq!(item["exact_action_persistence_eligible"], json!(false));
    assert_eq!(item["exact_context_token"], Value::Null);
}

/// The approval invariant over every recorded review: a review that offers
/// any allow scope offers Allow once (the exact action) and either Always
/// allow (a saved exact action or saved broader scope) or a named once-only
/// reason; a review that offers no allow scope
/// names the restriction that explains why, so the card can show recovery
/// instead of a button that cannot run the reviewed action.
#[test]
fn every_recorded_review_offers_both_choices_or_names_why_not() {
    let vectors = gunzip_json(VECTORS);
    let (mut both, mut once_only, mut unavailable, mut unidentified) = (0, 0, 0, 0);
    let mut problems = Vec::new();
    let mut unnamed = std::collections::BTreeMap::<String, usize>::new();
    for (index, case) in vectors["cases"].as_array().unwrap().iter().enumerate() {
        let request = &case["request"];
        if !matches!(
            request["policy_action"].as_str(),
            Some("review" | "require-reapproval")
        ) {
            continue;
        }
        let item = item_for(request, &case["expected"]["workspace_target"]);
        let contract = evaluate_one(item);
        let allow = contract["allowed_scopes_by_action"]["allow"]
            .as_array()
            .unwrap();
        let restrictions = contract["scope_restrictions"].as_array().unwrap();
        // Always allow is a saved exact action or any saved broader scope.
        let persists = contract["exact_action_persistence_eligible"] == json!(true)
            || allow.iter().any(|scope| scope != "artifact");
        let once_reason = contract["once_only_reason"].as_str();
        if allow.is_empty() {
            unavailable += 1;
            let explained = once_reason.is_some()
                || restrictions.iter().any(|reason| {
                    reason
                        .as_str()
                        .is_some_and(|reason| UNAVAILABLE_REASONS.contains(&reason))
                });
            let no_identity = contract["allowed_scopes_by_action"]["block"]
                .as_array()
                .is_some_and(Vec::is_empty);
            if !explained && no_identity {
                // No usable artifact identity: neither Allow nor Block can be
                // recorded, and no restriction says so. Pinned below.
                unidentified += 1;
            } else if !explained {
                problems.push(format!(
                    "case {index}: no allow scope and no reason ({restrictions:?})"
                ));
            }
        } else if !allow.contains(&json!("artifact")) {
            problems.push(format!("case {index}: allow scopes without Allow once"));
        } else if persists {
            both += 1;
        } else if once_reason.is_some() {
            once_only += 1;
        } else {
            let raw = request["artifact_type"].as_str().unwrap_or_default();
            let kind = match raw.trim() {
                "" => "none".to_owned(),
                trimmed if trimmed != raw => format!("padded:{trimmed}"),
                trimmed => trimmed.to_owned(),
            };
            *unnamed.entry(kind).or_insert(0) += 1;
        }
    }
    assert!(
        problems.is_empty(),
        "{} violations: {:?}",
        problems.len(),
        &problems[..problems.len().min(10)]
    );
    assert!(both > 500, "only {both} reviews offer both choices");
    // Known gap: a recorded review without an artifact identity offers no
    // choice and names no restriction. Lower this cap when the contract
    // learns to name it; never raise it.
    assert!(
        unidentified <= UNIDENTIFIED_REVIEW_CAP,
        "{unidentified} reviews have no identity and no reason (cap {UNIDENTIFIED_REVIEW_CAP})"
    );
    assert!(
        once_only > 0 && unavailable > 0,
        "a branch of the invariant went unexercised"
    );
    // Known gap, reported rather than hidden: these artifact types have no
    // exact-action binding, so they offer Allow once with neither Always allow
    // nor a named once-only reason (the card shows generic copy). A new type
    // joining this set, or a known type gaining cases, fails here.
    for (kind, count) in &unnamed {
        let cap = UNBOUND_ONCE_ONLY_TYPES
            .iter()
            .find(|(known, _)| known == kind)
            .map(|(_, cap)| *cap);
        assert!(
            cap.is_some_and(|cap| *count <= cap),
            "Allow once without Always allow or a reason grew for {kind}: {count} (cap {cap:?})"
        );
    }
}

const UNIDENTIFIED_REVIEW_CAP: usize = 204;

/// Restrictions that explain why a review offers no allow scope. The generic
/// entries every contract carries (`reusable_allow_is_action_bound`, the task
/// capability code) do not.
const UNAVAILABLE_REASONS: &[&str] = &[
    "execution_binding_unavailable",
    "current_action_not_overridable",
    "provider_account_unverified_once_only",
];

/// Artifact types whose reviews may still offer Allow once without Always
/// allow or a named reason, with the recorded case count for each. Lower a
/// count when a type gains a binding; never raise one.
const UNBOUND_ONCE_ONLY_TYPES: &[(&str, usize)] = &[
    ("file_read_request", 130),
    ("mcp_server", 267),
    ("mcp_tool_call", 306),
    ("none", 266),
    ("other", 34),
    // A whitespace-padded type is not read as `tool_call`, so it has no binding.
    ("padded:tool_call", 44),
    ("prompt_request", 123),
    ("tool_action_request", 42),
];
