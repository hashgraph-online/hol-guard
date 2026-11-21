//! Parity vectors recorded from the Python policy-stack tail (frozen in
//! `scripts/ci/record_policy_stack_tail_vectors.py`), replayed through the
//! resident's artifact facts and composition queries.
//!
//! `approval_source` and `policy_composition` land in the persisted receipt
//! and the hook response, so the composition vectors are compared whole: the
//! same key set, values and label, not a projection of them.

use guard_contracts::{HookArtifactComposeQueryV1, HookArtifactV1, PolicyCompositionQueryV1};
use serde_json::{json, Value};

use super::approval_source;
use crate::hook_artifact_compose_op::compose;
use crate::hook_artifact_facts_op::evaluate;
use crate::store_vectors_support_tests::gunzip_json;

const VECTORS: &[u8] = include_bytes!("../tests/fixtures/policy_stack_tail_vectors.json.gz");
const COMPOSE_VECTORS: &str = include_str!("../tests/fixtures/hook_artifact_compose_vectors.json");

fn recorded(kind: &str) -> Vec<Value> {
    gunzip_json(VECTORS)
        .as_array()
        .unwrap()
        .iter()
        .filter(|vector| vector["kind"] == kind)
        .cloned()
        .collect()
}

fn base_stack_query() -> Value {
    let vectors: Vec<Value> = serde_json::from_str(COMPOSE_VECTORS).unwrap();
    vectors
        .into_iter()
        .find(|vector| vector["name"] == "stack_defaults")
        .expect("the base stack vector is recorded")["query"]
        .clone()
}

fn composition_query(inputs: &Value) -> Value {
    let mut query = inputs.clone();
    query["kind"] = json!("policy_composition");
    query
}

fn composition(inputs: &Value) -> Value {
    let query: HookArtifactComposeQueryV1 = serde_json::from_value(composition_query(inputs))
        .unwrap_or_else(|error| {
            panic!("{inputs}: {error}");
        });
    compose(&query).unwrap()
}

#[test]
fn skip_native_floor_matches_the_recorded_python() {
    let vectors = recorded("skip_native_floor");
    assert!(vectors.len() >= 500);
    let (mut skipped, mut kept) = (0, 0);
    for vector in vectors {
        let artifact = HookArtifactV1 {
            artifact_type: vector["artifact"]["artifact_type"]
                .as_str()
                .unwrap()
                .to_owned(),
            metadata: vector["artifact"]["metadata"].clone(),
            configured_override: None,
            ..HookArtifactV1::default()
        };
        let facts = evaluate(&artifact);
        assert_eq!(facts["skip_native_floor"], vector["expected"], "{vector}");
        if vector["expected"] == json!(true) {
            skipped += 1;
        } else {
            kept += 1;
        }
    }
    // Both answers are recorded: a replay of one would pass a stuck flag.
    assert!(skipped > 50 && kept > 50, "{skipped} skipped, {kept} kept");
}

#[test]
fn a_package_request_skips_the_floor_whatever_its_metadata_says() {
    for metadata in [
        json!({}),
        json!({"command_action_floor": "block"}),
        json!({"command_action_floor": "review", "risk_classes": ["destructive_shell"]}),
        json!("not an object"),
        Value::Null,
    ] {
        let artifact = HookArtifactV1 {
            artifact_type: "package_request".to_owned(),
            metadata,
            configured_override: None,
            ..HookArtifactV1::default()
        };
        assert_eq!(evaluate(&artifact)["skip_native_floor"], json!(true));
    }
}

#[test]
fn local_eligibility_matches_the_recorded_python() {
    let vectors = recorded("local_eligibility_required");
    assert!(vectors.len() >= 80);
    let mut required = 0;
    for vector in vectors {
        let mut query = base_stack_query();
        for field in ["event_name", "artifact_type", "has_raw_command"] {
            query[field] = vector["stack"][field].clone();
        }
        let query: HookArtifactComposeQueryV1 =
            serde_json::from_value(query).unwrap_or_else(|error| panic!("{vector}: {error}"));
        let answer = compose(&query).unwrap();
        assert_eq!(
            answer["local_eligibility_required"], vector["expected"],
            "{vector}"
        );
        if vector["expected"] == json!(true) {
            required += 1;
        }
    }
    assert!(required >= 2);
}

#[test]
fn composition_matches_the_recorded_python_exactly() {
    let vectors = recorded("policy_composition");
    assert!(vectors.len() >= 2_000);
    for vector in vectors {
        assert_eq!(
            composition(&vector["inputs"]),
            vector["expected"],
            "{}",
            vector["inputs"]
        );
    }
}

#[test]
fn the_receipt_fields_are_pinned() {
    let inputs = json!({
        "current_config_action": "review",
        "current_action_override": null,
        "trusted_cli_action": "block",
        "untrusted_payload_action": null,
        "package_policy_action": "warn",
        "data_flow_action": null,
        "scanner_action": "review",
        "current_composed_action": "block",
        "saved_policy_action": "allow",
        "approval_reuse_source": "saved_policy",
        "trusted_request_override": true,
        "trusted_request_override_reason": "token_match",
        "authoritative_action": "require-reapproval",
        "claude_native_approval_observed": false,
        "user_override_present": false,
    });
    let answer = composition(&inputs);
    let expected_trace = json!({
        "current_config_action": "review",
        "current_action_override": null,
        "trusted_cli_override": "block",
        "untrusted_hook_payload_hint": null,
        "package_action": "warn",
        "data_flow_action": null,
        "scanner_action": "review",
        "current_composed_action": "block",
        "saved_policy_action": "allow",
        "approval_reuse_source": "saved_policy",
        "trusted_request_override": true,
        "trusted_request_override_reason": "token_match",
        "authoritative_action": "require-reapproval",
    });
    assert_eq!(answer["policy_composition"], expected_trace);
    let mut evidence = expected_trace;
    evidence["source"] = json!("policy_composition");
    assert_eq!(answer["evidence"], evidence);
    assert_eq!(answer["approval_source"], json!("approval_center"));
}

#[test]
fn the_source_is_inline_for_either_inline_signal_and_for_both() {
    for (claude, override_present) in [(true, false), (false, true), (true, true)] {
        for action in ["allow", "review", "require-reapproval", "block"] {
            let mut inputs = recorded("policy_composition")[0]["inputs"].clone();
            inputs["claude_native_approval_observed"] = json!(claude);
            inputs["user_override_present"] = json!(override_present);
            inputs["authoritative_action"] = json!(action);
            assert_eq!(composition(&inputs)["approval_source"], json!("inline"));
        }
    }
}

/// The label records who approved; it never withdraws a choice. A verdict that
/// waits on the approval center is labelled so only when nothing approved it
/// inline, and no other verdict is.
#[test]
fn only_a_reapproval_awaiting_the_center_is_labelled_for_it() {
    for vector in recorded("policy_composition") {
        let inputs = &vector["inputs"];
        let label = approval_source(
            &serde_json::from_value::<PolicyCompositionQueryV1>(inputs.clone()).unwrap(),
        );
        let inline = inputs["claude_native_approval_observed"] == json!(true)
            || inputs["user_override_present"] == json!(true);
        let awaiting = inputs["authoritative_action"] == json!("require-reapproval");
        assert_eq!(label == "inline", inline, "{inputs}");
        assert_eq!(label == "approval_center", awaiting && !inline, "{inputs}");
        assert!(["inline", "approval_center", "policy"].contains(&label));
    }
}

/// The approval invariant: a review-tier verdict always offers Allow once and
/// Always allow. The composition answer is a trace and a receipt label only: it
/// repeats the verdict it was given and carries nothing that narrows the choices,
/// whichever way the source is labelled.
#[test]
fn review_tier_verdicts_keep_allow_once_and_always_allow() {
    for action in ["review", "require-reapproval"] {
        for (claude, override_present) in [(false, false), (true, false), (false, true)] {
            let mut inputs = recorded("policy_composition")[0]["inputs"].clone();
            inputs["authoritative_action"] = json!(action);
            inputs["claude_native_approval_observed"] = json!(claude);
            inputs["user_override_present"] = json!(override_present);
            let answer = composition(&inputs);
            assert_eq!(
                answer["policy_composition"]["authoritative_action"],
                json!(action)
            );
            let mut keys: Vec<&str> = answer
                .as_object()
                .unwrap()
                .keys()
                .map(String::as_str)
                .collect();
            keys.sort();
            assert_eq!(keys, ["approval_source", "evidence", "policy_composition"]);
        }
    }
}

#[test]
fn a_malformed_composition_query_is_refused() {
    let good = recorded("policy_composition")[0]["inputs"].clone();
    let cases = [
        ("missing field", {
            let mut query = good.clone();
            query
                .as_object_mut()
                .unwrap()
                .remove("user_override_present");
            query
        }),
        ("unknown field", {
            let mut query = good.clone();
            query["approval_source"] = json!("policy");
            query
        }),
        ("non-string action", {
            let mut query = good.clone();
            query["authoritative_action"] = json!(7);
            query
        }),
        ("non-bool signal", {
            let mut query = good.clone();
            query["claude_native_approval_observed"] = json!("yes");
            query
        }),
        ("null verdict", {
            let mut query = good.clone();
            query["authoritative_action"] = Value::Null;
            query
        }),
    ];
    for (name, inputs) in cases {
        serde_json::from_value::<HookArtifactComposeQueryV1>(composition_query(&inputs))
            .expect_err(name);
    }
}

#[test]
fn a_stack_query_without_the_eligibility_fields_is_refused() {
    for field in ["event_name", "artifact_type", "has_raw_command"] {
        let mut query = base_stack_query();
        query.as_object_mut().unwrap().remove(field);
        serde_json::from_value::<HookArtifactComposeQueryV1>(query).expect_err(field);
    }
}
