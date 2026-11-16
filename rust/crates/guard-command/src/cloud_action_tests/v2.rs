//! Version 2 requests: parity with version 1, the fact-rule join, windows
//! and obligations.

use super::*;
use crate::cloud_action_v2::{REQUEST_SCHEMA_V2, RESULT_SCHEMA_V2};

const FACT_FIXTURES: &str =
    include_str!("../../../../../contracts/cloud-actions/action-facts-v2-fixtures.json");

pub(super) fn facts(class: &str) -> Value {
    let fixtures: Value = serde_json::from_str(FACT_FIXTURES).unwrap();
    let mut facts = fixtures["base"].clone();
    facts["class"] = class.into();
    facts
}

/// The class a binding's effect corresponds to, so v2 adds nothing.
fn class_for(action_id: &str) -> &'static str {
    match action_id {
        LIST => "read",
        POST => "send",
        ARCHIVE => "delete",
        _ => "admin",
    }
}

pub(super) fn v2_request(evaluator: &CloudActionEvaluator) -> Value {
    upgrade(request_for(evaluator))
}

fn upgrade(mut request: Value) -> Value {
    let action_id = request["action"]["action_id"].as_str().unwrap().to_owned();
    request["schema"] = REQUEST_SCHEMA_V2.into();
    request["supported_obligations"] = json!([]);
    request["policy"]["pack_digest"] = Value::Null;
    request["policy"]["fact_rules"] = json!([]);
    request["facts"] = facts(class_for(&action_id));
    request["usage_windows"] = json!({});
    request["session_flow"] = json!({
        "untrusted_content_seen": false, "sensitive_data_seen": false, "injection_signal_seen": false
    });
    request
}

pub(super) fn fact_rule(rule_id: &str, action: &str, selector: Value) -> Value {
    json!({"rule_id": rule_id, "action": action, "match": {"action_id": "*"}, "facts": selector})
}

pub(super) fn assert_v2(result: &Value) {
    assert!(result.get("error").is_none(), "{result}");
    assert_eq!(result["schema"], RESULT_SCHEMA_V2, "{result}");
    assert_eq!(result["engine"]["contract"], REQUEST_SCHEMA_V2);
}

#[test]
fn version_one_requests_decide_the_same_through_version_two() {
    let evaluator = evaluator();
    let base = request_for(&evaluator);
    let mut variants = Vec::new();
    for (action_id, arguments) in [
        (LIST, json!({})),
        (POST, json!({"channel": "C0SYNTH01", "text": "hi"})),
        (ARCHIVE, json!({"channel": "C0SYNTH01"})),
        (TRANSFER, json!({"user": "U0SYNTH01"})),
    ] {
        for rules in [
            json!([]),
            json!([rule("r-allow", "allow", action_id)]),
            json!([rule("r-block", "block", "slack.*")]),
            json!([
                rule("r-wide", "review", "*"),
                rule("r-narrow", "allow", action_id)
            ]),
            json!([{"rule_id": "r-res", "action": "warn",
                    "match": {"action_id": action_id, "resource_id": "C0SYNTH01"}}]),
        ] {
            for capabilities in [
                base["target_capabilities"].clone(),
                json!(["egress-pinned"]),
            ] {
                let mut request = base.clone();
                set_action(&mut request, action_id, arguments.clone());
                request["policy"]["rules"] = rules.clone();
                request["target_capabilities"] = capabilities;
                variants.push(request);
            }
        }
    }
    for mut request in variants {
        let v1 = run(&evaluator, &request);
        assert_success(&v1);
        if let Some(identity) = v1["action_identity_sha256"].as_str() {
            request["saved_consents"] = json!([consent("c-1", "always", identity)]);
        }
        let v1 = run(&evaluator, &request);
        let mut v2_request = upgrade(request.clone());
        if let Some(identity) = v1["action_identity_sha256"].as_str() {
            v2_request["saved_consents"] = json!([{"consent_id": "c-1", "kind": "always",
                "scope": {"exact": {"action_identity_sha256": identity}}}]);
        }
        let v2 = run(&evaluator, &v2_request);
        assert_v2(&v2);
        for key in [
            "action",
            "dispatch_permitted",
            "review_eligible",
            "reason_codes",
            "matched_rule_ids",
            "required_capabilities",
            "missing_capabilities",
            "consent_applied",
            "consent_id",
            "action_identity_sha256",
            "execution_identity_digest",
        ] {
            assert_eq!(v1[key], v2[key], "{key}: {request}");
        }
        assert_eq!(v2["unknown_fact_rule_ids"], json!([]));
        assert_eq!(v2["obligations"], json!([]));
    }
}

#[test]
fn version_fields_do_not_cross_schemas() {
    let evaluator = evaluator();
    let mut v1 = request_for(&evaluator);
    v1["facts"] = facts("send");
    assert_error(&run(&evaluator, &v1), "invalid_request");

    for missing in ["facts", "usage_windows", "supported_obligations"] {
        let mut v2 = v2_request(&evaluator);
        v2.as_object_mut().unwrap().remove(missing);
        let result = run(&evaluator, &v2);
        assert_eq!(result["error"]["code"], "invalid_request", "{missing}");
        assert_eq!(result["schema"], RESULT_SCHEMA_V2);
        assert_eq!(result["dispatch_permitted"], false);
    }
    let mut v2 = v2_request(&evaluator);
    v2["facts"]["record_count"] = json!({"state": "known", "value": 0});
    v2["facts"]["scope"] = json!({"state": "known", "value": "single"});
    assert_eq!(run(&evaluator, &v2)["error"]["code"], "facts_inconsistent");
    let mut v2 = v2_request(&evaluator);
    v2["facts"]["scope"] = json!({"state": "bogus"});
    assert_eq!(run(&evaluator, &v2)["error"]["code"], "facts_invalid");
    let mut v2 = v2_request(&evaluator);
    v2["policy"]["fact_rules"] = json!([fact_rule("r", "allow", json!({}))]);
    assert_eq!(run(&evaluator, &v2)["error"]["code"], "invalid_request");
    let mut v2 = v2_request(&evaluator);
    v2["policy"]["pack_digest"] = "not-a-digest".into();
    assert_eq!(run(&evaluator, &v2)["error"]["code"], "invalid_request");
}

#[test]
fn a_fact_rule_can_lower_the_default_and_unknown_facts_cannot() {
    let evaluator = evaluator();
    let mut request = v2_request(&evaluator);
    set_action(&mut request, ARCHIVE, json!({"channel": "C0SYNTH01"}));
    request["facts"] = facts("delete");
    let floor = run(&evaluator, &request);
    assert_eq!(floor["action"], "require-reapproval");

    request["policy"]["fact_rules"] = json!([fact_rule(
        "small-trash",
        "allow",
        json!({"max_record_count": 25})
    )]);
    let lowered = run(&evaluator, &request);
    assert_v2(&lowered);
    assert_eq!(lowered["action"], "allow");
    assert_eq!(lowered["matched_rule_ids"], json!(["small-trash"]));
    assert_eq!(
        lowered["reason_codes"],
        json!(["effect_floor", "fact_rule"])
    );

    // byte_count is unknown in the facts: an allow that depends on it is ignored.
    request["policy"]["fact_rules"] = json!([fact_rule(
        "small-bytes",
        "allow",
        json!({"max_byte_count": 10})
    )]);
    let held = run(&evaluator, &request);
    assert_eq!(held["action"], "require-reapproval");
    assert_eq!(held["unknown_fact_rule_ids"], json!(["small-bytes"]));
    assert_eq!(held["matched_rule_ids"], json!([]));

    // ...while a block that depends on it applies.
    request["policy"]["fact_rules"] = json!([fact_rule(
        "big-bytes",
        "block",
        json!({"min_byte_count": 10})
    )]);
    let blocked = run(&evaluator, &request);
    assert_eq!(blocked["action"], "block");
    assert_eq!(
        blocked["reason_codes"],
        json!(["effect_floor", "fact_unknown"])
    );
}

#[test]
fn rule_order_never_changes_the_result() {
    let evaluator = evaluator();
    let rules = [
        fact_rule("a", "allow", json!({"classes": ["delete"]})),
        fact_rule("b", "review", json!({"max_record_count": 20})),
        fact_rule("c", "warn", json!({"objects": ["message"]})),
        fact_rule("d", "block", json!({"min_byte_count": 1_000_000})),
        fact_rule("e", "block", json!({"classes": ["send"]})),
    ];
    let mut request = v2_request(&evaluator);
    set_action(&mut request, ARCHIVE, json!({"channel": "C0SYNTH01"}));
    request["facts"] = facts("delete");
    let mut expected: Option<Value> = None;
    let mut order: Vec<usize> = (0..rules.len()).collect();
    // Heap's algorithm over all 120 orders.
    let mut counters = vec![0; order.len()];
    let mut check = |order: &[usize]| {
        request["policy"]["fact_rules"] =
            Value::Array(order.iter().map(|i| rules[*i].clone()).collect());
        let mut result = run(&evaluator, &request);
        // The provenance digest hashes the rule bytes in the order sent, so
        // it is checked for presence and left out of the comparison.
        let provenance = result
            .as_object_mut()
            .and_then(|object| object.remove("evaluation_provenance_digest"));
        assert!(provenance.as_ref().is_some_and(Value::is_string));
        for key in ["matched_rule_ids", "unknown_fact_rule_ids"] {
            let sorted = result[key].as_array().map(|ids| {
                let mut ids = ids.clone();
                ids.sort_by_key(|id| id.to_string());
                ids
            });
            result[key] = sorted.map_or(Value::Null, Value::Array);
        }
        match &expected {
            Some(first) => assert_eq!(first, &result),
            None => expected = Some(result),
        }
    };
    check(&order);
    let mut i = 0;
    while i < order.len() {
        if counters[i] < i {
            let swap = if i % 2 == 0 { 0 } else { counters[i] };
            order.swap(swap, i);
            check(&order);
            counters[i] += 1;
            i = 0;
        } else {
            counters[i] = 0;
            i += 1;
        }
    }
    let result = expected.unwrap();
    assert_eq!(result["action"], "block", "{result}");
    assert_eq!(result["unknown_fact_rule_ids"], json!(["d"]));
}

#[test]
fn intrinsic_blocks_hold_against_any_allow() {
    let evaluator = evaluator();
    let mut request = v2_request(&evaluator);
    set_action(&mut request, TRANSFER, json!({"user": "U0SYNTH01"}));
    request["facts"] = facts("admin");
    request["policy"]["rules"] = json!([rule("r", "allow", TRANSFER)]);
    request["policy"]["fact_rules"] =
        json!([fact_rule("f", "allow", json!({"classes": ["admin"]}))]);
    let result = run(&evaluator, &request);
    assert_eq!(result["action"], "block");
    assert_eq!(result["reason_codes"], json!(["admin_effect_unsupported"]));

    // Facts can raise a read binding: an admin class is blocked even there.
    let mut request = v2_request(&evaluator);
    set_action(&mut request, LIST, json!({}));
    request["facts"] = facts("admin");
    request["policy"]["fact_rules"] =
        json!([fact_rule("f", "allow", json!({"classes": ["admin"]}))]);
    let result = run(&evaluator, &request);
    assert_eq!(result["action"], "block");
    assert_eq!(
        result["reason_codes"],
        json!(["admin_effect_unsupported", "facts_effect"])
    );

    request["facts"] = facts("delete");
    request["policy"]["fact_rules"] = json!([]);
    let raised = run(&evaluator, &request);
    assert_eq!(raised["action"], "require-reapproval");
    assert_eq!(
        raised["reason_codes"],
        json!(["effect_floor", "facts_effect"])
    );

    // A version 1 allow written for the read binding cannot lower the raised effect.
    request["policy"]["rules"] = json!([rule("r", "allow", LIST)]);
    let ruled = run(&evaluator, &request);
    assert_eq!(ruled["action"], "require-reapproval");
    assert_eq!(
        ruled["reason_codes"],
        json!(["policy_rule", "facts_effect", "facts_effect_floor"])
    );
}

#[test]
fn cumulative_windows_hold_under_and_at_the_limit_and_block_over_or_missing() {
    let evaluator = evaluator();
    let mut request = v2_request(&evaluator);
    set_action(&mut request, ARCHIVE, json!({"channel": "C0SYNTH01"}));
    request["facts"] = facts("delete");
    request["policy"]["fact_rules"] = json!([fact_rule(
        "hourly-deletes",
        "block",
        json!({"windows": [{"window": "deletes_per_hour", "above": 20}]})
    )]);
    // This call deletes 12 records.
    for (used, expected) in [
        (Some(0), "require-reapproval"),
        (Some(8), "require-reapproval"),
        (Some(9), "block"),
        (None, "block"),
    ] {
        request["usage_windows"] = match used {
            Some(count) => json!({"deletes_per_hour": count}),
            None => json!({}),
        };
        let result = run(&evaluator, &request);
        assert_v2(&result);
        assert_eq!(result["action"], expected, "{used:?}");
    }
    request["usage_windows"] = json!({"Bad Name": 1});
    assert_eq!(
        run(&evaluator, &request)["error"]["code"],
        "invalid_request"
    );
}

#[test]
fn an_unfulfillable_obligation_blocks() {
    let evaluator = evaluator();
    let mut request = v2_request(&evaluator);
    set_action(&mut request, ARCHIVE, json!({"channel": "C0SYNTH01"}));
    request["facts"] = facts("delete");
    let mut readback = fact_rule("readback", "allow", json!({"max_record_count": 25}));
    readback["obligations"] = json!(["count_readback", "preview_required"]);
    request["policy"]["fact_rules"] = json!([readback]);
    request["supported_obligations"] = json!(["count_readback"]);
    let blocked = run(&evaluator, &request);
    assert_eq!(blocked["action"], "block");
    assert_eq!(blocked["dispatch_permitted"], false);
    assert_eq!(blocked["missing_obligations"], json!(["preview_required"]));
    assert_eq!(
        blocked["reason_codes"],
        json!(["effect_floor", "fact_rule", "capability_unavailable"])
    );

    request["supported_obligations"] = json!(["preview_required", "count_readback"]);
    let allowed = run(&evaluator, &request);
    assert_eq!(allowed["action"], "allow");
    assert_eq!(
        allowed["obligations"],
        json!(["count_readback", "preview_required"])
    );
    assert_eq!(allowed["missing_obligations"], json!([]));
}

#[test]
fn provenance_names_facts_and_pack() {
    let evaluator = evaluator();
    let mut request = v2_request(&evaluator);
    let first = run(&evaluator, &request);
    assert!(is_hex_digest(&first["facts_digest"]));
    assert_eq!(first["pack_digest"], Value::Null);
    request["policy"]["pack_digest"] = "ab".repeat(32).into();
    let packed = run(&evaluator, &request);
    assert_eq!(packed["pack_digest"], "ab".repeat(32));
    assert_ne!(
        first["evaluation_provenance_digest"],
        packed["evaluation_provenance_digest"]
    );
    request["facts"]["record_count"] = json!({"state": "known", "value": 13});
    let changed = run(&evaluator, &request);
    assert_ne!(packed["facts_digest"], changed["facts_digest"]);
    assert_ne!(
        packed["evaluation_provenance_digest"],
        changed["evaluation_provenance_digest"]
    );
}
