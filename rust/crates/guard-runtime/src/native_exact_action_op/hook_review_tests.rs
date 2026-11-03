use super::*;
use std::collections::BTreeMap;

use crate::native_exact_action_op::context::ResidentEngines;
use crate::native_exact_action_op::{decide_query, Fallback};
use guard_contracts::NativeExactActionPayloadV1;

/// The daemon's recorded queries: each payload, verdict and receipt with the
/// ExactAction query the retired daemon builder sent for it when the receipt
/// bound extension policy.
const VECTORS: &str = include_str!("../../tests/fixtures/hook_direct_saved_decision_vectors.json");

fn vectors() -> Value {
    serde_json::from_str(VECTORS).expect("saved-decision vectors parse")
}

fn hook_review(vectors: &Value, case: &Value) -> NativeExactActionQueryV1 {
    let environment: BTreeMap<String, String> =
        serde_json::from_value(vectors["environment"].clone()).unwrap();
    NativeExactActionQueryV1::HookReview {
        harness: case["harness"].as_str().unwrap().to_owned(),
        payload: case["payload"].as_object().unwrap().clone(),
        result: case["result"].as_object().unwrap().clone(),
        receipt: case["receipt"].as_object().cloned(),
        workspace: vectors["workspace"].as_str().map(str::to_owned),
        home_dir: vectors["home_dir"].as_str().map(str::to_owned),
        environment,
        extension_control_digest: vectors["control_digest"].as_str().unwrap().to_owned(),
        budget_ms: 4_000,
    }
}

/// The query with its tool-input pairs in key order and the recorded budget.
/// A parsed payload here does not keep the daemon's key order, and the token
/// does not depend on it.
fn normalized(mut query: NativeExactActionQueryV1, budget: u64) -> NativeExactActionQueryV1 {
    if let NativeExactActionQueryV1::ExactAction {
        tool_input,
        budget_ms,
        ..
    } = &mut query
    {
        if let Some(pairs) = tool_input {
            pairs.sort_by(|left, right| left.0.cmp(&right.0));
        }
        *budget_ms = budget;
    }
    query
}

fn case<'a>(vectors: &'a Value, name: &str) -> &'a Value {
    vectors["queries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["name"] == name)
        .unwrap_or_else(|| panic!("no vector {name}"))
}

#[test]
fn bound_reviews_derive_the_daemon_queries() {
    let vectors = vectors();
    let bound: Vec<&Value> = vectors["queries"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|case| !case["query"].is_null())
        .collect();
    assert!(bound.len() >= 8);
    for case in bound {
        let name = case["name"].as_str().unwrap();
        let recorded: NativeExactActionQueryV1 =
            serde_json::from_value(case["query"].clone()).unwrap();
        let NativeExactActionQueryV1::ExactAction {
            budget_ms,
            policy_binding,
            facts,
            command,
            payload_cwd,
            workspace,
            ..
        } = &recorded
        else {
            panic!("{name}: recorded query is not ExactAction");
        };
        let review = derive(&hook_review(&vectors, case)).unwrap();
        assert!(review.policy_binding_valid, "{name}");
        assert_eq!(
            normalized(review.action, *budget_ms),
            normalized(recorded.clone(), *budget_ms),
            "{name}"
        );
        let NativeExactActionQueryV1::ReviewBinding {
            harness,
            command: binding_command,
            cwd,
            workspace_bound,
            facts: binding_facts,
            receipt,
            policy_binding: binding_policy,
            workspace: binding_workspace,
            execution_environment,
        } = review.binding
        else {
            panic!("{name}: binding query is not ReviewBinding");
        };
        assert_eq!(harness, case["harness"].as_str().unwrap(), "{name}");
        assert_eq!(&binding_command, command, "{name}");
        assert_eq!(&cwd, payload_cwd, "{name}");
        assert!(workspace_bound, "{name}");
        assert_eq!(&binding_facts, facts, "{name}");
        assert_eq!(receipt.as_ref(), Some(&case["receipt"]), "{name}");
        assert_eq!(&binding_policy, policy_binding, "{name}");
        assert_eq!(&binding_workspace, workspace, "{name}");
        assert_eq!(execution_environment, None, "{name}");
    }
}

#[test]
fn a_receipt_that_does_not_prove_the_claimed_policy_invalidates_the_review() {
    let vectors = vectors();
    for name in [
        "receipt-decision-mismatch",
        "receipt-observe-mode-mismatch",
        "negative-uncertainty",
        "harness-mismatch",
        "prompt-risk-classes",
        "missing-receipt",
    ] {
        let review = derive(&hook_review(&vectors, case(&vectors, name))).unwrap();
        assert!(!review.policy_binding_valid, "{name}");
        let NativeExactActionQueryV1::ExactAction { policy_binding, .. } = review.action else {
            panic!("{name}: action query is not ExactAction");
        };
        assert_eq!(policy_binding, NativePolicyBindingV1::Invalid, "{name}");
    }
}

#[test]
fn a_verdict_without_extension_policy_binds_none() {
    let vectors = vectors();
    let review = derive(&hook_review(
        &vectors,
        case(&vectors, "unbound-legacy-review"),
    ))
    .unwrap();
    assert!(review.policy_binding_valid);
    let NativeExactActionQueryV1::ExactAction { policy_binding, .. } = review.action else {
        panic!("action query is not ExactAction");
    };
    assert_eq!(policy_binding, NativePolicyBindingV1::Unbound);
}

#[test]
fn a_receipt_without_its_payload_kind_proves_nothing() {
    let vectors = vectors();
    let mut bound = case(&vectors, "bash-command").clone();
    bound["receipt"]
        .as_object_mut()
        .unwrap()
        .remove("payload_kind");
    let review = derive(&hook_review(&vectors, &bound)).unwrap();
    assert!(!review.policy_binding_valid);
}

#[test]
fn verdict_facts_read_as_the_daemon_read_them() {
    let result = json!({
        "decision": "deny",
        "minimum_action": null,
        "policy_action": 0,
        "reason_code": "",
        "action": {"action_type": "shell"},
    });
    let facts = facts(result.as_object().unwrap()).unwrap();
    assert_eq!(facts.decision.as_deref(), Some("deny"));
    assert_eq!(facts.minimum_action.as_deref(), Some(""));
    assert_eq!(facts.policy_action.as_deref(), Some(""));
    assert_eq!(facts.reason_code.as_deref(), Some(""));
    assert_eq!(facts.action_type.as_deref(), Some("shell"));
    let absent = super::facts(&Map::new()).unwrap();
    assert_eq!(absent.decision.as_deref(), Some(""));
    assert_eq!(absent.action_type, None);
    for value in [json!(true), json!(1), json!(["deny"]), json!({"a": 1})] {
        let result = json!({ "decision": value });
        assert_eq!(
            super::facts(result.as_object().unwrap()).unwrap_err(),
            INVALID,
            "{value}"
        );
    }
}

#[test]
fn a_tool_input_that_is_not_an_object_still_binds() {
    let payload = json!({"tool_name": "Bash", "tool_input": "npm test", "arguments": null});
    let payload = payload.as_object().unwrap();
    assert_eq!(tool_input_pairs(payload), None);
    assert_eq!(raw_tool_input(payload), Some(json!("npm test")));
    let object = json!({"tool_input": "ignored", "arguments": {"cmd": "ls"}});
    let object = object.as_object().unwrap();
    assert_eq!(raw_tool_input(object), None);
    assert_eq!(
        tool_input_pairs(object),
        Some(vec![("cmd".to_owned(), json!("ls"))])
    );
}

#[test]
fn the_stamped_environment_and_a_blank_cwd() {
    let vectors = vectors();
    let mut stamped = case(&vectors, "bash-command").clone();
    let environment = json!({"PATH": "/usr/bin", "HOME": "/home/agent", "names": []});
    stamped["payload"]["guard_execution_environment"] = environment.clone();
    stamped["payload"]["cwd"] = json!(" \t ");
    let review = derive(&hook_review(&vectors, &stamped)).unwrap();
    let NativeExactActionQueryV1::ReviewBinding {
        cwd,
        execution_environment,
        ..
    } = review.binding
    else {
        panic!("binding query is not ReviewBinding");
    };
    assert_eq!(cwd, None);
    assert_eq!(execution_environment, Some(environment));
}

#[test]
fn a_hook_review_answers_with_the_validity_of_its_binding() {
    let vectors = vectors();
    for (name, valid) in [("no-tool-input", true), ("missing-receipt", false)] {
        let query = hook_review(&vectors, case(&vectors, name));
        let answer = decide_query(
            &query,
            &ResidentEngines { guard_home: None },
            Fallback::CommandHash,
        )
        .unwrap();
        let NativeExactActionPayloadV1::HookReview {
            policy_binding_valid,
            token,
            once_only_reason,
            ..
        } = answer
        else {
            panic!("{name}: answer is not HookReview");
        };
        assert_eq!(policy_binding_valid, valid, "{name}");
        assert!(token.is_some() != once_only_reason.is_some(), "{name}");
    }
    let not_a_hook_review = NativeExactActionQueryV1::LaunchEvidence {
        action: Box::new(hook_review(&vectors, case(&vectors, "bash-command"))),
    };
    assert_eq!(derive(&not_a_hook_review).err(), Some(INVALID));
}

#[test]
fn a_hook_review_is_observed_through_its_exact_action() {
    let vectors = vectors();
    let query = hook_review(&vectors, case(&vectors, "bash-command"));
    let engines = ResidentEngines { guard_home: None };
    let observe = |action: NativeExactActionQueryV1| {
        decide_query(
            &NativeExactActionQueryV1::LaunchEvidence {
                action: Box::new(action),
            },
            &engines,
            Fallback::CommandHash,
        )
    };
    let through_review = observe(query.clone()).unwrap();
    let through_action = observe(derive(&query).unwrap().action).unwrap();
    assert!(matches!(
        through_review,
        NativeExactActionPayloadV1::LaunchEvidence { .. }
    ));
    assert_eq!(through_review, through_action);
}
