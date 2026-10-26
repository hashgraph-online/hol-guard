//! Parity vectors recorded from the retired Python reuse ladder
//! (`evaluate_native_artifact_hook`, frozen in
//! `scripts/ci/record_artifact_reuse_step_vectors.py`), replayed through the
//! resident `hook_decide` operation, and the approval invariant's cases for the
//! reuse step.

use guard_contracts::{HOOK_DECISION_ARTIFACT_REUSE_STEP_FEATURE, HOOK_DECISION_REQUEST_SCHEMA};
use serde_json::{json, Value};

use crate::store_vectors_support_tests::gunzip_json;

const VECTORS: &[u8] = include_bytes!("../tests/fixtures/artifact_reuse_step_vectors.json.gz");

const CHANGED: &str = "approval_reuse_content_changed";
const IDENTITY_CHANGED: &str = "approval_reuse_identity_changed";
const REVIEW_TIER: [&str; 2] = ["review", "require-reapproval"];

fn reply(inputs: &Value) -> Option<Value> {
    let request = json!({
        "operation": "hook_decide",
        "request": {
            "schema": HOOK_DECISION_REQUEST_SCHEMA,
            "request_id": "req-artifact-reuse-step",
            "query": {"kind": "artifact_reuse_step", "inputs": inputs},
        }
    });
    let out =
        crate::resident_protocol::evaluate_resident_bytes(request.to_string().as_bytes(), None)
            .ok()?;
    serde_json::from_slice(&out).ok()
}

fn plan(inputs: &Value) -> Value {
    let reply = reply(inputs).expect("hook decision op should answer");
    assert_eq!(reply["status"], "ok", "{reply}");
    assert_eq!(reply["payload"]["kind"], "artifact_reuse_step", "{reply}");
    reply["payload"]["plan"].clone()
}

fn rejected(inputs: &Value) -> bool {
    match reply(inputs) {
        None => true,
        Some(reply) => reply["status"] == "error",
    }
}

fn vectors() -> Vec<Value> {
    gunzip_json(VECTORS).as_array().unwrap().clone()
}

/// Run `check` on the live plan of every recorded fact set.
fn each_plan(mut check: impl FnMut(&Value, &Value)) {
    for vector in vectors() {
        let facts = &vector["facts"];
        check(facts, &plan(facts));
    }
}

/// A node of a plan, and how it was reached.
struct Node<'a> {
    plan: &'a Value,
    /// `root`, `claimed` (the claim won) or `failed` (the claim was lost).
    via: &'static str,
    /// Some claim above this node was lost.
    lost: bool,
}

fn nodes<'a>(plan: &'a Value, via: &'static str, lost: bool, out: &mut Vec<Node<'a>>) {
    out.push(Node { plan, via, lost });
    if plan["effect"] == "claim" {
        nodes(&plan["on_claimed"], "claimed", lost, out);
        nodes(&plan["on_failed"], "failed", true, out);
    }
}

fn walk(plan: &Value) -> Vec<Node<'_>> {
    let mut out = Vec::new();
    nodes(plan, "root", false, &mut out);
    out
}

fn is_tool(facts: &Value) -> bool {
    facts["lookup"]["mode"] == "tool"
}

fn plain_tool_request(facts: &Value) -> bool {
    is_tool(facts) && facts["trusted_override"].is_null() && facts["claimed"].is_null()
}

fn first_fact(matches: impl Fn(&Value) -> bool) -> Value {
    vectors()
        .into_iter()
        .map(|vector| vector["facts"].clone())
        .find(matches)
        .expect("a recorded fact set should match")
}

#[test]
fn matches_python_reuse_ladder_vectors() {
    let vectors = vectors();
    assert!(vectors.len() > 6_000);
    for vector in &vectors {
        let facts = &vector["facts"];
        assert_eq!(plan(facts), vector["plan"], "{facts}");
    }
}

#[test]
fn feature_is_advertised() {
    assert!(crate::resident_op_features::RESIDENT_OP_FEATURES
        .contains(&HOOK_DECISION_ARTIFACT_REUSE_STEP_FEATURE));
}

/// A claim that wins is followed by the revalidation and nothing else, so the
/// approval it consumed is spent only by the run it was issued for.
#[test]
fn a_won_claim_always_revalidates() {
    each_plan(|facts, tree| {
        for node in walk(tree) {
            if node.plan["effect"] == "claim" {
                assert_eq!(node.plan["on_claimed"]["effect"], "revalidate", "{facts}");
            }
        }
    });
}

/// A tool request revalidates only behind a claim it won. A package request's
/// own resolver claimed before this step, so it may also revalidate at the
/// root, and only for a saved allow it was asked to claim.
#[test]
fn a_revalidation_follows_a_claim() {
    each_plan(|facts, tree| {
        for node in walk(tree) {
            if node.plan["effect"] != "revalidate" || node.via == "claimed" {
                continue;
            }
            assert!(!is_tool(facts), "{facts}");
            assert_eq!(node.via, "root", "{facts}");
            assert!(facts["claim_saved_approval"].as_bool().unwrap(), "{facts}");
            let saved_allow = facts["lookup"]["reasons"]
                .as_array()
                .unwrap()
                .iter()
                .any(|reason| reason["code"] == "saved_package_approval");
            assert!(saved_allow, "{facts}");
        }
    });
}

/// Allow once keeps its retry binding: the revalidation after a claim names
/// the request the approval was issued for and consumes nothing of its own,
/// and the trusted-request override is claimed only when one resolved it.
#[test]
fn allow_once_revalidates_the_request_it_was_issued_for() {
    let mut claims = 0;
    each_plan(|facts, tree| {
        for node in walk(tree) {
            if node.plan["effect"] != "claim" {
                continue;
            }
            claims += 1;
            let revalidate = &node.plan["on_claimed"];
            assert_eq!(
                revalidate["request_id"], facts["stored"]["request_id"],
                "{facts}"
            );
            assert_eq!(revalidate["package_approval_consumed"], false, "{facts}");
            if revalidate["trusted_request_override"] == true {
                assert!(facts["trusted_override"].is_object(), "{facts}");
            }
        }
    });
    assert!(claims > 100);
}

/// A saved allow the store holds for a review is claimed before it is used,
/// never read as an accepted allow without the claim that spends it.
#[test]
fn a_saved_allow_is_claimed_before_it_is_used() {
    each_plan(|facts, tree| {
        let saved = &facts["lookup"]["saved"];
        let live_allow = plain_tool_request(facts)
            && facts["claim_saved_approval"] == true
            && facts["current_action"] == "review"
            && facts["remembered_rule_rejected"] == false
            && facts["stored"].is_object()
            && saved["stored_action"] == "allow"
            && saved["stored_validation_reason"].is_null()
            && saved["integrity_failure"] == false
            && saved["stored_artifact_hash"]
                .as_str()
                .is_some_and(|hash| hash.starts_with("guard-approval-context:v1:"));
        if live_allow {
            assert_eq!(tree["effect"], "claim", "{facts}");
        }
    });
}

/// A claim another run won is a refusal: the request is reviewed again, and
/// the lost approval is never read as an allow.
#[test]
fn a_lost_claim_never_allows() {
    each_plan(|facts, tree| {
        if !is_tool(facts) || !facts["claimed"].is_null() {
            return;
        }
        let review_tier = REVIEW_TIER.contains(&facts["current_action"].as_str().unwrap());
        for node in walk(tree).into_iter().filter(|node| node.lost) {
            if node.plan["effect"] == "settled" && review_tier {
                assert_ne!(node.plan["policy_action"], "allow", "{facts}");
            }
        }
    });
}

/// An approval ends when its command hash changes: a saved allow whose hash
/// changed, was cleared or expired is refused and is never claimed, so the
/// fresh review offers both choices again.
#[test]
fn a_changed_hash_is_refused_and_never_claimed() {
    let mut refused = 0;
    each_plan(|facts, tree| {
        let saved = &facts["lookup"]["saved"];
        let changed = plain_tool_request(facts)
            && (saved["stored_validation_reason"] == CHANGED
                || saved["stored_validation_reason"] == IDENTITY_CHANGED
                || !saved["diagnostic_reason"].is_null());
        if !changed || !REVIEW_TIER.contains(&facts["current_action"].as_str().unwrap()) {
            return;
        }
        refused += 1;
        assert_eq!(tree["effect"], "settled", "{facts}");
        assert_eq!(tree["approval_reuse"]["status"], "rejected", "{facts}");
        assert_ne!(tree["policy_action"], "allow", "{facts}");
    });
    assert!(refused > 40, "the vectors should exercise a changed hash");
}

/// An integrity failure is never reused, whatever else was saved.
#[test]
fn an_integrity_failure_is_never_claimed() {
    each_plan(|facts, tree| {
        let saved = &facts["lookup"]["saved"];
        if plain_tool_request(facts) && saved["integrity_failure"] == true {
            for node in walk(tree) {
                assert_ne!(node.plan["effect"], "claim", "{facts}");
                assert_ne!(node.plan["effect"], "revalidate", "{facts}");
            }
        }
    });
}

/// Always allow is honored under `require-reapproval` and retained: a package
/// request's saved allow is revalidated whatever the current action, and only
/// a once claim is consumed. A saved block is never lifted.
#[test]
fn a_saved_package_allow_is_honored_under_require_reapproval() {
    let mut retained = 0;
    let mut consumed = 0;
    each_plan(|facts, tree| {
        if is_tool(facts) {
            return;
        }
        let reasons = facts["lookup"]["reasons"].as_array().unwrap();
        let allow = reasons
            .iter()
            .find(|r| r["code"] == "saved_package_approval");
        if let (Some(allow), true) = (allow, facts["claim_saved_approval"] == true) {
            assert_eq!(tree["effect"], "revalidate", "{facts}");
            let once = allow["approval_claim_disposition"] == "consumed";
            assert_eq!(tree["package_approval_consumed"], once, "{facts}");
            if facts["current_action"] == "require-reapproval" {
                if once {
                    consumed += 1;
                } else {
                    retained += 1;
                }
            }
        }
        if facts["stored"]["action"] == "block" && tree["effect"] == "settled" {
            assert_eq!(tree["policy_action"], "block", "{facts}");
        }
    });
    assert!(retained > 0 && consumed > 0);
}

/// Does any claim in the plan spend a trusted-request override's approval?
fn claims_an_override(plan: &Value) -> bool {
    walk(plan).iter().any(|node| {
        node.plan["effect"] == "claim"
            && node.plan["on_claimed"]["trusted_request_override"] == true
    })
}

fn with_source(facts: &Value, source: &str) -> Value {
    let mut facts = facts.clone();
    facts["stored"]["source"] = json!(source);
    facts
}

/// Reuse reads no scope. The facts name only the saved row's action, hash,
/// source and request, so a saved allow is honored whichever scope saved it,
/// and a scope is not a field the wire accepts. The source label is read in
/// one place only: a trusted browser request's override claims a saved allow
/// the approval gate wrote, and no other source's.
#[test]
fn a_saved_allow_is_honored_at_any_scope() {
    let tool = first_fact(|facts| plain_tool_request(facts) && facts["stored"].is_object());
    for field in ["scope", "approval_scope"] {
        let mut facts = tool.clone();
        facts["stored"][field] = json!("workspace");
        assert!(rejected(&facts), "{field}");
    }
    let gate = ["approval-gate", "approval-gate-once"];
    let others = ["manual", "imported"];
    let (mut saved_path, mut override_claims) = (0, 0);
    for vector in vectors() {
        let facts = &vector["facts"];
        if !facts["stored"].is_object() {
            continue;
        }
        if facts["trusted_override"].is_null() {
            // The saved-reuse path never reads the source.
            let expected = plan(facts);
            for source in gate.into_iter().chain(others) {
                assert_eq!(plan(&with_source(facts, source)), expected, "{facts}");
            }
            saved_path += 1;
            continue;
        }
        // Both gate sources are claimed alike; any other source is refused.
        let by_gate = plan(&with_source(facts, gate[0]));
        assert_eq!(plan(&with_source(facts, gate[1])), by_gate, "{facts}");
        if claims_an_override(&by_gate) {
            override_claims += 1;
            for source in others {
                let refused = plan(&with_source(facts, source));
                assert!(!claims_an_override(&refused), "{source}: {facts}");
            }
        }
    }
    assert!(saved_path > 1_000 && override_claims > 50);
}

#[test]
fn malformed_inputs_fail_closed() {
    let tool = first_fact(|facts| plain_tool_request(facts) && facts["stored"].is_object());
    let tool_alone = first_fact(|facts| plain_tool_request(facts) && facts["stored"].is_null());
    assert!(!rejected(&tool));
    let mut cases: Vec<Value> = Vec::new();
    let mut tweak = |facts: &Value, edit: &dyn Fn(&mut Value)| {
        let mut case = facts.clone();
        edit(&mut case);
        cases.push(case);
    };
    tweak(&tool, &|c| c["extra"] = json!(1));
    tweak(&tool, &|c| {
        drop(c.as_object_mut().unwrap().remove("lookup"))
    });
    tweak(&tool, &|c| {
        drop(c.as_object_mut().unwrap().remove("claim_saved_approval"))
    });
    tweak(&tool, &|c| c["claim_saved_approval"] = json!("yes"));
    tweak(&tool, &|c| c["lookup"]["mode"] = json!("workflow"));
    tweak(&tool, &|c| c["lookup"]["extra"] = json!(true));
    tweak(&tool, &|c| c["lookup"]["saved"]["extra"] = json!(true));
    tweak(&tool, &|c| {
        drop(
            c["lookup"]["saved"]
                .as_object_mut()
                .unwrap()
                .remove("stored_action"),
        )
    });
    tweak(&tool, &|c| c["stored"]["extra"] = json!(true));
    tweak(&tool, &|c| c["stored"]["request_id"] = json!(7));
    tweak(&tool, &|c| {
        c["trusted_override"] = json!({"token_validation_reason": 3})
    });
    tweak(&tool, &|c| c["claimed"] = json!({"claimed_hash": 3}));
    // The lookup and the store read one saved decision: facts that disagree
    // about whether it exists describe no real request.
    tweak(&tool, &|c| c["stored"] = Value::Null);
    tweak(&tool_alone, &|c| {
        c["stored"] = json!({
            "action": "allow",
            "artifact_hash": "hash",
            "source": "approval-gate-once",
            "request_id": "request-1",
        })
    });
    // A package request carries no saved lookup.
    tweak(&tool, &|c| {
        c["lookup"] = json!({"mode": "package", "saved": {}, "reasons": []})
    });
    for case in &cases {
        assert!(rejected(case), "{case}");
    }
    assert!(rejected(&json!({})));
}
