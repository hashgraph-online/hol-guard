//! PRD R16: an action no admitted pack describes is decided by the pack's
//! Unclassified section, not by a rule's strict branch on facts the
//! classifier can never know.

use super::v2::{fact_rule, v2_request};
use super::*;
use crate::cloud_pack_cli::answer;
use crate::cloud_pack_facts::class_only_facts;
use guard_contracts::ActionClassV2;

fn class_only(class: ActionClassV2) -> Value {
    serde_json::to_value(class_only_facts(class)).unwrap()
}

/// A Balanced-shaped rule an Unclassified update can never rule out: its
/// object and reversibility are unknown.
fn force_push() -> Value {
    fact_rule(
        "force_push",
        "block",
        json!({"classes": ["update"], "objects": ["branch"], "reversibility": ["permanent"]}),
    )
}

fn unclassified_request(evaluator: &CloudActionEvaluator) -> Value {
    let mut request = v2_request(evaluator);
    set_action(
        &mut request,
        POST,
        json!({"channel": "C0SYNTH01", "text": "hi"}),
    );
    request["facts"] = class_only(ActionClassV2::Update);
    request["policy"]["fact_rules"] = json!([force_push()]);
    request["policy"]["unclassified"] =
        json!({"action": "review", "destructive_name_action": "require-reapproval"});
    request["unclassified"] = json!({"destructive": false});
    request
}

#[test]
fn an_unclassified_update_is_reviewed_not_blocked_by_an_unknown_fact() {
    let evaluator = evaluator();
    let request = unclassified_request(&evaluator);
    let reviewed = run(&evaluator, &request);
    assert_eq!(reviewed["action"], "review", "{reviewed}");
    assert_eq!(reviewed["unknown_fact_rule_ids"], json!(["force_push"]));
    assert!(!reviewed["reason_codes"]
        .as_array()
        .unwrap()
        .contains(&json!("fact_unknown")));

    let mut destructive = request.clone();
    destructive["unclassified"] = json!({"destructive": true});
    assert_eq!(
        run(&evaluator, &destructive)["action"],
        "require-reapproval"
    );

    // Without the marker the unknown fact still takes the strict branch.
    let mut unmarked = request.clone();
    unmarked.as_object_mut().unwrap().remove("unclassified");
    assert_eq!(run(&evaluator, &unmarked)["action"], "block");

    // A marker without the pack's section keeps the strict branch too.
    let mut no_section = request.clone();
    no_section["policy"]["unclassified"] = Value::Null;
    assert_eq!(run(&evaluator, &no_section)["action"], "block");
}

#[test]
fn a_rule_that_surely_matches_still_applies_to_an_unclassified_call() {
    let evaluator = evaluator();
    let mut request = unclassified_request(&evaluator);
    request["policy"]["fact_rules"] = json!([fact_rule(
        "all_updates",
        "block",
        json!({"classes": ["update"]})
    )]);
    let blocked = run(&evaluator, &request);
    assert_eq!(blocked["action"], "block");
    assert_eq!(blocked["matched_rule_ids"], json!(["all_updates"]));

    request["policy"]["unclassified"] =
        json!({"action": "block", "destructive_name_action": "block"});
    request["policy"]["fact_rules"] = json!([]);
    assert_eq!(run(&evaluator, &request)["action"], "block");
}

#[test]
fn the_marker_is_refused_on_pack_facts_and_a_lenient_section() {
    let evaluator = evaluator();
    let mut rich = unclassified_request(&evaluator);
    rich["facts"]["object"] = json!({"state": "known", "value": "branch"});
    assert_eq!(
        run(&evaluator, &rich)["error"]["code"],
        "unclassified_facts_invalid"
    );

    let mut lenient = unclassified_request(&evaluator);
    lenient["policy"]["unclassified"] =
        json!({"action": "allow", "destructive_name_action": "allow"});
    assert!(run(&evaluator, &lenient)["error"]["code"].is_string());

    let request = unclassified_request(&evaluator);
    let mut unmarked = request.clone();
    unmarked.as_object_mut().unwrap().remove("unclassified");
    unmarked["policy"]
        .as_object_mut()
        .unwrap()
        .remove("unclassified");
    assert_ne!(
        run(&evaluator, &request)["evaluation_provenance_digest"],
        run(&evaluator, &unmarked)["evaluation_provenance_digest"]
    );
}

fn simulate(preset: &str, unclassified: bool, class: ActionClassV2) -> String {
    let mut call = json!({
        "provider": "remote_mcp",
        "actionId": "mcp.qualify.record_note",
        "facts": class_only(class),
        "effect": crate::cloud_action_v2::class_effect(class),
        "resourceId": null,
    });
    if unclassified {
        call["unclassified"] = true.into();
    }
    let line = json!({"op": "simulate", "preset": preset, "calls": [call]}).to_string();
    let result = answer(line.as_bytes());
    result["results"][0]["action"]
        .as_str()
        .unwrap_or("error")
        .to_owned()
}

#[test]
fn the_shipped_presets_decide_an_unclassified_update_as_r16_says() {
    let update = ActionClassV2::Update;
    assert_eq!(simulate("relaxed", true, update), "review");
    assert_eq!(simulate("balanced", true, update), "review");
    assert_eq!(simulate("strict", true, update), "block");
    // The same facts without the marker keep the unknown-fact branch.
    assert_eq!(simulate("balanced", false, update), "block");
    // A destructive proposal asks again, including one the classifier raised
    // to a payment from the input schema alone: the stored class carries it.
    assert_eq!(
        simulate("balanced", true, ActionClassV2::Delete),
        "require-reapproval"
    );
    assert_eq!(
        simulate("balanced", true, ActionClassV2::Pay),
        "require-reapproval"
    );
}
