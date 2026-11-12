use std::sync::Arc;

use guard_command::native_command_catalog::packaged_command_catalog;
use serde_json::{json, Value};

use super::*;

const RESET_RULE: &str = "command.git.hard-reset";
const PRUNE_PERMISSION: &str = "command.container-runtime.permission.build-cache-prune";
const NODE_PACKAGES: &str = "command.package.node";

fn catalog() -> Arc<CommandCatalog> {
    packaged_command_catalog().expect("packaged catalog")
}

fn step(
    index: u64,
    extension_id: &str,
    rule_id: Option<&str>,
    permission_id: Option<&str>,
) -> Value {
    json!({
        "index": index,
        "executable": null,
        "extension_ids": [extension_id],
        "rule_ids": rule_id.into_iter().collect::<Vec<_>>(),
        "permission_ids": permission_id.into_iter().collect::<Vec<_>>(),
    })
}

fn git(index: u64) -> Value {
    step(index, "command.git", Some(RESET_RULE), None)
}

fn hint(steps: Vec<Value>, total: Option<u64>) -> Value {
    let mut hint = json!({
        "schema": "guard.extension-coverage-hint.v1",
        "catalog_digest": "b".repeat(64),
        "segments": steps,
    });
    if let Some(total) = total {
        hint["segment_total"] = json!(total);
    }
    hint
}

fn indexes(coverage: &Value) -> Vec<u64> {
    coverage["segments"]
        .as_array()
        .expect("segments")
        .iter()
        .map(|segment| segment["index"].as_u64().expect("index"))
        .collect()
}

/// The package firewall's rule-less permission, which only hands a step on.
fn handed_off() -> String {
    let catalog = catalog();
    let extension = catalog.get(NODE_PACKAGES).expect("node packages");
    assert_eq!(
        extension.delegated_protection.as_deref(),
        Some("package-firewall")
    );
    extension
        .permissions
        .iter()
        .find(|permission| permission.rule_ids.is_empty())
        .expect("a rule-less permission")
        .permission_id
        .clone()
}

#[test]
fn every_step_is_labelled_from_the_catalog() {
    let catalog = catalog();
    let mut first = git(0);
    first["executable"] = json!("git");
    let mut second = step(1, "command.container-runtime", None, Some(PRUNE_PERMISSION));
    second["executable"] = json!("docker");
    let coverage = coverage(&hint(vec![first, second], None), &catalog).expect("coverage");
    let (_, rule) = catalog.get_rule(RESET_RULE).expect("reset rule");
    let prune = catalog
        .permission(PRUNE_PERMISSION)
        .expect("prune permission");
    assert_eq!(
        coverage,
        json!({
            "schema": "guard.approval-extension-coverage.v1",
            "catalog_digest": catalog.catalog_digest,
            "compound": true,
            "segments": [
                {
                    "index": 0,
                    "executable": "git",
                    "extensions": [{
                        "extension_id": "command.git",
                        "name": catalog.get("command.git").expect("git").name,
                        "focus_rule_id": RESET_RULE,
                    }],
                    "rules": [{
                        "rule_id": RESET_RULE,
                        "title": rule.title,
                        "severity": rule.severity,
                        "description": bounded(&rule.description, MAX_TEXT_CHARS),
                        "safer_alternatives": rule
                            .safer_alternatives
                            .iter()
                            .filter_map(|text| bounded(text, MAX_TEXT_CHARS))
                            .take(MAX_SAFER_ALTERNATIVES)
                            .collect::<Vec<_>>(),
                    }],
                    "permissions": [],
                },
                {
                    "index": 1,
                    "executable": "docker",
                    "extensions": [{
                        "extension_id": "command.container-runtime",
                        "name": catalog.get("command.container-runtime").expect("runtime").name,
                        "focus_rule_id": null,
                    }],
                    "rules": [],
                    "permissions": [{
                        "permission_id": PRUNE_PERMISSION,
                        "label": prune.label,
                        "configurable": prune.configurable,
                    }],
                },
            ],
        })
    );
}

#[test]
fn the_step_count_decides_whether_the_rest_comes_back() {
    let catalog = catalog();
    let compound = |steps: Vec<Value>, total: Option<u64>| {
        coverage(&hint(steps, total), &catalog).expect("coverage")["compound"].clone()
    };
    // A single later step still says the rest comes back.
    assert_eq!(compound(vec![git(2)], None), json!(true));
    assert_eq!(compound(vec![git(0)], None), json!(false));
    // A covered first step of a longer command does too.
    assert_eq!(compound(vec![git(0)], Some(3)), json!(true));
    assert_eq!(compound(vec![git(0)], Some(1)), json!(false));
}

#[test]
fn a_step_count_that_cannot_hold_the_covered_steps_is_refused() {
    let catalog = catalog();
    assert!(coverage(&hint(vec![git(2)], Some(3)), &catalog).is_some());
    for total in [json!(2), json!(0), json!("3")] {
        let mut stored = hint(vec![git(2)], None);
        stored["segment_total"] = total;
        assert_eq!(coverage(&stored, &catalog), None);
    }
}

#[test]
fn delivery_stops_at_the_steps_the_card_renders() {
    let steps = (0..14).map(git).collect();
    let coverage = coverage(&hint(steps, None), &catalog()).expect("coverage");
    assert_eq!(indexes(&coverage), (0..12).collect::<Vec<_>>());
    assert_eq!(coverage["compound"], true);
}

#[test]
fn a_step_whose_ids_this_catalog_does_not_carry_is_dropped() {
    let retired = step(
        1,
        "command.retired-extension",
        Some("command.retired-extension.rule"),
        None,
    );
    let covered = coverage(&hint(vec![git(0), retired], Some(2)), &catalog()).expect("coverage");
    assert_eq!(indexes(&covered), vec![0]);
    assert_eq!(covered["compound"], true);
    let only_retired = step(0, "command.retired-extension", None, None);
    assert_eq!(coverage(&hint(vec![only_retired], None), &catalog()), None);
}

#[test]
fn a_package_firewall_match_alone_is_not_offered_as_coverage() {
    // `npx jest <file>` matched Node package protection only because npx is a
    // package manager. Offering that extension as "covers this command" sent
    // people to a single Allow switch that turns the firewall off and still
    // leaves the paused command paused.
    let catalog = catalog();
    let firewall = handed_off();
    let only_firewall = step(0, NODE_PACKAGES, None, Some(firewall.as_str()));
    assert_eq!(
        coverage(&hint(vec![only_firewall], Some(1)), &catalog),
        None
    );
    let beside_a_rule = vec![
        git(0),
        step(1, NODE_PACKAGES, None, Some(firewall.as_str())),
    ];
    let covered = coverage(&hint(beside_a_rule, None), &catalog).expect("coverage");
    assert_eq!(indexes(&covered), vec![0]);
    assert_eq!(covered["compound"], true);
}

#[test]
fn a_malformed_or_absent_hint_has_no_coverage() {
    let catalog = catalog();
    for stored in [
        Value::Null,
        json!("guard.extension-coverage-hint.v1"),
        json!({"schema": "guard.extension-coverage-hint.v1", "segments": []}),
        hint(vec![], None),
        hint(vec![json!({"index": 0})], None),
    ] {
        assert_eq!(coverage(&stored, &catalog), None, "{stored}");
    }
    // The coverage an allow hint carries is read too.
    let carried =
        json!({"schema": "guard.extension-allow-hint.v1", "coverage": hint(vec![git(0)], None)});
    assert!(coverage(&carried, &catalog).is_some());
}

#[test]
fn the_resident_op_answers_a_coverage_query_from_its_catalog() {
    use guard_contracts::{
        ApprovalExtensionRecommendationPayloadV1, ApprovalExtensionRecommendationQueryV1,
        ApprovalExtensionRecommendationRequestV1, ApprovalExtensionRecommendationResultV1,
        APPROVAL_EXTENSION_RECOMMENDATION_REQUEST_SCHEMA,
    };
    let request = |hint: Value| ApprovalExtensionRecommendationRequestV1 {
        schema: APPROVAL_EXTENSION_RECOMMENDATION_REQUEST_SCHEMA.into(),
        request_id: "coverage-test".into(),
        query: ApprovalExtensionRecommendationQueryV1::Coverage { hint },
    };
    let answer = |hint: Value| {
        let bytes =
            crate::approval_extension_recommendation_op::evaluate_with_store(&request(hint), None)
                .expect("answer");
        let result: ApprovalExtensionRecommendationResultV1 =
            serde_json::from_slice(&bytes).expect("result");
        assert_eq!(result.status, "ok", "{}", result.code);
        match result.payload {
            Some(ApprovalExtensionRecommendationPayloadV1::Coverage { coverage }) => coverage,
            other => panic!("unexpected payload {other:?}"),
        }
    };
    let stored = hint(vec![git(0)], Some(1));
    assert_eq!(answer(stored.clone()), coverage(&stored, &catalog()));
    assert_eq!(answer(Value::Null), None);
    let wire = serde_json::to_value(request(json!({}))).expect("wire");
    assert_eq!(wire["query"], json!({"kind": "coverage", "hint": {}}));
}

#[test]
fn a_matched_rule_carries_its_catalog_text() {
    let catalog = catalog();
    let coverage = coverage(&hint(vec![git(0)], Some(1)), &catalog).expect("coverage");
    let (_, rule) = catalog.get_rule(RESET_RULE).expect("reset rule");
    let entry = &coverage["segments"][0]["rules"][0];
    assert!(entry["description"].is_string(), "{entry}");
    assert_eq!(
        entry["description"],
        json!(bounded(&rule.description, MAX_TEXT_CHARS))
    );
    let safer = entry["safer_alternatives"].as_array().expect("safer");
    assert!(safer.len() <= MAX_SAFER_ALTERNATIVES, "{entry}");
    assert!(safer.iter().all(|text| text
        .as_str()
        .is_some_and(|text| text.chars().count() <= MAX_TEXT_CHARS)));
}
