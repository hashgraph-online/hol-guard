//! Replays Managed Controls policy-field vectors recorded from the reference
//! Python (`scripts/record_managed_controls_policy_fields_vectors.py`).

use serde_json::{json, Value};

use super::*;

const VECTORS: &str = include_str!("../tests/fixtures/managed_controls_policy_fields_vectors.json");
const CAPS: [&str; 3] = [LAYER_CAP, TARGETS_CAP, ATOMIC_CAP];

fn fixture() -> Value {
    serde_json::from_str(VECTORS).expect("vectors")
}

fn run(document: Value) -> Value {
    let mut request = json!({ "document": document, "capabilities": CAPS });
    request["catalog"] = fixture()["catalog"].clone();
    evaluate(&request).expect("answer")
}

fn code(document: Value) -> String {
    let answer = run(document);
    answer["error"]["code"]
        .as_str()
        .unwrap_or_else(|| panic!("expected a refusal, got {answer}"))
        .to_owned()
}

fn controls(mode: &str, items: Vec<Value>) -> Value {
    json!({
        "spec": { "rules": [] },
        CONTROLS_FIELD: { "schemaVersion": CONTROLS_SCHEMA, "authorityMode": mode, "controls": items },
    })
}

fn targets(extension_ids: Vec<String>, permission_ids: Vec<String>) -> Value {
    json!({ "schemaVersion": TARGETS_SCHEMA, "extensionIds": extension_ids, "permissionIds": permission_ids })
}

#[test]
fn parser_matches_python_vectors() {
    let fixture = fixture();
    let vectors = fixture["vectors"].as_array().expect("vector list");
    assert!(vectors.len() >= 350);
    for vector in vectors {
        let mut request = vector["request"].clone();
        request["catalog"] = fixture["catalog"].clone();
        let got = evaluate(&request).expect("answer");
        assert_eq!(got, vector["expected"], "vector {}", vector["name"]);
    }
}

#[test]
fn size_limits_are_enforced() {
    let disable = json!({ "targetKind": "extension", "targetId": "command.agentbridge", "state": "disabled" });
    assert_eq!(
        code(controls(
            "managed-restrictive",
            vec![disable; MAX_CONTROLS_PER_LAYER + 1]
        )),
        "control_limit_exceeded"
    );

    let rule =
        |index: usize| json!({ "id": format!("r{index}"), TARGETS_FIELD: targets(vec![], vec![]) });
    let mut rules: Vec<Value> = (0..=MAX_CONTROL_SET_RULES).map(rule).collect();
    assert_eq!(
        code(json!({ "spec": { "rules": rules } })),
        "rule_limit_exceeded"
    );
    rules.truncate(MAX_CONTROL_SET_RULES);
    rules.push(json!({ "id": "plain" }));
    let answer = run(json!({ "spec": { "rules": rules } }));
    assert_eq!(
        answer["ok"]["rule_targets"].as_array().map(Vec::len),
        Some(MAX_CONTROL_SET_RULES)
    );

    let many: Vec<String> = (0..=MAX_CONTROL_SET_TARGETS)
        .map(|index| format!("command.git.permission.p{index}"))
        .collect();
    let document =
        json!({ "spec": { "rules": [{ "id": "r", TARGETS_FIELD: targets(vec![], many) }] } });
    assert_eq!(code(document), "target_limit_exceeded");

    let permissions: Vec<String> = fixture()["catalog"]["permissions"]
        .as_object()
        .expect("permissions")
        .keys()
        .filter(|id| id.starts_with("command.git."))
        .take(30)
        .cloned()
        .collect();
    let rules: Vec<Value> = (0..35)
        .map(|index| json!({ "id": format!("r{index}"), TARGETS_FIELD: targets(vec![], permissions.clone()) }))
        .collect();
    assert_eq!(
        code(json!({ "spec": { "rules": rules } })),
        "target_limit_exceeded"
    );
}

#[test]
fn values_the_reference_crashed_on_are_refused() {
    let control = |kind: Value, id: Value, state: Value| json!({ "targetKind": kind, "targetId": id, "state": state });
    for (document, expected) in [
        (controls_with_mode(json!([])), "invalid_authority"),
        (controls_with_mode(json!({})), "invalid_authority"),
        (
            controls(
                "workspace-shared",
                vec![control(json!([]), json!("command.git"), json!("disabled"))],
            ),
            "invalid_target_kind",
        ),
        (
            controls(
                "workspace-shared",
                vec![control(json!("extension"), json!("command.git"), json!({}))],
            ),
            "invalid_control_state",
        ),
        (
            controls(
                "workspace-shared",
                vec![control(
                    json!("extension"),
                    json!("command.git.permission.force-push"),
                    json!("disabled"),
                )],
            ),
            "invalid_extension_id",
        ),
    ] {
        assert_eq!(code(document), expected);
    }
}

fn controls_with_mode(mode: Value) -> Value {
    json!({
        "spec": { "rules": [] },
        CONTROLS_FIELD: { "schemaVersion": CONTROLS_SCHEMA, "authorityMode": mode, "controls": [] },
    })
}

#[test]
fn canonical_ids_follow_the_catalog_grammar() {
    for id in ["command.git", "command.package.node", "command.a-b.c9"] {
        assert!(is_extension_id(id), "{id}");
    }
    for id in [
        "command.",
        "command.git.",
        "command.-git",
        "Command.git",
        "command.git\n",
        "command.gït",
    ] {
        assert!(!is_extension_id(id), "{id}");
    }
    for id in [
        "command.git.permission.force-push",
        "command.permission.permission.x",
        "command.a.permission.permission.b",
    ] {
        assert!(is_permission_id(id), "{id}");
    }
    for id in [
        "command.git",
        "command.git.permission.",
        "command..permission.x",
        "command.gït.permission.x",
    ] {
        assert!(!is_permission_id(id), "{id}");
    }
}

#[test]
fn malformed_requests_are_errors_not_refusals() {
    let catalog = fixture()["catalog"].clone();
    for request in [
        json!({}),
        json!({ "document": {}, "capabilities": [] }),
        json!({ "document": {}, "capabilities": "x", "catalog": catalog }),
        json!({ "document": {}, "capabilities": [1], "catalog": catalog }),
        json!({ "capabilities": [], "catalog": catalog }),
        json!({ "document": {}, "capabilities": [], "catalog": { "extensions": {} } }),
    ] {
        assert!(evaluate(&request) == Err(ERR_REQUEST), "{request}");
    }
}
