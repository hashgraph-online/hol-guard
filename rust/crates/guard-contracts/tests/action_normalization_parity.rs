//! Replay recorded action-lattice decisions through `guard-contracts`.
//!
//! `decision_lattice` is the second Rust implementation of the lattice
//! (`guard-command`'s `action_lattice` is the other) and it owns
//! `is_action_bearing_key`, which decides whether a field in an untyped
//! payload can carry an action authority at all. Every case below was recorded
//! from Python's `action_lattice`, so these are the answers the CLI route gives.

use guard_contracts::{
    guard_action_severity, is_action_bearing_key, most_restrictive_guard_action,
    normalize_guard_action_result, DEFAULT_UNKNOWN_GUARD_ACTION,
};
use serde_json::Value;

const FIXTURE: &str = include_str!("../../../../tests/fixtures/guard-action-normalization.v1.json");

fn text<'a>(case: &'a Value, field: &str) -> &'a str {
    case.get(field)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("case is missing {field}"))
}

fn document() -> Value {
    let document: Value = serde_json::from_str(FIXTURE).expect("fixture parses");
    assert_eq!(
        document["schema"], "guard-action-normalization-parity.v1",
        "fixture schema moved"
    );
    document
}

fn section<'a>(document: &'a Value, name: &str) -> &'a Vec<Value> {
    let cases = document[name].as_array().expect("section is a list");
    assert!(!cases.is_empty(), "the fixture records no {name}");
    cases
}

#[test]
fn recorded_normalizations_replay() {
    let document = document();
    for case in section(&document, "values") {
        let name = text(case, "name");
        let value: Value =
            serde_json::from_str(text(case, "value_json")).expect("recorded value parses");
        let normalized = normalize_guard_action_result(&value, DEFAULT_UNKNOWN_GUARD_ACTION);

        assert_eq!(
            normalized.action.as_str(),
            text(case, "action"),
            "case {name} picks a different action than Python"
        );
        assert_eq!(
            normalized.reason_code,
            case["reason_code"].as_str(),
            "case {name} reports a different reason code"
        );
        assert_eq!(
            normalized.original_action.as_deref(),
            case["original_action"].as_str(),
            "case {name} keeps a different original action"
        );
        // A number that no i64 holds is still an `int` to `json.loads`.
        assert_eq!(
            normalized.original_type,
            text(case, "original_type"),
            "case {name} names a different input type"
        );
        assert_eq!(
            normalized.recognized(),
            case["recognized"].as_bool().expect("recorded flag"),
            "case {name} disagrees on recognition"
        );
        assert_eq!(
            i64::from(guard_action_severity(&value, DEFAULT_UNKNOWN_GUARD_ACTION)),
            case["severity"].as_i64().expect("recorded rank"),
            "case {name} ranks differently"
        );
    }
}

#[test]
fn recorded_compositions_replay() {
    let document = document();
    for case in section(&document, "compositions") {
        let name = text(case, "name");
        let values: Vec<Value> = case["values_json"]
            .as_array()
            .expect("recorded values")
            .iter()
            .map(|item| {
                serde_json::from_str(item.as_str().expect("recorded value text"))
                    .expect("recorded value parses")
            })
            .collect();
        assert_eq!(
            most_restrictive_guard_action(&values, DEFAULT_UNKNOWN_GUARD_ACTION).as_str(),
            text(case, "action"),
            "composition {name} resolves differently than Python"
        );
    }
}

#[test]
fn recorded_action_bearing_keys_replay() {
    let document = document();
    for case in section(&document, "action_bearing_keys") {
        let key = text(case, "key");
        assert_eq!(
            is_action_bearing_key(key),
            case["action_bearing"].as_bool().expect("recorded flag"),
            "key {key:?} is read differently than Python reads it"
        );
    }
}

#[test]
fn the_fixture_keeps_recording_keys_on_both_sides_of_the_line() {
    let document = document();
    let keys = section(&document, "action_bearing_keys");
    let bearing = keys
        .iter()
        .filter(|case| case["action_bearing"] == Value::Bool(true))
        .count();
    assert!(
        bearing >= 8,
        "the fixture must keep recording action-bearing keys"
    );
    assert!(
        keys.len() - bearing >= 4,
        "the fixture must keep recording names that only look like actions"
    );
}
