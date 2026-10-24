//! Replay recorded action-lattice decisions through `guard-command`.
//!
//! The lattice decides which action wins when several parts of Guard disagree,
//! so a drift here changes enforcement rather than wording. Every case was
//! recorded from Python's `action_lattice`, which means the action, the rank
//! and the diagnostics below are the ones the CLI route produces.

use guard_command::action_lattice::{
    guard_action_severity, most_restrictive_guard_action, normalize_guard_action_result,
    DEFAULT_UNKNOWN_GUARD_ACTION,
};
use serde_json::Value;

const FIXTURE: &str = include_str!("../../../../tests/fixtures/guard-action-normalization.v1.json");

fn text<'a>(case: &'a Value, field: &str) -> &'a str {
    case.get(field)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("case is missing {field}"))
}

/// The recorded JSON value, decoded from the text the fixture carries.
fn recorded_value(case: &Value) -> Value {
    serde_json::from_str(text(case, "value_json")).expect("recorded value parses")
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
        let value = recorded_value(case);
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
        // The diagnostic names the input's own Python type, so a reader can
        // tell a malformed action from a missing one. A number that no i64
        // holds is still an `int` to `json.loads`.
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
            u64::from(guard_action_severity(&value, DEFAULT_UNKNOWN_GUARD_ACTION)),
            case["severity"].as_u64().expect("recorded rank"),
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
fn the_fixture_keeps_recording_every_non_string_json_type() {
    // Each one reaches a different branch of the `Value` match above, so
    // dropping a type here would let that branch drift unnoticed.
    let document = document();
    for wanted in ["NoneType", "bool", "int", "float", "list", "dict", "str"] {
        assert!(
            section(&document, "values")
                .iter()
                .any(|case| text(case, "original_type") == wanted),
            "the fixture no longer records a {wanted} input"
        );
    }
}
