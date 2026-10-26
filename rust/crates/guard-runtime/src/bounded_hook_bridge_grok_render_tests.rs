//! Python parity for the Grok client's rendering, recorded from the
//! rendered client by `testdata/bounded_hook_bridge/grok_vectors.json`.

use serde_json::Value;

use super::*;

const VECTORS: &str = include_str!("../testdata/bounded_hook_bridge/grok_vectors.json");

fn vectors(section: &str) -> Vec<Value> {
    let all: Value = serde_json::from_str(VECTORS).unwrap();
    all[section].as_array().unwrap().clone()
}

fn text(case: &Value, key: &str) -> String {
    case[key].as_str().unwrap().to_owned()
}

fn object(source: &str) -> Vec<(String, PyVal)> {
    let Some(payload) = json_object(source) else {
        panic!("vector JSON is not an object: {source}");
    };
    payload
}

#[test]
fn event_names_and_conflicts_match_python() {
    for case in vectors("events") {
        let input = text(&case, "input");
        assert_eq!(event_name_of_text(&input), text(&case, "event"), "{case}");
        let source = if input.is_empty() { "{}" } else { &input };
        let conflict = json_object(source).is_some_and(|payload| pretool_event_conflict(&payload));
        assert_eq!(conflict, case["conflict"].as_bool().unwrap(), "{case}");
    }
}

#[test]
fn failures_match_python() {
    for case in vectors("failures") {
        assert_eq!(
            failure_stdout(&text(&case, "input")),
            text(&case, "stdout"),
            "{case}"
        );
    }
}

#[test]
fn daemon_answers_render_as_python_renders_them() {
    for case in vectors("to_native") {
        let response = object(&text(&case, "response"));
        let Some((payload, exit_code)) = to_native(&response, &text(&case, "event")) else {
            panic!("no render for {case}");
        };
        assert_eq!(dump_object(&payload), text(&case, "stdout"), "{case}");
        assert_eq!(
            i64::from(exit_code),
            case["exit"].as_i64().unwrap(),
            "{case}"
        );
    }
}

#[test]
fn answers_python_would_render_through_repr_are_not_rendered() {
    for source in [
        r#"{"policy_action":{"a":1}}"#,
        r#"{"policy_action":["block"]}"#,
        r#"{"policy_action":"block","reason":{"why":1}}"#,
        r#"{"policy_action":"review","reason":[1]}"#,
    ] {
        assert_eq!(to_native(&object(source), "PreToolUse"), None, "{source}");
    }
}

#[test]
fn approval_request_ids_match_python() {
    for case in vectors("request_ids") {
        let expected: Vec<String> = case["ids"]
            .as_array()
            .unwrap()
            .iter()
            .map(|id| id.as_str().unwrap().to_owned())
            .collect();
        assert_eq!(
            approval_request_ids(&object(&text(&case, "payload"))),
            expected,
            "{case}"
        );
    }
}

#[test]
fn decision_rewrites_match_python() {
    for case in vectors("rewrite") {
        let payload = object(&text(&case, "payload"));
        let rewritten = rewrite_decision(&payload, case["allowed"].as_bool().unwrap());
        assert_eq!(dump_object(&rewritten), text(&case, "stdout"), "{case}");
    }
}

#[test]
fn approval_wait_matches_python() {
    for case in vectors("wait_seconds") {
        let config = case["config"].as_str();
        let timeout = case["timeout"].as_f64().unwrap();
        let expected = case["seconds"].as_f64().unwrap();
        assert_eq!(approval_wait_seconds(config, timeout), expected, "{case}");
    }
}

#[test]
fn a_non_ascii_wait_override_waits_not_at_all() {
    // Python's float() reads other scripts' digits; the port reads none.
    let config = "approval_wait_timeout_seconds = \u{0662}\n";
    assert_eq!(approval_wait_seconds(Some(config), 8.0), 0.0);
}

#[test]
fn toml_scalars_match_python() {
    for case in vectors("toml_scalar") {
        assert_eq!(
            toml_scalar(&text(&case, "raw"), &text(&case, "key")),
            text(&case, "value"),
            "{case}"
        );
    }
}

#[test]
fn request_ids_quote_as_python_quotes_them() {
    for case in vectors("quote") {
        assert_eq!(
            quote_component(&text(&case, "text")),
            text(&case, "quoted"),
            "{case}"
        );
    }
}
