use serde_json::{json, Value};

use super::dispatch;
use crate::runner_authority_op::ERR_INVALID;

const PARITY: &str = include_str!("../../guard-command/testdata/inventory_redaction_parity.json");

fn safe_json_text(value: &str, parent_key: &str, parent_sensitive: bool) -> String {
    let reply = dispatch(&json!({
        "op": "safe_json",
        "value": value,
        "parent_key": parent_key,
        "parent_sensitive": parent_sensitive,
    }))
    .expect("answer");
    reply["value"].as_str().expect("value text").to_owned()
}

fn safe_json(value: &Value, parent_key: &str, parent_sensitive: bool) -> Value {
    let text = safe_json_text(&value.to_string(), parent_key, parent_sensitive);
    serde_json::from_str(&text).expect("value json")
}

fn payload_safe(payload: &str) -> bool {
    let reply =
        dispatch(&json!({"op": "assert_payload_safe", "payload": payload})).expect("answer");
    reply["safe"].as_bool().expect("safe flag")
}

#[test]
fn serializer_answers_match_the_python_corpus() {
    let parity: Value = serde_json::from_str(PARITY).expect("parity");
    for case in parity["safe_json"].as_array().expect("safe_json") {
        assert_eq!(
            safe_json(&case["value"], "", false),
            case["expected"],
            "{case}"
        );
    }
    for case in parity["sanitize_serializer_string"]
        .as_array()
        .expect("sanitize_serializer_string")
    {
        let parent_key = case["parent_key"].as_str().expect("parent_key");
        let parent_sensitive = case["parent_sensitive"]
            .as_bool()
            .expect("parent_sensitive");
        assert_eq!(
            safe_json(&case["value"], parent_key, parent_sensitive),
            case["expected"],
            "{case}"
        );
    }
    for case in parity["assert_payload_safe"]
        .as_array()
        .expect("assert_payload_safe")
    {
        assert_eq!(
            payload_safe(&case["payload"].to_string()),
            case["safe"].as_bool().expect("safe"),
            "{case}"
        );
    }
}

#[test]
fn redacted_values_keep_their_declared_order() {
    assert_eq!(
        safe_json_text(
            r#"{"z":"/tmp/x","a":[1,2.5,null,true],"m":{"token":"t"}}"#,
            "",
            false
        ),
        r#"{"z":"[REDACTED]","a":[1,2.5,null,true],"m":{"token":"[REDACTED]"}}"#
    );
}

#[test]
fn colliding_redacted_keys_keep_the_first_place_and_last_value() {
    // Both keys redact to `[REDACTED]`; the dict comprehension keeps the first
    // key's slot and the second key's value.
    assert_eq!(
        safe_json_text(r#"{"sk-one":"a","plain":"b","sk-two":"c"}"#, "", false),
        r#"{"[REDACTED]":"c","plain":"b"}"#
    );
}

#[test]
fn a_sensitive_parent_masks_every_nested_string() {
    assert_eq!(
        safe_json_text(r#"{"auth":{"inner":["x",{"deep":"y"}],"n":3}}"#, "", false),
        r#"{"auth":{"inner":["[REDACTED]",{"deep":"[REDACTED]"}],"n":3}}"#
    );
    assert_eq!(
        safe_json_text(r#"{"safe":"x"}"#, "", true),
        r#"{"safe":"[REDACTED]"}"#
    );
}

#[test]
fn lone_surrogates_round_trip_through_the_answer() {
    assert_eq!(
        safe_json_text(r#"{"k\ud800":"v\udc00"}"#, "", false),
        r#"{"k\ud800":"v\udc00"}"#
    );
}

#[test]
fn the_safety_check_reads_the_sorted_spaced_ascii_text() {
    // `json.dumps` escapes the no-break space, so the text the check scans
    // holds `\u00a0` and the assignment never reaches its `=`.
    assert!(payload_safe(r#"{"note": "password\u00a0=abc"}"#));
    assert!(!payload_safe(r#"{"note": "password =abc"}"#));
    assert!(!payload_safe(r#"{"note": "token=abc"}"#));
    assert!(!payload_safe(r#"{"path": "/Users/someone/x"}"#));
    assert!(payload_safe(r#"{"b": 1, "a": [2.0, null]}"#));
}

#[test]
fn malformed_requests_are_refused() {
    let safe =
        json!({"op": "safe_json", "value": "{}", "parent_key": "", "parent_sensitive": false});
    assert!(dispatch(&safe).is_ok());
    for key in ["value", "parent_key", "parent_sensitive"] {
        let mut missing = safe.clone();
        missing.as_object_mut().expect("object").remove(key);
        assert_eq!(dispatch(&missing), Err(ERR_INVALID), "{key}");
    }
    let mut extra = safe.clone();
    extra["payload"] = json!("{}");
    assert_eq!(dispatch(&extra), Err(ERR_INVALID));
    let mut broken = safe.clone();
    broken["value"] = json!("{");
    assert_eq!(dispatch(&broken), Err(ERR_INVALID));
    let mut flag = safe;
    flag["parent_sensitive"] = json!(1);
    assert_eq!(dispatch(&flag), Err(ERR_INVALID));
    assert_eq!(
        dispatch(&json!({"op": "assert_payload_safe"})),
        Err(ERR_INVALID)
    );
    assert_eq!(
        dispatch(&json!({"op": "other", "payload": "{}"})),
        Err(ERR_INVALID)
    );
}
