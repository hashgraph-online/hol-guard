//! Parity tests for the inventory serializer-redaction port.
//!
//! Every expectation comes from running the real Python functions in
//! `scripts/ci/generate_inventory_redaction_parity.py`; regenerate the fixture
//! after changing either side.

use serde_json::{Map, Value};

use super::{
    assert_serialized_inventory_payload_safe, classify_endpoint_host, redact_headers, redact_url,
    safe_json, safe_source_detail, sanitize_serializer_string,
};
use crate::inventory_fingerprints::{python_json, DEFAULT_SEPARATORS};

const PARITY: &str = include_str!("../testdata/inventory_redaction_parity.json");
const URL_PARITY: &str = include_str!("../testdata/inventory_url_parity.json");

fn section(name: &str) -> Vec<Value> {
    let document: Value = serde_json::from_str(PARITY).expect("parity fixture parses");
    document
        .get(name)
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("fixture section {name}"))
        .clone()
}

fn text(case: &Value, key: &str) -> String {
    case.get(key)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("case field {key}"))
        .to_string()
}

#[test]
fn sanitize_serializer_string_matches_python() {
    for case in section("sanitize_serializer_string") {
        let value = text(&case, "value");
        let parent_key = text(&case, "parent_key");
        let parent_sensitive = case
            .get("parent_sensitive")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        assert_eq!(
            sanitize_serializer_string(&value, &parent_key, parent_sensitive),
            text(&case, "expected"),
            "value {value:?} under key {parent_key:?} sensitive={parent_sensitive}",
        );
    }
}

#[test]
fn safe_json_matches_python() {
    for case in section("safe_json") {
        let value = case.get("value").expect("case value").clone();
        let expected = case.get("expected").expect("case expected").clone();
        assert_eq!(safe_json(&value, "", false), expected, "value {value}");
    }
}

#[test]
fn payload_safety_matches_python() {
    for case in section("assert_payload_safe") {
        let payload = case.get("payload").expect("case payload").clone();
        let expected = case
            .get("safe")
            .and_then(Value::as_bool)
            .expect("case safe flag");
        assert_eq!(
            assert_serialized_inventory_payload_safe(&payload).is_ok(),
            expected,
            "payload {payload}",
        );
    }
}

#[test]
fn source_detail_matches_python() {
    for case in section("safe_source_detail") {
        let run = case
            .get("run")
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_else(Map::new);
        assert_eq!(
            safe_source_detail(&run),
            text(&case, "expected"),
            "run {case}",
        );
    }
}

#[test]
fn sorted_json_matches_python_dumps() {
    for case in section("sorted_json") {
        let value = case.get("value").expect("case value").clone();
        assert_eq!(
            python_json(&value, DEFAULT_SEPARATORS),
            text(&case, "expected"),
            "value {value}",
        );
    }
}

fn url_section(name: &str) -> Vec<Value> {
    let document: Value = serde_json::from_str(URL_PARITY).expect("url parity fixture parses");
    document
        .get(name)
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("fixture section {name}"))
        .clone()
}

#[test]
fn redact_url_matches_python() {
    for case in url_section("redact_url") {
        let url = text(&case, "url");
        assert_eq!(redact_url(&url), text(&case, "expected"), "url {url:?}");
    }
}

#[test]
fn classify_endpoint_host_matches_python() {
    for case in url_section("classify_endpoint_host") {
        let value = case.get("value").and_then(Value::as_str);
        assert_eq!(
            classify_endpoint_host(value),
            text(&case, "expected"),
            "value {value:?}",
        );
    }
}

#[test]
fn redact_headers_matches_python() {
    for case in url_section("redact_headers") {
        let names: Vec<String> = case
            .get("names")
            .and_then(Value::as_array)
            .expect("case field names")
            .iter()
            .map(|name| name.as_str().unwrap_or_default().to_string())
            .collect();
        let expected: Vec<(String, String)> = case
            .get("expected")
            .and_then(Value::as_array)
            .expect("case field expected")
            .iter()
            .map(|pair| {
                let entries = pair.as_array().expect("header pair");
                (
                    entries[0].as_str().unwrap_or_default().to_string(),
                    entries[1].as_str().unwrap_or_default().to_string(),
                )
            })
            .collect();
        assert_eq!(redact_headers(&names), expected, "headers {names:?}");
    }
}
