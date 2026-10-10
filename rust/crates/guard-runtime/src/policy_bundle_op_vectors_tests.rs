//! Parity vectors recorded from the retired Python implementation.
//!
//! Every case is `{kind, input, expected}` where `input` is the exact wire
//! input of the `PolicyBundleAuthority` op and `expected` is the verdict the
//! Python code produced for the same arguments before it was removed.

use std::collections::BTreeMap;
use std::io::Read;

use flate2::read::GzDecoder;
use guard_contracts::{
    PolicyBundleAuthorityRequestV1, POLICY_BUNDLE_AUTHORITY_REQUEST_SCHEMA,
    POLICY_BUNDLE_AUTHORITY_RESULT_SCHEMA,
};
use serde_json::Value;

use crate::policy_bundle_op::evaluate_policy_bundle_authority_request;

const VECTORS: &[u8] = include_bytes!("../tests/fixtures/policy_bundle_authority_vectors.json.gz");

fn load() -> Vec<Value> {
    let mut text = String::new();
    GzDecoder::new(VECTORS).read_to_string(&mut text).unwrap();
    let mut document: Value = serde_json::from_str(&text).unwrap();
    match document["cases"].take() {
        Value::Array(cases) => cases,
        _ => panic!("fixture has no cases"),
    }
}

pub(crate) fn run(kind: &str, input: Value) -> Value {
    let request = PolicyBundleAuthorityRequestV1 {
        schema: POLICY_BUNDLE_AUTHORITY_REQUEST_SCHEMA.to_owned(),
        request_id: "vector".to_owned(),
        kind: kind.to_owned(),
        input,
    };
    let bytes = evaluate_policy_bundle_authority_request(&request).unwrap();
    let response: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(response["schema"], POLICY_BUNDLE_AUTHORITY_RESULT_SCHEMA);
    assert_eq!(response["request_id"], "vector");
    assert_eq!(response["status"], "ok", "{kind}: {response}");
    response["result"].clone()
}

fn normalized(mut value: Value) -> Value {
    if let Some(Value::Array(keys)) = value.get_mut("payload_keys") {
        keys.sort_by_key(|key| key.as_str().unwrap_or_default().to_owned());
    }
    value
}

#[test]
fn every_recorded_python_verdict_is_reproduced() {
    let cases = load();
    assert!(cases.len() > 30_000, "fixture unexpectedly small");
    let mut failures: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut seen: BTreeMap<String, usize> = BTreeMap::new();
    for case in &cases {
        let kind = case["kind"].as_str().unwrap();
        *seen.entry(kind.to_owned()).or_default() += 1;
        let actual = normalized(run(kind, case["input"].clone()));
        if actual != case["expected"] {
            let note = format!(
                "input={} note={} expected={} actual={}",
                case["input"]
                    .to_string()
                    .chars()
                    .take(1500)
                    .collect::<String>(),
                case["note"],
                case["expected"]
                    .to_string()
                    .chars()
                    .take(300)
                    .collect::<String>(),
                actual.to_string().chars().take(300).collect::<String>()
            );
            failures.entry(kind.to_owned()).or_default().push(note);
        }
    }
    let total: usize = failures.values().map(Vec::len).sum();
    for (kind, list) in &failures {
        eprintln!("== {kind}: {} mismatches of {}", list.len(), seen[kind]);
        for line in list.iter().take(4) {
            eprintln!("   {line}");
        }
    }
    assert_eq!(
        total, 0,
        "{total} vectors diverge from recorded Python behavior"
    );
    assert!(seen.len() >= 20, "every kind must be covered: {seen:?}");
}
