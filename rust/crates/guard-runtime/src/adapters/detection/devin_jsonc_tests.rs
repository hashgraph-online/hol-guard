//! Replays Devin JSONC vectors recorded from the original Python parser (see
//! `testdata/devin/record_devin_jsonc_vectors.py`). Expected payloads and
//! flags come from Python, never from Rust output.

use serde_json::{json, Value};

use crate::devin_jsonc::{document, parse, parse_jsonc};
use crate::pyjson::{parse_marking_lone_surrogates, PyVal};
use crate::runner_authority_op::ERR_INVALID;

const VECTORS: &str = include_str!("../../../testdata/devin/jsonc_vectors.json");

/// `{:?}` compares NaN with NaN, which `PartialEq` never does.
fn shown(value: &PyVal) -> String {
    format!("{value:?}")
}

#[test]
fn replays_every_recorded_devin_jsonc_case() {
    let vectors: Value = serde_json::from_str(VECTORS).unwrap();
    assert_eq!(vectors["schema"], "guard-devin-jsonc-vectors.v1");
    let mut failures = Vec::new();
    let cases = vectors["cases"].as_array().unwrap();
    for case in cases {
        let name = case["name"].as_str().unwrap();
        let text = case["text"].as_str().unwrap();
        let answer = parse(text);
        if case["refused"] == true {
            if answer.is_ok() {
                failures.push(format!("{name}: parsed input Python refuses"));
            }
            continue;
        }
        let Ok(answer) = answer else {
            failures.push(format!("{name}: refused input Python parses"));
            continue;
        };
        let payload = parse_marking_lone_surrogates(case["payload"].as_str().unwrap()).unwrap();
        let decoded = answer
            .source
            .as_deref()
            .map(|source| parse_marking_lone_surrogates(source).unwrap())
            .unwrap_or(PyVal::Dict(Vec::new()));
        let flags = (answer.had_comments, answer.parse_failed);
        let expected = (case["had_comments"] == true, case["parse_failed"] == true);
        if shown(&answer.payload) != shown(&payload)
            || shown(&decoded) != shown(&payload)
            || flags != expected
        {
            failures.push(format!(
                "{name}: {:?} {flags:?}, expected {payload:?} {expected:?}",
                answer.payload
            ));
        }
        let detected = parse_jsonc(text).unwrap();
        let expected_detected = (!expected.1).then_some(shown(&payload));
        if detected.as_ref().map(shown) != expected_detected {
            failures.push(format!("{name}: devin_detect view {detected:?}"));
        }
    }
    assert!(cases.len() >= 30, "{} cases", cases.len());
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn the_kind_answers_the_source_text_and_flags() {
    let answer = document(&json!({"text": "// c\n{\"a\": [1,],}"})).unwrap();
    assert_eq!(
        answer,
        json!({"source": "\n{\"a\": [1]}", "had_comments": true, "parse_failed": false})
    );
    let answer = document(&json!({"text": "{\"a\": 1}"})).unwrap();
    assert_eq!(answer["source"], "{\"a\": 1}");
    let answer = document(&json!({"text": "[1]"})).unwrap();
    assert_eq!(
        answer,
        json!({"source": null, "had_comments": false, "parse_failed": true})
    );
}

#[test]
fn input_python_cannot_decode_is_refused() {
    let deep = format!("{}{}", "[".repeat(2000), "]".repeat(2000));
    assert!(parse(&deep).is_err());
    assert!(document(&json!({"text": format!("// c\n{{\"a\": {}}}", "9".repeat(5000))})).is_err());
}

#[test]
fn malformed_requests_are_refused() {
    for args in [
        json!([]),
        json!({}),
        json!({"text": 5}),
        json!({"text": "{}", "extra": 1}),
    ] {
        assert_eq!(document(&args), Err(ERR_INVALID));
    }
}
