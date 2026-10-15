//! Replays OpenClaw detection vectors recorded from the original Python
//! implementation (see `testdata/openclaw/record_openclaw_vectors.py`).
//! Fixture trees and expected artifacts, paths and warnings come from Python,
//! never from Rust output. `<ROOT>` is the fixture root, and `<DIGEST path>`
//! is the digest Python took of that resolved path, retaken under this root.

use std::fs;

use regex::Regex;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::guard_store_cmd_vectors_tests::temp_home;
use crate::openclaw_detect::detect;
use crate::pi_vectors_tests::{materialize, release, substitute};
use crate::runner_authority_op::KindResult;

const VECTORS: &str = include_str!("../testdata/openclaw/vectors.json");

/// Swaps each `<DIGEST path>` token for the digest of `path` under the
/// canonical fixture root.
fn undigest(value: &Value, canonical_root: &str) -> Value {
    let token = Regex::new(r"<DIGEST (<ROOT>[^>]*)>").unwrap();
    match value {
        Value::String(text) => Value::String(
            token
                .replace_all(text, |captures: &regex::Captures<'_>| {
                    let path = captures[1].replace("<ROOT>", canonical_root);
                    hex::encode(Sha256::digest(path.as_bytes()))[..12].to_owned()
                })
                .into_owned(),
        ),
        Value::Array(items) => Value::Array(
            items
                .iter()
                .map(|item| undigest(item, canonical_root))
                .collect(),
        ),
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(key, item)| (key.clone(), undigest(item, canonical_root)))
                .collect(),
        ),
        other => other.clone(),
    }
}

fn check(case: &Value, name: &str, roots: (&str, &str), result: KindResult) -> Result<(), String> {
    if case["refused"] == true {
        return match result {
            Err(_) => Ok(()),
            Ok(answer) => Err(format!(
                "{name}: expected a refusal, the resident answered {answer}"
            )),
        };
    }
    let answer = result.map_err(|code| format!("{name}: resident refused with {code}"))?;
    let (root_text, canonical_root) = roots;
    let mismatches: Vec<String> = ["artifacts", "found_paths", "warnings"]
        .into_iter()
        .filter_map(|field| {
            let expected = substitute(&undigest(&case[field], canonical_root), root_text);
            (answer[field] != expected).then(|| {
                format!(
                    "{name}: {field}\n  resident: {}\n  python:   {expected}",
                    answer[field]
                )
            })
        })
        .collect();
    if mismatches.is_empty() {
        Ok(())
    } else {
        Err(mismatches.join("\n"))
    }
}

#[test]
fn replays_every_recorded_openclaw_detection_case() {
    let vectors: Value = serde_json::from_str(VECTORS).unwrap();
    assert_eq!(vectors["schema"], "guard-openclaw-vectors.v1");
    let mut replayed = 0;
    let mut failures = Vec::new();
    for case in vectors["cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let root = temp_home(&format!("oc-{name}").chars().take(60).collect::<String>());
        materialize(&root, case);
        let root_text = root.to_string_lossy().into_owned();
        let canonical = fs::canonicalize(&root).unwrap();
        let canonical_root = canonical.to_string_lossy().into_owned();
        let result = detect(&substitute(&case["args"], &root_text));
        if let Err(message) = check(
            case,
            name,
            (root_text.as_str(), canonical_root.as_str()),
            result,
        ) {
            failures.push(message);
        }
        release(&root);
        replayed += 1;
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
    assert!(replayed >= 25, "only {replayed} cases recorded");
}

#[test]
fn malformed_requests_are_refused() {
    let valid = json!({
        "harness": "openclaw",
        "home": "/nonexistent/home",
        "workspace": null,
        "config_path": "/nonexistent/home/.openclaw/openclaw.json",
        "payload": "{}",
    });
    assert!(detect(&valid).is_ok(), "the valid request is answered");
    for (key, value) in [
        ("harness", json!("opencode")),
        ("config_path", Value::Null),
        ("config_path", json!("relative/openclaw.json")),
        ("payload", Value::Null),
        ("payload", json!({})),
        ("payload", json!("[]")),
        ("payload", json!("{not json")),
    ] {
        let mut request = valid.clone();
        request[key] = value.clone();
        assert!(detect(&request).is_err(), "{key}={value} must be refused");
    }
}
