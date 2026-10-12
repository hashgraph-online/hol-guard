//! Selector matching and highest-version selection agree with vectors
//! recorded from the Python matcher that this resident implementation replaced.

use guard_command::js_semver::{highest_js_version_for_selector, version_matches_js_selector};
use serde_json::Value;

const VECTORS: &str =
    include_str!("../../../../tests/fixtures/supply-chain-eval/js-semver-cases.v1.json");

fn vectors() -> Value {
    serde_json::from_str(VECTORS).expect("vectors parse")
}

#[test]
fn selector_matching_agrees_with_recorded_vectors() {
    let vectors = vectors();
    let cases = vectors["matches"].as_array().expect("matches array");
    assert!(cases.len() > 80);
    for case in cases {
        let version = case["version"].as_str().expect("version");
        let selector = case["selector"].as_str().expect("selector");
        let expected = case["matches"].as_bool().expect("matches");
        assert_eq!(
            version_matches_js_selector(version, selector),
            expected,
            "version {version:?} against selector {selector:?}"
        );
    }
}

#[test]
fn highest_version_selection_agrees_with_recorded_vectors() {
    let vectors = vectors();
    let cases = vectors["highest"].as_array().expect("highest array");
    assert!(!cases.is_empty());
    for case in cases {
        let versions: Vec<String> = case["versions"]
            .as_array()
            .expect("versions")
            .iter()
            .map(|value| value.as_str().expect("version").to_owned())
            .collect();
        let selector = case["selector"].as_str().expect("selector");
        let expected = case["highest"].as_str();
        assert_eq!(
            highest_js_version_for_selector(&versions, selector),
            expected,
            "versions {versions:?} against selector {selector:?}"
        );
    }
}
