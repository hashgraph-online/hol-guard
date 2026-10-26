//! The transition diagnostic against Python's `_write_transition_observation`
//! for the same hook input and daemon answer.

use serde_json::Value;

use super::*;

/// Recorded from `_write_transition_observation(data, response)`.
const VECTORS: &str = include_str!("../testdata/codex_hook_bridge/transition_observation.json");

#[test]
fn the_observation_line_matches_python() {
    let vectors: Value = serde_json::from_str(VECTORS).unwrap();
    let vectors = vectors.as_array().unwrap();
    assert!(vectors.len() >= 40);
    let mut written = 0;
    for vector in vectors {
        let case = vector["case"].as_str().unwrap();
        let hook_input = vector["hook_input"].as_str().unwrap();
        let response = pyjson::parse_mapping_lone_surrogates(vector["response"].as_str().unwrap())
            .unwrap()
            .value;
        let expected = vector["stderr"].as_str().unwrap();
        let actual = response
            .get("guard_transition_observation")
            .and_then(|envelope| observation_line(hook_input, envelope));
        if expected.is_empty() {
            assert_eq!(actual, None, "{case}");
        } else {
            written += 1;
            assert_eq!(actual.as_deref(), Some(expected), "{case}");
        }
    }
    assert!(written >= 5);
}

#[test]
fn only_canonical_uuids_name_an_operation() {
    assert!(canonical_uuid("123e4567-e89b-12d3-a456-426614174000"));
    assert!(!canonical_uuid("123E4567-E89B-12D3-A456-426614174000"));
    assert!(!canonical_uuid("123e4567e89b12d3a456426614174000"));
    assert!(!canonical_uuid("123e4567-e89b-12d3-a456-42661417400"));
    assert!(!canonical_uuid("{123e4567-e89b-12d3-a456-426614174000}"));
}

#[test]
fn probe_requests_carry_a_lowercase_hex_suffix() {
    assert!(probe_request(&format!(
        "transition-hook-{}",
        "a1".repeat(16)
    )));
    assert!(!probe_request(&format!(
        "transition-hook-{}",
        "A1".repeat(16)
    )));
    assert!(!probe_request(&format!(
        "transition-hook-{}",
        "a".repeat(31)
    )));
    assert!(!probe_request(&format!("transition-{}", "a".repeat(32))));
}

#[test]
fn a_hook_without_a_probe_writes_nothing() {
    let envelope = PyVal::Dict(Vec::new());
    assert_eq!(
        observation_line(r#"{"hook_event_name":"PreToolUse"}"#, &envelope),
        None
    );
    assert_eq!(observation_line("not json", &envelope), None);
}
