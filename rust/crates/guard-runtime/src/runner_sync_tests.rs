//! Replays vectors recorded from the Python Guard Cloud sync helpers before
//! they moved here (`tests/fixtures/runner_sync_authority/vectors.json`).

use serde_json::Value;

use super::dispatch;

const VECTORS: &str = include_str!("../../../../tests/fixtures/runner_sync_authority/vectors.json");

#[test]
fn recorded_python_vectors_replay_exactly() {
    let document: Value = serde_json::from_str(VECTORS).unwrap();
    assert_eq!(document["version"], 1);
    let vectors = document["vectors"].as_array().unwrap();
    assert!(vectors.len() > 800);
    let mut mismatches = Vec::new();
    for vector in vectors {
        let kind = vector["kind"].as_str().unwrap();
        let actual = dispatch(kind, &vector["args"]);
        if actual.as_ref() != Ok(&vector["expected"]) {
            mismatches.push(format!("{kind} / {}", vector["name"]));
        }
    }
    assert!(mismatches.is_empty(), "{mismatches:#?}");
}

#[test]
fn malformed_sync_arguments_are_typed_errors() {
    for kind in [
        "sync_url",
        "pain_signal_batch",
        "value_metrics",
        "completed_event_ids",
        "canonical_rollout",
        "downgrade_reference",
        "policy_simulation",
    ] {
        assert!(
            dispatch(kind, &Value::from("not-an-object")).is_err(),
            "{kind}"
        );
        assert!(dispatch(kind, &serde_json::json!({})).is_err(), "{kind}");
    }
}
