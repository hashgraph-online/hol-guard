//! Replays runtime-hook saved-reuse inputs recorded from the Python owner
//! (`testdata/runtime_saved_reuse/record_vectors.py`).

use std::cell::Cell;

use guard_contracts::{RuntimeSavedLookupV1, RuntimeSavedReuseV1};
use serde_json::{json, Value};

use super::{saved_reuse_answer, saved_reuse_query};
use crate::hook_artifact_compose_reuse::saved_reuse;

const VECTORS: &str = include_str!("../testdata/runtime_saved_reuse/vectors.json");

fn vectors() -> Vec<Value> {
    let document: Value = serde_json::from_str(VECTORS).unwrap();
    assert_eq!(document["schema"], "guard-runtime-saved-reuse-vectors.v1");
    document["vectors"].as_array().unwrap().clone()
}

fn text(value: &Value) -> Option<String> {
    value.as_str().map(str::to_owned)
}

#[test]
fn recorded_saved_reuse_queries_replay() {
    let vectors = vectors();
    assert!(vectors.len() >= 30);
    for case in vectors {
        let name = case["name"].as_str().unwrap();
        let reuse: RuntimeSavedReuseV1 = serde_json::from_value(case["reuse"].clone())
            .unwrap_or_else(|error| panic!("{name}: {error}"));
        let recorded = case["validations"].as_array().unwrap();
        let mut calls: Vec<Value> = Vec::new();
        let diagnosed = Cell::new(false);
        let query = saved_reuse_query(
            &reuse,
            case["current_hash"].as_str().unwrap(),
            &case["composed"],
            |saved, current| {
                let call = recorded
                    .get(calls.len())
                    .unwrap_or_else(|| panic!("{name}: unrecorded token check"));
                assert_eq!((&call[0], &call[1]), (saved, current), "{name}");
                calls.push(call.clone());
                text(&call[2])
            },
            || {
                diagnosed.set(true);
                (text(&case["diagnosis"][0]), text(&case["diagnosis"][1]))
            },
        );
        assert_eq!(calls.len(), recorded.len(), "{name}: token checks");
        assert_eq!(
            diagnosed.get(),
            case["diagnosed"] == json!(true),
            "{name}: diagnosis"
        );
        assert_eq!(
            serde_json::to_value(&query).unwrap(),
            case["expected"],
            "{name}"
        );
    }
}

#[test]
fn answer_echoes_the_query_it_composed() {
    let reuse: RuntimeSavedReuseV1 =
        serde_json::from_value(json!({"current_action": "review"})).unwrap();
    let composed = json!({
        "lookup": {"decision": null, "ignored_local_integrity": null},
        "decision": null,
    });
    let answer = saved_reuse_answer(&reuse, "token-current", &composed, || {
        (
            Some("approval_reuse_content_changed".to_owned()),
            Some("token-stored".to_owned()),
        )
    });
    let query: guard_contracts::SavedReuseQueryV1 =
        serde_json::from_value(answer["query"].clone()).unwrap();
    assert_eq!(
        query.diagnostic_reason.as_deref(),
        Some("approval_reuse_content_changed")
    );
    assert_eq!(answer["answer"], saved_reuse(&query));
    assert_eq!(
        answer["answer"]["approval_reuse_source"],
        json!("invalidated_saved_policy")
    );
}

#[test]
fn runtime_reuse_rejects_unknown_fields() {
    let probe = json!({"harness": "codex", "artifact_id": "codex:x", "artifact_hash": "hash"});
    let saved: RuntimeSavedLookupV1 = serde_json::from_value(json!({
        "current": probe,
        "legacy": probe,
        "reuse": {"current_action": "allow", "cursor_native_token": "token"},
    }))
    .unwrap();
    assert_eq!(
        saved
            .reuse
            .and_then(|reuse| reuse.cursor_native_token)
            .as_deref(),
        Some("token")
    );
    let rejected = serde_json::from_value::<RuntimeSavedLookupV1>(json!({
        "current": probe,
        "legacy": probe,
        "reuse": {"current_action": "allow", "approval_context_inputs": {}},
    }));
    assert!(rejected.is_err());
}
