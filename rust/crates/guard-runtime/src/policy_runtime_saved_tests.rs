//! Replays runtime-hook saved-decision vectors recorded from the Python owner.

use std::io::Read;

use flate2::read::GzDecoder;
use guard_contracts::{PolicyLookupProbeGroupsV1, RuntimeSavedLookupV1};
use serde_json::{json, Value};

use super::{compose, Probe};

const VECTORS: &[u8] = include_bytes!("../tests/fixtures/runtime_saved_decision_vectors.json.gz");

fn vectors() -> Vec<Value> {
    let mut text = String::new();
    GzDecoder::new(VECTORS).read_to_string(&mut text).unwrap();
    let document: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(
        document["schema"],
        "guard-runtime-saved-decision-vectors.v1"
    );
    document["vectors"].as_array().unwrap().clone()
}

fn key(probe: &Probe<'_>) -> String {
    serde_json::to_string(&json!([
        probe.harness,
        probe.artifact_id,
        probe.artifact_hash,
        probe.workspace,
        probe.context,
    ]))
    .unwrap()
}

#[test]
fn recorded_runtime_saved_decisions_replay() {
    let vectors = vectors();
    assert!(vectors.len() >= 1000);
    for case in vectors {
        let name = case["name"].as_str().unwrap();
        let saved: RuntimeSavedLookupV1 = serde_json::from_value(case["runtime"].clone())
            .unwrap_or_else(|error| panic!("{name}: {error}"));
        let table = case["table"].as_object().unwrap();
        let actual = compose(&saved, |probe| {
            let key = key(probe);
            table
                .get(&key)
                .cloned()
                .ok_or_else(|| format!("{name}: unrecorded probe {key}"))
        })
        .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(actual, case["expected"], "{name}");
    }
}

fn probe(memory: bool) -> Value {
    let mut probe = json!({
        "harness": "codex",
        "artifact_id": "codex:project:tool-action:npm-test",
        "artifact_hash": "hash",
        "workspace": "/work/repo",
        "portable_workspace": null,
        "publisher": null,
    });
    if memory {
        probe["memory"] = json!({"command": "npm test", "artifact_type": "tool_action_request"});
    }
    probe
}

#[test]
fn degraded_store_skips_remembered_decision_probes() {
    let saved: RuntimeSavedLookupV1 =
        serde_json::from_value(json!({"current": probe(true), "legacy": probe(true)})).unwrap();
    let degraded = json!({
        "decision": null,
        "ignored_local_integrity": null,
        "trust_status": {"remembered_rules": "disabled_degraded", "trusted": false},
        "authority_revision": -1,
    });
    let mut probes = 0;
    let actual = compose(&saved, |_probe| {
        probes += 1;
        Ok(degraded.clone())
    })
    .unwrap();
    assert_eq!(probes, 2);
    assert_eq!(actual, json!({"lookup": degraded, "decision": null}));
}

#[test]
fn runtime_probes_reject_unknown_fields() {
    let mut extra = probe(false);
    extra["consume_one_shot"] = json!(true);
    let rejected = serde_json::from_value::<RuntimeSavedLookupV1>(
        json!({"current": extra, "legacy": probe(false)}),
    );
    assert!(rejected.is_err());
    let rejected = serde_json::from_value::<RuntimeSavedLookupV1>(
        json!({"current": probe(false), "legacy": probe(false), "fallback": probe(false)}),
    );
    assert!(rejected.is_err());
    let groups: PolicyLookupProbeGroupsV1 = serde_json::from_value(json!({
        "groups": [],
        "runtime": {"current": probe(false), "legacy": probe(false)},
    }))
    .unwrap();
    assert!(groups
        .runtime
        .is_some_and(|runtime| runtime.alias.is_none()));
}
