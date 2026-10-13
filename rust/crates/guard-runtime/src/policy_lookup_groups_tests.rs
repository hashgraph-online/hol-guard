//! Replays generic-hook saved-decision vectors recorded from the Python owner.

use std::io::Read;

use flate2::read::GzDecoder;
use guard_contracts::PolicyLookupProbeGroupsV1;
use serde_json::{json, Value};

use super::{compose_groups, with_current_token};

const VECTORS: &[u8] = include_bytes!("../tests/fixtures/generic_saved_decision_vectors.json.gz");

fn vectors() -> Vec<Value> {
    let mut text = String::new();
    GzDecoder::new(VECTORS).read_to_string(&mut text).unwrap();
    let document: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(
        document["schema"],
        "guard-generic-saved-decision-vectors.v1"
    );
    document["vectors"].as_array().unwrap().clone()
}

fn degraded() -> Value {
    json!({
        "decision": null,
        "ignored_local_integrity": null,
        "trust_status": {"remembered_rules": "disabled_degraded", "trusted": false},
        "authority_revision": -1,
    })
}

#[test]
fn recorded_generic_saved_decisions_replay() {
    let vectors = vectors();
    assert!(vectors.len() >= 400);
    for case in vectors {
        let name = case["name"].as_str().unwrap();
        let groups: PolicyLookupProbeGroupsV1 = serde_json::from_value(json!({
            "portable_workspace": case["portable_workspace"],
            "groups": case["groups"],
        }))
        .unwrap_or_else(|error| panic!("{name}: {error}"));
        let table = &case["table"];
        let is_degraded = case["degraded"].as_bool().unwrap();
        let actual = compose_groups(&groups, case["workspace"].as_str(), |id, hash, at| {
            if is_degraded {
                return Ok(degraded());
            }
            let key = serde_json::to_string(&json!([id, hash, at])).unwrap();
            table
                .get(&key)
                .cloned()
                .ok_or_else(|| format!("{name}: missing probe {key}"))
        })
        .unwrap_or_else(|error| panic!("{name}: {error}"));
        assert_eq!(actual, case["expected"], "{name}");
    }
}

#[test]
fn group_and_candidate_counts_are_bounded() {
    let probe = |_: &str, _: &str, _: Option<&str>| Ok(degraded());
    let empty: PolicyLookupProbeGroupsV1 = serde_json::from_value(json!({"groups": []})).unwrap();
    assert!(compose_groups(&empty, None, probe).is_err());
    let no_ids: PolicyLookupProbeGroupsV1 = serde_json::from_value(json!({
        "groups": [{"artifact_hash": "h", "candidate_artifact_ids": []}],
    }))
    .unwrap();
    assert!(compose_groups(&no_ids, None, probe).is_err());
    let many: PolicyLookupProbeGroupsV1 = serde_json::from_value(json!({
        "groups": vec![json!({"artifact_hash": "h", "candidate_artifact_ids": ["a"]}); 5],
    }))
    .unwrap();
    assert!(compose_groups(&many, None, probe).is_err());
}

#[test]
fn unknown_probe_group_fields_are_rejected() {
    let parsed = serde_json::from_value::<PolicyLookupProbeGroupsV1>(json!({
        "groups": [],
        "degraded_trust_status": {},
    }));
    assert!(parsed.is_err());
}

#[test]
fn current_token_fills_groups_and_drops_a_repeated_legacy_group() {
    let groups: PolicyLookupProbeGroupsV1 = serde_json::from_value(json!({
        "groups": [
            {"candidate_artifact_ids": ["a", "a#memory"]},
            {"candidate_artifact_ids": ["policy:a"]},
            {"artifact_hash": "token", "candidate_artifact_ids": ["a", "a#memory"]},
            {"artifact_hash": "legacy", "candidate_artifact_ids": ["a", "a#memory"]},
        ],
    }))
    .unwrap();
    let resolved = with_current_token(&groups, Some("token")).unwrap();
    let hashes: Vec<_> = resolved
        .groups
        .iter()
        .map(|group| {
            (
                group.artifact_hash.as_deref(),
                group.candidate_artifact_ids.len(),
            )
        })
        .collect();
    assert_eq!(
        hashes,
        [(Some("token"), 2), (Some("token"), 1), (Some("legacy"), 2)]
    );
    assert!(with_current_token(&groups, None).is_err());
}
