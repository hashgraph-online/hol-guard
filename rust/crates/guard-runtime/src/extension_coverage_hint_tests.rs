use super::*;

const DIGEST: &str = "ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12";

fn result(extensions: Value, model: Value) -> Map<String, Value> {
    json!({"command_extensions": extensions, "command_model": model})
        .as_object()
        .cloned()
        .unwrap()
}

fn evidence() -> Value {
    json!({
        "binding": {"catalog_digest": DIGEST},
        "observations": [
            {
                "extension_id": "command.git",
                "rule_id": "command.git.push",
                "effective_segment_indexes": [2],
                "matcher_evidence": [
                    {"segment_index": 2, "executable": "git"},
                    {"segment_index": 2, "executable": "ignored"},
                ],
            },
            {"extension_id": "not-a-catalog-id", "rule_id": "command.x.y", "effective_segment_indexes": [0]},
        ],
        "permission_observations": [
            {
                "extension_id": "command.git",
                "permission_id": "command.git.remote-write",
                "effective_segment_indexes": [2, 0, true, 256],
            },
        ],
    })
}

#[test]
fn names_the_extension_on_each_step_it_matched() {
    let hint = compute(&result(evidence(), json!({"segments": [{}, {}, {}]}))).unwrap();
    assert_eq!(
        hint,
        json!({
            "schema": EXTENSION_COVERAGE_HINT_SCHEMA,
            "catalog_digest": DIGEST,
            "segments": [
                {
                    "index": 0,
                    "executable": null,
                    "extension_ids": ["command.git"],
                    "rule_ids": [],
                    "permission_ids": ["command.git.remote-write"],
                },
                {
                    "index": 2,
                    "executable": "git",
                    "extension_ids": ["command.git"],
                    "rule_ids": ["command.git.push"],
                    "permission_ids": ["command.git.remote-write"],
                },
            ],
            "segment_total": 3,
        })
    );
}

#[test]
fn a_model_without_segments_leaves_the_total_out() {
    let hint = compute(&result(evidence(), json!({"normalized_text": "git push"}))).unwrap();
    assert!(hint.get("segment_total").is_none());
}

#[test]
fn a_total_too_small_for_the_covered_steps_drops_the_hint() {
    assert_eq!(
        compute(&result(evidence(), json!({"segments": [{}, {}]}))),
        None
    );
}

#[test]
fn no_hint_without_usable_evidence() {
    let mut failed = evidence();
    failed["evaluation_error"] = json!("native_command_extension_evidence_invalid");
    assert_eq!(compute(&result(failed, Value::Null)), None);
    let mut undigested = evidence();
    undigested["binding"]["catalog_digest"] = json!(DIGEST.to_uppercase());
    assert_eq!(compute(&result(undigested, Value::Null)), None);
    let unobserved = json!({"binding": {"catalog_digest": DIGEST}, "observations": []});
    assert_eq!(compute(&result(unobserved, Value::Null)), None);
    assert_eq!(compute(&Map::new()), None);
}

#[test]
fn coverage_rides_on_an_allow_hint_or_stands_alone() {
    let coverage = json!({"schema": EXTENSION_COVERAGE_HINT_SCHEMA});
    let allow = json!({"schema": "guard.extension-allow-hint.v1"});
    assert_eq!(with_coverage(None, None), None);
    assert_eq!(
        with_coverage(Some(allow.clone()), None),
        Some(allow.clone())
    );
    assert_eq!(
        with_coverage(None, Some(coverage.clone())),
        Some(coverage.clone())
    );
    assert_eq!(
        with_coverage(Some(allow), Some(coverage.clone())).unwrap()["coverage"],
        coverage
    );
}

fn observation(rule_id: &str, match_class: &str, index: u64) -> Value {
    json!({
        "extension_id": "command.git",
        "rule_id": rule_id,
        "match_class": match_class,
        "effective_segment_indexes": [index],
        "matcher_evidence": [{"segment_index": index, "executable": "git"}],
    })
}

fn observed(observations: Vec<Value>) -> Value {
    json!({"binding": {"catalog_digest": DIGEST}, "observations": observations})
}

#[test]
fn a_rule_matched_only_as_uncertainty_is_named_as_uncertain() {
    let hint = compute(&result(
        observed(vec![
            observation("command.git.push", "uncertainty", 0),
            observation("command.git.hard-reset", "unsafe", 0),
        ]),
        Value::Null,
    ))
    .unwrap();
    let step = &hint["segments"][0];
    assert_eq!(
        step["rule_ids"],
        json!(["command.git.push", "command.git.hard-reset"])
    );
    assert_eq!(step["uncertain_rule_ids"], json!(["command.git.push"]));
}

#[test]
fn a_rule_that_also_matched_plainly_is_not_uncertain() {
    let hint = compute(&result(
        observed(vec![
            observation("command.git.push", "uncertainty", 0),
            observation("command.git.push", "unsafe", 0),
            observation("command.git.push", "uncertainty", 1),
        ]),
        Value::Null,
    ))
    .unwrap();
    assert!(hint["segments"][0].get("uncertain_rule_ids").is_none());
    assert_eq!(
        hint["segments"][1]["uncertain_rule_ids"],
        json!(["command.git.push"])
    );
}

#[test]
fn validation_keeps_uncertain_ids_only_when_they_name_matched_rules() {
    let stored = |uncertain: Value| {
        json!({
            "schema": EXTENSION_COVERAGE_HINT_SCHEMA,
            "catalog_digest": DIGEST,
            "segments": [{
                "index": 0,
                "executable": "git",
                "extension_ids": ["command.git"],
                "rule_ids": ["command.git.push"],
                "permission_ids": [],
                "uncertain_rule_ids": uncertain,
            }],
        })
    };
    let kept = validated(&stored(json!(["command.git.push"]))).unwrap();
    assert_eq!(
        kept["segments"][0]["uncertain_rule_ids"],
        json!(["command.git.push"])
    );
    // A hint stored before the key existed, or with nothing uncertain.
    for absent in [Value::Null, json!([])] {
        let checked = validated(&stored(absent)).unwrap();
        assert!(checked["segments"][0].get("uncertain_rule_ids").is_none());
    }
    // An id the step never matched, or not a catalog id, is not this hint.
    assert_eq!(validated(&stored(json!(["command.git.hard-reset"]))), None);
    assert_eq!(validated(&stored(json!(["push"]))), None);
    assert_eq!(validated(&stored(json!("command.git.push"))), None);
}
