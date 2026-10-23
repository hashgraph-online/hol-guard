use super::*;
use serde_json::{json, Value};

const SOURCE: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const CONFIG: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

fn six_records() -> (Vec<u8>, BTreeMap<String, Vec<u8>>) {
    let records: BTreeMap<String, Vec<u8>> = ROLES
        .iter()
        .map(|role| {
            (
                (*role).to_owned(),
                format!("{{\"role\":\"{role}\"}}\n").into_bytes(),
            )
        })
        .collect();
    let cells: Vec<Value> = ROLES
        .iter()
        .map(|role| {
            json!({
                "episode_id": role,
                "status": "passed",
                "record_sha256": sha256(&records[*role]),
            })
        })
        .collect();
    let report = json!({
        "schema": "gauntlet-ci-check.v1",
        "profile": "deterministic",
        "status": "passed",
        "exit_code": 0,
        "expected_guard_source_sha": SOURCE,
        "guard_source_sha": SOURCE,
        "runner_config_digest": CONFIG,
        "model_tokens": 0,
        "model_requests": 0,
        "model_usage_known": true,
        "selected_cases": 6,
        "cells": cells,
    });
    (report.to_string().into_bytes(), records)
}

#[test]
fn complete_six_role_hashes_are_available_only_as_ineligible_bytes() {
    let (report, records) = six_records();
    let observed =
        verify_six_deterministic_control_records(&report, records, SOURCE, CONFIG, 0).unwrap();
    assert_eq!(observed.digests.len(), 6);
    assert_eq!(
        observed.record_bytes("injection").unwrap(),
        b"{\"role\":\"injection\"}\n"
    );
    assert!(observed.record_bytes("not-a-role").is_none());
    assert!(!observed.execution_eligible);
    assert!(!observed.report.execution_eligible);
}

#[test]
fn changed_missing_or_malformed_record_refuses_the_complete_set() {
    let (report, mut records) = six_records();
    records.get_mut("success").unwrap().push(b' ');
    assert!(verify_six_deterministic_control_records(&report, records, SOURCE, CONFIG, 0).is_err());
    let (report, mut records) = six_records();
    records.remove("cancel");
    assert!(verify_six_deterministic_control_records(&report, records, SOURCE, CONFIG, 0).is_err());
    let (report, mut records) = six_records();
    records.insert(
        "success".to_owned(),
        b"{\"role\":\"x\",\"role\":\"y\"}".to_vec(),
    );
    assert!(verify_six_deterministic_control_records(&report, records, SOURCE, CONFIG, 0).is_err());
}

#[test]
fn duplicate_role_missing_hash_and_wrong_outside_pin_refuse() {
    let (report, records) = six_records();
    let mut value: Value = serde_json::from_slice(&report).unwrap();
    value["cells"][1]["episode_id"] = json!("success");
    assert!(verify_six_deterministic_control_records(
        value.to_string().as_bytes(),
        records.clone(),
        SOURCE,
        CONFIG,
        0,
    )
    .is_err());
    value["cells"][1]["episode_id"] = json!("input-binding");
    value["cells"][1]
        .as_object_mut()
        .unwrap()
        .remove("record_sha256");
    assert!(verify_six_deterministic_control_records(
        value.to_string().as_bytes(),
        records.clone(),
        SOURCE,
        CONFIG,
        0,
    )
    .is_err());
    assert!(
        verify_six_deterministic_control_records(&report, records, &"0".repeat(40), CONFIG, 0,)
            .is_err()
    );
}
