//! Containment evidence cases for `protection_health_facts`, sharing the
//! fact fixtures in `protection_health_facts_tests`.

use serde_json::{json, Value};

use crate::protection_health_facts::CONTAINMENT_CHECK_IDS;
use crate::protection_health_facts_tests::{collect, evidence, pair, row, sha, NOW};

fn evidence_with(key: &str, value: Value) -> Value {
    let mut evidence = evidence();
    evidence[key] = value;
    evidence
}

fn containment_rows(overrides: Value) -> Vec<(String, String)> {
    let signals = collect(overrides);
    CONTAINMENT_CHECK_IDS
        .iter()
        .map(|check_id| row(&signals, check_id))
        .collect()
}

fn daemon_with(containment_health: Value) -> Value {
    json!({"daemon": {
        "registration_status": null,
        "last_heartbeat_at": NOW,
        "containment_health": containment_health,
    }})
}

#[test]
fn compatible_health_proves_the_containment_owned_checks() {
    assert_eq!(
        containment_rows(json!({})),
        [
            pair("pass", "policy_engine_compatible"),
            pair("pass", "decision_plane_compatible"),
            pair("pass", "containment_compatible"),
            pair("pass", "containment_backend_enforced"),
        ]
    );
}

#[test]
fn containment_faults_fail_closed() {
    let cases = [
        (
            evidence_with("backend", json!("unsupported")),
            "unsupported_platform",
        ),
        (
            evidence_with("probe_enforced", json!(false)),
            "containment_probe_failed",
        ),
        (
            evidence_with("probe_at", json!("2026-07-19T14:54:00+00:00")),
            "containment_probe_stale",
        ),
        (
            evidence_with("probe_at", json!("2026-07-19T15:00:06+00:00")),
            "containment_probe_future",
        ),
        (
            evidence_with("policy_contract_digest", json!(sha(b"other"))),
            "policy_version_mismatch",
        ),
        (
            evidence_with("effect_decision_schema_version", json!("9.9.9")),
            "policy_version_mismatch",
        ),
        (
            evidence_with("containment_schema_version", json!("guard.containment.v0")),
            "policy_version_mismatch",
        ),
        (
            evidence_with("runtime_fingerprint", json!(sha(b"drift"))),
            "daemon_runtime_drift",
        ),
    ];
    for (value, reason) in cases {
        assert_eq!(
            containment_rows(daemon_with(value)),
            vec![pair("fail", reason); 4],
            "{reason}"
        );
    }
}

#[test]
fn unsupported_takes_precedence_over_probe_failure() {
    let mut value = evidence_with("backend", json!("unsupported"));
    value["probe_enforced"] = json!(false);
    assert_eq!(
        containment_rows(daemon_with(value)),
        vec![pair("fail", "unsupported_platform"); 4]
    );
}

#[test]
fn daemon_drift_has_an_explicit_daemon_failure() {
    let signals = collect(daemon_with(evidence_with(
        "runtime_fingerprint",
        json!(sha(b"drift")),
    )));
    assert_eq!(
        row(&signals, "daemon"),
        pair("fail", "daemon_runtime_drift")
    );

    let invalid = collect(daemon_with(json!({"schema_version": "future"})));
    assert_eq!(
        row(&invalid, "daemon"),
        pair("fail", "daemon_containment_health_invalid")
    );
}

#[test]
fn missing_or_malformed_health_is_blocking_not_unknown() {
    let mut extra = evidence();
    extra["raw_command"] = json!("secret");
    let mut dropped = evidence();
    dropped.as_object_mut().expect("object").remove("probe_at");
    let malformed = [
        Value::Null,
        json!({}),
        json!({"schema_version": "future"}),
        json!(["not", "a", "mapping"]),
        extra,
        dropped,
        evidence_with("backend", json!("windows-appcontainer")),
        evidence_with("backend_digest", json!(sha(b"x").to_uppercase())),
        evidence_with("probe_enforced", json!("true")),
        evidence_with("probe_at", json!("2026-07-19T15:00:00")),
        evidence_with("probe_at", json!("2026-07-19T15:00:00z")),
        evidence_with("policy_version", json!(1)),
        evidence_with("schema_version", json!("guard.containment-health.v2")),
    ];
    for value in malformed {
        assert_eq!(
            containment_rows(daemon_with(value.clone())),
            vec![pair("fail", "containment_health_invalid"); 4],
            "{value}"
        );
    }
}
