use serde_json::{json, Value};

use super::*;

fn fixture(name: &str) -> Value {
    let text = match name {
        "valid_reconnected" => {
            include_str!("../../../../tests/fixtures/daemon_recovery_v1/valid_reconnected.json")
        }
        "valid_timeout" => {
            include_str!("../../../../tests/fixtures/daemon_recovery_v1/valid_timeout.json")
        }
        "invalid_unknown_reason" => include_str!(
            "../../../../tests/fixtures/daemon_recovery_v1/invalid_unknown_reason.json"
        ),
        "unsupported_schema" => {
            include_str!("../../../../tests/fixtures/daemon_recovery_v1/unsupported_schema.json")
        }
        _ => include_str!(
            "../../../../tests/fixtures/daemon_recovery_v1/diagnostics_privacy_source.json"
        ),
    };
    serde_json::from_str(text).unwrap()
}

#[test]
fn valid_fixtures_round_trip() {
    for name in ["valid_reconnected", "valid_timeout"] {
        let payload = fixture(name);
        assert_eq!(validate(&payload, true).unwrap(), payload);
    }
}

#[test]
fn invalid_fixtures_name_the_contract_code() {
    assert_eq!(
        validate(&fixture("invalid_unknown_reason"), true).unwrap_err(),
        "recovery_reasonCode_invalid"
    );
    assert_eq!(
        validate(&fixture("unsupported_schema"), true).unwrap_err(),
        "unsupported_protocol"
    );
}

#[test]
fn mutation_events_need_an_operation_id() {
    let mut payload = fixture("valid_timeout");
    payload["operationId"] = Value::Null;
    assert!(validate(&payload, true).is_ok());
    assert_eq!(
        validate(&payload, false).unwrap_err(),
        "recovery_operation_id_required"
    );
}

#[test]
fn uppercase_operation_ids_are_canonicalized() {
    let mut payload = fixture("valid_timeout");
    let id = payload["operationId"].as_str().unwrap().to_uppercase();
    payload["operationId"] = json!(id);
    let validated = validate(&payload, false).unwrap();
    assert_eq!(validated["operationId"], json!(id.to_lowercase()));
    assert_eq!(canonical_uuid("{".to_owned().as_str()), None);
    assert_eq!(
        lenient_uuid("{11111111111141118111111111111111}").as_deref(),
        Some("11111111-1111-4111-8111-111111111111")
    );
}

#[test]
fn sensitive_and_unknown_keys_are_refused() {
    let mut payload = fixture("valid_timeout");
    payload["checks"] = json!([{"id": "update_idle", "result": "pass", "url": "x"}]);
    assert_eq!(
        validate(&payload, true).unwrap_err(),
        "recovery_check_fields_invalid"
    );
    let mut payload = fixture("valid_timeout");
    payload["sequence"] = json!(1.5);
    assert_eq!(
        validate(&payload, true).unwrap_err(),
        "recovery_sequence_invalid"
    );
    payload["sequence"] = json!(true);
    assert_eq!(
        validate(&payload, true).unwrap_err(),
        "recovery_sequence_invalid"
    );
}

#[test]
fn sequence_rejects_late_and_cross_operation_events() {
    let previous = fixture("valid_timeout");
    let mut current = previous.clone();
    current["sequence"] = json!(8);
    assert_eq!(
        validate_sequence(Some(&previous), &current).unwrap()["sequence"],
        json!(8)
    );
    assert_eq!(
        validate_sequence(Some(&previous), &previous).unwrap_err(),
        "recovery_sequence_not_increasing"
    );
    current["operationId"] = json!("33333333-3333-4333-8333-333333333333");
    assert_eq!(
        validate_sequence(Some(&previous), &current).unwrap_err(),
        "recovery_operation_changed"
    );
}

#[test]
fn terminal_invariants_hold() {
    let mut payload = fixture("valid_reconnected");
    payload["checks"] = json!([]);
    assert_eq!(
        validate(&payload, true).unwrap_err(),
        "recovery_protection_unverified"
    );
    let mut payload = fixture("valid_timeout");
    payload["retryAllowed"] = json!(true);
    assert_eq!(
        validate(&payload, true).unwrap_err(),
        "recovery_timeout_worker_invalid"
    );
}

#[test]
fn reports_drop_private_fields_and_truncate_from_the_front() {
    let source = fixture("diagnostics_privacy_source");
    let report = build_report(&source, "2026-09-20T00:00:00+00:00").unwrap();
    let encoded = String::from_utf8(encode(&report)).unwrap();
    for key in source.as_object().unwrap().keys() {
        if !SNAPSHOT_FIELDS.contains(&key.as_str()) {
            assert!(!encoded.contains(key.as_str()), "{key} leaked");
        }
    }
    assert_eq!(validate_report(&report).unwrap(), report);

    let mut events = Vec::new();
    for sequence in 1..=100 {
        let mut event = report["latest"].clone();
        event["sequence"] = json!(sequence);
        events.push(event);
    }
    let large = build_report(&Value::Array(events), "2026-09-20T00:00:00+00:00").unwrap();
    assert_eq!(large["eventCount"], json!(100));
    assert_eq!(
        large["truncated"],
        json!(large["retainedEventCount"] != json!(100))
    );
    assert_eq!(large["latest"]["sequence"], json!(100));
    assert!(encode(&large).len() <= MAX_REPORT_BYTES);
}

#[test]
fn malformed_reports_are_refused() {
    let report = build_report(&fixture("valid_timeout"), "2026-09-20T00:00:00+00:00").unwrap();
    let cases = [
        (
            "schema",
            json!("unsupported"),
            "recovery_diagnostics_schema_invalid",
        ),
        (
            "eventCount",
            json!(0),
            "recovery_diagnostics_event_count_invalid",
        ),
        (
            "truncated",
            json!(true),
            "recovery_diagnostics_truncation_invalid",
        ),
        ("events", json!([]), "recovery_diagnostics_events_invalid"),
        (
            "generatedAt",
            json!("2026-09-20T00:00:00"),
            "recovery_diagnostics_timestamp_invalid",
        ),
        (
            "operationId",
            json!("not-a-uuid"),
            "recovery_diagnostics_operation_id_invalid",
        ),
    ];
    for (field, value, code) in cases {
        let mut candidate = report.clone();
        candidate[field] = value;
        assert_eq!(validate_report(&candidate).unwrap_err(), code, "{field}");
    }
    assert_eq!(
        build_report(&json!([null]), "2026-09-20T00:00:00+00:00").unwrap_err(),
        "recovery_diagnostics_snapshot_invalid"
    );
    assert_eq!(
        build_report(&json!([]), "2026-09-20T00:00:00+00:00").unwrap_err(),
        "recovery_diagnostics_events_empty"
    );
}
