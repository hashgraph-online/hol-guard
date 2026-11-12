use serde_json::json;

use super::{command_activity_evidence, hook_capacity, hook_load, sqlite_migration_gate};

#[test]
fn activity_evidence_degrades_on_a_persistence_error() {
    let healthy = command_activity_evidence(&json!({
        "dropped_event_count": 2,
        "persistence_error_count": 0,
        "last_error_code": null,
        "last_error_at": null,
        "schema_version": "1.0.0",
    }));
    assert_eq!(healthy["state"], "healthy");
    assert_eq!(healthy["dropped_event_count"], 2);
    let degraded = command_activity_evidence(&json!({
        "dropped_event_count": 1,
        "persistence_error_count": 1,
        "last_error_code": "sqlite_busy",
        "last_error_at": "2026-01-01T00:00:00+00:00",
        "schema_version": "1.0.0",
    }));
    assert_eq!(degraded["state"], "degraded");
    assert_eq!(degraded["last_error_code"], "sqlite_busy");
}

#[test]
fn hook_load_reports_a_contended_store_before_capacity() {
    let capacity = hook_capacity();
    assert_eq!(hook_load(&json!({}), &capacity)["state"], "healthy");
    let writer = json!({ "failures": 1, "queued": 3 });
    assert_eq!(hook_load(&writer, &capacity)["state"], "store-contended");
    let writer = json!({ "failures": 1, "queued": 0 });
    assert_eq!(hook_load(&writer, &capacity)["state"], "healthy");
}

#[test]
fn capacity_and_gate_keep_the_daemon_shape() {
    let capacity = hook_capacity();
    assert_eq!(capacity["limit"], 32);
    assert_eq!(capacity["queued_limit"], 128);
    assert_eq!(capacity["retained_bytes_limit"], 33_554_432);
    assert_eq!(
        capacity["queue_wait_by_lane_p95_ms"]["content-security"],
        0.0
    );
    let gate = sqlite_migration_gate();
    assert!(gate["store_wait_gate_tripped"].is_null());
    assert_eq!(gate["conclusion"], "insufficient_end_to_end_profile");
}
