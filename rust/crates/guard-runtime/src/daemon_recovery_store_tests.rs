use serde_json::{json, Value};

use super::*;

const NOW: &str = "2026-09-23T00:00:00+00:00";

fn home() -> tempfile::TempDir {
    tempfile::tempdir().unwrap()
}

fn snapshot(operation_id: &str, sequence: u64, phase: &str) -> Value {
    let mut value: Value = serde_json::from_str(include_str!(
        "../../../../tests/fixtures/daemon_recovery_v1/valid_timeout.json"
    ))
    .unwrap();
    value["operationId"] = json!(operation_id);
    value["sequence"] = json!(sequence);
    value["phase"] = json!(phase);
    value
}

fn ask(home: &Path, request: Value) -> Result<Value, Fail> {
    answer(home.to_str().unwrap(), &request)
}

const OP: &str = "11111111-1111-4111-8111-111111111111";

#[test]
fn persisted_snapshots_answer_status_receipts_and_diagnostics() {
    let directory = home();
    let path = directory.path();
    ask(
        path,
        json!({"op": "persist", "snapshot": snapshot(OP, 1, "timed_out_waiting"), "now": NOW}),
    )
    .unwrap();
    ask(
        path,
        json!({"op": "persist", "snapshot": snapshot(OP, 2, "timed_out_waiting"), "now": NOW}),
    )
    .unwrap();
    let status = ask(
        path,
        json!({"op": "status", "operation_id": OP.to_uppercase()}),
    )
    .unwrap();
    assert_eq!(status["sequence"], json!(2));
    let receipt = ask(path, json!({"op": "receipt", "operation_id": OP})).unwrap();
    assert_eq!(receipt["sequence"], json!(2));
    let report = ask(
        path,
        json!({"op": "diagnostics", "operation_id": OP, "now": NOW}),
    )
    .unwrap();
    assert_eq!(report["eventCount"], json!(2));
    let missing = ask(
        path,
        json!({"op": "status", "operation_id": "22222222-2222-4222-8222-222222222222"}),
    )
    .unwrap_err();
    assert_eq!(missing.kind, "missing");
}

#[test]
fn a_malformed_archive_falls_back_to_the_operation_record() {
    let directory = home();
    let path = directory.path();
    ask(
        path,
        json!({"op": "persist", "snapshot": snapshot(OP, 1, "timed_out_waiting"), "now": NOW}),
    )
    .unwrap();
    write_state(
        path,
        DIAGNOSTICS_NAME,
        b"{not-json",
        MAX_DIAGNOSTICS_BYTES as u64,
    )
    .unwrap();
    let failure = ask(
        path,
        json!({"op": "diagnostics_for", "operation_id": OP, "now": NOW}),
    )
    .unwrap_err();
    assert_eq!(failure.code, "recovery_diagnostics_state_invalid");
    let report = ask(
        path,
        json!({"op": "diagnostics", "operation_id": OP, "now": NOW}),
    )
    .unwrap();
    assert_eq!(report["operationId"], json!(OP));
}

#[test]
fn retention_keeps_recent_incidents_in_instant_order() {
    let directory = home();
    let path = directory.path();
    for (index, generated) in [
        "2026-09-01T00:00:00+00:00",
        "2026-09-22T00:00:00+02:00",
        "2026-09-21T23:00:00+00:00",
    ]
    .iter()
    .enumerate()
    {
        let id = format!("{index}1111111-1111-4111-8111-111111111111");
        ask(
            path,
            json!({"op": "persist_diagnostics", "snapshots": [snapshot(&id, 1, "verifying")],
                   "generated_at": generated, "now": NOW}),
        )
        .unwrap();
    }
    let archive: Value = serde_json::from_slice(
        &read_state(path, DIAGNOSTICS_NAME, 1 << 20)
            .unwrap()
            .unwrap(),
    )
    .unwrap();
    let ids: Vec<&str> = archive["reports"]
        .as_array()
        .unwrap()
        .iter()
        .map(|report| report["operationId"].as_str().unwrap())
        .collect();
    assert_eq!(
        ids,
        [
            "11111111-1111-4111-8111-111111111111",
            "21111111-1111-4111-8111-111111111111"
        ]
    );
    let latest = ask(path, json!({"op": "load_diagnostics", "now": NOW})).unwrap();
    assert_eq!(latest["operationId"], json!(ids[1]));
}

#[test]
fn non_receipt_phases_only_update_the_latest_state() {
    let directory = home();
    let path = directory.path();
    ask(
        path,
        json!({"op": "persist", "snapshot": snapshot(OP, 1, "checking"), "now": NOW}),
    )
    .unwrap();
    assert_eq!(
        ask(path, json!({"op": "receipt", "operation_id": OP})).unwrap(),
        Value::Null
    );
    assert_eq!(
        ask(path, json!({"op": "latest"})).unwrap()["phase"],
        json!("checking")
    );
}
