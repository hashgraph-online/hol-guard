//! Replays `queue_blocked_approvals` vectors recorded from the original
//! Python implementation (see
//! `testdata/guard_store/record_approval_queue_vectors.py`). Every request
//! the loop writes, its persisted id, the notices and the stopping error
//! come from Python, never from Rust output.

use guard_contracts::{GuardStoreRequestV1, GUARD_STORE_REQUEST_SCHEMA};
use rusqlite::Connection;
use serde_json::{json, Value};

use super::{TEST_REQUEST_ID_COUNTER, TEST_WRITES};
use crate::guard_store_cmd_vectors_tests::temp_home;
use crate::guard_store_op::evaluate_guard_store_request;

const VECTORS: &str = include_str!("../testdata/guard_store/approval_queue_vectors.json");
/// The store schema and caller source of the queue write's own vectors.
const WRITE_VECTORS: &str =
    include_str!("../testdata/guard_store/approval_request_write_vectors.json");

/// Python's exception class for each error tag the reply carries.
fn python_error(error: &Value) -> Value {
    if error.is_null() {
        return Value::Null;
    }
    let class = match error["type"].as_str().unwrap() {
        "value" => "ValueError",
        "runtime" => "RuntimeError",
        other => other,
    };
    json!({"type": class, "message": error["message"]})
}

fn queue(home: &std::path::Path, source: &str, args: &Value) -> Value {
    let request = GuardStoreRequestV1 {
        schema: GUARD_STORE_REQUEST_SCHEMA.to_owned(),
        request_id: "vector".to_owned(),
        store_path: home.join("guard.db").to_string_lossy().into_owned(),
        guard_home: home.to_string_lossy().into_owned(),
        method: "queue_blocked_approvals".to_owned(),
        source: source.to_owned(),
        busy_timeout_ms: 5000,
        args: args.as_object().unwrap().clone(),
    };
    serde_json::from_slice(&evaluate_guard_store_request(&request).unwrap()).unwrap()
}

#[test]
fn replays_every_recorded_approval_queue_loop() {
    let vectors: Value = serde_json::from_str(VECTORS).unwrap();
    assert_eq!(vectors["schema"], "guard-store-approval-queue-vectors.v1");
    let store: Value = serde_json::from_str(WRITE_VECTORS).unwrap();
    let source = store["source"].as_str().unwrap();
    let mut replayed = 0;
    for vector in vectors["vectors"].as_array().unwrap() {
        let name = vector["name"].as_str().unwrap();
        let home = temp_home(&format!("queue-{name}"));
        let connection = Connection::open(home.join("guard.db")).unwrap();
        for statement in store["schema_sql"].as_array().unwrap() {
            connection
                .execute_batch(statement.as_str().unwrap())
                .unwrap();
        }
        drop(connection);
        TEST_REQUEST_ID_COUNTER.with(|counter| counter.set(Some(1)));
        TEST_WRITES.with(|writes| writes.borrow_mut().clear());
        let reply = queue(&home, source, &vector["args"]);
        TEST_REQUEST_ID_COUNTER.with(|counter| counter.set(None));
        assert_eq!(reply["status"], "ok", "{name}: {reply}");
        let payload = &reply["payload"];
        let writes: Vec<Value> = TEST_WRITES.with(|writes| {
            writes
                .borrow()
                .iter()
                .map(|(request, id)| json!({"request": request, "persisted_id": id}))
                .collect()
        });
        let expected = vector["writes"].as_array().unwrap();
        assert_eq!(writes.len(), expected.len(), "{name}: write count");
        for (index, (write, recorded)) in writes.iter().zip(expected).enumerate() {
            assert_eq!(write, recorded, "{name}: write {index}");
        }
        let notices: Vec<Value> = payload["queued"]
            .as_array()
            .unwrap()
            .iter()
            .map(|queued| {
                assert_eq!(queued["request_id"], queued["notice"]["request_id"]);
                queued["notice"].clone()
            })
            .collect();
        assert_eq!(Value::Array(notices), vector["notices"], "{name}: notices");
        assert_eq!(
            python_error(&payload["error"]),
            vector["error"],
            "{name}: error"
        );
        let _ = std::fs::remove_dir_all(&home);
        replayed += 1;
    }
    assert!(replayed >= 49, "replayed {replayed}");
}
