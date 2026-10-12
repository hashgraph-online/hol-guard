//! Replays policy decision source-context vectors recorded from the original
//! Python store (see
//! `testdata/guard_store/record_policy_source_context_vectors.py`). Seeds,
//! items and expected contexts all come from Python, never from Rust output.

use guard_contracts::{GuardStoreRequestV1, GUARD_STORE_REQUEST_SCHEMA};
use rusqlite::Connection;
use serde_json::{json, Map, Value};

use crate::guard_store_cmd_vectors_tests::{insert_rows, temp_home};
use crate::guard_store_op::evaluate_guard_store_request;

const VECTORS: &str = include_str!("../testdata/guard_store/policy_source_context_vectors.json");

fn request(home: &std::path::Path, args: Value) -> Value {
    let Value::Object(args) = args else {
        panic!("args must be an object");
    };
    let request = GuardStoreRequestV1 {
        schema: GUARD_STORE_REQUEST_SCHEMA.to_owned(),
        request_id: "vector".to_owned(),
        store_path: home.join("guard.db").to_string_lossy().into_owned(),
        guard_home: home.to_string_lossy().into_owned(),
        method: "policy_source_contexts".to_owned(),
        source: "guard".to_owned(),
        busy_timeout_ms: 5000,
        args,
    };
    serde_json::from_slice(&evaluate_guard_store_request(&request).unwrap()).unwrap()
}

fn build_database(home: &std::path::Path, vectors: &Value, scenario: &Value) {
    let connection = Connection::open(home.join("guard.db")).unwrap();
    connection
        .execute_batch("create table guard_review_outbox_events (stream_sequence integer primary key, payload_hash text not null default '')")
        .unwrap();
    for statement in vectors["schema_sql"].as_array().unwrap() {
        connection
            .execute_batch(statement.as_str().unwrap())
            .unwrap();
    }
    for (table, rows) in scenario["seed"].as_object().unwrap() {
        insert_rows(&connection, table, rows);
    }
}

#[test]
fn replays_every_recorded_policy_source_context_scenario() {
    let vectors: Value = serde_json::from_str(VECTORS).unwrap();
    assert_eq!(
        vectors["schema"],
        "guard-store-policy-source-context-vectors.v1"
    );
    let mut compared = 0;
    let mut non_empty = 0;
    for scenario in vectors["scenarios"].as_array().unwrap() {
        let name = scenario["name"].as_str().unwrap();
        let home = temp_home(name);
        build_database(&home, &vectors, scenario);
        let reply = request(&home, json!({"items": scenario["items"]}));
        assert_eq!(reply["status"], "ok", "{name}: {reply}");
        let expected = scenario["contexts"].as_array().unwrap();
        let actual = reply["payload"].as_array().unwrap();
        assert_eq!(actual.len(), expected.len(), "{name}");
        for (position, (actual, expected)) in actual.iter().zip(expected).enumerate() {
            assert_eq!(
                actual, expected,
                "{name} item {position}: {}",
                scenario["items"][position]
            );
            non_empty += usize::from(!expected.is_null());
            compared += 1;
        }
        std::fs::remove_dir_all(&home).ok();
    }
    assert!(
        compared >= 400 && non_empty >= 250,
        "{compared} items, {non_empty} contexts"
    );
}

#[test]
fn rejects_malformed_items() {
    let home = temp_home("policy-source-context-invalid");
    build_database(
        &home,
        &serde_json::from_str(VECTORS).unwrap(),
        &json!({"seed": Map::new()}),
    );
    for args in [
        json!({}),
        json!({"items": {}}),
        json!({"items": ["codex"]}),
        json!({"items": [{"artifact_id": "a"}]}),
        json!({"items": [{"harness": "codex", "artifact_hash": 7}]}),
    ] {
        let reply = request(&home, args.clone());
        assert_eq!(reply["status"], "error", "{args}: {reply}");
        assert_eq!(reply["code"], "native_guard_store_invalid", "{args}");
    }
    let reply = request(&home, json!({"items": []}));
    assert_eq!(reply["payload"], json!([]));
    std::fs::remove_dir_all(&home).ok();
}
