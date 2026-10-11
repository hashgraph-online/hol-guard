//! Replays native-review consume vectors recorded from the original Python
//! implementation (see
//! `testdata/guard_store/record_native_review_consume_vectors.py`). Seeds,
//! expected booleans and post-call effect rows all come from Python, never
//! from Rust output.

use guard_contracts::{GuardStoreRequestV1, GUARD_STORE_REQUEST_SCHEMA};
use rusqlite::Connection;
use serde_json::{Map, Value};

use crate::guard_store_cmd_vectors_tests::{dump, insert_rows, temp_home};
use crate::guard_store_op::evaluate_guard_store_request;

const VECTORS: &str = include_str!("../testdata/guard_store/native_review_consume_vectors.json");

fn consume(home: &std::path::Path, args: &Value) -> Value {
    let mut wire: Map<String, Value> = args.as_object().unwrap().clone();
    wire.entry("workspace").or_insert(Value::Null);
    let request = GuardStoreRequestV1 {
        schema: GUARD_STORE_REQUEST_SCHEMA.to_owned(),
        request_id: "vector".to_owned(),
        store_path: home.join("guard.db").to_string_lossy().into_owned(),
        guard_home: home.to_string_lossy().into_owned(),
        method: "consume_native_review_approval".to_owned(),
        source: "guard".to_owned(),
        busy_timeout_ms: 5000,
        args: wire,
    };
    serde_json::from_slice(&evaluate_guard_store_request(&request).unwrap()).unwrap()
}

fn seed(path: &std::path::Path, vectors: &Value) {
    let connection = Connection::open(path).unwrap();
    connection.execute_batch("pragma journal_mode=wal").ok();
    connection
        .execute_batch("create table guard_review_outbox_events (stream_sequence integer primary key, payload_hash text not null default '')")
        .unwrap();
    for statement in vectors["schema_sql"].as_array().unwrap() {
        connection
            .execute_batch(statement.as_str().unwrap())
            .unwrap();
    }
}

#[test]
fn replays_every_recorded_consume_scenario() {
    let vectors: Value = serde_json::from_str(VECTORS).unwrap();
    assert_eq!(
        vectors["schema"],
        "guard-store-native-review-consume-vectors.v1"
    );
    let mut calls = 0;
    for scenario in vectors["scenarios"].as_array().unwrap() {
        let name = scenario["name"].as_str().unwrap();
        let may_deny = scenario["native_may_deny"] == true;
        let home = temp_home(name);
        let db = home.join("guard.db");
        seed(&db, &vectors);
        insert_rows(
            &Connection::open(&db).unwrap(),
            "approval_requests",
            &scenario["rows"],
        );
        for (index, call) in scenario["calls"].as_array().unwrap().iter().enumerate() {
            let label = format!("{name}#{index}");
            let reply = consume(&home, &call["args"]);
            assert_eq!(reply["status"], "ok", "{label}: {reply}");
            let connection = Connection::open(&db).unwrap();
            let effects = dump(&connection, "guard_continuation_effects", "effect_key");
            if may_deny {
                // CPython accepts this spelling; the resident refuses it and
                // must not spend anything.
                assert_eq!(reply["payload"], Value::Bool(false), "{label}");
                assert_eq!(effects, Value::Array(vec![]), "{label}: effects");
            } else {
                assert_eq!(reply["payload"], call["result"], "{label}");
                assert_eq!(effects, call["effects"], "{label}: effects");
            }
            if index == 0 {
                insert_rows(
                    &connection,
                    "approval_requests",
                    &scenario["after_first_call_rows"],
                );
            }
            calls += 1;
        }
        let _ = std::fs::remove_dir_all(&home);
    }
    assert!(calls >= 80, "only {calls} recorded calls");
}
