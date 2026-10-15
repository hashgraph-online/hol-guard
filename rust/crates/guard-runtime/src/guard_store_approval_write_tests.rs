//! Replays approval-request write vectors recorded from the original Python
//! implementation (see
//! `testdata/guard_store/record_approval_request_write_vectors.py`). Seeds,
//! returned ids, errors and the resulting queue and outbox rows all come from
//! Python, never from Rust output.

use guard_contracts::{GuardStoreRequestV1, GUARD_STORE_REQUEST_SCHEMA};
use rusqlite::Connection;
use serde_json::{json, Map, Value};

use crate::guard_store_cmd_vectors_tests::{dump, insert_rows, temp_home};
use crate::guard_store_op::evaluate_guard_store_request;

const VECTORS: &str = include_str!("../testdata/guard_store/approval_request_write_vectors.json");
const TABLES: [(&str, &str); 2] = [
    ("approval_requests", "request_id"),
    ("guard_review_outbox_events", "stream_sequence"),
];

fn write(home: &std::path::Path, source: &str, scenario: &Value, method: &str) -> Value {
    let mut args = Map::new();
    args.insert("request".to_owned(), scenario["request"].clone());
    args.insert("now".to_owned(), scenario["now"].clone());
    let request = GuardStoreRequestV1 {
        schema: GUARD_STORE_REQUEST_SCHEMA.to_owned(),
        request_id: "vector".to_owned(),
        store_path: home.join("guard.db").to_string_lossy().into_owned(),
        guard_home: home.to_string_lossy().into_owned(),
        method: method.to_owned(),
        source: source.to_owned(),
        busy_timeout_ms: 5000,
        args,
    };
    serde_json::from_slice(&evaluate_guard_store_request(&request).unwrap()).unwrap()
}

/// Outbox event ids are random per insert, so the replay checks their shape
/// and compares every other column.
fn without_event_ids(rows: Value, label: &str) -> Value {
    let mut rows = rows;
    for row in rows.as_array_mut().unwrap() {
        if let Some(id) = row.as_object_mut().unwrap().remove("event_id") {
            let id = id.as_str().unwrap_or_default();
            assert!(
                id.len() == 32 && id.bytes().all(|byte| byte.is_ascii_hexdigit()),
                "{label}: event id {id}"
            );
        }
    }
    rows
}

fn tables(connection: &Connection, label: &str) -> Value {
    let mut out = Map::new();
    for (table, order) in TABLES {
        let rows = dump(connection, table, order);
        let rows = if table == "guard_review_outbox_events" {
            without_event_ids(rows, label)
        } else {
            rows
        };
        out.insert(table.to_owned(), rows);
    }
    Value::Object(out)
}

fn expected(recorded: &Value, label: &str) -> Value {
    let mut out = recorded.clone();
    let events = out["guard_review_outbox_events"].take();
    out["guard_review_outbox_events"] = without_event_ids(events, label);
    out
}

/// The seed's queue and outbox rows, ignoring outbox digests: committing any
/// write finalizes the digests the seed's insert triggers left empty.
fn unchanged(rows: &Value) -> Value {
    let mut rows = rows.clone();
    for row in rows["guard_review_outbox_events"].as_array_mut().unwrap() {
        row.as_object_mut().unwrap().remove("payload_hash");
    }
    rows
}

fn seed(path: &std::path::Path, vectors: &Value, scenario: &Value) {
    let connection = Connection::open(path).unwrap();
    connection.execute_batch("pragma journal_mode=wal").ok();
    for statement in vectors["schema_sql"].as_array().unwrap() {
        connection
            .execute_batch(statement.as_str().unwrap())
            .unwrap();
    }
    for (table, rows) in scenario["seed"].as_object().unwrap() {
        insert_rows(&connection, table, rows);
    }
    insert_rows(&connection, "approval_requests", &scenario["rows"]);
}

#[test]
fn replays_every_recorded_approval_request_write() {
    let vectors: Value = serde_json::from_str(VECTORS).unwrap();
    assert_eq!(
        vectors["schema"],
        "guard-store-approval-request-write-vectors.v1"
    );
    let source = vectors["source"].as_str().unwrap();
    let mut replayed = 0;
    for scenario in vectors["scenarios"].as_array().unwrap() {
        let name = scenario["name"].as_str().unwrap();
        let home = temp_home(name);
        let db = home.join("guard.db");
        seed(&db, &vectors, scenario);
        let before = expected(&scenario["before"], name);
        assert_eq!(
            tables(&Connection::open(&db).unwrap(), name),
            before,
            "{name}: seed"
        );
        let reply = write(
            &home,
            source,
            scenario,
            "add_native_review_approval_request",
        );
        let after = tables(&Connection::open(&db).unwrap(), name);
        if scenario["native_defers"] == true {
            // The daemon backfills legacy rows before writing; the resident
            // defers to it without touching the store.
            assert_eq!(reply["status"], "ok", "{name}: {reply}");
            assert_eq!(reply["payload"], Value::Null, "{name}");
            assert_eq!(unchanged(&after), unchanged(&before), "{name}: unchanged");
        } else if let Some(error) = scenario.get("error") {
            assert_eq!(reply["status"], "error", "{name}: {reply}");
            assert_eq!(reply["code"], "native_guard_store_value_error", "{name}");
            assert_eq!(reply["payload"], json!({"message": error}), "{name}");
            assert_eq!(unchanged(&after), unchanged(&before), "{name}: rolled back");
        } else {
            assert_eq!(reply["status"], "ok", "{name}: {reply}");
            assert_eq!(reply["payload"], scenario["result"], "{name}");
            assert_eq!(after, expected(&scenario["after"], name), "{name}: rows");
        }
        replayed += 1;
        let _ = std::fs::remove_dir_all(&home);
    }
    assert!(replayed >= 26, "only {replayed} recorded scenarios");
}

/// `add_approval_request` backfills legacy rows itself and so reproduces
/// every Python outcome, the deferred scenarios included.
#[test]
fn general_write_replays_every_recorded_outcome() {
    let vectors: Value = serde_json::from_str(VECTORS).unwrap();
    let source = vectors["source"].as_str().unwrap();
    let mut backfilled = 0;
    for scenario in vectors["scenarios"].as_array().unwrap() {
        let name = scenario["name"].as_str().unwrap();
        let label = format!("{name}-general");
        let home = temp_home(&label);
        let db = home.join("guard.db");
        seed(&db, &vectors, scenario);
        let before = expected(&scenario["before"], name);
        let reply = write(&home, source, scenario, "add_approval_request");
        let after = tables(&Connection::open(&db).unwrap(), name);
        if let Some(error) = scenario.get("error").filter(|error| !error.is_null()) {
            assert_eq!(reply["status"], "error", "{label}: {reply}");
            assert_eq!(reply["code"], "native_guard_store_value_error", "{label}");
            assert_eq!(reply["payload"], json!({"message": error}), "{label}");
            assert_eq!(
                unchanged(&after),
                unchanged(&before),
                "{label}: rolled back"
            );
        } else {
            assert_eq!(reply["status"], "ok", "{label}: {reply}");
            assert_eq!(reply["payload"], scenario["result"], "{label}");
            assert_eq!(after, expected(&scenario["after"], name), "{label}: rows");
        }
        backfilled += usize::from(scenario["native_defers"] == true);
        let _ = std::fs::remove_dir_all(&home);
    }
    assert!(backfilled >= 2, "only {backfilled} legacy scenarios");
}
