//! Replays silent native review vectors recorded from the original Python
//! implementation (see
//! `testdata/guard_store/record_silent_review_vectors.py`). Seeds, returned
//! ids, errors, the queued fields the event reads and the resulting queue,
//! outbox and event rows all come from Python, never from Rust output.

use guard_contracts::{GuardStoreRequestV1, GUARD_STORE_REQUEST_SCHEMA};
use rusqlite::Connection;
use serde_json::{json, Map, Value};

use super::queued_request;
use crate::guard_store_cmd_vectors_tests::{dump, insert_rows, temp_home};
use crate::guard_store_op::evaluate_guard_store_request;

const VECTORS: &str = include_str!("../testdata/guard_store/silent_review_vectors.json");
const TABLES: [(&str, &str); 3] = [
    ("approval_requests", "request_id"),
    ("guard_review_outbox_events", "stream_sequence"),
    ("guard_events", "event_id"),
];

fn write(home: &std::path::Path, source: &str, scenario: &Value) -> Value {
    let mut args = Map::new();
    args.insert("request".to_owned(), scenario["request"].clone());
    args.insert("now".to_owned(), scenario["now"].clone());
    let request = GuardStoreRequestV1 {
        schema: GUARD_STORE_REQUEST_SCHEMA.to_owned(),
        request_id: "vector".to_owned(),
        store_path: home.join("guard.db").to_string_lossy().into_owned(),
        guard_home: home.to_string_lossy().into_owned(),
        method: "add_silent_native_review_approval_request".to_owned(),
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
    // This recorded native-pretool request has no reusable execution binding.
    // Keep its stored snapshot, but emit no unavailable allow recommendation.
    if label == "fresh_native_tool_call" {
        for event in out["guard_events"].as_array_mut().unwrap() {
            let recorded = event["payload_json"].as_str().unwrap();
            let payload: Value = serde_json::from_str(recorded).unwrap();
            assert_eq!(payload["artifact_id"], "codex:native-pretool:Bash");
            assert_eq!(payload["recommended_scope"], "artifact");
            event["payload_json"] = Value::String(recorded.replace(
                "\"recommended_scope\": \"artifact\"",
                "\"recommended_scope\": null",
            ));
        }
    }
    out
}

/// The seed's rows, ignoring outbox digests: committing any write finalizes
/// the digests the seed's insert triggers left empty.
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
    insert_rows(&connection, "approval_requests", &scenario["rows"]);
}

fn check_queued(connection: &Connection, scenario: &Value, name: &str) {
    let request_id = scenario["result"].as_str().unwrap();
    let queued = queued_request(connection, request_id).unwrap();
    let mut expected = scenario["queued"].clone();
    if name == "fresh_native_tool_call" {
        assert_eq!(expected["recommended_scope"], "artifact");
        expected["recommended_scope"] = Value::Null;
    }
    assert_eq!(Value::Object(queued), expected, "{name}: queued");
}

#[test]
fn replays_every_recorded_silent_review() {
    let vectors: Value = serde_json::from_str(VECTORS).unwrap();
    assert_eq!(vectors["schema"], "guard-store-silent-review-vectors.v1");
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
        let reply = write(&home, source, scenario);
        let connection = Connection::open(&db).unwrap();
        let after = tables(&connection, name);
        if scenario["native_defers"] == true {
            // The daemon backfills legacy rows before queueing; the resident
            // defers to it without touching the store.
            assert_eq!(reply["status"], "ok", "{name}: {reply}");
            assert_eq!(reply["payload"], Value::Null, "{name}");
            assert_eq!(unchanged(&after), unchanged(&before), "{name}: unchanged");
        } else if let Some(error) = scenario["error"].as_str() {
            assert_eq!(reply["status"], "error", "{name}: {reply}");
            assert_eq!(reply["code"], "native_guard_store_value_error", "{name}");
            assert_eq!(reply["payload"], json!({"message": error}), "{name}");
            assert_eq!(unchanged(&after), unchanged(&before), "{name}: rolled back");
        } else {
            assert_eq!(reply["status"], "ok", "{name}: {reply}");
            assert_eq!(reply["payload"], scenario["result"], "{name}");
            assert_eq!(after, expected(&scenario["after"], name), "{name}: rows");
            check_queued(&connection, scenario, name);
        }
        drop(connection);
        replayed += 1;
        let _ = std::fs::remove_dir_all(&home);
    }
    assert!(replayed >= 13, "only {replayed} recorded scenarios");
}

#[test]
fn an_unreadable_queued_row_rolls_back_the_review() {
    let vectors: Value = serde_json::from_str(VECTORS).unwrap();
    let source = vectors["source"].as_str().unwrap();
    let scenario = vectors["scenarios"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["name"] == "dedupe_keeps_stored_fields")
        .unwrap();
    let home = temp_home("silent-review-unreadable");
    let db = home.join("guard.db");
    seed(&db, &vectors, scenario);
    // The write keeps the stored `created_at`; one Python reads as `str(bytes)`
    // is left to the daemon, and the queued update is rolled back with it.
    Connection::open(&db)
        .unwrap()
        .execute("update approval_requests set created_at = x'00'", [])
        .unwrap();
    let reply = write(&home, source, scenario);
    assert_eq!(reply["status"], "error", "{reply}");
    let connection = Connection::open(&db).unwrap();
    let (name, count): (String, i64) = connection
        .query_row(
            "select artifact_name, dedupe_count from approval_requests",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!((name.as_str(), count), ("OldBash", 1), "rolled back");
    let events: i64 = connection
        .query_row("select count(*) from guard_events", [], |row| row.get(0))
        .unwrap();
    assert_eq!(events, 0, "no event");
    drop(connection);
    let _ = std::fs::remove_dir_all(&home);
}
