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

fn write(home: &std::path::Path, source: &str, scenario: &Value, daemon: bool) -> Value {
    let mut args = Map::new();
    args.insert("request".to_owned(), scenario["request"].clone());
    args.insert("now".to_owned(), scenario["now"].clone());
    if daemon {
        args.insert("daemon".to_owned(), Value::Bool(true));
    }
    call(
        home,
        source,
        "add_silent_native_review_approval_request",
        args,
    )
}

fn call(home: &std::path::Path, source: &str, method: &str, args: Map<String, Value>) -> Value {
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

fn replay(daemon: bool) {
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
        let reply = write(&home, source, scenario, daemon);
        let connection = Connection::open(&db).unwrap();
        let after = tables(&connection, name);
        if scenario["native_defers"] == true && !daemon {
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
            let result = if daemon {
                json!({"request_id": scenario["result"], "event_error": null})
            } else {
                scenario["result"].clone()
            };
            assert_eq!(reply["payload"], result, "{name}");
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
fn replays_every_recorded_silent_review() {
    replay(false);
}

/// The daemon backfills legacy rows itself, so every scenario, including the
/// ones the hook path defers, lands exactly the rows Python wrote.
#[test]
fn the_daemon_replays_every_recorded_silent_review() {
    replay(true);
}

fn write_over_unreadable_row(label: &str, daemon: bool) -> (Value, Connection, std::path::PathBuf) {
    let vectors: Value = serde_json::from_str(VECTORS).unwrap();
    let source = vectors["source"].as_str().unwrap();
    let scenario = vectors["scenarios"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["name"] == "dedupe_keeps_stored_fields")
        .unwrap();
    let home = temp_home(label);
    let db = home.join("guard.db");
    seed(&db, &vectors, scenario);
    // The write keeps the stored `created_at`, which Python reads as
    // `str(bytes)`, so no event can reproduce it.
    Connection::open(&db)
        .unwrap()
        .execute("update approval_requests set created_at = x'00'", [])
        .unwrap();
    let reply = write(&home, source, scenario, daemon);
    (reply, Connection::open(&db).unwrap(), home)
}

fn queued_and_events(connection: &Connection) -> (String, i64, i64) {
    let (name, count): (String, i64) = connection
        .query_row(
            "select artifact_name, dedupe_count from approval_requests",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    let events: i64 = connection
        .query_row("select count(*) from guard_events", [], |row| row.get(0))
        .unwrap();
    (name, count, events)
}

#[test]
fn an_unreadable_queued_row_rolls_back_the_review() {
    // The hook path leaves this to the daemon and rolls the update back.
    let (reply, connection, home) = write_over_unreadable_row("silent-review-unreadable", false);
    assert_eq!(reply["status"], "error", "{reply}");
    let (name, count, events) = queued_and_events(&connection);
    assert_eq!(
        (name.as_str(), count, events),
        ("OldBash", 1, 0),
        "rolled back"
    );
    drop(connection);
    let _ = std::fs::remove_dir_all(&home);
}

#[test]
fn the_daemon_keeps_a_review_whose_event_cannot_be_written() {
    // The daemon's event was always best effort: the queued review stands.
    let (reply, connection, home) =
        write_over_unreadable_row("silent-review-unreadable-daemon", true);
    assert_eq!(reply["status"], "ok", "{reply}");
    assert_eq!(
        reply["payload"],
        json!({"request_id": "r-old", "event_error": "native_guard_store_invalid"}),
        "{reply}"
    );
    let (name, count, events) = queued_and_events(&connection);
    assert_eq!(
        (name.as_str(), count, events),
        ("NewBash", 2, 0),
        "queued, no event"
    );
    drop(connection);
    let _ = std::fs::remove_dir_all(&home);
}

#[test]
fn the_daemon_keeps_a_review_when_the_event_insert_fails() {
    // Any failed event write, not only an unreadable row, rolls back to the
    // savepoint alone: the queued review and its outbox entry stand.
    let vectors: Value = serde_json::from_str(VECTORS).unwrap();
    let source = vectors["source"].as_str().unwrap();
    let scenario = vectors["scenarios"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["name"] == "dedupe_keeps_stored_fields")
        .unwrap();
    let home = temp_home("silent-review-event-insert-fails");
    let db = home.join("guard.db");
    seed(&db, &vectors, scenario);
    Connection::open(&db)
        .unwrap()
        .execute_batch(
            "create trigger refuse_event before insert on guard_events \
             begin select raise(abort, 'refused'); end;",
        )
        .unwrap();
    let reply = write(&home, source, scenario, true);
    assert_eq!(reply["status"], "ok", "{reply}");
    assert_eq!(
        reply["payload"],
        json!({"request_id": scenario["result"], "event_error": "native_guard_store_integrity_error"}),
        "{reply}"
    );
    let connection = Connection::open(&db).unwrap();
    let mut expected_rows = expected(&scenario["after"], "event-insert-fails");
    expected_rows["guard_events"] =
        expected(&scenario["before"], "event-insert-fails")["guard_events"].clone();
    assert_eq!(
        tables(&connection, "event-insert-fails"),
        expected_rows,
        "queued, no event"
    );
    drop(connection);
    let _ = std::fs::remove_dir_all(&home);
}

fn scenario_named<'a>(vectors: &'a Value, name: &str) -> &'a Value {
    vectors["scenarios"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["name"] == name)
        .unwrap()
}

#[test]
fn a_queue_write_answers_the_row_it_stored_when_asked() {
    // The hook queues a review and reads it back in one resident call; the
    // row is the one a separate `get_approval_request` reads afterwards.
    let vectors: Value = serde_json::from_str(VECTORS).unwrap();
    let source = vectors["source"].as_str().unwrap();
    let scenario = scenario_named(&vectors, "dedupe_keeps_stored_fields");
    for (method, daemon) in [
        ("add_silent_native_review_approval_request", true),
        ("add_approval_request", false),
    ] {
        let home = temp_home(&format!("stored-row-{method}"));
        seed(&home.join("guard.db"), &vectors, scenario);
        let mut args = Map::new();
        args.insert("request".to_owned(), scenario["request"].clone());
        args.insert("now".to_owned(), scenario["now"].clone());
        args.insert("return_row".to_owned(), Value::Bool(true));
        if daemon {
            args.insert("daemon".to_owned(), Value::Bool(true));
        }
        let reply = call(&home, source, method, args);
        assert_eq!(reply["status"], "ok", "{method}: {reply}");
        let payload = &reply["payload"];
        assert_eq!(
            payload["request_id"], scenario["result"],
            "{method}: {reply}"
        );
        assert!(payload.get("row_error").is_none(), "{method}: {reply}");
        let read = call(
            &home,
            source,
            "get_approval_request",
            Map::from_iter([
                ("request_id".to_owned(), scenario["result"].clone()),
                ("derive_scope".to_owned(), Value::Bool(true)),
            ]),
        );
        assert_eq!(read["status"], "ok", "{method}: {read}");
        assert!(read["payload"].is_object(), "{method}: {read}");
        assert_eq!(payload["row"], read["payload"], "{method}: same row");
        let _ = std::fs::remove_dir_all(&home);
    }
}

#[test]
fn a_row_that_cannot_be_read_back_keeps_the_queued_review() {
    // The read-back is answered as `row_error`; it never undoes the write.
    let vectors: Value = serde_json::from_str(VECTORS).unwrap();
    let source = vectors["source"].as_str().unwrap();
    let scenario = scenario_named(&vectors, "dedupe_keeps_stored_fields");
    let home = temp_home("stored-row-unreadable");
    let db = home.join("guard.db");
    seed(&db, &vectors, scenario);
    Connection::open(&db)
        .unwrap()
        .execute("update approval_requests set created_at = x'00'", [])
        .unwrap();
    let mut args = Map::new();
    args.insert("request".to_owned(), scenario["request"].clone());
    args.insert("now".to_owned(), scenario["now"].clone());
    args.insert("daemon".to_owned(), Value::Bool(true));
    args.insert("return_row".to_owned(), Value::Bool(true));
    let reply = call(
        &home,
        source,
        "add_silent_native_review_approval_request",
        args,
    );
    assert_eq!(reply["status"], "ok", "{reply}");
    let payload = &reply["payload"];
    assert_eq!(payload["request_id"], "r-old", "{reply}");
    assert_eq!(
        payload["row_error"], "native_guard_store_invalid",
        "{reply}"
    );
    assert!(payload.get("row").is_none(), "{reply}");
    let (name, count, _) = queued_and_events(&Connection::open(&db).unwrap());
    assert_eq!((name.as_str(), count), ("NewBash", 2), "queued");
    let _ = std::fs::remove_dir_all(&home);
}

#[test]
fn a_malformed_return_row_flag_rolls_the_write_back() {
    let vectors: Value = serde_json::from_str(VECTORS).unwrap();
    let source = vectors["source"].as_str().unwrap();
    let scenario = scenario_named(&vectors, "dedupe_keeps_stored_fields");
    let home = temp_home("stored-row-malformed");
    let db = home.join("guard.db");
    seed(&db, &vectors, scenario);
    let mut args = Map::new();
    args.insert("request".to_owned(), scenario["request"].clone());
    args.insert("now".to_owned(), scenario["now"].clone());
    args.insert("return_row".to_owned(), json!("yes"));
    let reply = call(&home, source, "add_approval_request", args);
    assert_eq!(reply["status"], "error", "{reply}");
    let before = expected(&scenario["before"], "stored-row-malformed");
    assert_eq!(
        unchanged(&tables(
            &Connection::open(&db).unwrap(),
            "stored-row-malformed"
        )),
        unchanged(&before),
        "rolled back"
    );
    let _ = std::fs::remove_dir_all(&home);
}
