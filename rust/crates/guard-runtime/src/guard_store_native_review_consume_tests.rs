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
    call(home, args, "consume_native_review_approval")
}

fn call(home: &std::path::Path, args: &Value, method: &str) -> Value {
    let mut wire: Map<String, Value> = args.as_object().unwrap().clone();
    wire.entry("workspace").or_insert(Value::Null);
    let request = GuardStoreRequestV1 {
        schema: GUARD_STORE_REQUEST_SCHEMA.to_owned(),
        request_id: "vector".to_owned(),
        store_path: home.join("guard.db").to_string_lossy().into_owned(),
        guard_home: home.to_string_lossy().into_owned(),
        method: method.to_owned(),
        source: "guard".to_owned(),
        busy_timeout_ms: 5000,
        args: wire,
    };
    serde_json::from_slice(&evaluate_guard_store_request(&request).unwrap()).unwrap()
}

#[test]
fn blocks_use_the_same_identity_window_scope_and_latest_decision_rules() {
    let vectors: Value = serde_json::from_str(VECTORS).unwrap();
    for scenario in vectors["scenarios"].as_array().unwrap() {
        let name = scenario["name"].as_str().unwrap();
        let home = temp_home(&format!("block-{name}"));
        let db = home.join("guard.db");
        seed(&db, &vectors);
        let mut rows = scenario["rows"].clone();
        for row in rows.as_array_mut().unwrap() {
            row["resolution_action"] = match row["resolution_action"].as_str() {
                Some("allow") => Value::from("block"),
                Some("block") => Value::from("allow"),
                _ => row["resolution_action"].clone(),
            };
        }
        insert_rows(&Connection::open(&db).unwrap(), "approval_requests", &rows);
        let first = &scenario["calls"][0];
        let expected = scenario["native_may_deny"] != true && first["result"] == true;
        for _ in 0..2 {
            let reply = call(&home, &first["args"], "matching_native_review_block");
            assert_eq!(reply["status"], "ok", "{name}: {reply}");
            assert_eq!(reply["payload"], expected, "{name}");
        }
        assert_eq!(
            dump(
                &Connection::open(&db).unwrap(),
                "guard_continuation_effects",
                "effect_key"
            ),
            serde_json::json!([])
        );
        std::fs::remove_dir_all(home).unwrap();
    }
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
            // The vectors name the dedupe digest `effect_digest`: a key-shaped
            // field name next to a 64-hex value reads as a credential to scanners.
            let mut effects = dump(&connection, "guard_continuation_effects", "effect_key");
            for row in effects.as_array_mut().unwrap() {
                let object = row.as_object_mut().unwrap();
                if let Some(digest) = object.remove("effect_key") {
                    object.insert("effect_digest".to_owned(), digest);
                }
            }
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

/// The retry sends the command as run; the resolved row holds it with
/// credentials masked. The exact binding is `artifact_hash`, so the masked
/// row still answers the retry.
#[test]
fn a_masked_stored_target_still_answers_the_raw_retry() {
    let vectors: Value = serde_json::from_str(VECTORS).unwrap();
    let scenario = vectors["scenarios"]
        .as_array()
        .unwrap()
        .iter()
        .find(|scenario| scenario["name"] == "once_allow_then_replay")
        .unwrap();
    let first = &scenario["calls"][0];
    assert_eq!(first["result"], true);
    let sent = first["args"]["launch_target"].as_str().unwrap().to_owned();
    let raw = format!("{sent} -H \"Authorization: Bearer secret-token-value\"");
    let stored = guard_command::redacted_command_tokens::redact_text(&raw).text;
    assert_ne!(stored, raw);
    let home = temp_home("masked-target");
    let db = home.join("guard.db");
    seed(&db, &vectors);
    let mut rows = scenario["rows"].clone();
    for row in rows.as_array_mut().unwrap() {
        if row["launch_target"] == sent.as_str() {
            row["launch_target"] = Value::from(stored.clone());
        }
    }
    insert_rows(&Connection::open(&db).unwrap(), "approval_requests", &rows);
    let mut args = first["args"].clone();
    args["launch_target"] = Value::from(raw);
    let reply = consume(&home, &args);
    assert_eq!(reply["status"], "ok", "{reply}");
    assert_eq!(reply["payload"], true);
    std::fs::remove_dir_all(home).unwrap();
}
