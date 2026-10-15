//! Replays Guard event write vectors recorded from the original Python
//! implementation (see `testdata/guard_store/record_guard_event_vectors.py`).
//! The schema, the resulting `guard_events` rows (payload JSON text byte for
//! byte), the `approval.created` payloads and the safe-alternative deny text
//! all come from Python, never from Rust output.

use rusqlite::Connection;
use serde_json::{json, Map, Value};

use crate::blocked_request_mode::safe_alternative_reason;
use crate::guard_store_cmd_vectors_tests::{dump, temp_home};
use crate::guard_store_guard_event::{add_guard_event, approval_created_event};
use crate::pyjson::{self, PyVal};

const VECTORS: &str = include_str!("../testdata/guard_store/guard_event_vectors.json");

fn vectors() -> Value {
    let vectors: Value = serde_json::from_str(VECTORS).unwrap();
    assert_eq!(vectors["schema"], "guard-store-guard-event-vectors.v1");
    vectors
}

fn open(vectors: &Value, tag: &str) -> (std::path::PathBuf, Connection) {
    let home = temp_home(tag);
    let connection = Connection::open(home.join("guard.db")).unwrap();
    for statement in vectors["schema_sql"].as_array().unwrap() {
        connection
            .execute_batch(statement.as_str().unwrap())
            .unwrap();
    }
    (home, connection)
}

fn rows(connection: &Connection) -> Value {
    json!({
        "guard_events": dump(connection, "guard_events", "event_id"),
        "sqlite_sequence": dump(connection, "sqlite_sequence", "name"),
    })
}

fn payload(text: &str) -> Vec<(String, PyVal)> {
    pyjson::parse(text).unwrap().as_dict().unwrap().to_vec()
}

#[test]
fn replays_every_recorded_add_event() {
    let vectors = vectors();
    let mut replayed = 0;
    for scenario in vectors["add_event"].as_array().unwrap() {
        let name = scenario["name"].as_str().unwrap();
        let (home, connection) = open(&vectors, name);
        for (index, event) in scenario["events"].as_array().unwrap().iter().enumerate() {
            let id = add_guard_event(
                &connection,
                event["event_name"].as_str().unwrap(),
                &payload(event["payload_text"].as_str().unwrap()),
                event["now"].as_str().unwrap(),
            )
            .unwrap();
            assert_eq!(id, Some(index as i64 + 1), "{name}: event id");
        }
        assert_eq!(rows(&connection), scenario["after"], "{name}: rows");
        replayed += 1;
        let _ = std::fs::remove_dir_all(&home);
    }
    assert!(replayed >= 20, "only {replayed} recorded scenarios");
}

#[test]
fn defers_an_integer_python_refuses_to_encode() {
    let vectors = vectors();
    let recorded = &vectors["add_event_digit_limit"];
    assert_eq!(recorded["error"], "ValueError");
    let digits = "9".repeat(recorded["int_digits"].as_u64().unwrap() as usize);
    let (home, connection) = open(&vectors, "digit-limit");
    let event = vec![("n".to_owned(), PyVal::Int(digits))];
    let id = add_guard_event(&connection, "metric", &event, "2026-03-01T12:00:00+00:00");
    assert_eq!(id.unwrap(), None);
    assert_eq!(rows(&connection), recorded["after"]);
    let _ = std::fs::remove_dir_all(&home);
}

#[test]
fn defers_a_repeated_key_no_python_dict_holds() {
    let vectors = vectors();
    let (home, connection) = open(&vectors, "repeated-key");
    let nested = PyVal::Dict(vec![
        ("k".to_owned(), PyVal::Null),
        ("k".to_owned(), PyVal::Bool(true)),
    ]);
    let event = vec![("outer".to_owned(), nested)];
    let id = add_guard_event(&connection, "x", &event, "2026-03-01T12:00:00+00:00");
    assert_eq!(id.unwrap(), None);
    assert_eq!(dump(&connection, "guard_events", "event_id"), json!([]));
    let _ = std::fs::remove_dir_all(&home);
}

#[test]
fn replays_every_recorded_approval_created_event() {
    let vectors = vectors();
    let clock = vectors["pinned_clock"].as_str().unwrap();
    let mut replayed = 0;
    for scenario in vectors["approval_created"].as_array().unwrap() {
        let name = scenario["name"].as_str().unwrap();
        let queued: Map<String, Value> =
            serde_json::from_str(scenario["queued_text"].as_str().unwrap()).unwrap();
        let built = approval_created_event(&queued, clock);
        if scenario["native_defers"] == true {
            assert!(built.is_none(), "{name}: should defer");
            continue;
        }
        let (event, timestamp) = built.unwrap_or_else(|| panic!("{name}: deferred"));
        let (home, connection) = open(&vectors, name);
        let id = add_guard_event(&connection, "approval.created", &event, &timestamp).unwrap();
        assert_eq!(id, Some(1), "{name}: event id");
        assert_eq!(rows(&connection), scenario["after"], "{name}: rows");
        replayed += 1;
        let _ = std::fs::remove_dir_all(&home);
    }
    assert!(replayed >= 10, "only {replayed} recorded scenarios");
}

#[test]
fn replays_every_recorded_safe_alternative_reason() {
    let vectors = vectors();
    let cases = vectors["safe_alternative_reason"].as_array().unwrap();
    for case in cases {
        let text = safe_alternative_reason(
            case["reason"].as_str().unwrap(),
            case["reason_code"].as_str(),
            case["approval_queued"].as_bool(),
        );
        assert_eq!(text, case["text"].as_str().unwrap(), "{case}");
    }
    assert!(cases.len() >= 150, "only {} recorded cases", cases.len());
}
