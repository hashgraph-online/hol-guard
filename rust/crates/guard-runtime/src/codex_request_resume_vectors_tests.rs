//! Parity with `codex_resume.py` over the store statements of
//! `store_resume.py`: each vector seeds the approval, operation and resume
//! rows, runs one call against an in-memory `guard.db` and compares the
//! returned record or refusal, the continuations sent and the final row.

use std::cell::RefCell;

use rusqlite::Connection;
use serde_json::{json, Map, Value};

use super::{defer, retry, seed as seed_record, status, Call, Outcome};

const VECTORS: &str =
    include_str!("../testdata/codex_app_server/codex_request_resume_vectors.json");
const FINAL_COLUMNS: [&str; 16] = [
    "request_id",
    "operation_id",
    "harness",
    "resolution_action",
    "strategy",
    "supported",
    "status",
    "thread_id",
    "reason",
    "message",
    "last_error",
    "attempt_count",
    "created_at",
    "updated_at",
    "last_attempt_at",
    "sent_at",
];

fn store() -> Connection {
    let connection = Connection::open_in_memory().expect("open");
    // `approval_requests` keeps each cell's own type so a non-text
    // resolution stays non-text, as the recording's store returned it.
    connection
        .execute_batch(
            "create table approval_requests (request_id text primary key, harness, resolution_action);
             create table guard_operations (
               operation_id text primary key, session_id text not null, harness text not null,
               operation_type text not null, status text not null,
               approval_request_ids_json text not null, resume_token text,
               metadata_json text not null, created_at text not null, updated_at text not null);
             create table guard_request_resumes (
               request_id text primary key, operation_id text, harness text not null,
               resolution_action text, strategy text not null,
               supported integer not null default 0, status text not null, thread_id text,
               reason text, message text, last_error text,
               attempt_count integer not null default 0, created_at text not null,
               updated_at text not null, last_attempt_at text, sent_at text,
               continuation_contract_version text, continuation_capability text,
               continuation_status text, continuation_reason text,
               continuation_evidence_json text not null default '[]',
               continuation_offer_hash text, continuation_action text,
               continuation_completed_at text, continuation_cancelled_at text);",
        )
        .expect("schema");
    connection
}

fn sql(value: &Value) -> rusqlite::types::Value {
    match value {
        Value::Null => rusqlite::types::Value::Null,
        Value::Bool(flag) => rusqlite::types::Value::Integer(i64::from(*flag)),
        Value::Number(number) => number.as_i64().map_or_else(
            || rusqlite::types::Value::Real(number.as_f64().unwrap_or_default()),
            rusqlite::types::Value::Integer,
        ),
        Value::String(text) => rusqlite::types::Value::Text(text.clone()),
        other => rusqlite::types::Value::Text(other.to_string()),
    }
}

fn insert_operation(connection: &Connection, request_id: &str, operation: &Value) {
    let metadata = operation.get("metadata").cloned().unwrap_or(Value::Null);
    connection
        .execute(
            "insert into guard_operations values (?, 'session-1', ?, 'tool', ?, ?, null, ?, ?, ?)",
            rusqlite::params![
                operation["operation_id"].as_str().unwrap_or("op-1"),
                operation["harness"].as_str().unwrap_or("codex"),
                operation["status"]
                    .as_str()
                    .unwrap_or("waiting_on_approval"),
                json!([request_id]).to_string(),
                metadata.to_string(),
                "2026-10-11T10:00:00+00:00",
                "2026-10-11T10:00:00+00:00",
            ],
        )
        .expect("operation");
}

fn seed(connection: &Connection, vector: &Value, request_id: &str) {
    if let Some(approval) = vector["approval_request"].as_object() {
        connection
            .execute(
                "insert into approval_requests values (?, ?, ?)",
                rusqlite::params![
                    request_id,
                    sql(&approval["harness"]),
                    sql(&approval["resolution_action"]),
                ],
            )
            .expect("approval");
    }
    let operation = &vector["operation"];
    if operation.is_object() {
        insert_operation(connection, request_id, operation);
    } else if !vector["expected"]["dispatch_calls"]
        .as_array()
        .is_none_or(Vec::is_empty)
    {
        // The recording stubbed the send; give the replay an operation to send to.
        insert_operation(
            connection,
            request_id,
            &json!({ "metadata": { "codex_thread_id": "thread-1" } }),
        );
    }
    if let Some(existing) = vector["existing_resume"].as_object() {
        let columns: Vec<&str> = existing.keys().map(String::as_str).collect();
        let marks = vec!["?"; columns.len()].join(", ");
        let values: Vec<rusqlite::types::Value> = existing.values().map(sql).collect();
        connection
            .execute(
                &format!(
                    "insert into guard_request_resumes ({}) values ({marks})",
                    columns.join(", ")
                ),
                rusqlite::params_from_iter(values),
            )
            .expect("resume");
    }
}

fn final_row(connection: &Connection, request_id: &str) -> Value {
    let sql = format!(
        "select {} from guard_request_resumes where request_id = ?",
        FINAL_COLUMNS.join(", ")
    );
    let row = connection
        .query_row(&sql, [request_id], |row| {
            let mut map = Map::new();
            for (index, column) in FINAL_COLUMNS.iter().enumerate() {
                let value: rusqlite::types::Value = row.get(index)?;
                let value = match value {
                    rusqlite::types::Value::Integer(number) => json!(number),
                    rusqlite::types::Value::Text(text) => json!(text),
                    _ => Value::Null,
                };
                map.insert((*column).to_owned(), value);
            }
            Ok(Value::Object(map))
        })
        .ok();
    row.unwrap_or(Value::Null)
}

fn replay(vector: &Value) -> Value {
    let call_spec = &vector["call"];
    let request_id = call_spec["request_id"].as_str().expect("request id");
    let connection = store();
    seed(&connection, vector, request_id);
    let call = Call {
        request_id,
        now: call_spec["now"].as_str().expect("now"),
    };
    let sent = RefCell::new(Vec::new());
    let result = vector["dispatch_result"].clone();
    let send = |action: &str, _metadata: &Map<String, Value>| {
        sent.borrow_mut().push(action.to_owned());
        result.clone()
    };
    let outcome = match call_spec["kind"].as_str() {
        Some("seed") => Outcome::Resume(seed_record(&connection, &call).expect("seed")),
        Some("status") => Outcome::Resume(status(&connection, &call).expect("status")),
        Some("retry") => {
            let force = call_spec["force"].as_bool().unwrap_or(false);
            retry(&connection, &call, force, &send).expect("retry")
        }
        _ => Outcome::Resume(
            defer(
                &connection,
                &call,
                call_spec["action"].as_str().expect("action"),
            )
            .expect("defer"),
        ),
    };
    let mut expected = match outcome {
        Outcome::Resume(resume) => json!({ "result": resume }),
        Outcome::Refused(error) => json!({ "error": error }),
    };
    expected["dispatch_calls"] = json!(sent.into_inner());
    expected["final_row"] = final_row(&connection, request_id);
    expected
}

#[test]
fn codex_request_resume_matches_recorded_python() {
    let document: Value = serde_json::from_str(VECTORS).expect("vectors");
    let vectors = document["vectors"].as_array().expect("vector list");
    assert!(vectors.len() >= 60);
    let mut failures = Vec::new();
    for vector in vectors {
        let mut want = vector["expected"].clone();
        let actions: Vec<Value> = want["dispatch_calls"]
            .as_array()
            .expect("calls")
            .iter()
            .map(|call| call["action"].clone())
            .collect();
        want["dispatch_calls"] = Value::Array(actions);
        let got = replay(vector);
        if got != want {
            failures.push(format!("{}:\n  want {want}\n  got  {got}", vector["name"]));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn retry_without_a_codex_operation_reports_the_session_missing_without_sending() {
    let connection = store();
    connection
        .execute_batch(
            "insert into approval_requests values ('req-1', 'codex', 'allow-once');
             insert into guard_request_resumes (request_id, harness, strategy, supported, status,
               thread_id, attempt_count, created_at, updated_at)
             values ('req-1', 'codex', 'codex-app-server-thread', 1, 'pending', 'thread-1', 0,
               '2026-10-11T10:00:00+00:00', '2026-10-11T10:00:00+00:00');",
        )
        .expect("rows");
    insert_operation(
        &connection,
        "req-1",
        &json!({ "harness": "cursor", "metadata": { "codex_thread_id": "thread-1" } }),
    );
    let call = Call {
        request_id: "req-1",
        now: "2026-10-11T12:00:00+00:00",
    };
    let send = |_: &str, _: &Map<String, Value>| -> Value { panic!("no continuation expected") };
    let Outcome::Resume(Some(resume)) = retry(&connection, &call, false, &send).expect("retry")
    else {
        panic!("resume record expected");
    };
    assert_eq!(resume["status"], "skipped");
    assert_eq!(resume["reason"], "session_not_found");
    assert_eq!(resume["supported"], false);
}

#[test]
fn retry_sends_to_the_newest_codex_operation_listing_the_request() {
    let connection = store();
    connection
        .execute_batch(
            "insert into approval_requests values ('req-1', 'codex', 'allow');
             insert into guard_request_resumes (request_id, harness, strategy, supported, status,
               thread_id, attempt_count, created_at, updated_at)
             values ('req-1', 'codex', 'codex-app-server-thread', 1, 'pending', 'thread-1', 0,
               '2026-10-11T10:00:00+00:00', '2026-10-11T10:00:00+00:00');
             insert into guard_operations values ('op-a', 's', 'claude-code', 'tool', 'waiting',
               '[\"req-1\"]', null, '{}', 't', '2026-10-11T11:00:00+00:00');
             insert into guard_operations values ('op-b', 's', 'codex', 'tool', 'waiting',
               '[\"req-1\"]', null, '{\"codex_thread_id\": \"thread-b\"}', 't',
               '2026-10-11T09:00:00+00:00');",
        )
        .expect("rows");
    let call = Call {
        request_id: "req-1",
        now: "2026-10-11T12:00:00+00:00",
    };
    let seen = RefCell::new(None);
    let send = |_: &str, metadata: &Map<String, Value>| {
        *seen.borrow_mut() = metadata.get("codex_thread_id").cloned();
        json!({ "status": "sent", "reason": "turn_started" })
    };
    let Outcome::Resume(Some(resume)) = retry(&connection, &call, false, &send).expect("retry")
    else {
        panic!("resume record expected");
    };
    assert_eq!(seen.into_inner(), Some(json!("thread-b")));
    assert_eq!(resume["status"], "sent");
    assert_eq!(resume["sent_at"], "2026-10-11T12:00:00+00:00");
}
