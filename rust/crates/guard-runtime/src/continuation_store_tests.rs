//! Durable-state traces for the native continuation store.
use super::*;

#[test]
fn sqlite_exception_and_windows_wake_keys_preserve_public_behavior() {
    for (code, expected) in [
        (1, "sqlite3.OperationalError"),
        (2, "sqlite3.InternalError"),
        (5, "sqlite3.OperationalError"),
        (6, "sqlite3.OperationalError"),
        (8, "sqlite3.OperationalError"),
        (10, "sqlite3.OperationalError"),
        (12, "sqlite3.InternalError"),
        (13, "sqlite3.OperationalError"),
        (14, "sqlite3.OperationalError"),
        (16, "sqlite3.OperationalError"),
        (18, "sqlite3.DataError"),
        (19, "sqlite3.IntegrityError"),
        (20, "sqlite3.IntegrityError"),
        (21, "sqlite3.InterfaceError"),
        (22, "sqlite3.DatabaseError"),
        (23, "sqlite3.DatabaseError"),
        (25, "sqlite3.InterfaceError"),
        (27, "sqlite3.DatabaseError"),
        (2067, "sqlite3.IntegrityError"),
    ] {
        let error = rusqlite::Error::SqliteFailure(rusqlite::ffi::Error::new(code), None);
        assert_eq!(sqlite_exception(&error), expected, "SQLite code {code}");
    }
    assert_eq!(
        wake_database_key(r"\\?\C:\guard\store.db"),
        r"C:\guard\store.db"
    );
    assert_eq!(
        wake_database_key(r"\\?\UNC\server\share\store.db"),
        r"\\server\share\store.db"
    );
    assert_eq!(wake_database_key("/guard/store.db"), "/guard/store.db");
}

fn sql_value(value: &Value) -> rusqlite::types::Value {
    match value {
        Value::Null => rusqlite::types::Value::Null,
        Value::String(value) => rusqlite::types::Value::Text(value.clone()),
        _ => panic!("lease fixture cells must be text or null"),
    }
}

#[test]
fn original_python_sqlite_lease_transition_traces() {
    let document: Value = serde_json::from_str(include_str!(
        "../tests/fixtures/continuation_lease_traces.json"
    ))
    .unwrap();
    for (index, case) in document["cases"].as_array().unwrap().iter().enumerate() {
        let mut connection = Connection::open_in_memory().unwrap();
        connection
            .execute_batch(document["schema_sql"].as_str().unwrap())
            .unwrap();
        for seed in case["seed"].as_array().unwrap() {
            let values: Vec<_> = seed.as_array().unwrap().iter().map(sql_value).collect();
            connection
                .execute(
                    "insert into guard_continuation_claims values (?,?,?,?,?,?,?,?)",
                    rusqlite::params_from_iter(values),
                )
                .unwrap();
        }
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        let outcome = match claim(&tx, &case["args"]) {
            Ok(result) => {
                tx.commit().unwrap();
                result
            }
            Err(StoreError::Value(error)) => {
                tx.rollback().unwrap();
                json!({"exception":"ValueError","error":error})
            }
            Err(error) => panic!("trace {index}: {error:?}"),
        };
        assert_eq!(outcome, case["expected"], "trace {index}");
        let mut statement = connection
            .prepare("select * from guard_continuation_claims order by request_id")
            .unwrap();
        let rows = statement
            .query_map([], |row| {
                (0..8)
                    .map(|i| row.get::<_, Option<String>>(i).map(|v| json!(v)))
                    .collect::<rusqlite::Result<Vec<_>>>()
            })
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        assert_eq!(json!(rows), case["rows"], "trace {index} durable state");
    }
}

#[test]
fn persisted_continuation_evidence_matches_original_python_bytes() {
    let connection = Connection::open_in_memory().unwrap();
    connection
        .execute_batch(
            "create table guard_request_resumes (request_id text primary key, operation_id text, \
             harness text not null, resolution_action text, strategy text not null, \
             supported integer not null default 0, status text not null, thread_id text, \
             reason text, message text, last_error text, attempt_count integer not null default 0, \
             created_at text not null, updated_at text not null, last_attempt_at text, sent_at text, \
             continuation_contract_version text, continuation_capability text, \
             continuation_status text, continuation_reason text, \
             continuation_evidence_json text not null default '[]', continuation_offer_hash text, \
             continuation_action text, continuation_completed_at text, continuation_cancelled_at text)",
        )
        .unwrap();
    let args = json!({
        "request_id": "req-1",
        "now": "2026-10-12T00:00:00+00:00",
        "resume_seed": {"operation_id": "op-1", "harness": "codex", "strategy": "continuation", "supported": true, "thread_id": null},
        "resume_update": {
            "resolution_action": "allow_once", "status": "sent", "attempt_count": 1,
            "continuation_evidence": [{"correlationId": "corr-\u{e9}1", "evidenceId": "ev-1", "status": "completed"}]
        },
        "operation_update": null
    });
    persist_resume(&connection, &args).unwrap();
    let stored: String = connection
        .query_row(
            "select continuation_evidence_json from guard_request_resumes where request_id = 'req-1'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    // Recorded from the original Python writer:
    // json.dumps(evidence, separators=(",", ":")).
    assert_eq!(
        stored,
        r#"[{"correlationId":"corr-\u00e91","evidenceId":"ev-1","status":"completed"}]"#
    );
}
