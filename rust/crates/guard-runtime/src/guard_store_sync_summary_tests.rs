//! The summary row and the connect proof are written together.

use serde_json::json;

use super::*;

const T1: &str = "2026-08-03T00:01:00+00:00";
const SUMMARY_TEXT: &str = "{\"synced_at\": \"2026-08-03T00:01:00+00:00\", \"receipts_stored\": 4, \"inventory_tracked\": 2}";
const SCHEMA: &str = "create table sync_state (state_key text primary key,
       payload_json text not null, updated_at text not null);
     create table guard_connect_states (request_id text primary key,
       sync_url text not null, allowed_origin text not null, status text not null,
       milestone text not null, reason text, created_at text not null,
       updated_at text not null, expires_at text not null, completed_at text,
       proof_json text);";

fn store(status: &str) -> Connection {
    let connection = Connection::open_in_memory().unwrap();
    connection.execute_batch(SCHEMA).unwrap();
    seed(&connection, status);
    connection
}

fn seed(connection: &Connection, status: &str) {
    connection
        .execute(
            "insert into guard_connect_states values ('req-1', 'https://sync.example.test', \
             'https://sync.example.test', ?, 'first_sync_pending', null, 't0', 't0', \
             '2026-08-03T01:00:00+00:00', 't0', '{}')",
            [status],
        )
        .unwrap();
}

fn run(connection: &Connection, args: Value) -> StoreResult<Value> {
    let Value::Object(args) = args else {
        unreachable!()
    };
    method(connection, &Args(&args))
}

fn summary_row(connection: &Connection) -> Option<(String, String)> {
    connection
        .query_row(
            "select payload_json, updated_at from sync_state where state_key = ?",
            [SUMMARY],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .ok()
}

fn connect_row(connection: &Connection) -> (String, String, String) {
    connection
        .query_row(
            "select status, milestone, proof_json from guard_connect_states",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap()
}

#[test]
fn both_rows_are_written_from_one_summary() {
    let connection = store("connected");
    let state = run(
        &connection,
        json!({"summary_json": SUMMARY_TEXT, "now": T1,
               "persist_summary": true, "record_connect": true}),
    )
    .unwrap();
    assert_eq!(
        summary_row(&connection),
        Some((SUMMARY_TEXT.to_owned(), T1.to_owned()))
    );
    let (status, milestone, proof) = connect_row(&connection);
    assert_eq!(
        (status.as_str(), milestone.as_str()),
        ("connected", "first_sync_succeeded")
    );
    let proof: Value = serde_json::from_str(&proof).unwrap();
    assert_eq!(proof["first_synced_at"], json!(T1));
    assert_eq!(proof["receipts_stored"], json!(4));
    assert_eq!(proof["inventory_items"], json!(2));
    assert_eq!(state["milestone"], json!("first_sync_succeeded"));
}

#[test]
fn each_write_can_be_skipped() {
    let connection = store("connected");
    let answer = run(
        &connection,
        json!({"summary_json": SUMMARY_TEXT, "now": T1, "persist_summary": true}),
    )
    .unwrap();
    assert_eq!(answer, Value::Null);
    assert!(summary_row(&connection).is_some());
    assert_eq!(connect_row(&connection).1, "first_sync_pending");

    let connection = store("connected");
    run(
        &connection,
        json!({"summary_json": SUMMARY_TEXT, "now": T1, "record_connect": true}),
    )
    .unwrap();
    assert_eq!(summary_row(&connection), None);
    assert_eq!(connect_row(&connection).1, "first_sync_succeeded");
}

#[test]
fn a_device_without_a_connected_state_still_stores_the_summary() {
    let connection = store("waiting");
    let answer = run(
        &connection,
        json!({"summary_json": SUMMARY_TEXT, "now": T1,
               "persist_summary": true, "record_connect": true}),
    )
    .unwrap();
    assert_eq!(answer, Value::Null);
    assert!(summary_row(&connection).is_some());
    assert_eq!(connect_row(&connection).0, "waiting");
}

#[test]
fn a_summary_that_is_not_an_object_is_refused() {
    let connection = store("connected");
    for text in ["[1]", "not json", "\"text\""] {
        let result = run(
            &connection,
            json!({"summary_json": text, "now": T1, "persist_summary": true}),
        );
        assert!(result.is_err(), "{text}");
    }
    assert_eq!(summary_row(&connection), None);
}

#[test]
fn a_failed_connect_update_rolls_back_the_summary_through_the_store_op() {
    // A trigger makes the connect update fail after the summary row is
    // written. Only the store op's write transaction can undo the row, so this
    // fails if the method stops being dispatched as a write.
    let nonce = crate::unique_nanos::unique_nanos();
    let home = std::env::temp_dir().join(format!(
        "hol-guard-store-sync-summary-{}-{nonce}",
        std::process::id()
    ));
    std::fs::create_dir_all(&home).unwrap();
    let home = std::fs::canonicalize(home).unwrap();
    let path = home.join("guard.db");
    let previous = "{\"synced_at\": \"older\"}";
    {
        let connection = Connection::open(&path).unwrap();
        connection.execute_batch(SCHEMA).unwrap();
        seed(&connection, "connected");
        connection
            .execute_batch(
                "create trigger refuse_connect before update on guard_connect_states
                   begin select raise(abort, 'refused'); end;",
            )
            .unwrap();
        connection
            .execute(
                "insert into sync_state values (?, ?, 't0')",
                [SUMMARY, previous],
            )
            .unwrap();
    }
    let Value::Object(args) = json!({"summary_json": SUMMARY_TEXT, "now": T1,
                                      "persist_summary": true, "record_connect": true})
    else {
        unreachable!()
    };
    let request = guard_contracts::GuardStoreRequestV1 {
        schema: guard_contracts::GUARD_STORE_REQUEST_SCHEMA.to_owned(),
        request_id: "sync-summary".to_owned(),
        store_path: path.to_string_lossy().into_owned(),
        guard_home: home.to_string_lossy().into_owned(),
        method: "record_sync_summary".to_owned(),
        source: "default".to_owned(),
        busy_timeout_ms: 5000,
        args,
    };
    match crate::guard_store_op::evaluate(&request) {
        Err(crate::guard_store_db::StoreError::Sqlite(error)) => {
            assert!(error.to_string().contains("refused"), "{error}");
        }
        other => panic!("expected the refused connect update, got {other:?}"),
    }
    let connection = Connection::open(&path).unwrap();
    assert_eq!(
        summary_row(&connection),
        Some((previous.to_owned(), "t0".to_owned()))
    );
    drop(connection);
    let _ = std::fs::remove_dir_all(&home);
}
