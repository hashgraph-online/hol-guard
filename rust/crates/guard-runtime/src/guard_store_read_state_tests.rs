//! Read marks answer as `store_read_state.py` did.

use rusqlite::Connection;
use serde_json::json;

use super::*;

fn store() -> Connection {
    let connection = Connection::open_in_memory().unwrap();
    connection
        .execute_batch(
            "create table guard_request_read_state (
               request_id text primary key, read_at text not null);",
        )
        .unwrap();
    connection
}

fn call(
    connection: &Connection,
    op: fn(&Connection, &Args<'_>) -> StoreResult<Value>,
    args: Value,
) -> StoreResult<Value> {
    let Value::Object(args) = args else {
        unreachable!()
    };
    op(connection, &Args(&args))
}

fn read_ids(connection: &Connection) -> Value {
    let mut all = Vec::new();
    let mut after = Value::Null;
    loop {
        let page = call(connection, ids, json!({"after": after})).unwrap();
        all.extend(page["ids"].as_array().unwrap().iter().cloned());
        after = page["after"].clone();
        if after.is_null() {
            return Value::Array(all);
        }
    }
}

#[test]
fn marks_read_newest_first_and_a_repeat_moves_to_the_front() {
    let connection = store();
    call(
        &connection,
        mark_read,
        json!({"request_ids": ["a", "b", "a"], "now": "t1"}),
    )
    .unwrap();
    call(
        &connection,
        mark_read,
        json!({"request_ids": ["c"], "now": "t2"}),
    )
    .unwrap();
    assert_eq!(read_ids(&connection)[0], json!("c"));
    assert_eq!(read_ids(&connection).as_array().unwrap().len(), 3);

    call(
        &connection,
        mark_read,
        json!({"request_ids": ["a"], "now": "t3"}),
    )
    .unwrap();
    assert_eq!(read_ids(&connection)[0], json!("a"));
    assert_eq!(read_ids(&connection).as_array().unwrap().len(), 3);
}

#[test]
fn no_ids_writes_nothing_and_needs_no_time() {
    let connection = store();
    call(&connection, mark_read, json!({"request_ids": []})).unwrap();
    assert_eq!(read_ids(&connection), json!([]));
    assert!(matches!(
        call(&connection, mark_read, json!({"now": "t1"})),
        Err(StoreError::Invalid("native_guard_store_args_invalid"))
    ));
}

#[test]
fn only_the_newest_marks_are_kept() {
    let connection = store();
    for index in 0..=READ_STATE_LIMIT {
        connection
            .execute(
                "insert into guard_request_read_state values (?1, ?2)",
                (format!("old-{index}"), format!("t0-{index:06}")),
            )
            .unwrap();
    }
    call(
        &connection,
        mark_read,
        json!({"request_ids": ["new"], "now": "t1"}),
    )
    .unwrap();
    let kept = read_ids(&connection);
    let kept = kept.as_array().unwrap();
    assert_eq!(kept.len() as i64, READ_STATE_LIMIT);
    assert_eq!(kept[0], json!("new"));
    assert!(!kept.contains(&json!("old-0")));
    assert!(!kept.contains(&json!("old-1")));
    assert!(kept.contains(&json!("old-2")));
}

#[test]
fn unread_and_clear_remove_marks() {
    let connection = store();
    call(
        &connection,
        mark_read,
        json!({"request_ids": ["a", "b"], "now": "t1"}),
    )
    .unwrap();
    call(&connection, mark_unread, json!({"request_id": "a"})).unwrap();
    assert_eq!(read_ids(&connection), json!(["b"]));
    call(&connection, mark_unread, json!({"request_id": "missing"})).unwrap();
    call(&connection, clear, json!({})).unwrap();
    assert_eq!(read_ids(&connection), json!([]));
}

#[test]
fn a_read_pages_by_cursor_and_a_mark_between_pages_shifts_nothing() {
    let connection = store();
    for index in 0..PAGE_ROWS + 2 {
        connection
            .execute(
                "insert into guard_request_read_state values (?1, 't1')",
                [format!("id-{index}")],
            )
            .unwrap();
    }
    let first = call(&connection, ids, json!({})).unwrap();
    assert_eq!(first["ids"].as_array().unwrap().len() as i64, PAGE_ROWS);
    assert_eq!(first["ids"][0], json!("id-0"));
    call(
        &connection,
        mark_read,
        json!({"request_ids": ["newest"], "now": "t2"}),
    )
    .unwrap();
    let rest = call(&connection, ids, json!({"after": first["after"]})).unwrap();
    let last = PAGE_ROWS + 1;
    assert_eq!(
        rest["ids"],
        json!([format!("id-{PAGE_ROWS}"), format!("id-{last}")])
    );
    assert_eq!(rest["after"], Value::Null);
}

#[test]
fn a_read_stops_at_its_byte_budget() {
    let connection = store();
    let long = "x".repeat(READ_BYTES_BUDGET / 2 + 1);
    for index in 0..3 {
        connection
            .execute(
                "insert into guard_request_read_state values (?1, 't1')",
                [format!("{index}{long}")],
            )
            .unwrap();
    }
    let first = call(&connection, ids, json!({})).unwrap();
    assert_eq!(first["ids"].as_array().unwrap().len(), 1);
    assert!(!first["after"].is_null());
    assert_eq!(read_ids(&connection).as_array().unwrap().len(), 3);
}

#[test]
fn a_cursor_that_is_not_a_read_at_and_rowid_pair_is_refused() {
    let connection = store();
    for after in [json!("t1"), json!(["t1"]), json!([1, "t1"])] {
        assert!(matches!(
            call(&connection, ids, json!({"after": after})),
            Err(StoreError::Invalid("native_guard_store_args_invalid"))
        ));
    }
}
