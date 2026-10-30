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
    call(connection, ids, json!({})).unwrap()
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
