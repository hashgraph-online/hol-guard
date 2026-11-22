use super::*;
use serde_json::{json, Map};

use crate::guard_store_db::StoreError;
use crate::guard_store_op_kind::{method_kind, Kind};

fn store() -> Connection {
    let connection = Connection::open_in_memory().unwrap();
    connection
        .execute_batch(
            "create table native_hook_decision_receipts (
               decision_id text primary key, harness text, workspace_bound integer,
               command_extensions_json text);
             create table native_prompt_decision_receipts (
               decision_id text primary key, harness text, workspace_bound integer,
               prompt_risk_classes_json text);",
        )
        .unwrap();
    connection
}

fn id(digit: char) -> String {
    std::iter::repeat_n(digit, 64).collect()
}

fn read(connection: &Connection, decision_id: Value) -> StoreResult<Value> {
    let mut map = Map::new();
    map.insert("decision_id".to_owned(), decision_id);
    dispatch(connection, &Args(&map))
}

#[test]
fn a_hook_receipt_reads_back_column_by_column() {
    let connection = store();
    connection
        .execute(
            "insert into native_hook_decision_receipts values (?1, 'codex', 1, '{\"b\":1,\"a\":2}')",
            [id('a')],
        )
        .unwrap();
    assert_eq!(
        read(&connection, json!(id('a'))).unwrap(),
        json!({
            "decision_id": id('a'),
            "harness": "codex",
            "workspace_bound": 1,
            "command_extensions_json": "{\"b\":1,\"a\":2}",
        })
    );
}

#[test]
fn a_prompt_receipt_is_found_when_no_hook_receipt_has_the_id() {
    let connection = store();
    connection
        .execute(
            "insert into native_prompt_decision_receipts values (?1, 'omp', 0, '[\"x\"]')",
            [id('b')],
        )
        .unwrap();
    assert_eq!(
        read(&connection, json!(id('b'))).unwrap()["prompt_risk_classes_json"],
        json!("[\"x\"]")
    );
}

#[test]
fn the_hook_table_is_read_before_the_prompt_table() {
    let connection = store();
    connection
        .execute(
            "insert into native_hook_decision_receipts values (?1, 'hook', 1, null)",
            [id('c')],
        )
        .unwrap();
    connection
        .execute(
            "insert into native_prompt_decision_receipts values (?1, 'prompt', 1, null)",
            [id('c')],
        )
        .unwrap();
    assert_eq!(
        read(&connection, json!(id('c'))).unwrap()["harness"],
        json!("hook")
    );
}

#[test]
fn an_unknown_or_malformed_id_reads_as_no_receipt() {
    let connection = store();
    assert_eq!(read(&connection, json!(id('d'))).unwrap(), Value::Null);
    for malformed in [
        id('A'),
        id('g'),
        "a".repeat(63),
        "a".repeat(65),
        String::new(),
    ] {
        assert_eq!(read(&connection, json!(malformed)).unwrap(), Value::Null);
    }
}

#[test]
fn a_decision_id_must_be_text() {
    assert!(matches!(
        read(&store(), json!(7)),
        Err(StoreError::Invalid(_))
    ));
}

#[test]
fn the_read_is_routed_as_a_snapshot() {
    assert!(handles("get_native_decision_receipt"));
    assert!(!handles("record_native_decision_receipt"));
    assert!(super::super::handles("get_native_decision_receipt"));
    assert!(super::super::handles("record_native_decision_receipt"));
    assert!(matches!(
        method_kind("get_native_decision_receipt"),
        Some(Kind::Snapshot)
    ));
}
