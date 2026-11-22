//! Authority evidence lands on this evaluation's receipts and nowhere else.

use serde_json::{json, Map};

use super::*;
use crate::guard_store_op_kind::{method_kind, Kind};

fn store() -> Connection {
    let connection = Connection::open_in_memory().unwrap();
    connection
        .execute_batch(
            "create table runtime_receipts (artifact_id text, policy_decision text, \
             scanner_evidence_json text, approval_source text);",
        )
        .unwrap();
    connection
}

fn add(connection: &Connection, artifact: &str, decision: &str, evidence: &str) {
    connection
        .execute(
            "insert into runtime_receipts values (?, ?, ?, 'policy')",
            [artifact, decision, evidence],
        )
        .unwrap();
}

fn rows(connection: &Connection) -> Vec<(String, String)> {
    let mut statement = connection
        .prepare(
            "select scanner_evidence_json, approval_source from runtime_receipts order by rowid",
        )
        .unwrap();
    statement
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
        .unwrap()
        .map(Result::unwrap)
        .collect()
}

fn amend_with(connection: &Connection, args: Value) -> StoreResult<Value> {
    let args: Map<String, Value> = args.as_object().unwrap().clone();
    amend(connection, &Args(&args))
}

fn request(after: i64, replace: bool) -> Value {
    json!({
        "after_rowid": after,
        "artifact_ids": ["a"],
        "evidence": {"source": "runner", "reason_code": "ok"},
        "approval_source": "saved",
        "source_actions": ["allow"],
        "replace_existing_source": replace,
    })
}

#[test]
fn only_later_rows_of_the_named_artifacts_change() {
    let connection = store();
    add(&connection, "a", "allow", "[]");
    add(&connection, "a", "allow", "[]");
    add(&connection, "b", "allow", "[]");
    add(&connection, "a", "block", "[]");
    assert_eq!(
        amend_with(&connection, request(1, false)).unwrap(),
        json!(2)
    );
    let merged = "[{\"reason_code\": \"ok\", \"source\": \"runner\"}]";
    assert_eq!(
        rows(&connection),
        vec![
            ("[]".into(), "policy".into()),
            (merged.into(), "saved".into()),
            ("[]".into(), "policy".into()),
            (merged.into(), "policy".into()),
        ]
    );
}

#[test]
fn replacing_drops_older_entries_from_the_same_source() {
    let connection = store();
    add(
        &connection,
        "a",
        "allow",
        "[{\"source\": \"runner\", \"reason_code\": \"old\"}, {\"source\": \"other\"}]",
    );
    amend_with(&connection, request(0, true)).unwrap();
    assert_eq!(
        rows(&connection)[0].0,
        "[{\"source\": \"other\"}, {\"reason_code\": \"ok\", \"source\": \"runner\"}]"
    );
}

#[test]
fn rows_past_one_page_are_all_amended() {
    let connection = store();
    for _ in 0..(PAGE_ROWS + 3) {
        add(&connection, "a", "allow", "[]");
    }
    assert_eq!(
        amend_with(&connection, request(0, false)).unwrap(),
        json!(PAGE_ROWS + 3)
    );
}

#[test]
fn an_empty_store_changes_nothing() {
    assert_eq!(amend_with(&store(), request(0, false)).unwrap(), json!(0));
}

#[test]
fn malformed_arguments_are_refused_and_the_method_is_a_write() {
    let connection = store();
    let mut missing = request(0, false);
    missing.as_object_mut().unwrap().remove("artifact_ids");
    assert!(amend_with(&connection, missing).is_err());
    let mut bad = request(0, false);
    bad["evidence"] = json!("text");
    assert!(amend_with(&connection, bad).is_err());
    assert!(matches!(
        method_kind("amend_receipt_authority_evidence"),
        Some(Kind::Write)
    ));
}
