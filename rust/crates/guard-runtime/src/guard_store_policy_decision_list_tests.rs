//! The saved-decision listing: newest first, optionally one harness, and never
//! a temporary approval-gate grant.

use serde_json::{json, Map, Value};

use super::super::super::tests::request_store;
use super::{list_local_policy_rows, list_policy_decision_rows, read_policy_decision_row};
use crate::guard_store_args::Args;

fn listed(connection: &rusqlite::Connection, args: Value) -> Vec<(String, String)> {
    let args: Map<String, Value> = args.as_object().cloned().unwrap_or_default();
    let reply = list_policy_decision_rows(connection, &Args(&args)).unwrap();
    reply["rows"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| {
            (
                row["harness"].as_str().unwrap().to_owned(),
                row["source"].as_str().unwrap().to_owned(),
            )
        })
        .collect()
}

fn seeded() -> rusqlite::Connection {
    let connection = request_store();
    connection
        .execute_batch(
            "delete from policy_decisions;
             insert into policy_decisions (harness, scope, action, source, updated_at, expires_at) values
             ('codex', 'global', 'allow', 'manual', '2026-10-16T09:00:01Z', null),
             ('claude-code', 'global', 'block', 'cloud-sync', '2026-10-16T09:00:03Z', null),
             ('codex', 'global', 'allow', 'approval-gate', '2026-10-16T09:00:02Z', null),
             ('codex', 'global', 'allow', 'approval-gate', '2026-10-16T09:00:04Z', '2026-10-16T10:00:00Z');",
        )
        .unwrap();
    connection
}

#[test]
fn rows_are_listed_newest_first_without_temporary_grants() {
    let connection = seeded();
    assert_eq!(
        listed(&connection, json!({})),
        vec![
            ("claude-code".to_owned(), "cloud-sync".to_owned()),
            ("codex".to_owned(), "approval-gate".to_owned()),
            ("codex".to_owned(), "manual".to_owned()),
        ]
    );
}

#[test]
fn a_harness_narrows_the_listing() {
    let connection = seeded();
    assert_eq!(
        listed(&connection, json!({"harness": "codex"})),
        vec![
            ("codex".to_owned(), "approval-gate".to_owned()),
            ("codex".to_owned(), "manual".to_owned()),
        ]
    );
}

#[test]
fn a_listed_row_carries_every_column_the_listing_reads() {
    let connection = seeded();
    let args = Map::new();
    let reply = list_policy_decision_rows(&connection, &Args(&args)).unwrap();
    let row = reply["rows"][0].as_object().unwrap();
    for column in [
        "decision_id",
        "artifact_hash",
        "policy_provenance_json",
        "integrity_generation",
        "payload_mac",
        "signed_at",
    ] {
        assert!(row.contains_key(column), "{column}");
    }
}

#[test]
fn a_harness_that_is_not_text_is_refused() {
    let connection = seeded();
    let args: Map<String, Value> = json!({"harness": 7}).as_object().cloned().unwrap();
    assert!(list_policy_decision_rows(&connection, &Args(&args)).is_err());
}

fn read(connection: &rusqlite::Connection, decision_id: Value) -> Value {
    let args: Map<String, Value> = json!({ "decision_id": decision_id })
        .as_object()
        .cloned()
        .unwrap_or_default();
    read_policy_decision_row(connection, &Args(&args)).unwrap()["row"].clone()
}

fn id_of(connection: &rusqlite::Connection, source: &str, temporary: bool) -> i64 {
    let sql = if temporary {
        "select decision_id from policy_decisions where source = ? and expires_at is not null"
    } else {
        "select decision_id from policy_decisions where source = ? and expires_at is null"
    };
    connection
        .query_row(sql, [source], |row| row.get(0))
        .unwrap()
}

#[test]
fn a_saved_decision_reads_back_by_its_id_with_every_column() {
    let connection = seeded();
    let id = id_of(&connection, "cloud-sync", false);
    let row = read(&connection, json!(id));
    assert_eq!(row["decision_id"], json!(id));
    assert_eq!(row["harness"], json!("claude-code"));
    for column in [
        "policy_provenance_json",
        "integrity_generation",
        "payload_mac",
        "signed_at",
    ] {
        assert!(row.as_object().unwrap().contains_key(column), "{column}");
    }
}

#[test]
fn a_temporary_grant_or_a_missing_id_reads_as_no_row() {
    let connection = seeded();
    let temporary = id_of(&connection, "approval-gate", true);
    assert_eq!(read(&connection, json!(temporary)), Value::Null);
    assert_eq!(read(&connection, json!(999_999)), Value::Null);
    let saved_gate = id_of(&connection, "approval-gate", false);
    assert_eq!(
        read(&connection, json!(saved_gate))["source"],
        json!("approval-gate")
    );
}

#[test]
fn a_decision_id_that_is_not_an_integer_is_refused() {
    let connection = seeded();
    for bad in [json!("7"), json!(true), json!(1.5)] {
        let args: Map<String, Value> = json!({ "decision_id": bad }).as_object().cloned().unwrap();
        assert!(read_policy_decision_row(&connection, &Args(&args)).is_err());
    }
    assert!(read_policy_decision_row(&connection, &Args(&Map::new())).is_err());
}

fn local(connection: &rusqlite::Connection, args: Value) -> Vec<(String, String, Option<String>)> {
    let args: Map<String, Value> = args.as_object().cloned().unwrap_or_default();
    let reply = list_local_policy_rows(connection, &Args(&args)).unwrap();
    reply["rows"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| {
            assert!(row.as_object().unwrap().contains_key("payload_mac"));
            (
                row["harness"].as_str().unwrap().to_owned(),
                row["source"].as_str().unwrap().to_owned(),
                row["expires_at"].as_str().map(str::to_owned),
            )
        })
        .collect()
}

#[test]
fn local_rows_leave_out_remote_sources_but_keep_temporary_grants() {
    let connection = seeded();
    assert_eq!(
        local(&connection, json!({})),
        vec![
            (
                "codex".to_owned(),
                "approval-gate".to_owned(),
                Some("2026-10-16T10:00:00Z".to_owned())
            ),
            ("codex".to_owned(), "approval-gate".to_owned(), None),
            ("codex".to_owned(), "manual".to_owned(), None),
        ]
    );
}

#[test]
fn a_harness_narrows_the_local_rows() {
    let connection = seeded();
    assert!(local(&connection, json!({"harness": "claude-code"})).is_empty());
    assert_eq!(local(&connection, json!({"harness": "codex"})).len(), 3);
}
