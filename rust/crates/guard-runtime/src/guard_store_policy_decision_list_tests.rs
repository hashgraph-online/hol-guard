//! The saved-decision listing: newest first, optionally one harness, and never
//! a temporary approval-gate grant.

use serde_json::{json, Map, Value};

use super::super::super::tests::request_store;
use super::list_policy_decision_rows;
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
