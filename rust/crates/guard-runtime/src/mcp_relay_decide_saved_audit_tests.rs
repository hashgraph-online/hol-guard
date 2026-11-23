//! The audit events a relayed lookup raises are collected on the read-only
//! snapshot and written afterwards, as the proxy's lookup writes them.

use super::super::store::{self, AUDIT_UNWRITTEN};
use super::tests::{binding, decide_row, guard_home, Row};
use rusqlite::Connection;
use serde_json::json;
use std::path::Path;

fn events(connection: &Connection) -> Vec<(String, String)> {
    let mut statement = connection
        .prepare("select event_name, occurred_at from guard_events order by event_id")
        .unwrap();
    statement
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap()
}

fn need() -> serde_json::Value {
    json!({
        "kind": "policy_lookup",
        "harness": "codex",
        "artifact_id": "codex:project:files:read",
        "artifact_hash": "sha256:relay",
        "workspace": null,
        "publisher": null,
        "runtime_exact_match_context": null,
        "memory_command": null,
        "memory_artifact_type": null,
        "memory_artifact_name": null,
    })
}

/// A local row with no integrity metadata, under the protected state. The
/// lookup refuses it and records the refusal; on the snapshot the lookup now
/// answers, and the relay writes the events it collected.
#[test]
fn an_unsigned_local_row_is_refused_and_its_audit_is_written_after() {
    let (home, connection) = guard_home("audit-unsigned");
    decide_row(
        &connection,
        &Row {
            unsigned: true,
            ..Row::default()
        },
    );
    let guard_home = home.to_str().unwrap();
    let snapshot = store::open(Path::new(guard_home)).unwrap().expect("store");
    let saved = store::saved(&snapshot, &binding(), guard_home, "codex")
        .unwrap()
        .expect("saved rows");
    let answer = saved.answer(&need()).unwrap();
    assert!(answer["decision"].is_null());
    assert_eq!(answer["ignored_local_integrity"], true);
    assert!(
        events(&connection).is_empty(),
        "nothing written on the snapshot"
    );

    let audit = saved.into_audit();
    let names: Vec<&str> = audit.iter().map(|(name, _, _)| name.as_str()).collect();
    assert_eq!(
        names,
        ["policy_integrity_violation", "rule.ignored.local_integrity"]
    );
    drop(snapshot);
    store::write_audit(guard_home, &audit).unwrap();
    let written = events(&connection);
    assert_eq!(
        written,
        audit
            .iter()
            .map(|(name, _, at)| (name.clone(), at.clone()))
            .collect::<Vec<_>>()
    );
}

#[test]
fn a_signed_row_raises_no_audit_and_an_empty_audit_writes_nothing() {
    let (home, connection) = guard_home("audit-signed");
    decide_row(&connection, &Row::default());
    let guard_home = home.to_str().unwrap();
    let snapshot = store::open(Path::new(guard_home)).unwrap().expect("store");
    let saved = store::saved(&snapshot, &binding(), guard_home, "codex")
        .unwrap()
        .expect("saved rows");
    assert_eq!(
        saved.answer(&need()).unwrap()["decision"]["action"],
        "block"
    );
    let audit = saved.into_audit();
    assert!(audit.is_empty());
    // No store is opened for nothing to write, so even a missing home is fine.
    store::write_audit("/nonexistent-guard-home", &audit).unwrap();
    assert!(events(&connection).is_empty());
}

#[test]
fn an_audit_the_store_refuses_fails_the_call_and_writes_nothing() {
    let (home, connection) = guard_home("audit-refused");
    connection
        .execute_batch(
            "create trigger reject_audit before insert on guard_events
             when new.event_name = 'rule.ignored.local_integrity'
             begin select raise(abort, 'audit rejected'); end;",
        )
        .unwrap();
    let audit = vec![
        (
            "policy_integrity_violation".to_owned(),
            json!({"decision_id": 1}),
            "2026-01-01T00:00:00+00:00".to_owned(),
        ),
        (
            "rule.ignored.local_integrity".to_owned(),
            json!({"decision_id": 1}),
            "2026-01-01T00:00:00+00:00".to_owned(),
        ),
    ];
    assert_eq!(
        store::write_audit(home.to_str().unwrap(), &audit),
        Err(AUDIT_UNWRITTEN)
    );
    assert!(
        events(&connection).is_empty(),
        "the transaction rolled back"
    );
}
