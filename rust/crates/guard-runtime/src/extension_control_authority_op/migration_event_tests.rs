//! Pins `record_migration`: the event a protected read reports owed is
//! written once, from the migration the committed head holds, and never for
//! a head the request does not name.

use guard_contracts::{ExtensionControlAuthorityRequestV1, ExtensionControlMigrationRecordV1};
use serde_json::{json, Value};

use super::super::tests::{catalog, local, run, Home};

const NOW: &str = "2026-10-21T00:05:00+00:00";

fn home() -> Home {
    let home = Home::new();
    home.commit(1, &catalog('a'), &[local(&catalog('a'))], "committed");
    home.commit(2, &catalog('b'), &[local(&catalog('b'))], "committed");
    home
}

fn record(home: &Home, revision: i64, catalog_digest: &str) -> Value {
    run(&ExtensionControlAuthorityRequestV1 {
        now: Some(NOW.to_owned()),
        revision: Some(revision),
        migration_record: Some(ExtensionControlMigrationRecordV1 {
            provenance: json!({"trigger": "authority-read-backfill", "writer_version": "2.0.0"}),
            downgraded_from: None,
            retired_target_ids: vec!["forged".to_owned()],
        }),
        ..home.request("record_migration", catalog_digest)
    })
}

fn events(home: &Home) -> Vec<(String, String, String)> {
    let mut statement = home
        .db
        .prepare("select event_name, payload_json, occurred_at from guard_events")
        .unwrap();
    statement
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
        .unwrap()
        .map(Result::unwrap)
        .collect()
}

#[test]
fn an_owed_migration_event_is_recorded_once() {
    let home = home();
    assert_eq!(record(&home, 2, &catalog('b')), json!({ "recorded": true }));
    assert_eq!(
        record(&home, 2, &catalog('b')),
        json!({ "recorded": false })
    );
    let events = events(&home);
    assert_eq!(events.len(), 1);
    let (name, payload, occurred_at) = &events[0];
    assert_eq!(name, "extension_control_authority_catalog_migrated");
    assert_eq!(occurred_at, NOW);
    assert_eq!(
        serde_json::from_str::<Value>(payload).unwrap(),
        json!({
            "previous_revision": 1,
            "revision": 2,
            "previous_catalog_digest": catalog('a'),
            "catalog_digest": catalog('b'),
            "layer_count": 1,
            "control_count": 1,
            "retired_target_count": 0,
            "retired_target_ids": [],
            "provenance": {"trigger": "authority-read-backfill", "writer_version": "2.0.0"},
        })
    );
}

#[test]
fn a_migration_the_head_does_not_hold_is_not_recorded() {
    let home = home();
    assert_eq!(
        record(&home, 1, &catalog('a')),
        json!({ "recorded": false })
    );
    assert_eq!(
        record(&home, 2, &catalog('c')),
        json!({ "recorded": false })
    );
    let same_catalog = Home::new();
    same_catalog.commit(1, &catalog('a'), &[local(&catalog('a'))], "committed");
    same_catalog.commit(2, &catalog('a'), &[local(&catalog('a'))], "committed");
    assert_eq!(
        record(&same_catalog, 2, &catalog('a')),
        json!({ "recorded": false })
    );
    assert!(events(&home).is_empty());
    assert!(events(&same_catalog).is_empty());
}

#[test]
fn a_request_without_its_provenance_writes_nothing() {
    let home = home();
    let refused = run(&ExtensionControlAuthorityRequestV1 {
        now: Some(NOW.to_owned()),
        revision: Some(2),
        ..home.request("record_migration", &catalog('b'))
    });
    assert_eq!(refused["fault"], json!("tampered"), "{refused}");
    assert!(events(&home).is_empty());
}
