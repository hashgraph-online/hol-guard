//! Pins the migrate op: the prepared row, the anchored and committed vault
//! anchors, the moved snapshot and the migration event, or nothing at all.

use guard_contracts::{
    ExtensionControlAuthorityRequestV1, ExtensionControlCatalogMigrationV1,
    ExtensionControlMigrationRecordV1,
};
use serde_json::{json, Value};

use super::super::layers::layers_to_values;
use super::super::resume::{anchor_ref, resolved_home};
use super::super::tests::{anchor, catalog, local, run, Home};
use crate::encrypted_secret_store::EncryptedFileSecretStore;

const NOW: &str = "2026-10-21T00:05:00+00:00";

fn migrate(home: &Home, previous_revision: i64, downgraded_from: Option<&str>) -> Value {
    run(&ExtensionControlAuthorityRequestV1 {
        now: Some(NOW.to_owned()),
        catalog_migration: Some(ExtensionControlCatalogMigrationV1 {
            previous_revision,
            previous_catalog_digest: catalog('b'),
            layers: layers_to_values(&[local(&catalog('a'))]),
            installed_upgrade: None,
        }),
        migration_record: Some(ExtensionControlMigrationRecordV1 {
            provenance: json!({"writer_version": "2.0.0", "trigger": "catalog-migration"}),
            downgraded_from: downgraded_from.map(str::to_owned),
            retired_target_ids: vec!["retired".to_owned()],
        }),
        ..home.request("migrate", &catalog('a'))
    })
}

fn count(home: &Home, sql: &str) -> i64 {
    home.db.query_row(sql, [], |row| row.get(0)).unwrap()
}

fn vault_anchor(home: &Home) -> Option<String> {
    let resolved = resolved_home(&home.root.to_string_lossy());
    EncryptedFileSecretStore::new(&resolved).get_secret(&anchor_ref(&resolved))
}

fn event(home: &Home, name: &str) -> Value {
    let payload: String = home
        .db
        .query_row(
            "select payload_json from guard_events where event_name = ?",
            [name],
            |row| row.get(0),
        )
        .unwrap();
    serde_json::from_str(&payload).unwrap()
}

#[test]
fn migrate_commits_the_rebinding_and_records_it() {
    let home = Home::new();
    home.commit(1, &catalog('b'), &[local(&catalog('b'))], "committed");
    let reply = migrate(&home, 1, None);
    assert_eq!(
        reply["resumed"],
        json!({"revision": 2, "catalog_digest": catalog('a')}),
        "{reply}"
    );
    assert_eq!(
        count(
            &home,
            "select count(*) from extension_control_authority_snapshot \
             where singleton = 1 and revision = 2 and committed_at = '2026-10-21T00:05:00+00:00'"
        ),
        1
    );
    assert_eq!(
        count(
            &home,
            "select count(*) from extension_control_authority_transition \
             where revision = 2 and phase = 'committed' and committed_at = '2026-10-21T00:05:00+00:00'"
        ),
        1
    );
    let digest: String = home
        .db
        .query_row(
            "select snapshot_digest from extension_control_authority_snapshot",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let sealed = reply["anchor_json"].as_str().unwrap().to_owned();
    let parse = |text: &str| serde_json::from_str::<Value>(text).unwrap();
    assert_eq!(parse(&sealed), parse(&anchor(2, &digest, "committed")));
    assert_eq!(vault_anchor(&home), Some(sealed));
    assert_eq!(
        event(&home, "extension_control_authority_catalog_migrated"),
        json!({
            "previous_revision": 1,
            "revision": 2,
            "previous_catalog_digest": catalog('b'),
            "catalog_digest": catalog('a'),
            "layer_count": 1,
            "control_count": 1,
            "retired_target_count": 1,
            "retired_target_ids": ["retired"],
            "provenance": {"writer_version": "2.0.0", "trigger": "catalog-migration"},
        })
    );
    assert_eq!(count(&home, "select count(*) from guard_events"), 1);
}

#[test]
fn migrate_records_a_downgrade_as_a_regression() {
    let home = Home::new();
    home.commit(1, &catalog('b'), &[local(&catalog('b'))], "committed");
    let reply = migrate(&home, 1, Some("3.0.0"));
    assert_eq!(reply["resumed"]["revision"], json!(2), "{reply}");
    let regression = json!({
        "previous_writer_version": "3.0.0",
        "writer_version": "2.0.0",
        "retired_target_count": 1,
        "retired_target_ids": ["retired"],
    });
    assert_eq!(
        event(&home, "extension_control_authority_catalog_migrated")["regression"],
        regression
    );
    let mut row = regression;
    row["revision"] = json!(2);
    row["previous_catalog_digest"] = json!(catalog('b'));
    row["catalog_digest"] = json!(catalog('a'));
    assert_eq!(
        event(&home, "extension_control_authority_catalog_regressed"),
        row
    );
}

#[test]
fn migrate_writes_nothing_when_the_source_moved() {
    let home = Home::new();
    home.commit(1, &catalog('b'), &[local(&catalog('b'))], "committed");
    let refused = migrate(&home, 2, None);
    assert_eq!(refused["fault"], json!("tampered"), "{refused}");
    assert_eq!(
        count(
            &home,
            "select count(*) from extension_control_authority_transition"
        ),
        1
    );
    assert_eq!(count(&home, "select count(*) from guard_events"), 0);
    assert_eq!(vault_anchor(&home), None);
}

#[test]
fn migrate_refuses_a_request_without_its_record() {
    let home = Home::new();
    home.commit(1, &catalog('b'), &[local(&catalog('b'))], "committed");
    let mut request = ExtensionControlAuthorityRequestV1 {
        now: Some(NOW.to_owned()),
        ..home.request("migrate", &catalog('a'))
    };
    request.catalog_migration = Some(ExtensionControlCatalogMigrationV1 {
        previous_revision: 1,
        previous_catalog_digest: catalog('b'),
        layers: layers_to_values(&[local(&catalog('a'))]),
        installed_upgrade: None,
    });
    // Without its record the op refuses before it opens a transaction.
    let refused = run(&request);
    assert_eq!(refused["fault"], json!("tampered"), "{refused}");
    assert_eq!(
        count(
            &home,
            "select count(*) from extension_control_authority_transition"
        ),
        1
    );
}
