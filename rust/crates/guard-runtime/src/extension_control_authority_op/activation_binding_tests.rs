//! A read across catalogs keeps the authority head on the catalog its own
//! command-pack activation names.

use rusqlite::params;
use serde_json::{json, Value};

use super::records::{canonical, sha256_hex};
use super::tests::{catalog, local, manifest, read_request, run, Home, AT};
use guard_contracts::ExtensionControlAuthorityRequestV1;

/// Stores an activation record for `catalog_digest` and returns its digest,
/// the value a head bound to it seals as `command_pack_record_digest`.
fn activate(home: &Home, catalog_digest: &str) -> String {
    home.db
        .execute_batch(
            "create table if not exists extension_command_pack_activation (
                singleton integer primary key, revision integer not null, record_json text not null,
                record_digest text not null, record_mac text not null, recorded_at text not null);",
        )
        .unwrap();
    let record = canonical(&json!({
        "catalog_digest": catalog_digest,
        "schema": "guard.command-pack-activation.v2",
    }))
    .unwrap();
    let digest = sha256_hex(&record);
    home.db
        .execute(
            "insert or replace into extension_command_pack_activation values (1, 1, ?, ?, ?, ?)",
            params![record, digest, "0".repeat(64), AT],
        )
        .unwrap();
    digest
}

fn migrating(
    home: &Home,
    catalog_digest: &str,
    anchor: String,
) -> ExtensionControlAuthorityRequestV1 {
    ExtensionControlAuthorityRequestV1 {
        migration: true,
        allow_migration: true,
        current_manifest: Some(manifest("fp1")),
        ..read_request(home, catalog_digest, Some(anchor))
    }
}

/// Commits `revision` on `to` the way a catalog migration from `from` records it.
fn migrate(home: &Home, revision: i64, from: &str, to: &str, pack: &str) -> String {
    let reference = format!("catalog-migration:{from}:{to}:{}", revision - 1);
    home.commit_keyed(
        revision,
        to,
        &[local(to)],
        "committed",
        Some(pack),
        false,
        &reference,
    )
}

fn served_in_memory(result: &Value, catalog_digest: &str) {
    assert!(result.get("action").is_none(), "{result}");
    assert_eq!(result["view"]["health"], json!("protected"));
    assert_eq!(result["view"]["catalog_digest"], json!(catalog_digest));
}

#[test]
fn a_head_moved_off_its_activation_catalog_migrates_back_despite_the_oscillation_guard() {
    // An upgrade moved the head from a to b and activated b's packs; an older
    // runtime still on a then moved it back. The pair reads as two runtimes
    // fighting, which alone holds every further migration in memory, and the
    // next installed upgrade, planned from b, failed on every startup.
    let home = Home::new();
    let pack = activate(&home, &catalog('b'));
    home.commit_bound(
        1,
        &catalog('a'),
        &[local(&catalog('a'))],
        "committed",
        Some(&pack),
        false,
    );
    migrate(&home, 2, &catalog('a'), &catalog('b'), &pack);
    let anchor = migrate(&home, 3, &catalog('b'), &catalog('a'), &pack);

    let action = &run(&migrating(&home, &catalog('b'), anchor))["action"];
    assert_eq!(action["action"], json!("migrate_catalog"), "{action}");
    assert_eq!(action["previous_revision"], json!(3));
    assert_eq!(action["previous_catalog_digest"], json!(catalog('a')));
    assert_eq!(action["catalog_digest"], json!(catalog('b')));
}

#[test]
fn a_runtime_on_another_catalog_never_moves_the_head_off_its_activation() {
    let home = Home::new();
    let pack = activate(&home, &catalog('b'));
    let anchor = home.commit_bound(
        1,
        &catalog('b'),
        &[local(&catalog('b'))],
        "committed",
        Some(&pack),
        false,
    );

    served_in_memory(
        &run(&migrating(&home, &catalog('a'), anchor)),
        &catalog('a'),
    );
}

#[test]
fn an_activation_the_head_does_not_name_leaves_the_migration_as_it_was() {
    let home = Home::new();
    activate(&home, &catalog('b'));
    let other = "f".repeat(64);
    let anchor = home.commit_bound(
        1,
        &catalog('b'),
        &[local(&catalog('b'))],
        "committed",
        Some(&other),
        false,
    );

    let action = &run(&migrating(&home, &catalog('a'), anchor))["action"];
    assert_eq!(action["action"], json!("migrate_catalog"), "{action}");
}

#[test]
fn an_oscillating_pair_away_from_the_activation_is_still_held_in_memory() {
    let home = Home::new();
    let pack = activate(&home, &catalog('c'));
    home.commit_bound(
        1,
        &catalog('a'),
        &[local(&catalog('a'))],
        "committed",
        Some(&pack),
        false,
    );
    migrate(&home, 2, &catalog('a'), &catalog('b'), &pack);
    let anchor = migrate(&home, 3, &catalog('b'), &catalog('a'), &pack);

    served_in_memory(
        &run(&migrating(&home, &catalog('b'), anchor)),
        &catalog('b'),
    );
}
