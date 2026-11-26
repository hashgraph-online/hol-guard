//! An installed-release migration carries the managed policy its candidate was
//! prepared against, and the resident refuses it once that policy moves.

use guard_command::extension_control::{ControlLayerKind, ControlState};
use guard_contracts::{ExtensionControlAuthorityRequestV1, ExtensionControlCatalogMigrationV1};
use serde_json::{json, Value};

use super::layers::layers_to_values;
use super::managed_tests::{activation_state, revision_state};
use super::tests::{catalog, layer, local, run, Home, AT};

const MANAGED: &str = "managed policy changed before installed upgrade";
/// What the next check refuses with once the managed gate has let the
/// migration through.
const PAST_THE_GATE: &str = "installed command pack upgrade changed controls";

fn managed_layer(catalog_digest: &str, state: ControlState) -> Value {
    layers_to_values(&[layer(ControlLayerKind::SignedCloud, catalog_digest, state)])
}

/// A migration off catalog `a` onto catalog `b` whose requested layers never
/// match the retained ones, so the only verdict before it is the managed one.
fn migrate(home: &Home, anchor_json: String, managed: Value) -> ExtensionControlAuthorityRequestV1 {
    ExtensionControlAuthorityRequestV1 {
        anchor_json: Some(anchor_json),
        now: Some(AT.to_owned()),
        catalog_migration: Some(ExtensionControlCatalogMigrationV1 {
            previous_revision: 1,
            previous_catalog_digest: catalog('a'),
            layers: layers_to_values(&[layer(
                ControlLayerKind::LocalAdmin,
                &catalog('b'),
                ControlState::Disabled,
            )]),
            installed_upgrade: Some(json!({ "managed": managed })),
        }),
        ..home.request("migrate_plan", &catalog('b'))
    }
}

fn published(home: &Home, revision: i64) {
    home.set_state(
        "managed_controls_active",
        &activation_state(&catalog('a'), revision),
    );
    home.set_state("managed_controls_revision", &revision_state(revision));
}

#[test]
fn installed_upgrade_accepts_the_managed_policy_the_candidate_saw() {
    let home = Home::new();
    let anchor = home.commit(1, &catalog('a'), &[local(&catalog('a'))], "committed");
    published(&home, 2);
    let request = migrate(
        &home,
        anchor,
        json!({
            "revision": 2,
            "layers": managed_layer(&catalog('a'), ControlState::Enabled),
        }),
    );
    assert_eq!(run(&request)["reason"], json!(PAST_THE_GATE));
}

#[test]
fn installed_upgrade_refuses_a_managed_policy_that_moved() {
    let home = Home::new();
    let anchor = home.commit(1, &catalog('a'), &[local(&catalog('a'))], "committed");
    published(&home, 2);
    let enabled = managed_layer(&catalog('a'), ControlState::Enabled);

    let moved_revision = migrate(
        &home,
        anchor.clone(),
        json!({ "revision": 3, "layers": enabled }),
    );
    assert_eq!(run(&moved_revision)["reason"], json!(MANAGED));

    let moved_controls = migrate(
        &home,
        anchor,
        json!({
            "revision": 2,
            "layers": managed_layer(&catalog('a'), ControlState::Disabled),
        }),
    );
    assert_eq!(run(&moved_controls)["reason"], json!(MANAGED));
}

#[test]
fn installed_upgrade_refuses_managed_evidence_the_authority_never_published() {
    let home = Home::new();
    let anchor = home.commit(1, &catalog('a'), &[local(&catalog('a'))], "committed");
    let request = migrate(
        &home,
        anchor,
        json!({
            "revision": 2,
            "layers": managed_layer(&catalog('a'), ControlState::Enabled),
        }),
    );
    assert_eq!(run(&request)["reason"], json!(MANAGED));
}

#[test]
fn installed_upgrade_refuses_a_head_that_is_not_protected() {
    let home = Home::new();
    let anchor = home.commit(1, &catalog('a'), &[local(&catalog('a'))], "committed");
    // An abandoned transition above the head: the read answers with the
    // writer work it needs, not a view.
    home.commit(2, &catalog('a'), &[local(&catalog('a'))], "prepared");
    published(&home, 2);
    let request = migrate(
        &home,
        anchor,
        json!({
            "revision": 2,
            "layers": managed_layer(&catalog('a'), ControlState::Enabled),
        }),
    );
    assert_eq!(run(&request)["reason"], json!(MANAGED));
}

/// Refusals past the managed gate keep the prefix callers match on and name
/// the binding that failed, so a refused first attempt says what moved.
const REFUSED: &str = "installed command pack upgrade is not authorized";

/// A migration whose controls and managed policy both hold, so the next
/// verdict is the command-pack activation binding.
fn past_controls(home: &Home, previous: Value) -> ExtensionControlAuthorityRequestV1 {
    let anchor = home.commit(1, &catalog('a'), &[local(&catalog('a'))], "committed");
    published(home, 2);
    home.db
        .execute_batch(
            "create table extension_command_pack_activation (
                singleton integer primary key, revision integer not null, record_json text not null,
                record_digest text not null, record_mac text not null, recorded_at text not null);",
        )
        .unwrap();
    ExtensionControlAuthorityRequestV1 {
        anchor_json: Some(anchor),
        now: Some(AT.to_owned()),
        catalog_migration: Some(ExtensionControlCatalogMigrationV1 {
            previous_revision: 1,
            previous_catalog_digest: catalog('a'),
            layers: layers_to_values(&[local(&catalog('b'))]),
            installed_upgrade: Some(json!({
                "managed": {
                    "revision": 2,
                    "layers": managed_layer(&catalog('a'), ControlState::Enabled),
                },
                "previous": previous,
            })),
        }),
        ..home.request("migrate_plan", &catalog('b'))
    }
}

fn activate(home: &Home, record: &str, digest: &str, mac: &str) {
    home.db
        .execute(
            "insert into extension_command_pack_activation values (1, 1, ?, ?, ?, ?)",
            [record, digest, mac, AT],
        )
        .unwrap();
}

fn previous(record: &str) -> Value {
    json!({"record": record, "digest": "d".repeat(64), "mac": "m".repeat(64)})
}

#[test]
fn installed_upgrade_names_a_missing_activation() {
    let home = Home::new();
    let request = past_controls(&home, previous("{}"));
    assert_eq!(
        run(&request)["reason"],
        json!(format!("{REFUSED}: command pack activation missing"))
    );
}

#[test]
fn installed_upgrade_names_an_activation_that_moved_after_preparation() {
    let home = Home::new();
    let request = past_controls(&home, previous("{\"revision\":1}"));
    activate(&home, "{\"revision\":2}", &"d".repeat(64), &"m".repeat(64));
    assert_eq!(
        run(&request)["reason"],
        json!(format!(
            "{REFUSED}: command pack activation changed since preparation (record)"
        ))
    );
}

#[test]
fn installed_upgrade_names_a_missing_verifier_key() {
    let home = Home::new();
    let request = past_controls(&home, previous("{}"));
    activate(&home, "{}", &"d".repeat(64), &"m".repeat(64));
    assert_eq!(
        run(&request)["reason"],
        json!(format!("{REFUSED}: policy verifier key unavailable"))
    );
}
