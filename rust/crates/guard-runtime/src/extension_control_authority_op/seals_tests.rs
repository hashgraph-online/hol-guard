use std::fs;

use guard_contracts::{ExtensionControlAuthorityRequestV1, ExtensionControlCatalogMigrationV1};
use rusqlite::params;
use serde_json::{json, Value};

use super::layers::{layers_to_json, layers_to_values};
use super::records::{
    parse_anchor, private_hash, verify_record, Phase, CATALOG_MANIFEST_PURPOSE, SNAPSHOT_PURPOSE,
    TRANSITION_PURPOSE,
};
use super::tests::{anchor, catalog, local, run, Home, AT, KEY};

const NOW: &str = "2026-10-21T00:05:00+00:00";

fn sealed(record: &Value, purpose: &str) -> serde_json::Map<String, Value> {
    verify_record(
        record["json"].as_str().unwrap(),
        record["digest"].as_str().unwrap(),
        record["mac"].as_str().unwrap(),
        &KEY,
        purpose,
    )
    .unwrap()
}

fn refusal(result: &Value) -> &str {
    assert_eq!(result["fault"], json!("tampered"), "{result}");
    result["reason"].as_str().unwrap()
}

fn writer(home: &Home, op: &str) -> ExtensionControlAuthorityRequestV1 {
    ExtensionControlAuthorityRequestV1 {
        now: Some(NOW.to_owned()),
        ..home.request(op, &catalog('a'))
    }
}

#[test]
fn a_sealed_anchor_reads_back_as_the_anchor_it_names() {
    let home = Home::new();
    let digest = catalog('d');
    let request = ExtensionControlAuthorityRequestV1 {
        revision: Some(3),
        snapshot_digest: Some(digest.clone()),
        phase: Some("anchored".to_owned()),
        ..home.request("seal_anchor", &catalog('a'))
    };
    let sealed = run(&request)["anchor_json"].as_str().unwrap().to_owned();
    let parsed = parse_anchor(&sealed, &KEY).unwrap();
    assert_eq!(
        (parsed.revision, parsed.snapshot_digest, parsed.phase),
        (3, digest, Phase::Anchored)
    );
    for bad in [
        ExtensionControlAuthorityRequestV1 {
            phase: Some("finished".to_owned()),
            ..request.clone()
        },
        ExtensionControlAuthorityRequestV1 {
            revision: Some(-1),
            ..request.clone()
        },
        ExtensionControlAuthorityRequestV1 {
            snapshot_digest: Some("short".to_owned()),
            ..request.clone()
        },
    ] {
        assert_eq!(refusal(&run(&bad)), "invalid authority anchor");
    }
}

#[test]
fn a_sealed_manifest_is_the_record_load_manifest_trusts() {
    let home = Home::new();
    let manifest = std::collections::BTreeMap::from([
        ("extension:b".to_owned(), "2".to_owned()),
        ("extension:a".to_owned(), "1".to_owned()),
    ]);
    let sealed_manifest = run(&ExtensionControlAuthorityRequestV1 {
        current_manifest: Some(manifest.clone()),
        ..writer(&home, "seal_manifest")
    });
    let manifest_json = sealed_manifest["manifest_json"].as_str().unwrap();
    assert_eq!(manifest_json, r#"{"extension:a":"1","extension:b":"2"}"#);
    let record = &sealed_manifest["record"];
    let payload = sealed(record, CATALOG_MANIFEST_PURPOSE);
    assert_eq!(payload["recorded_at"], json!(NOW));
    home.db
        .execute(
            "insert into extension_control_catalog_manifest values (?, ?, ?, ?, ?, ?)",
            params![
                catalog('a'),
                manifest_json,
                record["json"].as_str(),
                record["digest"].as_str(),
                record["mac"].as_str(),
                NOW
            ],
        )
        .unwrap();
    let loaded = run(&home.request("load_manifest", &catalog('a')));
    assert_eq!(loaded["manifest"], json!(manifest));
}

#[test]
fn bootstrap_seals_an_empty_first_snapshot_only_once() {
    let home = Home::new();
    let plan = &run(&writer(&home, "bootstrap_plan"))["plan"];
    assert_eq!(plan["outcome"], json!("bootstrap"));
    assert_eq!(plan["layers_json"], json!("[]"));
    let snapshot = sealed(&plan["snapshot"], SNAPSHOT_PURPOSE);
    assert_eq!(snapshot["revision"], json!(0));
    assert_eq!(snapshot["previous_digest"], Value::Null);
    assert_eq!(snapshot["committed_at"], json!(NOW));
    home.commit(1, &catalog('a'), &[], "committed");
    assert_eq!(
        refusal(&run(&writer(&home, "bootstrap_plan"))),
        "extension control authority already exists"
    );
}

fn migration(previous_catalog_digest: &str) -> ExtensionControlCatalogMigrationV1 {
    ExtensionControlCatalogMigrationV1 {
        previous_revision: 1,
        previous_catalog_digest: previous_catalog_digest.to_owned(),
        layers: layers_to_values(&[local(&catalog('a'))]),
        installed_upgrade: None,
    }
}

#[test]
fn ordinary_catalog_rebinding_retains_the_committed_pack_without_reserving_one() {
    let home = Home::new();
    let pack = "a".repeat(64);
    home.commit_bound(
        1,
        &catalog('b'),
        &[local(&catalog('b'))],
        "committed",
        Some(&pack),
    );
    let result = run(&ExtensionControlAuthorityRequestV1 {
        catalog_migration: Some(migration(&catalog('b'))),
        ..writer(&home, "migrate_plan")
    });
    let plan = &result["plan"];
    assert_eq!(plan["outcome"], "migrate", "{result}");
    assert_eq!(
        sealed(&plan["snapshot"], SNAPSHOT_PURPOSE)["command_pack_record_digest"],
        json!(pack)
    );
    assert!(
        !sealed(&plan["transition"], TRANSITION_PURPOSE).contains_key("command_pack_record_digest")
    );
    assert!(plan["command_pack_record_digest"].is_null());
}

#[test]
fn a_catalog_migration_seals_the_rebinding_on_the_source_head() {
    let home = Home::new();
    home.commit(1, &catalog('b'), &[local(&catalog('b'))], "committed");
    let head: String = home
        .db
        .query_row(
            "select snapshot_digest from extension_control_authority_snapshot",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let request = |from: &str| ExtensionControlAuthorityRequestV1 {
        catalog_migration: Some(migration(from)),
        ..writer(&home, "migrate_plan")
    };
    let plan = &run(&request(&catalog('b')))["plan"];
    assert_eq!(plan["outcome"], json!("migrate"));
    assert_eq!(plan["revision"], json!(2));
    assert_eq!(plan["previous_digest"], json!(head));
    let layers_json = layers_to_json(&[local(&catalog('a'))]).unwrap();
    assert_eq!(plan["layers_json"], json!(layers_json));
    let reference = format!("catalog-migration:{}:{}:1", catalog('b'), catalog('a'));
    assert_eq!(
        plan["hashes"]["idempotency"],
        json!(private_hash(&reference, &KEY, "idempotency"))
    );
    let transition = sealed(&plan["transition"], TRANSITION_PURPOSE);
    assert_eq!(transition["snapshot_digest"], plan["snapshot"]["digest"]);
    assert_eq!(
        transition["actor_id_hash"],
        json!(private_hash("trusted-catalog-migration", &KEY, "actor"))
    );
    assert_eq!(
        refusal(&run(&request(&catalog('c')))),
        "extension control catalog migration source changed"
    );
    // The new revision must follow the head it chains to.
    let mut stale = migration(&catalog('b'));
    stale.previous_revision = 2;
    let stale = ExtensionControlAuthorityRequestV1 {
        catalog_migration: Some(stale),
        ..writer(&home, "migrate_plan")
    };
    assert_eq!(
        refusal(&run(&stale)),
        "extension control catalog migration source changed"
    );
}

/// Commits revisions 1 and 2, exports the head, and leaves the database
/// re-created without its snapshot or the head's transition.
fn quarantined(home: &Home) -> String {
    home.commit(1, &catalog('a'), &[], "committed");
    let head = home.commit(2, &catalog('a'), &[local(&catalog('a'))], "committed");
    let export: Value = home
        .db
        .query_row(
            "select * from extension_control_authority_snapshot",
            [],
            |row| {
                Ok(json!({
                    "schema": "guard.extension-control-last-good.v1",
                    "revision": row.get::<_, i64>("revision")?,
                    "catalog_digest": row.get::<_, String>("catalog_digest")?,
                    "layers_json": row.get::<_, String>("layers_json")?,
                    "previous_digest": row.get::<_, String>("previous_digest")?,
                    "snapshot_json": row.get::<_, String>("snapshot_json")?,
                    "snapshot_digest": row.get::<_, String>("snapshot_digest")?,
                    "snapshot_mac": row.get::<_, String>("snapshot_mac")?,
                    "committed_at": row.get::<_, String>("committed_at")?,
                }))
            },
        )
        .unwrap();
    fs::write(
        home.root.join("extension-control-last-good.json"),
        export.to_string(),
    )
    .unwrap();
    home.db
        .execute_batch(
            "delete from extension_control_authority_snapshot;
             delete from extension_control_authority_transition where revision = 2;",
        )
        .unwrap();
    head
}

fn restore(home: &Home, anchor_json: &str) -> Value {
    run(&ExtensionControlAuthorityRequestV1 {
        anchor_json: Some(anchor_json.to_owned()),
        ..writer(home, "restore_plan")
    })["plan"]
        .clone()
}

#[test]
fn a_verified_export_restores_the_anchored_head_and_its_baseline() {
    let home = Home::new();
    let head = quarantined(&home);
    let plan = restore(&home, &head);
    assert_eq!(plan["outcome"], json!("restore"));
    assert_eq!(plan["revision"], json!(2));
    assert_eq!(plan["control_count"], json!(1));
    assert_eq!(plan["committed_at"], json!(AT));
    assert_eq!(plan["restored_at"], json!(NOW));
    let snapshot = sealed(&plan["snapshot"], SNAPSHOT_PURPOSE);
    assert_eq!(snapshot["revision"], json!(2));
    let baseline = sealed(&plan["baseline"]["transition"], TRANSITION_PURPOSE);
    assert_eq!(baseline["restored_baseline"], json!(true));
    assert_eq!(baseline["created_at"], json!(AT));
    assert_eq!(baseline["snapshot_digest"], plan["snapshot"]["digest"]);
    assert_eq!(baseline["previous_digest"], plan["previous_digest"]);
}

#[test]
fn an_export_that_does_not_match_the_committed_anchor_is_skipped() {
    let home = Home::new();
    let head = quarantined(&home);
    let digest = parse_anchor(&head, &KEY).unwrap().snapshot_digest;
    for other in [
        anchor(2, &digest, "anchored"),
        anchor(1, &digest, "committed"),
        anchor(2, &catalog('f'), "committed"),
    ] {
        assert_eq!(restore(&home, &other)["outcome"], json!("skip"));
    }
    let path = home.root.join("extension-control-last-good.json");
    let text = fs::read_to_string(&path).unwrap();
    let mut forged: Value = serde_json::from_str(&text).unwrap();
    forged["snapshot_mac"] = json!("0".repeat(64));
    fs::write(&path, forged.to_string()).unwrap();
    assert_eq!(restore(&home, &head)["outcome"], json!("skip"));
    fs::write(&path, text).unwrap();
    home.commit(2, &catalog('a'), &[local(&catalog('a'))], "committed");
    // A snapshot row already exists: nothing is restored over it.
    assert_eq!(restore(&home, &head)["outcome"], json!("skip"));
}

#[cfg(unix)]
#[test]
fn a_symlinked_export_is_never_read() {
    let home = Home::new();
    let head = quarantined(&home);
    let path = home.root.join("extension-control-last-good.json");
    let moved = home.root.join("elsewhere.json");
    fs::rename(&path, &moved).unwrap();
    std::os::unix::fs::symlink(&moved, &path).unwrap();
    assert_eq!(restore(&home, &head)["outcome"], json!("skip"));
}
