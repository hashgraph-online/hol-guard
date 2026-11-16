//! Pins the authority schema a writer op ensures: a fresh store gets the base
//! schema and the epoch counter, a pack reservation moves the marker to the
//! pack schema its record names, the marker never moves back, an unknown or
//! forged marker refuses, and the triggers carry the exact text the Python
//! epoch reader trusts.

use rusqlite::Connection;
use serde_json::json;
use sha2::{Digest, Sha256};

use super::records::Fault;
use super::schema::{ensure_schema, wanted_version};

/// `_TRIGGERS_DIGEST` and `_LEGACY_TRIGGERS_DIGEST` from
/// `store_extension_control_authority_epoch`.
const PACK_TRIGGERS_DIGEST: &str =
    "d1764b0693e690ee4a4d0fa443a3bfda0cd893af30a1c1072ddef4ec515f8d8b";
const LEGACY_TRIGGERS_DIGEST: &str =
    "6cc138096b6235dd71f45b844462783118c8305332ad572554d3132aa622ceba";

fn store() -> Connection {
    let db = Connection::open_in_memory().unwrap();
    db.execute_batch(
        "create table guard_events (event_name text not null, payload_json text not null);
         create table sync_state (state_key text primary key, payload_json text not null);",
    )
    .unwrap();
    db
}

fn marker(db: &Connection) -> i64 {
    db.query_row(
        "select version from extension_control_schema_migration",
        [],
        |row| row.get(0),
    )
    .unwrap()
}

fn has_table(db: &Connection, name: &str) -> bool {
    db.query_row(
        "select count(*) from sqlite_master where type = 'table' and name = ?",
        [name],
        |row| row.get::<_, i64>(0),
    )
    .unwrap()
        == 1
}

fn epoch(db: &Connection) -> i64 {
    db.query_row(
        "select epoch from extension_control_authority_epoch",
        [],
        |row| row.get(0),
    )
    .unwrap()
}

fn triggers_digest(db: &Connection) -> String {
    let mut statement = db
        .prepare(
            "select name, sql from sqlite_master where type = 'trigger' \
             and name glob 'trg_extension_control_epoch_*' order by name",
        )
        .unwrap();
    let rows = statement
        .query_map([], |row| {
            Ok(format!(
                "{}\n{}",
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?
            ))
        })
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    hex::encode(Sha256::digest(rows.join("\n").as_bytes()))
}

fn record(schema: &str) -> String {
    json!({ "schema": schema }).to_string()
}

#[test]
fn a_pack_reservation_asks_for_the_schema_its_record_names() {
    assert_eq!(wanted_version(None), 4);
    assert_eq!(
        wanted_version(Some(&record("guard.command-pack-activation.v1"))),
        5
    );
    assert_eq!(
        wanted_version(Some(&record("guard.command-pack-activation.v2"))),
        6
    );
    assert_eq!(wanted_version(Some("not json")), 5);
}

#[test]
fn a_fresh_store_gets_the_base_schema_and_the_triggers_python_trusts() {
    let db = store();
    ensure_schema(&db, 4).unwrap();
    assert_eq!(marker(&db), 4);
    for table in [
        "extension_control_authority_snapshot",
        "extension_control_catalog_manifest",
        "extension_control_authority_recovery_archive",
        "extension_control_authority_transition",
        "extension_control_authority_proof",
    ] {
        assert!(has_table(&db, table), "{table}");
    }
    assert!(!has_table(&db, "extension_command_pack_activation"));
    assert_eq!(triggers_digest(&db), LEGACY_TRIGGERS_DIGEST);
    assert_eq!(epoch(&db), 0);

    // Ensuring again writes nothing.
    ensure_schema(&db, 4).unwrap();
    assert_eq!(epoch(&db), 0);
}

#[test]
fn the_pack_schema_adds_its_tables_and_moves_the_epoch() {
    let db = store();
    ensure_schema(&db, 4).unwrap();
    ensure_schema(&db, 5).unwrap();
    assert_eq!(marker(&db), 5);
    for table in [
        "extension_command_pack_activation",
        "extension_command_pack_pending",
        "extension_control_pack_reservation_archive",
    ] {
        assert!(has_table(&db, table), "{table}");
    }
    assert_eq!(triggers_digest(&db), PACK_TRIGGERS_DIGEST);
    assert!(epoch(&db) > 0);

    ensure_schema(&db, 6).unwrap();
    assert_eq!(marker(&db), 6);
}

#[test]
fn the_marker_never_moves_back_and_a_pack_store_keeps_its_tables() {
    let db = store();
    ensure_schema(&db, 6).unwrap();
    db.execute_batch("drop table extension_command_pack_pending")
        .unwrap();
    ensure_schema(&db, 4).unwrap();
    ensure_schema(&db, 5).unwrap();
    assert_eq!(marker(&db), 6);
    assert!(has_table(&db, "extension_command_pack_pending"));
}

#[test]
fn an_unknown_or_forged_marker_refuses_by_name() {
    let refused = Err(Fault::Tampered(
        "unsupported or invalid extension control schema".to_owned(),
    ));
    let v7 = hex::encode(Sha256::digest(
        b"hol-guard.extension-control-authority.schema.v7",
    ));
    for (version, checksum) in [
        (json!(7), json!(v7)),
        (json!(4), json!("forged")),
        (json!("4"), json!("forged")),
    ] {
        let db = store();
        ensure_schema(&db, 4).unwrap();
        db.execute(
            "update extension_control_schema_migration set version = ?, checksum = ?",
            [
                version.to_string().trim_matches('"'),
                checksum.as_str().unwrap(),
            ],
        )
        .unwrap();
        if version.is_string() {
            db.execute(
                "update extension_control_schema_migration set version = cast(version as text) || 'x'",
                [],
            )
            .unwrap();
        }
        assert_eq!(ensure_schema(&db, 4), refused, "{version}");
    }
}
