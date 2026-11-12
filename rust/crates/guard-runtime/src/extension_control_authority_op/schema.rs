//! The forward-only extension-control authority schema every writer op
//! ensures before it writes: `ensure_extension_control_authority_schema` and
//! `ensure_extension_control_authority_epoch`.
//!
//! The marker only moves forward. A store that already activated command
//! packs keeps its pack tables, and an unknown or forged marker refuses the
//! write by name. The epoch triggers are written with the exact text the
//! Python reader digests, so a counter this module creates is trusted there.

use std::collections::BTreeSet;

use rusqlite::types::ValueRef;
use rusqlite::{params, Connection, OptionalExtension};
use sha2::{Digest, Sha256};

use super::pack_finish::{PACK_SCHEMA_VERSIONS, SCHEMA_V2};
use super::records::{store_fault, tampered, Res};

/// `EXTENSION_CONTROL_SCHEMA_VERSION`.
const SCHEMA_VERSION: i64 = 4;
const INCOMPATIBLE: &str = "unsupported or invalid extension control schema";

const TABLES: [&str; 5] = [
    "create table if not exists extension_control_authority_snapshot (
            singleton integer primary key check (singleton = 1),
            revision integer not null check (revision >= 0),
            catalog_digest text not null,
            layers_json text not null,
            previous_digest text,
            snapshot_json text not null,
            snapshot_digest text not null,
            snapshot_mac text not null,
            committed_at text not null
        )",
    "create table if not exists extension_control_catalog_manifest (
            catalog_digest text primary key,
            manifest_json text not null,
            record_json text not null,
            record_digest text not null,
            record_mac text not null,
            recorded_at text not null
        )",
    "create table if not exists extension_control_authority_recovery_archive (
            archive_id text primary key,
            reason text not null,
            archived_at text not null,
            previous_revision integer,
            previous_catalog_digest text,
            snapshot_row_json text,
            transition_rows_json text not null,
            proof_rows_json text not null
        )",
    "create table if not exists extension_control_authority_transition (
            revision integer primary key check (revision > 0),
            previous_revision integer not null check (previous_revision >= 0),
            phase text not null check (phase in ('prepared', 'anchored', 'committed')),
            actor_id_hash text not null,
            idempotency_key_hash text not null unique,
            nonce_hash text not null unique,
            catalog_digest text not null,
            layers_json text not null,
            snapshot_json text not null,
            snapshot_digest text not null,
            snapshot_mac text not null,
            transition_json text not null,
            transition_digest text not null,
            transition_mac text not null,
            created_at text not null,
            committed_at text
        )",
    "create table if not exists extension_control_authority_proof (
            proof_id_hash text primary key,
            mutation_digest text not null,
            transition_revision integer not null check (transition_revision > 0),
            reserved_at text not null,
            consumed_at text
        )",
];

const PACK_TABLES: [&str; 3] = [
    "create table if not exists extension_command_pack_activation (
                singleton integer primary key check (singleton = 1),
                revision integer not null check (revision >= 0),
                record_json text not null,
                record_digest text not null,
                record_mac text not null,
                recorded_at text not null
            )",
    "create table if not exists extension_command_pack_pending (
                control_revision integer primary key check (control_revision > 0),
                record_json text not null,
                record_digest text not null,
                record_mac text not null,
                link_json text not null,
                link_digest text not null,
                link_mac text not null
            )",
    "create table if not exists extension_control_pack_reservation_archive (
            archive_id text primary key,
            reservations_json text not null
        )",
];

const EPOCH_TABLE: &str = "create table if not exists extension_control_authority_epoch (
    singleton integer primary key check (singleton = 1),
    epoch integer not null
)";

/// `AUTHORITY_INPUT_TABLES`: each table the authority read depends on, with
/// the rows that matter (`None` is every row).
const AUTHORITY_INPUT_TABLES: [(&str, Option<&str>); 8] = [
    ("extension_control_schema_migration", None),
    ("extension_control_authority_snapshot", None),
    ("extension_control_catalog_manifest", None),
    ("extension_control_authority_transition", None),
    ("extension_control_authority_proof", None),
    ("extension_command_pack_activation", None),
    (
        "guard_events",
        Some("{row}.event_name = 'extension_control_authority_catalog_migrated'"),
    ),
    (
        "sync_state",
        Some("{row}.state_key in ('managed_controls_active', 'managed_controls_revision')"),
    ),
];

fn checksum(version: i64) -> String {
    hex::encode(Sha256::digest(
        format!("hol-guard.extension-control-authority.schema.v{version}").as_bytes(),
    ))
}

/// The marker a writer needs: the pack schema the activation's record names
/// when one is being reserved, the base schema otherwise.
pub(super) fn wanted_version(pack_record_json: Option<&str>) -> i64 {
    let Some(record) = pack_record_json else {
        return SCHEMA_VERSION;
    };
    let v2 = serde_json::from_str::<serde_json::Value>(record)
        .is_ok_and(|value| value.get("schema").and_then(|s| s.as_str()) == Some(SCHEMA_V2));
    PACK_SCHEMA_VERSIONS[usize::from(v2)]
}

/// Create what is missing and move the marker forward to `wanted`.
pub(super) fn ensure_schema(connection: &Connection, wanted: i64) -> Res<()> {
    connection
        .execute_batch(
            "create table if not exists extension_control_schema_migration (
            singleton integer primary key check (singleton = 1),
            version integer not null,
            checksum text not null
        )",
        )
        .map_err(store_fault)?;
    let marker = connection
        .query_row(
            "select version, checksum from extension_control_schema_migration where singleton = 1",
            [],
            |row| {
                let version = match row.get_ref(0)? {
                    ValueRef::Integer(version) => Some(version),
                    _ => None,
                };
                let checksum = match row.get_ref(1)? {
                    ValueRef::Text(text) => std::str::from_utf8(text).ok().map(str::to_owned),
                    _ => None,
                };
                Ok((version, checksum))
            },
        )
        .optional()
        .map_err(store_fault)?;
    let mut packs = PACK_SCHEMA_VERSIONS.contains(&wanted);
    match marker {
        None => {
            connection
                .execute(
                    "insert into extension_control_schema_migration (singleton, version, checksum) \
                     values (1, ?, ?)",
                    params![wanted, checksum(wanted)],
                )
                .map_err(store_fault)?;
        }
        Some((Some(version), Some(found)))
            if (1..=PACK_SCHEMA_VERSIONS[1]).contains(&version) && found == checksum(version) =>
        {
            packs |= PACK_SCHEMA_VERSIONS.contains(&version);
            if version < wanted {
                connection
                    .execute(
                        "update extension_control_schema_migration set version = ?, checksum = ? \
                         where singleton = 1",
                        params![wanted, checksum(wanted)],
                    )
                    .map_err(store_fault)?;
            }
        }
        Some(_) => return Err(tampered(INCOMPATIBLE)),
    }
    for table in TABLES {
        connection.execute_batch(table).map_err(store_fault)?;
    }
    if packs {
        for table in PACK_TABLES {
            connection.execute_batch(table).map_err(store_fault)?;
        }
    }
    ensure_epoch(connection)
}

fn trigger_name(table: &str, event: &str) -> String {
    format!("trg_extension_control_epoch_{table}_{event}")
}

/// `_trigger_sql`, byte for byte: the reader digests this text.
fn trigger_sql(table: &str, event: &str, rows: Option<&str>) -> String {
    let when = match (rows, event) {
        (None, _) => String::new(),
        (Some(rows), "insert") => format!(" when {}", rows.replace("{row}", "new")),
        (Some(rows), "delete") => format!(" when {}", rows.replace("{row}", "old")),
        (Some(rows), _) => format!(
            " when ({}) or ({})",
            rows.replace("{row}", "old"),
            rows.replace("{row}", "new")
        ),
    };
    format!(
        "CREATE TRIGGER {} after {event} on {table}{when} begin \
         update extension_control_authority_epoch set epoch = epoch + 1 where singleton = 1; end",
        trigger_name(table, event)
    )
}

/// The counter and every trigger whose table exists; only what is missing is
/// written.
fn ensure_epoch(connection: &Connection) -> Res<()> {
    let present = {
        let mut statement = connection
            .prepare("select type, name from sqlite_master where type in ('table', 'trigger')")
            .map_err(store_fault)?;
        let rows = statement
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(store_fault)?;
        rows.collect::<Result<BTreeSet<_>, _>>()
            .map_err(store_fault)?
    };
    let has = |kind: &str, name: &str| present.contains(&(kind.to_owned(), name.to_owned()));
    if !has("table", "extension_control_authority_epoch") {
        connection.execute_batch(EPOCH_TABLE).map_err(store_fault)?;
    }
    connection
        .execute(
            "insert or ignore into extension_control_authority_epoch (singleton, epoch) values (1, 0)",
            [],
        )
        .map_err(store_fault)?;
    for (table, rows) in AUTHORITY_INPUT_TABLES {
        if !has("table", table) {
            continue;
        }
        for event in ["insert", "update", "delete"] {
            if !has("trigger", &trigger_name(table, event)) {
                connection
                    .execute_batch(&trigger_sql(table, event, rows))
                    .map_err(store_fault)?;
            }
        }
    }
    Ok(())
}
