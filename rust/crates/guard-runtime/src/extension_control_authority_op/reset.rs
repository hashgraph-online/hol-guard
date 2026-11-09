//! `reset`: `_reset_extension_control_authority`'s store writes, made by the
//! resident.
//!
//! A reset never imports rows whose chain it cannot verify. It archives the
//! snapshot, every transition and every proof, records why, and empties the
//! authority so the caller can bootstrap a fresh one. Pending command-pack
//! reservations are archived and discarded with the transitions they were
//! bound to. When the caller lost the key, the catalog manifests that key
//! authenticated go too. All of it happens in one immediate transaction.

use guard_contracts::ExtensionControlAuthorityRequestV1;
use rusqlite::types::Value as SqlValue;
use rusqlite::{params, Connection};
use serde_json::{json, Map, Number, Value};

use super::records::{
    canonical, degraded, query_row, query_rows, row_py_int, row_text, sha256_hex, store_fault,
    tampered, Res, Row,
};
use super::resume::immediate;
use super::writes::open_writer;
use super::{fault_value, STORE_UNAVAILABLE};
use crate::local_store_read::table_exists;

const RESET_EVENT: &str = "extension_control_authority_reset";
const INVALID: &str = "invalid extension control reset request";

pub(super) fn reset_op(request: &ExtensionControlAuthorityRequestV1) -> Result<Value, String> {
    let connection = match open_writer(request)? {
        Ok(connection) => connection,
        Err(reply) => return Ok(reply),
    };
    Ok(immediate(&connection, || reset(&connection, request))
        .unwrap_or_else(|fault| fault_value(&fault, Vec::new())))
}

/// `abandon_bootstrap`: removes the revision-0 snapshot a bootstrap committed
/// before it failed to seal its anchor, so the home reads as unenrolled again
/// and the next enrollment starts over. A later revision is never touched.
pub(super) fn abandon_bootstrap_op(
    request: &ExtensionControlAuthorityRequestV1,
) -> Result<Value, String> {
    let connection = match open_writer(request)? {
        Ok(connection) => connection,
        Err(reply) => return Ok(reply),
    };
    let removed = connection.execute(
        "delete from extension_control_authority_snapshot where singleton = 1 and revision = 0",
        [],
    );
    Ok(match removed {
        Ok(removed) => json!({ "abandoned": removed > 0 }),
        Err(error) => fault_value(&store_fault(error), Vec::new()),
    })
}

/// `dict(row)` as `json.dumps` writes it.
fn row_json(row: &Row) -> Res<Value> {
    let mut object = Map::new();
    for (name, value) in row {
        let value = match value {
            SqlValue::Null => Value::Null,
            SqlValue::Integer(number) => json!(number),
            SqlValue::Real(number) => Number::from_f64(*number)
                .map(Value::Number)
                .ok_or_else(|| degraded("authority record is not encodable"))?,
            SqlValue::Text(text) => Value::String(text.clone()),
            SqlValue::Blob(_) => return Err(degraded("authority record is not encodable")),
        };
        object.insert(name.clone(), value);
    }
    Ok(Value::Object(object))
}

fn rows_json(rows: &[Row]) -> Res<String> {
    canonical(&Value::Array(
        rows.iter().map(row_json).collect::<Res<Vec<_>>>()?,
    ))
}

fn reset(connection: &Connection, request: &ExtensionControlAuthorityRequestV1) -> Res<Value> {
    let (Some(reset), Some(reset_at), Some(catalog_digest)) = (
        request.reset.as_ref(),
        request.now.as_deref(),
        request.catalog_digest.as_deref(),
    ) else {
        return Err(tampered(INVALID));
    };
    let snapshot = query_row(
        connection,
        "select * from extension_control_authority_snapshot where singleton = 1",
        [],
    )?;
    let transitions = query_rows(
        connection,
        "select * from extension_control_authority_transition order by revision",
        [],
    )?;
    let proofs = query_rows(
        connection,
        "select * from extension_control_authority_proof order by transition_revision, proof_id_hash",
        [],
    )?;
    let previous_snapshot_digest = match &snapshot {
        Some(row) => row_text(row, "snapshot_digest")?,
        None => "missing".to_owned(),
    };
    let archive_id = sha256_hex(&format!(
        "{reset_at}\0{}\0{previous_snapshot_digest}",
        reset.reason
    ));
    let (previous_revision, previous_catalog_digest, previous_layers_bytes) = match &snapshot {
        Some(row) => (
            Some(row_py_int(row, "revision")?),
            Some(row_text(row, "catalog_digest")?),
            row_text(row, "layers_json")?.len(),
        ),
        None => (None, None, 0),
    };
    let provenance = json!({
        "reason": reset.reason,
        "archive_id": archive_id,
        "previous_revision": previous_revision,
        "previous_catalog_digest": previous_catalog_digest,
        "previous_snapshot_digest": snapshot.as_ref().map(|_| &previous_snapshot_digest),
        "previous_layers_bytes": previous_layers_bytes,
        "previous_transition_count": transitions.len(),
        "catalog_digest": catalog_digest,
    });
    let snapshot_json = match &snapshot {
        Some(row) => canonical(&row_json(row)?)?,
        None => "null".to_owned(),
    };
    connection
        .execute(
            "insert into extension_control_authority_recovery_archive (
                archive_id, reason, archived_at, previous_revision, previous_catalog_digest,
                snapshot_row_json, transition_rows_json, proof_rows_json
             ) values (?, ?, ?, ?, ?, ?, ?, ?)",
            params![
                archive_id,
                reset.reason,
                reset_at,
                previous_revision,
                previous_catalog_digest,
                snapshot_json,
                rows_json(&transitions)?,
                rows_json(&proofs)?,
            ],
        )
        .map_err(store_fault)?;
    connection
        .execute(
            "insert into guard_events (event_name, payload_json, occurred_at) values (?, ?, ?)",
            params![RESET_EVENT, canonical(&provenance)?, reset_at],
        )
        .map_err(store_fault)?;
    for table in [
        "extension_control_authority_proof",
        "extension_control_authority_transition",
        "extension_control_authority_snapshot",
    ] {
        connection
            .execute(&format!("delete from {table}"), [])
            .map_err(store_fault)?;
    }
    abandon_reservations(connection, &archive_id)?;
    if reset.drop_manifest {
        // These rows authenticate with the lost key and cannot be reused
        // under the new one. The managed activation is authenticated on its
        // own and stays fail-closed.
        connection
            .execute("delete from extension_control_catalog_manifest", [])
            .map_err(store_fault)?;
    }
    Ok(json!({ "reset": true, "archive_id": archive_id }))
}

/// `abandon_all`: archives the pending pack reservations, then discards them.
fn abandon_reservations(connection: &Connection, archive_id: &str) -> Res<()> {
    if !table_exists(connection, "extension_command_pack_pending")
        .map_err(|_| degraded(STORE_UNAVAILABLE))?
    {
        return Ok(());
    }
    let pending = query_rows(
        connection,
        "select * from extension_command_pack_pending order by control_revision",
        [],
    )?;
    connection
        .execute(
            "insert into extension_control_pack_reservation_archive values (?, ?)",
            params![archive_id, rows_json(&pending)?],
        )
        .map_err(store_fault)?;
    connection
        .execute("delete from extension_command_pack_pending", [])
        .map_err(store_fault)?;
    Ok(())
}

#[cfg(test)]
#[path = "reset_tests.rs"]
mod tests;
