//! Artifact snapshots, diffs, inventory, capabilities and provenance cache.
//! Python supplies every instant and the JSON text of structured values.
//! Action normalization is the shared native lattice, never recomputed in
//! Python. Structured columns come back as raw text for Python to decode.

use guard_contracts::{normalize_guard_action_result, GuardAction};
use rusqlite::Connection;
use serde_json::{Map, Value};

use crate::guard_store_args::Args;
use crate::guard_store_db::{exec, query_all, query_one, value_error, StoreResult};

const INCONSISTENT: &str = "authoritative_decision_inconsistent";
const INVENTORY_COLUMNS: &str =
    "artifact_id, harness, artifact_name, artifact_type, source_scope, \
     config_path, publisher, origin_url, launch_command, transport, first_seen_at, last_seen_at, \
     last_changed_at, last_approved_at, removed_at, present, last_policy_action, artifact_hash";

fn opt(value: Option<&str>) -> Value {
    value.map_or(Value::Null, Value::from)
}

/// `_canonical_inventory_action`: the action and, when the input was not a
/// recognized action, the stable contract error.
fn canonical(raw: &Value, reject_unknown: bool) -> StoreResult<(GuardAction, bool)> {
    let normalized = normalize_guard_action_result(raw, GuardAction::RequireReapproval);
    if reject_unknown && normalized.reason_code.is_some() {
        return value_error(INCONSISTENT);
    }
    Ok((normalized.action, normalized.reason_code.is_some()))
}

fn grants_approval(action: GuardAction) -> bool {
    matches!(action, GuardAction::Allow | GuardAction::Warn)
}

/// `_inventory_payload_from_row`.
fn inventory_payload(row: &Map<String, Value>) -> StoreResult<Value> {
    let (action, contract_error) =
        canonical(row.get("last_policy_action").unwrap_or(&Value::Null), false)?;
    let mut payload = Map::new();
    for key in [
        "artifact_id",
        "harness",
        "artifact_name",
        "artifact_type",
        "source_scope",
        "config_path",
    ] {
        payload.insert(key.to_owned(), cell_text(row, key));
    }
    for key in ["publisher", "origin_url", "launch_command", "transport"] {
        payload.insert(key.to_owned(), row.get(key).cloned().unwrap_or(Value::Null));
    }
    payload.insert("first_seen_at".to_owned(), cell_text(row, "first_seen_at"));
    payload.insert("last_seen_at".to_owned(), cell_text(row, "last_seen_at"));
    payload.insert(
        "last_changed_at".to_owned(),
        row.get("last_changed_at").cloned().unwrap_or(Value::Null),
    );
    let approved_at = if grants_approval(action) {
        row.get("last_approved_at").cloned().unwrap_or(Value::Null)
    } else {
        Value::Null
    };
    payload.insert("last_approved_at".to_owned(), approved_at);
    payload.insert(
        "removed_at".to_owned(),
        row.get("removed_at").cloned().unwrap_or(Value::Null),
    );
    let present = row.get("present").and_then(Value::as_i64).unwrap_or(0) != 0;
    payload.insert("present".to_owned(), Value::from(present));
    payload.insert(
        "last_policy_action".to_owned(),
        Value::from(action.as_str()),
    );
    payload.insert("artifact_hash".to_owned(), cell_text(row, "artifact_hash"));
    if contract_error {
        payload.insert(
            "decision_contract_error".to_owned(),
            Value::from(INCONSISTENT),
        );
    }
    Ok(Value::Object(payload))
}

/// Python `str(value)` for the text columns this table declares NOT NULL.
fn cell_text(row: &Map<String, Value>, key: &str) -> Value {
    match row.get(key) {
        Some(Value::String(text)) => Value::from(text.as_str()),
        Some(Value::Null) | None => Value::from("None"),
        Some(other) => Value::from(other.to_string()),
    }
}

pub(crate) fn save_snapshot(connection: &Connection, args: &Args) -> StoreResult<Value> {
    let (artifact_id, harness) = (args.str("artifact_id")?, args.str("harness")?);
    let (hash, now) = (args.str("artifact_hash")?, args.str("now")?);
    exec(
        connection,
        "insert into artifact_snapshots (artifact_id, harness, snapshot_json, artifact_hash, recorded_at) \
         values (?, ?, ?, ?, ?) \
         on conflict(artifact_id, harness) do update set \
           snapshot_json = excluded.snapshot_json, \
           artifact_hash = excluded.artifact_hash, \
           recorded_at = excluded.recorded_at",
        &[
            Value::from(artifact_id),
            Value::from(harness),
            Value::from(args.str("snapshot_json")?),
            Value::from(hash),
            Value::from(now),
        ],
    )?;
    exec(
        connection,
        "insert into artifact_hashes (artifact_id, harness, artifact_hash, recorded_at) \
         values (?, ?, ?, ?)",
        &[
            Value::from(artifact_id),
            Value::from(harness),
            Value::from(hash),
            Value::from(now),
        ],
    )?;
    Ok(Value::Null)
}

pub(crate) fn get_snapshot(connection: &Connection, args: &Args) -> StoreResult<Value> {
    let row = query_one(
        connection,
        "select snapshot_json from artifact_snapshots where artifact_id = ? and harness = ?",
        &[
            Value::from(args.str("artifact_id")?),
            Value::from(args.str("harness")?),
        ],
    )?;
    Ok(row.map_or(Value::Null, Value::Object))
}

pub(crate) fn list_snapshots(connection: &Connection, args: &Args) -> StoreResult<Value> {
    let rows = query_all(
        connection,
        "select artifact_id, snapshot_json from artifact_snapshots where harness = ?",
        &[Value::from(args.str("harness")?)],
    )?;
    Ok(Value::Array(rows.into_iter().map(Value::Object).collect()))
}

pub(crate) fn delete_snapshot(connection: &Connection, args: &Args) -> StoreResult<Value> {
    exec(
        connection,
        "delete from artifact_snapshots where artifact_id = ? and harness = ?",
        &[
            Value::from(args.str("artifact_id")?),
            Value::from(args.str("harness")?),
        ],
    )?;
    Ok(Value::Null)
}

pub(crate) fn record_diff(connection: &Connection, args: &Args) -> StoreResult<Value> {
    exec(
        connection,
        "insert into artifact_diffs ( \
           artifact_id, harness, changed_fields_json, previous_hash, current_hash, recorded_at \
         ) values (?, ?, ?, ?, ?, ?)",
        &[
            Value::from(args.str("artifact_id")?),
            Value::from(args.str("harness")?),
            Value::from(args.str("changed_fields_json")?),
            opt(args.opt_str("previous_hash")?),
            Value::from(args.str("current_hash")?),
            Value::from(args.str("now")?),
        ],
    )?;
    Ok(Value::Null)
}

pub(crate) fn record_inventory_artifact(
    connection: &Connection,
    args: &Args,
) -> StoreResult<Value> {
    let (action, _) = canonical(args.raw("policy_action").unwrap_or(&Value::Null), true)?;
    let approved = args.flag("approved")?;
    if approved && !grants_approval(action) {
        return value_error(INCONSISTENT);
    }
    let (artifact_id, harness, now) = (
        args.str("artifact_id")?,
        args.str("harness")?,
        args.str("now")?,
    );
    let existing = query_one(
        connection,
        "select first_seen_at from artifact_inventory where artifact_id = ? and harness = ?",
        &[Value::from(artifact_id), Value::from(harness)],
    )?;
    let first_seen = existing
        .as_ref()
        .and_then(|row| row.get("first_seen_at"))
        .and_then(Value::as_str)
        .unwrap_or(now);
    let changed_at = if args.flag("changed")? {
        Value::from(now)
    } else {
        Value::Null
    };
    let approved_at = if approved {
        Value::from(now)
    } else {
        Value::Null
    };
    exec(
        connection,
        "insert into artifact_inventory ( \
           artifact_id, harness, artifact_name, artifact_type, source_scope, config_path, publisher, \
           origin_url, launch_command, transport, first_seen_at, last_seen_at, last_changed_at, \
           last_approved_at, removed_at, present, last_policy_action, artifact_hash \
         ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) \
         on conflict(artifact_id, harness) do update set \
           artifact_name = excluded.artifact_name, \
           artifact_type = excluded.artifact_type, \
           source_scope = excluded.source_scope, \
           config_path = excluded.config_path, \
           publisher = excluded.publisher, \
           origin_url = excluded.origin_url, \
           launch_command = excluded.launch_command, \
           transport = excluded.transport, \
           last_seen_at = excluded.last_seen_at, \
           last_changed_at = coalesce(excluded.last_changed_at, artifact_inventory.last_changed_at), \
           last_approved_at = excluded.last_approved_at, \
           removed_at = null, \
           present = 1, \
           last_policy_action = excluded.last_policy_action, \
           artifact_hash = excluded.artifact_hash",
        &[
            Value::from(artifact_id),
            Value::from(harness),
            Value::from(args.str("artifact_name")?),
            Value::from(args.str("artifact_type")?),
            Value::from(args.str("source_scope")?),
            Value::from(args.str("config_path")?),
            opt(args.opt_str("publisher")?),
            opt(args.opt_str("origin_url")?),
            opt(args.opt_str("launch_command")?),
            opt(args.opt_str("transport")?),
            Value::from(first_seen),
            Value::from(now),
            changed_at,
            approved_at,
            Value::Null,
            Value::from(1),
            Value::from(action.as_str()),
            Value::from(args.str("artifact_hash")?),
        ],
    )?;
    Ok(Value::Null)
}

pub(crate) fn mark_removed(connection: &Connection, args: &Args) -> StoreResult<Value> {
    let (action, _) = canonical(args.raw("policy_action").unwrap_or(&Value::Null), true)?;
    let now = args.str("now")?;
    let action_text = Value::from(action.as_str());
    exec(
        connection,
        "update artifact_inventory \
         set last_seen_at = ?, last_changed_at = ?, removed_at = ?, present = 0, \
             last_approved_at = case when ? in ('allow', 'warn') then last_approved_at else null end, \
             last_policy_action = ?, artifact_hash = ? \
         where artifact_id = ? and harness = ?",
        &[
            Value::from(now),
            Value::from(now),
            Value::from(now),
            action_text.clone(),
            action_text,
            Value::from(args.str("artifact_hash")?),
            Value::from(args.str("artifact_id")?),
            Value::from(args.str("harness")?),
        ],
    )?;
    Ok(Value::Null)
}

pub(crate) fn list_inventory(connection: &Connection, args: &Args) -> StoreResult<Value> {
    let mut sql = format!("select {INVENTORY_COLUMNS} from artifact_inventory");
    let mut params = Vec::new();
    if let Some(harness) = args.opt_str("harness")? {
        sql.push_str(" where harness = ?");
        params.push(Value::from(harness));
    }
    sql.push_str(" order by harness asc, artifact_name asc");
    let rows = query_all(connection, &sql, &params)?;
    rows.iter()
        .map(inventory_payload)
        .collect::<StoreResult<Vec<_>>>()
        .map(Value::Array)
}

pub(crate) fn find_inventory_item(connection: &Connection, args: &Args) -> StoreResult<Value> {
    let sql = format!(
        "select {INVENTORY_COLUMNS} from artifact_inventory where artifact_id = ? \
         order by last_seen_at desc limit 1"
    );
    match query_one(connection, &sql, &[Value::from(args.str("artifact_id")?)])? {
        Some(row) => inventory_payload(&row),
        None => Ok(Value::Null),
    }
}

pub(crate) fn save_capability(connection: &Connection, args: &Args) -> StoreResult<Value> {
    exec(
        connection,
        "insert into artifact_capabilities (artifact_id, harness, capability_json, updated_at) \
         values (?, ?, ?, ?) \
         on conflict(artifact_id, harness) do update set \
           capability_json = excluded.capability_json, \
           updated_at = excluded.updated_at",
        &[
            Value::from(args.str("artifact_id")?),
            Value::from(args.str("harness")?),
            Value::from(args.str("capability_json")?),
            Value::from(args.str("now")?),
        ],
    )?;
    Ok(Value::Null)
}

pub(crate) fn get_capability(connection: &Connection, args: &Args) -> StoreResult<Value> {
    let row = query_one(
        connection,
        "select capability_json from artifact_capabilities where artifact_id = ? and harness = ?",
        &[
            Value::from(args.str("artifact_id")?),
            Value::from(args.str("harness")?),
        ],
    )?;
    Ok(row.map_or(Value::Null, Value::Object))
}

pub(crate) fn upsert_provenance(connection: &Connection, args: &Args) -> StoreResult<Value> {
    exec(
        connection,
        "insert into provenance_cache (artifact_hash, payload_json, updated_at) values (?, ?, ?) \
         on conflict(artifact_hash) do update set \
           payload_json = excluded.payload_json, \
           updated_at = excluded.updated_at",
        &[
            Value::from(args.str("artifact_hash")?),
            Value::from(args.str("payload_json")?),
            Value::from(args.str("now")?),
        ],
    )?;
    Ok(Value::Null)
}

/// `next_aibom_trust_attestation_sequence`: unreadable or negative state
/// restarts the count; the new value is stored the way Python's `json.dumps`
/// spelled it.
pub(crate) fn next_attestation_sequence(
    connection: &Connection,
    args: &Args,
) -> StoreResult<Value> {
    const KEY: &str = "aibom_trust_attestation_sequence";
    let now = args.str("now")?;
    let row = query_one(
        connection,
        "select payload_json from sync_state where state_key = ?",
        &[Value::from(KEY)],
    )?;
    let current = row
        .as_ref()
        .and_then(|row| row.get("payload_json"))
        .and_then(Value::as_str)
        .and_then(|text| serde_json::from_str::<Value>(text).ok())
        .and_then(|payload| payload.get("sequence").and_then(sequence_value))
        .unwrap_or(0);
    let next = current.saturating_add(1);
    exec(
        connection,
        "insert into sync_state (state_key, payload_json, updated_at) values (?, ?, ?) \
         on conflict(state_key) do update set \
           payload_json = excluded.payload_json, \
           updated_at = excluded.updated_at",
        &[
            Value::from(KEY),
            Value::from(format!("{{\"sequence\": {next}}}")),
            Value::from(now),
        ],
    )?;
    Ok(Value::from(next))
}

fn sequence_value(raw: &Value) -> Option<i64> {
    match raw {
        Value::Bool(flag) => Some(i64::from(*flag)),
        Value::Number(number) => number.as_i64().filter(|value| *value >= 0),
        Value::String(text) if !text.is_empty() && text.bytes().all(|b| b.is_ascii_digit()) => {
            text.parse().ok()
        }
        _ => None,
    }
}
