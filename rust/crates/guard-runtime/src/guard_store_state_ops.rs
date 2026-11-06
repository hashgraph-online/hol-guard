//! Small `guard.db` state methods: the latest artifact diff, the configured
//! OAuth source profiles and the managed policy-bundle keyring mirror. Each
//! runs as one store transaction; Python supplies instants and encoded
//! payload text and decides nothing here.

use rusqlite::Connection;
use serde_json::{json, Value};

use crate::guard_store_args::Args;
use crate::guard_store_db::{
    exec, query_all, query_one, text, value_error, StoreError, StoreResult,
};

const OAUTH_STATE_KEY: &str = "oauth_local_credentials";
const MIRROR_STATE_KEYS: [&str; 3] = [
    "managed_policy_bundle_keyring_provenance",
    "managed_policy_bundle_keyring_mirror",
    "policy_bundle_keyring",
];

pub(crate) fn handles(method: &str) -> bool {
    matches!(
        method,
        "artifact_latest_diff" | "oauth_sources_list" | "managed_keyring_reconcile"
    )
}

pub(crate) fn dispatch(connection: &Connection, method: &str, args: &Args) -> StoreResult<Value> {
    match method {
        "artifact_latest_diff" => latest_diff(connection, args),
        "oauth_sources_list" => oauth_sources(connection),
        "managed_keyring_reconcile" => reconcile_keyring(connection, args),
        _ => Err(StoreError::Invalid("native_guard_store_method_unknown")),
    }
}

fn parse_json(raw: &str) -> StoreResult<Value> {
    serde_json::from_str(raw).or_else(|_| value_error("invalid stored JSON"))
}

fn latest_diff(connection: &Connection, args: &Args) -> StoreResult<Value> {
    let row = query_one(
        connection,
        "select artifact_id, harness, changed_fields_json, previous_hash, current_hash, recorded_at \
         from artifact_diffs where harness = ? and artifact_id = ? order by diff_id desc limit 1",
        &[
            Value::from(args.str("harness")?),
            Value::from(args.str("artifact_id")?),
        ],
    )?;
    let Some(row) = row else {
        return Ok(Value::Null);
    };
    Ok(json!({
        "artifact_id": text(&row, "artifact_id"),
        "harness": text(&row, "harness"),
        "changed_fields": parse_json(text(&row, "changed_fields_json"))?,
        "previous_hash": row.get("previous_hash").cloned().unwrap_or(Value::Null),
        "current_hash": text(&row, "current_hash"),
        "recorded_at": text(&row, "recorded_at"),
    }))
}

fn oauth_sources(connection: &Connection) -> StoreResult<Value> {
    let prefix = format!("{OAUTH_STATE_KEY}:");
    let rows = query_all(
        connection,
        "select state_key, payload_json from sync_state where state_key = ? or state_key like ?",
        &[
            Value::from(OAUTH_STATE_KEY),
            Value::from(format!("{prefix}%")),
        ],
    )?;
    let mut sources = Vec::new();
    for row in &rows {
        let key = text(row, "state_key");
        let source = if key == OAUTH_STATE_KEY {
            "default"
        } else if let Some(name) = key.strip_prefix(&prefix) {
            name
        } else {
            continue;
        };
        let Value::Object(payload) = parse_json(text(row, "payload_json"))? else {
            continue;
        };
        let string_or_null = |name: &str| match payload.get(name) {
            Some(value @ Value::String(_)) => value.clone(),
            _ => Value::Null,
        };
        sources.push(json!({
            "source": source,
            "issuer": string_or_null("issuer"),
            "workspace_id": string_or_null("workspace_id"),
        }));
    }
    Ok(Value::Array(sources))
}

/// Writes the diagnostic mirror, the emptied local anchor slot and the
/// provenance marker together, or clears all three. A clear without the
/// provenance marker is a no-op unless forced, so deleting the user-writable
/// marker cannot preserve a replacement local anchor.
fn reconcile_keyring(connection: &Connection, args: &Args) -> StoreResult<Value> {
    let now = args.str("now")?;
    if !args.flag("configured")? {
        let marker = query_one(
            connection,
            "select 1 as present from sync_state where state_key = ?",
            &[Value::from(MIRROR_STATE_KEYS[0])],
        )?;
        if marker.is_none() && !args.flag("force_clear")? {
            return Ok(Value::Bool(false));
        }
        exec(
            connection,
            "delete from sync_state where state_key in (?,?,?)",
            &MIRROR_STATE_KEYS.map(Value::from),
        )?;
        return Ok(Value::Bool(true));
    }
    let payloads = [
        args.str("provenance_json")?,
        args.str("managed_keyring_json")?,
        args.str("local_keyring_json")?,
    ];
    for (state_key, payload_json) in MIRROR_STATE_KEYS.iter().zip(payloads) {
        exec(
            connection,
            "insert into sync_state (state_key, payload_json, updated_at) values (?, ?, ?) \
             on conflict(state_key) do update set \
             payload_json = excluded.payload_json, updated_at = excluded.updated_at",
            &[
                Value::from(*state_key),
                Value::from(payload_json),
                Value::from(now),
            ],
        )?;
    }
    Ok(Value::Bool(true))
}
