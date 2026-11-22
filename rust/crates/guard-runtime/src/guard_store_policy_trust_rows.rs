//! The `sync_state` rows a cached policy bundle is judged against, read in one
//! snapshot: the bundle, the keyrings and checkpoint that decide whether it is
//! still live authority, the workspace it must belong to, and the delivery
//! rows the local policy status reports beside it.
//!
//! Port of the separate raw sync-payload reads in `synced_policy.py`,
//! `routes/policy_sync_call.py`, `policy_delivery_status.py` and
//! `review_signature_verification.py`. Reading them one by one let a sync
//! land between two reads, so a bundle could be judged against a keyring or
//! workspace from a different sync. The Review verification keyring write
//! lives here too.
//!
//! A reply is capped at 2 MiB, but a cached bundle may be up to 3 MiB. So a
//! bundle larger than half the cap is left out of the reply and replaced by
//! a stamp of its row; the caller reads it on its own and takes a second
//! snapshot to confirm nothing changed in between. Readers that only need
//! the keyrings ask for `keys_only` and never carry the bundle.

use rusqlite::Connection;
use serde_json::{json, Value};

use crate::guard_store_args::Args;
use crate::guard_store_db::{query_one, text, value_error, StoreError, StoreResult};
use crate::guard_store_sync_state::{read_payload, write_encoded};

const BUNDLE_KEY: &str = "policy_bundle";
const KEYRING_KEY: &str = "policy_bundle_keyring";
const CHECKPOINT_KEY: &str = "policy_bundle_acceptance_checkpoint";
/// `MANAGED_POLICY_BUNDLE_KEYRING_PROVENANCE_STATE_KEY`.
const PROVENANCE_KEY: &str = "managed_policy_bundle_keyring_provenance";
const SUPPLY_CHAIN_KEYRING_KEY: &str = "supply_chain_bundle_keyring";
/// `REVIEW_VERIFICATION_KEYRING_SYNC_KEY`.
const REVIEW_KEYRING_KEY: &str = "guard_review_verification_keyring";
const ACK_KEY: &str = "policy_bundle_ack";
const SYNC_SUMMARY_KEY: &str = "sync_summary";
const LAST_ERROR_KEY: &str = "policy_bundle_last_error";
/// `_OAUTH_LOCAL_CREDENTIALS_STATE_KEY`. Only its workspace id is read.
const OAUTH_CREDENTIALS_KEY: &str = "oauth_local_credentials";
/// Half the 2 MiB response limit, which leaves room for the other rows and
/// the envelope.
const BUNDLE_INLINE_BYTES: usize = 1024 * 1024;

/// Whether `method` is one of the policy trust row methods.
pub(crate) fn handles(method: &str) -> bool {
    matches!(
        method,
        "policy_bundle_trust_rows" | "record_review_verification_keyring"
    )
}

pub(crate) fn dispatch(
    connection: &Connection,
    method: &str,
    args: &Args<'_>,
) -> StoreResult<Value> {
    match method {
        "policy_bundle_trust_rows" => trust_rows(connection, args.flag("keys_only")?),
        "record_review_verification_keyring" => record_review_keyring(connection, args),
        _ => Err(StoreError::Invalid("native_guard_store_method_unknown")),
    }
}

/// Every row a cached bundle is judged against, as `get_sync_payload` would
/// return it (an object or array, else `null`), plus the bound workspace id.
/// `keys_only` leaves the bundle out. A bundle too large for the reply is
/// left out too, with `policy_bundle_deferred` set and its row stamp given.
fn trust_rows(connection: &Connection, keys_only: bool) -> StoreResult<Value> {
    let row = |key: &str| -> StoreResult<Value> {
        Ok(read_payload(connection, key)?.unwrap_or(Value::Null))
    };
    let (bundle, deferred, stamp) = if keys_only {
        (Value::Null, false, Value::Null)
    } else {
        bundle_row(connection)?
    };
    Ok(json!({
        "policy_bundle": bundle,
        "policy_bundle_deferred": deferred,
        "policy_bundle_stamp": stamp,
        "policy_bundle_keyring": row(KEYRING_KEY)?,
        "acceptance_checkpoint": row(CHECKPOINT_KEY)?,
        "managed_keyring_provenance": row(PROVENANCE_KEY)?,
        "supply_chain_keyring": row(SUPPLY_CHAIN_KEYRING_KEY)?,
        "review_verification_keyring": row(REVIEW_KEYRING_KEY)?,
        "policy_bundle_ack": row(ACK_KEY)?,
        "sync_summary": row(SYNC_SUMMARY_KEY)?,
        "policy_bundle_last_error": row(LAST_ERROR_KEY)?,
        "workspace_id": workspace_id(connection)?,
    }))
}

/// The bundle, whether it was left out for size, and the stamp of its row
/// (the write time and stored length) when it was.
fn bundle_row(connection: &Connection) -> StoreResult<(Value, bool, Value)> {
    let Some(row) = query_one(
        connection,
        "select payload_json, updated_at from sync_state where state_key = ?",
        &[Value::from(BUNDLE_KEY)],
    )?
    else {
        return Ok((Value::Null, false, Value::Null));
    };
    let encoded = text(&row, "payload_json");
    if encoded.len() > BUNDLE_INLINE_BYTES {
        let stamp = json!({ "updated_at": text(&row, "updated_at"), "bytes": encoded.len() });
        return Ok((Value::Null, true, stamp));
    }
    let bundle = serde_json::from_str::<Value>(encoded)
        .ok()
        .filter(|payload| payload.is_object() || payload.is_array())
        .unwrap_or(Value::Null);
    Ok((bundle, false, Value::Null))
}

/// `_cloud_workspace_id_from_connection`: the non-blank workspace id of the
/// stored OAuth credentials, else `null`. Nothing else leaves that row.
fn workspace_id(connection: &Connection) -> StoreResult<Value> {
    Ok(read_payload(connection, OAUTH_CREDENTIALS_KEY)?
        .and_then(|mut row| row.as_object_mut()?.remove("workspace_id"))
        .filter(|id| id.as_str().is_some_and(|text| !text.trim().is_empty()))
        .unwrap_or(Value::Null))
}

/// Store the anchored Review verification keys. Every key must be an object;
/// an empty list clears the keyring.
fn record_review_keyring(connection: &Connection, args: &Args<'_>) -> StoreResult<Value> {
    let now = args.str("now")?;
    if now.trim().is_empty() {
        return value_error("invalid_now");
    }
    let Some(keys) = args.raw("keys").and_then(Value::as_array) else {
        return value_error("invalid_keys");
    };
    if !keys.iter().all(Value::is_object) {
        return value_error("invalid_keys");
    }
    let encoded = serde_json::to_string(keys)
        .map_err(|_| StoreError::Invalid("native_review_keyring_invalid"))?;
    write_encoded(connection, REVIEW_KEYRING_KEY, &encoded, now)?;
    Ok(Value::Null)
}

#[cfg(test)]
#[path = "guard_store_policy_trust_rows_tests.rs"]
mod tests;
