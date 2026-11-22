//! A digest of the stored Guard Cloud sign-in record, and whether it is
//! present and bound to a device.
//!
//! Port of `_sign_in_stamp` in `runtime/command_queue_auth.py`. The command
//! worker reuses a resolved sign-in for a few seconds only while the stored
//! record it came from is unchanged, so it compares this stamp before and
//! after each resolve. Before, Python read the whole credential record just
//! to hash it. The store now hashes the stored text and hands back only the
//! digest, so the record never leaves the store for this check.
//!
//! The stamp is compared only with another stamp of the same home, so it is
//! the SHA-256 of the stored text rather than of a re-encoded record. Any
//! rewrite of the record changes it.
//!
//! `oauth_sign_in_presence` ports the two presence checks in
//! `runtime/exact_cloud_review.py` (`_oauth_metadata` and `_oauth_state`),
//! which also read the whole record only to look at its shape and its
//! `device_id`.

use rusqlite::{Connection, OptionalExtension};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use super::is_credential_key;
use crate::guard_store_args::Args;
use crate::guard_store_db::{value_error, StoreError, StoreResult};

/// Whether `method` is the sign-in stamp read.
pub(crate) fn handles(method: &str) -> bool {
    matches!(method, "oauth_sign_in_stamp" | "oauth_sign_in_presence")
}

pub(crate) fn dispatch(
    connection: &Connection,
    method: &str,
    args: &Args<'_>,
) -> StoreResult<Value> {
    match method {
        "oauth_sign_in_stamp" => sign_in_stamp(connection, args.str("state_key")?),
        "oauth_sign_in_presence" => sign_in_presence(connection, args.str("state_key")?),
        _ => Err(StoreError::Invalid("native_guard_store_method_unknown")),
    }
}

/// The stored bytes of a credential row, or `None` when there is no row.
/// Read as bytes so a damaged cell reads as no record instead of failing.
fn stored_record(connection: &Connection, state_key: &str) -> StoreResult<Option<Vec<u8>>> {
    if !is_credential_key(state_key) {
        return value_error("oauth_sign_in_key_invalid");
    }
    let stored: Option<Option<Vec<u8>>> = connection
        .query_row(
            "select cast(payload_json as blob) from sync_state where state_key = ?",
            [state_key],
            |row| row.get(0),
        )
        .optional()?;
    Ok(stored.flatten())
}

/// `{"present": bool, "device_bound": bool}`. `present` is whether the row
/// holds a JSON object. `device_bound` is whether that object also names a
/// `device_id` that is not blank after Python's `str.strip`.
fn sign_in_presence(connection: &Connection, state_key: &str) -> StoreResult<Value> {
    let record = stored_record(connection, state_key)?
        .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
        .filter(Value::is_object);
    let device_bound = record
        .as_ref()
        .and_then(|record| record.get("device_id"))
        .and_then(Value::as_str)
        .is_some_and(|device_id| !python_strip(device_id).is_empty());
    Ok(json!({ "present": record.is_some(), "device_bound": device_bound }))
}

/// Python's `str.strip()`: Unicode whitespace plus the separators
/// U+001C to U+001F, which Rust's `trim` keeps.
fn python_strip(text: &str) -> &str {
    text.trim_matches(|c: char| c.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&c))
}

/// `{"stamp": hex}` for a stored record holding a JSON object or array, else
/// `{"stamp": null}`, as `_sign_in_stamp` answered for a missing or
/// unreadable record. Only the OAuth credential rows can be stamped.
fn sign_in_stamp(connection: &Connection, state_key: &str) -> StoreResult<Value> {
    let stamp = stored_record(connection, state_key)?
        .filter(|bytes| {
            serde_json::from_slice::<Value>(bytes)
                .is_ok_and(|record| record.is_object() || record.is_array())
        })
        .map(|bytes| hex::encode(Sha256::digest(&bytes)));
    Ok(json!({ "stamp": stamp }))
}

#[cfg(test)]
#[path = "guard_store_oauth_sign_in_stamp_tests.rs"]
mod tests;
