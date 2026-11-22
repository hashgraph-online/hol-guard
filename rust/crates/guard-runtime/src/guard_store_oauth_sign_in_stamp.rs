//! A digest of the stored Guard Cloud sign-in record.
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

use rusqlite::{Connection, OptionalExtension};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use super::is_credential_key;
use crate::guard_store_args::Args;
use crate::guard_store_db::{value_error, StoreError, StoreResult};

/// Whether `method` is the sign-in stamp read.
pub(crate) fn handles(method: &str) -> bool {
    method == "oauth_sign_in_stamp"
}

pub(crate) fn dispatch(
    connection: &Connection,
    method: &str,
    args: &Args<'_>,
) -> StoreResult<Value> {
    match method {
        "oauth_sign_in_stamp" => sign_in_stamp(connection, args.str("state_key")?),
        _ => Err(StoreError::Invalid("native_guard_store_method_unknown")),
    }
}

/// `{"stamp": hex}` for a stored record holding a JSON object or array, else
/// `{"stamp": null}`, as `_sign_in_stamp` answered for a missing or
/// unreadable record. Only the OAuth credential rows can be stamped.
fn sign_in_stamp(connection: &Connection, state_key: &str) -> StoreResult<Value> {
    if !is_credential_key(state_key) {
        return value_error("oauth_sign_in_stamp_key_invalid");
    }
    // Read as bytes so a damaged cell reads as no record instead of failing.
    let stored: Option<Option<Vec<u8>>> = connection
        .query_row(
            "select cast(payload_json as blob) from sync_state where state_key = ?",
            [state_key],
            |row| row.get(0),
        )
        .optional()?;
    let stamp = stored
        .flatten()
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
