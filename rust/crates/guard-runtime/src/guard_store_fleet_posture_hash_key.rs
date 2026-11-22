//! `fleet_posture_hash_key`: the per-install secret that keys the fleet
//! posture digests of host names, config paths and workspace scopes.
//!
//! Port of `load_hash_key` in `runtime/fleet_posture_common.py`. Python read
//! the row and, when it held no usable key, created one and wrote it back in
//! a second step, so two reports starting together could each store their own
//! key and hash the same machine two ways. The store method runs in one write
//! transaction: it returns the stored key, or creates, stores and returns a
//! new one. The key never leaves the machine.

use rusqlite::Connection;
use serde_json::{json, Value};

use crate::guard_store_args::Args;
use crate::guard_store_db::{StoreError, StoreResult};

use super::{object_row, write};

/// `HASH_KEY_STATE_KEY`.
pub(super) const HASH_KEY_STATE_KEY: &str = "fleet_posture_hash_key";
/// The shortest stored key still accepted, in characters.
const MIN_KEY_CHARS: usize = 32;
/// Random bytes in a new key; hex-encoded, as `secrets.token_hex(32)` was.
const NEW_KEY_BYTES: usize = 32;

/// The stored key when it is a string of at least `MIN_KEY_CHARS` characters,
/// else a new random key that replaces the row.
pub(super) fn method(connection: &Connection, args: &Args<'_>) -> StoreResult<Value> {
    let now = args.str("now")?;
    let stored = object_row(connection, HASH_KEY_STATE_KEY)?
        .and_then(|row| row.get("key").and_then(Value::as_str).map(str::to_owned))
        .filter(|key| key.chars().count() >= MIN_KEY_CHARS);
    if let Some(key) = stored {
        return Ok(json!({"key": key}));
    }
    let mut secret = [0_u8; NEW_KEY_BYTES];
    getrandom::fill(&mut secret)
        .map_err(|_| StoreError::Runtime("fleet_posture_hash_key_random_failed".to_owned()))?;
    let key = hex::encode(secret);
    write(connection, HASH_KEY_STATE_KEY, &json!({"key": key}), now)?;
    Ok(json!({"key": key}))
}

#[cfg(test)]
#[path = "guard_store_fleet_posture_hash_key_tests.rs"]
mod tests;
