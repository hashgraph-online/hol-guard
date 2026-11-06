//! `upsert_policy` — the resident's own policy write.
//!
//! One transaction replaces the decision that shares a policy key, inserts the
//! new row unsigned, and — when the caller ships the policy-integrity key —
//! advances the integrity generation over every local row: rows that still
//! verify at the current generation, plus the row just written, are re-signed
//! at the next one. Rows that no longer verify are left as they are, so a
//! tampered row cannot ride a legitimate save back into the trusted set.
//!
//! The control state itself lives in the secret store, which the caller owns:
//! it persists the pending state before this call and the final state after,
//! exactly as the Python transaction did. This op reports the state the caller
//! should finalize, and reports none when nothing was signed.
//!
//! The key arrives as unpadded base64url in `integrity_key_b64`, is decoded
//! into zeroizing memory, and is never echoed in a payload or an error code.
//! The request digest omits it (`guard_store_op::request_digest`).

use base64ct::{Base64UrlUnpadded, Encoding};
use guard_policy_snapshot::policy_integrity::{
    is_remote_policy_source, sign_local_policy_row, verify_local_policy_row, REMOTE_POLICY_SOURCES,
};
use rusqlite::Connection;
use serde_json::{json, Value};
use zeroize::Zeroizing;

use crate::guard_store_args::Args;
use crate::guard_store_db::{
    exec, placeholders, query_all, value_error, Row, StoreError, StoreResult,
};
use crate::policy_integrity_generation::ROW_COLUMNS;
use crate::policy_integrity_resolver::POLICY_INTEGRITY_CONTROL_VERSION;

/// Upper bound on the decoded key; the store mints 32-byte keys.
const MAX_KEY_BYTES: usize = 1024;

/// `GuardStore.upsert_policy` (`store_policy.py`): the delete, the insert and
/// the generation advance, in one transaction.
pub(crate) fn upsert_policy(connection: &Connection, args: &Args) -> StoreResult<Value> {
    let harness = args.str("harness")?;
    let scope = args.str("scope")?;
    let artifact_id = args.opt_str("artifact_id")?;
    let artifact_hash = args.opt_str("artifact_hash")?;
    let workspace = args.opt_str("workspace")?;
    let publisher = args.opt_str("publisher")?;
    let source = args.str("source")?;
    let now = args.str("now")?;

    exec(
        connection,
        "delete from policy_decisions \
         where harness = ? and scope = ? and coalesce(artifact_id, '') = coalesce(?, '') \
           and coalesce(artifact_hash, '') = coalesce(?, '') \
           and coalesce(workspace, '') = coalesce(?, '') \
           and coalesce(publisher, '') = coalesce(?, '')",
        &[
            json!(harness),
            json!(scope),
            json!(artifact_id),
            json!(artifact_hash),
            json!(workspace),
            json!(publisher),
        ],
    )?;
    exec(
        connection,
        "insert into policy_decisions (\
           harness, scope, artifact_id, artifact_hash, workspace, publisher, action, reason, \
           owner, source, expires_at, updated_at, integrity_version, integrity_generation, \
           payload_hash, payload_mac, integrity_key_id, signed_at\
         ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, null, null, null, null, null, null)",
        &[
            json!(harness),
            json!(scope),
            json!(artifact_id),
            json!(artifact_hash),
            json!(workspace),
            json!(publisher),
            json!(args.str("action")?),
            json!(args.opt_str("reason")?),
            json!(args.opt_str("owner")?),
            json!(source),
            json!(args.opt_str("expires_at")?),
            json!(now),
        ],
    )?;
    let decision_id = connection.last_insert_rowid();

    let next_control_state = match signing_material(args)? {
        Some(material) if !is_remote_policy_source(Some(source)) => advance_generation(
            connection,
            &material.key,
            material.key_id,
            now,
            material.current_generation,
            decision_id,
        )?,
        _ => Value::Null,
    };
    Ok(json!({ "decision_id": decision_id, "next_control_state": next_control_state }))
}

/// The key, its id and the generation to advance from.
struct SigningMaterial<'a> {
    key: Zeroizing<Vec<u8>>,
    key_id: &'a str,
    current_generation: i64,
}

/// The signing material, when the caller shipped all three parts. A partial
/// set is a caller contract error, not a quiet unsigned write: the Python
/// store only ships the key once it has resolved every part.
fn signing_material<'a>(args: &Args<'a>) -> StoreResult<Option<SigningMaterial<'a>>> {
    let encoded = args.opt_str("integrity_key_b64")?;
    let key_id = args.opt_str("integrity_key_id")?;
    let generation = match args.raw("current_generation") {
        None => None,
        Some(_) => Some(args.int("current_generation")?),
    };
    match (encoded, key_id, generation) {
        (None, None, None) => Ok(None),
        (Some(encoded), Some(key_id), Some(generation)) => {
            let decoded = Base64UrlUnpadded::decode_vec(encoded)
                .map_err(|_| StoreError::Invalid("native_policy_integrity_key_invalid"))?;
            let key = Zeroizing::new(decoded);
            if key.is_empty() || key.len() > MAX_KEY_BYTES || key_id.is_empty() || generation < 0 {
                return value_error("native_policy_integrity_key_invalid");
            }
            Ok(Some(SigningMaterial {
                key,
                key_id,
                current_generation: generation,
            }))
        }
        _ => value_error("native_guard_store_invalid"),
    }
}

/// `_advance_policy_integrity_generation` (`store_secret_policy_integrity.py`)
/// without the control-state writes the caller owns.
fn advance_generation(
    connection: &Connection,
    key: &[u8],
    key_id: &str,
    now: &str,
    current_generation: i64,
    forced_decision_id: i64,
) -> StoreResult<Value> {
    let next_generation = current_generation
        .checked_add(1)
        .ok_or(StoreError::Invalid(
            "native_policy_integrity_generation_invalid",
        ))?;
    for row in local_rows(connection)? {
        let decision_id = row
            .get("decision_id")
            .and_then(Value::as_i64)
            .ok_or(StoreError::Invalid("native_guard_store_cell_invalid"))?;
        let row = Value::Object(row);
        if decision_id != forced_decision_id
            && verify_local_policy_row(
                &row,
                Some(key),
                Some(key_id),
                false,
                Some(current_generation),
            )
            .status
                != "valid"
        {
            continue;
        }
        let signed = sign_local_policy_row(&row, key, key_id, now, next_generation)
            .map_err(|_| StoreError::Invalid("native_policy_row_invalid"))?;
        exec(
            connection,
            "update policy_decisions \
             set integrity_version = ?, integrity_generation = ?, payload_hash = ?, \
                 payload_mac = ?, integrity_key_id = ?, signed_at = ? \
             where decision_id = ?",
            &[
                signed["integrity_version"].clone(),
                signed["integrity_generation"].clone(),
                signed["payload_hash"].clone(),
                signed["payload_mac"].clone(),
                signed["integrity_key_id"].clone(),
                signed["signed_at"].clone(),
                json!(decision_id),
            ],
        )?;
    }
    Ok(json!({
        "cutover_complete": true,
        "generation": next_generation,
        "pending_generation": Value::Null,
        "version": POLICY_INTEGRITY_CONTROL_VERSION,
    }))
}

/// `_load_local_policy_rows` (`store_policy_integrity_runtime.py`): every row
/// this store signs itself, newest first.
fn local_rows(connection: &Connection) -> StoreResult<Vec<Row>> {
    let placeholders = placeholders(REMOTE_POLICY_SOURCES.len());
    let sql = format!(
        "select {} from policy_decisions where source not in ({placeholders}) \
         order by updated_at desc",
        ROW_COLUMNS.join(", ")
    );
    let params: Vec<Value> = REMOTE_POLICY_SOURCES.iter().map(|s| json!(s)).collect();
    query_all(connection, &sql, &params)
}

#[cfg(test)]
#[path = "guard_store_policy_upsert_tests.rs"]
mod tests;
