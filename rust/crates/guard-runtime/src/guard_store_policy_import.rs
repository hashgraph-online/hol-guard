//! Policy document imports — the resident's own row writes for
//! `GuardStore.import_policy_document` and the MCP policy-request apply.
//!
//! The caller compiles and normalizes the document, checks the approval gate
//! and holds the command-control authority lock; this op writes the rows. In
//! `replace` mode every earlier imported row goes; in `merge` mode only the
//! rows that share a policy key with a new one. The new rows are inserted
//! unsigned and, when the caller ships the policy-integrity key, the
//! generation advances with every new row signed, as
//! `_import_policy_rows_on_connection` did.
//!
//! `apply_mcp_policy_request` runs the same write inside the request's own
//! transaction. Every check comes first, so a refused apply writes nothing
//! except the expiry of a request found past its deadline:
//!
//! - the request exists and is still pending, and has not expired;
//! - no recovery has been recorded for it;
//! - the stored candidate is the one the caller compiled;
//! - the imported rows are the ones the caller read its current digest from
//!   (`policy_rows_fingerprint`);
//! - the integrity generation is the one the request expected.
//!
//! A refusal is an `{"error": code}` answer the caller maps to its
//! `PolicyToolError`.

use std::collections::BTreeSet;

use rusqlite::Connection;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use crate::guard_store_args::Args;
use crate::guard_store_db::{exec, query_all, query_one, value_error, StoreError, StoreResult};
use crate::guard_store_json::aware_epoch_micros;
use crate::guard_store_policy_upsert::{advance_generation, signing_material};

const IMPORT_SOURCE: &str = "policy-yaml-import";
const RECOVERY_PREFIX: &str = "business_policy_request_recovered_v1/";
const INTEGRITY_STATE_KEY: &str = "policy_integrity";
/// The imported-row columns a policy document is rebuilt from.
const FINGERPRINT_COLUMNS: &str = "decision_id, harness, scope, artifact_id, artifact_hash, \
     workspace, publisher, action, reason, owner, source, expires_at, \
     policy_document_schema_version, policy_document_id, policy_document_digest, \
     policy_rule_id, policy_provenance_json, updated_at";

/// The SHA-256 of every imported row the current document is built from.
pub(crate) fn policy_rows_fingerprint(connection: &Connection, _args: &Args) -> StoreResult<Value> {
    Ok(json!({ "fingerprint": rows_fingerprint(connection)? }))
}

fn rows_fingerprint(connection: &Connection) -> StoreResult<String> {
    let rows = query_all(
        connection,
        &format!(
            "select {FINGERPRINT_COLUMNS} from policy_decisions where source = ? \
             order by decision_id"
        ),
        &[json!(IMPORT_SOURCE)],
    )?;
    let encoded = serde_json::to_vec(&rows)
        .map_err(|_| StoreError::Invalid("native_guard_store_cell_invalid"))?;
    Ok(hex::encode(Sha256::digest(encoded)))
}

/// `GuardStore.import_policy_document` (`store_policy_document.py`).
pub(crate) fn import_policy_rows(connection: &Connection, args: &Args) -> StoreResult<Value> {
    let (inserted, replaced, next_control_state) = write_rows(connection, args)?;
    Ok(json!({
        "inserted": inserted,
        "replaced": replaced,
        "next_control_state": next_control_state,
    }))
}

/// `MCPolicyRequestRepository.apply_request` with the import it runs.
pub(crate) fn apply_mcp_policy_request(connection: &Connection, args: &Args) -> StoreResult<Value> {
    let request_id = args.str("request_id")?;
    let now = args.str("now")?;
    if let Some(code) = refusal(connection, args, request_id, now)? {
        return Ok(code);
    }
    let (inserted, replaced, next_control_state) = write_rows(connection, args)?;
    let result_json = format!("{{\"inserted\":{inserted},\"replaced\":{replaced}}}");
    let updated = exec(
        connection,
        "update mcp_policy_requests set status = 'applied', resolved_at = ?, result_json = ? \
         where request_id = ? and status = 'pending'",
        &[json!(now), json!(result_json), json!(request_id)],
    )?;
    if updated == 0 {
        // The pending check above ran in this transaction, so this cannot
        // happen; the rows written above roll back with the error.
        return Err(StoreError::Runtime("policy_write_conflict".to_owned()));
    }
    Ok(json!({
        "applied": {
            "request_id": request_id,
            "resolved_at": now,
            "inserted": inserted,
            "replaced": replaced,
        },
        "next_control_state": next_control_state,
    }))
}

fn refused(code: &str) -> StoreResult<Option<Value>> {
    Ok(Some(json!({ "error": code })))
}

/// The first reason the request cannot be applied now, if any.
fn refusal(
    connection: &Connection,
    args: &Args,
    request_id: &str,
    now: &str,
) -> StoreResult<Option<Value>> {
    let Some(row) = query_one(
        connection,
        "select status, policy_document_digest, canonical_policy_yaml, mode, \
         expected_current_digest, expected_policy_generation, expires_at \
         from mcp_policy_requests where request_id = ?",
        &[json!(request_id)],
    )?
    else {
        return refused("policy_request_not_found");
    };
    let status = row.get("status").and_then(Value::as_str).unwrap_or("");
    match status {
        "pending" => {}
        "applied" | "declined" | "expired" | "failed" => {
            return Ok(Some(
                json!({"error": "approval_already_resolved", "status": status}),
            ));
        }
        _ => return refused("policy_write_conflict"),
    }
    let invalid = || StoreError::Invalid("native_guard_store_stored_value_invalid");
    let expires = row
        .get("expires_at")
        .and_then(Value::as_str)
        .and_then(aware_epoch_micros)
        .ok_or_else(invalid)?;
    let current =
        aware_epoch_micros(now).ok_or(StoreError::Invalid("native_guard_store_invalid"))?;
    if current > expires {
        exec(
            connection,
            "update mcp_policy_requests set status = 'expired', resolved_at = ? \
             where request_id = ? and status = 'pending'",
            &[json!(now), json!(request_id)],
        )?;
        return refused("approval_expired");
    }
    if query_one(
        connection,
        "select 1 as recorded from sync_state where state_key = ?",
        &[json!(format!("{RECOVERY_PREFIX}{request_id}"))],
    )?
    .is_some()
    {
        return refused("business_source_already_recovered");
    }
    let candidate = Args(args.object("candidate")?);
    let expected_generation = match candidate.raw("expected_policy_generation") {
        Some(_) => Some(candidate.int("expected_policy_generation")?),
        None => None,
    };
    let stored_text = |name: &str| {
        row.get(name)
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
    };
    if stored_text("policy_document_digest") != Some(candidate.str("policy_document_digest")?)
        || stored_text("canonical_policy_yaml") != Some(candidate.str("canonical_policy_yaml")?)
        || stored_text("mode") != Some(candidate.str("mode")?)
        || stored_text("expected_current_digest")
            != candidate
                .opt_str("expected_current_digest")?
                .filter(|value| !value.is_empty())
        || row
            .get("expected_policy_generation")
            .and_then(Value::as_i64)
            != expected_generation
    {
        return refused("candidate_digest_mismatch");
    }
    if rows_fingerprint(connection)? != args.str("rows_fingerprint")? {
        return refused("current_digest_mismatch");
    }
    if let Some(expected) = expected_generation {
        if let Some(generation) = stored_generation(connection)? {
            if generation != expected {
                return refused("stale_policy_generation");
            }
        }
    }
    Ok(None)
}

/// The generation the integrity state records, as `_safe_int` reads it.
fn stored_generation(connection: &Connection) -> StoreResult<Option<Value>> {
    let Some(row) = query_one(
        connection,
        "select payload_json from sync_state where state_key = ?",
        &[json!(INTEGRITY_STATE_KEY)],
    )?
    else {
        return Ok(None);
    };
    let payload: Value = row
        .get("payload_json")
        .and_then(Value::as_str)
        .and_then(|text| serde_json::from_str(text).ok())
        .unwrap_or(Value::Null);
    Ok(match payload.get("generation") {
        None | Some(Value::Null) => None,
        Some(Value::Number(number)) => Some(
            number
                .as_i64()
                .map(Value::from)
                .unwrap_or_else(|| Value::Number(number.clone())),
        ),
        Some(Value::String(text)) => Some(
            text.trim()
                .parse::<i64>()
                .map(Value::from)
                .unwrap_or_else(|_| Value::String(text.clone())),
        ),
        Some(other) => Some(other.clone()),
    })
}

/// The deletes, the inserts and the generation advance.
fn write_rows(connection: &Connection, args: &Args) -> StoreResult<(i64, i64, Value)> {
    let mode = args.str("mode")?;
    if !matches!(mode, "merge" | "replace") {
        return value_error("invalid_policy_import_mode");
    }
    let now = args.str("now")?;
    let document = Args(args.object("document")?);
    let api_version = document.str("api_version")?;
    let document_id = document.str("id")?;
    let digest = document.str("digest")?;
    let rows = args
        .raw("rows")
        .and_then(Value::as_array)
        .ok_or(StoreError::Invalid("native_guard_store_args_invalid"))?;
    let rows = rows
        .iter()
        .map(|row| {
            row.as_object()
                .ok_or(StoreError::Invalid("native_guard_store_args_invalid"))
        })
        .collect::<StoreResult<Vec<&Map<String, Value>>>>()?;

    let mut replaced = 0;
    if mode == "replace" {
        replaced += exec(
            connection,
            "delete from policy_decisions where source = ?",
            &[json!(IMPORT_SOURCE)],
        )?;
    }
    let mut inserted = BTreeSet::new();
    for row in rows {
        let row = Args(row);
        let key = [
            json!(row.str("harness")?),
            json!(row.str("scope")?),
            json!(row.opt_str("artifact_id")?),
            json!(row.opt_str("artifact_hash")?),
            json!(row.opt_str("workspace")?),
            json!(row.opt_str("publisher")?),
        ];
        if mode == "merge" {
            let mut params = vec![json!(IMPORT_SOURCE)];
            params.extend(key.iter().cloned());
            replaced += exec(
                connection,
                "delete from policy_decisions \
                 where source = ? \
                   and harness = ? and scope = ? and coalesce(artifact_id, '') = coalesce(?, '') \
                   and coalesce(artifact_hash, '') = coalesce(?, '') \
                   and coalesce(workspace, '') = coalesce(?, '') \
                   and coalesce(publisher, '') = coalesce(?, '')",
                &params,
            )?;
        }
        let mut params: Vec<Value> = key.to_vec();
        params.extend([
            json!(row.str("action")?),
            json!(row.opt_str("reason")?),
            json!(row.opt_str("owner")?),
            json!(row.str("source")?),
            json!(row.opt_str("expires_at")?),
            json!(api_version),
            json!(document_id),
            json!(digest),
            json!(row.str("rule_id")?),
            json!(row.opt_str("provenance_json")?),
            json!(now),
        ]);
        exec(
            connection,
            "insert into policy_decisions (\
               harness, scope, artifact_id, artifact_hash, workspace, publisher, action, reason, \
               owner, source, expires_at, policy_document_schema_version, policy_document_id, \
               policy_document_digest, policy_rule_id, policy_provenance_json, updated_at, \
               integrity_version, integrity_generation, payload_hash, payload_mac, \
               integrity_key_id, signed_at\
             ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, \
               null, null, null, null, null, null)",
            &params,
        )?;
        inserted.insert(connection.last_insert_rowid());
    }
    let inserted: Vec<i64> = inserted.into_iter().collect();
    let next_control_state = match signing_material(args)? {
        Some(material) => advance_generation(
            connection,
            &material.key,
            material.key_id,
            now,
            material.current_generation,
            &inserted,
        )?,
        None => Value::Null,
    };
    Ok((inserted.len() as i64, replaced, next_control_state))
}

#[cfg(test)]
#[path = "guard_store_policy_import_tests.rs"]
mod tests;
